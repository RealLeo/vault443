package network

// This file is the narrow in-process integration point for application-owned
// work tunnels. Nothing here accepts D-Bus supplied interface/mark identities.
import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type ManagedRoute struct {
	CIDR, Interface string
	DNSOnly         bool
}
type ManagedTunnel struct {
	ID, Interface, Kind  string
	Endpoint             Endpoint
	Endpoints            []Endpoint
	Active, Full4, Full6 bool
}
type ManagedPolicy struct {
	Tunnels []ManagedTunnel
	Routes  []ManagedRoute
	Uplink  string
}

var managedPolicy atomic.Pointer[ManagedPolicy]
var kernelMu sync.Mutex

// Kernel serializes short kernel transactions only, never DNS, process startup,
// backoff or management/event socket waits. It also prevents a VLESS nft table
// replacement racing a work-tunnel permissions update.
type Kernel struct{}

func WithKernel(ctx context.Context, f func(Kernel) error) error {
	kernelMu.Lock()
	defer kernelMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return f(Kernel{})
}
func (Kernel) Run(ctx context.Context, path string, args []string, input string) ([]byte, error) {
	if path == "/usr/sbin/nft" && strings.Contains(input, "# vault443-managed-output") {
		input = strings.ReplaceAll(input, "# vault443-managed-output", managedRules("output"))

		input = strings.ReplaceAll(input, "# vault443-managed-forward", managedRules("forward"))
	}
	if path == "/usr/sbin/nft" {
		input = strings.ReplaceAll(input, "# vault443-source-rules", sourceRules())
		input = strings.ReplaceAll(input, "# vault443-source-elements", sourceElements("add element inet "+TableName))
		input = strings.ReplaceAll(input, "# vault443-work-source-elements", sourceElements("add element inet vault443_work"))
	}
	return runCommand(ctx, command{Path: path, Args: args, Input: input})
}
func (Kernel) Collect(ctx context.Context) (Snapshot, error) { return collect(ctx, unlockedRunner{}) }

type unlockedRunner struct{}

func (unlockedRunner) Run(ctx context.Context, c command) ([]byte, error) {
	return (Kernel{}).Run(ctx, c.Path, c.Args, c.Input)
}

func CurrentManagedPolicy() ManagedPolicy {
	p := managedPolicy.Load()
	if p == nil {
		return ManagedPolicy{}
	}
	out := ManagedPolicy{Tunnels: append([]ManagedTunnel(nil), p.Tunnels...), Routes: append([]ManagedRoute(nil), p.Routes...), Uplink: p.Uplink}
	for i := range out.Tunnels {
		out.Tunnels[i].Endpoints = append([]Endpoint(nil), out.Tunnels[i].Endpoints...)
	}
	return out
}

// PublishManaged must be called inside WithKernel, after the work guard is
// installed. Its input comes only from authenticated owned OpenVPN sessions.
func (k Kernel) PublishManaged(ctx context.Context, p ManagedPolicy) error {
	p.Tunnels = append([]ManagedTunnel(nil), p.Tunnels...)
	for i := range p.Tunnels {
		p.Tunnels[i].Endpoints = append([]Endpoint(nil), p.Tunnels[i].Endpoints...)
	}
	p.Routes = append([]ManagedRoute(nil), p.Routes...)
	managedPolicy.Store(&p)
	out, e := k.Run(ctx, "/usr/sbin/nft", []string{"list", "table", "inet", TableName}, "")
	if e != nil { // A disconnected VLESS has no table; distinguish from broken nft.
		_, listErr := k.Run(ctx, "/usr/sbin/nft", []string{"list", "tables"}, "")
		return listErr
	}
	if !strings.Contains(string(out), "managed_output") {
		if len(p.Tunnels) == 0 && len(p.Routes) == 0 {
			return nil
		}
		return fmt.Errorf("VLESS firewall does not support managed work tunnels")
	}
	var script strings.Builder
	for _, hook := range []string{"output", "forward"} {
		fmt.Fprintf(&script, "flush chain inet %s managed_%s\n", TableName, hook)
		for _, line := range strings.Split(strings.TrimSpace(managedRules(hook)), "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Fprintf(&script, "add rule inet %s managed_%s %s\n", TableName, hook, line)
			}
		}
	}
	_, e = k.Run(ctx, "/usr/sbin/nft", []string{"-f", "-"}, script.String())
	return e
}
func managedRules(hook string) string {
	p := CurrentManagedPolicy()
	var b strings.Builder
	if hook == "output" {
		for _, t := range p.Tunnels {
			for _, endpoint := range t.transportEndpoints() {
				a, e := netip.ParseAddr(endpoint.Address)
				if e != nil || p.Uplink == "" {
					continue
				}
				fmt.Fprintf(&b, "meta mark 0x%x %s daddr %s %s dport %d oifname %s accept\n", OuterMark, familyOf(a), a, endpoint.Protocol, endpoint.Port, nftQuote(p.Uplink))
			}
		}
	}
	for _, r := range p.Routes {
		a, e := netip.ParsePrefix(r.CIDR)
		if e == nil && r.Interface != "" {
			if r.DNSOnly {
				if hook == "output" {
					for _, proto := range []string{"udp", "tcp"} {
						fmt.Fprintf(&b, "%s daddr %s %s dport 53 oifname %s accept\n", familyOf(a.Addr()), a, proto, nftQuote(r.Interface))
					}
				}
				continue
			}
			fmt.Fprintf(&b, "%s daddr %s oifname %s accept\n", familyOf(a.Addr()), a, nftQuote(r.Interface))
		}
	}
	return b.String()
}

// ResolveWorkEndpoint reuses the bounded, marked DNS/DoH bootstrap resolver.
// The caller installs the narrow physical transport policy before invoking it.
func ResolveWorkEndpoint(ctx context.Context, host string) (netip.Addr, error) {
	r := newBootstrapResolver(bootstrapDialer())
	defer r.close()
	return r.resolve(ctx, host)
}

func managedBindings() []Binding {
	var out []Binding
	for _, t := range CurrentManagedPolicy().Tunnels {
		manager := "openvpn"
		if t.Kind == "wireguard" {
			manager = "wg-quick"
		}
		out = append(out, Binding{Interface: t.Interface, Manager: manager, Managed: true, ManagedActive: t.Active, ManagedFull4: t.Full4, ManagedFull6: t.Full6, Endpoints: t.transportEndpoints()})
	}
	return out
}

// LocalRoutes returns directly connected physical/LAN/Docker routes only.
func LocalRoutes(s Snapshot) []Route { return localRoutes(s) }

// IPv6 work transports still bootstrap via fixed physical IPv4 DNS/HTTPS;
// only the requested answer family changes. No system-resolver recursion.
func ResolveWorkEndpointForProtocol(ctx context.Context, host, protocol string) (netip.Addr, error) {
	if !strings.Contains(protocol, "6") {
		return ResolveWorkEndpoint(ctx, host)
	}
	r := newBootstrapResolver(bootstrapDialer())
	defer r.close()
	r.ipv6 = true
	resolver := &net.Resolver{PreferGo: true, Dial: func(c context.Context, network, _ string) (net.Conn, error) {
		return bootstrapDialer().DialContext(c, network, "1.1.1.1:53")
	}}
	r.lookup = func(c context.Context, s string) ([]netip.Addr, error) { return resolver.LookupNetIP(c, "ip6", s) }
	a, e := r.resolve(ctx, host)
	if e != nil {
		return a, fmt.Errorf("%s", strings.ReplaceAll(e.Error(), "IPv4", "IPv6"))
	}
	return a, nil
}

func (t ManagedTunnel) transportEndpoints() []Endpoint {
	if len(t.Endpoints) > 0 {
		return append([]Endpoint(nil), t.Endpoints...)
	}
	if t.Endpoint.Address != "" {
		return []Endpoint{t.Endpoint}
	}
	return nil
}

// WorkUplinkFingerprint detects DHCP renewal/address replacement, recreated
// devices and IPv6 gateway changes without reacting to our own route rewrites.
// It contains no credentials and is independent of kernel JSON ordering.
func WorkUplinkFingerprint(s Snapshot) string {
	u, err := s.Uplink()
	if err != nil {
		return "unavailable"
	}
	link, ok := s.Link(u.Device)
	if !ok {
		return "unavailable"
	}
	rows := []string{fmt.Sprintf("link:%s:%d:%d", link.Name, link.Index, link.MTU)}
	b, _ := json.Marshal(u)
	rows = append(rows, "route4:"+string(b))
	for _, a := range link.Addresses {
		rows = append(rows, fmt.Sprintf("address:%s:%s/%d", a.Family, a.Local, a.PrefixLen))
	}
	for _, r := range s.Routes {
		p, valid := r.Prefix()
		if valid && p.Bits() == 0 && r.Family == 6 && r.Device == u.Device && !r.owned() {
			b, _ = json.Marshal(r)
			rows = append(rows, "route6:"+string(b))
		}
	}
	sort.Strings(rows)
	sum := sha256.Sum256([]byte(strings.Join(rows, "\n")))
	return fmt.Sprintf("%x", sum)
}
