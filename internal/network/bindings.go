package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"vault443/internal/core"
)

// Binding is explicit administrator enrollment, not a guess from interface name.
// Endpoints are transport-only exemptions, never destination-wide bypass routes.
type Binding struct {
	Interface  string     `json:"interface"`
	Manager    string     `json:"manager"`
	Unit       string     `json:"unit,omitempty"`
	Cgroup     string     `json:"cgroup,omitempty"`
	Endpoints  []Endpoint `json:"endpoints,omitempty"`
	Routes     []string   `json:"routes,omitempty"`
	DNSDomains []string   `json:"dnsDomains,omitempty"`
	DNSServers []string   `json:"dnsServers,omitempty"`
	Remove     bool       `json:"remove,omitempty"`
	// RootOnly is derived from verified local process metadata, never accepted
	// from the public binding JSON.
	RootOnly      bool `json:"-"`
	Managed       bool `json:"-"`
	ManagedActive bool `json:"-"`
	ManagedFull4  bool `json:"-"`
	ManagedFull6  bool `json:"-"`
}
type Endpoint struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Mark       uint32 `json:"mark,omitempty"`
	SourcePort int    `json:"sourcePort,omitempty"`
}

var safeCgroup = regexp.MustCompile(`^[A-Za-z0-9_.@\\x:-]+(/[A-Za-z0-9_.@\\x:-]+)*$`)
var safeUnit = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+\.service$`)
var safeDomain = regexp.MustCompile(`^~?[A-Za-z0-9_-]+([.][A-Za-z0-9_-]+)*[.]?$`)

func ParseBinding(text string) (Binding, error) {
	var b Binding
	d := json.NewDecoder(bytes.NewBufferString(text))
	d.DisallowUnknownFields()
	if err := d.Decode(&b); err != nil {
		return b, errors.New("invalid VPN binding JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return b, errors.New("VPN binding must contain one JSON object")
	}
	if !core.SafeInterface(b.Interface) || b.Interface == TunName || b.Interface == "lo" {
		return b, errors.New("invalid external interface")
	}
	switch b.Manager {
	case "networkmanager", "pritunl", "openvpn", "wg-quick":
	default:
		return b, errors.New("unsupported VPN manager")
	}
	if b.Unit != "" && !safeUnit.MatchString(b.Unit) {
		return b, errors.New("invalid systemd unit")
	}
	if b.Cgroup != "" && (!safeCgroup.MatchString(b.Cgroup) || strings.Contains(b.Cgroup, "..")) {
		return b, errors.New("invalid trusted cgroup")
	}
	if len(b.Routes) > 256 || len(b.Endpoints) > 64 || len(b.DNSDomains) > 64 || len(b.DNSServers) > 16 {
		return b, errors.New("VPN binding exceeds limits")
	}
	for _, s := range b.Routes {
		p, e := netip.ParsePrefix(s)
		if e != nil || p.Bits() < 2 {
			return b, errors.New("protected routes must be specific CIDR prefixes")
		}
	}
	for _, e := range b.Endpoints {
		a, err := netip.ParseAddr(e.Address)
		if err != nil || a.IsLoopback() || a.IsMulticast() || e.Port < 1 || e.Port > 65535 || (e.Protocol != "tcp" && e.Protocol != "udp") {
			return b, errors.New("invalid VPN transport endpoint")
		}
		if e.SourcePort < 0 || e.SourcePort > 65535 {
			return b, errors.New("invalid transport source port")
		}
		if e.Mark == OuterMark || e.Mark == BootstrapMark || e.Mark == IPv6ProbeMark {
			return b, errors.New("external mark conflicts with this application")
		}
	}
	for _, d := range b.DNSDomains {
		if !safeDomain.MatchString(d) {
			return b, errors.New("DNS domain must be a specific suffix")
		}
	}
	for _, d := range b.DNSServers {
		if _, e := netip.ParseAddr(d); e != nil {
			return b, errors.New("DNS server must be numeric")
		}
	}
	if (len(b.DNSDomains) == 0) != (len(b.DNSServers) == 0) {
		return b, errors.New("split DNS binding needs both servers and domains")
	}
	return b, nil
}

type external struct {
	Binding      Binding
	Link         Link
	Routes       []Route
	Full4, Full6 bool
	Cgroup       string
	Active       bool
}

func detectExternal(ctx context.Context, r runner, s Snapshot, bindings []Binding) ([]external, error) {
	var out []external
	for _, b := range bindings {
		if b.Managed {
			l, _ := s.Link(b.Interface)
			l.Name = b.Interface
			l.Kind = "tun"
			out = append(out, external{Binding: b, Link: l, Active: b.ManagedActive, Full4: b.ManagedFull4, Full6: b.ManagedFull6})
			continue
		}
		// Automatically discovered bindings do not pass ParseBinding. Their
		// kernel mark must not redirect one of our private probes/transports.
		for _, endpoint := range b.Endpoints {
			if endpoint.Mark == OuterMark || endpoint.Mark == BootstrapMark || endpoint.Mark == IPv6ProbeMark {
				return nil, errors.New("external VPN mark conflicts with this application")
			}
		}
		l, present := s.Link(b.Interface)
		if present && !isTunnel(l) {
			return nil, errors.New("enrolled VPN interface is not a TUN/WireGuard device")
		}
		if !present {
			l.Name = b.Interface
			l.Kind = "tun"
			if b.Manager == "wg-quick" {
				l.Kind = "wireguard"
			}
		}
		x := external{Binding: b, Link: l, Cgroup: b.Cgroup, Active: present}
		unit := b.Unit
		if unit == "" {
			switch b.Manager {
			case "pritunl":
				unit = "pritunl-client.service"
			case "networkmanager":
				unit = "NetworkManager.service"
			}
		}
		if unit != "" && l.Kind != "wireguard" {
			data, e := r.Run(ctx, command{Path: "/usr/bin/systemctl", Args: []string{"show", unit, "--property=ControlGroup", "--value"}})
			if e != nil {
				if !present {
					continue
				}
				return nil, errors.New("cannot verify enrolled VPN service")
			}
			cg := strings.Trim(strings.TrimSpace(string(data)), "/")
			if cg == "" && !present {
				continue
			}
			if cg == "" || !safeCgroup.MatchString(cg) {
				return nil, errors.New("enrolled VPN service has no trusted cgroup")
			}
			x.Cgroup = cg
		}
		if b.Manager == "networkmanager" && present {
			data, e := r.Run(ctx, command{Path: "/usr/bin/nmcli", Args: []string{"-t", "-f", "GENERAL.TYPE,GENERAL.STATE", "device", "show", b.Interface}})
			if e != nil || !strings.Contains(string(data), "100 (connected)") {
				return nil, errors.New("enrolled NetworkManager VPN is not connected")
			}
		}
		for _, route := range s.Routes {
			if route.Device == b.Interface && !route.owned() {
				x.Routes = append(x.Routes, route)
			}
		}
		x.Full4 = claimsDefault(x.Routes, 4)
		x.Full6 = claimsDefault(x.Routes, 6)
		// WireGuard has kernel sockets. A mark must be verified against the
		// actual interface rather than attributed to a userspace process.
		if l.Kind == "wireguard" && !present {
			continue
		}
		if l.Kind == "wireguard" && len(b.Endpoints) > 0 {
			data, e := r.Run(ctx, command{Path: "/usr/bin/wg", Args: []string{"show", b.Interface, "fwmark"}})
			if e != nil {
				return nil, errors.New("cannot verify WireGuard transport mark")
			}
			actual := strings.TrimSpace(string(data))
			if actual == "off" || actual == "0" || actual == "0x0" {
				portData, e := r.Run(ctx, command{Path: "/usr/bin/wg", Args: []string{"show", b.Interface, "listen-port"}})
				if e != nil {
					return nil, errors.New("cannot verify WireGuard listen port")
				}
				for _, ep := range b.Endpoints {
					if ep.Mark != 0 || ep.SourcePort < 1 || strings.TrimSpace(string(portData)) != fmt.Sprint(ep.SourcePort) || ep.Protocol != "udp" {
						return nil, errors.New("unmarked WireGuard needs its verified UDP listen port")
					}
				}
				x.Binding.RootOnly = true
			} else {
				for _, ep := range b.Endpoints {
					if ep.Mark == 0 || actual != fmt.Sprintf("0x%x", ep.Mark) {
						return nil, errors.New("WireGuard endpoint mark does not match its interface")
					}
				}
			}
		} else if len(b.Endpoints) > 0 && x.Cgroup == "" && !b.RootOnly {
			return nil, errors.New("OpenVPN transport endpoints need a trusted cgroup or systemd unit")
		}
		out = append(out, x)
	}
	// Never silently compete with an unidentified full tunnel, or claim it is
	// protected. Explicit enrollment is needed before it can pass the guard.
	for _, l := range s.Links {
		if l.Name == TunName || !isTunnel(l) {
			continue
		}
		found := false
		for _, x := range out {
			if x.Link.Name == l.Name {
				found = true
			}
		}
		if !found {
			var rr []Route
			for _, route := range s.Routes {
				if route.Device == l.Name {
					rr = append(rr, route)
				}
			}
			if len(rr) > 0 {
				if core.SafeInterface(l.Name) {
					return nil, fmt.Errorf("unrecognized VPN interface %q; enroll it before connecting so its routes remain protected", l.Name)
				}
				return nil, errors.New("unrecognized VPN interface; enroll it before connecting so its routes remain protected")
			}
		}
	}
	return out, nil
}

func claimsDefault(routes []Route, family int) bool {
	var low, high bool
	for _, r := range routes {
		p, ok := r.Prefix()
		if !ok || r.Family != family {
			continue
		}
		if p.Bits() == 0 {
			return true
		}
		if p.Bits() == 1 {
			if p.Addr().Is4() {
				a := p.Addr().As4()
				if a[0] == 0 {
					low = true
				} else {
					high = true
				}
			} else {
				a := p.Addr().As16()
				if a[0] == 0 {
					low = true
				} else {
					high = true
				}
			}
		}
	}
	return low && high
}

func privateWrite(dir, name string, v any) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0077 != 0 || fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must be private")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}
