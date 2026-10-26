package network

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"vault443/internal/core"
)

type protectedRoute struct {
	Prefix    string `json:"prefix"`
	Interface string `json:"interface"`
}
type guardOptions struct {
	Snapshot        Snapshot
	External        []external
	Protected       []protectedRoute
	Endpoint        netip.Addr
	Port            int
	Uplink          string
	TunnelReady     bool
	RejectQUIC      bool
	BlockTunnelIPv6 bool
	AllowIPv6Probe  bool
}

func nftQuote(s string) string { return strconv.Quote(s) }
func familyOf(a netip.Addr) string {
	if a.Is4() {
		return "ip"
	}
	return "ip6"
}

// GuardScript is an atomic replacement of our table only. An accept here does
// not bypass UFW/Docker/Pritunl drops in another base chain. A drop here is final.
func guardScript(o guardOptions, exists bool) string {
	var b strings.Builder
	if exists {
		fmt.Fprintf(&b, "delete table inet %s\n", TableName)
	}
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	// Mark externally managed userspace transports before policy routing. Match
	// both trusted service cgroup and explicit address/port, never uid 0 alone.
	fmt.Fprintln(&b, " chain transport { type route hook output priority mangle - 10; policy accept;")
	for _, x := range o.External {
		for _, e := range x.Binding.Endpoints {
			a, err := netip.ParseAddr(e.Address)
			if err != nil {
				continue
			}
			if x.Link.Kind != "wireguard" && x.Cgroup != "" {
				level := strings.Count(x.Cgroup, "/") + 1
				fmt.Fprintf(&b, "  socket cgroupv2 level %d %s %s daddr %s %s dport %d meta mark set 0x%x\n", level, nftQuote(x.Cgroup), familyOf(a), a, e.Protocol, e.Port, OuterMark)
			} else if x.Link.Kind == "wireguard" && e.Mark == 0 && e.SourcePort > 0 {
				// Encapsulated kernel WireGuard skbs have no usable skuid. The
				// verified wildcard kernel socket exclusively owns this UDP port;
				// ordinary processes cannot bind/reuse it. OUTPUT excludes spoofed
				// forwarded packets. Privileged raw-socket users already own networking.
				fmt.Fprintf(&b, "  udp sport %d %s daddr %s udp dport %d meta mark set 0x%x\n", e.SourcePort, familyOf(a), a, e.Port, OuterMark)
			} else if x.Binding.RootOnly {
				source := ""
				if e.SourcePort > 0 {
					source = fmt.Sprintf("%s sport %d ", e.Protocol, e.SourcePort)
				}
				fmt.Fprintf(&b, "  meta skuid 0 %s%s daddr %s %s dport %d meta mark set 0x%x\n", source, familyOf(a), a, e.Protocol, e.Port, OuterMark)
			}
		}
	}
	fmt.Fprintln(&b, " }")
	for _, hook := range []string{"output", "forward"} {
		fmt.Fprintf(&b, " chain %s_guard { type filter hook %s priority filter + 50; policy drop;\n", hook, hook)
		if hook == "output" {
			fmt.Fprintln(&b, "  oifname \"lo\" accept")
		}
		// Protected corporate prefixes never fall through to LAN or VLESS after
		// their owner disappears. More-specific routes are emitted first.
		pp := append([]protectedRoute(nil), o.Protected...)
		sort.SliceStable(pp, func(i, j int) bool {
			a, _ := netip.ParsePrefix(pp[i].Prefix)
			c, _ := netip.ParsePrefix(pp[j].Prefix)
			return a.Bits() > c.Bits()
		})
		for _, p := range pp {
			prefix, e := netip.ParsePrefix(p.Prefix)
			if e != nil {
				continue
			}
			present := false
			for _, x := range o.External {
				if x.Active && x.Link.Name == p.Interface {
					present = true
				}
			}
			if present {
				fmt.Fprintf(&b, "  %s daddr %s oifname %s accept\n", familyOf(prefix.Addr()), prefix, nftQuote(p.Interface))
			}
			fmt.Fprintf(&b, "  %s daddr %s drop\n", familyOf(prefix.Addr()), prefix)
		}
		if o.TunnelReady {
			if o.BlockTunnelIPv6 {
				if hook == "output" && o.AllowIPv6Probe {
					// Only the daemon may test an unverified IPv6 path. This is
					// never a physical-interface or container-forwarding bypass.
					fmt.Fprintf(&b, "  meta skuid 0 meta mark 0x%x meta nfproto ipv6 oifname %s tcp dport 443 accept comment \"vlt-ipv6-probe\"\n", IPv6ProbeMark, nftQuote(TunName))
				}
				// Reject before Xray's userspace TCP stack can acknowledge a SYN.
				// Browsers can then try IPv4 instead of accepting a dead IPv6 TCP
				// connection and failing later during TLS. Corporate/LAN paths
				// use their own interfaces and remain unaffected.
				fmt.Fprintf(&b, "  meta nfproto ipv6 oifname %s meta l4proto tcp counter reject with tcp reset comment \"vlt-ipv6-tcp-unavailable\"\n", nftQuote(TunName))
				fmt.Fprintf(&b, "  meta nfproto ipv6 oifname %s counter reject with icmpx type admin-prohibited comment \"vlt-ipv6-unavailable\"\n", nftQuote(TunName))
			}
			if o.RejectQUIC {
				// Plain Vision does not carry UDP/443. Return an explicit error
				// before TUN instead of making browsers wait for silently dropped
				// QUIC packets. Corporate routes above retain their own policy.
				fmt.Fprintf(&b, "  oifname %s udp dport 443 counter reject with icmpx type port-unreachable comment \"vlt-vision-quic-reject\"\n", nftQuote(TunName))
			}
			fmt.Fprintf(&b, "  oifname %s accept\n", nftQuote(TunName))
		}
		for _, x := range o.External {
			if x.Full4 {
				fmt.Fprintf(&b, "  oifname %s meta nfproto ipv4 accept\n", nftQuote(x.Link.Name))
			}
			if x.Full6 {
				fmt.Fprintf(&b, "  oifname %s meta nfproto ipv6 accept\n", nftQuote(x.Link.Name))
			}
		}
		if hook == "output" {
			// Endpoint permissions are never in FORWARD: a container cannot gain
			// a direct Internet exception by copying the core's destination.
			if o.Endpoint.IsValid() && core.SafeInterface(o.Uplink) {
				for _, proto := range []string{"tcp", "udp"} {
					fmt.Fprintf(&b, "  meta mark 0x%x %s daddr %s %s dport %d oifname %s accept\n", OuterMark, familyOf(o.Endpoint), o.Endpoint, proto, o.Port, nftQuote(o.Uplink))
				}
			}
			if core.SafeInterface(o.Uplink) {
				fmt.Fprintf(&b, "  meta mark 0x%x ip daddr 1.1.1.1 udp dport 53 oifname %s accept\n", BootstrapMark, nftQuote(o.Uplink))
				fmt.Fprintf(&b, "  meta mark 0x%x ip daddr 1.1.1.1 tcp dport 53 oifname %s accept\n", BootstrapMark, nftQuote(o.Uplink))
				fmt.Fprintf(&b, "  meta mark 0x%x ip daddr 1.1.1.1 tcp dport 443 oifname %s counter accept comment \"vlt-bootstrap-doh\"\n", BootstrapMark, nftQuote(o.Uplink))
			}
			for _, x := range o.External {
				for _, e := range x.Binding.Endpoints {
					a, err := netip.ParseAddr(e.Address)
					if err != nil {
						continue
					}
					mark := OuterMark
					if x.Link.Kind == "wireguard" {
						mark = e.Mark
						if mark == 0 && x.Binding.RootOnly && e.SourcePort > 0 {
							mark = OuterMark
						}
					}
					if mark != 0 && core.SafeInterface(o.Uplink) {
						source := ""
						if e.SourcePort > 0 {
							source = fmt.Sprintf("%s sport %d ", e.Protocol, e.SourcePort)
						}
						fmt.Fprintf(&b, "  meta mark 0x%x %s%s daddr %s %s dport %d oifname %s counter accept comment \"vlt-external-transport\"\n", mark, source, familyOf(a), a, e.Protocol, e.Port, nftQuote(o.Uplink))
					}
				}
			}
		}
		// Resolver fallback to a LAN router must not leak public queries when
		// Xray exits. Corporate DNS above remains scoped to its protected route.
		fmt.Fprintln(&b, "  udp dport { 53, 853 } drop")
		fmt.Fprintln(&b, "  tcp dport { 53, 853 } drop")
		for _, r := range localRoutes(o.Snapshot) {
			p, _ := r.Prefix()
			fmt.Fprintf(&b, "  %s daddr %s oifname %s accept\n", familyOf(p.Addr()), p, nftQuote(r.Device))
		}
		if hook == "output" {
			// Boot protection may run before udev has enumerated a NIC. These
			// bootstrap packets are link-scoped and cannot carry Internet data.
			fmt.Fprintln(&b, "  ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept")
			fmt.Fprintln(&b, "  ip6 daddr { fe80::/10, ff02::/16 } ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept")
			fmt.Fprintln(&b, "  ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept")
			for _, l := range o.Snapshot.Links {
				if l.Name == "lo" || l.Name == TunName || isTunnel(l) || !core.SafeInterface(l.Name) {
					continue
				}
				fmt.Fprintf(&b, "  oifname %s udp sport 68 udp dport 67 accept\n", nftQuote(l.Name))
				fmt.Fprintf(&b, "  oifname %s ip daddr 224.0.0.251 udp dport 5353 accept\n", nftQuote(l.Name))
				fmt.Fprintf(&b, "  oifname %s ip6 daddr ff02::fb udp dport 5353 accept\n", nftQuote(l.Name))
				fmt.Fprintf(&b, "  oifname %s ip6 daddr { fe80::/10, ff02::/16 } icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert, mld-listener-query, mld-listener-report, mld-listener-done, mld2-listener-report } accept\n", nftQuote(l.Name))
				fmt.Fprintf(&b, "  oifname %s ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept\n", nftQuote(l.Name))
			}
		}
		fmt.Fprintln(&b, "  counter drop")
		fmt.Fprintln(&b, " }")
	}
	fmt.Fprintln(&b, "}")
	return b.String()
}

func localRoutes(s Snapshot) []Route {
	var out []Route
	seen := map[string]bool{}
	for _, r := range s.Routes {
		p, ok := r.Prefix()
		if !ok || p.Bits() == 0 || r.owned() || (r.Type != "" && r.Type != "unicast") {
			continue
		}
		l, ok := s.Link(r.Device)
		if !ok || isTunnel(l) || l.Name == "lo" || !core.SafeInterface(l.Name) {
			continue
		}
		connected := r.Scope == "link"
		// iproute2 omits scope for IPv6 connected routes. Require both the
		// kernel protocol and an exact assigned subnet; a static or gateway
		// route must never become a broad LAN exception. Link-local IPv6 keeps
		// its existing scoped control rules instead of competing across links.
		if !connected && r.Family == 6 && r.Scope == "" && r.Gateway == "" && string(r.Protocol) == `"kernel"` && !p.Addr().IsLinkLocalUnicast() {
			for _, address := range l.Addresses {
				ip, err := netip.ParseAddr(address.Local)
				if err == nil && ip.Is6() && netip.PrefixFrom(ip, address.PrefixLen).Masked() == p {
					connected = true
					break
				}
			}
		}
		if !connected {
			continue
		}
		key := p.String() + "/" + r.Device
		if !seen[key] {
			out = append(out, r)
			seen[key] = true
		}
	}
	return out
}

func routePlan(s Snapshot, xs []external, protected []protectedRoute, uplink Route, tunnel bool) []command {
	var out []command
	add := func(f int, args ...string) {
		out = append(out, command{Path: "/usr/sbin/ip", Args: append([]string{fmt.Sprint("-", f)}, args...)})
	}
	// Only our dedicated tables are flushed. Guard is armed before this plan.
	for _, family := range []int{4, 6} {
		for _, table := range []int{ProxyTable, BypassTable, UnderlayTable} {
			if s.HasTable(family, table) {
				add(family, "route", "flush", "table", strconv.Itoa(table))
			}
		}
	}
	for _, r := range localRoutes(s) {
		p, _ := r.Prefix()
		args := []string{"route", "replace", p.String(), "dev", r.Device, "table", strconv.Itoa(BypassTable), "proto", "186"}
		add(r.Family, args...)
		args = []string{"route", "replace", p.String(), "dev", r.Device, "table", strconv.Itoa(UnderlayTable), "proto", "186"}
		add(r.Family, args...)
	}
	for _, p := range protected {
		prefix, e := netip.ParsePrefix(p.Prefix)
		if e != nil {
			continue
		}
		family := 4
		if prefix.Addr().Is6() {
			family = 6
		}
		args := []string{"route", "replace", "unreachable", prefix.String(), "table", strconv.Itoa(BypassTable), "proto", "186"}
		for _, x := range xs {
			if !x.Active || x.Link.Name != p.Interface {
				continue
			}
			for _, r := range x.Routes {
				q, ok := r.Prefix()
				if ok && q == prefix {
					args = []string{"route", "replace", prefix.String(), "dev", r.Device, "table", strconv.Itoa(BypassTable), "proto", "186"}
					if r.Gateway != "" {
						args = append(args, "via", r.Gateway, "onlink")
					}
				}
			}
		}
		add(family, args...)
	}
	if uplink.Device != "" {
		args := []string{"route", "replace", "default", "dev", uplink.Device, "table", strconv.Itoa(UnderlayTable), "proto", "186"}
		if uplink.Gateway != "" {
			args = append(args, "via", uplink.Gateway, "onlink")
		}
		add(4, args...)
		for _, r := range s.Routes {
			p, ok := r.Prefix()
			if ok && r.Family == 6 && p.Bits() == 0 && r.Device == uplink.Device && !r.owned() {
				args = []string{"route", "replace", "default", "dev", r.Device, "table", strconv.Itoa(UnderlayTable), "proto", "186"}
				if r.Gateway != "" {
					args = append(args, "via", r.Gateway, "onlink")
				}
				add(6, args...)
				break
			}
		}
	}
	for _, family := range []int{4, 6} {
		// Unreachable default prevents fallback to a physical default if the
		// preferred route disappears between a kernel event and reconciliation.
		add(family, "route", "replace", "unreachable", "default", "metric", "42760", "table", strconv.Itoa(ProxyTable), "proto", "186")
		if tunnel {
			add(family, "route", "replace", "default", "dev", TunName, "metric", "10", "table", strconv.Itoa(ProxyTable), "proto", "186")
		}
	}
	return out
}
