//go:build linux

package worknet

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"vault443/internal/network"
)

const (
	workTable       = "vault443_work"
	underlayTable   = 52783
	manualTable     = 52784
	specificTable   = 52785
	fullTable       = 52786
	replyTable      = 52787
	dnsTableStart   = 52800
	dnsReverseTable = 52832
	workProtocol    = "187"
)

func nftFamily(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "ip"
	}
	return "ip6"
}
func nftQ(s string) string { return strconv.Quote(s) }
func (m *Manager) guard(s network.Snapshot, u network.Route, sel selection, exists bool) string {
	var b strings.Builder
	if exists {
		fmt.Fprintf(&b, "delete table inet %s\n", workTable)
	}
	fmt.Fprintf(&b, "table inet %s {\n", workTable)
	fmt.Fprintln(&b, network.SourceGuardDeclarations())
	for _, ss := range sortedSessions(m.sessions) {
		if ss.Kind == "wireguard" || ss.Kind == "amneziawg" {
			writePeerGuard(&b, ss)
		}
	}
	for _, hook := range []string{"output", "forward"} {
		fmt.Fprintf(&b, "chain %s { type filter hook %s priority filter + 40; policy accept;\n", hook, hook)
		for _, ss := range sortedSessions(m.sessions) {
			if ss.Kind == "wireguard" || ss.Kind == "amneziawg" {
				fmt.Fprintf(&b, "oifname %s jump peer_%s\n", nftQ(ss.Interface), ss.Interface)
			}
		}
		if hook == "output" {
			fmt.Fprintln(&b, "jump source_download\noifname \"lo\" accept")
			for _, ss := range m.sessions {
				if !ss.Active {
					continue
				}
				for _, dns := range ss.DNSServers {
					a, e := netip.ParseAddr(dns)
					if e != nil || !routeAvailable(ss, netip.PrefixFrom(a, a.BitLen()).String()) {
						continue
					}
					for _, proto := range []string{"udp", "tcp"} {
						fmt.Fprintf(&b, "%s daddr %s %s dport 53 oifname %s accept\n", nftFamily(netip.PrefixFrom(a, a.BitLen())), a, proto, nftQ(ss.Interface))
					}
				}
			}
			if u.Device != "" {
				for _, ss := range m.sessions {
					for _, endpoint := range transportEndpoints(ss) {
						a, e := netip.ParseAddr(endpoint.Address)
						if e == nil {
							family := "ip"
							if a.Is6() {
								family = "ip6"
							}
							fmt.Fprintf(&b, "meta mark 0x%x %s daddr %s %s dport %d oifname %s accept\n", network.OuterMark, family, a, endpoint.Protocol, endpoint.Port, nftQ(u.Device))
						}
					}
				}
				for _, v := range []struct{ proto, port string }{{"udp", "53"}, {"tcp", "53"}, {"tcp", "443"}} {
					fmt.Fprintf(&b, "meta mark 0x%x ip daddr 1.1.1.1 %s dport %s oifname %s accept\n", network.BootstrapMark, v.proto, v.port, nftQ(u.Device))
				}
			}
		}

		if hook == "forward" {
			for _, lr := range network.LocalRoutes(s) {
				p, _ := lr.Prefix()
				fmt.Fprintf(&b, "iifname %s ct direction reply %s daddr %s oifname %s accept\n", nftQ(network.TunName), nftFamily(p), p, nftQ(lr.Device))
			}
			for _, ss := range m.sessions {
				for _, lr := range network.LocalRoutes(s) {
					p, _ := lr.Prefix()
					fmt.Fprintf(&b, "iifname %s ct direction reply %s daddr %s oifname %s accept\n", nftQ(ss.Interface), nftFamily(p), p, nftQ(lr.Device))
				}
			}
		}
		if u.Gateway != "" && u.Device != "" {
			fmt.Fprintf(&b, "ip daddr %s oifname %s udp dport {53,853} drop\nip daddr %s oifname %s tcp dport {53,853} drop\nip daddr %s oifname %s accept\n", u.Gateway, nftQ(u.Device), u.Gateway, nftQ(u.Device), u.Gateway, nftQ(u.Device))
		}
		var defaults []selected
		for _, r := range sel.routes {
			p, _ := netip.ParsePrefix(r.cidr)
			if p.Bits() == 0 {
				defaults = append(defaults, r)
				continue
			}
			if r.active {
				fmt.Fprintf(&b, "%s daddr %s oifname %s accept\n", nftFamily(p), p, nftQ(r.iface))
			}
			fmt.Fprintf(&b, "%s daddr %s drop\n", nftFamily(p), p)
		}
		if len(defaults) > 0 {
			for _, r := range defaults {
				p, _ := netip.ParsePrefix(r.cidr)
				if r.active {
					fmt.Fprintf(&b, "%s daddr %s oifname %s accept\n", nftFamily(p), p, nftQ(r.iface))
				}
			}
			fmt.Fprintln(&b, "udp dport {53,853} drop\ntcp dport {53,853} drop")
			for _, r := range network.LocalRoutes(s) {
				p, _ := r.Prefix()
				fmt.Fprintf(&b, "%s daddr %s oifname %s accept\n", nftFamily(p), p, nftQ(r.Device))
			}
			if hook == "output" {
				fmt.Fprintln(&b, "ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept\nip6 daddr { fe80::/10, ff02::/16 } icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept\nip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept")
			}
			for _, r := range defaults {
				p, _ := netip.ParsePrefix(r.cidr)
				if r.active {
					fmt.Fprintf(&b, "%s daddr %s oifname %s accept\n", nftFamily(p), p, nftQ(r.iface))
				}
				fmt.Fprintf(&b, "%s daddr %s drop\n", nftFamily(p), p)
			}
		}
		fmt.Fprintln(&b, "}")
	}
	fmt.Fprintln(&b, "}")
	return b.String() + "# vault443-work-source-elements\n"
}
func hasTable(ctx context.Context, k network.Kernel, name string) (bool, error) {
	b, e := k.Run(ctx, "/usr/sbin/nft", []string{"-j", "list", "tables"}, "")
	if e != nil {
		return false, e
	}
	var v struct {
		NFTables []struct {
			Table struct{ Family, Name string } `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal(b, &v) != nil {
		return false, errors.New("cannot inspect work firewall")
	}
	for _, x := range v.NFTables {
		if x.Table.Family == "inet" && x.Table.Name == name {
			return true, nil
		}
	}
	return false, nil
}
func ip(k network.Kernel, ctx context.Context, f int, args ...string) error {
	_, e := k.Run(ctx, "/usr/sbin/ip", append([]string{fmt.Sprintf("-%d", f)}, args...), "")
	return e
}
func ownedTable(t string) bool {
	n, _ := strconv.Atoi(t)
	return n >= underlayTable && n <= replyTable || n >= dnsTableStart && n <= dnsReverseTable
}
func removePolicy(ctx context.Context, k network.Kernel, s network.Snapshot) error {
	for i, rr := range [][]map[string]any{s.Rules4, s.Rules6} {
		f := 4
		if i == 1 {
			f = 6
		}
		for _, r := range rr {
			n, _ := r["priority"].(float64)
			if n < 5100 || n > 5202 {
				continue
			}
			table := fmt.Sprint(r["table"])
			if !ownedTable(table) {
				continue
			}
			if e := ip(k, ctx, f, "rule", "del", "priority", strconv.Itoa(int(n)), "table", table); e != nil {
				return e
			}
		}
	}
	for _, r := range s.Routes {
		if ownedTable(string(r.Table)) && string(r.Protocol) != "187" && string(r.Protocol) != "\"187\"" {
			return errors.New("work routing table contains foreign routes")
		}
	}
	for _, f := range []int{4, 6} {
		for _, t := range workTables() {
			if s.HasTable(f, t) {
				if e := ip(k, ctx, f, "route", "flush", "table", strconv.Itoa(t)); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func installRoute(ctx context.Context, k network.Kernel, t int, r selected) error {
	p, e := netip.ParsePrefix(r.cidr)
	if e != nil {
		return errors.New("invalid selected work route")
	}
	f := 4
	if p.Addr().Is6() {
		f = 6
	}
	args := []string{"route", "replace"}
	if !r.active {
		args = append(args, "unreachable", p.String())
	} else {
		args = append(args, p.String(), "dev", r.iface)
		if r.gateway != "" {
			args = append(args, "via", r.gateway, "onlink")
		}
	}
	args = append(args, "table", strconv.Itoa(t), "proto", workProtocol)
	return ip(k, ctx, f, args...)
}
func (m *Manager) applyLocked(ctx context.Context) error {
	return network.WithKernel(ctx, func(k network.Kernel) (result error) {
		s, e := k.Collect(ctx)
		if e != nil {
			return e
		}
		u, _ := s.Uplink()
		for _, ss := range m.sessions {
			if ss.Active {
				l, ok := s.Link(ss.Interface)
				if !ok || !sessionLinkMatches(ss, l) {
					ss.Active = false
					ss.PeerReady = map[string]bool{}
					m.lastPolicy = ""
					m.setStageLocked(ss.ID, "retry_wait", "retry_wait", "Work VPN interface disappeared; destinations remain protected")
				}
			}
		}
		for _, rr := range [][]map[string]any{s.Rules4, s.Rules6} {
			for _, r := range rr {
				n, _ := r["priority"].(float64)
				if len(m.sessions) > 0 && n >= 5100 && n <= 5202 && !ownedTable(fmt.Sprint(r["table"])) {
					return errors.New("work routing priority is occupied by another service")
				}
			}
		}
		sel := m.choose(s)
		defer func() {
			if result == nil {
				m.syncNMLocked(s, sel)
			}
		}()
		m.routeView = sel.rows
		if len(m.sessions) == 0 {
			m.routeView = nil
			if e = m.releaseKernel(ctx, k, s); e != nil {
				return e
			}
			m.lastPolicy = ""
			m.publishView()
			return m.persistLocked()
		}
		// Compute a stable plan key from actual link/route state relevant to the
		// policy, excluding owned work tables to avoid a netlink rewrite loop.
		keyInput := struct {
			Selection selection
			Sessions  []*session
			U         network.Route
			Local     []network.Route
		}{U: u, Local: network.LocalRoutes(s)}
		for _, v := range m.sessions {
			keyInput.Sessions = append(keyInput.Sessions, v)
		}
		sort.Slice(keyInput.Sessions, func(i, j int) bool { return keyInput.Sessions[i].ID < keyInput.Sessions[j].ID })
		raw, _ := json.Marshal(struct {
			Sessions []*session
			Rows     []RouteInfo
			U        network.Route
			Local    []network.Route
		}{keyInput.Sessions, sel.rows, u, keyInput.Local})
		key := fmt.Sprintf("%x", sha256.Sum256(raw))
		if m.lastPolicy == key && m.lastResources == workResourceKey(s) {
			m.publishView()
			return nil
		}
		exists, e := hasTable(ctx, k, workTable)
		if e != nil {
			return e
		}
		// Install fail-closed protection BEFORE any route is removed or replaced.
		if _, e = k.Run(ctx, "/usr/sbin/nft", []string{"-f", "-"}, m.guard(s, u, sel, exists)); e != nil {
			return errors.New("cannot install work VPN protection")
		}
		if e = m.persistLocked(); e != nil {
			return e
		}
		if e = removePolicy(ctx, k, s); e != nil {
			return e
		}
		// Own underlay is independent of VLESS: manual VLESS disconnect cannot
		// remove routes required by a still-running work VPN.
		for _, r := range network.LocalRoutes(s) {
			p, _ := r.Prefix()
			if e = installRoute(ctx, k, underlayTable, selected{cidr: p.String(), iface: r.Device, active: true}); e != nil {
				return e
			}
			if e = installRoute(ctx, k, replyTable, selected{cidr: p.String(), iface: r.Device, active: true}); e != nil {
				return e
			}
		}
		for _, f := range []int{4, 6} {
			def := "0.0.0.0/0"
			if f == 6 {
				def = "::/0"
			}
			r := selected{cidr: def}
			if f == 4 && u.Device != "" {
				r.iface = u.Device
				r.gateway = u.Gateway
				r.active = true
			}
			if f == 6 {
				for _, v := range s.Routes {
					p, ok := v.Prefix()
					if ok && p.Bits() == 0 && v.Family == 6 && v.Device == u.Device {
						r.iface = v.Device
						r.gateway = v.Gateway
						r.active = true
						break
					}
				}
			}
			if e = installRoute(ctx, k, underlayTable, r); e != nil {
				return e
			}
		}
		hasFull := false
		for _, r := range sel.routes {
			p, _ := netip.ParsePrefix(r.cidr)
			t := specificTable
			if p.Bits() == 0 {
				t = fullTable
				hasFull = true
			}
			if r.source == "manual" {
				t = manualTable
			}
			if e = installRoute(ctx, k, t, r); e != nil {
				return e
			}
		}
		if u.Gateway != "" {
			if g, err := netip.ParseAddr(u.Gateway); err == nil && g.Is4() {
				if e = installRoute(ctx, k, manualTable, selected{cidr: g.String() + "/32", iface: u.Device, active: true}); e != nil {
					return e
				}
			}
		}
		if hasFull {
			for _, r := range network.LocalRoutes(s) {
				p, _ := r.Prefix()
				if e = installRoute(ctx, k, fullTable, selected{cidr: p.String(), iface: r.Device, active: true}); e != nil {
					return e
				}
			}
		}
		for _, f := range []int{4, 6} {
			rules := [][]string{{"priority", "5100", "fwmark", fmt.Sprintf("0x%x", network.OuterMark), "lookup", strconv.Itoa(underlayTable)}, {"priority", "5101", "fwmark", fmt.Sprintf("0x%x", network.BootstrapMark), "lookup", strconv.Itoa(underlayTable)}}
			priority := 5102
			for _, v := range []struct{ a, p, proto string }{{"1.1.1.1", "53", "udp"}, {"1.1.1.1", "53", "tcp"}, {"1.1.1.1", "443", "tcp"}} {
				if f == 4 {
					rules = append(rules, []string{"priority", strconv.Itoa(priority), "uidrange", "0-0", "to", v.a, "ipproto", v.proto, "dport", v.p, "lookup", strconv.Itoa(underlayTable)})
					priority++
				}
			}
			seenTransport := map[string]bool{}
			for _, ss := range keyInput.Sessions {
				for _, ep := range transportEndpoints(ss) {
					a, er := netip.ParseAddr(ep.Address)
					if er != nil || a.Is4() != (f == 4) {
						continue
					}
					identity := fmt.Sprintf("%s/%s/%d", a, ep.Protocol, ep.Port)
					if seenTransport[identity] {
						continue
					}
					seenTransport[identity] = true
					rules = append(rules, []string{"priority", strconv.Itoa(priority), "uidrange", "0-0", "to", a.String(), "ipproto", ep.Protocol, "dport", strconv.Itoa(ep.Port), "lookup", strconv.Itoa(underlayTable)})
				}
			}
			for _, ss := range keyInput.Sessions {
				if _, present := s.Link(ss.Interface); present {
					rules = append(rules, []string{"priority", "5199", "iif", ss.Interface, "lookup", strconv.Itoa(replyTable)})
				}
			}
			// Main TUN replies to forwarded LAN clients must not be diverted
			// into overlapping corporate routes. This table contains only LANs.
			rules = append(rules, []string{"priority", "5199", "iif", network.TunName, "lookup", strconv.Itoa(replyTable)})
			for _, pair := range [][2]int{{5200, manualTable}, {5201, specificTable}, {5202, fullTable}} {
				rules = append(rules, []string{"priority", strconv.Itoa(pair[0]), "lookup", strconv.Itoa(pair[1])})
			}
			for _, r := range rules {
				if e = ip(k, ctx, f, append([]string{"rule", "add"}, r...)...); e != nil {
					return e
				}
			}
		}
		if e = installDNSPolicy(ctx, k, s, keyInput.Sessions); e != nil {
			return e
		}
		policy := network.ManagedPolicy{Uplink: u.Device}
		for _, ss := range keyInput.Sessions {
			t := network.ManagedTunnel{ID: ss.ID, Interface: ss.Interface, Kind: ss.Kind, Endpoints: transportEndpoints(ss), Active: ss.Active}
			for _, r := range sel.routes {
				p, _ := netip.ParsePrefix(r.cidr)
				if r.target == ss.ID && p.Bits() == 0 {
					if p.Addr().Is4() {
						t.Full4 = true
					} else {
						t.Full6 = true
					}
				}
			}
			policy.Tunnels = append(policy.Tunnels, t)
			if ss.Active {
				for _, dns := range ss.DNSServers {
					a, e := netip.ParseAddr(dns)
					if e == nil && routeAvailable(ss, netip.PrefixFrom(a, a.BitLen()).String()) {
						policy.Routes = append(policy.Routes, network.ManagedRoute{CIDR: netip.PrefixFrom(a, a.BitLen()).String(), Interface: ss.Interface, DNSOnly: true})
					}
				}
			}
		}
		for _, r := range sel.routes {
			if r.active {
				policy.Routes = append(policy.Routes, network.ManagedRoute{CIDR: r.cidr, Interface: r.iface})
			}
		}
		if e = k.PublishManaged(ctx, policy); e != nil {
			return e
		}
		for _, ss := range keyInput.Sessions {
			if _, present := s.Link(ss.Interface); !present {
				continue
			}
			var domains []string
			for d, id := range sel.dns {
				if id == ss.ID {
					domains = append(domains, "~"+d)
				}
			}
			sort.Strings(domains)
			if len(domains) > 0 && len(ss.DNSServers) > 0 {
				for _, args := range [][]string{append([]string{"dns", ss.Interface}, ss.DNSServers...), append([]string{"domain", ss.Interface}, domains...), {"default-route", ss.Interface, "no"}} {
					if _, e = k.Run(ctx, "/usr/bin/resolvectl", args, ""); e != nil {
						return errors.New("cannot configure work split DNS")
					}
				}
			} else {
				if _, e = k.Run(ctx, "/usr/bin/resolvectl", []string{"revert", ss.Interface}, ""); e != nil {
					return errors.New("cannot clear obsolete work DNS")
				}
			}
			if ss.Status.State == "connected" || ss.Status.State == "conflict" || ss.Status.State == "partial" {
				if sel.conflict[ss.ID] {
					ss.Status.State = "conflict"
					ss.Status.Stage = "route_conflict"
					ss.Status.Message = "Choose the work route owner in Routes"
				} else {
					ss.Status.State = "connected"
					ss.Status.Stage = "connected"
					ss.Status.Message = "Connected"
					if ss.Kind != "" && ss.Kind != "openvpn" && !allPeersReady(ss) {
						ss.Status.State = "partial"
						ss.Status.Stage = "partial"
						ss.Status.Message = "Some peers are unavailable; their routes remain protected"
					}
				}
				if ss.callback != nil {
					ss.callback(copyStatus(ss.Status))
				}
			}
		}
		observed, observeErr := k.Collect(ctx)
		if observeErr != nil {
			return errors.New("cannot verify installed work routes")
		}
		m.lastResources = workResourceKey(observed)
		m.lastPolicy = key
		m.publishView()
		return nil
	})
}
func (m *Manager) releaseKernel(ctx context.Context, k network.Kernel, s network.Snapshot) error {
	if e := removePolicy(ctx, k, s); e != nil {
		return e
	}
	if e := k.PublishManaged(ctx, network.ManagedPolicy{}); e != nil {
		return e
	}
	exists, e := hasTable(ctx, k, workTable)
	if e != nil {
		return e
	}
	if exists {
		_, e = k.Run(ctx, "/usr/sbin/nft", []string{"delete", "table", "inet", workTable}, "")
	}
	return e
}
func (m *Manager) setStageLocked(id, state, stage, message string) {
	ss := m.sessions[id]
	if ss == nil {
		return
	}
	ss.Status.State = state
	ss.Status.Stage = stage
	ss.Status.Message = message
	ss.Status.StageStartedAt = time.Now().UnixMilli()
	m.publishView()
	if ss.callback != nil {
		ss.callback(copyStatus(ss.Status))
	}
	ss.log.Log("info", message)
}

func workResourceKey(s network.Snapshot) string {
	var lines []string
	for _, r := range s.Routes {
		if ownedTable(string(r.Table)) {
			b, _ := json.Marshal(r)
			lines = append(lines, fmt.Sprintf("%d:%s", r.Family, b))
		}
	}
	for i, rr := range [][]map[string]any{s.Rules4, s.Rules6} {
		for _, r := range rr {
			if ownedTable(fmt.Sprint(r["table"])) {
				b, _ := json.Marshal(r)
				lines = append(lines, fmt.Sprintf("rule%d:%s", i, b))
			}
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
