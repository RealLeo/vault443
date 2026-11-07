package worknet

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
	"vault443/internal/network"
	"vault443/internal/workvpn"
)

type selected struct {
	cidr, target, iface, gateway, source string
	active                               bool
	local                                bool
}
type selection struct {
	routes      []selected
	rows        []RouteInfo
	dns         map[string]string
	dnsConflict map[string]bool
	conflict    map[string]bool
}

func isFull(r []route) bool {
	low4, high4, low6, high6 := false, false, false, false
	for _, r := range r {
		p, e := netip.ParsePrefix(r.CIDR)
		if e != nil {
			continue
		}
		if p.Bits() == 0 {
			return true
		}
		if p.Bits() == 1 {
			if p.Addr().Is4() {
				if p.Addr().As4()[0] == 0 {
					low4 = true
				} else {
					high4 = true
				}
			} else {
				if p.Addr().As16()[0] == 0 {
					low6 = true
				} else {
					high6 = true
				}
			}
		}
	}
	return low4 && high4 || low6 && high6
}
func normalizeRoutes(rr []route) []route {
	var out []route
	for _, family := range []int{4, 6} {
		var low, high *route
		full := "0.0.0.0/0"
		if family == 6 {
			full = "::/0"
		}
		for i := range rr {
			p, e := netip.ParsePrefix(rr[i].CIDR)
			if e != nil || p.Addr().Is4() != (family == 4) {
				continue
			}
			if p.Bits() == 1 {
				if p.Addr().IsUnspecified() {
					low = &rr[i]
				} else {
					high = &rr[i]
				}
			}
		}
		for _, r := range rr {
			p, e := netip.ParsePrefix(r.CIDR)
			if e != nil || p.Addr().Is4() != (family == 4) {
				continue
			}
			if low != nil && high != nil && p.Bits() == 1 {
				continue
			}
			out = append(out, r)
		}
		if low != nil && high != nil {
			out = append(out, route{full, low.Gateway})
		}
	}
	seen := map[string]bool{}
	var unique []route
	for _, r := range out {
		if !seen[r.CIDR] {
			unique = append(unique, r)
			seen[r.CIDR] = true
		}
	}
	return unique
}
func localFor(s network.Snapshot, cidr string) (network.Route, bool) {
	p, e := netip.ParsePrefix(cidr)
	if e != nil {
		return network.Route{}, false
	}
	best := -1
	var found network.Route
	for _, r := range network.LocalRoutes(s) {
		q, ok := r.Prefix()
		if ok && q.Contains(p.Addr()) && q.Bits() <= p.Bits() && q.Bits() > best {
			best = q.Bits()
			found = r
		}
	}
	return found, best >= 0
}
func validateLocalRules(s network.Snapshot, rules []workvpn.RouteRule) error {
	for _, r := range rules {
		if r.Target == "local" {
			if _, ok := localFor(s, r.CIDR); !ok {
				return errors.New("local route must be contained in an existing connected network")
			}
		}
	}
	return nil
}
func (m *Manager) choose(s network.Snapshot) selection {
	out := selection{dns: map[string]string{}, dnsConflict: map[string]bool{}, conflict: map[string]bool{}}
	list := make([]*session, 0, len(m.sessions))
	for _, v := range m.sessions {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Order < list[j].Order })
	winners := map[string]selected{}
	counts := map[string]int{}
	for _, v := range list {
		for _, r := range sessionRoutes(v) {
			counts[r.CIDR]++
			if _, ok := winners[r.CIDR]; !ok {
				winners[r.CIDR] = selected{r.CIDR, v.ID, v.Interface, r.Gateway, routeSource(v), routeAvailable(v, r.CIDR), false}
			}
		}
	}
	// User rules are a separate policy table, so a less-specific work route can
	// intentionally override a more-specific connected Docker route.
	explicit := map[string]bool{}
	manualOrigin := map[string]int{}
	for _, r := range m.rules {
		explicit[r.CIDR] = true
	}
	for _, r := range m.rules {
		if r.Target != "local" && m.sessions[r.Target] == nil {
			continue
		}
		v := selected{cidr: r.CIDR, target: r.Target, source: "manual"}
		if r.Target == "local" {
			v.local = true
			if lr, ok := localFor(s, r.CIDR); ok {
				v.iface = lr.Device
				v.active = true
			}
		} else {
			ss := m.sessions[r.Target]
			v.iface = ss.Interface
			v.active = routeAvailable(ss, r.CIDR)
			if ss.Kind == "wireguard" || ss.Kind == "amneziawg" {
				parent, _ := netip.ParsePrefix(r.CIDR)
				for _, child := range sessionRoutes(ss) {
					q, e := netip.ParsePrefix(child.CIDR)
					if e != nil || explicit[child.CIDR] || q.Bits() <= parent.Bits() || !parent.Contains(q.Addr()) {
						continue
					}
					previous, exists := manualOrigin[child.CIDR]
					if !exists || parent.Bits() > previous {
						manualOrigin[child.CIDR] = parent.Bits()
						winners[child.CIDR] = selected{cidr: child.CIDR, target: ss.ID, iface: ss.Interface, source: "manual", active: routeAvailable(ss, child.CIDR)}
					}
				}
			}
		}
		winners[r.CIDR] = v
	}
	for _, v := range list {
		for _, r := range sessionRoutes(v) {
			w := winners[r.CIDR]
			conflict := counts[r.CIDR] > 1 && w.source != "manual"
			state := "active"
			message := ""
			if !routeAvailable(v, r.CIDR) {
				state = "protected"
			}
			if w.target != v.ID {
				state = "overridden"
			}
			if conflict {
				state = "conflict"
				message = "Several work VPNs claim the same route; select a target"
				if w.target != v.ID {
					out.conflict[v.ID] = true
				}
			}
			out.rows = append(out.rows, RouteInfo{CIDR: r.CIDR, Source: routeSource(v), Target: v.ID, TargetName: v.Name, Interface: v.Interface, State: state, Message: message, Conflict: conflict})
		}
	}
	for _, v := range winners {
		out.routes = append(out.routes, v)
		if v.source == "manual" {
			state := "active"
			if !v.active {
				state = "protected"
			}
			name := v.target
			if p := m.sessions[v.target]; p != nil {
				name = p.Name
			}
			out.rows = append(out.rows, RouteInfo{CIDR: v.cidr, Source: "manual", Target: v.target, TargetName: name, Interface: v.iface, State: state})
		}
	}
	// Without an explicit choice, an already running external full tunnel keeps
	// ownership. Merely connecting another profile must never replace it.
	externalFull := map[string]bool{}
	for i := range out.routes {
		r := &out.routes[i]
		p, _ := netip.ParsePrefix(r.cidr)
		if p.Bits() != 0 || r.source == "manual" {
			continue
		}
		for _, ext := range s.Routes {
			q, ok := ext.Prefix()
			if !ok || q.Bits() > 1 || q.Addr().Is4() != p.Addr().Is4() || ext.Device == "" || ext.Device == network.TunName || strings.HasPrefix(ext.Device, "v443w") {
				continue
			}
			l, ok := s.Link(ext.Device)
			if ok && (l.Kind == "tun" || l.Kind == "wireguard") {
				r.active = false
				externalFull[r.cidr] = true
				out.conflict[r.target] = true
				out.rows = append(out.rows, RouteInfo{CIDR: r.cidr, Source: "external", Target: r.target, Interface: ext.Device, State: "conflict", Conflict: true, Message: "Another VPN owns Internet routing; choose its owner explicitly"})
				break
			}
		}
	}
	kept := out.routes[:0]
	for _, r := range out.routes {
		if !externalFull[r.cidr] {
			kept = append(kept, r)
		}
	}
	out.routes = kept
	// A full work tunnel must not expose the other address family directly
	// when VLESS is absent or paused. LAN/control traffic remains link-scoped.
	full4, full6 := false, false
	for _, r := range out.routes {
		p, _ := netip.ParsePrefix(r.cidr)
		if p.Bits() == 0 {
			if p.Addr().Is4() {
				full4 = true
			} else {
				full6 = true
			}
		}
	}
	if full4 && !full6 {
		out.routes = append(out.routes, selected{cidr: "::/0", source: "policy", target: "unavailable-family"})
	}
	if full6 && !full4 {
		out.routes = append(out.routes, selected{cidr: "0.0.0.0/0", source: "policy", target: "unavailable-family"})
	}
	sort.Slice(out.routes, func(i, j int) bool {
		a, _ := netip.ParsePrefix(out.routes[i].cidr)
		b, _ := netip.ParsePrefix(out.routes[j].cidr)
		if out.routes[i].source != out.routes[j].source {
			return out.routes[i].source == "manual"
		}
		if a.Bits() != b.Bits() {
			return a.Bits() > b.Bits()
		}
		return out.routes[i].cidr < out.routes[j].cidr
	})
	dnsCounts := map[string]int{}
	for _, v := range list {
		domains := append([]string(nil), v.DNSDomains...)
		if isFull(v.Routes) && len(v.DNSServers) > 0 {
			domains = append(domains, ".")
		}
		seenDomain := map[string]bool{}
		for _, d := range domains {
			if seenDomain[d] {
				continue
			}
			seenDomain[d] = true
			dnsCounts[d]++
			if out.dns[d] == "" {
				out.dns[d] = v.ID
			}
		}
	}
	fullOwners := map[string]bool{}
	for _, r := range out.routes {
		p, _ := netip.ParsePrefix(r.cidr)
		if p.Bits() == 0 && m.sessions[r.target] != nil {
			fullOwners[r.target] = true
		}
	}
	if len(fullOwners) == 1 {
		for id := range fullOwners {
			if len(m.sessions[id].DNSServers) > 0 {
				out.dns["."] = id
				dnsCounts["."] = 1
			}
		}
	}
	for _, r := range m.dnsRules {
		if m.sessions[r.Target] != nil {
			out.dns[r.Domain] = r.Target
			dnsCounts[r.Domain] = 1
		}
	}
	for d, id := range out.dns {
		v := m.sessions[id]
		conflict := dnsCounts[d] > 1
		out.dnsConflict[d] = conflict
		state := "active"
		if !dnsAvailable(v) {
			state = "protected"
		}
		if conflict {
			state = "conflict"
		}
		out.rows = append(out.rows, RouteInfo{Domain: d, Source: "dns", Target: id, TargetName: v.Name, Interface: v.Interface, State: state, Conflict: conflict, Message: map[bool]string{true: "Several work VPNs claim this DNS zone; select a target"}[conflict]})
	}
	for _, r := range network.LocalRoutes(s) {
		p, _ := r.Prefix()
		conflict := false
		for _, w := range out.routes {
			q, _ := netip.ParsePrefix(w.cidr)
			if !w.local && q.Bits() > 0 && p.Overlaps(q) {
				conflict = true
			}
		}
		out.rows = append(out.rows, RouteInfo{CIDR: p.String(), Source: "local", Target: "local", TargetName: r.Device, Interface: r.Device, State: "available", Conflict: conflict, Message: map[bool]string{true: "Work VPN routes take priority over this local network"}[conflict]})
	}
	sort.SliceStable(out.rows, func(i, j int) bool {
		if out.rows[i].Source != out.rows[j].Source {
			return out.rows[i].Source < out.rows[j].Source
		}
		if out.rows[i].CIDR != out.rows[j].CIDR {
			return out.rows[i].CIDR < out.rows[j].CIDR
		}
		return out.rows[i].Domain < out.rows[j].Domain
	})
	return out
}
