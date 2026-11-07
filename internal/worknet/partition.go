package worknet

import (
	"go4.org/netipx"
	"net/netip"
	"sort"
	"vault443/internal/network"
)

// Disjoint route ranges give manual policy precedence without changing foreign
// routes. Extra specific entries override connected LAN/container routes.
func effectiveWindowsRoutes(sel selection, observed network.Snapshot) []selected {
	ordered := append([]selected(nil), sel.routes...)
	full := false
	for _, r := range ordered {
		p, _ := netip.ParsePrefix(r.cidr)
		full = full || p.Bits() == 0
	}
	if full {
		for _, r := range network.LocalRoutes(observed) {
			p, _ := r.Prefix()
			ordered = append(ordered, selected{cidr: p.String(), target: "local", iface: r.Device, source: "local", local: true, active: true})
		}
	}
	priority := func(r selected) int {
		if r.source == "manual" {
			return 0
		}
		if r.local {
			return 2
		}
		p, _ := netip.ParsePrefix(r.cidr)
		if p.Bits() == 0 {
			return 3
		}
		return 1
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		pa, _ := netip.ParsePrefix(a.cidr)
		pb, _ := netip.ParsePrefix(b.cidr)
		if priority(a) != priority(b) {
			return priority(a) < priority(b)
		}
		if pa.Bits() != pb.Bits() {
			return pa.Bits() > pb.Bits()
		}
		if a.cidr != b.cidr {
			return a.cidr < b.cidr
		}
		return a.target < b.target
	})
	var covered []netip.Prefix
	var out []selected
	for _, r := range ordered {
		p, err := netip.ParsePrefix(r.cidr)
		if err != nil {
			continue
		}
		var builder netipx.IPSetBuilder
		builder.AddPrefix(p)
		for _, c := range covered {
			builder.RemovePrefix(c)
		}
		set, err := builder.IPSet()
		if err != nil {
			continue
		}
		for _, q := range set.Prefixes() {
			v := r
			v.cidr = q.String()
			out = append(out, v)
		}
		covered = append(covered, p)
	}
	return out
}
func splitPrefix(p netip.Prefix) []netip.Prefix {
	if p.Bits() == p.Addr().BitLen() {
		return []netip.Prefix{p}
	}
	first := netip.PrefixFrom(p.Masked().Addr(), p.Bits()+1)
	last := netipx.PrefixLastIP(first).Next()
	return []netip.Prefix{first, netip.PrefixFrom(last, p.Bits()+1)}
}
