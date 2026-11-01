package worknet

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"vault443/internal/network"
	"vault443/internal/workvpn"
)

func transportEndpoints(s *session) []network.Endpoint {
	if len(s.Endpoints) > 0 {
		return s.Endpoints
	}
	if s.Endpoint.Address != "" {
		return []network.Endpoint{s.Endpoint}
	}
	return nil
}
func routeSource(s *session) string {
	if s.Kind == "wireguard" || s.Kind == "amneziawg" {
		return s.Kind
	}
	return "server"
}
func sessionLinkMatches(s *session, l network.Link) bool {
	kind := "tun"
	if s.Kind == "wireguard" {
		kind = "wireguard"
	}
	if l.Kind != kind {
		return false
	}
	if s.Kind == "wireguard" || s.Kind == "amneziawg" {
		return l.Alias == "vault443:"+s.ID
	}
	return true
}
func allPeersReady(s *session) bool {
	for id := range s.PeerPrefixes {
		if !s.PeerReady[id] {
			return false
		}
	}
	return true
}

// A wider explicit rule must not revive an unavailable more-specific peer.
// OpenVPN has one availability flag; WG cryptokey routes additionally select
// their most specific peer. No missing prefix is implicitly added to AllowedIPs.
func routeAvailable(s *session, cidr string) bool {
	if !s.Active {
		return false
	}
	if s.Kind != "wireguard" && s.Kind != "amneziawg" {
		return true
	}
	p, e := netip.ParsePrefix(cidr)
	if e != nil {
		return false
	}
	best := -1
	ready := false
	for id, prefixes := range s.PeerPrefixes {
		for _, v := range prefixes {
			q, e := netip.ParsePrefix(v)
			if e != nil {
				continue
			}
			if q.Bits() <= p.Bits() && q.Contains(p.Addr()) && q.Bits() > best {
				best = q.Bits()
				ready = s.PeerReady[id]
			}
		}
	}
	if !ready {
		// Two different peers can cover the two halves of a default route.
		// The synthetic default only supplies full-tunnel policy metadata;
		// more-specific per-peer routes still control forwarding.
		if best < 0 && p.Bits() == 0 && allPeersReady(s) {
			var rr []route
			for _, prefixes := range s.PeerPrefixes {
				for _, prefix := range prefixes {
					q, _ := netip.ParsePrefix(prefix)
					if q.Addr().Is4() == p.Addr().Is4() {
						rr = append(rr, route{prefix, ""})
					}
				}
			}
			return isFull(rr)
		}
		return false
	}

	return true
}
func dnsAvailable(s *session) bool {
	if !s.Active {
		return false
	}
	for _, v := range s.DNSServers {
		a, e := netip.ParseAddr(v)
		if e == nil && routeAvailable(s, netip.PrefixFrom(a, a.BitLen()).String()) {
			return true
		}
	}
	return len(s.DNSServers) == 0
}

func sessionRoutes(s *session) []route {
	if s.Kind != "wireguard" && s.Kind != "amneziawg" {
		return normalizeRoutes(s.Routes)
	}
	out := append([]route(nil), s.Routes...)
	for _, family := range []bool{true, false} {
		var group []route
		hasDefault := false
		for _, r := range out {
			p, e := netip.ParsePrefix(r.CIDR)
			if e == nil && p.Addr().Is4() == family {
				group = append(group, r)
				hasDefault = hasDefault || p.Bits() == 0
			}
		}
		if !hasDefault && isFull(group) {
			prefix := "::/0"
			if family {
				prefix = "0.0.0.0/0"
			}
			out = append(out, route{prefix, ""})
		}
	}
	return out
}
func routeAllowed(s *session, cidr string) bool {
	if s.Kind != "wireguard" && s.Kind != "amneziawg" {
		return true
	}
	w := &workvpn.WireGuardConfig{}
	for _, prefixes := range s.PeerPrefixes {
		w.Peers = append(w.Peers, workvpn.WireGuardPeer{AllowedIPs: prefixes})
	}
	return (workvpn.Profile{Kind: s.Kind, WireGuard: w}).AllowsPrefix(cidr)
}

func sortedSessions(sessions map[string]*session) []*session {
	var out []*session
	for _, s := range sessions {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// A per-interface chain implements the same longest-prefix rule as WireGuard.
// A healthy narrow peer returns to normal policy before an offline broad peer;
// an offline narrow peer drops before a broad manual route can accept it.
func writePeerGuard(b *strings.Builder, s *session) {
	type entry struct {
		prefix netip.Prefix
		ready  bool
	}
	var entries []entry
	for id, prefixes := range s.PeerPrefixes {
		for _, raw := range prefixes {
			p, e := netip.ParsePrefix(raw)
			if e == nil {
				entries = append(entries, entry{p, s.Active && s.PeerReady[id]})
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].prefix.Bits() != entries[j].prefix.Bits() {
			return entries[i].prefix.Bits() > entries[j].prefix.Bits()
		}
		return entries[i].prefix.String() < entries[j].prefix.String()
	})
	fmt.Fprintf(b, "chain peer_%s {\n", s.Interface)
	for _, e := range entries {
		action := "drop"
		if e.ready {
			action = "return"
		}
		fmt.Fprintf(b, "%s daddr %s %s\n", nftFamily(e.prefix), e.prefix, action)
	}
	fmt.Fprintln(b, "}")
}
