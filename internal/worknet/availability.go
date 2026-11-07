package worknet

import (
	"net/netip"
	"vault443/internal/workvpn"
)

type route struct {
	CIDR    string `json:"cidr"`
	Gateway string `json:"gateway,omitempty"`
}

func copyStatus(s Status) Status {
	s.Peers = append([]PeerStatus(nil), s.Peers...)
	for i := range s.Peers {
		s.Peers[i].AllowedIPs = append([]string(nil), s.Peers[i].AllowedIPs...)
	}
	s.Routes = append([]string(nil), s.Routes...)
	s.DNSServers = append([]string(nil), s.DNSServers...)
	s.DNSDomains = append([]string(nil), s.DNSDomains...)
	return s
}
func routeSource(s *session) string {
	if s.Kind == "wireguard" || s.Kind == "amneziawg" {
		return s.Kind
	}
	return "server"
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
