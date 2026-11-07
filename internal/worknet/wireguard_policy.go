//go:build linux

package worknet

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"vault443/internal/network"
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
