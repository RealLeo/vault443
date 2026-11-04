package worknet

import (
	"net/netip"
	"sort"
	"vault443/internal/network"
)

// Called with the work metadata lock, after a successful policy transaction.
// Update just copies intent. No D-Bus call takes either this lock or Kernel's.
func (m *Manager) syncNMLocked(s network.Snapshot, sel selection) {
	m.nmSync.Update(m.nmTargets(s, sel))
}

func (m *Manager) nmTargets(s network.Snapshot, sel selection) []network.NMTunnel {
	var targets []network.NMTunnel
	for _, ss := range m.sessions {
		if ss.Kind != "" && ss.Kind != "openvpn" {
			continue
		}
		link, ok := s.Link(ss.Interface)
		if !ok || !sessionLinkMatches(ss, link) {
			continue
		}
		t := network.NMTunnel{ID: ss.ID, Interface: ss.Interface, Index: link.Index, Attempt: ss.Attempt,
			DNS: append([]string(nil), ss.DNSServers...)}
		// A full route learned from authenticated OpenVPN events supplies the actual
		// peer. Never guess local+1 (valid only for our synthetic main Xray subnet).
		for _, r := range ss.Routes {
			if r.CIDR == "0.0.0.0/0" {
				t.Gateway, _ = netip.ParseAddr(r.Gateway)
				break
			}
		}
		for _, a := range link.Addresses {
			p, e := netip.ParseAddr(a.Local)
			if e == nil && p.Is4() {
				t.Address = netip.PrefixFrom(p, a.PrefixLen)
				break
			}
		}
		if !t.Address.IsValid() {
			continue
		}
		for domain, id := range sel.dns {
			if id == ss.ID {
				t.Domains = append(t.Domains, "~"+domain)
			}
		}
		sort.Strings(t.Domains)
		if len(t.Domains) == 0 {
			t.DNS = nil
		}
		for _, r := range sel.routes {
			if r.cidr == "0.0.0.0/0" && r.target == ss.ID && r.active && ss.Active &&
				(ss.Status.State == "connected" || ss.Status.State == "conflict") && ss.nmIndex == link.Index && ss.nmAddress == t.Address.String() {
				t.Enabled = true
			}
		}
		targets = append(targets, t)
	}
	return targets
}
