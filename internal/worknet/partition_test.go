package worknet

import (
	"net/netip"
	"testing"
	"vault443/internal/network"
)

func partitionTarget(t *testing.T, rows []selected, text string) (string, bool) {
	t.Helper()
	ip := netip.MustParseAddr(text)
	target := ""
	active := false
	matches := 0
	for _, r := range rows {
		p, err := netip.ParsePrefix(r.cidr)
		if err != nil {
			t.Fatal(err)
		}
		if p.Contains(ip) {
			target, active = r.target, r.active
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("%s matched %d disjoint routes", text, matches)
	}
	return target, active
}
func TestWindowsPartitionPreservesManualPrecedenceAndOfflinePeer(t *testing.T) {
	rows := effectiveWindowsRoutes(selection{routes: []selected{
		{cidr: "10.0.0.0/8", target: "manual", source: "manual", active: true},
		{cidr: "10.20.0.0/16", target: "manual", source: "manual", active: false},
		{cidr: "10.30.0.0/16", target: "automatic", source: "wireguard", active: true},
	}}, network.Snapshot{})
	if target, active := partitionTarget(t, rows, "10.20.1.1"); target != "manual" || active {
		t.Fatalf("offline narrow peer escaped protection: %s %v", target, active)
	}
	if target, active := partitionTarget(t, rows, "10.30.1.1"); target != "manual" || !active {
		t.Fatalf("automatic narrow route defeated manual policy: %s %v", target, active)
	}
	for i, a := range rows {
		p := netip.MustParsePrefix(a.cidr)
		for _, b := range rows[i+1:] {
			if p.Overlaps(netip.MustParsePrefix(b.cidr)) {
				t.Fatal("partition produced overlapping forwarding choices")
			}
		}
	}
}
func TestWindowsPartitionKeepsLocalBeforeFullAndSpecificBeforeLocal(t *testing.T) {
	snapshot := network.Snapshot{Links: []network.Link{{Name: "docker0", Index: 7, Kind: "bridge"}}, Routes: []network.Route{{Destination: "172.18.0.0/16", Device: "docker0", Scope: "link", Family: 4}}}
	// Windows connected-route observations additionally verify assigned subnets.
	snapshot.Links[0].Addresses = append(snapshot.Links[0].Addresses, struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Family    string `json:"family"`
	}{"172.18.0.1", 16, "inet"})
	rows := effectiveWindowsRoutes(selection{routes: []selected{
		{cidr: "0.0.0.0/0", target: "full", source: "wireguard", active: true},
		{cidr: "172.18.40.0/24", target: "corporate", source: "wireguard", active: true},
	}}, snapshot)
	for _, check := range []struct{ ip, target string }{{"8.8.8.8", "full"}, {"172.18.2.2", "local"}, {"172.18.40.4", "corporate"}} {
		if target, active := partitionTarget(t, rows, check.ip); target != check.target || !active {
			t.Fatalf("%s selected %s active=%v", check.ip, target, active)
		}
	}
}
func TestSplitPrefixCoversIPv4AndIPv6WithoutExpansion(t *testing.T) {
	for _, text := range []string{"0.0.0.0/0", "10.1.0.0/24", "10.1.2.3/32", "::/0", "2001:db8::/64", "2001:db8::1/128"} {
		p := netip.MustParsePrefix(text)
		parts := splitPrefix(p)
		if len(parts) < 1 || len(parts) > 2 {
			t.Fatal("unexpected split")
		}
		for _, q := range parts {
			if !p.Contains(q.Addr()) || q.Bits() < p.Bits() {
				t.Fatal("route expansion outside authorized range")
			}
		}
		if len(parts) == 2 && parts[0].Overlaps(parts[1]) {
			t.Fatal("split halves overlap")
		}
	}
}
