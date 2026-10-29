package worknet

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"vault443/internal/network"
	"vault443/internal/workvpn"
)

func fixtureSnapshot() network.Snapshot {
	var s network.Snapshot
	s.Links = []network.Link{{Name: "eth0", Kind: "ether"}, {Name: "docker0", Kind: "bridge"}, {Name: "v443w00000001", Kind: "tun"}, {Name: "v443w00000002", Kind: "tun"}}
	s.Routes = []network.Route{{Destination: "default", Gateway: "192.0.2.1", Device: "eth0", Family: 4}, {Destination: "192.168.96.0/20", Device: "docker0", Scope: "link", Family: 4}, {Destination: "192.0.2.0/24", Device: "eth0", Scope: "link", Family: 4}}
	return s
}
func fixtureManager() *Manager {
	m := New(Config{}, nil)
	m.sessions["a"] = &session{ID: "a", Name: "Work A", Interface: "v443w00000001", Active: true, Order: 1, Routes: []route{{"192.168.0.0/16", "10.70.0.1"}}, DNSServers: []string{"10.70.0.1"}, DNSDomains: []string{"corp.test"}}
	m.sessions["b"] = &session{ID: "b", Name: "Work B", Interface: "v443w00000002", Active: true, Order: 2, Routes: []route{{"10.42.0.0/24", "10.71.0.1"}}, DNSServers: []string{"10.71.0.1"}, DNSDomains: []string{"corp.test"}}
	return m
}
func TestWorkWinsOverMoreSpecificDocker(t *testing.T) {
	m := fixtureManager()
	s := fixtureSnapshot()
	p := m.choose(s)
	if len(p.routes) != 2 {
		t.Fatalf("%+v", p.routes)
	}
	u, _ := s.Uplink()
	script := m.guard(s, u, p, false)
	work := strings.Index(script, "ip daddr 192.168.0.0/16 oifname \"v443w00000001\" accept")
	drop := strings.Index(script, "ip daddr 192.168.0.0/16 drop")
	if work < 0 || drop < work {
		t.Fatal(script)
	}
	conflict := false
	for _, r := range p.rows {
		if r.Source == "local" && r.CIDR == "192.168.96.0/20" && r.Conflict {
			conflict = true
		}
	}
	if !conflict {
		t.Fatal("overlap hidden")
	}
}
func TestExplicitLocalOverridesWorkButCannotBypassInternet(t *testing.T) {
	m := fixtureManager()
	m.rules = []workvpn.RouteRule{{CIDR: "192.168.100.15/32", Target: "local"}, {CIDR: "8.8.8.8/32", Target: "local"}}
	p := m.choose(fixtureSnapshot())
	if p.routes[0].source != "manual" {
		t.Fatal("manual rules not first")
	}
	for _, r := range p.routes {
		if r.cidr == "192.168.100.15/32" && (!r.active || r.iface != "docker0") {
			t.Fatal(r)
		}
		if r.cidr == "8.8.8.8/32" && r.active {
			t.Fatal("physical Internet bypass granted")
		}
	}
}
func TestExactConflictRetainsFirstAndExplicitChoiceWins(t *testing.T) {
	m := fixtureManager()
	m.sessions["b"].Routes = []route{{"192.168.0.0/16", "10.71.0.1"}}
	p := m.choose(fixtureSnapshot())
	if p.routes[0].target != "a" || !p.conflict["b"] {
		t.Fatalf("%+v", p)
	}
	m.rules = []workvpn.RouteRule{{CIDR: "192.168.0.0/16", Target: "b"}}
	p = m.choose(fixtureSnapshot())
	if p.routes[0].target != "b" || p.conflict["b"] {
		t.Fatal("explicit selection ignored")
	}
}
func TestDownDoesNotFallThroughAndManualForgetRemovesPrefix(t *testing.T) {
	m := fixtureManager()
	m.sessions["a"].Active = false
	s := fixtureSnapshot()
	p := m.choose(s)
	u, _ := s.Uplink()
	script := m.guard(s, u, p, false)
	if strings.Contains(script, "192.168.0.0/16 oifname") {
		t.Fatal("inactive tunnel allowed")
	}
	if !strings.Contains(script, "192.168.0.0/16 drop") {
		t.Fatal("no fail-closed corporate guard")
	}
	delete(m.sessions, "a")
	p = m.choose(s)
	script = m.guard(s, u, p, false)
	if strings.Contains(script, "192.168.0.0/16 drop") {
		t.Fatal("explicit disconnect retained protection")
	}
}
func TestExternalFullOwnerNotBlackholed(t *testing.T) {
	m := fixtureManager()
	m.sessions["a"].Routes = []route{{"0.0.0.0/0", "10.70.0.1"}}
	s := fixtureSnapshot()
	s.Links = append(s.Links, network.Link{Name: "tun0", Kind: "tun"})
	s.Routes = append(s.Routes, network.Route{Destination: "0.0.0.0/1", Device: "tun0", Family: 4}, network.Route{Destination: "128.0.0.0/1", Device: "tun0", Family: 4})
	p := m.choose(s)
	for _, r := range p.routes {
		if r.cidr == "0.0.0.0/0" {
			t.Fatal("new tunnel blackholes existing full owner")
		}
	}
	if !p.conflict["a"] {
		t.Fatal("missing full conflict")
	}
}
func TestDNSChoicesAndFullDefault(t *testing.T) {
	m := fixtureManager()
	m.sessions["a"].Routes = append(m.sessions["a"].Routes, route{"0.0.0.0/0", "10.70.0.1"})
	p := m.choose(fixtureSnapshot())
	if p.dns["corp.test"] != "a" || !p.dnsConflict["corp.test"] || p.dns["."] != "a" {
		t.Fatalf("%+v", p)
	}
	m.dnsRules = []workvpn.DNSRule{{Domain: "corp.test", Target: "b"}}
	p = m.choose(fixtureSnapshot())
	if p.dns["corp.test"] != "b" || p.dnsConflict["corp.test"] {
		t.Fatal("explicit DNS ignored")
	}
}
func TestNormalizeDef1IPv4AndIPv6(t *testing.T) {
	r := normalizeRoutes([]route{{"0.0.0.0/1", "10.0.0.1"}, {"128.0.0.0/1", "10.0.0.1"}, {"::/1", "fd00::1"}, {"8000::/1", "fd00::1"}})
	if len(r) != 2 || r[0].CIDR != "0.0.0.0/0" || r[1].CIDR != "::/0" {
		t.Fatal(r)
	}
}
func TestSnapshotIndependentOfMutationLock(t *testing.T) {
	m := fixtureManager()
	m.sessions["a"].Status = Status{State: "connected", Routes: []string{"10.0.0.0/8"}}
	m.publishView()
	m.mu.Lock()
	s := m.Snapshot("a")
	rows := m.Routes()
	m.mu.Unlock()
	s.Routes[0] = "changed"
	if m.Snapshot("a").Routes[0] != "10.0.0.0/8" || len(rows) != 0 {
		t.Fatal("view aliases mutable state")
	}
}
func TestWorkUnderlayNeverSelectedAsPhysicalUplink(t *testing.T) {
	s := fixtureSnapshot()
	s.Routes = append(s.Routes, network.Route{Destination: "default", Gateway: "192.0.2.99", Device: "eth0", Family: 4, Table: json.RawMessage(`52783`)})
	u, e := s.Uplink()
	if e != nil || u.Gateway != "192.0.2.1" {
		t.Fatal(u, e)
	}
}
func TestLocalMustBeContainedNotMerelyOverlap(t *testing.T) {
	s := fixtureSnapshot()
	if _, ok := localFor(s, "192.168.0.0/16"); ok {
		t.Fatal("broad override opened physical access")
	}
	if _, ok := localFor(s, "192.168.100.15/32"); !ok {
		t.Fatal("valid local override denied")
	}
	if _, ok := localFor(s, netip.MustParsePrefix("::/0").String()); ok {
		t.Fatal("IPv6 default local bypass")
	}
}

func TestLocalRuleValidationRejectsInternetBeforeApplying(t *testing.T) {
	s := fixtureSnapshot()
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "8.8.8.8/32", "192.168.0.0/16", "invalid"} {
		if err := validateLocalRules(s, []workvpn.RouteRule{{CIDR: cidr, Target: "local"}}); err == nil {
			t.Fatalf("accepted local bypass %s", cidr)
		}
	}
	if err := validateLocalRules(s, []workvpn.RouteRule{{CIDR: "192.168.100.15/32", Target: "local"}, {CIDR: "0.0.0.0/0", Target: "work-profile"}}); err != nil {
		t.Fatal(err)
	}
}

func TestDNSAllowanceIsLinkScopedAndNotForwarded(t *testing.T) {
	m := fixtureManager()
	m.sessions["b"].DNSServers = []string{"10.70.0.1"}
	s := fixtureSnapshot()
	u, _ := s.Uplink()
	script := m.guard(s, u, m.choose(s), false)
	output, forward, ok := strings.Cut(script, "chain forward")
	if !ok {
		t.Fatal(script)
	}
	for _, iface := range []string{"v443w00000001", "v443w00000002"} {
		for _, proto := range []string{"udp", "tcp"} {
			want := "ip daddr 10.70.0.1 " + proto + " dport 53 oifname \"" + iface + "\" accept"
			if !strings.Contains(output, want) || strings.Contains(forward, want) {
				t.Fatal("missing local-only bound DNS allowance", want, script)
			}
		}
	}
	m.sessions["b"].Active = false
	script = m.guard(s, u, m.choose(s), false)
	if strings.Contains(script, "ip daddr 10.70.0.1 udp dport 53 oifname \"v443w00000002\" accept") {
		t.Fatal("inactive DNS provider is still allowed")
	}
}

func TestWorkDNSTablesAreOwnedAndBounded(t *testing.T) {
	tables := workTables()
	if len(tables) != 38 {
		t.Fatal(tables)
	}
	for _, n := range tables {
		if !ownedTable(strconv.Itoa(n)) {
			t.Fatal(n)
		}
	}
	for _, n := range []string{"52788", "52799", "52833", "254"} {
		if ownedTable(n) {
			t.Fatal("foreign table claimed", n)
		}
	}
}

func TestFullTunnelProtectsUnsupportedFamilyAndDNS(t *testing.T) {
	m := fixtureManager()
	m.sessions["a"].Routes = append(m.sessions["a"].Routes, route{"0.0.0.0/0", "10.70.0.1"})
	s := fixtureSnapshot()
	p := m.choose(s)
	blocked := false
	for _, r := range p.routes {
		if r.cidr == "::/0" && !r.active {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("full IPv4 would leak physical IPv6")
	}
	u, _ := s.Uplink()
	guard := m.guard(s, u, p, false)
	if !strings.Contains(guard, "ip6 daddr ::/0 drop") || !strings.Contains(guard, "udp dport {53,853} drop") {
		t.Fatal(guard)
	}
}
