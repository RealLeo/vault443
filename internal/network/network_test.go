package network

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vault443/internal/journal"
	"vault443/internal/model"
)

func fixture() Snapshot {
	return Snapshot{Links: []Link{{Name: "eth0", Kind: "ether"}, {Name: "docker0", Kind: "bridge"}, {Name: "corp0", Kind: "tun"}}, Routes: []Route{{Destination: "default", Device: "eth0", Gateway: "192.0.2.1", Family: 4}, {Destination: "192.0.2.0/24", Device: "eth0", Scope: "link", Family: 4}, {Destination: "172.18.0.0/16", Device: "docker0", Scope: "link", Family: 4}, {Destination: "10.20.0.0/16", Device: "corp0", Family: 4}}}
}

func TestSubnetSelectionUsesAllTablesAndAddresses(t *testing.T) {
	s := fixture()
	s.Routes = append(s.Routes, Route{Destination: "198.18.0.0/24", Device: "docker0", Table: json.RawMessage(`999`), Family: 4}, Route{Destination: "fd56:4c54::/64", Device: "docker0", Family: 6})
	v4, v6, e := ChooseSubnets(s)
	if e != nil {
		t.Fatal(e)
	}
	if v4.Masked().Overlaps(netip.MustParsePrefix("198.18.0.0/24")) || v6.Masked().Overlaps(netip.MustParsePrefix("fd56:4c54::/64")) {
		t.Fatal("selected an overlapping subnet")
	}
	s.Routes = append(s.Routes, Route{Destination: "198.18.0.0/15", Device: "docker0", Family: 4})
	if _, _, e = ChooseSubnets(s); e == nil {
		t.Fatal("expected exhausted pool error")
	}
}

func TestDefaultDetectionIncludesSplitDefault(t *testing.T) {
	if claimsDefault([]Route{{Destination: "10.0.0.0/8", Family: 4}}, 4) {
		t.Fatal("corporate prefix claimed full Internet")
	}
	if !claimsDefault([]Route{{Destination: "0.0.0.0/1", Family: 4}, {Destination: "128.0.0.0/1", Family: 4}}, 4) {
		t.Fatal("missed OpenVPN def1")
	}
	if !claimsDefault([]Route{{Destination: "default", Family: 6}}, 6) {
		t.Fatal("missed IPv6 default")
	}
}

func TestGuardNoBroadDirectOrForwardEndpointBypass(t *testing.T) {
	script := guardScript(guardOptions{Snapshot: fixture(), TunnelReady: true, Endpoint: netip.MustParseAddr("203.0.113.1"), Port: 443, Uplink: "eth0", Protected: []protectedRoute{{"10.20.0.0/16", "corp0"}}}, true)
	for _, bad := range []string{"flush ruleset", "ct state established", "10.0.0.0/8 accept", "172.16.0.0/12", "meta skuid 0"} {
		if strings.Contains(script, bad) {
			t.Fatalf("unsafe broad exemption: %s", bad)
		}
	}
	if !strings.Contains(script, "delete table inet vault443") {
		t.Fatal("missing owned replacement")
	}
	drop := strings.Index(script, "ip daddr 10.20.0.0/16 drop")
	tun := strings.Index(script, `oifname "vault4430" accept`)
	if drop < 0 || drop > tun {
		t.Fatal("corporate traffic could fall through into VLESS")
	}
	forward := strings.Split(script, "chain forward_guard")[1]
	if strings.Contains(forward, "203.0.113.1") || strings.Contains(forward, "meta mark") {
		t.Fatal("container may use direct core endpoint exemption")
	}
	if !strings.Contains(forward, `ip daddr 172.18.0.0/16 oifname "docker0" accept`) {
		t.Fatal("local container route lost")
	}
	if strings.Count(script, "policy drop") != 2 {
		t.Fatal("both host and forwarded paths must fail closed")
	}
}

func TestExternalTakeoverPreservesFamilyScopedGuard(t *testing.T) {
	script := guardScript(guardOptions{Snapshot: fixture(), External: []external{{Link: Link{Name: "corp0"}, Active: true, Full4: true}}}, false)
	if !strings.Contains(script, `oifname "corp0" meta nfproto ipv4 accept`) {
		t.Fatal("external IPv4 Internet blocked")
	}
	if strings.Contains(script, `oifname "corp0" meta nfproto ipv6 accept`) || strings.Contains(script, `oifname "vault4430" accept`) {
		t.Fatal("unowned IPv6 or paused VLESS permitted")
	}
	if !strings.Contains(script, "policy drop") {
		t.Fatal("takeover disabled protection")
	}
}

func TestBindingValidation(t *testing.T) {
	for _, data := range []string{`{"interface":"eth0;evil","manager":"openvpn"}`, `{"interface":"tun0","manager":"unknown"}`, `{"interface":"tun0","manager":"openvpn","routes":["0.0.0.0/0"]}`, `{"interface":"tun0","manager":"openvpn","command":"evil"}`, `{"interface":"tun0","manager":"openvpn"} {}`, `{"interface":"tun0","manager":"openvpn","dnsDomains":["corp.example"]}`} {
		if _, e := ParseBinding(data); e == nil {
			t.Fatalf("accepted invalid binding: %s", data)
		}
	}
	if _, e := ParseBinding(`{"interface":"tun0","manager":"openvpn","unit":"openvpn-client@work.service","routes":["10.20.0.0/16"],"endpoints":[{"address":"203.0.113.2","port":1194,"protocol":"udp"}]}`); e != nil {
		t.Fatal(e)
	}
}

type fakeRunner struct {
	calls        []command
	failMutation bool
	s            Snapshot
}

func (r *fakeRunner) Run(ctx context.Context, c command) ([]byte, error) {
	r.calls = append(r.calls, c)
	args := strings.Join(c.Args, " ")
	if c.Path == "/usr/sbin/ip" {
		if strings.Contains(args, "address show") {
			links := append([]Link(nil), r.s.Links...)
			for i := range links {
				links[i].LinkInfo.Kind = links[i].Kind
			}
			return json.Marshal(links)
		}
		if strings.Contains(args, "route show") {
			var rr []Route
			f := 4
			if strings.Contains(args, "-6") {
				f = 6
			}
			for _, route := range r.s.Routes {
				if route.Family == f {
					rr = append(rr, route)
				}
			}
			return json.Marshal(rr)
		}
		if strings.Contains(args, "rule show") {
			return []byte(`[]`), nil
		}
	}
	if c.Path == "/usr/sbin/nft" && args == "-j list tables" {
		return []byte(`{"nftables":[]}`), nil
	}
	if r.failMutation {
		return nil, errors.New("unexpected mutating command")
	}
	return []byte{}, nil
}

func TestConstructorAndDryRunHaveNoSideEffects(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	m := New(Config{StateDir: dir, RuntimeDir: filepath.Join(dir, "run"), DryRun: true})
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("constructor wrote state")
	}
	f := &fakeRunner{s: fixture(), failMutation: true}
	m.r = f
	m.bindings = []Binding{{Interface: "corp0", Manager: "openvpn"}}
	p := model.Profile{ID: "test", Server: "example.com", Port: 443, UUID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Transport: "tcp", Security: "tls"}
	if e := m.Connect(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if m.Status().State == "connected" || m.Status().GuardArmed {
		t.Fatal("dry run claims real protection")
	}
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("dry run wrote state")
	}
	if len(m.commands) == 0 {
		t.Fatal("dry run produced no plan")
	}
}

func TestRoutePlanTouchesOnlyOwnedTables(t *testing.T) {
	s := fixture()
	u, _ := s.Uplink()
	plan := routePlan(s, nil, []protectedRoute{{"10.20.0.0/16", "corp0"}}, u, false)
	for _, c := range plan {
		a := strings.Join(c.Args, " ")
		if strings.Contains(a, "table main") || strings.Contains(a, "table all") {
			t.Fatalf("foreign routes modified: %s", a)
		}
	}
	found := false
	for _, c := range plan {
		if strings.Contains(strings.Join(c.Args, " "), "unreachable 10.20.0.0/16") {
			found = true
		}
	}
	if !found {
		t.Fatal("missing corporate fail-closed route")
	}
}

func TestExternalPauseResumeAndManualReleaseContract(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	m := New(Config{StateDir: dir, RuntimeDir: filepath.Join(dir, "run")})
	m.loaded = true
	m.dnsSaved = map[string]dnsSettings{}
	m.status.GuardArmed = true
	m.status.State = "connected"
	m.bindings = []Binding{{Interface: "corp0", Manager: "openvpn"}}
	s := fixture()
	s.Routes = append(s.Routes, Route{Destination: "default", Device: "corp0", Family: 4})
	f := &fakeRunner{s: s}
	m.r = f
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	if m.status.State != "paused_external" || !m.status.GuardArmed {
		t.Fatal("takeover disarmed protection")
	}
	f.s = fixture()
	if e := m.Reconcile(context.Background()); e == nil {
		t.Fatal("resumption must request core reconnect")
	}
	if m.status.State != "reconnecting" || !m.status.GuardArmed {
		t.Fatal("foreign disappearance disarmed protection")
	}
	for _, c := range m.commands {
		if c.Path == "/usr/sbin/nft" && strings.Join(c.Args, " ") == "delete table inet "+TableName {
			t.Fatal("automatic state transition removed guard")
		}
	}
	if e := m.Disconnect(context.Background()); e != nil {
		t.Fatal(e)
	}
	if m.status.State != "disconnected" || m.status.GuardArmed {
		t.Fatal("manual disconnect did not release")
	}
}

func TestUnrecognizedSplitVPNRefusedBeforeArming(t *testing.T) {
	m := New(Config{StateDir: filepath.Join(t.TempDir(), "none"), DryRun: true})
	m.r = &fakeRunner{s: fixture()}
	if e := m.Arm(context.Background()); e == nil {
		t.Fatal("unrecognized split VPN silently ignored")
	}
	if len(m.commands) > 0 {
		t.Fatal("network was changed before compatibility check")
	}
	diagnostic := m.Diagnostics(context.Background()).(map[string]any)
	if diagnostic["message"] != m.Status().Message || !strings.Contains(m.Status().Message, `"corp0"`) {
		t.Fatal("diagnostics must explain which unrecognized VPN blocks arming")
	}
}

func TestWireGuardUnmarkedTupleIsNarrow(t *testing.T) {
	e := Endpoint{Address: "203.0.113.3", Port: 51820, Protocol: "udp", SourcePort: 51821}
	x := external{Binding: Binding{RootOnly: true, Endpoints: []Endpoint{e}}, Link: Link{Name: "wg0", Kind: "wireguard"}, Active: true}
	script := guardScript(guardOptions{Snapshot: fixture(), External: []external{x}, Uplink: "eth0"}, false)
	if !strings.Contains(script, "udp sport 51821 ip daddr 203.0.113.3 udp dport 51820 meta mark set") {
		t.Fatal("unmarked kernel transport exemption is not specific")
	}
	if strings.Contains(script, "meta skuid 0 accept") {
		t.Fatal("blanket root bypass")
	}
}

func TestRouterDNSFallbackIsBlockedBeforeLANAllowance(t *testing.T) {
	script := guardScript(guardOptions{Snapshot: fixture(), Uplink: "eth0"}, false)
	dns := strings.Index(script, "udp dport { 53, 853 } drop")
	lan := strings.Index(script, `ip daddr 192.0.2.0/24 oifname "eth0" accept`)
	if dns < 0 || dns > lan {
		t.Fatal("router DNS can bypass protection")
	}
}

func TestCheckpointDoesNotAuthorizeDeletingForeignRoutes(t *testing.T) {
	m := New(Config{DryRun: true})
	m.ownedRules = true
	s := fixture()
	s.Routes = append(s.Routes, Route{Destination: "10.1.0.0/16", Device: "eth0", Table: json.RawMessage(`52780`), Protocol: json.RawMessage(`"static"`), Family: 4})
	if e := m.checkOwnership(s); e == nil {
		t.Fatal("checkpoint overrode foreign route ownership")
	}
	s.Routes[len(s.Routes)-1].Protocol = json.RawMessage(`186`)
	if e := m.checkOwnership(s); e != nil {
		t.Fatal(e)
	}
	s.Rules4 = []map[string]any{{"priority": float64(RuleBase), "table": float64(100)}}
	if e := m.checkOwnership(s); e == nil {
		t.Fatal("foreign policy priority accepted")
	}
}

func TestRouteCacheRepairsDeletedResourcesAndRechecksOwnership(t *testing.T) {
	m := New(Config{DryRun: true})
	m.ownedRules = true
	s := fixture()
	s.Routes = append(s.Routes,
		Route{Destination: "default", Device: TunName, Table: json.RawMessage(`52780`), Protocol: json.RawMessage(`186`), Family: 4},
		Route{Destination: "default", Type: "unreachable", Table: json.RawMessage(`52780`), Protocol: json.RawMessage(`186`), Metric: 42760, Family: 4})
	if e := m.installRoutes(context.Background(), s, nil, true, false); e != nil {
		t.Fatal(e)
	}
	m.commands = nil
	if e := m.installRoutes(context.Background(), s, nil, true, false); e != nil || len(m.commands) != 0 {
		t.Fatalf("unchanged policy was rewritten: %v", e)
	}
	// The table still exists, so the desired command plan is identical even
	// though its live default route was deleted outside this process.
	s.Routes = append(s.Routes[:len(s.Routes)-2], s.Routes[len(s.Routes)-1])
	if e := m.installRoutes(context.Background(), s, nil, true, false); e != nil || len(m.commands) == 0 {
		t.Fatalf("deleted resource was not repaired: %v", e)
	}
	m.commands = nil
	s.Routes[len(s.Routes)-1].Protocol = json.RawMessage(`"static"`)
	if e := m.installRoutes(context.Background(), s, nil, true, false); e == nil || len(m.commands) != 0 {
		t.Fatal("cached desired plan bypassed ownership validation")
	}
}

func TestFreshManagerLoadsArmedCheckpointAndReleases(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if e := privateWrite(dir, "network-state.json", persisted{Armed: true}); e != nil {
		t.Fatal(e)
	}
	m := New(Config{StateDir: dir, RuntimeDir: filepath.Join(dir, "run")})
	m.r = &fakeRunner{s: Snapshot{Links: []Link{{Name: "lo"}}}}
	if e := m.Disconnect(context.Background()); e != nil {
		t.Fatal(e)
	}
	if m.Status().GuardArmed || m.Status().State != "disconnected" {
		t.Fatal("fresh maintenance manager failed to release")
	}
	b, e := os.ReadFile(filepath.Join(dir, "network-state.json"))
	if e != nil {
		t.Fatal(e)
	}
	var p persisted
	_ = json.Unmarshal(b, &p)
	if p.Armed {
		t.Fatal("manual release did not persist")
	}
}

// Namespace/container integration runs may request an artifact without touching
// the host firewall. The artifact contains no credentials or user addresses.
func TestExportGuardForIsolatedValidation(t *testing.T) {
	path := os.Getenv("VLT_NFT_TEST_ARTIFACT")
	if path == "" {
		t.Skip("optional isolated nft validation")
	}
	b := guardScript(guardOptions{Snapshot: fixture(), TunnelReady: true, Endpoint: netip.MustParseAddr("203.0.113.1"), Port: 443, Uplink: "eth0"}, false)
	if e := os.WriteFile(path, []byte(b), 0600); e != nil {
		t.Fatal(e)
	}
}

func TestLifecycleJournalStaysWithExplicitSession(t *testing.T) {
	j, e := journal.Open(filepath.Join(t.TempDir(), "journal"))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	m := New(Config{StateDir: filepath.Join(t.TempDir(), "state"), RuntimeDir: filepath.Join(t.TempDir(), "run"), DryRun: true})
	m.r = &fakeRunner{s: fixture(), failMutation: true}
	m.bindings = []Binding{{Interface: "corp0", Manager: "openvpn"}}
	p := model.Profile{ID: "first", Server: "example.com", Port: 443, UUID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Transport: "tcp", Security: "tls"}
	first := j.NewSession(1000, p.ID, p.UUID)
	m.SetLogSession(first)
	if e = m.Connect(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	j.Flush()
	rows, e := j.Read(1000, p.ID, "", 500)
	if e != nil || len(rows.Entries) < 3 {
		t.Fatalf("missing lifecycle entries %+v %v", rows, e)
	}
	m.SetLogSession(j.NewSession(1001, "failed"))
	m.mu.Lock()
	m.fail(errors.New("connection failed"))
	m.mu.Unlock()
	j.Flush()
	old, _ := j.Read(1000, p.ID, "", 500)
	if len(old.Entries) != len(rows.Entries) {
		t.Fatal("new owner appended to previous profile")
	}
	failed, _ := j.Read(1001, "failed", "", 500)
	if len(failed.Entries) != 1 || failed.Entries[0].Level != "error" {
		t.Fatal("failure not bound to new owner")
	}
}
