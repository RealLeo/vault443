package workvpn

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func wgTestKey(n byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)) }
func wgFixture() string {
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.77.0.2/32, fd77::2/128\nDNS = 10.77.0.1, work.example.test\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 10.77.0.0/24, fd77::/64\nPersistentKeepalive = 25\n", wgTestKey(7), wgTestKey(8), wgTestKey(9))
}
func awgFixture() string {
	params := "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 12\nS2 = 13\nS3 = 14\nS4 = 15\nH1 = 100-199\nH2 = 200-299\nH3 = 300-399\nH4 = 400-499\nI1 = <b 0xabcdef><r 8><rd 3><rc 5><t>\nHeaderProtectionKey = " + wgTestKey(10) + "\nContentPaddingAddition = 0-32\nRekeyAfterTime = 100-120\nRekeyTimeout = 5-8\nRejectAfterTime = 180-200\nKeepaliveTimeout = 10-15\nMaxHandshakeAttempts = 5-10\nRandomTrailers = true\nDisableCookies = false\n"
	return strings.Replace(wgFixture(), "[Interface]\n", "[Interface]\n"+params, 1)
}
func amneziaKey(t *testing.T, source string, compressed bool) string {
	t.Helper()
	config, _ := json.Marshal(map[string]interface{}{"config": source})
	root, _ := json.Marshal(map[string]interface{}{"description": "Export", "containers": []interface{}{map[string]interface{}{"container": "amnezia-awg", "awg": map[string]interface{}{"last_config": string(config)}}}})
	return wrapAmnezia(t, root, compressed)
}
func wrapAmnezia(t *testing.T, root []byte, compressed bool) string {
	t.Helper()
	if compressed {
		var out bytes.Buffer
		_ = binary.Write(&out, binary.BigEndian, uint32(len(root)))
		w := zlib.NewWriter(&out)
		_, _ = w.Write(root)
		if e := w.Close(); e != nil {
			t.Fatal(e)
		}
		root = out.Bytes()
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(root)
}

func TestWireGuardCanonicalIdentityAndPrivateRoundtrip(t *testing.T) {
	p, e := ParseWireGuard("Office", wgFixture())
	if e != nil {
		t.Fatal(e)
	}
	if p.Protocol() != "wireguard" || !strings.HasPrefix(p.ID, "wg-") || p.WireGuard.MTU != 1280 || p.WireGuard.Peers[0].Endpoint.Host != "2001:db8::1" {
		t.Fatal("wrong normalized WireGuard profile")
	}
	if e = ValidateProfile(p); e != nil {
		t.Fatal(e)
	}
	q, e := ParseWireGuard("Different name", strings.ReplaceAll(wgFixture(), "\n", "\r\n"))
	if e != nil || p.ID != q.ID {
		t.Fatal("equivalent config identity changed", e)
	}
	p.Name = "Renamed"
	p.IconID = "vault-door"
	p.DebugLogging = true
	if e = ValidateProfile(p); e != nil {
		t.Fatal("metadata changes must preserve identity", e)
	}
	if !p.AllowsPrefix("10.77.0.15/32") || p.AllowsPrefix("10.0.0.0/8") || p.AllowsPrefix("192.0.2.1/32") {
		t.Fatal("incorrect AllowedIPs containment")
	}
	for _, secret := range []string{wgTestKey(7), wgTestKey(9)} {
		if !strings.Contains(strings.Join(p.Secrets(), "\n"), secret) {
			t.Fatal("secret redaction context incomplete")
		}
	}
	s, dir := privateStore(t)
	if e = s.Update(func(st *State) error { st.SetUser(1000, WorkUser{Profiles: []Profile{p}}); return nil }); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	saved, ok := reopened.Snapshot().Profile(1000, p.ID)
	if !ok || saved.WireGuard.Peers[0].PresharedKey != p.WireGuard.Peers[0].PresharedKey {
		t.Fatal("private WG credentials not preserved")
	}
}

func TestAmneziaAllGenerationsAndEquivalentExports(t *testing.T) {
	for _, text := range []string{
		strings.Replace(wgFixture(), "[Interface]", "[Interface]\nJc=4\nJmin=40\nJmax=70\nS1=20\nS2=30\nH1=100\nH2=200\nH3=300\nH4=400", 1),
		strings.Replace(wgFixture(), "[Interface]", "[Interface]\nI1=<b 0xab><r 4>", 1),
		strings.Replace(wgFixture(), "[Interface]", "[Interface]\nS3=20\nS4=30\nH1=100-199", 1),
		awgFixture(),
	} {
		p, e := ParseWireGuard("Office", text)
		if e != nil {
			t.Fatal(e)
		}
		if p.Protocol() != "amneziawg" {
			t.Fatal("AWG silently became WireGuard")
		}
		if e = ValidateProfile(p); e != nil {
			t.Fatal("AWG round trip failed", e)
		}
		for _, compressed := range []bool{false, true} {
			imported, e := ParseWork("File", amneziaKey(t, text, compressed))
			if e != nil || len(imported) != 1 || imported[0].ID != p.ID {
				t.Fatal("native/export identity differs", e)
			}
		}
	}
	p, e := ParseWireGuard("AWG", strings.Replace(awgFixture(), "PersistentKeepalive = 25", "PersistentKeepalive = 20-30", 1))
	if e != nil || p.WireGuard.Peers[0].PersistentKeepalive != "20-30" {
		t.Fatal("AWG keepalive range", e)
	}
}

func TestWireGuardRejectedInputDoesNotExposeSecrets(t *testing.T) {
	base := wgFixture()
	cases := []string{
		strings.Replace(base, "PrivateKey = "+wgTestKey(7), "PrivateKey = secret-invalid-key", 1),
		strings.Replace(base, "[Peer]", "PreUp = super-secret-script\n[Peer]", 1),
		strings.Replace(base, "[Peer]", "Table = off\n[Peer]", 1),
		strings.Replace(base, "[Peer]", "FwMark = 42\n[Peer]", 1),
		strings.Replace(base, "[Peer]", "SaveConfig = true\n[Peer]", 1),
		strings.Replace(base, "[Peer]", "UnknownOption = secret-value\n[Peer]", 1),
		strings.Replace(base, "PrivateKey =", "PrivateKey = "+wgTestKey(7)+"\nPrivateKey =", 1),
		strings.Replace(base, "[2001:db8::1]:51820", "[fe80::1%eth0]:51820", 1),
		strings.Replace(base, "[2001:db8::1]:51820", "localhost:0", 1),
		strings.Replace(base, "DNS = 10.77.0.1", "DNS = 192.0.2.1", 1),
		strings.Replace(base, "PrivateKey =", "Address = 127.0.0.1\nPrivateKey =", 1),
		strings.Replace(base, "[Peer]", "MTU=1200\n[Peer]", 1),
		strings.Replace(base, "PersistentKeepalive = 25", "PersistentKeepalive = 25-30", 1),
		base + "PublicKey = " + wgTestKey(12) + "\n",
		strings.Replace(base, "[Peer]", "Jc = 1000000000\n[Peer]", 1),
		strings.Replace(base, "[Peer]", "I1 = <r 999999999>\n[Peer]", 1),
		strings.Replace(base, "[Peer]", "HeaderProtectionKey="+wgTestKey(10)+"\n[Peer]", 1),
	}
	for i, source := range cases {
		_, e := ParseWireGuard("Test", source)
		if e == nil {
			t.Fatalf("unsafe case %d accepted", i)
		}
		for _, secret := range []string{wgTestKey(7), wgTestKey(9), "super-secret-script", "secret-invalid-key", "secret-value"} {
			if strings.Contains(e.Error(), secret) {
				t.Fatalf("case %d leaked credentials", i)
			}
		}
	}
}

func TestMultiplePeersLongestPrefixesAndAmbiguity(t *testing.T) {
	second := fmt.Sprintf("[Peer]\nPublicKey=%s\nEndpoint=second.example.test:443\nAllowedIPs=10.77.0.128/25\n", wgTestKey(22))
	p, e := ParseWireGuard("Multi", wgFixture()+second)
	if e != nil || len(p.WireGuard.Peers) != 2 {
		t.Fatal(e)
	}
	if _, e = ParseWireGuard("Ambiguous", wgFixture()+strings.Replace(second, "10.77.0.128/25", "10.77.0.0/24", 1)); e == nil {
		t.Fatal("ambiguous equal AllowedIPs accepted")
	}
	if _, e = ParseWireGuard("No endpoint", wgFixture()+strings.Replace(second, "Endpoint=second.example.test:443\n", "", 1)); e == nil {
		t.Fatal("endpointless client peer accepted")
	}
}

func TestAmneziaMalformedAndBoundedDocuments(t *testing.T) {
	for _, document := range []string{
		`{"containers":[],"containers":[]}`,
		`{"api_key":"sensitive-api-token","containers":[]}`,
		`{"auth_data":"sensitive-api-token","containers":[]}`,
		`{"userName":"root","password":"sensitive-password","containers":[]}`,
		`{"containers":[{"container":"amnezia-openvpn"}]}`,
		`{"containers":[{"container":"amnezia-awg","awg":{}}]}`,
		`{"containers":[]} {}`,
	} {
		_, e := ParseWork("Key", wrapAmnezia(t, []byte(document), true))
		if e == nil || strings.Contains(e.Error(), "sensitive-") {
			t.Fatal("bad or leaking export validation", e)
		}
	}
	var oversized bytes.Buffer
	_ = binary.Write(&oversized, binary.BigEndian, uint32(1))
	z := zlib.NewWriter(&oversized)
	_, _ = z.Write(bytes.Repeat([]byte{'x'}, MaxBytes+1))
	_ = z.Close()
	if _, e := ParseWork("Bomb", "vpn://"+base64.RawURLEncoding.EncodeToString(oversized.Bytes())); e == nil {
		t.Fatal("decompression size mismatch accepted")
	}
	if _, e := ParseWork("Huge", strings.Repeat("a", MaxBytes+1)); e == nil {
		t.Fatal("oversized document accepted")
	}
}

func TestLegacyWorkStoreMigrationPreservesIdentityAndBackup(t *testing.T) {
	s, dir := privateStore(t)
	p := addProfile(t, s, 1000)
	state := s.Snapshot()
	state.Version = 1
	user := state.User(1000)
	user.Profiles[0].Kind = ""
	user.Profiles[0].Name = "Existing"
	state.SetUser(1000, user)
	state.BootID = "boot"
	state.Desired = []Desired{{1000, p.ID}}
	rule, e := NewRouteRule("192.168.100.15", p.ID)
	if e != nil {
		t.Fatal(e)
	}
	user = state.User(1000)
	user.Rules = []RouteRule{rule}
	state.SetUser(1000, user)
	before, _ := json.Marshal(state)
	path := filepath.Join(dir, StoreFilename)
	if e = os.WriteFile(path, before, 0600); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		migrated, e := Open(dir, true)
		if e != nil {
			t.Fatal(e)
		}
		got := migrated.Snapshot()
		saved, ok := got.Profile(1000, p.ID)
		if !ok || saved.Protocol() != "openvpn" || saved.Name != "Existing" || got.Version != 2 || got.BootID != "boot" || len(got.Desired) != 1 || got.Desired[0].ProfileID != p.ID || got.User(1000).Rules[0] != rule {
			t.Fatal("migration changed existing identity or intent")
		}
	}
	backup := filepath.Join(dir, "work-vpn.v1.backup.json")
	saved, e := os.ReadFile(backup)
	if e != nil || !bytes.Equal(saved, before) {
		t.Fatal("migration backup differs", e)
	}
	info, _ := os.Stat(backup)
	if info.Mode().Perm() != 0600 {
		t.Fatal("backup permissions")
	}
	// Interrupted migration: the exact durable backup permits resuming.
	if e = os.WriteFile(path, before, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(dir, true); e != nil {
		t.Fatal("resume failed", e)
	}
	if e = os.WriteFile(path, before, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(backup, []byte("conflict"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(dir, true); e == nil {
		t.Fatal("conflicting backup overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, before) {
		t.Fatal("failed migration changed original")
	}
}

func TestWGRouteRuleCannotExpandAllowedIPs(t *testing.T) {
	s, _ := privateStore(t)
	p, e := ParseWireGuard("WG", wgFixture())
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Update(func(st *State) error { st.SetUser(1000, WorkUser{Profiles: []Profile{p}}); return nil }); e != nil {
		t.Fatal(e)
	}
	r, e := NewRouteRule("0.0.0.0/0", p.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Update(func(st *State) error { u := st.User(1000); u.Rules = []RouteRule{r}; st.SetUser(1000, u); return nil }); e == nil {
		t.Fatal("manual rule expanded AllowedIPs")
	}
}

func TestAllowedIPsUnionCoverage(t *testing.T) {
	text := strings.Replace(wgFixture(), "10.77.0.0/24, fd77::/64", "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1", 1)
	p, e := ParseWireGuard("Split full", text)
	if e != nil {
		t.Fatal(e)
	}
	if !p.AllowsPrefix("0.0.0.0/0") || !p.AllowsPrefix("::/0") {
		t.Fatal("complete split-default coverage was not recognized")
	}
	p.WireGuard.Peers[0].AllowedIPs = []string{"0.0.0.0/2", "128.0.0.0/1"}
	if p.AllowsPrefix("0.0.0.0/0") {
		t.Fatal("gap in AllowedIPs was expanded")
	}
}

func TestAmneziaSupplementPreservesHiddenCryptoAndRejectsConflicts(t *testing.T) {
	native := strings.Replace(wgFixture(), "[Interface]", "[Interface]\nS1=12\nS2=12\nS3=12\nS4=12", 1)
	config := map[string]interface{}{"config": native, "HeaderProtectionKey": wgTestKey(14), "RandomTrailers": "on", "mtu": "1280"}
	wrap := func(config map[string]interface{}) string {
		last, _ := json.Marshal(config)
		root, _ := json.Marshal(map[string]interface{}{"containers": []interface{}{map[string]interface{}{"container": "amnezia-awg", "awg": map[string]interface{}{"last_config": string(last)}}}})
		return wrapAmnezia(t, root, true)
	}
	items, e := ParseWork("Hidden", wrap(config))
	if e != nil {
		t.Fatal(e)
	}
	w := items[0].WireGuard
	if w.Parameters["HeaderProtectionKey"] != wgTestKey(14) || w.Parameters["RandomTrailers"] != "true" || w.MTU != 1280 {
		t.Fatal("export metadata was silently dropped")
	}
	config["config"] = strings.Replace(native, "[Interface]", "[Interface]\nHeaderProtectionKey="+wgTestKey(15), 1)
	if _, e = ParseWork("Conflicting", wrap(config)); e == nil || strings.Contains(e.Error(), wgTestKey(14)) || strings.Contains(e.Error(), wgTestKey(15)) {
		t.Fatal("conflicting crypto accepted or leaked", e)
	}
	config["config"] = native
	config["unknown_mask"] = "private-value"
	if _, e = ParseWork("Future", wrap(config)); e == nil {
		t.Fatal("unknown significant client field dropped")
	}
}

func TestAmneziaProtocolMetadataIsValidated(t *testing.T) {
	wrap := func(protocol, config map[string]interface{}, kind string) string {
		config["config"] = wgFixture()
		last, _ := json.Marshal(config)
		protocol["last_config"] = string(last)
		root, _ := json.Marshal(map[string]interface{}{"containers": []interface{}{map[string]interface{}{"container": "amnezia-" + kind, kind: protocol}}})
		return wrapAmnezia(t, root, true)
	}
	for _, version := range []interface{}{nil, "1", "1.0", "1.5", 2, "2.0", "3", "3.0", "3.1"} {
		if _, e := ParseWork("Supported", wrap(map[string]interface{}{"protocol_version": version, "transport_proto": "udp"}, map[string]interface{}{}, "awg")); e != nil {
			t.Fatalf("supported generation %v: %v", version, e)
		}
	}
	for _, row := range []struct {
		protocol, config map[string]interface{}
		kind             string
	}{
		{map[string]interface{}{"transport_proto": "tcp"}, map[string]interface{}{}, "awg"},
		{map[string]interface{}{}, map[string]interface{}{"transport_proto": "tcp"}, "wireguard"},
		{map[string]interface{}{"protocol_version": "4-private"}, map[string]interface{}{}, "awg"},
		{map[string]interface{}{}, map[string]interface{}{"protocol_version": "3.2"}, "awg"},
		{map[string]interface{}{"protocol_version": "2"}, map[string]interface{}{}, "wireguard"},
		{map[string]interface{}{"protocol_version": "2"}, map[string]interface{}{"protocol_version": "3.1"}, "awg"},
	} {
		if _, e := ParseWork("Unsupported", wrap(row.protocol, row.config, row.kind)); e == nil || strings.Contains(e.Error(), "4-private") {
			t.Fatal("unsupported or conflicting metadata was silently ignored or leaked", e)
		}
	}
}

func FuzzWireGuardCanonicalRoundTrip(f *testing.F) {
	f.Add(wgFixture())
	f.Add(awgFixture())
	f.Add("[Interface]\nPrivateKey=bad\n")
	f.Fuzz(func(t *testing.T, source string) {
		p, e := ParseWireGuard("Fuzz", source)
		if e != nil {
			return
		}
		if e = ValidateProfile(p); e != nil {
			t.Fatal("accepted profile cannot survive storage", e)
		}
	})
}
