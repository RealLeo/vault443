package worknet

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"vault443/internal/network"
	"vault443/internal/workvpn"
)

func syntheticWGKey(v byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = v
	}
	return base64.StdEncoding.EncodeToString(b)
}
func testWGProfile() *workvpn.WireGuardConfig {
	return &workvpn.WireGuardConfig{PrivateKey: syntheticWGKey(1), Addresses: []string{"10.200.0.2/32", "fd42::2/128"}, MTU: 1280, Parameters: map[string]string{}, Peers: []workvpn.WireGuardPeer{{PublicKey: syntheticWGKey(2), PresharedKey: syntheticWGKey(3), Endpoint: workvpn.Remote{Host: "192.0.2.1", Port: 51820, Protocol: "udp"}, AllowedIPs: []string{"10.0.0.0/8", "fd42::/64"}, PersistentKeepalive: "25"}}}
}

func TestWireGuardRenderKeepsKeysOffCommandLineAndMappings(t *testing.T) {
	w := testWGProfile()
	w.Parameters = map[string]string{"Jc": "4", "S4": "12", "H1": "100-200", "I1": "<r 12>", "HeaderProtectionKey": syntheticWGKey(4), "ContentPaddingAddition": "0-16", "RekeyAfterTime": "60-80", "RandomTrailers": "true", "DisableCookies": "false"}
	e := []network.Endpoint{{Address: "2001:db8::1", Port: 51820, Protocol: "udp", Mark: network.OuterMark}}
	a := amneziaConfig(w, e)
	for _, want := range []string{"fwmark=1447842817\n", "public_key=" + keyHex(w.Peers[0].PublicKey), "preshared_key=" + keyHex(w.Peers[0].PresharedKey), "endpoint=[2001:db8::1]:51820", "header_protection_key=" + keyHex(w.Parameters["HeaderProtectionKey"]), "content_padding_addition=0-16", "random_trailers=1", "disable_cookies=0", "i1=<r 12>", "h1=100-200"} {
		if !strings.Contains(a, want) {
			t.Errorf("missing checked UAPI field %q", strings.SplitN(want, "=", 2)[0])
		}
	}
	plain := wireGuardConfig(w, e)
	if strings.Contains(plain, "Address") || strings.Contains(plain, "DNS") || strings.Contains(plain, "Jc") {
		t.Fatal("runtime passed wg-quick or AWG options to kernel WireGuard")
	}
	if !strings.Contains(plain, "Endpoint = [2001:db8::1]:51820") {
		t.Fatal("IPv6 endpoint lost brackets")
	}
}

func TestAmneziaStatusNeverReturnsUAPISecrets(t *testing.T) {
	w := testWGProfile()
	key := keyHex(w.Peers[0].PublicKey)
	raw := "private_key=SECRET_PRIVATE\nheader_protection_key=SECRET_HEADER\npublic_key=" + key + "\npreshared_key=SECRET_PSK\nendpoint=[2001:db8::1]:51820\nlast_handshake_time_sec=1234\nrx_bytes=120\ntx_bytes=99\nerrno=0\n"
	got, err := parseAmneziaStatus([]byte(raw), w.Peers)
	if err != nil {
		t.Fatal(err)
	}
	v := got[peerID(w.Peers[0].PublicKey)]
	if v.Handshake != 1234 || v.RX != 120 || v.TX != 99 || v.Endpoint != "[2001:db8::1]:51820" {
		t.Fatal("safe peer fields missing")
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SECRET_") {
		t.Fatal("secret entered status")
	}
	for _, bad := range []string{strings.Replace(raw, key, keyHex(syntheticWGKey(99)), 1), strings.Replace(raw, "rx_bytes=120", "rx_bytes=SECRET_PRIVATE", 1)} {
		_, err = parseAmneziaStatus([]byte(bad), w.Peers)
		if err == nil || strings.Contains(err.Error(), "SECRET_") {
			t.Fatal("unsafe status error", err)
		}
	}
}

func TestWireGuardHealthRequiresAuthenticationAndDoesNotExpireIdleByAge(t *testing.T) {
	started := time.Unix(1000, 0)
	h := wgHealth{}
	updateWGHealth(&h, wgPeerObservation{}, started.Add(time.Second), started, 190*time.Second)
	if h.Ready {
		t.Fatal("link creation counted as authentication")
	}
	o := wgPeerObservation{Handshake: 1001, RX: 32}
	updateWGHealth(&h, o, started.Add(time.Second), started, 190*time.Second)
	h.Observation = o
	if !h.Ready {
		t.Fatal("handshake did not confirm peer")
	}
	check := started.Add(193 * time.Second)
	updateWGHealth(&h, o, check, started, 190*time.Second)
	if !h.Ready || h.CheckingAt.IsZero() {
		t.Fatal("idle peer must stay ready during explicit bounded check")
	}
	updateWGHealth(&h, o, check.Add(59*time.Second), started, 190*time.Second)
	if !h.Ready {
		t.Fatal("peer failed before check deadline")
	}
	updateWGHealth(&h, o, check.Add(61*time.Second), started, 190*time.Second)
	if h.Ready {
		t.Fatal("failed exchange did not protect peer routes")
	}
	o.Handshake = 1300
	o.RX = 64
	updateWGHealth(&h, o, time.Unix(1300, 0), started, 190*time.Second)
	if !h.Ready || !h.CheckingAt.IsZero() {
		t.Fatal("new handshake did not recover peer")
	}
	h = wgHealth{}
	updateWGHealth(&h, wgPeerObservation{Handshake: 999, RX: 100}, started.Add(time.Second), started, 190*time.Second)
	if h.Ready {
		t.Fatal("previous attempt handshake accepted")
	}
}

func TestWireGuardPeerRoutesStaySeparateDuringPartialFailure(t *testing.T) {
	s := &session{ID: "wg-test", Kind: "wireguard", Interface: "v443w00000001", Active: true, Order: 1, PeerPrefixes: map[string][]string{"a": {"10.0.0.0/8"}, "b": {"10.42.0.0/16"}}, PeerReady: map[string]bool{"a": true}, Routes: []route{{"10.0.0.0/8", ""}, {"10.42.0.0/16", ""}}, DNSServers: []string{"10.42.0.53"}}
	if !routeAvailable(s, "10.20.0.0/16") || routeAvailable(s, "10.42.1.2/32") || dnsAvailable(s) {
		t.Fatal("cryptokey longest prefix or DNS availability lost")
	}
	m := New(Config{}, nil)
	m.sessions[s.ID] = s
	m.rules = []workvpn.RouteRule{{CIDR: "10.0.0.0/8", Target: s.ID}}
	sel := m.choose(network.Snapshot{})
	guard := m.guard(network.Snapshot{}, network.Route{}, sel, false)
	deny := strings.Index(guard, `ip daddr 10.42.0.0/16 drop`)
	allow := strings.Index(guard, `ip daddr 10.0.0.0/8 oifname "v443w00000001" accept`)
	if deny < 0 || allow < 0 || deny > allow {
		t.Fatal("broad manual rule revived unavailable peer", guard)
	}
	s.PeerReady["b"] = true
	if !routeAvailable(s, "10.42.1.2/32") || !dnsAvailable(s) {
		t.Fatal("peer did not recover")
	}
}

func TestWireGuardSplitDefaultPeersRetainCoverageAndProtection(t *testing.T) {
	s := &session{ID: "wg-test", Kind: "wireguard", Active: true, Order: 1, PeerPrefixes: map[string][]string{"a": {"0.0.0.0/1"}, "b": {"128.0.0.0/1"}}, PeerReady: map[string]bool{"a": true, "b": true}, Routes: []route{{"0.0.0.0/1", ""}, {"128.0.0.0/1", ""}}}
	if !routeAllowed(s, "0.0.0.0/0") || !routeAvailable(s, "0.0.0.0/0") {
		t.Fatal("split default is not recognized")
	}
	routes := sessionRoutes(s)
	if len(routes) != 3 {
		t.Fatal("lost distinct peer routes or full-tunnel policy", routes)
	}
	s.PeerReady["b"] = false
	if routeAvailable(s, "128.0.0.0/1") || !routeAvailable(s, "0.0.0.0/1") {
		t.Fatal("partial failure disabled healthy half or exposed failed half")
	}
	m := New(Config{}, nil)
	m.sessions[s.ID] = s
	sel := m.choose(network.Snapshot{})
	blocked6 := false
	for _, r := range sel.routes {
		if r.cidr == "::/0" && !r.active {
			blocked6 = true
		}
	}
	if !blocked6 {
		t.Fatal("IPv4 full tunnel exposed IPv6")
	}
}

func TestWireGuardHealthyNarrowPeerSurvivesOfflineBroadPeerAndManualSelection(t *testing.T) {
	s := &session{ID: "wg-test", Kind: "wireguard", Interface: "v443w00000001", Active: true, Order: 1, PeerPrefixes: map[string][]string{"a": {"0.0.0.0/0"}, "b": {"10.42.0.0/16"}}, PeerReady: map[string]bool{"b": true}, Routes: []route{{"0.0.0.0/0", ""}, {"10.42.0.0/16", ""}}}
	m := New(Config{}, nil)
	m.sessions[s.ID] = s
	m.rules = []workvpn.RouteRule{{CIDR: "0.0.0.0/0", Target: s.ID}}
	sel := m.choose(network.Snapshot{})
	found := false
	for _, r := range sel.routes {
		if r.cidr == "10.42.0.0/16" && r.active && r.source == "manual" {
			found = true
		}
	}
	if !found {
		t.Fatal("manual full-profile choice blackholed its healthy more-specific peer")
	}
	guard := m.guard(network.Snapshot{}, network.Route{}, sel, false)
	allow := strings.Index(guard, "ip daddr 10.42.0.0/16 return")
	deny := strings.Index(guard, "ip daddr 0.0.0.0/0 drop")
	if allow < 0 || deny < 0 || allow > deny {
		t.Fatal("offline broad peer blocked healthy narrow peer", guard)
	}
	// An explicit local override remains the user's choice, not an inherited
	// child of a broader profile selection.
	m.rules = append(m.rules, workvpn.RouteRule{CIDR: "10.42.0.0/16", Target: "local"})
	sel = m.choose(network.Snapshot{})
	for _, r := range sel.routes {
		if r.cidr == "10.42.0.0/16" && r.target != "local" {
			t.Fatal("generated peer rule replaced explicit destination override")
		}
	}
}

func TestWireGuardTwoHalvesMustNotTieAnotherPeersDefault(t *testing.T) {
	s := &session{ID: "wg-test", Kind: "wireguard", Interface: "v443w00000001", Active: true, Order: 1, PeerPrefixes: map[string][]string{"a": {"0.0.0.0/0"}, "b": {"0.0.0.0/1", "128.0.0.0/1"}}, PeerReady: map[string]bool{"b": true}, Routes: []route{{"0.0.0.0/0", ""}, {"0.0.0.0/1", ""}, {"128.0.0.0/1", ""}}}
	for i := 0; i < 100; i++ {
		if !routeAvailable(s, "1.1.1.1/32") || !routeAvailable(s, "192.0.2.42/32") {
			t.Fatal("normalization made real default tie a more-specific peer")
		}
	}
	if len(sessionRoutes(s)) != 3 {
		t.Fatal("peer route prefixes were coalesced")
	}
	m := New(Config{}, nil)
	m.sessions[s.ID] = s
	m.rules = []workvpn.RouteRule{{CIDR: "0.0.0.0/0", Target: s.ID}}
	sel := m.choose(network.Snapshot{})
	count := 0
	for _, r := range sel.routes {
		p, _ := netip.ParsePrefix(r.cidr)
		if p.Addr().Is4() && p.Bits() == 1 && r.active && r.source == "manual" {
			count++
		}
	}
	if count != 2 {
		t.Fatal("explicit full-profile rule lost healthy halves")
	}
	guard := m.guard(network.Snapshot{}, network.Route{}, sel, false)
	deny := strings.Index(guard, "ip daddr 0.0.0.0/0 drop")
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		allow := strings.Index(guard, "ip daddr "+prefix+" return")
		if allow < 0 || allow > deny {
			t.Fatal("peer chain discarded cryptokey specificity")
		}
	}
}

func TestWireGuardManualRuleFailureIsNonMutating(t *testing.T) {
	m := New(Config{}, nil)
	s := &session{ID: "wg-test", Kind: "wireguard", PeerPrefixes: map[string][]string{"a": {"10.0.0.0/8"}}}
	m.sessions[s.ID] = s
	m.rules = []workvpn.RouteRule{{CIDR: "10.42.0.0/16", Target: s.ID}}
	before := append([]workvpn.RouteRule(nil), m.rules...)
	// The invalid WG rule must be checked even if a local rule precedes it;
	// this also proves no kernel collection/mutation occurs before rejection.
	if err := m.SetRules(context.Background(), []workvpn.RouteRule{{CIDR: "192.168.0.0/24", Target: "local"}, {CIDR: "198.51.100.0/24", Target: s.ID}}); err == nil {
		t.Fatal("accepted route outside AllowedIPs")
	}
	if !reflect.DeepEqual(before, m.rules) {
		t.Fatal("invalid rules changed committed state")
	}
	if err := m.SetDNSRules(context.Background(), []workvpn.DNSRule{{Domain: "corp.test", Target: s.ID}}); err == nil {
		t.Fatal("DNS target without a resolver accepted")
	}
}

func TestWireGuardProbeChoosesIntendedPeerAndChecksums(t *testing.T) {
	w := testWGProfile()
	w.Peers = append(w.Peers, workvpn.WireGuardPeer{PublicKey: syntheticWGKey(5), AllowedIPs: []string{"10.0.0.0/24"}})
	p, f, e := wireGuardProbePacket(w, w.Peers[0])
	if e != nil || f != 4 {
		t.Fatal(e)
	}
	dst := netip.AddrFrom4([4]byte(p[16:20]))
	if !netip.MustParsePrefix("10.0.0.0/8").Contains(dst) || netip.MustParsePrefix("10.0.0.0/24").Contains(dst) {
		t.Fatal("probe was stolen by more-specific peer", dst)
	}
	if internetChecksum(p[:20]) != 0 || len(p) != 28 {
		t.Fatal("invalid IPv4 probe")
	}
	w.Peers[0].AllowedIPs = []string{"fd42::/64"}
	p, f, e = wireGuardProbePacket(w, w.Peers[0])
	if e != nil || f != 6 || len(p) != 48 {
		t.Fatal("invalid IPv6 probe", e)
	}
	pseudo := make([]byte, 48)
	copy(pseudo, p[8:40])
	binary.BigEndian.PutUint32(pseudo[32:], 8)
	pseudo[39] = 17
	copy(pseudo[40:], p[40:])
	if internetChecksum(pseudo) != 0 {
		t.Fatal("invalid IPv6 UDP checksum")
	}
}

func TestWireGuardFullyShadowedPeerHasNonfatalProbeResult(t *testing.T) {
	w := testWGProfile()
	w.Peers[0].AllowedIPs = []string{"10.42.0.0/24"}
	w.Peers = append(w.Peers, workvpn.WireGuardPeer{PublicKey: syntheticWGKey(5), AllowedIPs: []string{"10.42.0.0/25", "10.42.0.128/25"}})
	if _, _, err := wireGuardProbePacket(w, w.Peers[0]); !errors.Is(err, errNoProbeDestination) {
		t.Fatal("fully shadowed peer must be unavailable, not a fatal backend failure", err)
	}
	if _, _, err := wireGuardProbePacket(w, w.Peers[1]); err != nil {
		t.Fatal("healthy covering peer cannot be probed", err)
	}
}

func TestWireGuardPathMTUAndOwnership(t *testing.T) {
	w := testWGProfile()
	w.MTU = 1420
	ep := []network.Endpoint{{Address: "2001:db8::1"}}
	if err := validateWGPathMTU(w, ep, 1500); err != nil {
		t.Fatal(err)
	}
	w.Parameters["S4"] = "12"
	if err := validateWGPathMTU(w, ep, 1500); err == nil || w.MTU != 1420 {
		t.Fatal("incompatible AWG overhead was ignored or MTU silently changed")
	}
	w.MTU = 1280
	if err := validateWGPathMTU(w, ep, 1500); err != nil {
		t.Fatal(err)
	}
	s := &session{ID: "wg-test", Kind: "wireguard"}
	if sessionLinkMatches(s, network.Link{Kind: "wireguard"}) || sessionLinkMatches(s, network.Link{Kind: "tun", Alias: "vault443:wg-test"}) || !sessionLinkMatches(s, network.Link{Kind: "wireguard", Alias: "vault443:wg-test"}) {
		t.Fatal("interface ownership check incorrect")
	}
}
