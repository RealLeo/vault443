package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"vault443/internal/workvpn"
)

func requireWireGuardFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("VAULT443_WIREGUARD_E2E") != "1" {
		t.Skip("requires isolated synthetic WireGuard/AmneziaWG servers")
	}
	requireWorkIsolated(t)
}

func wgProfile(t *testing.T, file string, transform func(string) string) workvpn.Profile {
	t.Helper()
	b, err := os.ReadFile("/fixture/wireguard/" + file + ".conf")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if transform != nil {
		s = transform(s)
	}
	profiles, err := workvpn.ParseWork("Isolated "+file, s)
	if err != nil || len(profiles) != 1 {
		t.Fatalf("synthetic WG profile validation failed: %v", err)
	}
	return profiles[0]
}

func TestRealWireGuardAlongsideAmneziaAndVLESS(t *testing.T) {
	requireWireGuardFixture(t)
	for _, first := range []bool{false, true} {
		t.Run(fmt.Sprintf("VLESSFirst=%v", first), func(t *testing.T) {
			h := newWorkHarness(t)
			wg, awg := wgProfile(t, "client-1", nil), wgProfile(t, "client-2", nil)
			if first {
				if err := h.n.Connect(h.ctx, localProfile(t)); err != nil {
					t.Fatal(err)
				}
			}
			h.start(wg)
			h.waitConnected(wg.ID)
			h.start(awg)
			h.waitConnected(awg.ID)
			if !first {
				if err := h.n.Connect(h.ctx, localProfile(t)); err != nil {
					h.dump()
					t.Fatal(err)
				}
			}
			if err := h.n.Reconcile(h.ctx); err != nil {
				h.dump()
				t.Fatal(err)
			}
			h.assertWork("192.168.100.15", "10.80.")
			h.assertWork("10.42.0.15", "10.81.")
			h.assertWork("2001:db8:100::15", "2001:db8:80:")
			if reply, err := workDockerHTTP(h.ctx, "192.168.100.15"); err != nil || !strings.HasPrefix(reply.Peer, "10.80.") {
				h.dump()
				t.Fatalf("Docker failed to use WireGuard: %+v %v", reply, err)
			}
			for _, zone := range []string{"wg1", "wg2"} {
				out := command(t, "resolvectl", "query", "--type=A", "host."+zone+".e2e.test")
				if !strings.Contains(out, "192.168.100.15") && !strings.Contains(out, "10.42.0.15") {
					t.Fatal("WG split DNS failed:", out)
				}
			}
			if _, err := workHTTP(h.ctx, "192.168.100.15", "e2euplink"); err == nil {
				t.Fatal("physical bypass escaped WG protection")
			}
			if err := h.n.Disconnect(h.ctx); err != nil {
				t.Fatal(err)
			}
			h.assertWork("192.168.100.15", "10.80.")
			h.assertWork("10.42.0.15", "10.81.")
			h.stop(awg.ID)
			op := workProfile(t, 2, "")
			h.start(op)
			h.waitConnected(op.ID)
			h.assertWork("10.42.0.15", "10.71.")
			h.assertWork("192.168.100.15", "10.80.")
			h.stop(wg.ID)
			h.assertWork("10.42.0.15", "10.71.")
		})
	}
}

func TestRealWireGuardFullTunnelAndIPv6Endpoint(t *testing.T) {
	requireWireGuardFixture(t)
	for _, source := range []string{"client-1", "client-2"} {
		t.Run(source, func(t *testing.T) {
			h := newWorkHarness(t)
			if err := h.n.Connect(h.ctx, localProfile(t)); err != nil {
				t.Fatal(err)
			}
			p := wgProfile(t, source, func(s string) string {
				lines := strings.Split(s, "\n")
				for i, line := range lines {
					if strings.HasPrefix(line, "AllowedIPs =") {
						lines[i] = "AllowedIPs = 0.0.0.0/0, ::/0"
					}
				}
				return strings.ReplaceAll(strings.Join(lines, "\n"), "Endpoint = 192.0.2.1:", "Endpoint = [2001:db8:2::1]:")
			})
			h.start(p)
			h.waitConnected(p.ID)
			if err := h.n.Reconcile(h.ctx); err != nil {
				h.dump()
				t.Fatal(err)
			}
			if h.n.Status().State != "paused_external" {
				h.dump()
				t.Fatal("full WG tunnel did not pause VLESS")
			}
			prefix := "10.80."
			if source == "client-2" {
				prefix = "10.81."
			}
			internet, err := request(h.ctx, "")
			if err != nil || !strings.HasPrefix(internet.Peer, prefix) {
				h.dump()
				t.Fatalf("full WG Internet failed: %+v %v", internet, err)
			}
			if _, err := request(h.ctx, "e2euplink"); err == nil {
				t.Fatal("full tunnel allowed physical bypass")
			}
			h.stop(p.ID)
			_ = h.n.Reconcile(h.ctx)
			if err := h.n.Connect(h.ctx, localProfile(t)); err != nil {
				h.dump()
				t.Fatal(err)
			}
		})
	}
}

func TestRealWireGuardPartialPeersAndCancellation(t *testing.T) {
	requireWireGuardFixture(t)
	h := newWorkHarness(t)
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "table", "inet", "wg_failure")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "chain", "inet", "wg_failure", "input", "{ type filter hook input priority -100; policy accept; }")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "rule", "inet", "wg_failure", "input", "udp", "dport", "51822", "drop")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "fixture", "nft", "delete", "table", "inet", "wg_failure").Run()
	})
	p := wgProfile(t, "multi", nil)
	h.start(p)
	partial := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		if h.w.Snapshot(p.ID).State == "partial" {
			partial = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !partial {
		h.dump()
		t.Fatalf("partial peers not reported: %+v", h.w.Snapshot(p.ID))
	}
	h.assertWork("192.168.100.15", "10.80.")
	if _, err := workHTTP(h.ctx, "10.42.0.15", ""); err == nil {
		t.Fatal("unavailable peer fell through to another path")
	}
	if _, err := workHTTP(h.ctx, "10.42.0.15", "e2euplink"); err == nil {
		t.Fatal("unavailable peer leaked directly")
	}
	command(t, "ip", "netns", "exec", "fixture", "nft", "flush", "chain", "inet", "wg_failure", "input")
	h.waitConnected(p.ID)
	h.assertWork("10.42.0.15", "10.80.")
	run := h.running[p.ID]
	run.cancel()
	select {
	case err := <-run.done:
		run.done <- err
	case <-time.After(5 * time.Second):
		t.Fatal("WG cancellation stalled")
	}
	for _, address := range []string{"192.168.100.15", "10.42.0.15", "2001:db8:100::15"} {
		if _, err := workHTTP(h.ctx, address, ""); err == nil {
			t.Fatal("canceled WG leaked destination", address)
		}
	}
	h.stop(p.ID)
}

func TestRealWireGuardNoHandshakeNeverConnected(t *testing.T) {
	requireWireGuardFixture(t)
	for _, mode := range []string{"unreachable", "wrong-psk"} {
		t.Run(mode, func(t *testing.T) {
			h := newWorkHarness(t)
			p := wgProfile(t, "client-1", func(s string) string {
				if mode == "unreachable" {
					return strings.ReplaceAll(s, ":51820", ":51829")
				}
				lines := strings.Split(s, "\n")
				for i, line := range lines {
					if strings.HasPrefix(line, "PresharedKey =") {
						// A valid, independent synthetic PSK must never authenticate.
						lines[i] = "PresharedKey = " + strings.TrimSpace(command(t, "wg", "genpsk"))
					}
				}
				return strings.Join(lines, "\n")
			})
			h.start(p)
			for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
				state := h.w.Snapshot(p.ID)
				if state.State == "connected" || state.State == "partial" {
					t.Fatal("false connection without handshake")
				}
				time.Sleep(100 * time.Millisecond)
			}
			for _, address := range []string{"192.168.100.15", "2001:db8:100::15"} {
				if _, err := workHTTP(h.ctx, address, "e2euplink"); err == nil {
					t.Fatal("unauthenticated tunnel allowed physical bypass")
				}
			}
			start := time.Now()
			h.stop(p.ID)
			if time.Since(start) > 3*time.Second {
				t.Fatal("cancel waited for handshake timeout")
			}
		})
	}
}

func TestRealWireGuardRejectedRulesLeaveConnectivity(t *testing.T) {
	requireWireGuardFixture(t)
	h := newWorkHarness(t)
	p := wgProfile(t, "client-1", nil)
	h.start(p)
	h.waitConnected(p.ID)
	rule, err := workvpn.NewRouteRule("198.51.100.0/24", p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.w.SetRules(h.ctx, []workvpn.RouteRule{rule}); err == nil {
		t.Fatal("rule outside AllowedIPs accepted")
	}
	h.assertWork("192.168.100.15", "10.80.")
	ctx, cancel := context.WithTimeout(h.ctx, 2*time.Second)
	defer cancel()
	if _, err = workHTTP(ctx, "192.168.100.15", "e2euplink"); err == nil {
		t.Fatal("rejected rule damaged guard")
	}
}

func TestRealWireGuardAmneziaGenerationsAndProcessFailure(t *testing.T) {
	requireWireGuardFixture(t)
	for _, number := range []int{4, 5, 2} {
		t.Run(fmt.Sprintf("Server%d", number), func(t *testing.T) {
			h := newWorkHarness(t)
			p := wgProfile(t, fmt.Sprintf("client-%d", number), nil)
			h.start(p)
			h.waitConnected(p.ID)
			prefix := map[int]string{4: "10.83.", 5: "10.84.", 2: "10.81."}[number]
			h.assertWork("10.42.0.15", prefix)
			iface := h.w.Snapshot(p.ID).Interface
			command(t, "pkill", "-KILL", "-f", "^/usr/lib/vault443/amneziawg-go (--foreground|-f) "+iface+"$")
			run := h.running[p.ID]
			select {
			case err := <-run.done:
				run.done <- err
			case <-time.After(8 * time.Second):
				t.Fatal("AWG process exit was not observed")
			}
			if _, err := workHTTP(h.ctx, "10.42.0.15", "e2euplink"); err == nil {
				t.Fatal("AWG crash released destination protection")
			}
			run.cancel()
			h.start(p) // A fresh attempt must reuse the protected persistent TUN safely.
			h.waitConnected(p.ID)
			h.assertWork("10.42.0.15", prefix)
		})
	}
}

func TestRealWireGuardIdleAndEstablishedPeerFailure(t *testing.T) {
	requireWireGuardFixture(t)
	h := newWorkHarness(t)
	p := wgProfile(t, "client-2", func(s string) string {
		s = strings.Replace(s, "[Peer]", "RejectAfterTime = 10\nRekeyAfterTime = 5\nRekeyTimeout = 1\nMaxHandshakeAttempts = 10\n[Peer]", 1)
		return strings.ReplaceAll(s, "PersistentKeepalive = 1", "PersistentKeepalive = 0")
	})
	h.start(p)
	h.waitConnected(p.ID)
	initial := h.w.Snapshot(p.ID).Peers[0].LastHandshakeAt
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); {
		if h.w.Snapshot(p.ID).State != "connected" {
			h.dump()
			t.Fatal("idle tunnel was incorrectly treated as disconnected")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if h.w.Snapshot(p.ID).Peers[0].LastHandshakeAt <= initial {
		t.Fatal("idle health exchange did not refresh the expired key")
	}
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "table", "inet", "wg_health_failure")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "chain", "inet", "wg_health_failure", "input", "{ type filter hook input priority -100; policy accept; }")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "rule", "inet", "wg_health_failure", "input", "udp", "dport", "51821", "drop")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "chain", "inet", "wg_health_failure", "output", "{ type filter hook output priority -100; policy accept; }")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "rule", "inet", "wg_health_failure", "output", "udp", "sport", "51821", "drop")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "fixture", "nft", "delete", "table", "inet", "wg_health_failure").Run()
	})
	failed := false
	for end := time.Now().Add(95 * time.Second); time.Now().Before(end); {
		if h.w.Snapshot(p.ID).State == "reconnecting" {
			failed = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !failed {
		h.dump()
		t.Fatal("established peer outage was never reported")
	}
	if _, err := workHTTP(h.ctx, "10.42.0.15", ""); err == nil {
		t.Fatal("unavailable established peer leaked its route")
	}
	command(t, "ip", "netns", "exec", "fixture", "nft", "flush", "chain", "inet", "wg_health_failure", "input")
	command(t, "ip", "netns", "exec", "fixture", "nft", "flush", "chain", "inet", "wg_health_failure", "output")
	h.waitConnected(p.ID)
	h.assertWork("10.42.0.15", "10.81.")
}

// A broad, unavailable peer must not hide the healthy peer's two more-specific
// half-defaults, including when an explicit rule selects the whole profile.
func TestRealWireGuardHealthySpecificPeerOverridesOfflineDefault(t *testing.T) {
	requireWireGuardFixture(t)
	h := newWorkHarness(t)
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "table", "inet", "wg_overlap")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "chain", "inet", "wg_overlap", "input", "{ type filter hook input priority -100; policy accept; }")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "rule", "inet", "wg_overlap", "input", "udp", "dport", "51820", "drop")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", "fixture", "nft", "delete", "table", "inet", "wg_overlap").Run()
	})
	p := wgProfile(t, "multi", func(s string) string {
		lines, peer := strings.Split(s, "\n"), 0
		for i, line := range lines {
			if strings.HasPrefix(line, "[Peer]") {
				peer++
			}
			if strings.HasPrefix(line, "AllowedIPs =") {
				if peer == 1 {
					lines[i] = "AllowedIPs = 0.0.0.0/0"
				} else {
					lines[i] = "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1"
				}
			}
			if strings.HasPrefix(line, "DNS =") {
				lines[i] = ""
			}
		}
		return strings.Join(lines, "\n")
	})
	h.start(p)
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end) && h.w.Snapshot(p.ID).State != "partial"; {
		time.Sleep(100 * time.Millisecond)
	}
	if h.w.Snapshot(p.ID).State != "partial" {
		h.dump()
		t.Fatal("healthy specific peer did not remain available")
	}
	h.assertWork("10.42.0.15", "10.80.")
	rule, err := workvpn.NewRouteRule("0.0.0.0/0", p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.w.SetRules(h.ctx, []workvpn.RouteRule{rule}); err != nil {
		t.Fatal(err)
	}
	h.assertWork("10.42.0.15", "10.80.")
	if _, err := workHTTP(h.ctx, "10.42.0.15", "e2euplink"); err == nil {
		t.Fatal("overlapping peer route leaked physically")
	}
}

func TestRealWireGuardUnderlayChangeRequiresFreshHandshake(t *testing.T) {
	requireWireGuardFixture(t)
	for _, source := range []string{"client-1", "client-2"} {
		t.Run(source, func(t *testing.T) {
			h := newWorkHarness(t)
			p := wgProfile(t, source, nil)
			h.start(p)
			h.waitConnected(p.ID)
			before := h.w.Snapshot(p.ID).Peers[0].LastHandshakeAt
			command(t, "ip", "link", "set", "dev", "e2euplink", "name", "e2umoved")
			t.Cleanup(func() { _ = exec.Command("ip", "link", "set", "dev", "e2umoved", "name", "e2euplink").Run() })
			fresh := false
			for end := time.Now().Add(20 * time.Second); time.Now().Before(end); {
				s := h.w.Snapshot(p.ID)
				if s.State == "connected" && len(s.Peers) == 1 && s.Peers[0].LastHandshakeAt > before {
					fresh = true
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if !fresh {
				h.dump()
				t.Fatal("underlay change did not revalidate with a fresh handshake")
			}
			address, prefix := "192.168.100.15", "10.80."
			if source == "client-2" {
				address, prefix = "10.42.0.15", "10.81."
			}
			h.assertWork(address, prefix)
			if _, err := workHTTP(h.ctx, address, "e2umoved"); err == nil {
				t.Fatal("changed underlay bypassed guard")
			}
		})
	}
}
