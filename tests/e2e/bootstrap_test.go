package e2e

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"vault443/internal/model"
	"vault443/internal/network"
)

func TestRealVLESSBootstrapFallbackAndCancellation(t *testing.T) {
	requireIsolated(t)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	// Blackhole DNS in the fixture namespace, so this reproduces the full two
	// seconds rather than receiving an immediate ICMP refusal from a closed port.
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "table", "inet", "bootstrap_test")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "chain", "inet", "bootstrap_test", "input", "{ type filter hook input priority 0; policy accept; }")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "rule", "inet", "bootstrap_test", "input", "udp", "dport", "53", "drop")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "rule", "inet", "bootstrap_test", "input", "tcp", "dport", "53", "drop")
	defer command(t, "ip", "netns", "exec", "fixture", "nft", "delete", "table", "inet", "bootstrap_test")
	p := localProfile(t)
	p.Server = "vpn-bootstrap.e2e.invalid"
	m := network.New(network.Config{StateDir: "/var/lib/vault443-e2e-bootstrap", RuntimeDir: "/run/vault443-e2e-bootstrap", XrayPath: "/usr/lib/vault443/xray"})
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = m.Disconnect(clean)
	}()
	var stages []string
	m.SetProgressHandler(func(status model.RuntimeStatus) {
		if len(stages) == 0 || stages[len(stages)-1] != status.Stage {
			stages = append(stages, status.Stage)
		}
		started := time.Now()
		_ = m.Status()
		_ = m.Diagnostics(context.Background())
		if time.Since(started) > 100*time.Millisecond {
			t.Error("status/diagnostics blocked inside an active network operation")
		}
	})
	start := time.Now()
	if err := m.Connect(ctx, p); err != nil {
		for _, args := range [][]string{{"nft", "list", "ruleset"}, {"ip", "-4", "rule", "show"}, {"ip", "-4", "route", "show", "table", "all"}, {"ip", "route", "get", "1.1.1.1", "mark", "0x564c5402"}} {
			output, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
			t.Logf("%v: %s", args, output)
		}
		t.Fatal("DNS/53 blocked but HTTPS fallback did not connect:", err)
	}
	if elapsed := time.Since(start); elapsed < 2*time.Second || elapsed > 12*time.Second {
		t.Fatalf("fallback/connect timing: %v", elapsed)
	}
	for _, expected := range []string{"checking_vpn", "enabling_guard", "resolving_endpoint", "starting_core", "configuring_network", "checking_connection", "connected"} {
		if !strings.Contains(strings.Join(stages, ","), expected) {
			t.Fatalf("missing progress %s in %v", expected, stages)
		}
	}
	response, err := request(ctx, "")
	if err != nil || response.Peer == "192.0.2.2" {
		t.Fatal("fallback connected without actual VLESS traffic", response, err)
	}
	fixtureLog, _ := os.ReadFile("/results/fixture.log")
	if !strings.Contains(string(fixtureLog), "bootstrap DoH vpn-bootstrap.e2e.invalid from 192.0.2.2:") {
		t.Fatal("bootstrap did not use physical fixed-IP HTTPS resolver")
	}
	assertBootstrapBlocked(t, ctx)
	t.Log("blocked DNS/53 → verified fixed-IP HTTPS → real VLESS succeeded; status/diagnostics remained readable")
	if err := m.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}

	p.Server = "missing-bootstrap.e2e.invalid"
	if err := m.Connect(ctx, p); err == nil || m.Status().FailureCode != "dns_not_found" || !m.Status().GuardArmed {
		t.Fatal("NXDOMAIN lost its reason or guard", err, m.Status())
	}
	assertBootstrapBlocked(t, ctx)
	if err := m.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("NXDOMAIN preserved the concrete reason and protection; Xray was not started")

	p.Server = "slow-bootstrap.e2e.invalid"
	attempt, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- m.Connect(attempt, p) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		fixtureLog, _ = os.ReadFile("/results/fixture.log")
		if strings.Contains(string(fixtureLog), "bootstrap DoH waiting for cancellation") {
			break
		}
		if time.Now().After(deadline) {
			stop()
			<-done
			t.Fatal("slow HTTPS fixture was never reached")
		}
		time.Sleep(20 * time.Millisecond)
	}
	start = time.Now()
	_ = m.Diagnostics(ctx)
	stop()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation became a network error", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("HTTPS cancellation waited for the DNS timeout")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("cancel or diagnostics blocked")
	}
	assertBootstrapBlocked(t, ctx)
	if err := m.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("in-flight HTTPS canceled immediately; guard remained armed until explicit cleanup")

	// Block HTTPS too: the attempt must remain bounded and preserve protection.
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "rule", "inet", "bootstrap_test", "input", "tcp", "dport", "443", "drop")
	p.Server = "vpn-bootstrap.e2e.invalid"
	start = time.Now()
	if err := m.Connect(ctx, p); err == nil || m.Status().FailureCode != "dns_timeout" || !m.Status().GuardArmed {
		t.Fatal("both resolvers unavailable did not fail safely", err, m.Status())
	}
	if time.Since(start) > 9*time.Second {
		t.Fatal("bootstrap exceeded total timeout")
	}
	assertBootstrapBlocked(t, ctx)
	if err := m.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("both DNS/53 and HTTPS blocked: bounded concrete timeout, no unprotected output")
}

func assertBootstrapBlocked(t *testing.T, ctx context.Context) {
	t.Helper()
	d := net.Dialer{Timeout: 150 * time.Millisecond, Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if e := raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "e2euplink")
		}); e != nil {
			return e
		}
		return err
	}}
	c, err := d.DialContext(ctx, "tcp4", "1.1.1.1:443")
	if err == nil {
		c.Close()
		t.Fatal("unmarked host traffic gained the bootstrap HTTPS exception")
	}
	if _, err := request(ctx, "e2euplink"); err == nil {
		t.Fatal("direct Internet escaped protection")
	}
	// The existing kernel frame-injection test exercises FORWARD at packet level;
	// also inspect the live E2E table so runtime policy cannot accidentally diverge.
	b, err := exec.CommandContext(ctx, "nft", "list", "chain", "inet", network.TableName, "forward_guard").Output()
	if err != nil || strings.Contains(string(b), "1.1.1.1") || strings.Contains(string(b), "meta mark") {
		t.Fatal("forwarded traffic inherited bootstrap exception", err)
	}
}
