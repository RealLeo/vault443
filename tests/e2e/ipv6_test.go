package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"vault443/internal/network"
	"vault443/internal/profiles"
)

// These are real unprivileged browser-like sockets. In particular, the IPv6
// regression must fail during TCP connect, before gVisor can acknowledge a SYN
// whose remote IPv6 connection will later close during the TLS handshake.
func TestRealVLESSIPv6BrowserProcess(t *testing.T) {
	state := os.Getenv("VAULT443_E2E_IPV6_BROWSER_STATE")
	if state == "" {
		t.Skip("unprivileged IPv6 fallback subprocess helper")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Getenv("VAULT443_E2E_ISOLATED") != "1" || os.Geteuid() != 1000 {
		t.Fatal("IPv6 browser helper requires UID 1000 in an isolated disposable container")
	}
	if state != "available" && state != "unavailable" && state != "legacy" {
		t.Fatal("invalid expected IPv6 state")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.53:53")
	}}
	// Verify that DNS has not hidden AAAA answers to manufacture fallback.
	addresses, err := resolver.LookupIPAddr(ctx, "webdual.e2e.example.com")
	if err != nil {
		t.Fatal(err)
	}
	seen4, seen6 := false, false
	for _, address := range addresses {
		seen4 = seen4 || address.IP.String() == "93.184.215.14"
		seen6 = seen6 || address.IP.String() == "2001:db8:66::14"
	}
	if !seen4 || !seen6 {
		t.Fatalf("dual-stack fixture did not retain both A and AAAA: %v", addresses)
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second, Resolver: resolver}
	started := time.Now()
	connection, err := dialer.DialContext(ctx, "tcp6", "[2001:db8:66::14]:443")
	elapsed := time.Since(started)
	if state == "legacy" {
		if err != nil {
			t.Fatalf("legacy TUN behavior did not complete the misleading IPv6 TCP handshake: %v", err)
		}
		defer connection.Close()
		tlsConnection := tls.Client(connection, &tls.Config{ServerName: "web6.e2e.example.com", MinVersion: tls.VersionTLS12})
		handshake, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		if err := tlsConnection.HandshakeContext(handshake); err == nil {
			t.Fatal("fixture IPv6 exit block did not fail the verified TLS handshake")
		} else {
			t.Logf("legacy behavior reproduced: IPv6 TCP connect accepted in %v, then TLS failed: %v", elapsed, err)
		}
		return
	}
	if connection != nil {
		connection.Close()
	}
	if state == "unavailable" {
		if err == nil {
			t.Fatal("unavailable IPv6 completed TCP connect; browser fallback would be defeated by a false TUN SYN-ACK")
		}
		if elapsed >= time.Second {
			t.Fatalf("unavailable IPv6 was not rejected promptly: %v after %v", err, elapsed)
		}
		t.Logf("unavailable IPv6 rejected before TLS in %v: %v", elapsed, err)
	} else if err != nil {
		t.Fatalf("working IPv6 was blocked: %v", err)
	}
	hosts := []string{"web.e2e.example.com", "webdual.e2e.example.com"}
	if state == "available" {
		hosts = append(hosts, "web6.e2e.example.com")
	}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			var destination string
			transport := &http.Transport{
				Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2: true, DisableKeepAlives: true,
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					connection, err := dialer.DialContext(ctx, network, address)
					if err == nil {
						destination = connection.RemoteAddr().String()
					}
					return connection, err
				},
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, err := client.Get("https://" + host + "/large")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var body struct{ Marker, Peer, Payload string }
			if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 || response.ProtoMajor != 2 || body.Marker != "vless-e2e-ok" || body.Peer == "192.0.2.2" || body.Payload != strings.Repeat("vless-browser-payload-", 32768) {
				t.Fatalf("verified HTTP/2 response did not traverse VLESS intact: status=%d protocol=%s marker=%q peer=%q size=%d", response.StatusCode, response.Proto, body.Marker, body.Peer, len(body.Payload))
			}
			if state == "unavailable" && destination != "93.184.215.14:443" {
				t.Fatalf("unavailable IPv6 did not fall back to fixture IPv4: %s", destination)
			}
			t.Logf("UID 1000 HTTPS %s used %s and read %d bytes through VLESS", host, destination, len(body.Payload))
		})
	}
}

func runIPv6Browser(t *testing.T, ctx context.Context, state string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, executable, "-test.v", "-test.run=^TestRealVLESSIPv6BrowserProcess$", "-test.timeout=20s")
	child.Env = append(os.Environ(), "VAULT443_E2E_IPV6_BROWSER_STATE="+state)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	output, err := child.CombinedOutput()
	t.Logf("ordinary browser IPv6 %s:\n%s", state, output)
	if err != nil {
		t.Fatalf("ordinary browser IPv6 %s failed: %v", state, err)
	}
}

func assertIPv6State(t *testing.T, manager *network.Manager, state string) {
	t.Helper()
	diagnostics, ok := manager.Diagnostics(context.Background()).(map[string]any)
	if !ok || diagnostics["ipv6State"] != state {
		t.Fatalf("IPv6 diagnostics did not report %s: %v", state, diagnostics)
	}
	if status := manager.Status(); status.State != "connected" || !status.GuardArmed {
		t.Fatalf("IPv6 capability assessment broke the protected IPv4 connection: %+v", status)
	}
}

func demonstrateLegacyIPv6Acknowledgment(t *testing.T, ctx context.Context) {
	t.Helper()
	// Reproduce the old unconditional TUN acceptance only for this local test
	// fixture and its unprivileged process. The physical-interface guard stays
	// intact. This establishes why a successful TCP connect can defeat browser
	// Happy Eyeballs even though an eventual TLS handshake fails.
	const comment = "vlt-e2e-legacy-ipv6"
	command(t, "nft", "insert", "rule", "inet", network.TableName, "output_guard", "meta", "skuid", "1000", "ip6", "daddr", "2001:db8:66::14", "oifname", network.TunName, "tcp", "dport", "443", "accept", "comment", comment)
	var listing struct {
		Objects []struct {
			Rule *struct {
				Handle  int    `json:"handle"`
				Comment string `json:"comment"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(command(t, "nft", "-j", "list", "chain", "inet", network.TableName, "output_guard")), &listing); err != nil {
		t.Fatal(err)
	}
	handle := 0
	for _, object := range listing.Objects {
		if object.Rule != nil && object.Rule.Comment == comment {
			handle = object.Rule.Handle
		}
	}
	if handle == 0 {
		t.Fatal("legacy fixture-only exception handle missing")
	}
	defer command(t, "nft", "delete", "rule", "inet", network.TableName, "output_guard", "handle", strconv.Itoa(handle))
	runIPv6Browser(t, ctx, "legacy")
}

func TestRealVLESSIPv6UnavailableFallback(t *testing.T) {
	requireIsolated(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	uri, err := os.ReadFile("/fixture/reality.uri")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := profiles.Parse(strings.Replace(strings.TrimSpace(string(uri)), "fp=chrome", "fp=firefox", 1))
	if err != nil {
		t.Fatal("invalid isolated REALITY profile")
	}
	profile.DebugLogging = true
	manager := network.New(network.Config{StateDir: "/var/lib/vault443-e2e-ipv6", RuntimeDir: "/run/vault443-e2e-ipv6", XrayPath: "/usr/lib/vault443/xray"})
	openConnectionJournal(t, "/var/lib/vault443-e2e-ipv6/journal", manager, profile, 1000)
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if err := manager.Disconnect(cleanup); err != nil {
			t.Error(err)
		}
	}()
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "table", "inet", "ipv6_exit_test")
	defer command(t, "ip", "netns", "exec", "fixture", "nft", "delete", "table", "inet", "ipv6_exit_test")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "chain", "inet", "ipv6_exit_test", "output", "{ type filter hook output priority 0; policy accept; }")
	blockExit := func() {
		command(t, "ip", "netns", "exec", "fixture", "nft", "add", "rule", "inet", "ipv6_exit_test", "output", "ip6", "daddr", "2001:db8:66::14", "tcp", "dport", "443", "reject", "with", "tcp", "reset")
	}
	restoreExit := func() {
		command(t, "ip", "netns", "exec", "fixture", "nft", "flush", "chain", "inet", "ipv6_exit_test", "output")
	}
	blockExit()
	if err := manager.Connect(ctx, profile); err != nil {
		t.Fatal(err)
	}
	assertIPv6State(t, manager, "unavailable")
	demonstrateLegacyIPv6Acknowledgment(t, ctx)
	runIPv6Browser(t, ctx, "unavailable")
	if _, err := request(ctx, "e2euplink"); err == nil {
		t.Fatal("IPv6 fallback opened a direct physical-interface IPv4 bypass")
	}
	t.Log("IPv4 remains connected with IPv6 rejected before TCP; normal dual-stack browser requests fall back without bypassing VLESS")
	restoreExit()
	if err := manager.Connect(ctx, profile); err != nil {
		t.Fatal(err)
	}
	assertIPv6State(t, manager, "available")
	runIPv6Browser(t, ctx, "available")
	t.Log("reconnection rechecked IPv6 and restored ordinary IPv6 HTTPS")
	blockExit()
	// Exercise the production periodic probe without a test-only clock or
	// interval knob. IPv4 connectivity remains live throughout this wait.
	timer := time.NewTimer(31 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	if err := manager.Reconcile(ctx); err != nil {
		t.Fatal(fmt.Errorf("IPv6 degradation must not disconnect healthy IPv4: %w", err))
	}
	assertIPv6State(t, manager, "unavailable")
	runIPv6Browser(t, ctx, "unavailable")
	t.Log("periodic probe detected IPv6-only degradation while preserving the connected IPv4 tunnel")
}
