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
	"strings"
	"syscall"
	"testing"
	"time"

	"vault443/internal/model"
	"vault443/internal/network"
	"vault443/internal/profiles"
)

// Runs with real unprivileged socket credentials, a normal system-resolver
// request and no SO_BINDTODEVICE/SO_MARK or proxy. The parent alone owns TUN.
func TestRealVLESSBrowserProcess(t *testing.T) {
	if os.Getenv("VAULT443_E2E_BROWSER_CHILD") != "1" {
		t.Skip("unprivileged browser-path subprocess helper")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Getenv("VAULT443_E2E_ISOLATED") != "1" {
		t.Fatal("browser helper requires isolated disposable container")
	}
	for _, host := range []string{"web.e2e.example.com", "web6.e2e.example.com"} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			for _, http2 := range []bool{false, true} {
				for _, path := range []string{"/", "/large"} {
					t.Run(fmt.Sprintf("uid%d/%s/tls%x/h2-%v%s", os.Geteuid(), host, version, http2, path), func(t *testing.T) {
						resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
							return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.53:53")
						}}
						dialer := &net.Dialer{Timeout: 3 * time.Second, Resolver: resolver}
						transport := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{MinVersion: version, MaxVersion: version}, ForceAttemptHTTP2: http2, DisableKeepAlives: true}
						defer transport.CloseIdleConnections()
						client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
						response, err := client.Get("https://" + host + path)
						if err != nil {
							t.Fatal(err)
						}
						defer response.Body.Close()
						if (response.ProtoMajor == 2) != http2 {
							t.Fatalf("unexpected negotiated HTTP protocol: %s", response.Proto)
						}
						var body struct{ Marker, Peer, Payload string }
						if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&body); err != nil {
							t.Fatal(err)
						}
						if response.StatusCode != 200 || body.Marker != "vless-e2e-ok" || body.Peer == "192.0.2.2" {
							t.Fatalf("response did not traverse VLESS: status=%d marker=%q peer=%q", response.StatusCode, body.Marker, body.Peer)
						}
						if path == "/large" && body.Payload != strings.Repeat("vless-browser-payload-", 32768) {
							t.Fatalf("large TLS payload corrupted/truncated: %d bytes", len(body.Payload))
						}
					})
				}
			}
		}
	}
}

func TestRealVLESSBrowserHTTPS(t *testing.T) {
	requireIsolated(t)
	link, err := os.ReadFile("/fixture/reality.uri")
	if err != nil {
		t.Fatal(err)
	}
	reality, err := profiles.Parse(strings.Replace(strings.TrimSpace(string(link)), "fp=chrome", "fp=firefox", 1))
	if err != nil {
		t.Fatal("invalid local REALITY fixture")
	}
	for _, profile := range []model.Profile{localProfile(t), reality} {
		t.Run(profile.Security, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			profile.DebugLogging = true
			dir := "/var/lib/vault443-e2e-browser-" + profile.Security
			manager := network.New(network.Config{StateDir: dir, RuntimeDir: "/run/vault443-e2e-browser-" + profile.Security, XrayPath: "/usr/lib/vault443/xray"})
			openConnectionJournal(t, dir+"/journal", manager, profile, 1000)
			defer func() {
				cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
				defer done()
				if err := manager.Disconnect(cleanup); err != nil {
					t.Error(err)
				}
			}()
			if err := manager.Connect(ctx, profile); err != nil {
				t.Fatal(err)
			}
			for _, uid := range []uint32{0, 1000} {
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				child := exec.CommandContext(ctx, executable, "-test.v", "-test.run=^TestRealVLESSBrowserProcess$", "-test.timeout=75s")
				child.Env = append(os.Environ(), "VAULT443_E2E_BROWSER_CHILD=1")
				child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
				output, err := child.CombinedOutput()
				t.Logf("ordinary HTTPS process UID %d:\n%s", uid, output)
				if err != nil {
					t.Fatalf("browser traffic with UID %d failed: %v", uid, err)
				}
			}
		})
	}
}

// DNS is handled by Xray's internal HTTPS client. A successful answer must not
// make the application report connected when ordinary TUN HTTPS is blackholed.
func TestRealVLESSRejectsDNSOnlyReadiness(t *testing.T) {
	requireIsolated(t)
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "table", "inet", "browser_readiness_test")
	defer command(t, "ip", "netns", "exec", "fixture", "nft", "delete", "table", "inet", "browser_readiness_test")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "chain", "inet", "browser_readiness_test", "input", "{ type filter hook input priority 0; policy accept; }")
	command(t, "ip", "netns", "exec", "fixture", "nft", "add", "rule", "inet", "browser_readiness_test", "input", "ip", "daddr", "93.184.215.14", "tcp", "dport", "443", "drop")
	manager := network.New(network.Config{StateDir: "/var/lib/vault443-e2e-dns-only", RuntimeDir: "/run/vault443-e2e-dns-only", XrayPath: "/usr/lib/vault443/xray"})
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := manager.Disconnect(cleanup); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	err := manager.Connect(ctx, localProfile(t))
	// Independent system-resolver lookup demonstrates that the old DNS-only
	// health check still succeeds in precisely this failure scenario.
	if dns := command(t, "resolvectl", "query", "example.com"); !strings.Contains(dns, "93.184.215.14") {
		t.Fatalf("DNS did not stay available in isolated HTTPS failure: %s", dns)
	}
	if err == nil || manager.Status().State == "connected" {
		t.Fatal("DNS-only readiness falsely accepted a tunnel with unavailable web HTTPS")
	}
	if !manager.Status().GuardArmed {
		t.Fatal("HTTPS readiness failure disabled protection")
	}
	if manager.Status().State != "error" || manager.Status().FailureCode != "vpn_https_timeout" {
		t.Fatalf("HTTPS blackhole should expose a timeout failure: %+v", manager.Status())
	}
	t.Logf("DNS succeeded while web HTTPS failed; connection correctly rejected: %v", err)
	command(t, "ip", "netns", "exec", "fixture", "nft", "flush", "chain", "inet", "browser_readiness_test", "input")
	if err = manager.Connect(ctx, localProfile(t)); err != nil || manager.Status().State != "connected" {
		t.Fatalf("HTTPS readiness did not recover after removing the block: %v, %+v", err, manager.Status())
	}
	t.Log("HTTPS restored: the next connection attempt completed successfully")
}
