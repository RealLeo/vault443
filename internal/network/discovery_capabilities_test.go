package network

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise /proc access against an independently privileged, real OpenVPN.
// Ordinary kernel tests run with equal capability sets and miss this failure.
func TestDiscoveryServiceCapabilities(t *testing.T) {
	if os.Getenv("VAULT443_KERNEL_TEST") != "1" {
		t.Skip("requires isolated Docker namespace")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("refusing non-Docker environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := execRunner{}
	s, err := collect(ctx, r)
	if err != nil || len(s.Links) != 1 || s.Links[0].Name != "lo" {
		t.Fatal("requires an empty network namespace", err)
	}
	for _, args := range [][]string{{"link", "add", "uplink0", "type", "dummy"}, {"addr", "add", "192.0.2.2/24", "dev", "uplink0"}, {"link", "set", "uplink0", "up"}} {
		if _, err := r.Run(ctx, command{Path: "/usr/sbin/ip", Args: args}); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	key, cert, config := filepath.Join(dir, "key"), filepath.Join(dir, "cert"), filepath.Join(dir, "config")
	if err := exec.CommandContext(ctx, "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=discovery.invalid", "-days", "1", "-keyout", key, "-out", cert).Run(); err != nil {
		t.Fatal(err)
	}
	// TLS server mode opens the TUN/socket without requiring an external peer.
	// Static-key mode is deliberately avoided: OpenVPN 2.7 removed it.
	if err := os.WriteFile(config, []byte("dev ovtest0\ndev-type tun\nifconfig 10.40.0.2 10.40.0.1\nproto udp\nremote 192.0.2.1 1194\ntls-server\nca "+cert+"\ncert "+cert+"\nkey "+key+"\ndh none\nverb 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	peer := exec.CommandContext(ctx, "/usr/sbin/openvpn", "--config", config)
	peer.Stdout, peer.Stderr = io.Discard, io.Discard
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Process.Kill(); _ = peer.Wait() }()
	for deadline := time.Now().Add(3 * time.Second); ; {
		if _, err := os.Stat("/sys/class/net/ovtest0"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real OpenVPN did not create its TUN")
		}
		time.Sleep(20 * time.Millisecond)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("VAULT443_PACKAGE_SOURCE")
	if source == "" {
		t.Fatal("missing read-only package sources")
	}
	for _, unit := range []string{"old-capabilities", "vault443.service", "vault443-guard.service"} {
		t.Run(unit, func(t *testing.T) {
			args := []string{"--bounding-set=-all,+net_admin,+net_raw,+net_bind_service", "--no-new-privs", binary, "-test.run=^TestDiscoveryCapabilityProbe$", "-test.v"}
			cmd := exec.CommandContext(ctx, "/usr/bin/setpriv", args...)
			expect := "0"
			if unit != "old-capabilities" {
				cmd = exec.CommandContext(ctx, "/usr/bin/python3", filepath.Join(source, "tests/service-sandbox-probe.py"), filepath.Join(source, "packaging", unit), binary, "-test.run=^TestDiscoveryCapabilityProbe$", "-test.v")
				expect = "1"
			}
			cmd.Env = append(os.Environ(), "VAULT443_DISCOVERY_CAPS_PROBE=1", "VAULT443_DISCOVERY_EXPECT="+expect)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("service capability probe failed: %v\n%s", err, out)
			}
			t.Log(strings.TrimSpace(string(out)))
		})
	}
}

func TestDiscoveryCapabilityProbe(t *testing.T) {
	if os.Getenv("VAULT443_DISCOVERY_CAPS_PROBE") != "1" {
		t.Skip("private child probe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := execRunner{}
	s, err := collect(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := automaticBindings(ctx, r, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, binding := range bindings {
		for _, ep := range binding.Endpoints {
			if binding.Interface == "ovtest0" && binding.Manager == "openvpn" && ep.Address == "192.0.2.1" && ep.Port == 1194 && ep.Protocol == "udp" {
				found = true
			}
		}
	}
	if found != (os.Getenv("VAULT443_DISCOVERY_EXPECT") == "1") {
		t.Fatalf("verified OpenVPN TUN/transport found=%v", found)
	}
	// The UI endpoint uses the same verified process metadata while disconnected.
	// This probe runs under the actual service capability/seccomp sandbox.
	m := New(Config{StateDir: filepath.Join(t.TempDir(), "absent"), RuntimeDir: filepath.Join(t.TempDir(), "run")})
	before, _ := json.Marshal(s)
	report := m.VPNCompatibility(ctx)
	item := compatibilityItem(t, report, "ovtest0")
	if item.Verified != found || item.Active != true || (found && item.Source != "automatic") || (!found && item.Source != "unknown") {
		t.Fatalf("compatibility verification differs from controller: %+v", report)
	}
	after, err := collect(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(after)
	if string(before) != string(encoded) || m.loaded || m.Status().GuardArmed || m.Status().State != "disconnected" || len(m.commands) != 0 {
		t.Fatal("read-only compatibility changed networking or runtime state")
	}
	if _, err := os.Stat(m.config.StateDir); !os.IsNotExist(err) {
		t.Fatal("read-only compatibility wrote persistent state")
	}
}
