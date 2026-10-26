package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"vault443/internal/model"
)

type compatibilityRunner struct {
	s          Snapshot
	commands   []command
	failedPath string
	started    chan struct{}
	release    chan struct{}
}

func (r *compatibilityRunner) Run(ctx context.Context, c command) ([]byte, error) {
	r.commands = append(r.commands, c)
	if r.started != nil {
		close(r.started)
		r.started = nil
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.Path == r.failedPath {
		return nil, errors.New("private config argument credential must not escape")
	}
	args := strings.Join(c.Args, " ")
	switch c.Path {
	case "/usr/sbin/ip":
		if args == "-j -d address show" {
			links := append([]Link(nil), r.s.Links...)
			for i := range links {
				links[i].LinkInfo.Kind = links[i].Kind
			}
			return json.Marshal(links)
		}
		return (&fakeRunner{s: r.s, failMutation: true}).Run(ctx, c)
	case "/usr/bin/systemctl":
		if args == "show pritunl-client.service --property=ControlGroup --value" {
			return []byte("/system.slice/pritunl-client.service\n"), nil
		}
	case "/usr/bin/wg":
		if args == "show wg0 fwmark" {
			return []byte("0xca6c\n"), nil
		}
	}
	return nil, errors.New("inspection attempted an unexpected command")
}

func compatibilityItem(t *testing.T, report model.VPNCompatibility, iface string) model.VPNCompatibilityItem {
	t.Helper()
	for _, item := range report.Items {
		if item.Interface == iface {
			return item
		}
	}
	t.Fatalf("missing interface %s in %+v", iface, report)
	return model.VPNCompatibilityItem{}
}

func TestCompatibilityReportsSourcesFamiliesAndVerificationIndependently(t *testing.T) {
	s := fixture()
	s.Links = append(s.Links, Link{Name: "tun0", Kind: "tun"}, Link{Name: "wg0", Kind: "wireguard"}, Link{Name: TunName, Kind: "tun"}, Link{Name: "tun-unknown", Kind: "tun"})
	s.Routes = append(s.Routes,
		Route{Device: "tun0", Destination: "0.0.0.0/1", Family: 4}, Route{Device: "tun0", Destination: "128.0.0.0/1", Family: 4},
		Route{Device: "wg0", Destination: "default", Family: 6}, Route{Device: "tun-unknown", Destination: "default", Family: 4})
	r := &compatibilityRunner{s: s}
	manual := []Binding{{Interface: "corp0", Manager: "openvpn"}, {Interface: "absent0", Manager: "openvpn"}}
	automatic := []Binding{{Interface: "tun0", Manager: "pritunl", Endpoints: []Endpoint{{Address: "198.51.100.42", Port: 1194, Protocol: "udp"}}}, {Interface: "wg0", Manager: "wg-quick", Endpoints: []Endpoint{{Address: "203.0.113.42", Port: 51820, Protocol: "udp", Mark: 0xca6c}}}}
	report := inspectCompatibility(context.Background(), r, s, manual, automatic)
	pritunl := compatibilityItem(t, report, "tun0")
	if !pritunl.Verified || !pritunl.Active || pritunl.Source != "automatic" || pritunl.Application != "Pritunl" || !pritunl.FullIPv4 || pritunl.FullIPv6 {
		t.Fatalf("bad Pritunl discovery: %+v", pritunl)
	}
	wg := compatibilityItem(t, report, "wg0")
	if !wg.Verified || wg.FullIPv4 || !wg.FullIPv6 {
		t.Fatalf("bad independent IPv6 discovery: %+v", wg)
	}
	corp := compatibilityItem(t, report, "corp0")
	if !corp.Verified || corp.Source != "manual" || corp.FullIPv4 || corp.FullIPv6 {
		t.Fatalf("work routes incorrectly claimed Internet: %+v", corp)
	}
	absent := compatibilityItem(t, report, "absent0")
	if absent.Verified || absent.Active || absent.Message == "" {
		t.Fatal("absent manual interface marked active")
	}
	unknown := compatibilityItem(t, report, "tun-unknown")
	if unknown.Verified || unknown.Source != "unknown" || !unknown.FullIPv4 || unknown.Message == "" || len(report.Items) != 5 {
		t.Fatal("unknown tunnel must be explained without trusting it", report)
	}
	data, _ := json.Marshal(report)
	for _, forbidden := range []string{"198.51.100", "203.0.113", "1194", "51820", "system.slice", "endpoints", "cgroup", "uuid", "config"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("compatibility response leaks %s", forbidden)
		}
	}
	// Inspection must not weaken the actual controller's fail-closed behavior.
	if _, err := detectExternal(context.Background(), r, s, append(manual, automatic...)); err == nil || !strings.Contains(err.Error(), "tun-unknown") {
		t.Fatal("unknown routed tunnel no longer blocks connection", err)
	}
}

func TestCompatibilityRechecksDisappearanceReuseAndErrors(t *testing.T) {
	s := fixture()
	automatic := []Binding{{Interface: "corp0", Manager: "pritunl"}}
	r := &compatibilityRunner{s: s}
	if !compatibilityItem(t, inspectCompatibility(context.Background(), r, s, nil, automatic), "corp0").Verified {
		t.Fatal("initial verified tunnel missing")
	}
	s.Links = s.Links[:2]
	if item := compatibilityItem(t, inspectCompatibility(context.Background(), r, s, nil, automatic), "corp0"); item.Active || item.Verified {
		t.Fatal("disappeared interface stayed verified", item)
	}
	s.Links = append(s.Links, Link{Name: "corp0", Kind: "tun"})
	if item := compatibilityItem(t, inspectCompatibility(context.Background(), r, s, nil, nil), "corp0"); item.Verified || item.Source != "unknown" {
		t.Fatal("reused interface name inherited automatic trust", item)
	}
	r.failedPath = "/usr/bin/systemctl"
	item := compatibilityItem(t, inspectCompatibility(context.Background(), r, s, nil, automatic), "corp0")
	if item.Verified || !strings.Contains(item.Message, "системную службу") || strings.Contains(item.Message, "credential") {
		t.Fatal("verification error missing or unsanitized", item)
	}
}

func TestCompatibilityDoesNotRestoreOrWritePersistentRuntimeState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	bindings := []Binding{{Interface: "corp0", Manager: "openvpn"}}
	if err := privateWrite(dir, "vpn-bindings.json", bindings); err != nil {
		t.Fatal(err)
	}
	if err := privateWrite(dir, "network-state.json", persisted{Armed: true}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "vpn-bindings.json"))
	m := New(Config{StateDir: dir, RuntimeDir: filepath.Join(dir, "run")})
	r := &compatibilityRunner{s: fixture()}
	m.r = r
	status := m.Status()
	for i := 0; i < 2; i++ {
		report := m.VPNCompatibility(context.Background())
		if report.Message != "" || !compatibilityItem(t, report, "corp0").Verified {
			t.Fatal("fresh manager failed to read manual binding", report)
		}
	}
	if m.loaded || len(m.bindings) != 0 || len(m.commands) != 0 || !reflect.DeepEqual(m.Status(), status) || m.core.Alive() || len(m.dnsSaved) != 0 || len(m.protected) != 0 {
		t.Fatal("inspection changed controller state")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "vpn-bindings.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("inspection persisted bindings")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 2 {
		t.Fatal("inspection created files or runtime directory")
	}
	for _, c := range r.commands {
		if c.Path != "/usr/sbin/ip" || !strings.Contains(strings.Join(c.Args, " "), "show") || c.Input != "" {
			t.Fatalf("unexpected network/DNS/firewall mutation: %+v", c)
		}
	}
}

func TestCompatibilityDoesNotBlockControllerOrOverlapInspections(t *testing.T) {
	m := New(Config{StateDir: t.TempDir()})
	started, release := make(chan struct{}), make(chan struct{})
	r := &compatibilityRunner{s: fixture(), started: started, release: release}
	m.r = r
	done := make(chan model.VPNCompatibility, 1)
	go func() { done <- m.VPNCompatibility(context.Background()) }()
	<-started
	if !m.mu.TryLock() {
		t.Fatal("controller mutex held across inspection I/O")
	}
	m.mu.Unlock()
	if report := m.VPNCompatibility(context.Background()); report.Message == "" || len(report.Items) != 0 {
		t.Fatal("parallel inspection was not rejected", report)
	}
	close(release)
	<-done
	m.mu.Lock()
	start := time.Now()
	report := m.VPNCompatibility(context.Background())
	m.mu.Unlock()
	if report.Message == "" || time.Since(start) > 200*time.Millisecond {
		t.Fatal("inspection waited for busy controller")
	}
}

func TestCompatibilityHonorsDeadlineAndSanitizesReadErrors(t *testing.T) {
	m := New(Config{StateDir: t.TempDir()})
	r := &compatibilityRunner{s: fixture(), started: make(chan struct{}), release: make(chan struct{})}
	m.r = r
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if report := m.VPNCompatibility(ctx); !strings.Contains(report.Message, "вовремя") || len(report.Items) != 0 || time.Since(start) > time.Second {
		t.Fatal("inspection ignored timeout or returned partial trusted rows", report)
	}
	r = &compatibilityRunner{s: fixture(), failedPath: "/usr/sbin/ip"}
	m.r = r
	if report := m.VPNCompatibility(context.Background()); report.Message == "" || strings.Contains(report.Message, "credential") || len(report.Items) != 0 {
		t.Fatal("raw command error escaped or missing error", report)
	}
	path := filepath.Join(m.config.StateDir, "vpn-bindings.json")
	if err := os.WriteFile(path, []byte(`[{"interface":"corp0","manager":"openvpn"}]`), 0644); err != nil {
		t.Fatal(err)
	}
	r.commands = nil
	if report := m.VPNCompatibility(context.Background()); report.Message == "" || len(report.Items) != 0 || len(r.commands) != 0 {
		t.Fatal("unsafe persisted binding was trusted", report)
	}
}
