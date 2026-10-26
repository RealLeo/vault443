package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"vault443/internal/journal"
	"vault443/internal/model"
	"vault443/internal/network"
	"vault443/internal/profiles"
)

type webReply struct {
	Marker string `json:"marker"`
	Peer   string `json:"peer"`
}

func requireIsolated(t *testing.T) {
	t.Helper()
	if os.Getenv("VAULT443_E2E_ISOLATED") != "1" {
		t.Skip("requires the explicit isolated Docker runner")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("refusing network test outside a root disposable container")
	}
	links, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if link.Name != "lo" && link.Name != "e2euplink" && link.Name != network.TunName {
			t.Fatalf("unexpected interface %s; refusing network test", link.Name)
		}
	}
}

func localProfile(t *testing.T) model.Profile {
	t.Helper()
	p, err := profiles.Parse("vless://11111111-2222-4333-8444-555555555555@192.0.2.1:8443?security=tls&type=tcp&sni=vpn.e2e.invalid#Private%20E2E")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func request(ctx context.Context, bind string) (webReply, error) {
	d := &net.Dialer{Timeout: 2 * time.Second}
	if bind != "" {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var e error
			err := c.Control(func(fd uintptr) {
				e = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, bind)
			})
			if err != nil {
				return err
			}
			return e
		}
	}
	tr := &http.Transport{DialContext: d.DialContext, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://93.184.215.14:8080/", nil)
	res, err := client.Do(req)
	if err != nil {
		return webReply{}, err
	}
	defer res.Body.Close()
	var out webReply
	err = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&out)
	return out, err
}
func command(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v: %s", args[0], err, b)
	}
	return string(b)
}
func TestRealVLESSTLSAndCrashProtection(t *testing.T) {
	requireIsolated(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	var before webReply
	var err error
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); {
		before, err = request(ctx, "")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || before.Marker != "vless-e2e-ok" || before.Peer != "192.0.2.2" {
		t.Fatalf("isolated direct fixture unavailable: %+v %v", before, err)
	}
	t.Log("baseline: direct HTTP reaches isolated fixture")
	p := localProfile(t)
	p.DebugLogging = true
	m := network.New(network.Config{StateDir: "/var/lib/vault443-e2e", RuntimeDir: "/run/vault443-e2e", XrayPath: "/usr/lib/vault443/xray"})
	history := openConnectionJournal(t, "/var/lib/vault443-e2e/journal", m, p, 1000)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = m.Disconnect(cleanup)
	}()
	if err = m.Connect(ctx, p); err != nil {
		_ = os.WriteFile("/results/connect-failure.txt", []byte(err.Error()), 0600)
		for _, args := range [][]string{{"ip", "-4", "rule", "show"}, {"ip", "-4", "route", "show", "table", "all"}, {"nft", "list", "ruleset"}, {"resolvectl", "status"}} {
			b, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
			t.Logf("%v\n%s", args, b)
		}
		t.Fatalf("real Manager.Connect failed: %v", err)
	}
	if st := m.Status(); st.State != "connected" || !st.GuardArmed {
		t.Fatalf("unexpected runtime %+v", st)
	}
	through, err := request(ctx, "")
	if err != nil || through.Marker != "vless-e2e-ok" || through.Peer == "192.0.2.2" {
		t.Fatalf("HTTP did not traverse VLESS: %+v %v", through, err)
	}
	t.Logf("connected: HTTP traversed VLESS/TLS; server observed peer %s", through.Peer)
	dns := command(t, "resolvectl", "query", "example.com")
	if !strings.Contains(dns, "93.184.215.14") {
		t.Fatalf("system DNS did not return fixture response: %s", dns)
	}
	t.Log("connected: systemd-resolved → TUN → VLESS → HTTPS DNS succeeded")
	if _, err = request(ctx, "e2euplink"); err == nil {
		t.Fatal("direct physical-interface HTTP bypassed the kill switch")
	}
	t.Log("connected: explicitly bound physical-interface bypass was blocked")
	pid := findCore(t, "/run/vault443-e2e/core.json")
	if err = syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
		if _, e := net.InterfaceByName(network.TunName); e != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = request(ctx, ""); err == nil {
		t.Fatal("HTTP escaped directly after core SIGKILL before reconciliation")
	}
	_ = m.Reconcile(ctx)
	if !m.Status().GuardArmed {
		t.Fatal("core crash disarmed protection")
	}
	if _, err = request(ctx, "e2euplink"); err == nil {
		t.Fatal("physical-interface HTTP escaped after core SIGKILL")
	}
	t.Log("SIGKILL: traffic blocked immediately and after reconciliation")
	if err = m.Disconnect(ctx); err != nil {
		t.Fatalf("explicit cleanup: %v", err)
	}
	after, err := request(ctx, "")
	if err != nil || after.Peer != "192.0.2.2" {
		t.Fatalf("direct connectivity not restored: %+v %v", after, err)
	}
	if strings.Contains(command(t, "nft", "list", "tables"), network.TableName) {
		t.Fatal("owned firewall table remains after disconnect")
	}
	rules := command(t, "ip", "-4", "rule", "show")
	if strings.Contains(rules, "52780") || strings.Contains(rules, "52781") || strings.Contains(rules, "52782") {
		t.Fatalf("owned routing policy remains: %s", rules)
	}
	if m.Status().GuardArmed || m.Status().State != "disconnected" {
		t.Fatal("cleanup state incorrect")
	}
	t.Log("disconnect: direct HTTP restored; owned firewall/routing resources removed")
	history.Flush()
	rows, e := history.Read(1000, p.ID, "", 500)
	if e != nil {
		t.Fatal(e)
	}
	foundDebug, foundExit := false, false
	for _, r := range rows.Entries {
		foundDebug = foundDebug || (r.Level == "debug" && strings.HasPrefix(r.Message, "Xray:"))
		foundExit = foundExit || strings.Contains(r.Message, "Xray process stopped: signal: killed")
	}
	if !foundDebug || !foundExit {
		t.Fatalf("missing real debug/crash journal messages: debug=%v exit=%v", foundDebug, foundExit)
	}
	assertPrivateJournal(t, history, 1000, p, "connection-journal-tls.json")
	bad := p
	bad.ID = "failed-profile"
	bad.UUID = "00000000-0000-4000-8000-000000000001"
	m.SetLogSession(history.NewSession(1001, bad.ID, bad.UUID))
	if e = m.Connect(ctx, bad); e == nil {
		t.Fatal("invalid credential unexpectedly connected")
	}
	if !m.Status().GuardArmed {
		t.Fatal("failed authentication released guard")
	}
	if e = m.Disconnect(ctx); e != nil {
		t.Fatal(e)
	}
	history.Flush()
	failed, e := history.Read(1001, bad.ID, "", 500)
	if e != nil || len(failed.Entries) == 0 {
		t.Fatal("failed connection history missing")
	}
	foundError := false
	for _, r := range failed.Entries {
		foundError = foundError || r.Level == "error"
	}
	if !foundError {
		t.Fatal("connection failure absent from history")
	}
	if foreign, _ := history.Read(1000, bad.ID, "", 500); len(foreign.Entries) != 0 {
		t.Fatal("new owner history exposed to previous UID")
	}
	assertPrivateJournal(t, history, 1001, bad, "connection-journal-failure.json")
	t.Log("journal: real Xray debug and crash output persisted; failed authentication and UID/profile switch isolated")
}

// The helper owns a real Manager and core. Killing it exercises the same process
// lifetime boundary as killing the daemon, without replacing production paths or
// introducing a network/authentication bypass into the daemon executable.
func TestRealVLESSOwnerProcess(t *testing.T) {
	if os.Getenv("VAULT443_E2E_OWNER_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	requireIsolated(t)
	m := ownerManager()
	history := openConnectionJournal(t, "/var/lib/vault443-e2e-owner/journal", m, localProfile(t), 1000)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := m.Connect(ctx, localProfile(t)); err != nil {
		t.Fatalf("child Manager.Connect: %v", err)
	}
	history.Flush()
	if err := os.WriteFile("/run/vault443-e2e-owner.ready", []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Second)
	}
}

func ownerManager() *network.Manager {
	return network.New(network.Config{StateDir: "/var/lib/vault443-e2e-owner", RuntimeDir: "/run/vault443-e2e-owner", XrayPath: "/usr/lib/vault443/xray"})
}

func TestRealVLESSOwnerDeathAndRecovery(t *testing.T) {
	requireIsolated(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.Create("/results/owner-process.log")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	child := exec.CommandContext(ctx, exe, "-test.v", "-test.run=^TestRealVLESSOwnerProcess$", "-test.timeout=80s")
	child.Env = append(os.Environ(), "VAULT443_E2E_OWNER_CHILD=1")
	child.Stdout, child.Stderr = log, log
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	m := ownerManager()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = m.Disconnect(cleanup)
	}()
	ready := false
	for end := time.Now().Add(45 * time.Second); time.Now().Before(end); {
		if _, err = os.Stat("/run/vault443-e2e-owner.ready"); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("manager subprocess never became ready; inspect owner-process.log")
	}
	before, err := request(ctx, "")
	if err != nil || before.Marker != "vless-e2e-ok" || before.Peer == "192.0.2.2" {
		t.Fatalf("child-owned tunnel unavailable: %+v %v", before, err)
	}
	_ = findCore(t, "/run/vault443-e2e-owner/core.json")
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); {
		if _, e := net.InterfaceByName(network.TunName); e != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err = net.InterfaceByName(network.TunName); err == nil {
		t.Fatal("core TUN survived owning manager death")
	}
	if _, err = request(ctx, ""); err == nil {
		t.Fatal("HTTP escaped after manager SIGKILL before restart")
	}
	if !strings.Contains(command(t, "nft", "list", "tables"), network.TableName) {
		t.Fatal("persistent firewall disappeared with manager process")
	}
	t.Log("manager SIGKILL: child core stopped; persistent kernel guard blocked traffic before restart")
	history := openConnectionJournal(t, "/var/lib/vault443-e2e-owner/journal", m, localProfile(t), 1000)
	prior, e := history.Read(1000, localProfile(t).ID, "", 500)
	if e != nil || len(prior.Entries) == 0 {
		t.Fatal("journal history did not survive owner SIGKILL")
	}
	t.Log("journal: private connection history survived abrupt service death and reload")
	if err = m.Arm(ctx); err != nil {
		t.Fatalf("fresh Manager.Arm: %v", err)
	}
	if !m.Status().GuardArmed {
		t.Fatal("fresh manager did not recover armed checkpoint")
	}
	if _, err = request(ctx, "e2euplink"); err == nil {
		t.Fatal("direct traffic escaped during manager recovery")
	}
	if err = m.Connect(ctx, localProfile(t)); err != nil {
		t.Fatalf("fresh manager reconnect: %v", err)
	}
	recovered, err := request(ctx, "")
	if err != nil || recovered.Marker != "vless-e2e-ok" || recovered.Peer == "192.0.2.2" {
		t.Fatalf("restored tunnel unavailable: %+v %v", recovered, err)
	}
	if dns := command(t, "resolvectl", "query", "example.com"); !strings.Contains(dns, "93.184.215.14") {
		t.Fatalf("restored system DNS unavailable: %s", dns)
	}
	t.Log("manager restart: checkpoint recovered; real VLESS HTTP and system DNS restored")
	if err = m.Disconnect(ctx); err != nil {
		t.Fatalf("recovered manager cleanup: %v", err)
	}
	after, err := request(ctx, "")
	if err != nil || after.Peer != "192.0.2.2" {
		t.Fatalf("direct traffic not restored after recovery cleanup: %+v %v", after, err)
	}
	if strings.Contains(command(t, "nft", "list", "tables"), network.TableName) {
		t.Fatal("guard remains after recovery cleanup")
	}
	t.Log("recovery cleanup: explicit disconnect restored direct HTTP and removed the guard")
	assertPrivateJournal(t, history, 1000, localProfile(t), "connection-journal-recovery.json")
}

func TestRealVLESSREALITYVision(t *testing.T) {
	requireIsolated(t)
	for _, fingerprint := range []string{"native", "chrome", "firefox", "safari"} {
		t.Run(fingerprint, func(t *testing.T) { testREALITYVision(t, fingerprint) })
	}
}

func testREALITYVision(t *testing.T, fingerprint string) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	link, err := os.ReadFile("/fixture/reality.uri")
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.TrimSpace(string(link))
	if fingerprint != "native" {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal("invalid local fixture URI")
		}
		q := u.Query()
		q.Set("fp", fingerprint)
		q.Set("support-x25519mlkem768", "true")
		q.Set("spx", "/local-regression")
		u.RawQuery = q.Encode()
		raw = u.String()
	}
	p, err := profiles.Parse(raw)
	if err != nil {
		t.Fatal("generated REALITY profile is invalid")
	}
	p.DebugLogging = true
	stateDir := "/var/lib/vault443-e2e-reality-" + fingerprint
	m := network.New(network.Config{StateDir: stateDir, RuntimeDir: "/run/vault443-e2e-reality-" + fingerprint, XrayPath: "/usr/lib/vault443/xray"})
	history := openConnectionJournal(t, stateDir+"/journal", m, p, 1000)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = m.Disconnect(cleanup)
	}()
	if err = m.Connect(ctx, p); err != nil {
		t.Fatalf("REALITY/Vision connection: %v", err)
	}
	through, err := request(ctx, "")
	if err != nil || through.Marker != "vless-e2e-ok" || through.Peer == "192.0.2.2" {
		t.Fatalf("HTTP did not traverse REALITY/Vision: %+v %v", through, err)
	}
	if dns := command(t, "resolvectl", "query", "example.com"); !strings.Contains(dns, "93.184.215.14") {
		t.Fatalf("system DNS did not traverse REALITY/Vision: %s", dns)
	}
	if st := m.Status(); st.State != "connected" || !st.GuardArmed {
		t.Fatalf("REALITY/Vision runtime state incorrect: %+v", st)
	}
	t.Log("REALITY/Vision: real TUN HTTP and system DNS succeeded through authenticated VLESS")
	if _, err = request(ctx, "e2euplink"); err == nil {
		t.Fatal("physical-interface bypass escaped REALITY/Vision guard")
	}
	if err = m.Disconnect(ctx); err != nil {
		t.Fatalf("REALITY/Vision disconnect: %v", err)
	}
	if after, err := request(ctx, ""); err != nil || after.Peer != "192.0.2.2" {
		t.Fatalf("REALITY/Vision cleanup did not restore direct traffic: %+v %v", after, err)
	}
	t.Log("REALITY/Vision: physical bypass blocked; explicit disconnect restored direct HTTP")
	assertPrivateJournal(t, history, 1000, p, "connection-journal-reality-"+fingerprint+".json")
}

func findCore(t *testing.T, config string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err == nil && strings.Contains(string(b), "xray\x00run\x00") && strings.Contains(string(b), config) {
			return pid
		}
	}
	t.Fatal("client core process not found")
	return 0
}

func openConnectionJournal(t *testing.T, dir string, m *network.Manager, p model.Profile, uid uint32) *journal.Journal {
	t.Helper()
	j, e := journal.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := j.Close(); e != nil {
			t.Error(e)
		}
	})
	m.SetLogSession(j.NewSession(uid, p.ID, p.UUID, p.PublicKey, p.ShortID))
	return j
}
func assertPrivateJournal(t *testing.T, j *journal.Journal, uid uint32, p model.Profile, name string) {
	t.Helper()
	j.Flush()
	page, e := j.Read(uid, p.ID, "tail", 500)
	if e != nil || len(page.Entries) == 0 {
		t.Fatalf("journal empty: %v", e)
	}
	b, e := json.MarshalIndent(page, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{p.UUID, p.PublicKey, p.ShortID} {
		if secret != "" && strings.Contains(string(b), secret) {
			t.Fatal("credential appeared in real connection journal")
		}
	}
	if e = os.WriteFile(filepath.Join("/results", name), b, 0600); e != nil {
		t.Fatal(e)
	}
	if other, _ := j.Read(uid+10, p.ID, "", 500); len(other.Entries) != 0 {
		t.Fatal("journal crossed owner boundary")
	}
}
