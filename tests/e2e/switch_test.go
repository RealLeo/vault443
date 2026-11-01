package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"vault443/internal/model"
	"vault443/internal/network"
	"vault443/internal/profiles"
	"vault443/internal/service"
	"vault443/internal/store"
)

type switchFaultRuntime struct {
	*network.Manager
	failAfter string
}

func (r *switchFaultRuntime) Connect(ctx context.Context, p model.Profile) error {
	if e := r.Manager.Connect(ctx, p); e != nil {
		return e
	}
	if p.ID == r.failAfter {
		return errors.New("synthetic failure after verified candidate TUN")
	}
	return nil
}
func TestRealTransactionalProfileSwitch(t *testing.T) {
	requireIsolated(t)
	if os.Getenv("VAULT443_PROXY_E2E") != "1" {
		t.Skip("proxy fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dir, run := "/var/lib/vault443-switch", "/run/vault443-switch"
	st, e := store.Open(dir, false)
	if e != nil {
		t.Fatal(e)
	}
	r := &switchFaultRuntime{Manager: network.New(network.Config{StateDir: dir, RuntimeDir: run})}
	s := service.New(st, r)
	c := service.Caller{UID: 1000, Admin: true}
	defer s.Disconnect(context.Background(), c)
	if e = s.Start(ctx, "switch-test-boot"); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("/fixture/proxy-links.txt")
	if e != nil {
		t.Fatal(e)
	}
	links := strings.Split(strings.TrimSpace(string(raw)), "\n")
	preview, e := s.ImportProfiles(c, "vless://11111111-2222-4333-8444-555555555555@192.0.2.1:8443?security=tls&sni=vpn.e2e.invalid#A\n"+links[0])
	if e != nil || len(preview.Profiles) != 2 {
		t.Fatal("import", e)
	}
	a, b := preview.Profiles[0].ID, preview.Profiles[1].ID
	assertTraffic := func(want string) {
		t.Helper()
		v := s.GetSnapshot(c)
		if v.ActiveProfileID != want || v.Runtime.State != "connected" || !v.Runtime.GuardArmed || st.Snapshot().Desired.ProfileID != want {
			t.Fatalf("bad confirmed session: %+v", v)
		}
		response, e := request(ctx, "")
		if e != nil || response.Peer == "192.0.2.2" {
			t.Fatalf("missing encrypted exit: %+v %v", response, e)
		}
		blocked, stop := context.WithTimeout(ctx, 500*time.Millisecond)
		defer stop()
		if _, e = request(blocked, "e2euplink"); e == nil {
			t.Fatal("direct traffic escaped")
		}
	}
	if e = s.Connect(ctx, c, a); e != nil {
		t.Fatal(e)
	}
	session := s.GetSnapshot(c).Traffic.SessionID
	assertTraffic(a)
	// Provider denial is a preparation failure: A's actual Xray process and TUN stay alive.
	source, e := profiles.ParseOutline("ss://aes-256-gcm:synthetic-password@192.0.2.1:8501", "https://93.184.215.14/outline", "Denied")
	if e != nil {
		t.Fatal(e)
	}
	source.Source.UpdatedAt = time.Now().Unix()
	if e = st.Update(func(st *store.State) error {
		u := st.User(c.UID)
		u.Profiles = append(u.Profiles, source)
		st.SetUser(c.UID, u)
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	os.WriteFile("/fixture/dynamic-outline", []byte(`error: {message: "key expired"}`), 0600)
	before := command(t, "cat", "/sys/class/net/vault4430/ifindex")
	if e = s.Connect(ctx, c, source.ID); e == nil {
		t.Fatal("provider denial ignored")
	}
	assertTraffic(a)
	if command(t, "cat", "/sys/class/net/vault4430/ifindex") != before {
		t.Fatal("preparation failure restarted A")
	}
	// A real bad TLS/SNI candidate passes preparation but fails through TUN.
	invalid, e := s.ImportProfiles(c, "trojan://synthetic-password@192.0.2.1:8450?security=tls&sni=wrong.invalid#BadTLS")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Connect(ctx, c, invalid.Profiles[0].ID); e == nil {
		t.Fatal("bad TLS candidate verified")
	}
	assertTraffic(a)
	if s.GetSnapshot(c).Traffic.SessionID != session {
		t.Fatal("rollback reset logical traffic session")
	}
	// Cancel during source preparation: A continues serving real traffic.
	slow, _ := profiles.ParseOutline("ss://aes-256-gcm:synthetic-password@192.0.2.1:8501", "https://93.184.215.14/slow-source", "Slow")
	slow.Source.UpdatedAt = time.Now().Unix()
	if e = st.Update(func(st *store.State) error {
		u := st.User(c.UID)
		u.Profiles = append(u.Profiles, slow)
		st.SetUser(c.UID, u)
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	operation, e := s.RequestConnect(ctx, c, slow.ID)
	if e != nil {
		t.Fatal(e)
	}
	assertTraffic(a)
	if _, e = s.CancelSwitch(c, operation); e != nil {
		t.Fatal(e)
	}
	wait := func(stage string) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			v := s.GetSnapshot(c)
			if v.Operation != nil && v.Operation.Stage == stage {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("operation stage missing", stage, s.GetSnapshot(c))
	}
	wait("switch_cancelled")
	assertTraffic(a)
	// Cancellation after replacing the shared TUN restores A. Disconnect instead
	// removes the desired main session; it must not resurrect A behind the GUI.
	for _, disconnect := range []bool{false, true} {
		operation, e = s.RequestConnect(ctx, c, invalid.Profiles[0].ID)
		if e != nil {
			t.Fatal(e)
		}
		wait("checking_connection")
		if disconnect {
			if e = s.Disconnect(ctx, c); e != nil {
				t.Fatal(e)
			}
			if st.Snapshot().Desired != nil || s.GetSnapshot(c).ActiveProfileID != "" {
				t.Fatal("disconnect restored A")
			}
			if e = s.Connect(ctx, c, a); e != nil {
				t.Fatal(e)
			}
			session = s.GetSnapshot(c).Traffic.SessionID
		} else {
			if _, e = s.CancelSwitch(c, operation); e != nil {
				t.Fatal(e)
			}
			wait("switch_cancelled")
		}
		assertTraffic(a)
	}
	// Force failure after B has really passed DNS/HTTPS; A must still be restored.
	r.failAfter = b
	if e = s.Connect(ctx, c, b); e == nil {
		t.Fatal("post-cutover fault ignored")
	}
	assertTraffic(a)
	if s.GetSnapshot(c).Traffic.SessionID != session {
		t.Fatal("post-cutover rollback reset session")
	}
	s.Tick(ctx, time.Now())
	if v := s.GetSnapshot(c); v.Operation.Stage != "switch_failed" || v.Operation.ProfileID != b {
		t.Fatal("background reconciliation erased candidate failure", v)
	}
	r.failAfter = ""
	if e = s.Connect(ctx, c, b); e != nil {
		t.Fatal(e)
	}
	assertTraffic(b)
	if s.GetSnapshot(c).Traffic.SessionID == session {
		t.Fatal("confirmed B inherited A statistics")
	}
	config, e := os.ReadFile(run + "/core.json")
	if e != nil || !strings.Contains(string(config), `"trojan"`) {
		t.Fatal("actual core still uses A", e)
	}
	if e = s.Disconnect(ctx, c); e != nil {
		t.Fatal(e)
	}
	if s.GetSnapshot(c).ActiveProfileID != "" {
		t.Fatal("disconnect retained session")
	}
	fmt.Println("PASS: source refusal, TLS failure, post-TUN rollback, verified commit, physical bypass blocked")
}
