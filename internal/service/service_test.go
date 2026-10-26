package service

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vault443/internal/model"
	"vault443/internal/store"
)

const link = "vless://11111111-2222-4333-8444-555555555555@vpn.example:443?security=tls#Primary"

type fakeRuntime struct {
	status   model.RuntimeStatus
	calls    []string
	connects int
	fail     bool
	paused   bool
}

type eventRuntime struct {
	fakeRuntime
	events chan struct{}
	ticks  chan struct{}
}

type armFailureRuntime struct{ fakeRuntime }

func (r *armFailureRuntime) Arm(context.Context) error {
	r.status.State = "error"
	r.status.Message = `unrecognized VPN interface "corp0"; enroll it before connecting so its routes remain protected`
	return errors.New("raw subprocess output with private credentials")
}

func TestArmFailureExplainsSafeReasonWithoutLeakingRawError(t *testing.T) {
	s, _, _ := setup(t)
	r := &armFailureRuntime{}
	s.runtime = r
	c := Caller{UID: 1000}
	id := importOne(t, s, c, link)
	err := s.Connect(context.Background(), c, id)
	if err == nil || !strings.Contains(err.Error(), r.status.Message) || strings.Contains(err.Error(), "credentials") {
		t.Fatal("arming failure must report only the controller's safe reason", err)
	}
	if r.connects != 0 || r.status.GuardArmed {
		t.Fatal("core started despite failed protection")
	}
	diagnostic := s.GetDiagnostics(context.Background(), Caller{UID: 1001}).(map[string]interface{})
	if diagnostic["busyByOtherUser"] != true || diagnostic["network"] != nil {
		t.Fatal("another user received private diagnostics")
	}
}

func (r *eventRuntime) Watch(context.Context) (<-chan struct{}, error) { return r.events, nil }
func (r *eventRuntime) Reconcile(context.Context) error {
	select {
	case r.ticks <- struct{}{}:
	default:
	}
	return nil
}

func TestRunHandlesNetworkEventsAndClosedWatcher(t *testing.T) {
	s, _, _ := setup(t)
	r := &eventRuntime{events: make(chan struct{}, 32), ticks: make(chan struct{}, 32)}
	s.runtime = r
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case <-r.ticks:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not start")
	}
	for i := 0; i < 32; i++ {
		r.events <- struct{}{}
	}
	select {
	case <-r.ticks:
	case <-time.After(time.Second):
		t.Fatal("network event did not reconcile before the periodic timer")
	}
	close(r.events)
	select {
	case <-r.ticks:
		t.Fatal("event burst or closed watcher caused repeated reconciliation")
	case <-time.After(250 * time.Millisecond):
	}
}

func (f *fakeRuntime) Connect(_ context.Context, p model.Profile) error {
	f.calls = append(f.calls, "connect")
	f.connects++
	if f.fail {
		f.status.State = "error"
		return errors.New("internal secret not public")
	}
	f.status.State = "connected"
	return nil
}
func (f *fakeRuntime) Disconnect(context.Context) error {
	f.calls = append(f.calls, "disconnect")
	f.status.State = "disconnected"
	f.status.GuardArmed = false
	return nil
}
func (f *fakeRuntime) Reconcile(context.Context) error {
	if f.paused {
		f.status.State = "paused_external"
	}
	return nil
}
func (f *fakeRuntime) Status() model.RuntimeStatus { return f.status }
func (f *fakeRuntime) Arm(context.Context) error {
	f.calls = append(f.calls, "arm")
	f.status.GuardArmed = true
	return nil
}
func (f *fakeRuntime) SetVPNBinding(context.Context, string) error { return nil }
func (f *fakeRuntime) Diagnostics(context.Context) interface{} {
	return map[string]interface{}{"guardArmed": f.status.GuardArmed}
}
func setup(t *testing.T) (*Service, *fakeRuntime, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRuntime{status: model.RuntimeStatus{State: "disconnected"}}
	return New(st, r), r, st
}
func importOne(t *testing.T, s *Service, c Caller, text string) string {
	t.Helper()
	p, err := s.ImportProfiles(c, text)
	if err != nil || len(p.Errors) > 0 || len(p.Profiles) != 1 {
		t.Fatalf("import failed %+v %v", p, err)
	}
	return p.Profiles[0].ID
}

func TestUIDIsolationOwnershipAndAdminBoundaries(t *testing.T) {
	s, r, _ := setup(t)
	ctx := context.Background()
	a := Caller{UID: 1001, Admin: true}
	b := Caller{UID: 1002}
	id := importOne(t, s, a, link)
	if err := s.Connect(ctx, b, id); err == nil {
		t.Fatal("another UID used a private profile")
	}
	if err := s.RenameProfile(b, id, "stolen"); err == nil {
		t.Fatal("another UID renamed a profile")
	}
	if err := s.SetBootProfile(b, id); err == nil {
		t.Fatal("non-admin set boot profile")
	}
	if err := s.SetVPNBinding(ctx, b, `{}`); err == nil {
		t.Fatal("non-admin set VPN bindings")
	}
	if err := s.Connect(ctx, a, id); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) < 2 || r.calls[0] != "arm" || r.calls[1] != "connect" {
		t.Fatal("connection preceded protection")
	}
	view := s.GetSnapshot(b)
	if len(view.Profiles) != 0 || !view.BusyByOtherUser || view.ActiveProfileID != "" {
		t.Fatal("another user saw private session metadata")
	}
	if err := s.Disconnect(ctx, b); err == nil {
		t.Fatal("another UID disconnected without takeover")
	}
	if err := s.RemoveProfile(a, id); err == nil {
		t.Fatal("deleted active profile")
	}
	if err := s.TakeControl(ctx, b); err != nil {
		t.Fatal(err)
	}
	if r.status.State != "disconnected" {
		t.Fatal("takeover kept prior user's session")
	}
	if err := s.SetBootProfile(a, id); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveProfile(a, id); err == nil {
		t.Fatal("deleted boot profile")
	}
	if err := s.SetBootProfile(a, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveProfile(a, id); err != nil {
		t.Fatal(err)
	}
}
func TestBootVersusDaemonRestartAndEarlyGuard(t *testing.T) {
	s, r, st := setup(t)
	ctx := context.Background()
	c := Caller{UID: 1000, Admin: true}
	id := importOne(t, s, c, link)
	if err := s.Start(ctx, "boot-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Connect(ctx, c, id); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx, "boot-a"); err != nil {
		t.Fatal(err)
	}
	if st.Snapshot().Desired == nil {
		t.Fatal("daemon restart forgot active intent")
	}
	if err := s.Start(ctx, "boot-b"); err != nil {
		t.Fatal(err)
	}
	if st.Snapshot().Desired != nil {
		t.Fatal("new boot silently resumed a non-boot profile")
	}
	if err := s.SetBootProfile(c, id); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	if err := s.BootGuard(ctx, "boot-c"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || r.calls[0] != "arm" {
		t.Fatal("early guard connected or failed to protect")
	}
	if st.Snapshot().BootID != "boot-b" {
		t.Fatal("early guard modified boot identity before main daemon")
	}
	if err := s.Start(ctx, "boot-c"); err != nil {
		t.Fatal(err)
	}
	if st.Snapshot().Desired == nil {
		t.Fatal("boot profile not elected")
	}
	if err := s.Disconnect(ctx, c); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	if err := s.BootGuard(ctx, "boot-c"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 0 {
		t.Fatal("daemon restart rearmed after explicit disconnect")
	}
	if err := s.Start(ctx, "boot-c"); err != nil {
		t.Fatal(err)
	}
	if st.Snapshot().Desired != nil {
		t.Fatal("restart overrode explicit disconnect")
	}
}
func TestRetryAndExternalVPNPause(t *testing.T) {
	s, r, _ := setup(t)
	ctx := context.Background()
	c := Caller{UID: 1000}
	id := importOne(t, s, c, link)
	r.fail = true
	err := s.Connect(ctx, c, id)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("unsafe error or missing failure")
	}
	if !r.status.GuardArmed {
		t.Fatal("failure disarmed protection")
	}
	now := time.Now()
	s.Tick(ctx, now)
	calls := r.connects
	s.Tick(ctx, now)
	if r.connects != calls {
		t.Fatal("retry busy-loop")
	}
	r.paused = true
	s.Tick(ctx, now.Add(time.Minute))
	if r.connects != calls {
		t.Fatal("tried to replace external VPN")
	}
	r.paused = false
	r.status.State = "error"
	r.fail = false
	s.Tick(ctx, now.Add(2*time.Minute))
	if r.status.State != "connected" {
		t.Fatal("did not recover desired connection")
	}
}
func TestSubscriptionAtomicRefreshAndNoSilentRestart(t *testing.T) {
	s, r, st := setup(t)
	ctx := context.Background()
	c := Caller{UID: 1000, Admin: true}
	body := link
	s.fetch = func(context.Context, string) (string, error) { return body, nil }
	p, err := s.AddSubscription(ctx, c, "https://provider.example/sub?token=DO_NOT_LEAK", "Provider")
	if err != nil {
		t.Fatal(err)
	}
	id := p.Profiles[0].ID
	if err = s.Connect(ctx, c, id); err != nil {
		t.Fatal(err)
	}
	if err = s.SetBootProfile(c, id); err != nil {
		t.Fatal(err)
	}
	calls := r.connects
	body = strings.Replace(link, "vpn.example", "new.example", 1)
	result := s.RefreshSubscriptions(ctx, c)
	if len(result) != 1 || !result[0].Updated || r.connects != calls {
		t.Fatal("subscription silently restarted VPN or failed")
	}
	if len(st.Snapshot().User(c.UID).Profiles) != 2 {
		t.Fatal("active/boot profile was discarded by source update")
	}
	body += "\nnot-a-link"
	before := st.Snapshot().User(c.UID).Profiles
	result = s.RefreshSubscriptions(ctx, c)
	if result[0].Updated || len(st.Snapshot().User(c.UID).Profiles) != len(before) {
		t.Fatal("invalid subscription partially replaced profiles")
	}
	diag, _ := json.Marshal(s.GetDiagnostics(ctx, c))
	snapshot, _ := json.Marshal(s.GetSnapshot(c))
	for _, b := range [][]byte{diag, snapshot} {
		if strings.Contains(string(b), "DO_NOT_LEAK") || strings.Contains(string(b), "11111111-2222") {
			t.Fatal("public view leaked secrets")
		}
	}
	subID := st.Snapshot().User(c.UID).Subscriptions[0].ID
	if err = s.RemoveSubscription(c, subID); err != nil {
		t.Fatal(err)
	}
	u := st.Snapshot().User(c.UID)
	if len(u.Subscriptions) != 0 || len(u.Profiles) != 2 {
		t.Fatal("source removal deleted profiles")
	}
	for _, p := range u.Profiles {
		if p.SubscriptionID != "" {
			t.Fatal("removed source still attached")
		}
	}
}
func TestDailyRefreshOnlyWhenDue(t *testing.T) {
	s, _, st := setup(t)
	ctx := context.Background()
	c := Caller{UID: 1000}
	downloads := 0
	s.fetch = func(context.Context, string) (string, error) { downloads++; return link, nil }
	if _, err := s.AddSubscription(ctx, c, "https://provider.example/sub", "Daily"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.refreshDue(ctx, now)
	if downloads != 1 {
		t.Fatal("fresh subscription fetched immediately")
	}
	if err := st.Update(func(st *store.State) error {
		u := st.User(c.UID)
		u.Subscriptions[0].LastAttempt = now.Add(-25 * time.Hour).Unix()
		st.SetUser(c.UID, u)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.refreshDue(ctx, now)
	s.refreshDue(ctx, now)
	if downloads != 2 {
		t.Fatal("daily refresh count incorrect")
	}
}

func TestMaintenanceReleasePreservesLibraries(t *testing.T) {
	s, r, st := setup(t)
	ctx := context.Background()
	c := Caller{UID: 1000, Admin: true}
	id := importOne(t, s, c, link)
	if err := s.SetBootProfile(c, id); err != nil {
		t.Fatal(err)
	}
	if err := s.Connect(ctx, c, id); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	state := st.Snapshot()
	if state.Boot != nil || state.Desired != nil || len(state.User(c.UID).Profiles) != 1 || r.status.GuardArmed {
		t.Fatal("maintenance release did not preserve profiles and clear network intent")
	}
}
