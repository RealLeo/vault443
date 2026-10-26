package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vault443/internal/journal"
	"vault443/internal/model"
	"vault443/internal/store"
)

type blockingRuntime struct {
	mu             sync.Mutex
	status         model.RuntimeStatus
	progress       func(model.RuntimeStatus)
	started        chan struct{}
	cancelled      chan struct{}
	cleanupStarted chan struct{}
	cleanupRelease chan struct{}
	connects       atomic.Int32
	fail           bool
	delay          time.Duration
}

func (r *blockingRuntime) SetProgressHandler(fn func(model.RuntimeStatus)) {
	r.mu.Lock()
	r.progress = fn
	r.mu.Unlock()
}
func (r *blockingRuntime) publish(state, stage, message, code string) {
	r.mu.Lock()
	r.status.State = state
	r.status.Stage = stage
	r.status.StageStartedAt = time.Now().UnixMilli()
	r.status.Message = message
	r.status.FailureCode = code
	status := r.status
	fn := r.progress
	r.mu.Unlock()
	if fn != nil {
		fn(status)
	}
}
func (r *blockingRuntime) Connect(ctx context.Context, p model.Profile) error {
	r.connects.Add(1)
	r.publish("connecting", "resolving_endpoint", "Resolving endpoint", "")
	if r.fail {
		time.Sleep(r.delay)
		r.publish("error", "resolving_endpoint", "DNS did not answer; protected HTTPS fallback also failed", "dns_unavailable")
		return errors.New("private raw failure")
	}
	if r.started != nil {
		close(r.started)
	}
	<-ctx.Done()
	if r.cancelled != nil {
		close(r.cancelled)
	}
	// Simulate a late completion from a controller that has already been cancelled.
	r.publish("connected", "connected", "late success", "")
	return nil
}
func (r *blockingRuntime) Disconnect(context.Context) error {
	if r.cleanupStarted != nil {
		close(r.cleanupStarted)
	}
	if r.cleanupRelease != nil {
		<-r.cleanupRelease
	}
	r.publish("disconnected", "disconnected", "", "")
	return nil
}
func (r *blockingRuntime) Arm(context.Context) error {
	r.publish("connecting", "enabling_guard", "Protection enabled", "")
	return nil
}
func (r *blockingRuntime) Reconcile(context.Context) error             { return nil }
func (r *blockingRuntime) SetVPNBinding(context.Context, string) error { return nil }
func (r *blockingRuntime) Status() model.RuntimeStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}
func (r *blockingRuntime) Diagnostics(context.Context) interface{} {
	return map[string]interface{}{"coreVersion": "test", "coreRunning": false, "publishedStage": r.Status().Stage}
}
func (r *blockingRuntime) VPNCompatibility(context.Context) model.VPNCompatibility {
	return model.VPNCompatibility{Items: []model.VPNCompatibilityItem{{Interface: "private-tun"}}}
}
func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	end := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(end) {
			t.Fatal("timed out waiting for state")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestAsyncCancelKeepsSnapshotsResponsiveAndOwnershipUntilCleanup(t *testing.T) {
	s, _, st := setup(t)
	r := &blockingRuntime{started: make(chan struct{}), cancelled: make(chan struct{}), cleanupStarted: make(chan struct{}), cleanupRelease: make(chan struct{})}
	s.runtime = r
	owner, other := Caller{UID: 1000}, Caller{UID: 1001}
	id := importOne(t, s, owner, link)
	importOne(t, s, other, link)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := time.Now()
	operationID, err := s.RequestConnect(ctx, owner, id)
	if err != nil || operationID == "" || time.Since(started) > 100*time.Millisecond {
		t.Fatal("request did not acknowledge promptly", err)
	}
	<-r.started
	ready := make(chan Snapshot, 1)
	go func() { _ = s.GetDiagnostics(ctx, owner); ready <- s.GetSnapshot(owner) }()
	var snapshot Snapshot
	select {
	case snapshot = <-ready:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("read APIs blocked behind DNS")
	}
	if snapshot.Operation == nil || snapshot.Operation.Stage != "resolving_endpoint" || snapshot.Operation.Attempt != 1 {
		t.Fatalf("no live stage: %+v", snapshot)
	}
	diagnostic := s.GetDiagnostics(ctx, owner).(map[string]interface{})["network"].(map[string]interface{})
	if diagnostic["publishedStage"] != "resolving_endpoint" {
		t.Fatal("diagnostics kept a previous operation's snapshot during connection", diagnostic)
	}
	foreign := s.GetSnapshot(other)
	if !foreign.BusyByOtherUser || foreign.Operation != nil || foreign.Runtime.Message != "" {
		t.Fatal("foreign stage disclosed", foreign)
	}
	_, err = s.RequestDisconnect(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.cancelled:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("cancellation waited for DNS timeout")
	}
	<-r.cleanupStarted
	if st.Snapshot().Desired != nil {
		t.Fatal("cancellation did not persist intent before cleanup")
	}
	snapshot = s.GetSnapshot(owner)
	if snapshot.Runtime.State == "connected" || snapshot.Operation.Action != "disconnect" {
		t.Fatal("late cancelled result replaced cleanup", snapshot)
	}
	diagnostic = s.GetDiagnostics(ctx, owner).(map[string]interface{})["network"].(map[string]interface{})
	if diagnostic["publishedStage"] == "connected" {
		t.Fatal("late cancelled result replaced diagnostics", diagnostic)
	}
	foreign = s.GetSnapshot(other)
	if !foreign.BusyByOtherUser || foreign.ActiveProfileID != "" || foreign.Operation != nil {
		t.Fatal("cleanup prematurely released ownership", foreign)
	}
	if _, err = s.RequestConnect(ctx, other, id); err == nil {
		t.Fatal("foreign user started while cleanup owned")
	}
	if _, err = s.RequestConnect(ctx, owner, id); err == nil {
		t.Fatal("owner started before cleanup completed")
	}
	report := s.GetVPNCompatibility(ctx, other)
	if !report.BusyByOtherUser || len(report.Items) != 0 {
		t.Fatal("cleanup compatibility disclosed private tunnel", report)
	}
	if err = s.RemoveProfile(owner, id); err == nil {
		t.Fatal("removed profile while its cleanup was running")
	}
	close(r.cleanupRelease)
	waitFor(t, func() bool { return s.GetSnapshot(owner).Runtime.State == "disconnected" })
	snapshot = s.GetSnapshot(other)
	if snapshot.BusyByOtherUser || snapshot.Operation != nil {
		t.Fatal("completed operation disclosed to next user", snapshot)
	}
	s.Tick(ctx, time.Now().Add(time.Hour))
	if r.connects.Load() != 1 {
		t.Fatal("explicit cancellation started another attempt")
	}
	if s.GetSnapshot(owner).LastFailure != nil {
		t.Fatal("user cancellation recorded as failure")
	}
}
func TestRetryDelayMeasuredFromCompletionAndLastFailureSurvivesDisconnect(t *testing.T) {
	s, _, _ := setup(t)
	r := &blockingRuntime{fail: true, delay: 30 * time.Millisecond}
	s.runtime = r
	c := Caller{UID: 1000}
	id := importOne(t, s, c, link)
	if err := s.Connect(context.Background(), c, id); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("missing safe error", err)
	}
	first := s.GetSnapshot(c)
	if first.LastFailure == nil || first.LastFailure.Code != "dns_unavailable" {
		t.Fatal("failure missing", first)
	}
	for i, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second} {
		snap := s.GetSnapshot(c)
		if snap.Operation.Attempt != i+1 {
			t.Fatal("wrong attempt count", snap.Operation)
		}
		remaining := time.Until(time.UnixMilli(snap.Operation.NextRetryAt))
		fromFailure := time.Duration(snap.Operation.NextRetryAt-snap.LastFailure.Time) * time.Millisecond
		if fromFailure < delay-time.Millisecond || remaining > delay+20*time.Millisecond {
			t.Fatalf("retry not counted from completion: delay=%s fromFailure=%s remaining=%s", delay, fromFailure, remaining)
		}
		if i < 6 {
			s.Tick(context.Background(), time.UnixMilli(snap.Operation.NextRetryAt).Add(time.Millisecond))
		}
	}
	last := s.GetSnapshot(c).LastFailure
	if err := s.Disconnect(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	after := s.GetSnapshot(c)
	if after.LastFailure == nil || *after.LastFailure != *last {
		t.Fatal("disconnect erased original failure")
	}
	diag, err := s.GetProfileDiagnostics(context.Background(), c, id)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(diag)
	if !strings.Contains(string(encoded), "dns_unavailable") || strings.Contains(string(encoded), "private raw") {
		t.Fatal("diagnostics omitted safe cause", string(encoded))
	}
}
func TestFailureRecoversFromPrivateSevenDayJournal(t *testing.T) {
	s, _, st := setup(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := &blockingRuntime{fail: true}
	s = New(st, r, j)
	c := Caller{UID: 1000}
	id := importOne(t, s, c, link)
	_ = s.Connect(context.Background(), c, id)
	before := s.GetSnapshot(c).LastFailure
	_ = s.Disconnect(context.Background(), c)
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	recovered := New(st, &fakeRuntime{}, j)
	after := recovered.GetSnapshot(c).LastFailure
	if before == nil || after == nil || *before != *after {
		t.Fatalf("failure not recovered: before=%+v after=%+v", before, after)
	}
	if recovered.GetSnapshot(Caller{UID: 1001}).LastFailure != nil {
		t.Fatal("journal recovery disclosed another user's error")
	}
	if _, err = recovered.GetProfileDiagnostics(context.Background(), Caller{UID: 1001}, id); err == nil {
		t.Fatal("foreign profile diagnostics allowed")
	}
}

type failedHealthRuntime struct {
	fakeRuntime
	crashed bool
}

func (r *failedHealthRuntime) Reconcile(context.Context) error {
	if r.crashed {
		r.crashed = false
		r.status.State = "error"
		r.status.Message = "Xray exited unexpectedly; protection remains enabled"
		r.status.FailureCode = "core_exited"
		return errors.New("raw private exit details")
	}
	return nil
}
func TestFailureFromReconcileSurvivesSuccessfulRecovery(t *testing.T) {
	s, _, _ := setup(t)
	r := &failedHealthRuntime{}
	s.runtime = r
	c := Caller{UID: 1000}
	id := importOne(t, s, c, link)
	if err := s.Connect(context.Background(), c, id); err != nil {
		t.Fatal(err)
	}
	r.crashed = true
	s.Tick(context.Background(), time.Now())
	failed := s.GetSnapshot(c)
	if failed.LastFailure == nil || failed.LastFailure.Code != "core_exited" || failed.Operation.Stage != "retry_wait" {
		t.Fatal("reconcile lost initiating failure", failed)
	}
	if r.connects != 1 {
		t.Fatal("recovery ignored first retry delay")
	}
	s.Tick(context.Background(), time.UnixMilli(failed.Operation.NextRetryAt).Add(time.Millisecond))
	recovered := s.GetSnapshot(c)
	if recovered.Runtime.State != "connected" || recovered.LastFailure == nil || *recovered.LastFailure != *failed.LastFailure {
		t.Fatal("successful recovery erased initiating failure", recovered)
	}
}

func TestRefreshRetainsProfileWhileCleanupOwnsIt(t *testing.T) {
	s, _, st := setup(t)
	r := &blockingRuntime{started: make(chan struct{}), cleanupStarted: make(chan struct{}), cleanupRelease: make(chan struct{})}
	s.runtime = r
	c := Caller{UID: 1000}
	body := link
	s.fetch = func(context.Context, string) (string, error) { return body, nil }
	preview, err := s.AddSubscription(context.Background(), c, "https://example.com/sub", "source")
	if err != nil {
		t.Fatal(err)
	}
	id := preview.Profiles[0].ID
	if _, err = s.RequestConnect(context.Background(), c, id); err != nil {
		t.Fatal(err)
	}
	<-r.started
	if _, err = s.RequestDisconnect(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	<-r.cleanupStarted
	body = strings.Replace(link, "vpn.example", "replacement.example", 1)
	result := s.RefreshSubscriptions(context.Background(), c)
	if len(result) != 1 || !result[0].Updated {
		t.Fatal("refresh failed", result)
	}
	state := st.Snapshot()
	if _, ok := state.Profile(&store.Session{UID: c.UID, ProfileID: id}); !ok {
		t.Fatal("refresh discarded cleanup profile")
	}
	if _, err = s.GetProfileDiagnostics(context.Background(), c, id); err != nil {
		t.Fatal("cleanup profile diagnostics became inaccessible", err)
	}
	close(r.cleanupRelease)
	waitFor(t, func() bool { return s.GetSnapshot(c).Runtime.State == "disconnected" })
}

type failedCleanupRuntime struct {
	fakeRuntime
	cleanupFails bool
}

func (r *failedCleanupRuntime) Disconnect(ctx context.Context) error {
	if r.cleanupFails {
		return errors.New("raw private cleanup failure")
	}
	return r.fakeRuntime.Disconnect(ctx)
}
func TestCleanupFailureKeepsOwnerAndPublishesDistinctSafeReason(t *testing.T) {
	s, _, _ := setup(t)
	r := &failedCleanupRuntime{fakeRuntime: fakeRuntime{fail: true}, cleanupFails: true}
	s.runtime = r
	c := Caller{UID: 1000}
	id := importOne(t, s, c, link)
	_ = s.Connect(context.Background(), c, id)
	failure := s.GetSnapshot(c).LastFailure
	if err := s.Disconnect(context.Background(), c); err == nil {
		t.Fatal("expected cleanup failure")
	}
	current := s.GetSnapshot(c)
	if current.Operation.Stage != "cleanup_failed" || current.Runtime.State != "error" || current.Runtime.FailureCode != "cleanup_failed" || !strings.Contains(current.Runtime.Message, "Retry disconnection") || strings.Contains(current.Runtime.Message, "private") {
		t.Fatal("cleanup failure missing or unsafe", current)
	}
	if current.LastFailure == nil || *current.LastFailure != *failure {
		t.Fatal("cleanup erased initiating failure")
	}
	if !s.GetSnapshot(Caller{UID: 1001}).BusyByOtherUser {
		t.Fatal("failed cleanup released ownership")
	}
	s.Tick(context.Background(), time.Now().Add(time.Minute))
	current = s.GetSnapshot(c)
	if current.Operation.Stage != "cleanup_failed" || current.Runtime.FailureCode != "cleanup_failed" {
		t.Fatal("periodic reconciliation erased actionable cleanup failure", current)
	}
	r.cleanupFails = false
	if err := s.Disconnect(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

type resumedExternalRuntime struct {
	fakeRuntime
	released bool
}

func (r *resumedExternalRuntime) Reconcile(context.Context) error {
	if r.released {
		r.released = false
		r.status.State = "reconnecting"
		r.status.Message = "External VPN released Internet; restoring protected VLESS"
		return errors.New(r.status.Message)
	}
	return nil
}
func TestNormalExternalVPNReleaseIsNotRecordedAsFailure(t *testing.T) {
	s, _, _ := setup(t)
	r := &resumedExternalRuntime{}
	s.runtime = r
	c := Caller{UID: 1000}
	id := importOne(t, s, c, link)
	if err := s.Connect(context.Background(), c, id); err != nil {
		t.Fatal(err)
	}
	r.status.State = "paused_external"
	r.released = true
	s.Tick(context.Background(), time.Now())
	snap := s.GetSnapshot(c)
	if snap.Runtime.State != "connected" || snap.LastFailure != nil {
		t.Fatal("normal full tunnel release treated as a failure", snap)
	}
}

func TestFailureRecoveryWithShortRealitySecretAndClear(t *testing.T) {
	s, _, st := setup(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s = New(st, &fakeRuntime{fail: true}, j)
	c := Caller{UID: 1000}
	var source string
	for i := 0; i < 1000; i++ {
		candidate := fmt.Sprintf("vless://11111111-2222-4333-8444-555555555555@vpn%d.example:443?encryption=none&flow=xtls-rprx-vision&fp=firefox&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&security=reality&sid=fa&sni=www.example.com&spx=Connection&type=tcp", i)
		preview := s.PreviewImport(c, candidate)
		if len(preview.Profiles) == 1 && strings.Contains(preview.Profiles[0].ID, "fa") {
			source = candidate
			break
		}
	}
	if source == "" {
		t.Fatal("could not construct ID/short-secret collision fixture")
	}
	id := importOne(t, s, c, source)
	_ = s.Connect(context.Background(), c, id)
	before := s.GetSnapshot(c).LastFailure
	_ = s.Disconnect(context.Background(), c)
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	recovered := New(st, &fakeRuntime{}, j)
	after := recovered.GetSnapshot(c).LastFailure
	if before == nil || after == nil || *before != *after || after.Code != "connection_failed" {
		t.Fatalf("secret corrupted structured failure: before=%+v after=%+v", before, after)
	}
	if err = recovered.ClearProfileLogs(c, id); err != nil {
		t.Fatal(err)
	}
	if recovered.GetSnapshot(c).LastFailure != nil {
		t.Fatal("cleared journal left stale cached failure")
	}
}
