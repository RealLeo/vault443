package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"vault443/internal/model"
	"vault443/internal/profiles"
	"vault443/internal/store"
)

type switchRuntime struct {
	mu                             sync.Mutex
	status                         model.RuntimeStatus
	live                           string
	connections                    []string
	failPrepare, failConnect       string
	prepareEntered, connectEntered chan struct{}
	waitPrepare, waitConnect       bool
	onConnect                      func(model.Profile) error
	failRestore                    string
}

func (r *switchRuntime) PrepareConnect(ctx context.Context, p model.Profile) error {
	if r.prepareEntered != nil {
		close(r.prepareEntered)
	}
	if r.waitPrepare {
		<-ctx.Done()
		return ctx.Err()
	}
	if p.ID == r.failPrepare {
		return errors.New("synthetic preparation failure")
	}
	return nil
}
func (r *switchRuntime) Connect(ctx context.Context, p model.Profile) error {
	r.mu.Lock()
	r.live = p.ID
	r.connections = append(r.connections, p.ID)
	r.status = model.RuntimeStatus{State: "connecting", GuardArmed: true}
	r.mu.Unlock()
	if r.onConnect != nil {
		if e := r.onConnect(p); e != nil {
			return e
		}
	}
	if p.ID == r.failConnect || p.ID == r.failRestore {
		if r.connectEntered != nil {
			close(r.connectEntered)
		}
		if r.waitConnect {
			<-ctx.Done()
			return ctx.Err()
		}
		return errors.New("synthetic post-cutover failure")
	}
	r.mu.Lock()
	r.status.State = "connected"
	r.mu.Unlock()
	return nil
}
func (r *switchRuntime) Arm(context.Context) error { return nil }
func (r *switchRuntime) Disconnect(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.live = ""
	r.status = model.RuntimeStatus{State: "disconnected"}
	return nil
}
func (r *switchRuntime) Reconcile(context.Context) error { return nil }
func (r *switchRuntime) Status() model.RuntimeStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}
func (r *switchRuntime) Diagnostics(context.Context) interface{}     { return map[string]any{} }
func (r *switchRuntime) SetVPNBinding(context.Context, string) error { return nil }

func switchSetup(t *testing.T) (*Service, *switchRuntime, *store.Store, Caller, string, string) {
	t.Helper()
	s, _, st := setup(t)
	r := &switchRuntime{status: model.RuntimeStatus{State: "disconnected"}}
	s.runtime = r
	c := Caller{UID: 1000}
	a := importOne(t, s, c, link)
	b := importOne(t, s, c, "trojan://synthetic-password@second.example:443#Second")
	if e := s.Connect(context.Background(), c, a); e != nil {
		t.Fatal(e)
	}
	return s, r, st, c, a, b
}
func waitSwitchStage(t *testing.T, s *Service, c Caller, stage string) Snapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		v := s.GetSnapshot(c)
		if v.Operation != nil && v.Operation.Stage == stage {
			return v
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("stage %s not reached: %+v", stage, s.GetSnapshot(c))
	return Snapshot{}
}
func TestSwitchFailureKeepsOrRestoresConfirmedSession(t *testing.T) {
	for _, cutover := range []bool{false, true} {
		t.Run(map[bool]string{false: "preparation", true: "after_cutover"}[cutover], func(t *testing.T) {
			s, r, st, c, a, b := switchSetup(t)
			before := s.GetSnapshot(c).Traffic.SessionID
			if cutover {
				r.failConnect = b
			} else {
				r.failPrepare = b
			}
			if e := s.Connect(context.Background(), c, b); e == nil {
				t.Fatal("failed switch succeeded")
			}
			v := s.GetSnapshot(c)
			if v.ActiveProfileID != a || v.Runtime.State != "connected" || st.Snapshot().Desired.ProfileID != a || v.Operation.ProfileID != b || v.Operation.Failure == nil || v.Traffic.SessionID != before {
				t.Fatalf("A identity/traffic lost: %+v", v)
			}
			count := 1
			if cutover {
				count = 3
			}
			r.mu.Lock()
			if r.live != a || len(r.connections) != count {
				t.Fatal("wrong actual session", r.live, r.connections)
			}
			r.mu.Unlock()
			s.stateMu.Lock()
			s.worker.activeContext = context.Background()
			s.worker.activeGeneration = s.worker.generation
			s.stateMu.Unlock()
			s.progress(model.RuntimeStatus{State: "connected", Stage: "connected", GuardArmed: true})
			if v := s.GetSnapshot(c); v.Operation.Stage != "switch_failed" {
				t.Fatal("background status erased switch failure", v.Operation)
			}
			s.Tick(context.Background(), time.Now().Add(time.Hour))
			if s.GetSnapshot(c).ActiveProfileID != a {
				t.Fatal("failed B automatically retried")
			}
		})
	}
}
func TestDeniedSourceSwitchDoesNotArmOrReplaceA(t *testing.T) {
	s, r, st, c, a, _ := switchSetup(t)
	b, e := profiles.ParseOutline("ss://aes-256-gcm:synthetic@second.example:443", "https://source.example/key", "B")
	if e != nil {
		t.Fatal(e)
	}
	b.Source.UpdatedAt = time.Now().Unix()
	if e = st.Update(func(st *store.State) error {
		u := st.User(c.UID)
		u.Profiles = append(u.Profiles, b)
		st.SetUser(c.UID, u)
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	s.fetch = func(context.Context, string) (string, error) {
		return "", &profiles.ProviderError{Message: "key expired"}
	}
	if e = s.Connect(context.Background(), c, b.ID); e == nil {
		t.Fatal("denied profile accepted")
	}
	s.Tick(context.Background(), time.Now())
	v := s.GetSnapshot(c)
	if v.ActiveProfileID != a || v.Runtime.State != "connected" || st.Snapshot().Desired.ProfileID != a || len(r.connections) != 1 {
		t.Fatalf("denial changed A: %+v", v)
	}
}
func TestSwitchCommitsOnlyVerifiedB(t *testing.T) {
	s, r, st, c, _, b := switchSetup(t)
	before := s.GetSnapshot(c).Traffic.SessionID
	if e := s.Connect(context.Background(), c, b); e != nil {
		t.Fatal(e)
	}
	v := s.GetSnapshot(c)
	if v.ActiveProfileID != b || st.Snapshot().Desired.ProfileID != b || v.Traffic.SessionID == before || r.live != b {
		t.Fatal("B was not committed", v)
	}
}
func TestSwitchCancellationAndDisconnectAreDifferent(t *testing.T) {
	for _, cutover := range []bool{false, true} {
		for _, disconnect := range []bool{false, true} {
			t.Run(fmtSwitchCase(cutover, disconnect), func(t *testing.T) {
				s, r, st, c, a, b := switchSetup(t)
				entered := make(chan struct{})
				if cutover {
					r.failConnect = b
					r.waitConnect = true
					r.connectEntered = entered
				} else {
					r.waitPrepare = true
					r.prepareEntered = entered
				}
				id, e := s.RequestConnect(context.Background(), c, b)
				if e != nil {
					t.Fatal(e)
				}
				<-entered
				if st.Snapshot().Desired.ProfileID != a {
					t.Fatal("pending B persisted before verification")
				}
				if _, e = s.CancelSwitch(Caller{UID: 1001}, id); e == nil {
					t.Fatal("foreign cancellation accepted")
				}
				if _, e = s.CancelSwitch(c, id+"stale"); e == nil {
					t.Fatal("stale cancellation accepted")
				}
				if disconnect {
					if e = s.Disconnect(context.Background(), c); e != nil {
						t.Fatal(e)
					}
					if st.Snapshot().Desired != nil || s.GetSnapshot(c).ActiveProfileID != "" || r.live != "" {
						t.Fatal("disconnect restored old session")
					}
				} else {
					if _, e = s.CancelSwitch(c, id); e != nil {
						t.Fatal(e)
					}
					v := waitSwitchStage(t, s, c, "switch_cancelled")
					if v.ActiveProfileID != a || v.Runtime.State != "connected" || st.Snapshot().Desired.ProfileID != a {
						t.Fatal("cancel failed to preserve A", v)
					}
				}
			})
		}
	}
}
func fmtSwitchCase(cutover, disconnect bool) string {
	if cutover {
		if disconnect {
			return "cutover_disconnect"
		}
		return "cutover_cancel"
	}
	if disconnect {
		return "prepare_disconnect"
	}
	return "prepare_cancel"
}

func TestSwitchPersistenceFailureRestoresAAndRestartIntent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st, e := store.Open(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	r := &switchRuntime{status: model.RuntimeStatus{State: "disconnected"}}
	s := New(st, r)
	c := Caller{UID: 1000}
	a := importOne(t, s, c, link)
	b := importOne(t, s, c, "trojan://synthetic@second.example:443#B")
	if e = s.Start(context.Background(), "same-boot"); e != nil {
		t.Fatal(e)
	}
	if e = s.Connect(context.Background(), c, a); e != nil {
		t.Fatal(e)
	}
	r.onConnect = func(p model.Profile) error {
		if p.ID == b {
			return os.Rename(dir, dir+".held")
		}
		return os.Rename(dir+".held", dir)
	}
	if e = s.Connect(context.Background(), c, b); e == nil {
		t.Fatal("unsaved candidate committed")
	}
	if s.GetSnapshot(c).ActiveProfileID != a || r.live != a {
		t.Fatal("A not restored")
	}
	reopened, e := store.Open(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	if reopened.Snapshot().Desired.ProfileID != a {
		t.Fatal("crash would restore B")
	}
	recovered := New(reopened, &switchRuntime{status: model.RuntimeStatus{State: "disconnected"}})
	if e = recovered.Start(context.Background(), "same-boot"); e != nil {
		t.Fatal(e)
	}
	recovered.Tick(context.Background(), time.Now().Add(time.Minute))
	if recovered.GetSnapshot(c).ActiveProfileID != a {
		t.Fatal("restart did not recover confirmed A")
	}
}
func TestFailedRestorationRetriesAOnly(t *testing.T) {
	s, r, st, c, a, b := switchSetup(t)
	r.failConnect, r.failRestore = b, a
	if e := s.Connect(context.Background(), c, b); e == nil {
		t.Fatal("failed switch succeeded")
	}
	v := s.GetSnapshot(c)
	if v.ActiveProfileID != a || !v.Runtime.GuardArmed || v.Runtime.State != "error" || st.Snapshot().Desired.ProfileID != a {
		t.Fatal("unsafe restoration failure", v)
	}
	r.failRestore = ""
	s.Tick(context.Background(), time.Now().Add(time.Minute))
	var retained *Failure
	for _, p := range s.GetSnapshot(c).Profiles {
		if p.ID == b {
			retained = p.SwitchFailure
		}
	}
	if retained == nil || retained.ProfileID != b {
		t.Fatal("A recovery erased B card failure")
	}
	if r.live != a || s.GetSnapshot(c).Runtime.State != "connected" {
		t.Fatal("A recovery did not run")
	}
	for _, p := range r.connections[2:] {
		if p == b {
			t.Fatal("B retried automatically")
		}
	}
}

func (r *switchRuntime) Suspend(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.live = ""
	r.status = model.RuntimeStatus{State: "error", GuardArmed: true}
	return nil
}
func TestSwitchRollbackNeverUsesSourceDeniedCache(t *testing.T) {
	s, r, st, c, a, b := switchSetup(t)
	r.failConnect = b
	r.onConnect = func(p model.Profile) error {
		if p.ID != b {
			return nil
		}
		return st.Update(func(st *store.State) error {
			u := st.User(c.UID)
			for i := range u.Profiles {
				if u.Profiles[i].ID == a {
					u.Profiles[i].Source = &model.DynamicSource{URL: "https://source.example/denied", Blocked: true, LastAttempt: time.Now().Unix()}
				}
			}
			st.SetUser(c.UID, u)
			return nil
		})
	}
	s.fetch = func(context.Context, string) (string, error) { return "", errors.New("source offline") }
	if e := s.Connect(context.Background(), c, b); e == nil {
		t.Fatal("failed candidate committed")
	}
	v := s.GetSnapshot(c)
	if v.Runtime.State != "error" || !v.Runtime.GuardArmed || r.live != "" || len(r.connections) != 2 {
		t.Fatal("denied A cache restored", v, r.connections)
	}
	s.Tick(context.Background(), time.Now().Add(time.Minute))
	if r.live != "" || len(r.connections) != 2 || st.Snapshot().Desired.ProfileID != a {
		t.Fatal("retry bypassed source denial")
	}
}
