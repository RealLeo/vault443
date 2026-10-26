package service

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"vault443/internal/model"
	"vault443/internal/store"
)

func counter(at time.Time, epoch, index, download, upload uint64) model.TUNCounters {
	return model.TUNCounters{SampledAt: at, Epoch: epoch, IfIndex: index, RXBytes: download, TXBytes: upload, Valid: true}
}

func startTraffic(s *Service, at time.Time, sample model.TUNCounters) {
	s.resetTrafficLocked(&store.Session{UID: 1000, ProfileID: "profile"}, "session-one")
	s.worker.runtime.State = "connected"
	s.syncTrafficLocked(s.worker.runtime, sample, at)
}

func TestTrafficLogicalSessionAndActualElapsedRate(t *testing.T) {
	s, _, _ := setup(t)
	start := time.Now()
	startTraffic(s, start, counter(start, 1, 14, 300, 200))
	s.updateTrafficLocked(counter(start.Add(2500*time.Millisecond), 1, 14, 2800, 5200))
	view := s.trafficSnapshotLocked(1000, start.Add(2500*time.Millisecond))
	if view.DownloadBytes != 2500 || view.UploadBytes != 5000 || view.DownloadBytesPerSecond != 1000 || view.UploadBytesPerSecond != 2000 || view.DurationSeconds != 2 {
		t.Fatalf("wrong direction, rate or elapsed: %+v", view)
	}
	if s.trafficSnapshotLocked(1001, start) != nil {
		t.Fatal("traffic leaked to another UID")
	}
	// A pause preserves totals and elapsed wall time, while foreign VPN bytes
	// cannot appear without a measurement of this Manager's owned interface.
	s.worker.runtime.State = "paused_external"
	s.syncTrafficLocked(s.worker.runtime, model.TUNCounters{}, start.Add(3*time.Second))
	view = s.trafficSnapshotLocked(1000, start.Add(20*time.Second))
	if view.DownloadBytes != 2500 || view.DownloadBytesPerSecond != 0 || view.DurationSeconds != 20 || !view.Valid {
		t.Fatalf("pause discarded accounting: %+v", view)
	}
	// A recreated TUN can start above zero: only increments after the new
	// baseline belong to the session, never its unrelated absolute counters.
	s.updateTrafficLocked(counter(start.Add(21*time.Second), 2, 15, 9000, 8000))
	s.worker.runtime.State = "connected"
	s.syncTrafficLocked(s.worker.runtime, counter(start.Add(22*time.Second), 2, 15, 9200, 8400), start.Add(22*time.Second))
	view = s.trafficSnapshotLocked(1000, start.Add(22*time.Second))
	if view.SessionID != "session-one" || view.StartedAt != start.UnixMilli() || view.DownloadBytes != 2700 || view.UploadBytes != 5400 || view.DurationSeconds != 22 {
		t.Fatalf("recreated TUN reset session or spiked counters: %+v", view)
	}
	s.worker.runtime.State = "error"
	s.syncTrafficLocked(s.worker.runtime, model.TUNCounters{}, start.Add(23*time.Second))
	view = s.trafficSnapshotLocked(1000, start.Add(26*time.Second))
	if view.DownloadBytesPerSecond != 0 || view.DownloadBytes != 2700 || !view.Valid {
		t.Fatalf("crash/retry lost last successful observation: %+v", view)
	}
	s.finishTrafficLocked(start.Add(27 * time.Second))
	s.worker.runtime.State = "disconnected"
	view = s.trafficSnapshotLocked(1000, start.Add(time.Hour))
	if view.DurationSeconds != 27 || view.DownloadBytes != 2700 || view.UploadBytes != 5400 || !view.Valid {
		t.Fatalf("manual disconnect did not freeze totals: %+v", view)
	}
	s.resetTrafficLocked(&store.Session{UID: 1001, ProfileID: "different-profile"}, "session-two")
	if s.trafficSnapshotLocked(1000, start) != nil {
		t.Fatal("previous owner saw new session")
	}
	view = s.trafficSnapshotLocked(1001, start)
	if view.SessionID != "" || view.DownloadBytes != 0 || !view.Valid {
		t.Fatalf("new intention did not reset accounting: %+v", view)
	}
}

func TestTrafficUnavailableCounterResetAndLateObservation(t *testing.T) {
	s, _, _ := setup(t)
	start := time.Now()
	startTraffic(s, start, counter(start, 1, 10, 100, 200))
	s.updateTrafficLocked(counter(start.Add(time.Second), 1, 10, 200, 400))
	s.updateTrafficLocked(counter(start.Add(500*time.Millisecond), 1, 10, 150, 300))
	view := s.trafficSnapshotLocked(1000, start.Add(time.Second))
	if view.DownloadBytes != 100 || view.UploadBytes != 200 || view.MeasuredAt != start.Add(time.Second).UnixMilli() {
		t.Fatalf("late sample changed counters: %+v", view)
	}
	s.updateTrafficLocked(counter(start.Add(2*time.Second), 1, 10, 5, 8))
	s.updateTrafficLocked(counter(start.Add(3*time.Second), 1, 10, 15, 28))
	view = s.trafficSnapshotLocked(1000, start.Add(3*time.Second))
	if view.DownloadBytes != 110 || view.UploadBytes != 220 || view.DownloadBytesPerSecond != 10 {
		t.Fatalf("counter reset underflowed or lost session: %+v", view)
	}
	s.updateTrafficLocked(model.TUNCounters{})
	view = s.trafficSnapshotLocked(1000, start.Add(3*time.Second))
	if view.Valid || view.DownloadBytes != 110 || view.DownloadBytesPerSecond != 0 {
		t.Fatalf("unavailable counter presented as a valid zero: %+v", view)
	}
	s.updateTrafficLocked(counter(start.Add(4*time.Second), 1, 10, 25, 48))
	if s.trafficSnapshotLocked(1000, start.Add(8*time.Second)).Valid {
		t.Fatal("stale measurement remained valid")
	}
	if addCounter(math.MaxUint64-1, 20) != math.MaxUint64 {
		t.Fatal("session counter wrapped")
	}
}

type trafficRuntime struct {
	blockingRuntime
	counterMu        sync.Mutex
	sample           model.TUNCounters
	observer         func(model.TUNCounters)
	waitReconcile    chan struct{}
	reconcileEntered chan struct{}
}

func (r *trafficRuntime) TrafficCounters() model.TUNCounters {
	r.counterMu.Lock()
	defer r.counterMu.Unlock()
	sample := r.sample
	sample.SampledAt = time.Now()
	return sample
}
func (r *trafficRuntime) SetTrafficHandler(fn func(model.TUNCounters)) {
	r.counterMu.Lock()
	r.observer = fn
	r.counterMu.Unlock()
}
func (r *trafficRuntime) setCounters(rx, tx uint64) {
	r.counterMu.Lock()
	r.sample = counter(time.Now(), 1, 10, rx, tx)
	r.counterMu.Unlock()
}
func (r *trafficRuntime) Connect(context.Context, model.Profile) error {
	r.publish("connected", "connected", "", "")
	return nil
}
func (r *trafficRuntime) Disconnect(ctx context.Context) error {
	r.counterMu.Lock()
	fn := r.observer
	r.counterMu.Unlock()
	if fn != nil {
		fn(r.TrafficCounters())
	}
	return r.blockingRuntime.Disconnect(ctx)
}
func (r *trafficRuntime) Reconcile(ctx context.Context) error {
	if r.waitReconcile != nil {
		select {
		case r.reconcileEntered <- struct{}{}:
		default:
		}
		select {
		case <-r.waitReconcile:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func TestTrafficSamplerIndependentOfNetworkWorkerAndFinalRead(t *testing.T) {
	_, _, st := setup(t)
	r := &trafficRuntime{waitReconcile: make(chan struct{}), reconcileEntered: make(chan struct{}, 1)}
	r.setCounters(100, 200)
	s := New(st, r)
	c := Caller{UID: 1000}
	id := importOne(t, s, c, link)
	if err := s.Connect(context.Background(), c, id); err != nil {
		t.Fatal(err)
	}
	first := s.GetSnapshot(c).Traffic
	if first == nil || first.SessionID == "" || !first.Valid {
		t.Fatalf("first success did not start a session: %+v", first)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	select {
	case <-r.reconcileEntered:
	case <-time.After(time.Second):
		t.Fatal("worker did not block")
	}
	r.setCounters(8100, 4200)
	// One-second sampling continues even while the sequential network worker
	// waits on a deliberately blocked reconciliation call.
	deadline := time.Now().Add(2500 * time.Millisecond)
	var view *model.Traffic
	for time.Now().Before(deadline) {
		view = s.GetSnapshot(c).Traffic
		if view != nil && view.DownloadBytes == 8000 && view.UploadBytes == 4000 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if view.DownloadBytes != 8000 || view.UploadBytesPerSecond <= 0 {
		t.Fatalf("sampler blocked behind network operation: %+v", view)
	}
	if s.GetSnapshot(Caller{UID: 1001}).Traffic != nil {
		t.Fatal("foreign caller received statistics")
	}
	close(r.waitReconcile)
	r.setCounters(9100, 6200)
	if err := s.Disconnect(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	view = s.GetSnapshot(c).Traffic
	if view.DownloadBytes != 9000 || view.UploadBytes != 6000 || view.DownloadBytesPerSecond != 0 {
		t.Fatalf("final pre-stop sample was lost: %+v", view)
	}
	if err := s.Connect(context.Background(), c, id); err != nil {
		t.Fatal(err)
	}
	reset := s.GetSnapshot(c).Traffic
	if reset.SessionID == first.SessionID || reset.DownloadBytes != 0 {
		t.Fatalf("new manual connection retained old session: %+v", reset)
	}
	cancel()
	<-done
	// A fresh service deliberately does not restore statistics from Store.
	restarted := New(st, &trafficRuntime{})
	if got := restarted.GetSnapshot(c).Traffic; got == nil || got.SessionID != "" || got.DownloadBytes != 0 {
		t.Fatalf("daemon restart retained volatile traffic: %+v", got)
	}
}

func TestTrafficCancelledGenerationCannotContaminateNewSession(t *testing.T) {
	s, _, _ := setup(t)
	start := time.Now()
	s.worker.generation = 1
	startTraffic(s, start, counter(start, 1, 10, 0, 0))
	s.worker.generation = 2
	s.resetTrafficLocked(&store.Session{UID: 1001, ProfileID: "next"}, "new-session")
	s.worker.runtime.State = "connected"
	s.syncTrafficLocked(s.worker.runtime, counter(start, 2, 11, 0, 0), start)
	s.observeTraffic(1, counter(start.Add(time.Second), 1, 10, 100000, 100000))
	if view := s.trafficSnapshotLocked(1001, start.Add(time.Second)); view.DownloadBytes != 0 || view.UploadBytes != 0 {
		t.Fatalf("late old operation contaminated next owner: %+v", view)
	}
}
