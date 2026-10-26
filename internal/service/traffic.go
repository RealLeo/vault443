package service

import (
	"context"
	"math"
	"time"

	"vault443/internal/model"
	"vault443/internal/store"
)

// All accounting state is protected by stateMu; reading the kernel happens
// outside it. Nothing here depends on a DNS request, core start or Reconcile.
type trafficState struct {
	owner    *store.Session
	id       string
	started  time.Time
	finished time.Time
	state    string
	previous model.TUNCounters
	view     model.Traffic
}

type trafficSource interface{ TrafficCounters() model.TUNCounters }

func (s *Service) readTraffic() model.TUNCounters {
	if source, ok := s.runtime.(trafficSource); ok {
		return source.TrafficCounters()
	}
	return model.TUNCounters{}
}

func (s *Service) resetTrafficLocked(owner *store.Session, id string) {
	s.traffic = trafficState{owner: copyOwner(owner), id: id, view: model.Traffic{Valid: true}}
}

// syncTrafficLocked is called only for accepted, current worker publications.
// A logical session starts after the first successful health check, never when
// the connect button is pressed. Subsequent reconnections retain that session.
func (s *Service) syncTrafficLocked(status model.RuntimeStatus, sample model.TUNCounters, now time.Time) {
	t := &s.traffic
	if t.owner == nil || !t.finished.IsZero() {
		return
	}
	if t.state == status.State {
		return
	}
	t.state = status.State
	if t.started.IsZero() {
		if status.State != "connected" {
			return
		}
		t.started = now
		t.view.SessionID, t.view.StartedAt = t.id, now.UnixMilli()
		// Discard health-check bytes preceding the first verified connection.
		t.previous = model.TUNCounters{}
	}
	s.updateTrafficLocked(sample)
	if status.State != "connected" {
		t.view.DownloadBytesPerSecond, t.view.UploadBytesPerSecond = 0, 0
	}
}

func addCounter(total, delta uint64) uint64 {
	if math.MaxUint64-total < delta {
		return math.MaxUint64
	}
	return total + delta
}

func (s *Service) updateTrafficLocked(sample model.TUNCounters) {
	t := &s.traffic
	if t.started.IsZero() || !t.finished.IsZero() {
		return
	}
	if !sample.Valid {
		t.view.DownloadBytesPerSecond, t.view.UploadBytesPerSecond = 0, 0
		if s.worker.runtime.State == "connected" {
			t.view.Valid = false
		}
		return
	}
	previous := t.previous
	if previous.Valid && !sample.SampledAt.After(previous.SampledAt) {
		// Concurrent periodic/final observations may arrive out of order.
		return
	}
	t.previous = sample
	t.view.MeasuredAt, t.view.Valid = sample.SampledAt.UnixMilli(), true
	t.view.DownloadBytesPerSecond, t.view.UploadBytesPerSecond = 0, 0
	if !previous.Valid || previous.Epoch != sample.Epoch || previous.IfIndex != sample.IfIndex || sample.RXBytes < previous.RXBytes || sample.TXBytes < previous.TXBytes {
		// New owned device or kernel counter reset: take a baseline, never add
		// its absolute counter to the logical session or underflow a uint64.
		return
	}
	download, upload := sample.RXBytes-previous.RXBytes, sample.TXBytes-previous.TXBytes
	t.view.DownloadBytes = addCounter(t.view.DownloadBytes, download)
	t.view.UploadBytes = addCounter(t.view.UploadBytes, upload)
	if s.worker.runtime.State == "connected" {
		seconds := sample.SampledAt.Sub(previous.SampledAt).Seconds()
		t.view.DownloadBytesPerSecond = float64(download) / seconds
		t.view.UploadBytesPerSecond = float64(upload) / seconds
	}
}

func (s *Service) finishTrafficLocked(now time.Time) {
	if !s.traffic.started.IsZero() && s.traffic.finished.IsZero() {
		s.traffic.finished = now
		s.traffic.view.DownloadBytesPerSecond, s.traffic.view.UploadBytesPerSecond = 0, 0
		// The last successfully sampled totals remain trustworthy after the
		// device disappears, including a crash before manual disconnection.
		s.traffic.view.Valid = s.traffic.previous.Valid
	}
}

func (s *Service) trafficSnapshotLocked(uid uint32, now time.Time) *model.Traffic {
	t := &s.traffic
	if t.owner != nil && t.owner.UID != uid {
		return nil
	}
	view := t.view
	if t.started.IsZero() {
		view.Valid = true
		return &view
	}
	end := now
	if !t.finished.IsZero() {
		end = t.finished
	}
	view.DurationSeconds = int64(end.Sub(t.started) / time.Second)
	if view.DurationSeconds < 0 {
		view.DurationSeconds = 0
	}
	if !t.finished.IsZero() || s.worker.runtime.State != "connected" {
		view.DownloadBytesPerSecond, view.UploadBytesPerSecond = 0, 0
		// Paused/retry states have no eligible transport, but the confirmed
		// accumulated total and elapsed logical-session time remain valid.
		view.Valid = t.previous.Valid
	} else if !t.previous.Valid || now.Sub(t.previous.SampledAt) > 3*time.Second {
		view.Valid = false
		view.DownloadBytesPerSecond, view.UploadBytesPerSecond = 0, 0
	}
	return &view
}

func (s *Service) observeTraffic(generation uint64, sample model.TUNCounters) {
	s.stateMu.Lock()
	if generation == s.worker.generation {
		s.updateTrafficLocked(sample)
	}
	s.stateMu.Unlock()
}

func (s *Service) sampleTraffic() {
	s.stateMu.Lock()
	generation := s.worker.generation
	needed := !s.traffic.started.IsZero() && s.traffic.finished.IsZero()
	s.stateMu.Unlock()
	if !needed {
		return
	}
	s.observeTraffic(generation, s.readTraffic())
	s.changed()
}

func (s *Service) runTraffic(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sampleTraffic()
		}
	}
}
