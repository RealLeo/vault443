package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"vault443/internal/journal"
	"vault443/internal/model"
	"vault443/internal/store"
)

// Only the sequential worker changes the network. Fields are guarded by stateMu;
// confirmed identity and persisted Desired remain A until B has passed health.
type profileSwitch struct {
	previous                      model.Profile
	owner                         *store.Session
	cancelled, cutover, restoring bool
	trafficEpoch, trafficIfIndex  uint64
}

func (s *Service) requestSwitchLocked(ctx context.Context, c Caller, wanted *store.Session, candidate model.Profile) (string, *workItem) {
	if s.worker.cancel != nil {
		s.worker.cancel()
	}
	s.worker.generation++
	s.worker.sequence++
	generation := s.worker.generation
	id := fmt.Sprintf("%d-%d", time.Now().UnixNano(), s.worker.sequence)
	sw := &profileSwitch{previous: *s.worker.confirmed, owner: copyOwner(s.worker.owner)}
	s.worker.switching = sw
	s.worker.operationUID = c.UID
	s.worker.operation = &Operation{ID: id, Action: "connect", ProfileID: candidate.ID, PreviousProfileID: sw.previous.ID, Stage: "preparing_switch", StageStartedAt: time.Now().UnixMilli(), Attempt: 1}
	s.nextRetry = time.Time{}
	job := &workItem{ctx: ctx, generation: generation, done: make(chan error, 1)}
	job.run = func(ctx context.Context) error { return s.switchProfile(ctx, generation, sw, wanted, candidate) }
	s.enqueueLocked(job)
	return id, job
}

func (s *Service) CancelSwitch(c Caller, operationID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	op, sw := s.worker.operation, s.worker.switching
	if op == nil || sw == nil || op.ID != operationID {
		return "", errors.New("Profile switch is no longer active")
	}
	if s.worker.operationUID != c.UID {
		return "", errors.New("another user owns the VPN")
	}
	if sw.cancelled {
		return operationID, nil
	}
	sw.cancelled = true
	if s.worker.cancel != nil {
		s.worker.cancel()
	}
	return operationID, nil
}

func (s *Service) switchProfile(ctx context.Context, generation uint64, sw *profileSwitch, wanted *store.Session, p model.Profile) error {
	var candidateLog *journal.Session
	if s.journal != nil {
		candidateLog = s.journal.NewSession(wanted.UID, p.ID, p.Secrets()...)
	}
	candidateLog.Log("info", "Preparing profile switch; previous connection remains active")
	s.stateMu.Lock()
	cancelled := sw.cancelled
	s.stateMu.Unlock()
	var err error
	if cancelled {
		err = context.Canceled
	}
	if err == nil && p.Source != nil {
		p, err = s.refreshSource(ctx, wanted.UID, p.ID, true)
	}
	if err == nil {
		if r, ok := s.runtime.(interface {
			PrepareConnect(context.Context, model.Profile) error
		}); ok {
			err = r.PrepareConnect(ctx, p)
		}
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil {
		sample := s.readTraffic()
		s.stateMu.Lock()
		if generation != s.worker.generation {
			s.stateMu.Unlock()
			return context.Canceled
		}
		s.updateTrafficLocked(sample)
		sw.trafficEpoch, sw.trafficIfIndex = sample.Epoch, sample.IfIndex
		sw.cutover = true
		s.stateMu.Unlock()
		s.stage(generation, "switching_profile")
		s.beginLog(wanted, p)
		err = s.runtime.Connect(ctx, p)
		if err == nil && s.runtime.Status().State != "connected" {
			err = errors.New("Candidate connection was not verified")
		}
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	// Serialize the durable commit with Disconnect/TakeControl. A stale worker
	// can never overwrite a newer cancellation or republish its own profile.
	s.mu.Lock()
	s.stateMu.Lock()
	current := generation == s.worker.generation
	cancelled = sw.cancelled
	s.stateMu.Unlock()
	if !current {
		s.mu.Unlock()
		return context.Canceled
	}
	if cancelled {
		err = context.Canceled
	}
	if err == nil {
		err = s.store.Update(func(st *store.State) error {
			current, exists := st.Profile(wanted)
			if !exists || current.Source != nil && current.Source.Blocked {
				return errors.New("Candidate profile is unavailable or denied by its source")
			}
			st.Desired = copyOwner(wanted)
			return nil
		})
		if err != nil {
			// A failed directory sync can follow rename. Best-effort durable
			// rollback must also restore A on disk, not merely in memory.
			_ = s.store.Update(func(st *store.State) error { st.Desired = copyOwner(sw.owner); return nil })
		}
	}
	if err == nil {
		s.stateMu.Lock()
		s.worker.owner, s.worker.confirmed = copyOwner(wanted), &p
		s.worker.switching = nil
		s.resetTrafficLocked(wanted, s.worker.operation.ID)
		s.worker.operation.Stage, s.worker.operation.StageStartedAt = "connected", time.Now().UnixMilli()
		s.worker.operation.PreviousProfileID = ""
		s.retryDelay, s.nextRetry = time.Second, time.Time{}
		s.stateMu.Unlock()
		s.mu.Unlock()
		s.captureRuntime(generation)
		s.changed()
		return nil
	}
	s.mu.Unlock()
	message := journal.SanitizeSecrets(err.Error(), p.Secrets()...)
	if errors.Is(err, context.Canceled) {
		message = "Profile switch cancelled"
	}
	message, epoch := candidateLog.RecordFailure("switch_failed", message, time.Now().UnixMilli())
	failure := Failure{ProfileID: wanted.ProfileID, Time: time.Now().UnixMilli(), Code: "switch_failed", Message: message, journalEpoch: epoch}
	var restoreErr error
	if sw.cutover {
		s.stateMu.Lock()
		sw.restoring = true
		s.stateMu.Unlock()
		s.stage(generation, "restoring_previous")
		// CancelSwitch must stop B, but still permit bounded restoration of A.
		// Disconnect changes generation and cancels this new restoration context.
		restore, stop := context.WithTimeout(context.Background(), 45*time.Second)
		s.stateMu.Lock()
		if generation != s.worker.generation {
			s.stateMu.Unlock()
			stop()
			return context.Canceled
		}
		s.worker.cancel, s.worker.activeContext = stop, restore
		s.stateMu.Unlock()
		old, exists := s.store.Snapshot().Profile(sw.owner)
		if !exists || old.Source != nil && old.Source.Blocked {
			restoreErr = errors.New("Previous profile is unavailable or denied by its source")
			if r, ok := s.runtime.(interface{ Suspend(context.Context) error }); ok {
				_ = r.Suspend(restore)
			}
		} else {
			s.beginLog(sw.owner, sw.previous)
			restoreErr = s.runtime.Connect(restore, sw.previous)
		}
		stop()
	}
	s.captureRuntime(generation)
	restoredSample := s.readTraffic()
	s.stateMu.Lock()
	if generation != s.worker.generation {
		s.stateMu.Unlock()
		return context.Canceled
	}
	s.worker.switching = nil
	// Preserve the last valid totals even if A is restored into an external-VPN
	// pause. A new owned TUN carries a new epoch, which resets its baseline on
	// the next sample without discarding A's known measurement validity here.
	if sw.cutover && restoreErr == nil && s.worker.runtime.State == "connected" {
		s.updateTrafficLocked(restoredSample)
	}
	if s.worker.failures[wanted.UID] == nil {
		s.worker.failures[wanted.UID] = map[string]Failure{}
	}
	s.worker.failures[wanted.UID][wanted.ProfileID] = failure
	if !cancelled && !errors.Is(err, context.Canceled) {
		if s.worker.switchFailures[wanted.UID] == nil {
			s.worker.switchFailures[wanted.UID] = map[string]Failure{}
		}
		s.worker.switchFailures[wanted.UID][wanted.ProfileID] = failure
	}
	s.worker.operation.Failure = &failure
	s.worker.operation.Stage = "switch_failed"
	if cancelled || errors.Is(err, context.Canceled) {
		s.worker.operation.Stage = "switch_cancelled"
	}
	s.worker.operation.StageStartedAt = time.Now().UnixMilli()
	if restoreErr != nil {
		s.worker.runtime.State, s.worker.runtime.Message = "error", "Previous connection could not be restored; traffic remains protected"
		s.nextRetry, s.retryDelay = time.Now().Add(time.Second), time.Second
	} else {
		s.nextRetry = time.Time{}
	}
	s.stateMu.Unlock()
	s.changed()
	return errors.New(message)
}
