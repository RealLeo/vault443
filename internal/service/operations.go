package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"vault443/internal/journal"
	"vault443/internal/model"
	"vault443/internal/store"
)

// Operation is an accepted intention, independent of an individual retry. Times
// are Unix milliseconds so clients can display elapsed time without guessing.
type Operation struct {
	ID             string `json:"id"`
	Action         string `json:"action"`
	ProfileID      string `json:"profileId,omitempty"`
	Stage          string `json:"stage"`
	StageStartedAt int64  `json:"stageStartedAt"`
	Attempt        int    `json:"attempt"`
	NextRetryAt    int64  `json:"nextRetryAt,omitempty"`
}
type Failure struct {
	ProfileID    string `json:"profileId"`
	Time         int64  `json:"time"`
	Code         string `json:"code"`
	Message      string `json:"message"`
	journalEpoch uint64
}
type workItem struct {
	ctx        context.Context
	generation uint64
	run        func(context.Context) error
	done       chan error
}
type workerState struct {
	queue            []*workItem
	running          bool
	generation       uint64
	sequence         uint64
	activeGeneration uint64
	activeContext    context.Context
	cancel           context.CancelFunc
	owner            *store.Session // retained until network cleanup has completed
	operation        *Operation
	operationUID     uint32
	runtime          model.RuntimeStatus
	diagnostics      interface{}
	failures         map[uint32]map[string]Failure
	wake             chan struct{}
}

func (s *Service) initWorker() {
	s.worker.runtime = s.runtime.Status()
	s.worker.diagnostics = s.runtime.Diagnostics(context.Background())
	s.worker.failures = make(map[uint32]map[string]Failure)
	s.worker.wake = make(chan struct{}, 1)
	s.recoverFailures()
}
func (s *Service) OnChange(fn func()) { s.changeMu.Lock(); s.onChange = fn; s.changeMu.Unlock() }

// Coalesce notifications on a separate short-lived dispatcher. A stalled D-Bus
// client must never hold a manager or service lock and delay cancellation.
func (s *Service) changed() {
	s.changeMu.Lock()
	if s.onChange != nil {
		s.changePending = true
		if !s.notifying {
			s.notifying = true
			go s.dispatchChanges()
		}
	}
	s.changeMu.Unlock()
	select {
	case s.worker.wake <- struct{}{}:
	default:
	}
}
func (s *Service) dispatchChanges() {
	for {
		s.changeMu.Lock()
		if !s.changePending {
			s.notifying = false
			s.changeMu.Unlock()
			return
		}
		s.changePending = false
		fn := s.onChange
		s.changeMu.Unlock()
		if fn != nil {
			fn()
		}
	}
}
func copyOwner(owner *store.Session) *store.Session {
	if owner == nil {
		return nil
	}
	value := *owner
	return &value
}
func copyOperation(op *Operation) *Operation {
	if op == nil {
		return nil
	}
	value := *op
	return &value
}
func copyStatus(status model.RuntimeStatus) model.RuntimeStatus {
	status.ExternalVPNs = append([]string{}, status.ExternalVPNs...)
	return status
}
func (s *Service) ownerLocked(st store.State) *store.Session {
	if s.worker.owner != nil {
		return s.worker.owner
	}
	return st.Desired
}
func (s *Service) currentOwner() *store.Session {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return copyOwner(s.worker.owner)
}

func (s *Service) busyFor(c Caller) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.store.Snapshot()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	owner := s.ownerLocked(st)
	return (owner != nil && owner.UID != c.UID) || s.workBusyFor(c)
}
func (s *Service) latestFailureLocked(uid uint32, profileID string) *Failure {
	var latest *Failure
	for id, failure := range s.worker.failures[uid] {
		if profileID != "" && id != profileID {
			continue
		}
		if time.Since(time.UnixMilli(failure.Time)) > 7*24*time.Hour {
			delete(s.worker.failures[uid], id)
			continue
		}
		if latest == nil || failure.Time > latest.Time {
			value := failure
			latest = &value
		}
	}
	return latest
}
func (s *Service) GetSnapshot(c Caller) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.store.Snapshot()
	u := st.User(c.UID)
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	out := Snapshot{Profiles: []ProfileInfo{}, Subscriptions: []SubscriptionInfo{}, Runtime: copyStatus(s.worker.runtime), CanAdmin: c.Admin, WorkProfiles: s.workProfiles(c)}
	for _, p := range u.Profiles {
		out.Profiles = append(out.Profiles, ProfileInfo{ID: p.ID, Name: p.Name, Server: p.Server, Transport: p.Transport, Security: p.Security, IconID: p.Icon(), DebugLogging: p.DebugLogging})
	}
	for _, sub := range u.Subscriptions {
		out.Subscriptions = append(out.Subscriptions, SubscriptionInfo{sub.ID, sub.Name, sub.UpdatedAt})
	}
	if owner := s.ownerLocked(st); owner != nil {
		out.BusyByOtherUser = owner.UID != c.UID
		if !out.BusyByOtherUser {
			out.ActiveProfileID = owner.ProfileID
		}
	}
	out.BusyByOtherUser = out.BusyByOtherUser || s.workBusyFor(c)
	if out.BusyByOtherUser {
		out.ActiveProfileID = ""
		// Even an error message or external interface may identify another session.
		out.Runtime = model.RuntimeStatus{State: out.Runtime.State, GuardArmed: out.Runtime.GuardArmed}
	} else {
		out.Traffic = s.trafficSnapshotLocked(c.UID, time.Now())
		if s.worker.operationUID == c.UID {
			out.Operation = copyOperation(s.worker.operation)
		}
		out.LastFailure = s.latestFailureLocked(c.UID, out.ActiveProfileID)
	}
	if c.Admin && st.Boot != nil && st.Boot.UID == c.UID {
		out.BootProfileID = st.Boot.ProfileID
	}
	return out
}
func (s *Service) GetDiagnostics(ctx context.Context, c Caller) interface{} {
	out, _ := s.profileDiagnostics(c, "")
	return out
}
func (s *Service) GetProfileDiagnostics(ctx context.Context, c Caller, id string) (interface{}, error) {
	return s.profileDiagnostics(c, id)
}
func (s *Service) profileDiagnostics(c Caller, id string) (interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.store.Snapshot()
	u := st.User(c.UID)
	if id != "" {
		if _, ok := st.Profile(&store.Session{UID: c.UID, ProfileID: id}); !ok {
			return nil, errors.New("profile not found")
		}
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if owner := s.ownerLocked(st); (owner != nil && owner.UID != c.UID) || s.workBusyFor(c) {
		return map[string]interface{}{"state": s.worker.runtime.State, "busyByOtherUser": true}, nil
	}
	subs := []map[string]interface{}{}
	for _, sub := range u.Subscriptions {
		subs = append(subs, map[string]interface{}{"id": sub.ID, "lastAttempt": sub.LastAttempt, "lastError": sub.LastError})
	}
	// The cached controller diagnostic was produced on the worker. Overlay the
	// most recent published status; no network mutex or filesystem I/O is needed.
	network := map[string]interface{}{}
	if previous, ok := s.worker.diagnostics.(map[string]interface{}); ok {
		for k, v := range previous {
			network[k] = v
		}
	}
	current := s.worker.runtime
	network["state"], network["message"], network["guardArmed"] = current.State, current.Message, current.GuardArmed
	network["stage"], network["stageStartedAt"] = current.Stage, current.StageStartedAt
	op := copyOperation(s.worker.operation)
	if s.worker.operationUID != c.UID || (id != "" && op != nil && op.ProfileID != id) {
		op = nil
	}
	return map[string]interface{}{"network": network, "runtime": copyStatus(current), "operation": op, "lastFailure": s.latestFailureLocked(c.UID, id), "profileCount": len(u.Profiles), "subscriptions": subs, "capturedAt": time.Now().UnixMilli()}, nil
}

// enqueueLocked and workLoop implement one sequential network executor. The
// control/state locks are never held while invoking the network controller.
func (s *Service) enqueueLocked(job *workItem) {
	s.worker.queue = append(s.worker.queue, job)
	if !s.worker.running {
		s.worker.running = true
		go s.workLoop()
	}
}
func (s *Service) workLoop() {
	for {
		s.stateMu.Lock()
		if len(s.worker.queue) == 0 {
			s.worker.running = false
			s.worker.cancel = nil
			s.worker.activeContext = nil
			s.stateMu.Unlock()
			return
		}
		job := s.worker.queue[0]
		s.worker.queue = s.worker.queue[1:]
		if job.generation != 0 && job.generation != s.worker.generation {
			s.stateMu.Unlock()
			job.done <- context.Canceled
			continue
		}
		ctx, cancel := context.WithCancel(job.ctx)
		s.worker.cancel = cancel
		s.worker.activeContext = ctx
		s.worker.activeGeneration = s.worker.generation
		s.stateMu.Unlock()
		if progress, ok := s.runtime.(interface {
			SetProgressHandler(func(model.RuntimeStatus))
		}); ok {
			progress.SetProgressHandler(s.progress)
		}
		if source, ok := s.runtime.(interface{ SetTrafficHandler(func(model.TUNCounters)) }); ok {
			generation := s.worker.activeGeneration
			source.SetTrafficHandler(func(sample model.TUNCounters) { s.observeTraffic(generation, sample) })
		}
		err := ctx.Err()
		if err == nil {
			err = job.run(ctx)
		}
		cancel()
		s.stateMu.Lock()
		s.worker.cancel = nil
		s.worker.activeContext = nil
		s.stateMu.Unlock()
		job.done <- err
	}
}
func (s *Service) cleanupFailedLocked() bool {
	op := s.worker.operation
	return op != nil && op.Action == "disconnect" && op.Stage == "cleanup_failed"
}

func (s *Service) progress(status model.RuntimeStatus) {
	// Manager publishes an immutable diagnostic view before calling us. Keep it
	// alongside the stage, so a new connection cannot report an earlier session's
	// IPv6 availability while its own probe is still running. Read outside locks.
	diagnostics := s.runtime.Diagnostics(context.Background())
	sample := s.readTraffic()
	s.stateMu.Lock()
	if s.worker.activeGeneration != s.worker.generation || s.worker.activeContext == nil || s.worker.activeContext.Err() != nil || s.cleanupFailedLocked() {
		s.stateMu.Unlock()
		return
	}
	s.worker.runtime = copyStatus(status)
	s.syncTrafficLocked(status, sample, time.Now())
	s.worker.diagnostics = diagnostics
	if op := s.worker.operation; op != nil && status.Stage != "" && op.NextRetryAt == 0 {
		if op.Stage != status.Stage {
			op.Stage = status.Stage
			op.StageStartedAt = status.StageStartedAt
			if op.StageStartedAt == 0 {
				op.StageStartedAt = time.Now().UnixMilli()
			}
		}
	}
	s.stateMu.Unlock()
	s.changed()
}
func (s *Service) captureRuntime(generation uint64) {
	status := s.runtime.Status()
	diagnostics := s.runtime.Diagnostics(context.Background())
	sample := s.readTraffic()
	s.stateMu.Lock()
	if generation == 0 {
		generation = s.worker.activeGeneration
	}
	if generation == s.worker.generation && !s.cleanupFailedLocked() {
		s.worker.runtime = copyStatus(status)
		s.syncTrafficLocked(status, sample, time.Now())
		s.worker.diagnostics = diagnostics
	}
	s.stateMu.Unlock()
}
func (s *Service) stage(generation uint64, value string) {
	s.stateMu.Lock()
	if generation == s.worker.generation && s.worker.operation != nil {
		s.worker.operation.Stage = value
		s.worker.operation.StageStartedAt = time.Now().UnixMilli()
		s.worker.operation.NextRetryAt = 0
	}
	s.stateMu.Unlock()
	s.changed()
}
func waitJob(ctx context.Context, job *workItem) error {
	select {
	case err := <-job.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Service) requestConnect(ctx context.Context, c Caller, id string) (string, *workItem, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.controlChanging {
		return "", nil, errors.New("VPN ownership is changing; wait for cleanup")
	}
	st := s.store.Snapshot()
	s.stateMu.Lock()
	owner := s.ownerLocked(st)
	if (owner != nil && owner.UID != c.UID) || s.workBusyFor(c) {
		s.stateMu.Unlock()
		return "", nil, errors.New("another user owns the VPN; explicitly take control first")
	}
	if s.worker.operation != nil && s.worker.operation.Action == "disconnect" && s.worker.owner != nil {
		s.stateMu.Unlock()
		return "", nil, errors.New("network cleanup is in progress; wait until disconnection completes")
	}
	s.stateMu.Unlock()
	wanted := &store.Session{UID: c.UID, ProfileID: id}
	p, ok := st.Profile(wanted)
	if !ok {
		return "", nil, errors.New("profile not found")
	}
	if err := s.store.Update(func(st *store.State) error { st.Desired = wanted; return nil }); err != nil {
		return "", nil, err
	}
	s.stateMu.Lock()
	if s.worker.cancel != nil {
		s.worker.cancel()
	}
	s.worker.generation++
	generation := s.worker.generation
	s.worker.sequence++
	operationID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), s.worker.sequence)
	s.worker.owner = copyOwner(wanted)
	s.resetTrafficLocked(wanted, operationID)
	s.worker.operationUID = c.UID
	s.worker.operation = &Operation{ID: operationID, Action: "connect", ProfileID: id, Stage: "requested", StageStartedAt: time.Now().UnixMilli(), Attempt: 1}
	s.worker.runtime.State = "connecting"
	s.worker.runtime.Message = ""
	s.worker.runtime.Stage = "requested"
	s.worker.runtime.StageStartedAt = s.worker.operation.StageStartedAt
	s.nextRetry = time.Time{}
	s.retryDelay = time.Second
	job := &workItem{ctx: ctx, generation: generation, done: make(chan error, 1)}
	job.run = func(ctx context.Context) error { return s.attempt(ctx, generation, wanted, p) }
	s.enqueueLocked(job)
	s.stateMu.Unlock()
	s.changed()
	return operationID, job, nil
}
func (s *Service) RequestConnect(ctx context.Context, c Caller, id string) (string, error) {
	id, _, err := s.requestConnect(ctx, c, id)
	return id, err
}
func (s *Service) Connect(ctx context.Context, c Caller, id string) error {
	_, job, err := s.requestConnect(ctx, c, id)
	if err != nil {
		return err
	}
	return waitJob(ctx, job)
}
func (s *Service) requestDisconnect(ctx context.Context, c Caller, takeover bool) (string, *workItem, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.store.Snapshot()
	s.stateMu.Lock()
	owner := copyOwner(s.ownerLocked(st))
	if ((owner != nil && owner.UID != c.UID) || s.workBusyFor(c)) && !takeover {
		s.stateMu.Unlock()
		return "", nil, errors.New("another user owns the VPN; explicitly take control first")
	}
	s.stateMu.Unlock()
	// Crash-safe intent is cleared before cancelling DNS/HTTP or starting cleanup.
	if err := s.store.Update(func(st *store.State) error { st.Desired = nil; return nil }); err != nil {
		return "", nil, err
	}
	s.stateMu.Lock()
	if s.worker.cancel != nil {
		s.worker.cancel()
	}
	s.worker.generation++
	generation := s.worker.generation
	s.worker.sequence++
	operationID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), s.worker.sequence)
	if owner == nil {
		owner = &store.Session{UID: c.UID}
	}
	s.worker.owner = owner
	s.worker.operationUID = owner.UID
	s.worker.operation = &Operation{ID: operationID, Action: "disconnect", ProfileID: owner.ProfileID, Stage: "restoring_network", StageStartedAt: time.Now().UnixMilli()}
	s.worker.runtime.State = "disconnecting"
	s.worker.runtime.Stage = "restoring_network"
	s.worker.runtime.StageStartedAt = s.worker.operation.StageStartedAt
	s.nextRetry = time.Time{}
	job := &workItem{ctx: ctx, generation: generation, done: make(chan error, 1)}
	job.run = func(ctx context.Context) error {
		err := s.runtime.Disconnect(ctx)
		s.captureRuntime(generation)
		s.logResult(err, "Disconnected by user; network protection released", "Network cleanup is incomplete")
		s.stateMu.Lock()
		if generation == s.worker.generation {
			if err == nil {
				s.finishTrafficLocked(time.Now())
				s.worker.owner = nil
				s.worker.operation.Stage = "disconnected"
			} else {
				s.worker.operation.Stage = "cleanup_failed"
				s.worker.runtime.State = "error"
				s.worker.runtime.Stage = "cleanup_failed"
				s.worker.runtime.StageStartedAt = time.Now().UnixMilli()
				s.worker.runtime.Message = "Network cleanup is incomplete; protection may remain enabled. Retry disconnection."
				s.worker.runtime.FailureCode = "cleanup_failed"
			}
			s.worker.operation.StageStartedAt = time.Now().UnixMilli()
		}
		s.stateMu.Unlock()
		if err == nil {
			s.endLog()
		}
		s.changed()
		if err != nil {
			return errors.New("network cleanup is incomplete; see diagnostics")
		}
		return nil
	}
	s.enqueueLocked(job)
	s.stateMu.Unlock()
	s.changed()
	return operationID, job, nil
}
func (s *Service) RequestDisconnect(ctx context.Context, c Caller) (string, error) {
	id, _, err := s.requestDisconnect(ctx, c, false)
	return id, err
}
func (s *Service) Disconnect(ctx context.Context, c Caller) error {
	_, job, err := s.requestDisconnect(ctx, c, false)
	if err != nil {
		return err
	}
	return waitJob(ctx, job)
}
func (s *Service) TakeControl(ctx context.Context, c Caller) error {
	s.mu.Lock()
	if s.controlChanging {
		s.mu.Unlock()
		return errors.New("VPN ownership is changing; wait for cleanup")
	}
	s.controlChanging = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.controlChanging = false; s.mu.Unlock() }()
	if err := s.disconnectAllWork(ctx); err != nil {
		return err
	}
	_, job, err := s.requestDisconnect(ctx, c, true)
	if err != nil {
		return err
	}
	return waitJob(ctx, job)
}
func (s *Service) attempt(ctx context.Context, generation uint64, owner *store.Session, p model.Profile) error {
	s.beginLog(owner, p)
	s.log("info", "Connection requested")
	s.stage(generation, "enabling_guard")
	err := s.runtime.Arm(ctx)
	s.captureRuntime(generation)
	if err == nil && ctx.Err() == nil {
		s.stage(generation, "checking_vpn")
		err = s.runtime.Connect(ctx, p)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	status := s.runtime.Status()
	s.captureRuntime(generation)
	s.stateMu.Lock()
	if generation != s.worker.generation {
		s.stateMu.Unlock()
		return context.Canceled
	}
	if err != nil {
		failure := s.rememberFailureLocked(owner, status)
		s.stateMu.Unlock()
		s.changed()
		return errors.New(failure.Message)
	}
	s.retryDelay = time.Second
	s.nextRetry = time.Time{}
	stage := "connected"
	if status.State == "paused_external" {
		stage = "paused_external"
	}
	s.worker.operation.Stage = stage
	s.worker.operation.StageStartedAt = time.Now().UnixMilli()
	s.worker.operation.NextRetryAt = 0
	s.stateMu.Unlock()
	s.log("info", "Connection attempt completed")
	s.changed()
	return nil
}

// Caller holds stateMu. RecordFailure only sanitizes and enqueues into reserved
// memory; the journal writer performs filesystem I/O independently.
func (s *Service) rememberFailureLocked(owner *store.Session, status model.RuntimeStatus) Failure {
	reason := journal.Sanitize(status.Message)
	if reason == "" {
		reason = "Connection failed; see the profile journal"
	}
	code := journal.NormalizeFailureCode(status.FailureCode)
	at := time.Now().UnixMilli()
	reason, epoch := s.logSession.RecordFailure(code, reason, at)
	failure := Failure{ProfileID: owner.ProfileID, Time: at, Code: code, Message: reason, journalEpoch: epoch}
	if s.worker.failures[owner.UID] == nil {
		s.worker.failures[owner.UID] = map[string]Failure{}
	}
	s.worker.failures[owner.UID][owner.ProfileID] = failure
	s.nextRetry = time.Now().Add(s.retryDelay)
	s.retryDelay *= 2
	if s.retryDelay > 30*time.Second {
		s.retryDelay = 30 * time.Second
	}
	if s.worker.operation != nil {
		s.worker.operation.Stage = "retry_wait"
		s.worker.operation.StageStartedAt = time.Now().UnixMilli()
		s.worker.operation.NextRetryAt = s.nextRetry.UnixMilli()
	}
	s.worker.runtime.State = "error"
	s.worker.runtime.Message = reason
	return failure
}

func (s *Service) maintenance(ctx context.Context, run func(context.Context) error) error {
	job := &workItem{ctx: ctx, run: run, done: make(chan error, 1)}
	s.stateMu.Lock()
	s.enqueueLocked(job)
	s.stateMu.Unlock()
	return waitJob(ctx, job)
}
func (s *Service) SetVPNBinding(ctx context.Context, c Caller, binding string) error {
	if !c.Admin {
		return errors.New("administrator membership is required")
	}
	if len(binding) > 64<<10 {
		return errors.New("binding exceeds size limit")
	}
	return s.maintenance(ctx, func(ctx context.Context) error {
		if err := s.runtime.SetVPNBinding(ctx, binding); err != nil {
			return errors.New("invalid VPN binding; use the documented manager/interface format")
		}
		s.captureRuntime(0)
		s.changed()
		return nil
	})
}

// Early boot and root maintenance use the same executor as ordinary requests.
func (s *Service) BootGuard(ctx context.Context, bootID string) error {
	if bootID == "" {
		return errors.New("missing system boot identity")
	}
	st := s.store.Snapshot()
	selected := st.Boot
	if st.BootID == bootID {
		selected = st.Desired
	}
	if selected == nil {
		return nil
	}
	p, ok := st.Profile(selected)
	if !ok {
		return errors.New("boot guard profile is missing")
	}
	return s.maintenance(ctx, func(ctx context.Context) error {
		s.beginLog(selected, p)
		err := s.runtime.Arm(ctx)
		s.captureRuntime(0)
		s.logResult(err, "Early boot protection armed", "Early boot protection failed")
		return err
	})
}
func (s *Service) ReleaseNetwork(ctx context.Context) error {
	if err := s.disconnectAllWork(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	err := s.store.Update(func(st *store.State) error { st.Desired = nil; st.Boot = nil; return nil })
	s.stateMu.Lock()
	if s.worker.cancel != nil {
		s.worker.cancel()
	}
	s.worker.generation++
	s.nextRetry = time.Time{}
	s.stateMu.Unlock()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.maintenance(ctx, func(ctx context.Context) error {
		if err := s.runtime.Disconnect(ctx); err != nil {
			s.log("error", "Network release failed")
			return errors.New("network release failed; protection may remain armed; inspect system journal and retry --release-network")
		}
		s.captureRuntime(0)
		s.log("info", "Network released for maintenance")
		s.endLog()
		s.stateMu.Lock()
		s.finishTrafficLocked(time.Now())
		s.worker.owner = nil
		s.worker.operation = nil
		s.stateMu.Unlock()
		s.changed()
		return nil
	})
}

// A daemon restart resumes desired intent; a new boot elects only its boot profile.
func (s *Service) Start(ctx context.Context, bootID string) error {
	if bootID == "" {
		return errors.New("missing system boot identity")
	}
	s.mu.Lock()
	err := s.store.Update(func(st *store.State) error {
		if st.BootID != bootID {
			st.Desired = st.Boot
			st.BootID = bootID
		}
		return nil
	})
	st := s.store.Snapshot()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if st.Desired == nil {
		s.stateMu.Lock()
		s.worker.owner = nil
		s.worker.operation = nil
		s.stateMu.Unlock()
		return nil
	}
	owner := copyOwner(st.Desired)
	p, ok := st.Profile(owner)
	if !ok {
		return errors.New("startup profile is missing")
	}
	s.stateMu.Lock()
	s.worker.owner = copyOwner(owner)
	s.worker.operationUID = owner.UID
	s.worker.generation++
	generation := s.worker.generation
	s.worker.operation = &Operation{ID: fmt.Sprintf("%d-startup", time.Now().UnixNano()), Action: "connect", ProfileID: p.ID, Stage: "requested", StageStartedAt: time.Now().UnixMilli()}
	s.resetTrafficLocked(owner, s.worker.operation.ID)
	s.stateMu.Unlock()
	return s.maintenance(ctx, func(ctx context.Context) error {
		s.beginLog(owner, p)
		s.log("info", "Restoring persisted connection after service startup")
		err := s.runtime.Arm(ctx)
		s.captureRuntime(generation)
		if err != nil {
			s.log("error", "Startup network protection could not be armed")
			return errors.New("boot network protection could not be armed")
		}
		return nil
	})
}
func (s *Service) tickJob(ctx context.Context, now time.Time) *workItem {
	if s.work != nil {
		s.work.mu.Lock()
		s.pruneWorkDraftsLocked()
		s.work.mu.Unlock()
	}
	s.draftMu.Lock()
	s.pruneDrafts(now)
	s.draftMu.Unlock()
	s.stateMu.Lock()
	generation := s.worker.generation
	job := &workItem{ctx: ctx, generation: generation, done: make(chan error, 1)}
	job.run = func(ctx context.Context) error {
		s.stateMu.Lock()
		cleanupFailed := s.cleanupFailedLocked()
		s.stateMu.Unlock()
		// Cancellation cleared desired intent; preserve failed-cleanup ownership and
		// its actionable Retry state until an explicit new disconnect performs it.
		if cleanupFailed {
			return nil
		}
		before := s.runtime.Status()
		reconcileErr := s.runtime.Reconcile(ctx)
		s.captureRuntime(generation)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.mu.Lock()
		st := s.store.Snapshot()
		s.stateMu.Lock()
		status := s.worker.runtime
		owner := copyOwner(st.Desired)
		var failure *Failure
		if reconcileErr != nil && status.State == "error" && owner != nil && generation == s.worker.generation && (before.State == "connected" || before.State == "paused_external") {
			value := s.rememberFailureLocked(owner, status)
			failure = &value
		}
		due := failure == nil && owner != nil && generation == s.worker.generation && status.State != "connected" && status.State != "paused_external" && !now.Before(s.nextRetry)
		p, ok := st.Profile(owner)
		if due && ok {
			if s.worker.operation == nil {
				s.worker.operation = &Operation{ID: fmt.Sprintf("%d-recovery", time.Now().UnixNano()), Action: "connect", ProfileID: p.ID}
			}
			s.worker.owner = copyOwner(owner)
			s.worker.operationUID = owner.UID
			s.worker.operation.Attempt++
			s.worker.operation.NextRetryAt = 0
		} else if generation == s.worker.generation && s.worker.operation != nil && s.worker.operation.Action == "connect" && status.State == "paused_external" {
			s.worker.operation.Stage = "paused_external"
			s.worker.operation.NextRetryAt = 0
			s.nextRetry = time.Time{}
		}
		s.stateMu.Unlock()
		s.mu.Unlock()
		if failure != nil {
			s.changed()
		}
		if due && ok {
			return s.attempt(ctx, generation, owner, p)
		}
		after := s.runtime.Status()
		if before.State != after.State || before.GuardArmed != after.GuardArmed || before.RXBytes != after.RXBytes || before.TXBytes != after.TXBytes {
			s.changed()
		}
		return nil
	}
	s.enqueueLocked(job)
	s.stateMu.Unlock()
	return job
}
func (s *Service) Tick(ctx context.Context, now time.Time) { _ = waitJob(ctx, s.tickJob(ctx, now)) }
func (s *Service) Run(ctx context.Context) {
	go s.runTraffic(ctx)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var events <-chan struct{}
	if watcher, ok := s.runtime.(interface {
		Watch(context.Context) (<-chan struct{}, error)
	}); ok {
		var err error
		events, err = watcher.Watch(ctx)
		if err != nil {
			log.Print("Network event subscription unavailable; periodic reconciliation remains active")
		}
	}
	debounce := time.NewTimer(time.Hour)
	debounce.Stop()
	defer debounce.Stop()
	retry := time.NewTimer(time.Hour)
	retry.Stop()
	defer retry.Stop()
	var pending <-chan time.Time
	var retryC <-chan time.Time
	var tickDone <-chan error
	dispatch := func(now time.Time) {
		if tickDone == nil {
			tickDone = s.tickJob(ctx, now).done
		}
	}
	resetRetry := func() {
		if !retry.Stop() {
			select {
			case <-retry.C:
			default:
			}
		}
		s.stateMu.Lock()
		next := s.nextRetry
		s.stateMu.Unlock()
		retryC = nil
		if !next.IsZero() && tickDone == nil {
			delay := time.Until(next)
			if delay < 0 {
				delay = 0
			}
			retry.Reset(delay)
			retryC = retry.C
		}
	}
	dispatch(time.Now())
	for {
		select {
		case <-ctx.Done():
			s.stateMu.Lock()
			if s.worker.cancel != nil {
				s.worker.cancel()
			}
			s.stateMu.Unlock()
			return
		case now := <-ticker.C:
			dispatch(now)
		case <-s.worker.wake:
			resetRetry()
		case <-tickDone:
			tickDone = nil
			resetRetry()
		case now := <-retryC:
			retryC = nil
			dispatch(now)
		case _, open := <-events:
			if !open {
				events = nil
				continue
			}
			if pending == nil {
				debounce.Reset(150 * time.Millisecond)
				pending = debounce.C
			}
		case now := <-pending:
			pending = nil
			dispatch(now)
		}
	}
}

func (s *Service) recoverFailures() {
	if s.journal == nil {
		return
	}
	st := s.store.Snapshot()
	for key, user := range st.Users {
		uidValue, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			continue
		}
		uid := uint32(uidValue)
		for _, profile := range user.Profiles {
			cursor := "tail"
			var fallback *Failure
			var recovered *Failure
			for cursor != "" {
				page, err := s.journal.Read(uid, profile.ID, cursor, 500)
				if err != nil {
					break
				}
				for i := len(page.Entries) - 1; i >= 0; i-- {
					entry := page.Entries[i]
					if entry.FailureCode != "" {
						at := entry.FailureTime
						if at == 0 {
							if parsed, err := time.Parse(time.RFC3339Nano, entry.Time); err == nil {
								at = parsed.UnixMilli()
							}
						}
						recovered = &Failure{ProfileID: profile.ID, Time: at, Code: entry.FailureCode, Message: entry.Message}
						break
					}
					if fallback == nil && entry.Level == "error" {
						if at, err := time.Parse(time.RFC3339Nano, entry.Time); err == nil {
							fallback = &Failure{ProfileID: profile.ID, Time: at.UnixMilli(), Code: "previous_failure", Message: journal.Sanitize(entry.Message)}
						}
					}
				}
				if recovered != nil {
					break
				}
				cursor = page.PreviousCursor
			}
			if recovered == nil {
				recovered = fallback
			}
			if recovered != nil {
				if s.worker.failures[uid] == nil {
					s.worker.failures[uid] = map[string]Failure{}
				}
				s.worker.failures[uid][profile.ID] = *recovered
			}
		}
	}
}
