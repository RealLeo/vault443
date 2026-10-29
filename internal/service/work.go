package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vault443/internal/journal"
	"vault443/internal/model"
	"vault443/internal/profiles"
	"vault443/internal/worknet"
	"vault443/internal/workvpn"
)

// WorkRuntime owns processes and the shared network coordinator. Run represents
// one attempt; the service owns intention, retries, user isolation and journals.
type WorkRuntime interface {
	Run(context.Context, uint32, workvpn.Profile, *journal.Session, func(worknet.Status)) error
	Forget(context.Context, string) error
	SetRules(context.Context, []workvpn.RouteRule) error
	SetDNSRules(context.Context, []workvpn.DNSRule) error
	Routes() []worknet.RouteInfo
	Snapshot(string) worknet.Status
}
type WorkProfileInfo struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	IconID       string         `json:"iconId"`
	DebugLogging bool           `json:"debugLogging"`
	Kind         string         `json:"kind"`
	Server       string         `json:"server"`
	Transport    string         `json:"transport"`
	Runtime      worknet.Status `json:"runtime"`
	Operation    *Operation     `json:"operation,omitempty"`
	LastFailure  *Failure       `json:"lastFailure,omitempty"`
}
type workActor struct {
	uid           uint32
	profile       workvpn.Profile
	cancel        context.CancelFunc
	done          chan struct{}
	operation     Operation
	status        worknet.Status
	disconnect    bool
	cleanupFailed bool
}
type workService struct {
	store     *workvpn.Store
	runtime   WorkRuntime
	mu        sync.Mutex
	routeMu   sync.Mutex
	actors    map[string]*workActor
	failures  map[uint32]map[string]Failure
	drafts    map[string]workDraft
	preparing map[uint32]int // bounded imports in flight, protected by mu
}

// AttachWork is called before serving requests; existing embedders/tests may
// omit it and retain the complete 1.0 VLESS API.
func (s *Service) AttachWork(st *workvpn.Store, runtime WorkRuntime) {
	s.work = &workService{store: st, runtime: runtime, actors: map[string]*workActor{}, failures: map[uint32]map[string]Failure{}, drafts: map[string]workDraft{}, preparing: map[uint32]int{}}
	if s.journal == nil {
		return
	}
	for key, user := range st.Snapshot().Users {
		n, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			continue
		}
		uid := uint32(n)
		for _, p := range user.Profiles {
			if failure := s.recoverWorkFailure(uid, p.ID); failure != nil {
				if s.work.failures[uid] == nil {
					s.work.failures[uid] = map[string]Failure{}
				}
				s.work.failures[uid][p.ID] = *failure
			}
		}
	}
}
func (s *Service) recoverWorkFailure(uid uint32, id string) *Failure {
	cursor := "tail"
	var fallback *Failure
	for cursor != "" {
		page, err := s.journal.Read(uid, id, cursor, 500)
		if err != nil {
			return fallback
		}
		for i := len(page.Entries) - 1; i >= 0; i-- {
			entry := page.Entries[i]
			if entry.Level != "error" {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, entry.Time)
			if err != nil {
				continue
			}
			f := &Failure{ProfileID: id, Time: at.UnixMilli(), Code: entry.FailureCode, Message: journal.Sanitize(entry.Message)}
			if entry.FailureTime != 0 {
				f.Time = entry.FailureTime
			}
			if entry.FailureCode != "" {
				return f
			}
			if fallback == nil {
				f.Code = "previous_failure"
				fallback = f
			}
		}
		cursor = page.PreviousCursor
	}
	return fallback
}
func (s *Service) requireWork() error {
	if s.work == nil {
		return errors.New("managed OpenVPN is unavailable; update the system service")
	}
	return nil
}
func workOperationID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return fmt.Sprintf("work-%d", time.Now().UnixNano())
	}
	return "work-" + hex.EncodeToString(b[:])
}

// Called under service.mu whenever ownership may change. Lock order is service,
// state, work; no runtime calls are made with those locks held.
func (s *Service) workOwner() (uint32, bool) {
	if s.work == nil {
		return 0, false
	}
	s.work.mu.Lock()
	defer s.work.mu.Unlock()
	for _, a := range s.work.actors {
		return a.uid, true
	}
	for _, d := range s.work.store.Snapshot().Desired {
		return d.UID, true
	}
	return 0, false
}
func (s *Service) workBusyFor(c Caller) bool { uid, ok := s.workOwner(); return ok && uid != c.UID }
func (s *Service) workProfiles(c Caller) []WorkProfileInfo {
	if s.work == nil {
		return nil
	}
	user := s.work.store.Snapshot().User(c.UID)
	s.work.mu.Lock()
	defer s.work.mu.Unlock()
	out := make([]WorkProfileInfo, 0, len(user.Profiles))
	for _, p := range user.Profiles {
		v := WorkProfileInfo{ID: p.ID, Name: p.Name, IconID: p.IconID, DebugLogging: p.DebugLogging, Kind: "openvpn", Runtime: worknet.Status{State: "disconnected"}}
		if len(p.Remotes) > 0 {
			v.Server = p.Remotes[0].Host
			v.Transport = p.Remotes[0].Protocol
		}
		if a := s.work.actors[p.ID]; a != nil && a.uid == c.UID {
			v.Runtime = a.status
			v.Operation = copyOperation(&a.operation)
		}
		if f, ok := s.work.failures[c.UID][p.ID]; ok && time.Since(time.UnixMilli(f.Time)) <= 7*24*time.Hour {
			value := f
			v.LastFailure = &value
		}
		out = append(out, v)
	}
	return out
}
func (s *Service) RequestOpenVPNConnect(ctx context.Context, c Caller, id string) (string, error) {
	if err := s.requireWork(); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.controlChanging {
		return "", errors.New("VPN ownership is changing; wait for cleanup")
	}
	st := s.store.Snapshot()
	s.stateMu.Lock()
	owner := copyOwner(s.ownerLocked(st))
	s.stateMu.Unlock()
	if owner != nil && owner.UID != c.UID || s.workBusyFor(c) {
		return "", errors.New("another user owns the VPN; explicitly take control first")
	}
	p, ok := s.work.store.Snapshot().Profile(c.UID, id)
	if !ok {
		return "", errors.New("profile not found")
	}
	s.work.mu.Lock()
	defer s.work.mu.Unlock()
	if a := s.work.actors[id]; a != nil {
		if a.disconnect {
			return "", errors.New("network cleanup is in progress; retry disconnection if cleanup failed")
		}
		return a.operation.ID, nil
	}
	if len(s.work.actors) >= 16 {
		return "", errors.New("at most 16 work VPN connections may run simultaneously")
	}
	if err := s.work.store.Update(func(st *workvpn.State) error {
		for _, d := range st.Desired {
			if d.ProfileID == id && d.UID == c.UID {
				return nil
			}
		}
		st.Desired = append(st.Desired, workvpn.Desired{UID: c.UID, ProfileID: id})
		return nil
	}); err != nil {
		return "", err
	}
	runctx, cancel := context.WithCancel(ctx)
	a := &workActor{uid: c.UID, profile: p, cancel: cancel, done: make(chan struct{}), operation: Operation{ID: workOperationID(), ProfileID: id, Action: "connect", Stage: "requested", StageStartedAt: time.Now().UnixMilli()}, status: worknet.Status{State: "connecting", Stage: "requested", StageStartedAt: time.Now().UnixMilli()}}
	s.work.actors[id] = a
	go s.runWork(runctx, a)
	s.changed()
	return a.operation.ID, nil
}
func (s *Service) runWork(ctx context.Context, a *workActor) {
	defer close(a.done)
	var log *journal.Session
	if s.journal != nil {
		secrets := []string{}
		for _, v := range a.profile.Inline {
			secrets = append(secrets, v)
			for _, line := range strings.Split(v, "\n") {
				if len(line) > 8 {
					secrets = append(secrets, line)
				}
			}
		}
		for _, o := range a.profile.Options {
			if o.Key == "setenv" && len(o.Args) > 1 {
				secrets = append(secrets, o.Args[1])
			}
		}
		log = s.journal.NewSession(a.uid, a.profile.ID, secrets...)
	}
	log.Log("info", "Work VPN connection requested")
	delay := time.Second
	var successful atomic.Bool
	for ctx.Err() == nil {
		s.work.mu.Lock()
		a.operation.Attempt++
		a.operation.NextRetryAt = 0
		a.operation.Stage = "checking_vpn"
		a.operation.StageStartedAt = time.Now().UnixMilli()
		s.work.mu.Unlock()
		s.changed()
		// Persisted explicit rules must be in force before releasing the handshake.
		err := s.applyWorkRules(ctx, a.uid)
		if err == nil {
			// Metadata changes never interrupt a running tunnel. Pick them up on
			// the next attempt, including automatic recovery after a failure.
			profile := a.profile
			if current, ok := s.work.store.Snapshot().Profile(a.uid, a.profile.ID); ok {
				profile = current
			}
			err = s.work.runtime.Run(ctx, a.uid, profile, log, func(status worknet.Status) {
				if ctx.Err() != nil {
					return
				}
				s.work.mu.Lock()
				if s.work.actors[a.profile.ID] != a || a.disconnect {
					s.work.mu.Unlock()
					return
				}
				a.status = status
				if status.Stage != "" {
					if a.operation.Stage != status.Stage {
						a.operation.Stage = status.Stage
						a.operation.StageStartedAt = status.StageStartedAt
					}
				}
				if status.State == "connected" {
					successful.Store(true)
				}
				s.work.mu.Unlock()
				s.changed()
			})
		}
		if successful.Swap(false) {
			delay = time.Second
		}
		if ctx.Err() != nil {
			break
		}
		if err == nil {
			err = errors.New("OpenVPN connection ended")
		}
		reason := journal.Sanitize(err.Error())
		at := time.Now().UnixMilli()
		s.work.mu.Lock()
		reason, epoch := log.RecordFailure("openvpn_failed", reason, at)
		if s.work.failures[a.uid] == nil {
			s.work.failures[a.uid] = map[string]Failure{}
		}
		s.work.failures[a.uid][a.profile.ID] = Failure{ProfileID: a.profile.ID, Time: at, Code: "openvpn_failed", Message: reason, journalEpoch: epoch}
		a.status = worknet.Status{State: "error", Stage: "retry_wait", Message: reason, StageStartedAt: at}
		a.operation.Stage = "retry_wait"
		a.operation.StageStartedAt = at
		a.operation.NextRetryAt = time.Now().Add(delay).UnixMilli()
		s.work.mu.Unlock()
		s.changed()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		delay *= 2
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
	s.work.mu.Lock()
	manual := a.disconnect
	s.work.mu.Unlock()
	if manual {
		s.finishWorkDisconnect(a, log)
	}
}
func (s *Service) finishWorkDisconnect(a *workActor, log *journal.Session) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	err := s.work.runtime.Forget(ctx, a.profile.ID)
	s.work.mu.Lock()
	if s.work.actors[a.profile.ID] == a {
		if err == nil {
			delete(s.work.actors, a.profile.ID)
		} else {
			a.cleanupFailed = true
			a.status = worknet.Status{State: "error", Stage: "cleanup_failed", Message: "Network cleanup is incomplete; retry disconnection", StageStartedAt: time.Now().UnixMilli()}
			a.operation.Stage = "cleanup_failed"
		}
	}
	s.work.mu.Unlock()
	if err == nil {
		log.Log("info", "Work VPN disconnected by user")
	} else {
		log.Log("error", "Work VPN cleanup is incomplete; retry disconnection")
	}
	s.changed()
}
func (s *Service) RequestOpenVPNDisconnect(ctx context.Context, c Caller, id string) (string, error) {
	if err := s.requireWork(); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.workBusyFor(c) {
		return "", errors.New("another user owns the VPN; explicitly take control first")
	}
	if _, ok := s.work.store.Snapshot().Profile(c.UID, id); !ok {
		return "", errors.New("profile not found")
	}
	s.work.mu.Lock()
	defer s.work.mu.Unlock()
	if err := s.work.store.Update(func(st *workvpn.State) error {
		out := st.Desired[:0]
		for _, d := range st.Desired {
			if d.ProfileID != id || d.UID != c.UID {
				out = append(out, d)
			}
		}
		st.Desired = out
		return nil
	}); err != nil {
		return "", err
	}
	a := s.work.actors[id]
	if a == nil {
		// A supervisor may have died after clearing intention but before Forget.
		// Explicit disconnect must clean persisted controller state even when no
		// live actor remains, and retain ownership if that cleanup fails.
		p, _ := s.work.store.Snapshot().Profile(c.UID, id)
		a = &workActor{uid: c.UID, profile: p, cancel: func() {}, done: make(chan struct{}), disconnect: true,
			operation: Operation{ID: workOperationID(), ProfileID: id, Action: "disconnect", Stage: "restoring_network", StageStartedAt: time.Now().UnixMilli()},
			status:    worknet.Status{State: "disconnecting", Stage: "restoring_network"}}
		s.work.actors[id] = a
		go func() { defer close(a.done); s.finishWorkDisconnect(a, nil) }()
		s.changed()
		return a.operation.ID, nil
	}
	if a.disconnect && !a.cleanupFailed {
		return a.operation.ID, nil
	}
	a.disconnect = true
	a.operation = Operation{ID: workOperationID(), ProfileID: id, Action: "disconnect", Stage: "restoring_network", StageStartedAt: time.Now().UnixMilli()}
	a.status.State = "disconnecting"
	a.status.Stage = "restoring_network"
	if a.cleanupFailed {
		a.cleanupFailed = false
		go s.finishWorkDisconnect(a, nil)
	} else {
		a.cancel()
	}
	s.changed()
	return a.operation.ID, nil
}
func (s *Service) applyWorkRules(ctx context.Context, uid uint32) error {
	s.work.routeMu.Lock()
	defer s.work.routeMu.Unlock()
	u := s.work.store.Snapshot().User(uid)
	if err := s.work.runtime.SetRules(ctx, u.Rules); err != nil {
		return err
	}
	return s.work.runtime.SetDNSRules(ctx, u.DNSRules)
}
func (s *Service) StartWork(ctx context.Context, bootID string) error {
	if s.work == nil {
		return nil
	}
	if bootID == "" {
		return errors.New("missing system boot identity")
	}
	if err := s.work.store.Update(func(st *workvpn.State) error {
		if st.BootID != bootID {
			st.Desired = nil
			st.BootID = bootID
		}
		return nil
	}); err != nil {
		return err
	}
	desired := s.work.store.Snapshot().Desired
	for _, d := range desired {
		if _, err := s.RequestOpenVPNConnect(ctx, Caller{UID: d.UID}, d.ProfileID); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) StopWork(ctx context.Context) {
	if s.work == nil {
		return
	}
	s.work.mu.Lock()
	actors := make([]*workActor, 0, len(s.work.actors))
	for _, a := range s.work.actors {
		actors = append(actors, a)
		a.cancel()
	}
	s.work.mu.Unlock()
	for _, a := range actors {
		select {
		case <-a.done:
		case <-ctx.Done():
			return
		}
	}
}
func (s *Service) disconnectAllWork(ctx context.Context) error {
	if s.work == nil {
		return nil
	}
	s.work.mu.Lock()
	var ids []workvpn.Desired
	for id, a := range s.work.actors {
		ids = append(ids, workvpn.Desired{UID: a.uid, ProfileID: id})
	}
	s.work.mu.Unlock()
	for _, d := range ids {
		if _, err := s.RequestOpenVPNDisconnect(ctx, Caller{UID: d.UID}, d.ProfileID); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.work.mu.Lock()
		n := len(s.work.actors)
		failed := false
		for _, a := range s.work.actors {
			failed = failed || a.cleanupFailed
		}
		s.work.mu.Unlock()
		if n == 0 {
			return nil
		}
		if failed {
			return errors.New("work VPN cleanup is incomplete; retry disconnection")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (s *Service) UpdateOpenVPNProfile(c Caller, id, name, icon string) error {
	if err := s.requireWork(); err != nil {
		return err
	}
	var err error
	name, err = profiles.Name(name)
	if err != nil {
		return err
	}
	if !model.ValidIcon(icon) {
		return errors.New("invalid profile icon")
	}
	err = s.work.store.Update(func(st *workvpn.State) error {
		u := st.User(c.UID)
		for i := range u.Profiles {
			if u.Profiles[i].ID == id {
				u.Profiles[i].Name = name
				u.Profiles[i].IconID = icon
				st.SetUser(c.UID, u)
				return nil
			}
		}
		return errors.New("profile not found")
	})
	if err == nil {
		s.changed()
	}
	return err
}
func (s *Service) SetOpenVPNDebug(c Caller, id string, enabled bool) error {
	if err := s.requireWork(); err != nil {
		return err
	}
	err := s.work.store.Update(func(st *workvpn.State) error {
		u := st.User(c.UID)
		for i := range u.Profiles {
			if u.Profiles[i].ID == id {
				u.Profiles[i].DebugLogging = enabled
				st.SetUser(c.UID, u)
				return nil
			}
		}
		return errors.New("profile not found")
	})
	if err == nil {
		s.changed()
	}
	return err
}
func (s *Service) RemoveOpenVPNProfile(c Caller, id string) error {
	if err := s.requireWork(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.work.mu.Lock()
	defer s.work.mu.Unlock()
	if a := s.work.actors[id]; a != nil && a.uid == c.UID {
		return errors.New("disconnect the profile before removing it")
	}
	err := s.work.store.Update(func(st *workvpn.State) error {
		u := st.User(c.UID)
		for _, r := range u.Rules {
			if r.Target == id {
				return errors.New("remove this profile's route rules first")
			}
		}
		for _, r := range u.DNSRules {
			if r.Target == id {
				return errors.New("remove this profile's DNS rules first")
			}
		}
		for i, p := range u.Profiles {
			if p.ID == id {
				u.Profiles = append(u.Profiles[:i], u.Profiles[i+1:]...)
				st.SetUser(c.UID, u)
				return nil
			}
		}
		return errors.New("profile not found")
	})
	if err == nil {
		delete(s.work.failures[c.UID], id)
		s.changed()
	}
	return err
}
func (s *Service) GetOpenVPNDiagnostics(c Caller, id string) (interface{}, error) {
	if err := s.requireWork(); err != nil {
		return nil, err
	}
	if _, ok := s.work.store.Snapshot().Profile(c.UID, id); !ok {
		return nil, errors.New("profile not found")
	}
	s.mu.Lock()
	busy := s.workBusyFor(c)
	s.stateMu.Lock()
	owner := s.ownerLocked(s.store.Snapshot())
	busy = busy || (owner != nil && owner.UID != c.UID)
	s.stateMu.Unlock()
	defer s.mu.Unlock()
	if busy {
		return map[string]interface{}{"busyByOtherUser": true}, nil
	}
	for _, p := range s.workProfiles(c) {
		if p.ID == id {
			return map[string]interface{}{"runtime": p.Runtime, "network": s.work.runtime.Snapshot(id), "operation": p.Operation, "lastFailure": p.LastFailure, "routes": s.work.runtime.Routes(), "capturedAt": time.Now().UnixMilli()}, nil
		}
	}
	return nil, errors.New("profile not found")
}
func (s *Service) GetOpenVPNLogs(c Caller, id, cursor string, limit int) (journal.Page, error) {
	if err := s.requireWork(); err != nil {
		return journal.Page{}, err
	}
	if _, ok := s.work.store.Snapshot().Profile(c.UID, id); !ok {
		return journal.Page{}, errors.New("profile not found")
	}
	if s.journal == nil {
		return journal.Page{Entries: []journal.Entry{}, NextCursor: cursor}, nil
	}
	return s.journal.Read(c.UID, id, cursor, limit)
}
func (s *Service) ClearOpenVPNLogs(c Caller, id string) error {
	if err := s.requireWork(); err != nil {
		return err
	}
	if _, ok := s.work.store.Snapshot().Profile(c.UID, id); !ok {
		return errors.New("profile not found")
	}
	if s.journal != nil {
		if err := s.journal.Clear(c.UID, id); err != nil {
			return err
		}
	}
	epoch := uint64(0)
	if s.journal != nil {
		epoch = s.journal.Epoch(c.UID, id)
	}
	s.work.mu.Lock()
	if f, ok := s.work.failures[c.UID][id]; ok && (s.journal == nil || f.journalEpoch < epoch) {
		delete(s.work.failures[c.UID], id)
	}
	s.work.mu.Unlock()
	s.changed()
	return nil
}
