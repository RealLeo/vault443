// Package service owns profiles, authorization-independent domain operations,
// and the persistent desired session. IPC supplies a verified caller identity.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"vault443/internal/journal"
	"vault443/internal/model"
	"vault443/internal/profiles"
	"vault443/internal/store"
)

type Runtime interface {
	Connect(context.Context, model.Profile) error
	Disconnect(context.Context) error
	Reconcile(context.Context) error
	Status() model.RuntimeStatus
	Arm(context.Context) error
	SetVPNBinding(context.Context, string) error
	Diagnostics(context.Context) interface{}
}
type Caller struct {
	UID   uint32
	Admin bool
}
type ProfileInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Server       string `json:"server"`
	Transport    string `json:"transport"`
	Security     string `json:"security"`
	IconID       string `json:"iconId"`
	DebugLogging bool   `json:"debugLogging"`
}
type SubscriptionInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	UpdatedAt int64  `json:"updatedAt"`
}
type Snapshot struct {
	Profiles        []ProfileInfo       `json:"profiles"`
	Subscriptions   []SubscriptionInfo  `json:"subscriptions"`
	Runtime         model.RuntimeStatus `json:"runtime"`
	Traffic         *model.Traffic      `json:"traffic,omitempty"`
	ActiveProfileID string              `json:"activeProfileId"`
	BusyByOtherUser bool                `json:"busyByOtherUser"`
	BootProfileID   string              `json:"bootProfileId"`
	CanAdmin        bool                `json:"canAdmin"`
	Operation       *Operation          `json:"operation,omitempty"`
	LastFailure     *Failure            `json:"lastFailure,omitempty"`
}
type Fetch func(context.Context, string) (string, error)
type Service struct {
	mu            sync.Mutex
	changeMu      sync.Mutex
	notifying     bool
	changePending bool
	stateMu       sync.Mutex
	worker        workerState
	traffic       trafficState
	draftMu       sync.Mutex
	drafts        map[string]importDraft
	now           func() time.Time
	refreshMu     sync.Mutex
	store         *store.Store
	runtime       Runtime
	journal       *journal.Journal
	logSession    *journal.Session
	logOwner      *store.Session
	fetch         Fetch
	onChange      func()
	nextRetry     time.Time
	retryDelay    time.Duration
}

func New(st *store.Store, r Runtime, journals ...*journal.Journal) *Service {
	s := &Service{store: st, runtime: r, fetch: profiles.FetchSubscription, retryDelay: time.Second, drafts: map[string]importDraft{}, now: time.Now}
	if len(journals) > 0 {
		s.journal = journals[0]
	}
	s.initWorker()
	return s
}
func (s *Service) PreviewImport(c Caller, text string) profiles.Preview {
	return profiles.PreviewText(text, s.store.Snapshot().User(c.UID).Profiles)
}
func (s *Service) ImportProfiles(c Caller, text string) (profiles.Preview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result profiles.Preview
	err := s.store.Update(func(state *store.State) error {
		u := state.User(c.UID)
		result = profiles.PreviewText(text, u.Profiles)
		for _, entry := range result.Profiles {
			if !entry.Duplicate {
				u.Profiles = append(u.Profiles, entry.Profile)
			}
		}
		if len(u.Profiles) > profiles.MaxProfiles {
			return errors.New("a user may keep at most 1024 profiles")
		}
		state.SetUser(c.UID, u)
		return nil
	})
	if err == nil {
		s.changed()
	}
	return result, err
}
func (s *Service) RemoveProfile(c Caller, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateMu.Lock()
	owner := s.worker.owner
	removingActive := owner != nil && owner.UID == c.UID && owner.ProfileID == id
	s.stateMu.Unlock()
	if removingActive {
		return errors.New("disconnect the profile before removing it")
	}

	err := s.store.Update(func(st *store.State) error {
		if st.Desired != nil && st.Desired.UID == c.UID && st.Desired.ProfileID == id {
			return errors.New("disconnect the profile before removing it")
		}
		if st.Boot != nil && st.Boot.UID == c.UID && st.Boot.ProfileID == id {
			return errors.New("disable boot autoconnect before removing the profile")
		}
		u := st.User(c.UID)
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
		s.stateMu.Lock()
		delete(s.worker.failures[c.UID], id)
		s.stateMu.Unlock()
		s.changed()
	}
	return err
}
func (s *Service) RenameProfile(c Caller, id, name string) error {
	name, err := profiles.Name(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.store.Update(func(st *store.State) error {
		u := st.User(c.UID)
		for i := range u.Profiles {
			if u.Profiles[i].ID == id {
				u.Profiles[i].Name = name
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
func (s *Service) SetBootProfile(c Caller, id string) error {
	if !c.Admin {
		return errors.New("administrator membership is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.store.Update(func(st *store.State) error {
		if id == "" {
			st.Boot = nil
			return nil
		}
		candidate := &store.Session{UID: c.UID, ProfileID: id}
		if _, ok := st.Profile(candidate); !ok {
			return errors.New("profile not found")
		}
		st.Boot = candidate
		return nil
	})
	if err == nil {
		s.changed()
	}
	return err
}
func (s *Service) RunSubscriptions(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		s.refreshDue(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func subscriptionID(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}
func (s *Service) AddSubscription(ctx context.Context, c Caller, raw, name string) (profiles.Preview, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	var empty profiles.Preview
	if _, err := profiles.SubscriptionURL(raw); err != nil {
		return empty, err
	}
	name, err := profiles.Name(name)
	if err != nil {
		return empty, err
	}
	text, err := s.fetch(ctx, raw)
	if err != nil {
		return empty, err
	}
	preview := profiles.PreviewText(text, nil)
	if len(preview.Errors) > 0 || len(preview.Profiles) == 0 {
		return preview, errors.New("subscription contains unsupported or invalid profiles; nothing changed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := subscriptionID(raw)
	now := time.Now().Unix()
	err = s.store.Update(func(st *store.State) error {
		u := st.User(c.UID)
		for _, sub := range u.Subscriptions {
			if sub.ID == id {
				return errors.New("subscription already exists")
			}
		}
		if len(u.Subscriptions) >= 32 {
			return errors.New("a user may keep at most 32 subscriptions")
		}
		u.Subscriptions = append(u.Subscriptions, store.Subscription{ID: id, Name: name, URL: raw, UpdatedAt: now, LastAttempt: now})
		if err := replaceSource(st, c.UID, &u, id, preview, s.currentOwner()); err != nil {
			return err
		}
		st.SetUser(c.UID, u)
		return nil
	})
	if err == nil {
		s.changed()
	}
	return preview, err
}

// Removing a source never deletes a working profile. Detach all of its nodes,
// preserving active and boot selections and allowing manual profile management.
func (s *Service) RemoveSubscription(c Caller, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.store.Update(func(st *store.State) error {
		u := st.User(c.UID)
		index := -1
		for i, sub := range u.Subscriptions {
			if sub.ID == id {
				index = i
				break
			}
		}
		if index < 0 {
			return errors.New("subscription not found")
		}
		u.Subscriptions = append(u.Subscriptions[:index], u.Subscriptions[index+1:]...)
		for i := range u.Profiles {
			if u.Profiles[i].SubscriptionID == id {
				u.Profiles[i].SubscriptionID = ""
			}
		}
		st.SetUser(c.UID, u)
		return nil
	})
	if err == nil {
		s.changed()
	}
	return err
}

type RefreshResult struct {
	ID      string `json:"id"`
	Updated bool   `json:"updated"`
	Message string `json:"message,omitempty"`
}

func (s *Service) RefreshSubscriptions(ctx context.Context, c Caller) []RefreshResult {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	subs := s.store.Snapshot().User(c.UID).Subscriptions
	out := []RefreshResult{}
	for _, sub := range subs {
		if ctx.Err() != nil {
			break
		}
		out = append(out, s.refresh(ctx, c.UID, sub))
	}
	return out
}
func (s *Service) refreshDue(ctx context.Context, now time.Time) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	st := s.store.Snapshot()
	for uidKey, u := range st.Users {
		var uid uint32
		if _, err := fmt.Sscan(uidKey, &uid); err != nil {
			continue
		}
		for _, sub := range u.Subscriptions {
			if ctx.Err() != nil {
				return
			}
			if now.Unix()-sub.LastAttempt >= 86400 {
				_ = s.refresh(ctx, uid, sub)
			}
		}
	}
}
func (s *Service) refresh(ctx context.Context, uid uint32, sub store.Subscription) RefreshResult {
	text, err := s.fetch(ctx, sub.URL)
	preview := profiles.PreviewText(text, nil)
	if err == nil && (len(preview.Errors) > 0 || len(preview.Profiles) == 0) {
		err = errors.New("subscription contains unsupported or invalid profiles")
	}
	result := RefreshResult{ID: sub.ID}
	if err != nil {
		result.Message = "Refresh failed; existing profiles were preserved"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	saveErr := s.store.Update(func(st *store.State) error {
		u := st.User(uid)
		index := -1
		for i := range u.Subscriptions {
			if u.Subscriptions[i].ID == sub.ID {
				index = i
				break
			}
		}
		if index < 0 {
			return errors.New("subscription no longer exists")
		}
		u.Subscriptions[index].LastAttempt = time.Now().Unix()
		u.Subscriptions[index].LastError = result.Message
		if err == nil {
			if e := replaceSource(st, uid, &u, sub.ID, preview, s.currentOwner()); e != nil {
				return e
			}
			u.Subscriptions[index].UpdatedAt = time.Now().Unix()
			result.Updated = true
		}
		st.SetUser(uid, u)
		return nil
	})
	if saveErr != nil {
		result.Updated = false
		result.Message = "Refresh could not be saved; existing profiles were preserved"
	} else {
		s.changed()
	}
	return result
}
func replaceSource(st *store.State, uid uint32, u *store.User, id string, preview profiles.Preview, protected *store.Session) error {
	old := map[string]model.Profile{}
	retained := []model.Profile{}
	seen := map[string]bool{}
	for _, p := range u.Profiles {
		old[p.ID] = p
		active := st.Desired != nil && st.Desired.UID == uid && st.Desired.ProfileID == p.ID
		boot := st.Boot != nil && st.Boot.UID == uid && st.Boot.ProfileID == p.ID
		cleanup := protected != nil && protected.UID == uid && protected.ProfileID == p.ID
		if p.SubscriptionID != id || active || boot || cleanup {
			retained = append(retained, p)
			seen[p.ID] = true
		}
	}
	for _, entry := range preview.Profiles {
		p := entry.Profile
		if seen[p.ID] {
			continue
		}
		if prev, ok := old[p.ID]; ok {
			p.Name = prev.Name
			p.IconID = prev.Icon()
			p.DebugLogging = prev.DebugLogging
		}
		p.SubscriptionID = id
		retained = append(retained, p)
		seen[p.ID] = true
	}
	if len(retained) > profiles.MaxProfiles {
		return errors.New("subscription would exceed 1024 profiles")
	}
	u.Profiles = retained
	return nil
}
