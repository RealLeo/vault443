package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"vault443/internal/journal"
	"vault443/internal/model"
	"vault443/internal/profiles"
	"vault443/internal/store"
)

// SourceInfo contains no URL, path, credential, endpoint chain or raw document.
type SourceInfo struct {
	Kind        string `json:"kind"`
	UpdatedAt   int64  `json:"updatedAt"`
	LastAttempt int64  `json:"lastAttempt"`
	LastError   string `json:"lastError,omitempty"`
	UsingCached bool   `json:"usingCached"`
	Blocked     bool   `json:"blocked"`
	Updating    bool   `json:"updating"`
}

func (s *Service) sourceInfo(uid uint32, p model.Profile) *SourceInfo {
	if p.Source == nil {
		return nil
	}
	s.sourceMu.Lock()
	_, updating := s.sourceJobs[sourceKey(uid, p.ID)]
	s.sourceMu.Unlock()
	return &SourceInfo{Kind: "outline", UpdatedAt: p.Source.UpdatedAt, LastAttempt: p.Source.LastAttempt, LastError: p.Source.LastError, UsingCached: p.Source.UsingCached, Blocked: p.Source.Blocked, Updating: updating}
}
func sourceKey(uid uint32, id string) string { return fmt.Sprintf("%d:%s", uid, id) }

// Independent source jobs never hold the network worker, store or service lock
// while downloading. A per-profile promise deduplicates background/manual and
// connection refreshes; canceled waiters do not cancel somebody else's job.
func (s *Service) refreshSource(ctx context.Context, uid uint32, id string, force bool) (model.Profile, error) {
	key := sourceKey(uid, id)
	s.sourceMu.Lock()
	if pending := s.sourceJobs[key]; pending != nil {
		s.sourceMu.Unlock()
		select {
		case <-ctx.Done():
			return model.Profile{}, ctx.Err()
		case <-pending:
		}
		return s.checkedSource(uid, id)
	}
	p, ok := s.store.Snapshot().Profile(&store.Session{UID: uid, ProfileID: id})
	if !ok || p.Source == nil {
		s.sourceMu.Unlock()
		return p, errors.New("dynamic profile not found")
	}
	if !force && s.now().Unix()-p.Source.LastAttempt < 60 {
		s.sourceMu.Unlock()
		return s.checkedSource(uid, id)
	}
	if len(s.sourceJobs) >= 8 {
		s.sourceMu.Unlock()
		return p, errors.New("too many source refreshes")
	}
	done := make(chan struct{})
	s.sourceJobs[key] = done
	s.sourceMu.Unlock()
	s.changed()
	defer func() { s.sourceMu.Lock(); delete(s.sourceJobs, key); close(done); s.sourceMu.Unlock(); s.changed() }()
	text, err := s.fetch(ctx, p.Source.URL)
	var next model.Profile
	if err == nil {
		next, err = profiles.ParseOutline(text, p.Source.URL, p.Name)
	}
	if ctx.Err() != nil {
		return p, ctx.Err()
	}
	// The cache and source status update in one transaction. Metadata may have
	// changed while the request was in flight; preserve the current values.
	saveErr := s.store.Update(func(st *store.State) error {
		u := st.User(uid)
		for i, old := range u.Profiles {
			if old.ID != id || old.Source == nil || old.Source.URL != p.Source.URL {
				continue
			}
			status := *old.Source
			status.LastAttempt = s.now().Unix()
			if err != nil {
				var provider *profiles.ProviderError
				if errors.As(err, &provider) {
					status.Blocked = true
					status.LastError = journal.SanitizeSecrets(provider.Error(), old.Secrets()...)
				} else {
					status.LastError = "Source refresh failed; saved configuration retained"
				}
				status.UsingCached = !status.Blocked
				old.Source = &status
				p = old
			} else {
				next.ID, next.Name, next.IconID, next.DebugLogging, next.SubscriptionID = old.ID, old.Name, old.IconID, old.DebugLogging, old.SubscriptionID
				next.Source.UpdatedAt, next.Source.LastAttempt = s.now().Unix(), s.now().Unix()
				p = next
			}
			u.Profiles[i] = p
			st.SetUser(uid, u)
			return nil
		}
		return errors.New("dynamic profile no longer exists")
	})
	if saveErr != nil {
		return p, errors.New("source refresh could not be saved")
	}
	return s.checkedSource(uid, id)
}
func (s *Service) checkedSource(uid uint32, id string) (model.Profile, error) {
	p, ok := s.store.Snapshot().Profile(&store.Session{UID: uid, ProfileID: id})
	if !ok || p.Source == nil {
		return p, errors.New("dynamic profile not found")
	}
	if p.Source.Blocked {
		return p, errors.New(p.Source.LastError)
	}
	if p.Source.UpdatedAt == 0 {
		return p, errors.New("no verified Outline configuration is available")
	}
	return p, nil
}

// RequestSourceRefresh is additive IPC. It changes only saved configuration;
// the running process keeps its immutable session configuration until reconnect.
func (s *Service) RequestSourceRefresh(c Caller, id string) (string, error) {
	p, ok := s.store.Snapshot().Profile(&store.Session{UID: c.UID, ProfileID: id})
	if !ok || p.Source == nil {
		return "", errors.New("dynamic profile not found")
	}
	s.sourceMu.Lock()
	count := len(s.sourceJobs)
	s.sourceMu.Unlock()
	if count >= 8 {
		return "", errors.New("too many source refreshes")
	}
	token := fmt.Sprintf("source-%d", time.Now().UnixNano())
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		_, _ = s.refreshSource(ctx, c.UID, id, true)
	}()
	return token, nil
}

func (s *Service) refreshSourcesDue(ctx context.Context) {
	for uidKey, u := range s.store.Snapshot().Users {
		var uid uint32
		if _, e := fmt.Sscan(uidKey, &uid); e != nil {
			continue
		}
		for _, p := range u.Profiles {
			if ctx.Err() != nil {
				return
			}
			if p.Source != nil && s.now().Unix()-p.Source.LastAttempt >= 86400 {
				_, _ = s.refreshSource(ctx, uid, p.ID, false)
			}
		}
	}
}
