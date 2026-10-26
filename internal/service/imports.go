package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"vault443/internal/model"
	"vault443/internal/profiles"
	"vault443/internal/store"
)

const importLifetime = 10 * time.Minute

type PreparedImport struct {
	DraftID   string `json:"draftId"`
	ExpiresAt int64  `json:"expiresAt"`
	profiles.Preview
}

type importDraft struct {
	UID                uint32
	Expires            time.Time
	Kind, Source, Name string
	Preview            profiles.Preview
}

// Prepared drafts contain the fetched, validated profiles, never just a URL to
// fetch again. They are private process memory and intentionally expire on restart.
func (s *Service) PrepareImport(ctx context.Context, c Caller, source, kind, name string) (PreparedImport, error) {
	var out PreparedImport
	if kind != "text" && kind != "subscription" {
		return out, errors.New("unsupported import kind")
	}
	if kind == "text" && len(source) > profiles.MaxBytes {
		return out, errors.New("import exceeds 1 MiB")
	}
	text := source
	if kind == "subscription" {
		if _, err := profiles.SubscriptionURL(source); err != nil {
			return out, err
		}
		var err error
		name, err = profiles.Name(name)
		if err != nil {
			return out, err
		}
		text, err = s.fetch(ctx, source)
		if err != nil {
			return out, err
		}
	}
	if err := ctx.Err(); err != nil {
		return out, errors.New("import preparation canceled")
	}
	user := s.store.Snapshot().User(c.UID)
	out.Preview = profiles.PreviewText(text, user.Profiles)
	for i := range out.Profiles {
		for _, p := range user.Profiles {
			if p.ID == out.Profiles[i].ID {
				out.Profiles[i].IconID = p.Icon()
				break
			}
		}
	}
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		return out, errors.New("cannot create import draft")
	}
	s.draftMu.Lock()
	defer s.draftMu.Unlock()
	now := s.now()
	s.pruneDrafts(now)
	count := 0
	for _, draft := range s.drafts {
		if draft.UID == c.UID {
			count++
		}
	}
	if count >= 4 || len(s.drafts) >= 64 {
		return out, errors.New("too many pending imports; cancel an earlier preview")
	}
	out.DraftID = hex.EncodeToString(token[:])
	out.ExpiresAt = now.Add(importLifetime).Unix()
	if kind == "text" {
		source = ""
	} // The checked profiles are sufficient to commit.
	s.drafts[out.DraftID] = importDraft{UID: c.UID, Expires: now.Add(importLifetime), Kind: kind, Source: source, Name: name, Preview: out.Preview}
	return out, nil
}

func (s *Service) pruneDrafts(now time.Time) {
	for id, draft := range s.drafts {
		if !now.Before(draft.Expires) {
			delete(s.drafts, id)
		}
	}
}

func (s *Service) CancelImport(c Caller, id string) error {
	s.draftMu.Lock()
	defer s.draftMu.Unlock()
	s.pruneDrafts(s.now())
	if draft, ok := s.drafts[id]; !ok || draft.UID != c.UID {
		return errors.New("import draft not found or expired")
	}
	delete(s.drafts, id)
	return nil
}

func (s *Service) CommitImport(c Caller, id, iconsJSON string) (profiles.Preview, error) {
	var empty profiles.Preview
	if len(iconsJSON) > 128<<10 {
		return empty, errors.New("icon selection exceeds size limit")
	}
	icons := map[string]string{}
	if err := json.Unmarshal([]byte(iconsJSON), &icons); err != nil || icons == nil {
		return empty, errors.New("invalid icon selection")
	}
	s.draftMu.Lock()
	defer s.draftMu.Unlock()
	s.pruneDrafts(s.now())
	draft, ok := s.drafts[id]
	if !ok || draft.UID != c.UID {
		return empty, errors.New("import draft not found or expired")
	}
	if len(draft.Preview.Profiles) == 0 || (draft.Kind == "subscription" && len(draft.Preview.Errors) != 0) {
		return draft.Preview, errors.New("import contains no usable profiles or an invalid subscription")
	}
	known := map[string]bool{}
	for _, entry := range draft.Preview.Profiles {
		known[entry.ID] = true
	}
	for profileID, icon := range icons {
		if !known[profileID] || !model.ValidIcon(icon) {
			return empty, errors.New("invalid icon or profile selection")
		}
	}
	// Copy the draft slice: a failed transaction must leave the checked preview intact.
	preview := profiles.Preview{Profiles: append([]profiles.Entry(nil), draft.Preview.Profiles...), Errors: draft.Preview.Errors}
	for i := range preview.Profiles {
		if icon, ok := icons[preview.Profiles[i].ID]; ok {
			preview.Profiles[i].Profile.IconID = icon
			preview.Profiles[i].IconID = icon
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.store.Update(func(st *store.State) error {
		u := st.User(c.UID)
		seen := map[string]model.Profile{}
		for _, p := range u.Profiles {
			seen[p.ID] = p
		}
		for i := range preview.Profiles {
			entry := &preview.Profiles[i]
			previous, duplicate := seen[entry.ID]
			entry.Duplicate = duplicate
			if duplicate {
				entry.IconID = previous.Icon()
			} else {
				seen[entry.ID] = entry.Profile
			}
		}
		if draft.Kind == "subscription" {
			subID := subscriptionID(draft.Source)
			for _, sub := range u.Subscriptions {
				if sub.ID == subID {
					return errors.New("subscription already exists")
				}
			}
			if len(u.Subscriptions) >= 32 {
				return errors.New("a user may keep at most 32 subscriptions")
			}
			now := s.now().Unix()
			u.Subscriptions = append(u.Subscriptions, store.Subscription{ID: subID, Name: draft.Name, URL: draft.Source, UpdatedAt: now, LastAttempt: now})
			if err := replaceSource(st, c.UID, &u, subID, preview, s.currentOwner()); err != nil {
				return err
			}
		} else {
			for _, entry := range preview.Profiles {
				if !entry.Duplicate {
					u.Profiles = append(u.Profiles, entry.Profile)
				}
			}
			if len(u.Profiles) > profiles.MaxProfiles {
				return errors.New("a user may keep at most 1024 profiles")
			}
		}
		st.SetUser(c.UID, u)
		return nil
	})
	if err == nil {
		delete(s.drafts, id)
		s.changed()
	}
	return preview, err
}

func (s *Service) UpdateProfile(c Caller, id, name, icon string) error {
	name, err := profiles.Name(name)
	if err != nil {
		return err
	}
	if !model.ValidIcon(icon) {
		return errors.New("unknown profile icon")
	}
	return s.updateMetadata(c, id, func(p *model.Profile) { p.Name = name; p.IconID = icon })
}

func (s *Service) SetProfileDebug(c Caller, id string, enabled bool) error {
	return s.updateMetadata(c, id, func(p *model.Profile) { p.DebugLogging = enabled })
}

func (s *Service) updateMetadata(c Caller, id string, update func(*model.Profile)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.store.Update(func(st *store.State) error {
		u := st.User(c.UID)
		for i := range u.Profiles {
			if u.Profiles[i].ID == id {
				update(&u.Profiles[i])
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
