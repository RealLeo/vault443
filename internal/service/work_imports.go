package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"vault443/internal/model"
	"vault443/internal/workvpn"
)

type WorkImportFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}
type WorkImportEntry struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	IconID    string `json:"iconId"`
	Duplicate bool   `json:"duplicate"`
	Server    string `json:"server"`
	Transport string `json:"transport"`
}
type WorkImportError struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}
type WorkPreview struct {
	DraftID   string            `json:"draftId"`
	ExpiresAt int64             `json:"expiresAt"`
	Profiles  []WorkImportEntry `json:"profiles"`
	Errors    []WorkImportError `json:"errors"`
}
type workDraft struct {
	UID      uint32
	Expires  time.Time
	Profiles []workvpn.Profile
	Preview  WorkPreview
}

func (s *Service) pruneWorkDraftsLocked() {
	for id, d := range s.work.drafts {
		if !s.now().Before(d.Expires) {
			delete(s.work.drafts, id)
		}
	}
}

// reserveWorkImport accounts for both retained drafts and preparations before
// decoding or certificate parsing. Four simultaneous parses bound expanded
// credential allocations while callers are rejected promptly, without holding
// the control mutex during expensive work.
func (s *Service) reserveWorkImport(uid uint32) error {
	s.work.mu.Lock()
	defer s.work.mu.Unlock()
	s.pruneWorkDraftsLocked()
	active := 0
	for _, n := range s.work.preparing {
		active += n
	}
	owned := s.work.preparing[uid]
	for _, d := range s.work.drafts {
		if d.UID == uid {
			owned++
		}
	}
	if owned >= 4 || len(s.work.drafts)+active >= 32 {
		return errors.New("too many pending imports; cancel an earlier preview")
	}
	if active >= 4 {
		return errors.New("too many imports are being checked; retry shortly")
	}
	s.work.preparing[uid]++
	return nil
}

// Caller holds work.mu. A successful preparation converts its reservation into
// a draft in the same critical section, so neither resource is double-counted.
func (s *Service) releaseWorkImportLocked(uid uint32) {
	if s.work.preparing[uid] <= 1 {
		delete(s.work.preparing, uid)
	} else {
		s.work.preparing[uid]--
	}
}

func (s *Service) PrepareOpenVPNImport(c Caller, filesJSON string) (WorkPreview, error) {
	return s.prepareWorkImport(c, filesJSON, true)
}
func (s *Service) PrepareWorkImport(c Caller, filesJSON string) (WorkPreview, error) {
	return s.prepareWorkImport(c, filesJSON, false)
}
func (s *Service) prepareWorkImport(c Caller, filesJSON string, openVPNOnly bool) (WorkPreview, error) {
	out := WorkPreview{Profiles: []WorkImportEntry{}, Errors: []WorkImportError{}}
	if err := s.requireWork(); err != nil {
		return out, err
	}
	if len(filesJSON) > 8<<20 {
		return out, errors.New("work VPN import exceeds 8 MiB")
	}
	if err := s.reserveWorkImport(c.UID); err != nil {
		return out, err
	}
	reserved := true
	defer func() {
		if reserved {
			s.work.mu.Lock()
			s.releaseWorkImportLocked(c.UID)
			s.work.mu.Unlock()
		}
	}()
	var files []WorkImportFile
	dec := json.NewDecoder(strings.NewReader(filesJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&files); err != nil || len(files) == 0 || len(files) > 32 {
		return out, errors.New("choose between 1 and 32 work VPN files")
	}
	if dec.Decode(new(interface{})) != io.EOF {
		return out, errors.New("invalid work VPN import document")
	}
	seen := map[string]workvpn.Profile{}
	for _, p := range s.work.store.Snapshot().User(c.UID).Profiles {
		seen[p.ID] = p
	}
	draft := workDraft{UID: c.UID, Expires: s.now().Add(importLifetime)}
	for i, file := range files {
		var parsed []workvpn.Profile
		var err error
		if openVPNOnly {
			p, e := workvpn.Parse(file.Name, file.Content)
			err = e
			if e == nil {
				parsed = []workvpn.Profile{p}
			}
		} else {
			parsed, err = workvpn.ParseWork(file.Name, file.Content)
		}
		if err != nil {
			out.Errors = append(out.Errors, WorkImportError{Line: i + 1, Message: err.Error()})
			continue
		}
		if len(out.Profiles)+len(parsed) > 32 {
			return out, errors.New("a work VPN import may contain at most 32 profiles")
		}
		for _, p := range parsed {
			entry := WorkImportEntry{ID: p.ID, Name: p.Name, IconID: p.IconID, Kind: p.Protocol()}
			if len(p.Remotes) > 0 {
				entry.Server = p.Remotes[0].Host
				entry.Transport = p.Remotes[0].Protocol
			}
			if p.WireGuard != nil && len(p.WireGuard.Peers) > 0 {
				entry.Server = p.WireGuard.Peers[0].Endpoint.Host
				entry.Transport = "udp"
			}
			if old, ok := seen[p.ID]; ok {
				entry.Duplicate = true
				entry.IconID = old.IconID
			} else {
				draft.Profiles = append(draft.Profiles, p)
				seen[p.ID] = p
			}
			out.Profiles = append(out.Profiles, entry)
		}
	}
	s.work.mu.Lock()
	defer s.work.mu.Unlock()
	s.pruneWorkDraftsLocked()
	s.releaseWorkImportLocked(c.UID)
	reserved = false
	out.DraftID = workOperationID()
	out.ExpiresAt = draft.Expires.Unix()
	draft.Preview = out
	s.work.drafts[out.DraftID] = draft
	return out, nil
}
func (s *Service) CancelWorkImport(c Caller, id string) error {
	if err := s.requireWork(); err != nil {
		return err
	}
	s.work.mu.Lock()
	defer s.work.mu.Unlock()
	s.pruneWorkDraftsLocked()
	d, ok := s.work.drafts[id]
	if !ok || d.UID != c.UID {
		return errors.New("import draft not found or expired")
	}
	delete(s.work.drafts, id)
	return nil
}
func (s *Service) CommitWorkImport(c Caller, id, iconsJSON string) (WorkPreview, error) {
	var out WorkPreview
	if err := s.requireWork(); err != nil {
		return out, err
	}
	if len(iconsJSON) > 128<<10 {
		return out, errors.New("icon selection exceeds size limit")
	}
	icons := map[string]string{}
	if err := json.Unmarshal([]byte(iconsJSON), &icons); err != nil || icons == nil {
		return out, errors.New("invalid icon selection")
	}
	s.work.mu.Lock()
	defer s.work.mu.Unlock()
	s.pruneWorkDraftsLocked()
	d, ok := s.work.drafts[id]
	if !ok || d.UID != c.UID {
		return out, errors.New("import draft not found or expired")
	}
	out = d.Preview
	if len(out.Profiles) == 0 {
		return out, errors.New("import contains no usable profiles")
	}
	known := map[string]bool{}
	for _, p := range out.Profiles {
		known[p.ID] = true
	}
	for id, icon := range icons {
		if !known[id] || !model.ValidIcon(icon) {
			return out, errors.New("invalid icon or profile selection")
		}
	}
	err := s.work.store.Update(func(st *workvpn.State) error {
		user := st.User(c.UID)
		existing := map[string]bool{}
		for _, p := range user.Profiles {
			existing[p.ID] = true
		}
		for _, p := range d.Profiles {
			if existing[p.ID] {
				continue
			}
			if icon, ok := icons[p.ID]; ok {
				p.IconID = icon
			}
			user.Profiles = append(user.Profiles, p)
			existing[p.ID] = true
		}
		if len(user.Profiles) > workvpn.MaxProfiles {
			return fmt.Errorf("a user may keep at most %d work profiles", workvpn.MaxProfiles)
		}
		st.SetUser(c.UID, user)
		return nil
	})
	if err != nil {
		return out, err
	}
	delete(s.work.drafts, id)
	s.changed()
	return out, nil
}
