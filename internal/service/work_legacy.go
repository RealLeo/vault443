package service

import (
	"context"
	"errors"
	"vault443/internal/journal"
)

// Public 1.1 methods retain their OpenVPN-only semantics. Shared implementation
// is protocol-neutral, but legacy callers cannot accidentally control WG/AWG.
func (s *Service) requireOpenVPN(c Caller, id string) error {
	if e := s.requireWork(); e != nil {
		return e
	}
	p, ok := s.work.store.Snapshot().Profile(c.UID, id)
	if !ok || p.Protocol() != "openvpn" {
		return errors.New("OpenVPN profile not found")
	}
	return nil
}
func (s *Service) requireOpenVPNDraft(c Caller, id string) error {
	if e := s.requireWork(); e != nil {
		return e
	}
	s.work.mu.Lock()
	defer s.work.mu.Unlock()
	s.pruneWorkDraftsLocked()
	d, ok := s.work.drafts[id]
	if !ok || d.UID != c.UID {
		return errors.New("import draft not found or expired")
	}
	for _, p := range d.Preview.Profiles {
		if p.Kind != "openvpn" {
			return errors.New("import draft contains non-OpenVPN profiles")
		}
	}
	return nil
}
func (s *Service) CommitOpenVPNImport(c Caller, id, icons string) (WorkPreview, error) {
	if e := s.requireOpenVPNDraft(c, id); e != nil {
		return WorkPreview{}, e
	}
	return s.CommitWorkImport(c, id, icons)
}
func (s *Service) CancelOpenVPNImport(c Caller, id string) error {
	if e := s.requireOpenVPNDraft(c, id); e != nil {
		return e
	}
	return s.CancelWorkImport(c, id)
}
func (s *Service) RequestOpenVPNConnect(ctx context.Context, c Caller, id string) (string, error) {
	if e := s.requireOpenVPN(c, id); e != nil {
		return "", e
	}
	return s.RequestWorkConnect(ctx, c, id)
}
func (s *Service) RequestOpenVPNDisconnect(ctx context.Context, c Caller, id string) (string, error) {
	if e := s.requireOpenVPN(c, id); e != nil {
		return "", e
	}
	return s.RequestWorkDisconnect(ctx, c, id)
}
func (s *Service) UpdateOpenVPNProfile(c Caller, id, name, icon string) error {
	if e := s.requireOpenVPN(c, id); e != nil {
		return e
	}
	return s.UpdateWorkProfile(c, id, name, icon)
}
func (s *Service) RemoveOpenVPNProfile(c Caller, id string) error {
	if e := s.requireOpenVPN(c, id); e != nil {
		return e
	}
	return s.RemoveWorkProfile(c, id)
}
func (s *Service) SetOpenVPNDebug(c Caller, id string, enabled bool) error {
	if e := s.requireOpenVPN(c, id); e != nil {
		return e
	}
	return s.SetWorkDebug(c, id, enabled)
}
func (s *Service) GetOpenVPNDiagnostics(c Caller, id string) (interface{}, error) {
	if e := s.requireOpenVPN(c, id); e != nil {
		return nil, e
	}
	return s.GetWorkDiagnostics(c, id)
}
func (s *Service) GetOpenVPNLogs(c Caller, id, cursor string, limit int) (journal.Page, error) {
	if e := s.requireOpenVPN(c, id); e != nil {
		return journal.Page{}, e
	}
	return s.GetWorkLogs(c, id, cursor, limit)
}
func (s *Service) ClearOpenVPNLogs(c Caller, id string) error {
	if e := s.requireOpenVPN(c, id); e != nil {
		return e
	}
	return s.ClearWorkLogs(c, id)
}
