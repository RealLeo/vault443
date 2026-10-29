package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"vault443/internal/worknet"
	"vault443/internal/workvpn"
)

type WorkRoutes struct {
	Items           []worknet.RouteInfo `json:"items"`
	Rules           []workvpn.RouteRule `json:"rules"`
	DNSRules        []workvpn.DNSRule   `json:"dnsRules"`
	Profiles        []WorkRouteProfile  `json:"profiles"`
	BusyByOtherUser bool                `json:"busyByOtherUser"`
	Message         string              `json:"message,omitempty"`
}
type WorkRouteProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *Service) GetWorkRoutes(c Caller) (WorkRoutes, error) {
	out := WorkRoutes{Items: []worknet.RouteInfo{}, Rules: []workvpn.RouteRule{}, DNSRules: []workvpn.DNSRule{}, Profiles: []WorkRouteProfile{}}
	if err := s.requireWork(); err != nil {
		return out, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateMu.Lock()
	owner := s.ownerLocked(s.store.Snapshot())
	busy := owner != nil && owner.UID != c.UID
	s.stateMu.Unlock()
	if busy || s.workBusyFor(c) {
		out.BusyByOtherUser = true
		out.Message = "Another user owns the VPN"
		return out, nil
	}
	u := s.work.store.Snapshot().User(c.UID)
	out.Items = s.work.runtime.Routes()
	out.Rules = u.Rules
	out.DNSRules = u.DNSRules
	if out.Rules == nil {
		out.Rules = []workvpn.RouteRule{}
	}
	if out.DNSRules == nil {
		out.DNSRules = []workvpn.DNSRule{}
	}
	for _, p := range u.Profiles {
		out.Profiles = append(out.Profiles, WorkRouteProfile{p.ID, p.Name})
	}
	return out, nil
}
func (s *Service) SetWorkRoute(ctx context.Context, c Caller, cidr, target string) error {
	r, err := workvpn.NewRouteRule(cidr, target)
	if err != nil {
		return err
	}
	value := r.CIDR
	return s.changeWorkRules(ctx, c, func(u *workvpn.WorkUser) error {
		if target != "local" && !hasWorkProfile(*u, target) {
			return errors.New("profile not found")
		}
		if target == "local" && strings.HasSuffix(value, "/0") {
			return errors.New("local rules require a directly connected subnet")
		}
		for i, old := range u.Rules {
			if old.ID == r.ID {
				u.Rules[i] = r
				return nil
			}
		}
		u.Rules = append(u.Rules, r)
		return nil
	})
}
func (s *Service) SetWorkDNS(ctx context.Context, c Caller, domain, target string) error {
	if strings.TrimSpace(domain) == "" {
		return errors.New("enter a DNS domain")
	}
	r, err := workvpn.NewDNSRule(domain, target)
	if err != nil {
		return err
	}
	return s.changeWorkRules(ctx, c, func(u *workvpn.WorkUser) error {
		if !hasWorkProfile(*u, target) {
			return errors.New("profile not found")
		}
		for i, old := range u.DNSRules {
			if old.ID == r.ID {
				u.DNSRules[i] = r
				return nil
			}
		}
		u.DNSRules = append(u.DNSRules, r)
		return nil
	})
}
func hasWorkProfile(u workvpn.WorkUser, id string) bool {
	for _, p := range u.Profiles {
		if p.ID == id {
			return true
		}
	}
	return false
}
func (s *Service) RemoveWorkRoute(ctx context.Context, c Caller, id string) error {
	return s.changeWorkRules(ctx, c, func(u *workvpn.WorkUser) error {
		for i, r := range u.Rules {
			if r.ID == id {
				u.Rules = append(u.Rules[:i], u.Rules[i+1:]...)
				return nil
			}
		}
		return errors.New("route rule not found")
	})
}
func (s *Service) RemoveWorkDNS(ctx context.Context, c Caller, id string) error {
	return s.changeWorkRules(ctx, c, func(u *workvpn.WorkUser) error {
		for i, r := range u.DNSRules {
			if r.ID == id {
				u.DNSRules = append(u.DNSRules[:i], u.DNSRules[i+1:]...)
				return nil
			}
		}
		return errors.New("DNS rule not found")
	})
}
func (s *Service) changeWorkRules(ctx context.Context, c Caller, change func(*workvpn.WorkUser) error) error {
	if err := s.requireWork(); err != nil {
		return err
	}
	s.work.routeMu.Lock()
	defer s.work.routeMu.Unlock()
	s.mu.Lock()
	s.stateMu.Lock()
	owner := s.ownerLocked(s.store.Snapshot())
	busy := owner != nil && owner.UID != c.UID
	s.stateMu.Unlock()
	if busy || s.workBusyFor(c) {
		s.mu.Unlock()
		return errors.New("another user owns the VPN; explicitly take control first")
	}
	old := s.work.store.Snapshot().User(c.UID)
	next := s.work.store.Snapshot().User(c.UID)
	if err := change(&next); err != nil {
		s.mu.Unlock()
		return err
	}
	// Store validates limits and ownership before any runtime modification. The
	// route mutex serializes revisions; snapshots never wait for the network.
	if err := s.work.store.Update(func(st *workvpn.State) error {
		u := st.User(c.UID)
		u.Rules = next.Rules
		u.DNSRules = next.DNSRules
		st.SetUser(c.UID, u)
		return nil
	}); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	err := s.work.runtime.SetRules(ctx, next.Rules)
	if err == nil {
		err = s.work.runtime.SetDNSRules(ctx, next.DNSRules)
	}
	if err != nil {
		// Fail closed in the controller; rollback only our rule revision, preserving
		// independently edited names, icons, debug flags and new imports.
		_ = s.work.store.Update(func(st *workvpn.State) error {
			u := st.User(c.UID)
			u.Rules = old.Rules
			u.DNSRules = old.DNSRules
			st.SetUser(c.UID, u)
			return nil
		})
		restoreCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.work.runtime.SetRules(restoreCtx, old.Rules)
		_ = s.work.runtime.SetDNSRules(restoreCtx, old.DNSRules)
	}
	s.changed()
	return err
}
