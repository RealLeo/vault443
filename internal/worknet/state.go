package worknet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"vault443/internal/network"
)

const networkState = "work-network.json"

type persisted struct {
	Version  int        `json:"version"`
	BootID   string     `json:"bootId"`
	Sessions []*session `json:"sessions"`
}

func (m *Manager) persistLocked() error {
	if e := os.MkdirAll(m.config.StateDir, 0700); e != nil {
		return e
	}
	fi, e := os.Lstat(m.config.StateDir)
	if e != nil || !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		return errors.New("work state directory must be private")
	}
	p := persisted{Version: 1, BootID: m.bootID}
	for _, s := range m.sessions {
		p.Sessions = append(p.Sessions, s)
	}
	b, e := json.Marshal(p)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(m.config.StateDir, ".work-network-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(f.Name(), filepath.Join(m.config.StateDir, networkState))
	}
	return e
}
func (m *Manager) loadLocked() error {
	f, e := os.OpenFile(filepath.Join(m.config.StateDir, networkState), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return errors.New("cannot read work network recovery state")
	}
	defer f.Close()
	fi, e := f.Stat()
	if e != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 || fi.Size() > 2<<20 {
		return errors.New("invalid work network recovery state")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return errors.New("work recovery state belongs to another user")
	}
	var p persisted
	d := json.NewDecoder(io.LimitReader(f, 2<<20))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || p.Version != 1 || len(p.Sessions) > 32 {
		return errors.New("invalid work network recovery state")
	}
	for _, s := range p.Sessions {
		if s == nil || !ifaceRE.MatchString(s.Interface) || s.ID == "" || len(s.Routes) > 512 {
			return errors.New("invalid work recovery tunnel")
		}
		for _, r := range s.Routes {
			if !validRoute(r) {
				return errors.New("invalid protected work route")
			}
		}
		s.Active = false
		s.Status = Status{State: "retry_wait", Stage: "retry_wait", Message: "Restoring protected work connection", Interface: s.Interface}
		m.sessions[s.ID] = s
		if s.Order > m.nextOrder {
			m.nextOrder = s.Order
		}
	}
	m.bootID = p.BootID
	return nil
}
func (m *Manager) Initialize(ctx context.Context, bootID string, retain bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.loadLocked(); e != nil {
		return e
	}
	same := m.bootID == bootID
	m.bootID = bootID
	if !retain || !same {
		if e := m.removeDevicesLocked(ctx); e != nil {
			return e
		}
		m.sessions = map[string]*session{}
	}
	m.lastPolicy = ""
	return m.applyLocked(ctx)
}
func (m *Manager) Release(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.loadLocked(); e != nil {
		return e
	}
	if e := m.removeDevicesLocked(ctx); e != nil {
		return e
	}
	m.sessions = map[string]*session{}
	m.rules = nil
	m.dnsRules = nil
	m.lastPolicy = ""
	return m.applyLocked(ctx)
}
func (m *Manager) Forget(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ss := m.sessions[id]
	if ss != nil && ss.Active {
		return errors.New("stop the OpenVPN process before releasing its routes")
	}
	if ss != nil {
		if e := m.removeDeviceLocked(ctx, ss.Interface); e != nil {
			return e
		}
	}
	delete(m.sessions, id)
	m.lastPolicy = ""
	return m.applyLocked(ctx)
}
func (m *Manager) markDown(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ss := m.sessions[id]
	if ss == nil {
		return nil
	}
	ss.Active = false
	ss.Endpoint = network.Endpoint{}
	m.setStageLocked(id, "retry_wait", "retry_wait", "Work VPN stopped; corporate traffic remains protected")
	m.lastPolicy = ""
	return m.applyLocked(ctx)
}

func (m *Manager) removeDevicesLocked(ctx context.Context) error {
	for _, s := range m.sessions {
		if e := m.removeDeviceLocked(ctx, s.Interface); e != nil {
			return e
		}
	}
	return nil
}
func (m *Manager) removeDeviceLocked(ctx context.Context, iface string) error {
	if !ifaceRE.MatchString(iface) {
		return errors.New("invalid managed tunnel identity")
	}
	return network.WithKernel(ctx, func(k network.Kernel) error {
		s, e := k.Collect(ctx)
		if e != nil {
			return e
		}
		l, present := s.Link(iface)
		if !present {
			return nil
		}
		if l.Kind != "tun" {
			return errors.New("managed name is occupied by a foreign interface")
		}
		if _, e = k.Run(ctx, "/usr/bin/resolvectl", []string{"revert", iface}, ""); e != nil {
			return e
		}
		_, e = k.Run(ctx, "/usr/sbin/ip", []string{"tuntap", "del", "dev", iface, "mode", "tun"}, "")
		return e
	})
}

// RetainDesired prunes recovery metadata for connections explicitly canceled
// before a crash. A single remaining desired profile never revives its peers.
func (m *Manager) RetainDesired(ctx context.Context, ids []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[string]bool{}
	for _, id := range ids {
		keep[id] = true
	}
	for id, s := range m.sessions {
		if keep[id] {
			continue
		}
		if e := m.removeDeviceLocked(ctx, s.Interface); e != nil {
			return e
		}
		delete(m.sessions, id)
	}
	m.lastPolicy = ""
	return m.applyLocked(ctx)
}
