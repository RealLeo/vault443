// Package worknet supervises owned OpenVPN processes and their shared routing
// policy. Imported configuration never selects privileged executable paths.
package worknet

import (
	"context"
	"sync"
	"sync/atomic"
	"vault443/internal/journal"
	"vault443/internal/network"
	"vault443/internal/workvpn"
)

type Config struct{ StateDir, RuntimeDir, OpenVPNPath, EventHelperPath string }
type Status struct {
	State          string   `json:"state"`
	Stage          string   `json:"stage"`
	Message        string   `json:"message,omitempty"`
	StageStartedAt int64    `json:"stageStartedAt"`
	ConnectedAt    int64    `json:"connectedAt,omitempty"`
	Interface      string   `json:"interface,omitempty"`
	Routes         []string `json:"routes,omitempty"`
	DNSServers     []string `json:"dnsServers,omitempty"`
	DNSDomains     []string `json:"dnsDomains,omitempty"`
}
type RouteInfo struct {
	CIDR       string `json:"cidr,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Source     string `json:"source"`
	Target     string `json:"target"`
	TargetName string `json:"targetName,omitempty"`
	Interface  string `json:"interface,omitempty"`
	State      string `json:"state"`
	Message    string `json:"message,omitempty"`
	Conflict   bool   `json:"conflict"`
}
type route struct {
	CIDR    string `json:"cidr"`
	Gateway string `json:"gateway,omitempty"`
}
type session struct {
	ID           string           `json:"id"`
	Name         string           `json:"-"`
	Interface    string           `json:"interface"`
	Routes       []route          `json:"routes"`
	DNSServers   []string         `json:"dnsServers,omitempty"`
	DNSDomains   []string         `json:"dnsDomains,omitempty"`
	Endpoint     network.Endpoint `json:"-"`
	Active       bool             `json:"-"`
	Order        uint64           `json:"order"`
	Attempt      uint64           `json:"-"`
	Status       Status           `json:"-"`
	Full4, Full6 bool             `json:"-"`
	RemoteOrder  []int            `json:"-"`
	callback     func(Status)
	log          *journal.Session
}
type Manager struct {
	mu            sync.Mutex // metadata and short kernel transactions; never network waits
	config        Config
	network       *network.Manager
	sessions      map[string]*session
	rules         []workvpn.RouteRule
	dnsRules      []workvpn.DNSRule
	nextOrder     uint64
	routeView     []RouteInfo
	lastPolicy    string
	lastResources string
	bootID        string
	view          atomic.Pointer[view]
}

func New(c Config, n *network.Manager) *Manager {
	if c.StateDir == "" {
		c.StateDir = "/var/lib/vault443"
	}
	if c.RuntimeDir == "" {
		c.RuntimeDir = "/run/vault443"
	}
	if c.OpenVPNPath == "" {
		c.OpenVPNPath = "/usr/sbin/openvpn"
	}
	if c.EventHelperPath == "" {
		c.EventHelperPath = "/usr/sbin/vault443d"
	}
	return &Manager{config: c, network: n, sessions: map[string]*session{}}
}

type view struct {
	statuses map[string]Status
	routes   []RouteInfo
}

func (m *Manager) publishView() {
	v := &view{statuses: map[string]Status{}, routes: append([]RouteInfo(nil), m.routeView...)}
	for id, s := range m.sessions {
		v.statuses[id] = copyStatus(s.Status)
	}
	m.view.Store(v)
}
func (m *Manager) Snapshot(id string) Status {
	v := m.view.Load()
	if v == nil {
		return Status{State: "disconnected", Stage: "disconnected"}
	}
	if s, ok := v.statuses[id]; ok {
		return copyStatus(s)
	}
	return Status{State: "disconnected", Stage: "disconnected"}
}
func copyStatus(s Status) Status {
	s.Routes = append([]string(nil), s.Routes...)
	s.DNSServers = append([]string(nil), s.DNSServers...)
	s.DNSDomains = append([]string(nil), s.DNSDomains...)
	return s
}
func (m *Manager) Routes() []RouteInfo {
	v := m.view.Load()
	if v == nil {
		return []RouteInfo{}
	}
	return append([]RouteInfo(nil), v.routes...)
}
func (m *Manager) SetRules(ctx context.Context, r []workvpn.RouteRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rule := range r {
		if rule.Target != "local" {
			continue
		}
		if err := network.WithKernel(ctx, func(k network.Kernel) error {
			s, err := k.Collect(ctx)
			if err != nil {
				return err
			}
			return validateLocalRules(s, r)
		}); err != nil {
			return err
		}
		break
	}
	old := m.rules
	m.rules = append([]workvpn.RouteRule(nil), r...)
	if e := m.applyLocked(ctx); e != nil {
		m.rules = old
		return e
	}
	return nil
}
func (m *Manager) SetDNSRules(ctx context.Context, r []workvpn.DNSRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.dnsRules
	m.dnsRules = append([]workvpn.DNSRule(nil), r...)
	if e := m.applyLocked(ctx); e != nil {
		m.dnsRules = old
		return e
	}
	return nil
}
