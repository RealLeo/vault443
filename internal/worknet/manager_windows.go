package worknet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"vault443/internal/journal"
	"vault443/internal/network"
	"vault443/internal/securefs"
	"vault443/internal/winplatform"
	"vault443/internal/workvpn"
)

type session struct {
	ID           string                 `json:"id"`
	Kind         string                 `json:"kind"`
	PeerPrefixes map[string][]string    `json:"peerPrefixes,omitempty"`
	PeerReady    map[string]bool        `json:"-"`
	Name         string                 `json:"name"`
	Interface    string                 `json:"interface"`
	Routes       []route                `json:"routes"`
	DNSServers   []string               `json:"dnsServers,omitempty"`
	DNSDomains   []string               `json:"dnsDomains,omitempty"`
	Active       bool                   `json:"-"`
	Order        uint64                 `json:"order"`
	Status       Status                 `json:"-"`
	LUID         winipcfg.LUID          `json:"-"`
	Endpoints    []winplatform.Endpoint `json:"-"`
	Attempt      uint64                 `json:"-"`
	Running      bool                   `json:"-"`
	RemoteOrder  []int                  `json:"-"`
	callback     func(Status)
	log          *journal.Session
}
type view struct {
	statuses map[string]Status
	routes   []RouteInfo
}
type Manager struct {
	mu         sync.Mutex
	config     Config
	network    *network.Manager
	platform   *winplatform.Coordinator
	sessions   map[string]*session
	rules      []workvpn.RouteRule
	dnsRules   []workvpn.DNSRule
	nextOrder  uint64
	bootID     string
	lastPolicy string
	routeView  []RouteInfo
	view       atomic.Pointer[view]
}

func New(c Config, n *network.Manager) *Manager {
	if c.WireGuardPath == "" {
		c.WireGuardPath = filepath.Join(filepath.Dir(c.EventHelperPath), "vault443-tunnel.exe")
	}
	if c.OpenVPNPath == "" {
		c.OpenVPNPath = filepath.Join(filepath.Dir(c.EventHelperPath), "openvpn", "openvpn.exe")
	}
	return &Manager{config: c, network: n, sessions: map[string]*session{}}
}
func (m *Manager) persistLocked() error {
	var list []*session
	for _, s := range m.sessions {
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Order < list[j].Order })
	data, err := json.Marshal(struct {
		BootID   string     `json:"bootId"`
		Sessions []*session `json:"sessions"`
	}{m.bootID, list})
	if err != nil {
		return err
	}
	return securefs.Write(filepath.Join(m.config.StateDir, "windows-work.json"), data)
}
func (m *Manager) Initialize(ctx context.Context, bootID string, retain bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.network.Platform()
	if err != nil {
		return err
	}
	m.platform = p
	data, err := os.ReadFile(filepath.Join(m.config.StateDir, "windows-work.json"))
	if err == nil {
		var state struct {
			BootID   string     `json:"bootId"`
			Sessions []*session `json:"sessions"`
		}
		if len(data) > 2<<20 || json.Unmarshal(data, &state) != nil || len(state.Sessions) > 32 {
			return errors.New("invalid private work network recovery state")
		}
		if retain && state.BootID == bootID {
			for _, s := range state.Sessions {
				if s == nil || s.ID == "" || s.Interface != workInterface(s.ID) {
					return errors.New("invalid work tunnel recovery identity")
				}
				s.Active = false
				s.LUID = 0
				s.PeerReady = map[string]bool{}
				s.Status = Status{State: "retry_wait", Stage: "retry_wait", Interface: s.Interface, Message: "Restoring protected work connection"}
				m.sessions[s.ID] = s
				if s.Order > m.nextOrder {
					m.nextOrder = s.Order
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	m.bootID = bootID
	return m.applyLocked(ctx)
}
func (m *Manager) RetainDesired(ctx context.Context, ids []string) error {
	keep := map[string]bool{}
	for _, id := range ids {
		keep[id] = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.sessions {
		if !keep[id] {
			delete(m.sessions, id)
		}
	}
	return m.applyLocked(ctx)
}
func (m *Manager) Release(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.platform == nil {
		p, e := m.network.Platform()
		if e != nil {
			return e
		}
		m.platform = p
	}
	m.sessions = map[string]*session{}
	m.rules = nil
	m.dnsRules = nil
	return m.applyLocked(ctx)
}
func (m *Manager) Forget(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.sessions[id]; s != nil && s.Running {
		return errors.New("stop the work VPN process before releasing protection")
	}
	delete(m.sessions, id)
	return m.applyLocked(ctx)
}

// beginSession is called with m.mu held; credentials remain in the Run stack,
// while only route/DNS ownership is retained across failed attempts.
func (m *Manager) beginSession(p workvpn.Profile, logs *journal.Session, callback func(Status)) (*session, error) {
	iface := workInterface(p.ID)
	s := m.sessions[p.ID]
	if s == nil {
		if len(m.sessions) >= 32 {
			return nil, errors.New("at most 32 work VPNs may be requested")
		}
		for _, other := range m.sessions {
			if other.Interface == iface {
				return nil, errors.New("work tunnel identity collision")
			}
		}
		m.nextOrder++
		s = &session{ID: p.ID, Interface: iface, Order: m.nextOrder}
		m.sessions[p.ID] = s
	}
	if s.Running {
		return nil, errors.New("work VPN attempt is already running")
	}
	s.Kind, s.Name, s.callback, s.log = p.Protocol(), p.Name, callback, logs
	s.Active, s.Running, s.LUID = false, true, 0
	s.PeerReady = map[string]bool{}
	s.Endpoints = nil
	s.Attempt++
	s.Status = Status{State: "connecting", Stage: "checking_vpn", Interface: iface, StageStartedAt: time.Now().UnixMilli()}
	return s, nil
}

// finishSession follows child termination. Protection remains until Forget.
func (m *Manager) finishSession(_ context.Context, id string) error {
	m.mu.Lock()
	if s := m.sessions[id]; s != nil {
		s.Running = false
	}
	m.mu.Unlock()
	return nil
}
func (m *Manager) publishView() {
	v := &view{statuses: map[string]Status{}, routes: append([]RouteInfo(nil), m.routeView...)}
	for id, s := range m.sessions {
		v.statuses[id] = copyStatus(s.Status)
	}
	m.view.Store(v)
}
func (m *Manager) Snapshot(id string) Status {
	if v := m.view.Load(); v != nil {
		if s, ok := v.statuses[id]; ok {
			return copyStatus(s)
		}
	}
	return Status{State: "disconnected", Stage: "disconnected"}
}
func (m *Manager) Routes() []RouteInfo {
	if v := m.view.Load(); v != nil {
		return append([]RouteInfo(nil), v.routes...)
	}
	return []RouteInfo{}
}
func (m *Manager) SetRules(ctx context.Context, r []workvpn.RouteRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := network.CollectWindows()
	if err != nil {
		return err
	}
	if err = validateLocalRules(s, r); err != nil {
		return err
	}
	for _, rule := range r {
		if ss := m.sessions[rule.Target]; ss != nil && !routeAllowed(ss, rule.CIDR) {
			return errors.New("manual route is outside WireGuard AllowedIPs")
		}
	}
	old := m.rules
	m.rules = append([]workvpn.RouteRule(nil), r...)
	if err = m.applyLocked(ctx); err != nil {
		m.rules = old
		return err
	}
	return nil
}
func (m *Manager) SetDNSRules(ctx context.Context, r []workvpn.DNSRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rule := range r {
		if ss := m.sessions[rule.Target]; ss != nil && len(ss.DNSServers) == 0 {
			return errors.New("work VPN has no DNS servers")
		}
	}
	old := m.dnsRules
	m.dnsRules = append([]workvpn.DNSRule(nil), r...)
	if err := m.applyLocked(ctx); err != nil {
		m.dnsRules = old
		return err
	}
	return nil
}
func (m *Manager) setStageLocked(id, state, stage, message string) {
	s := m.sessions[id]
	if s == nil {
		return
	}
	if s.Status.Stage != stage {
		s.Status.StageStartedAt = time.Now().UnixMilli()
	}
	s.Status.State, s.Status.Stage, s.Status.Message = state, stage, message
	m.publishView()
	if s.callback != nil {
		s.callback(copyStatus(s.Status))
	}
}
func (m *Manager) markDown(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil {
		return nil
	}
	s.Active = false
	s.LUID = 0
	s.Endpoints = nil
	s.PeerReady = map[string]bool{}
	m.lastPolicy = ""
	for i := range s.Status.Peers {
		s.Status.Peers[i].State = "reconnecting"
	}
	if err := m.applyLocked(ctx); err != nil {
		return err
	}
	m.setStageLocked(id, "retry_wait", "retry_wait", "Work VPN stopped; destinations remain protected")
	return nil
}

func (m *Manager) applyLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.platform == nil {
		p, e := m.network.Platform()
		if e != nil {
			return e
		}
		m.platform = p
	}
	observed, err := network.CollectWindows()
	if err != nil {
		return fmt.Errorf("work collect: %w", err)
	}
	sel := m.choose(observed)
	effective := effectiveWindowsRoutes(sel, observed)
	part := winplatform.GuardPart{}
	var routes []winplatform.OwnedRoute
	var ids []string
	for id := range m.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	uplink, upErr := winplatform.PhysicalUplink(false)
	if upErr != nil {
		uplink, upErr = winplatform.PhysicalUplink(true)
	}
	if len(m.sessions) > 0 {
		part.DNSPhysical = []uint64{0}
	}
	if len(m.sessions) > 0 && upErr == nil {
		physical, endpoints, e := m.platform.DNSGuardEndpoints(uplink.LUID)
		if e != nil {
			return e
		}
		part.DNSPhysical = physical
		part.Endpoints = append(part.Endpoints, endpoints...)
	}
	for _, s := range m.sessions {
		if s.LUID != 0 {
			part.DNSTunnels = append(part.DNSTunnels, uint64(s.LUID))
		}
	}
	sort.Slice(part.DNSTunnels, func(i, j int) bool { return part.DNSTunnels[i] < part.DNSTunnels[j] })
	full := false
	for _, r := range effective {
		prefix, err := netip.ParsePrefix(r.cidr)
		if err != nil {
			return err
		}
		luid := winipcfg.LUID(0)
		if r.local {
			luid, err = winplatform.InterfaceByName(r.iface)
			if err != nil {
				luid = 0
			}
		} else if s := m.sessions[r.target]; s != nil && r.active {
			luid = s.LUID
		}
		part.Routes = append(part.Routes, winplatform.GuardRoute{Prefix: prefix, Interface: uint64(luid)})
		if prefix.Bits() == 0 && !r.local {
			full = true
		}
		if luid == 0 {
			continue
		}
		next := netip.Addr{}
		if r.gateway != "" {
			next, _ = netip.ParseAddr(r.gateway)
		}
		for _, q := range splitPrefix(prefix) {
			if r.local {
				routes = append(routes, winplatform.Route(luid, q, next))
			} else {
				routes = append(routes, winplatform.PolicyRoute(luid, q, next))
			}
		}
		// Override connected LAN/container prefixes only. Arbitrary physical
		// static routes include VPN transport pins and must keep their scope.
		for _, existing := range network.LocalRoutes(observed) {
			q, ok := existing.Prefix()
			if !ok || q.Addr().Is4() != prefix.Addr().Is4() || q.Bits() <= prefix.Bits() || !prefix.Contains(q.Addr()) || existing.Device == r.iface || strings.HasPrefix(strings.ToLower(existing.Device), "v443") {
				continue
			}
			for _, child := range splitPrefix(q) {
				if r.local {
					routes = append(routes, winplatform.Route(luid, child, next))
				} else {
					routes = append(routes, winplatform.PolicyRoute(luid, child, next))
				}
			}
		}
	}
	for _, id := range ids {
		part.Endpoints = append(part.Endpoints, m.sessions[id].Endpoints...)
		for _, ep := range m.sessions[id].Endpoints {
			ip := ep.Address
			link, e := winplatform.PhysicalUplink(ip.Is6())
			if e == nil {
				routes = append(routes, winplatform.Route(link.LUID, netip.PrefixFrom(ip, ip.BitLen()), link.Gateway))
			}
		}
	}
	// Preserve the full-tunnel intent while disconnected; the other family is
	// blocked by the shared selection policy until the owner can carry it.
	for _, s := range m.sessions {
		if isFull(s.Routes) {
			full = true
		}
	}
	// A requested full work tunnel also protects periods in which another
	// adapter wins route arbitration. Only verified VPN/transport exceptions
	// and local control networks can pass the persistent base block.
	part.BlockAll = full
	if full && upErr == nil {
		part.Local = append([]netip.Prefix(nil), uplink.Local...)
	}
	plans := map[string]winplatform.DNSPlan{}
	for domain, id := range sel.dns {
		s := m.sessions[id]
		if s == nil {
			continue
		}
		plan := winplatform.DNSPlan{Interface: s.LUID, Active: dnsAvailable(s), Priority: 100, Default: domain == "."}
		if domain != "." {
			plan.Domains = []string{domain}
		}
		for _, raw := range s.DNSServers {
			ip, e := netip.ParseAddr(raw)
			if e == nil && routeAvailable(s, netip.PrefixFrom(ip, ip.BitLen()).String()) {
				plan.Servers = append(plan.Servers, ip)
			}
		}
		plans["work:"+domain] = plan
	}
	if full {
		if _, exists := plans["work:."]; !exists {
			plans["work:."] = winplatform.DNSPlan{Default: true, Priority: 100}
		}
	}
	// Native route enumeration order is not stable. A canonical resource plan
	// prevents our own IP Helper notifications from causing endless rewrites.
	routes = canonicalRoutes(routes)
	part.Endpoints = canonicalEndpoints(part.Endpoints)
	encoded, _ := json.Marshal(struct {
		Part   winplatform.GuardPart
		Routes []winplatform.OwnedRoute
		DNS    map[string]winplatform.DNSPlan
		Full   bool
	}{part, routes, plans, full})
	hash := sha256.Sum256(encoded)
	key := hex.EncodeToString(hash[:])
	if key != m.lastPolicy {
		if err = m.persistLocked(); err != nil {
			return err
		}
		if len(m.sessions) == 0 {
			if err = m.platform.Guard.Remove("work"); err != nil {
				return fmt.Errorf("work guard.remove: %w", err)
			}
		} else {
			if err = m.platform.Guard.Set("work", part); err != nil {
				return fmt.Errorf("work guard.set: %w", err)
			}
		}
		if err = m.platform.Routes.Set("work", routes); err != nil {
			return fmt.Errorf("work routes.set: %w", err)
		}
		if len(plans) > 0 && upErr != nil {
			return upErr
		}
		if err = m.platform.DNS.SetGroup("work:", plans, uplink.LUID); err != nil {
			return fmt.Errorf("work dns.setgroup: %w", err)
		}
		m.platform.SetFull("work", full)
		if full && m.network.Status().GuardArmed {
			if err = m.network.Reconcile(ctx); err != nil {
				return fmt.Errorf("work main.reconcile: %w", err)
			}
		}
		m.lastPolicy = key
	}
	m.routeView = sel.rows
	var changed []*session
	for id, s := range m.sessions {
		before := s.Status
		if s.Active {
			if sel.conflict[id] {
				s.Status.State, s.Status.Stage, s.Status.Message = "conflict", "route_conflict", "Choose the work route owner in Routes"
			} else if s.Status.State == "conflict" || s.Status.State == "connected" || s.Status.State == "partial" {
				s.Status.State, s.Status.Stage, s.Status.Message = "connected", "connected", "Connected"
				if (s.Kind == "wireguard" || s.Kind == "amneziawg") && !allPeersReady(s) {
					s.Status.State, s.Status.Stage, s.Status.Message = "partial", "partial", "Some peers are unavailable; their routes remain protected"
				}
			}
		}
		if before.State != s.Status.State || before.Stage != s.Status.Stage || before.Message != s.Status.Message {
			s.Status.StageStartedAt = time.Now().UnixMilli()
			changed = append(changed, s)
		}
	}
	m.publishView()
	for _, s := range changed {
		if s.callback != nil {
			s.callback(copyStatus(s.Status))
		}
	}
	return nil
}

func canonicalRoutes(input []winplatform.OwnedRoute) []winplatform.OwnedRoute {
	byKey := map[string]winplatform.OwnedRoute{}
	for _, r := range input {
		data, _ := json.Marshal(r)
		byKey[string(data)] = r
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]winplatform.OwnedRoute, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out
}
func canonicalEndpoints(input []winplatform.Endpoint) []winplatform.Endpoint {
	byKey := map[string]winplatform.Endpoint{}
	for _, r := range input {
		data, _ := json.Marshal(r)
		byKey[string(data)] = r
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]winplatform.Endpoint, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out
}
