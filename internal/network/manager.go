// Package network manages only resources named/allocated to Vault 443.
// Constructing a Manager is inert. DryRun never executes mutating commands,
// starts a core, writes state, or probes Internet connectivity.
package network

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"vault443/internal/core"
	"vault443/internal/journal"
	"vault443/internal/model"
)

type Config struct {
	StateDir, RuntimeDir, XrayPath string
	DryRun                         bool
}
type Manager struct {
	operationContext        context.Context
	logSession              *journal.Session
	guardReady, guardLogged bool
	mu                      sync.Mutex
	inspectionMu            sync.Mutex
	config                  Config
	r                       runner
	core                    core.Process
	status                  model.RuntimeStatus
	statusView              atomic.Value
	diagnosticsView         atomic.Value
	progressHandler         atomic.Pointer[progressHandler]
	trafficHandler          atomic.Pointer[trafficHandler]
	trafficEpoch            atomic.Uint64
	trafficIfIndex          atomic.Uint64
	trafficActive           atomic.Bool
	loaded                  bool
	bindings                []Binding
	protected               []protectedRoute
	profile                 *model.Profile
	endpoint                netip.Addr
	v4, v6                  netip.Prefix
	uplink                  Route
	commands                []command
	lastPlan                string
	lastResources           string
	lastCheck               time.Time
	ipv6State               string
	ipv6Message             string
	ownedRules              bool
	dnsSaved                map[string]dnsSettings
	nm                      nmConnectivity
}
type persisted struct {
	Armed              bool             `json:"armed"`
	Protected          []protectedRoute `json:"protected"`
	Gateway4, Gateway6 string
}

func New(c Config) *Manager {
	if c.StateDir == "" {
		c.StateDir = "/var/lib/vault443"
	}
	if c.RuntimeDir == "" {
		c.RuntimeDir = "/run/vault443"
	}
	if c.XrayPath == "" {
		c.XrayPath = "/usr/lib/vault443/xray"
	}
	m := &Manager{config: c, r: execRunner{}, status: model.RuntimeStatus{State: "disconnected", ExternalVPNs: []string{}}, ipv6State: "inactive", ipv6Message: "VLESS IPv6 is inactive"}
	m.nm.state = "inactive"
	m.publish()
	return m
}

// SetLogSession must be called before starting an owned connection attempt.
// Process output retains the previous immutable Session when ownership changes.
func (m *Manager) SetLogSession(session *journal.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logSession = session
	m.guardLogged = false
}
func (m *Manager) Status() model.RuntimeStatus {
	s := m.statusView.Load().(model.RuntimeStatus)
	s.ExternalVPNs = append([]string{}, s.ExternalVPNs...)
	if sample := m.TrafficCounters(); sample.Valid {
		s.RXBytes = sample.RXBytes
		s.TXBytes = sample.TXBytes
	}
	return s
}

// SetProgressHandler installs a short observer. It must not enter network
// mutation methods: publish runs inside the sequential network worker.
func (m *Manager) SetProgressHandler(fn func(model.RuntimeStatus)) {
	m.progressHandler.Store(&progressHandler{fn: fn})
}

type progressHandler struct{ fn func(model.RuntimeStatus) }

func (m *Manager) stage(code, message string) {
	if m.status.Stage != code {
		m.status.StageStartedAt = time.Now().UnixMilli()
	}
	m.status.Stage, m.status.Message, m.status.FailureCode = code, message, ""
	m.publish()
}
func (m *Manager) publish() {
	s := m.status
	if previous := m.statusView.Load(); previous != nil {
		old := previous.(model.RuntimeStatus)
		if old.State != s.State || old.Message != s.Message {
			level := "info"
			if s.State == "error" {
				level = "error"
			}
			message := s.Message
			if message == "" {
				message = "Connection state: " + s.State
			}
			m.logSession.Log(level, message)
		}
		if old.GuardArmed != s.GuardArmed {
			if s.GuardArmed {
				m.logSession.Log("info", "Traffic protection enabled")
			} else {
				m.logSession.Log("info", "Traffic protection disabled; normal routing restored")
			}
		}
	}
	s.ExternalVPNs = append([]string{}, s.ExternalVPNs...)
	m.statusView.Store(s)
	m.diagnosticsView.Store(map[string]any{"state": s.State, "message": s.Message, "stage": s.Stage, "stageStartedAt": s.StageStartedAt, "failureCode": s.FailureCode, "snapshotAt": time.Now().UnixMilli(), "guardArmed": s.GuardArmed, "dryRun": m.config.DryRun, "coreVersion": core.Version, "interface": TunName, "enrolledVPNCount": len(m.bindings), "protectedRouteCount": len(m.protected), "plannedOperationCount": len(m.commands), "ipv6State": m.ipv6State, "ipv6Message": m.ipv6Message, "networkManagerState": m.nm.state, "networkManagerMessage": m.nm.message})
	if observer := m.progressHandler.Load(); observer != nil && observer.fn != nil {
		observer.fn(s)
	}
}
func (m *Manager) fail(err error) error {
	if m.operationContext != nil && errors.Is(m.operationContext.Err(), context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.Canceled) {
		return err
	}
	m.status.FailureCode = ""
	var failure *bootstrapError
	if errors.As(err, &failure) {
		m.status.FailureCode = failure.code
	}
	var healthFailure *healthError
	if errors.As(err, &healthFailure) {
		m.status.FailureCode = healthFailure.code
	}
	m.status.State = "error"
	m.status.Message = err.Error()
	m.lastPlan = ""
	m.publish()
	return err
}
func (m *Manager) execute(ctx context.Context, c command) error {
	m.commands = append(m.commands, c)
	if len(m.commands) > 256 {
		m.commands = m.commands[len(m.commands)-256:]
	}
	if m.config.DryRun {
		return nil
	}
	_, e := m.r.Run(ctx, c)
	return e
}

func (m *Manager) load() error {
	if m.loaded {
		return nil
	}
	for _, dir := range []string{m.config.StateDir, m.config.RuntimeDir} {
		if !filepath.IsAbs(dir) {
			return errors.New("service directories must be absolute")
		}
	}
	read := func(name string, target any) error {
		return readPrivateState(m.config.StateDir, name, target)
	}
	if e := read("vpn-bindings.json", &m.bindings); e != nil {
		return e
	}
	for _, b := range m.bindings {
		data, _ := json.Marshal(b)
		if _, e := ParseBinding(string(data)); e != nil {
			return e
		}
	}
	var p persisted
	if e := read("network-state.json", &p); e != nil {
		return e
	}
	m.protected = p.Protected
	for _, p := range m.protected {
		q, e := netip.ParsePrefix(p.Prefix)
		if e != nil || q.Bits() < 2 || !core.SafeInterface(p.Interface) {
			return errors.New("invalid protected route state")
		}
	}
	if p.Armed {
		m.status.GuardArmed = true
		m.status.State = "reconnecting"
		m.status.Message = "Restoring protected connection"
		m.ownedRules = true
	}
	m.v4, _ = netip.ParsePrefix(p.Gateway4)
	m.v6, _ = netip.ParsePrefix(p.Gateway6)
	if e := read("dns-backup.json", &m.dnsSaved); e != nil {
		return e
	}
	if m.dnsSaved == nil {
		m.dnsSaved = map[string]dnsSettings{}
	}
	m.loaded = true
	m.publish()
	return nil
}
func (m *Manager) persist() error {
	m.publish()
	if m.config.DryRun {
		return nil
	}
	return privateWrite(m.config.StateDir, "network-state.json", persisted{Armed: m.status.GuardArmed, Protected: m.protected, Gateway4: m.v4.String(), Gateway6: m.v6.String()})
}

func (m *Manager) nftExists(ctx context.Context) (bool, error) {
	b, e := m.r.Run(ctx, command{Path: "/usr/sbin/nft", Args: []string{"-j", "list", "tables"}})
	if e != nil {
		return false, errors.New("cannot inspect firewall; protection is not verified")
	}
	var result struct {
		NFTables []struct {
			Table struct{ Family, Name string } `json:"table"`
		} `json:"nftables"`
	}
	if e = json.Unmarshal(b, &result); e != nil {
		return false, errors.New("cannot parse firewall tables")
	}
	for _, t := range result.NFTables {
		if t.Table.Family == "inet" && t.Table.Name == TableName {
			return true, nil
		}
	}
	return false, nil
}
func (m *Manager) applyGuard(ctx context.Context, s Snapshot, x []external, ready bool) error {
	exists, e := m.nftExists(ctx)
	if e != nil {
		return e
	}
	port := 0
	if m.profile != nil {
		port = m.profile.Port
	}
	rejectQUIC := m.profile != nil && m.profile.Flow == "xtls-rprx-vision"
	script := guardScript(guardOptions{Snapshot: s, External: x, Protected: m.protected, Endpoint: m.endpoint, Port: port, Uplink: m.uplink.Device, TunnelReady: ready, RejectQUIC: rejectQUIC, BlockTunnelIPv6: m.ipv6State != "available", AllowIPv6Probe: m.ipv6State == "checking"}, exists)
	if e = m.execute(ctx, command{Path: "/usr/sbin/nft", Args: []string{"-f", "-"}, Input: script}); e != nil {
		return errors.New("cannot atomically install protection")
	}
	m.status.GuardArmed = !m.config.DryRun
	if !m.guardLogged || m.guardReady != ready {
		if ready {
			m.logSession.Log("info", "Firewall updated: tunnel traffic allowed; direct Internet blocked")
		} else {
			m.logSession.Log("info", "Firewall updated: Internet blocked until a protected tunnel is ready")
		}
		m.guardLogged = true
		m.guardReady = ready
	}
	m.status.ExternalVPNs = []string{}
	for _, v := range x {
		if v.Active {
			m.status.ExternalVPNs = append(m.status.ExternalVPNs, v.Link.Name)
		}
	}
	return m.persist()
}

func (m *Manager) remember(xs []external) error {
	seen := map[string]bool{}
	for _, p := range m.protected {
		seen[p.Prefix+"/"+p.Interface] = true
	}
	for _, b := range m.bindings {
		for _, p := range b.Routes {
			if !seen[p+"/"+b.Interface] {
				m.protected = append(m.protected, protectedRoute{p, b.Interface})
				seen[p+"/"+b.Interface] = true
			}
		}
	}
	for _, x := range xs {
		for _, r := range x.Routes {
			p, ok := r.Prefix()
			if !ok || p.Bits() < 2 {
				continue
			}
			key := p.String() + "/" + x.Link.Name
			if !seen[key] {
				m.protected = append(m.protected, protectedRoute{p.String(), x.Link.Name})
				seen[key] = true
			}
		}
	}
	if len(m.protected) > 1024 {
		return errors.New("too many protected routes")
	}
	return nil
}

func (m *Manager) Arm(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.operationContext = ctx
	defer func() { m.operationContext = nil }()
	return m.arm(ctx)
}
func (m *Manager) arm(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.status.State = "connecting"
	m.stage("checking_vpn", "Checking other VPN connections")
	if e := m.load(); e != nil {
		return m.fail(e)
	}
	s, e := collect(ctx, m.r)
	if e != nil {
		return m.fail(e)
	}
	x, e := m.external(ctx, s)
	if e != nil {
		return m.fail(e)
	}
	if e = m.remember(x); e != nil {
		return m.fail(e)
	}
	u, e := s.Uplink()
	if e == nil {
		m.uplink = u
	}
	if e = m.checkOwnership(s); e != nil {
		return m.fail(e)
	}
	m.stage("enabling_guard", "Enabling traffic protection")
	if e = m.applyGuard(ctx, s, x, false); e != nil {
		return m.fail(e)
	}
	m.status.State = "connecting"
	m.status.Message = "Protection enabled; waiting for connection"
	m.publish()
	return nil
}

func (m *Manager) Connect(ctx context.Context, p model.Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.operationContext = ctx
	defer func() { m.operationContext = nil }()
	m.logSession.Log("info", "Preparing protected connection")
	m.nm = nmConnectivity{state: "inactive"}
	// IPv6 availability belongs to a single core session. Never carry a prior
	// server's success into another connection or restore it from disk.
	m.ipv6State, m.ipv6Message = "inactive", "VLESS IPv6 is inactive"
	if e := m.load(); e != nil {
		return m.fail(e)
	}
	// Stop old core only after the persistent guard has been installed.
	if e := m.arm(ctx); e != nil {
		return e
	}
	if e := m.stopCore(ctx); e != nil {
		return m.fail(e)
	}
	m.profile = &p
	m.endpoint = netip.Addr{}
	m.lastPlan = ""
	s, e := collect(ctx, m.r)
	if e != nil {
		return m.fail(e)
	}
	x, e := m.external(ctx, s)
	if e != nil {
		return m.fail(e)
	}
	if e = m.remember(x); e != nil {
		return m.fail(e)
	}
	if anyFull(x) {
		return m.pause(ctx, s, x)
	}
	m.uplink, e = s.Uplink()
	if e != nil {
		return m.fail(e)
	}
	m.v4, m.v6, e = ChooseSubnets(s)
	if e != nil {
		return m.fail(e)
	}
	if e = m.applyGuard(ctx, s, x, false); e != nil {
		return m.fail(e)
	}
	if e = m.installRoutes(ctx, s, x, false, false); e != nil {
		return m.fail(e)
	}
	if m.config.DryRun {
		a, e := netip.ParseAddr(p.Server)
		if e != nil {
			a = netip.MustParseAddr("203.0.113.1")
		}
		m.endpoint = a
	} else {
		m.stage("resolving_endpoint", "Resolving VPN server address")
		m.logSession.Log("info", "Resolving VPN endpoint through protected bootstrap DNS")
		m.endpoint, e = m.resolveEndpoint(ctx, p.Server)
		if e != nil {
			return m.fail(e)
		}
	}
	bytes, e := core.Build(p, core.Options{Interface: TunName, Gateway4: m.v4, Gateway6: m.v6, DNSAddress: m.v4.Addr().Next(), Endpoint: m.endpoint, Uplink: m.uplink.Device, Mark: OuterMark})
	if e != nil {
		return m.fail(e)
	}
	if e = m.applyGuard(ctx, s, x, false); e != nil {
		return m.fail(e)
	}
	// The resolved core endpoint also needs a reverse-path lookup before its
	// first packet. The guard remains closed to unmarked physical traffic.
	if !m.config.DryRun {
		s, e = collect(ctx, m.r)
		if e != nil {
			return m.fail(e)
		}
	}
	if e = m.installRoutes(ctx, s, x, false, false); e != nil {
		return m.fail(e)
	}
	if m.config.DryRun {
		_ = bytes
		if e = m.installRoutes(ctx, s, x, true, false); e != nil {
			return m.fail(e)
		}
		m.status.State = "connecting"
		m.status.Message = "Dry run: plan generated; no connection or firewall changes executed"
		m.status.GuardArmed = false
		m.publish()
		return nil
	}
	m.ipv6State, m.ipv6Message = "checking", "IPv6 is blocked until HTTPS through the tunnel has been verified"
	path, e := core.WriteConfig(m.config.RuntimeDir, bytes)
	if e != nil {
		return m.fail(errors.New("cannot write private runtime configuration"))
	}
	m.stage("starting_core", "Validating configuration and starting Xray")
	m.logSession.Log("info", "Validating configuration and starting Xray")
	m.trafficIfIndex.Store(0)
	m.trafficEpoch.Add(1)
	if e = m.core.Start(ctx, m.config.XrayPath, path, m.logSession); e != nil {
		return m.fail(e)
	}
	m.trafficActive.Store(true)
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if !m.core.Alive() {
			return m.fail(errors.New("core exited before creating the tunnel"))
		}
		if link, e := net.InterfaceByName(TunName); e == nil {
			m.trafficIfIndex.Store(uint64(link.Index))
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return m.fail(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !ready {
		return m.fail(errors.New("core tunnel did not become ready"))
	}
	m.observeTraffic()
	m.stage("configuring_network", "Configuring protected routes and DNS")
	s, e = collect(ctx, m.r)
	if e != nil {
		return m.fail(e)
	}
	if e = m.applyGuard(ctx, s, x, true); e != nil {
		return m.fail(e)
	}
	if e = m.installRoutes(ctx, s, x, true, false); e != nil {
		return m.fail(e)
	}
	if e = m.setDNS(ctx); e != nil {
		return m.fail(e)
	}
	if e = m.configureExternalDNS(ctx, x); e != nil {
		return m.fail(e)
	}
	m.stage("checking_connection", "Verifying connection through VLESS")
	m.logSession.Log("info", "Verifying DNS and HTTPS through VLESS")
	if e = m.health(ctx); e != nil {
		return m.fail(e)
	}
	m.stage("checking_connection", "Verifying IPv6 through VLESS")
	available, e := m.checkIPv6(ctx)
	if e != nil {
		return m.fail(e)
	}
	if e = m.finishIPv6Check(ctx, s, x, available); e != nil {
		return m.fail(e)
	}
	m.syncNetworkManager(ctx, s)
	m.status.State = "connected"
	m.status.Message = "Connected"
	m.status.Stage = "connected"
	m.status.StageStartedAt = time.Now().UnixMilli()
	m.status.ConnectedAt = time.Now().Unix()
	m.lastCheck = time.Now()
	return m.persist()
}

func anyFull(x []external) bool {
	for _, v := range x {
		if v.Full4 || v.Full6 {
			return true
		}
	}
	return false
}

// finishIPv6Check publishes availability only after the corresponding firewall
// policy is installed. A failed IPv6 probe does not invalidate verified IPv4;
// retry IPv6 on the next explicit/recovery connection, rather than repeatedly
// reopening an unusable path under active browser connections.
func (m *Manager) finishIPv6Check(ctx context.Context, s Snapshot, x []external, available bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	previousState, previousMessage := m.ipv6State, m.ipv6Message
	if available {
		m.ipv6State, m.ipv6Message = "available", "HTTPS over IPv6 through the VPN tunnel is verified"
	} else {
		m.ipv6State, m.ipv6Message = "unavailable", "IPv6 through the VPN is unavailable; applications use verified IPv4. IPv6 will be checked on the next connection"
	}
	if err := m.applyGuard(ctx, s, x, true); err != nil {
		m.ipv6State, m.ipv6Message = previousState, previousMessage
		return err
	}
	level := "info"
	if !available {
		level = "warning"
	}
	m.logSession.Log(level, m.ipv6Message)
	return nil
}

func (m *Manager) pause(ctx context.Context, s Snapshot, x []external) error {
	m.nm = nmConnectivity{state: "inactive"}
	m.ipv6State, m.ipv6Message = "inactive", "VLESS IPv6 is inactive while another VPN owns Internet routing"
	if e := m.applyGuard(ctx, s, x, false); e != nil {
		return m.fail(e)
	}
	if _, ok := s.Link(TunName); ok {
		if e := m.execute(ctx, command{Path: "/usr/bin/resolvectl", Args: []string{"revert", TunName}}); e != nil {
			return m.fail(e)
		}
	}
	if e := m.stopCore(ctx); e != nil {
		return m.fail(e)
	}
	if e := m.installRoutes(ctx, s, x, false, true); e != nil {
		return m.fail(e)
	}
	m.status.State = "paused_external"
	m.status.Stage = "paused_external"
	m.status.StageStartedAt = time.Now().UnixMilli()
	m.status.FailureCode = ""
	m.status.Message = "Another VPN owns Internet routing; VLESS is paused and direct Internet remains blocked"
	m.status.ExternalVPNs = nil
	for _, v := range x {
		m.status.ExternalVPNs = append(m.status.ExternalVPNs, v.Link.Name)
	}
	return m.persist()
}

func (m *Manager) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.operationContext = ctx
	defer func() { m.operationContext = nil }()
	if e := m.load(); e != nil {
		return m.fail(e)
	}
	if !m.status.GuardArmed {
		return nil
	}
	s, e := collect(ctx, m.r)
	if e != nil {
		return m.fail(e)
	}
	x, e := m.external(ctx, s)
	if e != nil {
		return m.fail(e)
	}
	if e = m.remember(x); e != nil {
		return m.fail(e)
	}
	if e = m.configureExternalDNS(ctx, x); e != nil {
		return m.fail(e)
	}
	if anyFull(x) {
		return m.pause(ctx, s, x)
	}
	if m.status.State == "paused_external" {
		if e = m.applyGuard(ctx, s, x, false); e != nil {
			return m.fail(e)
		}
		if e = m.installRoutes(ctx, s, x, false, false); e != nil {
			return m.fail(e)
		}
		m.status.State = "reconnecting"
		m.status.Message = "External VPN released Internet; restoring protected VLESS"
		m.publish()
		return errors.New("VLESS needs reconnect after external VPN")
	}
	u, e := s.Uplink()
	if e != nil {
		if guardErr := m.applyGuard(ctx, s, x, false); guardErr != nil {
			return m.fail(guardErr)
		}
		return m.fail(e)
	}
	if u.Device != m.uplink.Device || u.Gateway != m.uplink.Gateway {
		m.uplink = u
		_ = m.stopCore(ctx)
		if e = m.applyGuard(ctx, s, x, false); e != nil {
			return m.fail(e)
		}
		return m.fail(errors.New("network changed; reconnect required"))
	}
	ready := m.core.Alive()
	if e = m.applyGuard(ctx, s, x, ready); e != nil {
		return m.fail(e)
	}
	if e = m.installRoutes(ctx, s, x, ready, false); e != nil {
		return m.fail(e)
	}
	if !ready && !m.config.DryRun {
		m.nm = nmConnectivity{state: "inactive"}
		// Preserve the concrete failed attempt until the next attempt starts.
		if m.status.State == "error" && m.status.Message != "" {
			return errors.New(m.status.Message)
		}
		return m.fail(errors.New("core is not running; protection remains enabled"))
	}
	if ready {
		m.syncNetworkManager(ctx, s)
	}
	if ready && time.Since(m.lastCheck) > 30*time.Second {
		if e = m.health(ctx); e != nil {
			return m.fail(e)
		}
		if m.ipv6State == "available" {
			available, probeErr := m.checkIPv6(ctx)
			if probeErr != nil {
				return m.fail(probeErr)
			}
			if !available {
				if e = m.finishIPv6Check(ctx, s, x, false); e != nil {
					return m.fail(e)
				}
			}
		}
		m.lastCheck = time.Now()
	}
	return nil
}

func (m *Manager) Disconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.operationContext = ctx
	defer func() { m.operationContext = nil }()
	m.ipv6State, m.ipv6Message = "inactive", "VLESS IPv6 is inactive"
	m.nm = nmConnectivity{state: "inactive"}
	m.status.State = "disconnecting"
	m.stage("restoring_network", "Stopping Xray and restoring network state")
	m.logSession.Log("info", "Disconnect requested; stopping Xray and restoring network state")
	if e := m.load(); e != nil {
		return m.fail(e)
	}
	_ = m.stopCore(ctx)
	if !m.status.GuardArmed && !m.ownedRules && !m.config.DryRun {
		exists, e := m.nftExists(ctx)
		if e != nil {
			return m.fail(e)
		}
		if !exists {
			m.status = model.RuntimeStatus{State: "disconnected", Stage: "disconnected", StageStartedAt: time.Now().UnixMilli(), ExternalVPNs: []string{}}
			m.publish()
			return nil
		}
	}
	s, e := collect(ctx, m.r)
	if e != nil {
		return m.fail(e)
	}
	if e = m.checkOwnership(s); e != nil {
		return m.fail(e)
	}
	if _, ok := s.Link(TunName); ok {
		if e = m.execute(ctx, command{Path: "/usr/bin/resolvectl", Args: []string{"revert", TunName}}); e != nil {
			return m.fail(e)
		}
	}
	if e = m.removeRules(ctx, s); e != nil {
		return m.fail(e)
	}
	if e = m.restoreExternalDNS(ctx, s); e != nil {
		return m.fail(e)
	}
	for _, f := range []int{4, 6} {
		for _, t := range []int{ProxyTable, BypassTable, UnderlayTable} {
			if !s.HasTable(f, t) {
				continue
			}
			if e = m.execute(ctx, command{Path: "/usr/sbin/ip", Args: []string{fmt.Sprint("-", f), "route", "flush", "table", strconv.Itoa(t)}}); e != nil {
				return m.fail(e)
			}
		}
	}
	exists, e := m.nftExists(ctx)
	if e != nil {
		return m.fail(e)
	}
	if exists {
		if e = m.execute(ctx, command{Path: "/usr/sbin/nft", Args: []string{"delete", "table", "inet", TableName}}); e != nil {
			return m.fail(e)
		}
	}
	m.profile = nil
	m.endpoint = netip.Addr{}
	m.lastPlan = ""
	m.status = model.RuntimeStatus{State: "disconnected", Stage: "disconnected", StageStartedAt: time.Now().UnixMilli(), ExternalVPNs: []string{}}
	return m.persist()
}

func (m *Manager) SetVPNBinding(ctx context.Context, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.load(); e != nil {
		return e
	}
	b, e := ParseBinding(text)
	if e != nil {
		return e
	}
	var next []Binding
	for _, old := range m.bindings {
		if old.Interface != b.Interface {
			next = append(next, old)
		}
	}
	if !b.Remove {
		next = append(next, b)
	}
	if len(next) > 32 {
		return errors.New("too many VPN bindings")
	}
	if !m.config.DryRun {
		if e = privateWrite(m.config.StateDir, "vpn-bindings.json", next); e != nil {
			return errors.New("cannot persist VPN binding")
		}
	}
	m.bindings = next
	if b.Remove {
		var protected []protectedRoute
		for _, p := range m.protected {
			if p.Interface != b.Interface {
				protected = append(protected, p)
			}
		}
		m.protected = protected
	}
	m.lastPlan = ""
	m.publish()
	return nil
}

func (m *Manager) Diagnostics(ctx context.Context) interface{} {
	// Return an independent immutable view; never wait for DNS, core startup,
	// routing commands, or the manager's mutation lock.
	view := m.diagnosticsView.Load().(map[string]any)
	out := make(map[string]any, len(view)+2)
	for key, value := range view {
		out[key] = value
	}
	out["routeTables"] = []int{ProxyTable, BypassTable, UnderlayTable}
	out["coreRunning"] = m.core.Alive()
	return out
}

func (m *Manager) setDNS(ctx context.Context) error {
	m.logSession.Log("info", "Configuring protected DNS")
	for _, args := range [][]string{{"dns", TunName, m.v4.Addr().Next().String()}, {"domain", TunName, "~."}, {"default-route", TunName, "yes"}} {
		if e := m.execute(ctx, command{Path: "/usr/bin/resolvectl", Args: args}); e != nil {
			return errors.New("cannot configure protected system DNS")
		}
	}
	return nil
}

func planKey(plan []command) string {
	b, _ := json.Marshal(plan)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func (m *Manager) checkOwnership(s Snapshot) error {
	for _, r := range s.Routes {
		if string(r.Table) == strconv.Itoa(ProxyTable) || string(r.Table) == strconv.Itoa(BypassTable) || string(r.Table) == strconv.Itoa(UnderlayTable) {
			if !m.ownedRules || (string(r.Protocol) != "186" && string(r.Protocol) != "\"186\"") {
				return errors.New("reserved routing table contains resources not owned by this service")
			}
		}
	}
	for _, rules := range [][]map[string]any{s.Rules4, s.Rules6} {
		for _, r := range rules {
			p, _ := r["priority"].(float64)
			if p >= RuleBase && p < RuleBase+100 {
				table := fmt.Sprint(r["table"])
				if !m.ownedRules || (table != strconv.Itoa(ProxyTable) && table != strconv.Itoa(BypassTable) && table != strconv.Itoa(UnderlayTable)) {
					return errors.New("reserved routing priority belongs to another service")
				}
			}
		}
	}
	return nil
}

func (m *Manager) installRoutes(ctx context.Context, s Snapshot, x []external, tunnel, paused bool) error {
	plan := routePlan(s, x, m.protected, m.uplink, tunnel)
	transportMetadata, _ := json.Marshal(x)
	key := planKey(plan) + strconv.FormatBool(paused) + fmt.Sprintf("%x", sha256.Sum256(transportMetadata)) + m.endpoint.String()
	if m.profile != nil {
		key += strconv.Itoa(m.profile.Port)
	}
	if e := m.checkOwnership(s); e != nil {
		return e
	}
	if m.lastPlan == key && m.lastResources == ownedResourceKey(s) {
		return nil
	}
	m.ownedRules = true
	if e := m.removeRules(ctx, s); e != nil {
		return e
	}
	for _, c := range plan {
		if e := m.execute(ctx, c); e != nil {
			return errors.New("cannot apply protected routes")
		}
	}
	for _, f := range []int{4, 6} {
		rules := [][]string{{"priority", strconv.Itoa(RuleBase), "fwmark", fmt.Sprintf("0x%x", OuterMark), "lookup", strconv.Itoa(UnderlayTable)}, {"priority", strconv.Itoa(RuleBase + 1), "fwmark", fmt.Sprintf("0x%x", BootstrapMark), "lookup", strconv.Itoa(UnderlayTable)}, {"priority", strconv.Itoa(RuleBase + 90), "lookup", strconv.Itoa(BypassTable)}}
		if !paused {
			rules = append(rules, []string{"priority", strconv.Itoa(RuleBase + 91), "lookup", strconv.Itoa(ProxyTable)})
		}
		// Linux reverse-path validation uses uid 0 and reversed transport
		// ports, but normally ignores SO_MARK. Without a matching route, an
		// unreachable proxy default rejects legitimate bootstrap/core replies
		// even though their marked requests left on the physical interface.
		// These are routing hints, not firewall exceptions: OUTPUT still
		// requires the exact private mark and FORWARD has no such allowance.
		priority := RuleBase + 2
		if f == 4 && !paused {
			for _, transport := range []struct{ protocol, port string }{{"udp", "53"}, {"tcp", "53"}, {"tcp", "443"}} {
				rules = append(rules, []string{"priority", strconv.Itoa(priority), "uidrange", "0-0", "to", "1.1.1.1", "ipproto", transport.protocol, "dport", transport.port, "lookup", strconv.Itoa(UnderlayTable)})
				priority++
			}
		}
		if !paused && m.endpoint.IsValid() && m.profile != nil && (f == 4) == m.endpoint.Is4() {
			for _, protocol := range []string{"tcp", "udp"} {
				rules = append(rules, []string{"priority", strconv.Itoa(priority), "uidrange", "0-0", "to", m.endpoint.String(), "ipproto", protocol, "dport", strconv.Itoa(m.profile.Port), "lookup", strconv.Itoa(UnderlayTable)})
				priority++
			}
		}
		for _, v := range x {
			for _, ep := range v.Binding.Endpoints {
				if priority >= RuleBase+90 {
					return errors.New("too many external transport routing exceptions")
				}
				a, e := netip.ParseAddr(ep.Address)
				if e != nil || (f == 4) != a.Is4() {
					continue
				}
				if v.Link.Kind != "wireguard" {
					// Select the physical source address before route-output marking.
					// OpenVPN sockets are normally created while privileged, including
					// service children that later drop privileges. The guard still
					// requires the verified cgroup/identity mark and exact endpoint.
					if v.Cgroup != "" || v.Binding.RootOnly {
						rules = append(rules, []string{"priority", strconv.Itoa(priority), "uidrange", "0-0", "to", ep.Address, "ipproto", ep.Protocol, "dport", strconv.Itoa(ep.Port), "lookup", strconv.Itoa(UnderlayTable)})
						priority++
					}
				} else if ep.Mark != 0 {
					rules = append(rules, []string{"priority", strconv.Itoa(priority), "fwmark", fmt.Sprintf("0x%x", ep.Mark), "lookup", strconv.Itoa(UnderlayTable)})
					priority++
				} else if ep.SourcePort > 0 {
					rules = append(rules, []string{"priority", strconv.Itoa(priority), "to", ep.Address, "ipproto", "udp", "sport", strconv.Itoa(ep.SourcePort), "dport", strconv.Itoa(ep.Port), "lookup", strconv.Itoa(UnderlayTable)})
					priority++
				}
			}
		}
		for _, rule := range rules {
			args := append([]string{fmt.Sprint("-", f), "rule", "add"}, rule...)
			if e := m.execute(ctx, command{Path: "/usr/sbin/ip", Args: args}); e != nil {
				return errors.New("cannot install protected routing policy")
			}
		}
	}
	m.ownedRules = true
	observed := s
	if !m.config.DryRun {
		var e error
		observed, e = collect(ctx, m.r)
		if e != nil {
			return errors.New("cannot verify installed routing policy")
		}
		if e = m.checkOwnership(observed); e != nil {
			return e
		}
	}
	m.lastPlan = key
	m.lastResources = ownedResourceKey(observed)
	m.logSession.Log("info", "Protected routing policy updated")
	return nil
}

// A desired-plan cache alone misses routes or rules deleted by another manager.
// Compare the installed owned resources too; ordering changes in kernel dumps
// must not trigger a rewrite and a self-sustaining netlink notification loop.
func ownedResourceKey(s Snapshot) string {
	var rows []string
	for _, r := range s.Routes {
		if string(r.Table) != strconv.Itoa(ProxyTable) && string(r.Table) != strconv.Itoa(BypassTable) && string(r.Table) != strconv.Itoa(UnderlayTable) {
			continue
		}
		b, _ := json.Marshal(r)
		rows = append(rows, fmt.Sprintf("route%d:%s", r.Family, b))
	}
	for i, rules := range [][]map[string]any{s.Rules4, s.Rules6} {
		for _, r := range rules {
			p, _ := r["priority"].(float64)
			if p < RuleBase || p >= RuleBase+100 {
				continue
			}
			b, _ := json.Marshal(r)
			rows = append(rows, fmt.Sprintf("rule%d:%s", i, b))
		}
	}
	sort.Strings(rows)
	b, _ := json.Marshal(rows)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func (m *Manager) removeRules(ctx context.Context, s Snapshot) error {
	for index, rules := range [][]map[string]any{s.Rules4, s.Rules6} {
		family := 4
		if index == 1 {
			family = 6
		}
		for _, r := range rules {
			p, _ := r["priority"].(float64)
			if p < RuleBase || p >= RuleBase+100 {
				continue
			}
			table := fmt.Sprint(r["table"])
			if table != strconv.Itoa(ProxyTable) && table != strconv.Itoa(BypassTable) && table != strconv.Itoa(UnderlayTable) {
				return errors.New("foreign policy occupies reserved priority")
			}
			if e := m.execute(ctx, command{Path: "/usr/sbin/ip", Args: []string{fmt.Sprint("-", family), "rule", "del", "priority", strconv.Itoa(int(p)), "table", table}}); e != nil {
				return errors.New("cannot remove own routing policy")
			}
		}
	}
	return nil
}
