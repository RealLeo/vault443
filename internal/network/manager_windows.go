package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"vault443/internal/core"
	"vault443/internal/journal"
	"vault443/internal/model"
	"vault443/internal/profiles"
	"vault443/internal/winplatform"
)

const TunName = "v443-main"

type Config struct {
	StateDir, RuntimeDir, XrayPath, OutlinePath string
	DryRun                                      bool
}
type Manager struct {
	mu             sync.Mutex
	initMu         sync.Mutex
	viewMu         sync.RWMutex
	config         Config
	platform       *winplatform.Coordinator
	status         model.RuntimeStatus
	progress       func(model.RuntimeStatus)
	logSession     *journal.Session
	core           core.Process
	outline        core.OutlineProcess
	uplink         winplatform.Uplink
	tun            atomic.Uint64
	epoch          atomic.Uint64
	trafficHandler func(model.TUNCounters)
	trafficMu      sync.Mutex
	profile        *model.Profile
	v4, v6         netip.Prefix
	part           winplatform.GuardPart
	ipv6State      string
	lastHealth     time.Time
	prepared       *preparedWindows
	mainAdapter    *ownedMainAdapter
}
type preparedWindows struct {
	profile   model.Profile
	endpoint  netip.Addr
	resolved  map[string]string
	endpoints []winplatform.Endpoint
	routes    []winplatform.OwnedRoute
	at        time.Time
}

func New(c Config) *Manager {
	if c.OutlinePath == "" {
		c.OutlinePath = filepath.Join(filepath.Dir(c.XrayPath), "vault443-outline.exe")
	}
	return &Manager{config: c, status: model.RuntimeStatus{State: "disconnected"}, ipv6State: "inactive"}
}
func (m *Manager) Platform() (*winplatform.Coordinator, error) {
	m.initMu.Lock()
	defer m.initMu.Unlock()
	if m.platform == nil {
		p, err := winplatform.NewCoordinator(m.config.StateDir)
		if err != nil {
			return nil, err
		}
		m.platform = p
	}
	return m.platform, nil
}
func (m *Manager) Status() model.RuntimeStatus {
	m.viewMu.RLock()
	defer m.viewMu.RUnlock()
	return m.status
}
func (m *Manager) SetProgressHandler(fn func(model.RuntimeStatus)) {
	m.viewMu.Lock()
	m.progress = fn
	m.viewMu.Unlock()
}
func (m *Manager) SetLogSession(session *journal.Session) {
	m.mu.Lock()
	m.logSession = session
	m.mu.Unlock()
}
func (m *Manager) publish(state, stage, message string) {
	m.viewMu.Lock()
	m.status.State, m.status.Stage, m.status.Message = state, stage, message
	m.status.StageStartedAt = time.Now().UnixMilli()
	status, fn := m.status, m.progress
	m.viewMu.Unlock()
	if fn != nil {
		fn(status)
	}
}
func (m *Manager) fail(err error) error {
	if err == nil {
		return nil
	}
	code := "connection_failed"
	var health *healthError
	if errors.As(err, &health) {
		code = health.code
	}
	var bootstrap *bootstrapError
	if errors.As(err, &bootstrap) {
		code = bootstrap.code
	}
	m.viewMu.Lock()
	m.status.FailureCode = code
	m.viewMu.Unlock()
	m.publish("error", "retry_wait", journal.Sanitize(err.Error()))
	m.logSession.Log("error", journal.Sanitize(err.Error()))
	return err
}
func (m *Manager) arm(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.config.DryRun {
		return nil
	}
	p, err := m.Platform()
	if err != nil {
		return err
	}
	if err = m.refreshExternalLocked(ctx); err != nil {
		return err
	}
	u, err := winplatform.PhysicalUplink(false)
	if err != nil {
		u, err = winplatform.PhysicalUplink(true)
	}
	if err != nil {
		return err
	}
	m.uplink = u
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	part := winplatform.GuardPart{BlockAll: true, Local: u.Local, DNSPhysical: []uint64{uint64(u.LUID)}}
	var routes []winplatform.OwnedRoute
	for _, text := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		ip := netip.MustParseAddr(text)
		link, e := winplatform.PhysicalUplink(ip.Is6())
		if e != nil {
			continue
		}
		for _, port := range []uint16{53, 443} {
			part.Endpoints = append(part.Endpoints, winplatform.Endpoint{App: exe, Address: ip, Port: port, Interface: uint64(link.LUID)})
			if port == 53 {
				part.Endpoints = append(part.Endpoints, winplatform.Endpoint{App: exe, Address: ip, Port: port, UDP: true, Interface: uint64(link.LUID)})
			}
		}
		routes = append(routes, winplatform.Route(link.LUID, netip.PrefixFrom(ip, ip.BitLen()), link.Gateway))
	}
	m.part = part
	if err = p.Guard.Set("main", part); err != nil {
		return err
	}
	m.viewMu.Lock()
	m.status.GuardArmed = true
	m.viewMu.Unlock()
	return p.Routes.Set("main-bootstrap", routes)
}
func (m *Manager) Arm(ctx context.Context) error { m.mu.Lock(); defer m.mu.Unlock(); return m.arm(ctx) }
func (m *Manager) stop(ctx context.Context) error {
	m.trafficMu.Lock()
	fn := m.trafficHandler
	m.trafficMu.Unlock()
	if fn != nil {
		fn(m.TrafficCounters())
	}
	m.tun.Store(0)
	if err := errors.Join(m.core.StopContext(ctx), m.outline.Stop(ctx)); err != nil {
		return err
	}
	return m.clearMainAddressesLocked()
}
func (m *Manager) Suspend(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.arm(ctx); err != nil {
		return m.fail(err)
	}
	if err := m.stop(ctx); err != nil {
		return m.fail(err)
	}
	return m.fail(errors.New("Previous connection is unavailable; traffic remains protected"))
}
func windowsBootstrap(u winplatform.Uplink) *bootstrapResolver {
	dialer := winplatform.Dialer(u.LUID)
	r := newBootstrapResolver(dialer)
	ip, network := "1.1.1.1", "tcp4"
	if u.Gateway.Is6() {
		ip, network = "2606:4700:4700::1111", "tcp6"
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip, "53"))
	}}
	r.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		family := "ip4"
		if r.ipv6 {
			family = "ip6"
		}
		return resolver.LookupNetIP(ctx, family, host)
	}
	r.client.Transport.(*http.Transport).DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip, "443"))
	}
	return r
}
func resolveWindows(ctx context.Context, host string, u winplatform.Uplink) (netip.Addr, error) {
	r := windowsBootstrap(u)
	defer r.close()
	ip, err := r.resolve(ctx, host)
	if err == nil {
		return ip, nil
	}
	if ctx.Err() != nil {
		return netip.Addr{}, ctx.Err()
	}
	r.ipv6 = true
	return r.resolve(ctx, host)
}

// ResolveWorkEndpointForProtocol uses the same fixed, physically pinned
// bootstrap as the main VPN, including when system DNS points at our proxy.
func ResolveWorkEndpointForProtocol(ctx context.Context, host, protocol string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if strings.Contains(protocol, "4") && !ip.Is4() || strings.Contains(protocol, "6") && !ip.Is6() {
			return netip.Addr{}, errors.New("VPN endpoint address family does not match the transport")
		}
		return ip, nil
	}
	u, err := winplatform.PhysicalUplink(false)
	if err != nil {
		u, err = winplatform.PhysicalUplink(true)
	}
	if err != nil {
		return netip.Addr{}, err
	}
	r := windowsBootstrap(u)
	defer r.close()
	if strings.Contains(protocol, "6") {
		r.ipv6 = true
		return r.resolve(ctx, host)
	}
	ip, err := r.resolve(ctx, host)
	if err == nil || ctx.Err() != nil || strings.Contains(protocol, "4") {
		return ip, err
	}
	r.ipv6 = true
	return r.resolve(ctx, host)
}
func ResolveWorkEndpoint(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveWorkEndpointForProtocol(ctx, host, "")
}
func (m *Manager) resolveProfile(ctx context.Context, p model.Profile) (*preparedWindows, error) {
	prepared := &preparedWindows{profile: p, resolved: map[string]string{}, at: time.Now()}
	ip, err := resolveWindows(ctx, p.Server, m.uplink)
	if err != nil {
		return nil, err
	}
	prepared.endpoint = ip
	physical := map[string][]string{net.JoinHostPort(p.Server, strconv.Itoa(p.Port)): {"tcp", "udp"}}
	app := m.config.XrayPath
	if p.Outline != nil {
		physical = profiles.OutlinePhysicalEndpoints(p.Outline)
		app = m.config.OutlinePath
	}
	keys := make([]string, 0, len(physical))
	for endpoint := range physical {
		keys = append(keys, endpoint)
	}
	sort.Strings(keys)
	for _, address := range keys {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid transport endpoint")
		}
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return nil, errors.New("invalid transport port")
		}
		endpoint, err := resolveWindows(ctx, host, m.uplink)
		if err != nil {
			return nil, err
		}
		u, err := winplatform.PhysicalUplink(endpoint.Is6())
		if err != nil {
			return nil, err
		}
		prepared.resolved[address] = net.JoinHostPort(endpoint.String(), port)
		for _, protocol := range physical[address] {
			prepared.endpoints = append(prepared.endpoints, winplatform.Endpoint{App: app, Address: endpoint, Port: uint16(number), UDP: protocol == "udp", Interface: uint64(u.LUID)})
		}
		prepared.routes = append(prepared.routes, winplatform.Route(u.LUID, netip.PrefixFrom(endpoint, endpoint.BitLen()), u.Gateway))
	}
	return prepared, nil
}
func (m *Manager) PrepareConnect(ctx context.Context, p model.Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	platform, err := m.Platform()
	if err != nil {
		return err
	}
	if err = m.refreshExternalLocked(ctx); err != nil {
		return err
	}
	if platform.HasFull() {
		return errors.New("Another VPN provides Internet access; switching is postponed")
	}
	u, err := winplatform.PhysicalUplink(false)
	if err != nil {
		u, err = winplatform.PhysicalUplink(true)
	}
	if err != nil {
		return err
	}
	m.uplink = u
	prepared, err := m.resolveProfile(ctx, p)
	if err != nil {
		return err
	}
	if err = core.CheckBinaryContext(ctx, m.config.XrayPath); err != nil {
		return err
	}
	m.prepared = prepared
	return nil
}
func chooseWindowsSubnets() (netip.Prefix, netip.Prefix, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, err
	}
	var occupied []netip.Prefix
	for _, route := range routes {
		prefix := route.DestinationPrefix.Prefix()
		if prefix.IsValid() && prefix.Bits() > 0 {
			occupied = append(occupied, prefix)
		}
	}
	return chooseFreeSubnets(occupied)
}
func (m *Manager) Connect(ctx context.Context, p model.Profile) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.config.DryRun {
		return errors.New("check mode cannot establish a VPN connection")
	}
	m.publish("connecting", "enabling_guard", "Enabling persistent Windows protection")
	if err = m.arm(ctx); err != nil {
		return m.fail(err)
	}
	defer func() {
		if err != nil {
			m.part.Default4, m.part.Default6 = 0, 0
			m.platform.Guard.Set("main", m.part)
			m.stop(context.Background())
			m.fail(err)
		}
	}()
	if err = m.stop(ctx); err != nil {
		return err
	}
	if err = m.platform.Routes.Set("main-tunnel", nil); err != nil {
		return err
	}
	m.profile = &p
	if m.platform.HasFull() {
		m.publish("paused_external", "paused_external", "Another VPN provides Internet access")
		return nil
	}
	m.ipv6State = "checking"
	m.publish("connecting", "resolving_endpoint", "Resolving VPN transport endpoints")
	prepared := m.prepared
	m.prepared = nil
	if prepared == nil || prepared.profile.ID != p.ID || time.Since(prepared.at) > 30*time.Second {
		prepared, err = m.resolveProfile(ctx, p)
		if err != nil {
			return err
		}
	}
	m.part.Endpoints = append(m.part.Endpoints, prepared.endpoints...)
	if err = m.platform.Guard.Set("main", m.part); err != nil {
		return err
	}
	if err = m.platform.Routes.Set("main-endpoints", prepared.routes); err != nil {
		return err
	}
	m.v4, m.v6, err = chooseWindowsSubnets()
	if err != nil {
		return err
	}
	options := core.Options{Interface: TunName, Gateway4: m.v4, Gateway6: m.v6, DNSAddress: m.v4.Addr().Next(), Endpoint: prepared.endpoint, Uplink: m.uplink.Name, Mark: 1}
	m.publish("connecting", "starting_core", "Starting installed VPN engines")
	if p.Outline != nil {
		if err = m.outline.Prepare(); err != nil {
			return err
		}
		if err = m.outline.Start(ctx, m.config.OutlinePath, model.OutlineRuntime{Transport: p.Outline, Resolved: prepared.resolved, Interface: m.uplink.Name}); err != nil {
			return err
		}
		options.LocalPort, options.LocalUser, options.LocalPassword = m.outline.Port, m.outline.User, m.outline.Password
		m.part.PrivatePorts = []winplatform.PrivatePort{{Port: uint16(m.outline.Port), App: m.config.XrayPath}}
		if err = m.platform.Guard.Set("main", m.part); err != nil {
			return err
		}
	}
	config, err := core.Build(p, options)
	if err != nil {
		return err
	}
	path, err := core.WriteConfig(m.config.RuntimeDir, config)
	if err != nil {
		return err
	}
	m.epoch.Add(1)
	if err = m.ensureMainAdapterLocked(ctx); err != nil {
		return err
	}
	if err = m.core.Start(ctx, m.config.XrayPath, path, m.logSession); err != nil {
		return err
	}
	ready, stop := context.WithTimeout(ctx, winplatform.InterfaceReadyTimeout)
	luid, err := winplatform.WaitInterface(ready, TunName, m.core.Alive)
	if err == nil {
		// The service owns creation; Xray opens it and assigns initial IPs. Wait until both
		// addresses are visible instead of flushing them during its Start().
		for {
			addresses, e := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
			v4, v6 := false, false
			if e == nil {
				for _, a := range addresses {
					if a.InterfaceLUID == luid {
						ip := a.Address.Addr()
						v4 = v4 || ip == m.v4.Addr()
						v6 = v6 || ip == m.v6.Addr()
					}
				}
			}
			if v4 && v6 {
				break
			}
			if !m.core.Alive() {
				err = errors.New("Xray stopped before configuring its TUN")
				break
			}
			select {
			case <-ready.Done():
				err = ready.Err()
			case <-time.After(50 * time.Millisecond):
			}
			if err != nil {
				break
			}
		}
	}
	stop()
	if err != nil {
		return fmt.Errorf("main TUN readiness: %w", err)
	}
	m.tun.Store(uint64(luid))
	m.publish("connecting", "configuring_network", "Configuring Windows routes and split DNS")
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		iface, e := luid.IPInterface(family)
		if e == nil {
			iface.UseAutomaticMetric = false
			iface.Metric = 1
			iface.NLMTU = 1400
			if e = iface.Set(); e != nil {
				return e
			}
		}
	}
	m.part.Default4 = uint64(luid)
	// IPv6 probes are scoped to the service until readiness is established.
	exe, _ := os.Executable()
	if err = m.platform.Guard.Set("main", m.part); err != nil {
		return err
	}
	var routes []winplatform.OwnedRoute
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		routes = append(routes, winplatform.Route(luid, netip.MustParsePrefix(prefix), netip.Addr{}))
	}
	if err = m.platform.Routes.Set("main-tunnel", routes); err != nil {
		return err
	}
	if err = winplatform.ConfigureOwnedDNS(luid, true); err != nil {
		return err
	}
	if err = m.platform.DNS.Set("main", winplatform.DNSPlan{Servers: []netip.Addr{m.v4.Addr().Next()}, Interface: luid, Active: true, Default: true, Priority: 10}, m.uplink.LUID); err != nil {
		return err
	}
	m.publish("connecting", "checking_connection", "Verifying DNS and HTTPS through the tunnel")
	if err = m.healthWindows(ctx, false); err != nil {
		return err
	}
	// Temporarily admit only service-owned IPv6 probes through this exact TUN.
	m.part.Probe6 = uint64(luid)
	m.part.ProbeApp = exe
	if err = m.platform.Guard.Set("main", m.part); err != nil {
		return err
	}
	v6ctx, done := context.WithTimeout(ctx, 4*time.Second)
	v6err := m.healthWindows(v6ctx, true)
	done()
	m.part.Probe6 = 0
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if v6err != nil {
		m.part.Default6 = 0
		m.ipv6State = "unavailable"
	} else {
		m.part.Default6 = uint64(luid)
		m.ipv6State = "available"
	}
	if err = m.platform.Guard.Set("main", m.part); err != nil {
		return err
	}
	m.lastHealth = time.Now()
	m.viewMu.Lock()
	m.status.ConnectedAt = time.Now().Unix()
	m.status.FailureCode = ""
	m.viewMu.Unlock()
	m.publish("connected", "connected", "")
	return nil
}
func (m *Manager) healthWindows(parent context.Context, ipv6 bool) error {
	luid := winipcfg.LUID(m.tun.Load())
	if luid == 0 {
		return errors.New("VPN tunnel is unavailable")
	}
	dialer := winplatform.Dialer(luid)
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort(m.v4.Addr().Next().String(), "53"))
	}}
	ctx, done := context.WithTimeout(parent, 8*time.Second)
	defer done()
	var last error
	family := "ip4"
	if ipv6 {
		family = "ip6"
	}
	for _, host := range []string{"cp.cloudflare.com", "www.gstatic.com"} {
		attempt, cancel := context.WithTimeout(ctx, 4*time.Second)
		err := checkHTTPSFamily(attempt, family, host, resolver.LookupNetIP, dialer.DialContext, nil)
		cancel()
		if err == nil {
			return nil
		}
		if last == nil || healthPriority(err) > healthPriority(last) {
			last = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return last
}
func (m *Manager) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshExternalLocked(ctx); err != nil {
		return m.fail(err)
	}
	status := m.Status()
	if !status.GuardArmed {
		return nil
	}
	if m.platform.HasFull() {
		if status.State != "paused_external" {
			m.part.Default4, m.part.Default6 = 0, 0
			if err := m.platform.Guard.Set("main", m.part); err != nil {
				return m.fail(err)
			}
			if err := m.stop(ctx); err != nil {
				return m.fail(err)
			}
			if err := m.platform.Routes.Set("main-tunnel", nil); err != nil {
				return m.fail(err)
			}
			if err := m.platform.DNS.Remove("main"); err != nil {
				return m.fail(err)
			}
			m.publish("paused_external", "paused_external", "Another VPN provides Internet access")
		}
		return nil
	}
	if status.State == "paused_external" {
		return m.fail(errors.New("Main VPN needs reconnect after external VPN"))
	}
	// Failed attempts retain their original diagnostic until the retry worker
	// runs. Rechecking a stopped engine would replace it every two seconds.
	if status.State != "connected" {
		return nil
	}
	u, err := winplatform.PhysicalUplink(m.uplink.Gateway.Is6())
	if err != nil {
		return m.fail(err)
	}
	if u.LUID != m.uplink.LUID || u.Gateway != m.uplink.Gateway {
		m.part.Default4, m.part.Default6 = 0, 0
		m.platform.Guard.Set("main", m.part)
		m.stop(ctx)
		return m.fail(errors.New("network changed; reconnect required"))
	}
	if !m.core.Alive() || (m.profile != nil && m.profile.Outline != nil && !m.outline.Alive()) {
		return m.fail(errors.New("VPN engine stopped; traffic remains protected"))
	}
	if time.Since(m.lastHealth) > 30*time.Second {
		if err = m.healthWindows(ctx, false); err != nil {
			return m.fail(err)
		}
		m.lastHealth = time.Now()
	}
	return nil
}
func (m *Manager) Disconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.config.DryRun {
		return nil
	}
	p, err := m.Platform()
	if err != nil {
		return err
	}
	m.publish("disconnecting", "restoring_network", "Restoring Windows networking")
	if err = m.stop(ctx); err != nil {
		return m.fail(err)
	}
	for _, owner := range []string{"main-tunnel", "main-endpoints", "main-bootstrap"} {
		if err = p.Routes.Set(owner, nil); err != nil {
			return m.fail(err)
		}
	}
	if err = p.DNS.Remove("main"); err != nil {
		return m.fail(err)
	}
	if err = p.Guard.Remove("main"); err != nil {
		return m.fail(err)
	}
	m.viewMu.Lock()
	m.status = model.RuntimeStatus{State: "disconnected"}
	m.viewMu.Unlock()
	m.profile = nil
	m.ipv6State = "inactive"
	m.publish("disconnected", "disconnected", "")
	return nil
}
func (m *Manager) Diagnostics(context.Context) any {
	status := m.Status()
	return map[string]any{"state": status.State, "message": status.Message, "stage": status.Stage, "guardArmed": status.GuardArmed, "failureCode": status.FailureCode, "platform": "windows", "coreVersion": core.Version, "capturedAt": time.Now().UnixMilli()}
}
func (m *Manager) Watch(ctx context.Context) (<-chan struct{}, error) {
	p, err := m.Platform()
	if err != nil {
		return nil, err
	}
	return p.Watch(ctx)
}
func (m *Manager) SetTrafficHandler(fn func(model.TUNCounters)) {
	m.trafficMu.Lock()
	m.trafficHandler = fn
	m.trafficMu.Unlock()
}
func (m *Manager) TrafficCounters() model.TUNCounters {
	epoch, luid := m.epoch.Load(), winipcfg.LUID(m.tun.Load())
	if luid == 0 || !m.core.Alive() {
		return model.TUNCounters{}
	}
	iface, err := luid.Interface()
	if err != nil || epoch != m.epoch.Load() || uint64(luid) != m.tun.Load() {
		return model.TUNCounters{}
	}
	return model.TUNCounters{Epoch: epoch, IfIndex: uint64(iface.InterfaceIndex), RXBytes: iface.InOctets, TXBytes: iface.OutOctets, SampledAt: time.Now(), Valid: true}
}
func (m *Manager) FetchSource(ctx context.Context, raw string) (document string, result error) {
	p, err := m.Platform()
	if err != nil {
		return "", err
	}
	u, err := winplatform.PhysicalUplink(false)
	if err != nil {
		return "", err
	}
	fetchContext, cancelFetch := context.WithCancel(ctx)
	var leases sourceFetchLeases
	defer func() { result = errors.Join(result, leases.finish(cancelFetch)) }()
	return profiles.FetchDocument(fetchContext, raw, func(ctx context.Context, network, address string) (net.Conn, error) {
		// Transport may start or complete a dial after FetchDocument returns.
		// Admission closes before finalization waits for all in-flight callbacks.
		if !leases.begin() {
			return nil, context.Canceled
		}
		defer leases.pending.Done()
		ctx, cancelDial := context.WithCancel(ctx)
		stopCancellation := context.AfterFunc(fetchContext, cancelDial)
		defer func() { stopCancellation(); cancelDial() }()
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid source endpoint")
		}
		ip, err := resolveWindows(ctx, host, u)
		if err != nil {
			return nil, err
		}
		if !profiles.PublicIP(net.IP(ip.AsSlice())) {
			return nil, errors.New("source address must be public")
		}
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return nil, errors.New("invalid source port")
		}
		link, err := winplatform.PhysicalUplink(ip.Is6())
		if err != nil {
			return nil, err
		}
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", address, time.Now().UnixNano())))
		key := "source-" + hex.EncodeToString(hash[:8])
		cleanup := func() error {
			return cleanupSourceResources(func() error { return p.Guard.Remove(key) }, func() error { return p.Routes.Set(key, nil) })
		}
		failed := func(err error) (net.Conn, error) {
			cleanupErr := cleanup()
			leases.recordCleanup(cleanupErr)
			return nil, errors.Join(err, cleanupErr)
		}
		if err = p.Guard.Set(key, winplatform.GuardPart{Endpoints: []winplatform.Endpoint{{App: exe, Address: ip, Port: uint16(number), Interface: uint64(link.LUID)}}}); err != nil {
			return failed(err)
		}
		if err = p.Routes.Set(key, []winplatform.OwnedRoute{winplatform.Route(link.LUID, netip.PrefixFrom(ip, ip.BitLen()), link.Gateway)}); err != nil {
			return failed(err)
		}
		conn, err := winplatform.Dialer(link.LUID).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err != nil {
			return failed(err)
		}
		lease := &sourceConn{Conn: conn, cleanup: cleanup}
		if err = leases.add(lease); err != nil {
			return nil, err
		}
		return lease, nil
	})
}

type sourceConn struct {
	net.Conn
	once    sync.Once
	cleanup func() error
	err     error
}

func (c *sourceConn) Close() error {
	c.once.Do(func() {
		closeErr := c.Conn.Close()
		var cleanupErr error
		if c.cleanup != nil {
			cleanupErr = c.cleanup()
		}
		c.err = errors.Join(closeErr, cleanupErr)
	})
	return c.err
}
func cleanupSourceResources(removeGuard, releaseRoute func() error) error {
	guardErr := removeGuard()
	routeErr := releaseRoute() // Always attempt route release, even on guard error.
	return errors.Join(guardErr, routeErr)
}

// A single FetchSource call owns this small lease set. No new callback can
// enter after finish, and admitted callbacks must complete cleanup before return.
type sourceFetchLeases struct {
	mu          sync.Mutex
	pending     sync.WaitGroup
	closed      bool
	connections []*sourceConn
	cleanupErr  error
	finishOnce  sync.Once
	result      error
}

func (s *sourceFetchLeases) begin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.pending.Add(1)
	return true
}
func (s *sourceFetchLeases) add(conn *sourceConn) error {
	s.mu.Lock()
	s.connections = append(s.connections, conn)
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return errors.Join(context.Canceled, conn.Close())
	}
	return nil
}
func (s *sourceFetchLeases) recordCleanup(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.cleanupErr = errors.Join(s.cleanupErr, err)
	s.mu.Unlock()
}
func (s *sourceFetchLeases) finish(cancel context.CancelFunc) error {
	s.finishOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		cancel()
		s.pending.Wait()
		s.mu.Lock()
		connections, cleanupErr := s.connections, s.cleanupErr
		s.mu.Unlock()
		for _, conn := range connections {
			cleanupErr = errors.Join(cleanupErr, conn.Close())
		}
		s.result = cleanupErr
	})
	return s.result
}

// ReleaseExternal restores only resources owned by the external-VPN
// coordinator. Ordinary main disconnection keeps corporate protection active.
func (m *Manager) ReleaseExternal(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.releaseExternalLocked(ctx)
}
