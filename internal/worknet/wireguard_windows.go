package worknet

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"vault443/internal/core"
	"vault443/internal/journal"
	"vault443/internal/network"
	"vault443/internal/winplatform"
	"vault443/internal/workvpn"
)

type tunnelConfig struct {
	Interface string `json:"interface"`
	Kind      string `json:"kind"`
	MTU       int    `json:"mtu"`
	UAPI      string `json:"uapi"`
	GUID      string `json:"guid"`
	Bind4     uint32 `json:"bind4"`
	Bind6     uint32 `json:"bind6"`
}
type tunnelCommand struct {
	UAPI  string   `json:"uapi,omitempty"`
	Probe []string `json:"probe,omitempty"`
	Bind4 *uint32  `json:"bind4,omitempty"`
	Bind6 *uint32  `json:"bind6,omitempty"`
}
type tunnelObservation struct {
	Ready bool `json:"ready"`
	Peers []struct {
		Key       string `json:"key"`
		Handshake int64  `json:"handshake"`
		RX        uint64 `json:"rx"`
		TX        uint64 `json:"tx"`
		Endpoint  string `json:"endpoint"`
	} `json:"peers"`
}
type wgResolution struct {
	Index    int
	Endpoint network.Endpoint
	Link     winplatform.Uplink
	Err      error
}

func (m *Manager) Run(ctx context.Context, uid uint32, p workvpn.Profile, logs *journal.Session, onStatus func(Status)) error {
	if err := workvpn.ValidateProfile(p); err != nil {
		return err
	}
	switch p.Protocol() {
	case "wireguard", "amneziawg":
		return m.runWireGuard(ctx, uid, p, logs, onStatus)
	case "openvpn":
		return m.runOpenVPN(ctx, uid, p, logs, onStatus)
	default:
		return errors.New("unsupported work VPN protocol")
	}
}
func windowsWorkGUID(id string) windows.GUID {
	h := sha256.Sum256([]byte("Vault443.WorkAdapter.1:" + id))
	return windows.GUID{Data1: uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3]), Data2: uint16(h[4])<<8 | uint16(h[5]), Data3: uint16(h[6])<<8 | uint16(h[7]), Data4: [8]byte(h[8:16])}
}
func windowsUAPI(w *workvpn.WireGuardConfig, endpoints []network.Endpoint) string {
	lines := strings.Split(amneziaConfig(w, endpoints), "\n")
	var b strings.Builder
	for _, line := range lines {
		if line == "set=1" || strings.HasPrefix(line, "fwmark=") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
func resolveWindowsPeer(ctx context.Context, index int, remote workvpn.Remote) wgResolution {
	out := wgResolution{Index: index}
	ip, err := network.ResolveWorkEndpointForProtocol(ctx, remote.Host, remote.Protocol)
	if err != nil {
		out.Err = err
		return out
	}
	u, err := winplatform.PhysicalUplink(ip.Is6())
	if err != nil {
		out.Err = err
		return out
	}
	out.Endpoint = network.Endpoint{Address: ip.String(), Port: remote.Port, Protocol: "udp"}
	out.Link = u
	return out
}
func (m *Manager) runWireGuard(ctx context.Context, _ uint32, p workvpn.Profile, logs *journal.Session, onStatus func(Status)) (result error) {
	ctx, stopAttempt := context.WithCancel(ctx)
	defer stopAttempt()
	if p.WireGuard == nil || len(p.WireGuard.Peers) == 0 {
		return errors.New("WireGuard profile has no peers")
	}
	w := p.WireGuard
	m.mu.Lock()
	ss, err := m.beginSession(p, logs, onStatus)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	ss.PeerPrefixes = map[string][]string{}
	ss.Routes = nil
	ss.DNSServers = append([]string(nil), w.DNSServers...)
	ss.DNSDomains = append([]string(nil), w.DNSDomains...)
	for _, peer := range w.Peers {
		id := peerID(peer.PublicKey)
		ss.PeerPrefixes[id] = append([]string(nil), peer.AllowedIPs...)
		for _, prefix := range peer.AllowedIPs {
			ss.Routes = append(ss.Routes, route{CIDR: prefix})
		}
	}
	ss.Status.Routes = nil
	for _, r := range ss.Routes {
		ss.Status.Routes = append(ss.Status.Routes, r.CIDR)
	}
	ss.Status.DNSServers = append([]string(nil), ss.DNSServers...)
	ss.Status.DNSDomains = append([]string(nil), ss.DNSDomains...)
	m.lastPolicy = ""
	err = m.applyLocked(ctx)
	m.setStageLocked(p.ID, "connecting", "enabling_guard", "Protecting WireGuard destinations")
	m.mu.Unlock()
	var process core.Process
	var control io.WriteCloser
	var closeControl sync.Once
	cleanupDone := make(chan struct{})
	closeHelperControl := func() {
		// EOF lets the engine close its TUN/Wintun owner before process exit.
		// Closing the writer also unblocks any pending private control update.
		closeControl.Do(func() {
			if control != nil {
				_ = control.Close()
			}
		})
	}
	stopHelper := func(ctx context.Context) error {
		closeHelperControl()
		grace, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := process.WaitContext(grace); err == nil {
			return nil
		}
		return process.StopContext(ctx)
	}
	defer func() {
		defer close(cleanupDone)
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// Invalidate readiness before killing the interface. The destination blocks
		// also protect the interval if a process has already crashed.
		down := m.markDown(cleanup, p.ID)
		stopped := stopHelper(cleanup)
		var finished error
		if stopped == nil {
			finished = m.finishSession(cleanup, p.ID)
		}
		if down != nil {
			down = fmt.Errorf("work markDown: %w", down)
		}
		if stopped != nil {
			stopped = fmt.Errorf("work stopHelper: %w", stopped)
		}
		if finished != nil {
			finished = fmt.Errorf("work finishSession: %w", finished)
		}
		result = errors.Join(result, down, stopped, finished)
	}()
	if err != nil {
		return err
	}
	// The name can only be reused when its persisted native identity matches.
	if existing, e := winplatform.InterfaceByName(ss.Interface); e == nil {
		guid, e := existing.GUID()
		if e != nil || *guid != windowsWorkGUID(p.ID) {
			return errors.New("work tunnel name belongs to another adapter")
		}
	}
	m.mu.Lock()
	m.setStageLocked(p.ID, "connecting", "resolving_endpoint", "Resolving WireGuard peers")
	m.mu.Unlock()
	endpoints := make([]network.Endpoint, len(w.Peers))
	links := make([]winplatform.Uplink, len(w.Peers))
	resolved := make(chan wgResolution, len(w.Peers))
	slots := make(chan struct{}, 4)
	var resolving sync.WaitGroup
	for i, peer := range w.Peers {
		resolving.Add(1)
		go func(index int, remote workvpn.Remote) {
			defer resolving.Done()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			r := resolveWindowsPeer(ctx, index, remote)
			<-slots
			select {
			case resolved <- r:
			case <-ctx.Done():
			}
		}(i, peer.Endpoint)
	}
	go func() { resolving.Wait(); close(resolved) }()
	valid := 0
	for r := range resolved {
		if r.Err == nil {
			endpoints[r.Index], links[r.Index] = r.Endpoint, r.Link
			valid++
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if valid == 0 {
		return errors.New("no WireGuard peer endpoint is available on a physical uplink")
	}
	var bind4, bind6 uint32
	if u, e := winplatform.PhysicalUplink(false); e == nil {
		bind4 = u.Index
	}
	if u, e := winplatform.PhysicalUplink(true); e == nil {
		bind6 = u.Index
	}
	m.mu.Lock()
	ss.Endpoints = wireGuardPermits(m.config.WireGuardPath, endpoints, links)
	m.lastPolicy = ""
	err = m.applyLocked(ctx)
	m.setStageLocked(p.ID, "connecting", "starting_core", "Creating WireGuard interface")
	m.mu.Unlock()
	if err != nil {
		return err
	}
	cmd := exec.Command(m.config.WireGuardPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return errors.New("cannot create private WireGuard control channel")
	}
	control = stdin
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return errors.New("cannot create WireGuard observation channel")
	}
	cmd.Stderr = io.Discard
	initialUnderlay := windowsUnderlayFingerprint()
	attemptStarted := time.Now()
	if err = process.StartInstalled(ctx, cmd); err != nil {
		return err
	}
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
		case <-stopped:
		}
		// Cancellation must not remove Wintun before markDown withdraws owned
		// routes and updates DNS. Only the expired cleanup deadline may force
		// termination, including a startup/control write stuck before Run exits.
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		select {
		case <-cleanupDone:
			return
		case <-deadline.C:
		}
		closeHelperControl()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = process.StopContext(shutdown)
	}()
	encoder := json.NewEncoder(stdin)
	initial := tunnelConfig{Interface: ss.Interface, Kind: p.Protocol(), MTU: w.MTU, UAPI: windowsUAPI(w, endpoints), GUID: windowsWorkGUID(p.ID).String(), Bind4: bind4, Bind6: bind6}
	if err = encoder.Encode(initial); err != nil {
		return errors.New("cannot configure private WireGuard engine")
	}
	observations := make(chan tunnelObservation, 2)
	readErrors := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 65536), 2<<20)
		draining := false
		for scanner.Scan() {
			if draining {
				continue
			}
			var observation tunnelObservation
			if json.Unmarshal(scanner.Bytes(), &observation) != nil || len(observation.Peers) > 32 {
				readErrors <- errors.New("invalid WireGuard engine observation")
				return
			}
			select {
			case observations <- observation:
			case <-stopped:
				// Keep the inherited pipe draining through graceful engine.Close.
				// Otherwise a final observation could block the helper before it
				// handles stdin EOF and releases its Wintun creator handle.
				draining = true
			}
		}
		if scanner.Err() != nil {
			readErrors <- errors.New("WireGuard observation channel failed")
		} else {
			readErrors <- errors.New("WireGuard engine stopped")
		}
	}()
	ready, cancelReady := context.WithTimeout(ctx, winplatform.InterfaceReadyTimeout)
	luid, err := winplatform.WaitInterface(ready, ss.Interface, process.Alive)
	cancelReady()
	if err != nil {
		return fmt.Errorf("%s TUN readiness: %w", p.Protocol(), err)
	}
	guid, err := luid.GUID()
	if err != nil || *guid != windowsWorkGUID(p.ID) {
		return errors.New("private WireGuard adapter identity changed")
	}
	addresses := make([]netip.Prefix, 0, len(w.Addresses))
	for _, text := range w.Addresses {
		ip, e := netip.ParsePrefix(text)
		if e != nil {
			return e
		}
		addresses = append(addresses, ip)
	}
	if err = luid.SetIPAddresses(addresses); err != nil {
		return fmt.Errorf("cannot configure WireGuard addresses: %w", err)
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		ipif, e := luid.IPInterface(family)
		if e != nil {
			continue
		}
		ipif.UseAutomaticMetric = false
		ipif.Metric = 1
		ipif.NLMTU = uint32(w.MTU)
		if e = ipif.Set(); e != nil {
			return fmt.Errorf("cannot configure WireGuard interface policy: %w", e)
		}
	}
	if err = winplatform.ConfigureOwnedDNS(luid, true); err != nil {
		return err
	}
	m.mu.Lock()
	ss.LUID = luid
	m.lastPolicy = ""
	err = m.applyLocked(ctx)
	m.setStageLocked(p.ID, "connecting", "exchanging_keys", "Waiting for authenticated WireGuard handshake")
	m.mu.Unlock()
	if err != nil {
		return err
	}
	health := make([]wgHealth, len(w.Peers))
	known := map[string]int{}
	for i, peer := range w.Peers {
		known[keyHex(peer.PublicKey)] = i
	}
	// PnP readiness is not time spent waiting for an authenticated peer. Keep
	// the engine-start epoch below to accept its genuine early handshakes.
	started := time.Now()
	everConnected := false
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastCheck := time.Time{}
	nextResolve := make([]time.Time, len(w.Peers))
	pending := make([]bool, len(w.Peers))
	updates := make(chan wgResolution, len(w.Peers))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErrors:
			return err
		case observation := <-observations:
			if !observation.Ready || len(observation.Peers) != len(w.Peers) {
				return errors.New("private WireGuard peer set changed")
			}
			now := time.Now()
			readyCount := 0
			statuses := make([]PeerStatus, len(w.Peers))
			seen := map[int]bool{}
			changed := false
			for _, observed := range observation.Peers {
				i, ok := known[observed.Key]
				if !ok || seen[i] {
					return errors.New("WireGuard peer identity changed")
				}
				seen[i] = true
				old := health[i].Observation
				current := wgPeerObservation{Handshake: observed.Handshake, RX: observed.RX, TX: observed.TX, Endpoint: observed.Endpoint}
				if observed.Endpoint != "" && (current.Handshake > old.Handshake || current.RX > old.RX) {
					if ep, e := parseWindowsEndpoint(observed.Endpoint); e == nil && ep != endpoints[i] {
						u, e := winplatform.PhysicalUplink(netip.MustParseAddr(ep.Address).Is6())
						if e == nil {
							endpoints[i], links[i] = ep, u
							changed = true
						}
					}
				}
				before := health[i].Ready
				updateWGHealth(&health[i], current, now, attemptStarted, wgKeyLifetime(w))
				health[i].Observation = current
				changed = changed || before != health[i].Ready
				state := "connecting"
				if health[i].Ready {
					readyCount++
					state = "connected"
				} else if everConnected {
					state = "reconnecting"
				}
				statuses[i] = PeerStatus{ID: peerID(w.Peers[i].PublicKey), Endpoint: endpointString(endpoints[i]), State: state, LastHandshakeAt: health[i].Handshake, AllowedIPs: append([]string(nil), w.Peers[i].AllowedIPs...)}
			}
			if readyCount > 0 {
				everConnected = true
			}
			if !everConnected && now.Sub(started) > wgInitialTimeout {
				return errors.New("WireGuard handshake timed out; no authenticated response from peers")
			}
			m.mu.Lock()
			ss.Active = readyCount > 0
			ss.Status.Peers = statuses
			for i, peer := range w.Peers {
				ss.PeerReady[peerID(peer.PublicKey)] = health[i].Ready
			}
			if readyCount > 0 && ss.Status.ConnectedAt == 0 {
				ss.Status.ConnectedAt = now.Unix()
			}
			ss.Endpoints = wireGuardPermits(m.config.WireGuardPath, endpoints, links)
			if changed {
				m.lastPolicy = ""
			}
			err = m.applyLocked(ctx)
			state, stage, message := "connecting", "exchanging_keys", "Waiting for authenticated WireGuard handshake"
			if readyCount == len(w.Peers) {
				state, stage, message = "connected", "connected", "Connected"
			} else if readyCount > 0 {
				state, stage, message = "partial", "partial", "Some peers are unavailable; their routes remain protected"
			} else if everConnected {
				state, stage, message = "reconnecting", "exchanging_keys", "Reconnecting WireGuard peers; destinations remain protected"
			}
			if ss.Status.State == "conflict" && readyCount > 0 {
				state, stage, message = ss.Status.State, ss.Status.Stage, ss.Status.Message
			}
			if err == nil {
				m.setStageLocked(p.ID, state, stage, message)
			}
			m.mu.Unlock()
			if err != nil {
				return err
			}
		case r := <-updates:
			pending[r.Index] = false
			if r.Err != nil || r.Endpoint == endpoints[r.Index] {
				continue
			}
			oldEndpoint, oldLink := endpoints[r.Index], links[r.Index]
			endpoints[r.Index], links[r.Index] = r.Endpoint, r.Link
			m.mu.Lock()
			ss.Endpoints = wireGuardPermits(m.config.WireGuardPath, endpoints, links)
			m.lastPolicy = ""
			err = m.applyLocked(ctx)
			m.mu.Unlock()
			if err != nil {
				endpoints[r.Index], links[r.Index] = oldEndpoint, oldLink
				return err
			}
			update := fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n\n", keyHex(w.Peers[r.Index].PublicKey), endpointString(r.Endpoint))
			if err = encoder.Encode(tunnelCommand{UAPI: update}); err != nil {
				return errors.New("cannot update private WireGuard endpoint")
			}
		case now := <-tick.C:
			if !process.Alive() {
				return errors.New("WireGuard engine stopped")
			}
			var probes []string
			for i, peer := range w.Peers {
				if endpoints[i].Address != "" && (!health[i].Ready || !health[i].CheckingAt.IsZero()) && now.Sub(health[i].LastProbe) >= 5*time.Second {
					probes = append(probes, keyHex(peer.PublicKey))
					health[i].LastProbe = now
				}
				if !health[i].Ready && !pending[i] && (nextResolve[i].IsZero() || !now.Before(nextResolve[i])) {
					pending[i] = true
					nextResolve[i] = now.Add(wgPeerRetry)
					go func(index int, remote workvpn.Remote) {
						r := resolveWindowsPeer(ctx, index, remote)
						select {
						case updates <- r:
						case <-ctx.Done():
						}
					}(i, peer.Endpoint)
				}
			}
			if len(probes) > 0 {
				if err = encoder.Encode(tunnelCommand{Probe: probes}); err != nil {
					return errors.New("cannot probe private WireGuard peers")
				}
			}
			if now.Sub(lastCheck) >= 5*time.Second {
				lastCheck = now
				if windowsUnderlayFingerprint() != initialUnderlay {
					return errors.New("physical network changed; WireGuard endpoints will be revalidated")
				}
			}
		}
	}
}
func wireGuardPermits(app string, endpoints []network.Endpoint, links []winplatform.Uplink) []winplatform.Endpoint {
	var result []winplatform.Endpoint
	for i, endpoint := range endpoints {
		ip, err := netip.ParseAddr(endpoint.Address)
		if err != nil || links[i].LUID == 0 {
			continue
		}
		result = append(result, winplatform.Endpoint{App: app, Address: ip, Port: uint16(endpoint.Port), UDP: true, Interface: uint64(links[i].LUID)})
	}
	return result
}
func parseWindowsEndpoint(text string) (network.Endpoint, error) {
	host, port, err := net.SplitHostPort(text)
	if err != nil {
		return network.Endpoint{}, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
		return network.Endpoint{}, errors.New("invalid peer endpoint")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return network.Endpoint{}, errors.New("invalid peer endpoint port")
	}
	return network.Endpoint{Address: ip.String(), Port: int(n), Protocol: "udp"}, nil
}

func windowsUnderlayFingerprint() string {
	var entries []string
	addresses, _ := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	for _, v6 := range []bool{false, true} {
		u, err := winplatform.PhysicalUplink(v6)
		if err != nil {
			entries = append(entries, fmt.Sprintf("missing:%v", v6))
			continue
		}
		entries = append(entries, fmt.Sprintf("%v:%d:%d:%s", v6, u.LUID, u.Index, u.Gateway))
		for _, a := range addresses {
			if a.InterfaceLUID == u.LUID {
				entries = append(entries, fmt.Sprintf("%d:%s/%d", u.LUID, a.Address.Addr(), a.OnLinkPrefixLength))
			}
		}
	}
	sort.Strings(entries)
	return strings.Join(entries, ";")
}
