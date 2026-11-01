package worknet

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vault443/internal/journal"
	"vault443/internal/network"
	"vault443/internal/workvpn"
)

const wgInitialTimeout = 60 * time.Second
const wgPeerRetry = 30 * time.Second

type wgHealth struct {
	ConfirmedAt time.Time
	NoProbe     bool
	Ready       bool
	Handshake   int64
	CheckingAt  time.Time
	LastProbe   time.Time
	LastResolve time.Time
	Observation wgPeerObservation
}

func workInterface(id string) string {
	h := sha256.Sum256([]byte(id))
	return "v443w" + hex.EncodeToString(h[:4])
}

func (m *Manager) runWireGuard(ctx context.Context, uid uint32, p workvpn.Profile, logs *journal.Session, onStatus func(Status)) error {
	ctx, stopAttempt := context.WithCancel(ctx)
	defer stopAttempt()
	if p.WireGuard == nil || len(p.WireGuard.Peers) == 0 {
		return errors.New("WireGuard profile has no peers")
	}
	if p.Protocol() != "wireguard" && p.Protocol() != "amneziawg" {
		return errors.New("unsupported work VPN protocol")
	}
	path := m.config.WireGuardPath
	if p.Protocol() == "amneziawg" {
		path = m.config.AmneziaWGPath
	}
	if err := secureExecutable(path); err != nil {
		return err
	}
	w := p.WireGuard
	iface := workInterface(p.ID)
	m.mu.Lock()
	ss := m.sessions[p.ID]
	if ss == nil {
		if len(m.sessions) >= 32 {
			m.mu.Unlock()
			return errors.New("at most 32 work VPNs may be requested")
		}
		for _, entry := range m.sessions {
			if entry.Interface == iface {
				m.mu.Unlock()
				return errors.New("work tunnel identity collision")
			}
		}
		m.nextOrder++
		ss = &session{ID: p.ID, Interface: iface, Order: m.nextOrder}
		m.sessions[p.ID] = ss
	}
	ss.Kind = p.Protocol()
	ss.Name = p.Name
	ss.callback = onStatus
	ss.log = logs
	ss.Active = false
	ss.PeerReady = map[string]bool{}
	ss.PeerPrefixes = map[string][]string{}
	ss.Routes = nil
	ss.Endpoints = nil
	ss.Endpoint = network.Endpoint{}
	ss.Status = Status{Interface: iface}
	ss.Attempt++
	ss.DNSServers = append([]string(nil), w.DNSServers...)
	ss.DNSDomains = append([]string(nil), w.DNSDomains...)
	if len(ss.DNSServers) > 0 && len(ss.DNSDomains) == 0 {
		ss.DNSDomains = []string{"."}
	}
	for _, peer := range w.Peers {
		id := peerID(peer.PublicKey)
		// Keep exact cryptokey prefix specificity. Combining a peer's two
		// /1 entries into /0 can incorrectly tie another peer's real /0.
		ss.PeerPrefixes[id] = append([]string(nil), peer.AllowedIPs...)

		for _, prefix := range ss.PeerPrefixes[id] {
			ss.Routes = append(ss.Routes, route{prefix, ""})
			ss.Status.Routes = append(ss.Status.Routes, prefix)
		}
	}
	ss.Status.DNSServers = append([]string(nil), ss.DNSServers...)
	ss.Status.DNSDomains = append([]string(nil), ss.DNSDomains...)
	m.setStageLocked(p.ID, "connecting", "enabling_guard", "Protecting WireGuard destinations")
	m.lastPolicy = ""
	err := m.applyLocked(ctx)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	// Retain interface and DNS ownership across failed attempts. The coordinator
	// installs unreachable routes before peers/processes are stopped.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = m.markDown(cleanup, p.ID)
		if p.Protocol() == "wireguard" {
			_, _ = runWG(cleanup, path, []string{"set", iface, "private-key", "/dev/null"}, "")
		}
	}()
	m.mu.Lock()
	m.setStageLocked(p.ID, "connecting", "resolving_endpoint", "Resolving WireGuard peers")
	m.mu.Unlock()
	endpoints := make([]network.Endpoint, len(w.Peers))
	health := make([]wgHealth, len(w.Peers))
	// Resolve peers concurrently with a shared bound and one deadline. A
	// slow hostname cannot hold healthy peers behind N sequential timeouts.
	initialCtx, initialCancel := context.WithTimeout(ctx, 8*time.Second)
	var initial sync.WaitGroup
	for i, peer := range w.Peers {
		initial.Add(1)
		go func(i int, peer workvpn.WireGuardPeer) {
			defer initial.Done()
			endpoint, e := resolveWGEndpoint(initialCtx, peer.Endpoint)
			if e == nil {
				endpoints[i] = endpoint
			}
			health[i].LastResolve = time.Now()
		}(i, peer)
	}
	initial.Wait()
	initialCancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}

	m.mu.Lock()
	ss.Endpoints = validEndpoints(endpoints)
	m.setStageLocked(p.ID, "connecting", "creating_interface", "Creating WireGuard interface")
	m.lastPolicy = ""
	err = m.applyLocked(ctx)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	index, err := m.prepareWGInterface(ctx, ss, w)
	if err != nil {
		return err
	}
	var cmd *exec.Cmd
	var processDone <-chan error
	uapi := filepath.Join(m.config.AmneziaWGSocketDir, iface+".sock")
	if p.Protocol() == "amneziawg" {
		cmd, processDone, err = startAmnezia(ctx, path, iface, logs, p.DebugLogging)
		if err != nil {
			return err
		}
		defer func() {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(syscall.SIGTERM)
			}
			select {
			case <-processDone:
			case <-time.After(4 * time.Second):
				_ = cmd.Process.Kill()
			}
		}()
		readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		controlReady := false
		for readyCtx.Err() == nil {
			// A dead backend leaves a socket pathname behind. Only a live
			// UAPI socket authenticated to this exact child is readiness.
			if _, e := amneziaRequest(readyCtx, uapi, cmd.Process.Pid, "get=1\n\n"); e == nil {
				controlReady = true
				break
			}
			select {
			case <-readyCtx.Done():
			case <-processDone:
				cancel()
				return errors.New("AmneziaWG exited before its control socket became ready")
			case <-time.After(25 * time.Millisecond):
			}
		}
		cancel()
		if !controlReady {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("AmneziaWG control socket did not become ready")
		}

		_, err = amneziaRequest(ctx, uapi, cmd.Process.Pid, amneziaConfig(w, endpoints))
	} else {
		_, err = runWG(ctx, path, []string{"setconf", iface, "/proc/self/fd/3"}, wireGuardConfig(w, endpoints))
	}
	if err != nil {
		return err
	}
	started := time.Now()
	m.mu.Lock()
	m.setStageLocked(p.ID, "connecting", "exchanging_keys", "Waiting for authenticated WireGuard handshake")
	m.lastPolicy = ""
	err = m.applyLocked(ctx)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastUplink string
	lastPolicyCheck := time.Time{}
	everConnected := false
	type resolution struct {
		index    int
		endpoint network.Endpoint
		err      error
	}
	resolved := make(chan resolution, len(w.Peers))
	resolving := make([]bool, len(w.Peers))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-processDone:
			return errors.New("AmneziaWG stopped; reconnect required")
		case <-ticker.C:
		}
		now := time.Now()
		var observations map[string]wgPeerObservation
		if p.Protocol() == "amneziawg" {
			var data []byte
			data, err = amneziaRequest(ctx, uapi, cmd.Process.Pid, "get=1\n\n")
			if err == nil {
				observations, err = parseAmneziaStatus(data, w.Peers)
			}
		} else {
			observations, err = readWireGuard(ctx, path, iface, w.Peers)
		}
		if err != nil {
			return err
		}
		uplinkChanged := false
		if now.Sub(lastPolicyCheck) >= 5*time.Second {
			var uplink string
			err = network.WithKernel(ctx, func(k network.Kernel) error {
				s, e := k.Collect(ctx)
				if e != nil {
					return e
				}
				l, ok := s.Link(iface)
				if !ok || l.Index != index || !sessionLinkMatches(ss, l) {
					return errors.New("WireGuard interface identity changed")
				}
				u, _ := s.Uplink()
				if underlay, ok := s.Link(u.Device); ok {
					if e = validateWGPathMTU(w, endpoints, underlay.MTU); e != nil {
						return e
					}
				}
				uplink = network.WorkUplinkFingerprint(s)
				return nil
			})
			if err != nil {
				return err
			}
			uplinkChanged = lastUplink != "" && uplink != lastUplink
			lastUplink = uplink
			lastPolicyCheck = now
		}
		changed := false
		for draining := true; draining; {
			select {
			case result := <-resolved:
				resolving[result.index] = false
				if result.err == nil && result.endpoint != endpoints[result.index] {
					endpoints[result.index] = result.endpoint
					m.mu.Lock()
					ss.Endpoints = validEndpoints(endpoints)
					m.lastPolicy = ""
					e := m.applyLocked(ctx)
					m.mu.Unlock()
					if e != nil {
						return e
					}
					if e = updateWGEndpoint(ctx, path, uapi, iface, cmd, w.Peers[result.index], result.endpoint); e != nil {
						return e
					}
					changed = true
				}
			default:
				draining = false
			}
		}
		ready := 0
		var statuses []PeerStatus
		for i, peer := range w.Peers {
			id := peerID(peer.PublicKey)
			h := &health[i]
			oldReady := h.Ready
			observation := observations[id]
			// A changed endpoint from this authenticated kernel/UAPI peer is
			// trusted only after a handshake or received encrypted traffic.
			if observation.Endpoint != "" && (observation.Handshake > h.Observation.Handshake || observation.RX > h.Observation.RX) {
				if ep, e := parseWGEndpoint(observation.Endpoint); e == nil && ep != endpoints[i] {
					endpoints[i] = ep
					changed = true
				}
			}
			updateWGHealth(h, observation, now, started, wgKeyLifetime(w))
			if uplinkChanged {
				h.CheckingAt = now
				h.Ready = false
				h.LastResolve = time.Time{}
				m.mu.Lock()
				ss.PeerReady[id] = false
				m.lastPolicy = ""
				e := m.applyLocked(ctx)
				m.mu.Unlock()
				if e != nil {
					return e
				}
				if e = resetWGPeer(ctx, path, uapi, iface, cmd, peer, endpoints[i]); e != nil {
					return e
				}
			}

			if (!h.Ready || uplinkChanged) && !resolving[i] && now.Sub(h.LastResolve) >= wgPeerRetry {
				h.LastResolve = now
				resolving[i] = true
				go func(index int, remote workvpn.Remote) {
					endpoint, e := resolveWGEndpoint(ctx, remote)
					select {
					case resolved <- resolution{index, endpoint, e}:
					case <-ctx.Done():
					}
				}(i, peer.Endpoint)
			}

			if !h.NoProbe && (!h.Ready || !h.CheckingAt.IsZero()) && endpoints[i].Address != "" && now.Sub(h.LastProbe) >= 5*time.Second {
				if e := probeWireGuard(iface, index, w, peer); e != nil {
					if !errors.Is(e, errNoProbeDestination) {
						return e
					}
					if !h.NoProbe {
						logs.Log("warning", "A peer is fully shadowed by other AllowedIPs; available peers remain connected")
					}
					h.NoProbe = true
				}
				h.LastProbe = now
			}
			state := "connecting"
			if h.Ready {
				ready++
				state = "connected"
			} else if everConnected {
				state = "reconnecting"
			}
			if oldReady != h.Ready {
				changed = true
			}
			statuses = append(statuses, PeerStatus{ID: id, Endpoint: endpointString(endpoints[i]), State: state, LastHandshakeAt: h.Handshake, AllowedIPs: append([]string(nil), peer.AllowedIPs...)})
			h.Observation = observation
		}
		if ready > 0 {
			everConnected = true
		}
		if !everConnected && now.Sub(started) > wgInitialTimeout {
			return errors.New("WireGuard handshake timed out; no authenticated response from peers")
		}
		m.mu.Lock()
		for i, peer := range w.Peers {
			ss.PeerReady[peerID(peer.PublicKey)] = health[i].Ready
		}
		ss.Endpoints = validEndpoints(endpoints)
		ss.Active = ready > 0
		ss.Status.Peers = statuses
		if ready > 0 && ss.Status.ConnectedAt == 0 {
			ss.Status.ConnectedAt = now.Unix()
		}
		state, stage, message := "connecting", "exchanging_keys", "Waiting for authenticated WireGuard handshake"
		if ready == len(w.Peers) {
			state, stage, message = "connected", "connected", "Connected"
		} else if ready > 0 {
			state, stage, message = "partial", "partial", "Some peers are unavailable; their routes remain protected"
		} else if everConnected {
			state, stage, message = "reconnecting", "exchanging_keys", "Reconnecting WireGuard peers; destinations remain protected"
		}
		previousState, previousStage := ss.Status.State, ss.Status.Stage
		if previousState == "conflict" && ready > 0 {
			state, stage, message = ss.Status.State, ss.Status.Stage, ss.Status.Message
		}
		ss.Status.State, ss.Status.Stage, ss.Status.Message = state, stage, message
		if changed || previousState != state {
			m.lastPolicy = ""
		}
		// Publication happens only after policy commits. applyLocked may turn
		// the desired state into route conflict; retain that authoritative result.
		err = m.applyLocked(ctx)
		if err == nil {
			if previousState != ss.Status.State || previousStage != ss.Status.Stage {
				m.setStageLocked(p.ID, ss.Status.State, ss.Status.Stage, ss.Status.Message)
			} else {
				m.publishView()
				if ss.callback != nil {
					ss.callback(copyStatus(ss.Status))
				}
			}
		}

		m.mu.Unlock()
		if err != nil {
			return err
		}
	}
}

func validEndpoints(in []network.Endpoint) []network.Endpoint {
	var out []network.Endpoint
	seen := map[network.Endpoint]bool{}
	for _, v := range in {
		if v.Address != "" && !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}
func parseWGEndpoint(value string) (network.Endpoint, error) {
	host, port, e := net.SplitHostPort(value)
	if e != nil {
		return network.Endpoint{}, errors.New("invalid WireGuard endpoint")
	}
	a, e := netip.ParseAddr(host)
	n, pe := strconv.Atoi(port)
	if e != nil || pe != nil || n < 1 || n > 65535 || a.Zone() != "" || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
		return network.Endpoint{}, errors.New("invalid WireGuard endpoint")
	}
	return network.Endpoint{Address: a.String(), Port: n, Protocol: "udp", Mark: network.OuterMark}, nil
}

var wgResolverSlots = make(chan struct{}, 8)

func resolveWGEndpoint(ctx context.Context, r workvpn.Remote) (network.Endpoint, error) {
	if a, e := netip.ParseAddr(r.Host); e == nil {
		return parseWGEndpoint(net.JoinHostPort(a.String(), strconv.Itoa(r.Port)))
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	select {
	case wgResolverSlots <- struct{}{}:
		defer func() { <-wgResolverSlots }()
	case <-ctx.Done():
		return network.Endpoint{}, ctx.Err()
	}
	a, e := network.ResolveWorkEndpointForProtocol(ctx, r.Host, "udp")
	if e != nil && ctx.Err() == nil {
		a, e = network.ResolveWorkEndpointForProtocol(ctx, r.Host, "udp6")
	}
	if e != nil {
		return network.Endpoint{}, e
	}
	return parseWGEndpoint(net.JoinHostPort(a.String(), strconv.Itoa(r.Port)))
}

func wgKeyLifetime(w *workvpn.WireGuardConfig) time.Duration {
	value := w.Parameters["RejectAfterTime"]
	if value != "" {
		parts := strings.Split(value, "-")
		if n, e := strconv.ParseUint(parts[len(parts)-1], 10, 32); e == nil && n > 0 {
			return time.Duration(n)*time.Second + 10*time.Second
		}
	}
	return 190 * time.Second
}
func updateWGEndpoint(ctx context.Context, path, uapi, iface string, cmd *exec.Cmd, peer workvpn.WireGuardPeer, endpoint network.Endpoint) error {
	if cmd != nil {
		_, e := amneziaRequest(ctx, uapi, cmd.Process.Pid, fmt.Sprintf("set=1\npublic_key=%s\nupdate_only=true\nendpoint=%s\n\n", keyHex(peer.PublicKey), endpointString(endpoint)))
		return e
	}
	_, e := runWG(ctx, path, []string{"set", iface, "peer", peer.PublicKey, "endpoint", endpointString(endpoint)}, "")
	return e
}

func (m *Manager) prepareWGInterface(ctx context.Context, ss *session, w *workvpn.WireGuardConfig) (int, error) {
	var index int
	err := network.WithKernel(ctx, func(k network.Kernel) error {
		s, e := k.Collect(ctx)
		if e != nil {
			return e
		}
		if uplink, uplinkErr := s.Uplink(); uplinkErr == nil {
			if link, present := s.Link(uplink.Device); present {
				if e = validateWGPathMTU(w, ss.Endpoints, link.MTU); e != nil {
					return e
				}
			}
		}
		if link, present := s.Link(ss.Interface); present {
			if !sessionLinkMatches(ss, link) {
				return errors.New("managed tunnel name belongs to another interface")
			}
		} else {
			args := []string{"link", "add", "dev", ss.Interface, "type", "wireguard"}
			if ss.Kind == "amneziawg" {
				args = []string{"tuntap", "add", "dev", ss.Interface, "mode", "tun"}
			}
			if _, e = k.Run(ctx, "/usr/sbin/ip", args, ""); e != nil {
				return errors.New("cannot create WireGuard interface; kernel support is required")
			}
			if _, e = k.Run(ctx, "/usr/sbin/ip", []string{"link", "set", "dev", ss.Interface, "alias", "vault443:" + ss.ID}, ""); e != nil {
				return e
			}
		}
		for _, family := range []int{4, 6} {
			if e = ip(k, ctx, family, "addr", "flush", "dev", ss.Interface, "scope", "global"); e != nil {
				return e
			}
		}
		if _, e = k.Run(ctx, "/usr/sbin/ip", []string{"link", "set", "dev", ss.Interface, "mtu", strconv.Itoa(w.MTU), "up"}, ""); e != nil {
			return errors.New("cannot configure WireGuard MTU")
		}
		for _, address := range w.Addresses {
			a, e := netip.ParsePrefix(address)
			if e != nil {
				return errors.New("invalid WireGuard interface address")
			}
			family := 4
			if a.Addr().Is6() {
				family = 6
			}
			if e = ip(k, ctx, family, "addr", "replace", address, "dev", ss.Interface, "noprefixroute"); e != nil {
				return errors.New("cannot configure WireGuard address")
			}
		}
		s, e = k.Collect(ctx)
		if e != nil {
			return e
		}
		link, ok := s.Link(ss.Interface)
		if !ok || !sessionLinkMatches(ss, link) {
			return errors.New("WireGuard interface identity mismatch")
		}
		index = link.Index
		return nil
	})
	return index, err
}

func startAmnezia(ctx context.Context, path, iface string, logs *journal.Session, debug bool) (*exec.Cmd, <-chan error, error) {
	cmd := exec.CommandContext(ctx, path, "--foreground", iface)
	level := "error"
	if debug {
		level = "debug"
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "LOG_LEVEL=" + level}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM, Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		return nil
	}
	cmd.WaitDelay = 3 * time.Second
	output, e := cmd.StdoutPipe()
	if e != nil {
		return nil, nil, e
	}
	cmd.Stderr = cmd.Stdout
	if e = cmd.Start(); e != nil {
		return nil, nil, errors.New("cannot start AmneziaWG")
	}
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 64<<10)
		for scanner.Scan() {
			logs.Log("info", scanner.Text())
		}
		if scanner.Err() != nil {
			logs.Log("warning", "Oversized AmneziaWG output discarded")
			_, _ = io.Copy(io.Discard, output)
		}
	}()
	go func() { done <- cmd.Wait(); close(done) }()
	return cmd, done, nil
}

// Readiness is based on successful authentication, not just link UP or an old
// handshake timestamp. An idle peer remains ready during a bounded active check.
func updateWGHealth(h *wgHealth, o wgPeerObservation, now, started time.Time, lifetime time.Duration) {
	if o.Handshake >= started.Unix() && o.Handshake > h.Handshake && o.Handshake <= now.Add(5*time.Second).Unix() {
		h.Handshake = o.Handshake
		h.Ready = true
		h.CheckingAt = time.Time{}
		h.ConfirmedAt = now
	}
	if h.Ready && h.CheckingAt.IsZero() && now.Sub(h.ConfirmedAt) > lifetime {
		h.CheckingAt = now
	}
	if !h.CheckingAt.IsZero() && now.Sub(h.CheckingAt) > wgInitialTimeout {
		h.Ready = false
	}
}
func resetWGPeer(ctx context.Context, path, uapi, iface string, cmd *exec.Cmd, peer workvpn.WireGuardPeer, endpoint network.Endpoint) error {
	if cmd != nil {
		var b strings.Builder
		fmt.Fprintf(&b, "set=1\npublic_key=%s\nremove=true\npublic_key=%s\n", keyHex(peer.PublicKey), keyHex(peer.PublicKey))
		if peer.PresharedKey != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", keyHex(peer.PresharedKey))
		}
		if endpoint.Address != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", endpointString(endpoint))
		}
		for _, prefix := range peer.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", prefix)
		}
		if peer.PersistentKeepalive != "" {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", peer.PersistentKeepalive)
		}
		b.WriteByte('\n')
		_, e := amneziaRequest(ctx, uapi, cmd.Process.Pid, b.String())
		return e
	}
	if _, e := runWG(ctx, path, []string{"set", iface, "peer", peer.PublicKey, "remove"}, ""); e != nil {
		return e
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Peer]\nPublicKey = %s\n", peer.PublicKey)
	if peer.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PresharedKey)
	}
	if endpoint.Address != "" {
		fmt.Fprintf(&b, "Endpoint = %s\n", endpointString(endpoint))
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", "))
	if peer.PersistentKeepalive != "" {
		fmt.Fprintf(&b, "PersistentKeepalive = %s\n", peer.PersistentKeepalive)
	}
	_, e := runWG(ctx, path, []string{"addconf", iface, "/proc/self/fd/3"}, b.String())
	return e
}

// Preserve the configured MTU; reject an incompatible physical path instead of
// silently lowering it or sending consistently oversized encrypted datagrams.
// AWG's random padding/trailers are bounded by its observed UDP window; the
// mandatory S4 prefix is additional to each full-sized inner packet.
func validateWGPathMTU(w *workvpn.WireGuardConfig, endpoints []network.Endpoint, linkMTU int) error {
	if linkMTU <= 0 {
		return nil
	}
	outer := 28
	for _, ep := range endpoints {
		a, e := netip.ParseAddr(ep.Address)
		if e == nil && a.Is6() {
			outer = 48
			break
		}
	}
	maximum := w.MTU + 32
	if value := w.Parameters["S4"]; value != "" {
		n, _ := strconv.Atoi(value)
		maximum += n
	}
	for name, base := range map[string]int{"S1": 148, "S2": 92, "S3": 64, "Jmax": 0} {
		n, _ := strconv.Atoi(w.Parameters[name])
		if n+base > maximum {
			maximum = n + base
		}
	}
	if maximum+outer > linkMTU {
		return errors.New("WireGuard MTU or padding exceeds the physical link MTU")
	}
	return nil
}
