package worknet

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"vault443/internal/journal"
	"vault443/internal/network"
	"vault443/internal/workvpn"
)

func render(p workvpn.Profile, remote workvpn.Remote, address, iface, management, eventSocket, token, helper string) string {
	var b strings.Builder
	for _, o := range p.Options {
		switch o.Key {
		case "dev", "dev-type", "verb", "mute", "persist-tun", "persist-key", "remote", "proto":
			continue
		}
		b.WriteString(o.Key)
		for _, a := range o.Args {
			b.WriteByte(' ')
			b.WriteString(strconv.Quote(a))
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "dev %s\ndev-type tun\nremote %s %d %s\nmark %d\n", iface, address, remote.Port, remote.Protocol, network.OuterMark)
	fmt.Fprintf(&b, "management %s unix\nmanagement-client\nmanagement-hold\nmanagement-up-down\nroute-noexec\nifconfig-noexec\nscript-security 2\n", strconv.Quote(management))
	fmt.Fprintf(&b, "setenv VAULT443_EVENT_SOCKET %s\nsetenv VAULT443_EVENT_TOKEN %s\n", strconv.Quote(eventSocket), strconv.Quote(token))
	hook := strconv.Quote(helper + " --openvpn-event")
	fmt.Fprintf(&b, "up %s\nroute-up %s\ndown %s\ndown-pre\n", hook, hook, hook)
	fmt.Fprintln(&b, "auth-nocache\nremap-usr1 SIGTERM\nconnect-retry-max 1\nresolv-retry 0\ndisable-dco")
	level := 3
	if p.DebugLogging {
		level = 4
	}
	fmt.Fprintf(&b, "verb %d\n", level)
	keys := make([]string, 0, len(p.Inline))
	for k := range p.Inline {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "<%s>\n%s\n</%s>\n", k, strings.TrimSpace(p.Inline[k]), k)
	}
	return b.String()
}
func validRoute(r route) bool {
	p, e := netip.ParsePrefix(r.CIDR)
	if e != nil || p.Addr().IsLoopback() || p.Addr().IsMulticast() {
		return false
	}
	if r.Gateway != "" {
		g, e := netip.ParseAddr(r.Gateway)
		if e != nil || g.IsLoopback() || g.IsMulticast() || g.Is4() != p.Addr().Is4() {
			return false
		}
	}
	return true
}
func (m *Manager) handleEvent(ctx context.Context, id string, e event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ss := m.sessions[id]
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if ss == nil || ss.Interface != e.Interface {
		return errors.New("expired OpenVPN session")
	}
	if e.Kind == "down" || e.Kind == "route-pre-down" {
		ss.Active = false
		m.lastPolicy = ""
		return m.applyLocked(ctx)
	}
	if e.Kind == "up" {
		m.setStageLocked(id, "connecting", "applying_routes", "Configuring work tunnel addresses")
		return network.WithKernel(ctx, func(k network.Kernel) error {
			// Persistent interfaces retain DNS ownership across an outage, but
			// an old lease must never remain the kernel's preferred source
			// when the next OpenVPN session receives a different address.
			if er := ip(k, ctx, 4, "addr", "flush", "dev", e.Interface); er != nil {
				return errors.New("cannot clear prior work tunnel IPv4 lease")
			}
			if er := ip(k, ctx, 6, "addr", "flush", "dev", e.Interface, "scope", "global"); er != nil {
				return errors.New("cannot clear prior work tunnel IPv6 lease")
			}
			if _, er := k.Run(ctx, "/usr/sbin/ip", []string{"link", "set", "dev", e.Interface, "mtu", strconv.Itoa(e.MTU), "up"}, ""); er != nil {
				return errors.New("cannot activate work tunnel")
			}
			if e.Local != "" {
				args := []string{"addr", "replace"}
				if e.Netmask != "" {
					p, er := ipv4Prefix(e.Local, e.Netmask)
					if er != nil {
						return er
					}
					args = append(args, e.Local+"/"+strconv.Itoa(p.Bits()))
				} else {
					args = append(args, e.Local+"/32")
					if e.Remote != "" {
						args = append(args, "peer", e.Remote+"/32")
					}
				}
				args = append(args, "dev", e.Interface)
				if er := ip(k, ctx, 4, args...); er != nil {
					return errors.New("cannot assign work tunnel IPv4")
				}
			}
			if e.Local6 != "" {
				if er := ip(k, ctx, 6, "addr", "replace", e.Local6+"/"+strconv.Itoa(e.Bits6), "dev", e.Interface); er != nil {
					return errors.New("cannot assign work tunnel IPv6")
				}
			}
			return nil
		})
	}
	if e.Kind != "route-up" {
		return errors.New("invalid OpenVPN network event")
	}
	for _, r := range e.Routes {
		if !validRoute(r) {
			return errors.New("invalid pushed work route")
		}
	}
	// Servers sometimes push only a tunnel subnet; it is still a protected
	// destination and must not fall through to an overlapping local network.
	if e.Local != "" {
		if e.Netmask != "" {
			p, er := ipv4Prefix(e.Local, e.Netmask)
			if er == nil {
				e.Routes = append(e.Routes, route{p.String(), ""})
			}
		} else if e.Remote != "" {
			e.Routes = append(e.Routes, route{e.Remote + "/32", ""})
		}
	}
	if e.Local6 != "" {
		a, er := netip.ParseAddr(e.Local6)
		if er == nil {
			e.Routes = append(e.Routes, route{netip.PrefixFrom(a, e.Bits6).Masked().String(), ""})
		}
	}
	// DNS addresses need the work tunnel even if the server omitted a host route.
	for _, dns := range e.DNSServers {
		a, _ := netip.ParseAddr(dns)
		e.Routes = append(e.Routes, route{netip.PrefixFrom(a, a.BitLen()).String(), ""})
	}
	if ss.Full4 {
		e.Routes = append(e.Routes, route{"0.0.0.0/0", e.Gateway4})
	}
	if ss.Full6 {
		if e.Local6 == "" {
			return errors.New("work VPN requests IPv6 Internet but supplies no IPv6 tunnel address")
		}
		e.Routes = append(e.Routes, route{"::/0", e.Gateway6})
	}
	for _, r := range e.Routes {
		if !validRoute(r) {
			return errors.New("invalid full-tunnel route")
		}
	}
	ss.Routes = normalizeRoutes(e.Routes)
	ss.DNSServers = append([]string(nil), e.DNSServers...)
	ss.DNSDomains = append([]string(nil), e.DNSDomains...)
	ss.Active = true
	ss.Status.Routes = nil
	for _, r := range ss.Routes {
		ss.Status.Routes = append(ss.Status.Routes, r.CIDR)
	}
	ss.Status.DNSServers = append([]string(nil), ss.DNSServers...)
	ss.Status.DNSDomains = append([]string(nil), ss.DNSDomains...)
	m.lastPolicy = ""
	if er := m.applyLocked(ctx); er != nil {
		ss.Active = false
		return er
	}
	return nil
}
func (m *Manager) Run(ctx context.Context, uid uint32, p workvpn.Profile, logs *journal.Session, onStatus func(Status)) error {
	if len(p.Remotes) == 0 {
		return errors.New("work profile has no server")
	}
	if len(m.config.RuntimeDir) > 60 {
		return errors.New("work runtime path is too long")
	}
	info, er := os.Stat(m.config.OpenVPNPath)
	if er != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("OpenVPN 2.6 or newer is not installed securely")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		return errors.New("OpenVPN executable is not root-owned")
	}
	version, er := exec.CommandContext(ctx, m.config.OpenVPNPath, "--version").Output()
	if er != nil || !supportedVersion(string(version)) {
		return errors.New("OpenVPN 2.6 or newer is required")
	}
	h := sha256.Sum256([]byte(p.ID))
	iface := "v443w" + hex.EncodeToString(h[:4])
	m.mu.Lock()
	ss := m.sessions[p.ID]
	if ss == nil {
		if len(m.sessions) >= 32 {
			m.mu.Unlock()
			return errors.New("at most 32 work VPNs may be requested")
		}
		for _, s := range m.sessions {
			if s.Interface == iface {
				m.mu.Unlock()
				return errors.New("work tunnel identity collision")
			}
		}
		m.nextOrder++
		ss = &session{ID: p.ID, Interface: iface, Order: m.nextOrder}
		m.sessions[p.ID] = ss
	}
	ss.Full4 = false
	ss.Full6 = false
	ignorePushedRoutes := false
	for _, o := range p.Options {
		if o.Key == "redirect-gateway" {
			ss.Full4, ss.Full6, er = redirectFlags(o.Args)
			if er != nil {
				m.mu.Unlock()
				return er
			}
		}
		if o.Key == "route-nopull" {
			ignorePushedRoutes = true
		}
	}
	ss.Name = p.Name
	ss.callback = onStatus
	ss.log = logs
	ss.Active = false
	ss.Status.Interface = iface
	ss.Attempt++
	if len(ss.RemoteOrder) != len(p.Remotes) {
		ss.RemoteOrder = make([]int, len(p.Remotes))
		for i := range ss.RemoteOrder {
			ss.RemoteOrder[i] = i
		}
		random := false
		for _, o := range p.Options {
			if o.Key == "remote-random" {
				random = true
			}
		}
		if random {
			for i := len(ss.RemoteOrder) - 1; i > 0; i-- {
				n, e := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
				if e != nil {
					m.mu.Unlock()
					return errors.New("cannot select work VPN server securely")
				}
				j := int(n.Int64())
				ss.RemoteOrder[i], ss.RemoteOrder[j] = ss.RemoteOrder[j], ss.RemoteOrder[i]
			}
		}
	}
	remote := p.Remotes[ss.RemoteOrder[(ss.Attempt-1)%uint64(len(p.Remotes))]]
	m.setStageLocked(p.ID, "connecting", "resolving_endpoint", "Resolving work VPN server")
	er = m.applyLocked(ctx)
	m.mu.Unlock()
	if er != nil {
		return er
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = m.markDown(cleanup, p.ID)
	}()
	a, er := network.ResolveWorkEndpointForProtocol(ctx, remote.Host, remote.Protocol)
	if er != nil {
		return er
	}
	if a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() {
		return errors.New("work VPN endpoint is not a usable network address")
	}
	if (strings.Contains(remote.Protocol, "6")) && a.Is4() || (strings.Contains(remote.Protocol, "4")) && a.Is6() {
		return errors.New("work VPN server address family does not match transport")
	}
	proto := "udp"
	if strings.HasPrefix(remote.Protocol, "tcp") {
		proto = "tcp"
	}
	m.mu.Lock()
	ss.Endpoint = network.Endpoint{Address: a.String(), Port: remote.Port, Protocol: proto, Mark: network.OuterMark}
	m.setStageLocked(p.ID, "connecting", "starting_openvpn", "Starting OpenVPN")
	m.lastPolicy = ""
	er = m.applyLocked(ctx)
	m.mu.Unlock()
	if er != nil {
		return er
	}
	// A daemon-owned persistent TUN retains split-DNS routing domains during
	// transport failures. Corporate DNS cannot silently fall back to public DNS
	// merely because an OpenVPN process exited. Manual Forget deletes this TUN.
	er = network.WithKernel(ctx, func(k network.Kernel) error {
		snap, e := k.Collect(ctx)
		if e != nil {
			return e
		}
		if l, ok := snap.Link(iface); ok {
			if l.Kind != "tun" {
				return errors.New("managed tunnel name belongs to another interface")
			}
			return nil
		}
		_, e = k.Run(ctx, "/usr/sbin/ip", []string{"tuntap", "add", "dev", iface, "mode", "tun"}, "")
		return e
	})
	if er != nil {
		return errors.New("cannot prepare persistent work tunnel")
	}
	if er = os.MkdirAll(m.config.RuntimeDir, 0700); er != nil {
		return er
	}
	dir, er := os.MkdirTemp(m.config.RuntimeDir, "work-")
	if er != nil {
		return er
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0700)
	tokenBytes := make([]byte, 32)
	if _, er = rand.Read(tokenBytes); er != nil {
		return er
	}
	token := hex.EncodeToString(tokenBytes)
	mgmtPath := filepath.Join(dir, "management")
	eventPath := filepath.Join(dir, "event")
	if len(mgmtPath) > 103 {
		return errors.New("work management socket path is too long")
	}
	management, er := net.ListenUnix("unix", &net.UnixAddr{Name: mgmtPath, Net: "unix"})
	if er != nil {
		return errors.New("cannot create private OpenVPN management socket")
	}
	defer management.Close()
	events, er := net.ListenUnix("unix", &net.UnixAddr{Name: eventPath, Net: "unix"})
	if er != nil {
		return er
	}
	defer events.Close()
	_ = os.Chmod(mgmtPath, 0600)
	_ = os.Chmod(eventPath, 0600)
	path := filepath.Join(dir, "client.conf")
	if er = os.WriteFile(path, []byte(render(p, remote, a.String(), iface, mgmtPath, eventPath, token, m.config.EventHelperPath)), 0600); er != nil {
		return er
	}
	processCtx, stop := context.WithCancel(ctx)
	defer stop()
	cmd := exec.CommandContext(processCtx, m.config.OpenVPNPath, "--config", path)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM, Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		return nil
	}
	cmd.WaitDelay = 3 * time.Second
	// Journal producers are nonblocking. Output is bounded and never used as
	// authoritative configuration; helper messages carry parsed route metadata.
	output, er := cmd.StdoutPipe()
	if er != nil {
		return er
	}
	cmd.Stderr = cmd.Stdout
	if er = cmd.Start(); er != nil {
		return errors.New("cannot start OpenVPN")
	}
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 64<<10)
		for scanner.Scan() {
			if !sensitiveOpenVPNLine(scanner.Text()) {
				logs.Log("info", strings.ReplaceAll(scanner.Text(), token, "[redacted]"))
			}
		}
	}()
	go func() { done <- cmd.Wait(); close(done) }()
	defer func() {
		stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
	}()
	errs := make(chan error, 8)
	// OpenVPN queues UPDOWN until its main loop resumes, so the hook must
	// acknowledge before waiting for that metadata. The hook only deposits its
	// authenticated configuration; policy is committed after the queued control
	// metadata is drained and before CONNECTED is exposed to the service.
	pendingRoutes := make(chan event, 1)
	go acceptEvents(processCtx, events, token, iface, cmd.Process.Pid, func(c context.Context, e event) error {
		if e.Kind == "route-up" {
			select {
			case pendingRoutes <- e:
				return nil
			case <-c.Done():
				return c.Err()
			default:
				return errors.New("duplicate OpenVPN route event")
			}
		}
		return m.handleEvent(c, p.ID, e)
	}, errs)

	accepted := make(chan *net.UnixConn, 1)
	acceptError := make(chan error, 1)
	go func() {
		c, e := management.AcceptUnix()
		if e != nil {
			acceptError <- e
			return
		}
		accepted <- c
	}()
	var mc *net.UnixConn
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return errors.New("OpenVPN exited during startup; see the profile log")
	case <-time.After(5 * time.Second):
		return errors.New("OpenVPN management connection timed out")
	case <-acceptError:
		return errors.New("OpenVPN management listener closed")
	case mc = <-accepted:
	}
	defer mc.Close()
	peer, peerUID, er := peerPID(mc)
	if er != nil || peer != cmd.Process.Pid || peerUID != 0 {
		return errors.New("OpenVPN management peer identity mismatch")
	}
	_, er = fmt.Fprintln(mc, "state on\nlog on\nhold release")
	if er != nil {
		return errors.New("cannot start OpenVPN management session")
	}
	lines := make(chan string, 32)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(mc)
		scanner.Buffer(make([]byte, 4096), 64<<10)
		metadataDone := false
		verifiedPhase := false
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, ">STATE:") {
				parts := strings.Split(line, ",")
				if len(parts) > 1 && (parts[1] == "AUTH" || parts[1] == "GET_CONFIG") {
					verifiedPhase = true
				}
			}
			if strings.HasPrefix(line, ">LOG:") {
				if !metadataDone && !ignorePushedRoutes && verifiedPhase {
					found, v4, v6, e := pushedRedirect(line)
					if e != nil {
						select {
						case errs <- e:
						default:
						}
						return
					}
					if found {
						m.mu.Lock()
						ss.Full4 = v4
						ss.Full6 = v6
						m.mu.Unlock()
					}
				}
				continue
			}
			if strings.HasPrefix(line, ">UPDOWN:") {
				if line == ">UPDOWN:ENV,END" && !metadataDone {
					metadataDone = true
					var e event
					select {
					case e = <-pendingRoutes:
					case <-processCtx.Done():
						return
					case <-time.After(3 * time.Second):
						select {
						case errs <- errors.New("OpenVPN helper route metadata did not arrive"):
						default:
						}
						return
					}
					if err := m.handleEvent(processCtx, p.ID, e); err != nil {
						select {
						case errs <- err:
						default:
						}
						return
					}
				}
				continue
			}

			if strings.HasPrefix(line, ">PASSWORD:Auth-Token:") {
				continue
			}
			if !strings.HasPrefix(line, ">STATE:") && !strings.HasPrefix(line, ">PASSWORD:") && !strings.HasPrefix(line, ">FATAL:") {
				continue
			}
			select {
			case lines <- line:
			case <-processCtx.Done():
				return
			}
		}
	}()

	timeout := time.NewTimer(60 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	connected := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case er := <-done:
			if er == nil {
				return errors.New("OpenVPN stopped; reconnect required")
			}
			return errors.New("OpenVPN exited; see the profile log")
		case er := <-errs:
			return er
		case <-timeout.C:
			if !connected {
				return errors.New("OpenVPN connection timed out")
			}
		case line, ok := <-lines:
			if !ok {
				return errors.New("OpenVPN management connection closed")
			}
			if strings.HasPrefix(line, ">PASSWORD:") {
				return errors.New("this work profile requires unsupported interactive authentication")
			}
			if strings.HasPrefix(line, ">FATAL:") {
				return errors.New("OpenVPN reported a fatal error; see the profile log")
			}
			if strings.HasPrefix(line, ">STATE:") {
				fields := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
				if len(fields) < 2 {
					continue
				}
				m.mu.Lock()
				switch fields[1] {
				case "WAIT", "TCP_CONNECT", "CONNECTING":
					m.setStageLocked(p.ID, "connecting", "connecting_server", "Connecting to work VPN server")
				case "AUTH":
					m.setStageLocked(p.ID, "connecting", "verifying_certificate", "Verifying work VPN certificate")
				case "GET_CONFIG":
					m.setStageLocked(p.ID, "connecting", "receiving_config", "Receiving work VPN configuration")
				case "ASSIGN_IP", "ADD_ROUTES":
					m.setStageLocked(p.ID, "connecting", "applying_routes", "Applying work routes and DNS")
				case "CONNECTED":
					if ss.Active {
						connected = true
						ss.Status.ConnectedAt = time.Now().Unix()
						// Do not publish CONNECTED while the policy transaction is
						// replacing routes. A new socket opened in that gap may
						// retain a physical source address for all its retries.
						ss.Status.State = "connected"
						ss.Status.Stage = "connected"
						ss.Status.Message = "Connected"
						m.lastPolicy = ""
						er = m.applyLocked(ctx)
						if er == nil {
							m.setStageLocked(p.ID, ss.Status.State, ss.Status.Stage, ss.Status.Message)
						}
					}
				case "RECONNECTING":
					er = errors.New("OpenVPN transport interrupted; reconnect required")
				}
				m.mu.Unlock()
				if er != nil {
					return er
				}
			}
		case <-tick.C:
			m.mu.Lock()
			er = m.applyLocked(ctx)
			m.mu.Unlock()
			if er != nil {
				return er
			}
		}
	}
}
func supportedVersion(s string) bool {
	line := strings.SplitN(s, "\n", 2)[0]
	var major, minor int
	_, e := fmt.Sscanf(line, "OpenVPN %d.%d", &major, &minor)
	return e == nil && (major > 2 || major == 2 && minor >= 6)
}
