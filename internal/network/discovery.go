package network

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var socketPID = regexp.MustCompile(`pid=([0-9]+),`)

// automaticBindings derives trust from kernel WireGuard metadata or a root-owned
// OpenVPN executable with its kernel TUN fd. Interface names alone grant nothing.
// NM and Pritunl OpenVPN children are identified by their actual cgroup; the same
// code supports dedicated systemd units and manually launched root OpenVPN.
func automaticBindings(ctx context.Context, r runner, s Snapshot, existing []Binding) ([]Binding, error) {
	known := map[string]bool{}
	for _, b := range existing {
		known[b.Interface] = true
	}
	var out []Binding
	for _, l := range s.Links {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if l.Name == TunName || l.Kind != "wireguard" || known[l.Name] {
			continue
		}
		markBytes, e := r.Run(ctx, command{Path: "/usr/bin/wg", Args: []string{"show", l.Name, "fwmark"}})
		if e != nil {
			return nil, errors.New("cannot inspect WireGuard routing mark")
		}
		markText := strings.TrimSpace(string(markBytes))
		if markText == "off" {
			markText = "0"
		}
		mark, e := strconv.ParseUint(markText, 0, 32)
		if e != nil {
			return nil, errors.New("cannot parse WireGuard routing mark")
		}
		listenPort := 0
		if mark == 0 {
			portBytes, e := r.Run(ctx, command{Path: "/usr/bin/wg", Args: []string{"show", l.Name, "listen-port"}})
			if e != nil {
				return nil, errors.New("cannot inspect WireGuard listen port")
			}
			listenPort, e = strconv.Atoi(strings.TrimSpace(string(portBytes)))
			if e != nil || listenPort < 1 || listenPort > 65535 {
				return nil, errors.New("WireGuard has no established transport socket")
			}
		}
		endpoints, e := r.Run(ctx, command{Path: "/usr/bin/wg", Args: []string{"show", l.Name, "endpoints"}})
		if e != nil {
			return nil, errors.New("cannot inspect WireGuard transport endpoints")
		}
		b := Binding{Interface: l.Name, Manager: "wg-quick"}
		for _, line := range strings.Split(string(endpoints), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 || fields[1] == "(none)" {
				continue
			}
			a, p, ok := parseSocketAddress(fields[1])
			if ok {
				b.Endpoints = append(b.Endpoints, Endpoint{Address: a.String(), Port: p, Protocol: "udp", Mark: uint32(mark), SourcePort: listenPort})
			}
		}
		if len(b.Endpoints) == 0 {
			return nil, errors.New("WireGuard has no verified transport endpoints")
		}
		out = append(out, b)
		known[l.Name] = true
	}
	processes, e := os.ReadDir("/proc")
	if e != nil {
		return nil, errors.New("cannot inspect VPN process ownership")
	}
	type process struct{ pid, iface, cgroup string }
	var verified []process
	for _, p := range processes {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !p.IsDir() {
			continue
		}
		if _, e := strconv.Atoi(p.Name()); e != nil {
			continue
		}
		base := filepath.Join("/proc", p.Name())
		comm, e := os.ReadFile(filepath.Join(base, "comm"))
		if e != nil || strings.TrimSpace(string(comm)) != "openvpn" {
			continue
		}
		fi, e := os.Stat(base)
		if e != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			continue
		}
		exe, e := os.Readlink(filepath.Join(base, "exe"))
		if e != nil || !filepath.IsAbs(exe) || filepath.Base(exe) != "openvpn" {
			continue
		}
		fi, e = os.Stat(exe)
		if e != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0022 != 0 {
			continue
		}
		st, ok = fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			continue
		}
		cgBytes, _ := os.ReadFile(filepath.Join(base, "cgroup"))
		cg := ""
		for _, line := range strings.Split(string(cgBytes), "\n") {
			if strings.HasPrefix(line, "0::/system.slice/") {
				candidate := strings.TrimPrefix(line, "0::/")
				if safeCgroup.MatchString(candidate) {
					cg = candidate
				}
			}
		}
		var names []string
		managedProcess := false
		fds, _ := os.ReadDir(filepath.Join(base, "fdinfo"))
		for _, fd := range fds {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			content, e := os.ReadFile(filepath.Join(base, "fdinfo", fd.Name()))
			if e != nil {
				continue
			}
			for _, line := range strings.Split(string(content), "\n") {
				if strings.HasPrefix(line, "iff:") {
					name := strings.TrimSpace(strings.TrimPrefix(line, "iff:"))
					for _, b := range existing {
						if b.Managed && b.Interface == name {
							managedProcess = true
						}
					}
					if _, exists := s.Link(name); exists && !known[name] {
						names = append(names, name)
					}
				}
			}
		}
		if managedProcess {
			continue
		}
		if len(names) == 0 {
			names = []string{"pending" + p.Name()}
		}
		for _, name := range names {
			verified = append(verified, process{p.Name(), name, cg})
		}
	}
	if len(verified) == 0 {
		return out, nil
	}
	data, e := r.Run(ctx, command{Path: "/usr/bin/ss", Args: []string{"-H", "-n", "-tup"}})
	if e != nil {
		return nil, errors.New("cannot verify OpenVPN transport sockets")
	}
	byPID := map[string][]Endpoint{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 7 || (fields[0] != "tcp" && fields[0] != "udp") {
			continue
		}
		a, p, ok := parseSocketAddress(fields[5])
		if !ok || a.IsUnspecified() || a.IsLoopback() {
			continue
		}
		for _, match := range socketPID.FindAllStringSubmatch(line, -1) {
			byPID[match[1]] = append(byPID[match[1]], Endpoint{Address: a.String(), Port: p, Protocol: fields[0]})
		}
	}
	for _, p := range verified {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Numeric root-owned metadata also covers unconnected UDP sockets and
		// OpenVPN startup before it owns a TUN descriptor.
		for _, ep := range processOpenVPNEndpoints(p.pid) {
			duplicate := false
			for _, old := range byPID[p.pid] {
				if old.Address == ep.Address && old.Port == ep.Port && old.Protocol == ep.Protocol {
					duplicate = true
				}
			}
			if !duplicate {
				byPID[p.pid] = append(byPID[p.pid], ep)
			}
		}
		if len(byPID[p.pid]) == 0 {
			continue
		}
		b := Binding{Interface: p.iface, Manager: "openvpn", Cgroup: p.cgroup, Endpoints: byPID[p.pid], RootOnly: p.cgroup == ""}
		if strings.Contains(p.cgroup, "pritunl-client.service") {
			b.Manager = "pritunl"
		}
		// Keep NetworkManager's own existing per-link DNS metadata. No secret
		// connection profile export or credential files are read here.
		if !known[p.iface] {
			out = append(out, b)
			known[p.iface] = true
		}
	}
	return out, nil
}

func parseSocketAddress(s string) (netip.Addr, int, bool) {
	host, port, e := net.SplitHostPort(s)
	if e != nil {
		i := strings.LastIndex(s, ":")
		if i < 0 {
			return netip.Addr{}, 0, false
		}
		host, port = s[:i], s[i+1:]
	}
	host = strings.Trim(host, "[]")
	if i := strings.Index(host, "%"); i >= 0 {
		host = host[:i]
	}
	a, e := netip.ParseAddr(host)
	p, pe := strconv.Atoi(port)
	return a, p, e == nil && pe == nil && p > 0 && p <= 65535
}

func (m *Manager) external(ctx context.Context, s Snapshot) ([]external, error) {
	bindings := append([]Binding(nil), m.bindings...)
	bindings = append(bindings, managedBindings()...)
	_, liveRunner := m.r.(execRunner)
	if !m.config.DryRun && liveRunner {
		auto, e := automaticBindings(ctx, m.r, s, bindings)
		if e != nil {
			return nil, e
		}
		bindings = append(bindings, auto...)
	}
	return detectExternal(ctx, m.r, s, bindings)
}
