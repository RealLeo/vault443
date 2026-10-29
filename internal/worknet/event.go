package worknet

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type event struct {
	Token                                   string `json:"token"`
	Kind                                    string `json:"kind"`
	Interface                               string `json:"interface"`
	Local, Remote, Netmask, Local6, Remote6 string
	Gateway4, Gateway6                      string
	Bits6                                   int
	MTU                                     int
	Routes                                  []route
	DNSServers, DNSDomains                  []string
}

var domainRE = regexp.MustCompile(`^[A-Za-z0-9_-]+([.][A-Za-z0-9_-]+)*[.]?$`)
var ifaceRE = regexp.MustCompile(`^v443w[0-9a-f]{8}$`)

func ipv4Prefix(address, mask string) (netip.Prefix, error) {
	a, e := netip.ParseAddr(address)
	if e != nil || !a.Is4() {
		return netip.Prefix{}, errors.New("invalid OpenVPN IPv4 route")
	}
	if mask == "" {
		mask = "255.255.255.255"
	}
	ip := net.ParseIP(mask)
	if ip == nil || ip.To4() == nil {
		return netip.Prefix{}, errors.New("invalid OpenVPN route mask")
	}
	ones, bits := net.IPMask(ip.To4()).Size()
	if bits != 32 {
		return netip.Prefix{}, errors.New("noncontiguous OpenVPN route mask")
	}
	return netip.PrefixFrom(a, ones).Masked(), nil
}
func parseEvent(env map[string]string) (event, error) {
	e := event{Token: env["VAULT443_EVENT_TOKEN"], Kind: env["script_type"], Interface: env["dev"], Local: env["ifconfig_local"], Remote: env["ifconfig_remote"], Netmask: env["ifconfig_netmask"], Local6: env["ifconfig_ipv6_local"], Remote6: env["ifconfig_ipv6_remote"]}
	e.Gateway4 = env["route_vpn_gateway"]
	e.Gateway6 = env["route_ipv6_gateway"]
	if !ifaceRE.MatchString(e.Interface) {
		return e, errors.New("invalid managed tunnel identity")
	}
	switch e.Kind {
	case "up", "route-up", "down", "route-pre-down":
	default:
		return e, errors.New("unsupported OpenVPN lifecycle event")
	}
	if s := env["ifconfig_ipv6_netbits"]; s != "" {
		var er error
		e.Bits6, er = strconv.Atoi(s)
		if er != nil || e.Bits6 < 1 || e.Bits6 > 128 {
			return e, errors.New("invalid tunnel IPv6 prefix")
		}
	}
	if e.Local6 != "" && e.Bits6 == 0 {
		return e, errors.New("missing tunnel IPv6 prefix length")
	}
	e.MTU = 1500
	if s := env["tun_mtu"]; s != "" {
		var er error
		e.MTU, er = strconv.Atoi(s)
		if er != nil || e.MTU < 576 || e.MTU > 9000 {
			return e, errors.New("invalid tunnel MTU")
		}
	}
	for _, a := range []string{e.Local, e.Remote, e.Local6, e.Remote6} {
		if a != "" {
			p, er := netip.ParseAddr(a)
			if er != nil || p.IsUnspecified() || p.IsMulticast() || p.IsLoopback() {
				return e, errors.New("invalid tunnel address")
			}
		}
	}
	for i := 1; i <= 256; i++ {
		key := strconv.Itoa(i)
		if a := env["route_network_"+key]; a != "" {
			p, er := ipv4Prefix(a, env["route_netmask_"+key])
			if er != nil {
				return e, er
			}
			g := env["route_gateway_"+key]
			if g == "" {
				g = env["route_vpn_gateway"]
			}
			if g != "" {
				ip, er := netip.ParseAddr(g)
				if er != nil || !ip.Is4() {
					return e, errors.New("invalid IPv4 route gateway")
				}
				if ip.IsUnspecified() {
					g = ""
				}
			}
			e.Routes = append(e.Routes, route{p.String(), g})
		}
		if a := env["route_ipv6_network_"+key]; a != "" {
			p, er := netip.ParsePrefix(a)
			if er != nil || !p.Addr().Is6() {
				return e, errors.New("invalid IPv6 route")
			}
			g := env["route_ipv6_gateway_"+key]
			if g != "" {
				ip, er := netip.ParseAddr(g)
				if er != nil || !ip.Is6() {
					return e, errors.New("invalid IPv6 route gateway")
				}
				if ip.IsUnspecified() {
					g = ""
				}
			}
			e.Routes = append(e.Routes, route{p.Masked().String(), g})
		}
	}
	if env["route_network_257"] != "" || env["route_ipv6_network_257"] != "" {
		return e, errors.New("too many OpenVPN routes")
	}
	// redirect-gateway is represented separately by OpenVPN, not as route_N.
	if f := env["redirect_gateway"]; f != "" && f != "0" {
		e.Routes = append(e.Routes, route{"0.0.0.0/0", env["route_vpn_gateway"]})
	}
	for i := 1; i <= 64; i++ {
		v := strings.Fields(env["foreign_option_"+strconv.Itoa(i)])
		if len(v) == 0 {
			continue
		}
		if len(v) != 3 || v[0] != "dhcp-option" {
			return e, errors.New("unsupported pushed network option")
		}
		switch v[1] {
		case "DNS", "DNS6":
			a, er := netip.ParseAddr(v[2])
			if er != nil || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
				return e, errors.New("invalid pushed DNS server")
			}
			e.DNSServers = append(e.DNSServers, a.String())
		case "DOMAIN", "DOMAIN-SEARCH", "DOMAIN-ROUTE":
			if v[2] != "." && !domainRE.MatchString(v[2]) {
				return e, errors.New("invalid pushed DNS suffix")
			}
			e.DNSDomains = append(e.DNSDomains, strings.ToLower(strings.TrimSuffix(v[2], ".")))
			if v[2] == "." {
				e.DNSDomains[len(e.DNSDomains)-1] = "."
			}
		default:
			return e, errors.New("unsupported pushed DHCP option")
		}
	}
	if env["foreign_option_65"] != "" || len(e.DNSServers) > 16 || len(e.DNSDomains) > 64 {
		return e, errors.New("pushed DNS settings exceed limits")
	}
	return e, nil
}

// RunEventHelper is invoked only by the fixed generated --up/--route-up hooks.
// It is not a public privileged command runner. The daemon authenticates its
// actual Unix peer PID, its parent OpenVPN process, and per-attempt nonce.
func RunEventHelper() error {
	if os.Geteuid() != 0 {
		return errors.New("OpenVPN event helper requires the system service")
	}
	env := map[string]string{}
	for _, line := range os.Environ() {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			env[k] = v
		}
	}
	e, err := parseEvent(env)
	if err != nil {
		return err
	}
	path := env["VAULT443_EVENT_SOCKET"]
	if !filepath.IsAbs(path) || len(path) > 100 || len(e.Token) != 64 {
		return errors.New("invalid OpenVPN event destination")
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("event directory is not private")
	}
	c, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return errors.New("OpenVPN event supervisor unavailable")
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if err = json.NewEncoder(c).Encode(e); err != nil {
		return errors.New("cannot deliver OpenVPN event")
	}
	var reply struct {
		OK bool `json:"ok"`
	}
	if json.NewDecoder(io.LimitReader(c, 1024)).Decode(&reply) != nil || !reply.OK {
		return errors.New("OpenVPN network setup failed")
	}
	return nil
}
func peerPID(c *net.UnixConn) (int, uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *syscall.Ucred
	var er error
	err = raw.Control(func(fd uintptr) { cred, er = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) })
	if err != nil {
		return 0, 0, err
	}
	if er != nil {
		return 0, 0, er
	}
	return int(cred.Pid), cred.Uid, nil
}
func parentPID(pid int) int {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if e != nil {
		return 0
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "PPid:") {
			n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(sc.Text(), "PPid:")))
			return n
		}
	}
	return 0
}
func readEvent(c *net.UnixConn, token, iface string, openvpnPID int) (event, error) {
	var e event
	pid, uid, err := peerPID(c)
	if err != nil || uid != 0 || parentPID(pid) != openvpnPID {
		return e, errors.New("untrusted OpenVPN lifecycle sender")
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	d := json.NewDecoder(io.LimitReader(c, 64<<10))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || subtle.ConstantTimeCompare([]byte(token), []byte(e.Token)) != 1 || e.Interface != iface {
		return e, errors.New("invalid OpenVPN lifecycle message")
	}
	return e, nil
}
func acceptEvents(ctx context.Context, l *net.UnixListener, token, iface string, pid int, fn func(context.Context, event) error, errch chan<- error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return
		}
		func() {
			defer c.Close()
			e, er := readEvent(c, token, iface, pid)
			if er == nil {
				er = fn(ctx, e)
			}
			_ = json.NewEncoder(c).Encode(map[string]bool{"ok": er == nil})
			if er != nil {
				select {
				case errch <- er:
				default:
				}
			}
		}()
	}
}
