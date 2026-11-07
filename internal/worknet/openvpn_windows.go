package worknet

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"vault443/internal/core"
	"vault443/internal/journal"
	"vault443/internal/network"
	"vault443/internal/securefs"
	"vault443/internal/winplatform"
	"vault443/internal/workvpn"
)

const openVPNWindowsVersion = "2.6.23"

// The management listener is owned by this supervisor before the child starts.
// The accepted connection is bound to the actual child PID through IP Helper,
// and OpenVPN additionally authenticates our per-attempt random password. Raw
// management/environment frames can contain credentials and are never logged.
func openVPNManagementPID(conn *net.TCPConn, expected uint32) error {
	client, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || !client.IP.IsLoopback() {
		return errors.New("invalid OpenVPN management client")
	}
	server, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || !server.IP.IsLoopback() {
		return errors.New("invalid OpenVPN management listener")
	}
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		size := uint32(0)
		code, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 5, 0)
		if code != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 16<<20 {
			return errors.New("cannot authenticate OpenVPN management socket")
		}
		data := make([]byte, size)
		code, _, _ = proc.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 5, 0)
		if code == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if code != 0 || size > uint32(len(data)) {
			return errors.New("cannot inspect OpenVPN management owner")
		}
		count := binary.LittleEndian.Uint32(data[:4])
		if uint64(count)*24+4 > uint64(size) {
			return errors.New("invalid native TCP owner table")
		}
		for i := uint32(0); i < count; i++ {
			row := data[4+i*24 : 4+(i+1)*24]
			port := func(p []byte) int { return int(binary.BigEndian.Uint16(p[:2])) }
			if binary.LittleEndian.Uint32(row[0:4]) == 5 && binary.LittleEndian.Uint32(row[4:8]) == binary.LittleEndian.Uint32(client.IP.To4()) && port(row[8:12]) == client.Port && binary.LittleEndian.Uint32(row[12:16]) == binary.LittleEndian.Uint32(server.IP.To4()) && port(row[16:20]) == server.Port {
				if binary.LittleEndian.Uint32(row[20:24]) != expected {
					return errors.New("OpenVPN management connection belongs to another process")
				}
				return nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("OpenVPN management process identity was not available")
}

type openVPNAdapter struct {
	library   windows.Handle
	handle    uintptr
	closeProc uintptr
	luid      winipcfg.LUID
}

func createOpenVPNAdapter(path, name string) (*openVPNAdapter, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("Wintun library path must be absolute")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil {
			return nil, e
		}
		if e = securefs.Check(info, p, 0, false); e != nil {
			return nil, fmt.Errorf("unsafe Wintun installation: %w", e)
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	library, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, errors.New("the signed Wintun library is unavailable")
	}
	closeLibrary := true
	defer func() {
		if closeLibrary {
			windows.FreeLibrary(library)
		}
	}()
	create, err := windows.GetProcAddress(library, "WintunCreateAdapter")
	if err != nil {
		return nil, err
	}
	closeProc, err := windows.GetProcAddress(library, "WintunCloseAdapter")
	if err != nil {
		return nil, err
	}
	getLUID, err := windows.GetProcAddress(library, "WintunGetAdapterLUID")
	if err != nil {
		return nil, err
	}
	// Refuse an existing foreign adapter rather than adopting it by display name.
	if existing, e := winplatform.InterfaceByName(name); e == nil && existing != 0 {
		return nil, errors.New("work adapter name is already in use")
	}
	name16, _ := windows.UTF16PtrFromString(name)
	kind16, _ := windows.UTF16PtrFromString("Wintun")
	handle, _, callErr := syscall.SyscallN(create, uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(kind16)), 0)
	if handle == 0 {
		return nil, fmt.Errorf("cannot create the OpenVPN Wintun adapter: %w", callErr)
	}
	a := &openVPNAdapter{library: library, handle: handle, closeProc: closeProc}
	closeLibrary = false
	var luid uint64
	syscall.SyscallN(getLUID, handle, uintptr(unsafe.Pointer(&luid)))
	if luid == 0 {
		a.Close()
		return nil, errors.New("Wintun did not return an interface identity")
	}
	a.luid = winipcfg.LUID(luid)
	closeLibrary = false
	return a, nil
}
func (a *openVPNAdapter) Close() {
	if a == nil || a.handle == 0 {
		return
	}
	syscall.SyscallN(a.closeProc, a.handle)
	a.handle = 0
	windows.FreeLibrary(a.library)
}

// Select Windows' preferred source for this destination while constraining
// lookup to the already verified physical uplink, then verify the returned
// address is assigned and preferred on that same interface. --local is source
// binding, not an IP_UNICAST_IF substitute; the physical-LUID WFP rule remains.
func openVPNSourceAddress(uplink winplatform.Uplink, endpoint netip.Addr) (netip.Addr, error) {
	var destination, source winipcfg.RawSockaddrInet
	if err := destination.SetAddr(endpoint); err != nil {
		return netip.Addr{}, err
	}
	var best winipcfg.MibIPforwardRow2
	luid := uplink.LUID
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetBestRoute2")
	code, _, _ := proc.Call(uintptr(unsafe.Pointer(&luid)), 0, 0, uintptr(unsafe.Pointer(&destination)), 0, uintptr(unsafe.Pointer(&best)), uintptr(unsafe.Pointer(&source)))
	if code != 0 {
		return netip.Addr{}, fmt.Errorf("cannot select the physical OpenVPN source: %w", windows.Errno(code))
	}
	ip := source.Addr()
	if best.InterfaceLUID != uplink.LUID || !ip.IsValid() || ip.Is4() != endpoint.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.Is4In6() || ip.IsLinkLocalUnicast() {
		return netip.Addr{}, errors.New("OpenVPN source does not belong to its physical uplink")
	}
	rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, row := range rows {
		if row.InterfaceLUID == uplink.LUID && row.Address.Addr() == ip && row.DadState == winipcfg.DadStatePreferred && !row.SkipAsSource {
			return ip, nil
		}
	}
	return netip.Addr{}, errors.New("the physical OpenVPN source address is no longer usable")
}

func openVPNQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
func renderWindowsOpenVPN(p workvpn.Profile, remote workvpn.Remote, address, local, iface, listen, passwordFile string) string {
	var b strings.Builder
	for _, o := range p.Options {
		switch o.Key {
		case "dev", "dev-type", "verb", "mute", "persist-tun", "persist-key", "remote", "proto", "nobind", "dhcp-option", "connect-retry-max", "resolv-retry":
			continue
		}
		b.WriteString(o.Key)
		for _, arg := range o.Args {
			b.WriteByte(' ')
			b.WriteString(openVPNQuote(arg))
		}
		b.WriteByte('\n')
	}
	host, port, _ := net.SplitHostPort(listen)
	fmt.Fprintf(&b, "dev tun\ndev-type tun\ndev-node %s\nwindows-driver wintun\nremote %s %d %s\n", openVPNQuote(iface), address, remote.Port, remote.Protocol)
	fmt.Fprintf(&b, "local %s\nlport 0\n", local)
	fmt.Fprintf(&b, "management %s %s %s\nmanagement-client\nmanagement-hold\nmanagement-up-down\n", host, port, openVPNQuote(passwordFile))
	// Windows normally mutates DNS while processing DHCP pushes. Retain the
	// authenticated PUSH_REPLY only as data for the shared DNS coordinator.
	fmt.Fprintln(&b, "route-noexec\nifconfig-noexec\nip-win32 manual\nscript-security 0\npull-filter ignore \"dhcp-option\"\npull-filter ignore \"dns \"\nauth-nocache\nremap-usr1 SIGTERM\nconnect-retry-max 1\nresolv-retry 0\ndisable-dco")
	level := 3
	if p.DebugLogging {
		level = 4
	}
	fmt.Fprintf(&b, "verb %d\n", level)
	keys := make([]string, 0, len(p.Inline))
	for key := range p.Inline {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&b, "<%s>\n%s\n</%s>\n", key, strings.TrimSpace(p.Inline[key]), key)
	}
	return b.String()
}

type openVPNNetwork struct {
	addresses              []netip.Prefix
	routes                 []route
	explicitRoutes6        map[string]bool
	dnsServers, dnsDomains []string
	mtu                    int
	full4, full6           bool
}

func openVPNUnicast(value string, ipv6 bool) (netip.Addr, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Is6() != ipv6 || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.Is4In6() || ip.Zone() != "" {
		return netip.Addr{}, errors.New("invalid OpenVPN network address")
	}
	return ip, nil
}
func openVPNPrefix4(address, mask string) (netip.Prefix, error) {
	ip, err := openVPNUnicast(address, false)
	if err != nil {
		return netip.Prefix{}, err
	}
	if mask == "" {
		return netip.PrefixFrom(ip, 32), nil
	}
	m := net.ParseIP(mask)
	if m == nil || m.To4() == nil {
		return netip.Prefix{}, errors.New("invalid OpenVPN IPv4 netmask")
	}
	ones, bits := net.IPMask(m.To4()).Size()
	if bits != 32 {
		return netip.Prefix{}, errors.New("noncontiguous OpenVPN IPv4 netmask")
	}
	return netip.PrefixFrom(ip, ones), nil
}
func openVPNRoute4(address, mask string) (route, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() || ip.IsMulticast() || ip.IsLoopback() {
		return route{}, errors.New("invalid OpenVPN route")
	}
	if mask == "" {
		mask = "255.255.255.255"
	}
	m := net.ParseIP(mask)
	if m == nil || m.To4() == nil {
		return route{}, errors.New("invalid OpenVPN route mask")
	}
	ones, bits := net.IPMask(m.To4()).Size()
	if bits != 32 {
		return route{}, errors.New("noncontiguous OpenVPN route mask")
	}
	return route{CIDR: netip.PrefixFrom(ip, ones).Masked().String()}, nil
}
func openVPNRoute6(value string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(value)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Addr().Zone() != "" || p.Addr().IsLoopback() || p.Addr().IsMulticast() {
		return netip.Prefix{}, errors.New("invalid OpenVPN IPv6 route")
	}
	return p.Masked(), nil
}
func (n *openVPNNetwork) noteExplicitRoute6(args []string) error {
	if len(args) < 1 || len(args) > 3 {
		return errors.New("invalid OpenVPN IPv6 route directive")
	}
	p, err := openVPNRoute6(args[0])
	if err != nil {
		return err
	}
	if n.explicitRoutes6 == nil {
		n.explicitRoutes6 = map[string]bool{}
	}
	n.explicitRoutes6[p.String()] = true
	if len(n.explicitRoutes6) > 256 {
		return errors.New("OpenVPN IPv6 route limit exceeded")
	}
	return nil
}
func windowsOpenVPNPolicy(options []workvpn.Option) (openVPNNetwork, bool, error) {
	policy := openVPNNetwork{}
	ignorePushed := false
	var err error
	for _, o := range options {
		switch o.Key {
		case "redirect-gateway":
			policy.full4, policy.full6, err = openVPNRedirect(o.Args)
		case "dhcp-option":
			err = openVPNDNS(&policy, o.Args)
		case "route-ipv6":
			err = policy.noteExplicitRoute6(o.Args)
		case "route-nopull":
			ignorePushed = true
		}
		if err != nil {
			return policy, ignorePushed, err
		}
	}
	return policy, ignorePushed, nil
}
func parseWindowsOpenVPNNetwork(env map[string]string, iface string, policy openVPNNetwork) (openVPNNetwork, error) {
	n := policy
	n.addresses = nil
	n.routes = nil
	n.mtu = 1500
	if env["dev"] != iface {
		return n, errors.New("OpenVPN reported a foreign adapter")
	}
	if text := env["tun_mtu"]; text != "" {
		v, e := strconv.Atoi(text)
		if e != nil || v < 576 || v > 65535 {
			return n, errors.New("invalid OpenVPN MTU")
		}
		n.mtu = v
	}
	if text := env["ifconfig_local"]; text != "" {
		p, e := openVPNPrefix4(text, env["ifconfig_netmask"])
		if e != nil {
			return n, e
		}
		n.addresses = append(n.addresses, p)
		if p.Bits() < 32 {
			n.routes = append(n.routes, route{CIDR: p.Masked().String()})
		} else if peer := env["ifconfig_remote"]; peer != "" {
			ip, e := openVPNUnicast(peer, false)
			if e != nil {
				return n, e
			}
			n.routes = append(n.routes, route{CIDR: netip.PrefixFrom(ip, 32).String()})
		}
	}
	if text := env["ifconfig_ipv6_local"]; text != "" {
		ip, e := openVPNUnicast(text, true)
		if e != nil {
			return n, e
		}
		bits, e := strconv.Atoi(env["ifconfig_ipv6_netbits"])
		if e != nil || bits < 1 || bits > 128 || n.mtu < 1280 {
			return n, errors.New("invalid OpenVPN IPv6 configuration")
		}
		p := netip.PrefixFrom(ip, bits)
		n.addresses = append(n.addresses, p)
		n.routes = append(n.routes, route{CIDR: p.Masked().String()})
	}
	if len(n.addresses) == 0 {
		return n, errors.New("OpenVPN supplied no tunnel address")
	}
	for i := 1; i <= 256; i++ {
		suffix := strconv.Itoa(i)
		if v := env["route_network_"+suffix]; v != "" {
			r, e := openVPNRoute4(v, env["route_netmask_"+suffix])
			if e != nil {
				return n, e
			}
			n.routes = append(n.routes, r)
		}
		if v := env["route_ipv6_network_"+suffix]; v != "" {
			p, e := openVPNRoute6(v)
			if e != nil {
				return n, e
			}
			// Pinned OpenVPN 2.6.23 init.c:do_init_route_ipv6_list adds these
			// redirect ranges to the same environment as explicit routes. They
			// represent full-tunnel intent, not more-specific corporate policy.
			// Keep an exact explicit client/PUSH declaration even if it matches.
			if n.full6 && !n.explicitRoutes6[p.String()] {
				switch p.String() {
				case "::/3", "2000::/4", "3000::/4", "fc00::/7":
					continue
				}
			}
			n.routes = append(n.routes, route{CIDR: p.String()})
		}
	}
	if env["route_network_257"] != "" || env["route_ipv6_network_257"] != "" {
		return n, errors.New("OpenVPN route limit exceeded")
	}
	for _, v := range n.dnsServers {
		ip, e := netip.ParseAddr(v)
		if e != nil {
			return n, e
		}
		n.routes = append(n.routes, route{CIDR: netip.PrefixFrom(ip, ip.BitLen()).String()})
	}
	if n.full4 {
		n.routes = append(n.routes, route{CIDR: "0.0.0.0/0"})
	}
	if n.full6 {
		has6 := false
		for _, a := range n.addresses {
			has6 = has6 || a.Addr().Is6()
		}
		if !has6 {
			return n, errors.New("OpenVPN requested IPv6 Internet without an IPv6 address")
		}
		n.routes = append(n.routes, route{CIDR: "::/0"})
	}
	n.routes = normalizeRoutes(n.routes)
	return n, nil
}
func openVPNRedirect(flags []string) (v4, v6 bool, err error) {
	v4 = true
	for _, flag := range flags {
		switch flag {
		case "def1", "local", "autolocal", "bypass-dhcp":
		case "ipv6":
			v6 = true
		case "!ipv4":
			v4 = false
		default:
			return false, false, errors.New("unsupported OpenVPN redirect flag")
		}
	}
	return
}
func openVPNDNS(n *openVPNNetwork, args []string) error {
	if len(args) != 2 {
		return errors.New("invalid OpenVPN DNS directive")
	}
	switch args[0] {
	case "DNS", "DNS6":
		ip, e := netip.ParseAddr(args[1])
		if e != nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.Is4In6() || ip.Zone() != "" {
			return errors.New("invalid OpenVPN DNS server")
		}
		n.dnsServers = append(n.dnsServers, ip.String())
	case "DOMAIN", "DOMAIN-SEARCH", "DOMAIN-ROUTE":
		d, e := workvpn.NormalizeDomain(args[1])
		if e != nil {
			return e
		}
		n.dnsDomains = append(n.dnsDomains, d)
	default:
		return errors.New("unsupported pushed OpenVPN DNS directive")
	}
	if len(n.dnsServers) > 16 || len(n.dnsDomains) > 64 {
		return errors.New("OpenVPN DNS limits exceeded")
	}
	return nil
}

// Parse only network policy from the authenticated control log. Credentials,
// auth tokens and unrelated pushed directives never enter diagnostics or logs.
func parseWindowsOpenVPNPush(line string, n *openVPNNetwork) (bool, error) {
	if !strings.HasPrefix(line, ">LOG:") {
		return false, nil
	}
	parts := strings.SplitN(strings.TrimPrefix(line, ">LOG:"), ",", 3)
	if len(parts) != 3 {
		return false, nil
	}
	if _, e := strconv.ParseInt(parts[0], 10, 64); e != nil {
		return false, nil
	}
	const prefix = "PUSH: Received control message: 'PUSH_REPLY"
	if !strings.HasPrefix(parts[2], prefix) {
		return false, nil
	}
	if !strings.HasSuffix(parts[2], "'") {
		return false, errors.New("invalid OpenVPN pushed policy")
	}
	body := strings.TrimSuffix(strings.TrimPrefix(parts[2], prefix), "'")
	if body == "" {
		return true, nil
	}
	if body[0] != ',' {
		return false, errors.New("invalid OpenVPN pushed policy")
	}
	var fields []string
	var field strings.Builder
	escaped := false
	quoted := rune(0)
	for _, c := range body[1:] {
		if c == 0 || c == '\r' || c == '\n' {
			return false, errors.New("invalid OpenVPN pushed control character")
		}
		if escaped {
			field.WriteRune(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' || c == '\'' {
			if quoted == 0 {
				quoted = c
				continue
			}
			if quoted == c {
				quoted = 0
				continue
			}
		}
		if c == ',' && quoted == 0 {
			fields = append(fields, field.String())
			field.Reset()
		} else {
			field.WriteRune(c)
		}
	}
	if escaped || quoted != 0 {
		return false, errors.New("invalid OpenVPN pushed quoting")
	}
	fields = append(fields, field.String())
	if len(fields) > 512 {
		return false, errors.New("OpenVPN pushed option limit exceeded")
	}
	for _, field := range fields {
		args := strings.Fields(field)
		if len(args) == 0 {
			return false, errors.New("empty OpenVPN pushed directive")
		}
		switch args[0] {
		case "redirect-gateway":
			v4, v6, e := openVPNRedirect(args[1:])
			if e != nil {
				return false, e
			}
			n.full4, n.full6 = v4, v6
		case "dhcp-option":
			if e := openVPNDNS(n, args[1:]); e != nil {
				return false, e
			}
		case "route-ipv6":
			if e := n.noteExplicitRoute6(args[1:]); e != nil {
				return false, e
			}
		case "dns":
			return false, errors.New("this OpenVPN DNS directive is unsupported; use dhcp-option DNS")
		}
	}
	return true, nil
}

func (m *Manager) applyOpenVPNNetwork(ctx context.Context, id string, luid winipcfg.LUID, n openVPNNetwork) error {
	// The child deliberately runs with route-noexec/ifconfig-noexec. Only this
	// supervisor assigns addresses and commits shared routes/DNS/protection.
	if err := luid.SetIPAddresses(n.addresses); err != nil {
		return err
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		row, e := luid.IPInterface(family)
		if e != nil {
			continue
		}
		row.UseAutomaticMetric = false
		row.Metric = 1
		row.NLMTU = uint32(n.mtu)
		if e = row.Set(); e != nil {
			return e
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil || !s.Running {
		return errors.New("OpenVPN attempt expired")
	}
	actual, e := winplatform.InterfaceByName(s.Interface)
	if e != nil || actual != luid {
		return errors.New("OpenVPN adapter identity changed")
	}
	if e = winplatform.ConfigureOwnedDNS(luid, true); e != nil {
		return e
	}
	s.LUID = luid
	s.Routes = n.routes
	s.DNSServers = append([]string(nil), n.dnsServers...)
	s.DNSDomains = append([]string(nil), n.dnsDomains...)
	s.Active = true
	s.Status.Routes = nil
	for _, r := range s.Routes {
		s.Status.Routes = append(s.Status.Routes, r.CIDR)
	}
	s.Status.DNSServers = append([]string(nil), s.DNSServers...)
	s.Status.DNSDomains = append([]string(nil), s.DNSDomains...)
	m.lastPolicy = ""
	if e = m.applyLocked(ctx); e != nil {
		s.Active = false
		return e
	}
	return nil
}
func openVPNCheckInstalled(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("OpenVPN installation path must be absolute")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if p == path && !info.Mode().IsRegular() {
			return errors.New("OpenVPN runtime is not a regular file")
		}
		if err = securefs.Check(info, p, 0, false); err != nil {
			return err
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

func verifyOpenVPNManagementPassword(scanner *bufio.Scanner) bool {
	for i := 0; i < 16 && scanner.Scan(); i++ {
		// OpenVPN 2.6.23 manage.c: man_prompt writes ENTER PASSWORD: without
		// CRLF; man_check_password appends the SUCCESS/ERROR response with
		// CRLF. They can therefore be one logical line regardless of TCP
		// fragmentation. Remove only that exact prompt, never arbitrary text.
		line := strings.TrimPrefix(scanner.Text(), "ENTER PASSWORD:")
		if line == "SUCCESS: password is correct" {
			return true
		}
		if strings.HasPrefix(line, "ERROR:") {
			return false
		}
	}
	return false
}

// Do not release the startup hold until both subscriptions have been
// acknowledged. Writing all three commands at once gives us no evidence that
// state/log reporting was enabled before the child starts its TLS handshake.
// Only fixed protocol replies are retained; raw frames can contain secrets.
func initializeOpenVPNManagement(scanner *bufio.Scanner, output io.Writer) error {
	wait := func(expected string, hold bool) bool {
		for i := 0; i < 32 && scanner.Scan(); i++ {
			line := scanner.Text()
			if hold && strings.HasPrefix(line, ">HOLD:Waiting for hold release:") {
				_, err := strconv.ParseUint(strings.TrimPrefix(line, ">HOLD:Waiting for hold release:"), 10, 32)
				return err == nil
			}
			if !hold && line == expected {
				return true
			}
			if strings.HasPrefix(line, ">INFO:") || strings.HasPrefix(line, ">HOLD:Waiting for hold release:") {
				continue
			}
			// With log reporting enabled, OpenVPN logs the hold-release
			// command before acknowledging it. It is still held at this point;
			// discard the bounded log frame without interpreting or logging it.
			if expected == "SUCCESS: hold release succeeded" && strings.HasPrefix(line, ">LOG:") {
				continue
			}
			return false
		}
		return false
	}
	if !wait("", true) {
		return errors.New("OpenVPN startup hold was not confirmed")
	}
	for _, command := range []struct{ request, reply, failure string }{
		{"state on", "SUCCESS: real-time state notification set to ON", "OpenVPN state notifications were not enabled"},
		{"log on", "SUCCESS: real-time log notification set to ON", "OpenVPN log notifications were not enabled"},
		{"hold release", "SUCCESS: hold release succeeded", "OpenVPN startup hold was not released"},
	} {
		if _, err := fmt.Fprintln(output, command.request); err != nil {
			return errors.New(command.failure)
		}
		if !wait(command.reply, false) {
			return errors.New(command.failure)
		}
	}
	return nil
}

func (m *Manager) runOpenVPN(ctx context.Context, uid uint32, p workvpn.Profile, logs *journal.Session, onStatus func(Status)) (result error) {
	ctx, stopAttempt := context.WithCancel(ctx)
	defer stopAttempt()
	_ = uid
	if err := workvpn.ValidateProfile(p); err != nil {
		return err
	}
	if p.Protocol() != "openvpn" || len(p.Remotes) == 0 {
		return errors.New("OpenVPN profile has no server")
	}
	if err := openVPNCheckInstalled(m.config.OpenVPNPath); err != nil {
		return fmt.Errorf("OpenVPN is not installed securely: %w", err)
	}
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	version, err := exec.CommandContext(check, m.config.OpenVPNPath, "--version").Output()
	cancel()
	if err != nil || !strings.HasPrefix(string(version), "OpenVPN "+openVPNWindowsVersion+" ") {
		return fmt.Errorf("pinned OpenVPN %s is required", openVPNWindowsVersion)
	}
	m.mu.Lock()
	s, err := m.beginSession(p, logs, onStatus)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	var child core.Process
	var adapter *openVPNAdapter
	var management *net.TCPConn
	// A failed attempt retains destination/DNS protection, including prior
	// metadata; explicit Forget is the operation which releases that intent.
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		guardErr := m.markDown(cleanup, p.ID)
		done()
		// Closing management can itself make OpenVPN exit. Withdraw readiness
		// first, while the creator handle still keeps the adapter alive.
		if management != nil {
			management.Close()
		}
		// A slow policy update must not consume the process-termination budget.
		shutdown, stopped := context.WithTimeout(context.Background(), 5*time.Second)
		stopErr := child.StopContext(shutdown)
		stopped()
		var finishErr error
		release := func() error {
			if adapter != nil {
				adapter.Close()
			}
			return m.finishSession(context.Background(), p.ID)
		}
		if stopErr == nil {
			finishErr = release()
		} else {
			// Keep the reservation/protection until termination is confirmed,
			// but do not permanently leak the creator handle if Wait finishes
			// just after the bounded stop call returns.
			go func() {
				if child.WaitContext(context.Background()) == nil {
					_ = release()
				}
			}()
		}
		// A process that has not confirmed termination retains its Running
		// reservation and adapter handle. Forget must not release protection.
		if guardErr != nil || stopErr != nil || finishErr != nil {
			result = errors.Join(result, guardErr, stopErr, finishErr)
		}
	}()
	policy, ignorePushed, err := windowsOpenVPNPolicy(p.Options)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if len(s.RemoteOrder) != len(p.Remotes) {
		s.RemoteOrder = make([]int, len(p.Remotes))
		for i := range s.RemoteOrder {
			s.RemoteOrder[i] = i
		}
		random := false
		for _, o := range p.Options {
			random = random || o.Key == "remote-random"
		}
		if random {
			for i := len(s.RemoteOrder) - 1; i > 0; i-- {
				var bytes [8]byte
				if _, err = rand.Read(bytes[:]); err != nil {
					m.mu.Unlock()
					return err
				}
				j := int(binary.LittleEndian.Uint64(bytes[:]) % uint64(i+1))
				s.RemoteOrder[i], s.RemoteOrder[j] = s.RemoteOrder[j], s.RemoteOrder[i]
			}
		}
	}
	remote := p.Remotes[s.RemoteOrder[(s.Attempt-1)%uint64(len(p.Remotes))]]
	iface := s.Interface
	m.setStageLocked(p.ID, "connecting", "resolving_endpoint", "Resolving work VPN server")
	err = m.applyLocked(ctx)
	m.mu.Unlock()

	if err != nil {
		return err
	}
	endpoint, err := network.ResolveWorkEndpointForProtocol(ctx, remote.Host, remote.Protocol)
	if err != nil {
		return err
	}
	if endpoint.IsLoopback() || endpoint.IsMulticast() || endpoint.IsUnspecified() {
		return errors.New("invalid OpenVPN transport address")
	}
	if strings.Contains(remote.Protocol, "6") && endpoint.Is4() || strings.Contains(remote.Protocol, "4") && endpoint.Is6() {
		return errors.New("OpenVPN transport address family does not match profile")
	}
	uplink, err := winplatform.PhysicalUplink(endpoint.Is6())
	if err != nil {
		return err
	}
	local, err := openVPNSourceAddress(uplink, endpoint)
	if err != nil {
		return err
	}
	m.mu.Lock()
	s.Endpoints = []winplatform.Endpoint{{App: m.config.OpenVPNPath, Address: endpoint, Port: uint16(remote.Port), UDP: !strings.HasPrefix(remote.Protocol, "tcp"), Interface: uint64(uplink.LUID)}}
	m.lastPolicy = ""
	m.setStageLocked(p.ID, "connecting", "starting_openvpn", "Starting OpenVPN")
	err = m.applyLocked(ctx)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if err = securefs.MkdirAll(m.config.RuntimeDir, 0700); err != nil {
		return err
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	password := hex.EncodeToString(nonce[:])
	dir := filepath.Join(m.config.RuntimeDir, "openvpn-"+password[:16])
	if err = securefs.MkdirAll(dir, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	passwordFile := filepath.Join(dir, "management-password")
	if err = securefs.Write(passwordFile, []byte(password+"\n")); err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer listener.Close()
	adapter, err = createOpenVPNAdapter(filepath.Join(filepath.Dir(m.config.EventHelperPath), "wintun.dll"), iface)
	if err != nil {
		return err
	}
	configPath := filepath.Join(dir, "client.ovpn")
	if err = securefs.Write(configPath, []byte(renderWindowsOpenVPN(p, remote, endpoint.String(), local.String(), iface, listener.Addr().String(), passwordFile))); err != nil {
		return err
	}
	cmd := exec.Command(m.config.OpenVPNPath, "--config", configPath)
	output, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err = child.StartInstalled(ctx, cmd); err != nil {
		return err
	}
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 64<<10)
		for scanner.Scan() {
			line := scanner.Text()
			lower := strings.ToLower(line)
			secret := false
			for _, text := range []string{"push_reply", "push_continuation", "auth-token", "auth_token", "password", "setenv", "management:"} {
				secret = secret || strings.Contains(lower, text)
			}
			if !secret {
				logs.Log("info", strings.ReplaceAll(line, password, "[redacted]"))
			}
		}
		if scanner.Err() != nil {
			io.Copy(io.Discard, output)
		}
	}()
	if err = listener.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	for accepted := 0; accepted < 32; accepted++ {
		management, err = listener.AcceptTCP()
		if err != nil {
			return errors.New("OpenVPN management connection timed out")
		}
		if err = openVPNManagementPID(management, uint32(cmd.Process.Pid)); err == nil {
			break
		}
		management.Close()
		management = nil
	}
	if management == nil {
		return errors.New("OpenVPN management process authentication failed")
	}
	listener.Close()
	if err = management.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err = fmt.Fprintln(management, password); err != nil {
		return err
	}
	scanner := bufio.NewScanner(management)
	scanner.Buffer(make([]byte, 4096), 128<<10)
	if !verifyOpenVPNManagementPassword(scanner) {
		return errors.New("OpenVPN management password verification failed")
	}
	if err = management.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	if err = initializeOpenVPNManagement(scanner, management); err != nil {
		return err
	}
	if err = management.SetDeadline(time.Time{}); err != nil {
		return err
	}
	lines := make(chan string, 64)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		defer close(lines)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	timeout := time.NewTimer(60 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	connected := false
	networkReady := false
	controlVerified := false
	environment := map[string]string(nil)
	environmentBytes := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			if !connected {
				return errors.New("OpenVPN authenticated connection timed out")
			}
		case <-tick.C:
			if !child.Alive() {
				return errors.New("OpenVPN exited; see the profile log")
			}
			current, e := winplatform.PhysicalUplink(endpoint.Is6())
			if e != nil || current.LUID != uplink.LUID || current.Gateway != uplink.Gateway {
				return errors.New("OpenVPN uplink changed; reconnect required")
			}
			nextSource, e := openVPNSourceAddress(current, endpoint)
			if e != nil || nextSource != local {
				return errors.New("OpenVPN source address changed; reconnect required")
			}
			m.mu.Lock()
			err = m.applyLocked(ctx)
			m.mu.Unlock()
			if err != nil {
				return err
			}
		case line, ok := <-lines:
			if !ok {
				return errors.New("OpenVPN management connection closed")
			}
			if strings.HasPrefix(line, ">PASSWORD:Auth-Token:") {
				continue
			}
			if strings.HasPrefix(line, ">PASSWORD:") || strings.HasPrefix(line, ">NEED-OK:") || strings.HasPrefix(line, ">NEED-STR:") {
				return errors.New("this OpenVPN profile requires unsupported interactive authentication")
			}
			if strings.HasPrefix(line, ">FATAL:") {
				return errors.New("OpenVPN reported a fatal error; see the profile log")
			}
			if strings.HasPrefix(line, ">LOG:") {
				if controlVerified && !ignorePushed && !networkReady {
					if _, err = parseWindowsOpenVPNPush(line, &policy); err != nil {
						return err
					}
				}
				continue
			}
			if line == ">UPDOWN:UP" {
				if !controlVerified {
					return errors.New("OpenVPN network metadata arrived before authentication")
				}
				environment = map[string]string{}
				environmentBytes = 0
				continue
			}
			if line == ">UPDOWN:DOWN" {
				return errors.New("OpenVPN tunnel stopped; reconnect required")
			}
			if strings.HasPrefix(line, ">UPDOWN:ENV,") {
				if environment == nil {
					return errors.New("OpenVPN sent unordered network metadata")
				}
				field := strings.TrimPrefix(line, ">UPDOWN:ENV,")
				if field == "END" {
					n, e := parseWindowsOpenVPNNetwork(environment, iface, policy)
					if e != nil {
						return e
					}
					if err = m.applyOpenVPNNetwork(ctx, p.ID, adapter.luid, n); err != nil {
						return err
					}
					networkReady = true
					environment = nil
					continue
				}
				environmentBytes += len(field)
				key, value, ok := strings.Cut(field, "=")
				if !ok || len(environment) > 1024 || environmentBytes > 256<<10 {
					return errors.New("OpenVPN network metadata exceeds limits")
				}
				environment[key] = value
				continue
			}
			if strings.HasPrefix(line, ">STATE:") {
				fields := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
				if len(fields) < 2 {
					continue
				}
				state := fields[1]
				m.mu.Lock()
				switch state {
				case "WAIT", "TCP_CONNECT", "CONNECTING":
					m.setStageLocked(p.ID, "connecting", "connecting_server", "Connecting to work VPN server")
				case "AUTH":
					controlVerified = true
					m.setStageLocked(p.ID, "connecting", "verifying_certificate", "Verifying work VPN certificate")
				case "GET_CONFIG":
					controlVerified = true
					m.setStageLocked(p.ID, "connecting", "receiving_config", "Receiving work VPN configuration")
				case "ASSIGN_IP", "ADD_ROUTES":
					m.setStageLocked(p.ID, "connecting", "applying_routes", "Applying work routes and DNS")
				case "CONNECTED":
					if len(fields) < 3 || fields[2] != "SUCCESS" || !networkReady || !s.Active {
						err = errors.New("OpenVPN did not complete protected network setup")
					} else {
						connected = true
						s.Status.ConnectedAt = time.Now().Unix()
						m.setStageLocked(p.ID, "connected", "connected", "Connected")
					}
				case "RECONNECTING", "EXITING":
					err = errors.New("OpenVPN transport interrupted; reconnect required")
				}
				m.mu.Unlock()
				if err != nil {
					return err
				}
			}
		}
	}
}
