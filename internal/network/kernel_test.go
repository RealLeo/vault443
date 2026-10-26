package network

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This test is intentionally NEVER run by ordinary go test. It requires both an
// explicit switch and an empty Docker network namespace (lo only). Run a compiled
// test binary in docker --network none --cap-add NET_ADMIN, never --network host.
func TestKernelIsolatedPolicy(t *testing.T) {
	if os.Getenv("VAULT443_KERNEL_TEST") != "1" {
		t.Skip("requires isolated Docker namespace")
	}
	if _, e := os.Stat("/.dockerenv"); e != nil {
		t.Fatal("kernel test refuses non-Docker environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	r := execRunner{}
	run := func(path string, args ...string) []byte {
		t.Helper()
		b, e := r.Run(ctx, command{Path: path, Args: args})
		if e != nil {
			t.Fatalf("%s %v: %v", path, args, e)
		}
		return b
	}
	var links []Link
	if e := json.Unmarshal(run("/usr/sbin/ip", "-j", "link", "show"), &links); e != nil {
		t.Fatal(e)
	}
	if len(links) != 1 || links[0].Name != "lo" {
		t.Fatal("refusing a namespace with non-loopback interfaces")
	}
	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	events, e := New(Config{}).Watch(watchCtx)
	if e != nil {
		t.Fatal(e)
	}
	run("/usr/sbin/ip", "link", "set", "lo", "up")
	for _, name := range []string{"eth0", "docker0", "corp0", TunName} {
		run("/usr/sbin/ip", "link", "add", name, "type", "dummy")
		run("/usr/sbin/ip", "link", "set", name, "up")
	}
	select {
	case _, ok := <-events:
		if !ok {
			t.Fatal("netlink watcher closed unexpectedly")
		}
	case <-time.After(time.Second):
		t.Fatal("netlink watcher missed interface creation")
	}
	run("/usr/sbin/ip", "address", "add", "192.0.2.2/24", "dev", "eth0")
	run("/usr/sbin/ip", "address", "add", "172.18.0.1/16", "dev", "docker0")
	run("/usr/sbin/ip", "address", "add", "198.18.0.1/30", "dev", TunName)
	run("/usr/sbin/ip", "route", "add", "default", "via", "192.0.2.1", "dev", "eth0")
	s := fixture()
	s.Links = append(s.Links, Link{Name: TunName, Kind: "tun"})
	options := guardOptions{Snapshot: s, TunnelReady: true, Endpoint: netip.MustParseAddr("203.0.113.1"), Port: 443, Uplink: "eth0", Protected: []protectedRoute{{"10.20.0.0/16", "corp0"}}}
	if _, e := r.Run(ctx, command{Path: "/usr/sbin/nft", Args: []string{"-f", "-"}, Input: guardScript(options, false)}); e != nil {
		t.Fatal("initial nft guard rejected:", e)
	}
	defer r.Run(context.Background(), command{Path: "/usr/sbin/nft", Args: []string{"delete", "table", "inet", TableName}})
	u, _ := s.Uplink()
	for _, c := range routePlan(s, nil, options.Protected, u, true) {
		if _, e := r.Run(ctx, c); e != nil {
			t.Fatalf("route plan rejected %v: %v", c.Args, e)
		}
	}
	// Policy deliberately omitted for this packet: a missed/deleted TUN route
	// must not expose direct Internet even for an existing physical default.
	c, e := net.DialTimeout("udp4", "203.0.113.9:9", time.Second)
	if e == nil {
		_, _ = c.Write([]byte("guard-test"))
		_ = c.Close()
	}
	b := run("/usr/sbin/nft", "-j", "list", "chain", "inet", TableName, "output_guard")
	var rules struct {
		NFTables []struct {
			Rule struct {
				Expr []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if e = json.Unmarshal(b, &rules); e != nil {
		t.Fatal(e)
	}
	dropped := false
	for _, rule := range rules.NFTables {
		for _, expr := range rule.Rule.Expr {
			if raw, ok := expr["counter"]; ok {
				var counter struct {
					Packets uint64 `json:"packets"`
				}
				_ = json.Unmarshal(raw, &counter)
				if counter.Packets > 0 {
					dropped = true
				}
			}
		}
	}
	if !dropped {
		t.Fatal("unprotected physical packet did not increment fail-closed counter")
	}
	// Inject a real Ethernet frame through a veth peer. The receive side treats
	// it as a forwarded packet rather than host OUTPUT, without another mount
	// namespace or enabling forwarding on the developer's machine.
	forwarding, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if e != nil || strings.TrimSpace(string(forwarding)) != "1" {
		t.Fatal("isolated container needs --sysctl net.ipv4.ip_forward=1")
	}
	run("/usr/sbin/ip", "link", "add", "inj0", "type", "veth", "peer", "name", "peer0")
	run("/usr/sbin/ip", "address", "add", "172.30.0.1/24", "dev", "inj0")
	run("/usr/sbin/ip", "link", "set", "inj0", "up")
	run("/usr/sbin/ip", "link", "set", "peer0", "up")
	before := kernelCounter(t, run("/usr/sbin/nft", "-j", "list", "chain", "inet", TableName, "forward_guard"), "")
	if e = injectUDPFrame("peer0", "inj0"); e != nil {
		t.Fatal("raw forward injection failed:", e)
	}
	after := kernelCounter(t, run("/usr/sbin/nft", "-j", "list", "chain", "inet", TableName, "forward_guard"), "")
	if after <= before {
		t.Fatal("forwarded physical leak attempt was not dropped")
	}
	// Exercise a real kernel WireGuard socket with fwmark=off. A route in main
	// deliberately points its outer endpoint at the dummy VLESS device; only
	// our verified source-port mark can reroute it to the underlay allowance.
	run("/usr/sbin/ip", "link", "add", "wgtest0", "type", "wireguard")
	private, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	peer, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	keyPath := filepath.Join(t.TempDir(), "wg-key")
	if e = os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(private.Bytes())+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	run("/usr/bin/wg", "set", "wgtest0", "private-key", keyPath, "listen-port", "51871", "peer", base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()), "endpoint", "203.0.113.33:51820", "allowed-ips", "10.77.0.0/24")
	run("/usr/sbin/ip", "address", "add", "10.77.0.2/32", "dev", "wgtest0")
	run("/usr/sbin/ip", "link", "set", "wgtest0", "up")
	run("/usr/sbin/ip", "route", "add", "10.77.0.0/24", "dev", "wgtest0")
	run("/usr/sbin/ip", "route", "add", "203.0.113.33/32", "dev", TunName)
	run("/usr/sbin/ip", "rule", "add", "priority", "100", "fwmark", strconv.FormatUint(uint64(OuterMark), 10), "lookup", strconv.Itoa(UnderlayTable))
	run("/usr/sbin/ip", "rule", "add", "priority", "101", "to", "203.0.113.33", "ipproto", "udp", "sport", "51871", "dport", "51820", "lookup", strconv.Itoa(UnderlayTable))
	// An unprivileged sender must not be able to reuse the kernel-owned source
	// port, even when it opts into both address/port reuse.
	probe, e := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if e != nil {
		t.Fatal(e)
	}
	_ = syscall.SetsockoptInt(probe, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	_ = syscall.SetsockoptInt(probe, syscall.SOL_SOCKET, 15, 1)
	bindErr := syscall.Bind(probe, &syscall.SockaddrInet4{Port: 51871})
	_ = syscall.Close(probe)
	if bindErr != syscall.EADDRINUSE {
		t.Fatalf("WG socket source port is not exclusive: %v", bindErr)
	}
	actual, e := collect(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	auto, e := automaticBindings(ctx, r, actual, nil)
	if e != nil {
		t.Fatal("WireGuard discovery failed:", e)
	}
	verifiedExternal, e := detectExternal(ctx, r, actual, auto)
	if e != nil {
		t.Fatal("WireGuard verification failed:", e)
	}
	options.Snapshot = actual
	options.External = verifiedExternal
	options.Protected = []protectedRoute{{"10.77.0.0/24", "wgtest0"}}
	if _, e = r.Run(ctx, command{Path: "/usr/sbin/nft", Args: []string{"-f", "-"}, Input: guardScript(options, true)}); e != nil {
		t.Fatal("WireGuard guard rejected:", e)
	}
	c, e = net.DialTimeout("udp4", "10.77.0.1:9", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = c.Write([]byte("wireguard-mark-test"))
	_ = c.Close()
	transportPackets := uint64(0)
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		transportPackets = kernelCounter(t, run("/usr/sbin/nft", "-j", "list", "chain", "inet", TableName, "output_guard"), "vlt-external-transport")
		if transportPackets > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if transportPackets == 0 {
		t.Logf("isolated nft state: %s", run("/usr/sbin/nft", "list", "table", "inet", TableName))
		t.Logf("isolated WG endpoint route: %s", run("/usr/sbin/ip", "route", "get", "203.0.113.33"))
		t.Fatal("kernel WireGuard socket did not receive source-port-scoped underlay mark")
	}
	// Userspace UDP transports started after VLESS initially select its source
	// address before nft route-output rerouting. Verify the real emitted packet
	// gets the underlay source via the identity-scoped policy, without NAT.
	udpPeer := "203.0.113.44"
	run("/usr/sbin/ip", "route", "add", udpPeer+"/32", "dev", TunName)
	run("/usr/sbin/ip", "neigh", "replace", "192.0.2.1", "lladdr", "02:00:00:00:00:01", "nud", "permanent", "dev", "eth0")
	options.External = append(options.External, external{Binding: Binding{RootOnly: true, Endpoints: []Endpoint{{Address: udpPeer, Port: 1194, Protocol: "udp"}}}, Link: Link{Name: "corp0", Kind: "tun"}, Active: true})
	if _, e = r.Run(ctx, command{Path: "/usr/sbin/nft", Args: []string{"-f", "-"}, Input: guardScript(options, true)}); e != nil {
		t.Fatal("userspace transport guard rejected:", e)
	}
	if source, e := emittedUDPSource("eth0", udpPeer, 1194); e != nil || source != "198.18.0.1" {
		t.Fatalf("source-selection regression fixture did not reproduce: source=%s error=%v", source, e)
	}
	actual, e = collect(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	m := New(Config{})
	m.ownedRules = true
	m.uplink = u
	m.protected = options.Protected
	if e = m.installRoutes(ctx, actual, options.External, true, false); e != nil {
		t.Fatal("userspace transport routing failed:", e)
	}
	if source, e := emittedUDPSource("eth0", udpPeer, 1194); e != nil || source != "192.0.2.2" {
		t.Fatalf("userspace transport selected wrong physical source: source=%s error=%v", source, e)
	}
	// A real OpenVPN process with a root-owned numeric UDP config need not
	// connect its UDP socket or create a TUN before discovery authorizes its
	// narrow transport. No credentials or config text leave the test process.
	ovpnDir := t.TempDir()
	ovpnKey, ovpnConfig := filepath.Join(ovpnDir, "key"), filepath.Join(ovpnDir, "config")
	run("/usr/sbin/openvpn", "--genkey", "secret", ovpnKey)
	if e = os.WriteFile(ovpnConfig, []byte("dev null\nproto udp\nremote 203.0.113.55 1194\nsecret "+ovpnKey+"\ncipher AES-256-CBC\nverb 0\n"), 0600); e != nil {
		t.Fatal(e)
	}
	ovpn := exec.CommandContext(ctx, "/usr/sbin/openvpn", "--config", ovpnConfig)
	ovpn.Stdout, ovpn.Stderr = io.Discard, io.Discard
	if e = ovpn.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = ovpn.Process.Kill(); _ = ovpn.Wait() }()
	found := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		discovered, err := automaticBindings(ctx, r, actual, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, binding := range discovered {
			for _, ep := range binding.Endpoints {
				if ep.Address == "203.0.113.55" && ep.Port == 1194 && ep.Protocol == "udp" {
					found = true
				}
			}
		}
		if found {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !found {
		t.Fatal("real unconnected OpenVPN UDP transport was not discovered")
	}
	// Atomic pause replacement keeps physical output blocked and permits only
	// IPv4 via the declared foreign full VPN; IPv6 remains blocked.
	options.TunnelReady = false
	options.External = []external{{Link: Link{Name: "corp0", Kind: "tun"}, Active: true, Full4: true}}
	if _, e := r.Run(ctx, command{Path: "/usr/sbin/nft", Args: []string{"-f", "-"}, Input: guardScript(options, true)}); e != nil {
		t.Fatal("pause guard rejected:", e)
	}
	b = run("/usr/sbin/nft", "list", "table", "inet", TableName)
	if !strings.Contains(string(b), `oifname "corp0" meta nfproto ipv4 accept`) {
		t.Fatal("external takeover guard missing")
	}
	for _, f := range []string{"-4", "-6"} {
		for _, table := range []int{ProxyTable, BypassTable, UnderlayTable} {
			if f == "-6" && (table == BypassTable || table == UnderlayTable) {
				continue
			}
			run("/usr/sbin/ip", f, "route", "flush", "table", strconv.Itoa(table))
		}
	}
}

func emittedUDPSource(device, peer string, port int) (string, error) {
	iface, e := net.InterfaceByName(device)
	if e != nil {
		return "", e
	}
	fd, e := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0x0300)
	if e != nil {
		return "", e
	}
	defer syscall.Close(fd)
	if e = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: 0x0300, Ifindex: iface.Index}); e != nil {
		return "", e
	}
	if e = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1}); e != nil {
		return "", e
	}
	c, e := net.ListenUDP("udp4", &net.UDPAddr{})
	if e != nil {
		return "", e
	}
	defer c.Close()
	if _, e = c.WriteToUDP([]byte("source-test"), &net.UDPAddr{IP: net.ParseIP(peer), Port: port}); e != nil {
		return "", e
	}
	b := make([]byte, 2048)
	for {
		n, _, e := syscall.Recvfrom(fd, b, 0)
		if e != nil {
			return "", e
		}
		if n < 42 || b[23] != 17 || net.IP(b[30:34]).String() != peer {
			continue
		}
		return net.IP(b[26:30]).String(), nil
	}
}

func kernelCounter(t *testing.T, b []byte, comment string) uint64 {
	t.Helper()
	var v struct {
		NFTables []struct {
			Rule struct {
				Comment string                       `json:"comment"`
				Expr    []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if e := json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	var count uint64
	for _, r := range v.NFTables {
		if comment != "" && r.Rule.Comment != comment {
			continue
		}
		for _, e := range r.Rule.Expr {
			if raw, ok := e["counter"]; ok {
				var c struct {
					Packets uint64 `json:"packets"`
				}
				_ = json.Unmarshal(raw, &c)
				count += c.Packets
			}
		}
	}
	return count
}

func injectUDPFrame(peerName, targetName string) error {
	peer, e := net.InterfaceByName(peerName)
	if e != nil {
		return e
	}
	target, e := net.InterfaceByName(targetName)
	if e != nil {
		return e
	}
	packet := make([]byte, 14+20+8+4)
	copy(packet[:6], target.HardwareAddr)
	copy(packet[6:12], peer.HardwareAddr)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 32)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], []byte{172, 30, 0, 2})
	copy(ip[16:20], []byte{203, 0, 113, 9})
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ip[10:12], ^uint16(sum))
	udp := packet[34:42]
	binary.BigEndian.PutUint16(udp[:2], 42000)
	binary.BigEndian.PutUint16(udp[2:4], 9)
	binary.BigEndian.PutUint16(udp[4:6], 12)
	copy(packet[42:], []byte("test"))
	fd, e := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(0x0008))
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	addr := &syscall.SockaddrLinklayer{Protocol: 0x0008, Ifindex: peer.Index, Halen: 6}
	copy(addr.Addr[:], target.HardwareAddr)
	return syscall.Sendto(fd, packet, 0, addr)
}
