package network

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Packet-level proof that bootstrap authorization is confined to marked host
// OUTPUT. Runtime requires an empty disposable Docker network namespace.
func TestKernelBootstrapScopes(t *testing.T) {
	if os.Getenv("VAULT443_KERNEL_TEST") != "1" {
		t.Skip("requires isolated Docker namespace")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("refusing non-Docker environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r := execRunner{}
	run := func(path string, args ...string) []byte {
		t.Helper()
		out, err := r.Run(ctx, command{Path: path, Args: args})
		if err != nil {
			t.Fatal(path, args, err)
		}
		return out
	}
	var links []Link
	if json.Unmarshal(run("/usr/sbin/ip", "-j", "link", "show"), &links) != nil || len(links) != 1 || links[0].Name != "lo" {
		t.Fatal("refusing nonempty namespace")
	}
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		data, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(data)) != "1" {
			t.Fatal("isolated container requires IPv4 and IPv6 forwarding sysctls")
		}
	}
	run("/usr/sbin/ip", "link", "set", "lo", "up")
	run("/usr/sbin/ip", "link", "add", "eth0", "type", "dummy")
	run("/usr/sbin/ip", "link", "set", "eth0", "up")
	run("/usr/sbin/ip", "address", "add", "192.0.2.2/24", "dev", "eth0")
	run("/usr/sbin/ip", "-6", "address", "add", "2001:db8:1::2/64", "dev", "eth0", "nodad")
	run("/usr/sbin/ip", "route", "add", "default", "via", "192.0.2.1", "dev", "eth0")
	run("/usr/sbin/ip", "-6", "route", "add", "default", "dev", "eth0")
	run("/usr/sbin/ip", "neigh", "replace", "192.0.2.1", "lladdr", "02:00:00:00:00:01", "nud", "permanent", "dev", "eth0")
	run("/usr/sbin/ip", "link", "add", "inj0", "type", "veth", "peer", "name", "peer0")
	run("/usr/sbin/ip", "address", "add", "172.30.0.1/24", "dev", "inj0")
	run("/usr/sbin/ip", "-6", "address", "add", "fd30::1/64", "dev", "inj0", "nodad")
	run("/usr/sbin/ip", "link", "set", "inj0", "up")
	run("/usr/sbin/ip", "link", "set", "peer0", "up")
	snapshot, err := collect(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Run(ctx, command{Path: "/usr/sbin/nft", Args: []string{"-f", "-"}, Input: guardScript(guardOptions{Snapshot: snapshot, Uplink: "eth0"}, false)}); err != nil {
		t.Fatal(err)
	}
	counter := func(chain, comment string) uint64 {
		return kernelCounter(t, run("/usr/sbin/nft", "-j", "list", "chain", "inet", TableName, chain), comment)
	}
	marked := bootstrapDialer()
	marked.Timeout = 100 * time.Millisecond
	conn, _ := marked.DialContext(ctx, "tcp4", bootstrapDoHAddress)
	if conn != nil {
		conn.Close()
	}
	if counter("output_guard", "vlt-bootstrap-doh") == 0 {
		t.Fatal("marked bootstrap HTTPS never reached its narrow allowance")
	}
	before := counter("output_guard", "")
	unmarked := net.Dialer{Timeout: 100 * time.Millisecond}
	conn, _ = unmarked.DialContext(ctx, "tcp4", bootstrapDoHAddress)
	if conn != nil {
		conn.Close()
	}
	if counter("output_guard", "") <= before {
		t.Fatal("unmarked host HTTPS did not reach fail-closed counter")
	}
	before = counter("output_guard", "")
	conn, _ = unmarked.DialContext(ctx, "udp6", "[2001:db8:2::1]:443")
	if conn != nil {
		_, _ = conn.Write([]byte("IPv6 blocked"))
		conn.Close()
	}
	if counter("output_guard", "") <= before {
		t.Fatal("unprotected host IPv6 did not reach fail-closed counter")
	}
	for _, v6 := range []bool{false, true} {
		before := counter("forward_guard", "")
		if err := injectBootstrapTCP("peer0", "inj0", v6); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(time.Second)
		for counter("forward_guard", "") <= before {
			if time.Now().After(deadline) {
				t.Fatalf("forwarded TCP/443 packet bypassed guard or never reached it (IPv6=%v)", v6)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Log("marked host DoH allowed; unmarked host TCP, host IPv6, forwarded IPv4/IPv6 TCP denied")
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 65535 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func injectBootstrapTCP(peerName, targetName string, v6 bool) error {
	peer, err := net.InterfaceByName(peerName)
	if err != nil {
		return err
	}
	target, err := net.InterfaceByName(targetName)
	if err != nil {
		return err
	}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp, 42001)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[12], tcp[13] = 0x50, 0x02
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	var ip, pseudo []byte
	ethernet := make([]byte, 14)
	copy(ethernet[:6], target.HardwareAddr)
	copy(ethernet[6:12], peer.HardwareAddr)
	if v6 {
		binary.BigEndian.PutUint16(ethernet[12:], 0x86dd)
		ip = make([]byte, 40)
		ip[0], ip[6], ip[7] = 0x60, 6, 64
		binary.BigEndian.PutUint16(ip[4:], 20)
		copy(ip[8:24], net.ParseIP("fd30::2").To16())
		copy(ip[24:40], net.ParseIP("2001:db8:2::1").To16())
		pseudo = append(pseudo, ip[8:40]...)
		pseudo = append(pseudo, 0, 0, 0, 20, 0, 0, 0, 6)
	} else {
		binary.BigEndian.PutUint16(ethernet[12:], 0x0800)
		ip = make([]byte, 20)
		ip[0], ip[8], ip[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(ip[2:], 40)
		copy(ip[12:16], []byte{172, 30, 0, 2})
		copy(ip[16:20], []byte{1, 1, 1, 1})
		binary.BigEndian.PutUint16(ip[10:], checksum(ip))
		pseudo = append(pseudo, ip[12:20]...)
		pseudo = append(pseudo, 0, 6, 0, 20)
	}
	binary.BigEndian.PutUint16(tcp[16:], checksum(append(pseudo, tcp...)))
	packet := append(append(ethernet, ip...), tcp...)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0x0300)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	address := &syscall.SockaddrLinklayer{Ifindex: peer.Index, Halen: 6}
	copy(address.Addr[:], target.HardwareAddr)
	return syscall.Sendto(fd, packet, 0, address)
}
