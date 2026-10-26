package network

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestKernelUnavailableIPv6FastFallback(t *testing.T) {
	if os.Getenv("VAULT443_KERNEL_TEST") != "1" {
		t.Skip("requires isolated Docker namespace")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("refusing non-Docker environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
		t.Fatal("refusing nonempty network namespace")
	}
	if data, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding"); err != nil || strings.TrimSpace(string(data)) != "1" {
		t.Fatal("test requires isolated IPv6 forwarding")
	}
	run("/usr/sbin/ip", "link", "set", "lo", "up")
	run("/usr/sbin/ip", "link", "add", TunName, "type", "dummy")
	run("/usr/sbin/ip", "link", "set", TunName, "up")
	run("/usr/sbin/ip", "-6", "address", "add", "fd56:4c54::1/64", "dev", TunName, "nodad")
	run("/usr/sbin/ip", "-6", "route", "add", "2001:db8:66::14/128", "dev", TunName)
	run("/usr/sbin/ip", "link", "add", "inj0", "type", "veth", "peer", "name", "peer0")
	run("/usr/sbin/ip", "-6", "address", "add", "fd30::1/64", "dev", "inj0", "nodad")
	run("/usr/sbin/ip", "link", "set", "inj0", "up")
	run("/usr/sbin/ip", "link", "set", "peer0", "up")
	peer, err := net.InterfaceByName("peer0")
	if err != nil {
		t.Fatal(err)
	}
	run("/usr/sbin/ip", "-6", "neigh", "replace", "fd30::2", "lladdr", peer.HardwareAddr.String(), "nud", "permanent", "dev", "inj0")
	snapshot, err := collect(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	for i, checking := range []bool{true, false} {
		script := guardScript(guardOptions{Snapshot: snapshot, TunnelReady: true, BlockTunnelIPv6: true, AllowIPv6Probe: checking}, i > 0)
		if _, err := r.Run(ctx, command{Path: "/usr/sbin/nft", Args: []string{"-f", "-"}, Input: script}); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name string
			mark uint32
			port string
		}{
			{"unmarked", 0, "443"},
			{"marked_probe", IPv6ProbeMark, "443"},
			{"wrong_mark", BootstrapMark, "443"},
			{"wrong_port", IPv6ProbeMark, "80"},
		} {
			dialer := net.Dialer{Timeout: 300 * time.Millisecond, Control: func(_, _ string, raw syscall.RawConn) error {
				var err error
				if e := raw.Control(func(fd uintptr) {
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(tc.mark))
				}); e != nil {
					return e
				}
				return err
			}}
			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp6", net.JoinHostPort("2001:db8:66::14", tc.port))
			if conn != nil {
				conn.Close()
				t.Fatal("dummy tunnel unexpectedly connected")
			}
			if checking && tc.name == "marked_probe" {
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("marked root HTTPS probe was not allowed into TUN: %v", err)
				}
			} else if !errors.Is(err, syscall.ECONNREFUSED) || time.Since(start) > 250*time.Millisecond {
				t.Fatalf("%s checking=%v IPv6 did not fail before TUN: %v in %v", tc.name, checking, err, time.Since(start))
			}
		}
		for _, tcp := range []bool{true, false} {
			if err := forwardedIPv6Unavailable(tcp); err != nil {
				t.Fatalf("forwarded IPv6 checking=%v tcp=%v did not receive fast rejection: %v", checking, tcp, err)
			}
		}
	}
	t.Log("Unverified IPv6 fails promptly for host and containers; only marked root OUTPUT HTTPS can probe TUN")
}

func forwardedIPv6Unavailable(tcp bool) error {
	peer, err := net.InterfaceByName("peer0")
	if err != nil {
		return err
	}
	target, err := net.InterfaceByName("inj0")
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0x0300)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: 0x0300, Ifindex: peer.Index}); err != nil {
		return err
	}
	if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 500000}); err != nil {
		return err
	}
	transport := []byte{0xa4, 0x11, 0x01, 0xbb, 0, 12, 0, 0, 'i', 'p', 'v', '6'}
	protocol, checksumOffset := byte(17), 6
	if tcp {
		transport = make([]byte, 20)
		binary.BigEndian.PutUint16(transport[:2], 42001)
		binary.BigEndian.PutUint16(transport[2:4], 443)
		binary.BigEndian.PutUint32(transport[4:8], 1)
		transport[12], transport[13] = 0x50, 0x02 // TCP data offset and SYN
		binary.BigEndian.PutUint16(transport[14:16], 65535)
		protocol, checksumOffset = 6, 16
	}
	ethernet := make([]byte, 14)
	copy(ethernet[:6], target.HardwareAddr)
	copy(ethernet[6:12], peer.HardwareAddr)
	binary.BigEndian.PutUint16(ethernet[12:], 0x86dd)
	ip := make([]byte, 40)
	ip[0], ip[6], ip[7] = 0x60, protocol, 64
	binary.BigEndian.PutUint16(ip[4:], uint16(len(transport)))
	copy(ip[8:24], net.ParseIP("fd30::2").To16())
	copy(ip[24:40], net.ParseIP("2001:db8:66::14").To16())
	pseudo := append([]byte(nil), ip[8:40]...)
	pseudo = append(pseudo, 0, 0, 0, byte(len(transport)), 0, 0, 0, protocol)
	binary.BigEndian.PutUint16(transport[checksumOffset:], checksum(append(pseudo, transport...)))
	packet := append(append(ethernet, ip...), transport...)
	address := &syscall.SockaddrLinklayer{Ifindex: peer.Index, Halen: 6}
	copy(address.Addr[:], target.HardwareAddr)
	if err := syscall.Sendto(fd, packet, 0, address); err != nil {
		return err
	}
	buffer := make([]byte, 2048)
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			return err
		}
		if !tcp && n >= 56 && binary.BigEndian.Uint16(buffer[12:]) == 0x86dd && buffer[20] == 58 && buffer[54] == 1 && buffer[55] == 1 {
			return nil
		}
		if tcp && n >= 74 && binary.BigEndian.Uint16(buffer[12:]) == 0x86dd && buffer[20] == 6 && buffer[67]&0x04 != 0 {
			return nil
		}
	}
	return errors.New("no IPv6 rejection received")
}
