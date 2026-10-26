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

	"vault443/internal/model"
)

func TestVisionQUICRejectIsRestrictedToActivePlainVision(t *testing.T) {
	for _, flow := range []string{"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"} {
		for _, ready := range []bool{false, true} {
			manager := New(Config{DryRun: true})
			manager.r = &fakeRunner{s: fixture()}
			manager.profile = &model.Profile{Flow: flow}
			manager.protected = []protectedRoute{{"10.20.0.0/16", "corp0"}}
			if err := manager.applyGuard(context.Background(), fixture(), nil, ready); err != nil {
				t.Fatal(err)
			}
			script := manager.commands[len(manager.commands)-1].Input
			count := strings.Count(script, "vlt-vision-quic-reject")
			if ready && flow == "xtls-rprx-vision" {
				if count != 2 {
					t.Fatalf("host and forwarded QUIC need explicit rejection: %d", count)
				}
				for _, chain := range strings.Split(script, "policy drop;")[1:] {
					reject := strings.Index(chain, `oifname "vault4430" udp dport 443`)
					if protected, accept := strings.Index(chain, "ip daddr 10.20.0.0/16 drop"), strings.Index(chain, `oifname "vault4430" accept`); protected < 0 || reject < protected || accept < reject {
						t.Fatal("QUIC rule must follow corporate protection and precede TUN allowance")
					}
				}
			} else if count != 0 {
				t.Fatalf("QUIC rejection changed supported/paused flow %q ready=%v", flow, ready)
			}
		}
	}
}

func TestLocalIPv6RequiresActualConnectedKernelSubnet(t *testing.T) {
	var snapshot Snapshot
	if err := json.Unmarshal([]byte(`{"Links":[{"ifname":"docker0","linkinfo":{"info_kind":"bridge"},"addr_info":[{"local":"fd30::1","prefixlen":64,"family":"inet6"}]}]}`), &snapshot); err != nil {
		t.Fatal(err)
	}
	base := Route{Destination: "fd30::/64", Device: "docker0", Family: 6, Protocol: json.RawMessage(`"kernel"`)}
	for _, tc := range []struct {
		name string
		edit func(*Route)
		want bool
	}{
		{"connected", func(*Route) {}, true},
		{"gateway", func(r *Route) { r.Gateway = "fd30::2" }, false},
		{"static", func(r *Route) { r.Protocol = json.RawMessage(`"static"`) }, false},
		{"public_unassigned", func(r *Route) { r.Destination = "2001:db8::/32" }, false},
		{"broader", func(r *Route) { r.Destination = "fd30::/48" }, false},
		{"default", func(r *Route) { r.Destination = "default" }, false},
		{"owned", func(r *Route) { r.Table = json.RawMessage(`52780`) }, false},
		{"non_unicast", func(r *Route) { r.Type = "blackhole" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := base
			tc.edit(&route)
			snapshot.Routes = []Route{route}
			if got := len(localRoutes(snapshot)) == 1; got != tc.want {
				t.Fatalf("connected IPv6 classification got=%v want=%v", got, tc.want)
			}
		})
	}
}

// Runs only in an empty disposable container namespace. Real sockets exercise
// OUTPUT; raw Ethernet packets across veth exercise FORWARD and the returned
// ICMP error, including delivery back through the OUTPUT protection rules.
func TestKernelVisionQUICFastFallback(t *testing.T) {
	if os.Getenv("VAULT443_KERNEL_TEST") != "1" {
		t.Skip("requires isolated Docker namespace")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("refusing non-Docker environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	runner := execRunner{}
	run := func(path string, args ...string) []byte {
		t.Helper()
		out, err := runner.Run(ctx, command{Path: path, Args: args})
		if err != nil {
			t.Fatal(path, args, err)
		}
		return out
	}
	var links []Link
	if json.Unmarshal(run("/usr/sbin/ip", "-j", "link", "show"), &links) != nil || len(links) != 1 || links[0].Name != "lo" {
		t.Fatal("refusing nonempty network namespace")
	}
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		data, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(data)) != "1" {
			t.Fatal("test requires isolated IPv4/IPv6 forwarding")
		}
	}
	run("/usr/sbin/ip", "link", "set", "lo", "up")
	run("/usr/sbin/ip", "link", "add", TunName, "type", "dummy")
	run("/usr/sbin/ip", "link", "set", TunName, "up")
	run("/usr/sbin/ip", "address", "add", "198.18.0.1/30", "dev", TunName)
	run("/usr/sbin/ip", "-6", "address", "add", "fd56:4c54::1/64", "dev", TunName, "nodad")
	run("/usr/sbin/ip", "route", "add", "93.184.215.14/32", "dev", TunName)
	run("/usr/sbin/ip", "-6", "route", "add", "2001:db8:66::14/128", "dev", TunName)
	run("/usr/sbin/ip", "link", "add", "inj0", "type", "veth", "peer", "name", "peer0")
	run("/usr/sbin/ip", "address", "add", "172.30.0.1/24", "dev", "inj0")
	run("/usr/sbin/ip", "-6", "address", "add", "fd30::1/64", "dev", "inj0", "nodad")
	run("/usr/sbin/ip", "link", "set", "inj0", "up")
	run("/usr/sbin/ip", "link", "set", "peer0", "up")
	peer, err := net.InterfaceByName("peer0")
	if err != nil {
		t.Fatal(err)
	}
	run("/usr/sbin/ip", "neigh", "replace", "172.30.0.2", "lladdr", peer.HardwareAddr.String(), "nud", "permanent", "dev", "inj0")
	run("/usr/sbin/ip", "-6", "neigh", "replace", "fd30::2", "lladdr", peer.HardwareAddr.String(), "nud", "permanent", "dev", "inj0")
	snapshot, err := collect(ctx, runner)
	if err != nil {
		t.Fatal(err)
	}
	for i, reject := range []bool{true, false} {
		if _, err := runner.Run(ctx, command{Path: "/usr/sbin/nft", Args: []string{"-f", "-"}, Input: guardScript(guardOptions{Snapshot: snapshot, TunnelReady: true, RejectQUIC: reject}, i > 0)}); err != nil {
			t.Fatal(err)
		}
		for _, target := range []struct{ network, address string }{{"udp4", "93.184.215.14:443"}, {"udp6", "[2001:db8:66::14]:443"}} {
			conn, err := net.Dial(target.network, target.address)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
			start := time.Now()
			_, err = conn.Write([]byte("quic-fallback-probe"))
			// nft REJECT may synchronously fail sendmsg with EPERM while also
			// queuing the more specific ICMP port-unreachable socket error.
			if err == nil || errors.Is(err, syscall.EPERM) {
				_, err = conn.Read(make([]byte, 64))
			}
			conn.Close()
			if reject {
				if !errors.Is(err, syscall.ECONNREFUSED) || time.Since(start) > 250*time.Millisecond {
					t.Fatalf("%s QUIC was not rejected promptly: %v after %v", target.network, err, time.Since(start))
				}
			} else {
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("%s supported UDP unexpectedly rejected: %v", target.network, err)
				}
			}
		}
		if reject {
			for _, v6 := range []bool{false, true} {
				if err := forwardedQUICReject(v6); err != nil {
					t.Logf("IPv6 routes: %s", run("/usr/sbin/ip", "-j", "-6", "route", "show", "table", "all"))
					t.Logf("guard: %s", run("/usr/sbin/nft", "list", "table", "inet", TableName))
					t.Fatalf("forwarded IPv6=%v QUIC did not receive port-unreachable: %v", v6, err)
				}
			}
		}
	}
	t.Log("Vision host and forwarded IPv4/IPv6 receive immediate UDP/443 errors; other flows retain UDP")
}

func forwardedQUICReject(v6 bool) error {
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
	udp := []byte{0xa4, 0x11, 0x01, 0xbb, 0, 12, 0, 0, 'q', 'u', 'i', 'c'}
	ethernet := make([]byte, 14)
	copy(ethernet[:6], target.HardwareAddr)
	copy(ethernet[6:12], peer.HardwareAddr)
	var ip, pseudo []byte
	if v6 {
		binary.BigEndian.PutUint16(ethernet[12:], 0x86dd)
		ip = make([]byte, 40)
		ip[0], ip[6], ip[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(ip[4:], uint16(len(udp)))
		copy(ip[8:24], net.ParseIP("fd30::2").To16())
		copy(ip[24:40], net.ParseIP("2001:db8:66::14").To16())
		pseudo = append(pseudo, ip[8:40]...)
		pseudo = append(pseudo, 0, 0, 0, byte(len(udp)), 0, 0, 0, 17)
	} else {
		binary.BigEndian.PutUint16(ethernet[12:], 0x0800)
		ip = make([]byte, 20)
		ip[0], ip[8], ip[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(udp)))
		copy(ip[12:16], net.ParseIP("172.30.0.2").To4())
		copy(ip[16:20], net.ParseIP("93.184.215.14").To4())
		binary.BigEndian.PutUint16(ip[10:], checksum(ip))
		pseudo = append(pseudo, ip[12:20]...)
		pseudo = append(pseudo, 0, 17, 0, byte(len(udp)))
	}
	binary.BigEndian.PutUint16(udp[6:], checksum(append(pseudo, udp...)))
	packet := append(append(ethernet, ip...), udp...)
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
		if v6 && n >= 56 && binary.BigEndian.Uint16(buffer[12:]) == 0x86dd && buffer[20] == 58 && buffer[54] == 1 && buffer[55] == 4 {
			return nil
		}
		if !v6 && n >= 36 && binary.BigEndian.Uint16(buffer[12:]) == 0x0800 && buffer[23] == 1 {
			offset := 14 + int(buffer[14]&0xf)*4
			if n >= offset+2 && buffer[offset] == 3 && buffer[offset+1] == 3 {
				return nil
			}
		}
	}
	return errors.New("no ICMP port-unreachable received")
}
