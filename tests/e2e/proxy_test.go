package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"vault443/internal/model"
	"vault443/internal/network"
	"vault443/internal/profiles"
	"vault443/internal/store"
)

func TestRealProxyProtocols(t *testing.T) {
	requireIsolated(t)
	if os.Getenv("VAULT443_PROXY_E2E") != "1" {
		t.Skip("proxy fixture required")
	}
	raw, e := os.ReadFile("/fixture/proxy-links.txt")
	if e != nil {
		t.Fatal(e)
	}
	var cases []model.Profile
	for _, link := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		p, e := profiles.Parse(link)
		if e != nil {
			t.Fatal(e)
		}
		cases = append(cases, p)
	}
	for _, kind := range []string{"split-prefix", "websocket", "chain", "tcp-only"} {
		endpoint := "192.0.2.1:8501"
		if kind == "websocket" {
			endpoint = `{$type: websocket, url: "wss://vpn.e2e.invalid/tcp", endpoint: "192.0.2.1:9443"}`
		}
		if kind == "chain" {
			endpoint = `{$type: dial, address: "93.184.215.14:8550", dialer: {$type: shadowsocks, endpoint: "192.0.2.1:8502", cipher: chacha20-ietf-poly1305, secret: synthetic-password}}`
		}
		udp := "192.0.2.1:8502"
		udpCipher := "chacha20-ietf-poly1305"
		if kind == "chain" {
			udp = endpoint
			udpCipher = "aes-256-gcm"
		}
		if kind == "websocket" {
			udp = `{$type: websocket, url: "wss://vpn.e2e.invalid/udp", endpoint: "192.0.2.1:9443"}`
		}
		document := fmt.Sprintf("transport:\n  $type: tcpudp\n  tcp: {$type: shadowsocks, endpoint: %s, cipher: aes-256-gcm, secret: synthetic-password, prefix: 'POST '}\n", endpoint)
		if kind != "tcp-only" {
			document += fmt.Sprintf("  udp: {$type: shadowsocks, endpoint: %s, cipher: %s, secret: synthetic-password}\n", udp, udpCipher)
		}
		p, e := profiles.ParseOutline(document, "https://source.example/"+kind, "Outline-"+kind)
		if e != nil {
			t.Fatal(e)
		}
		cases = append(cases, p)
	}
	for i, p := range cases {
		t.Run(p.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			dir := fmt.Sprintf("/var/lib/vault443-proxy-%d", i)
			run := fmt.Sprintf("/run/vault443-proxy-%d", i)
			m := network.New(network.Config{StateDir: dir, RuntimeDir: run})
			openConnectionJournal(t, dir+"/logs", m, p, 1000)
			defer func() {
				ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
				defer c()
				if e := m.Disconnect(ctx); e != nil {
					t.Error(e)
				}
			}()
			if e := m.Connect(ctx, p); e != nil {
				t.Fatalf("connect: %v", e)
			}
			if m.Status().State != "connected" || !m.Status().GuardArmed {
				t.Fatal("connection not verified")
			}
			reply, e := request(ctx, "")
			if e != nil || reply.Peer == "192.0.2.2" {
				t.Fatalf("TCP did not cross proxy: %+v %v", reply, e)
			}
			if e := proxyUDP(); p.Outline != nil && p.Outline.UDP == nil {
				if e == nil {
					t.Fatal("disabled UDP escaped")
				}
			} else if e != nil {
				t.Fatalf("UDP: %v", e)
			}
			if _, e = request(ctx, "e2euplink"); e == nil {
				t.Fatal("physical bypass escaped guard")
			}

			if os.Getenv("VAULT443_QUIC_E2E") == "1" && !(p.Outline != nil && p.Outline.UDP == nil) {
				child := exec.CommandContext(ctx, "/src/.cache/quic-fixture")
				child.Env = os.Environ()
				child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
				if out, e := child.CombinedOutput(); e != nil {
					t.Fatalf("HTTP/3: %v %s", e, out)
				}
			}
			if p.Name == "Trojan-tcp" || p.Name == "2022-blake3-aes-128-gcm" || p.Name == "Outline-websocket" {
				binary, _ := os.Executable()
				child := exec.CommandContext(ctx, binary, "-test.run=^TestRealVLESSBrowserProcess$", "-test.timeout=30s")
				child.Env = append(os.Environ(), "VAULT443_E2E_BROWSER_CHILD=1")
				child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
				if out, e := child.CombinedOutput(); e != nil {
					t.Fatalf("unprivileged HTTPS/HTTP2 matrix: %v %s", e, out)
				}
			}
			if p.Name == "Outline-websocket" {
				data, err := os.ReadFile(run + "/core.json")
				if err != nil {
					t.Fatal(err)
				}
				var config struct {
					Outbounds []struct {
						Protocol string
						Settings struct{ Servers []struct{ Port int } }
					}
				}
				if err = json.Unmarshal(data, &config); err != nil {
					t.Fatal(err)
				}
				port := 0
				for _, out := range config.Outbounds {
					if out.Protocol == "socks" {
						port = out.Settings.Servers[0].Port
					}
				}
				if port == 0 {
					t.Fatal("missing adapter")
				}
				// Even while Xray owns an authenticated UDP association, another
				// local user cannot open TCP or inject SOCKS datagrams.
				script := `import socket,sys
port=int(sys.argv[1])
s=socket.socket();s.settimeout(.25)
try: s.connect(('127.0.0.1',port))
except OSError: pass
else: sys.exit('unprivileged TCP adapter access')
s.close()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.25)
try:
 s.sendto(bytes([0,0,0,1,1,1,1,1,39,15])+b'forbidden',('127.0.0.1',port))
 s.recv(512)
except OSError: pass
else: sys.exit('unprivileged UDP adapter access')
`
				out, err := exec.CommandContext(ctx, "setpriv", "--reuid", "65534", "--regid", "65534", "--clear-groups", "python3", "-c", script, fmt.Sprint(port)).CombinedOutput()
				if err != nil {
					t.Fatalf("adapter isolation: %v %s", err, out)
				}
				command(t, "pkill", "-KILL", "-f", "^/usr/lib/vault443/vault443-outline$")
				time.Sleep(100 * time.Millisecond)
				if _, e = request(ctx, ""); e == nil {
					t.Fatal("traffic escaped after adapter crash")
				}
				if e = m.Reconcile(ctx); e == nil || !m.Status().GuardArmed {
					t.Fatal("adapter crash did not retain protection")
				}
				if e = m.Connect(ctx, p); e != nil {
					t.Fatal("adapter restart", e)
				}
				if _, e = request(ctx, ""); e != nil {
					t.Fatal("adapter recovery", e)
				}
			}
			t.Log("verified TUN, DNS, HTTPS/HTTP2, TCP, UDP and physical leak protection")
		})
	}
}
func proxyUDP() error {
	for _, port := range []int{9999, 443} {
		if e := proxyUDPPort(port); e != nil {
			return e
		}
	}
	return nil
}
func proxyUDPPort(port int) error {
	c, e := net.DialTimeout("udp4", fmt.Sprint("1.1.1.1:", port), time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte(strings.Repeat("vault443-synthetic-udp", 60))
	if _, e = c.Write(payload); e != nil {
		return e
	}
	b := make([]byte, 2048)
	n, e := c.Read(b)
	if e != nil {
		return e
	}
	if string(b[:n]) != string(payload) {
		return fmt.Errorf("unexpected UDP reply")
	}
	return nil
}

func TestRealProtectedSourceDownload(t *testing.T) {
	requireIsolated(t)
	if os.Getenv("VAULT443_PROXY_E2E") != "1" {
		t.Skip("proxy fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	m := network.New(network.Config{StateDir: "/var/lib/vault443-source", RuntimeDir: "/run/vault443-source"})
	defer m.Disconnect(context.Background())
	if e := m.Arm(ctx); e != nil {
		t.Fatal(e)
	}
	document := `ss://aes-256-gcm:synthetic-password@192.0.2.1:8501`
	if e := os.WriteFile("/fixture/dynamic-outline", []byte(document), 0600); e != nil {
		t.Fatal(e)
	}
	got, e := m.FetchSource(ctx, "https://93.184.215.14/outline")
	if e != nil || got != document {
		t.Fatalf("protected fetch: %v", e)
	}
	if _, e := request(ctx, ""); e == nil {
		t.Fatal("download exception allowed ordinary traffic")
	}
	for _, raw := range []string{"https://127.0.0.1/private", "https://169.254.169.254/latest", "https://93.184.215.14/redirect-local"} {
		if _, e := m.FetchSource(ctx, raw); e == nil {
			t.Fatal("source fetched a local endpoint")
		}
	}
	short, stop := context.WithTimeout(ctx, 150*time.Millisecond)
	defer stop()
	start := time.Now()
	if _, e := m.FetchSource(short, "https://93.184.215.14/slow-source"); e == nil || time.Since(start) > 2*time.Second {
		t.Fatal("source cancellation did not interrupt fetch", e)
	}
	rules := command(t, "ip", "-4", "rule", "show")
	if strings.Contains(rules, "52789") {
		t.Fatal("source routing permissions survived the request")
	}
}

// Package fixture seeds only synthetic data while PID1 has stopped the service.
func TestPackageProxyProfile(t *testing.T) {
	if os.Getenv("VAULT443_PACKAGE_PROXY_SEED") != "1" {
		t.Skip("package-only fixture")
	}
	requireWorkIsolated(t)
	document := `transport:
  $type: tcpudp
  tcp: {$type: shadowsocks, endpoint: {$type: websocket, url: "wss://vpn.e2e.invalid/tcp", endpoint: "192.0.2.1:9443"}, cipher: aes-256-gcm, secret: synthetic-password}
  udp: {$type: shadowsocks, endpoint: {$type: websocket, url: "wss://vpn.e2e.invalid/udp", endpoint: "192.0.2.1:9443"}, cipher: chacha20-ietf-poly1305, secret: synthetic-password}
`
	if e := os.WriteFile("/fixture/dynamic-outline", []byte(document), 0600); e != nil {
		t.Fatal(e)
	}
	p, e := profiles.ParseOutline(document, "https://93.184.215.14/outline", "Package Outline")
	if e != nil {
		t.Fatal(e)
	}
	p.Source.UpdatedAt = time.Now().Unix()
	st, e := store.OpenExclusive("/var/lib/vault443", false)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	if e = st.Update(func(s *store.State) error {
		u := s.User(11000)
		u.Profiles = append(u.Profiles, p)
		s.SetUser(11000, u)
		s.Desired = &store.Session{UID: 11000, ProfileID: p.ID}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestRealProxyWorkCompatibility(t *testing.T) {
	requireWorkIsolated(t)
	raw, e := os.ReadFile("/fixture/proxy-links.txt")
	if e != nil {
		t.Fatal(e)
	}
	links := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if e := os.WriteFile("/fixture/dynamic-outline", []byte(links[5]), 0600); e != nil {
		t.Fatal(e)
	}
	for _, index := range []int{0, 5, 8} {
		for _, first := range []bool{false, true} {
			p, e := profiles.Parse(links[index])
			if e != nil {
				t.Fatal(e)
			}
			t.Run(fmt.Sprintf("%s/mainFirst=%v", p.Name, first), func(t *testing.T) {
				h := newWorkHarness(t)
				work := workProfile(t, 1, "")
				if first {
					if e := h.n.Connect(h.ctx, p); e != nil {
						t.Fatal(e)
					}
				}
				h.start(work)
				h.waitConnected(work.ID)
				if !first {
					if e := h.n.Connect(h.ctx, p); e != nil {
						t.Fatal(e)
					}
				}
				h.assertWork("192.168.100.15", "10.70.")
				r, e := workDockerHTTP(h.ctx, "192.168.100.15")
				if e != nil || !strings.HasPrefix(r.Peer, "10.70.") {
					t.Fatal("Docker work path", e)
				}
				// Ordinary forwarded Internet traffic must cross the main encrypted path.
				out, e := exec.CommandContext(h.ctx, "ip", "netns", "exec", "work-docker", "curl", "--noproxy", "*", "--fail", "--silent", "--max-time", "2", "http://93.184.215.14:8080/").Output()
				if e != nil || strings.Contains(string(out), "192.0.2.2") {
					t.Fatal("Docker Internet path", e)
				}
				if _, e = h.n.FetchSource(h.ctx, "https://93.184.215.14/outline"); e != nil {
					t.Fatal("source fetch alongside work tunnel", e)
				}
				h.assertWork("192.168.100.15", "10.70.")
				if e = h.n.Disconnect(h.ctx); e != nil {
					t.Fatal(e)
				}
				h.assertWork("192.168.100.15", "10.70.")
			})
		}
	}
}
