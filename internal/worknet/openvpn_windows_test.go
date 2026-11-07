package worknet

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"testing/iotest"
	"time"
	"vault443/internal/network"
	"vault443/internal/workvpn"
)

func TestWindowsOpenVPNManagementPromptFraming(t *testing.T) {
	const success = "SUCCESS: password is correct\r\n"
	const rest = ">INFO:OpenVPN Management Interface Version 5\r\n>HOLD:Waiting for hold release:0\r\n"
	for _, prompt := range []string{"", "ENTER PASSWORD:", "ENTER PASSWORD:\r\n"} {
		for _, fragmented := range []bool{false, true} {
			t.Run(fmt.Sprintf("prompt=%q/fragmented=%t", prompt, fragmented), func(t *testing.T) {
				var reader io.Reader = strings.NewReader(prompt + success + rest)
				if fragmented {
					reader = iotest.OneByteReader(reader)
				}
				scanner := bufio.NewScanner(reader)
				if !verifyOpenVPNManagementPassword(scanner) {
					t.Fatal("valid management password reply rejected")
				}
				for _, expected := range []string{">INFO:OpenVPN Management Interface Version 5", ">HOLD:Waiting for hold release:0"} {
					if !scanner.Scan() || scanner.Text() != expected {
						t.Fatalf("following management frame lost: want %q, got %q", expected, scanner.Text())
					}
				}
			})
		}
	}
	for _, transcript := range []string{
		"ENTER PASSWORD:ERROR: bad password\r\n" + success,
		"untrusted prefix SUCCESS: password is correct\r\n",
		"ENTER PASSWORD:SUCCESS: password is correct with trailing data\r\n",
		"ENTER PASSWORD:ENTER PASSWORD:" + success,
	} {
		if verifyOpenVPNManagementPassword(bufio.NewScanner(iotest.OneByteReader(strings.NewReader(transcript)))) {
			t.Fatalf("invalid management authentication accepted: %q", transcript)
		}
	}
}

func TestWindowsOpenVPNManagementSubscriptionsPrecedeHoldRelease(t *testing.T) {
	for _, fragmented := range []bool{false, true} {
		t.Run(fmt.Sprintf("fragmented=%t", fragmented), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			client.SetDeadline(time.Now().Add(2 * time.Second))
			server.SetDeadline(time.Now().Add(2 * time.Second))
			result := make(chan error, 1)
			go func() {
				write := func(s string) error {
					if !fragmented {
						_, err := io.WriteString(server, s)
						return err
					}
					for i := range len(s) {
						if _, err := io.WriteString(server, s[i:i+1]); err != nil {
							return err
						}
					}
					return nil
				}
				if err := write(">INFO:OpenVPN Management Interface Version 5\r\n>HOLD:Waiting for hold release:0\r\n"); err != nil {
					result <- err
					return
				}
				requests := bufio.NewReader(server)
				for _, step := range []struct{ request, reply string }{
					{"state on\n", "SUCCESS: real-time state notification set to ON\r\n"},
					{"log on\n", "SUCCESS: real-time log notification set to ON\r\n"},
					{"hold release\n", ">LOG:1793952000,D,MANAGEMENT: CMD 'hold release'\r\nSUCCESS: hold release succeeded\r\n"},
				} {
					line, err := requests.ReadString('\n')
					if err != nil || line != step.request || requests.Buffered() != 0 {
						result <- fmt.Errorf("command before prior acknowledgement: got %q, want %q, err=%v", line, step.request, err)
						return
					}
					if err := write(step.reply); err != nil {
						result <- err
						return
					}
				}
				result <- write(">STATE:1793952000,AUTH,,,,\r\n>STATE:1793952000,GET_CONFIG,,,,\r\n")
			}()
			scanner := bufio.NewScanner(client)
			if err := initializeOpenVPNManagement(scanner, client); err != nil {
				t.Fatal(err)
			}
			for _, state := range []string{"AUTH", "GET_CONFIG"} {
				want := ">STATE:1793952000," + state + ",,,,"
				if !scanner.Scan() || scanner.Text() != want {
					t.Fatalf("first TLS notification consumed by initialization: got %q, want %q", scanner.Text(), want)
				}
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWindowsOpenVPNManagementStartupFailsClosed(t *testing.T) {
	const hold = ">HOLD:Waiting for hold release:0\r\n"
	const state = "SUCCESS: real-time state notification set to ON\r\n"
	const logs = "SUCCESS: real-time log notification set to ON\r\n"
	for _, tc := range []struct{ name, transcript, sent string }{
		{"missing-hold", state, ""},
		{"malformed-hold", ">HOLD:Waiting for hold release:invalid\r\n", ""},
		{"bounded-banner", strings.Repeat(">INFO:banner\r\n", 32) + hold, ""},
		{"state-error", hold + "ERROR: rejected\r\n", "state on\n"},
		{"state-wrong-ack", hold + logs, "state on\n"},
		{"up-before-subscriptions", hold + ">UPDOWN:UP\r\n", "state on\n"},
		{"log-error", hold + state + "ERROR: rejected\r\n", "state on\nlog on\n"},
		{"release-error", hold + state + logs + "ERROR: rejected\r\n", "state on\nlog on\nhold release\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sent strings.Builder
			err := initializeOpenVPNManagement(bufio.NewScanner(iotest.OneByteReader(strings.NewReader(tc.transcript))), &sent)
			if err == nil {
				t.Fatal("incomplete or unsolicited startup transcript accepted")
			}
			if sent.String() != tc.sent {
				t.Fatalf("network startup advanced before acknowledgement: got %q, want %q", sent.String(), tc.sent)
			}
		})
	}
}

func TestWindowsOpenVPNRenderingKeepsNetworkingInSupervisor(t *testing.T) {
	p := workvpn.Profile{Options: []workvpn.Option{{Key: "client"}, {Key: "dev", Args: []string{"tun"}}, {Key: "dhcp-option", Args: []string{"DNS", "10.42.0.1"}}, {Key: "persist-tun"}, {Key: "nobind"}, {Key: "remote-cert-tls", Args: []string{"server"}}}, Inline: map[string]string{"ca": "fixture-ca"}}
	config := renderWindowsOpenVPN(p, workvpn.Remote{Port: 1194, Protocol: "udp"}, "192.0.2.1", "192.0.2.2", "v443w12345678", "127.0.0.1:30123", `C:\ProgramData\Vault443\private password`)
	for _, required := range []string{"windows-driver wintun\n", "local 192.0.2.2\nlport 0\n", "route-noexec\n", "ifconfig-noexec\n", "ip-win32 manual\n", "script-security 0\n", "management-client\n", "management-up-down\n", "pull-filter ignore \"dhcp-option\"", "remote-cert-tls \"server\""} {
		if !strings.Contains(config, required) {
			t.Fatalf("missing fixed setting %q", required)
		}
	}
	for _, forbidden := range []string{"persist-tun\n", "nobind\n", "dhcp-option \"DNS\"", "\nup ", "\ndown ", "script-security 2"} {
		if strings.Contains(config, forbidden) {
			t.Fatalf("unexpected engine-owned operation %q", forbidden)
		}
	}
}
func TestWindowsOpenVPNAuthenticatedPushNetworkFields(t *testing.T) {
	n := openVPNNetwork{}
	found, err := parseWindowsOpenVPNPush(">LOG:1793952000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.42.0.1,dhcp-option DOMAIN-ROUTE Corp.Example,redirect-gateway def1 ipv6,auth-token must-never-be-logged'", &n)
	if err != nil || !found || !n.full4 || !n.full6 {
		t.Fatalf("policy rejected: %v", err)
	}
	if len(n.dnsServers) != 1 || n.dnsServers[0] != "10.42.0.1" || len(n.dnsDomains) != 1 || n.dnsDomains[0] != "corp.example" {
		t.Fatalf("incorrect DNS policy: %#v", n)
	}
	for _, bad := range []string{
		">LOG:1793952000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 127.0.0.1'",
		">LOG:1793952000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 224.0.0.1'",
		">LOG:1793952000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DOMAIN corp.example\nup evil'",
		">LOG:1793952000,I,PUSH: Received control message: 'PUSH_REPLY,redirect-gateway unsupported'",
		">LOG:1793952000,I,PUSH: Received control message: 'PUSH_REPLY,dns server 0 address 1.1.1.1'",
	} {
		copy := openVPNNetwork{}
		if _, err := parseWindowsOpenVPNPush(bad, &copy); err == nil {
			t.Fatalf("unsafe network metadata accepted: %q", bad)
		}
	}
}
func TestWindowsOpenVPNMetadataCannotSelectAnotherAdapter(t *testing.T) {
	env := map[string]string{"dev": "v443w12345678", "tun_mtu": "1400", "ifconfig_local": "10.42.0.2", "ifconfig_netmask": "255.255.255.0", "ifconfig_ipv6_local": "fd42::2", "ifconfig_ipv6_netbits": "64", "route_network_1": "10.99.0.0", "route_netmask_1": "255.255.0.0"}
	n, err := parseWindowsOpenVPNNetwork(env, "v443w12345678", openVPNNetwork{dnsServers: []string{"10.42.0.1"}, dnsDomains: []string{"corp.example"}, full4: true, full6: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(n.addresses) != 2 || n.addresses[0] != netip.MustParsePrefix("10.42.0.2/24") {
		t.Fatalf("wrong addresses: %v", n.addresses)
	}
	prefixes := map[string]bool{}
	for _, r := range n.routes {
		prefixes[r.CIDR] = true
		if r.Gateway != "" {
			t.Fatal("Wintun route must remain on-link")
		}
	}
	for _, prefix := range []string{"10.99.0.0/16", "10.42.0.1/32", "0.0.0.0/0", "::/0"} {
		if !prefixes[prefix] {
			t.Errorf("missing protected prefix %s", prefix)
		}
	}
	env["dev"] = "foreign-adapter"
	if _, err = parseWindowsOpenVPNNetwork(env, "v443w12345678", openVPNNetwork{}); err == nil {
		t.Fatal("foreign interface metadata accepted")
	}
}

func windowsOpenVPNRedirectEnvironment() map[string]string {
	return map[string]string{
		"dev": "v443w12345678", "tun_mtu": "1400",
		"ifconfig_local": "10.77.0.2", "ifconfig_netmask": "255.255.255.0",
		"ifconfig_ipv6_local": "fd77:443::1000", "ifconfig_ipv6_netbits": "64",
		"route_ipv6_network_1": "::/3", "route_ipv6_network_2": "2000::/4",
		"route_ipv6_network_3": "3000::/4", "route_ipv6_network_4": "fc00::/7",
		"route_network_1": "10.77.8.0", "route_netmask_1": "255.255.255.0",
	}
}

func windowsOpenVPNFullConflict(n openVPNNetwork) *Manager {
	return &Manager{sessions: map[string]*session{
		"wg": {ID: "wg", Kind: "wireguard", Interface: "v443w00000001", Order: 1, Active: true,
			Routes:       []route{{CIDR: "0.0.0.0/0"}, {CIDR: "::/0"}},
			PeerPrefixes: map[string][]string{"peer": {"0.0.0.0/0", "::/0"}}, PeerReady: map[string]bool{"peer": true}},
		"ovpn": {ID: "ovpn", Kind: "openvpn", Interface: "v443w00000002", Order: 2, Active: true, Routes: n.routes},
	}}
}

func TestWindowsOpenVPNRedirectIPv6RetainsIncumbent(t *testing.T) {
	policy, _, err := windowsOpenVPNPolicy([]workvpn.Option{{Key: "redirect-gateway", Args: []string{"def1", "ipv6"}}, {Key: "dhcp-option", Args: []string{"DNS6", "fd77:443::1"}}})
	if err != nil {
		t.Fatal(err)
	}
	env := windowsOpenVPNRedirectEnvironment()
	env["route_ipv6_network_5"] = "fd77:443:8::/64"
	n, err := parseWindowsOpenVPNNetwork(env, env["dev"], policy)
	if err != nil {
		t.Fatal(err)
	}
	prefixes := map[string]bool{}
	for _, r := range n.routes {
		prefixes[r.CIDR] = true
	}
	for _, generated := range []string{"::/3", "2000::/4", "3000::/4", "fc00::/7"} {
		if prefixes[generated] {
			t.Errorf("generated redirect range became more-specific policy: %s", generated)
		}
	}
	for _, retained := range []string{"::/0", "0.0.0.0/0", "10.77.8.0/24", "fd77:443::/64", "fd77:443:8::/64", "fd77:443::1/128"} {
		if !prefixes[retained] {
			t.Errorf("explicit/connected/DNS/full policy lost: %s", retained)
		}
	}
	snapshot := network.Snapshot{}
	m := windowsOpenVPNFullConflict(n)
	rows := effectiveWindowsRoutes(m.choose(snapshot), snapshot)
	for _, ip := range []string{"93.184.215.14", "2001:db8:66::14", "3001::1", "fc42::1", "100::1"} {
		if target, active := partitionTarget(t, rows, ip); target != "wg" || !active {
			t.Errorf("generated redirect defeated incumbent for %s: target=%s active=%v", ip, target, active)
		}
	}
}

func TestWindowsOpenVPNRedirectIPv6PreservesExplicitClientAndPush(t *testing.T) {
	for _, source := range []string{"client", "push"} {
		for _, explicit := range []string{"::/3", "2000::/4", "3000::/4", "fc00::/7", "2001:db8:66::/64"} {
			t.Run(source+"/"+explicit, func(t *testing.T) {
				options := []workvpn.Option{{Key: "redirect-gateway", Args: []string{"def1", "ipv6"}}}
				if source == "client" {
					options = append(options, workvpn.Option{Key: "route-ipv6", Args: []string{explicit}})
				}
				policy, _, err := windowsOpenVPNPolicy(options)
				if err != nil {
					t.Fatal(err)
				}
				if source == "push" {
					found, err := parseWindowsOpenVPNPush(">LOG:1793952000,I,PUSH: Received control message: 'PUSH_REPLY,route-ipv6 "+explicit+",redirect-gateway def1 ipv6'", &policy)
					if err != nil || !found {
						t.Fatalf("authenticated explicit PUSH rejected: %v", err)
					}
				}
				env := windowsOpenVPNRedirectEnvironment()
				env["route_ipv6_network_5"] = explicit
				n, err := parseWindowsOpenVPNNetwork(env, env["dev"], policy)
				if err != nil {
					t.Fatal(err)
				}
				found := 0
				for _, r := range n.routes {
					if r.CIDR == explicit {
						found++
					}
				}
				if found != 1 {
					t.Fatalf("explicit route lost or duplicated: %s count=%d", explicit, found)
				}
				if explicit == "2001:db8:66::/64" {
					snapshot := network.Snapshot{}
					m := windowsOpenVPNFullConflict(n)
					rows := effectiveWindowsRoutes(m.choose(snapshot), snapshot)
					if target, active := partitionTarget(t, rows, "2001:db8:66::14"); target != "ovpn" || !active {
						t.Fatalf("explicit specific policy no longer overrides default: %s active=%v", target, active)
					}
					if target, active := partitionTarget(t, rows, "2001:db8:77::14"); target != "wg" || !active {
						t.Fatalf("explicit policy leaked beyond its prefix: %s active=%v", target, active)
					}
				}
			})
		}
	}
}

func TestWindowsOpenVPNIPv6RoutesWithoutRedirectRemainExplicit(t *testing.T) {
	env := windowsOpenVPNRedirectEnvironment()
	n, err := parseWindowsOpenVPNNetwork(env, env["dev"], openVPNNetwork{})
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"::/3", "2000::/4", "3000::/4", "fc00::/7"} {
		found := false
		for _, r := range n.routes {
			found = found || r.CIDR == prefix
		}
		if !found {
			t.Errorf("non-redirect IPv6 route discarded: %s", prefix)
		}
	}
}
