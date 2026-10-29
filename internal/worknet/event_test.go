package worknet

import (
	"strings"
	"testing"
	"vault443/internal/workvpn"
)

func eventEnv() map[string]string {
	return map[string]string{"dev": "v443w12345678", "script_type": "route-up", "ifconfig_local": "10.70.0.7", "ifconfig_remote": "255.255.255.0", "ifconfig_netmask": "255.255.255.0", "route_vpn_gateway": "10.70.0.1", "route_network_1": "192.168.0.0", "route_netmask_1": "255.255.0.0", "route_gateway_1": "10.70.0.1", "foreign_option_1": "dhcp-option DNS 10.70.0.1", "foreign_option_2": "dhcp-option DOMAIN corp.test"}
}
func TestParseActualHookMetadata(t *testing.T) {
	e, err := parseEvent(eventEnv())
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Routes) != 1 || e.Routes[0].CIDR != "192.168.0.0/16" || e.DNSServers[0] != "10.70.0.1" || e.Gateway4 != "10.70.0.1" {
		t.Fatalf("%+v", e)
	}
}
func TestEventRejectsInvalidNetworkData(t *testing.T) {
	for _, bad := range []map[string]string{{"dev": "eth0"}, {"route_netmask_1": "255.0.255.0"}, {"route_gateway_1": "--evil"}, {"foreign_option_1": "dhcp-option DNS 127.0.0.1"}, {"foreign_option_2": "dhcp-option DOMAIN --evil;run"}, {"tun_mtu": "999999"}, {"ifconfig_ipv6_local": "fd00::1"}} {
		e := eventEnv()
		for k, v := range bad {
			e[k] = v
		}
		if _, err := parseEvent(e); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}
func TestConfigOnlyFixedControlHooks(t *testing.T) {
	p := workvpn.Profile{Options: []workvpn.Option{{Key: "client"}, {Key: "dev", Args: []string{"tun"}}, {Key: "verb", Args: []string{"9"}}}, Inline: map[string]string{"key": "TEST-KEY"}}
	c := render(p, workvpn.Remote{Host: "vpn.example", Port: 1194, Protocol: "udp"}, "192.0.2.1", "v443w12345678", "/run/work/m", "/run/work/e", "secret", "/usr/sbin/vault443d")
	for _, want := range []string{"route-noexec", "ifconfig-noexec", "up \"/usr/sbin/vault443d --openvpn-event\"", "management-client", "disable-dco", "remote 192.0.2.1 1194 udp"} {
		if !strings.Contains(c, want) {
			t.Fatal(want, c)
		}
	}
	if strings.Contains(c, "management-log-cache 0") || strings.Contains(c, "verb \"9\"") || strings.Contains(c, "dev tun\n") {
		t.Fatal(c)
	}
}
func TestPushedRedirectMetadataIsStrictAndDoesNotExtractSecrets(t *testing.T) {
	f, v4, v6, e := pushedRedirect(">LOG:123,I,PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0,redirect-gateway def1 ipv6,auth-token secret'")
	if e != nil || !f || !v4 || !v6 {
		t.Fatal(f, v4, v6, e)
	}
	for _, line := range []string{"stdout PUSH_REPLY,redirect-gateway def1", ">LOG:123,I,CN=PUSH_REPLY,redirect-gateway def1", ">LOG:bad,I,PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1'"} {
		f, _, _, _ := pushedRedirect(line)
		if f {
			t.Fatal("forged event accepted")
		}
	}
	for _, line := range []string{">LOG:123,I,PUSH: Received control message: 'PUSH_REPLY,redirect-gateway unknown'", ">LOG:123,I,PUSH: Received control message: 'PUSH_REPLY,redirect-gateway,redirect-gateway def1'", ">LOG:123,I,PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,,route 10.0.0.1'"} {
		_, _, _, err := pushedRedirect(line)
		if err == nil {
			t.Fatal("malformed metadata accepted")
		}
	}
	f, v4, v6, e = pushedRedirect(">LOG:123,I,PUSH: Received control message: 'PUSH_REPLY,redirect-gateway ipv6 !ipv4'")
	if e != nil || !f || v4 || !v6 {
		t.Fatal("IPv6-only redirect", f, v4, v6, e)
	}
}
func TestSensitiveOutputNeverJournaled(t *testing.T) {
	for _, s := range []string{"PUSH_REPLY,auth-token value", ">PASSWORD:Auth-Token:value", "auth_token = value", "VAULT443_EVENT_TOKEN=value", "PUSH_CONTINUATION,2"} {
		if !sensitiveOpenVPNLine(s) {
			t.Fatal(s)
		}
	}
	if sensitiveOpenVPNLine("TLS certificate verification failed") {
		t.Fatal("lost diagnostic")
	}
}
