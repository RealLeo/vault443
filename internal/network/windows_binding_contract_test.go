package network

import (
	"net/netip"
	"testing"
)

func TestWindowsBindingRejectsUnscopedBypass(t *testing.T) {
	for _, text := range []string{
		`{"interface":"Ethernet","manager":"openvpn","endpoints":[{"address":"1.1.1.1","port":443,"protocol":"tcp"}]}`,
		`{"interface":"corp","manager":"openvpn","unit":"Vault443","endpoints":[{"address":"1.1.1.1","port":443,"protocol":"tcp"}]}`,
		`{"interface":"corp","manager":"openvpn","unit":"OpenVPNService","endpoints":[{"address":"1.1.1.1","port":443,"protocol":"tcp","mark":5}]}`,
		`{"interface":"corp","manager":"openvpn","unit":"OpenVPNService","endpoints":[{"address":"1.1.1.1","port":443,"protocol":"tcp","sourcePort":1194}]}`,
		`{"interface":"corp","manager":"openvpn","routes":["0.0.0.0/0"]}`,
		`{"interface":"corp","manager":"openvpn","dnsServers":["10.0.0.1"],"dnsDomains":["corp; arbitrary"]}`,
		`{"interface":"corp","manager":"openvpn","dnsServers":["127.0.0.1"],"dnsDomains":["corp.example"]}`,
	} {
		if _, e := parseWindowsBinding(text); e == nil {
			t.Errorf("accepted unsafe binding: %s", text)
		}
	}
	b, e := parseWindowsBinding(`{"interface":"Corporate VPN 1","manager":"openvpn","unit":"OpenVPNService","routes":["10.1.2.3/8"],"dnsServers":["10.0.0.1"],"dnsDomains":["~Corp.Example."]}`)
	if e != nil || b.Routes[0] != "10.0.0.0/8" || b.DNSDomains[0] != "corp.example" {
		t.Fatalf("canonical binding: %+v %v", b, e)
	}
}
func TestExternalDefaultDNSClaimEndsWithTunnel(t *testing.T) {
	domains := externalDNSDomains([]string{"corp.example", "."}, nil)
	if len(domains) != 1 || domains[0] != "corp.example" {
		t.Fatalf("retained temporary full-tunnel DNS claim: %v", domains)
	}
	domains = externalDNSDomains([]string{"corp.example", "."}, []string{"."})
	if len(domains) != 2 || domains[1] != "." {
		t.Fatalf("discarded explicit administrator DNS claim: %v", domains)
	}
}
func TestWindowsFullTunnelNeedsComplementaryHalves(t *testing.T) {
	parse := func(s ...string) []netip.Prefix {
		var p []netip.Prefix
		for _, v := range s {
			p = append(p, netip.MustParsePrefix(v))
		}
		return p
	}
	if windowsClaimsDefault(parse("0.0.0.0/1", "0.0.0.0/1"), false) {
		t.Fatal("duplicate lower halves claimed a full tunnel")
	}
	if !windowsClaimsDefault(parse("0.0.0.0/1", "128.0.0.0/1"), false) || !windowsClaimsDefault(parse("::/1", "8000::/1"), true) {
		t.Fatal("complementary defaults were missed")
	}
	if windowsClaimsDefault(parse("0.0.0.0/0"), true) {
		t.Fatal("IPv4 default claimed IPv6")
	}
}

func TestWindowsOpenVPNFullIPv6RequiresExactRedirectSignature(t *testing.T) {
	parse := func(values ...string) []netip.Prefix {
		var prefixes []netip.Prefix
		for _, value := range values {
			prefixes = append(prefixes, netip.MustParsePrefix(value))
		}
		return prefixes
	}
	signature := []string{"::/3", "2000::/4", "3000::/4", "fc00::/7"}
	if !windowsClaimsDefault(parse(signature...), true) {
		t.Fatal("official OpenVPN IPv6 redirect routes were not classified as full")
	}
	if windowsClaimsDefault(parse(signature...), false) {
		t.Fatal("IPv6 OpenVPN redirect claimed IPv4")
	}
	// Route order, repeated rows and canonical host bits must not affect detection.
	if !windowsClaimsDefault(parse("fd00::1/7", "3001::1/4", "2001:db8::1/4", "100::1/3", "2000::/4"), true) {
		t.Fatal("canonicalized reordered/duplicated signature was missed")
	}
	for missing := range signature {
		var partial []string
		for i, prefix := range signature {
			if i != missing {
				partial = append(partial, prefix, prefix)
			}
		}
		if windowsClaimsDefault(parse(partial...), true) {
			t.Errorf("incomplete signature missing %s claimed full IPv6", signature[missing])
		}
	}
	for _, partial := range [][]string{
		{"2000::/4", "3000::/4"},
		{"::/4", "2000::/4", "3000::/4", "fc00::/7"},
		{"::/3", "2000::/5", "3000::/4", "fc00::/7"},
		{"::/3", "2000::/4", "3000::/4", "fc00::/8"},
		{"0.0.0.0/0", "2000::/4", "3000::/4", "fc00::/7"},
	} {
		if windowsClaimsDefault(parse(partial...), true) {
			t.Errorf("partial/near-miss routes claimed full IPv6: %v", partial)
		}
	}
}
