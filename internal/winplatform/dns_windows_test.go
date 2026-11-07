package winplatform

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestOwnedDNSRejectsForeignAdapters(t *testing.T) {
	for _, alias := range []string{"Ethernet", "v443-main-other", "v443w12345678-extra", "v443w1234567", "external-vpn"} {
		if ownedDNSIdentity(alias, "Wintun Userspace Tunnel") {
			t.Fatalf("foreign adapter accepted for DNS mutation: %s", alias)
		}
	}
	if ownedDNSIdentity("v443-main", "Ethernet") || !ownedDNSIdentity("v443-main", "Wintun Userspace Tunnel") || !ownedDNSIdentity("v443w609a02e3", "Wintun Userspace Tunnel") {
		t.Fatal("owned Wintun DNS boundary changed")
	}
}

func TestUnderlayDNSRenewalReplacesCachedLease(t *testing.T) {
	for _, tc := range []struct {
		old, renewed, fixed string
		v6                  bool
	}{
		{"192.0.2.53", "192.0.2.54", "192.0.2.55", false},
		{"2001:db8::53", "2001:db8::54", "2001:db8::55", true},
	} {
		old := []netip.Addr{netip.MustParseAddr(tc.old)}
		renewed := []netip.Addr{netip.MustParseAddr(tc.renewed)}
		got := selectUnderlayDNS("", renewed, true, old, tc.v6)
		if !reflect.DeepEqual(got, renewed) {
			t.Fatalf("renewal retained old lease: %v", got)
		}
		backup := dnsBackup{NameServer: tc.fixed}
		got = selectUnderlayDNS(backup.NameServer, renewed, true, old, tc.v6)
		if !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr(tc.fixed)}) || backup.NameServer != tc.fixed {
			t.Fatalf("DHCP changed original static configuration: %v %+v", got, backup)
		}
		if got := selectUnderlayDNS("", nil, true, old, tc.v6); len(got) != 0 {
			t.Fatalf("empty DHCP list reused old network resolver: %v", got)
		}
	}
}

func TestUnderlayDNSRejectsCoordinatorAndWrongFamily(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		got := selectUnderlayDNS("", nil, false, []netip.Addr{
			netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"),
			netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("ff02::1"),
			netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53"),
		}, v6)
		if len(got) != 1 || got[0].Is6() != v6 {
			t.Fatalf("invalid fallback family/coordinator: %v", got)
		}
	}
}

func TestMainProtectionStillBlocksRefreshedUnderlayDNS(t *testing.T) {
	checked := false
	d := &DNS{
		plans: map[string]DNSPlan{}, fallback: []netip.Addr{netip.MustParseAddr("192.0.2.54")}, physical: 1,
		fallbackAllowed: func() bool { checked = true; return false },
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("test.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	request, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	response := d.query(context.Background(), request, false)
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil || !checked || header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("refreshed underlay bypassed main DNS protection: checked=%t header=%+v err=%v", checked, header, err)
	}
}
