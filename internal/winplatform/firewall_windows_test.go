package winplatform

import (
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/tailscale/wf"
)

// Composer tests never install filters or change the host firewall.
func composedGuard(t *testing.T) []*wf.Rule {
	t.Helper()
	app, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	g := &Guard{parts: map[string]GuardPart{
		"main": {
			BlockAll: true, Default4: 11, Default6: 12,
			PrivatePorts: []PrivatePort{{Port: 10801, App: app}},
			Endpoints: []Endpoint{
				{Address: netip.MustParseAddr("192.0.2.1"), Port: 443, App: app, Interface: 3},
				{Address: netip.MustParseAddr("2001:db8::1"), Port: 443, App: app, Interface: 3},
			},
			Probe6: 4, ProbeApp: app, DNSPhysical: []uint64{3},
		},
		"work": {Routes: []GuardRoute{
			{Prefix: netip.MustParsePrefix("10.20.0.0/16"), Interface: 20},
			{Prefix: netip.MustParsePrefix("fd20::/48"), Interface: 21},
		}},
	}}
	rules, err := g.rules()
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func conditionValue(rule *wf.Rule, field wf.FieldID) any {
	for _, condition := range rule.Conditions {
		if condition.Field == field && condition.Op == wf.MatchTypeEqual {
			return condition.Value
		}
	}
	return nil
}

func TestGuardProtectsBothAuthorizationDirections(t *testing.T) {
	rules := composedGuard(t)
	for _, layer := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6, wf.LayerALEAuthRecvAcceptV4, wf.LayerALEAuthRecvAcceptV6} {
		var block, tunnel, route, routeBlock, endpoint, dns bool
		for _, rule := range rules {
			if rule.Layer != layer {
				continue
			}
			if !rule.Persistent || rule.BootTime {
				t.Fatalf("authorization rule is not persistent: %s", rule.Name)
			}
			switch {
			case rule.Action == wf.ActionBlock && len(rule.Conditions) == 0:
				block = true
			case strings.Contains(rule.Name, "main-tunnel"):
				tunnel = conditionValue(rule, wf.FieldIPLocalInterface) != nil
			case strings.Contains(rule.Name, "work-route-block"):
				routeBlock = rule.Action == wf.ActionBlock && conditionValue(rule, wf.FieldIPRemoteAddress) != nil
			case strings.Contains(rule.Name, "work-route-"):
				route = rule.Action == wf.ActionPermit && conditionValue(rule, wf.FieldIPRemoteAddress) != nil && conditionValue(rule, wf.FieldIPLocalInterface) != nil
			case strings.Contains(rule.Name, "main-endpoint"):
				endpoint = rule.Action == wf.ActionPermit && conditionValue(rule, wf.FieldALEAppID) != nil && conditionValue(rule, wf.FieldALEUserID) != nil && conditionValue(rule, wf.FieldIPLocalInterface) == uint64(3) && conditionValue(rule, wf.FieldIPRemotePort) == uint16(443)
			case strings.Contains(rule.Name, "dns-block"):
				dns = rule.Action == wf.ActionBlock && conditionValue(rule, wf.FieldIPRemotePort) != nil
			}
		}
		if !block || !tunnel || !route || !routeBlock || !endpoint || !dns {
			t.Errorf("incomplete layer %v: block=%t tunnel=%t route=%t fallbackBlock=%t endpoint=%t DNS=%t", layer, block, tunnel, route, routeBlock, endpoint, dns)
		}
	}
}

func TestGuardRuleIDsUniqueAndBootBlocksNotDuplicated(t *testing.T) {
	rules := composedGuard(t)
	ids := make(map[wf.RuleID]bool)
	boot := make(map[wf.LayerID]int)
	for _, rule := range rules {
		if ids[rule.ID] {
			t.Fatalf("duplicate WFP rule ID: %s", rule.Name)
		}
		ids[rule.ID] = true
		if rule.BootTime {
			if rule.Persistent || rule.Action != wf.ActionBlock {
				t.Fatalf("invalid boot protection: %s", rule.Name)
			}
			boot[rule.Layer]++
		}
		if strings.Contains(rule.Name, "private-") && rule.Layer != wf.LayerALEAuthConnectV4 {
			t.Fatalf("client-only loopback ACL applied to receiving helper: %s", rule.Name)
		}
	}
	if !reflect.DeepEqual(boot, map[wf.LayerID]int{wf.LayerOutboundIPPacketV4: 2, wf.LayerOutboundIPPacketV6: 2}) {
		t.Fatalf("boot blocks were lost or duplicated across ALE directions: %v", boot)
	}
	for i, rule := range composedGuard(t) {
		if rule.ID != rules[i].ID {
			t.Fatalf("unstable rule identity at index %d", i)
		}
	}
}

func TestGuardIPv6ControlDoesNotPermitEcho(t *testing.T) {
	rules := composedGuard(t)
	allowedTypes := map[uint16]bool{130: true, 131: true, 132: true, 133: true, 134: true, 135: true, 136: true, 137: true, 143: true}
	for _, layer := range []wf.LayerID{wf.LayerALEAuthConnectV6, wf.LayerALEAuthRecvAcceptV6} {
		seen := map[uint16]int{}
		for _, rule := range rules {
			if rule.Layer != layer || rule.Action != wf.ActionPermit || conditionValue(rule, wf.FieldIPProtocol) != wf.IPProtoICMPV6 {
				continue
			}
			kind, ok := conditionValue(rule, wf.FieldIPLocalPort).(uint16)
			prefix, prefixOK := conditionValue(rule, wf.FieldIPRemoteAddress).(netip.Prefix)
			if !ok || !allowedTypes[kind] || conditionValue(rule, wf.FieldIPRemotePort) != uint16(0) || !prefixOK || (prefix.String() != "fe80::/10" && prefix.String() != "ff02::/16") {
				t.Fatalf("unscoped IPv6 control permit: %+v", rule)
			}
			seen[kind]++
		}
		for kind := range allowedTypes {
			if seen[kind] != 2 {
				t.Fatalf("ND/MLD %d missing link-local/multicast scopes on %v: %v", kind, layer, seen)
			}
		}
		for _, echo := range []uint16{128, 129} {
			if seen[echo] != 0 {
				t.Fatalf("echo %d can bypass disabled LAN access", echo)
			}
		}
	}
}

func TestGuardDHCPSurvivesInboundProtection(t *testing.T) {
	rules := composedGuard(t)
	for layer, ports := range map[wf.LayerID][2]uint16{
		wf.LayerALEAuthConnectV4: {68, 67}, wf.LayerALEAuthRecvAcceptV4: {68, 67},
		wf.LayerALEAuthConnectV6: {546, 547}, wf.LayerALEAuthRecvAcceptV6: {546, 547},
	} {
		found := false
		for _, rule := range rules {
			if rule.Layer == layer && strings.Contains(rule.Name, "dhcp-") {
				found = rule.Action == wf.ActionPermit && conditionValue(rule, wf.FieldIPProtocol) == wf.IPProtoUDP && conditionValue(rule, wf.FieldALEAppID) != nil && conditionValue(rule, wf.FieldIPLocalPort) == ports[0] && conditionValue(rule, wf.FieldIPRemotePort) == ports[1]
			}
		}
		if !found {
			t.Errorf("missing scoped DHCP client exception on %v", layer)
		}
	}
}
