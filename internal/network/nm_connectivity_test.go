package network

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"
)

func nmSettingsFixture() nmSettings {
	return nmSettings{
		"connection": {"interface-name": dbus.MakeVariant(TunName), "type": dbus.MakeVariant("tun"), "autoconnect": dbus.MakeVariant(false), "uuid": dbus.MakeVariant("unchanged")},
		"ipv4":       {"method": dbus.MakeVariant("manual"), "address-data": dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant("198.18.4.1"), "prefix": dbus.MakeVariant(uint32(30))}}), "addresses": dbus.MakeVariant([][]uint32{{0, 30, 0}}), "routes": dbus.MakeVariant([][]uint32{}), "route-data": dbus.MakeVariant([]map[string]dbus.Variant{{"dest": dbus.MakeVariant("10.0.0.0"), "prefix": dbus.MakeVariant(uint32(24))}})},
		"ipv6":       {"method": dbus.MakeVariant("manual"), "address-data": dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant("fd56:4c54::1"), "prefix": dbus.MakeVariant(uint32(64))}}), "addresses": dbus.MakeVariant([][]any{}), "routes": dbus.MakeVariant([][]any{}), "route-data": dbus.MakeVariant([]map[string]dbus.Variant{})},
	}
}

func TestNMTunnelSettingsPreservesIdentityAndModernIPData(t *testing.T) {
	before := nmSettingsFixture()
	got, err := nmTunnelSettings(before, netip.MustParsePrefix("198.18.4.1/30"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got["connection"], before["connection"]) || !reflect.DeepEqual(got["ipv6"]["address-data"], before["ipv6"]["address-data"]) {
		t.Fatal("changed tunnel identity or IPv6 address")
	}
	if _, ok := before["ipv6"]["addresses"]; !ok {
		t.Fatal("modified input snapshot")
	}
	for _, section := range []string{"ipv4", "ipv6"} {
		for _, legacy := range []string{"addresses", "routes"} {
			if _, ok := got[section][legacy]; ok {
				t.Fatalf("retained ambiguous %s.%s", section, legacy)
			}
		}
	}
	var routes []map[string]dbus.Variant
	if err := got["ipv4"]["route-data"].Store(&routes); err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0]["dest"].Value() != "10.0.0.0" || routes[1]["next-hop"].Value() != "198.18.4.2" || got["ipv4"]["route-table"].Value() != uint32(254) {
		t.Fatal("lost route or wrong NM default", routes)
	}
	var dns []uint32
	if err := got["ipv4"]["dns"].Store(&dns); err != nil {
		t.Fatal(err)
	}
	var encoded [4]byte
	binary.NativeEndian.PutUint32(encoded[:], dns[0])
	if netip.AddrFrom4(encoded).String() != "198.18.4.2" {
		t.Fatal("wrong DNS byte order")
	}
	twice, err := nmTunnelSettings(got, netip.MustParsePrefix("198.18.4.1/30"))
	if err != nil || !reflect.DeepEqual(got, twice) {
		t.Fatal("registration is not idempotent", err)
	}
	if sig := dbus.SignatureOf(got).String(); sig != "a{sa{sv}}" {
		t.Fatal(sig)
	}
}

func TestNMTunnelSettingsRejectsForeignProfiles(t *testing.T) {
	for _, mutation := range []struct {
		section, key string
		value        any
	}{
		{"connection", "interface-name", "tun0"}, {"connection", "type", "ethernet"}, {"ipv4", "method", "auto"},
		{"ipv4", "address-data", []map[string]dbus.Variant{{"address": dbus.MakeVariant("192.0.2.2"), "prefix": dbus.MakeVariant(uint32(24))}}},
	} {
		input := nmSettingsFixture()
		input[mutation.section][mutation.key] = dbus.MakeVariant(mutation.value)
		if _, err := nmTunnelSettings(input, netip.MustParsePrefix("198.18.4.1/30")); err == nil {
			t.Fatalf("accepted foreign %s.%s", mutation.section, mutation.key)
		}
	}
	if _, err := nmTunnelSettings(nil, netip.Prefix{}); err == nil {
		t.Fatal("accepted missing profile")
	}
}

func TestNMDefaultDetectionDoesNotConfusePrivateOrForeignRoutes(t *testing.T) {
	gateway := netip.MustParseAddr("198.18.4.2")
	r := Route{Family: 4, Destination: "default", Device: TunName, Gateway: gateway.String()}
	if !nmHasDefault(Snapshot{Routes: []Route{r}}, gateway) {
		t.Fatal("missed own main default")
	}
	r.Table = json.RawMessage(`52780`)
	if nmHasDefault(Snapshot{Routes: []Route{r}}, gateway) {
		t.Fatal("mistook private table for NM default")
	}
	r.Table = nil
	r.Device = "eth0"
	if nmHasDefault(Snapshot{Routes: []Route{r}}, gateway) {
		t.Fatal("accepted foreign default")
	}
}

func TestNMSyncIsInertWithoutLiveCoreAndInDryRun(t *testing.T) {
	for _, dry := range []bool{false, true} {
		m := New(Config{DryRun: dry})
		m.syncNetworkManager(context.Background(), fixture())
		if m.nm.state != "inactive" || !m.nm.nextCheck.IsZero() {
			t.Fatal("attempted NM access without live core")
		}
	}
}

func TestNMTunnelSettingsAcceptsNewNMAutoconnectDefault(t *testing.T) {
	input := nmSettingsFixture()
	delete(input["connection"], "autoconnect")
	if _, err := nmTunnelSettings(input, netip.MustParsePrefix("198.18.4.1/30")); err != nil {
		t.Fatal(err)
	}
}
