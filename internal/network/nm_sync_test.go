//go:build linux

package network

import (
	"context"
	"github.com/godbus/dbus/v5"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestNMOpenVPNGatewayDNSAndExactCleanup(t *testing.T) {
	original := nmSettingsFixture()
	target := NMTunnel{Interface: TunName, Address: netip.MustParsePrefix("198.18.4.1/30"), Gateway: netip.MustParseAddr("198.18.4.3"), DNS: []string{"10.77.100.1", "2001:db8::53"}, Domains: []string{"~corp.test", "~."}, Enabled: true}
	got, err := nmDesiredSettings(original, target)
	if err != nil {
		t.Fatal(err)
	}
	var routes []map[string]dbus.Variant
	_ = got["ipv4"]["route-data"].Store(&routes)
	if len(routes) != 2 || routes[1]["next-hop"].Value() != "198.18.4.3" {
		t.Fatal("gateway was guessed", routes)
	}
	foreign := map[string]dbus.Variant{"dest": dbus.MakeVariant("0.0.0.0"), "prefix": dbus.MakeVariant(uint32(0)), "next-hop": dbus.MakeVariant("198.18.4.2"), "metric": dbus.MakeVariant(uint32(50))}
	got["ipv4"]["route-data"] = dbus.MakeVariant(append(routes, foreign))
	target.Enabled = false
	cleaned, err := nmDesiredSettings(got, target)
	if err != nil {
		t.Fatal(err)
	}
	_ = cleaned["ipv4"]["route-data"].Store(&routes)
	if len(routes) != 2 || !reflect.DeepEqual(routes[1], foreign) {
		t.Fatal("removed unrelated route", routes)
	}
	for _, section := range []string{"ipv4", "ipv6"} {
		for _, key := range []string{"dns", "dns-search", "address-data"} {
			if !reflect.DeepEqual(cleaned[section][key], got[section][key]) {
				t.Fatal("cleanup released DNS or address", section, key)
			}
		}
	}
	target.Domains = []string{"~corp.test"}
	cleaned, err = nmDesiredSettings(got, target)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cleaned["ipv4"]["dns-search"].Value(), target.Domains) {
		t.Fatal("old Internet owner retained DNS root domain")
	}
}

func TestNMRefreshesOnlyPreviouslyVerifiedLease(t *testing.T) {
	target := NMTunnel{Interface: TunName, Address: netip.MustParsePrefix("198.18.4.5/30"), Gateway: netip.MustParseAddr("198.18.4.6"), Enabled: true}
	original := nmSettingsFixture()
	if _, err := nmDesiredSettings(original, target); err == nil {
		t.Fatal("accepted unknown old lease")
	}
	target.previousAddress = netip.MustParsePrefix("198.18.4.1/30")
	got, err := nmDesiredSettings(original, target)
	if err != nil {
		t.Fatal(err)
	}
	var addresses []map[string]dbus.Variant
	_ = got["ipv4"]["address-data"].Store(&addresses)
	if addresses[0]["address"].Value() != "198.18.4.5" {
		t.Fatal("old NM lease retained")
	}
	// Typical generated OpenVPN profile: IPv6 is initially link-local even
	// when a pushed IPv6 address has subsequently been assigned externally.
	original["ipv6"]["method"] = dbus.MakeVariant("link-local")
	target.DNS = []string{"10.70.0.1"}
	target.Domains = []string{"~."}
	got, err = nmDesiredSettings(original, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["ipv6"]["dns-search"]; ok {
		t.Fatal("invalid DNS on link-local method")
	}
	if !reflect.DeepEqual(original["ipv6"]["address-data"], got["ipv6"]["address-data"]) {
		t.Fatal("IPv6 address was changed")
	}
}

func TestNMSynchronizerCompensatesCancelledRemoteApply(t *testing.T) {
	n := NewNMSynchronizer(func(NMTunnel, NMResult) { t.Error("stale notification") })
	started, cleaned := make(chan struct{}), make(chan struct{})
	var inFlight atomic.Int32
	n.apply = func(ctx context.Context, target NMTunnel) NMResult {
		if inFlight.Add(1) != 1 {
			t.Error("parallel D-Bus mutation")
		}
		defer inFlight.Add(-1)
		if target.Enabled {
			close(started)
			<-ctx.Done()
			return NMResult{State: "registered"}
		}
		close(cleaned)
		return NMResult{State: "inactive"}
	}
	target := NMTunnel{ID: "work", Interface: "owned", Index: 3, Enabled: true}
	n.Update([]NMTunnel{target})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker not started")
	}
	before := time.Now()
	n.Update(nil)
	if time.Since(before) > 100*time.Millisecond {
		t.Fatal("cancellation waited for worker")
	}
	select {
	case <-cleaned:
	case <-time.After(time.Second):
		t.Fatal("cancelled remote result was not cleaned")
	}
}

func TestNMSynchronizerCleanupFailureBlocksNewOwner(t *testing.T) {
	n := NewNMSynchronizer(nil)
	calls := make(chan NMTunnel, 20)
	var fail atomic.Bool
	n.apply = func(_ context.Context, target NMTunnel) NMResult {
		calls <- target
		if !target.Enabled {
			if fail.Load() {
				return NMResult{State: "pending"}
			}
			return NMResult{State: "inactive"}
		}
		return NMResult{State: "registered"}
	}
	a := NMTunnel{ID: "a", Enabled: true}
	b := NMTunnel{ID: "b", Enabled: true}
	n.Update([]NMTunnel{a})
	<-calls
	fail.Store(true)
	n.Update([]NMTunnel{b})
	select {
	case got := <-calls:
		if got.ID != "a" || got.Enabled {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("missing cleanup")
	}
	select {
	case got := <-calls:
		t.Fatal("registered second owner before cleanup", got)
	case <-time.After(30 * time.Millisecond):
	}
	fail.Store(false)
	n.Update(nil)
	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("missing cleanup retry")
	}
}
