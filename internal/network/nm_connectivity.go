//go:build linux

package network

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/godbus/dbus/v5"
)

const nmName = "org.freedesktop.NetworkManager"
const nmRegisteredMessage = "NetworkManager connectivity checks now use the VPN tunnel; direct Internet remains blocked"

type nmSettings map[string]map[string]dbus.Variant

type nmConnectivity struct {
	key, state, message string
	nextCheck           time.Time
}

func (m *Manager) nmReport(state, message string) {
	if m.nm.state != state || m.nm.message != message {
		m.nm.state, m.nm.message = state, message
		m.logSession.Log("info", message)
		m.publish()
	}
}

// Queue immutable core identity; D-Bus work never holds the manager/kernel locks.
func (m *Manager) syncNetworkManager(ctx context.Context, s Snapshot) {
	if m.config.DryRun || !m.core.Alive() {
		return
	}
	link, ok := s.Link(TunName)
	if !ok || link.Kind != "tun" || !m.v4.IsValid() {
		return
	}
	peer := m.v4.Addr().Next()
	m.nmSync.Update([]NMTunnel{{ID: "main", Interface: TunName, Index: link.Index,
		Address: m.v4, Gateway: peer, Enabled: true, DNS: []string{peer.String()}, Domains: []string{"~."}}})
}

func (m *Manager) resetNM() {
	m.nmSync.Update(nil)
	m.nm = nmConnectivity{state: "inactive"}
}

func nmProperty(ctx context.Context, obj dbus.BusObject, iface, name string, target any) error {
	var value dbus.Variant
	if err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, name).Store(&value); err != nil {
		return err
	}
	return value.Store(target)
}

func nmHasDefault(s Snapshot, gateway netip.Addr) bool {
	for _, r := range s.Routes {
		if r.Family == 4 && r.Device == TunName && r.Destination == "default" &&
			r.Gateway == gateway.String() && (len(r.Table) == 0 || string(r.Table) == `"main"` || string(r.Table) == "254") {
			return true
		}
	}
	return false
}

func nmTunnelSettings(original nmSettings, address netip.Prefix) (nmSettings, error) {
	peer := address.Addr().Next()
	return nmDesiredSettings(original, NMTunnel{Interface: TunName, Address: address,
		Gateway: peer, Enabled: true, DNS: []string{peer.String()}, Domains: []string{"~."}})
}

// Only modern IP data round-trips safely through godbus (legacy IPv6 tuples do
// not). The input snapshot and unrelated routes/settings remain untouched.
func nmDesiredSettings(original nmSettings, t NMTunnel) (nmSettings, error) {
	conn, ip := original["connection"], original["ipv4"]
	if !t.Address.IsValid() || !t.Address.Addr().Is4() || !t.Gateway.Is4() ||
		conn["interface-name"].Value() != t.Interface || conn["type"].Value() != "tun" || ip["method"].Value() != "manual" {
		return nil, errors.New("not an owned TUN connection")
	}
	var addresses []map[string]dbus.Variant
	matches := func(p netip.Prefix) bool {
		return p.IsValid() && len(addresses) == 1 && addresses[0]["address"].Value() == p.Addr().String() && addresses[0]["prefix"].Value() == uint32(p.Bits())
	}
	if err := ip["address-data"].Store(&addresses); err != nil || (!matches(t.Address) && !matches(t.previousAddress)) {
		return nil, errors.New("unexpected TUN address")
	}
	out := make(nmSettings, len(original))
	for section, values := range original {
		out[section] = make(map[string]dbus.Variant, len(values))
		for name, value := range values {
			out[section][name] = value
		}
	}
	for _, section := range []string{"ipv4", "ipv6"} {
		delete(out[section], "addresses")
		delete(out[section], "routes")
	}
	v4 := out["ipv4"]
	var routes []map[string]dbus.Variant
	if value, ok := v4["route-data"]; ok {
		if err := value.Store(&routes); err != nil {
			return nil, errors.New("unexpected route data")
		}
	}
	retained := make([]map[string]dbus.Variant, 0, len(routes)+1)
	for _, r := range routes {
		if nmOwnDefault(r, t.Gateway) {
			continue
		}
		retained = append(retained, r)
	}
	if t.Enabled {
		v4["address-data"] = dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant(t.Address.Addr().String()), "prefix": dbus.MakeVariant(uint32(t.Address.Bits()))}})
		retained = append(retained, map[string]dbus.Variant{
			"dest": dbus.MakeVariant("0.0.0.0"), "prefix": dbus.MakeVariant(uint32(0)),
			"next-hop": dbus.MakeVariant(t.Gateway.String()), "metric": dbus.MakeVariant(uint32(0)),
		})
		v4["never-default"] = dbus.MakeVariant(false)
		v4["route-metric"] = dbus.MakeVariant(int64(0))
		v4["route-table"] = dbus.MakeVariant(uint32(254))
	}
	if !t.preserveDNS {
		var dns4 []uint32
		var dns6 [][]byte
		for _, raw := range t.DNS {
			address, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, errors.New("unexpected DNS address")
			}
			if address.Is4() {
				b := address.As4()
				dns4 = append(dns4, binary.NativeEndian.Uint32(b[:]))
			} else {
				b := address.As16()
				dns6 = append(dns6, append([]byte(nil), b[:]...))
			}
		}
		if dns4 == nil {
			dns4 = []uint32{}
		}
		if dns6 == nil {
			dns6 = [][]byte{}
		}
		v4["dns"] = dbus.MakeVariant(dns4)
		domains := append([]string{}, t.Domains...)
		v4["dns-search"] = dbus.MakeVariant(domains)
		if v6 := out["ipv6"]; v6 != nil && (v6["method"].Value() == "manual" || v6["method"].Value() == "auto" || v6["method"].Value() == "dhcp") {
			out["ipv6"]["dns"] = dbus.MakeVariant(dns6)
			out["ipv6"]["dns-search"] = dbus.MakeVariant(domains)
		} else if len(dns6) > 0 {
			return nil, errors.New("NetworkManager IPv6 method cannot preserve the selected DNS servers")
		}
	}
	// Cleanup removes only our exact default. DNS stays attached to persistent
	// work TUNs during recovery so corporate requests cannot fall back outside.
	v4["route-data"] = dbus.MakeVariant(retained)
	return out, nil
}
func nmOwnDefault(r map[string]dbus.Variant, gateway netip.Addr) bool {
	return r["dest"].Value() == "0.0.0.0" && r["prefix"].Value() == uint32(0) &&
		r["next-hop"].Value() == gateway.String() && r["metric"].Value() == uint32(0)
}
