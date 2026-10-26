package network

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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

// syncNetworkManager advertises only our live, core-owned TUN. Ubuntu's
// connectivity checks bind their sockets to a device. Physical-interface checks
// must remain blocked by the guard; NM needs to check the tunnel instead.
//
// Reapply changes only the applied, volatile TUN connection. The main-table
// default makes NM account for it; our earlier policy rules still select all
// actual traffic, including transport exceptions and other VPNs. A next hop is
// necessary: Linux normalizes gateway-less IPv4 routes to scope link, which NM
// 1.46 refuses to probe. No firewall exception or global NM setting is added.
func (m *Manager) syncNetworkManager(ctx context.Context, s Snapshot) {
	if m.config.DryRun || !m.core.Alive() {
		return
	}
	link, ok := s.Link(TunName)
	if !ok || link.Kind != "tun" || !m.v4.IsValid() || time.Now().Before(m.nm.nextCheck) {
		return
	}
	m.nm.nextCheck = time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	bus, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		m.nmReport("unavailable", "NetworkManager integration unavailable; VPN protection is unchanged")
		return
	}
	defer bus.Close()
	var owner string
	if err = bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, nmName).Store(&owner); err != nil {
		m.nmReport("unavailable", "NetworkManager is not running; VPN protection is unchanged")
		return
	}
	var devicePath dbus.ObjectPath
	if err = bus.Object(owner, "/org/freedesktop/NetworkManager").CallWithContext(ctx, nmName+".GetDeviceByIpIface", 0, TunName).Store(&devicePath); err != nil {
		m.nmReport("pending", "Waiting for NetworkManager to recognize the VPN tunnel")
		return
	}
	device := bus.Object(owner, devicePath)
	var settings nmSettings
	var version uint64
	if err = device.CallWithContext(ctx, nmName+".Device.GetAppliedConnection", 0, uint32(0)).Store(&settings, &version); err != nil {
		m.nmReport("pending", "NetworkManager has not activated the external VPN tunnel yet")
		return
	}
	key := fmt.Sprintf("%s/%s/%d/%s", owner, devicePath, link.Index, m.v4)
	if m.nm.key == key && nmHasDefault(s, m.v4.Addr().Next()) {
		m.nmReport("registered", nmRegisteredMessage)
		return
	}
	// NM 1.54 omits autoconnect on assumed profiles (default true), unlike
	// 1.46. Generated + volatile flags, not that property, establish ownership.
	// Never adopt a user-created or persistent profile merely because its
	// interface is named vault4430. Require NM's generated, volatile connection.
	var activePath, connectionPath dbus.ObjectPath
	var flags uint32
	if nmProperty(ctx, device, nmName+".Device", "ActiveConnection", &activePath) != nil ||
		nmProperty(ctx, bus.Object(owner, activePath), nmName+".Connection.Active", "Connection", &connectionPath) != nil ||
		nmProperty(ctx, bus.Object(owner, connectionPath), nmName+".Settings.Connection", "Flags", &flags) != nil {
		m.nmReport("pending", "Cannot verify NetworkManager tunnel ownership yet")
		return
	}
	if flags&6 != 6 { // NM_GENERATED | VOLATILE
		m.nmReport("skipped", "NetworkManager tunnel profile is not generated and volatile; left unchanged")
		return
	}
	settings, err = nmTunnelSettings(settings, m.v4)
	if err != nil {
		m.nmReport("skipped", "NetworkManager tunnel identity differs from the running core; left unchanged")
		return
	}
	// Version guard rejects concurrent edits. Since NM 1.42, flag 1 preserves
	// external addresses/routes, notably the private policy-routing tables.
	if err = device.CallWithContext(ctx, nmName+".Device.Reapply", 0, settings, version, uint32(1)).Err; err != nil {
		m.nmReport("pending", "NetworkManager could not register the tunnel for connectivity checks; will retry")
		return
	}
	m.nm.key = key
	m.nmReport("registered", nmRegisteredMessage)
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
	conn, ip := original["connection"], original["ipv4"]
	if !address.IsValid() || !address.Addr().Is4() || conn["interface-name"].Value() != TunName ||
		conn["type"].Value() != "tun" || ip["method"].Value() != "manual" {
		return nil, errors.New("not an external core-owned TUN connection")
	}
	var addresses []map[string]dbus.Variant
	if err := ip["address-data"].Store(&addresses); err != nil || len(addresses) != 1 ||
		addresses[0]["address"].Value() != address.Addr().String() || addresses[0]["prefix"].Value() != uint32(address.Bits()) {
		return nil, errors.New("unexpected TUN address")
	}
	// Copy maps: the caller's snapshot remains intact, including on rejection.
	out := make(nmSettings, len(original))
	for section, values := range original {
		out[section] = make(map[string]dbus.Variant, len(values))
		for name, value := range values {
			out[section][name] = value
		}
	}
	for _, section := range []string{"ipv4", "ipv6"} {
		// GetAppliedConnection includes deprecated duplicates. The IPv6 tuple
		// variant cannot be round-tripped by godbus's generic decoder; modern
		// address-data/route-data are lossless and take precedence here.
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
	peer := address.Addr().Next()
	// Do not accumulate duplicate defaults on daemon/NM restart.
	retained := make([]map[string]dbus.Variant, 0, len(routes)+1)
	for _, r := range routes {
		if r["dest"].Value() == "0.0.0.0" && r["prefix"].Value() == uint32(0) {
			continue
		}
		retained = append(retained, r)
	}
	retained = append(retained, map[string]dbus.Variant{
		"dest": dbus.MakeVariant("0.0.0.0"), "prefix": dbus.MakeVariant(uint32(0)),
		"next-hop": dbus.MakeVariant(peer.String()), "metric": dbus.MakeVariant(uint32(0)),
	})
	v4["route-data"] = dbus.MakeVariant(retained)
	v4["never-default"] = dbus.MakeVariant(false)
	v4["route-metric"] = dbus.MakeVariant(int64(0))
	v4["route-table"] = dbus.MakeVariant(uint32(254))
	// NM must retain the TUN's existing resolver when adopting it. Corporate
	// per-link suffixes still win over ~.; no foreign DNS metadata is changed.
	b := peer.As4()
	v4["dns"] = dbus.MakeVariant([]uint32{binary.NativeEndian.Uint32(b[:])})
	v4["dns-search"] = dbus.MakeVariant([]string{"~."})
	return out, nil
}
