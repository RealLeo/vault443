package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// NMTunnel is trusted in-process intent, never a caller-supplied D-Bus object.
// Address is the authenticated lease (not a subnet's masked network address).
type NMTunnel struct {
	ID, Interface   string
	Index           int
	Attempt         uint64
	Address         netip.Prefix
	previousAddress netip.Prefix
	preserveDNS     bool
	Gateway         netip.Addr
	DNS, Domains    []string
	Enabled         bool
}
type NMResult struct {
	State, Message string
	Changed        bool
}

// NMSynchronizer coalesces immutable intents. Its single worker runs without
// network/service locks. Every possibly applied request is remembered before
// issuing D-Bus: cancellation cannot lose the compensating cleanup operation.
type NMSynchronizer struct {
	mu         sync.Mutex
	desired    map[string]NMTunnel
	known      map[string]NMTunnel
	leases     map[string]NMTunnel
	generation uint64
	running    bool
	next       time.Time
	cancel     context.CancelFunc
	retry      *time.Timer
	apply      func(context.Context, NMTunnel) NMResult
	notify     func(NMTunnel, NMResult)
}

func NewNMSynchronizer(notify func(NMTunnel, NMResult)) *NMSynchronizer {
	return &NMSynchronizer{known: map[string]NMTunnel{}, leases: map[string]NMTunnel{}, apply: applyNMTunnel, notify: notify}
}
func (n *NMSynchronizer) Current(t NMTunnel) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	current, ok := n.desired[t.ID]
	return ok && reflect.DeepEqual(current, t)
}
func (n *NMSynchronizer) notificationTarget(t NMTunnel) (NMTunnel, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	current, ok := n.desired[t.ID]
	if !ok {
		return t, false
	}
	if reflect.DeepEqual(current, t) || (!t.Enabled && !current.Enabled && t.Interface == current.Interface && t.Index == current.Index) {
		return current, true
	}
	return t, false
}
func (n *NMSynchronizer) Update(targets []NMTunnel) {
	desired := map[string]NMTunnel{}
	for _, t := range targets {
		t.DNS = append([]string(nil), t.DNS...)
		t.Domains = append([]string(nil), t.Domains...)
		desired[t.ID] = t
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	changed := !reflect.DeepEqual(desired, n.desired)
	if !changed && (n.running || time.Now().Before(n.next)) {
		return
	}
	if n.retry != nil {
		n.retry.Stop()
		n.retry = nil
	}
	n.desired = desired
	n.generation++
	if n.cancel != nil {
		n.cancel()
	}
	if !n.running {
		n.running = true
		go n.run()
	}
}
func sameNMLease(a, b NMTunnel) bool {
	return a.Interface == b.Interface && a.Index == b.Index && a.Address == b.Address && a.Gateway == b.Gateway && a.Attempt == b.Attempt
}
func (n *NMSynchronizer) run() {
	for {
		n.mu.Lock()
		generation := n.generation
		ctx, cancel := context.WithCancel(context.Background())
		n.cancel = cancel
		var clean, active []NMTunnel
		previous := map[string]netip.Prefix{}
		for id, old := range n.known {
			current, ok := n.desired[id]
			if !ok || !current.Enabled || !sameNMLease(current, old) {
				previous[id] = old.Address
				if ok {
					old.DNS, old.Domains = current.DNS, current.Domains
				} else {
					old.preserveDNS = true
				}
				if ok && current.Interface == old.Interface && current.Index == old.Index {
					old.previousAddress, old.Address = old.Address, current.Address
				}
				old.Enabled = false
				clean = append(clean, old)
			}
		}
		for id, t := range n.desired {
			if t.Enabled {
				t.previousAddress = previous[id]
				if old, ok := n.leases[id]; ok && old.Interface == t.Interface && old.Index == t.Index {
					t.previousAddress = old.Address
				}
				active = append(active, t)
			} else if _, ok := n.known[id]; !ok && t.Gateway.Is4() {
				clean = append(clean, t)
			}
		}
		n.mu.Unlock()
		sort.Slice(clean, func(i, j int) bool { return clean[i].ID < clean[j].ID })
		sort.Slice(active, func(i, j int) bool { return active[i].ID < active[j].ID })
		cleanupFailed := false
		for _, t := range append(clean, active...) {
			if ctx.Err() != nil {
				break
			}
			if t.Enabled {
				if cleanupFailed {
					continue
				}
			}
			n.known[t.ID] = t
			bounded, stop := context.WithTimeout(ctx, 2*time.Second)
			result := n.apply(bounded, t)
			stop()
			if result.State == "registered" {
				n.leases[t.ID] = t
			}
			if !t.Enabled && result.State == "inactive" {
				if _, ok := n.leases[t.ID]; !ok {
					n.leases[t.ID] = t
				}
			}
			if !t.Enabled && result.State == "inactive" {
				delete(n.known, t.ID)
			} else if !t.Enabled {
				cleanupFailed = true
			}
			t.previousAddress = netip.Prefix{}
			t.preserveDNS = false
			if target, current := n.notificationTarget(t); ctx.Err() == nil && current && n.notify != nil {
				n.notify(target, result)
			}
			if result.Changed && ctx.Err() == nil {
				requestNMConnectivity()
			}
		}
		cancel()
		n.mu.Lock()
		n.cancel = nil
		if generation != n.generation {
			n.mu.Unlock()
			continue
		}
		for id := range n.leases {
			if _, desired := n.desired[id]; !desired {
				if _, dirty := n.known[id]; !dirty {
					delete(n.leases, id)
				}
			}
		}
		n.next = time.Now().Add(5 * time.Second)
		n.running = false
		// Continue checking active registrations after an NM restart and retry
		// cleanup even when the last work session has already been forgotten.
		if len(n.known) > 0 {
			n.retry = time.AfterFunc(5*time.Second, func() {
				n.mu.Lock()
				defer n.mu.Unlock()
				if n.generation != generation || n.running {
					return
				}
				n.running = true
				go n.run()
			})
		}
		n.mu.Unlock()
		return
	}
}

func nmIdentity(t NMTunnel) bool {
	iface, err := net.InterfaceByName(t.Interface)
	if err != nil || iface.Index != t.Index {
		return false
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addresses {
		p, err := netip.ParsePrefix(a.String())
		if err == nil && p == t.Address {
			return true
		}
	}
	return false
}

// Main and work managers share one mutation lane, without taking kernel locks.
var nmMutation = make(chan struct{}, 1)

func nmDefaultRoutes(ctx context.Context, t NMTunnel) ([]Route, error) {
	raw, err := runCommand(ctx, command{Path: "/usr/sbin/ip", Args: []string{"-j", "-4", "route", "show", "table", "main", "dev", t.Interface}})
	if err != nil {
		return nil, err
	}
	var routes, own []Route
	if err = json.Unmarshal(raw, &routes); err != nil {
		return nil, err
	}
	for _, r := range routes {
		if r.Destination == "default" && r.Gateway == t.Gateway.String() && r.Metric == 0 {
			own = append(own, r)
		}
	}
	return own, nil
}

func applyNMTunnel(ctx context.Context, t NMTunnel) NMResult {
	pending := func(message string) NMResult { return NMResult{State: "pending", Message: message} }
	select {
	case nmMutation <- struct{}{}:
		defer func() { <-nmMutation }()
	case <-ctx.Done():
		return pending("NetworkManager synchronization was cancelled")
	}
	inactive := NMResult{State: "inactive", Message: "NetworkManager tunnel connectivity registration is inactive"}
	if !nmIdentity(t) {
		if !t.Enabled {
			return inactive
		}
		return pending("Waiting for the owned VPN tunnel address")
	}
	bus, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return NMResult{State: "unavailable", Message: "NetworkManager integration unavailable; VPN protection is unchanged"}
	}
	defer bus.Close()
	var owner string
	if bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, nmName).Store(&owner) != nil {
		return NMResult{State: "unavailable", Message: "NetworkManager is not running; VPN protection is unchanged"}
	}
	var path dbus.ObjectPath
	if bus.Object(owner, "/org/freedesktop/NetworkManager").CallWithContext(ctx, nmName+".GetDeviceByIpIface", 0, t.Interface).Store(&path) != nil {
		return pending("Waiting for NetworkManager to recognize the VPN tunnel")
	}
	device := bus.Object(owner, path)
	var settings nmSettings
	var version uint64
	if device.CallWithContext(ctx, nmName+".Device.GetAppliedConnection", 0, uint32(0)).Store(&settings, &version) != nil {
		return pending("NetworkManager has not activated the external VPN tunnel yet")
	}
	var activePath, connectionPath dbus.ObjectPath
	var flags uint32
	if nmProperty(ctx, device, nmName+".Device", "ActiveConnection", &activePath) != nil ||
		nmProperty(ctx, bus.Object(owner, activePath), nmName+".Connection.Active", "Connection", &connectionPath) != nil ||
		nmProperty(ctx, bus.Object(owner, connectionPath), nmName+".Settings.Connection", "Flags", &flags) != nil {
		return pending("Cannot verify NetworkManager tunnel ownership yet")
	}
	if flags&6 != 6 {
		return NMResult{State: "skipped", Message: "NetworkManager tunnel profile is not generated and volatile; left unchanged"}
	}
	desired, err := nmDesiredSettings(settings, t)
	if err != nil {
		return NMResult{State: "skipped", Message: "NetworkManager tunnel settings left unchanged: " + err.Error()}
	}
	// Ignore only deprecated duplicate tuples when comparing. A new NM owner
	// gets its own applied settings checked, rather than trusting a cached key.
	comparable := nmSettings{}
	for section, values := range settings {
		comparable[section] = map[string]dbus.Variant{}
		for k, v := range values {
			if (section != "ipv4" && section != "ipv6") || (k != "addresses" && k != "routes") {
				comparable[section][k] = v
			}
		}
	}
	changed := !reflect.DeepEqual(comparable, desired)
	routes, err := nmDefaultRoutes(ctx, t)
	if err != nil {
		return pending("Cannot inspect NetworkManager tunnel route; will retry")
	}
	if t.Enabled && len(routes) == 0 {
		changed = true
	}
	if !nmIdentity(t) || ctx.Err() != nil {
		return pending("VPN tunnel changed before NetworkManager synchronization")
	}
	if changed {
		if err := device.CallWithContext(ctx, nmName+".Device.Reapply", 0, desired, version, uint32(1)).Err; err != nil {
			return pending(fmt.Sprintf("NetworkManager could not register the tunnel for connectivity checks; will retry: %v", err))
		}
	}
	if !t.Enabled {
		// After NM restarts, it may assume our former route as external. Reapply's
		// preserve-external-ip correctly leaves it alone: remove that exact route
		// explicitly, after validating generated-profile and current link identity.
		if nmIdentity(t) {
			routes, e := nmDefaultRoutes(ctx, t)
			if e != nil {
				return pending("Cannot verify removal of NetworkManager tunnel route")
			}
			for _, r := range routes {
				if r.Destination == "default" && r.Gateway == t.Gateway.String() && r.Metric == 0 {
					if _, e = runCommand(ctx, command{Path: "/usr/sbin/ip", Args: []string{"-4", "route", "del", "default", "via", t.Gateway.String(), "dev", t.Interface, "metric", "0", "table", "main"}}); e != nil {
						return pending("Cannot remove obsolete NetworkManager tunnel route")
					}
					changed = true
				}
			}
		}
		inactive.Changed = changed
		return inactive
	}
	if routes, err = nmDefaultRoutes(ctx, t); err != nil || len(routes) == 0 {
		return NMResult{State: "pending", Message: "Waiting for NetworkManager tunnel default route", Changed: changed}
	}
	return NMResult{State: "registered", Message: nmRegisteredMessage, Changed: changed}
}

// One coalesced best-effort real probe after a registration change. It never
// decides the VPN state and does not hold up synchronization or cancellation.
var nmProbeMu sync.Mutex
var nmProbeRunning bool

func requestNMConnectivity() {
	nmProbeMu.Lock()
	if nmProbeRunning {
		nmProbeMu.Unlock()
		return
	}
	nmProbeRunning = true
	nmProbeMu.Unlock()
	go func() {
		defer func() { nmProbeMu.Lock(); nmProbeRunning = false; nmProbeMu.Unlock() }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		bus, e := dbus.ConnectSystemBus(dbus.WithContext(ctx))
		if e != nil {
			return
		}
		defer bus.Close()
		_ = bus.Object(nmName, "/org/freedesktop/NetworkManager").CallWithContext(ctx, nmName+".CheckConnectivity", 0).Err
	}()
}
