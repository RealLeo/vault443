package winplatform

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"vault443/internal/securefs"
)

type Uplink struct {
	LUID    winipcfg.LUID
	Index   uint32
	Name    string
	Gateway netip.Addr
	Local   []netip.Prefix
}

func IsVPNInterface(iface *winipcfg.MibIfRow2) bool {
	if iface.Type == winipcfg.IfTypeTunnel || iface.Type == 23 || strings.HasPrefix(strings.ToLower(iface.Alias()), "v443") {
		return true
	}
	description := strings.ToLower(iface.Description())
	for _, name := range []string{"wintun", "wireguard", "openvpn", "tap-windows", "amnezia", "pritunl"} {
		if strings.Contains(description, name) {
			return true
		}
	}
	return false
}

func PhysicalUplink(v6 bool) (Uplink, error) {
	family := winipcfg.AddressFamily(windows.AF_INET)
	if v6 {
		family = windows.AF_INET6
	}
	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return Uplink{}, err
	}
	best := uint64(^uint64(0))
	var result Uplink
	for _, route := range routes {
		prefix := route.DestinationPrefix.Prefix()
		if !prefix.IsValid() || prefix.Bits() != 0 {
			continue
		}
		iface, e := route.InterfaceLUID.Interface()
		if e != nil || iface.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		if iface.Type != winipcfg.IfTypeEthernetCSMACD && iface.Type != 71 {
			continue
		}
		if IsVPNInterface(iface) {
			continue
		}
		ip, e := route.InterfaceLUID.IPInterface(family)
		if e != nil {
			continue
		}
		metric := uint64(route.Metric) + uint64(ip.Metric)
		if metric < best {
			best = metric
			result = Uplink{LUID: route.InterfaceLUID, Index: route.InterfaceIndex, Name: iface.Alias(), Gateway: route.NextHop.Addr()}
		}
	}
	if result.LUID == 0 {
		return Uplink{}, errors.New("no active physical default route")
	}
	all, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return Uplink{}, err
	}
	addresses, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return Uplink{}, err
	}
	seen := map[netip.Prefix]bool{}
	for _, r := range all {
		prefix := r.DestinationPrefix.Prefix()
		if !prefix.IsValid() || prefix.Bits() == 0 || prefix.Addr().IsLoopback() || prefix.Addr().IsMulticast() || !r.NextHop.Addr().IsUnspecified() {
			continue
		}
		iface, e := r.InterfaceLUID.Interface()
		if e != nil || IsVPNInterface(iface) || iface.Type == 24 {
			continue
		}
		for _, address := range addresses {
			if address.InterfaceLUID == r.InterfaceLUID && netip.PrefixFrom(address.Address.Addr(), int(address.OnLinkPrefixLength)).Masked() == prefix.Masked() && !seen[prefix.Masked()] {
				result.Local = append(result.Local, prefix.Masked())
				seen[prefix.Masked()] = true
			}
		}
	}
	return result, nil
}
func InterfaceByName(name string) (winipcfg.LUID, error) {
	interfaces, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
	if err != nil {
		return 0, err
	}
	for _, iface := range interfaces {
		if iface.Alias() == name {
			return iface.InterfaceLUID, nil
		}
	}
	return 0, errors.New("VPN interface is not available")
}

// A first Wintun installation can spend tens of seconds in PnP before TCP/IP
// binds. This bounds readiness, rather than delaying an already ready adapter.
const InterfaceReadyTimeout = time.Minute

func WaitInterface(ctx context.Context, name string, alive func() bool) (winipcfg.LUID, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	changed := make(chan struct{}, 1)
	callback, err := winipcfg.RegisterInterfaceChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPInterfaceRow) {
		select {
		case changed <- struct{}{}:
		default:
		}
	})
	if err != nil {
		return 0, fmt.Errorf("cannot watch VPN interface readiness: %w", err)
	}
	defer callback.Unregister()
	// Register before reading state, so an addition between registration and the
	// first snapshot cannot be lost. OperStatus changes also get a safety probe.
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	last := "adapter is not present"
	for {
		if err := ctx.Err(); err != nil {
			return 0, fmt.Errorf("VPN interface %s readiness (%s): %w", name, last, err)
		}
		if alive != nil && !alive() {
			return 0, errors.New("VPN engine stopped before interface readiness")
		}
		last = "adapter is not present"
		if luid, e := InterfaceByName(name); e == nil {
			// IP Helper exposes a new Wintun row before TCP/IP has bound to it.
			// Do not race address/route configuration against that transition.
			iface, statusErr := luid.Interface()
			_, v4Err := luid.IPInterface(windows.AF_INET)
			_, v6Err := luid.IPInterface(windows.AF_INET6)
			up := statusErr == nil && iface.OperStatus == winipcfg.IfOperStatusUp
			if up && v4Err == nil && v6Err == nil {
				return luid, nil
			}
			last = fmt.Sprintf("operational=%t IPv4=%t IPv6=%t", up, v4Err == nil, v6Err == nil)
		}
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("VPN interface %s readiness (%s): %w", name, last, ctx.Err())
		case <-changed:
		case <-timer.C:
		}
	}
}
func Dialer(luid winipcfg.LUID) *net.Dialer {
	return &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second, Control: func(network, address string, conn syscall.RawConn) error {
		iface, err := luid.Interface()
		if err != nil {
			return err
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return errors.New("bound socket destination must be numeric")
		}
		level, index := windows.IPPROTO_IPV6, int(iface.InterfaceIndex)
		if ip.Is4() {
			level = windows.IPPROTO_IP
			var bytes [4]byte
			binary.LittleEndian.PutUint32(bytes[:], uint32(index))
			index = int(binary.BigEndian.Uint32(bytes[:]))
		}
		var result error
		err = conn.Control(func(fd uintptr) { result = windows.SetsockoptInt(windows.Handle(fd), level, 31, index) })
		if err != nil {
			return err
		}
		return result
	}}
}

type OwnedRoute struct {
	LUID     winipcfg.LUID `json:"luid"`
	Prefix   netip.Prefix  `json:"prefix"`
	Gateway  netip.Addr    `json:"gateway"`
	Priority bool          `json:"priority,omitempty"`
}

const ownedMetric = 443

func (r OwnedRoute) key() string {
	return fmt.Sprintf("%d/%s/%s/%d", r.LUID, r.Prefix, r.Gateway, r.metric())
}
func (r OwnedRoute) metric() uint32 {
	if r.Priority {
		return 0
	}
	return ownedMetric
}
func Route(luid winipcfg.LUID, prefix netip.Prefix, gateway netip.Addr) OwnedRoute {
	if !gateway.IsValid() {
		gateway = netip.IPv4Unspecified()
		if prefix.Addr().Is6() {
			gateway = netip.IPv6Unspecified()
		}
	}
	return OwnedRoute{LUID: luid, Prefix: prefix.Masked(), Gateway: gateway}
}
func PolicyRoute(luid winipcfg.LUID, prefix netip.Prefix, gateway netip.Addr) OwnedRoute {
	r := Route(luid, prefix, gateway)
	r.Priority = true
	return r
}

type Routes struct {
	mu     sync.Mutex
	path   string
	owners map[string][]OwnedRoute
	ops    routeOps
}

// Keep the ownership policy independent of IP Helper for focused native tests.
// Lookup identifies a native row by LUID/prefix/gateway; metric proves that its
// current value still belongs to our recorded route before sharing/deleting it.
type routeOps interface {
	Lookup(OwnedRoute) (uint32, error)
	Add(OwnedRoute) error
	Delete(OwnedRoute) error
}
type windowsRouteOps struct{}

func (windowsRouteOps) Lookup(route OwnedRoute) (uint32, error) {
	row, err := route.LUID.Route(route.Prefix, route.Gateway)
	if err != nil {
		return 0, err
	}
	return row.Metric, nil
}
func (windowsRouteOps) Add(route OwnedRoute) error {
	return route.LUID.AddRoute(route.Prefix, route.Gateway, route.metric())
}
func (windowsRouteOps) Delete(route OwnedRoute) error {
	row, err := route.LUID.Route(route.Prefix, route.Gateway)
	if err != nil {
		return err
	}
	if row.Metric != route.metric() {
		return nil // A foreign change revoked our ownership of this native row.
	}
	return row.Delete()
}

func (r OwnedRoute) nativeKey() string {
	return fmt.Sprintf("%d/%s/%s", r.LUID, r.Prefix, r.Gateway)
}

func NewRoutes(dir string) (*Routes, error) {
	r := &Routes{path: filepath.Join(dir, "windows-routes.json"), owners: map[string][]OwnedRoute{}, ops: windowsRouteOps{}}
	data, err := os.ReadFile(r.path)
	if err == nil {
		if len(data) > 4<<20 || json.Unmarshal(data, &r.owners) != nil || r.owners == nil {
			return nil, errors.New("invalid Windows route ownership manifest")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return r, nil
}
func (r *Routes) save() error {
	data, err := json.Marshal(r.owners)
	if err != nil {
		return err
	}
	return securefs.Write(r.path, data)
}
func (r *Routes) Set(owner string, next []OwnedRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ops == nil {
		r.ops = windowsRouteOps{}
	}
	// Validate the complete request before changing either the journal or FIB.
	keep := map[string]bool{}
	for _, route := range next {
		if !route.Prefix.IsValid() || !route.Gateway.IsValid() || route.LUID == 0 {
			return errors.New("invalid owned route")
		}
		keep[route.key()] = true
	}
	refs := map[string]int{}
	metrics := map[string]uint32{}
	for _, routes := range r.owners {
		seen := map[string]bool{}
		for _, route := range routes {
			if !seen[route.key()] {
				refs[route.key()]++
				seen[route.key()] = true
			}
			metrics[route.nativeKey()] = route.metric()
		}
	}
	known := map[string]bool{}
	for _, route := range r.owners[owner] {
		known[route.key()] = true
	}
	seen := map[string]bool{}
	for _, route := range next {
		key := route.key()
		if seen[key] {
			continue
		}
		seen[key] = true
		if metric, managed := metrics[route.nativeKey()]; managed && metric != route.metric() {
			return errors.New("owned route is already requested with an incompatible metric")
		}
		metric, lookupErr := r.ops.Lookup(route)
		if lookupErr != nil && !errors.Is(lookupErr, windows.ERROR_NOT_FOUND) {
			return fmt.Errorf("cannot inspect requested Windows route: %w", lookupErr)
		}
		if lookupErr == nil && refs[key] == 0 {
			// An existing row is foreign unless this exact metric is recorded in
			// our journal. Even metric443 alone is not an ownership claim.
			continue
		}
		if lookupErr == nil && metric != route.metric() {
			return errors.New("owned Windows route was changed outside the application")
		}
		if !known[key] {
			// Share a globally owned route by persisting every owner's reference.
			// For a new row, persist intent before Add so crash cleanup can find it.
			routes := append(append([]OwnedRoute(nil), r.owners[owner]...), route)
			if err := r.setOwner(owner, routes); err != nil {
				return err
			}
			known[key] = true
			refs[key]++
			metrics[route.nativeKey()] = route.metric()
		}
		if lookupErr != nil {
			if err := r.ops.Add(route); err != nil {
				return err
			}
		}
	}
	// Remove references one at a time only after any last-owner native deletion
	// is confirmed. Transient Lookup/Delete errors retain durable cleanup proof.
	for _, route := range append([]OwnedRoute(nil), r.owners[owner]...) {
		if keep[route.key()] {
			continue
		}
		if refs[route.key()] <= 1 {
			metric, err := r.ops.Lookup(route)
			if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
				return fmt.Errorf("cannot inspect owned Windows route during cleanup: %w", err)
			}
			if err == nil && metric == route.metric() {
				if err = r.ops.Delete(route); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
					return err
				}
			}
		}
		var retained []OwnedRoute
		for _, candidate := range r.owners[owner] {
			if candidate.key() != route.key() {
				retained = append(retained, candidate)
			}
		}
		if err := r.setOwner(owner, retained); err != nil {
			return err
		}
		refs[route.key()]--
	}
	return nil
}

// Caller holds mu. Roll back memory on failed persistence: later operations must
// not treat an unsaved sharing reference as a durable owner.
func (r *Routes) setOwner(owner string, next []OwnedRoute) error {
	old, existed := r.owners[owner]
	if len(next) > 0 {
		r.owners[owner] = next
	} else {
		delete(r.owners, owner)
	}
	if err := r.save(); err != nil {
		if existed {
			r.owners[owner] = old
		} else {
			delete(r.owners, owner)
		}
		return err
	}
	return nil
}
func (r *Routes) ClearExcept(keep map[string]bool) error {
	r.mu.Lock()
	var owners []string
	for owner := range r.owners {
		if !keep[owner] {
			owners = append(owners, owner)
		}
	}
	r.mu.Unlock()
	for _, owner := range owners {
		if err := r.Set(owner, nil); err != nil {
			return err
		}
	}
	return nil
}

type Coordinator struct {
	Guard  *Guard
	Routes *Routes
	DNS    *DNS
	mu     sync.Mutex
	full   map[string]bool
	events chan struct{}
}

func NewCoordinator(dir string) (*Coordinator, error) {
	guard, err := NewGuard(dir)
	if err != nil {
		return nil, err
	}
	routes, err := NewRoutes(dir)
	if err != nil {
		return nil, err
	}
	dns, err := NewDNS(dir)
	if err != nil {
		return nil, err
	}
	dns.fallbackAllowed = func() bool { return !guard.BlockAllActive() }
	return &Coordinator{Guard: guard, Routes: routes, DNS: dns, full: map[string]bool{}, events: make(chan struct{}, 1)}, nil
}
func (c *Coordinator) SetFull(id string, full bool) {
	c.mu.Lock()
	if c.full[id] == full {
		c.mu.Unlock()
		return
	}
	if full {
		c.full[id] = true
	} else {
		delete(c.full, id)
	}
	c.mu.Unlock()
	c.Notify()
}
func (c *Coordinator) HasFull() bool { c.mu.Lock(); defer c.mu.Unlock(); return len(c.full) > 0 }
func (c *Coordinator) Notify() {
	select {
	case c.events <- struct{}{}:
	default:
	}
}
func (c *Coordinator) Watch(ctx context.Context) (<-chan struct{}, error) {
	iface, err := winipcfg.RegisterInterfaceChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPInterfaceRow) { c.Notify() })
	if err != nil {
		return nil, err
	}
	route, err := winipcfg.RegisterRouteChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPforwardRow2) { c.Notify() })
	if err != nil {
		iface.Unregister()
		return nil, err
	}
	go func() { <-ctx.Done(); iface.Unregister(); route.Unregister() }()
	return c.events, nil
}
