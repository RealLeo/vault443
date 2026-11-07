package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"vault443/internal/model"
	"vault443/internal/securefs"
	"vault443/internal/winplatform"
	"vault443/internal/workvpn"
)

type externalObservation struct {
	GUID       string   `json:"guid"`
	Interface  string   `json:"interface"`
	Manager    string   `json:"manager"`
	Unit       string   `json:"unit,omitempty"`
	Source     string   `json:"source"`
	Routes     []string `json:"routes,omitempty"`
	DNSServers []string `json:"dnsServers,omitempty"`
	DNSDomains []string `json:"dnsDomains,omitempty"`
}
type externalTunnel struct {
	observation                    externalObservation
	binding                        windowsBinding
	luid                           winipcfg.LUID
	active, verified, full4, full6 bool
	endpoints                      []winplatform.Endpoint
	message                        string
}
type externalCacheEntry struct {
	key  string
	view model.VPNCompatibility
}

var externalCache sync.Map // one entry per daemon Manager; never used as recovery authority

func (m *Manager) readBindings() (map[string]windowsBinding, error) {
	result := map[string]windowsBinding{}
	data, e := os.ReadFile(filepath.Join(m.config.StateDir, "windows-bindings.json"))
	if os.IsNotExist(e) {
		return result, nil
	}
	if e != nil {
		return nil, e
	}
	if len(data) > 256<<10 || json.Unmarshal(data, &result) != nil || result == nil || len(result) > 32 {
		return nil, errors.New("invalid private Windows VPN bindings")
	}
	for _, b := range result {
		if _, e = windows.GUIDFromString(b.GUID); e != nil {
			return nil, errors.New("invalid enrolled Windows VPN adapter GUID")
		}
		data, _ := json.Marshal(b)
		if _, e = parseWindowsBinding(string(data)); e != nil {
			return nil, e
		}
	}
	return result, nil
}
func (m *Manager) SetVPNBinding(ctx context.Context, text string) error {
	b, e := parseWindowsBinding(text)
	if e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	bindings, e := m.readBindings()
	if e != nil {
		return e
	}
	if b.Remove {
		for key, old := range bindings {
			if strings.EqualFold(old.Interface, b.Interface) {
				delete(bindings, key)
			}
		}
	} else {
		interfaces, e := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
		if e != nil {
			return e
		}
		found := false
		for _, iface := range interfaces {
			if !strings.EqualFold(iface.Alias(), b.Interface) {
				continue
			}
			if !winplatform.IsVPNInterface(&iface) || strings.HasPrefix(strings.ToLower(iface.Alias()), "v443") {
				return errors.New("only an external VPN adapter can be enrolled")
			}
			guid, e := iface.InterfaceLUID.GUID()
			if e != nil {
				return e
			}
			b.GUID = guid.String()
			b.Interface = iface.Alias()
			found = true
			break
		}
		if !found {
			return errors.New("the external VPN adapter must be present when enrolled")
		}
		if b.Unit != "" {
			if _, e = inspectExternalService(ctx, b.Unit, b.Manager); e != nil {
				return e
			}
		}
		for key, old := range bindings {
			if strings.EqualFold(old.GUID, b.GUID) {
				delete(bindings, key)
			}
		}
		bindings[b.Interface] = b
	}
	if len(bindings) > 32 {
		return errors.New("at most 32 external VPN bindings are supported")
	}
	data, e := json.Marshal(bindings)
	if e != nil {
		return e
	}
	if e = securefs.Write(filepath.Join(m.config.StateDir, "windows-bindings.json"), data); e != nil {
		return e
	}
	externalCache.Delete(m)
	if e = m.refreshExternalLocked(ctx); e != nil {
		return e
	}
	if m.platform != nil {
		m.platform.Notify()
	}
	return nil
}
func (m *Manager) externalHistory() (map[string]externalObservation, error) {
	result := map[string]externalObservation{}
	data, e := os.ReadFile(filepath.Join(m.config.StateDir, "windows-external.json"))
	if os.IsNotExist(e) {
		return result, nil
	}
	if e != nil {
		return nil, e
	}
	if len(data) > 2<<20 || json.Unmarshal(data, &result) != nil || result == nil || len(result) > 32 {
		return nil, errors.New("invalid private external VPN recovery state")
	}
	for key, item := range result {
		if key != item.GUID || len(item.Routes) > 256 || len(item.DNSServers) > 16 || len(item.DNSDomains) > 64 {
			return nil, errors.New("invalid protected external VPN metadata")
		}
		if _, e = windows.GUIDFromString(key); e != nil {
			return nil, e
		}
		for _, raw := range item.Routes {
			p, e := netip.ParsePrefix(raw)
			if e != nil || p.Bits() < 2 || !validExternalPrefix(p) {
				return nil, errors.New("invalid protected external VPN recovery route")
			}
		}
		for _, raw := range item.DNSServers {
			ip, e := netip.ParseAddr(raw)
			if e != nil || !externalIP(ip) {
				return nil, errors.New("invalid external DNS recovery server")
			}
		}
		for _, raw := range item.DNSDomains {
			if _, e = workvpn.NormalizeDomain(raw); e != nil {
				return nil, e
			}
		}
	}
	return result, nil
}
func uniqueExternalStrings(values []string) []string {
	set := map[string]bool{}
	for _, v := range values {
		if v != "" {
			set[v] = true
		}
	}
	result := make([]string, 0, len(set))
	for v := range set {
		result = append(result, v)
	}
	sort.Strings(result)
	return result
}
func (m *Manager) collectExternal(ctx context.Context) ([]externalTunnel, []model.VPNCompatibilityItem, error) {
	bindings, e := m.readBindings()
	if e != nil {
		return nil, nil, e
	}
	history, e := m.externalHistory()
	if e != nil {
		return nil, nil, e
	}
	interfaces, e := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
	if e != nil {
		return nil, nil, e
	}
	routes, e := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if e != nil {
		return nil, nil, e
	}
	byGUID := map[string]winipcfg.MibIfRow2{}
	byName := map[string]string{}
	for _, iface := range interfaces {
		guid, e := iface.InterfaceLUID.GUID()
		if e != nil {
			continue
		}
		byGUID[guid.String()] = iface
		byName[strings.ToLower(iface.Alias())] = guid.String()
	}
	candidates := map[string]windowsBinding{}
	sources := map[string]string{}
	for _, b := range bindings {
		candidates[b.GUID] = b
		sources[b.GUID] = "manual"
	}
	scm, e := mgr.Connect()
	if e != nil {
		return nil, nil, e
	}
	names, e := scm.ListServices()
	scm.Disconnect()
	if e != nil {
		return nil, nil, e
	}
	serviceNames := map[string]bool{}
	for _, name := range names {
		serviceNames[strings.ToLower(name)] = true
	}
	// A conventional service name is only a candidate. Its LocalSystem token,
	// executable DACL, native driver query and kernel UDP socket must also agree.
	services := map[string]externalService{}
	for _, name := range names {
		if !strings.HasPrefix(strings.ToLower(name), "wireguardtunnel$") {
			continue
		}
		service, err := inspectExternalService(ctx, name, "wireguard")
		if err != nil {
			continue
		}
		alias, ok := automaticWireGuardName(service)
		if !ok {
			continue
		}
		guid := byName[strings.ToLower(alias)]
		if guid == "" {
			for id, old := range history {
				if old.Source == "automatic" && strings.EqualFold(old.Unit, name) {
					guid = id
					alias = old.Interface
					break
				}
			}
		}
		if guid == "" {
			continue
		}
		if _, manual := candidates[guid]; manual {
			continue
		}
		candidates[guid] = windowsBinding{Interface: alias, GUID: guid, Manager: "wireguard", Unit: name}
		sources[guid] = "automatic"
		services[strings.ToLower(name)] = service
	}
	// Previously enrolled automatic routes remain blocked when the adapter is
	// absent, until that Windows service is removed or can be revalidated.
	for id, old := range history {
		if old.Source == "automatic" && serviceNames[strings.ToLower(old.Unit)] {
			if _, ok := candidates[id]; !ok {
				candidates[id] = windowsBinding{Interface: old.Interface, GUID: id, Manager: old.Manager, Unit: old.Unit}
				sources[id] = "automatic"
			}
		}
	}
	if len(candidates) > 32 {
		return nil, nil, errors.New("external VPN limit exceeded")
	}
	ports, e := udpOwnerPorts()
	if e != nil {
		return nil, nil, e
	}
	adapters, _ := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, 0)
	suffixes := map[winipcfg.LUID]string{}
	for _, adapter := range adapters {
		if suffix, e := workvpn.NormalizeDomain(adapter.DNSSuffix()); e == nil {
			suffixes[adapter.LUID] = suffix
		}
	}
	var result []externalTunnel
	seen := map[string]bool{}
	var unknown []model.VPNCompatibilityItem
	keys := make([]string, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, guid := range keys {
		if e = ctx.Err(); e != nil {
			return nil, nil, e
		}
		b := candidates[guid]
		source := sources[guid]
		item := externalTunnel{binding: b, observation: externalObservation{GUID: guid, Interface: b.Interface, Manager: b.Manager, Unit: b.Unit, Source: source, Routes: append([]string(nil), b.Routes...), DNSServers: append([]string(nil), b.DNSServers...), DNSDomains: append([]string(nil), b.DNSDomains...)}, verified: source == "manual"}
		if old, ok := history[guid]; ok && old.Source == source && old.Manager == b.Manager && strings.EqualFold(old.Unit, b.Unit) {
			item.observation.Routes = append(item.observation.Routes, old.Routes...)
			if len(item.observation.DNSServers) == 0 {
				item.observation.DNSServers = old.DNSServers
				item.observation.DNSDomains = old.DNSDomains
			}
		}
		item.observation.DNSDomains = externalDNSDomains(item.observation.DNSDomains, b.DNSDomains)
		iface, present := byGUID[guid]
		if !present {
			item.message = "The enrolled adapter is not present"
			item.observation.Routes = uniqueExternalStrings(item.observation.Routes)
			result = append(result, item)
			continue
		}
		seen[guid] = true
		item.observation.Interface = iface.Alias()
		item.luid = iface.InterfaceLUID
		if !winplatform.IsVPNInterface(&iface) || strings.HasPrefix(strings.ToLower(iface.Alias()), "v443") {
			item.verified = false
			item.message = "The enrolled GUID no longer identifies an external VPN adapter"
			result = append(result, item)
			continue
		}
		item.active = iface.OperStatus == winipcfg.IfOperStatusUp
		var service externalService
		serviceOK := false
		if b.Unit != "" {
			service, serviceOK = services[strings.ToLower(b.Unit)]
			if !serviceOK {
				var err error
				service, err = inspectExternalService(ctx, b.Unit, b.Manager)
				serviceOK = err == nil
			}
			if !serviceOK {
				item.active = false
				item.message = "The enrolled LocalSystem VPN service could not be verified"
			} else {
				item.active = item.active && service.running
			}
		}
		if serviceOK && service.running && (b.Manager == "wireguard" || b.Manager == "wg-quick") {
			kernel, allowed, err := readKernelWireGuard(ctx, service, iface.Alias(), iface.InterfaceLUID, ports)
			if err == nil {
				item.endpoints = kernel
				item.verified = true
				if source == "automatic" {
					item.observation.Routes = allowed
				}
			} else if source == "automatic" {
				item.active = false
				item.verified = false
				item.message = "WireGuard driver ownership could not be verified"
			}
		}
		if source == "automatic" && !item.verified {
			item.active = false
		}
		if source == "manual" && serviceOK && service.running && len(item.endpoints) == 0 {
			for _, ep := range b.Endpoints {
				address, _ := netip.ParseAddr(ep.Address)
				uplink, err := winplatform.PhysicalUplink(address.Is6())
				if err != nil {
					continue
				}
				family := uint32(windows.AF_INET)
				if address.Is6() {
					family = windows.AF_INET6
				}
				for pid, path := range service.workers {
					if ep.SourcePort != 0 && !ports[family][uint16(ep.SourcePort)][pid] {
						continue
					}
					item.endpoints = append(item.endpoints, winplatform.Endpoint{App: path, Address: address, Port: uint16(ep.Port), UDP: ep.Protocol == "udp", Interface: uint64(uplink.LUID), SourcePort: uint16(ep.SourcePort)})
				}
			}
			if len(b.Endpoints) > 0 && len(item.endpoints) == 0 {
				item.message = "No trusted VPN transport process is running"
			}
		}
		if item.active && item.verified {
			var prefixes []netip.Prefix
			for _, route := range routes {
				if route.InterfaceLUID != item.luid {
					continue
				}
				p := route.DestinationPrefix.Prefix().Masked()
				if !validExternalPrefix(p) {
					continue
				}
				prefixes = append(prefixes, p)
				if p.Bits() > 1 {
					item.observation.Routes = append(item.observation.Routes, p.String())
				}
			}
			item.full4 = windowsClaimsDefault(prefixes, false)
			item.full6 = windowsClaimsDefault(prefixes, true)
			if len(b.DNSServers) == 0 {
				if servers, err := item.luid.DNS(); err == nil {
					item.observation.DNSServers = nil
					for _, ip := range servers {
						if externalIP(ip) {
							item.observation.DNSServers = append(item.observation.DNSServers, ip.String())
						}
					}
				}
				if suffix := suffixes[item.luid]; suffix != "" {
					item.observation.DNSDomains = []string{suffix}
				}
			}
			if (item.full4 || item.full6) && len(item.observation.DNSServers) > 0 {
				item.observation.DNSDomains = append(item.observation.DNSDomains, ".")
			}
		}
		item.observation.Routes = uniqueExternalStrings(item.observation.Routes)
		item.observation.DNSServers = uniqueExternalStrings(item.observation.DNSServers)
		item.observation.DNSDomains = uniqueExternalStrings(item.observation.DNSDomains)
		if len(item.observation.Routes) > 256 || len(item.observation.DNSServers) > 16 || len(item.observation.DNSDomains) > 64 || len(item.endpoints) > 64 {
			return nil, nil, errors.New("external VPN policy limits exceeded")
		}
		result = append(result, item)
	}
	for guid, iface := range byGUID {
		if seen[guid] || !winplatform.IsVPNInterface(&iface) || strings.HasPrefix(strings.ToLower(iface.Alias()), "v443") {
			continue
		}
		entry := model.VPNCompatibilityItem{Interface: iface.Alias(), Manager: "unknown", Application: iface.Alias(), Source: "unknown", Active: iface.OperStatus == winipcfg.IfOperStatusUp, Message: "Administrator binding is required; adapter ownership has not been verified"}
		var prefixes []netip.Prefix
		for _, route := range routes {
			if route.InterfaceLUID == iface.InterfaceLUID {
				prefixes = append(prefixes, route.DestinationPrefix.Prefix())
			}
		}
		entry.FullIPv4 = windowsClaimsDefault(prefixes, false)
		entry.FullIPv6 = windowsClaimsDefault(prefixes, true)
		unknown = append(unknown, entry)
	}
	return result, unknown, nil
}
func externalView(tunnels []externalTunnel, unknown []model.VPNCompatibilityItem) model.VPNCompatibility {
	view := model.VPNCompatibility{Items: append([]model.VPNCompatibilityItem{}, unknown...)}
	for _, item := range tunnels {
		o := item.observation
		view.Items = append(view.Items, model.VPNCompatibilityItem{Interface: o.Interface, Manager: o.Manager, Application: o.Unit, Source: o.Source, Active: item.active, Verified: item.verified, FullIPv4: item.full4, FullIPv6: item.full6, Message: item.message})
	}
	sort.Slice(view.Items, func(i, j int) bool { return view.Items[i].Interface < view.Items[j].Interface })
	return view
}
func (m *Manager) refreshExternalLocked(parent context.Context) (err error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	// If new protected policy cannot commit, terminate main transport rather than
	// keep forwarding newly corporate traffic through an obsolete policy.
	defer func() {
		if err != nil && m.Status().GuardArmed {
			stop, done := context.WithTimeout(context.Background(), 3*time.Second)
			defer done()
			_ = m.stop(stop)
		}
	}()
	platform, err := m.Platform()
	if err != nil {
		return err
	}
	tunnels, unknown, err := m.collectExternal(ctx)
	if err != nil {
		return err
	}
	part := winplatform.GuardPart{}
	plans := map[string]winplatform.DNSPlan{}
	observations := map[string]externalObservation{}
	var endpointRoutes, dnsRoutes []winplatform.OwnedRoute
	full := false
	count := 0
	uplink, upErr := winplatform.PhysicalUplink(false)
	if upErr != nil {
		uplink, upErr = winplatform.PhysicalUplink(true)
	}
	for _, item := range tunnels {
		o := item.observation
		observations[o.GUID] = o
		active := item.active && item.verified
		luid := uint64(0)
		if active {
			luid = uint64(item.luid)
		}
		for _, raw := range o.Routes {
			prefix, e := netip.ParsePrefix(raw)
			if e != nil {
				return e
			}
			part.Routes = append(part.Routes, winplatform.GuardRoute{Prefix: prefix, Interface: luid})
			count++
		}
		if active && (item.full4 || item.full6) {
			full = true
			for _, v6 := range []bool{false, true} {
				prefix := "0.0.0.0/0"
				iface := uint64(0)
				if v6 {
					prefix = "::/0"
				}
				if (!v6 && item.full4) || (v6 && item.full6) {
					iface = luid
				}
				part.Routes = append(part.Routes, winplatform.GuardRoute{Prefix: netip.MustParsePrefix(prefix), Interface: iface})
			}
		}
		if active {
			part.DNSTunnels = append(part.DNSTunnels, luid)
		}
		for _, ep := range item.endpoints {
			part.Endpoints = append(part.Endpoints, ep)
			link, e := winplatform.PhysicalUplink(ep.Address.Is6())
			if e != nil {
				return e
			}
			endpointRoutes = append(endpointRoutes, winplatform.Route(link.LUID, netip.PrefixFrom(ep.Address, ep.Address.BitLen()), link.Gateway))
		}
		if len(o.DNSDomains) > 0 && len(o.DNSServers) > 0 {
			plan := winplatform.DNSPlan{Interface: item.luid, Active: active, Priority: 50}
			for _, domain := range o.DNSDomains {
				if domain == "." {
					plan.Default = true
				} else {
					plan.Domains = append(plan.Domains, domain)
				}
			}
			for _, raw := range o.DNSServers {
				ip, _ := netip.ParseAddr(raw)
				plan.Servers = append(plan.Servers, ip)
				part.Routes = append(part.Routes, winplatform.GuardRoute{Prefix: netip.PrefixFrom(ip, ip.BitLen()), Interface: luid})
				if active {
					dnsRoutes = append(dnsRoutes, winplatform.Route(item.luid, netip.PrefixFrom(ip, ip.BitLen()), netip.Addr{}))
				}
			}
			plans["external:"+o.GUID] = plan
		}
	}
	if count > 1024 || len(part.Endpoints) > 256 {
		return errors.New("combined external VPN policy exceeds limits")
	}
	if len(plans) > 0 {
		if upErr != nil {
			return upErr
		}
		part.DNSPhysical = []uint64{uint64(uplink.LUID)}
		servers, e := platform.DNS.UnderlayServers(uplink.LUID)
		if e != nil {
			return e
		}
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		for _, ip := range servers {
			for _, udp := range []bool{true, false} {
				part.Endpoints = append(part.Endpoints, winplatform.Endpoint{App: exe, Address: ip, Port: 53, UDP: udp, Interface: uint64(uplink.LUID), FallbackDNS: true})
			}
		}
	}
	data, _ := json.Marshal(struct {
		Part                 winplatform.GuardPart
		Endpoints, DNSRoutes []winplatform.OwnedRoute
		DNS                  map[string]winplatform.DNSPlan
		Full                 bool
		History              map[string]externalObservation
	}{part, endpointRoutes, dnsRoutes, plans, full, observations})
	sum := sha256.Sum256(data)
	key := hex.EncodeToString(sum[:])
	view := externalView(tunnels, unknown)
	cached, exists := externalCache.Load(m)
	if exists && cached.(externalCacheEntry).key == key {
		externalCache.Store(m, externalCacheEntry{key, view})
		return nil
	}
	stored, e := json.Marshal(observations)
	if e != nil {
		return e
	}
	if e = securefs.Write(filepath.Join(m.config.StateDir, "windows-external.json"), stored); e != nil {
		return e
	}
	if len(tunnels) > 0 {
		err = platform.Guard.Set("external", part)
	} else {
		err = platform.Guard.Remove("external")
	}
	if err != nil {
		return err
	}
	if err = platform.Routes.Set("external-endpoints", endpointRoutes); err != nil {
		return err
	}
	if err = platform.Routes.Set("external-dns", dnsRoutes); err != nil {
		return err
	}
	if err = platform.DNS.SetGroup("external:", plans, uplink.LUID); err != nil {
		return err
	}
	platform.SetFull("external", full)
	externalCache.Store(m, externalCacheEntry{key, view})
	return nil
}
func (m *Manager) releaseExternalLocked(ctx context.Context) error {
	platform, e := m.Platform()
	if e != nil {
		return e
	}
	if e = platform.Routes.Set("external-endpoints", nil); e != nil {
		return e
	}
	if e = platform.Routes.Set("external-dns", nil); e != nil {
		return e
	}
	if e = platform.DNS.SetGroup("external:", nil, 0); e != nil {
		return e
	}
	if e = platform.Guard.Remove("external"); e != nil {
		return e
	}
	platform.SetFull("external", false)
	externalCache.Delete(m)
	return nil
}
func (m *Manager) VPNCompatibility(ctx context.Context) model.VPNCompatibility {
	if value, ok := externalCache.Load(m); ok {
		cached := value.(externalCacheEntry).view
		cached.Items = append([]model.VPNCompatibilityItem(nil), cached.Items...)
		return cached
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	items, unknown, e := m.collectExternal(child)
	if e != nil {
		return model.VPNCompatibility{Items: []model.VPNCompatibilityItem{}, Message: "Windows VPN ownership could not be verified"}
	}
	return externalView(items, unknown)
}
