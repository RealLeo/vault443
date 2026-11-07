// Package winplatform owns the Windows kernel resources shared by main/work VPNs.
package winplatform

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
	"vault443/internal/securefs"
)

type Endpoint struct {
	App         string
	Address     netip.Addr
	Port        uint16
	UDP         bool
	Interface   uint64
	FallbackDNS bool
	SourcePort  uint16
	Kernel      bool
}
type GuardRoute struct {
	Prefix    netip.Prefix
	Interface uint64
}
type PrivatePort struct {
	Port uint16
	App  string
}
type GuardPart struct {
	BlockAll           bool
	Default4, Default6 uint64
	Routes             []GuardRoute
	Endpoints          []Endpoint
	Local              []netip.Prefix
	PrivatePorts       []PrivatePort
	Probe6             uint64
	ProbeApp           string
	DNSPhysical        []uint64
	DNSTunnels         []uint64
}
type Guard struct {
	mu    sync.Mutex
	path  string
	parts map[string]GuardPart
	ids   []wf.RuleID
}
type guardState struct {
	IDs   []wf.RuleID          `json:"ids"`
	Parts map[string]GuardPart `json:"parts"`
}

func stableGUID(label string) windows.GUID {
	h := sha256.Sum256([]byte("Vault443.Windows.WFP.1:" + label))
	return windows.GUID{Data1: uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3]), Data2: uint16(h[4])<<8 | uint16(h[5]), Data3: uint16(h[6])<<8 | uint16(h[7]), Data4: [8]byte(h[8:16])}
}

var providerID = wf.ProviderID(stableGUID("provider"))
var sublayerID = wf.SublayerID(stableGUID("sublayer"))

func NewGuard(stateDir string) (*Guard, error) {
	g := &Guard{path: filepath.Join(stateDir, "windows-wfp.json"), parts: map[string]GuardPart{}}
	data, err := os.ReadFile(g.path)
	if err == nil {
		var state guardState
		if len(data) > 4<<20 || json.Unmarshal(data, &state) != nil || state.Parts == nil {
			return nil, errors.New("invalid Windows protection resource manifest")
		}
		g.ids, g.parts = state.IDs, state.Parts
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return g, nil
}
func (g *Guard) Set(key string, part GuardPart) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	old, exists := g.parts[key]
	g.parts[key] = part
	if err := g.apply(); err != nil {
		if exists {
			g.parts[key] = old
		} else {
			delete(g.parts, key)
		}
		return err
	}
	return nil
}
func (g *Guard) Remove(key string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	old, exists := g.parts[key]
	delete(g.parts, key)
	if err := g.apply(); err != nil {
		if exists {
			g.parts[key] = old
		}
		return err
	}
	return nil
}
func match(field wf.FieldID, value any) *wf.Match {
	return &wf.Match{Field: field, Op: wf.MatchTypeEqual, Value: value}
}

func (g *Guard) BlockAllActive() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, part := range g.parts {
		if part.BlockAll {
			return true
		}
	}
	return false
}

func (g *Guard) rules() ([]*wf.Rule, error) {
	var rules []*wf.Rule
	systemOnly, err := windows.SecurityDescriptorFromString("D:(A;;CC;;;SY)")
	if err != nil {
		return nil, err
	}
	// The pinned WFP composer converts an absolute descriptor to the native
	// self-relative blob. Convert the SDDL result before handing it over.
	systemOnly, err = systemOnly.ToAbsolute()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(g.parts))
	for key := range g.parts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	blockFallback := false
	dnsProtected := false
	trustedDNS := map[uint64]bool{}
	for _, part := range g.parts {
		blockFallback = blockFallback || part.BlockAll
	}
	for _, part := range g.parts {
		dnsProtected = dnsProtected || len(part.DNSPhysical) > 0
		for _, luid := range append(append([]uint64{}, part.DNSTunnels...), part.Default4, part.Default6, part.Probe6) {
			if luid != 0 {
				trustedDNS[luid] = true
			}
		}
	}
	add := func(label string, layer wf.LayerID, action wf.Action, weight uint64, conditions ...*wf.Match) *wf.Rule {
		r := &wf.Rule{ID: wf.RuleID(stableGUID(label)), Name: "Vault 443 " + label, Layer: layer, Sublayer: sublayerID, Provider: providerID, Persistent: true, Action: action, Weight: weight, Conditions: conditions}
		rules = append(rules, r)
		return r
	}
	// An inbound flow authorizes its replies at RECV_ACCEPT, not CONNECT.
	// Protect both original authorization layers so installing these filters
	// also reauthorizes existing flows in either direction.
	for _, scope := range []struct {
		layer    wf.LayerID
		v6       bool
		outbound bool
		suffix   string
	}{
		{wf.LayerALEAuthConnectV4, false, true, "-out-0"},
		{wf.LayerALEAuthConnectV6, true, true, "-out-1"},
		{wf.LayerALEAuthRecvAcceptV4, false, false, "-in-0"},
		{wf.LayerALEAuthRecvAcceptV6, true, false, "-in-1"},
	} {
		layer, v6, suffix := scope.layer, scope.v6, scope.suffix
		if len(keys) > 0 {
			add("loopback"+suffix, layer, wf.ActionPermit, 1000000, &wf.Match{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: wf.ConditionFlagIsLoopback})
			// DHCP is necessary to recover an uplink while the Internet is blocked.
			local, remote := uint16(68), uint16(67)
			if v6 {
				local, remote = 546, 547
			}
			app, err := wf.AppID(filepath.Join(os.Getenv("SystemRoot"), "System32", "svchost.exe"))
			if err != nil {
				return nil, err
			}
			add("dhcp"+suffix, layer, wf.ActionPermit, 900000, match(wf.FieldALEAppID, app), match(wf.FieldIPProtocol, wf.IPProtoUDP), match(wf.FieldIPLocalPort, local), match(wf.FieldIPRemotePort, remote))
			if v6 {
				for i, prefix := range []string{"fe80::/10", "ff02::/16"} {
					// RFC 4861 ND and RFC 2710/3810 MLD only. In the Windows
					// SDK ICMP_TYPE/CODE alias IP_LOCAL/REMOTE_PORT (UINT16).
					// A protocol-only exception would also permit echo payloads
					// over the physical LAN when local access is disabled.
					for _, kind := range []uint16{130, 131, 132, 133, 134, 135, 136, 137, 143} {
						add(fmt.Sprintf("neighbor-%d-%d%s", i, kind, suffix), layer, wf.ActionPermit, 900000,
							match(wf.FieldIPProtocol, wf.IPProtoICMPV6), match(wf.FieldIPRemoteAddress, netip.MustParsePrefix(prefix)),
							match(wf.FieldIPLocalPort, kind), match(wf.FieldIPRemotePort, uint16(0)))
					}
				}
			}
		}
		if dnsProtected {
			var trusted []uint64
			for luid := range trustedDNS {
				trusted = append(trusted, luid)
			}
			sort.Slice(trusted, func(i, j int) bool { return trusted[i] < trusted[j] })
			// Complement the trusted LUIDs. New network adapters are covered
			// immediately, before any route-change notification is handled.
			start := uint64(0)
			for i, end := range append(trusted, ^uint64(0)) {
				if start < end {
					for _, port := range []uint16{53, 853} {
						add(fmt.Sprintf("dns-block-%d-%d%s", i, port, suffix), layer, wf.ActionBlock, 800000,
							&wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeRange, Value: wf.Range{From: start, To: end - 1}}, match(wf.FieldIPRemotePort, port))
					}
				}
				start = end + 1
			}
		}
		for _, key := range keys {
			part := g.parts[key]
			if part.BlockAll {
				add(key+"-block"+suffix, layer, wf.ActionBlock, 1)
				if scope.outbound {
					bootLayer := wf.LayerOutboundIPPacketV4
					if v6 {
						bootLayer = wf.LayerOutboundIPPacketV6
					}
					boot := add(key+"-boot"+suffix, bootLayer, wf.ActionBlock, 1)
					boot.Persistent = false
					boot.BootTime = true
				}
			}
			luid := part.Default4
			if v6 {
				luid = part.Default6
			}
			if luid != 0 {
				add(key+"-tunnel"+suffix, layer, wf.ActionPermit, 200, match(wf.FieldIPLocalInterface, luid))
			}
			if v6 && part.Probe6 != 0 {
				app, e := wf.AppID(part.ProbeApp)
				if e != nil {
					return nil, e
				}
				add(key+"-probe6"+suffix, layer, wf.ActionPermit, 200, match(wf.FieldIPLocalInterface, part.Probe6), match(wf.FieldALEAppID, app), match(wf.FieldALEUserID, systemOnly))
			}
			for i, route := range part.Routes {
				if route.Prefix.Addr().Is6() != v6 {
					continue
				}
				conditions := []*wf.Match{match(wf.FieldIPRemoteAddress, route.Prefix)}
				action := wf.ActionBlock
				if route.Interface != 0 {
					action = wf.ActionPermit
					conditions = append(conditions, match(wf.FieldIPLocalInterface, route.Interface))
				}
				add(fmt.Sprintf("%s-route-%d%s", key, i, suffix), layer, action, uint64(500000+route.Prefix.Bits()), conditions...)
				// A separate destination block prevents another interface, including
				// the main VPN, from taking over a protected work destination.
				if route.Interface != 0 {
					add(fmt.Sprintf("%s-route-block-%d%s", key, i, suffix), layer, wf.ActionBlock, uint64(400000+route.Prefix.Bits()), match(wf.FieldIPRemoteAddress, route.Prefix))
				}
				if scope.outbound {
					bootLayer := wf.LayerOutboundIPPacketV4
					if v6 {
						bootLayer = wf.LayerOutboundIPPacketV6
					}
					boot := add(fmt.Sprintf("%s-route-boot-%d%s", key, i, suffix), bootLayer, wf.ActionBlock, uint64(400000+route.Prefix.Bits()), match(wf.FieldIPRemoteAddress, route.Prefix))
					boot.Persistent = false
					boot.BootTime = true
				}
			}
			for i, prefix := range part.Local {
				if prefix.Addr().Is6() == v6 {
					add(fmt.Sprintf("%s-local-%d%s", key, i, suffix), layer, wf.ActionPermit, 100, match(wf.FieldIPRemoteAddress, prefix))
				}
			}
			for i, endpoint := range part.Endpoints {
				if endpoint.FallbackDNS && blockFallback {
					continue
				}
				if endpoint.Address.Is6() != v6 {
					continue
				}
				protocol := wf.IPProtoTCP
				if endpoint.UDP {
					protocol = wf.IPProtoUDP
				}
				conditions := []*wf.Match{match(wf.FieldALEUserID, systemOnly), match(wf.FieldIPRemoteAddress, endpoint.Address), match(wf.FieldIPRemotePort, endpoint.Port), match(wf.FieldIPProtocol, protocol)}
				if endpoint.Kernel {
					if !endpoint.UDP || endpoint.SourcePort == 0 || endpoint.Interface == 0 {
						return nil, errors.New("unscoped kernel VPN endpoint")
					}
				} else {
					app, e := wf.AppID(endpoint.App)
					if e != nil {
						return nil, e
					}
					conditions = append(conditions, match(wf.FieldALEAppID, app))
				}
				if endpoint.SourcePort != 0 {
					conditions = append(conditions, match(wf.FieldIPLocalPort, endpoint.SourcePort))
				}
				if endpoint.Interface != 0 {
					conditions = append(conditions, match(wf.FieldIPLocalInterface, endpoint.Interface))
				}
				add(fmt.Sprintf("%s-endpoint-%d%s", key, i, suffix), layer, wf.ActionPermit, 950000, conditions...)
			}
			// These ACLs identify the connecting client. RECV_ACCEPT identifies
			// the local helper server instead, so retain its loopback permit.
			if !v6 && scope.outbound {
				for i, port := range part.PrivatePorts {
					conditions := []*wf.Match{match(wf.FieldIPRemoteAddress, netip.MustParseAddr("127.0.0.1")), match(wf.FieldIPRemotePort, port.Port)}
					add(fmt.Sprintf("%s-private-block-%d%s", key, i, suffix), layer, wf.ActionBlock, 1200000, conditions...)
					app, e := wf.AppID(port.App)
					if e != nil {
						return nil, e
					}
					conditions = append(conditions, match(wf.FieldALEAppID, app), match(wf.FieldALEUserID, systemOnly))
					add(fmt.Sprintf("%s-private-allow-%d%s", key, i, suffix), layer, wf.ActionPermit, 1300000, conditions...)
				}
			}
		}
	}
	return rules, nil
}

// The pinned wf version exposes rule composition but no transaction API. Its
// native session handle is read here only; no internal memory is modified. A
// dependency upgrade must retain this checked field or fail before any change.
func transaction(s *wf.Session, fn func() error) error {
	field := reflect.ValueOf(s).Elem().FieldByName("handle")
	if !field.IsValid() || field.Kind() != reflect.Uintptr {
		return errors.New("unsupported pinned WFP session layout")
	}
	handle := uintptr(field.Uint())
	dll := windows.NewLazySystemDLL("fwpuclnt.dll")
	begin, commit, abort := dll.NewProc("FwpmTransactionBegin0"), dll.NewProc("FwpmTransactionCommit0"), dll.NewProc("FwpmTransactionAbort0")
	code, _, _ := begin.Call(handle, 0)
	if code != 0 {
		return windows.Errno(code)
	}
	defer abort.Call(handle)
	if err := fn(); err != nil {
		return err
	}
	code, _, _ = commit.Call(handle)
	if code != 0 {
		return windows.Errno(code)
	}
	return nil
}
func (g *Guard) apply() error {
	rules, err := g.rules()
	if err != nil {
		return err
	}
	s, err := wf.New(&wf.Options{Name: "Vault 443 protection", Dynamic: false, TransactionStartTimeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer s.Close()
	// Record the union before touching WFP. Either side of a crash can then be
	// removed on recovery, including boot-time filters not shown by normal tools.
	all := map[wf.RuleID]bool{}
	for _, id := range g.ids {
		all[id] = true
	}
	for _, r := range rules {
		all[r.ID] = true
	}
	// A provider reference alone is not ownership proof. Keep unknown native
	// filters out of this union; write-before-WFP journals already retain all
	// application IDs, including boot rules and interrupted replacements.
	union := make([]wf.RuleID, 0, len(all))
	for id := range all {
		union = append(union, id)
	}
	data, err := json.Marshal(guardState{union, g.parts})
	if err != nil {
		return err
	}
	if err = securefs.Write(g.path, data); err != nil {
		return err
	}
	err = transaction(s, func() error {
		for _, id := range union {
			if e := s.DeleteRule(id); e != nil && !errors.Is(e, windows.Errno(0x80320003)) {
				return e
			}
		}
		if len(g.parts) == 0 && len(rules) == 0 {
			// Remove only our stable containers, after their filters, in this
			// same transaction. A foreign reference returns FWP_E_IN_USE and
			// aborts the entire cleanup; never remove the referencing object.
			if e := s.DeleteSublayer(sublayerID); e != nil && !errors.Is(e, windows.Errno(windows.FWP_E_SUBLAYER_NOT_FOUND)) {
				return fmt.Errorf("cannot remove Vault 443 WFP sublayer: %w", e)
			}
			if e := s.DeleteProvider(providerID); e != nil && !errors.Is(e, windows.Errno(windows.FWP_E_PROVIDER_NOT_FOUND)) {
				return fmt.Errorf("cannot remove Vault 443 WFP provider: %w", e)
			}
			return nil
		}
		providers, e := s.Providers()
		if e != nil {
			return e
		}
		exists := false
		for _, p := range providers {
			exists = exists || p.ID == providerID
		}
		if !exists {
			if e = s.AddProvider(&wf.Provider{ID: providerID, Name: "Vault 443", Persistent: true}); e != nil {
				return e
			}
		}
		sublayers, e := s.Sublayers(providerID)
		if e != nil {
			return e
		}
		exists = false
		for _, sl := range sublayers {
			exists = exists || sl.ID == sublayerID
		}
		if !exists {
			if e = s.AddSublayer(&wf.Sublayer{ID: sublayerID, Name: "Vault 443", Provider: providerID, Persistent: true, Weight: 0xffff}); e != nil {
				return e
			}
		}
		for _, r := range rules {
			if e = s.AddRule(r); e != nil {
				return fmt.Errorf("cannot install %s: %w", r.Name, e)
			}
		}
		return nil
	})
	if err != nil {
		g.ids = union
		return err
	}
	g.ids = nil
	for _, r := range rules {
		g.ids = append(g.ids, r.ID)
	}
	data, _ = json.Marshal(guardState{g.ids, g.parts})
	return securefs.Write(g.path, data)
}

func (g *Guard) ClearExcept(keep map[string]bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	old := g.parts
	g.parts = map[string]GuardPart{}
	for key, part := range old {
		if keep[key] {
			g.parts[key] = part
		}
	}
	if err := g.apply(); err != nil {
		g.parts = old
		return err
	}
	return nil
}
