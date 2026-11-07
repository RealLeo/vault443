package network

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"vault443/internal/winplatform"
)

// Only a handle returned by CreateAdapter owns the software device lifetime.
// Holding OpenAdapter after Xray created it would not prevent Xray's creator
// handle from removing the device. Keep the creator in the service instead.
// https://raw.githubusercontent.com/WireGuard/wintun/0.14.1/api/wintun.h
type ownedMainAdapter struct {
	creator *wintun.Adapter
	luid    winipcfg.LUID
}

// Match pinned Xray 26.9.30 proxy/tun/tun_windows.go: md5(name) interpreted as
// the native Windows GUID bytes, including little endian Data1/Data2/Data3.
func mainAdapterGUID() windows.GUID {
	id := md5.Sum([]byte(TunName))
	return windows.GUID{Data1: binary.LittleEndian.Uint32(id[:4]), Data2: binary.LittleEndian.Uint16(id[4:6]), Data3: binary.LittleEndian.Uint16(id[6:8]), Data4: [8]byte(id[8:])}
}

func mainAdapterIdentity(guid windows.GUID, alias, description string) bool {
	return guid == mainAdapterGUID() && alias == TunName && strings.Contains(strings.ToLower(description), "wintun")
}

func mainAdapterRowAllowsCreate(guid *windows.GUID, alias, description string, status winipcfg.IfOperStatus) error {
	if guid == nil || !mainAdapterIdentity(*guid, alias, description) {
		return errors.New("main VPN adapter name or GUID belongs to another interface")
	}
	switch status {
	case winipcfg.IfOperStatusDown, winipcfg.IfOperStatusNotPresent, winipcfg.IfOperStatusLowerLayerDown:
		return nil
	default:
		return fmt.Errorf("main VPN adapter is active or its state is ambiguous (%d); refusing to adopt it", status)
	}
}

func (owner *ownedMainAdapter) verify() error {
	guid, err := owner.luid.GUID()
	if err != nil {
		return fmt.Errorf("cannot verify service-owned main adapter GUID: %w", err)
	}
	iface, err := owner.luid.Interface()
	if err != nil {
		return fmt.Errorf("service-owned main adapter is not ready: %w", err)
	}
	if !mainAdapterIdentity(*guid, iface.Alias(), iface.Description()) {
		return errors.New("service-owned main adapter identity changed")
	}
	return nil
}

// Caller holds m.mu and has stopped the previous Xray process. A fresh Manager
// never opens/adopts an existing row. For an exact inactive identity, permit the
// official Create API to recover its software device and queue vendor orphan
// housekeeping; rejecting every existing row would prevent that recovery path.
func (m *Manager) ensureMainAdapterLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.mainAdapter != nil {
		return m.mainAdapter.verify()
	}
	interfaces, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
	if err != nil {
		return err
	}
	expected := mainAdapterGUID()
	for _, iface := range interfaces {
		guid, err := iface.InterfaceLUID.GUID()
		matchesGUID := err == nil && *guid == expected
		if !strings.EqualFold(iface.Alias(), TunName) && !matchesGUID {
			continue
		}
		if err != nil {
			guid = nil
		}
		if err := mainAdapterRowAllowsCreate(guid, iface.Alias(), iface.Description(), iface.OperStatus); err != nil {
			return err
		}
	}
	creator, err := wintun.CreateAdapter(TunName, "Wintun", &expected)
	if err != nil {
		return fmt.Errorf("cannot create service-owned main adapter: %w", err)
	}
	// Retain this actual creator even if TCP/IP readiness is delayed. Recreating
	// it on every retry would repeat the PnP removal/recreation cycle.
	m.mainAdapter = &ownedMainAdapter{creator: creator, luid: winipcfg.LUID(creator.LUID())}
	if err = ctx.Err(); err != nil {
		return err
	}
	return m.mainAdapter.verify()
}

// Called only after both engines stop. Delete only the exact addresses that the
// previous main configuration assigned; leave other addresses/routes untouched.
// The empty creator-owned adapter remains available for the next Xray open.
func (m *Manager) clearMainAddressesLocked() error {
	if m.mainAdapter == nil {
		return nil
	}
	addresses, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return err
	}
	var owned []winipcfg.MibUnicastIPAddressRow
	for _, row := range addresses {
		if row.InterfaceLUID == m.mainAdapter.luid &&
			((m.v4.IsValid() && row.Address.Addr() == m.v4.Addr() && int(row.OnLinkPrefixLength) == m.v4.Bits()) ||
				(m.v6.IsValid() && row.Address.Addr() == m.v6.Addr() && int(row.OnLinkPrefixLength) == m.v6.Bits())) {
			owned = append(owned, row)
		}
	}
	if err = m.mainAdapter.verify(); err != nil {
		return err
	}
	for _, row := range owned {
		if err = row.Delete(); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return fmt.Errorf("cannot clear service-owned main address: %w", err)
		}
	}
	return winplatform.ConfigureOwnedDNS(m.mainAdapter.luid, false)
}

// Shutdown stops consumers before closing the creator, so SCM shutdown finishes
// the owned device lifetime deliberately. Persistent protection and desired
// connection state remain available to the next service process.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.stop(ctx); err != nil {
		return err
	}
	if m.mainAdapter == nil {
		return nil
	}
	owner := m.mainAdapter
	m.mainAdapter = nil
	return owner.creator.Close()
}
