//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"time"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// This tool opens an enumeration session only. It never calls Add/Delete/Set,
// starts a transaction, changes service configuration, or reads VPN profiles.
type filterTemplate struct {
	Provider        *windows.GUID
	Layer           windows.GUID
	EnumType, Flags uint32
	Context         uintptr
	NumConditions   uint32
	Conditions      uintptr
	ActionMask      uint32
	Callout         uintptr
}
type filterHead struct {
	ID                windows.GUID
	Name, Description *uint16
	Flags             uint32
	Provider          *windows.GUID
}
type counts struct{ Total, Persistent, BootTime, Disabled int }

func run() error {
	h := sha256.Sum256([]byte("Vault443.Windows.WFP.1:provider"))
	id := windows.GUID{Data1: uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3]), Data2: uint16(h[4])<<8 | uint16(h[5]), Data3: uint16(h[6])<<8 | uint16(h[7]), Data4: [8]byte(h[8:16])}
	s, err := wf.New(&wf.Options{Name: "Vault 443 QA read-only WFP inspector", TransactionStartTimeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer s.Close()
	providers, err := s.Providers()
	if err != nil {
		return err
	}
	var provider *wf.Provider
	for _, p := range providers {
		if windows.GUID(p.ID) == id {
			provider = p
		}
	}
	field := reflect.ValueOf(s).Elem().FieldByName("handle")
	if !field.IsValid() || field.Kind() != reflect.Uintptr {
		return fmt.Errorf("unsupported pinned WFP session layout")
	}
	handle := uintptr(field.Uint())
	dll := windows.NewLazySystemDLL("fwpuclnt.dll")
	create, enumerate, destroy, free := dll.NewProc("FwpmFilterCreateEnumHandle0"), dll.NewProc("FwpmFilterEnum0"), dll.NewProc("FwpmFilterDestroyEnumHandle0"), dll.NewProc("FwpmFreeMemory0")
	var result counts
	layers := []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6, wf.LayerALEAuthRecvAcceptV4, wf.LayerALEAuthRecvAcceptV6, wf.LayerOutboundIPPacketV4, wf.LayerOutboundIPPacketV6}
	// SDK FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME=0x8, INCLUDE_DISABLED=0x10.
	// wf.Rules() uses a nil template and does not include these hidden objects.
	for _, layer := range layers {
		tpl := filterTemplate{Provider: &id, Layer: windows.GUID(layer), Flags: 0x8 | 0x10, ActionMask: 0xffffffff}
		var enum windows.Handle
		code, _, _ := create.Call(handle, uintptr(unsafe.Pointer(&tpl)), uintptr(unsafe.Pointer(&enum)))
		if code != 0 {
			return fmt.Errorf("filter enumeration setup: %w", windows.Errno(code))
		}
		var loopErr error
		for {
			var entries **filterHead
			var n uint32
			code, _, _ = enumerate.Call(handle, uintptr(enum), 100, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&n)))
			if code != 0 {
				loopErr = fmt.Errorf("filter enumeration: %w", windows.Errno(code))
				break
			}
			if n > 100 {
				loopErr = fmt.Errorf("invalid filter page size")
				if entries != nil {
					free.Call(uintptr(unsafe.Pointer(&entries)))
				}
				break
			}
			if entries != nil {
				for _, row := range unsafe.Slice(entries, int(n)) {
					if row == nil || row.Provider == nil || *row.Provider != id {
						continue
					}
					result.Total++
					if row.Flags&0x1 != 0 {
						result.Persistent++
					}
					if row.Flags&0x2 != 0 {
						result.BootTime++
					}
					if row.Flags&0x20 != 0 {
						result.Disabled++
					}
				}
				free.Call(uintptr(unsafe.Pointer(&entries)))
			}
			if n == 0 {
				break
			}
		}
		destroy.Call(handle, uintptr(enum))
		if loopErr != nil {
			return loopErr
		}
	}
	out := struct {
		Timestamp          string `json:"timestamp"`
		ProviderID         string `json:"providerId"`
		ProviderFound      bool   `json:"providerFound"`
		ServiceName        string `json:"serviceName"`
		ProviderPersistent bool   `json:"providerPersistent"`
		ProviderDisabled   bool   `json:"providerDisabled"`
		Scope              string `json:"scope"`
		OwnedRules         counts `json:"ownedRules"`
	}{Timestamp: time.Now().UTC().Format(time.RFC3339), ProviderID: id.String(), ProviderFound: provider != nil, Scope: "six Vault443 ALE connect/receive and outbound boot layers; includes disabled and boot-time filters", OwnedRules: result}
	if provider != nil {
		out.ServiceName = provider.ServiceName
		out.ProviderPersistent = provider.Persistent
		out.ProviderDisabled = provider.Disabled
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
