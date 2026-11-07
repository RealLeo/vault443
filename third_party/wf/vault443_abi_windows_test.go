// Copyright (c) 2026 Vault 443 contributors.
// Use of this source code is governed by the BSD-style license in LICENSE.

package wf

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestVault443FWPMFilter0ABI(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("Vault 443 ships Windows x64 only")
	}
	var filter fwpmFilter0
	for _, check := range []struct {
		name      string
		got, want uintptr
	}{
		{"sizeof", unsafe.Sizeof(filter), 200},
		{"action", unsafe.Offsetof(filter.Action), 128},
		{"rawContext/providerContextKey union", unsafe.Offsetof(filter.Context), 152},
		{"context union sizeof", unsafe.Sizeof(filter.Context), 16},
		{"reserved", unsafe.Offsetof(filter.Reserved), 168},
		{"filterId", unsafe.Offsetof(filter.FilterID), 176},
		{"effectiveWeight", unsafe.Offsetof(filter.EffectiveWeight), 184},
	} {
		t.Logf("%s=%d", check.name, check.got)
		if check.got != check.want {
			t.Errorf("%s=%d, Windows SDK expects %d", check.name, check.got, check.want)
		}
	}
}

func TestVault443ArenaAlignment(t *testing.T) {
	var a arena
	defer a.Dispose()
	const alignment = unsafe.Alignof(uintptr(0))
	// Odd byte/string allocations and padding at a slab boundary previously
	// placed the next FWPM_FILTER0 at an invalid bulk-write-barrier address.
	for iteration := 0; iteration < 20; iteration++ {
		for _, length := range []uintptr{1, 3, 7, 13, slabSize - 1, 1, 2, 15, slabSize} {
			p := a.Alloc(length)
			if uintptr(p)%alignment != 0 {
				t.Fatalf("length %d returned unaligned address %p", length, p)
			}
			filter := (*fwpmFilter0)(a.Alloc(unsafe.Sizeof(fwpmFilter0{})))
			if uintptr(unsafe.Pointer(filter))%alignment != 0 {
				t.Fatalf("filter after length %d has unaligned address %p", length, filter)
			}
			*filter = fwpmFilter0{ProviderKey: toGUID(&a, windows.GUID{Data1: 1})}
		}
	}
}
