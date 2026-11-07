package network

import (
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func TestMainAdapterMatchesPinnedXrayGUID(t *testing.T) {
	expected, err := windows.GUIDFromString("{7D31E73C-889C-E1F6-C9C2-21CCAFD7A057}")
	if err != nil || mainAdapterGUID() != expected {
		t.Fatalf("main adapter no longer matches pinned Xray native MD5 GUID: %s %v", mainAdapterGUID().String(), err)
	}
	if !mainAdapterIdentity(expected, TunName, "Wintun Userspace Tunnel") {
		t.Fatal("owned main identity rejected")
	}
	other := expected
	other.Data1++
	if mainAdapterIdentity(other, TunName, "Wintun") || mainAdapterIdentity(expected, "another-vpn", "Wintun") || mainAdapterIdentity(expected, TunName, "Ethernet") {
		t.Fatal("foreign adapter identity accepted")
	}
}

func TestMainAdapterRecoveryRowEligibility(t *testing.T) {
	guid := mainAdapterGUID()
	for _, tc := range []struct {
		status winipcfg.IfOperStatus
		allow  bool
	}{
		{winipcfg.IfOperStatusDown, true},
		{winipcfg.IfOperStatusNotPresent, true},
		{winipcfg.IfOperStatusLowerLayerDown, true},
		{winipcfg.IfOperStatusUp, false},
		{winipcfg.IfOperStatusTesting, false},
		{winipcfg.IfOperStatusUnknown, false},
		{winipcfg.IfOperStatusDormant, false},
		{winipcfg.IfOperStatus(0), false},
		{winipcfg.IfOperStatus(99), false},
	} {
		err := mainAdapterRowAllowsCreate(&guid, TunName, "Wintun Userspace Tunnel", tc.status)
		if (err == nil) != tc.allow {
			t.Errorf("status %d: allow=%t, error=%v", tc.status, tc.allow, err)
		}
	}
}

func TestMainAdapterRecoveryRefusesIdentityCollisions(t *testing.T) {
	guid := mainAdapterGUID()
	foreign := guid
	foreign.Data1++
	for _, tc := range []struct {
		name, alias, description string
		guid                     *windows.GUID
	}{
		{"GUID lookup failed", TunName, "Wintun", nil},
		{"same name foreign GUID", TunName, "Wintun", &foreign},
		{"same GUID foreign name", "another-vpn", "Wintun", &guid},
		{"case-only name collision", "V443-MAIN", "Wintun", &guid},
		{"foreign driver description", TunName, "Ethernet", &guid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, status := range []winipcfg.IfOperStatus{winipcfg.IfOperStatusDown, winipcfg.IfOperStatusNotPresent, winipcfg.IfOperStatusLowerLayerDown} {
				if mainAdapterRowAllowsCreate(tc.guid, tc.alias, tc.description, status) == nil {
					t.Fatalf("inactive foreign identity accepted for creation: status %d", status)
				}
			}
		})
	}
}
