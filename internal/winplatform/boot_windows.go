package winplatform

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

// The kernel boot GUID survives a service restart and changes on a new boot.
// Wall-clock estimates and per-user registry values are not recovery identities.
func BootID() (string, error) {
	var environment struct {
		ID       windows.GUID
		Firmware uint32
		Flags    uint64
	}
	var returned uint32
	status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQuerySystemInformation").Call(90, uintptr(unsafe.Pointer(&environment)), unsafe.Sizeof(environment), uintptr(unsafe.Pointer(&returned)))
	if status != 0 {
		return "", windows.NTStatus(status)
	}
	return environment.ID.String(), nil
}
