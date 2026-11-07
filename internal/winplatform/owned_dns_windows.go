package winplatform

import (
	"errors"
	"regexp"
	"strings"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var ownedWorkDNSName = regexp.MustCompile(`^v443w[0-9a-f]{8}$`)

func ownedDNSIdentity(alias, description string) bool {
	return (alias == "v443-main" || ownedWorkDNSName.MatchString(alias)) && strings.Contains(strings.ToLower(description), "wintun")
}

// ConfigureOwnedDNS is called only with a creator-owned LUID after the runtime
// verifies its private GUID. It does not enroll adapters based on their name.
// No backup is needed: work adapters are removed by their creator, and the main
// adapter is retained empty until its service-owned creator is closed.
func ConfigureOwnedDNS(luid winipcfg.LUID, enabled bool) error {
	iface, err := luid.Interface()
	if err != nil {
		return err
	}
	if !ownedDNSIdentity(iface.Alias(), iface.Description()) {
		return errors.New("DNS coordinator configuration requires an owned Wintun adapter")
	}
	guid, err := luid.GUID()
	if err != nil {
		return err
	}
	for _, v6 := range []bool{false, true} {
		value := ""
		if enabled {
			value = "127.0.0.1"
			if v6 {
				value = "::1"
			}
		}
		// SetInterfaceDnsSettings changes only the static NameServer field for
		// this GUID/family, preserving suffixes and registration settings.
		if err = setStaticDNS(dnsBackup{GUID: *guid, IPv6: v6}, value); err != nil {
			return err
		}
	}
	return nil
}
