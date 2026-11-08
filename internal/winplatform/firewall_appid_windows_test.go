package winplatform

import (
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWFPAppIDUsesInvariantWindowsLowercase(t *testing.T) {
	for _, test := range []struct{ input, classified string }{
		{`\Device\HarddiskVolume7\Windows\System32\SVCHOST.EXE`, `\device\harddiskvolume7\windows\system32\svchost.exe`},
		// Native ALE_CLASSIFY_DROP used lowercase Cyrillic п, while the original
		// FwpmGetAppIdFromFileName0 blob retained uppercase П for this directory.
		{`\Device\HarddiskVolume7\Программы VPN\Vault443\vault443d.exe`, `\device\harddiskvolume7\программы vpn\vault443\vault443d.exe`},
	} {
		actual, err := lowercaseAppID(test.input)
		if err != nil {
			t.Fatal(err)
		}
		if actual != test.classified {
			t.Errorf("identity %q != classified %q", actual, test.classified)
		}
		// The WFP composer encodes this string as a terminated UTF-16 blob.
		actualBlob, _ := windows.UTF16FromString(actual)
		classifiedBlob, _ := windows.UTF16FromString(test.classified)
		if !reflect.DeepEqual(actualBlob, classifiedBlob) {
			t.Errorf("WFP UTF-16 blobs differ: %x != %x", actualBlob, classifiedBlob)
		}
		again, err := lowercaseAppID(actual)
		if err != nil || again != actual {
			t.Errorf("normalization is not idempotent: %q, %v", again, err)
		}
	}
}

func TestWFPAppIDRejectsEmptyOrEmbeddedNUL(t *testing.T) {
	for _, input := range []string{"", "\\device\\image.exe\x00other.exe"} {
		if _, err := lowercaseAppID(input); err == nil {
			t.Errorf("accepted invalid application identity %q", input)
		}
	}
}
