package journal

import (
	"strings"
	"testing"
)

func TestWireGuardSecretsAndAmneziaExportAreRedacted(t *testing.T) {
	// Deliberately synthetic strings exercise both source syntax and UAPI's
	// snake_case hex keys; the generic reader must sanitize historical records.
	for _, field := range []string{"PrivateKey", "PresharedKey", "HeaderProtectionKey", "private_key", "preshared_key", "header_protection_key", "client_priv_key"} {
		for _, value := range []string{"c3ludGhldGljLWZpeHR1cmUta2V5LW5vdC1yZWFsLTE=", strings.Repeat("ad", 32)} {
			for _, line := range []string{field + " = " + value, `{"` + field + `":"` + value + `"}`} {
				clean := Sanitize(line)
				if strings.Contains(clean, value) || !strings.Contains(clean, "[redacted]") {
					t.Fatalf("secret leaked for field %s", field)
				}
			}
		}
	}
	if clean := Sanitize("import vpn://ZmljdGlvbmFsLWtleQ failed"); strings.Contains(clean, "ZmljdGlvbmFs") || !strings.Contains(clean, "[redacted URI]") {
		t.Fatal("Amnezia export was retained in a journal")
	}
}
