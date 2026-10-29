package journal

import (
	"strings"
	"testing"
)

func TestOpenVPNTokensRemovedBeforeRetentionAndDelivery(t *testing.T) {
	for _, message := range []string{"PUSH_REPLY,route 10.0.0.0,auth-token supersecret,auth-token-user dXNlcg==", "auth_token = 'supersecret'", "auth-token-user=supersecret", "auth-token \"supersecret\""} {
		clean := Sanitize(message)
		if strings.Contains(clean, "supersecret") || strings.Contains(clean, "dXNlcg==") {
			t.Fatalf("secret retained: %q", clean)
		}
	}
	if NormalizeFailureCode("openvpn_failed") != "openvpn_failed" {
		t.Fatal("work failure lost its classification")
	}
}
