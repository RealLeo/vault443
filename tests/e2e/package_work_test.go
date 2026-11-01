package e2e

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"vault443/internal/workvpn"
)

// Fixture-only store seeding lets the actual hardened systemd unit be tested
// without weakening the production D-Bus active-session authorization policy.
func TestPackageWorkProfiles(t *testing.T) {
	if os.Getenv("VAULT443_PACKAGE_WORK_SEED") != "1" {
		t.Skip("package fixture only")
	}
	requireWorkIsolated(t)
	if os.Getenv("VAULT443_PACKAGE_TEST") != "1" {
		t.Fatal("package isolation missing")
	}
	store, err := workvpn.Open("/var/lib/vault443")
	if err != nil {
		t.Fatal(err)
	}
	first, second := workProfile(t, 1, ""), workProfile(t, 2, "")
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	err = store.Update(func(s *workvpn.State) error {
		s.SetUser(11000, workvpn.WorkUser{Profiles: []workvpn.Profile{first, second}})
		s.SetUser(11001, workvpn.WorkUser{Profiles: []workvpn.Profile{first}})
		s.Desired = []workvpn.Desired{{UID: 11000, ProfileID: first.ID}, {UID: 11000, ProfileID: second.ID}}
		s.BootID = strings.TrimSpace(string(boot))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("VAULT443_PACKAGE_LEGACY_WORK_SEED") == "1" {
		// Only the isolated upgrade fixture needs to materialize the exact old
		// schema. Production migration exclusively runs forward in Store.Open.
		bytes, err := os.ReadFile("/var/lib/vault443/work-vpn.json")
		if err != nil {
			t.Fatal(err)
		}
		var legacy map[string]interface{}
		if err = json.Unmarshal(bytes, &legacy); err != nil {
			t.Fatal(err)
		}
		legacy["version"] = 1
		for _, user := range legacy["users"].(map[string]interface{}) {
			for _, profile := range user.(map[string]interface{})["profiles"].([]interface{}) {
				delete(profile.(map[string]interface{}), "kind")
				delete(profile.(map[string]interface{}), "wireguard")
			}
		}
		bytes, err = json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile("/var/lib/vault443/work-vpn.json", bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPackageWireGuardProfiles(t *testing.T) {
	if os.Getenv("VAULT443_PACKAGE_WIREGUARD_SEED") != "1" {
		t.Skip("package fixture only")
	}
	requireWireGuardFixture(t)
	if os.Getenv("VAULT443_PACKAGE_TEST") != "1" {
		t.Fatal("package isolation missing")
	}
	store, err := workvpn.Open("/var/lib/vault443")
	if err != nil {
		t.Fatal(err)
	}
	first, second := wgProfile(t, "client-1", nil), wgProfile(t, "client-2", nil)
	err = store.Update(func(s *workvpn.State) error {
		user := s.User(11000)
		user.Profiles = append(user.Profiles, first, second)
		s.SetUser(11000, user)
		s.Desired = []workvpn.Desired{{UID: 11000, ProfileID: first.ID}, {UID: 11000, ProfileID: second.ID}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
