package e2e

import (
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
}
