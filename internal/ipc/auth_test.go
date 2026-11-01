package ipc

import (
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
)

type identity struct {
	uid    uint32
	groups []string
	active bool
	fail   bool
}

func (i identity) UID(dbus.Sender) (uint32, error) {
	if i.fail {
		return 0, errors.New("denied")
	}
	return i.uid, nil
}
func (i identity) Groups(uint32) ([]string, error)  { return i.groups, nil }
func (i identity) LocalActive(uint32) (bool, error) { return i.active, nil }
func TestIdentityPolicy(t *testing.T) {
	for _, tc := range []struct {
		name           string
		i              identity
		allowed, admin bool
	}{
		{"operator", identity{uid: 1000, groups: []string{"vault443"}, active: true}, true, false},
		{"admin", identity{uid: 1000, groups: []string{"vault443", "sudo"}, active: true}, true, true},
		{"wheel admin", identity{uid: 1000, groups: []string{"vault443", "wheel"}, active: true}, true, true},
		{"wheel without enrollment", identity{uid: 1000, groups: []string{"wheel"}, active: true}, false, false},
		{"inactive wheel", identity{uid: 1000, groups: []string{"vault443", "wheel"}}, false, false},
		{"inactive", identity{uid: 1000, groups: []string{"vault443"}}, false, false},
		{"not enrolled", identity{uid: 1000, groups: []string{"sudo"}, active: true}, false, false},
		{"peer lookup failed", identity{fail: true}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := Authorizer{Source: tc.i, OperatorGroup: "vault443"}
			c, err := a.Authorize(":1.42")
			if (err == nil) != tc.allowed {
				t.Fatalf("unexpected policy outcome: %v", err)
			}
			if err == nil && (c.UID != 1000 || c.Admin != tc.admin) {
				t.Fatal("wrong peer identity/privileges")
			}
		})
	}
	a := Authorizer{Source: identity{uid: 1000, groups: []string{"vault443"}, active: true}, OperatorGroup: "vault443"}
	if _, err := a.Authorize("org.attacker.ClaimsRoot"); err == nil {
		t.Fatal("accepted a caller-controlled well-known name")
	}
}
func TestDBusWireDoesNotExposeCallerIdentityArgument(t *testing.T) {
	methods := introspect.Methods(&API{})
	found := false
	for _, m := range methods {
		for _, a := range m.Args {
			if a.Direction == "in" && a.Type == "u" {
				t.Fatalf("%s accepts forgeable UID", m.Name)
			}
		}
		if m.Name == "GetSnapshot" {
			found = true
			for _, a := range m.Args {
				if a.Direction == "in" {
					t.Fatal("Sender leaked onto public wire")
				}
			}
		}
	}
	if !found {
		t.Fatal("snapshot absent from exported methods")
	}
}
