package workvpn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func privateStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	s, e := Open(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	return s, dir
}
func addProfile(t *testing.T, s *Store, uid uint32) Profile {
	t.Helper()
	p, e := Parse("Work", fixture(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Update(func(st *State) error {
		u := st.User(uid)
		u.Profiles = append(u.Profiles, p)
		st.SetUser(uid, u)
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	return p
}

func TestPrivateStorePersistenceAndIsolation(t *testing.T) {
	s, dir := privateStore(t)
	p := addProfile(t, s, 1000)
	if e := s.Update(func(st *State) error { st.Desired = []Desired{{1000, p.ID}}; st.BootID = "boot-a"; return nil }); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(filepath.Join(dir, StoreFilename))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("state not private", e)
	}
	reopened, e := Open(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	snap := reopened.Snapshot()
	if _, ok := snap.Profile(1000, p.ID); !ok {
		t.Fatal("lost profile")
	}
	if _, ok := snap.Profile(1001, p.ID); ok {
		t.Fatal("wrong owner can retrieve profile")
	}
	u := snap.User(1000)
	u.Profiles[0].Inline["key"] = "changed"
	snap.SetUser(1000, u)
	if s.Snapshot().User(1000).Profiles[0].Inline["key"] == "changed" {
		t.Fatal("snapshot aliases private state")
	}
}

func TestUnsupportedStateNeverOverwritten(t *testing.T) {
	_, dir := privateStore(t)
	path := filepath.Join(dir, StoreFilename)
	for _, raw := range []string{`{"version":2,"users":{}}`, `{"version":1,"users":{},"unrecognized":"x"}`, `{"version":1,"users":{}} {}`} {
		if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := Open(dir, true); e == nil {
			t.Fatal("unsupported state accepted")
		}
		after, _ := os.ReadFile(path)
		if string(after) != raw {
			t.Fatal("unsupported state overwritten")
		}
	}
}

func TestAtomicValidationAndSingleOwner(t *testing.T) {
	s, dir := privateStore(t)
	p := addProfile(t, s, 1000)
	q := addProfile(t, s, 1001)
	before, _ := os.ReadFile(filepath.Join(dir, StoreFilename))
	for _, fn := range []func(*State) error{
		func(st *State) error { st.Version = 123; return nil },
		func(st *State) error { st.Desired = []Desired{{1000, p.ID}, {1001, q.ID}}; return nil },
		func(st *State) error {
			u := st.User(1000)
			u.Profiles[0].Options = append(u.Profiles[0].Options, Option{"up", []string{"/tmp/script"}})
			st.SetUser(1000, u)
			return nil
		},
		func(st *State) error {
			u := st.User(1000)
			u.Profiles[0].Inline["unrecognized"] = "secret"
			st.SetUser(1000, u)
			return nil
		},
	} {
		if e := s.Update(fn); e == nil {
			t.Fatal("invalid update accepted")
		}
		after, _ := os.ReadFile(filepath.Join(dir, StoreFilename))
		if string(before) != string(after) {
			t.Fatal("rejected update modified document")
		}
	}
}

func TestPermissionsAndSymlinks(t *testing.T) {
	s, dir := privateStore(t)
	addProfile(t, s, 1000)
	path := filepath.Join(dir, StoreFilename)
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(dir, true); e == nil {
		t.Fatal("public credentials accepted")
	}
	if e := s.Update(func(*State) error { return nil }); e == nil {
		t.Fatal("public credentials silently repaired")
	}
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	real := path + ".real"
	if e := os.Rename(path, real); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(real, path); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(dir, true); e == nil {
		t.Fatal("symlink accepted")
	}
	if e := s.Update(func(*State) error { return nil }); e == nil {
		t.Fatal("symlink silently replaced")
	}
	link := filepath.Join(t.TempDir(), "link")
	if e := os.Symlink(dir, link); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(link, true); e == nil {
		t.Fatal("symlink directory accepted")
	}
}

func TestRoutingRules(t *testing.T) {
	s, _ := privateStore(t)
	p := addProfile(t, s, 1000)
	r, e := NewRouteRule("192.168.100.15", p.ID)
	if e != nil || r.CIDR != "192.168.100.15/32" {
		t.Fatal("host rule normalization failed", e)
	}
	local, e := NewRouteRule("192.168.100.15/32", "local")
	if e != nil || r.ID != local.ID {
		t.Fatal("changing direction should retain rule identity")
	}
	d, e := NewDNSRule("~Work.Example.Test.", p.ID)
	if e != nil || d.Domain != "work.example.test" {
		t.Fatal("DNS normalization failed", e)
	}
	if e = s.Update(func(st *State) error {
		u := st.User(1000)
		u.Rules = []RouteRule{r}
		u.DNSRules = []DNSRule{d}
		st.SetUser(1000, u)
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = s.Update(func(st *State) error {
		u := st.User(1000)
		u.Rules = append(u.Rules, local)
		st.SetUser(1000, u)
		return nil
	}); e == nil {
		t.Fatal("duplicate rule allowed")
	}
	for _, target := range []string{"/tmp/command", "physical", "ovpn-invalid"} {
		if _, e := NewRouteRule("10.0.0.0/8", target); e == nil {
			t.Fatal("invalid target allowed")
		}
	}
	for _, cidr := range []string{"127.0.0.1", "224.0.0.0/8", "fe80::/64", "::ffff:192.0.2.1/128", "host.example.test"} {
		if _, e := NewRouteRule(cidr, p.ID); e == nil {
			t.Fatal("invalid route accepted", cidr)
		}
	}
	for _, domain := range []string{"example.test\nup script", "*", "bad/name", "-invalid.test"} {
		if _, e := NewDNSRule(domain, p.ID); e == nil {
			t.Fatal("invalid DNS rule accepted")
		}
	}
	// Secrets are intentionally present only in this private state, not errors.
	_, e = Parse("Test", fixture(t)+"setenv SECRET_TOKEN super-secret\n")
	if e == nil || strings.Contains(e.Error(), "super-secret") {
		t.Fatal("unsafe metadata error leak")
	}
	b, _ := json.Marshal(s.Snapshot())
	if !strings.Contains(string(b), `"version":1`) {
		t.Fatal("wrong work state version")
	}
}
