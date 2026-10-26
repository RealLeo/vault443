package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"vault443/internal/model"
)

func TestAtomicPersistenceAndUIDIsolation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Update(func(st *State) error {
		st.SetUser(1001, User{Profiles: []model.Profile{{ID: "a", UUID: "secret"}}})
		st.SetUser(1002, User{Profiles: []model.Profile{{ID: "b"}}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if err = s.Update(func(st *State) error { st.Users = map[string]User{}; return errors.New("abort") }); err == nil {
		t.Fatal("aborted update accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if string(before) != string(after) {
		t.Fatal("failed transaction changed disk")
	}
	reloaded, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	st := reloaded.Snapshot()
	if st.User(1001).Profiles[0].ID != "a" || st.User(1002).Profiles[0].ID != "b" {
		t.Fatal("users mixed")
	}
	st.Users["1001"] = User{}
	if len(reloaded.Snapshot().User(1001).Profiles) != 1 {
		t.Fatal("snapshot aliases live state")
	}
	info, _ := os.Stat(filepath.Join(dir, "state.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("secrets not private")
	}
}
func TestRejectUnsafePathsAndCorruption(t *testing.T) {
	t.Run("directory symlink", func(t *testing.T) {
		base := t.TempDir()
		real := filepath.Join(base, "real")
		os.Mkdir(real, 0700)
		os.Symlink(real, filepath.Join(base, "alias"))
		if _, err := Open(filepath.Join(base, "alias", "state"), true); err == nil {
			t.Fatal("followed symlink ancestor")
		}
	})
	t.Run("file symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "secret")
		os.WriteFile(target, []byte("{}"), 0600)
		os.Symlink(target, filepath.Join(dir, "state.json"))
		if _, err := Open(dir, true); err == nil {
			t.Fatal("followed state symlink")
		}
	})
	t.Run("broad permissions", func(t *testing.T) {
		dir := t.TempDir()
		os.Chmod(dir, 0755)
		if _, err := Open(dir, true); err == nil {
			t.Fatal("world-readable state accepted")
		}
	})
	t.Run("unknown schema", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"version":3,"users":{}}`), 0600)
		if _, err := Open(dir, true); err == nil {
			t.Fatal("unsupported version accepted")
		}
	})
	t.Run("trailing state", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"version":2,"users":{}} {}`), 0600)
		if _, err := Open(dir, true); err == nil {
			t.Fatal("trailing state accepted")
		}
	})
}

func TestUnsupportedSchemaIsNeverRewritten(t *testing.T) {
	for _, version := range []string{"1", "3"} {
		t.Run(version, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")
			original := []byte(`{"version":` + version + `,"users":{}}`)
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			for _, open := range []func(string, bool) (*Store, error){Open, OpenExclusive} {
				if s, err := open(dir, true); err == nil {
					s.Close()
					t.Fatal("unsupported state accepted")
				}
				got, err := os.ReadFile(path)
				if err != nil || string(got) != string(original) {
					t.Fatal("unsupported state modified", err)
				}
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Fatal("unsupported schema created extra files")
			}
		})
	}
}

func TestExclusiveDaemonAndMaintenanceLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenExclusive(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := OpenExclusive(dir, true); err == nil {
		second.Close()
		t.Fatal("second process acquired daemon lock")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenExclusive(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
}
