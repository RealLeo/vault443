package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"vault443/internal/model"
)

func TestMainStoreV2MigrationKeepsIdentityAndPrivateBackup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	original := State{Version: 2, Users: map[string]User{"1000": {Profiles: []model.Profile{{ID: "unchanged", Name: "My profile", UUID: "synthetic", IconID: "vault-door", DebugLogging: true, SubscriptionID: "subscription"}}, Subscriptions: []Subscription{{ID: "subscription", URL: "https://source.example/private"}}}}, Boot: &Session{1000, "unchanged"}, Desired: &Session{1000, "unchanged"}, BootID: "same-boot"}
	raw, _ := json.Marshal(original)
	path := filepath.Join(dir, "state.json")
	_ = os.WriteFile(path, raw, 0600)
	st, e := OpenExclusive(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	now := st.Snapshot()
	if now.Version != 3 || !reflect.DeepEqual(now.Boot, original.Boot) || !reflect.DeepEqual(now.Desired, original.Desired) || now.BootID != original.BootID {
		t.Fatal("session identity lost")
	}
	p := now.User(1000).Profiles[0]
	if p.ID != "unchanged" || p.Kind != "vless" || p.Icon() != "vault-door" || !p.DebugLogging || p.SubscriptionID != "subscription" {
		t.Fatal("metadata changed")
	}
	backup := filepath.Join(dir, "state.v2.backup.json")
	b, e := os.ReadFile(backup)
	if e != nil || !bytes.Equal(b, raw) {
		t.Fatal("backup differs")
	}
	fi, _ := os.Stat(backup)
	if fi.Mode().Perm() != 0600 {
		t.Fatal("backup not private")
	}
	if _, e = OpenExclusive(dir, true); e == nil {
		t.Fatal("second writer acquired locked store")
	}
	if e = st.Close(); e != nil {
		t.Fatal(e)
	}
	// Newer/unknown stores remain byte-identical on failed open.
	now.Version = 99
	b, _ = json.Marshal(now)
	_ = os.WriteFile(path, b, 0600)
	if _, e = Open(dir, true); e == nil {
		t.Fatal("unknown version accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, b) {
		t.Fatal("unsupported store overwritten")
	}
}
