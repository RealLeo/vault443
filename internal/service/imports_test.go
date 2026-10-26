package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"vault443/internal/profiles"
)

func TestPreparedREALITYHintImport(t *testing.T) {
	body := "vless://11111111-2222-4333-8444-555555555555@vpn.example:443?encryption=none&flow=xtls-rprx-vision&fp=firefox&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&security=reality&sid=a1b2&sni=www.example.com&spx=%2Ftest-path&support-x25519mlkem768=true&type=tcp#Regression"
	for _, kind := range []string{"text", "subscription"} {
		t.Run(kind, func(t *testing.T) {
			s, _, st := setup(t)
			c := Caller{UID: 1000}
			source, name := body, ""
			if kind == "subscription" {
				source, name = "https://provider.example/sub", "Provider"
				s.fetch = func(context.Context, string) (string, error) {
					return base64.StdEncoding.EncodeToString([]byte(body)), nil
				}
			}
			draft, err := s.PrepareImport(context.Background(), c, source, kind, name)
			if err != nil || len(draft.Errors) != 0 || len(draft.Profiles) != 1 {
				t.Fatalf("hint import failed: %v, issues: %v", err, draft.Errors)
			}
			icons, _ := json.Marshal(map[string]string{draft.Profiles[0].ID: "atom"})
			if _, err := s.CommitImport(c, draft.DraftID, string(icons)); err != nil {
				t.Fatal(err)
			}
			p := st.Snapshot().User(c.UID).Profiles[0]
			if p.Fingerprint != "firefox" || p.IconID != "atom" || p.SpiderX != "/test-path" {
				t.Fatal("prepared import changed profile settings")
			}
		})
	}
}

func TestPreparedImportAtomicIconsOwnershipExpiryAndRestart(t *testing.T) {
	s, runtime, st := setup(t)
	ctx := context.Background()
	c := Caller{UID: 1000}
	now := time.Now()
	s.now = func() time.Time { return now }
	body := link + "\n" + strings.Replace(link, "vpn.example", "second.example", 1) + "\nbad-link"
	draft, err := s.PrepareImport(ctx, c, body, "text", "")
	if err != nil || len(draft.Profiles) != 2 || len(draft.Errors) != 1 {
		t.Fatal(draft, err)
	}
	icons, _ := json.Marshal(map[string]string{draft.Profiles[0].ID: "atom", draft.Profiles[1].ID: "rocket"})
	if _, err = s.CommitImport(Caller{UID: 1001}, draft.DraftID, string(icons)); err == nil {
		t.Fatal("another UID stole a draft")
	}
	if _, err = s.CommitImport(c, draft.DraftID, `{"unknown":"shield"}`); err == nil {
		t.Fatal("accepted unknown profile selection")
	}
	badIcons, _ := json.Marshal(map[string]string{draft.Profiles[0].ID: "../../secret"})
	if _, err = s.CommitImport(c, draft.DraftID, string(badIcons)); err == nil || len(st.Snapshot().User(c.UID).Profiles) != 0 {
		t.Fatal("invalid icons partially committed")
	}
	if _, err = s.CommitImport(c, draft.DraftID, string(icons)); err != nil {
		t.Fatal(err)
	}
	got := st.Snapshot().User(c.UID).Profiles
	if len(got) != 2 || got[0].IconID != "atom" || got[1].IconID != "rocket" {
		t.Fatal("per-profile icons not atomic", got)
	}
	if _, err = s.CommitImport(c, draft.DraftID, string(icons)); err == nil {
		t.Fatal("draft replay accepted")
	}
	duplicate, _ := s.PrepareImport(ctx, c, link, "text", "")
	if !duplicate.Profiles[0].Duplicate || duplicate.Profiles[0].IconID != "atom" {
		t.Fatal("duplicate preview lost metadata")
	}
	if _, err = s.CommitImport(c, duplicate.DraftID, `{}`); err != nil || len(st.Snapshot().User(c.UID).Profiles) != 2 {
		t.Fatal("duplicate import changed library")
	}
	expiring, _ := s.PrepareImport(ctx, c, body, "text", "")
	now = now.Add(importLifetime)
	if _, err = s.CommitImport(c, expiring.DraftID, `{}`); err == nil {
		t.Fatal("expired draft accepted")
	}
	canceled, _ := s.PrepareImport(ctx, c, body, "text", "")
	if err = s.CancelImport(c, canceled.DraftID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CommitImport(c, canceled.DraftID, `{}`); err == nil {
		t.Fatal("canceled draft accepted")
	}
	pending, _ := s.PrepareImport(ctx, c, body, "text", "")
	restarted := New(st, runtime)
	if _, err = restarted.CommitImport(c, pending.DraftID, `{}`); err == nil {
		t.Fatal("unpersisted draft survived restart")
	}
}

func TestPreparedSubscriptionFetchedOnceAndRefreshKeepsMetadata(t *testing.T) {
	s, runtime, st := setup(t)
	c := Caller{UID: 1000}
	ctx := context.Background()
	body := link
	fetches := 0
	s.fetch = func(context.Context, string) (string, error) { fetches++; return body, nil }
	draft, err := s.PrepareImport(ctx, c, "https://provider.example/?token=secret", "subscription", "Provider")
	if err != nil {
		t.Fatal(err)
	}
	body = strings.Replace(link, "vpn.example", "second.example", 1)
	id := draft.Profiles[0].ID
	icons, _ := json.Marshal(map[string]string{id: "gas-mask"})
	if _, err = s.CommitImport(c, draft.DraftID, string(icons)); err != nil {
		t.Fatal(err)
	}
	if fetches != 1 || st.Snapshot().User(c.UID).Profiles[0].ID != id {
		t.Fatal("commit refetched subscription")
	}
	if err = s.UpdateProfile(c, id, "Personal name", "shield"); err != nil {
		t.Fatal(err)
	}
	if err = s.SetProfileDebug(c, id, true); err != nil {
		t.Fatal(err)
	}
	if err = s.Connect(ctx, c, id); err != nil {
		t.Fatal(err)
	}
	calls := runtime.connects
	if err = s.SetProfileDebug(c, id, false); err != nil || runtime.connects != calls {
		t.Fatal("debug change restarted active connection")
	}
	if err = s.SetProfileDebug(c, id, true); err != nil {
		t.Fatal(err)
	}
	if err = s.Disconnect(ctx, c); err != nil {
		t.Fatal(err)
	}
	body = link + "\n" + body
	result := s.RefreshSubscriptions(ctx, c)
	if len(result) != 1 || !result[0].Updated {
		t.Fatal(result)
	}
	got := st.Snapshot().User(c.UID).Profiles
	if len(got) != 2 || got[0].Name != "Personal name" || got[0].IconID != "shield" || !got[0].DebugLogging || got[1].IconID != "antenna" {
		t.Fatal("refresh lost metadata or default icon", got)
	}
	p := got[0]
	p.Name = "other"
	p.IconID = "robot"
	p.DebugLogging = false
	if profiles.Identity(p) != id {
		t.Fatal("display metadata altered connection identity")
	}
	if err = s.UpdateProfile(Caller{UID: 1001}, id, "Other user", "key"); err == nil {
		t.Fatal("another user changed metadata")
	}
	if err = s.SetProfileDebug(Caller{UID: 1001}, id, true); err == nil {
		t.Fatal("another user changed debug logging")
	}
}

func TestPreparedSubscriptionRejectsPartialAndRechecksDuplicates(t *testing.T) {
	s, _, st := setup(t)
	c := Caller{UID: 1000}
	ctx := context.Background()
	s.fetch = func(context.Context, string) (string, error) { return link + "\ninvalid", nil }
	draft, err := s.PrepareImport(ctx, c, "https://provider.example/sub", "subscription", "Provider")
	if err != nil || len(draft.Errors) != 1 {
		t.Fatal(draft, err)
	}
	if _, err = s.CommitImport(c, draft.DraftID, `{}`); err == nil || len(st.Snapshot().User(c.UID).Profiles) != 0 {
		t.Fatal("partial subscription committed")
	}
	draft, err = s.PrepareImport(ctx, c, link, "text", "")
	if err != nil {
		t.Fatal(err)
	}
	id := importOne(t, s, c, link)
	if err = s.UpdateProfile(c, id, "Existing", "radar"); err != nil {
		t.Fatal(err)
	}
	icons, _ := json.Marshal(map[string]string{id: "battery"})
	result, err := s.CommitImport(c, draft.DraftID, string(icons))
	if err != nil || !result.Profiles[0].Duplicate || len(st.Snapshot().User(c.UID).Profiles) != 1 || st.Snapshot().User(c.UID).Profiles[0].IconID != "radar" {
		t.Fatal("commit did not recheck current duplicates", err)
	}
}
