package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vault443/internal/profiles"
	"vault443/internal/store"
)

func TestDynamicSourceDraftRefreshCacheAndDenial(t *testing.T) {
	s, _, st := setup(t)
	c := Caller{UID: 1000, Admin: true}
	var calls atomic.Int64
	source := `ss://aes-256-gcm:synthetic-password@first.example:8388`
	s.fetch = func(context.Context, string) (string, error) { calls.Add(1); return source, nil }
	prepared, e := s.PrepareImport(context.Background(), c, "ssconf://source.example/secret#Dynamic", "outline", "")
	if e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 || len(prepared.Profiles) != 1 {
		t.Fatal("prepare did not fetch once")
	}
	b, _ := json.Marshal(prepared)
	if strings.Contains(string(b), "synthetic-password") || strings.Contains(string(b), "/secret") {
		t.Fatal("secret escaped preview")
	}
	id := prepared.Profiles[0].ID
	if _, e = s.CommitImport(c, prepared.DraftID, `{"`+id+`":"vault-door"}`); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 {
		t.Fatal("commit fetched twice")
	}
	if _, e = s.CommitImport(Caller{UID: 1001}, prepared.DraftID, "{}"); e == nil {
		t.Fatal("foreign draft accepted")
	}
	source = `ss://aes-256-gcm:new-password@second.example:9999`
	p, e := s.refreshSource(context.Background(), c.UID, id, true)
	if e != nil || p.ID != id || p.Icon() != "vault-door" || p.Server != "second.example" {
		t.Fatal("refresh lost identity or metadata", e)
	}
	s.fetch = func(context.Context, string) (string, error) {
		calls.Add(1)
		return "", errors.New("temporary transport failure")
	}
	p, e = s.refreshSource(context.Background(), c.UID, id, true)
	if e != nil || !p.Source.UsingCached || p.Server != "second.example" {
		t.Fatal("temporary failure lost cache", e)
	}
	before := calls.Load()
	_, _ = s.refreshSource(context.Background(), c.UID, id, false)
	if calls.Load() != before {
		t.Fatal("retry downloaded within one minute")
	}
	s.fetch = func(context.Context, string) (string, error) { return `error: {message: "Quota exceeded"}`, nil }
	p, e = s.refreshSource(context.Background(), c.UID, id, true)
	if e == nil || !p.Source.Blocked || p.Source.UsingCached {
		t.Fatal("provider denial bypassed")
	}
	s.fetch = func(context.Context, string) (string, error) { return "", errors.New("offline") }
	if _, e = s.refreshSource(context.Background(), c.UID, id, true); e == nil {
		t.Fatal("offline refresh cleared provider denial")
	}
	if _, e = s.RequestSourceRefresh(Caller{UID: 1001}, id); e == nil {
		t.Fatal("foreign source refreshed")
	}
	if st.Snapshot().Version != 3 {
		t.Fatal("wrong store schema")
	}
}
func TestSourceRefreshCancellationPreservesMetadataAndUnblocksSnapshot(t *testing.T) {
	s, _, st := setup(t)
	p, e := profiles.ParseOutline(`ss://aes-256-gcm:synthetic@one.example:443`, "https://source.example/key", "Original")
	if e != nil {
		t.Fatal(e)
	}
	p.Source.UpdatedAt = time.Now().Unix()
	_ = st.Update(func(state *store.State) error {
		u := state.User(1000)
		u.Profiles = append(u.Profiles, p)
		state.SetUser(1000, u)
		return nil
	})
	started := make(chan struct{})
	s.fetch = func(ctx context.Context, _ string) (string, error) {
		close(started)
		<-ctx.Done()
		return "", ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := s.refreshSource(ctx, 1000, p.ID, true); done <- e }()
	<-started
	snapshot := s.GetSnapshot(Caller{UID: 1000})
	if len(snapshot.Profiles) == 0 {
		t.Fatal("snapshot unavailable")
	}
	if e := s.RenameProfile(Caller{UID: 1000}, p.ID, "Renamed"); e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh cancellation blocked")
	}
	p, _ = st.Snapshot().Profile(&store.Session{UID: 1000, ProfileID: p.ID})
	if p.Name != "Renamed" || p.Source.UsingCached || p.Source.Blocked {
		t.Fatal("cancellation changed saved profile")
	}
}
