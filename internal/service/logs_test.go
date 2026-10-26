package service

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"vault443/internal/journal"
)

type logRuntime struct {
	fakeRuntime
	session *journal.Session
}

func (r *logRuntime) SetLogSession(session *journal.Session) { r.session = session }

func TestJournalOwnershipSessionSwitchAndPersistence(t *testing.T) {
	s, _, st := setup(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	r := &logRuntime{}
	s = New(st, r, j)
	ctx := context.Background()
	a, b := Caller{UID: 1000}, Caller{UID: 1001}
	id := importOne(t, s, a, link)
	if _, err = s.GetProfileLogs(b, id, "", 100); err == nil {
		t.Fatal("another user read a private profile journal")
	}
	if err = s.ClearProfileLogs(b, id); err == nil {
		t.Fatal("another user cleared a private profile journal")
	}
	if err = s.Connect(ctx, a, id); err != nil {
		t.Fatal(err)
	}
	oldSession := r.session
	oldSession.Log("debug", "credential 11111111-2222-4333-8444-555555555555\x1b[31m")
	if err = s.TakeControl(ctx, b); err != nil {
		t.Fatal(err)
	}
	importOne(t, s, b, link)
	if err = s.Connect(ctx, b, id); err != nil {
		t.Fatal(err)
	}
	oldSession.Log("warning", "Late output from previous owner")
	r.session.Log("info", "New owner output")
	j.Flush()
	first, err := s.GetProfileLogs(a, id, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.GetProfileLogs(b, id, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !strings.Contains(string(firstJSON), "Late output from previous owner") || strings.Contains(string(secondJSON), "Late output from previous owner") || strings.Contains(string(firstJSON), "New owner output") {
		t.Fatal("late core output acquired another owner")
	}
	if strings.Contains(string(firstJSON), "11111111-2222") || strings.Contains(string(firstJSON), `\u001b`) {
		t.Fatal("journal leaked a credential or terminal escape")
	}
	if len(first.Entries) < 4 || len(second.Entries) < 3 || first.Entries[0].SessionID == second.Entries[0].SessionID {
		t.Fatal("lifecycle or session identity missing")
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	s.journal = j
	reloaded, err := s.GetProfileLogs(a, id, "", 100)
	if err != nil || len(reloaded.Entries) != len(first.Entries) {
		t.Fatal("journal lost history after service restart", err)
	}
	if err = s.ClearProfileLogs(a, id); err != nil {
		t.Fatal(err)
	}
	empty, err := s.GetProfileLogs(a, id, "", 100)
	if err != nil || len(empty.Entries) != 0 {
		t.Fatal("clear did not remove history", err)
	}
	other, err := s.GetProfileLogs(b, id, "", 100)
	if err != nil || len(other.Entries) != len(second.Entries) {
		t.Fatal("clear changed another user's same-ID journal", err)
	}
}
