package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"vault443/internal/workvpn"
)

func serviceWGFixture() string {
	key := func(n byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)) }
	return fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=10.88.0.2/32\nDNS=10.88.0.1,corp.example\n[Peer]\nPublicKey=%s\nPresharedKey=%s\nEndpoint=wg.example.test:51820\nAllowedIPs=10.88.0.0/24\n", key(11), key(12), key(13))
}
func importGenericWG(t *testing.T, s *Service, c Caller) string {
	t.Helper()
	raw, _ := json.Marshal([]WorkImportFile{{Name: "WireGuard", Content: serviceWGFixture()}})
	preview, e := s.PrepareWorkImport(c, string(raw))
	if e != nil || len(preview.Errors) > 0 || len(preview.Profiles) != 1 {
		t.Fatalf("generic preparation: %v, %v", e, preview.Errors)
	}
	if preview.Profiles[0].Kind != "wireguard" {
		t.Fatal("missing protocol in preview")
	}
	encoded, _ := json.Marshal(preview)
	if strings.Contains(string(encoded), "PrivateKey") || strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))) {
		t.Fatal("preview leaked credentials")
	}
	if _, e = s.CommitOpenVPNImport(c, preview.DraftID, `{}`); e == nil {
		t.Fatal("legacy commit accepted WG draft")
	}
	if _, e = s.CommitWorkImport(Caller{UID: c.UID + 1}, preview.DraftID, `{}`); e == nil {
		t.Fatal("foreign caller committed draft")
	}
	if _, e = s.CommitWorkImport(c, preview.DraftID, `{}`); e != nil {
		t.Fatal(e)
	}
	return preview.Profiles[0].ID
}

func TestGenericWorkWireGuardImportAndLegacyIsolation(t *testing.T) {
	s, _, st, ctx := setupWork(t)
	c := Caller{UID: 1000}
	id := importGenericWG(t, s, c)
	profile, ok := st.Snapshot().Profile(c.UID, id)
	if !ok || profile.Protocol() != "wireguard" {
		t.Fatal("generic import not stored")
	}
	if e := s.UpdateWorkProfile(c, id, "Renamed", "vault-door"); e != nil {
		t.Fatal(e)
	}
	if e := s.SetWorkDebug(c, id, true); e != nil {
		t.Fatal(e)
	}
	if e := s.UpdateOpenVPNProfile(c, id, "Wrong", "antenna"); e == nil {
		t.Fatal("legacy edit accepted WG")
	}
	if _, e := s.RequestOpenVPNConnect(ctx, c, id); e == nil {
		t.Fatal("legacy connect accepted WG")
	}
	if _, e := s.GetOpenVPNLogs(c, id, "", 10); e == nil {
		t.Fatal("legacy logs accepted WG")
	}
	if _, e := s.RequestWorkConnect(ctx, c, id); e != nil {
		t.Fatal(e)
	}
	if _, e := s.RequestWorkDisconnect(ctx, Caller{UID: 1001}, id); e == nil {
		t.Fatal("foreign disconnect accepted")
	}
	if _, e := s.GetWorkLogs(Caller{UID: 1001}, id, "", 10); e == nil {
		t.Fatal("foreign logs accepted")
	}
	if len(s.GetSnapshot(Caller{UID: 1001}).WorkProfiles) != 0 {
		t.Fatal("foreign snapshot exposed profile")
	}
	snapshot := s.GetSnapshot(c)
	if len(snapshot.WorkProfiles) != 1 || snapshot.WorkProfiles[0].Kind != "wireguard" || snapshot.WorkProfiles[0].Name != "Renamed" {
		t.Fatal("wrong public profile metadata")
	}
	data, _ := json.Marshal(snapshot)
	for _, n := range []byte{11, 13} {
		if strings.Contains(string(data), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32))) {
			t.Fatal("snapshot leaked key")
		}
	}
	if _, e := s.RequestWorkDisconnect(ctx, c, id); e != nil {
		t.Fatal(e)
	}
	waitWork(t, func() bool { return s.GetSnapshot(c).WorkProfiles[0].Operation == nil })
	if e := s.RemoveWorkProfile(c, id); e != nil {
		t.Fatal(e)
	}
}

func TestGenericWorkDraftCancellationDuplicatesAndExpiration(t *testing.T) {
	s, _, st, _ := setupWork(t)
	c := Caller{UID: 1000}
	id := importGenericWG(t, s, c)
	raw, _ := json.Marshal([]WorkImportFile{{Name: "Again", Content: serviceWGFixture()}})
	preview, e := s.PrepareWorkImport(c, string(raw))
	if e != nil || !preview.Profiles[0].Duplicate || preview.Profiles[0].ID != id {
		t.Fatal("duplicate changed identity", e)
	}
	if e = s.CancelWorkImport(Caller{UID: 1001}, preview.DraftID); e == nil {
		t.Fatal("foreign cancel")
	}
	if e = s.CancelWorkImport(c, preview.DraftID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.CommitWorkImport(c, preview.DraftID, `{}`); e == nil {
		t.Fatal("canceled import committed")
	}
	preview, e = s.PrepareWorkImport(c, string(raw))
	if e != nil {
		t.Fatal(e)
	}
	s.work.mu.Lock()
	draft := s.work.drafts[preview.DraftID]
	draft.Expires = time.Now().Add(-time.Hour)
	s.work.drafts[preview.DraftID] = draft
	s.work.mu.Unlock()
	if _, e = s.CommitWorkImport(c, preview.DraftID, `{}`); e == nil {
		t.Fatal("expired import committed")
	}
	if len(st.Snapshot().User(c.UID).Profiles) != 1 {
		t.Fatal("failed draft altered store")
	}
}

func TestGenericWorkRoutesRespectCryptokeyRouting(t *testing.T) {
	s, _, _, ctx := setupWork(t)
	c := Caller{UID: 1000}
	id := importGenericWG(t, s, c)
	if e := s.SetWorkRoute(ctx, c, "10.88.0.15", id); e != nil {
		t.Fatal(e)
	}
	if e := s.SetWorkRoute(ctx, c, "0.0.0.0/0", id); e == nil {
		t.Fatal("route expanded AllowedIPs")
	}
	if e := s.SetWorkDNS(ctx, c, "corp.example", id); e != nil {
		t.Fatal(e)
	}
}

func TestGenericWorkIntentRestoresOnlySameBoot(t *testing.T) {
	s, _, st, _ := setupWork(t)
	c := Caller{UID: 1000}
	id := importGenericWG(t, s, c)
	if e := st.Update(func(state *workvpn.State) error {
		state.BootID = "boot-a"
		state.Desired = []workvpn.Desired{{UID: c.UID, ProfileID: id}}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if e := s.StartWork(ctx, "boot-a"); e != nil {
		t.Fatal(e)
	}
	waitWork(t, func() bool { return s.GetSnapshot(c).WorkProfiles[0].Operation != nil })
	cancel()
	end, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	s.StopWork(end)
	// A fresh service instance is constructed with the same store after a new boot.
	next, _, _ := setup(t)
	next.AttachWork(st, &workFake{started: make(chan string, 1), ended: make(chan string, 1)})
	if e := next.StartWork(context.Background(), "boot-b"); e != nil {
		t.Fatal(e)
	}
	if len(st.Snapshot().Desired) != 0 || next.GetSnapshot(c).WorkProfiles[0].Operation != nil {
		t.Fatal("new boot auto-connected a manual profile")
	}
}
