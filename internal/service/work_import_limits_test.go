package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkImportCapacityIsReservedBeforeParsing(t *testing.T) {
	s, _, _, _ := setupWork(t)
	for i := 0; i < 4; i++ {
		if e := s.reserveWorkImport(uint32(1000 + i)); e != nil {
			t.Fatal(e)
		}
	}
	// Deliberately invalid input proves capacity is checked before even JSON
	// decoding. No fifth caller allocates a decoded credential document.
	if _, e := s.PrepareOpenVPNImport(Caller{UID: 2000}, "not-json"); e == nil || !strings.Contains(e.Error(), "being checked") {
		t.Fatalf("missing early global parse bound: %v", e)
	}
	started := time.Now()
	_ = s.GetSnapshot(Caller{UID: 1000})
	if time.Since(started) > 200*time.Millisecond {
		t.Fatal("reserved parses blocked status reads")
	}
	s.work.mu.Lock()
	active := len(s.work.preparing)
	s.releaseWorkImportLocked(1000)
	s.work.mu.Unlock()
	if active != 4 {
		t.Fatal("rejected call consumed capacity")
	}
	if e := s.reserveWorkImport(2000); e != nil {
		t.Fatal("released parse slot was not reusable", e)
	}
}

func TestWorkImportPendingAndInflightShareQuota(t *testing.T) {
	s, _, _, _ := setupWork(t)
	deadline := time.Now().Add(time.Hour)
	s.work.mu.Lock()
	for i := 0; i < 3; i++ {
		s.work.drafts[fmt.Sprintf("own-%d", i)] = workDraft{UID: 1000, Expires: deadline}
	}
	s.work.mu.Unlock()
	if e := s.reserveWorkImport(1000); e != nil {
		t.Fatal(e)
	}
	if _, e := s.PrepareOpenVPNImport(Caller{UID: 1000}, "not-json"); e == nil || !strings.Contains(e.Error(), "pending imports") {
		t.Fatalf("pending plus inflight quota not enforced before parsing: %v", e)
	}
	s.work.mu.Lock()
	s.releaseWorkImportLocked(1000)
	for i := 0; i < 29; i++ {
		s.work.drafts[fmt.Sprintf("other-%d", i)] = workDraft{UID: uint32(2000 + i), Expires: deadline}
	}
	s.work.mu.Unlock()
	if e := s.reserveWorkImport(3000); e == nil {
		t.Fatal("global pending capacity exceeded")
	}
	s.work.mu.Lock()
	s.work.drafts["own-0"] = workDraft{UID: 1000, Expires: time.Now().Add(-time.Minute)}
	s.work.mu.Unlock()
	if e := s.reserveWorkImport(3000); e != nil {
		t.Fatal("expired preview did not release capacity", e)
	}
}

func TestWorkImportReservationsReleaseAndConvert(t *testing.T) {
	s, _, _, _ := setupWork(t)
	c := Caller{UID: 1000}
	for _, bad := range []string{"not-json", `[]`, `[{"name":"x","content":"x","extra":"x"}]`, `[{"name":"x","content":"x"}] {}`} {
		if _, e := s.PrepareOpenVPNImport(c, bad); e == nil {
			t.Fatal("malformed import accepted")
		}
		s.work.mu.Lock()
		n := len(s.work.preparing)
		s.work.mu.Unlock()
		if n != 0 {
			t.Fatal("failed decoding leaked a reservation")
		}
	}
	b, _ := json.Marshal([]WorkImportFile{{Name: "Work", Content: workFixture(t, "one.example.test")}})
	preview, e := s.PrepareOpenVPNImport(c, string(b))
	if e != nil {
		t.Fatal(e)
	}
	s.work.mu.Lock()
	n, drafts := len(s.work.preparing), len(s.work.drafts)
	s.work.mu.Unlock()
	if n != 0 || drafts != 1 {
		t.Fatal("reservation was not atomically converted into one preview")
	}
	if e = s.CancelOpenVPNImport(c, preview.DraftID); e != nil {
		t.Fatal(e)
	}
	s.work.mu.Lock()
	n, drafts = len(s.work.preparing), len(s.work.drafts)
	s.work.mu.Unlock()
	if n != 0 || drafts != 0 {
		t.Fatal("canceled import kept capacity")
	}
}

func TestConcurrentWorkPreviewsStayWithinOwnerQuota(t *testing.T) {
	s, _, _, _ := setupWork(t)
	b, _ := json.Marshal([]WorkImportFile{{Name: "Work", Content: workFixture(t, "one.example.test")}})
	var accepted atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, e := s.PrepareOpenVPNImport(Caller{UID: 1000}, string(b)); e == nil {
				accepted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if accepted.Load() != 4 {
		t.Fatalf("accepted %d previews, expected bounded owner capacity", accepted.Load())
	}
	s.work.mu.Lock()
	n, drafts := len(s.work.preparing), len(s.work.drafts)
	s.work.mu.Unlock()
	if n != 0 || drafts != 4 {
		t.Fatal("concurrent reservations leaked or exceeded quota")
	}
}
