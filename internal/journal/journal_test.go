package journal

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTest(t *testing.T, opts ...Options) *Journal {
	t.Helper()
	j, e := Open(filepath.Join(t.TempDir(), "journal"), opts...)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := j.Close(); e != nil {
			t.Error(e)
		}
	})
	return j
}
func page(t *testing.T, j *Journal, uid uint32, id string) Page {
	t.Helper()
	p, e := j.Read(uid, id, "", 500)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestPrivatePersistentOwnershipAndPagination(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	a := j.NewSession(1000, "first", "PRIVATE_KEY_VALUE")
	b := j.NewSession(1001, "first")
	c := j.NewSession(1000, "second")
	a.Log("info", "first message")
	b.Log("warning", "other user")
	c.Log("debug", "other profile")
	a.Log("error", "PRIVATE_KEY_VALUE password=hunter2 vless://uuid@host:443 \x1b[31mfailed\x1b[0m\u202etest")
	j.Flush()
	p, e := j.Read(1000, "first", "", 1)
	if e != nil || len(p.Entries) != 1 {
		t.Fatalf("page: %+v %v", p, e)
	}
	next, e := j.Read(1000, "first", p.NextCursor, 10)
	if e != nil || len(next.Entries) != 1 {
		t.Fatalf("next page: %+v %v", next, e)
	}
	if next.Entries[0].SessionID != a.ID() || next.Entries[0].Level != "error" {
		t.Fatal("session lost")
	}
	empty, e := j.Read(1000, "first", next.NextCursor, 10)
	if e != nil || len(empty.Entries) != 0 || empty.NextCursor != next.NextCursor {
		t.Fatal("polling cursor was reset")
	}
	if got := page(t, j, 1002, "first"); len(got.Entries) != 0 {
		t.Fatal("another UID received logs")
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	j, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if got := page(t, j, 1000, "first"); len(got.Entries) != 2 {
		t.Fatal("history lost after reopening")
	}
	if got := page(t, j, 1001, "first"); len(got.Entries) != 1 || got.Entries[0].Message != "other user" {
		t.Fatal("owners mixed")
	}
	filepath.Walk(dir, func(path string, fi os.FileInfo, e error) error {
		if e != nil {
			t.Fatal(e)
		}
		if fi.Mode().Perm()&0077 != 0 {
			t.Errorf("unsafe permissions %s", path)
		}
		if fi.Mode().IsRegular() {
			data, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			for _, secret := range []string{"PRIVATE_KEY_VALUE", "hunter2", "vless://", "\\u001b", "\\u202e"} {
				if strings.Contains(string(data), secret) {
					t.Errorf("secret/control persisted: %s", secret)
				}
			}
		}
		return nil
	})
}
func TestClearInvalidatesQueuedEntriesWithoutStoppingSession(t *testing.T) {
	j := openTest(t, Options{FlushInterval: time.Hour})
	s := j.NewSession(1000, "profile")
	s.Log("info", "queued before clear")
	if e := j.Clear(1000, "profile"); e != nil {
		t.Fatal(e)
	}
	j.Flush()
	if len(page(t, j, 1000, "profile").Entries) != 0 {
		t.Fatal("queued history reappeared after clear")
	}
	s.Log("info", "new record after clear")
	j.Flush()
	p := page(t, j, 1000, "profile")
	if len(p.Entries) != 1 || p.Entries[0].Message != "new record after clear" {
		t.Fatalf("live session broken after clear: %+v", p)
	}
}
func TestRetentionAndOldestFirstSizeLimits(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	j := openTest(t, Options{Now: func() time.Time { return now }, ProfileBytes: 1800, UserBytes: 2600, FlushInterval: time.Hour})
	a := j.NewSession(1000, "old")
	b := j.NewSession(1000, "new")
	other := j.NewSession(1001, "separate")
	for n := 0; n < 12; n++ {
		a.Log("info", fmt.Sprintf("old %02d %s", n, strings.Repeat("x", 100)))
	}
	j.Flush()
	p := page(t, j, 1000, "old")
	if len(p.Entries) == 0 || len(p.Entries) >= 12 || !strings.Contains(p.Entries[len(p.Entries)-1].Message, "old 11") {
		t.Fatalf("profile rotation %+v", p)
	}
	for n := 0; n < 12; n++ {
		b.Log("info", fmt.Sprintf("new %02d %s", n, strings.Repeat("x", 100)))
	}
	other.Log("info", "separate user survives quota")
	j.Flush()
	if len(page(t, j, 1000, "old").Entries) >= len(p.Entries) {
		t.Fatal("UID quota did not evict oldest profile records")
	}
	if len(page(t, j, 1001, "separate").Entries) != 1 {
		t.Fatal("quota crossed UID boundary")
	}
	sums := map[string]int64{}
	filepath.Walk(j.dir, func(path string, fi os.FileInfo, e error) error {
		if e != nil {
			t.Fatal(e)
		}
		if fi.Mode().IsRegular() {
			if fi.Size() > 1800 {
				t.Errorf("profile quota exceeded: %d", fi.Size())
			}
			sums[filepath.Dir(path)] += fi.Size()
		}
		return nil
	})
	for _, n := range sums {
		if n > 2600 {
			t.Errorf("UID quota exceeded: %d", n)
		}
	}
	now = now.Add(7*24*time.Hour + time.Second)
	j.drain(true)
	if len(page(t, j, 1000, "new").Entries) != 0 || len(page(t, j, 1001, "separate").Entries) != 0 {
		t.Fatal("expired history retained")
	}
	a.Log("info", "new week")
	j.Flush()
	if len(page(t, j, 1000, "old").Entries) != 1 {
		t.Fatal("new history failed after retention cleanup")
	}
}
func TestFloodNonblockingAndConcurrentCursorOrder(t *testing.T) {
	j := openTest(t, Options{QueueSize: 16, FlushInterval: time.Hour})
	s := j.NewSession(1000, "flood")
	done := make(chan struct{})
	go func() {
		for n := 0; n < 10000; n++ {
			s.Log("debug", "finite bounded flood")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("producer blocked on full journal queue")
	}
	if len(j.queue) != 16 {
		t.Fatal("queue unbounded or unexpectedly drained")
	}
	j.Flush()
	s.Log("info", "after flood")
	j.Flush()
	p := page(t, j, 1000, "flood")
	found := false
	for _, e := range p.Entries {
		if strings.Contains(e.Message, "messages omitted") {
			found = true
		}
	}
	if !found {
		t.Fatal("dropped records not reported")
	}
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for x := 0; x < 20; x++ {
				s.Log("info", "parallel")
			}
		}()
	}
	wg.Wait()
	j.Flush()
	p = page(t, j, 1000, "flood")
	var prev uint64
	for _, e := range p.Entries {
		v, _ := strconv.ParseUint(e.ID, 10, 64)
		if v <= prev {
			t.Fatal("cursor order lost under concurrency")
		}
		prev = v
	}
}
func TestSanitizerHandlesKnownEncodedSecretsAndControls(t *testing.T) {
	secret := "a+b/credential?part=value"
	got := sanitize("\x1b]0;malicious title\x07hello\x1b[31m UUID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee publicKey=abc123 Authorization:Bearer_token token='abcdef' https://host/path?token=foo a%2Bb%2Fcredential%3Fpart%3Dvalue\n\r\x00\u202e", secretVariants([]string{secret}))
	for _, raw := range []string{"malicious title", "aaaaaaaa", "abc123", "abcdef", "https://", "a%2Bb", "\x1b", "\x00", "\u202e"} {
		if strings.Contains(got, raw) {
			t.Errorf("sanitizer retained %q in %q", raw, got)
		}
	}
	if len(Sanitize(strings.Repeat("Ж", 5000))) > MaxMessageBytes {
		t.Fatal("message bound exceeded")
	}
}
func TestUnsafeJournalPathsAreRejected(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	if j, e := Open(dir); e == nil {
		j.Close()
		t.Fatal("accepted public journal directory")
	}
	root := t.TempDir()
	target := t.TempDir()
	if e := os.Symlink(target, filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	if j, e := Open(filepath.Join(root, "link")); e == nil {
		j.Close()
		t.Fatal("accepted symlink")
	}
}

func TestAuthorizationAndQuotedSecretsAreFullyRemoved(t *testing.T) {
	for _, v := range []string{`Authorization: Bearer supersecret`, `Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l`, `password="secret words"`, `{"token":"secret \"words\""}`} {
		clean := Sanitize(v)
		for _, secret := range []string{"supersecret", "YWxhZGRpbjpvcGVuc2VzYW1l", "secret", "words"} {
			if strings.Contains(clean, secret) {
				t.Errorf("credential leaked from %q: %q", v, clean)
			}
		}
	}
	if clean := sanitize(strings.Repeat("x", MaxMessageBytes*4-3)+"SECRET_VALUE", []string{"SECRET_VALUE"}); strings.Contains(clean, "SEC") {
		t.Fatal("truncated credential fragment leaked")
	}
}
func TestNewSessionAndProducerNeverWaitForStorageLock(t *testing.T) {
	j := openTest(t)
	j.mu.Lock()
	done := make(chan struct{})
	go func() { s := j.NewSession(1000, "profile"); s.Log("info", "available while storage busy"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		j.mu.Unlock()
		t.Fatal("VPN producer waited for storage mutex")
	}
	j.mu.Unlock()
	j.Flush()
	if len(page(t, j, 1000, "profile").Entries) != 1 {
		t.Fatal("record missing")
	}
}
func TestTailAndPreviousPagesRemainChronological(t *testing.T) {
	j := openTest(t)
	s := j.NewSession(1000, "profile")
	for n := 0; n < 9; n++ {
		s.Log("info", strconv.Itoa(n))
	}
	j.Flush()
	p, e := j.Read(1000, "profile", "tail", 3)
	if e != nil || len(p.Entries) != 3 || p.Entries[0].Message != "6" || p.Entries[2].Message != "8" || p.PreviousCursor == "" {
		t.Fatalf("tail %+v %v", p, e)
	}
	liveCursor := p.NextCursor
	p, e = j.Read(1000, "profile", p.PreviousCursor, 3)
	if e != nil || len(p.Entries) != 3 || p.Entries[0].Message != "3" || p.Entries[2].Message != "5" || p.PreviousCursor == "" {
		t.Fatalf("older %+v %v", p, e)
	}
	p, e = j.Read(1000, "profile", p.PreviousCursor, 3)
	if e != nil || len(p.Entries) != 3 || p.Entries[0].Message != "0" || p.PreviousCursor != "" {
		t.Fatalf("oldest %+v %v", p, e)
	}
	s.Log("info", "9")
	j.Flush()
	p, e = j.Read(1000, "profile", liveCursor, 3)
	if e != nil || len(p.Entries) != 1 || p.Entries[0].Message != "9" {
		t.Fatalf("poll %+v %v", p, e)
	}
}

func TestFailureMetadataSurvivesRedactionFloodClearAndRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j, err := Open(dir, Options{QueueSize: 1, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	session := j.NewSession(1000, "profile-fa", "fa", "Connection")
	for i := 0; i < 10000; i++ {
		session.Log("debug", fmt.Sprintf("Xray stream %d", i))
	}
	at := time.Now().UnixMilli()
	redacted, epoch := session.RecordFailure("connection_failed", "Connection failed; private fa", at)
	if epoch != 0 || strings.Contains(redacted, "Connection") || strings.Contains(redacted, "fa") {
		t.Fatal("failure text was not redacted", redacted)
	}
	j.Flush()
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	records, err := j.Read(1000, "profile-fa", "tail", 500)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range records.Entries {
		if entry.FailureCode != "" {
			found = true
			if entry.FailureCode != "connection_failed" || entry.FailureTime != at || entry.Message != redacted {
				t.Fatal("metadata damaged by message redaction", entry)
			}
		}
	}
	if !found {
		t.Fatal("normal stream displaced reserved failure")
	}
	session = j.NewSession(1000, "profile-fa", "fa")
	session.RecordFailure("dns_timeout", "before clear", time.Now().UnixMilli())
	if err = j.Clear(1000, "profile-fa"); err != nil {
		t.Fatal(err)
	}
	j.Flush()
	if records = page(t, j, 1000, "profile-fa"); len(records.Entries) != 0 {
		t.Fatal("reserved failure survived clear", records)
	}
	_, epoch = session.RecordFailure("dns_tls", "after clear", time.Now().UnixMilli())
	if epoch != j.Epoch(1000, "profile-fa") {
		t.Fatal("record epoch disagrees with persisted scope")
	}
	j.Flush()
	records = page(t, j, 1000, "profile-fa")
	if len(records.Entries) != 1 || records.Entries[0].FailureCode != "dns_tls" {
		t.Fatal("post-clear failure lost", records)
	}
}

func TestClearPublishesEpochOnlyInsideWriterLockAndAfterSuccessfulDelete(t *testing.T) {
	j := openTest(t, Options{FlushInterval: time.Hour})
	session := j.NewSession(1000, "profile")
	j.mu.Lock()
	started, done := make(chan struct{}), make(chan error, 1)
	go func() { close(started); done <- j.Clear(1000, "profile") }()
	<-started
	// Clear must wait behind the writer lock without advertising its new epoch.
	// Producers remain nonblocking and their pre-clear records retain old scope.
	time.Sleep(20 * time.Millisecond)
	_, epoch := session.RecordFailure("dns_timeout", "before clear commits", time.Now().UnixMilli())
	current := j.Epoch(1000, "profile")
	j.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if epoch != 0 || current != 0 {
		t.Fatal("clear advanced epoch before acquiring writer lock", epoch, current)
	}
	j.Flush()
	if rows := page(t, j, 1000, "profile"); len(rows.Entries) != 0 {
		t.Fatal("pre-clear record survived", rows)
	}
	_, epoch = session.RecordFailure("dns_tls", "after clear commits", time.Now().UnixMilli())
	if epoch != 1 {
		t.Fatal("clear did not advance record scope", epoch)
	}
	j.Flush()
	if rows := page(t, j, 1000, "profile"); len(rows.Entries) != 1 || rows.Entries[0].FailureCode != "dns_tls" {
		t.Fatal("new-epoch record was erased", rows)
	}
	// A failed file deletion must not invalidate queued/persisted records.
	blocked := profileKey(1000, "blocked")
	if err := os.MkdirAll(j.path(blocked), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(j.path(blocked), "child"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := j.Clear(1000, "blocked"); err == nil {
		t.Fatal("expected failed directory deletion")
	}
	if j.Epoch(1000, "blocked") != 0 {
		t.Fatal("failed clear changed record epoch")
	}
}
