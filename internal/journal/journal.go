// Package journal stores private, bounded connection history. Producers only
// enqueue sanitized records; filesystem I/O never runs on a VPN or core pipe.
package journal

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const MaxMessageBytes = 4096
const maxPendingFailures = 1024

type Options struct {
	Retention               time.Duration
	ProfileBytes, UserBytes int64
	QueueSize               int
	FlushInterval           time.Duration
	Now                     func() time.Time
}
type Entry struct {
	ID          string `json:"id"`
	Time        string `json:"time"`
	Level       string `json:"level"`
	Message     string `json:"message"`
	SessionID   string `json:"sessionId"`
	FailureCode string `json:"failureCode,omitempty"`
	FailureTime int64  `json:"failureTime,omitempty"`
}
type Page struct {
	PreviousCursor string  `json:"previousCursor,omitempty"`
	Entries        []Entry `json:"entries"`
	NextCursor     string  `json:"nextCursor"`
}
type key struct {
	uid     uint32
	profile string
}
type record struct {
	Entry
	bytes int64
	at    time.Time
}
type history struct {
	persisted uint64
	rows      []record
	bytes     int64
}
type pending struct {
	key   key
	row   record
	epoch uint64
}
type Journal struct {
	epochs     sync.Map
	produceMu  sync.Mutex
	criticalMu sync.Mutex
	critical   map[key]pending
	dir        string
	opts       Options
	mu         sync.Mutex
	histories  map[key]*history
	err        error
	queue      chan pending
	flush      chan chan struct{}
	stop, done chan struct{}
	closed     atomic.Bool
	sequence   atomic.Uint64
}

// Session keeps ownership and redaction context immutable, even after another
// user/profile takes control while the previous process is finishing its output.
type Session struct {
	journal *Journal
	key     key
	epoch   *atomic.Uint64
	id      string
	secrets []string
	dropped atomic.Uint64
}

func Open(dir string, options ...Options) (*Journal, error) {
	o := Options{Retention: 7 * 24 * time.Hour, ProfileBytes: 10 << 20, UserBytes: 50 << 20, QueueSize: 2048, FlushInterval: 50 * time.Millisecond, Now: time.Now}
	if len(options) > 0 {
		v := options[0]
		if v.Retention > 0 {
			o.Retention = v.Retention
		}
		if v.ProfileBytes > 0 {
			o.ProfileBytes = v.ProfileBytes
		}
		if v.UserBytes > 0 {
			o.UserBytes = v.UserBytes
		}
		if v.QueueSize > 0 {
			o.QueueSize = v.QueueSize
		}
		if v.FlushInterval > 0 {
			o.FlushInterval = v.FlushInterval
		}
		if v.Now != nil {
			o.Now = v.Now
		}
	}
	if !filepath.IsAbs(dir) {
		return nil, errors.New("journal directory must be absolute")
	}
	if e := privateDir(dir); e != nil {
		return nil, e
	}
	j := &Journal{dir: dir, opts: o, histories: map[key]*history{}, critical: map[key]pending{}, queue: make(chan pending, o.QueueSize), flush: make(chan chan struct{}), stop: make(chan struct{}), done: make(chan struct{})}
	j.sequence.Store(uint64(o.Now().UnixNano()))
	if e := j.load(); e != nil {
		return nil, e
	}
	go j.run()
	return j, nil
}
func privateDir(dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return errors.New("cannot create private journal directory")
	}
	fi, e := os.Lstat(dir)
	if e != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0077 != 0 || !owned(fi) {
		return errors.New("journal directory must be private")
	}
	return nil
}
func owned(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}
func profileKey(uid uint32, profileID string) key {
	sum := sha256.Sum256([]byte(profileID))
	return key{uid, hex.EncodeToString(sum[:])}
}
func (j *Journal) path(k key) string {
	return filepath.Join(j.dir, strconv.FormatUint(uint64(k.uid), 10), k.profile+".jsonl")
}
func (j *Journal) NewSession(uid uint32, profileID string, secrets ...string) *Session {
	k := profileKey(uid, profileID)
	epoch, _ := j.epochs.LoadOrStore(k, &atomic.Uint64{})
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		b = []byte(strconv.FormatUint(j.sequence.Add(1), 10))
	}
	return &Session{journal: j, key: k, epoch: epoch.(*atomic.Uint64), id: hex.EncodeToString(b), secrets: secretVariants(secrets)}
}
func (s *Session) ID() string {
	if s == nil {
		return ""
	}
	return s.id
}
func (s *Session) Log(level, message string) {
	if s == nil || s.journal.closed.Load() {
		return
	}
	message = sanitize(message, s.secrets)
	if message == "" {
		return
	}
	if n := s.dropped.Swap(0); n > 0 {
		if !s.enqueue("warning", fmt.Sprintf("Journal rate limit: %d messages omitted", n)) {
			s.dropped.Add(n)
		}
	}
	if !s.enqueue(level, message) {
		s.dropped.Add(1)
	}
}

// RecordFailure keeps machine metadata outside the redacted message. A short
// REALITY ID can occur in ordinary words, code names, or profile hashes; text
// replacement must never corrupt recovery identity. The profile/UID come from
// the immutable journal scope, not a string embedded inside Message.
// The returned message has exactly the same redaction as the persisted record.
func (s *Session) RecordFailure(code, message string, at int64) (string, uint64) {
	var secrets []string
	if s != nil {
		secrets = s.secrets
	}
	message = sanitize(message, secrets)
	if s == nil || s.journal.closed.Load() {
		return message, 0
	}
	accepted, epoch := s.enqueueRecord("error", message, NormalizeFailureCode(code), at)
	if !accepted {
		s.dropped.Add(1)
	}
	return message, epoch
}

// Only controller-defined classifications are allowed in unredacted metadata.
func NormalizeFailureCode(code string) string {
	switch code {
	case "dns_timeout", "dns_no_answer", "dns_not_found", "dns_tls", "dns_transport", "dns_invalid_response", "dns_unavailable", "connection_failed", "openvpn_failed", "core_exited", "cleanup_failed", "previous_failure", "vpn_dns_failed", "vpn_https_timeout", "vpn_https_tls", "vpn_https_response", "vpn_https_failed":
		return code
	default:
		return "connection_failed"
	}
}
func (s *Session) enqueue(level, message string) bool {
	accepted, _ := s.enqueueRecord(level, message, "", 0)
	return accepted
}
func (s *Session) enqueueRecord(level, message, code string, failureTime int64) (bool, uint64) {
	j := s.journal
	j.produceMu.Lock()
	defer j.produceMu.Unlock()
	if j.closed.Load() {
		return false, s.epoch.Load()
	}
	at := j.opts.Now().UTC()
	e := Entry{ID: strconv.FormatUint(j.sequence.Add(1), 10), Time: at.Format(time.RFC3339Nano), Level: normalizeLevel(level), Message: message, SessionID: s.id, FailureCode: code, FailureTime: failureTime}
	b, _ := json.Marshal(e)
	p := pending{s.key, record{e, int64(len(b) + 1), at}, s.epoch.Load()}
	if code != "" {
		// Reserve independent capacity for failure metadata. An unbounded Xray
		// stream can fill the ordinary queue but cannot displace the latest failure.
		// Coalesce each scope; in an exceptional cross-user flood retain newest
		// scopes first, with an explicit bounded memory budget.
		j.criticalMu.Lock()
		if _, exists := j.critical[s.key]; !exists && len(j.critical) >= maxPendingFailures {
			var oldest key
			var oldestID uint64
			for k, pending := range j.critical {
				value := entryID(pending.row)
				if oldestID == 0 || value < oldestID {
					oldest = k
					oldestID = value
				}
			}
			delete(j.critical, oldest)
		}
		j.critical[s.key] = p
		j.criticalMu.Unlock()
		return true, p.epoch
	}
	select {
	case j.queue <- p:
		return true, p.epoch
	default:
		return false, s.epoch.Load()
	}
}
func normalizeLevel(v string) string {
	switch strings.ToLower(v) {
	case "debug":
		return "debug"
	case "warn", "warning":
		return "warning"
	case "error", "fatal":
		return "error"
	default:
		return "info"
	}
}

// Read returns chronological pages. Empty/numeric cursors walk forwards;
// "tail" begins at the newest page and "before:<id>" pages into older history.
// Empty forward pages preserve their cursor for incremental polling.
func (j *Journal) Read(uid uint32, profileID, cursor string, limit int) (Page, error) {
	page := Page{Entries: []Entry{}, NextCursor: cursor}
	backwards := cursor == "tail" || strings.HasPrefix(cursor, "before:")
	var boundary uint64
	if backwards {
		page.NextCursor = ""
	}
	if cursor != "" && cursor != "tail" {
		value := strings.TrimPrefix(cursor, "before:")
		var e error
		boundary, e = strconv.ParseUint(value, 10, 64)
		if e != nil {
			return page, errors.New("invalid journal cursor")
		}
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.err != nil {
		return page, errors.New("connection journal storage is unavailable")
	}
	h := j.histories[profileKey(uid, profileID)]
	if h == nil {
		return page, nil
	}
	cutoff := j.opts.Now().Add(-j.opts.Retention)
	eligible := make([]int, 0, len(h.rows))
	for i, r := range h.rows {
		if r.at.Before(cutoff) {
			continue
		}
		id := entryID(r)
		if backwards {
			if cursor != "tail" && id >= boundary {
				continue
			}
		} else if id <= boundary {
			continue
		}
		eligible = append(eligible, i)
	}
	first, last := 0, len(eligible)
	if backwards {
		if last > limit {
			first = last - limit
		}
	} else if last > limit {
		last = limit
	}
	for _, i := range eligible[first:last] {
		e := h.rows[i].Entry
		e.Message = Sanitize(e.Message)
		page.Entries = append(page.Entries, e)
		page.NextCursor = e.ID
	}
	if len(page.Entries) > 0 {
		firstID, _ := strconv.ParseUint(page.Entries[0].ID, 10, 64)
		for _, r := range h.rows {
			if !r.at.Before(cutoff) && entryID(r) < firstID {
				page.PreviousCursor = "before:" + page.Entries[0].ID
				break
			}
		}
	}
	return page, nil
}

// Epoch identifies which records survive a concurrent clear without requiring
// callers to hold their own state locks during journal filesystem operations.
func (j *Journal) Epoch(uid uint32, profileID string) uint64 {
	epoch, _ := j.epochs.LoadOrStore(profileKey(uid, profileID), &atomic.Uint64{})
	return epoch.(*atomic.Uint64).Load()
}

func (j *Journal) Clear(uid uint32, profileID string) error {
	k := profileKey(uid, profileID)
	epoch, _ := j.epochs.LoadOrStore(k, &atomic.Uint64{})
	j.mu.Lock()
	defer j.mu.Unlock()
	h := j.histories[k]
	if h == nil {
		h = &history{}
		j.histories[k] = h
	}
	if e := os.Remove(j.path(k)); e != nil && !os.IsNotExist(e) {
		return errors.New("cannot clear connection journal")
	}
	// Publish the new epoch while holding the same lock as the writer, only
	// after deletion succeeds. New-epoch records cannot be written then erased
	// by an older Clear that was waiting for this lock.
	epoch.(*atomic.Uint64).Add(1)
	h.rows = nil
	h.bytes = 0
	h.persisted = 0
	return nil
}

// Flush is useful before orderly shutdown and in tests; normal producers never wait.
func (j *Journal) Flush() {
	if j.closed.Load() {
		<-j.done
		return
	}
	ack := make(chan struct{})
	select {
	case j.flush <- ack:
		<-ack
	case <-j.done:
	}
}
func (j *Journal) Close() error {
	j.produceMu.Lock()
	if j.closed.CompareAndSwap(false, true) {
		close(j.stop)
	}
	j.produceMu.Unlock()
	<-j.done
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.err
}
func (j *Journal) run() {
	defer close(j.done)
	tick := time.NewTicker(j.opts.FlushInterval)
	defer tick.Stop()
	sweep := time.NewTicker(time.Hour)
	defer sweep.Stop()
	for {
		select {
		case <-j.stop:
			j.drain(false)
			return
		case ack := <-j.flush:
			j.drain(false)
			close(ack)
		case <-tick.C:
			j.drain(false)
		case <-sweep.C:
			j.drain(true)
		}
	}
}
func (j *Journal) drain(sweep bool) {
	// Bound each batch even under an endless producer; readers and shutdown retain
	// an opportunity to progress. A full queue sheds messages at the producer.
	j.criticalMu.Lock()
	items := make([]pending, 0, len(j.critical)+len(j.queue))
	priority := make(map[key]bool, len(j.critical))
	for k, p := range j.critical {
		items = append(items, p)
		priority[k] = true
		delete(j.critical, k)
	}
	j.criticalMu.Unlock()
	for n := len(j.queue); n > 0; n-- {
		select {
		case p := <-j.queue:
			items = append(items, p)
		default:
			n = 0
		}
	}
	if len(items) == 0 && !sweep {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	changed := map[key]bool{}
	for _, p := range items {
		h := j.histories[p.key]
		epoch, _ := j.epochs.Load(p.key)
		if epoch == nil || epoch.(*atomic.Uint64).Load() != p.epoch {
			continue
		}
		if h == nil {
			h = &history{}
			j.histories[p.key] = h
		}
		p.row.Message = Sanitize(p.row.Message)
		h.rows = append(h.rows, p.row)
		h.bytes += p.row.bytes
		changed[p.key] = false
	}
	j.prune(changed)
	// Persist recovered failure scopes first, then ordinary stream batches.
	for k := range priority {
		if rewrite, ok := changed[k]; ok {
			if e := j.write(k, rewrite); e != nil {
				j.err = e
			}
			delete(changed, k)
		}
	}
	for k := range changed {
		if e := j.write(k, changed[k]); e != nil {
			j.err = e
		}
	}
}
func (j *Journal) prune(changed map[key]bool) {
	cutoff := j.opts.Now().Add(-j.opts.Retention)
	totals := map[uint32]int64{}
	for k, h := range j.histories {
		// Producers may enqueue out of order; IDs provide one stable pagination order.
		if _, ok := changed[k]; ok {
			sort.Slice(h.rows, func(a, b int) bool { return entryID(h.rows[a]) < entryID(h.rows[b]) })
		}
		first := 0
		for first < len(h.rows) && (h.rows[first].at.Before(cutoff) || h.bytes > j.opts.ProfileBytes) {
			h.bytes -= h.rows[first].bytes
			first++
		}
		if first > 0 {
			h.rows = append([]record(nil), h.rows[first:]...)
			changed[k] = true
		}
		totals[k.uid] += h.bytes
	}
	for uid, total := range totals {
		for total > j.opts.UserBytes {
			var oldest key
			found := false
			for k, h := range j.histories {
				if k.uid != uid || len(h.rows) == 0 {
					continue
				}
				if !found || entryID(h.rows[0]) < entryID(j.histories[oldest].rows[0]) {
					oldest = k
					found = true
				}
			}
			if !found {
				break
			}
			h := j.histories[oldest]
			total -= h.rows[0].bytes
			h.bytes -= h.rows[0].bytes
			h.rows = h.rows[1:]
			changed[oldest] = true
		}
	}
}
func entryID(r record) uint64 { n, _ := strconv.ParseUint(r.ID, 10, 64); return n }
func (j *Journal) write(k key, rewrite bool) error {
	h := j.histories[k]
	path := j.path(k)
	if len(h.rows) == 0 {
		e := os.Remove(path)
		if os.IsNotExist(e) {
			return nil
		}
		return e
	}
	if e := privateDir(filepath.Dir(path)); e != nil {
		return e
	}
	if !rewrite {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return errors.New("cannot append connection journal")
		}
		fi, e := f.Stat()
		if e != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 || !owned(fi) {
			f.Close()
			return errors.New("journal file permissions are unsafe")
		}
		w := bufio.NewWriter(f)
		enc := json.NewEncoder(w)
		for _, r := range h.rows {
			if entryID(r) <= h.persisted {
				continue
			}
			if e = enc.Encode(r.Entry); e != nil {
				break
			}
		}
		if e == nil {
			e = w.Flush()
		}
		if e == nil {
			e = f.Sync()
		}
		if ce := f.Close(); e == nil {
			e = ce
		}
		if e != nil {
			return errors.New("cannot persist connection journal")
		}
		h.persisted = entryID(h.rows[len(h.rows)-1])
		return nil
	}
	// Atomic rewrite also repairs permissions and never follows an existing symlink.
	f, e := os.CreateTemp(filepath.Dir(path), ".journal-*")
	if e != nil {
		return errors.New("cannot write connection journal")
	}
	defer os.Remove(f.Name())
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, r := range h.rows {
		if e = enc.Encode(r.Entry); e != nil {
			break
		}
	}
	if e == nil {
		e = w.Flush()
	}
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(f.Name(), path)
	}
	if e != nil {
		return errors.New("cannot persist connection journal")
	}
	h.persisted = entryID(h.rows[len(h.rows)-1])
	return nil
}
func (j *Journal) load() error {
	dirs, e := os.ReadDir(j.dir)
	if e != nil {
		return errors.New("cannot read journal directory")
	}
	changed := map[key]bool{}
	for _, d := range dirs {
		uid, e := strconv.ParseUint(d.Name(), 10, 32)
		if e != nil || !d.IsDir() {
			continue
		}
		dir := filepath.Join(j.dir, d.Name())
		if e = privateDir(dir); e != nil {
			return e
		}
		files, e := os.ReadDir(dir)
		if e != nil {
			return e
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".jsonl") {
				continue
			}
			hash := strings.TrimSuffix(f.Name(), ".jsonl")
			if len(hash) != 64 {
				continue
			}
			if _, e = hex.DecodeString(hash); e != nil {
				continue
			}
			path := filepath.Join(dir, f.Name())
			fi, e := os.Lstat(path)
			if e != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 || !owned(fi) {
				return errors.New("journal file permissions are unsafe")
			}
			if fi.Size() > 64<<20 {
				return errors.New("connection journal exceeds safe read size")
			}
			in, e := os.Open(path)
			if e != nil {
				return e
			}
			scan := bufio.NewScanner(io.LimitReader(in, 64<<20))
			scan.Buffer(make([]byte, 8192), MaxMessageBytes*8)
			k := key{uint32(uid), hash}
			h := &history{}
			for scan.Scan() {
				var v Entry
				if json.Unmarshal(scan.Bytes(), &v) != nil {
					continue
				}
				id, e := strconv.ParseUint(v.ID, 10, 64)
				if e != nil {
					continue
				}
				at, e := time.Parse(time.RFC3339Nano, v.Time)
				if e != nil {
					continue
				}
				v.Message = Sanitize(v.Message)
				if v.FailureCode != "" {
					v.FailureCode = NormalizeFailureCode(v.FailureCode)
					if v.FailureTime <= 0 || v.FailureTime > at.Add(time.Second).UnixMilli() {
						v.FailureTime = at.UnixMilli()
					}
				}
				v.Level = normalizeLevel(v.Level)
				v.SessionID = Sanitize(v.SessionID)
				b, _ := json.Marshal(v)
				h.rows = append(h.rows, record{v, int64(len(b) + 1), at})
				h.bytes += int64(len(b) + 1)
				if id > j.sequence.Load() {
					j.sequence.Store(id)
				}
			}
			scanErr := scan.Err()
			in.Close()
			if scanErr != nil {
				return errors.New("cannot parse connection journal")
			}
			j.histories[k] = h
			changed[k] = true
		}
	}
	j.prune(changed)
	for k := range changed {
		if e = j.write(k, changed[k]); e != nil {
			return e
		}
	}
	return nil
}
