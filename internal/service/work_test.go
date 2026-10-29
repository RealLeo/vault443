package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vault443/internal/journal"
	"vault443/internal/worknet"
	"vault443/internal/workvpn"
)

type workFake struct {
	mu          sync.Mutex
	started     chan string
	ended       chan string
	rules       []workvpn.RouteRule
	fail        bool
	failCleanup bool
	cleanup     int
}

func (w *workFake) Run(ctx context.Context, uid uint32, p workvpn.Profile, log *journal.Session, notify func(worknet.Status)) error {
	select {
	case w.started <- p.ID:
	default:
	}
	w.mu.Lock()
	fail := w.fail
	w.mu.Unlock()
	if fail {
		return errors.New("test connection failed")
	}
	notify(worknet.Status{State: "connecting", Stage: "resolving", StageStartedAt: time.Now().UnixMilli()})
	<-ctx.Done()
	select {
	case w.ended <- p.ID:
	default:
	}
	return ctx.Err()
}
func (w *workFake) Forget(ctx context.Context, id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cleanup++
	if w.failCleanup {
		return errors.New("cleanup unavailable")
	}
	return nil
}
func (w *workFake) SetRules(ctx context.Context, r []workvpn.RouteRule) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rules = append([]workvpn.RouteRule{}, r...)
	return nil
}
func (w *workFake) SetDNSRules(context.Context, []workvpn.DNSRule) error { return nil }
func (w *workFake) Routes() []worknet.RouteInfo                          { return []worknet.RouteInfo{} }
func (w *workFake) Snapshot(string) worknet.Status                       { return worknet.Status{State: "connecting"} }
func workFixture(t *testing.T, host string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Work VPN fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	priv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
	return fmt.Sprintf("client\ndev tun\nremote %s 1194 udp\nremote-cert-tls server\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n", host, cert, cert, priv)
}
func setupWork(t *testing.T) (*Service, *workFake, *workvpn.Store, context.Context) {
	t.Helper()
	s, _, _ := setup(t)
	st, e := workvpn.Open(filepath.Join(t.TempDir(), "work"), true)
	if e != nil {
		t.Fatal(e)
	}
	r := &workFake{started: make(chan string, 32), ended: make(chan string, 32)}
	s.AttachWork(st, r)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		end, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		s.StopWork(end)
	})
	return s, r, st, ctx
}
func importWork(t *testing.T, s *Service, c Caller, host string) string {
	t.Helper()
	b, _ := json.Marshal([]WorkImportFile{{Name: "Work", Content: workFixture(t, host)}})
	p, e := s.PrepareOpenVPNImport(c, string(b))
	if e != nil || len(p.Profiles) != 1 {
		t.Fatalf("preview %v %#v", e, p)
	}
	_, e = s.CommitOpenVPNImport(c, p.DraftID, `{}`)
	if e != nil {
		t.Fatal(e)
	}
	return p.Profiles[0].ID
}
func waitWork(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("work state transition timed out")
		}
		time.Sleep(time.Millisecond * 10)
	}
}
func TestWorkImportAtomicPrivateAndExpiring(t *testing.T) {
	s, _, st, _ := setupWork(t)
	c := Caller{UID: 1000}
	source := workFixture(t, "one.example.test")
	b, _ := json.Marshal([]WorkImportFile{{Name: "One", Content: source}, {Name: "Two", Content: source}, {Name: "Unsafe", Content: source + "up /tmp/script\n"}})
	preview, e := s.PrepareOpenVPNImport(c, string(b))
	if e != nil || len(preview.Profiles) != 2 || !preview.Profiles[1].Duplicate || len(preview.Errors) != 1 {
		t.Fatalf("%v %#v", e, preview)
	}
	wire, _ := json.Marshal(preview)
	if strings.Contains(string(wire), "PRIVATE KEY") || strings.Contains(string(wire), "/tmp/script") {
		t.Fatal("preview exposed config contents")
	}
	if len(st.Snapshot().User(1000).Profiles) != 0 {
		t.Fatal("preview wrote profiles")
	}
	if _, e = s.CommitOpenVPNImport(Caller{UID: 1001}, preview.DraftID, `{}`); e == nil {
		t.Fatal("foreign draft accepted")
	}
	icons, _ := json.Marshal(map[string]string{preview.Profiles[0].ID: "shield"})
	if _, e = s.CommitOpenVPNImport(c, preview.DraftID, string(icons)); e != nil {
		t.Fatal(e)
	}
	user := st.Snapshot().User(1000)
	if len(user.Profiles) != 1 || user.Profiles[0].IconID != "shield" {
		t.Fatal("non-atomic duplicate/icon import")
	}
	preview, e = s.PrepareOpenVPNImport(c, string(b))
	if e != nil {
		t.Fatal(e)
	}
	s.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if _, e = s.CommitOpenVPNImport(c, preview.DraftID, `{}`); e == nil {
		t.Fatal("expired draft accepted")
	}
}
func TestWorkMultipleSessionsRemainResponsiveAndIsolated(t *testing.T) {
	s, r, st, ctx := setupWork(t)
	c := Caller{UID: 1000}
	one := importWork(t, s, c, "one.example.test")
	two := importWork(t, s, c, "two.example.test")
	for _, id := range []string{one, two} {
		if _, e := s.RequestOpenVPNConnect(ctx, c, id); e != nil {
			t.Fatal(e)
		}
		select {
		case <-r.started:
		case <-time.After(time.Second):
			t.Fatal("attempt did not start")
		}
	}
	start := time.Now()
	snapshot := s.GetSnapshot(c)
	_, e := s.GetOpenVPNDiagnostics(c, one)
	if e != nil || time.Since(start) > 200*time.Millisecond || len(snapshot.WorkProfiles) != 2 {
		t.Fatal("blocked state read", e)
	}
	foreign := Caller{UID: 1001}
	if !s.GetSnapshot(foreign).BusyByOtherUser {
		t.Fatal("missing shared ownership")
	}
	id := importOne(t, s, foreign, link)
	if _, e := s.RequestConnect(ctx, foreign, id); e == nil {
		t.Fatal("foreign VLESS started alongside work owner")
	}
	if _, e := s.RequestOpenVPNDisconnect(ctx, foreign, one); e == nil {
		t.Fatal("foreign disconnect allowed")
	}
	if _, e := s.GetOpenVPNLogs(foreign, one, "", 100); e == nil {
		t.Fatal("foreign logs allowed")
	}
	if _, e = s.RequestOpenVPNDisconnect(ctx, c, one); e != nil {
		t.Fatal(e)
	}
	waitWork(t, func() bool { s.work.mu.Lock(); defer s.work.mu.Unlock(); return s.work.actors[one] == nil })
	if len(st.Snapshot().Desired) != 1 || st.Snapshot().Desired[0].ProfileID != two {
		t.Fatal("disconnect cleared sibling intent")
	}
	s.work.mu.Lock()
	running := s.work.actors[two] != nil
	s.work.mu.Unlock()
	if !running {
		t.Fatal("sibling stopped")
	}
}
func TestWorkRetryCancellationAndCleanupOwnership(t *testing.T) {
	s, r, st, ctx := setupWork(t)
	c := Caller{UID: 1000}
	id := importWork(t, s, c, "one.example.test")
	r.fail = true
	r.failCleanup = true
	if _, e := s.RequestOpenVPNConnect(ctx, c, id); e != nil {
		t.Fatal(e)
	}
	waitWork(t, func() bool {
		p := s.GetSnapshot(c).WorkProfiles[0]
		return p.Operation != nil && p.Operation.Stage == "retry_wait"
	})
	p := s.GetSnapshot(c).WorkProfiles[0]
	if p.LastFailure == nil || p.Operation.NextRetryAt-p.Operation.StageStartedAt < 990 {
		t.Fatal("retry delay/error incorrect")
	}
	if _, e := s.RequestOpenVPNDisconnect(ctx, c, id); e != nil {
		t.Fatal(e)
	}
	waitWork(t, func() bool { return s.GetSnapshot(c).WorkProfiles[0].Runtime.Stage == "cleanup_failed" })
	if len(st.Snapshot().Desired) != 0 {
		t.Fatal("disconnect did not persist cancellation")
	}
	if !s.GetSnapshot(Caller{UID: 1001}).BusyByOtherUser {
		t.Fatal("ownership released before cleanup")
	}
	r.mu.Lock()
	r.failCleanup = false
	r.mu.Unlock()
	if _, e := s.RequestOpenVPNDisconnect(ctx, c, id); e != nil {
		t.Fatal(e)
	}
	waitWork(t, func() bool { return !s.GetSnapshot(Caller{UID: 1001}).BusyByOtherUser })
	if s.GetSnapshot(c).WorkProfiles[0].LastFailure == nil {
		t.Fatal("disconnect erased failure")
	}
	time.Sleep(1100 * time.Millisecond)
	r.mu.Lock()
	cleanup := r.cleanup
	r.mu.Unlock()
	if cleanup != 2 {
		t.Fatalf("cleanup calls %d", cleanup)
	}
}
func TestWorkRestartIntentionAndFreshBoot(t *testing.T) {
	s, r, st, ctx := setupWork(t)
	c := Caller{UID: 1000}
	id := importWork(t, s, c, "one.example.test")
	if e := st.Update(func(v *workvpn.State) error {
		v.BootID = "boot-a"
		v.Desired = []workvpn.Desired{{UID: 1000, ProfileID: id}}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := s.StartWork(ctx, "boot-a"); e != nil {
		t.Fatal(e)
	}
	select {
	case <-r.started:
	case <-time.After(time.Second):
		t.Fatal("restart did not resume")
	}
	if _, e := s.RequestOpenVPNDisconnect(ctx, c, id); e != nil {
		t.Fatal(e)
	}
	waitWork(t, func() bool { return !s.GetSnapshot(Caller{UID: 1001}).BusyByOtherUser })
	if e := st.Update(func(v *workvpn.State) error { v.Desired = []workvpn.Desired{{UID: 1000, ProfileID: id}}; return nil }); e != nil {
		t.Fatal(e)
	}
	if e := s.StartWork(ctx, "boot-b"); e != nil {
		t.Fatal(e)
	}
	if len(st.Snapshot().Desired) != 0 {
		t.Fatal("reboot auto-started manual work profile")
	}
}
func TestWorkRulesArePrivateAndCanonical(t *testing.T) {
	s, _, st, ctx := setupWork(t)
	c := Caller{UID: 1000}
	id := importWork(t, s, c, "one.example.test")
	if e := s.SetWorkRoute(ctx, c, "192.168.100.15", id); e != nil {
		t.Fatal(e)
	}
	if e := s.SetWorkDNS(ctx, c, "Work.Example.test.", id); e != nil {
		t.Fatal(e)
	}
	u := st.Snapshot().User(c.UID)
	if len(u.Rules) != 1 || u.Rules[0].CIDR != "192.168.100.15/32" || len(u.DNSRules) != 1 {
		t.Fatalf("bad rules %#v", u.Rules)
	}
	if e := s.SetWorkRoute(ctx, c, "0.0.0.0/0", "local"); e == nil {
		t.Fatal("physical default bypass allowed")
	}
	if e := s.SetWorkRoute(ctx, Caller{UID: 1001}, "10.0.0.1", id); e == nil {
		t.Fatal("rule points to foreign profile")
	}
	if e := s.RemoveOpenVPNProfile(c, id); e == nil {
		t.Fatal("removed profile with rule references")
	}
	if e := s.RemoveWorkRoute(ctx, c, u.Rules[0].ID); e != nil {
		t.Fatal(e)
	}
	if e := s.RemoveWorkDNS(ctx, c, u.DNSRules[0].ID); e != nil {
		t.Fatal(e)
	}
	if e := s.RemoveOpenVPNProfile(c, id); e != nil {
		t.Fatal(e)
	}
}

func TestWorkDisconnectCleansRecoveryWithoutLiveActor(t *testing.T) {
	s, r, _, ctx := setupWork(t)
	c := Caller{UID: 1000}
	id := importWork(t, s, c, "orphan.example.test")
	r.failCleanup = true
	if _, e := s.RequestOpenVPNDisconnect(ctx, c, id); e != nil {
		t.Fatal(e)
	}
	waitWork(t, func() bool { return s.GetSnapshot(c).WorkProfiles[0].Runtime.Stage == "cleanup_failed" })
	if !s.GetSnapshot(Caller{UID: 1001}).BusyByOtherUser {
		t.Fatal("orphan cleanup lost owner")
	}
	r.mu.Lock()
	r.failCleanup = false
	r.mu.Unlock()
	if _, e := s.RequestOpenVPNDisconnect(ctx, c, id); e != nil {
		t.Fatal(e)
	}
	waitWork(t, func() bool { return !s.GetSnapshot(Caller{UID: 1001}).BusyByOtherUser })
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cleanup != 2 {
		t.Fatal("orphan cleanup was skipped", r.cleanup)
	}
}
func TestWorkFailureRecoveryReadsBeyondNewestPage(t *testing.T) {
	s, r, st, _ := setupWork(t)
	c := Caller{UID: 1000}
	id := importWork(t, s, c, "history.example.test")
	logs, e := journal.Open(filepath.Join(t.TempDir(), "journal"), journal.Options{QueueSize: 4096})
	if e != nil {
		t.Fatal(e)
	}
	defer logs.Close()
	log := logs.NewSession(c.UID, id)
	log.RecordFailure("openvpn_failed", "Historic work failure", time.Now().UnixMilli())
	logs.Flush()
	for i := 0; i < 650; i++ {
		log.Log("info", fmt.Sprintf("Follow-up message %d", i))
	}
	logs.Flush()
	s.journal = logs
	s.AttachWork(st, r)
	f := s.GetSnapshot(c).WorkProfiles[0].LastFailure
	if f == nil || f.Message != "Historic work failure" || f.Code != "openvpn_failed" {
		t.Fatalf("failure not restored %#v", f)
	}
	if e = s.ClearOpenVPNLogs(c, id); e != nil {
		t.Fatal(e)
	}
	if s.GetSnapshot(c).WorkProfiles[0].LastFailure != nil {
		t.Fatal("cleared failure still shown")
	}
}
