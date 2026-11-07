package winplatform

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const testNRPTGUID = "{59d4e4fc-a059-441e-b466-3c57dad8134c}"
const testNRPTNextGUID = "{70de3b9c-645b-451c-b15e-2e0e1af550bc}"

func newTestNRPTDNS(t *testing.T) *DNS {
	t.Helper()
	d, err := NewDNS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func readTestNRPTState(t *testing.T, path string) dnsState {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state dnsState
	if err = json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state
}
func testNRPTQuestion(t *testing.T, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 17, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	query, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return query
}
func assertNRPTServfail(t *testing.T, d *DNS, name string) {
	t.Helper()
	answer := d.query(context.Background(), testNRPTQuestion(t, name), false)
	var parser dnsmessage.Parser
	header, err := parser.Start(answer)
	if err != nil || header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("expected fail-closed DNS: header=%+v err=%v", header, err)
	}
}

func TestNRPTPreStartIntentAndDurableIdentity(t *testing.T) {
	d := newTestNRPTDNS(t)
	calls := 0
	d.nrptRun = func(ctx context.Context, r nrptRequest) (nrptResponse, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 15*time.Second {
			t.Fatal("NRPT command has no bounded context")
		}
		state := readTestNRPTState(t, d.path)
		if state.NRPT == nil || state.NRPT.OwnerToken != r.OwnerToken || state.NRPT.Phase != "creating" || state.NRPT.RuleGUID != "" {
			t.Fatal("Add could precede durable recovery identity")
		}
		return nrptResponse{RuleGUID: testNRPTGUID, Effective: true}, nil
	}
	plan := DNSPlan{Domains: []string{"corp.example"}, Interface: 1, Active: true}
	if err := d.SetGroup("work:", map[string]DNSPlan{"work:one": plan}, 0); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || d.nrpt != nil || len(d.saved) != 0 {
		t.Fatal("pre-Start plans changed OS DNS or created an NRPT identity")
	}
	assertNRPTServfail(t, d, "app.corp.example.")
	d.started = true // Listener reservation is separately exercised by native service tests.
	if err := d.activatePlansLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !d.nrptReady || d.nrpt.Phase != "active" || d.nrpt.RuleGUID != testNRPTGUID || d.blocked["work:one"] {
		t.Fatal("plans not activated after verified policy")
	}
	if err := d.SetGroup("work:", map[string]DNSPlan{"work:one": plan}, 0); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("unchanged coordinator refresh spawned another PowerShell command")
	}
}

func TestNRPTWorkFullTunnelRootNamespaces(t *testing.T) {
	for _, root := range []string{".", "~."} {
		zones, err := nrptZones(map[string]DNSPlan{"work:wireguard-full": {Domains: []string{root}, Default: true}})
		if err != nil || len(zones) != 1 || zones[0] != "." {
			t.Fatalf("full tunnel root %q rejected: zones=%v err=%v", root, zones, err)
		}
	}
}

func TestNRPTWriteFailureCannotSkipWriteBeforeAddOnRetry(t *testing.T) {
	d := newTestNRPTDNS(t)
	d.plans["main"] = DNSPlan{Default: true}
	original := d.path
	d.path = filepath.Join(filepath.Dir(d.path), "blocked")
	if err := os.Mkdir(d.path, 0700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	d.nrptRun = func(_ context.Context, r nrptRequest) (nrptResponse, error) {
		calls++
		state := readTestNRPTState(t, d.path)
		if state.NRPT == nil || state.NRPT.OwnerToken != r.OwnerToken {
			t.Fatal("retry Add did not have durable identity")
		}
		return nrptResponse{RuleGUID: testNRPTGUID, Effective: true}, nil
	}
	if err := d.ensureNRPTLocked(context.Background()); err == nil || calls != 0 {
		t.Fatal("failed journal write still invoked Add")
	}
	token := d.nrpt.OwnerToken
	d.path = original
	if err := d.ensureNRPTLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || d.nrpt.OwnerToken != token {
		t.Fatal("write retry lost its unique ownership token")
	}
}

func TestNRPTCrashAfterAddBeforeNamePersistenceRecoversSameToken(t *testing.T) {
	d := newTestNRPTDNS(t)
	d.plans["main"] = DNSPlan{Default: true}
	original := d.path
	blocked := filepath.Join(filepath.Dir(original), "blocked")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	var token string
	d.nrptRun = func(_ context.Context, r nrptRequest) (nrptResponse, error) {
		token = r.OwnerToken
		d.path = blocked
		return nrptResponse{RuleGUID: testNRPTGUID, Effective: true}, nil
	}
	if err := d.ensureNRPTLocked(context.Background()); err == nil {
		t.Fatal("post-Add persistence failure was ignored")
	}
	saved := readTestNRPTState(t, original)
	if saved.NRPT.OwnerToken != token || saved.NRPT.RuleGUID != "" || saved.NRPT.Phase != "creating" {
		t.Fatal("crash journal cannot identify Add's exact marker")
	}
	recovered, err := NewDNS(filepath.Dir(original))
	if err != nil {
		t.Fatal(err)
	}
	recovered.plans["main"] = DNSPlan{Default: true}
	recovered.nrptRun = func(_ context.Context, r nrptRequest) (nrptResponse, error) {
		if r.OwnerToken != token || r.RuleGUID != "" {
			t.Fatal("recovery replaced the durable token instead of adopting its matching rule")
		}
		return nrptResponse{RuleGUID: testNRPTGUID, Effective: true}, nil
	}
	if err = recovered.ensureNRPTLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := readTestNRPTState(t, original); state.NRPT.RuleGUID != testNRPTGUID || state.NRPT.OwnerToken != token {
		t.Fatal("recovered rule identity not persisted")
	}
}

func TestNRPTMissingKnownRulePersistsNewAddBoundary(t *testing.T) {
	d := newTestNRPTDNS(t)
	d.nrpt = &nrptState{OwnerToken: testNRPTGUID, RuleGUID: testNRPTGUID, Phase: "active"}
	d.plans["main"] = DNSPlan{Default: true}
	if err := d.saveLocked(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	d.nrptRun = func(_ context.Context, r nrptRequest) (nrptResponse, error) {
		calls++
		if calls == 1 {
			return nrptResponse{Missing: true}, nil
		}
		state := readTestNRPTState(t, d.path)
		if r.RuleGUID != "" || state.NRPT.RuleGUID != "" || state.NRPT.Phase != "creating" {
			t.Fatal("recreated rule could leave an obsolete GUID in crash journal")
		}
		return nrptResponse{RuleGUID: testNRPTNextGUID, Effective: true}, nil
	}
	if err := d.ensureNRPTLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || d.nrpt.RuleGUID != testNRPTNextGUID {
		t.Fatal("known missing rule was not safely recreated")
	}
}

func TestNRPTRemovalFailureRetainsIdentityAndMissingRemovalIsIdempotent(t *testing.T) {
	d := newTestNRPTDNS(t)
	d.nrpt = &nrptState{OwnerToken: testNRPTGUID, RuleGUID: testNRPTGUID, Phase: "active"}
	d.nrptRun = func(_ context.Context, r nrptRequest) (nrptResponse, error) {
		if r.Mode != "remove" {
			t.Fatal("cleanup attempted to install a new policy")
		}
		return nrptResponse{Failure: "owned_rule_changed"}, nil
	}
	if err := d.Restore(); err == nil {
		t.Fatal("changed owned rule permitted uninstall cleanup")
	}
	if state := readTestNRPTState(t, d.path); state.NRPT == nil || state.NRPT.RuleGUID != testNRPTGUID || state.NRPT.Phase != "removing" {
		t.Fatal("failed removal discarded recovery identity")
	}
	d.nrptRun = func(_ context.Context, r nrptRequest) (nrptResponse, error) { return nrptResponse{Removed: true}, nil }
	if err := d.Restore(); err != nil {
		t.Fatal(err)
	}
	if state := readTestNRPTState(t, d.path); state.NRPT != nil || d.nrpt != nil || d.blockAll {
		t.Fatal("verified missing/removed own rule did not clear journal")
	}
}

func TestNRPTNewConflictingZoneDoesNotDisableHealthyDNSPlan(t *testing.T) {
	d := newTestNRPTDNS(t)
	d.started = true
	calls := 0
	d.nrptRun = func(_ context.Context, r nrptRequest) (nrptResponse, error) {
		calls++
		response := nrptResponse{RuleGUID: testNRPTGUID, Effective: true}
		for index, zone := range r.Zones {
			if zone == "blocked.example" {
				response.Conflicts = append(response.Conflicts, index)
			}
		}
		return response, nil
	}
	healthy := DNSPlan{Domains: []string{"healthy.example"}, Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, Interface: 1, Active: true}
	if err := d.Set("work:healthy", healthy, 0); err != nil {
		t.Fatal(err)
	}
	blocked := DNSPlan{Domains: []string{"blocked.example"}, Interface: 1, Active: true}
	if err := d.Set("work:blocked", blocked, 0); err == nil {
		t.Fatal("shadowed protected zone was accepted")
	}
	if !d.nrptReady || d.blockAll || d.blocked["work:healthy"] || !d.plans["work:healthy"].Active || !d.blocked["work:blocked"] {
		t.Fatal("one work-zone failure disabled healthy DNS or permitted the new zone")
	}
	assertNRPTServfail(t, d, "secret.blocked.example.")
	if err := d.activatePlansLocked(context.Background()); err == nil || calls != 2 {
		t.Fatal("identical conflict state repeatedly launched PowerShell")
	}
	if err := d.Remove("work:blocked"); err != nil {
		t.Fatal(err)
	}
	if calls != 3 || d.blocked["work:healthy"] || d.blockAll {
		t.Fatal("removing the conflicting intent failed to preserve healthy plan")
	}
}

func TestNRPTUnverifiedPolicyNeverUsesPhysicalFallback(t *testing.T) {
	d := newTestNRPTDNS(t)
	d.started = true
	d.physical = 1
	d.fallback = []netip.Addr{netip.MustParseAddr("192.0.2.53")}
	fallbackCalled := false
	d.fallbackAllowed = func() bool { fallbackCalled = true; return true }
	d.nrptRun = func(context.Context, nrptRequest) (nrptResponse, error) {
		return nrptResponse{}, errors.New("fixed command timed out")
	}
	if err := d.Set("work:new", DNSPlan{Domains: []string{"corp.example"}, Interface: 1, Active: true}, 0); err == nil {
		t.Fatal("policy command failure activated a plan")
	}
	assertNRPTServfail(t, d, "secret.corp.example.")
	assertNRPTServfail(t, d, "outside.example.")
	if fallbackCalled || !d.blockAll {
		t.Fatal("unverified policy leaked to physical fallback")
	}
}
