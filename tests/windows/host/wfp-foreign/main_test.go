//go:build windows

package main

import (
	"net/netip"
	"testing"

	"github.com/tailscale/wf"
)

func testFixtureJournal() fixtureJournal {
	j := fixtureJournal{Version: 1, Machine: "VAULT443-WIN10", ControllerSID: "S-1-5-21-1-2-3-1000", RuleID: stableID("qa-test-only").String(), Token: "0123456789abcdef0123456789abcdef"}
	j.Name = "Vault443 QA foreign-reference " + j.Token
	return j
}

func TestForeignJournalRefusesDifferentControllerAndIdentity(t *testing.T) {
	j := testFixtureJournal()
	if _, err := validateJournal(j, j.Machine, j.ControllerSID); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*fixtureJournal){func(j *fixtureJournal) { j.ControllerSID = "S-1-5-18" }, func(j *fixtureJournal) { j.Machine = "DESKTOP" }, func(j *fixtureJournal) { j.Token = "" }, func(j *fixtureJournal) { j.Name = "some other filter" }, func(j *fixtureJournal) { j.RuleID = "{00000000-0000-0000-0000-000000000000}" }} {
		copy := j
		change(&copy)
		if _, err := validateJournal(copy, j.Machine, j.ControllerSID); err == nil {
			t.Fatal("modified fixture identity accepted")
		}
	}
}

func TestForeignRuleCleanupRefusesFieldChanges(t *testing.T) {
	j := testFixtureJournal()
	id, err := validateJournal(j, j.Machine, j.ControllerSID)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyRule(fixtureRule(j, id), j, id); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*wf.Rule){
		"name":       func(r *wf.Rule) { r.Name = "another rule" },
		"id":         func(r *wf.Rule) { r.ID = wf.RuleID(stableID("other")) },
		"provider":   func(r *wf.Rule) { r.Provider = wf.ProviderID(stableID("other")) },
		"sublayer":   func(r *wf.Rule) { r.Sublayer = wf.SublayerID(stableID("other")) },
		"permit":     func(r *wf.Rule) { r.Action = wf.ActionPermit },
		"weight":     func(r *wf.Rule) { r.Weight = 2 },
		"persistent": func(r *wf.Rule) { r.Persistent = false },
		"boot":       func(r *wf.Rule) { r.BootTime = true },
		"remote":     func(r *wf.Rule) { r.Conditions[0].Value = "198.51.100.254/32" },
		"port":       func(r *wf.Rule) { r.Conditions[1].Value = uint16(10) },
		"protocol":   func(r *wf.Rule) { r.Conditions[2].Value = wf.IPProtoUDP },
		"duplicate":  func(r *wf.Rule) { r.Conditions[2] = r.Conditions[1] },
	} {
		t.Run(name, func(t *testing.T) {
			r := fixtureRule(j, id)
			change(r)
			if err := verifyRule(r, j, id); err == nil {
				t.Fatal("changed filter could be deleted")
			}
		})
	}
}

func TestForeignRuleAcceptsOnlyEquivalentNativeCanonicalForms(t *testing.T) {
	j := testFixtureJournal()
	id, err := validateJournal(j, j.Machine, j.ControllerSID)
	if err != nil {
		t.Fatal(err)
	}
	r := fixtureRule(j, id)
	r.Conditions[0].Value = netip.MustParseAddr("198.51.100.254")
	r.Conditions[2].Value = uint8(wf.IPProtoTCP)
	if err = verifyRule(r, j, id); err != nil {
		t.Fatalf("equivalent native host/TCP representation refused: %v", err)
	}
	for name, value := range map[string]any{
		"other-host": netip.MustParseAddr("198.51.100.253"),
		"subnet":     netip.MustParsePrefix("198.51.100.0/24"),
	} {
		t.Run(name, func(t *testing.T) {
			r.Conditions[0].Value = value
			if err = verifyRule(r, j, id); err == nil {
				t.Fatal("different remote destination accepted")
			}
		})
	}
	r.Conditions[0].Value = netip.MustParseAddr("198.51.100.254")
	r.Conditions[2].Value = uint8(wf.IPProtoUDP)
	if err = verifyRule(r, j, id); err == nil {
		t.Fatal("native UDP representation accepted as TCP")
	}
}
