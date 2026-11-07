//go:build linux

package worknet

import (
	"encoding/json"
	"testing"
)

func TestNMOnlyVerifiedSelectedOpenVPNFullTunnel(t *testing.T) {
	m := fixtureManager()
	s := fixtureSnapshot()
	for i, id := range []string{"a", "b"} {
		ss := m.sessions[id]
		ss.Routes = append(ss.Routes, route{"0.0.0.0/0", "10.70.0.1"})
		ss.Status.State = "connected"
		ss.nmIndex = i + 10
		ss.nmAddress = "10.70.0.2/24"
		s.Links[i+2].Index = ss.nmIndex
		_ = json.Unmarshal([]byte(`[{"local":"10.70.0.2","prefixlen":24}]`), &s.Links[i+2].Addresses)
	}
	targets := m.nmTargets(s, m.choose(s))
	for _, target := range targets {
		if target.Enabled != (target.ID == "a") {
			t.Fatal("wrong full owner", target)
		}
		if target.Gateway.String() != "10.70.0.1" {
			t.Fatal("wrong gateway", target)
		}
	}
	m.sessions["a"].nmIndex++
	for _, target := range m.nmTargets(s, m.choose(s)) {
		if target.Enabled {
			t.Fatal("accepted reused interface", target)
		}
	}
	m.sessions["a"].nmIndex--
	m.sessions["a"].Active = false
	for _, target := range m.nmTargets(s, m.choose(s)) {
		if target.Enabled && target.ID == "a" {
			t.Fatal("outage advertised Internet", target)
		}
	}
	m.sessions["b"].Routes = []route{{"10.42.0.0/24", "10.71.0.1"}}
	for _, target := range m.nmTargets(s, m.choose(s)) {
		if target.ID == "b" && target.Enabled {
			t.Fatal("partial tunnel registered", target)
		}
	}
	m.sessions["a"].Kind = "wireguard"
	for _, target := range m.nmTargets(s, m.choose(s)) {
		if target.ID == "a" {
			t.Fatal("scope extended beyond OpenVPN")
		}
	}
}
