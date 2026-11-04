package e2e

import (
	"context"
	"fmt"
	"github.com/godbus/dbus/v5"
	"os/exec"
	"strings"
	"testing"
	"time"
	"vault443/internal/worknet"
	"vault443/internal/workvpn"
)

func eventuallyNM(t *testing.T, check func() bool) {
	t.Helper()
	for end := time.Now().Add(16 * time.Second); time.Now().Before(end); {
		if check() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("NetworkManager registration did not converge")
}

func TestRealOpenVPNNetworkManagerConnectivity(t *testing.T) {
	requireWorkIsolated(t)
	f := startNMFixture(t)
	h := newWorkHarness(t)
	const boot = "nm-openvpn-fixture"
	if err := h.w.Initialize(h.ctx, boot, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			for id := range h.running {
				t.Logf("NM status: %+v", h.w.Snapshot(id))
			}
			h.dump()
		}
	})
	f.full("baseline")
	partial := workProfile(t, 2, "")
	h.start(partial)
	h.waitConnected(partial.ID)
	time.Sleep(time.Second)
	if s := h.w.Snapshot(partial.ID); s.NetworkManagerState == "registered" {
		t.Fatal("partial tunnel registered as Internet")
	}
	p := workProfile(t, 1, "redirect-gateway def1\n")
	h.start(p)
	h.waitConnected(p.ID)
	registered := func(id string) {
		t.Helper()
		eventuallyNM(t, func() bool {
			s := h.w.Snapshot(id)
			if s.NetworkManagerState != "registered" {
				return false
			}
			return strings.Contains(command(t, "ip", "-4", "route", "show", "table", "main", "default", "dev", s.Interface), "via 10.")
		})
	}
	registered(p.ID)
	f.full("OpenVPN full tunnel")
	s := h.w.Snapshot(p.ID)
	reply, err := request(h.ctx, s.Interface)
	if err != nil || !strings.HasPrefix(reply.Peer, "10.70.") {
		t.Fatalf("probe missed OpenVPN: %+v %v", reply, err)
	}
	if _, err := request(h.ctx, "e2euplink"); err == nil {
		t.Fatal("physical probe escaped protection")
	}
	if dns := command(t, "resolvectl", "query", "example.com"); !strings.Contains(dns, "192.168.100.15") {
		t.Fatal("lost DNS", dns)
	}
	var device dbus.ObjectPath
	if err := f.obj.CallWithContext(h.ctx, "org.freedesktop.NetworkManager.GetDeviceByIpIface", 0, s.Interface).Store(&device); err != nil {
		t.Fatal(err)
	}
	version := func() uint64 {
		var settings map[string]map[string]dbus.Variant
		var version uint64
		if err := f.bus.Object("org.freedesktop.NetworkManager", device).CallWithContext(h.ctx, "org.freedesktop.NetworkManager.Device.GetAppliedConnection", 0, uint32(0)).Store(&settings, &version); err != nil {
			t.Fatal(err)
		}
		return version
	}
	before := version()
	time.Sleep(6 * time.Second)
	if after := version(); after != before {
		t.Fatalf("unchanged NM settings reapplied: %d -> %d", before, after)
	}
	f.stop()
	f.start()
	time.Sleep(6 * time.Second)
	registered(p.ID)
	f.full("NetworkManager restart with OpenVPN")
	// Pause the fixture server so OpenVPN's real ping timeout ends this attempt.
	command(t, "sh", "-c", "kill -STOP $(cat /fixture/work/server-1.pid)")
	defer exec.Command("sh", "-c", "kill -CONT $(cat /fixture/work/server-1.pid)").Run()
	select {
	case <-h.running[p.ID].done:
	case <-time.After(18 * time.Second):
		t.Fatal("OpenVPN did not detect server outage")
	}
	// Keep the failed attempt's persistent TUN and protected routes.
	eventuallyNM(t, func() bool {
		return command(t, "ip", "-4", "route", "show", "table", "main", "default", "dev", s.Interface) == ""
	})
	command(t, "ip", "link", "show", s.Interface)
	if dns := command(t, "resolvectl", "dns", s.Interface); !strings.Contains(dns, "10.70.0.1") {
		t.Fatal("outage released corporate DNS", dns)
	}
	if _, err := request(h.ctx, ""); err == nil {
		t.Fatal("traffic escaped OpenVPN outage")
	}
	probe, cancel := context.WithTimeout(h.ctx, 8*time.Second)
	var connectivity uint32
	err = f.obj.CallWithContext(probe, "org.freedesktop.NetworkManager.CheckConnectivity", 0).Store(&connectivity)
	cancel()
	if err == nil && connectivity == 4 {
		t.Fatal("outage falsely reported FULL")
	}
	command(t, "sh", "-c", "kill -CONT $(cat /fixture/work/server-1.pid)")
	// Reconstruct the supervisor from its private same-boot journal while the
	// persistent TUN and NM's old applied lease still exist.
	h.stop(partial.ID)
	h.running[p.ID].cancel()
	h.w = worknet.New(h.workConfig, h.n)
	if err := h.w.Initialize(h.ctx, boot, true); err != nil {
		t.Fatal(err)
	}
	eventuallyNM(t, func() bool { return h.w.Snapshot(p.ID).NetworkManagerState == "inactive" })
	h.start(p)
	h.waitConnected(p.ID)
	registered(p.ID)
	f.full("OpenVPN reconnect")
	if addresses := strings.TrimSpace(command(t, "ip", "-o", "-4", "addr", "show", "dev", s.Interface)); len(strings.Split(addresses, "\n")) != 1 {
		t.Fatal("old lease was restored by NM", addresses)
	}
	// A second full tunnel must not advertise Internet until explicitly chosen.
	other := workProfile(t, 3, "")
	h.start(other)
	eventuallyNM(t, func() bool { state := h.w.Snapshot(other.ID).State; return state == "conflict" || state == "connected" })
	otherStatus := h.w.Snapshot(other.ID)
	if routes := command(t, "ip", "-4", "route", "show", "table", "main", "default", "dev", otherStatus.Interface); routes != "" {
		t.Fatal("losing full tunnel advertised Internet", routes)
	}
	if err := h.w.SetRules(h.ctx, []workvpn.RouteRule{{CIDR: "0.0.0.0/0", Target: other.ID}}); err != nil {
		t.Fatal(err)
	}
	registered(other.ID)
	eventuallyNM(t, func() bool {
		return command(t, "ip", "-4", "route", "show", "table", "main", "default", "dev", s.Interface) == ""
	})
	f.full("full-route owner changed")
	if domains := command(t, "resolvectl", "domain", s.Interface); strings.Contains(domains, "~. ") || strings.HasSuffix(strings.TrimSpace(domains), "~.") {
		t.Fatal("losing full tunnel retained default DNS", domains)
	}
	for _, id := range []string{other.ID, p.ID, partial.ID} {
		h.stop(id)
	}
	f.full("manual disconnect")
	if after := command(t, "nmcli", "-t", "-f", "connection.id,connection.uuid,connection.type,connection.interface-name,connection.autoconnect,ipv4,ipv6", "con", "show", "fixture-uplink"); after != f.profileBefore {
		t.Fatal("physical profile changed")
	}
	t.Log(fmt.Sprint("OpenVPN registration, real HTTP, DNS, idempotence, NM restart, persistent-TUN outage, recovery, owner change and cleanup passed"))
}

func TestRealOpenVPNNetworkManagerWithMain(t *testing.T) {
	requireWorkIsolated(t)
	f := startNMFixture(t)
	for _, mainFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("MainFirst=%v", mainFirst), func(t *testing.T) {
			h := newWorkHarness(t)
			if mainFirst {
				if err := h.n.Connect(h.ctx, localProfile(t)); err != nil {
					t.Fatal(err)
				}
			}
			p := workProfile(t, 1, "redirect-gateway def1\n")
			h.start(p)
			h.waitConnected(p.ID)
			if !mainFirst {
				if err := h.n.Connect(h.ctx, localProfile(t)); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.n.Reconcile(h.ctx); err != nil {
				t.Fatal(err)
			}
			if h.n.Status().State != "paused_external" {
				t.Fatal("main VPN did not pause", h.n.Status())
			}
			eventuallyNM(t, func() bool { return h.w.Snapshot(p.ID).NetworkManagerState == "registered" })
			f.full("OpenVPN with main VPN paused")
			if _, err := request(h.ctx, "e2euplink"); err == nil {
				t.Fatal("physical bypass")
			}
			h.stop(p.ID)
			_ = h.n.Reconcile(h.ctx)
			if err := h.n.Connect(h.ctx, localProfile(t)); err != nil {
				t.Fatal(err)
			}
			eventuallyNM(t, func() bool { return h.n.Diagnostics(h.ctx).(map[string]any)["networkManagerState"] == "registered" })
			f.full("main VPN resumed")
		})
	}
}
