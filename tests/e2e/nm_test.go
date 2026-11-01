package e2e

import (
	"context"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"vault443/internal/network"
)

// Runs real NM and resolved against a local VLESS server. The HTTP response is
// fetched through Xray; no connectivity state is mocked and no host bus is used.
func TestRealVLESSNetworkManagerConnectivity(t *testing.T) {
	requireIsolated(t)
	if os.Getenv("VAULT443_E2E_NM") != "1" {
		t.Skip("opt-in isolated NetworkManager fixture required")
	}
	config := `[main]
plugins=keyfile
dns=systemd-resolved
rc-manager=unmanaged
[keyfile]
unmanaged-devices=
[connectivity]
uri=http://93.184.215.14:8080/
response={"marker":"vless-e2e-ok"
interval=300
[logging]
backend=debug
level=DEBUG
domains=CONCHECK,DEVICE,IP4
`
	if err := os.WriteFile("/fixture/NetworkManager.conf", []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create("/results/networkmanager.log")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	bus, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	obj := bus.Object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
	var nm *exec.Cmd
	stop := func() {
		if nm != nil {
			if nm.Process != nil {
				_ = nm.Process.Kill()
				_ = nm.Wait()
			}
			nm = nil
		}
	}
	defer stop()
	start := func() {
		nm = exec.Command("NetworkManager", "--no-daemon", "--debug", "--config=/fixture/NetworkManager.conf", "--pid-file=/fixture/nm.pid")
		nm.Stdout, nm.Stderr = log, log
		if err := nm.Start(); err != nil {
			t.Fatal(err)
		}
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end); {
			if _, err := obj.GetProperty("org.freedesktop.NetworkManager.Version"); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("NetworkManager did not start")
	}
	start()
	// A real managed uplink, as on Ubuntu Wi-Fi. Its saved profile must not change.
	metric := os.Getenv("VAULT443_E2E_NM_METRIC")
	if metric == "" {
		metric = "600"
	}
	command(t, "nmcli", "con", "add", "type", "ethernet", "ifname", "e2euplink", "con-name", "fixture-uplink", "autoconnect", "no", "ipv4.method", "manual", "ipv4.addresses", "192.0.2.2/24", "ipv4.gateway", "192.0.2.1", "ipv4.route-metric", metric, "ipv4.dns", "1.1.1.1", "ipv6.method", "disabled")
	command(t, "nmcli", "con", "up", "fixture-uplink")
	profileBefore := command(t, "nmcli", "-t", "-f", "connection.id,connection.uuid,connection.type,connection.interface-name,connection.autoconnect,ipv4,ipv6", "con", "show", "fixture-uplink")
	full := func(label string) {
		t.Helper()
		var state uint32
		if err := obj.CallWithContext(ctx, "org.freedesktop.NetworkManager.CheckConnectivity", 0).Store(&state); err != nil || state != 4 {
			t.Fatalf("%s: NM connectivity=%d, error=%v", label, state, err)
		}
		t.Log(label + ": real NetworkManager connectivity FULL")
	}
	full("baseline")
	m := network.New(network.Config{StateDir: "/var/lib/vault443-e2e", RuntimeDir: "/run/vault443-e2e", XrayPath: "/usr/lib/vault443/xray"})
	defer func() {
		cleanup, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = m.Disconnect(cleanup)
	}()
	registered := func() {
		t.Helper()
		for end := time.Now().Add(12 * time.Second); time.Now().Before(end); {
			if err := m.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			d := m.Diagnostics(ctx).(map[string]any)
			if d["networkManagerState"] == "registered" {
				routes := command(t, "ip", "-4", "route", "show", "default", "dev", network.TunName)
				if strings.Contains(routes, "via 198.18.0.2") {
					return
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		var path dbus.ObjectPath
		if obj.CallWithContext(ctx, "org.freedesktop.NetworkManager.GetDeviceByIpIface", 0, network.TunName).Store(&path) == nil {
			var settings map[string]map[string]dbus.Variant
			var version uint64
			_ = bus.Object("org.freedesktop.NetworkManager", path).CallWithContext(ctx, "org.freedesktop.NetworkManager.Device.GetAppliedConnection", 0, uint32(0)).Store(&settings, &version)
			t.Logf("fixture applied connection: %+v", settings)
		}
		t.Fatalf("tunnel not registered: %v", m.Diagnostics(ctx))
	}
	if err := m.Connect(ctx, localProfile(t)); err != nil {
		t.Fatal(err)
	}
	registered()
	full("VLESS active")
	reply, err := request(ctx, network.TunName)
	if err != nil || reply.Marker != "vless-e2e-ok" || reply.Peer == "192.0.2.2" {
		t.Fatalf("probe did not traverse VLESS: %+v %v", reply, err)
	}
	if _, err := request(ctx, "e2euplink"); err == nil {
		t.Fatal("physical-interface probe bypassed protection")
	}
	if dns := command(t, "resolvectl", "query", "example.com"); !strings.Contains(dns, "93.184.215.14") {
		t.Fatal("tunnel DNS lost", dns)
	}
	t.Log("TUN HTTP and DNS work; direct physical probe remains blocked")
	var devicePath dbus.ObjectPath
	if err := obj.CallWithContext(ctx, "org.freedesktop.NetworkManager.GetDeviceByIpIface", 0, network.TunName).Store(&devicePath); err != nil {
		t.Fatal(err)
	}
	applied := func() (map[string]map[string]dbus.Variant, uint64) {
		var settings map[string]map[string]dbus.Variant
		var version uint64
		if err := bus.Object("org.freedesktop.NetworkManager", devicePath).CallWithContext(ctx, "org.freedesktop.NetworkManager.Device.GetAppliedConnection", 0, uint32(0)).Store(&settings, &version); err != nil {
			t.Fatal(err)
		}
		return settings, version
	}
	settings, version := applied()
	time.Sleep(5 * time.Second)
	if err := m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	again, againVersion := applied()
	if version != againVersion || !reflect.DeepEqual(settings, again) {
		t.Fatal("unchanged reconcile reapplied NM settings")
	}
	if after := command(t, "nmcli", "-t", "-f", "connection.id,connection.uuid,connection.type,connection.interface-name,connection.autoconnect,ipv4,ipv6", "con", "show", "fixture-uplink"); after != profileBefore {
		t.Fatal("physical connection profile changed")
	}
	t.Log("reconciliation is idempotent; saved physical profile unchanged")
	stop()
	start()
	// Give a new NM owner a chance to assume existing TUN/IP state.
	time.Sleep(6 * time.Second)
	registered()
	full("NetworkManager restarted")
	pid := findCore(t, "/run/vault443-e2e/core.json")
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := request(ctx, ""); err == nil {
		t.Fatal("traffic escaped after core crash")
	}
	_ = m.Reconcile(ctx)
	var state uint32
	if err := obj.CallWithContext(ctx, "org.freedesktop.NetworkManager.CheckConnectivity", 0).Store(&state); err != nil || state == 4 {
		t.Fatalf("outage falsely online: %d %v", state, err)
	}
	if routes := command(t, "ip", "-4", "route", "show", "default"); strings.Contains(routes, network.TunName) {
		t.Fatal("TUN default survived core death", routes)
	}
	t.Log("Xray SIGKILL: no false FULL, no TUN default, no direct escape")
	if err := m.Connect(ctx, localProfile(t)); err != nil {
		t.Fatal(err)
	}
	registered()
	full("reconnected")
	if err := m.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	full("manual disconnect restores physical connectivity")
	if routes := command(t, "ip", "-4", "route", "show", "default"); strings.Contains(routes, network.TunName) {
		t.Fatal("TUN route leaked after disconnect")
	}
	if profiles := command(t, "nmcli", "-t", "-f", "NAME", "con", "show"); strings.Contains(profiles, network.TunName) {
		t.Fatal("volatile profile leaked after disconnect", profiles)
	}
	if after := command(t, "nmcli", "-t", "-f", "connection.id,connection.uuid,connection.type,connection.interface-name,connection.autoconnect,ipv4,ipv6", "con", "show", "fixture-uplink"); after != profileBefore {
		t.Fatal("physical profile changed after cleanup")
	}
}
