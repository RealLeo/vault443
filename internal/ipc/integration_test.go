package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"vault443/internal/model"
	"vault443/internal/service"
	"vault443/internal/store"
)

// Authentication still obtains the real kernel-authenticated D-Bus peer UID.
// Only group/logind fixtures are supplied, without any production auth bypass.
type testIdentity struct{ SystemIdentity }

func (testIdentity) Groups(uint32) ([]string, error)  { return []string{"vault443", "sudo"}, nil }
func (testIdentity) LocalActive(uint32) (bool, error) { return true, nil }

type inertRuntime struct{ status model.RuntimeStatus }

func (r *inertRuntime) Connect(context.Context, model.Profile) error {
	r.status.State = "connected"
	return nil
}
func (r *inertRuntime) Disconnect(context.Context) error {
	r.status.State = "disconnected"
	r.status.GuardArmed = false
	return nil
}
func (r *inertRuntime) Reconcile(context.Context) error             { return nil }
func (r *inertRuntime) Status() model.RuntimeStatus                 { return r.status }
func (r *inertRuntime) Arm(context.Context) error                   { r.status.GuardArmed = true; return nil }
func (r *inertRuntime) SetVPNBinding(context.Context, string) error { return nil }
func (r *inertRuntime) Diagnostics(context.Context) interface{}     { return nil }
func (r *inertRuntime) VPNCompatibility(context.Context) model.VPNCompatibility {
	return model.VPNCompatibility{Items: []model.VPNCompatibilityItem{{
		Interface: "tun0", Manager: "pritunl", Application: "Pritunl", Source: "automatic",
		Active: true, Verified: true, FullIPv4: true,
	}}}
}

func TestPrivateDBusPeerIdentitySignalsAndReappearance(t *testing.T) {
	binary, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--session", "--nofork", "--nopidfile", "--print-address=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			line <- scanner.Text()
		} else {
			line <- ""
		}
	}()
	var address string
	select {
	case address = <-line:
	case <-ctx.Done():
		t.Fatal("private bus startup timeout")
	}
	if address == "" {
		t.Fatal("private bus did not provide address")
	}
	server, err := dbus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := dbus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	s := service.New(st, &inertRuntime{status: model.RuntimeStatus{State: "disconnected"}})
	if err = serve(ctx, server, s, Authorizer{Source: testIdentity{SystemIdentity{server}}, OperatorGroup: "vault443"}); err != nil {
		t.Fatal(err)
	}
	signals := make(chan *dbus.Signal, 8)
	client.Signal(signals)
	defer client.RemoveSignal(signals)
	if err = client.AddMatchSignal(dbus.WithMatchObjectPath(ObjectPath), dbus.WithMatchInterface(BusName), dbus.WithMatchMember("Changed")); err != nil {
		t.Fatal(err)
	}
	object := client.Object(BusName, ObjectPath)
	link := "vless://11111111-2222-4333-8444-555555555555@vpn.example:443?security=tls#Peer"
	var reply string
	if err = object.CallWithContext(ctx, BusName+".ImportProfiles", 0, link).Store(&reply); err != nil {
		t.Fatal(err)
	}
	if len(st.Snapshot().User(uint32(os.Geteuid())).Profiles) != 1 {
		t.Fatal("profile not stored under actual D-Bus UID")
	}
	select {
	case sig := <-signals:
		if sig.Name != BusName+".Changed" || len(sig.Body) != 0 {
			t.Fatal("unexpected or secret-bearing signal")
		}
	case <-ctx.Done():
		t.Fatal("no Changed signal")
	}
	if err = object.CallWithContext(ctx, BusName+".GetSnapshot", 0).Store(&reply); err != nil {
		t.Fatal(err)
	}
	var snapshot service.Snapshot
	if err = json.Unmarshal([]byte(reply), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Profiles) != 1 || strings.Contains(reply, "11111111-2222") {
		t.Fatal("snapshot missing profile or leaking secret")
	}
	before, _ := json.Marshal(st.Snapshot())
	if err = object.CallWithContext(ctx, BusName+".GetVPNCompatibility", 0).Store(&reply); err != nil {
		t.Fatal(err)
	}
	var compatibility model.VPNCompatibility
	if err = json.Unmarshal([]byte(reply), &compatibility); err != nil || len(compatibility.Items) != 1 || compatibility.Items[0].Application != "Pritunl" || compatibility.BusyByOtherUser {
		t.Fatal("invalid compatibility wire response", reply, err)
	}
	after, _ := json.Marshal(st.Snapshot())
	if string(before) != string(after) {
		t.Fatal("compatibility D-Bus call changed stored state")
	}
	select {
	case <-signals:
		t.Fatal("read-only compatibility emitted Changed")
	default:
	}
	if err = st.Update(func(state *store.State) error {
		state.Desired = &store.Session{UID: uint32(os.Geteuid()) + 1, ProfileID: "private-profile"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = object.CallWithContext(ctx, BusName+".GetVPNCompatibility", 0).Store(&reply); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(reply), &compatibility); err != nil || !compatibility.BusyByOtherUser || len(compatibility.Items) != 0 || strings.Contains(reply, "tun0") || strings.Contains(reply, "private-profile") {
		t.Fatal("foreign user compatibility data escaped", reply, err)
	}
	if err = st.Update(func(state *store.State) error { state.Desired = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if err = object.CallWithContext(ctx, BusName+".GetVPNCompatibility", 0, uint32(0)).Err; err == nil {
		t.Fatal("compatibility accepted client-supplied UID")
	}
	// Exercise the actual wire signatures used by the 0.2 GUI, including the
	// int32 pagination limit and UID-free metadata/draft operations.
	newLink := strings.Replace(link, "vpn.example", "new.example", 1)
	if err = object.CallWithContext(ctx, BusName+".PrepareImport", 0, newLink, "text", "").Store(&reply); err != nil {
		t.Fatal(err)
	}
	var prepared service.PreparedImport
	if err = json.Unmarshal([]byte(reply), &prepared); err != nil || len(prepared.Profiles) != 1 {
		t.Fatal("bad prepared import", err)
	}
	id := prepared.Profiles[0].ID
	icons, _ := json.Marshal(map[string]string{id: "robot"})
	if err = object.CallWithContext(ctx, BusName+".CommitImport", 0, prepared.DraftID, string(icons)).Store(&reply); err != nil {
		t.Fatal(err)
	}
	if err = object.CallWithContext(ctx, BusName+".UpdateProfile", 0, id, "Wire name", "shield").Err; err != nil {
		t.Fatal(err)
	}
	if err = object.CallWithContext(ctx, BusName+".SetProfileDebug", 0, id, true).Err; err != nil {
		t.Fatal(err)
	}
	if err = object.CallWithContext(ctx, BusName+".GetProfileLogs", 0, id, "", int32(100)).Store(&reply); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply, `"entries":[]`) {
		t.Fatal("empty journal is not an array", reply)
	}
	if err = object.CallWithContext(ctx, BusName+".ClearProfileLogs", 0, id).Err; err != nil {
		t.Fatal(err)
	}
	if err = object.CallWithContext(ctx, BusName+".PrepareImport", 0, newLink, "text", "").Store(&reply); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(reply), &prepared); err != nil {
		t.Fatal(err)
	}
	if err = object.CallWithContext(ctx, BusName+".CancelImport", 0, prepared.DraftID).Err; err != nil {
		t.Fatal(err)
	}
	stored := st.Snapshot().User(uint32(os.Geteuid())).Profiles[1]
	if stored.IconID != "shield" || !stored.DebugLogging || stored.Name != "Wire name" {
		t.Fatal("wire metadata was not saved")
	}
	if err = object.CallWithContext(ctx, BusName+".GetSnapshot", 0, uint32(0)).Err; err == nil {
		t.Fatal("accepted client-supplied UID argument")
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	if err = object.CallWithContext(ctx, BusName+".GetSnapshot", 0).Err; err == nil {
		t.Fatal("removed service still reachable")
	}
	server2, err := dbus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	defer server2.Close()
	if err = serve(ctx, server2, s, Authorizer{Source: testIdentity{SystemIdentity{server2}}, OperatorGroup: "vault443"}); err != nil {
		t.Fatal(err)
	}
	if err = object.CallWithContext(ctx, BusName+".GetSnapshot", 0).Store(&reply); err != nil {
		t.Fatal("service did not reappear:", err)
	}
}
