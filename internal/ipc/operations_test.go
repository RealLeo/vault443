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

func TestPrivateDBusCancellableOperationAndDiagnostics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	binary, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon unavailable")
	}
	cmd := exec.CommandContext(ctx, binary, "--session", "--nofork", "--nopidfile", "--print-address=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatal("private bus did not provide address")
	}
	server, err := dbus.Connect(scanner.Text())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := dbus.Connect(scanner.Text())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &guiRuntime{inertRuntime: inertRuntime{status: model.RuntimeStatus{State: "disconnected"}}}
	s := service.New(st, runtime)
	caller := service.Caller{UID: uint32(os.Geteuid()), Admin: true}
	preview, err := s.ImportProfiles(caller, "vless://11111111-2222-4333-8444-555555555555@blocked.example:443?security=tls#Blocked\nvless://21111111-2222-4333-8444-555555555555@failed.example:443?security=tls#Failure")
	if err != nil {
		t.Fatal(err)
	}
	if err = serve(ctx, server, s, Authorizer{Source: testIdentity{SystemIdentity{server}}, OperatorGroup: "vault443"}); err != nil {
		t.Fatal(err)
	}
	object := client.Object(BusName, ObjectPath)
	call := func(method string, args ...interface{}) string {
		t.Helper()
		bounded, stop := context.WithTimeout(ctx, 500*time.Millisecond)
		defer stop()
		var reply string
		if err := object.CallWithContext(bounded, BusName+"."+method, 0, args...).Store(&reply); err != nil {
			t.Fatalf("%s blocked or failed: %v", method, err)
		}
		return reply
	}
	id := preview.Profiles[0].ID
	reply := call("RequestConnect", id)
	if !strings.Contains(reply, "operationId") {
		t.Fatal("no accepted operation identity", reply)
	}
	var snapshot service.Snapshot
	until := time.Now().Add(time.Second)
	for {
		if err = json.Unmarshal([]byte(call("GetSnapshot")), &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.Operation != nil && snapshot.Operation.Stage == "resolving_endpoint" {
			break
		}
		if time.Now().After(until) {
			t.Fatal("no DNS progress", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(call("GetProfileDiagnostics", id), "resolving_endpoint") {
		t.Fatal("diagnostics missing live stage")
	}
	if object.CallWithContext(ctx, BusName+".RequestDisconnect", 0, uint32(0)).Err == nil {
		t.Fatal("request accepted spoofed UID")
	}
	reply = call("RequestDisconnect")
	if !strings.Contains(reply, "operationId") {
		t.Fatal("no cancellation identity")
	}
	until = time.Now().Add(time.Second)
	for {
		if err = json.Unmarshal([]byte(call("GetSnapshot")), &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.Runtime.State == "disconnected" {
			break
		}
		if time.Now().After(until) {
			t.Fatal("cancel did not interrupt request")
		}
		time.Sleep(time.Millisecond)
	}
	if st.Snapshot().Desired != nil {
		t.Fatal("cancel did not persist clear intent")
	}
	id = preview.Profiles[1].ID
	call("RequestConnect", id)
	until = time.Now().Add(time.Second)
	for {
		if err = json.Unmarshal([]byte(call("GetSnapshot")), &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.LastFailure != nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("no published failure")
		}
		time.Sleep(time.Millisecond)
	}
	if snapshot.LastFailure.Code != "dns_unavailable" || snapshot.Operation.Stage != "retry_wait" {
		t.Fatal("safe failure or retry missing", snapshot)
	}
	if !strings.Contains(call("GetProfileDiagnostics", id), "dns_unavailable") {
		t.Fatal("diagnostics missing cause")
	}
	call("RequestDisconnect")
	// Existing accepted methods and the new switch cancellation coexist on the bus.
	for i := 0; i < 200; i++ {
		json.Unmarshal([]byte(call("GetSnapshot")), &snapshot)
		if snapshot.Runtime.State == "disconnected" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	good, e := s.ImportProfiles(caller, "trojan://synthetic@healthy.example:443#A")
	if e != nil {
		t.Fatal(e)
	}
	a := good.Profiles[0].ID
	if e = s.Connect(ctx, caller, a); e != nil {
		t.Fatal(e)
	}
	var accepted map[string]string
	if e = json.Unmarshal([]byte(call("RequestConnect", preview.Profiles[0].ID)), &accepted); e != nil {
		t.Fatal(e)
	}
	op := accepted["operationId"]
	if op == "" {
		t.Fatal("switch operation missing")
	}
	if e = object.CallWithContext(ctx, BusName+".CancelSwitch", 0, op+"stale").Err; e == nil {
		t.Fatal("stale switch cancellation accepted")
	}
	if e = object.CallWithContext(ctx, BusName+".CancelSwitch", 0, uint32(0), op).Err; e == nil {
		t.Fatal("caller UID spoof accepted")
	}
	if !strings.Contains(call("CancelSwitch", op), op) {
		t.Fatal("wrong cancellation result")
	}
	until = time.Now().Add(time.Second)
	for {
		json.Unmarshal([]byte(call("GetSnapshot")), &snapshot)
		if snapshot.Operation != nil && snapshot.Operation.Stage == "switch_cancelled" {
			break
		}
		if time.Now().After(until) {
			t.Fatal("switch cancellation stalled", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
	if snapshot.ActiveProfileID != a || snapshot.Runtime.State != "connected" || st.Snapshot().Desired.ProfileID != a {
		t.Fatal("cancel replaced A", snapshot)
	}
	call("RequestDisconnect")

}
