package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	"vault443/internal/workvpn"
)

func TestPrivateDBusGenericWireGuardLifecycle(t *testing.T) {
	binary, e := exec.LookPath("dbus-daemon")
	if e != nil {
		t.Skip("dbus-daemon unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--session", "--nofork", "--nopidfile", "--print-address=1")
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line := make(chan string, 1)
	go func() {
		reader := bufio.NewScanner(stdout)
		if reader.Scan() {
			line <- reader.Text()
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
	server, e := dbus.Connect(address)
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	client, e := dbus.Connect(address)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	st, e := store.Open(filepath.Join(t.TempDir(), "vless"), true)
	if e != nil {
		t.Fatal(e)
	}
	work, e := workvpn.Open(filepath.Join(t.TempDir(), "work"), true)
	if e != nil {
		t.Fatal(e)
	}
	s := service.New(st, &inertRuntime{status: model.RuntimeStatus{State: "disconnected"}})
	s.AttachWork(work, &inertWorkRuntime{})
	defer func() {
		cancel()
		end, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		s.StopWork(end)
	}()
	if e = serve(ctx, server, s, Authorizer{Source: testIdentity{SystemIdentity{server}}, OperatorGroup: "vault443"}); e != nil {
		t.Fatal(e)
	}
	object := client.Object(BusName, ObjectPath)
	key := func(n byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)) }
	conf := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=10.90.0.2/32\n[Peer]\nPublicKey=%s\nPresharedKey=%s\nEndpoint=wireguard.example.test:51820\nAllowedIPs=10.90.0.0/24\n", key(31), key(32), key(33))
	files, _ := json.Marshal([]service.WorkImportFile{{Name: "Private WG", Content: conf}})
	var reply string
	if e = object.CallWithContext(ctx, BusName+".PrepareWorkImport", 0, string(files)).Store(&reply); e != nil {
		t.Fatal(e)
	}
	var preview service.WorkPreview
	if e = json.Unmarshal([]byte(reply), &preview); e != nil || len(preview.Profiles) != 1 || len(preview.Errors) > 0 {
		t.Fatalf("generic preview failed: %v / %v", e, preview.Errors)
	}
	if strings.Contains(reply, key(31)) || strings.Contains(reply, key(33)) {
		t.Fatal("D-Bus preview leaked keys")
	}
	id := preview.Profiles[0].ID
	if preview.Profiles[0].Kind != "wireguard" {
		t.Fatal("preview lost protocol")
	}
	if e = object.CallWithContext(ctx, BusName+".CommitOpenVPNImport", 0, preview.DraftID, `{}`).Err; e == nil {
		t.Fatal("legacy API accepted WG draft")
	}
	if e = object.CallWithContext(ctx, BusName+".CommitWorkImport", 0, preview.DraftID, `{}`).Store(&reply); e != nil {
		t.Fatal(e)
	}
	if _, ok := work.Snapshot().Profile(uint32(os.Geteuid()), id); !ok {
		t.Fatal("import not bound to real bus UID")
	}
	if e = object.CallWithContext(ctx, BusName+".UpdateWorkProfile", 0, id, "Renamed WG", "vault-door").Err; e != nil {
		t.Fatal(e)
	}
	if e = object.CallWithContext(ctx, BusName+".SetWorkDebug", 0, id, true).Err; e != nil {
		t.Fatal(e)
	}
	if e = object.CallWithContext(ctx, BusName+".RequestOpenVPNConnect", 0, id).Err; e == nil {
		t.Fatal("legacy connect accepted WG")
	}
	if e = object.CallWithContext(ctx, BusName+".RequestWorkConnect", 0, id).Store(&reply); e != nil || !strings.Contains(reply, "operationId") {
		t.Fatal("generic request not acknowledged", e)
	}
	for _, method := range []string{"GetSnapshot", "GetWorkDiagnostics", "GetWorkLogs"} {
		var args []interface{}
		if method == "GetWorkDiagnostics" {
			args = []interface{}{id}
		}
		if method == "GetWorkLogs" {
			args = []interface{}{id, "", int32(50)}
		}
		if e = object.CallWithContext(ctx, BusName+"."+method, 0, args...).Store(&reply); e != nil {
			t.Fatal(method, e)
		}
		if strings.Contains(reply, key(31)) || strings.Contains(reply, key(33)) {
			t.Fatal("D-Bus view leaked credentials")
		}
	}
	if e = object.CallWithContext(ctx, BusName+".ClearWorkLogs", 0, id).Err; e != nil {
		t.Fatal(e)
	}
	if e = object.CallWithContext(ctx, BusName+".RequestWorkDisconnect", 0, id).Store(&reply); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if e = object.CallWithContext(ctx, BusName+".RemoveWorkProfile", 0, id).Err; e == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e != nil {
		t.Fatal("generic disconnect did not finish", e)
	}
	if e = object.CallWithContext(ctx, BusName+".PrepareWorkImport", 0, string(files)).Store(&reply); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal([]byte(reply), &preview); e != nil {
		t.Fatal(e)
	}
	if e = object.CallWithContext(ctx, BusName+".CancelWorkImport", 0, preview.DraftID).Err; e != nil {
		t.Fatal(e)
	}
	if e = object.CallWithContext(ctx, BusName+".CommitWorkImport", 0, preview.DraftID, `{}`).Err; e == nil {
		t.Fatal("canceled draft committed")
	}
}
