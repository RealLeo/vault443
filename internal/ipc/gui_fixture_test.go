package ipc

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"vault443/internal/model"
	"vault443/internal/service"
	"vault443/internal/store"
)

// This opt-in, test-only fixture lets Qt exercise actual asynchronous D-Bus
// requests without root or host network changes. No such mode exists in the
// production daemon. Set VAULT443_GUI_DBUS_ADDRESS_FILE to a new private file path,
// then give its contents to Qt as DBUS_SYSTEM_BUS_ADDRESS. It expires in 5 minutes.
func TestPrivateDBusGUIFixture(t *testing.T) {
	addressFile := os.Getenv("VAULT443_GUI_DBUS_ADDRESS_FILE")
	if addressFile == "" {
		t.Skip("opt-in interactive GUI fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scanner := bufio.NewScanner(out)
	if !scanner.Scan() {
		t.Fatal("private GUI bus did not start")
	}
	address := scanner.Text()
	conn, err := dbus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	s := service.New(st, &guiRuntime{inertRuntime: inertRuntime{status: model.RuntimeStatus{State: "disconnected", ExternalVPNs: []string{}}}})
	caller := service.Caller{UID: uint32(os.Geteuid()), Admin: true}
	_, err = s.ImportProfiles(caller, "vless://11111111-2222-4333-8444-555555555555@vault.example:443?security=tls#VAULT-13\nvless://21111111-2222-4333-8444-555555555555@new-reno.example:443?security=tls&type=ws#NEW%20RENO\nvless://31111111-2222-4333-8444-555555555555@ncr.example:443?security=tls&type=grpc#NCR%20RELAY")
	if err != nil {
		t.Fatal(err)
	}
	if err = serve(ctx, conn, s, Authorizer{Source: testIdentity{SystemIdentity{conn}}, OperatorGroup: "vault443"}); err != nil {
		t.Fatal(err)
	}
	// Override only this test fixture's diagnostics method, keeping all real wire
	// signatures and authentication. Production daemon has no delayed-call mode.
	if err = conn.Export(&slowDiagnosticsAPI{API: &API{ctx: ctx, service: s, auth: Authorizer{Source: testIdentity{SystemIdentity{conn}}, OperatorGroup: "vault443"}}}, ObjectPath, BusName); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(addressFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString(address); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(addressFile)
	t.Log("Private GUI D-Bus fixture ready")
	// Removing the address file lets an automated Qt run shut down the fixture
	// and its private bus promptly, including after a failed GUI assertion.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := os.Stat(addressFile); os.IsNotExist(err) {
				return
			}
		}
	}
}

// Slow/failing endpoints exist only in this opt-in test binary. They exercise
// real Qt/D-Bus control flow without sockets, privileged operations, or secrets.
type guiRuntime struct {
	inertRuntime
	mu       sync.Mutex
	observer func(model.RuntimeStatus)
}

func (r *guiRuntime) SetProgressHandler(fn func(model.RuntimeStatus)) {
	r.mu.Lock()
	r.observer = fn
	r.mu.Unlock()
}
func (r *guiRuntime) publish(state, stage, message, code string) {
	r.mu.Lock()
	r.status.State = state
	r.status.Stage = stage
	r.status.StageStartedAt = time.Now().UnixMilli()
	r.status.Message = message
	r.status.FailureCode = code
	status := r.status
	observer := r.observer
	r.mu.Unlock()
	if observer != nil {
		observer(status)
	}
}
func (r *guiRuntime) Connect(ctx context.Context, p model.Profile) error {
	switch p.Server {
	case "blocked.example":
		r.publish("connecting", "resolving_endpoint", "Resolving endpoint through protected DNS", "")
		<-ctx.Done()
		return ctx.Err()
	case "failed.example":
		r.publish("error", "resolving_endpoint", "Bootstrap DNS and protected HTTPS fallback did not answer", "dns_unavailable")
		return errors.New("fixture DNS unavailable")
	default:
		r.publish("connected", "connected", "", "")
		return nil
	}
}
func (r *guiRuntime) Arm(context.Context) error {
	r.mu.Lock()
	r.status.GuardArmed = true
	r.mu.Unlock()
	r.publish("connecting", "enabling_guard", "Protection enabled", "")
	return nil
}
func (r *guiRuntime) Disconnect(context.Context) error {
	r.mu.Lock()
	r.status.GuardArmed = false
	r.mu.Unlock()
	r.publish("disconnected", "disconnected", "", "")
	return nil
}
func (r *guiRuntime) Status() model.RuntimeStatus { r.mu.Lock(); defer r.mu.Unlock(); return r.status }

type slowDiagnosticsAPI struct{ *API }

func (a *slowDiagnosticsAPI) GetProfileDiagnostics(sender dbus.Sender, id string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	for _, p := range a.service.GetSnapshot(c).Profiles {
		if p.ID == id && p.Server == "slowdiagnostics.example" {
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-a.ctx.Done():
				return "", busError(a.ctx.Err())
			}
			break
		}
	}
	return a.API.GetProfileDiagnostics(sender, id)
}
