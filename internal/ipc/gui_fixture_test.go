package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"vault443/internal/journal"
	"vault443/internal/model"
	"vault443/internal/service"
	"vault443/internal/store"
	"vault443/internal/workvpn"
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
	history, err := journal.Open(filepath.Join(t.TempDir(), "journal"), journal.Options{QueueSize: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	s := service.New(st, &guiRuntime{inertRuntime: inertRuntime{status: model.RuntimeStatus{State: "disconnected", ExternalVPNs: []string{}}}}, history)
	workStore, err := workvpn.Open(filepath.Join(t.TempDir(), "work"), true)
	if err != nil {
		t.Fatal(err)
	}
	s.AttachWork(workStore, &guiWorkRuntime{})
	defer func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		s.StopWork(stopCtx)
	}()
	// Exercise exported bracketed IPv6 through the actual GUI/private-bus import.
	writeGUIOpenVPNFixture(t, addressFile+".ovpn", "[2001:db8::42]")
	writeGUIOpenVPNFixture(t, addressFile+".blocked.ovpn", "gui-blocked.example")
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
	fixture := &slowDiagnosticsAPI{API: &API{ctx: ctx, service: s, auth: Authorizer{Source: testIdentity{SystemIdentity{conn}}, OperatorGroup: "vault443"}}, conn: conn, history: history}
	if err = conn.Export(fixture, ObjectPath, BusName); err != nil {
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
	lastPulse := time.Now()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if fixture.options().Pulse && time.Since(lastPulse) >= time.Second {
				_ = conn.Emit(ObjectPath, BusName+".Changed")
				lastPulse = time.Now()
			}
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

type guiFixtureOptions struct {
	Pulse                                 bool
	SnapshotMS, LogsMS, PrepareMS, BootMS int
	FailPrepare, FailLogs, FailBoot       bool
}
type slowDiagnosticsAPI struct {
	*API
	mu      sync.Mutex
	config  guiFixtureOptions
	conn    *dbus.Conn
	history *journal.Journal
	tick    uint64
}

func (a *slowDiagnosticsAPI) options() guiFixtureOptions {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.config
}
func (a *slowDiagnosticsAPI) pause(ms int) {
	if ms <= 0 {
		return
	}
	timer := time.NewTimer(time.Duration(ms) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-a.ctx.Done():
	}
}
func (a *slowDiagnosticsAPI) FixtureConfigure(data string) *dbus.Error {
	var config guiFixtureOptions
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return busError(err)
	}
	a.mu.Lock()
	a.config = config
	a.mu.Unlock()
	return nil
}
func (a *slowDiagnosticsAPI) FixtureRestart() *dbus.Error {
	if _, err := a.conn.ReleaseName(BusName); err != nil {
		return busError(err)
	}
	go func() { a.pause(500); _, _ = a.conn.RequestName(BusName, dbus.NameFlagDoNotQueue) }()
	return nil
}
func (a *slowDiagnosticsAPI) FixtureSeedLogs(sender dbus.Sender, id string, count int32) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	if _, err := a.service.GetProfileLogs(c, id, "tail", 1); err != nil {
		return busError(err)
	}
	if count > 1000 || count < 0 {
		return busError(errors.New("invalid fixture count"))
	}
	if err := a.service.ClearProfileLogs(c, id); err != nil {
		return busError(err)
	}
	log := a.history.NewSession(c.UID, id)
	for i := int32(0); i < count; i++ {
		log.Log("info", fmt.Sprintf("Synthetic journal line %d", i))
	}
	a.history.Flush()
	return nil
}
func (a *slowDiagnosticsAPI) FixtureAppendLog(sender dbus.Sender, id, message string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	if _, err := a.service.GetProfileLogs(c, id, "tail", 1); err != nil {
		return busError(err)
	}
	a.history.NewSession(c.UID, id).Log("info", message)
	a.history.Flush()
	return nil
}
func (a *slowDiagnosticsAPI) GetSnapshot(sender dbus.Sender) (string, *dbus.Error) {
	options := a.options()
	result, e := a.API.GetSnapshot(sender)
	if e != nil {
		return result, e
	}
	a.pause(options.SnapshotMS)
	if options.Pulse {
		var snapshot map[string]any
		_ = json.Unmarshal([]byte(result), &snapshot)
		a.mu.Lock()
		a.tick++
		tick := a.tick
		a.mu.Unlock()
		snapshot["fixtureTick"] = tick
		data, _ := json.Marshal(snapshot)
		result = string(data)
	}
	return result, nil
}
func (a *slowDiagnosticsAPI) GetProfileLogs(sender dbus.Sender, id, cursor string, limit int32) (string, *dbus.Error) {
	options := a.options()
	result, e := a.API.GetProfileLogs(sender, id, cursor, limit)
	a.pause(options.LogsMS)
	if options.FailLogs {
		return "", busError(errors.New("synthetic log failure"))
	}
	return result, e
}
func (a *slowDiagnosticsAPI) GetWorkLogs(sender dbus.Sender, id, cursor string, limit int32) (string, *dbus.Error) {
	options := a.options()
	result, e := a.API.GetWorkLogs(sender, id, cursor, limit)
	a.pause(options.LogsMS)
	if options.FailLogs {
		return "", busError(errors.New("synthetic log failure"))
	}
	return result, e
}
func (a *slowDiagnosticsAPI) PrepareImport(sender dbus.Sender, source, kind, name string) (string, *dbus.Error) {
	options := a.options()
	result, e := a.API.PrepareImport(sender, source, kind, name)
	a.pause(options.PrepareMS)
	if options.FailPrepare {
		return "", busError(errors.New("synthetic import failure"))
	}
	return result, e
}
func (a *slowDiagnosticsAPI) PrepareWorkImport(sender dbus.Sender, data string) (string, *dbus.Error) {
	options := a.options()
	result, e := a.API.PrepareWorkImport(sender, data)
	a.pause(options.PrepareMS)
	if options.FailPrepare {
		return "", busError(errors.New("synthetic import failure"))
	}
	return result, e
}
func (a *slowDiagnosticsAPI) SetBootProfile(sender dbus.Sender, id string) *dbus.Error {
	options := a.options()
	a.pause(options.BootMS)
	if options.FailBoot {
		return busError(errors.New("synthetic boot failure"))
	}
	return a.API.SetBootProfile(sender, id)
}

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
