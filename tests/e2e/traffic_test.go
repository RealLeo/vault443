package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"vault443/internal/model"
	"vault443/internal/network"
	"vault443/internal/service"
	"vault443/internal/store"
)

func TestRealVLESSTrafficAccounting(t *testing.T) {
	requireIsolated(t)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	dir := "/var/lib/vault443-e2e-traffic"
	state, err := store.Open(filepath.Join(dir, "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	p := localProfile(t)
	caller := service.Caller{UID: 1000}
	if err = state.Update(func(st *store.State) error {
		u := st.User(caller.UID)
		u.Profiles = []model.Profile{p}
		st.SetUser(caller.UID, u)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m := network.New(network.Config{StateDir: dir, RuntimeDir: "/run/vault443-e2e-traffic", XrayPath: "/usr/lib/vault443/xray"})
	s := service.New(state, m)
	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { s.Run(runCtx); close(done) }()
	defer func() {
		stopRun()
		<-done
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := s.Disconnect(cleanup, caller); err != nil {
			t.Error(err)
		}
	}()
	if err = s.Connect(ctx, caller, p.ID); err != nil {
		t.Fatal(err)
	}
	initial := s.GetSnapshot(caller).Traffic
	if initial == nil || initial.SessionID == "" || !initial.Valid || initial.DownloadBytes != 0 {
		t.Fatalf("initial traffic snapshot incorrect: %+v", initial)
	}
	if s.GetSnapshot(service.Caller{UID: 1001}).Traffic != nil {
		t.Fatal("foreign user obtained traffic")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "web.e2e.example.com", MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	transfer := func(method, path string, data []byte) int64 {
		t.Helper()
		req, e := http.NewRequestWithContext(ctx, method, "https://93.184.215.14"+path, bytes.NewReader(data))
		if e != nil {
			t.Fatal(e)
		}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("transfer status %d", res.StatusCode)
		}
		if method == http.MethodPost {
			var reply struct {
				Received int64 `json:"received"`
			}
			if e := json.NewDecoder(res.Body).Decode(&reply); e != nil {
				t.Fatal(e)
			}
			if reply.Received != int64(len(data)) {
				t.Fatalf("server did not receive upload: %+v", reply)
			}
			return reply.Received
		}
		n, e := io.Copy(io.Discard, res.Body)
		if e != nil {
			t.Fatal(e)
		}
		return n
	}
	waitTraffic := func(condition func(*model.Traffic) bool) *model.Traffic {
		t.Helper()
		var last *model.Traffic
		for end := time.Now().Add(4 * time.Second); time.Now().Before(end); {
			last = s.GetSnapshot(caller).Traffic
			if last != nil && condition(last) {
				return last
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("traffic observation timeout: %+v", last)
		return nil
	}
	downloaded := transfer(http.MethodGet, "/large", nil)
	down := waitTraffic(func(v *model.Traffic) bool {
		return v.DownloadBytes >= uint64(downloaded) && v.DownloadBytesPerSecond > 0
	})
	if down.UploadBytes >= down.DownloadBytes/2 {
		t.Fatalf("RX/download direction reversed: %+v", down)
	}
	uploaded := transfer(http.MethodPost, "/upload", bytes.Repeat([]byte("vault443-upload-"), 131072))
	up := waitTraffic(func(v *model.Traffic) bool {
		return v.UploadBytes >= down.UploadBytes+uint64(uploaded) && v.UploadBytesPerSecond > 0
	})
	if up.DownloadBytes-down.DownloadBytes >= uint64(uploaded)/2 {
		t.Fatalf("TX/upload direction reversed: before=%+v after=%+v", down, up)
	}
	t.Logf("real TUN: download payload=%d counted=%d rate=%.0f B/s; upload payload=%d counted=%d rate=%.0f B/s", downloaded, down.DownloadBytes, down.DownloadBytesPerSecond, uploaded, up.UploadBytes-down.UploadBytes, up.UploadBytesPerSecond)
	link, err := net.InterfaceByName(network.TunName)
	if err != nil {
		t.Fatal(err)
	}
	pid := findCore(t, "/run/vault443-e2e-traffic/core.json")
	if err = syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	var resumed *model.Traffic
	for end := time.Now().Add(25 * time.Second); time.Now().Before(end); {
		view := s.GetSnapshot(caller)
		current, e := net.InterfaceByName(network.TunName)
		if view.Runtime.State == "connected" && e == nil && current.Index != link.Index {
			resumed = view.Traffic
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resumed == nil || resumed.SessionID != initial.SessionID || resumed.StartedAt != initial.StartedAt || resumed.DownloadBytes < up.DownloadBytes || resumed.UploadBytes < up.UploadBytes {
		t.Fatalf("automatic core recovery reset logical session: before=%+v resumed=%+v", up, resumed)
	}
	if resumed.DownloadBytes-up.DownloadBytes > 1<<20 || resumed.UploadBytes-up.UploadBytes > 1<<20 {
		t.Fatalf("recreated TUN introduced counter spike: %+v", resumed)
	}
	t.Log("core SIGKILL/recreation: session identity, start time and totals preserved without a counter spike")
	// Stop immediately after a transfer: the final synchronous pre-stop read
	// must account for its bytes even if the one-second sampler has not run.
	beforeStop := s.GetSnapshot(caller).Traffic
	finalPayload := transfer(http.MethodGet, "/large", nil)
	if err = s.Disconnect(ctx, caller); err != nil {
		t.Fatal(err)
	}
	frozen := s.GetSnapshot(caller).Traffic
	if frozen.DownloadBytes < beforeStop.DownloadBytes+uint64(finalPayload) || frozen.DownloadBytesPerSecond != 0 || !frozen.Valid {
		t.Fatalf("last pre-stop transfer lost: before=%+v frozen=%+v payload=%d", beforeStop, frozen, finalPayload)
	}
	time.Sleep(1100 * time.Millisecond)
	if after := s.GetSnapshot(caller).Traffic; *after != *frozen {
		t.Fatalf("disconnected session not frozen: before=%+v after=%+v", frozen, after)
	}
	if err = s.Connect(ctx, caller, p.ID); err != nil {
		t.Fatal(err)
	}
	if fresh := s.GetSnapshot(caller).Traffic; fresh.SessionID == initial.SessionID || fresh.DownloadBytes != 0 || fresh.UploadBytes != 0 {
		t.Fatalf("manual connection did not reset session: %+v", fresh)
	}
	if err = s.Disconnect(ctx, caller); err != nil {
		t.Fatal(err)
	}
	restarted := service.New(state, network.New(network.Config{StateDir: dir, RuntimeDir: "/run/vault443-e2e-traffic", XrayPath: "/usr/lib/vault443/xray"}))
	if fresh := restarted.GetSnapshot(caller).Traffic; fresh.SessionID != "" || fresh.DownloadBytes != 0 || fresh.UploadBytes != 0 {
		t.Fatalf("daemon restart restored volatile traffic: %+v", fresh)
	}
	encoded, err := json.MarshalIndent(frozen, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/results/traffic-session.json", encoded, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("manual disconnect freezes final totals; manual reconnect and daemon restart reset statistics")
}
