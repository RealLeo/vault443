package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"vault443/internal/journal"
	"vault443/internal/network"
	"vault443/internal/worknet"
	"vault443/internal/workvpn"
)

var workCase atomic.Uint64

type workHarness struct {
	t          *testing.T
	ctx        context.Context
	n          *network.Manager
	w          *worknet.Manager
	workConfig worknet.Config
	logs       *journal.Journal
	running    map[string]*workRun
	profileIDs []string
	caseID     string
}
type workRun struct {
	cancel context.CancelFunc
	done   chan error
}

func requireWorkIsolated(t *testing.T) {
	t.Helper()
	if os.Getenv("VAULT443_WORKVPN_E2E") != "1" {
		t.Skip("requires opt-in isolated OpenVPN fixture")
	}
	if os.Getenv("VAULT443_E2E_ISOLATED") != "1" || os.Geteuid() != 0 {
		t.Fatal("refusing work VPN network test outside isolated root container")
	}
	if _, e := os.Stat("/.dockerenv"); e != nil {
		t.Fatal("refusing work VPN test outside Docker")
	}
	links, e := net.Interfaces()
	if e != nil {
		t.Fatal(e)
	}
	for _, l := range links {
		if l.Name != "lo" && l.Name != "e2euplink" && l.Name != "wdock" && l.Name != "wclient" && l.Name != network.TunName && !strings.HasPrefix(l.Name, "v443w") {
			t.Fatalf("unexpected interface %s; refusing network mutations", l.Name)
		}
	}
}

func newWorkHarness(t *testing.T) *workHarness {
	t.Helper()
	requireWorkIsolated(t)
	serial := workCase.Add(1)
	state := fmt.Sprintf("/var/lib/vault443-e2e/work-%d", serial)
	runtime := fmt.Sprintf("/run/v443we-%d", serial)
	for _, d := range []string{state, runtime} {
		if e := os.MkdirAll(d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	logs, e := journal.Open(filepath.Join(state, "journal"))
	if e != nil {
		t.Fatal(e)
	}
	n := network.New(network.Config{StateDir: state, RuntimeDir: runtime, XrayPath: "/usr/lib/vault443/xray"})
	helper := os.Getenv("VAULT443_WORKVPN_EVENT_HELPER")
	if helper == "" {
		helper = "/src/build/vault443d"
	}
	workConfig := worknet.Config{StateDir: state, RuntimeDir: runtime, OpenVPNPath: "/usr/sbin/openvpn", EventHelperPath: helper}
	w := worknet.New(workConfig, n)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	h := &workHarness{t: t, ctx: ctx, n: n, w: w, workConfig: workConfig, logs: logs, running: map[string]*workRun{}, caseID: fmt.Sprintf("%d", serial)}
	t.Cleanup(func() {
		for id := range h.running {
			h.stop(id)
		}
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = n.Disconnect(cleanup)
		h.saveJournals()
		logs.Close()
		cancel()
	})
	return h
}

func workProfile(t *testing.T, index int, extra string) workvpn.Profile {
	t.Helper()
	b, e := os.ReadFile(fmt.Sprintf("/fixture/work/client-%d.ovpn", index))
	if e != nil {
		t.Fatal(e)
	}
	p, e := workvpn.Parse(fmt.Sprintf("Isolated work %d", index), string(b)+extra)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func (h *workHarness) start(p workvpn.Profile) {
	h.t.Helper()
	ctx, cancel := context.WithCancel(h.ctx)
	done := make(chan error, 1)
	h.running[p.ID] = &workRun{cancel, done}
	h.profileIDs = append(h.profileIDs, p.ID)
	log := h.logs.NewSession(1000, p.ID, p.Secrets()...)
	go func() { done <- h.w.Run(ctx, 1000, p, log, func(worknet.Status) {}) }()
}
func (h *workHarness) waitConnected(id string) {
	h.t.Helper()
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); {
		s := h.w.Snapshot(id)
		if s.State == "connected" {
			return
		}
		select {
		case e := <-h.running[id].done:
			h.running[id].done <- e
			h.dump()
			h.t.Fatalf("OpenVPN exited before connected: %v; state=%+v", e, s)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.dump()
	h.t.Fatalf("OpenVPN did not connect: %+v", h.w.Snapshot(id))
}
func (h *workHarness) stop(id string) {
	h.t.Helper()
	r, ok := h.running[id]
	if !ok {
		return
	}
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(12 * time.Second):
		h.t.Error("OpenVPN cancellation did not complete")
	}
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e := h.w.Forget(c, id); e != nil {
		h.t.Errorf("manual OpenVPN cleanup: %v", e)
	}
	delete(h.running, id)
}
func (h *workHarness) dump() {
	for _, args := range [][]string{{"ip", "-4", "rule", "show"}, {"ip", "-4", "route", "show", "table", "all"}, {"nft", "list", "ruleset"}, {"resolvectl", "status"}} {
		b, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
		h.t.Logf("%v\n%s", args, b)
	}
	h.logs.Flush()
	for id := range h.running {
		page, e := h.logs.Read(1000, id, "", 100)
		if e == nil {
			for _, row := range page.Entries {
				h.t.Log(row.Message)
			}
		}
	}
}

type workReply struct{ Marker, Peer, Server string }

func workHTTP(ctx context.Context, address, bind string) (workReply, error) {
	dial := &net.Dialer{Timeout: 1500 * time.Millisecond}
	if bind != "" {
		dial.Control = func(_, _ string, c syscall.RawConn) error {
			var e error
			err := c.Control(func(fd uintptr) {
				e = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, bind)
			})
			if err != nil {
				return err
			}
			return e
		}
	}
	tr := &http.Transport{Proxy: nil, DialContext: dial.DialContext, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+net.JoinHostPort(address, "8081")+"/", nil)
	res, e := client.Do(req)
	if e != nil {
		return workReply{}, e
	}
	defer res.Body.Close()
	var reply workReply
	e = json.NewDecoder(res.Body).Decode(&reply)
	return reply, e
}
func (h *workHarness) assertWork(address, sourcePrefix string) {
	h.t.Helper()
	r, e := workHTTP(h.ctx, address, "")
	if e != nil || r.Marker != "work-vpn-ok" || !strings.HasPrefix(r.Peer, sourcePrefix) {
		h.dump()
		h.t.Fatalf("work request wrong path: address=%s reply=%+v err=%v", address, r, e)
	}
}

func TestRealWorkVPNSplitRoutingAndVLESSOrders(t *testing.T) {
	for _, first := range []bool{false, true} {
		t.Run(fmt.Sprintf("VLESSFirst=%v", first), func(t *testing.T) {
			h := newWorkHarness(t)
			p1 := workProfile(t, 1, "")
			p2 := workProfile(t, 2, "")
			if first {
				if e := h.n.Connect(h.ctx, localProfile(t)); e != nil {
					t.Fatal(e)
				}
			}
			h.start(p1)
			h.waitConnected(p1.ID)
			h.start(p2)
			h.waitConnected(p2.ID)
			if !first {
				if e := h.n.Connect(h.ctx, localProfile(t)); e != nil {
					h.dump()
					t.Fatal(e)
				}
			}
			if e := h.n.Reconcile(h.ctx); e != nil {
				h.dump()
				t.Fatal(e)
			}
			h.assertWork("192.168.100.15", "10.70.")
			h.assertWork("10.42.0.15", "10.71.")
			route := command(t, "ip", "-4", "route", "get", "192.168.100.15")
			if strings.Contains(route, "wdock") || !strings.Contains(route, "v443w") {
				t.Fatal("Docker stole broader work route:", route)
			}
			internet, e := request(h.ctx, "")
			if e != nil || internet.Peer == "192.0.2.2" {
				h.dump()
				t.Fatalf("internet did not use VLESS: %+v %v", internet, e)
			}
			for _, domain := range []string{"host.work1.e2e.test", "host.work2.e2e.test"} {
				out := command(t, "resolvectl", "query", "--type=A", domain)
				if !strings.Contains(out, "192.168.100.15") && !strings.Contains(out, "10.42.0.15") {
					t.Fatal("split DNS failed:", out)
				}
			}
			if _, e := workHTTP(h.ctx, "192.168.100.15", "e2euplink"); e == nil {
				t.Fatal("physical interface bypassed work-route protection")
			}
			if e := h.n.Disconnect(h.ctx); e != nil {
				t.Fatal(e)
			}
			h.assertWork("192.168.100.15", "10.70.")
			h.assertWork("10.42.0.15", "10.71.")
			h.stop(p1.ID)
			h.assertWork("10.42.0.15", "10.71.")
			route = command(t, "ip", "-4", "route", "get", "192.168.100.15")
			if !strings.Contains(route, "wdock") {
				t.Fatal("manual work disconnect did not restore Docker routing:", route)
			}
			h.stop(p2.ID)
			if strings.Contains(command(t, "nft", "list", "tables"), "vault443_work") {
				t.Fatal("owned work firewall left after final manual disconnect")
			}
		})
	}
}

func TestRealWorkVPNRouteOverrideAndConflict(t *testing.T) {
	h := newWorkHarness(t)
	p1 := workProfile(t, 1, "")
	p2 := workProfile(t, 1, "setenv UV_ID second-fixture-identity\n")
	h.start(p1)
	h.waitConnected(p1.ID)
	h.start(p2)
	var conflict bool
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); {
		select {
		case err := <-h.running[p2.ID].done:
			h.running[p2.ID].done <- err
			h.dump()
			t.Fatalf("second work VPN exited before route conflict: %v", err)
		default:
		}
		for _, r := range h.w.Routes() {
			if r.Source == "server" && r.CIDR == "192.168.0.0/16" && r.Target == p2.ID && r.Conflict {
				state := h.w.Snapshot(p2.ID).State
				conflict = state == "connected" || state == "conflict"
			}
		}
		if conflict {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !conflict {
		h.dump()
		t.Fatal("equal work routes did not report conflict")
	}
	h.assertWork("192.168.100.15", "10.70.")
	before := command(t, "ip", "-4", "route", "get", "192.168.100.15")
	// Equal routes keep whichever tunnel was selected first. Explicitly choose
	// the other actual interface instead of relying on profile/map ordering.
	selected := p1
	selectedInterface := h.w.Snapshot(p1.ID).Interface
	if strings.Contains(before, "dev "+selectedInterface+" ") {
		selected = p2
		selectedInterface = h.w.Snapshot(p2.ID).Interface
	}
	if selectedInterface == "" || strings.Contains(before, "dev "+selectedInterface+" ") {
		t.Fatal("cannot identify the alternate work tunnel:", before)
	}
	rule, e := workvpn.NewRouteRule("192.168.0.0/16", selected.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.w.SetRules(h.ctx, []workvpn.RouteRule{rule}); e != nil {
		h.dump()
		t.Fatal(e)
	}
	after := command(t, "ip", "-4", "route", "get", "192.168.100.15")
	if !strings.Contains(after, "dev "+selectedInterface+" ") {
		t.Fatalf("explicit route selection did not choose %s: before=%s after=%s", selectedInterface, before, after)
	}
	h.assertWork("192.168.100.15", "10.70.")
	local, e := workvpn.NewRouteRule("192.168.100.15", "local")
	if e != nil {
		t.Fatal(e)
	}
	if e = h.w.SetRules(h.ctx, []workvpn.RouteRule{rule, local}); e != nil {
		t.Fatal(e)
	}
	if route := command(t, "ip", "-4", "route", "get", "192.168.100.15"); !strings.Contains(route, "wdock") {
		t.Fatal("specific local override did not restore Docker:", route)
	}
	if e = h.w.SetRules(h.ctx, []workvpn.RouteRule{rule}); e != nil {
		t.Fatal(e)
	}
	h.assertWork("192.168.100.15", "10.70.")
	bad, e := workvpn.NewRouteRule("0.0.0.0/0", "local")
	if e != nil {
		t.Fatal(e)
	}
	if e = h.w.SetRules(h.ctx, []workvpn.RouteRule{bad}); e == nil {
		t.Fatal("arbitrary physical Internet override accepted")
	}
	h.assertWork("192.168.100.15", "10.70.")
	dns, e := workvpn.NewDNSRule("work1.e2e.test", selected.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.w.SetDNSRules(h.ctx, []workvpn.DNSRule{dns}); e != nil {
		t.Fatal(e)
	}
	out := command(t, "resolvectl", "query", "--type=A", "host.work1.e2e.test")
	if !strings.Contains(out, "192.168.100.15") {
		t.Fatal("explicit DNS provider failed:", out)
	}
	if e = h.n.Connect(h.ctx, localProfile(t)); e != nil {
		t.Fatal(e)
	}
	command(t, "resolvectl", "flush-caches")
	out = command(t, "resolvectl", "query", "--type=A", "host.work1.e2e.test")
	if !strings.Contains(out, "192.168.100.15") {
		t.Fatal("explicit DNS provider failed with VLESS guard:", out)
	}
}

func TestRealWorkVPNCancellationKeepsProtection(t *testing.T) {
	h := newWorkHarness(t)
	p := workProfile(t, 1, "")
	h.start(p)
	h.waitConnected(p.ID)
	h.assertWork("192.168.100.15", "10.70.")
	// Cancellation of one attempt is the same transition the service uses before
	// retrying after a core failure. Known routes must stay closed until Forget.
	r := h.running[p.ID]
	r.cancel()
	select {
	case e := <-r.done:
		r.done <- e
	case <-time.After(12 * time.Second):
		t.Fatal("cancel did not stop OpenVPN")
	}
	if _, e := workHTTP(h.ctx, "192.168.100.15", ""); e == nil {
		t.Fatal("corporate traffic escaped after attempt ended")
	}
	if _, e := workHTTP(h.ctx, "192.168.100.15", "e2euplink"); e == nil {
		t.Fatal("corporate traffic escaped through physical interface")
	}
	h.stop(p.ID)
	if route := command(t, "ip", "-4", "route", "get", "192.168.100.15"); !strings.Contains(route, "wdock") {
		t.Fatal("explicit disconnect did not release corporate reservation:", route)
	}
}

func TestRealWorkVPNFullTunnelPausesAndResumesVLESS(t *testing.T) {
	for _, push := range []bool{false, true} {
		t.Run(fmt.Sprintf("ServerPush=%v", push), func(t *testing.T) {
			h := newWorkHarness(t)
			if e := h.n.Connect(h.ctx, localProfile(t)); e != nil {
				t.Fatal(e)
			}
			p := workProfile(t, 1, "redirect-gateway def1\n")
			peerPrefix := "10.70."
			if push {
				p = workProfile(t, 3, "")
				peerPrefix = "10.72."
			}
			h.start(p)
			h.waitConnected(p.ID)
			if e := h.n.Reconcile(h.ctx); e != nil {
				h.dump()
				t.Fatal(e)
			}
			if state := h.n.Status().State; state != "paused_external" {
				h.dump()
				t.Fatalf("VLESS did not pause for full work tunnel: %s", state)
			}
			internet, e := request(h.ctx, "")
			if e != nil || !strings.HasPrefix(internet.Peer, peerPrefix) {
				h.dump()
				t.Fatalf("Internet did not use full OpenVPN tunnel: %+v %v", internet, e)
			}
			if _, e = request(h.ctx, "e2euplink"); e == nil {
				t.Fatal("full work tunnel permitted physical Internet bypass")
			}
			h.stop(p.ID)
			// The service consumes this transition and reconnects its still-desired
			// profile. Reconcile intentionally does not own that profile or launch it.
			e = h.n.Reconcile(h.ctx)
			if e == nil || h.n.Status().State != "reconnecting" {
				h.dump()
				t.Fatalf("missing protected resume transition: state=%s error=%v", h.n.Status().State, e)
			}
			if e = h.n.Connect(h.ctx, localProfile(t)); e != nil {
				h.dump()
				t.Fatal(e)
			}
			if h.n.Status().State != "connected" {
				h.dump()
				t.Fatal("VLESS did not resume after full work VPN disconnected")
			}
			internet, e = request(h.ctx, "")
			if e != nil || strings.HasPrefix(internet.Peer, peerPrefix) || internet.Peer == "192.0.2.2" {
				t.Fatalf("Internet did not return to VLESS: %+v %v", internet, e)
			}
		})
	}
}

// workDockerHTTP originates inside a distinct namespace, so it exercises the
// kernel forward hook and bridge source NAT instead of host output filtering.
func workDockerHTTP(ctx context.Context, address string) (workReply, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "netns", "exec", "work-docker", "curl", "--noproxy", "*", "--fail", "--silent", "--show-error", "--max-time", "2", "http://"+net.JoinHostPort(address, "8081")+"/").Output()
	if err != nil {
		return workReply{}, err
	}
	var reply workReply
	err = json.Unmarshal(out, &reply)
	return reply, err
}

func TestRealWorkVPNForwardedDockerAndIPv6Protection(t *testing.T) {
	h := newWorkHarness(t)
	p := workProfile(t, 1, "")
	// Prove that a physical IPv6 path exists before requiring the work guard to
	// block it. Otherwise a missing default route could hide a protection bug.
	before, err := workHTTP(h.ctx, "2001:db8:100::15", "e2euplink")
	if err != nil || before.Marker != "work-vpn-ok" {
		t.Fatalf("physical IPv6 control path unavailable: %+v %v", before, err)
	}
	h.start(p)
	h.waitConnected(p.ID)
	h.assertWork("2001:db8:100::15", "2001:db8:70:")
	forwarded, err := workDockerHTTP(h.ctx, "192.168.100.15")
	if err != nil || forwarded.Marker != "work-vpn-ok" || !strings.HasPrefix(forwarded.Peer, "10.70.") {
		h.dump()
		t.Fatalf("Docker-origin traffic did not use work tunnel: %+v %v", forwarded, err)
	}
	if err = h.n.Connect(h.ctx, localProfile(t)); err != nil {
		t.Fatal(err)
	}
	forwarded, err = workDockerHTTP(h.ctx, "192.168.100.15")
	if err != nil || !strings.HasPrefix(forwarded.Peer, "10.70.") {
		h.dump()
		t.Fatalf("VLESS changed work forwarding: %+v %v", forwarded, err)
	}
	h.assertWork("2001:db8:100::15", "2001:db8:70:")
	r := h.running[p.ID]
	r.cancel()
	select {
	case e := <-r.done:
		r.done <- e
	case <-time.After(12 * time.Second):
		t.Fatal("OpenVPN did not cancel")
	}
	if _, err = workDockerHTTP(h.ctx, "192.168.100.15"); err == nil {
		t.Fatal("Docker-origin work traffic escaped after cancellation")
	}
	for _, bind := range []string{"", "e2euplink"} {
		if _, err = workHTTP(h.ctx, "2001:db8:100::15", bind); err == nil {
			t.Fatalf("IPv6 work traffic escaped after cancellation (bind=%q)", bind)
		}
	}
	// Force a temporary forward-only physical route inside this namespace to
	// verify the firewall as well as the coordinator's unreachable route.
	command(t, "ip", "-4", "route", "add", "192.168.100.15/32", "via", "192.0.2.1", "dev", "e2euplink", "table", "52990")
	t.Cleanup(func() { _, _ = exec.Command("ip", "-4", "route", "flush", "table", "52990").CombinedOutput() })
	command(t, "ip", "-4", "rule", "add", "priority", "900", "iif", "wdock", "to", "192.168.100.15/32", "lookup", "52990")
	t.Cleanup(func() {
		_, _ = exec.Command("ip", "-4", "rule", "del", "priority", "900", "iif", "wdock", "to", "192.168.100.15/32", "lookup", "52990").CombinedOutput()
	})
	if _, err = workDockerHTTP(h.ctx, "192.168.100.15"); err == nil {
		t.Fatal("forward guard allowed canceled corporate traffic over physical route")
	}
	// Verify the same synthetic physical path becomes usable after both manual
	// disconnects; its prior failure must be protection, not a broken fixture.
	h.stop(p.ID)
	if err = h.n.Disconnect(h.ctx); err != nil {
		t.Fatal(err)
	}
	forwarded, err = workDockerHTTP(h.ctx, "192.168.100.15")
	if err != nil || forwarded.Marker != "work-vpn-ok" || forwarded.Peer != "192.0.2.2" {
		h.dump()
		t.Fatalf("physical forwarding control path failed after manual disconnect: %+v %v", forwarded, err)
	}
	if _, err = workHTTP(h.ctx, "2001:db8:100::15", "e2euplink"); err != nil {
		t.Fatalf("physical IPv6 route was not released after manual disconnect: %v", err)
	}
}

func TestRealWorkVPNSameBootRecoveryRetainsOnlyDesired(t *testing.T) {
	h := newWorkHarness(t)
	bootID := "isolated-work-recovery-" + h.caseID
	if e := h.w.Initialize(h.ctx, bootID, false); e != nil {
		t.Fatal(e)
	}
	p1, p2 := workProfile(t, 1, ""), workProfile(t, 2, "")
	h.start(p1)
	h.waitConnected(p1.ID)
	h.start(p2)
	h.waitConnected(p2.ID)
	h.assertWork("192.168.100.15", "10.70.")
	h.assertWork("10.42.0.15", "10.71.")
	oldInterface := h.w.Snapshot(p1.ID).Interface
	// Stop the processes while keeping their recovery metadata, as service
	// shutdown does. Profile 1's cancellation was persisted immediately before
	// that shutdown; profile 2 still has a saved desired connection.
	for _, id := range []string{p1.ID, p2.ID} {
		r := h.running[id]
		r.cancel()
		select {
		case e := <-r.done:
			r.done <- e
		case <-time.After(12 * time.Second):
			t.Fatal("OpenVPN did not stop before simulated service restart")
		}
	}
	h.w = worknet.New(h.workConfig, h.n)
	if e := h.w.Initialize(h.ctx, bootID, true); e != nil {
		h.dump()
		t.Fatal(e)
	}
	if e := h.w.RetainDesired(h.ctx, []string{p2.ID}); e != nil {
		h.dump()
		t.Fatal(e)
	}
	if h.w.Snapshot(p1.ID).State != "disconnected" || h.w.Snapshot(p2.ID).State != "retry_wait" {
		t.Fatalf("incorrect recovered desired set: canceled=%+v retained=%+v", h.w.Snapshot(p1.ID), h.w.Snapshot(p2.ID))
	}
	if route := command(t, "ip", "-4", "route", "get", "192.168.100.15"); !strings.Contains(route, "wdock") {
		t.Fatal("canceled connection's protected route survived restart:", route)
	}
	if _, e := net.InterfaceByName(oldInterface); e == nil {
		t.Fatal("canceled connection's persistent TUN survived restart")
	}
	if _, e := workHTTP(h.ctx, "10.42.0.15", ""); e == nil {
		t.Fatal("retained corporate destination escaped before reconnect")
	}
	if _, e := workHTTP(h.ctx, "10.42.0.15", "e2euplink"); e == nil {
		t.Fatal("retained corporate destination escaped via physical interface")
	}
	h.stop(p1.ID)
	h.start(p2)
	h.waitConnected(p2.ID)
	h.assertWork("10.42.0.15", "10.71.")
	h.stop(p2.ID)
	if strings.Contains(command(t, "nft", "list", "tables"), "vault443_work") {
		t.Fatal("recovered work firewall left after final disconnect")
	}
}

func (h *workHarness) saveJournals() {
	h.logs.Flush()
	for _, id := range h.profileIDs {
		page, e := h.logs.Read(1000, id, "", 500)
		if e != nil {
			h.t.Logf("cannot retain fixture journal: %v", e)
			continue
		}
		b, e := json.MarshalIndent(page, "", "  ")
		if e == nil {
			e = os.WriteFile(filepath.Join("/results", "work-journal-"+h.caseID+"-"+id+".json"), b, 0600)
		}
		if e != nil {
			h.t.Logf("cannot write fixture journal: %v", e)
		}
	}
}
