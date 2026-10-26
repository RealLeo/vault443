package network

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"vault443/internal/model"
)

func failureCode(t *testing.T, err error) string {
	t.Helper()
	var failure *bootstrapError
	if !errors.As(err, &failure) {
		t.Fatalf("expected safe bootstrap error, got %v", err)
	}
	if strings.Contains(err.Error(), "private.example") || strings.Contains(err.Error(), "secret") {
		t.Fatal("resolver error leaked input")
	}
	return failure.code
}
func dnsJSON(name, ip string) string {
	data, _ := json.Marshal(map[string]any{"Status": 0, "Question": []any{map[string]any{"name": name, "type": 1}}, "Answer": []any{map[string]any{"name": name, "type": 1, "data": ip}}})
	return string(data)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testBootstrap(t *testing.T, response func(*http.Request) (*http.Response, error)) *bootstrapResolver {
	t.Helper()
	r := newBootstrapResolver(&net.Dialer{})
	t.Cleanup(r.close)
	r.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return nil, &net.OpError{Op: "dial", Net: "udp", Err: errors.New("unreachable")}
	}
	r.client.Transport = roundTripFunc(response)
	return r
}
func TestBootstrapTransportRestrictions(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	r := newBootstrapResolver(bootstrapDialer())
	defer r.close()
	tr := r.client.Transport.(*http.Transport)
	if tr.Proxy != nil || tr.DialContext == nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.ServerName != bootstrapDoHHost || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("unsafe HTTPS bootstrap transport")
	}
	if r.client.CheckRedirect(&http.Request{}, nil) != http.ErrUseLastResponse {
		t.Fatal("redirect allowed")
	}
	if r.dnsTimeout != 2*time.Second || r.totalTimeout != 8*time.Second {
		t.Fatal("bootstrap timeout contract changed")
	}
	// Inspect the socket destination through Control; fail before actual dialing.
	var destination string
	stop := errors.New("test: do not send traffic")
	dialer := &net.Dialer{Control: func(network, address string, _ syscall.RawConn) error { destination = address; return stop }}
	pinned := newBootstrapResolver(dialer)
	defer pinned.close()
	_, err := pinned.client.Transport.(*http.Transport).DialContext(context.Background(), "tcp", "unrelated.invalid:99")
	if !errors.Is(err, stop) || destination != bootstrapDoHAddress {
		t.Fatalf("dial escaped fixed resolver: %s, %v", destination, err)
	}
}
func TestBootstrapDNSDeadlineThenHTTPS(t *testing.T) {
	var calls atomic.Int32
	r := testBootstrap(t, func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if req.URL.Host != bootstrapDoHHost || req.URL.Path != "/dns-query" || req.URL.Query().Get("name") != "private.example" || req.URL.Query().Get("type") != "A" || req.Header.Get("Accept") != "application/dns-json" {
			t.Error("incorrect DoH request")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/dns-json"}}, Body: io.NopCloser(strings.NewReader(dnsJSON("private.example", "203.0.113.10")))}, nil
	})
	r.dnsTimeout = 25 * time.Millisecond
	r.lookup = func(ctx context.Context, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() }
	start := time.Now()
	got, err := r.resolve(context.Background(), "private.example")
	if err != nil || got.String() != "203.0.113.10" || calls.Load() != 1 {
		t.Fatalf("fallback: %v %v", got, err)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond || elapsed > time.Second {
		t.Fatalf("unexpected DNS budget: %v", elapsed)
	}
}
func TestBootstrapNumericAndAmbiguousNegativeDNS(t *testing.T) {
	var calls atomic.Int32
	body := `{"Status":3,"Question":[{"name":"private.example.","type":1}]}`
	r := testBootstrap(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/dns-json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	r.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Name: "private.example", IsNotFound: true}
	}
	address, err := r.resolve(context.Background(), "2001:db8::1")
	if err != nil || address.String() != "2001:db8::1" || calls.Load() != 0 {
		t.Fatal(address, err)
	}
	_, err = r.resolve(context.Background(), "private.example")
	if failureCode(t, err) != "dns_not_found" || calls.Load() != 1 {
		t.Fatal("NXDOMAIN not confirmed", err)
	}
	body = `{"Status":0,"Question":[{"name":"private.example.","type":1}]}`
	_, err = r.resolve(context.Background(), "private.example")
	if failureCode(t, err) != "dns_no_answer" || calls.Load() != 2 {
		t.Fatal("existing name without IPv4 mislabeled as NXDOMAIN", err)
	}
	r.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("HTTPS unavailable") })
	_, err = r.resolve(context.Background(), "private.example")
	if failureCode(t, err) != "dns_no_answer" {
		t.Fatal("known negative DNS answer replaced by fallback transport error", err)
	}
	r.lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	_, err = r.resolve(context.Background(), "private.example")
	if failureCode(t, err) != "dns_no_answer" || calls.Load() != 2 {
		t.Fatal("empty DNS response lost", err)
	}
}
func TestBootstrapHTTPSValidation(t *testing.T) {
	for _, tc := range []struct {
		name, body, code string
		status           int
	}{
		{"nxdomain", `{"Status":3,"Question":[{"name":"private.example.","type":1}]}`, "dns_not_found", 200},
		{"no answer", `{"Status":0,"Question":[{"name":"private.example.","type":1}]}`, "dns_no_answer", 200},
		{"wrong question", dnsJSON("unrelated.example", "203.0.113.10"), "dns_invalid_response", 200},
		{"redirect", "", "dns_invalid_response", 302},
		{"missing status", `{"Question":[{"name":"private.example","type":1}]}`, "dns_invalid_response", 200},
		{"truncated", `{"TC":true,"Status":0,"Question":[{"name":"private.example","type":1}]}`, "dns_invalid_response", 200},
		{"oversized", strings.Repeat("x", 65537), "dns_invalid_response", 200},
		{"unrelated answer", `{"Status":0,"Question":[{"name":"private.example","type":1}],"Answer":[{"name":"other.example","type":1,"data":"203.0.113.9"}]}`, "dns_no_answer", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := testBootstrap(t, func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"application/dns-json"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			_, err := r.resolve(context.Background(), "private.example")
			if failureCode(t, err) != tc.code {
				t.Fatalf("%v", err)
			}
		})
	}
	got, err := parseBootstrapAnswer([]byte(`{"Status":0,"Question":[{"name":"private.example","type":1}],"Answer":[{"name":"edge.example.","type":1,"data":"203.0.113.9"},{"name":"private.example.","type":5,"data":"edge.example."}]}`), "private.example")
	if err != nil || got.String() != "203.0.113.9" {
		t.Fatal("valid CNAME chain failed", got, err)
	}
}
func TestBootstrapCancellationAndTotalBudget(t *testing.T) {
	for _, phase := range []string{"dns", "https"} {
		t.Run(phase, func(t *testing.T) {
			started := make(chan struct{})
			r := testBootstrap(t, func(req *http.Request) (*http.Response, error) {
				close(started)
				<-req.Context().Done()
				return nil, req.Context().Err()
			})
			if phase == "dns" {
				r.lookup = func(ctx context.Context, _ string) ([]netip.Addr, error) {
					close(started)
					<-ctx.Done()
					return nil, ctx.Err()
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { _, err := r.resolve(ctx, "private.example"); result <- err }()
			<-started
			start := time.Now()
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("cancel did not interrupt bootstrap")
			}
			if time.Since(start) > 250*time.Millisecond {
				t.Fatal("slow cancellation")
			}
		})
	}
	r := testBootstrap(t, func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	r.totalTimeout = 45 * time.Millisecond
	_, err := r.resolve(context.Background(), "private.example")
	if failureCode(t, err) != "dns_timeout" {
		t.Fatal(err)
	}
	r = testBootstrap(t, func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Err: errors.New("secret URL")}
	})
	_, err = r.resolve(context.Background(), "private.example")
	if failureCode(t, err) != "dns_transport" {
		t.Fatal(err)
	}
}
func bootstrapCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: bootstrapDoHHost}, DNSNames: []string{bootstrapDoHHost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, ca
}
func TestBootstrapRealTLSValidationAndNoRedirect(t *testing.T) {
	certificate, ca := bootstrapCertificate(t)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		if req.TLS.ServerName != bootstrapDoHHost {
			t.Error("TLS server name not pinned")
		}
		if req.URL.Query().Get("name") == "redirect.example" {
			http.Redirect(w, req, "https://outside.invalid/secret", 302)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		io.WriteString(w, dnsJSON(req.URL.Query().Get("name"), "203.0.113.10"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()
	r := newBootstrapResolver(&net.Dialer{})
	defer r.close()
	r.lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("blocked DNS/53") }
	transport := r.client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	_, err := r.resolve(context.Background(), "private.example")
	if failureCode(t, err) != "dns_tls" || requests.Load() != 0 {
		t.Fatal("untrusted certificate accepted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	transport.TLSClientConfig.RootCAs = pool
	address, err := r.resolve(context.Background(), "private.example")
	if err != nil || address.String() != "203.0.113.10" || requests.Load() != 1 {
		t.Fatal(address, err)
	}
	_, err = r.resolve(context.Background(), "redirect.example")
	if failureCode(t, err) != "dns_invalid_response" || requests.Load() != 2 {
		t.Fatal("redirect followed")
	}
}
func TestDiagnosticsDoNotWaitForNetworkMutation(t *testing.T) {
	manager := New(Config{DryRun: true})
	manager.mu.Lock()
	done := make(chan struct{})
	go func() {
		view := manager.Diagnostics(context.Background()).(map[string]any)
		view["state"] = "tampered"
		_ = manager.Status()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		manager.mu.Unlock()
		t.Fatal("diagnostics blocked on network mutex")
	}
	manager.mu.Unlock()
	if manager.Diagnostics(context.Background()).(map[string]any)["state"] != "disconnected" {
		t.Fatal("caller mutated published diagnostics")
	}
	var stages []string
	manager.SetProgressHandler(func(status model.RuntimeStatus) {
		if manager.Status().Stage != status.Stage {
			t.Error("notification preceded atomic snapshot")
		}
		stages = append(stages, status.Stage)
	})
	manager.stage("resolving_endpoint", "Resolving VPN server address")
	manager.fail(bootstrapFailure("dns_timeout"))
	if len(stages) != 2 || manager.Status().FailureCode != "dns_timeout" || manager.Status().StageStartedAt == 0 {
		t.Fatal("progress or failure was not published")
	}
}

func TestBootstrapReverseRoutesRespectPause(t *testing.T) {
	for _, paused := range []bool{false, true} {
		manager := New(Config{DryRun: true})
		manager.r = &fakeRunner{s: fixture()}
		manager.endpoint = netip.MustParseAddr("203.0.113.7")
		manager.profile = &model.Profile{Port: 8443}
		manager.uplink, _ = fixture().Uplink()
		if err := manager.installRoutes(context.Background(), fixture(), nil, false, paused); err != nil {
			t.Fatal(err)
		}
		foundResolver, foundCore := false, false
		for _, command := range manager.commands {
			text := strings.Join(command.Args, " ")
			if strings.Contains(text, "uidrange 0-0 to 1.1.1.1") {
				foundResolver = true
			}
			if strings.Contains(text, "uidrange 0-0 to 203.0.113.7") {
				foundCore = true
			}
		}
		if paused && (foundResolver || foundCore) {
			t.Fatal("VLESS changed root transport routing while an external VPN owns Internet")
		}
		if !paused && (!foundResolver || !foundCore) {
			t.Fatal("missing narrow reverse-path routes")
		}
	}
}
func TestCanceledMutationDoesNotReplaceFailure(t *testing.T) {
	manager := New(Config{DryRun: true})
	manager.fail(bootstrapFailure("dns_tls"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager.operationContext = ctx
	if err := manager.fail(errors.New("command failed due to canceled context")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if manager.Status().FailureCode != "dns_tls" {
		t.Fatal("cancellation replaced the original failure")
	}
}
