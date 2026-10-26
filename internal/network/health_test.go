package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"vault443/internal/journal"
)

func TestHTTPSHealthRequiresVerifiedTLSAndExpectedResponse(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	for _, tc := range []struct {
		name, host, want string
		status           int
	}{
		{"success", "example.com", "", 204},
		{"portal", "example.com", "vpn_https_response", 200},
		{"redirect", "example.com", "vpn_https_response", 302},
		{"certificate", "not-in-certificate.example", "vpn_https_tls", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/generate_204" || r.Host != tc.host || r.TLS.ServerName != tc.host {
					t.Error("HTTPS probe lost its target or SNI")
				}
				w.Header().Set("Location", "https://must-not-be-requested.invalid/")
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			roots := x509.NewCertPool()
			roots.AddCert(srv.Certificate())
			lookup := func(_ context.Context, family, host string) ([]netip.Addr, error) {
				if family != "ip4" || host != tc.host {
					t.Error("unexpected DNS lookup")
				}
				return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
			}
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp4" || address != "93.184.215.14:443" {
					t.Error("probe escaped DNS address or used proxy")
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
			}
			err := checkHTTPS(context.Background(), tc.host, lookup, dial, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var failure *healthError
				if !errors.As(err, &failure) || failure.code != tc.want {
					t.Fatalf("got %v, want %s", err, tc.want)
				}
			}
			if calls.Load() > 1 {
				t.Fatal("redirect followed")
			}
		})
	}
}

func TestHTTPSHealthCancellationAndFailurePersistence(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		if cancelEarly {
			cancel()
		}
		lookup := func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
		}
		dial := func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
		start := time.Now()
		err := checkHTTPS(ctx, "example.com", lookup, dial, nil)
		cancel()
		if time.Since(start) > time.Second {
			t.Fatal("probe did not honor cancellation")
		}
		if cancelEarly {
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		} else {
			var failure *healthError
			if !errors.As(err, &failure) || failure.code != "vpn_https_timeout" {
				t.Fatal(err)
			}
			manager := New(Config{DryRun: true})
			_ = manager.fail(err)
			if manager.Status().FailureCode != failure.code || journal.NormalizeFailureCode(failure.code) != failure.code {
				t.Fatal("HTTPS failure lost between runtime and persistent history")
			}
		}
	}
}

func TestHTTPSIPv6ProbeDoesNotFallBackToIPv4(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "example.com" {
			t.Error("lost certificate hostname")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	var calls atomic.Int32
	lookup := func(_ context.Context, family, host string) ([]netip.Addr, error) {
		if family != "ip6" || host != "example.com" {
			t.Error("IPv6 probe used an IPv4/mixed lookup")
		}
		return []netip.Addr{netip.MustParseAddr("2001:db8:66::14")}, nil
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		if network != "tcp6" || address != "[2001:db8:66::14]:443" {
			t.Error("IPv6 probe fell back to IPv4")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}
	if err := checkHTTPSFamily(context.Background(), "ip6", "example.com", lookup, dial, &tls.Config{RootCAs: roots}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("unexpected probe request count")
	}
	// A closed IPv6 stream must fail the check even if the host also has A
	// records; only a separate IPv4 health check is allowed to use them.
	dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("IPv6 unavailable") }
	if err := checkHTTPSFamily(context.Background(), "ip6", "example.com", lookup, dial, nil); err == nil {
		t.Fatal("unavailable IPv6 incorrectly confirmed")
	}
}
