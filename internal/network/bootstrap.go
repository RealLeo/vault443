package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

const (
	bootstrapDNSTimeout   = 2 * time.Second
	bootstrapTotalTimeout = 8 * time.Second
	bootstrapDoHHost      = "cloudflare-dns.com"
	bootstrapDoHAddress   = "1.1.1.1:443"
)

// Error messages deliberately omit endpoint names, response bodies and URLs.
// The UI may safely expose the reason without exposing another profile's data.
type bootstrapError struct{ code, message string }

func (e *bootstrapError) Error() string { return e.message }
func bootstrapFailure(code string) error {
	messages := map[string]string{
		"dns_timeout":          "VPN server DNS lookup timed out; DNS and HTTPS fallback did not complete",
		"dns_no_answer":        "DNS returned no IPv4 address for the VPN server",
		"dns_not_found":        "VPN server DNS name does not exist",
		"dns_tls":              "DNS HTTPS fallback certificate or TLS verification failed",
		"dns_transport":        "VPN server DNS lookup failed; protected DNS and HTTPS fallback are unavailable",
		"dns_invalid_response": "DNS HTTPS fallback returned an invalid response",
	}
	return &bootstrapError{code: code, message: messages[code]}
}

type bootstrapResolver struct {
	lookup                   func(context.Context, string) ([]netip.Addr, error)
	client                   *http.Client
	close                    func()
	dnsTimeout, totalTimeout time.Duration
}

func bootstrapDialer() *net.Dialer {
	return &net.Dialer{Timeout: bootstrapDNSTimeout, Control: func(_, _ string, raw syscall.RawConn) error {
		var markErr error
		if err := raw.Control(func(fd uintptr) {
			markErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(BootstrapMark))
		}); err != nil {
			return err
		}
		return markErr
	}}
}

// Fixed-IP dialing prevents bootstrap recursion and pins the narrow firewall
// exception. TLS still authenticates the public resolver's DNS name. A fresh
// transport is scoped to one attempt; neither an environment proxy nor a
// redirect can send a privileged, marked request to another destination.
func newBootstrapResolver(dialer *net.Dialer) *bootstrapResolver {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, "1.1.1.1:53")
	}}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", bootstrapDoHAddress)
		},
		TLSClientConfig:        &tls.Config{ServerName: bootstrapDoHHost, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    bootstrapDNSTimeout,
		ResponseHeaderTimeout:  bootstrapTotalTimeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &bootstrapResolver{
		lookup: func(ctx context.Context, server string) ([]netip.Addr, error) {
			return resolver.LookupNetIP(ctx, "ip4", server)
		},
		client:     &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		close:      transport.CloseIdleConnections,
		dnsTimeout: bootstrapDNSTimeout, totalTimeout: bootstrapTotalTimeout,
	}
}

func (m *Manager) resolveEndpoint(ctx context.Context, server string) (netip.Addr, error) {
	resolver := newBootstrapResolver(bootstrapDialer())
	defer resolver.close()
	return resolver.resolve(ctx, server)
}

func (r *bootstrapResolver) resolve(ctx context.Context, server string) (netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	if address, err := netip.ParseAddr(server); err == nil {
		return address, nil
	}
	total, cancel := context.WithTimeout(ctx, r.totalTimeout)
	defer cancel()
	dnsCtx, dnsCancel := context.WithTimeout(total, r.dnsTimeout)
	addresses, err := r.lookup(dnsCtx, server)
	dnsCancel()
	if ctx.Err() != nil {
		return netip.Addr{}, ctx.Err()
	}
	if err == nil {
		for _, address := range addresses {
			if address.Unmap().Is4() {
				return address.Unmap(), nil
			}
		}
		return netip.Addr{}, bootstrapFailure("dns_no_answer")
	}
	// Go's resolver folds both NXDOMAIN and an existing name without an A
	// record into DNSError.IsNotFound. Confirm ambiguous negative answers via
	// HTTPS as well, so the UI never labels NODATA as a nonexistent server.
	var dnsErr *net.DNSError
	negative := errors.As(err, &dnsErr) && dnsErr.IsNotFound
	if total.Err() != nil {
		if negative {
			return netip.Addr{}, bootstrapFailure("dns_no_answer")
		}
		return netip.Addr{}, bootstrapFailure("dns_timeout")
	}
	address, httpsErr := r.lookupHTTPS(total, server)
	if negative && httpsErr != nil && !errors.Is(httpsErr, context.Canceled) {
		var failure *bootstrapError
		if !errors.As(httpsErr, &failure) || (failure.code != "dns_not_found" && failure.code != "dns_no_answer") {
			// Preserve the known negative DNS result if confirmation fails;
			// it proves no usable IPv4 answer, not whether the name exists.
			return netip.Addr{}, bootstrapFailure("dns_no_answer")
		}
	}
	return address, httpsErr
}

func (r *bootstrapResolver) lookupHTTPS(ctx context.Context, server string) (netip.Addr, error) {
	query := url.Values{"name": {server}, "type": {"A"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+bootstrapDoHHost+"/dns-query?"+query.Encode(), nil)
	if err != nil {
		return netip.Addr{}, bootstrapFailure("dns_invalid_response")
	}
	req.Header.Set("Accept", "application/dns-json")
	response, err := r.client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return netip.Addr{}, context.Canceled
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return netip.Addr{}, bootstrapFailure("dns_timeout")
		}
		var certificate *tls.CertificateVerificationError
		var invalidCertificate x509.CertificateInvalidError
		var unknownAuthority x509.UnknownAuthorityError
		var hostname x509.HostnameError
		var record tls.RecordHeaderError
		if errors.As(err, &certificate) || errors.As(err, &invalidCertificate) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &record) || strings.Contains(err.Error(), "tls:") {
			return netip.Addr{}, bootstrapFailure("dns_tls")
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return netip.Addr{}, bootstrapFailure("dns_timeout")
		}
		return netip.Addr{}, bootstrapFailure("dns_transport")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, bootstrapFailure("dns_invalid_response")
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if mediaType != "application/dns-json" && mediaType != "application/json" {
		return netip.Addr{}, bootstrapFailure("dns_invalid_response")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if errors.Is(ctx.Err(), context.Canceled) {
		return netip.Addr{}, context.Canceled
	}
	if ctx.Err() != nil {
		return netip.Addr{}, bootstrapFailure("dns_timeout")
	}
	if err != nil || len(data) > 64<<10 {
		return netip.Addr{}, bootstrapFailure("dns_invalid_response")
	}
	return parseBootstrapAnswer(data, server)
}

func dnsName(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }
func parseBootstrapAnswer(data []byte, server string) (netip.Addr, error) {
	var answer struct {
		Status   *int
		TC       bool
		Question []struct {
			Name string
			Type int
		}
		Answer []struct {
			Name string
			Type int
			Data string
		}
	}
	if json.Unmarshal(data, &answer) != nil || answer.Status == nil || answer.TC || len(answer.Question) != 1 || answer.Question[0].Type != 1 || dnsName(answer.Question[0].Name) != dnsName(server) {
		return netip.Addr{}, bootstrapFailure("dns_invalid_response")
	}
	switch *answer.Status {
	case 3:
		return netip.Addr{}, bootstrapFailure("dns_not_found")
	case 0:
	default:
		return netip.Addr{}, bootstrapFailure("dns_no_answer")
	}
	// Accept only records for the requested name or a bounded chain of its
	// CNAMEs, never an unrelated address in the same JSON response.
	current := dnsName(server)
	seen := map[string]bool{}
	for hops := 0; hops < 16; hops++ {
		if seen[current] {
			return netip.Addr{}, bootstrapFailure("dns_invalid_response")
		}
		seen[current] = true
		next := ""
		for _, record := range answer.Answer {
			if dnsName(record.Name) != current {
				continue
			}
			if record.Type == 1 {
				address, err := netip.ParseAddr(record.Data)
				if err == nil && address.Is4() {
					return address, nil
				}
				return netip.Addr{}, bootstrapFailure("dns_invalid_response")
			}
			if record.Type == 5 {
				next = dnsName(record.Data)
			}
		}
		if next == "" {
			return netip.Addr{}, bootstrapFailure("dns_no_answer")
		}
		current = next
	}
	return netip.Addr{}, bootstrapFailure("dns_invalid_response")
}
