package network

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"
)

type healthError struct{ code string }

func (e *healthError) Error() string {
	switch e.code {
	case "vpn_dns_failed":
		return "VPN DNS did not return an IPv4 address; Internet remains protected"
	case "vpn_https_timeout":
		return "VPN DNS works, but HTTPS through the tunnel timed out; Internet remains protected"
	case "vpn_https_tls":
		return "VPN DNS works, but HTTPS certificate verification failed; Internet remains protected"
	case "vpn_https_response":
		return "VPN DNS works, but the HTTPS connectivity check returned an unexpected response; Internet remains protected"
	default:
		return "VPN DNS works, but HTTPS through the tunnel failed; Internet remains protected"
	}
}

func healthPriority(err error) int {
	var e *healthError
	if !errors.As(err, &e) {
		return 0
	}
	switch e.code {
	case "vpn_dns_failed":
		return 1
	case "vpn_https_timeout":
		return 2
	case "vpn_https_failed":
		return 3
	default:
		return 4
	}
}

func checkHTTPS(ctx context.Context, host string,
	lookup func(context.Context, string, string) ([]netip.Addr, error),
	dial func(context.Context, string, string) (net.Conn, error), tlsConfig *tls.Config,
) error {
	return checkHTTPSFamily(ctx, "ip4", host, lookup, dial, tlsConfig)
}

func checkHTTPSFamily(ctx context.Context, family, host string,
	lookup func(context.Context, string, string) ([]netip.Addr, error),
	dial func(context.Context, string, string) (net.Conn, error), tlsConfig *tls.Config,
) error {
	addresses, err := lookup(ctx, family, host)
	tcpNetwork := "tcp4"
	if family == "ip6" {
		tcpNetwork = "tcp6"
	}
	if err != nil || len(addresses) == 0 {
		if errors.Is(ctx.Err(), context.Canceled) {
			return context.Canceled
		}
		return &healthError{"vpn_dns_failed"}
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.ServerName = host
	tr := &http.Transport{
		Proxy: nil, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
		DisableKeepAlives: true, TLSHandshakeTimeout: 3 * time.Second,
		MaxResponseHeaderBytes: 8192,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var last error
			for i, ip := range addresses {
				if i >= 4 { // Bounded even for an unexpectedly large DNS answer.
					break
				}
				conn, err := dial(ctx, tcpNetwork, net.JoinHostPort(ip.String(), "443"))
				if err == nil {
					return conn, nil
				}
				last = err
				if ctx.Err() != nil {
					break
				}
			}
			return nil, last
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/generate_204", nil)
	if err != nil {
		return &healthError{"vpn_https_failed"}
	}
	res, err := client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return context.Canceled
		}
		var cert *tls.CertificateVerificationError
		if errors.As(err, &cert) {
			return &healthError{"vpn_https_tls"}
		}
		var timeout net.Error
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
			return &healthError{"vpn_https_timeout"}
		}
		return &healthError{"vpn_https_failed"}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		return &healthError{"vpn_https_response"}
	}
	return nil
}
