package network

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
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

// Bind all health sockets to TUN. Only the IPv6 capability probe carries its
// dedicated mark, which never allows a physical-interface bypass.
func tunnelHealthDialer(ipv6Probe bool) *net.Dialer {
	return &net.Dialer{Timeout: 2 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if e := raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, TunName)
			if err == nil && ipv6Probe {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(IPv6ProbeMark))
			}
		}); e != nil {
			return e
		}
		return err
	}}
}

func (m *Manager) tunnelHealthResolver() *net.Resolver {
	dialer := tunnelHealthDialer(false)
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort(m.v4.Addr().Next().String(), "53"))
	}}
}

// DNS through Xray's internal DoH client does not exercise application TCP
// entering TUN. Require a verified TLS + HTTP response on a fresh host socket,
// without a proxy, privileged socket mark, redirects or a physical bypass.
func (m *Manager) health(ctx context.Context) error {
	dialer, resolver := tunnelHealthDialer(false), m.tunnelHealthResolver()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var best error
	// Independent providers avoid treating one unavailable check URL as a
	// broken tunnel. Both must fail before the connection is rejected.
	for _, host := range []string{"cp.cloudflare.com", "www.gstatic.com"} {
		attempt, stop := context.WithTimeout(ctx, 4*time.Second)
		err := checkHTTPS(attempt, host, resolver.LookupNetIP, dialer.DialContext, nil)
		stop()
		if err == nil {
			m.logSession.Log("info", "Verified DNS and HTTPS through the VPN tunnel")
			return nil
		}
		if ctx.Err() == context.Canceled {
			return context.Canceled
		}
		// Retain evidence that DNS worked even if the second resolver query
		// times out. Never replace a concrete TLS error with a generic timeout.
		if best == nil || healthPriority(err) > healthPriority(best) {
			best = err
		}
	}
	return best
}

// A userspace TUN can accept a TCP SYN before the exit server attempts the
// destination connection. Thus Happy Eyeballs can pick an unusable IPv6 path
// and fail later in TLS without trying IPv4. Keep ordinary IPv6 rejected until
// real IPv6 HTTPS succeeds; only these marked probes may enter TUN meanwhile.
func (m *Manager) checkIPv6(ctx context.Context) (bool, error) {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	dialer, resolver := tunnelHealthDialer(true), m.tunnelHealthResolver()
	for _, host := range []string{"cp.cloudflare.com", "www.gstatic.com"} {
		attempt, stop := context.WithTimeout(ctx, 2*time.Second)
		err := checkHTTPSFamily(attempt, "ip6", host, resolver.LookupNetIP, dialer.DialContext, nil)
		stop()
		if parent.Err() != nil {
			return false, parent.Err()
		}
		if err == nil {
			return true, nil
		}
	}
	return false, nil
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
