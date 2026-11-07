//go:build linux

package network

import (
	"context"
	"net"
	"syscall"
	"time"
)

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
