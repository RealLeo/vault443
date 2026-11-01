package profiles

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	app "vault443"
)

func SubscriptionURL(raw string) (*url.URL, error) {
	if len(raw) > 8192 {
		return nil, errors.New("subscription URL is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !ValidHost(u.Hostname()) || u.User != nil || u.Fragment != "" {
		return nil, errors.New("subscription requires an HTTPS URL without user info or fragment")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !publicIP(ip) {
		return nil, errors.New("subscription address must be publicly routable")
	}
	if strings.EqualFold(u.Hostname(), "localhost") || strings.HasSuffix(strings.ToLower(u.Hostname()), ".localhost") {
		return nil, errors.New("subscription address must be publicly routable")
	}
	return u, nil
}

func PublicIP(ip net.IP) bool { return publicIP(ip) }
func publicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	// CGNAT and documentation/benchmark ranges are not remote subscriptions.
	for _, cidr := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/23", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16"} {
		_, n, _ := net.ParseCIDR(cidr)
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// FetchSubscription never follows a redirect to a local endpoint. DNS is resolved
// inside DialContext and the selected public IP is dialled directly (no rebind gap).
func FetchSubscription(ctx context.Context, raw string) (string, error) {
	return FetchDocument(ctx, raw, nil)
}

// FetchDocument lets the supervisor supply a pinned, protected dialer. Callers
// must reject non-public destinations and prevent DNS rebinding.
func FetchDocument(ctx context.Context, raw string, dial func(context.Context, string, string) (net.Conn, error)) (string, error) {
	u, err := SubscriptionURL(raw)
	if err != nil {
		return "", err
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32 << 10}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid subscription endpoint")
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, errors.New("subscription DNS lookup failed")
		}
		if len(ips) == 0 {
			return nil, errors.New("subscription DNS returned no addresses")
		}
		for _, ip := range ips {
			if !publicIP(ip.IP) {
				return nil, errors.New("subscription resolved to a non-public address")
			}
		}
		var last error
		for _, ip := range ips {
			c, e := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if e == nil {
				return c, nil
			}
			last = e
		}
		_ = last
		return nil, errors.New("subscription endpoint unavailable")
	}
	if dial != nil {
		tr.DialContext = dial
	}
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many subscription redirects")
		}
		_, e := SubscriptionURL(req.URL.String())
		return e
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", errors.New("invalid subscription request")
	}
	req.Header.Set("User-Agent", "Vault443/"+app.Version())
	res, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("configuration download failed (HTTPS, DNS, or timeout)")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusGone || res.StatusCode == http.StatusForbidden {
		return "", &ProviderError{Message: "source access is expired or denied"}
	}
	if res.StatusCode != http.StatusOK {
		return "", errors.New("subscription server returned an unsuccessful response")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, MaxBytes+1))
	if err != nil {
		return "", errors.New("subscription download was interrupted")
	}
	if len(data) > MaxBytes {
		return "", errors.New("subscription exceeds 1 MiB")
	}
	return string(data), nil
}
