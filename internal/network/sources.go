package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"vault443/internal/core"
	"vault443/internal/profiles"
)

const sourceTable = 52789
const sourcePriority = 5098

type sourcePermit struct {
	address netip.Addr
	port    int
	uplink  Route
	expires time.Time
}

var sourcePermits = map[uint64]sourcePermit{} // accessed only inside WithKernel
var sourceSequence atomic.Uint64
var sourceFetchSlot = make(chan struct{}, 1)

// FetchSource never takes the main connection mutex. Only short kernel
// transactions share the coordinator with work VPNs. Network I/O is cancellable.
func (m *Manager) FetchSource(ctx context.Context, raw string) (string, error) {
	if _, e := profiles.SubscriptionURL(raw); e != nil {
		return "", e
	}
	if m.config.DryRun {
		return "", errors.New("source downloads are disabled in dry-run mode")
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	select {
	case sourceFetchSlot <- struct{}{}:
		defer func() { <-sourceFetchSlot }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	bootstrapID := sourceSequence.Add(1)
	err := WithKernel(ctx, func(k Kernel) error {
		s, e := k.Collect(ctx)
		if e != nil {
			return e
		}
		u, e := s.Uplink()
		if e != nil {
			return e
		}
		sourcePermits[bootstrapID] = sourcePermit{address: netip.MustParseAddr("1.1.1.1"), uplink: u, expires: time.Now().Add(30 * time.Second)}
		return syncSourcePermits(ctx, k)
	})
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = WithKernel(clean, func(k Kernel) error { delete(sourcePermits, bootstrapID); return syncSourcePermits(clean, k) })
	}()
	if err != nil {
		return "", errors.New("cannot prepare source DNS route")
	}
	return profiles.FetchDocument(ctx, raw, func(c context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, errors.New("invalid source endpoint")
		}
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid source HTTPS port")
		}
		a, e := ResolveWorkEndpoint(c, host)
		if e != nil {
			return nil, e
		}
		if !profiles.PublicIP(net.IP(a.AsSlice())) {
			return nil, errors.New("source resolved to a non-public address")
		}
		id := sourceSequence.Add(1)
		e = WithKernel(c, func(k Kernel) error {
			s, err := k.Collect(c)
			if err != nil {
				return err
			}
			u, err := s.Uplink()
			if err != nil {
				return err
			}
			if a.Is6() {
				found := false
				for _, route := range s.Routes {
					prefix, ok := route.Prefix()
					if ok && route.Family == 6 && prefix.Bits() == 0 && route.Device == u.Device && !route.owned() {
						u.Gateway = route.Gateway
						found = true
						break
					}
				}
				if !found {
					return errors.New("no physical IPv6 route to source")
				}
			}
			sourcePermits[id] = sourcePermit{a, n, u, time.Now().Add(30 * time.Second)}
			if err = syncSourcePermits(c, k); err != nil {
				delete(sourcePermits, id)
				return err
			}
			return nil
		})
		if e != nil {
			return nil, errors.New("cannot prepare protected source download")
		}
		cleanup := func() {
			clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = WithKernel(clean, func(k Kernel) error { delete(sourcePermits, id); return syncSourcePermits(clean, k) })
		}
		var permit sourcePermit
		_ = WithKernel(c, func(Kernel) error { permit = sourcePermits[id]; return nil })
		dialer := &net.Dialer{Timeout: 8 * time.Second, Control: func(_, _ string, r syscall.RawConn) error {
			var err error
			e := r.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(BootstrapMark))
				if err == nil {
					err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, permit.uplink.Device)
				}
			})
			if e != nil {
				return e
			}
			return err
		}}
		conn, e := dialer.DialContext(c, network, net.JoinHostPort(a.String(), port))
		if e != nil {
			cleanup()
			return nil, errors.New("source HTTPS endpoint unavailable")
		}
		return &sourceConn{Conn: conn, cleanup: cleanup}, nil
	})
}

type sourceConn struct {
	net.Conn
	once    sync.Once
	cleanup func()
}

func (c *sourceConn) Close() error { e := c.Conn.Close(); c.once.Do(c.cleanup); return e }

func SourceGuardDeclarations() string {
	return "set source4 { type ipv4_addr . inet_service; flags timeout; }\nset source6 { type ipv6_addr . inet_service; flags timeout; }\nchain source_download {\n# vault443-source-rules\n}\n"
}

func sourceRules() string {
	// Restrict both the UID and mark. FORWARD has no jump to this chain.
	var b strings.Builder
	seen := map[string]bool{}
	for _, p := range sourcePermits {
		if !core.SafeInterface(p.uplink.Device) || seen[p.uplink.Device] {
			continue
		}
		seen[p.uplink.Device] = true
		for _, f := range []string{"4", "6"} {
			family := "ip"
			if f == "6" {
				family = "ip6"
			}
			fmt.Fprintf(&b, "meta skuid 0 meta mark 0x%x %s daddr . tcp dport @source%s oifname %s accept\n", BootstrapMark, family, f, nftQuote(p.uplink.Device))
		}
	}
	return b.String()
}
func sourceElements(prefix string) string {
	var b strings.Builder
	seen := map[string]bool{}
	for _, p := range sourcePermits {
		if p.port == 0 {
			continue
		}
		ttl := int(time.Until(p.expires).Seconds())
		if ttl < 1 {
			continue
		}
		f := "6"
		if p.address.Is4() {
			f = "4"
		}
		key := p.address.String() + ":" + strconv.Itoa(p.port)
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Fprintf(&b, "%s source%s { %s . %d timeout %ds }\n", prefix, f, p.address, p.port, ttl)
	}
	return b.String()
}
func syncSourcePermits(ctx context.Context, k Kernel) error {
	// Clear only the dedicated download routing table and its two priorities.
	// Replies need the UID/port route because rp_filter does not use SO_MARK.
	snapshot, err := k.Collect(ctx)
	if err != nil {
		return err
	}
	for _, route := range snapshot.Routes {
		if string(route.Table) == strconv.Itoa(sourceTable) && string(route.Protocol) != "186" {
			return errors.New("source routing table belongs to another service")
		}
	}
	for _, family := range []struct {
		number int
		rules  []map[string]any
	}{{4, snapshot.Rules4}, {6, snapshot.Rules6}} {
		for _, rule := range family.rules {
			priority, _ := rule["priority"].(float64)
			if priority != sourcePriority && priority != sourcePriority+1 {
				continue
			}
			if fmt.Sprint(rule["table"]) != strconv.Itoa(sourceTable) {
				return errors.New("source routing priority belongs to another service")
			}
			if _, e := k.Run(ctx, "/usr/sbin/ip", []string{fmt.Sprint("-", family.number), "rule", "del", "priority", strconv.Itoa(int(priority)), "lookup", strconv.Itoa(sourceTable)}, ""); e != nil {
				return e
			}
		}
		if snapshot.HasTable(family.number, sourceTable) {
			if _, e := k.Run(ctx, "/usr/sbin/ip", []string{fmt.Sprint("-", family.number), "route", "flush", "table", strconv.Itoa(sourceTable)}, ""); e != nil {
				return e
			}
		}
	}

	// One bounded request at a time, with normally one connection; redirects may
	// briefly overlap. Deduplicate identical address/port rules.
	seen := map[string]bool{}
	for _, p := range sourcePermits {
		key := fmt.Sprint(p.address, p.port)
		if seen[key] {
			continue
		}
		seen[key] = true
		f, bits := 4, 32
		if p.address.Is6() {
			f, bits = 6, 128
		}
		route := []string{fmt.Sprint("-", f), "route", "replace", p.address.String() + "/" + strconv.Itoa(bits), "table", strconv.Itoa(sourceTable), "proto", "186"}
		if p.uplink.Gateway != "" {
			route = append(route, "via", p.uplink.Gateway, "onlink")
		}

		route = append(route, "dev", p.uplink.Device)
		if _, e := k.Run(ctx, "/usr/sbin/ip", route, ""); e != nil {
			return e
		}
		for _, mark := range []bool{true, false} {
			pri := sourcePriority
			if !mark {
				pri++
			}
			rule := []string{fmt.Sprint("-", f), "rule", "add", "priority", strconv.Itoa(pri), "uidrange", "0-0", "to", p.address.String(), "ipproto", "tcp", "dport", strconv.Itoa(p.port), "lookup", strconv.Itoa(sourceTable)}
			if p.port == 0 {
				rule = []string{fmt.Sprint("-", f), "rule", "add", "priority", strconv.Itoa(pri), "uidrange", "0-0", "to", p.address.String(), "lookup", strconv.Itoa(sourceTable)}
			}
			if mark {
				rule = append(rule, "fwmark", fmt.Sprintf("0x%x", BootstrapMark))
			}
			if _, e := k.Run(ctx, "/usr/sbin/ip", rule, ""); e != nil {
				return e
			}
		}
	}
	for _, table := range []string{TableName, "vault443_work"} {
		if _, e := k.Run(ctx, "/usr/sbin/nft", []string{"list", "set", "inet", table, "source4"}, ""); e != nil {
			continue
		}
		script := "flush set inet " + table + " source4\nflush set inet " + table + " source6\nflush chain inet " + table + " source_download\n"
		script += sourceElements("add element inet " + table)
		for _, line := range strings.Split(strings.TrimSpace(sourceRules()), "\n") {
			if line != "" {
				script += "add rule inet " + table + " source_download " + line + "\n"
			}
		}
		if _, e := k.Run(ctx, "/usr/sbin/nft", []string{"-f", "-"}, script); e != nil {
			return e
		}
	}
	return nil
}

// ResetSourceDownloads is called before accepting clients, while holding the
// exclusive store lock. It expires temporary privileges left by a dead daemon.
func ResetSourceDownloads(ctx context.Context) error {
	return WithKernel(ctx, func(k Kernel) error {
		clear(sourcePermits)
		return syncSourcePermits(ctx, k)
	})
}
