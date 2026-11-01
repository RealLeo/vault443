package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	TunName              = "vault4430"
	TableName            = "vault443"
	ProxyTable           = 52780
	BypassTable          = 52781
	UnderlayTable        = 52782
	RuleBase             = 5270
	OuterMark     uint32 = 0x564c5401
	BootstrapMark uint32 = 0x564c5402
	// IPv6ProbeMark is valid only for root-owned HTTPS probes through TUN.
	// It deliberately has no policy-routing or physical-interface exception.
	IPv6ProbeMark uint32 = 0x564c5403
)

type command struct {
	Path  string   `json:"path"`
	Args  []string `json:"args"`
	Input string   `json:"-"`
}
type runner interface {
	Run(context.Context, command) ([]byte, error)
}
type execRunner struct{}

func (execRunner) Run(ctx context.Context, c command) ([]byte, error) {
	var out []byte
	var err error
	err = WithKernel(ctx, func(k Kernel) error { out, err = k.Run(ctx, c.Path, c.Args, c.Input); return err })
	return out, err
}
func runCommand(ctx context.Context, c command) ([]byte, error) {
	if c.Path == "/usr/sbin/ip" {
		isJSON, isRoute := false, false
		for _, a := range c.Args {
			isJSON = isJSON || a == "-j"
			isRoute = isRoute || a == "route" || a == "rule"
		}
		if isJSON && isRoute {
			c.Args = append([]string{"-N"}, c.Args...)
		}
	}

	child, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, c.Path, c.Args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	if c.Input != "" {
		cmd.Stdin = strings.NewReader(c.Input)
	}
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s operation failed", c.Path)
	} // stderr may contain secrets
	return output, nil
}

type Link struct {
	Index    int      `json:"ifindex"`
	Name     string   `json:"ifname"`
	Alias    string   `json:"ifalias,omitempty"`
	MTU      int      `json:"mtu"`
	Flags    []string `json:"flags"`
	Kind     string   `json:"-"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
	Addresses []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Family    string `json:"family"`
	} `json:"addr_info"`
}
type Route struct {
	Destination string          `json:"dst"`
	Gateway     string          `json:"gateway,omitempty"`
	Device      string          `json:"dev,omitempty"`
	Scope       string          `json:"scope,omitempty"`
	Type        string          `json:"type,omitempty"`
	Table       json.RawMessage `json:"table,omitempty"`
	Protocol    json.RawMessage `json:"protocol,omitempty"`
	Metric      int             `json:"metric,omitempty"`
	Family      int             `json:"-"`
	Nexthops    []Route         `json:"nexthops,omitempty"`
}

func (r Route) Prefix() (netip.Prefix, bool) {
	if r.Destination == "default" {
		if r.Family == 6 {
			return netip.MustParsePrefix("::/0"), true
		}
		return netip.MustParsePrefix("0.0.0.0/0"), true
	}
	p, e := netip.ParsePrefix(r.Destination)
	if e != nil {
		a, err := netip.ParseAddr(r.Destination)
		if err != nil {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return p.Masked(), true
}
func (r Route) owned() bool {
	t, _ := strconv.Atoi(string(r.Table))
	return t == sourceTable || (t >= 52783 && t <= 52787 || t >= 52800 && t <= 52832) || r.Device == TunName || string(r.Table) == strconv.Itoa(ProxyTable) || string(r.Table) == strconv.Itoa(BypassTable) || string(r.Table) == strconv.Itoa(UnderlayTable)
}

type Snapshot struct {
	Links          []Link
	Routes         []Route
	Rules4, Rules6 []map[string]any
}

func (s Snapshot) HasTable(family, table int) bool {
	for _, r := range s.Routes {
		if r.Family == family && string(r.Table) == strconv.Itoa(table) {
			return true
		}
	}
	return false
}

func (s Snapshot) Link(name string) (Link, bool) {
	for _, l := range s.Links {
		if l.Name == name {
			return l, true
		}
	}
	return Link{}, false
}
func (s Snapshot) Uplink() (Route, error) {
	var candidates []Route
	for _, r := range s.Routes {
		p, ok := r.Prefix()
		if !ok || p.Bits() != 0 || r.owned() || r.Type == "unreachable" {
			continue
		}
		l, ok := s.Link(r.Device)
		if !ok || isTunnel(l) || l.Name == "lo" || l.Kind == "bridge" {
			continue
		}
		if r.Family == 4 {
			candidates = append(candidates, r)
		}
	}
	if len(candidates) == 0 {
		return Route{}, errors.New("no physical IPv4 default route; waiting for network")
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Metric < candidates[j].Metric })
	return candidates[0], nil
}
func isTunnel(l Link) bool {
	return l.Kind == "tun" || l.Kind == "wireguard" || l.Kind == "tap" || strings.HasPrefix(l.Name, "tun") || strings.HasPrefix(l.Name, "wg")
}

func collect(ctx context.Context, r runner) (Snapshot, error) {
	var s Snapshot
	b, e := r.Run(ctx, command{Path: "/usr/sbin/ip", Args: []string{"-j", "-d", "address", "show"}})
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(b, &s.Links); e != nil {
		return s, errors.New("cannot parse network links")
	}
	for i := range s.Links {
		s.Links[i].Kind = s.Links[i].LinkInfo.Kind
	}
	for _, f := range []int{4, 6} {
		b, e = r.Run(ctx, command{Path: "/usr/sbin/ip", Args: []string{"-j", fmt.Sprint("-", f), "route", "show", "table", "all"}})
		if e != nil {
			return s, e
		}
		var routes []Route
		if e = json.Unmarshal(b, &routes); e != nil {
			return s, errors.New("cannot parse network routes")
		}
		for i := range routes {
			routes[i].Family = f
			routes[i].Table = normalizeNumber(routes[i].Table)
			routes[i].Protocol = normalizeNumber(routes[i].Protocol)
			if n, ok := map[string]string{"0": "global", "200": "site", "253": "link", "254": "host", "255": "nowhere"}[routes[i].Scope]; ok {
				routes[i].Scope = n
			}
			if n, ok := map[string]string{"1": "unicast", "2": "local", "3": "broadcast", "5": "multicast", "6": "blackhole", "7": "unreachable", "8": "prohibit", "9": "throw"}[routes[i].Type]; ok {
				routes[i].Type = n
			}
		}
		s.Routes = append(s.Routes, routes...)
		b, e = r.Run(ctx, command{Path: "/usr/sbin/ip", Args: []string{"-j", fmt.Sprint("-", f), "rule", "show"}})
		if e != nil {
			return s, e
		}
		var rules []map[string]any
		if e = json.Unmarshal(b, &rules); e != nil {
			return s, errors.New("cannot parse policy rules")
		}
		if f == 4 {
			s.Rules4 = rules
		} else {
			s.Rules6 = rules
		}
	}
	return s, nil
}

func ChooseSubnets(s Snapshot) (netip.Prefix, netip.Prefix, error) {
	var occupied []netip.Prefix
	for _, r := range CurrentManagedPolicy().Routes {
		if p, e := netip.ParsePrefix(r.CIDR); e == nil && p.Bits() > 0 {
			occupied = append(occupied, p)
		}
	}
	for _, r := range s.Routes {
		p, ok := r.Prefix()
		if ok && p.Bits() > 0 && !r.owned() {
			occupied = append(occupied, p)
		}
	}
	for _, l := range s.Links {
		if l.Name == TunName {
			continue
		}
		for _, a := range l.Addresses {
			ip, e := netip.ParseAddr(a.Local)
			if e == nil {
				occupied = append(occupied, netip.PrefixFrom(ip, a.PrefixLen).Masked())
			}
		}
	}
	free := func(p netip.Prefix) bool {
		for _, q := range occupied {
			if p.Overlaps(q) {
				return false
			}
		}
		return true
	}
	var v4, v6 netip.Prefix
	// Avoid generic Docker/RFC1918 assumptions. Check every candidate against all
	// tables, including connected routes and addresses not in the main table.
	for a := 18; a <= 19 && !v4.IsValid(); a++ {
		for b := 0; b < 256; b++ {
			p := netip.MustParsePrefix(fmt.Sprintf("198.%d.%d.0/30", a, b))
			if free(p) {
				v4 = netip.PrefixFrom(p.Addr().Next(), 30)
				break
			}
		}
	}
	for n := 0; n < 256; n++ {
		p := netip.MustParsePrefix(fmt.Sprintf("fd56:4c54:%x::/64", n))
		if free(p) {
			v6 = netip.PrefixFrom(p.Addr().Next(), 64)
			break
		}
	}
	if !v4.IsValid() || !v6.IsValid() {
		return v4, v6, errors.New("no collision-free TUN subnet available")
	}
	return v4, v6, nil
}

// iproute2 emits numeric table IDs as JSON strings on several supported
// releases even in numeric mode. Normalize before ownership and flush checks.
func normalizeNumber(raw json.RawMessage) json.RawMessage {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if n, e := strconv.ParseUint(s, 10, 32); e == nil {
			return json.RawMessage(strconv.FormatUint(n, 10))
		}
	}
	return raw
}
