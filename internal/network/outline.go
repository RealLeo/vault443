package network

import (
	"context"
	"fmt"
	"os"
	"strings"

	"vault443/internal/core"
)

func (m *Manager) mainEndpoints() []Endpoint {
	if len(m.endpoints) > 0 {
		return m.endpoints
	}
	if m.profile == nil || !m.endpoint.IsValid() {
		return nil
	}
	return []Endpoint{{Address: m.endpoint.String(), Port: m.profile.Port, Protocol: "tcp"}, {Address: m.endpoint.String(), Port: m.profile.Port, Protocol: "udp"}}
}

// A separate table gates loopback before ordinary loopback accepts. UDP SOCKS
// frames have no password field, so require a privileged session mark as well
// as an authenticated TCP association. Scope to our inherited cgroup where
// cgroup v2 is available; containers with a namespace root still require mark
// and root socket ownership. No user or container gets a direct adapter path.
func (m *Manager) protectOutline(ctx context.Context) error {
	cgroup := ""
	if data, e := os.ReadFile("/proc/self/cgroup"); e == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "0::/") {
				cgroup = strings.TrimPrefix(line, "0::/")
			}
		}
	}
	return m.execute(ctx, command{Path: "/usr/sbin/nft", Args: []string{"-f", "-"}, Input: outlineGuard(m.outline.Port, cgroup)})
}
func outlineGuard(port int, cgroup string) string {
	// `add table` is idempotent; flush replaces only this application's gate.
	s := "add table inet vault443_outline\nflush table inet vault443_outline\n"
	s += "table inet vault443_outline { chain adapter { type filter hook output priority filter - 20; policy accept;\n"
	scope := ""
	if cgroup != "" {
		scope = fmt.Sprintf("socket cgroupv2 level %d %s ", strings.Count(cgroup, "/")+1, nftQuote(cgroup))
	}
	for _, proto := range []string{"tcp", "udp"} {
		s += fmt.Sprintf("ip daddr 127.0.0.1 %s dport %d meta skuid 0 meta mark 0x%x %saccept\n", proto, port, core.OutlineMark, scope)
		s += fmt.Sprintf("ip daddr 127.0.0.1 %s dport %d drop\n", proto, port)
	}
	return s + "}\n}\n"
}
