package network

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"vault443/internal/model"
)

func TestIPv6PolicyScopesProbeAndFastFailure(t *testing.T) {
	for _, state := range []string{"inactive", "checking", "available", "unavailable"} {
		for _, ready := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ready=%v", state, ready), func(t *testing.T) {
				m := New(Config{DryRun: true})
				m.r = &fakeRunner{s: fixture()}
				m.ipv6State = state
				m.protected = []protectedRoute{{"fd20::/64", "corp0"}}
				x := []external{{Link: Link{Name: "corp0"}, Active: true, Full6: true}}
				if err := m.applyGuard(context.Background(), fixture(), x, ready); err != nil {
					t.Fatal(err)
				}
				script := m.commands[len(m.commands)-1].Input
				chains := strings.Split(script, "policy drop;")[1:]
				for i, chain := range chains {
					reject := strings.Index(chain, `comment "vlt-ipv6-unavailable"`)
					wantBlock := ready && state != "available"
					if (reject >= 0) != wantBlock {
						t.Fatalf("IPv6 reject present=%v want=%v", reject >= 0, wantBlock)
					}
					if wantBlock {
						corporate := strings.Index(chain, "ip6 daddr fd20::/64 drop")
						accept := strings.Index(chain, `oifname "vault4430" accept`)
						tcpReset := strings.Index(chain, `meta l4proto tcp counter reject with tcp reset`)
						if corporate < 0 || tcpReset <= corporate || reject <= tcpReset || accept <= reject {
							t.Fatal("IPv6 rejection must respect corporate routes and precede TUN acceptance")
						}
					}
					probe := strings.Index(chain, `comment "vlt-ipv6-probe"`)
					if (probe >= 0) != (i == 0 && ready && state == "checking") {
						t.Fatal("IPv6 probe permission leaked outside OUTPUT verification")
					}
					if probe >= 0 && (!strings.Contains(chain, `meta skuid 0 meta mark 0x564c5403 meta nfproto ipv6 oifname "vault4430" tcp dport 443 accept`) || probe >= reject) {
						t.Fatal("probe permission is not restricted to privileged marked HTTPS inside TUN")
					}
					if !strings.Contains(chain, `oifname "corp0" meta nfproto ipv6 accept`) || !strings.Contains(chain, `ip daddr 172.18.0.0/16 oifname "docker0" accept`) {
						t.Fatal("external VPN or local Docker route was lost")
					}
				}
			})
		}
	}
}

func TestIPv6AvailabilityUpdatesAreAtomicAndCancelable(t *testing.T) {
	m := New(Config{DryRun: true})
	f := &fakeRunner{s: fixture()}
	m.r = f
	m.status.State = "connected"
	m.ipv6State = "checking"
	for _, available := range []bool{true, false} {
		if err := m.finishIPv6Check(context.Background(), fixture(), nil, available); err != nil {
			t.Fatal(err)
		}
		diagnostic := m.Diagnostics(context.Background()).(map[string]any)
		want := "unavailable"
		if available {
			want = "available"
		}
		if diagnostic["ipv6State"] != want || diagnostic["ipv6Message"] == "" || m.Status().State != "connected" {
			t.Fatalf("availability must not disconnect working IPv4: %v", diagnostic)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := len(m.commands)
	if err := m.finishIPv6Check(ctx, fixture(), nil, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification accepted: %v", err)
	}
	if len(m.commands) != before || m.ipv6State != "unavailable" {
		t.Fatal("late successful IPv6 result reopened canceled connection")
	}
	// A failed nft transaction must not advertise an enabled path.
	m.config.DryRun = false
	f.failMutation = true
	if err := m.finishIPv6Check(context.Background(), fixture(), nil, true); err == nil {
		t.Fatal("expected firewall transaction failure")
	}
	if m.ipv6State != "unavailable" || m.Diagnostics(context.Background()).(map[string]any)["ipv6State"] != "unavailable" {
		t.Fatal("failed firewall transaction published IPv6 availability")
	}
}

func TestIPv6AvailabilityIsSessionScoped(t *testing.T) {
	m := New(Config{StateDir: t.TempDir(), DryRun: true})
	m.r = &fakeRunner{s: fixture()}
	m.bindings = []Binding{{Interface: "corp0", Manager: "openvpn"}}
	m.ipv6State = "available"
	profile := model.Profile{ID: "test", Server: "example.com", Port: 443, UUID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Transport: "tcp", Security: "tls"}
	if err := m.Connect(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	if m.ipv6State != "inactive" {
		t.Fatal("dry run inherited a prior session's IPv6 success")
	}
	m.ipv6State = "available"
	if err := m.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Diagnostics(context.Background()).(map[string]any)["ipv6State"] != "inactive" {
		t.Fatal("disconnect left stale IPv6 availability")
	}
}

func TestIPv6ProbeMarkCannotBeUsedByExternalVPN(t *testing.T) {
	text := fmt.Sprintf(`{"interface":"wg0","manager":"wg-quick","endpoints":[{"address":"203.0.113.2","port":51820,"protocol":"udp","mark":%d}]}`, IPv6ProbeMark)
	if _, err := ParseBinding(text); err == nil {
		t.Fatal("external VPN may collide with private IPv6 verification mark")
	}
	// Automatic WireGuard metadata reaches detection without JSON parsing.
	binding := Binding{Interface: "wg0", Manager: "wg-quick", Endpoints: []Endpoint{{Address: "203.0.113.2", Port: 51820, Protocol: "udp", Mark: IPv6ProbeMark}}}
	if _, err := detectExternal(context.Background(), &fakeRunner{}, fixture(), []Binding{binding}); err == nil {
		t.Fatal("automatic WireGuard discovery accepted private IPv6 verification mark")
	}
}
