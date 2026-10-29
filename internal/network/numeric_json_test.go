package network

import (
	"context"
	"strings"
	"testing"
)

type numericJSONRunner struct{}

func (numericJSONRunner) Run(_ context.Context, c command) ([]byte, error) {
	s := strings.Join(c.Args, " ")
	switch {
	case strings.Contains(s, "address show"):
		return []byte(`[{"ifname":"eth0","linkinfo":{"info_kind":"ether"}},{"ifname":"docker0","linkinfo":{"info_kind":"bridge"}}]`), nil
	case strings.Contains(s, "-4 route"):
		return []byte(`[{"dst":"192.168.96.0/20","dev":"docker0","protocol":"2","scope":"253"},{"dst":"default","table":"52783","gateway":"192.0.2.1","dev":"eth0","protocol":"187"},{"dst":"192.168.0.0/16","table":"52785","type":"7","protocol":"187"},{"dst":"default","gateway":"192.0.2.2","dev":"eth0","protocol":"16"}]`), nil
	default:
		return []byte(`[]`), nil
	}
}
func TestIPRouteNumericStringsRemainOwnedAndConnected(t *testing.T) {
	s, e := collect(context.Background(), numericJSONRunner{})
	if e != nil {
		t.Fatal(e)
	}
	if !s.HasTable(4, 52783) || !s.HasTable(4, 52785) {
		t.Fatal("owned tables would not be flushed", s)
	}
	if s.Routes[2].Type != "unreachable" || string(s.Routes[2].Protocol) != "187" {
		t.Fatal("numeric route attributes not normalized")
	}
	u, e := s.Uplink()
	if e != nil || u.Gateway != "192.0.2.2" {
		t.Fatal("old work underlay chosen instead of real uplink", u, e)
	}
	local := localRoutes(s)
	if len(local) != 1 || local[0].Device != "docker0" {
		t.Fatal("numeric scope lost connected Docker subnet", local)
	}
}
func TestBootstrapAAAAAnswer(t *testing.T) {
	data := []byte(`{"Status":0,"Question":[{"name":"vpn.example","type":28}],"Answer":[{"name":"vpn.example","type":28,"data":"2001:db8::8"}]}`)
	a, e := parseBootstrapAnswerType(data, "vpn.example", 28)
	if e != nil || a.String() != "2001:db8::8" {
		t.Fatal(a, e)
	}
	if _, e = parseBootstrapAnswer(data, "vpn.example"); e == nil {
		t.Fatal("AAAA answer accepted for A request")
	}
}
