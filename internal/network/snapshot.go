package network

import (
	"encoding/json"
	"net/netip"
)

const OuterMark uint32 = 0x564c5401

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

type Snapshot struct {
	Links          []Link
	Routes         []Route
	Rules4, Rules6 []map[string]any
}

func (s Snapshot) Link(name string) (Link, bool) {
	for _, l := range s.Links {
		if l.Name == name {
			return l, true
		}
	}
	return Link{}, false
}

type Endpoint struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Mark       uint32 `json:"mark,omitempty"`
	SourcePort int    `json:"sourcePort,omitempty"`
}
