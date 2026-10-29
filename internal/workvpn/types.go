// Package workvpn validates and privately stores application-managed OpenVPN
// profiles. The imported document is data, never an executable configuration.
package workvpn

import "strconv"

const (
	MaxBytes      = 1 << 20
	MaxProfiles   = 1024
	MaxStateBytes = 32 << 20
	StoreFilename = "work-vpn.json"
)

type Remote struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type Option struct {
	Key  string   `json:"key"`
	Args []string `json:"args,omitempty"`
}

// Profile contains credentials; never marshal it in D-Bus replies or logs.
type Profile struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	IconID       string            `json:"iconId"`
	DebugLogging bool              `json:"debugLogging"`
	Remotes      []Remote          `json:"remotes"`
	Options      []Option          `json:"options"`
	Inline       map[string]string `json:"inline"`
}

// RouteRule targets a profile ID or "local" (an existing directly connected
// LAN/Docker route). It never permits a physical Internet bypass.
type RouteRule struct {
	ID     string `json:"id"`
	CIDR   string `json:"cidr"`
	Target string `json:"target"`
}

type DNSRule struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	Target string `json:"target"`
}

type WorkUser struct {
	Profiles []Profile   `json:"profiles"`
	Rules    []RouteRule `json:"rules"`
	DNSRules []DNSRule   `json:"dnsRules,omitempty"`
}

type Desired struct {
	UID       uint32 `json:"uid"`
	ProfileID string `json:"profileId"`
}

type State struct {
	Version int                 `json:"version"`
	Users   map[string]WorkUser `json:"users"`
	Desired []Desired           `json:"desired,omitempty"`
	BootID  string              `json:"bootId,omitempty"`
}

func UserKey(uid uint32) string                 { return strconv.FormatUint(uint64(uid), 10) }
func (s State) User(uid uint32) WorkUser        { return s.Users[UserKey(uid)] }
func (s *State) SetUser(uid uint32, u WorkUser) { s.Users[UserKey(uid)] = u }
func (s State) Profile(uid uint32, id string) (Profile, bool) {
	for _, p := range s.User(uid).Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}
