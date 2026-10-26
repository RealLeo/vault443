package model

// Profile is the validated application-owned subset of an Xray outbound.
// Never send UUID, public keys, or subscription URLs in public status events.
type Profile struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	IconID         string   `json:"iconId"`
	DebugLogging   bool     `json:"debugLogging"`
	Server         string   `json:"server"`
	Port           int      `json:"port"`
	UUID           string   `json:"uuid"`
	Transport      string   `json:"transport"`
	Security       string   `json:"security"`
	Flow           string   `json:"flow,omitempty"`
	SNI            string   `json:"sni,omitempty"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	PublicKey      string   `json:"publicKey,omitempty"`
	ShortID        string   `json:"shortId,omitempty"`
	SpiderX        string   `json:"spiderX,omitempty"`
	Path           string   `json:"path,omitempty"`
	Host           string   `json:"host,omitempty"`
	ServiceName    string   `json:"serviceName,omitempty"`
	ALPN           []string `json:"alpn,omitempty"`
	Mode           string   `json:"mode,omitempty"`
	SubscriptionID string   `json:"subscriptionId,omitempty"`
}

// Icon identifiers are application resources, never caller-supplied file paths.
func ValidIcon(id string) bool {
	switch id {
	case "antenna", "dish", "globe", "vault-door", "radiation", "atom", "gear", "wrench", "lightning", "battery", "shield", "key", "gas-mask", "crt-terminal", "robot", "radar", "compass", "rocket", "canteen", "vacuum-tube", "plug", "binoculars", "satellite":
		return true
	}
	return false
}

func (p Profile) Icon() string {
	if ValidIcon(p.IconID) {
		return p.IconID
	}
	return "antenna"
}

type RuntimeStatus struct {
	Stage          string   `json:"stage,omitempty"`
	StageStartedAt int64    `json:"stageStartedAt,omitempty"`
	FailureCode    string   `json:"failureCode,omitempty"`
	State          string   `json:"state"`
	Message        string   `json:"message,omitempty"`
	ConnectedAt    int64    `json:"connectedAt,omitempty"`
	RXBytes        uint64   `json:"rxBytes"`
	TXBytes        uint64   `json:"txBytes"`
	GuardArmed     bool     `json:"guardArmed"`
	ExternalVPNs   []string `json:"externalVpns,omitempty"`
}

// VPNCompatibility is a read-only, credential-free view of current VPN
// discovery. It never grants transport exceptions or persists interface trust.
type VPNCompatibility struct {
	BusyByOtherUser bool                   `json:"busyByOtherUser"`
	Items           []VPNCompatibilityItem `json:"items"`
	Message         string                 `json:"message,omitempty"`
}

type VPNCompatibilityItem struct {
	Interface   string `json:"interface"`
	Manager     string `json:"manager"`
	Application string `json:"application"`
	Source      string `json:"source"`
	Active      bool   `json:"active"`
	Verified    bool   `json:"verified"`
	FullIPv4    bool   `json:"fullIPv4"`
	FullIPv6    bool   `json:"fullIPv6"`
	Message     string `json:"message,omitempty"`
}
