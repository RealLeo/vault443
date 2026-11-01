package model

// Profile is the validated application-owned subset of an Xray outbound.
// Never send UUID, public keys, or subscription URLs in public status events.
type Profile struct {
	Kind           string            `json:"kind,omitempty"`
	Password       string            `json:"password,omitempty"`
	Method         string            `json:"method,omitempty"`
	Outline        *OutlineTransport `json:"outline,omitempty"`
	Source         *DynamicSource    `json:"source,omitempty"`
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	IconID         string            `json:"iconId"`
	DebugLogging   bool              `json:"debugLogging"`
	Server         string            `json:"server"`
	Port           int               `json:"port"`
	UUID           string            `json:"uuid"`
	Transport      string            `json:"transport"`
	Security       string            `json:"security"`
	Flow           string            `json:"flow,omitempty"`
	SNI            string            `json:"sni,omitempty"`
	Fingerprint    string            `json:"fingerprint,omitempty"`
	PublicKey      string            `json:"publicKey,omitempty"`
	ShortID        string            `json:"shortId,omitempty"`
	SpiderX        string            `json:"spiderX,omitempty"`
	Path           string            `json:"path,omitempty"`
	Host           string            `json:"host,omitempty"`
	ServiceName    string            `json:"serviceName,omitempty"`
	ALPN           []string          `json:"alpn,omitempty"`
	Mode           string            `json:"mode,omitempty"`
	SubscriptionID string            `json:"subscriptionId,omitempty"`
}

func (p Profile) Protocol() string {
	if p.Kind == "" {
		return "vless"
	}
	return p.Kind
}

// DynamicSource and Outline nodes are private credentials, never public API objects.
type DynamicSource struct {
	URL         string `json:"url"`
	UpdatedAt   int64  `json:"updatedAt"`
	LastAttempt int64  `json:"lastAttempt"`
	LastError   string `json:"lastError,omitempty"`
	UsingCached bool   `json:"usingCached,omitempty"`
	Blocked     bool   `json:"blocked,omitempty"`
}
type OutlineTransport struct {
	TCP *OutlineNode `json:"tcp,omitempty"`
	UDP *OutlineNode `json:"udp,omitempty"`
}

// OutlineNode is a bounded, normalized transport tree, not an executable config.
type OutlineNode struct {
	Type     string       `json:"type"`
	Address  string       `json:"address,omitempty"`
	URL      string       `json:"url,omitempty"`
	Cipher   string       `json:"cipher,omitempty"`
	Secret   string       `json:"secret,omitempty"`
	Prefix   []byte       `json:"prefix,omitempty"`
	Endpoint *OutlineNode `json:"endpoint,omitempty"`
	Dialer   *OutlineNode `json:"dialer,omitempty"`
}

func (p Profile) Secrets() []string {
	out := []string{p.UUID, p.Password, p.PublicKey, p.ShortID}
	for _, value := range []string{p.SpiderX, p.Path, p.ServiceName} {
		if len(value) > 1 {
			out = append(out, value)
		}
	}
	if p.Source != nil {
		out = append(out, p.Source.URL)
	}
	var visit func(*OutlineNode)
	visit = func(n *OutlineNode) {
		if n == nil {
			return
		}
		out = append(out, n.Secret, n.URL)
		visit(n.Endpoint)
		visit(n.Dialer)
	}
	if p.Outline != nil {
		visit(p.Outline.TCP)
		visit(p.Outline.UDP)
	}
	return out
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
