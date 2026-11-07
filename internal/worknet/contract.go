package worknet

type Config struct{ StateDir, RuntimeDir, OpenVPNPath, EventHelperPath, WireGuardPath, AmneziaWGPath, AmneziaWGSocketDir string }
type PeerStatus struct {
	ID              string   `json:"id"`
	Endpoint        string   `json:"endpoint"`
	State           string   `json:"state"`
	LastHandshakeAt int64    `json:"lastHandshakeAt,omitempty"`
	AllowedIPs      []string `json:"allowedIPs"`
}
type Status struct {
	Peers                 []PeerStatus `json:"peers,omitempty"`
	State                 string       `json:"state"`
	Stage                 string       `json:"stage"`
	Message               string       `json:"message,omitempty"`
	StageStartedAt        int64        `json:"stageStartedAt"`
	ConnectedAt           int64        `json:"connectedAt,omitempty"`
	Interface             string       `json:"interface,omitempty"`
	Routes                []string     `json:"routes,omitempty"`
	DNSServers            []string     `json:"dnsServers,omitempty"`
	DNSDomains            []string     `json:"dnsDomains,omitempty"`
	NetworkManagerState   string       `json:"networkManagerState,omitempty"`
	NetworkManagerMessage string       `json:"networkManagerMessage,omitempty"`
}
type RouteInfo struct {
	CIDR       string `json:"cidr,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Source     string `json:"source"`
	Target     string `json:"target"`
	TargetName string `json:"targetName,omitempty"`
	Interface  string `json:"interface,omitempty"`
	State      string `json:"state"`
	Message    string `json:"message,omitempty"`
	Conflict   bool   `json:"conflict"`
}
