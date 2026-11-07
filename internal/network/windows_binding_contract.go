package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf16"

	"vault443/internal/workvpn"
)

// windowsBinding deliberately shares public field names with the Linux binding.
// GUID is derived by the elevated service; input never selects an executable.
type windowsBinding struct {
	Interface  string     `json:"interface"`
	Manager    string     `json:"manager"`
	Unit       string     `json:"unit,omitempty"`
	Cgroup     string     `json:"cgroup,omitempty"`
	GUID       string     `json:"guid,omitempty"`
	Endpoints  []Endpoint `json:"endpoints,omitempty"`
	Routes     []string   `json:"routes,omitempty"`
	DNSServers []string   `json:"dnsServers,omitempty"`
	DNSDomains []string   `json:"dnsDomains,omitempty"`
	Remove     bool       `json:"remove,omitempty"`
}

func validWindowsName(name string) bool {
	if strings.TrimSpace(name) != name || name == "" || len(utf16.Encode([]rune(name))) > 256 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}
func externalIP(ip netip.Addr) bool {
	return ip.IsValid() && !ip.Is4In6() && ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}
func validExternalPrefix(p netip.Prefix) bool {
	return p.IsValid() && !p.Addr().Is4In6() && p.Addr().Zone() == "" && !p.Addr().IsLoopback() && !p.Addr().IsMulticast() && !p.Addr().IsLinkLocalUnicast()
}
func parseWindowsBinding(text string) (windowsBinding, error) {
	var b windowsBinding
	if len(text) > 64<<10 {
		return b, errors.New("Windows VPN binding exceeds limits")
	}
	d := json.NewDecoder(bytes.NewBufferString(text))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF || !validWindowsName(b.Interface) || strings.HasPrefix(strings.ToLower(b.Interface), "v443") {
		return b, errors.New("invalid Windows VPN binding")
	}
	if b.Remove {
		return b, nil
	}
	switch b.Manager {
	case "pritunl", "openvpn", "wireguard", "wg-quick":
	default:
		return b, errors.New("unsupported Windows VPN manager")
	}
	if b.Cgroup != "" {
		return b, errors.New("Windows VPN ownership uses a service name, not a Linux cgroup")
	}
	if b.Unit != "" && (!validWindowsName(b.Unit) || strings.HasPrefix(strings.ToLower(b.Unit), "vault443")) {
		return b, errors.New("invalid external Windows VPN service")
	}
	if len(b.Routes) > 256 || len(b.Endpoints) > 64 || len(b.DNSServers) > 16 || len(b.DNSDomains) > 64 {
		return b, errors.New("VPN binding exceeds limits")
	}
	if len(b.Endpoints) > 0 && b.Unit == "" {
		return b, errors.New("transport exceptions require a trusted LocalSystem VPN service")
	}
	for i, raw := range b.Routes {
		p, e := netip.ParsePrefix(raw)
		if e != nil || p.Bits() < 2 || !validExternalPrefix(p) {
			return b, errors.New("protected Windows VPN routes must be specific CIDR prefixes")
		}
		b.Routes[i] = p.Masked().String()
	}
	for _, ep := range b.Endpoints {
		a, e := netip.ParseAddr(ep.Address)
		if e != nil || !externalIP(a) || ep.Port < 1 || ep.Port > 65535 || (ep.Protocol != "tcp" && ep.Protocol != "udp") || ep.Mark != 0 || ep.SourcePort < 0 || ep.SourcePort > 65535 || (ep.Protocol != "udp" && ep.SourcePort != 0) {
			return b, errors.New("invalid Windows VPN transport endpoint")
		}
	}
	for i, raw := range b.DNSServers {
		ip, e := netip.ParseAddr(raw)
		if e != nil || !externalIP(ip) {
			return b, errors.New("invalid Windows VPN DNS server")
		}
		b.DNSServers[i] = ip.String()
	}
	for i, raw := range b.DNSDomains {
		domain, e := workvpn.NormalizeDomain(raw)
		if e != nil {
			return b, e
		}
		b.DNSDomains[i] = domain
	}
	if (len(b.DNSDomains) == 0) != (len(b.DNSServers) == 0) {
		return b, errors.New("split DNS binding needs both servers and domains")
	}
	b.GUID = ""
	return b, nil
}

// A detected full tunnel is temporary policy. Its default DNS claim must stop
// when the tunnel disappears, while explicit administrator DNS claims persist.
func externalDNSDomains(remembered, explicit []string) []string {
	explicitDefault := false
	for _, domain := range explicit {
		explicitDefault = explicitDefault || domain == "."
	}
	result := make([]string, 0, len(remembered))
	for _, domain := range remembered {
		if domain != "." || explicitDefault {
			result = append(result, domain)
		}
	}
	return result
}
func windowsClaimsDefault(prefixes []netip.Prefix, v6 bool) bool {
	low, high := false, false
	var redirect6 uint8
	for _, p := range prefixes {
		if !p.IsValid() || p.Addr().Is6() != v6 {
			continue
		}
		p = p.Masked()
		if p.Bits() == 0 {
			return true
		}
		if p.Bits() == 1 {
			if p.Addr().IsUnspecified() {
				low = true
			} else {
				high = true
			}
		}
		if v6 {
			// OpenVPN 2.6.23 init.c:do_init_route_ipv6_list uses this exact
			// four-prefix redirect signature instead of an IPv6 /0 or /1 pair.
			// Require every component; repeated corporate routes are not full.
			switch p.String() {
			case "::/3":
				redirect6 |= 1
			case "2000::/4":
				redirect6 |= 2
			case "3000::/4":
				redirect6 |= 4
			case "fc00::/7":
				redirect6 |= 8
			}
		}
	}
	return low && high || v6 && redirect6 == 15
}
