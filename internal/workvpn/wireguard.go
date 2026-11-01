package workvpn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"vault443/internal/profiles"
)

// AWGParameterNames is the vocabulary of the pinned AmneziaWG 3.1 backend.
// Values are data, never command-line fragments or executable hooks.
var AWGParameterNames = []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"}

func ParseWireGuard(name, source string) (Profile, error) { return parseWireGuard(name, source, false) }

func parseWireGuard(name, source string, forceAWG bool) (Profile, error) {
	p := Profile{Kind: "wireguard", IconID: "shield", WireGuard: &WireGuardConfig{MTU: 1280, Parameters: map[string]string{}}}
	var err error
	if p.Name, err = profiles.Name(name); err != nil {
		return Profile{}, err
	}
	if len(source) == 0 || len(source) > MaxBytes || !utf8.ValidString(source) {
		return Profile{}, errors.New("WireGuard profile must be valid UTF-8 and at most 1 MiB")
	}
	source = strings.TrimPrefix(source, "\ufeff")
	source = strings.ReplaceAll(source, "\r\n", "\n")
	for _, r := range source {
		if unicode.IsControl(r) && r != '\n' && r != '\t' || r == '\u202e' || r == '\u202d' {
			return Profile{}, errors.New("WireGuard profile contains unsupported control characters")
		}
	}
	w := p.WireGuard
	section := ""
	seenInterface := false
	seen := map[string]bool{}
	var peer *WireGuardPeer
	for index, raw := range strings.Split(source, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		fail := func(reason string) (Profile, error) {
			return Profile{}, fmt.Errorf("WireGuard line %d: %s", index+1, reason)
		}
		if len(line) > 16384 {
			return fail("directive exceeds 16 KiB")
		}
		if strings.HasPrefix(line, "[") {
			switch line {
			case "[Interface]":
				if seenInterface || len(w.Peers) > 0 {
					return fail("duplicate or misplaced Interface section")
				}
				seenInterface = true
				section = "interface"
				seen = map[string]bool{}
			case "[Peer]":
				if !seenInterface || len(w.Peers) >= 32 {
					return fail("Peer requires Interface; at most 32 peers are supported")
				}
				w.Peers = append(w.Peers, WireGuardPeer{})
				peer = &w.Peers[len(w.Peers)-1]
				section = "peer"
				seen = map[string]bool{}
			default:
				return fail("unsupported configuration section")
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || section == "" || value == "" && !(section == "interface" && oneOf(key, "I1", "I2", "I3", "I4", "I5")) {
			return fail("expected a parameter inside Interface or Peer")
		}
		if !validWGField(key) {
			return fail("unsupported parameter")
		}
		repeatable := section == "interface" && (key == "Address" || key == "DNS") || section == "peer" && key == "AllowedIPs"
		if seen[key] && !repeatable {
			return fail("duplicate " + key + " parameter")
		}
		seen[key] = true
		if section == "interface" {
			switch key {
			case "PrivateKey":
				if !validWGKey(value) {
					return fail("invalid PrivateKey")
				}
				w.PrivateKey = value
			case "Address":
				for _, s := range strings.Split(value, ",") {
					a, e := parseInterfaceAddress(strings.TrimSpace(s))
					if e != nil {
						return fail("invalid Address")
					}
					w.Addresses = append(w.Addresses, a)
				}
			case "DNS":
				for _, s := range strings.Split(value, ",") {
					s = strings.TrimSpace(s)
					if a, e := netip.ParseAddr(s); e == nil {
						if !wgUnicast(a) {
							return fail("invalid DNS address")
						}
						w.DNSServers = append(w.DNSServers, a.String())
					} else {
						domain, e := NormalizeDomain(s)
						if e != nil {
							return fail("invalid DNS routing domain")
						}
						w.DNSDomains = append(w.DNSDomains, domain)
					}
				}
			case "MTU":
				if !integer(value, 576, 65535) {
					return fail("invalid MTU")
				}
				w.MTU, _ = strconv.Atoi(value)
			case "ListenPort":
				if !integer(value, 0, 65535) {
					return fail("invalid ListenPort")
				}
				w.ListenPort, _ = strconv.Atoi(value)
			case "Table":
				if value != "auto" {
					return fail("only Table=auto is supported; routing is managed by Vault 443")
				}
			case "SaveConfig":
				if value != "false" {
					return fail("SaveConfig=true is unsupported")
				}
			default:
				if !oneOf(key, AWGParameterNames...) {
					return fail("unsupported " + key + " parameter; scripts and runtime overrides are forbidden")
				}
				v, e := normalizeAWG(key, value)
				if e != nil {
					return fail("invalid " + key + " parameter")
				}
				w.Parameters[key] = v
				p.Kind = "amneziawg"
			}
		} else {
			switch key {
			case "PublicKey":
				if !validWGKey(value) {
					return fail("invalid PublicKey")
				}
				peer.PublicKey = value
			case "PresharedKey":
				if !validWGKey(value) {
					return fail("invalid PresharedKey")
				}
				peer.PresharedKey = value
			case "Endpoint":
				host, port, e := net.SplitHostPort(value)
				if e != nil || !validRemoteHost(host) || !integer(port, 1, 65535) {
					return fail("invalid Endpoint; use host:port or [IPv6]:port")
				}
				if a, e := netip.ParseAddr(host); e == nil {
					host = a.String()
				}
				peer.Endpoint = Remote{Host: strings.ToLower(host), Protocol: "udp"}
				peer.Endpoint.Port, _ = strconv.Atoi(port)
			case "AllowedIPs":
				for _, s := range strings.Split(value, ",") {
					prefix, e := parseAllowedPrefix(strings.TrimSpace(s))
					if e != nil {
						return fail("invalid AllowedIPs")
					}
					peer.AllowedIPs = append(peer.AllowedIPs, prefix)
				}
			case "PersistentKeepalive":
				v, e := normalizeRange(value, 65535, true)
				if e != nil {
					return fail("invalid PersistentKeepalive")
				}
				peer.PersistentKeepalive = v
			default:
				return fail("unsupported " + key + " peer parameter")
			}
		}
	}
	if forceAWG {
		p.Kind = "amneziawg"
	}
	if !seenInterface || w.PrivateKey == "" || len(w.Addresses) == 0 || len(w.Peers) == 0 {
		return Profile{}, errors.New("WireGuard requires PrivateKey, Address and at least one Peer")
	}
	if len(w.Addresses) > 32 || len(w.DNSServers) > 16 || len(w.DNSDomains) > 64 {
		return Profile{}, errors.New("WireGuard address or DNS limit exceeded")
	}
	w.Addresses = uniqueSorted(w.Addresses)
	w.DNSServers = unique(w.DNSServers)
	w.DNSDomains = uniqueSorted(w.DNSDomains)
	if len(w.DNSDomains) > 0 && len(w.DNSServers) == 0 {
		return Profile{}, errors.New("WireGuard DNS domains require a DNS server")
	}
	if len(w.DNSServers) > 0 && len(w.DNSDomains) == 0 {
		w.DNSDomains = []string{"."}
	}
	families := map[bool]bool{}
	for _, address := range w.Addresses {
		a, _ := netip.ParsePrefix(address)
		families[a.Addr().Is4()] = true
		if a.Addr().Is6() && w.MTU < 1280 {
			return Profile{}, errors.New("WireGuard IPv6 requires MTU of at least 1280")
		}
	}
	keys, routes := map[string]bool{}, map[string]string{}
	for i := range w.Peers {
		peer := &w.Peers[i]
		if peer.PublicKey == "" || peer.Endpoint.Host == "" || len(peer.AllowedIPs) == 0 {
			return Profile{}, fmt.Errorf("WireGuard peer %d requires PublicKey, Endpoint and AllowedIPs", i+1)
		}
		if keys[peer.PublicKey] {
			return Profile{}, errors.New("WireGuard contains duplicate peer public keys")
		}
		keys[peer.PublicKey] = true
		if p.Kind == "wireguard" && strings.Contains(peer.PersistentKeepalive, "-") {
			return Profile{}, errors.New("WireGuard PersistentKeepalive ranges require AmneziaWG")
		}
		peer.AllowedIPs = uniqueSorted(peer.AllowedIPs)
		for _, prefix := range peer.AllowedIPs {
			if previous, ok := routes[prefix]; ok && previous != peer.PublicKey {
				return Profile{}, errors.New("WireGuard peers claim the same AllowedIPs prefix")
			}
			routes[prefix] = peer.PublicKey
			q, _ := netip.ParsePrefix(prefix)
			if !families[q.Addr().Is4()] {
				return Profile{}, errors.New("WireGuard AllowedIPs requires an interface address of the same IP family")
			}
		}
		if peer.PersistentKeepalive == "0" {
			peer.PersistentKeepalive = ""
		}
	}
	if len(routes) > 512 {
		return Profile{}, errors.New("WireGuard supports at most 512 AllowedIPs prefixes")
	}
	for _, dns := range w.DNSServers {
		a, _ := netip.ParseAddr(dns)
		if !p.AllowsPrefix(netip.PrefixFrom(a, a.BitLen()).String()) {
			return Profile{}, errors.New("WireGuard DNS server is outside AllowedIPs")
		}
	}
	if p.Kind == "amneziawg" {
		if err := validateAWGRelationships(w); err != nil {
			return Profile{}, err
		}
	}
	sort.Slice(w.Peers, func(i, j int) bool { return w.Peers[i].PublicKey < w.Peers[j].PublicKey })
	b, _ := json.Marshal(struct {
		Kind   string
		Config *WireGuardConfig
	}{p.Kind, w})
	sum := sha256.Sum256(b)
	prefix := "wg-"
	if p.Kind == "amneziawg" {
		prefix = "awg-"
	}
	p.ID = prefix + hex.EncodeToString(sum[:16])
	return p, nil
}

func validWGField(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func validWGKey(s string) bool {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	return e == nil && len(b) == 32 && !bytes.Equal(b, make([]byte, 32)) && base64.StdEncoding.EncodeToString(b) == s
}
func wgUnicast(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast() && !a.Is4In6() && a.Zone() == ""
}
func parseInterfaceAddress(s string) (string, error) {
	if a, e := netip.ParseAddr(s); e == nil {
		s = netip.PrefixFrom(a, a.BitLen()).String()
	}
	p, e := netip.ParsePrefix(s)
	if e != nil || !wgUnicast(p.Addr()) {
		return "", errors.New("address")
	}
	return p.String(), nil
}
func parseAllowedPrefix(s string) (string, error) {
	if a, e := netip.ParseAddr(s); e == nil {
		s = netip.PrefixFrom(a, a.BitLen()).String()
	}
	p, e := netip.ParsePrefix(s)
	if e != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" || p.Addr().IsLoopback() || p.Addr().IsMulticast() || p.Addr().IsLinkLocalUnicast() {
		return "", errors.New("prefix")
	}
	return p.Masked().String(), nil
}
func unique(v []string) []string {
	out := make([]string, 0, len(v))
	seen := map[string]bool{}
	for _, s := range v {
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	return out
}
func uniqueSorted(v []string) []string { v = unique(v); sort.Strings(v); return v }

// AllowsPrefix covers a complete destination, not merely its first IP. A manual
// rule must not accidentally grant destinations absent from cryptokey routing.
func (p Profile) AllowsPrefix(s string) bool {
	if p.Protocol() == "openvpn" {
		return true
	}
	q, e := netip.ParsePrefix(s)
	if e != nil || p.WireGuard == nil {
		return false
	}
	var allowedPrefixes []netip.Prefix
	for _, peer := range p.WireGuard.Peers {
		for _, allowed := range peer.AllowedIPs {
			a, e := netip.ParsePrefix(allowed)
			if e == nil {
				allowedPrefixes = append(allowedPrefixes, a.Masked())
			}
		}
	}
	return prefixesCover(q.Masked(), allowedPrefixes)
}

func prefixesCover(q netip.Prefix, allowed []netip.Prefix) bool {
	var children []netip.Prefix
	for _, a := range allowed {
		if a.Addr().Is4() != q.Addr().Is4() {
			continue
		}
		if a.Bits() <= q.Bits() && a.Contains(q.Addr()) {
			return true
		}
		if q.Contains(a.Addr()) {
			children = append(children, a)
		}
	}
	if len(children) == 0 || q.Bits() == q.Addr().BitLen() {
		return false
	}
	bit := q.Bits()
	var high netip.Addr
	if q.Addr().Is4() {
		a := q.Addr().As4()
		a[bit/8] |= 1 << (7 - bit%8)
		high = netip.AddrFrom4(a)
	} else {
		a := q.Addr().As16()
		a[bit/8] |= 1 << (7 - bit%8)
		high = netip.AddrFrom16(a)
	}
	return prefixesCover(netip.PrefixFrom(q.Addr(), bit+1), children) && prefixesCover(netip.PrefixFrom(high, bit+1), children)
}

func normalizeRange(s string, maximum uint64, allowOff bool) (string, error) {
	if allowOff && s == "off" || allowOff && s == "(off)" {
		return "0", nil
	}
	parts := strings.Split(s, "-")
	if len(parts) > 2 {
		return "", errors.New("range")
	}
	var first uint64
	for i, v := range parts {
		if v == "" || strings.Trim(v, "0123456789") != "" {
			return "", errors.New("range")
		}
		n, e := strconv.ParseUint(v, 10, 32)
		if e != nil || n > maximum || i == 1 && n < first {
			return "", errors.New("range")
		}
		parts[i] = strconv.FormatUint(n, 10)
		if i == 0 {
			first = n
		}
	}
	if len(parts) == 2 && parts[0] == parts[1] {
		return parts[0], nil
	}
	return strings.Join(parts, "-"), nil
}
func normalizeAWG(key, value string) (string, error) {
	switch key {
	case "HeaderProtectionKey":
		if validWGKey(value) {
			return value, nil
		}
	case "RandomTrailers", "DisableCookies":
		value = strings.ToLower(value)
		if value == "true" || value == "1" || value == "on" {
			return "true", nil
		}
		if value == "false" || value == "0" || value == "off" {
			return "false", nil
		}
	case "I1", "I2", "I3", "I4", "I5":
		return normalizeSignature(value)
	case "Jc":
		if integer(value, 0, 128) {
			n, _ := strconv.Atoi(value)
			return strconv.Itoa(n), nil
		}
	case "Jmin", "Jmax", "S1", "S2", "S3", "S4":
		if integer(value, 0, 65507) {
			n, _ := strconv.Atoi(value)
			return strconv.Itoa(n), nil
		}
	case "H1", "H2", "H3", "H4":
		return normalizeRange(value, 4294967295, false)
	case "ContentPaddingAddition":
		return normalizeRange(value, 65507, true)
	case "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout":
		return normalizeRange(value, 86400, true)
	case "MaxHandshakeAttempts":
		return normalizeRange(value, 128, true)
	}
	return "", errors.New("invalid AmneziaWG parameter")
}
func normalizeSignature(s string) (string, error) {
	// Bounded interpreter for the pinned backend's CPS grammar. No network or
	// filesystem expansion is involved, and expansion cannot exceed a UDP packet.
	var result []string
	total := 0
	for len(strings.TrimSpace(s)) > 0 {
		s = strings.TrimSpace(s)
		if !strings.HasPrefix(s, "<") {
			return "", errors.New("signature")
		}
		tag, rest, ok := strings.Cut(s[1:], ">")
		if !ok {
			return "", errors.New("signature")
		}
		s = rest
		parts := strings.Fields(tag)
		if len(parts) == 0 || len(parts) > 2 {
			return "", errors.New("signature")
		}
		switch parts[0] {
		case "t":
			if len(parts) != 1 {
				return "", errors.New("signature")
			}
			total += 4
		case "b":
			if len(parts) != 2 || !strings.HasPrefix(parts[1], "0x") {
				return "", errors.New("signature")
			}
			b, e := hex.DecodeString(parts[1][2:])
			if e != nil || len(b) == 0 {
				return "", errors.New("signature")
			}
			total += len(b)
			parts[1] = "0x" + hex.EncodeToString(b)
		case "r", "rd", "rc":
			if len(parts) != 2 || !integer(parts[1], 0, 65507) {
				return "", errors.New("signature")
			}
			n, _ := strconv.Atoi(parts[1])
			total += n
			parts[1] = strconv.Itoa(n)
		default:
			return "", errors.New("signature")
		}
		if total > 65507 || len(result) >= 256 {
			return "", errors.New("signature")
		}
		result = append(result, "<"+strings.Join(parts, " ")+">")
	}
	return strings.Join(result, ""), nil
}

// PeerID identifies public diagnostic rows without exposing the public key.
func PeerID(publicKey string) string {
	sum := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(sum[:6])
}
func validateAWGRelationships(w *WireGuardConfig) error {
	n := func(key string) int { v, _ := strconv.Atoi(w.Parameters[key]); return v }
	if n("Jmin") > n("Jmax") {
		return errors.New("AmneziaWG Jmin exceeds Jmax")
	}
	for key, overhead := range map[string]int{"S1": 148, "S2": 92, "S3": 64, "S4": w.MTU + 32} {
		if n(key)+overhead > 65507 {
			return errors.New("AmneziaWG padding exceeds UDP packet size")
		}
	}
	if w.Parameters["HeaderProtectionKey"] != "" {
		for _, key := range []string{"S1", "S2", "S3", "S4"} {
			if n(key) < 12 {
				return errors.New("AmneziaWG HeaderProtectionKey requires S1–S4 of at least 12")
			}
		}
	}
	return nil
}

func (p Profile) wireGuardSource() string {
	w := p.WireGuard
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\nMTU = %d\nListenPort = %d\n", w.PrivateKey, strings.Join(w.Addresses, ", "), w.MTU, w.ListenPort)
	if len(w.DNSServers)+len(w.DNSDomains) > 0 {
		values := append([]string{}, w.DNSServers...)
		for _, domain := range w.DNSDomains {
			values = append(values, "~"+domain)
		}
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(values, ", "))
	}
	var keys []string
	for key := range w.Parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&b, "%s = %s\n", key, w.Parameters[key])
	}
	for _, peer := range w.Peers {
		fmt.Fprintf(&b, "[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\n", peer.PublicKey, net.JoinHostPort(peer.Endpoint.Host, strconv.Itoa(peer.Endpoint.Port)), strings.Join(peer.AllowedIPs, ", "))
		if peer.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PresharedKey)
		}
		if peer.PersistentKeepalive != "" {
			fmt.Fprintf(&b, "PersistentKeepalive = %s\n", peer.PersistentKeepalive)
		}
	}
	return b.String()
}
func validateWireGuardProfile(p Profile) error {
	if !oneOf(p.Kind, "wireguard", "amneziawg") || p.WireGuard == nil || len(p.Remotes)+len(p.Options)+len(p.Inline) != 0 {
		return errors.New("invalid work protocol settings")
	}
	q, e := parseWireGuard(p.Name, p.Source(), p.Kind == "amneziawg")
	if e != nil {
		return e
	}
	a, _ := json.Marshal(p.WireGuard)
	b, _ := json.Marshal(q.WireGuard)
	if p.ID != q.ID || p.Kind != q.Kind || !bytes.Equal(a, b) {
		return errors.New("invalid WireGuard profile identity or noncanonical settings")
	}
	return nil
}

func (p Profile) Secrets() []string {
	var out []string
	for _, v := range p.Inline {
		out = append(out, v)
		for _, line := range strings.Split(v, "\n") {
			if len(line) > 8 {
				out = append(out, line)
			}
		}
	}
	for _, o := range p.Options {
		if o.Key == "setenv" && len(o.Args) > 1 {
			out = append(out, o.Args[1])
		}
	}
	if w := p.WireGuard; w != nil {
		out = append(out, w.PrivateKey, w.Parameters["HeaderProtectionKey"])
		for _, peer := range w.Peers {
			out = append(out, peer.PresharedKey)
		}
		// UAPI uses hexadecimal keys; redact both encodings before retention.
		for _, key := range append([]string{}, out...) {
			if b, e := base64.StdEncoding.DecodeString(key); e == nil && len(b) == 32 {
				out = append(out, hex.EncodeToString(b))
			}
		}
	}
	return out
}
