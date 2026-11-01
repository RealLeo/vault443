// Package profiles accepts a deliberately bounded subset of VLESS share links.
// It never accepts executable Xray configuration or silently drops URL options.
package profiles

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"vault443/internal/model"
)

const MaxBytes = 1 << 20
const MaxProfiles = 1024

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var shortPattern = regexp.MustCompile(`^[0-9a-fA-F]{0,16}$`)
var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

type Entry struct {
	Kind       string        `json:"kind"`
	SourceKind string        `json:"sourceKind,omitempty"`
	Line       int           `json:"line"`
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Server     string        `json:"server"`
	IconID     string        `json:"iconId"`
	Duplicate  bool          `json:"duplicate"`
	Profile    model.Profile `json:"-"`
}
type Issue struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}
type Preview struct {
	Profiles []Entry `json:"profiles"`
	Errors   []Issue `json:"errors"`
}

func Name(s string) (string, error) {
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u202e' || r == '\u202d' || r == '\u2066' || r == '\u2067' || r == '\u2068' || r == '\u2069' {
			return "", errors.New("name contains unsupported control characters")
		}
	}
	s = strings.TrimSpace(s)
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > 80 {
		return "", errors.New("name must contain 1–80 characters")
	}
	return s, nil
}

func Parse(raw string) (model.Profile, error) {
	if strings.HasPrefix(strings.TrimSpace(raw), "trojan://") {
		return parseTrojan(raw)
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "ss://") {
		return parseShadowsocks(raw)
	}
	return parseVLESS(raw)
}
func parseVLESS(raw string) (model.Profile, error) {
	p := model.Profile{IconID: "antenna"}
	if len(raw) > 16384 {
		return p, errors.New("profile link exceeds 16 KiB")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "vless" || u.Opaque != "" || u.User == nil || u.Path != "" {
		return p, errors.New("expected a vless://UUID@host:port link")
	}
	if _, yes := u.User.Password(); yes || !uuidPattern.MatchString(u.User.Username()) {
		return p, errors.New("invalid VLESS UUID")
	}
	p.UUID = strings.ToLower(u.User.Username())
	p.Server = strings.ToLower(u.Hostname())
	if !ValidHost(p.Server) {
		return p, errors.New("invalid server hostname or IP address")
	}
	p.Port, err = strconv.Atoi(u.Port())
	if err != nil || p.Port < 1 || p.Port > 65535 {
		return p, errors.New("server port must be 1–65535")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return p, errors.New("invalid percent-encoded profile parameters")
	}
	allowed := map[string]bool{"type": true, "security": true, "encryption": true, "flow": true, "sni": true, "fp": true, "pbk": true, "sid": true, "spx": true, "path": true, "host": true, "serviceName": true, "authority": true, "alpn": true, "mode": true, "headerType": true, "support-x25519mlkem768": true}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !allowed[k] {
			return p, errors.New("unsupported profile parameter; no parameters were silently ignored")
		}
		if len(q[k]) != 1 {
			return p, errors.New("duplicate profile parameter")
		}
		if strings.ContainsAny(q.Get(k), "\x00\r\n") {
			return p, errors.New("control characters in profile parameter")
		}
	}
	if q.Get("encryption") != "" && q.Get("encryption") != "none" {
		return p, errors.New("only encryption=none with TLS or REALITY is supported")
	}
	p.Transport = q.Get("type")
	if p.Transport == "" || p.Transport == "raw" {
		p.Transport = "tcp"
	}
	switch p.Transport {
	case "tcp", "ws", "grpc", "xhttp":
	default:
		return p, errors.New("unsupported transport; supported: tcp, ws, grpc, xhttp")
	}
	p.Security = q.Get("security")
	if p.Security != "tls" && p.Security != "reality" {
		return p, errors.New("TLS or REALITY is required; unencrypted VLESS is unsupported")
	}
	p.Flow = q.Get("flow")
	if p.Flow != "" && p.Flow != "xtls-rprx-vision" && p.Flow != "xtls-rprx-vision-udp443" {
		return p, errors.New("unsupported VLESS flow")
	}
	if p.Flow != "" && p.Transport != "tcp" {
		return p, errors.New("Vision requires the tcp transport")
	}
	p.SNI = q.Get("sni")
	if p.SNI == "" {
		p.SNI = p.Server
	}
	if !ValidHost(p.SNI) {
		return p, errors.New("invalid TLS server name")
	}
	p.Fingerprint = q.Get("fp")
	fps := map[string]bool{"": true, "chrome": true, "firefox": true, "safari": true, "ios": true, "android": true, "edge": true, "360": true, "qq": true, "random": true, "randomized": true}
	if !fps[p.Fingerprint] {
		return p, errors.New("unsupported TLS fingerprint")
	}
	p.PublicKey, p.ShortID, p.SpiderX = q.Get("pbk"), strings.ToLower(q.Get("sid")), q.Get("spx")
	if p.Security == "reality" {
		if p.Transport != "tcp" && p.Transport != "grpc" && p.Transport != "xhttp" {
			return p, errors.New("REALITY is unsupported with this transport")
		}
		key, err := base64.RawURLEncoding.DecodeString(p.PublicKey)
		if err != nil || len(key) != 32 {
			return p, errors.New("REALITY requires a valid 32-byte public key")
		}
		if !shortPattern.MatchString(p.ShortID) || len(p.ShortID)%2 != 0 {
			return p, errors.New("REALITY short ID must be 0–16 hexadecimal digits in byte pairs")
		}
		if p.Fingerprint == "" {
			p.Fingerprint = "chrome"
		}
	} else if hasAny(q, "pbk", "sid", "spx", "support-x25519mlkem768") {
		return p, errors.New("REALITY parameters require security=reality")
	}
	if hasAny(q, "support-x25519mlkem768") {
		enabled, err := strconv.ParseBool(q.Get("support-x25519mlkem768"))
		if err != nil {
			return p, errors.New("support-x25519mlkem768 must be a boolean")
		}
		if !enabled {
			return p, errors.New("support-x25519mlkem768=false is unsupported: the pinned Xray does not expose an ML-KEM disable switch")
		}
		// This URI hint is emitted by 3x-ui for Mihomo compatibility, not an
		// Xray JSON setting. Xray 26.9.30's pinned uTLS presets already send
		// X25519MLKEM768 for these fingerprints. Validate that requirement
		// instead of discarding it or changing the requested fingerprint.
		// The resulting connection (and therefore its ID) is unchanged.
		switch p.Fingerprint {
		case "chrome", "firefox", "safari":
		default:
			return p, errors.New("support-x25519mlkem768=true requires fp=chrome, firefox or safari with the pinned Xray")
		}
	}
	if q.Get("alpn") != "" {
		for _, v := range strings.Split(q.Get("alpn"), ",") {
			if v != "h2" && v != "http/1.1" && v != "h3" {
				return p, errors.New("unsupported ALPN value")
			}
			p.ALPN = append(p.ALPN, v)
		}
	}
	p.Path, p.Host, p.ServiceName, p.Mode = q.Get("path"), q.Get("host"), q.Get("serviceName"), q.Get("mode")
	switch p.Transport {
	case "tcp":
		if hasAny(q, "path", "host", "serviceName", "authority", "mode") || (q.Get("headerType") != "" && q.Get("headerType") != "none") {
			return p, errors.New("unsupported tcp transport parameters")
		}
	case "ws":
		if hasAny(q, "serviceName", "authority", "mode", "headerType") {
			return p, errors.New("unsupported WebSocket transport parameters")
		}
		if p.Path == "" {
			p.Path = "/"
		}
	case "grpc":
		if hasAny(q, "path", "host", "headerType") {
			return p, errors.New("unsupported gRPC transport parameters")
		}
		p.Host = q.Get("authority")
		if p.Mode == "" {
			p.Mode = "gun"
		}
		if p.Mode != "gun" && p.Mode != "multi" {
			return p, errors.New("unsupported gRPC mode")
		}
	case "xhttp":
		if hasAny(q, "serviceName", "authority", "headerType") {
			return p, errors.New("unsupported XHTTP transport parameters")
		}
		if p.Path == "" {
			p.Path = "/"
		}
		if p.Mode == "" {
			p.Mode = "auto"
		}
		if p.Mode != "auto" && p.Mode != "packet-up" && p.Mode != "stream-up" && p.Mode != "stream-one" {
			return p, errors.New("unsupported XHTTP mode")
		}
	}
	if p.Path != "" && (!strings.HasPrefix(p.Path, "/") || len(p.Path) > 4096) {
		return p, errors.New("transport path must start with / and fit 4096 bytes")
	}
	if len(p.Host) > 253 || len(p.ServiceName) > 1024 || len(p.SpiderX) > 4096 {
		return p, errors.New("transport parameter exceeds size limit")
	}
	name := u.Fragment
	if name == "" {
		name = p.Server
	}
	p.Name, err = Name(name)
	if err != nil {
		return p, err
	}
	// Hash canonical connection fields, excluding display/source metadata.
	p.ID = Identity(p)
	return p, nil
}

func ValidHost(h string) bool {
	return h != "" && (net.ParseIP(h) != nil || (hostPattern.MatchString(h) && !strings.Contains(h, "..")))
}
func hasAny(q url.Values, keys ...string) bool {
	for _, k := range keys {
		if _, ok := q[k]; ok {
			return true
		}
	}
	return false
}
func Identity(p model.Profile) string {
	if p.Source != nil {
		return sourceIdentity(p.Source.URL)
	}
	if p.Protocol() != "vless" {
		return proxyIdentity(p)
	}
	parts := []string{p.Server, strconv.Itoa(p.Port), p.UUID, p.Transport, p.Security, p.Flow, p.SNI, p.Fingerprint, p.PublicKey, p.ShortID, p.SpiderX, p.Path, p.Host, p.ServiceName, strings.Join(p.ALPN, ","), p.Mode}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}

func Decode(text string) (string, error) {
	if len(text) > MaxBytes {
		return "", errors.New("import exceeds 1 MiB")
	}
	text = strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if containsLink(text) {
		return text, nil
	}
	compact := strings.Join(strings.Fields(text), "")
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := encoding.DecodeString(compact); err == nil && utf8.Valid(b) && containsLink(string(b)) {
			return string(b), nil
		}
	}
	return text, nil
}

func PreviewText(text string, existing []model.Profile) Preview {
	out := Preview{Profiles: []Entry{}, Errors: []Issue{}}
	decoded, err := Decode(text)
	if err != nil {
		out.Errors = append(out.Errors, Issue{0, err.Error()})
		return out
	}
	seen := map[string]bool{}
	for _, p := range existing {
		seen[Identity(p)] = true
	}
	count := 0
	for i, line := range strings.Split(decoded, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		count++
		if count > MaxProfiles {
			out.Errors = append(out.Errors, Issue{i + 1, fmt.Sprintf("import is limited to %d profiles", MaxProfiles)})
			break
		}
		p, err := Parse(line)
		if err != nil {
			out.Errors = append(out.Errors, Issue{i + 1, err.Error()})
			continue
		}
		out.Profiles = append(out.Profiles, Entry{Line: i + 1, ID: p.ID, Name: p.Name, Server: p.Server, Kind: p.Protocol(), IconID: p.Icon(), Duplicate: seen[p.ID], Profile: p})
		seen[p.ID] = true
	}
	if count == 0 {
		out.Errors = append(out.Errors, Issue{0, "no supported proxy profiles found"})
	}
	return out
}

func containsLink(text string) bool {
	for _, scheme := range []string{"vless://", "trojan://", "ss://"} {
		if strings.HasPrefix(text, scheme) || strings.Contains(text, "\n"+scheme) {
			return true
		}
	}
	return false
}
