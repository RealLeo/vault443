package profiles

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"vault443/internal/model"
)

func parseTrojan(raw string) (model.Profile, error) {
	var empty model.Profile
	if len(raw) > 16384 {
		return empty, errors.New("profile link exceeds 16 KiB")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "trojan" || u.User == nil || u.Opaque != "" || u.Path != "" {
		return empty, errors.New("invalid Trojan link")
	}
	password := u.User.Username()
	if _, hasPassword := u.User.Password(); hasPassword {
		return empty, errors.New("Trojan password delimiters must be percent encoded")
	}
	if err := validPassword(password); err != nil {
		return empty, err
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return empty, errors.New("invalid Trojan parameters")
	}
	allowed := map[string]bool{"type": true, "security": true, "sni": true, "peer": true, "fp": true, "alpn": true, "path": true, "host": true, "serviceName": true, "authority": true, "mode": true, "headerType": true, "allowInsecure": true}
	for k, v := range q {
		if !allowed[k] {
			return empty, errors.New("unsupported Trojan parameter: " + safeParameter(k))
		}
		if len(v) != 1 {
			return empty, errors.New("duplicate Trojan parameter")
		}
	}
	if q.Get("security") != "" && q.Get("security") != "tls" {
		return empty, errors.New("Trojan requires TLS; REALITY and plaintext are unsupported")
	}
	if value, exists := q["allowInsecure"]; exists {
		if value[0] != "0" && value[0] != "false" {
			return empty, errors.New("TLS certificate verification cannot be disabled")
		}
		q.Del("allowInsecure")
	}
	if peer, exists := q["peer"]; exists {
		if q.Has("sni") && q.Get("sni") != peer[0] {
			return empty, errors.New("conflicting TLS server names")
		}
		q.Set("sni", peer[0])
		q.Del("peer")
	}
	// Reuse the existing bounded TLS/transport parser, without letting Trojan
	// acquire VLESS-only settings or alter legacy VLESS identities.
	v := *u
	v.Scheme = "vless"
	v.User = url.User("00000000-0000-4000-8000-000000000000")
	q.Set("security", "tls")
	v.RawQuery = q.Encode()
	p, err := parseVLESS(v.String())
	if err != nil {
		return empty, err
	}
	if ip := net.ParseIP(p.Server); ip != nil {
		p.Server = ip.String()
	}
	p.Kind = "trojan"
	p.UUID = ""
	p.Password = password
	p.ID = Identity(p)
	return p, nil
}

func validPassword(s string) error {
	if s == "" || len(s) > 4096 || !utf8.ValidString(s) || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return errors.New("password must be nonempty valid text without control characters, up to 4096 bytes")
	}
	return nil
}
func safeParameter(s string) string {
	if len(s) > 48 {
		return "(invalid name)"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return "(invalid name)"
		}
	}
	return s
}
func decodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if out, e := enc.DecodeString(s); e == nil {
			return out, nil
		}
	}
	return nil, errors.New("invalid Base64 encoding")
}

// NormalizeMethod does not upgrade or substitute encryption. Aliases identify
// exactly the same AEAD construction in the pinned core.
func NormalizeMethod(method, password string) (string, error) {
	switch strings.ToLower(method) {
	case "aes-128-gcm", "aes-256-gcm":
		method = strings.ToLower(method)
	case "chacha20-poly1305", "chacha20-ietf-poly1305":
		method = "chacha20-ietf-poly1305"
	case "xchacha20-poly1305", "xchacha20-ietf-poly1305":
		method = "xchacha20-ietf-poly1305"
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		method = strings.ToLower(method)
		keys := strings.Split(password, ":")
		if len(keys) > 8 || (strings.Contains(method, "chacha") && len(keys) != 1) {
			return "", errors.New("unsupported Shadowsocks 2022 key chain")
		}
		length := 32
		if method == "2022-blake3-aes-128-gcm" {
			length = 16
		}
		for _, key := range keys {
			decoded, e := base64.StdEncoding.DecodeString(key)
			if e != nil || len(decoded) != length {
				return "", errors.New("Shadowsocks 2022 requires correctly sized Base64 keys")
			}
		}
	default:
		return "", errors.New("unsupported Shadowsocks cipher")
	}
	return method, validPassword(password)
}

func parseShadowsocks(raw string) (model.Profile, error) {
	p := model.Profile{Kind: "shadowsocks", IconID: "antenna", Transport: "tcp", Security: "shadowsocks"}
	if len(raw) > 16384 {
		return p, errors.New("profile link exceeds 16 KiB")
	}
	raw = strings.TrimSpace(raw)
	// Historical ss://BASE64(method:password@host:port)#name form.
	if !strings.Contains(strings.SplitN(strings.TrimPrefix(raw, "ss://"), "#", 2)[0], "@") {
		parts := strings.SplitN(strings.TrimPrefix(raw, "ss://"), "#", 2)
		decoded, e := decodeBase64(strings.TrimSuffix(parts[0], "/"))
		if e != nil {
			return p, errors.New("invalid legacy Shadowsocks link")
		}
		credentials, address, ok := cutLast(string(decoded), "@")
		if !ok {
			return p, errors.New("invalid legacy Shadowsocks endpoint")
		}
		method, password, ok := strings.Cut(credentials, ":")
		if !ok {
			return p, errors.New("invalid Shadowsocks credentials")
		}
		u := url.URL{Scheme: "ss", Host: address, User: url.UserPassword(method, password)}
		if len(parts) == 2 {
			name, e := url.PathUnescape(parts[1])
			if e != nil {
				return p, errors.New("invalid profile name encoding")
			}
			u.Fragment = name
		}
		raw = u.String()
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "ss" || u.User == nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return p, errors.New("invalid Shadowsocks link")
	}
	p.Server = strings.ToLower(u.Hostname())
	if ip := net.ParseIP(p.Server); ip != nil {
		p.Server = ip.String()
	}
	if !ValidHost(p.Server) {
		return p, errors.New("invalid server hostname or IP address")
	}
	p.Port, e = strconv.Atoi(u.Port())
	if e != nil || p.Port < 1 || p.Port > 65535 {
		return p, errors.New("server port must be 1–65535")
	}
	method := u.User.Username()
	password, plain := u.User.Password()
	if !plain {
		data, e := decodeBase64(method)
		if e != nil {
			return p, errors.New("invalid Shadowsocks credentials")
		}
		var ok bool
		method, password, ok = strings.Cut(string(data), ":")
		if !ok {
			return p, errors.New("invalid Shadowsocks credentials")
		}
		if strings.HasPrefix(method, "2022-") {
			return p, errors.New("SIP002 requires percent-encoded credentials for Shadowsocks 2022")
		}
	}
	p.Method, e = NormalizeMethod(method, password)
	if e != nil {
		return p, e
	}
	p.Password = password
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return p, errors.New("invalid Shadowsocks parameters")
	}
	for k, v := range q {
		if len(v) != 1 {
			return p, errors.New("duplicate Shadowsocks parameter")
		}
		switch k {
		case "outline":
			if v[0] != "1" {
				return p, errors.New("unsupported Outline marker")
			}
		case "prefix":
			if strings.HasPrefix(p.Method, "2022-") {
				return p, errors.New("Outline prefix with Shadowsocks 2022 is unsupported")
			}
		case "plugin":
			return p, errors.New("external Shadowsocks plugins are unsupported")
		default:
			return p, errors.New("unsupported Shadowsocks parameter: " + safeParameter(k))
		}
	}
	if q.Has("prefix") {
		prefix, err := outlinePrefix(q.Get("prefix"))
		if err != nil {
			return p, err
		}
		if len(prefix) > 16 {
			return p, errors.New("Outline prefix exceeds 16 bytes")
		}
		n := &model.OutlineNode{Type: "shadowsocks", Cipher: p.Method, Secret: p.Password, Endpoint: &model.OutlineNode{Type: "address", Address: net.JoinHostPort(p.Server, strconv.Itoa(p.Port))}}
		tcp := *n
		tcp.Prefix = prefix
		p.Outline = &model.OutlineTransport{TCP: &tcp, UDP: n}
		if e := supportedOutlineNode(&tcp); e != nil {
			return p, e
		}
	}
	name := u.Fragment
	if name == "" {
		name = p.Server
	}
	p.Name, e = Name(name)
	if e != nil {
		return p, e
	}
	p.ID = Identity(p)
	return p, nil
}
func cutLast(s, separator string) (string, string, bool) {
	i := strings.LastIndex(s, separator)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(separator):], true
}
func proxyIdentity(p model.Profile) string {
	p.ID = ""
	p.Name = ""
	p.IconID = ""
	p.DebugLogging = false
	p.SubscriptionID = ""
	p.Source = nil
	p.Kind = p.Protocol()
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}
func sourceIdentity(raw string) string {
	h := sha256.Sum256([]byte("outline\x00" + raw))
	return hex.EncodeToString(h[:16])
}
