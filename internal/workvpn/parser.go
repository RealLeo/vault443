package workvpn

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"vault443/internal/model"
	"vault443/internal/profiles"
)

var optionName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var algorithmList = regexp.MustCompile(`^[A-Za-z0-9_?-]+(?::[A-Za-z0-9_?-]+)*$`)
var envName = regexp.MustCompile(`^UV_[A-Z0-9_]{1,40}$`)

// Parse accepts a deliberately small, safe OpenVPN client vocabulary. It never
// executes or expands input and never follows file references. Error messages
// contain line numbers and fixed directive names, not credential material.
func Parse(name, source string) (Profile, error) {
	p := Profile{IconID: "shield", Inline: map[string]string{}}
	var err error
	if p.Name, err = profiles.Name(name); err != nil {
		return Profile{}, err
	}
	if len(source) == 0 || len(source) > MaxBytes || !utf8.ValidString(source) {
		return Profile{}, errors.New("OpenVPN profile must be valid UTF-8 and at most 1 MiB")
	}
	source = strings.TrimPrefix(source, "\ufeff")
	source = strings.ReplaceAll(source, "\r\n", "\n")
	for _, r := range source {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || r == '\u202e' || r == '\u202d' {
			return Profile{}, errors.New("OpenVPN profile contains unsupported control characters")
		}
	}
	seen := map[string]bool{}
	defaultProtocol := "udp"
	defaultPort, remotePort := 1194, 0
	var rawRemotes [][]string
	lines := strings.Split(source, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fail := func(message string) (Profile, error) {
			return Profile{}, fmt.Errorf("OpenVPN line %d: %s", i+1, message)
		}
		if strings.HasPrefix(line, "<") {
			tag := strings.TrimSuffix(strings.TrimPrefix(line, "<"), ">")
			if line != "<"+tag+">" || (tag != "ca" && tag != "cert" && tag != "key" && tag != "tls-auth" && tag != "tls-crypt") {
				return fail("unsupported inline block")
			}
			if _, ok := p.Inline[tag]; ok {
				return fail("duplicate inline credential block")
			}
			var body []string
			closed := false
			for i++; i < len(lines); i++ {
				if strings.TrimSpace(lines[i]) == "</"+tag+">" {
					closed = true
					break
				}
				if strings.HasPrefix(strings.TrimSpace(lines[i]), "<") {
					return fail("nested or mismatched inline block")
				}
				body = append(body, lines[i])
			}
			if !closed {
				return fail("unterminated inline credential block")
			}
			p.Inline[tag] = strings.TrimSpace(strings.Join(body, "\n")) + "\n"
			continue
		}
		if len(line) > 16384 {
			return fail("directive exceeds 16 KiB")
		}
		words, e := splitOptions(line)
		if e != nil {
			return fail("invalid quoting or escape sequence")
		}
		if len(words) == 0 {
			continue
		}
		key := strings.TrimPrefix(words[0], "--")
		if !optionName.MatchString(key) {
			return fail("invalid or unsupported directive")
		}
		args := words[1:]
		if key == "ignore-unknown-option" {
			// Exporters use this compatibility hint for pre-2.5 clients. It must
			// never turn off our own strict validation, including for named options.
			if len(args) != 1 || args[0] != "data-ciphers" {
				return fail("only the data-ciphers compatibility hint is supported")
			}
			continue
		}
		repeatable := key == "remote" || key == "route" || key == "route-ipv6" || key == "dhcp-option" || key == "setenv"
		identity := key
		if key == "setenv" && len(args) > 0 {
			identity += "/" + args[0]
		}
		if seen[identity] && !repeatable {
			return fail("duplicate directive")
		}
		if key == "setenv" && seen[identity] {
			return fail("duplicate client metadata variable")
		}
		seen[identity] = true
		switch key {
		case "remote":
			if len(args) < 1 || len(args) > 3 {
				return fail("invalid remote server")
			}
			host, ok := normalizeRemoteHost(args[0])
			if !ok {
				return fail("invalid remote server")
			}
			args[0] = host
			if len(args) >= 2 && !integer(args[1], 1, 65535) {
				return fail("invalid remote port")
			}
			if len(args) == 3 && !validProtocol(args[2]) {
				return fail("unsupported OpenVPN transport")
			}
			rawRemotes = append(rawRemotes, append([]string(nil), args...))
			if len(rawRemotes) > 16 {
				return fail("at most 16 remote servers are supported")
			}
			continue
		case "proto":
			if len(args) != 1 || !validProtocol(args[0]) {
				return fail("unsupported OpenVPN transport")
			}
			defaultProtocol = normalizeProtocol(args[0])
			continue
		case "port", "rport":
			if len(args) != 1 || !integer(args[0], 1, 65535) {
				return fail("invalid remote port")
			}
			n, _ := strconv.Atoi(args[0])
			if key == "port" {
				defaultPort = n
			} else {
				remotePort = n
			}
			continue
		case "client", "pull", "nobind", "persist-key", "persist-tun", "remote-random", "push-peer-info", "auth-nocache", "route-nopull":
			if len(args) != 0 {
				return fail("unexpected directive arguments")
			}
		case "dev", "dev-type":
			if len(args) != 1 || args[0] != "tun" {
				return fail("only TUN client profiles are supported")
			}
		case "cipher", "data-ciphers", "data-ciphers-fallback":
			if len(args) != 1 || len(args[0]) > 512 || !algorithmList.MatchString(args[0]) {
				return fail("invalid cipher setting")
			}
			for _, alg := range strings.Split(args[0], ":") {
				if !supportedCipher(strings.TrimPrefix(alg, "?")) {
					return fail("unsupported or insecure data cipher")
				}
			}
			if key != "data-ciphers" && strings.Contains(args[0], ":") {
				return fail("expected one cipher")
			}
		case "auth":
			if len(args) != 1 || !oneOf(args[0], "SHA1", "SHA224", "SHA256", "SHA384", "SHA512") {
				return fail("unsupported packet authentication algorithm")
			}
		case "remote-cert-tls":
			if len(args) != 1 || args[0] != "server" {
				return fail("server certificate validation is required")
			}
		case "verify-x509-name":
			if len(args) < 1 || len(args) > 2 || len(args[0]) > 1024 || (len(args) == 2 && !oneOf(args[1], "subject", "name", "name-prefix")) {
				return fail("invalid certificate name constraint")
			}
		case "tls-version-min", "tls-version-max":
			if len(args) != 1 || !oneOf(args[0], "1.2", "1.3") {
				return fail("only TLS 1.2 or newer is supported")
			}
		case "tls-cipher", "tls-ciphersuites":
			if len(args) != 1 || len(args[0]) > 2048 || !algorithmList.MatchString(args[0]) || strings.Contains(strings.ToUpper(args[0]), "NULL") {
				return fail("invalid TLS cipher setting")
			}
		case "key-direction":
			if len(args) != 1 || !oneOf(args[0], "0", "1") {
				return fail("invalid TLS key direction")
			}
		case "setenv":
			if len(args) != 2 || !envName.MatchString(args[0]) || len(args[1]) > 1024 {
				return fail("only bounded UV_ client metadata is supported")
			}
		case "verb":
			if len(args) != 1 || !integer(args[0], 0, 4) {
				return fail("supported log verbosity is 0–4")
			}
		case "mute":
			if len(args) != 1 || !integer(args[0], 0, 10000) {
				return fail("invalid log repetition limit")
			}
		case "reneg-sec":
			if len(args) != 1 || !integer(args[0], 0, 2147483647) {
				return fail("invalid renegotiation interval")
			}
		case "ping", "ping-restart", "ping-exit", "hand-window", "tran-window", "server-poll-timeout", "connect-timeout", "auth-retry":
			if key == "auth-retry" {
				if len(args) != 1 || args[0] != "none" {
					return fail("interactive authentication is unsupported")
				}
			} else if len(args) != 1 || !integer(args[0], 0, 3600) {
				return fail("invalid connection timeout")
			}
		case "connect-retry":
			if len(args) < 1 || len(args) > 2 {
				return fail("invalid retry interval")
			}
			for _, a := range args {
				if !integer(a, 1, 300) {
					return fail("invalid retry interval")
				}
			}
		case "connect-retry-max":
			if len(args) != 1 || !integer(args[0], 1, 100) {
				return fail("invalid retry limit")
			}
		case "resolv-retry":
			if len(args) != 1 || (!integer(args[0], 0, 3600) && args[0] != "infinite") {
				return fail("invalid resolver retry setting")
			}
		case "sndbuf", "rcvbuf":
			if len(args) != 1 || !integer(args[0], 0, 16<<20) {
				return fail("invalid socket buffer size")
			}
		case "tun-mtu":
			if len(args) != 1 || !integer(args[0], 576, 65535) {
				return fail("invalid TUN MTU")
			}
		case "mssfix":
			if len(args) > 2 || (len(args) > 0 && !integer(args[0], 0, 65535)) || (len(args) == 2 && !oneOf(args[1], "mtu", "fixed")) {
				return fail("invalid MSS setting")
			}
		case "explicit-exit-notify":
			if len(args) > 1 || (len(args) == 1 && !integer(args[0], 0, 3)) {
				return fail("invalid exit notification setting")
			}
		case "comp-lzo":
			if len(args) != 1 || args[0] != "no" {
				return fail("active compression is unsupported")
			}
		case "compress":
			if len(args) != 1 || !oneOf(args[0], "stub", "stub-v2") {
				return fail("active compression is unsupported")
			}
		case "allow-compression":
			if len(args) != 1 || !oneOf(args[0], "no", "asym") {
				return fail("active compression is unsupported")
			}
		case "topology":
			if len(args) != 1 || !oneOf(args[0], "subnet", "net30", "p2p") {
				return fail("unsupported TUN topology")
			}
		case "redirect-gateway", "redirect-private":
			for _, a := range args {
				if !oneOf(a, "def1", "bypass-dhcp", "bypass-dns", "ipv6", "!ipv4", "block-local", "local", "autolocal") {
					return fail("unsupported redirect flag")
				}
			}
		case "route":
			if !validRoute4(args) {
				return fail("invalid numeric IPv4 route")
			}
		case "route-ipv6":
			if !validRoute6(args) {
				return fail("invalid numeric IPv6 route")
			}
		case "route-gateway":
			if len(args) != 1 || !ipv4(args[0]) {
				return fail("route gateway must be a numeric IPv4 address")
			}
		case "route-ipv6-gateway":
			if len(args) != 1 || !ipv6(args[0]) {
				return fail("route gateway must be a numeric IPv6 address")
			}
		case "route-metric":
			if len(args) != 1 || !integer(args[0], 0, 65535) {
				return fail("invalid route metric")
			}
		case "route-delay":
			if len(args) > 2 {
				return fail("invalid route delay")
			}
			for _, a := range args {
				if !integer(a, 0, 60) {
					return fail("invalid route delay")
				}
			}
		case "dhcp-option":
			if len(args) != 2 {
				return fail("invalid DNS option")
			}
			switch args[0] {
			case "DNS":
				if _, e := netip.ParseAddr(args[1]); e != nil {
					return fail("DNS server must be numeric")
				}
			case "DOMAIN", "DOMAIN-SEARCH", "DOMAIN-ROUTE":
				if _, e := NormalizeDomain(args[1]); e != nil {
					return fail("invalid DNS domain")
				}
			default:
				return fail("unsupported DHCP option")
			}
		case "ca", "cert", "key", "tls-auth", "tls-crypt":
			return fail("credentials must be embedded inline; external file references are unsupported")
		case "auth-user-pass", "askpass", "static-challenge", "pkcs11-providers", "pkcs12":
			return fail("passwords, MFA and external credential providers are unsupported")
		default:
			return fail("unsupported directive; scripts, plugins, includes and runtime overrides are forbidden")
		}
		p.Options = append(p.Options, Option{key, append([]string(nil), args...)})
	}
	if !seen["client"] || !seen["dev"] {
		return Profile{}, errors.New("OpenVPN profile requires client and dev tun")
	}
	if !seen["remote-cert-tls"] {
		return Profile{}, errors.New("OpenVPN profile requires remote-cert-tls server")
	}
	if len(rawRemotes) == 0 {
		return Profile{}, errors.New("OpenVPN profile has no remote server")
	}
	if remotePort > 0 {
		defaultPort = remotePort
	}
	for _, r := range rawRemotes {
		remote := Remote{strings.ToLower(r[0]), defaultPort, defaultProtocol}
		if len(r) > 1 {
			remote.Port, _ = strconv.Atoi(r[1])
		}
		if len(r) > 2 {
			remote.Protocol = normalizeProtocol(r[2])
		}
		p.Remotes = append(p.Remotes, remote)
	}
	if err = validateCredentials(p); err != nil {
		return Profile{}, err
	}
	// Independent options have canonical key ordering. Repeated options and
	// remotes retain their order because it can control DNS/failover preference.
	sort.SliceStable(p.Options, func(i, j int) bool {
		// Preserve ordered DNS server lists and repeated route declarations.
		// Only independent directive keys may be reordered canonically.
		return p.Options[i].Key < p.Options[j].Key
	})
	canonical := struct {
		Remotes []Remote
		Options []Option
		Inline  map[string]string
	}{p.Remotes, p.Options, p.Inline}
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(b)
	p.ID = "ovpn-" + hex.EncodeToString(sum[:16])
	return p, nil
}

func supportedCipher(s string) bool {
	return oneOf(s, "AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "CHACHA20-POLY1305")
}
func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func integer(s string, min, max int) bool {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return false
	}
	n, e := strconv.Atoi(s)
	return e == nil && n >= min && n <= max
}
func validProtocol(s string) bool {
	return oneOf(s, "udp", "udp4", "udp6", "tcp", "tcp-client", "tcp4-client", "tcp6-client")
}
func normalizeProtocol(s string) string {
	if s == "tcp" {
		return "tcp-client"
	}
	return s
}
func validRemoteHost(s string) bool {
	if !profiles.ValidHost(s) {
		return false
	}
	if a, e := netip.ParseAddr(s); e == nil {
		return !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && a.Zone() == ""
	}
	return true
}

// Some exporters wrap IPv6 remote addresses in brackets even though the port
// is a separate argument. Store the bare address expected by the resolver and
// runtime. Leave all previously accepted host spellings unchanged so existing
// profile identities are preserved.
func normalizeRemoteHost(s string) (string, bool) {
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is6() || a.Zone() != "" {
			return "", false
		}
	}
	return s, validRemoteHost(s)
}
func ipv4(s string) bool { a, e := netip.ParseAddr(s); return e == nil && a.Is4() }
func ipv6(s string) bool { a, e := netip.ParseAddr(s); return e == nil && a.Is6() && a.Zone() == "" }
func validRoute4(a []string) bool {
	if len(a) < 1 || len(a) > 4 || !ipv4(a[0]) {
		return false
	}
	if len(a) > 1 {
		ip := net.ParseIP(a[1]).To4()
		if ip == nil {
			return false
		}
		_, bits := net.IPMask(ip).Size()
		if bits != 32 {
			return false
		}
	}
	if len(a) > 2 && !ipv4(a[2]) && a[2] != "vpn_gateway" {
		return false
	}
	return len(a) < 4 || integer(a[3], 0, 65535)
}
func validRoute6(a []string) bool {
	if len(a) < 1 || len(a) > 3 {
		return false
	}
	p, e := netip.ParsePrefix(a[0])
	if e != nil || !p.Addr().Is6() {
		return false
	}
	if len(a) > 1 && !ipv6(a[1]) {
		return false
	}
	return len(a) < 3 || integer(a[2], 0, 65535)
}

func splitOptions(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	quote := rune(0)
	escaped := false
	active := false
	flush := func() {
		if active {
			out = append(out, b.String())
			b.Reset()
			active = false
		}
	}
	for _, r := range s {
		if escaped {
			if r != '\\' && r != '"' && r != '\'' && r != ' ' && r != '\t' {
				return nil, errors.New("escape")
			}
			b.WriteRune(r)
			escaped = false
			active = true
			continue
		}
		if r == '\\' {
			escaped = true
			active = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			active = true
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			active = true
			continue
		}
		if r == ' ' || r == '\t' {
			flush()
			continue
		}
		if (r == '#' || r == ';') && !active {
			break
		}
		b.WriteRune(r)
		active = true
	}
	if quote != 0 || escaped {
		return nil, errors.New("quote")
	}
	flush()
	return out, nil
}

func validateCredentials(p Profile) error {
	for _, tag := range []string{"ca", "cert", "key"} {
		if p.Inline[tag] == "" {
			return errors.New("OpenVPN profile requires embedded CA, client certificate and private key")
		}
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM([]byte(p.Inline["ca"])) {
		return errors.New("invalid embedded CA certificate")
	}
	// Reject encrypted keys explicitly, never invite an unavailable terminal prompt.
	block, _ := pem.Decode([]byte(p.Inline["key"]))
	if block == nil || strings.Contains(block.Type, "ENCRYPTED") || x509.IsEncryptedPEMBlock(block) {
		return errors.New("encrypted or invalid private keys are unsupported")
	}
	pair, e := tls.X509KeyPair([]byte(p.Inline["cert"]), []byte(p.Inline["key"]))
	if e != nil || len(pair.Certificate) == 0 {
		return errors.New("invalid embedded client certificate or mismatched private key")
	}
	if p.Inline["tls-auth"] != "" && p.Inline["tls-crypt"] != "" {
		return errors.New("tls-auth and tls-crypt cannot be combined")
	}
	for _, tag := range []string{"tls-auth", "tls-crypt"} {
		if text := p.Inline[tag]; text != "" && !validStaticKey(text) {
			return errors.New("invalid embedded TLS control-channel key")
		}
	}
	for _, o := range p.Options {
		if o.Key == "key-direction" && p.Inline["tls-auth"] == "" {
			return errors.New("key-direction requires an embedded tls-auth key")
		}
	}
	return nil
}
func validStaticKey(text string) bool {
	inside, closed := false, false
	var h strings.Builder
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		switch s {
		case "-----BEGIN OpenVPN Static key V1-----":
			if inside || closed {
				return false
			}
			inside = true
		case "-----END OpenVPN Static key V1-----":
			if !inside {
				return false
			}
			inside = false
			closed = true
		default:
			if inside {
				h.WriteString(s)
			} else if s != "" && !strings.HasPrefix(s, "#") {
				return false
			}
		}
	}
	if inside || !closed || h.Len() != 512 {
		return false
	}
	_, e := hex.DecodeString(h.String())
	return e == nil
}

// Source reconstructs the validated subset for private persistence validation.
// It is not a runtime configuration: the supervisor adds its own fixed controls.
func (p Profile) Source() string {
	var b strings.Builder
	for _, r := range p.Remotes {
		fmt.Fprintf(&b, "remote %s %d %s\n", quote(r.Host), r.Port, r.Protocol)
	}
	for _, o := range p.Options {
		b.WriteString(o.Key)
		for _, a := range o.Args {
			b.WriteByte(' ')
			b.WriteString(quote(a))
		}
		b.WriteByte('\n')
	}
	for _, tag := range []string{"ca", "cert", "key", "tls-auth", "tls-crypt"} {
		if s := p.Inline[tag]; s != "" {
			fmt.Fprintf(&b, "<%s>\n%s\n</%s>\n", tag, strings.TrimSpace(s), tag)
		}
	}
	return b.String()
}
func quote(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }

func ValidateProfile(p Profile) error {
	if !model.ValidIcon(p.IconID) {
		return errors.New("invalid profile icon")
	}
	q, e := Parse(p.Name, p.Source())
	if e != nil {
		return e
	}
	if p.ID != q.ID {
		return errors.New("invalid OpenVPN profile identity")
	}
	// Re-parsing must preserve every credential key; unknown serialized fields
	// must not disappear during reconstruction.
	if len(p.Inline) != len(q.Inline) {
		return errors.New("unsupported credential block")
	}
	return nil
}
