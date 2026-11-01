package journal

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ansi         = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?)`)
	uri          = regexp.MustCompile(`(?i)(?:vless|vmess|trojan|ss|vpn|https?)://[^\s<>"']+`)
	uuid         = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	namedSecret  = regexp.MustCompile(`(?i)(["']?(?:uuid|password|passwd|token|authorization|private[_-]?key|public[_-]?key|preshared[_-]?key|header[_-]?protection[_-]?key|client_priv_key|shortid|sid|pbk|psk|secret|spiderx)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}"']+)`)
	bearer       = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[a-z0-9+/=_-]+`)
	openVPNToken = regexp.MustCompile(`(?i)\b(auth[-_]token(?:[-_]user)?)(?:\s*[:=]\s*|\s+)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`)
)

func secretVariants(secrets []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range secrets {
		if s == "" {
			continue
		}
		for _, v := range []string{s, url.QueryEscape(s), url.PathEscape(s)} {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Slice(out, func(a, b int) bool { return len(out[a]) > len(out[b]) })
	return out
}

// Sanitize is applied both before writing and before delivering a record. Known
// session credentials are additionally removed by Session.Log, before enqueue.
func Sanitize(s string) string { return sanitize(s, nil) }
func sanitize(s string, secrets []string) string {
	// Cap work before running regexes on an untrusted core line. The pipe reader
	// separately drains overlong lines without allocating their remainder.
	if len(s) > MaxMessageBytes*4 {
		return "Oversized journal message omitted"
	}
	s = strings.ToValidUTF8(s, "")
	s = ansi.ReplaceAllString(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, s)
	for _, secret := range secrets {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	s = uri.ReplaceAllString(s, "[redacted URI]")
	s = uuid.ReplaceAllString(s, "[redacted UUID]")
	s = bearer.ReplaceAllString(s, "[redacted]")
	s = openVPNToken.ReplaceAllString(s, "${1} [redacted]")
	s = namedSecret.ReplaceAllString(s, "${1}[redacted]")
	s = strings.TrimSpace(s)
	if len(s) > MaxMessageBytes {
		n := MaxMessageBytes - len(" [truncated]")
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n] + " [truncated]"
	}
	return s
}
