package worknet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"vault443/internal/network"
	"vault443/internal/workvpn"
)

func peerID(key string) string { sum := sha256.Sum256([]byte(key)); return hex.EncodeToString(sum[:6]) }
func keyHex(key string) string {
	b, _ := base64.StdEncoding.DecodeString(key)
	return hex.EncodeToString(b)
}
func endpointString(e network.Endpoint) string {
	if e.Address == "" {
		return ""
	}
	return net.JoinHostPort(e.Address, strconv.Itoa(e.Port))
}

var awgUAPIKeys = map[string]string{
	"HeaderProtectionKey": "header_protection_key", "ContentPaddingAddition": "content_padding_addition",
	"RekeyAfterTime": "rekey_after_time", "RekeyTimeout": "rekey_timeout", "RejectAfterTime": "reject_after_time",
	"KeepaliveTimeout": "keepalive_timeout", "MaxHandshakeAttempts": "max_handshake_attempts",
	"RandomTrailers": "random_trailers", "DisableCookies": "disable_cookies",
}

func amneziaConfig(w *workvpn.WireGuardConfig, endpoints []network.Endpoint) string {
	var b strings.Builder
	fmt.Fprintf(&b, "set=1\nprivate_key=%s\nlisten_port=%d\nfwmark=%d\n", keyHex(w.PrivateKey), w.ListenPort, network.OuterMark)
	var names []string
	for name := range w.Parameters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		key := awgUAPIKeys[name]
		if key == "" {
			key = strings.ToLower(name)
		}
		value := w.Parameters[name]
		if name == "HeaderProtectionKey" {
			value = keyHex(value)
		}
		if name == "RandomTrailers" || name == "DisableCookies" {
			if value == "true" {
				value = "1"
			} else {
				value = "0"
			}
		}
		fmt.Fprintf(&b, "%s=%s\n", key, value)
	}
	b.WriteString("replace_peers=true\n")
	for i, p := range w.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", keyHex(p.PublicKey))
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", keyHex(p.PresharedKey))
		}
		if i < len(endpoints) && endpoints[i].Address != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", endpointString(endpoints[i]))
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, prefix := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", prefix)
		}
		if p.PersistentKeepalive != "" {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", p.PersistentKeepalive)
		}
	}
	b.WriteByte('\n')
	return b.String()
}
