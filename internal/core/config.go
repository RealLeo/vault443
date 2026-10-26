// Package core owns the deliberately restricted Xray configuration and process.
// It never accepts executable paths or arbitrary core JSON from an imported profile.
package core

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	"vault443/internal/model"
)

const Version = "26.9.30"

type Options struct {
	Interface  string
	Gateway4   netip.Prefix
	Gateway6   netip.Prefix
	DNSAddress netip.Addr
	Endpoint   netip.Addr
	Uplink     string
	Mark       uint32
}

// Build targets Xray 26.9.30. Addresses, routes and DNS are owned by our manager;
// Xray is forbidden from also installing automatic default routes or system DNS.
func Build(p model.Profile, o Options) ([]byte, error) {
	if !o.Endpoint.IsValid() || !o.Gateway4.IsValid() || !o.Gateway6.IsValid() || !o.DNSAddress.IsValid() || o.Interface == "" || o.Uplink == "" || o.Mark == 0 {
		return nil, errors.New("incomplete core network options")
	}
	if p.Port < 1 || p.Port > 65535 || p.UUID == "" || (p.Security != "tls" && p.Security != "reality") {
		return nil, errors.New("invalid secured VLESS profile")
	}
	if p.Security == "reality" && p.Transport == "ws" {
		return nil, errors.New("REALITY does not support WebSocket transport")
	}
	stream := map[string]any{"network": p.Transport, "security": p.Security, "sockopt": map[string]any{"mark": o.Mark, "interface": o.Uplink}}
	sni := p.SNI
	if sni == "" {
		sni = p.Server
	}
	if p.Security == "tls" {
		tls := map[string]any{"serverName": sni, "allowInsecure": false}
		if p.Fingerprint != "" {
			tls["fingerprint"] = p.Fingerprint
		}
		if len(p.ALPN) > 0 {
			tls["alpn"] = p.ALPN
		}
		stream["tlsSettings"] = tls
	} else {
		if p.PublicKey == "" {
			return nil, errors.New("REALITY public key is required")
		}
		r := map[string]any{"serverName": sni, "publicKey": p.PublicKey, "shortId": p.ShortID}
		if p.Fingerprint != "" {
			r["fingerprint"] = p.Fingerprint
		} else {
			r["fingerprint"] = "chrome"
		}
		if p.SpiderX != "" {
			r["spiderX"] = p.SpiderX
		}
		stream["realitySettings"] = r
	}
	switch p.Transport {
	case "tcp", "raw":
		stream["network"] = "tcp"
	case "ws":
		ws := map[string]any{"path": p.Path}
		if p.Host != "" {
			ws["headers"] = map[string]string{"Host": p.Host}
		}
		stream["wsSettings"] = ws
	case "grpc":
		if p.Mode != "" && p.Mode != "gun" && p.Mode != "multi" {
			return nil, errors.New("unsupported gRPC mode")
		}
		stream["grpcSettings"] = map[string]any{"serviceName": p.ServiceName, "multiMode": p.Mode == "multi", "authority": p.Host}
	case "xhttp":
		mode := p.Mode
		if mode == "" {
			mode = "auto"
		}
		if mode != "auto" && mode != "packet-up" && mode != "stream-up" && mode != "stream-one" {
			return nil, errors.New("unsupported XHTTP mode")
		}
		stream["xhttpSettings"] = map[string]any{"host": p.Host, "path": p.Path, "mode": mode}
	default:
		return nil, errors.New("unsupported transport")
	}
	if p.Flow != "" && ((p.Flow != "xtls-rprx-vision" && p.Flow != "xtls-rprx-vision-udp443") || (p.Transport != "tcp" && p.Transport != "raw")) {
		return nil, errors.New("unsupported flow for transport")
	}
	user := map[string]any{"id": p.UUID, "encryption": "none", "level": 0}
	if p.Flow != "" {
		user["flow"] = p.Flow
	}
	logLevel := "warning"
	if p.DebugLogging {
		logLevel = "debug"
	}
	config := map[string]any{
		"log": map[string]any{"loglevel": logLevel, "access": "none", "error": "", "dnsLog": false},
		"inbounds": []any{map[string]any{"tag": "tun", "protocol": "tun", "settings": map[string]any{
			"name": o.Interface, "mtu": 1400, "gateway": []string{o.Gateway4.String(), o.Gateway6.String()}, "autoSystemDnsToGateway": false,
		}}},
		"outbounds": []any{
			map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": o.Endpoint.String(), "port": p.Port, "users": []any{user}}}}, "streamSettings": stream},
			map[string]any{"tag": "dns", "protocol": "dns", "settings": map[string]any{"nonIPQuery": "drop"}},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		// A numeric HTTPS upstream avoids a bootstrap loop. Without +local its
		// traffic traverses Xray routing and the VLESS outbound, never direct.
		"dns": map[string]any{"servers": []string{"https://1.1.1.1/dns-query"}, "queryStrategy": "UseIP", "disableFallback": true},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{
			map[string]any{"type": "field", "inboundTag": []string{"tun"}, "ip": []string{o.DNSAddress.String()}, "port": "53", "outboundTag": "dns"},
		}},
	}
	return json.MarshalIndent(config, "", "  ")
}

func SafeInterface(s string) bool {
	if len(s) == 0 || len(s) > 15 || s == "." || s == ".." {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.')
	}) < 0
}
