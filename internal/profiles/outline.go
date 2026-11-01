package profiles

import (
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
	"vault443/internal/model"
)

type ProviderError struct{ Message string }

func (e *ProviderError) Error() string { return "Outline provider: " + e.Message }

func OutlineURL(raw string) (string, string, error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || (u.Scheme != "ssconf" && u.Scheme != "https") {
		return "", "", errors.New("Outline requires an ssconf:// or HTTPS URL")
	}
	name := u.Fragment
	u.Fragment = ""
	u.RawFragment = ""
	u.Scheme = "https"
	u.Host = strings.ToLower(u.Host)
	if _, e = SubscriptionURL(u.String()); e != nil {
		return "", "", e
	}
	if name == "" {
		name = u.Hostname()
	}
	name, e = Name(name)
	return u.String(), name, e
}

// ParseOutline accepts a bounded data graph. Unknown fields are rejected; no
// reporter, executable, filesystem reference or direct user-traffic path exists.
func ParseOutline(document, sourceURL, name string) (model.Profile, error) {
	var p model.Profile
	if len(document) > MaxBytes || !utf8.ValidString(document) {
		return p, errors.New("invalid or oversized Outline document")
	}
	var root yaml.Node
	d := yaml.NewDecoder(strings.NewReader(document))
	if e := d.Decode(&root); e != nil {
		return p, errors.New("invalid Outline JSON/YAML")
	}
	var extra yaml.Node
	if d.Decode(&extra) != io.EOF {
		return p, errors.New("Outline must contain one document")
	}
	budget := 4096
	value, e := outlineValue(&root, 0, &budget)
	if e != nil {
		return p, e
	}
	return selectOutline(value, sourceURL, name)
}

func parseResolvedOutline(value any, sourceURL, name string) (model.Profile, error) {
	var p model.Profile
	var e error
	if text, ok := value.(string); ok {
		if !strings.HasPrefix(text, "ss://") {
			return p, errors.New("Outline document must contain a Shadowsocks link")
		}
		p, e = parseShadowsocks(text)
	} else {
		m, ok := value.(map[string]any)
		if !ok {
			return p, errors.New("Outline document must be an object or ss:// link")
		}
		if v, ok := m["error"]; ok {
			if e = onlyKeys(m, "error"); e != nil {
				return p, e
			}
			info, ok := v.(map[string]any)
			if !ok {
				return p, errors.New("invalid Outline provider error")
			}
			if e = onlyKeys(info, "message", "details"); e != nil {
				return p, e
			}
			message, _ := info["message"].(string)
			// Provider prose is untrusted and can contain fresh credentials.
			// Expose only a fixed denial category, never its raw details.
			lower := strings.ToLower(message)
			message = "configuration is unavailable"
			if strings.Contains(lower, "expired") || strings.Contains(lower, "истёк") {
				message = "key expired"
			}
			if strings.Contains(lower, "quota") || strings.Contains(lower, "квот") {
				message = "quota exceeded"
			}

			return p, &ProviderError{message}
		}
		var transport *model.OutlineTransport
		if _, ok := m["transport"]; ok {
			if e = onlyKeys(m, "transport"); e != nil {
				return p, e
			}
			t, ok := m["transport"].(map[string]any)
			if !ok {
				return p, errors.New("invalid Outline transport")
			}
			if e = onlyKeys(t, "$type", "tcp", "udp"); e != nil {
				return p, e
			}
			if t["$type"] != "tcpudp" {
				return p, errors.New("unsupported Outline transport type")
			}
			transport = &model.OutlineTransport{}
			if t["tcp"] != nil {
				transport.TCP, e = outlineDialer(t["tcp"], 0)
				if e != nil {
					return p, e
				}
			}
			if t["udp"] != nil {
				transport.UDP, e = outlineDialer(t["udp"], 0)
				if e != nil {
					return p, e
				}
			}
		} else {
			if e = onlyKeys(m, "server", "server_port", "method", "password", "prefix"); e != nil {
				return p, e
			}
			server, _ := m["server"].(string)
			port, ok := m["server_port"].(int)
			if !ok {
				return p, errors.New("Outline server_port must be an integer")
			}
			method, _ := m["method"].(string)
			secret, _ := m["password"].(string)
			endpoint, e := addressNode(net.JoinHostPort(server, strconv.Itoa(port)))
			if e != nil {
				return p, e
			}
			method, e = NormalizeMethod(method, secret)
			if e != nil {
				return p, e
			}
			n := &model.OutlineNode{Type: "shadowsocks", Cipher: method, Secret: secret, Endpoint: endpoint}
			tcp := *n
			if v, ok := m["prefix"]; ok {
				tcp.Prefix, e = outlinePrefix(v)
				if e != nil {
					return p, e
				}
			}
			transport = &model.OutlineTransport{TCP: &tcp, UDP: n}
		}
		p, e = profileFromOutline(transport)
	}
	if e != nil {
		return model.Profile{}, e
	}
	if name == "" {
		name = p.Server
	}
	p.Name, e = Name(name)
	if e != nil {
		return model.Profile{}, e
	}
	p.Source = &model.DynamicSource{URL: sourceURL}
	p.ID = Identity(p)
	return p, nil
}

func outlineValue(n *yaml.Node, depth int, budget *int) (any, error) {
	*budget--
	if *budget < 0 || depth > 24 {
		return nil, errors.New("Outline YAML expansion or depth limit exceeded")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return nil, errors.New("empty Outline document")
		}
		return outlineValue(n.Content[0], depth+1, budget)
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil, errors.New("invalid YAML alias")
		}
		return outlineValue(n.Alias, depth+1, budget)
	case yaml.MappingNode:
		out := map[string]any{}
		seen := map[string]bool{}
		// YAML merge keys fill defaults; explicit fields override them.
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return nil, errors.New("Outline keys must be strings")
			}
			if seen[k.Value] {
				return nil, errors.New("duplicate Outline field: " + safeParameter(k.Value))
			}
			seen[k.Value] = true
			if k.Value != "<<" {
				continue
			}
			v, e := outlineValue(n.Content[i+1], depth+1, budget)
			if e != nil {
				return nil, e
			}
			items := []any{v}
			if list, ok := v.([]any); ok {
				items = list
			}
			for _, item := range items {
				m, ok := item.(map[string]any)
				if !ok {
					return nil, errors.New("invalid YAML merge")
				}
				for key, val := range m {
					if _, exists := out[key]; !exists {
						out[key] = val
					}
				}
			}
		}
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Value == "<<" {
				continue
			}
			v, e := outlineValue(n.Content[i+1], depth+1, budget)
			if e != nil {
				return nil, e
			}
			out[n.Content[i].Value] = v
		}
		return out, nil
	case yaml.SequenceNode:
		out := []any{}
		for _, c := range n.Content {
			v, e := outlineValue(c, depth+1, budget)
			if e != nil {
				return nil, e
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			return n.Value, nil
		case "!!int":
			v, e := strconv.Atoi(n.Value)
			if e != nil {
				return nil, errors.New("invalid Outline integer")
			}
			return v, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			return n.Value == "true", nil
		default:
			return nil, errors.New("unsupported Outline scalar type")
		}
	}
	return nil, errors.New("unsupported YAML node")
}
func onlyKeys(m map[string]any, keys ...string) error {
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return errors.New("unsupported Outline field: " + safeParameter(k))
		}
	}
	return nil
}
func outlinePrefix(value any) ([]byte, error) {
	s, ok := value.(string)
	if !ok {
		return nil, errors.New("Outline prefix must be a string")
	}
	// Outline maps Unicode codepoints 0..255 to their byte values.
	var out []byte
	for _, r := range s {
		if r > 255 {
			return nil, errors.New("Outline prefix characters must fit one byte")
		}
		out = append(out, byte(r))
	}
	if len(out) > 16 {
		return nil, errors.New("Outline prefix exceeds 16 bytes")
	}
	return out, nil
}
func outlineDialer(v any, depth int) (*model.OutlineNode, error) {
	if depth > 8 {
		return nil, errors.New("Outline chain exceeds eight levels")
	}
	if s, ok := v.(string); ok {
		p, e := parseShadowsocks(s)
		if e != nil {
			return nil, e
		}
		if p.Outline != nil {
			return p.Outline.TCP, nil
		}
		return &model.OutlineNode{Type: "shadowsocks", Cipher: p.Method, Secret: p.Password, Endpoint: &model.OutlineNode{Type: "address", Address: net.JoinHostPort(p.Server, strconv.Itoa(p.Port))}}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("Outline traffic must use an encrypted transport")
	}
	if e := onlyKeys(m, "$type", "endpoint", "cipher", "secret", "prefix"); e != nil {
		return nil, e
	}
	if m["$type"] != "shadowsocks" {
		return nil, errors.New("unsupported or direct Outline transport")
	}
	method, _ := m["cipher"].(string)
	secret, _ := m["secret"].(string)
	method, e := NormalizeMethod(method, secret)
	if e != nil {
		return nil, e
	}
	n := &model.OutlineNode{Type: "shadowsocks", Cipher: method, Secret: secret}
	n.Endpoint, e = outlineEndpoint(m["endpoint"], depth+1)
	if e != nil {
		return nil, e
	}
	if v, ok := m["prefix"]; ok {
		n.Prefix, e = outlinePrefix(v)
	}
	return n, e
}
func addressNode(address string) (*model.OutlineNode, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil || !ValidHost(host) {
		return nil, errors.New("invalid Outline endpoint")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, errors.New("invalid Outline endpoint port")
	}
	host = strings.ToLower(host)
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	return &model.OutlineNode{Type: "address", Address: net.JoinHostPort(host, strconv.Itoa(n))}, nil
}
func outlineEndpoint(v any, depth int) (*model.OutlineNode, error) {
	if depth > 8 {
		return nil, errors.New("Outline chain exceeds eight levels")
	}
	if address, ok := v.(string); ok {
		return addressNode(address)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("invalid Outline endpoint")
	}
	switch m["$type"] {
	case "dial":
		if e := onlyKeys(m, "$type", "address", "dialer"); e != nil {
			return nil, e
		}
		address, _ := m["address"].(string)
		n, e := addressNode(address)
		if e != nil {
			return nil, e
		}
		if m["dialer"] == nil {
			return n, nil
		}
		n.Type = "dial"
		n.Dialer, e = outlineDialer(m["dialer"], depth+1)
		return n, e
	case "websocket":
		if e := onlyKeys(m, "$type", "url", "endpoint"); e != nil {
			return nil, e
		}
		raw, _ := m["url"].(string)
		u, e := url.Parse(raw)
		if e != nil || (u.Scheme != "wss" && u.Scheme != "https" && u.Scheme != "ws" && u.Scheme != "http") || !ValidHost(u.Hostname()) || u.User != nil || u.Fragment != "" || len(raw) > 8192 {
			return nil, errors.New("invalid Outline WebSocket URL")
		}
		if u.Scheme == "https" {
			u.Scheme = "wss"
		}
		if u.Scheme == "http" {
			u.Scheme = "ws"
		}
		n := &model.OutlineNode{Type: "websocket", URL: u.String()}
		endpoint := m["endpoint"]
		if endpoint == nil {
			port := u.Port()
			if port == "" {
				if u.Scheme == "wss" {
					port = "443"
				} else {
					port = "80"
				}
			}
			endpoint = net.JoinHostPort(u.Hostname(), port)
		}
		n.Endpoint, e = outlineEndpoint(endpoint, depth+1)
		return n, e
	default:
		return nil, errors.New("unsupported Outline endpoint type")
	}
}
func profileFromOutline(t *model.OutlineTransport) (model.Profile, error) {
	p := model.Profile{Kind: "shadowsocks", IconID: "antenna", Transport: "outline", Security: "shadowsocks", Outline: t}
	if t == nil || t.TCP == nil && t.UDP == nil {
		return p, errors.New("Outline requires at least one encrypted direction")
	}
	first := t.TCP
	if first == nil {
		first = t.UDP
	}
	endpoints := OutlineEndpoints(first)
	if len(endpoints) == 0 {
		return p, errors.New("Outline has no transport endpoint")
	}
	host, port, _ := net.SplitHostPort(endpoints[0])
	p.Server = host
	p.Port, _ = strconv.Atoi(port)
	if simpleOutline(t) {
		p.Method = t.TCP.Cipher
		p.Password = t.TCP.Secret
		p.Transport = "tcp"
		p.Outline = nil
		return p, nil
	}
	if e := supportedOutlineNode(t.TCP); e != nil {
		return p, e
	}
	return p, supportedOutlineNode(t.UDP)

}
func simpleOutline(t *model.OutlineTransport) bool {
	a, b := t.TCP, t.UDP
	return a != nil && b != nil && a.Type == "shadowsocks" && b.Type == "shadowsocks" && len(a.Prefix) == 0 && len(b.Prefix) == 0 && a.Endpoint != nil && b.Endpoint != nil && a.Endpoint.Type == "address" && b.Endpoint.Type == "address" && a.Endpoint.Address == b.Endpoint.Address && a.Cipher == b.Cipher && a.Secret == b.Secret
}

// Only physical entry hops need resolving/allowlisting. Inner destinations are
// passed through their preceding encrypted dialer and never dialled directly.
func OutlineEndpoints(n *model.OutlineNode) []string {
	if n == nil {
		return nil
	}
	switch n.Type {
	case "address":
		return []string{n.Address}
	case "dial":
		return OutlineEndpoints(n.Dialer)
	default:
		return OutlineEndpoints(n.Endpoint)
	}
}
func OutlineTransportEndpoints(t *model.OutlineTransport) []string {
	if t == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range append(OutlineEndpoints(t.TCP), OutlineEndpoints(t.UDP)...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func supportedOutlineNode(n *model.OutlineNode) error {
	if n == nil {
		return nil
	}
	if n.Type == "shadowsocks" {
		switch n.Cipher {
		case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
		default:
			return errors.New("extended Outline requires AES-GCM or ChaCha20 AEAD; Shadowsocks 2022 and XChaCha20 are unsupported")
		}
		max := 16
		if n.Cipher == "aes-128-gcm" {
			max = 8
		}
		if len(n.Prefix) > max {
			return errors.New("Outline prefix leaves insufficient random salt for this cipher")
		}
	}
	if e := supportedOutlineNode(n.Endpoint); e != nil {
		return e
	}
	return supportedOutlineNode(n.Dialer)
}

// OutlinePhysicalEndpoints describes only outermost sockets. WebSocket always
// uses TCP even when it carries packets; inner chain hops get no bypass.
func OutlinePhysicalEndpoints(t *model.OutlineTransport) map[string][]string {
	out := map[string][]string{}
	var walk func(*model.OutlineNode, string)
	walk = func(n *model.OutlineNode, protocol string) {
		if n == nil {
			return
		}
		switch n.Type {
		case "address":
			for _, old := range out[n.Address] {
				if old == protocol {
					return
				}
			}
			out[n.Address] = append(out[n.Address], protocol)
		case "websocket":
			walk(n.Endpoint, "tcp")
		case "dial":
			walk(n.Dialer, protocol)
		default:
			walk(n.Endpoint, protocol)
		}
	}
	if t != nil {
		walk(t.TCP, "tcp")
		walk(t.UDP, "udp")
	}
	return out
}
