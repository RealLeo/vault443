package workvpn

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode/utf8"
)

// ParseWork accepts only self-contained documents. Import never resolves names,
// follows URLs, reads referenced files or executes a user-provided configuration.
func ParseWork(name, source string) ([]Profile, error) {
	if len(source) == 0 || len(source) > MaxBytes {
		return nil, errors.New("work profile exceeds 1 MiB or is empty")
	}
	source = strings.TrimSpace(strings.TrimPrefix(source, "\ufeff"))
	if strings.HasPrefix(source, "vpn://") {
		var result []Profile
		for _, line := range strings.Split(source, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !strings.HasPrefix(line, "vpn://") {
				return nil, errors.New("place each Amnezia key on a separate line")
			}
			items, err := parseAmnezia(name, line)
			if err != nil {
				return nil, err
			}
			if len(result)+len(items) > 32 {
				return nil, errors.New("at most 32 Amnezia profiles may be imported together")
			}
			result = append(result, items...)
		}
		return result, nil
	}
	if strings.Contains(source, "[Interface]") {
		p, e := ParseWireGuard(name, source)
		if e != nil {
			return nil, e
		}
		return []Profile{p}, nil
	}
	p, e := Parse(name, source)
	if e != nil {
		return nil, e
	}
	return []Profile{p}, nil
}

func decodeAmnezia(source string) ([]byte, error) {
	encoded := strings.TrimPrefix(source, "vpn://")
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		decoded, err = base64.URLEncoding.Strict().DecodeString(encoded)
	}
	if err != nil || len(decoded) == 0 || len(decoded) > MaxBytes {
		return nil, errors.New("invalid or oversized Amnezia key encoding")
	}
	if bytes.HasPrefix(bytes.TrimSpace(decoded), []byte("{")) {
		return decoded, nil
	}
	if len(decoded) < 6 {
		return nil, errors.New("invalid Amnezia compressed document")
	}
	size := binary.BigEndian.Uint32(decoded[:4])
	if size == 0 || size > MaxBytes {
		return nil, errors.New("Amnezia decoded document exceeds 1 MiB")
	}
	input := bytes.NewReader(decoded[4:])
	r, err := zlib.NewReader(input)
	if err != nil {
		return nil, errors.New("invalid Amnezia compressed document")
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil || len(data) != int(size) || input.Len() != 0 {
		return nil, errors.New("invalid Amnezia compressed document size or trailing data")
	}
	return data, nil
}

// jsonObject checks duplicate keys and depth before decoding. Unknown credential
// wrappers must not exploit JSON's usual last-wins duplicate-key behavior.
func jsonObject(data []byte) (map[string]json.RawMessage, error) {
	if len(data) == 0 || len(data) > MaxBytes || !utf8.Valid(data) {
		return nil, errors.New("invalid Amnezia JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("depth")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := k.(string)
				if !ok || keys[key] {
					return errors.New("duplicate")
				}
				keys[key] = true
				if len(keys) > 4096 {
					return errors.New("size")
				}
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for i := 0; d.More(); i++ {
				if i >= 4096 {
					return errors.New("size")
				}
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("delimiter")
		}
		_, e = d.Token()
		return e
	}
	if e := walk(0); e != nil {
		return nil, errors.New("invalid, duplicate or excessive Amnezia JSON fields")
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, errors.New("invalid trailing Amnezia JSON")
	}
	var out map[string]json.RawMessage
	if e := json.Unmarshal(data, &out); e != nil || out == nil {
		return nil, errors.New("Amnezia document must be an object")
	}
	return out, nil
}
func jsonString(m map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(m[key], &value)
	return value
}
func jsonScalar(m map[string]json.RawMessage, key string) (string, error) {
	if len(m[key]) == 0 || string(m[key]) == "null" {
		return "", nil
	}
	var value string
	if json.Unmarshal(m[key], &value) == nil {
		if strings.ContainsAny(value, "\x00\r\n") {
			return "", errors.New("invalid Amnezia scalar")
		}
		return value, nil
	}
	var number json.Number
	if json.Unmarshal(m[key], &number) == nil {
		return number.String(), nil
	}
	var boolean bool
	if json.Unmarshal(m[key], &boolean) == nil {
		if boolean {
			return "true", nil
		}
		return "false", nil
	}
	return "", errors.New("invalid Amnezia scalar")
}

func parseAmnezia(name, source string) ([]Profile, error) {
	raw, e := decodeAmnezia(source)
	if e != nil {
		return nil, e
	}
	root, e := jsonObject(raw)
	if e != nil {
		return nil, e
	}
	for _, key := range []string{"api_key", "apiConfig", "auth_data", "configVersion", "userName", "password"} {
		if value := root[key]; len(value) > 0 && string(value) != `""` && string(value) != "null" {
			return nil, errors.New("Amnezia API subscriptions and administrative access keys are unsupported; export a client configuration")
		}
	}
	var containers []json.RawMessage
	if json.Unmarshal(root["containers"], &containers) != nil || len(containers) == 0 || len(containers) > 32 {
		return nil, errors.New("Amnezia key contains no supported client containers")
	}
	var output []Profile
	for i, rawContainer := range containers {
		container, e := jsonObject(rawContainer)
		if e != nil {
			return nil, e
		}
		kind := jsonString(container, "container")
		field := ""
		switch kind {
		case "amnezia-awg":
			field = "awg"
		case "amnezia-wireguard":
			field = "wireguard"
		default:
			return nil, fmt.Errorf("Amnezia container %d uses an unsupported protocol", i+1)
		}
		protocol, e := jsonObject(container[field])
		if e != nil {
			return nil, errors.New("invalid Amnezia client protocol object")
		}
		last := protocol["last_config"]
		var text string
		if json.Unmarshal(last, &text) == nil {
			last = json.RawMessage(text)
		}
		config, e := jsonObject(last)
		if e != nil {
			return nil, errors.New("Amnezia key has no complete client configuration")
		}
		if e = validateAmneziaProtocolMetadata(protocol, config, field == "awg"); e != nil {
			return nil, e
		}
		native, e := amneziaNative(root, protocol, config)
		if e != nil {
			return nil, e
		}
		profileName := name
		if description := jsonString(root, "description"); description != "" {
			profileName = description
		}
		if len(containers) > 1 {
			profileName = fmt.Sprintf("%s %d", profileName, i+1)
		}
		p, e := parseWireGuard(profileName, native, field == "awg")
		if e != nil {
			return nil, e
		}
		output = append(output, p)
	}
	return output, nil
}

func validateAmneziaProtocolMetadata(protocol, config map[string]json.RawMessage, awg bool) error {
	// The official exporter uses protocol_version "1.5", "2" and "3.1".
	// Metadata cannot silently request another transport or a future protocol
	// while its native portion happens to resemble a supported configuration.
	version := ""
	for _, object := range []map[string]json.RawMessage{protocol, config} {
		transport, err := jsonScalar(object, "transport_proto")
		if err != nil || transport != "" && strings.ToLower(transport) != "udp" {
			return errors.New("unsupported Amnezia transport_proto; client WireGuard requires UDP")
		}
		v, err := jsonScalar(object, "protocol_version")
		if err != nil {
			return errors.New("invalid Amnezia protocol_version")
		}
		switch v {
		case "1.0":
			v = "1"
		case "2.0":
			v = "2"
		case "3.0":
			v = "3"
		}
		if v != "" && (!awg && v != "1" || awg && !oneOf(v, "1", "1.5", "2", "3", "3.1")) {
			return errors.New("unsupported Amnezia protocol_version; supported generations end at 3.1")
		}
		if version != "" && v != "" && version != v {
			return errors.New("Amnezia export contains conflicting protocol_version settings")
		}
		if v != "" {
			version = v
		}
	}
	return nil
}

func amneziaNative(root, protocol, config map[string]json.RawMessage) (string, error) {
	for key := range config {
		if !oneOf(key, AWGParameterNames...) && !oneOf(key, "config", "hostName", "port", "client_ip", "client_priv_key", "client_pub_key", "server_pub_key", "psk_key", "clientId", "allowed_ips", "persistent_keep_alive", "mtu", "transport_proto", "protocol_version") {
			return "", errors.New("unsupported Amnezia client configuration field")
		}
	}
	for key := range protocol {
		if !oneOf(key, AWGParameterNames...) && !oneOf(key, "last_config", "port", "transport_proto", "protocol_version", "subnet_address", "subnet_cidr", "isThirdPartyConfig") {
			return "", errors.New("unsupported Amnezia protocol configuration field")
		}
	}
	native := jsonString(config, "config")
	// The exported native configuration is authoritative. Supplement fields that
	// Amnezia keeps only in last_config, but reject conflicting copies explicitly.
	if native == "" {
		return "", errors.New("Amnezia export lacks a ready native client configuration")
	}
	for token, key := range map[string]string{"$PRIMARY_DNS": "dns1", "$SECONDARY_DNS": "dns2"} {
		if strings.Contains(native, token) {
			value := jsonString(root, key)
			if value == "" {
				return "", errors.New("Amnezia export has unresolved DNS placeholders")
			}
			native = strings.ReplaceAll(native, token, value)
		}
	}
	if strings.Contains(native, "$") {
		return "", errors.New("Amnezia export has unresolved configuration placeholders")
	}
	interfaceFields, peerFields := map[string]string{}, map[string]string{}
	section := ""
	peerCount := 0
	for _, raw := range strings.Split(native, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "[Interface]" {
			section = "interface"
			continue
		}
		if line == "[Peer]" {
			section = "peer"
			peerCount++
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if section == "interface" {
			interfaceFields[key] = value
		} else if section == "peer" {
			peerFields[key] = value
		}
	}
	var insertInterface, insertPeer []string
	merge := func(key, value string, target map[string]string, additions *[]string) error {
		if value == "" {
			return nil
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return errors.New("invalid Amnezia configuration field")
		}
		if old, exists := target[key]; exists {
			if old != value {
				// Numeric/boolean AWG spellings may differ without differing settings.
				if a, e := normalizeAWG(key, old); e == nil {
					if b, e := normalizeAWG(key, value); e == nil && a == b {
						return nil
					}
				}
				return fmt.Errorf("Amnezia export contains conflicting %s settings", key)
			}
			return nil
		}
		*additions = append(*additions, key+" = "+value)
		target[key] = value
		return nil
	}
	for _, key := range AWGParameterNames {
		value, e := jsonScalar(config, key)
		if e != nil {
			return "", e
		}
		if value == "" {
			value, e = jsonScalar(protocol, key)
			if e != nil {
				return "", e
			}
		}
		if e = merge(key, value, interfaceFields, &insertInterface); e != nil {
			return "", e
		}
	}
	for _, pair := range [][2]string{{"mtu", "MTU"}, {"client_priv_key", "PrivateKey"}, {"client_ip", "Address"}} {
		value, e := jsonScalar(config, pair[0])
		if e != nil {
			return "", e
		}
		// Address strings may differ by harmless comma spacing or omitted /32.
		if pair[1] == "Address" && interfaceFields["Address"] != "" {
			continue
		}
		if e = merge(pair[1], value, interfaceFields, &insertInterface); e != nil {
			return "", e
		}
	}
	if peerCount == 1 {
		for _, pair := range [][2]string{{"server_pub_key", "PublicKey"}, {"psk_key", "PresharedKey"}, {"persistent_keep_alive", "PersistentKeepalive"}} {
			value, e := jsonScalar(config, pair[0])
			if e != nil {
				return "", e
			}
			if e = merge(pair[1], value, peerFields, &insertPeer); e != nil {
				return "", e
			}
		}
		if peerFields["Endpoint"] == "" {
			host, e := jsonScalar(config, "hostName")
			if e != nil {
				return "", e
			}
			port, e := jsonScalar(config, "port")
			if e != nil {
				return "", e
			}
			if host != "" && port != "" {
				insertPeer = append(insertPeer, "Endpoint = "+net.JoinHostPort(host, port))
			}
		}
	}
	if len(insertInterface) > 0 {
		native = strings.Replace(native, "[Interface]", "[Interface]\n"+strings.Join(insertInterface, "\n"), 1)
	}
	if len(insertPeer) > 0 {
		native = strings.Replace(native, "[Peer]", "[Peer]\n"+strings.Join(insertPeer, "\n"), 1)
	}
	return native, nil
}
