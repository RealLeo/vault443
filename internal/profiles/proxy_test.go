package profiles

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestTrojanTransportsAndCredentialDelimiters(t *testing.T) {
	for _, transport := range []string{"tcp", "raw", "ws", "grpc", "xhttp"} {
		link := "trojan://" + url.User("p@ss:/?+#%✓").String() + "@[2001:db8::1]:443?type=" + transport + "&sni=tls.example&fp=firefox&alpn=h2%2Chttp%2F1.1"
		p, e := Parse(link)
		if e != nil {
			t.Fatal(e)
		}
		if p.Protocol() != "trojan" || p.Password != "p@ss:/?+#%✓" || p.UUID != "" || p.Security != "tls" || len(p.ALPN) != 2 {
			t.Fatal("Trojan data lost")
		}
	}
	for _, q := range []string{"security=reality", "flow=xtls-rprx-vision", "allowInsecure=1", "plugin=x", "type=kcp", "security=none", "sni=a&sni=b"} {
		if _, e := Parse("trojan://secret@example.net:443?" + q); e == nil {
			t.Fatalf("accepted %s", q)
		}
	}
}
func TestShadowsocksNormalizationAndCipherMatrix(t *testing.T) {
	password := "a:b@c/?+#%✓"
	plain := "ss://" + url.UserPassword("aes-256-gcm", password).String() + "@EXAMPLE.net:443#One"
	b64 := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:"+password)) + "@example.net:443/#Two"
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:"+password+"@example.net:443")) + "#Three"
	id := ""
	for _, raw := range []string{plain, b64, legacy} {
		p, e := Parse(raw)
		if e != nil {
			t.Fatal(e)
		}
		if p.Password != password {
			t.Fatal("password changed")
		}
		if id != "" && id != p.ID {
			t.Fatal("equivalent links have different IDs")
		}
		id = p.ID
	}
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		password := "synthetic"
		if strings.HasPrefix(method, "2022-") {
			size := 32
			if strings.Contains(method, "128") {
				size = 16
			}
			password = base64.StdEncoding.EncodeToString(make([]byte, size))
			if strings.Contains(method, "aes") {
				password = password + ":" + password
			}
		}
		if _, e := Parse("ss://" + url.UserPassword(method, password).String() + "@[2001:db8::1]:8388"); e != nil {
			t.Fatalf("%s: %v", method, e)
		}
	}
	for _, raw := range []string{"ss://aes-128-cfb:secret@example.net:1", "ss://aes-256-gcm:p@example.net:1?plugin=evil", "ss://2022-blake3-aes-128-gcm:bad@example.net:1", "ss://aes-128-gcm:p@example.net:1?prefix=abcdefghijklmnop"} {
		if _, e := Parse(raw); e == nil {
			t.Fatalf("accepted unsupported %s", raw)
		}
	}
}
func TestMixedSubscriptionAndPublicPreview(t *testing.T) {
	raw := uri("security=tls") + "\ntrojan://secret@example.net:443\nss://aes-256-gcm:password@example.net:8388"
	for _, text := range []string{raw, base64.StdEncoding.EncodeToString([]byte(raw))} {
		p := PreviewText(text, nil)
		if len(p.Profiles) != 3 || len(p.Errors) != 0 {
			t.Fatalf("mixed import: %+v", p.Errors)
		}
		data, _ := json.Marshal(p)
		for _, secret := range []string{"secret", "password", testID} {
			if strings.Contains(string(data), secret) {
				t.Fatal("secret escaped preview")
			}
		}
	}
	p := PreviewText("ssconf://example.net/private", nil)
	if len(p.Profiles) != 0 {
		t.Fatal("dynamic keys are not subscription entries")
	}
}
func TestOutlineGraphsLimitsAndStableIdentity(t *testing.T) {
	const source = "https://source.example/private/key"
	docs := []string{`ss://aes-256-gcm:one@server.example:1234`, `{"server":"server.example","server_port":1234,"method":"aes-256-gcm","password":"two"}`, `transport:
  $type: tcpudp
  tcp:
    <<: &shared
      $type: shadowsocks
      endpoint: server.example:1234
      cipher: aes-256-gcm
      secret: three
    prefix: "POST "
  udp: *shared
`}
	id := ""
	for _, doc := range docs {
		p, e := ParseOutline(doc, source, "Synthetic")
		if e != nil {
			t.Fatal(e)
		}
		if id != "" && p.ID != id {
			t.Fatal("source identity changed")
		}
		id = p.ID
	}
	doc := `transport:
  $type: tcpudp
  tcp:
    $type: shadowsocks
    cipher: aes-256-gcm
    secret: exit-secret
    endpoint:
      $type: dial
      address: exit.example:8388
      dialer:
        $type: first-supported
        options:
        - {$type: unsupported}
        - $type: shadowsocks
          cipher: chacha20-ietf-poly1305
          secret: entry-secret
          endpoint: {$type: websocket, url: "wss://entry.example/secret", endpoint: "cdn.example:443"}
`
	p, e := ParseOutline(doc, source, "Chain")
	if e != nil {
		t.Fatal(e)
	}
	physical := OutlineTransportEndpoints(p.Outline)
	if len(physical) != 1 || physical[0] != "cdn.example:443" || p.Outline.UDP != nil {
		t.Fatal("inner destination became physical endpoint or missing UDP became direct")
	}
	for _, bad := range []string{`reporter: {url: "https://evil.example"}`, `transport: {$type: tcpudp}`, `transport: {$type: tcpudp, tcp: {$type: direct}}`, `a: &a [*a]`, `server: a
server: b`, strings.Repeat("a", MaxBytes+1)} {
		if _, e := ParseOutline(bad, source, "Bad"); e == nil {
			t.Fatal("invalid Outline accepted")
		}
	}
	if _, e := ParseOutline(`error: {message: "Quota exceeded"}`, source, "Expired"); e == nil {
		t.Fatal("provider denial accepted")
	}
}
