package profiles

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"testing"
)

const testID = "11111111-2222-4333-8444-555555555555"

func uri(query string) string { return "vless://" + testID + "@vpn.example:443?" + query + "#Test" }
func TestTransportMatrix(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct{ name, q, transport string }{
		{"TLS", "security=tls", "tcp"},
		{"REALITY", "type=raw&security=reality&pbk=" + key + "&sid=abcd&flow=xtls-rprx-vision", "tcp"},
		{"WebSocket", "type=ws&security=tls&host=cdn.example&path=%2Fws", "ws"},
		{"gRPC", "type=grpc&security=tls&serviceName=tunnel&authority=cdn.example&mode=multi", "grpc"},
		{"XHTTP", "type=xhttp&security=tls&path=%2Fx&mode=stream-up", "xhttp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(uri(tc.q))
			if err != nil {
				t.Fatal(err)
			}
			if p.Transport != tc.transport || p.UUID != testID {
				t.Fatalf("incorrect result %+v", p)
			}
			if tc.name == "gRPC" && (p.Host != "cdn.example" || p.Mode != "multi") {
				t.Fatal("gRPC authority or mode lost")
			}
		})
	}
}
func TestSemanticOptionsNeverSilentlyDropped(t *testing.T) {
	for _, q := range []string{
		"security=none", "security=tls&allowInsecure=1", "security=tls&security=reality", "security=tls&encryption=mlkem768", "type=ws&security=tls&flow=xtls-rprx-vision", "type=xhttp&security=tls&extra=%7B%7D", "type=tcp&security=tls&headerType=http", "type=ws&security=tls&serviceName=x", "type=grpc&security=tls&path=%2Fx", "security=reality&pbk=bad", "security=tls&sid=abcd", "security=tls&host=cdn.example", "security=tls&fp=unknown", "type=xhttp&security=tls&mode=unknown", "security=tls&unknown=SUPERSECRET",
	} {
		if _, err := Parse(uri(q)); err == nil {
			t.Errorf("accepted %s", q)
		} else if strings.Contains(err.Error(), "SUPERSECRET") {
			t.Fatal("error exposed query value")
		}
	}
}

func TestREALITYMLKEMCompatibilityHint(t *testing.T) {
	// Same shape as a current 3x-ui link, using only synthetic credentials.
	query := "encryption=none&flow=xtls-rprx-vision&fp=firefox&pbk=" +
		base64.RawURLEncoding.EncodeToString(make([]byte, 32)) +
		"&security=reality&sid=a1b2&sni=www.example.com&spx=%2Ftest-path&type=tcp"
	baseline, err := Parse(uri(query))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"true", "1", "True", "TRUE", "t", "T"} {
		p, err := Parse(uri(query + "&support-x25519mlkem768=" + value))
		if err != nil {
			t.Fatalf("valid ML-KEM hint %q rejected: %v", value, err)
		}
		if p.ID != baseline.ID || p.Fingerprint != "firefox" || p.SpiderX != "/test-path" || p.Flow != "xtls-rprx-vision" {
			t.Fatal("compatibility hint changed connection identity or fields")
		}
	}
	for _, fp := range []string{"", "chrome", "safari"} {
		q := strings.Replace(query, "fp=firefox&", "", 1)
		if fp != "" {
			q += "&fp=" + fp
		}
		if _, err := Parse(uri(q + "&support-x25519mlkem768=true")); err != nil {
			t.Fatalf("supported fingerprint %q rejected: %v", fp, err)
		}
	}
	for _, q := range []string{
		query + "&support-x25519mlkem768=",
		query + "&support-x25519mlkem768=SECRET_INVALID_VALUE",
		query + "&support-x25519mlkem768=false",
		query + "&support-x25519mlkem768=0",
		query + "&support-x25519mlkem768=true&support-x25519mlkem768=true",
		"security=tls&support-x25519mlkem768=true",
		strings.Replace(query, "fp=firefox", "fp=ios", 1) + "&support-x25519mlkem768=true",
		strings.Replace(query, "fp=firefox", "fp=random", 1) + "&support-x25519mlkem768=true",
		query + "&support-x25519mlkem768=true&unknown=SECRET_INVALID_VALUE",
	} {
		if _, err := Parse(uri(q)); err == nil {
			t.Fatal("accepted incompatible or invalid hint")
		} else if strings.Contains(err.Error(), "SECRET_INVALID_VALUE") {
			t.Fatal("error exposed an untrusted value")
		}
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(uri(query) + "\n" + uri(query+"&support-x25519mlkem768=true")))
	preview := PreviewText(encoded, nil)
	if len(preview.Errors) != 0 || len(preview.Profiles) != 2 || !preview.Profiles[1].Duplicate {
		t.Fatal("subscription preview did not deduplicate the compatibility hint")
	}
}
func TestIPv6AndPortValidation(t *testing.T) {
	p, err := Parse("vless://" + testID + "@[2001:db8::1]:8443?security=tls&sni=example.com#IPv6")
	if err != nil || p.Server != "2001:db8::1" {
		t.Fatalf("%+v %v", p, err)
	}
	for _, s := range []string{"vless://" + testID + "@vpn.example:0?security=tls", "vless://" + testID + "@vpn.example:65536?security=tls", "vless://" + testID + "@vpn.example:443/path?security=tls", "vless://" + testID + ":password@vpn.example:443?security=tls"} {
		if _, err := Parse(s); err == nil {
			t.Fatalf("accepted malformed URI %q", s)
		}
	}
}
func TestCanonicalDedupAndNoSecretInPreview(t *testing.T) {
	a := uri("security=tls&type=raw")
	b := strings.Replace(uri("type=tcp&security=tls"), "#Test", "#Renamed", 1)
	preview := PreviewText(a+"\n"+b+"\nmalformed", nil)
	if len(preview.Profiles) != 2 || !preview.Profiles[1].Duplicate || len(preview.Errors) != 1 || preview.Errors[0].Line != 3 {
		t.Fatalf("unexpected preview %+v", preview)
	}
	data, _ := json.Marshal(preview)
	if strings.Contains(string(data), testID) || strings.Contains(string(data), "security=tls") {
		t.Fatal("preview leaked credentials or original link")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(a + "\n" + b))
	decoded := PreviewText(encoded, nil)
	if len(decoded.Profiles) != 2 || !decoded.Profiles[1].Duplicate {
		t.Fatal("base64 subscription not decoded")
	}
}
func TestBoundsAndControlCharacters(t *testing.T) {
	if p := PreviewText(strings.Repeat("x", MaxBytes+1), nil); len(p.Errors) != 1 || len(p.Profiles) != 0 {
		t.Fatal("unbounded import")
	}
	if _, err := Parse(uri("security=tls") + url.PathEscape("\n")); err == nil {
		t.Fatal("newline in name accepted")
	}
	if _, err := Name("\u202eabc"); err == nil {
		t.Fatal("bidi override accepted")
	}
}
func TestSubscriptionURLBoundaries(t *testing.T) {
	for _, raw := range []string{"http://example.com/sub", "https://name:token@example.com/sub", "https://localhost/sub", "https://127.0.0.1/sub", "https://[::1]/sub", "https://10.0.0.1/sub", "https://100.64.0.1/sub", "https://example.com/sub#token"} {
		if _, err := SubscriptionURL(raw); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if _, err := SubscriptionURL("https://provider.example/sub?token=sensitive"); err != nil {
		t.Fatal(err)
	}
	if publicIP(net.ParseIP("192.168.3.5")) || publicIP(net.ParseIP("fe80::1")) {
		t.Fatal("private DNS answer would be dialled")
	}
}
func FuzzParse(f *testing.F) {
	f.Add(uri("security=tls"))
	f.Add("vless://invalid")
	f.Add(strings.Repeat("%", 32))
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := Parse(raw)
		if err == nil {
			if p.Port < 1 || p.Port > 65535 || p.ID == "" || !uuidPattern.MatchString(p.UUID) {
				t.Fatal("invalid accepted profile")
			}
			b, e := json.Marshal(p)
			if e != nil || len(b) == 0 {
				t.Fatal("cannot serialize accepted profile")
			}
		}
	})
}
