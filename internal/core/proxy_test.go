package core

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"vault443/internal/model"
)

func TestNewProxyOutboundMatrix(t *testing.T) {
	var cases []model.Profile
	for _, transport := range []string{"tcp", "ws", "grpc", "xhttp"} {
		p := testProfile()
		p.Kind = "trojan"
		p.UUID = ""
		p.Password = "synthetic-only"
		p.Transport = transport
		p.Path = "/synthetic"
		cases = append(cases, p)
	}
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		p := model.Profile{Kind: "shadowsocks", Method: method, Password: "synthetic-only", Server: "example.net", Port: 443}
		if strings.HasPrefix(method, "2022-") {
			n := 32
			if strings.Contains(method, "128") {
				n = 16
			}
			p.Password = base64.StdEncoding.EncodeToString(make([]byte, n))
			if strings.Contains(method, "aes") {
				p.Password += ":" + p.Password
			}
		}
		cases = append(cases, p)
	}
	cases = append(cases, model.Profile{Kind: "shadowsocks", Outline: &model.OutlineTransport{TCP: &model.OutlineNode{Type: "shadowsocks"}}})
	for _, p := range cases {
		t.Run(p.Protocol()+"-"+p.Method+p.Transport, func(t *testing.T) {
			o := testOptions()
			o.LocalPort = 12345
			o.LocalUser = "synthetic"
			o.LocalPassword = strings.Repeat("a", 64)
			b, e := Build(p, o)
			if e != nil {
				t.Fatal(e)
			}
			var config map[string]any
			_ = json.Unmarshal(b, &config)
			out := config["outbounds"].([]any)[0].(map[string]any)
			if p.Outline != nil {
				if out["protocol"] != "socks" || !strings.Contains(string(b), "127.0.0.1") {
					t.Fatal("Outline bypassed private adapter")
				}
			} else if out["protocol"] != p.Protocol() {
				t.Fatal("wrong outbound protocol")
			}
			for _, forbidden := range []string{"freedom", "allowInsecure\": true", "+local", "plugin"} {
				if strings.Contains(string(b), forbidden) {
					t.Fatal("unsafe outbound")
				}
			}
			if binary := os.Getenv("XRAY_TEST_BINARY"); binary != "" {
				file := filepath.Join(t.TempDir(), "synthetic.json")
				_ = os.WriteFile(file, b, 0600)
				data, e := exec.Command(binary, "run", "-test", "-config", file).CombinedOutput()
				if e != nil {
					t.Fatalf("pinned core rejected %s: %s", p.Protocol(), data)
				}
			}
		})
	}
}
