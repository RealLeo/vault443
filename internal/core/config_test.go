package core

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"vault443/internal/model"
)

func testOptions() Options {
	return Options{Interface: "vault4430", Gateway4: netip.MustParsePrefix("198.18.0.1/30"), Gateway6: netip.MustParsePrefix("fd56:4c54::1/64"), DNSAddress: netip.MustParseAddr("198.18.0.2"), Endpoint: netip.MustParseAddr("203.0.113.20"), Uplink: "eth0", Mark: 0x564c5401}
}
func testProfile() model.Profile {
	return model.Profile{ID: "test", Server: "example.com", Port: 443, UUID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Transport: "tcp", Security: "tls", SNI: "example.com"}
}

func TestConfigurationSecurityBoundaries(t *testing.T) {
	b, e := Build(testProfile(), testOptions())
	if e != nil {
		t.Fatal(e)
	}
	var c map[string]any
	if e = json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"autoSystemRoutingTable", "freedom", "allowInsecure\": true", "+local"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("unsafe setting %s", s)
		}
	}
	if !strings.Contains(string(b), "203.0.113.20") {
		t.Fatal("endpoint was not pinned")
	}
	out := c["outbounds"].([]any)[0].(map[string]any)
	sock := out["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
	if uint32(sock["mark"].(float64)) != testOptions().Mark {
		t.Fatal("outer traffic unmarked")
	}
}

func TestUnsupportedSettingsFail(t *testing.T) {
	for _, change := range []func(*model.Profile){func(p *model.Profile) { p.Transport = "evil" }, func(p *model.Profile) { p.Security = "none" }, func(p *model.Profile) { p.Flow = "unknown" }, func(p *model.Profile) { p.Transport = "ws"; p.Flow = "xtls-rprx-vision" }, func(p *model.Profile) { p.Transport = "grpc"; p.Mode = "unknown" }} {
		p := testProfile()
		change(&p)
		if _, e := Build(p, testOptions()); e == nil {
			t.Fatalf("accepted invalid profile %+v", p)
		}
	}
}

func TestPinnedXrayAcceptsGeneratedConfigs(t *testing.T) {
	path := os.Getenv("XRAY_TEST_BINARY")
	if path == "" {
		t.Skip("set XRAY_TEST_BINARY for offline pinned-core validation")
	}
	for _, transport := range []string{"tcp", "ws", "grpc", "xhttp"} {
		for _, security := range []string{"tls", "reality"} {
			if transport == "ws" && security == "reality" {
				continue
			}
			t.Run(transport+"-"+security, func(t *testing.T) {
				p := testProfile()
				p.Transport = transport
				p.Security = security
				p.Path = "/tunnel"
				p.ServiceName = "example"
				p.PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				p.ShortID = "0123456789abcdef"
				p.Fingerprint = "chrome"
				if transport == "grpc" {
					p.Mode = "multi"
				}
				if transport == "xhttp" {
					p.Mode = "packet-up"
				}
				b, e := Build(p, testOptions())
				if e != nil {
					t.Fatal(e)
				}
				file := filepath.Join(t.TempDir(), "test.json")
				if e = os.WriteFile(file, b, 0600); e != nil {
					t.Fatal(e)
				}
				cmd := exec.Command(path, "run", "-test", "-config", file)
				output, e := cmd.CombinedOutput()
				if e != nil {
					t.Fatalf("core validation failed: %s", output)
				}
			})
		}
	}
	t.Run("vision-udp443", func(t *testing.T) {
		p := testProfile()
		p.Flow = "xtls-rprx-vision-udp443"
		b, e := Build(p, testOptions())
		if e != nil {
			t.Fatal(e)
		}
		file := filepath.Join(t.TempDir(), "test.json")
		if e = os.WriteFile(file, b, 0600); e != nil {
			t.Fatal(e)
		}
		output, e := exec.Command(path, "run", "-test", "-config", file).CombinedOutput()
		if e != nil {
			t.Fatalf("core validation failed: %s", output)
		}
	})
}

func TestPrivateConfigurationPermissions(t *testing.T) {
	d := filepath.Join(t.TempDir(), "run")
	p, e := WriteConfig(d, []byte(`{"test":true}`))
	if e != nil {
		t.Fatal(e)
	}
	fi, e := os.Stat(p)
	if e != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("private config permissions incorrect")
	}
}
