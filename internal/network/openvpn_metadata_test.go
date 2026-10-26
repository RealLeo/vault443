package network

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenVPNNumericMetadataOnly(t *testing.T) {
	config := `client
remote "203.0.113.2" 443
remote vpn.example.com 443
remote 2001:db8::2 1194 udp6
proto tcp-client
auth-user-pass /private/credentials
up /untrusted/script
<key>
remote 203.0.113.99 443
</key>
`
	reads := 0
	endpoints := openVPNEndpoints([]string{"--config", "/root/test.conf", "--remote", "203.0.113.3", "1194", "udp"}, func(path string) ([]byte, error) {
		reads++
		if path != "/root/test.conf" {
			t.Fatal("attempted to read a non-config path")
		}
		return []byte(config), nil
	})
	if reads != 1 || len(endpoints) != 3 {
		t.Fatalf("unexpected metadata count: %d", len(endpoints))
	}
	if endpoints[0].Address != "203.0.113.2" || endpoints[0].Protocol != "tcp" || endpoints[1].Protocol != "udp" || endpoints[2].Address != "203.0.113.3" {
		t.Fatal("numeric transport settings not preserved")
	}
	for _, config := range []string{"config /another.conf", "<connection>\nremote 203.0.113.5\n</connection>"} {
		if out := openVPNEndpoints([]string{"--config", "/x"}, func(string) ([]byte, error) { return []byte(config), nil }); len(out) != 0 {
			t.Fatal("ambiguous nested options accepted")
		}
	}
}

func TestOpenVPNConfigRequiresSafeRootRegularFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	if e := os.WriteFile(p, []byte("remote 203.0.113.3"), 0600); e != nil {
		t.Fatal(e)
	}
	_, e := readRootConfig(p)
	if os.Geteuid() == 0 && e != nil {
		t.Fatal(e)
	}
	if os.Geteuid() != 0 && e == nil {
		t.Fatal("non-root configuration accepted")
	}
	if e := os.Chmod(p, 0666); e != nil {
		t.Fatal(e)
	}
	if _, e := readRootConfig(p); e == nil {
		t.Fatal("writable configuration accepted")
	}
	link := p + ".link"
	if e := os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e := readRootConfig(link); e == nil {
		t.Fatal("symlink configuration followed")
	}
}
