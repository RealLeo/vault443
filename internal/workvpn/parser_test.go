package workvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Fixtures are generated locally for tests; no exported user credentials are
// kept in the source tree or fetched from an external VPN.
func fixture(t *testing.T) string {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Vault test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
	return fmt.Sprintf("client\ndev tun\nremote vpn.example.test 16743 udp\nremote-cert-tls server\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n", cert, cert, private)
}

func TestParseExportedCertificateProfile(t *testing.T) {
	source := fixture(t) + `ignore-unknown-option data-ciphers
setenv UV_ID "test client"
setenv UV_NAME example
nobind
persist-tun
cipher AES-128-CBC
data-ciphers AES-128-GCM:AES-128-CBC
auth SHA1
verb 2
mute 10
push-peer-info
ping 10
ping-restart 60
hand-window 60
server-poll-timeout 10
reneg-sec 0
sndbuf 393216
rcvbuf 393216
comp-lzo no
key-direction 1
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
` + strings.Repeat("0123456789abcdef", 32) + `
-----END OpenVPN Static key V1-----
</tls-auth>
`
	p, e := Parse("Рабочий профиль", source)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(p.ID, "ovpn-") || p.Remotes[0].Host != "vpn.example.test" || p.Remotes[0].Protocol != "udp" || p.Remotes[0].Port != 16743 {
		t.Fatalf("unexpected parsed profile: id=%s remote=%v", p.ID, p.Remotes)
	}
	if e = ValidateProfile(p); e != nil {
		t.Fatal(e)
	}
	p2, e := Parse("Different name", strings.ReplaceAll(source, "\n", "\r\n"))
	if e != nil || p.ID != p2.ID {
		t.Fatal("formatting or name changed canonical identity", e)
	}
	p2.IconID = "vault-door"
	p2.DebugLogging = true
	if e = ValidateProfile(p2); e != nil {
		t.Fatal(e)
	}
}

func TestUnsafeDirectivesNeverBypassValidation(t *testing.T) {
	source := fixture(t)
	for _, extra := range []string{
		"up /tmp/secret-script", "down /tmp/script", "plugin /tmp/p.so", "script-security 3", "config other.ovpn", "management /tmp/control unix", "mark 123", "iproute /tmp/ip", "dev-node /dev/net/tun", "daemon", "log /tmp/log", "status /tmp/status", "auth-user-pass", "askpass /tmp/password", "pkcs12 /tmp/keys", "setenv LD_PRELOAD /tmp/malicious", "setenv opt up /tmp/command", "ignore-unknown-option up\nup /tmp/command", "ignore-unknown-option data-ciphers\nscript-security 2", "ca /tmp/ca.pem", "<connection>\nremote test\n</connection>", "remote 127.0.0.1 443 tcp-client", "comp-lzo yes", "remote-cert-tls client", "dev tap",
	} {
		t.Run(strings.ReplaceAll(strings.Split(extra, "\n")[0], "/", "_"), func(t *testing.T) {
			_, e := Parse("Test", source+extra+"\n")
			if e == nil {
				t.Fatal("unsafe option accepted")
			}
			if strings.Contains(e.Error(), "secret-script") || strings.Contains(e.Error(), "malicious") {
				t.Fatal("error exposed argument")
			}
		})
	}
}

func TestCredentialValidation(t *testing.T) {
	s := fixture(t)
	other := fixture(t)
	for name, input := range map[string]string{
		"missing key":        s[:strings.Index(s, "<key>")],
		"bad key":            strings.Replace(s, "BEGIN PRIVATE KEY", "BEGIN ENCRYPTED PRIVATE KEY", 1),
		"mismatch":           s[:strings.Index(s, "<key>")] + other[strings.Index(other, "<key>"):],
		"nested":             strings.Replace(s, "<key>", "<key>\n<ca>", 1),
		"extra block":        s + "<evil>\nignored\n</evil>\n",
		"bad static key":     s + "<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n123\n-----END OpenVPN Static key V1-----\n</tls-auth>\n",
		"no peer role check": strings.Replace(s, "remote-cert-tls server\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := Parse("Test", input); e == nil {
				t.Fatal("invalid credentials accepted")
			}
		})
	}
}

func TestQuotingAndCanonicalIdentity(t *testing.T) {
	s := fixture(t)
	p, e := Parse("Test", s+"setenv UV_NAME \"hello \\\"world\\\"\" # trailing comment\n")
	if e != nil {
		t.Fatal(e)
	}
	var value string
	for _, o := range p.Options {
		if o.Key == "setenv" {
			value = o.Args[1]
		}
	}
	if value != `hello "world"` {
		t.Fatalf("incorrect quote decode %q", value)
	}
	round, e := Parse("Test", p.Source())
	if e != nil || round.ID != p.ID {
		t.Fatal("safe quoting did not round trip", e)
	}
	for _, bad := range []string{"setenv UV_NAME \"unterminated", "setenv UV_NAME bad\\nvalue", "setenv UV_NAME a\x00b", "setenv UV_NAME a\nsetenv UV_NAME b"} {
		if _, e := Parse("Test", s+bad+"\n"); e == nil {
			t.Fatalf("accepted bad quoted data: %q", bad)
		}
	}
	a, e := Parse("Test", s+"auth SHA1\ncipher AES-128-CBC\n")
	if e != nil {
		t.Fatal(e)
	}
	b, e := Parse("Renamed", s+"cipher AES-128-CBC\nauth SHA1\n")
	if e != nil || a.ID != b.ID {
		t.Fatal("order-independent options changed identity", e)
	}
	if _, e = Parse("Test", strings.Repeat("#", MaxBytes+1)); e == nil {
		t.Fatal("oversized input accepted")
	}
}

func TestRemoteDefaultsAndExplicitRoutes(t *testing.T) {
	s := strings.Replace(fixture(t), "remote vpn.example.test 16743 udp", "remote vpn.example.test\nproto tcp-client\nrport 443\nremote vpn2.example.test 1194 udp", 1)
	p, e := Parse("Test", s+"route 192.168.100.15\nroute-ipv6 fd00::/64\ndhcp-option DOMAIN example.test\ndhcp-option DNS 192.168.100.1\n")
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Remotes) != 2 || p.Remotes[0].Port != 443 || p.Remotes[0].Protocol != "tcp-client" || p.Remotes[1].Protocol != "udp" {
		t.Fatal("wrong remote defaults")
	}
	for _, bad := range []string{"route bad.example.test", "route 10.0.0.0 255.0.0.0 net_gateway", "route 10.0.0.0 255.0.0.0 remote_host", "route 10.0.0.1 255.1.255.0", "route-ipv6 bad/24", "dhcp-option DNS arbitrary.test", "dhcp-option DOMAIN /etc/passwd"} {
		if _, e := Parse("Test", s+bad+"\n"); e == nil {
			t.Fatal("invalid route/DNS accepted")
		}
	}
}

func TestDNSPreferenceOrderPreserved(t *testing.T) {
	p, e := Parse("Ordered DNS", fixture(t)+"dhcp-option DNS 10.0.0.2\ndhcp-option DNS 10.0.0.1\n")
	if e != nil {
		t.Fatal(e)
	}
	var addresses []string
	for _, o := range p.Options {
		if o.Key == "dhcp-option" && o.Args[0] == "DNS" {
			addresses = append(addresses, o.Args[1])
		}
	}
	if strings.Join(addresses, ",") != "10.0.0.2,10.0.0.1" {
		t.Fatal("DNS preference changed during import")
	}
}

func TestRenegotiationIntervalPreserved(t *testing.T) {
	for _, seconds := range []string{"0", "2592000", "2147483647"} {
		p, e := Parse("Long-lived certificate", fixture(t)+"reneg-sec "+seconds+"\n")
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, o := range p.Options {
			if o.Key == "reneg-sec" && o.Args[0] == seconds {
				found = true
			}
		}
		if !found {
			t.Fatal("renegotiation interval changed")
		}
	}
	if _, e := Parse("Overflow", fixture(t)+"reneg-sec 2147483648\n"); e == nil {
		t.Fatal("signed OpenVPN integer overflow accepted")
	}
}
