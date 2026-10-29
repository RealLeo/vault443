package ipc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"vault443/internal/journal"
	"vault443/internal/worknet"
	"vault443/internal/workvpn"
)

// This fixture only changes in-memory status. It neither resolves the reserved
// .example hosts nor launches OpenVPN, touches routes, or contacts the host bus.
type guiWorkRuntime struct{ inertWorkRuntime }

func (*guiWorkRuntime) Run(ctx context.Context, _ uint32, p workvpn.Profile, _ *journal.Session, notify func(worknet.Status)) error {
	now := time.Now().UnixMilli()
	if len(p.Remotes) > 0 && p.Remotes[0].Host == "gui-blocked.example" {
		notify(worknet.Status{State: "connecting", Stage: "resolving_endpoint", StageStartedAt: now})
	} else {
		notify(worknet.Status{State: "connected", Stage: "connected", StageStartedAt: now, ConnectedAt: now,
			Routes: []string{"192.168.96.0/20"}, DNSDomains: []string{"corp.example"}, DNSServers: []string{"192.168.100.1"}})
	}
	<-ctx.Done()
	return ctx.Err()
}

// Ephemeral self-signed credentials are generated for parser validation only.
// No fixture keys or exported profiles are saved in the source tree.
func writeGUIOpenVPNFixture(t *testing.T, path, host string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "Vault GUI private-bus fixture"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	priv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	content := fmt.Sprintf("client\ndev tun\nremote %s 1194 udp\nremote-cert-tls server\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n", host, cert, cert, priv)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	if _, err = file.WriteString(content); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
}
