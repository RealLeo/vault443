package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDNSWireDualStackSuffix(t *testing.T) {
	for _, tc := range []struct {
		name string
		dual bool
	}{
		{"webdual.e2e.example.com", true},
		{"probe-0123456789abcdef.webdual.e2e.example.com", true},
		{"PROBE-0123456789ABCDEF.WEBDUAL.E2E.EXAMPLE.COM", true},
		{"probe-notwebdual.e2e.example.com", false},
		{"probe.webdual.e2e.example.com.attacker.test", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, typ := range []uint16{1, 28} {
				q := []byte{0x44, 0x33, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
				for _, label := range strings.Split(tc.name, ".") {
					q = append(q, byte(len(label)))
					q = append(q, label...)
				}
				q = append(q, 0, byte(typ>>8), byte(typ), 0, 1)
				r, err := answer(q)
				if err != nil {
					t.Fatal(err)
				}
				want := uint16(1)
				if typ == 28 && !tc.dual {
					want = 0
				}
				if binary.BigEndian.Uint16(r[:2]) != 0x4433 || binary.BigEndian.Uint16(r[6:8]) != want {
					t.Fatalf("type %d: wrong transaction ID or answer count: %x", typ, r[:12])
				}
				if want == 0 {
					if len(r) != len(q) {
						t.Fatal("unexpected record in empty AAAA answer")
					}
					continue
				}
				rr := r[len(q):]
				wantIP := "93.184.215.14"
				if typ == 28 {
					wantIP = "2001:db8:66::14"
				}
				if len(rr) < 12 || binary.BigEndian.Uint16(rr[2:4]) != typ || !net.IP(rr[12:]).Equal(net.ParseIP(wantIP)) {
					t.Fatalf("type %d: unexpected DNS address record: %x", typ, rr)
				}
			}
		})
	}
}

func TestUDPReportsObservedSourceAndRequestNonce(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveUDP(server) }()
	t.Cleanup(func() { server.Close(); <-done })
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	// The first accepted response must belong to the valid request, rather than
	// turning arbitrary UDP into an echo or accepting a truncated nonce.
	for _, text := range []string{"unrelated packet", "vault443-main-udp:short", "vault443-main-udp:0123456789abcdef0123456789abcdef"} {
		if _, err := client.Write([]byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	var packet [512]byte
	n, err := client.Read(packet[:])
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	if err := json.Unmarshal(packet[:n], &body); err != nil {
		t.Fatal(err)
	}
	if body["marker"] != "main-udp-e2e-ok" || body["nonce"] != "0123456789abcdef0123456789abcdef" || body["peer"] != "127.0.0.1" {
		t.Fatalf("unexpected fixture observation: %v", body)
	}
}
