package main

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type localPacketListener struct{}

func (localPacketListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
}
func TestRelayRequiresAuthenticatedAssociationAndCancels(t *testing.T) {
	echo, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, e := echo.ReadFrom(b)
			if e != nil {
				return
			}
			echo.WriteTo(b[:n], a)
		}
	}()
	local, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer local.Close()
	client, e := net.Dial("udp4", local.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active atomic.Int64
	done := make(chan struct{})
	go func() { relayDatagrams(ctx, local, localPacketListener{}, &active); close(done) }()
	port := echo.LocalAddr().(*net.UDPAddr).Port
	packet := append([]byte{0, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}, []byte("synthetic")...)
	b := make([]byte, 512)
	client.SetDeadline(time.Now().Add(80 * time.Millisecond))
	client.Write(packet)
	if _, e = client.Read(b); e == nil {
		t.Fatal("unauthenticated packet relayed")
	}
	active.Store(1)
	client.SetDeadline(time.Now().Add(time.Second))
	client.Write(packet)
	n, e := client.Read(b)
	if e != nil || string(b[:n]) != string(packet) {
		t.Fatal("authenticated relay failed", e)
	}
	active.Store(0)
	client.SetDeadline(time.Now().Add(80 * time.Millisecond))
	client.Write(packet)
	if _, e = client.Read(b); e == nil {
		t.Fatal("packet relayed after association closed")
	}
	cancel()
	local.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not cancel")
	}
}
func TestOnlyRegisteredPhysicalEndpoints(t *testing.T) {
	b := transportBuilder{outlineRuntime{Resolved: map[string]string{"outer.example:443": "127.0.0.1:443"}}}
	if _, _, e := b.direct("tcp", "inner.example:443"); e == nil {
		t.Fatal("unregistered bypass accepted")
	}
	b.config.Resolved["outer.example:443"] = "unresolved.example:443"
	if _, _, e := b.direct("tcp", "outer.example:443"); e == nil {
		t.Fatal("unresolved address accepted")
	}
	sd, e := b.streamDialer(nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = sd.DialStream(context.Background(), "example.com:443"); e == nil {
		t.Fatal("missing TCP silently enabled")
	}
	pl, e := b.packetListener(nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pl.ListenPacket(context.Background()); e == nil {
		t.Fatal("missing UDP silently enabled")
	}
}
