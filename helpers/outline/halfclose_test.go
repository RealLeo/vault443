package main

import (
	"context"
	"github.com/things-go/go-socks5"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type tcpAddressConn struct{ net.Conn }

func (c *tcpAddressConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8000}
}

// This fixture models a transport exposing CloseWrite. Closing its pipe delivers
// EOF to the peer; the assertion also directly checks whether CloseWrite was called.
type halfCloseFixture struct {
	net.Conn
	calls atomic.Int32
}

func (c *halfCloseFixture) CloseWrite() error { c.calls.Add(1); return c.Conn.Close() }
func TestRemoteEOFPropagatesThroughHandshakeWrapper(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		name := "control_without_wrapper"
		if wrapped {
			name = "production_handshake_wrapper"
		}
		t.Run(name, func(t *testing.T) {
			serverSide, targetSide := net.Pipe()
			defer serverSide.Close()
			defer targetSide.Close()
			go func() { targetSide.Write([]byte("response")); targetSide.Close() }()
			clientSide, proxySide := net.Pipe()
			defer clientSide.Close()
			defer proxySide.Close()
			fixture := &halfCloseFixture{Conn: proxySide}
			var proxy net.Conn = fixture
			if wrapped {
				proxy = &handshakeConn{Conn: fixture}
			}
			done := make(chan error, 1)
			s := socks5.NewServer(socks5.WithCredential(socks5.StaticCredentials{"u": "p"}), socks5.WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return &tcpAddressConn{serverSide}, nil
			}))
			go func() { done <- s.ServeConn(proxy) }()
			c := clientSide
			c.SetDeadline(time.Now().Add(2 * time.Second))
			read := func(n int) {
				t.Helper()
				b := make([]byte, n)
				if _, e := io.ReadFull(c, b); e != nil {
					t.Fatal(e)
				}
			}
			c.Write([]byte{5, 1, 2})
			read(2)
			c.Write([]byte{1, 1, 'u', 1, 'p'})
			read(2)
			c.Write([]byte{5, 1, 0, 1, 1, 1, 1, 1, 0, 80})
			read(10)
			read(8)
			c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			b := make([]byte, 1)
			_, err := c.Read(b)
			if err != io.EOF || fixture.calls.Load() != 1 {
				t.Fatalf("EOF/half-close lost: error=%v CloseWrite=%d", err, fixture.calls.Load())
			}

			c.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("test cleanup timeout")
			}
		})
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	client, e := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if e != nil {
		t.Fatal(e)
	}
	server, e := ln.AcceptTCP()
	if e != nil {
		client.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}
func socksHandshake(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	for _, exchange := range []struct {
		send []byte
		read int
	}{{[]byte{5, 1, 2}, 2}, {[]byte{1, 1, 'u', 1, 'p'}, 2}, {[]byte{5, 1, 0, 1, 1, 1, 1, 1, 0, 80}, 10}} {
		if _, e := c.Write(exchange.send); e != nil {
			t.Fatal(e)
		}
		if _, e := io.ReadFull(c, make([]byte, exchange.read)); e != nil {
			t.Fatal(e)
		}
	}
}
func TestTCPHalfCloseBothDirectionsAndSlotReuse(t *testing.T) {
	slots := make(chan struct{}, 2)
	for i := 0; i < 300; i++ {
		client, proxy := tcpPair(t)
		upstream, target := tcpPair(t)
		server := socks5.NewServer(socks5.WithCredential(socks5.StaticCredentials{"u": "p"}), socks5.WithDial(func(context.Context, string, string) (net.Conn, error) { return upstream, nil }))
		done := make(chan struct{})
		slots <- struct{}{}
		go func() { servePrivateTCP(context.Background(), server, proxy, slots); close(done) }()
		socksHandshake(t, client)
		if i%2 == 0 {
			// The target waits for request EOF before sending the response.
			client.Write([]byte("request"))
			client.CloseWrite()
			data, e := io.ReadAll(target)
			if e != nil || string(data) != "request" {
				t.Fatalf("upstream half-close: %q %v", data, e)
			}
			target.Write([]byte("response"))
			target.CloseWrite()
			data, e = io.ReadAll(client)
			if e != nil || string(data) != "response" {
				t.Fatalf("response after request EOF: %q %v", data, e)
			}
		} else {
			// Remote EOF must not close the client's remaining send direction.
			target.Write([]byte("response"))
			target.CloseWrite()
			data, e := io.ReadAll(client)
			if e != nil || string(data) != "response" {
				t.Fatalf("remote EOF: %q %v", data, e)
			}
			client.Write([]byte("tail"))
			client.CloseWrite()
			data, e = io.ReadAll(target)
			if e != nil || string(data) != "tail" {
				t.Fatalf("reverse path lost: %q %v", data, e)
			}
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("slot not released")
		}
		if len(slots) != 0 {
			t.Fatal("connection slot leaked")
		}
		client.Close()
		proxy.Close()
		upstream.Close()
		target.Close()
	}
}
func TestTCPCancelAndDeadlineReleaseSlot(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		client, proxy := tcpPair(t)
		upstream, target := tcpPair(t)
		server := socks5.NewServer(socks5.WithCredential(socks5.StaticCredentials{"u": "p"}), socks5.WithDial(func(context.Context, string, string) (net.Conn, error) { return upstream, nil }))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		slots := make(chan struct{}, 1)
		slots <- struct{}{}
		done := make(chan struct{})
		go func() { servePrivateTCP(ctx, server, proxy, slots); close(done) }()
		if authenticated {
			socksHandshake(t, client)
			cancel()
		} else {
			// Synchronize with the server's first handshake read, then expire it.
			client.Write([]byte{5, 1, 2})
			if _, e := io.ReadFull(client, make([]byte, 2)); e != nil {
				t.Fatal(e)
			}
			proxy.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("cancel/deadline did not release slot")
		}
		if len(slots) != 0 {
			t.Fatal("slot leaked")
		}
		target.Close()
	}
}
