// vault443-outline is a fixed private transport adapter. It never owns a TUN,
// changes routes, resolves names directly or accepts user-selected executables.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"golang.getoutline.org/sdk/transport"
)

var version = "development"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("Vault 443 Outline " + version)
		return
	}
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "Outline adapter stopped: "+e.Error())
		os.Exit(1)
	}
}

type noResolver struct{}

func (noResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}
func run() error {
	var c outlineRuntime
	d := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(&c); e != nil {
		return errors.New("invalid private runtime configuration")
	}
	if c.Transport == nil || len(c.Password) < 32 || c.Username == "" {
		return errors.New("incomplete private runtime configuration")
	}
	b := transportBuilder{c}
	sd, e := b.streamDialer(c.Transport.TCP)
	if e != nil {
		return e
	}
	pl, e := b.packetListener(c.Transport.UDP)
	if e != nil {
		return e
	}
	lf := os.NewFile(3, "private-tcp")
	listener, e := net.FileListener(lf)
	lf.Close()
	if e != nil {
		return errors.New("missing private TCP descriptor")
	}
	defer listener.Close()
	uf := os.NewFile(4, "private-udp")
	packet, e := net.FilePacketConn(uf)
	uf.Close()
	if e != nil {
		return errors.New("missing private UDP descriptor")
	}
	defer packet.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	// Drop anything queued before the parent's firewall gate became active.
	packet.SetReadDeadline(time.Now().Add(2 * time.Millisecond))
	discard := make([]byte, 65535)
	for {
		if _, _, e := packet.ReadFrom(discard); e != nil {
			break
		}
	}
	packet.SetReadDeadline(time.Time{})
	var associations atomic.Int64
	go relayDatagrams(ctx, packet, pl, &associations)
	s := socks5.NewServer(socks5.WithCredential(socks5.StaticCredentials{c.Username: c.Password}), socks5.WithResolver(noResolver{}), socks5.WithDial(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("unexpected dial network")
		}
		dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		return sd.DialStream(dialCtx, address)
	}), socks5.WithBindHandle(func(_ context.Context, w io.Writer, _ *socks5.Request) error {
		return socks5.SendReply(w, statute.RepCommandNotSupported, nil)
	}), socks5.WithAssociateHandle(func(_ context.Context, w io.Writer, r *socks5.Request) error {
		if c.Transport.UDP == nil {
			return socks5.SendReply(w, statute.RepCommandNotSupported, nil)
		}
		associations.Add(1)
		defer associations.Add(-1)
		if e := socks5.SendReply(w, statute.RepSuccess, packet.LocalAddr()); e != nil {
			return e
		}
		_, e := io.Copy(io.Discard, r.Reader)
		return e
	}))
	go func() { <-ctx.Done(); listener.Close(); packet.Close() }()
	slots := make(chan struct{}, 256)
	fmt.Println(`{"ready":true}`)
	for {
		conn, e := listener.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("private listener failed")
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		go servePrivateTCP(ctx, s, conn, slots)
	}
}

func servePrivateTCP(ctx context.Context, server *socks5.Server, conn net.Conn, slots chan struct{}) {
	defer func() { <-slots }()
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	_ = server.ServeConn(&handshakeConn{Conn: conn})
}

// Clear the authentication deadline after SOCKS setup starts relaying. The
// library itself handles authentication and CONNECT framing.
type handshakeConn struct{ net.Conn }

// net.Conn intentionally omits half-close. Preserve the TCP capability through
// this wrapper so the SOCKS relay forwards upstream EOF without closing reads.
func (c *handshakeConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.New("underlying stream does not support half-close")
}

func (c *handshakeConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if len(p) >= 2 && p[0] == 5 && p[1] == 0 {
		_ = c.Conn.SetDeadline(time.Time{})
	}
	return n, e
}

type udpFlow struct {
	cancel  context.CancelFunc
	packets chan []byte
	last    atomic.Int64
}

func relayDatagrams(ctx context.Context, local net.PacketConn, pl transport.PacketListener, active *atomic.Int64) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	flows := map[string]*udpFlow{}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				mu.Lock()
				for _, f := range flows {
					f.cancel()
				}
				mu.Unlock()
				return
			case <-ticker.C:
				mu.Lock()
				for key, f := range flows {
					if active.Load() == 0 || time.Now().Unix()-f.last.Load() > 120 {
						f.cancel()
						delete(flows, key)
					}
				}
				mu.Unlock()
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, source, e := local.ReadFrom(buf)
		if e != nil {
			return
		}
		if active.Load() == 0 {
			continue
		}
		host, _, e := net.SplitHostPort(source.String())
		if e != nil || !net.ParseIP(host).IsLoopback() {
			continue
		}
		packet, e := statute.ParseDatagram(buf[:n])
		if e != nil || packet.Frag != 0 {
			continue
		}
		address := packet.DstAddr.String()
		key := source.String() + "|" + address
		mu.Lock()
		f := flows[key]
		if f == nil {
			if len(flows) >= 128 {
				mu.Unlock()
				continue
			}
			flowCtx, flowCancel := context.WithCancel(ctx)
			f = &udpFlow{cancel: flowCancel, packets: make(chan []byte, 8)}
			flows[key] = f
			header := append([]byte(nil), packet.Header()...)
			go func(f *udpFlow) {
				defer func() {
					f.cancel()
					mu.Lock()
					if flows[key] == f {
						delete(flows, key)
					}
					mu.Unlock()
				}()
				runUDPFlow(flowCtx, local, pl, f, address, source, header)
			}(f)
		}
		mu.Unlock()
		f.last.Store(time.Now().Unix())
		// Congestion drops datagrams without blocking other flows or Xray control.
		data := append([]byte(nil), packet.Data...)
		select {
		case f.packets <- data:
		default:
		}
	}
}
func runUDPFlow(ctx context.Context, local net.PacketConn, pl transport.PacketListener, f *udpFlow, address string, destination net.Addr, header []byte) {
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	conn, e := (&transport.PacketListenerDialer{Listener: pl}).DialPacket(dialCtx, address)
	cancel()
	if e != nil {
		return
	}
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()
	go func() {
		defer f.cancel()
		buf := make([]byte, 65535)
		for {
			n, e := conn.Read(buf)
			if e != nil {
				return
			}
			f.last.Store(time.Now().Unix())
			reply := append(append([]byte(nil), header...), buf[:n]...)
			if _, e = local.WriteTo(reply, destination); e != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-f.packets:
			conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
			if _, e = conn.Write(data); e != nil {
				return
			}
		}
	}
}
