package main

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	"golang.getoutline.org/sdk/x/websocket"
)

type transportBuilder struct{ config outlineRuntime }

func (b transportBuilder) direct(network, address string) (net.Dialer, string, error) {
	pinned, ok := b.config.Resolved[address]
	if !ok {
		return net.Dialer{}, "", errors.New("unregistered physical endpoint")
	}
	host, _, e := net.SplitHostPort(pinned)
	if e != nil || net.ParseIP(host) == nil {
		return net.Dialer{}, "", errors.New("physical endpoint is not resolved")
	}
	d := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
		var result error
		e := c.Control(func(fd uintptr) {
			if b.config.Mark != 0 {
				result = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(b.config.Mark))
			}
			if result == nil && b.config.Interface != "" {
				result = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, b.config.Interface)
			}
		})
		if e != nil {
			return e
		}
		return result
	}}
	return d, pinned, nil
}
func (b transportBuilder) streamEndpoint(n *outlineNode) (transport.StreamEndpoint, error) {
	if n == nil {
		return nil, errors.New("missing stream endpoint")
	}
	switch n.Type {
	case "address":
		d, address, e := b.direct("tcp", n.Address)
		if e != nil {
			return nil, e
		}
		return &transport.TCPEndpoint{Dialer: d, Address: address}, nil
	case "dial":
		d, e := b.streamDialer(n.Dialer)
		if e != nil {
			return nil, e
		}
		return &transport.StreamDialerEndpoint{Dialer: d, Address: n.Address}, nil
	case "websocket":
		inner, e := b.streamEndpoint(n.Endpoint)
		if e != nil {
			return nil, e
		}
		fn, e := websocket.NewStreamEndpoint(n.URL, inner)
		if e != nil {
			return nil, errors.New("invalid WebSocket endpoint")
		}
		return transport.FuncStreamEndpoint(fn), nil
	default:
		return nil, errors.New("unsupported stream endpoint")
	}
}
func (b transportBuilder) packetEndpoint(n *outlineNode) (transport.PacketEndpoint, error) {
	if n == nil {
		return nil, errors.New("missing packet endpoint")
	}
	switch n.Type {
	case "address":
		d, address, e := b.direct("udp", n.Address)
		if e != nil {
			return nil, e
		}
		return &transport.UDPEndpoint{Dialer: d, Address: address}, nil
	case "dial":
		l, e := b.packetListener(n.Dialer)
		if e != nil {
			return nil, e
		}
		return &transport.PacketDialerEndpoint{Dialer: transport.PacketListenerDialer{Listener: l}, Address: n.Address}, nil
	case "websocket":
		inner, e := b.streamEndpoint(n.Endpoint)
		if e != nil {
			return nil, e
		}
		fn, e := websocket.NewPacketEndpoint(n.URL, inner)
		if e != nil {
			return nil, errors.New("invalid packet WebSocket endpoint")
		}
		return transport.FuncPacketEndpoint(fn), nil
	default:
		return nil, errors.New("unsupported packet endpoint")
	}
}
func (b transportBuilder) streamDialer(n *outlineNode) (transport.StreamDialer, error) {
	if n == nil {
		return transport.FuncStreamDialer(func(context.Context, string) (transport.StreamConn, error) {
			return nil, errors.New("TCP disabled by profile")
		}), nil
	}
	if n.Type != "shadowsocks" {
		return nil, errors.New("nonencrypted stream transport refused")
	}
	key, e := shadowsocks.NewEncryptionKey(n.Cipher, n.Secret)
	if e != nil {
		return nil, errors.New("unsupported Outline cipher")
	}
	ep, e := b.streamEndpoint(n.Endpoint)
	if e != nil {
		return nil, e
	}
	d, e := shadowsocks.NewStreamDialer(ep, key)
	if e == nil && len(n.Prefix) > 0 {
		d.SaltGenerator = shadowsocks.NewPrefixSaltGenerator(n.Prefix)
	}
	return d, e
}
func (b transportBuilder) packetListener(n *outlineNode) (transport.PacketListener, error) {
	if n == nil {
		return disabledPackets{}, nil
	}
	if n.Type != "shadowsocks" {
		return nil, errors.New("nonencrypted packet transport refused")
	}
	key, e := shadowsocks.NewEncryptionKey(n.Cipher, n.Secret)
	if e != nil {
		return nil, errors.New("unsupported Outline cipher")
	}
	ep, e := b.packetEndpoint(n.Endpoint)
	if e != nil {
		return nil, e
	}
	l, e := shadowsocks.NewPacketListener(ep, key)
	if e == nil && len(n.Prefix) > 0 {
		l.SetSaltGenerator(shadowsocks.NewPrefixSaltGenerator(n.Prefix))
	}
	return l, e
}

type disabledPackets struct{}

func (disabledPackets) ListenPacket(context.Context) (net.PacketConn, error) {
	return nil, errors.New("UDP disabled by profile")
}
