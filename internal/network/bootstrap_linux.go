package network

import (
	"context"
	"net"
	"net/netip"
	"syscall"
)

func bootstrapDialer() *net.Dialer {
	return &net.Dialer{Timeout: bootstrapDNSTimeout, Control: func(_, _ string, raw syscall.RawConn) error {
		var markErr error
		if err := raw.Control(func(fd uintptr) {
			markErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(BootstrapMark))
		}); err != nil {
			return err
		}
		return markErr
	}}
}

func (m *Manager) resolveEndpoint(ctx context.Context, server string) (netip.Addr, error) {
	resolver := newBootstrapResolver(bootstrapDialer())
	defer resolver.close()
	return resolver.resolve(ctx, server)
}
