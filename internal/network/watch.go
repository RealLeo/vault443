package network

import (
	"context"
	"errors"
	"syscall"
)

// Watch subscribes to kernel link/address/route notifications. It changes no
// network state. Consumers should call Reconcile on notifications and retain a
// slow retry timer for transport sockets and remote health. Events are coalesced
// rather than exposing peer addresses or process metadata over the UI API.
func (m *Manager) Watch(ctx context.Context) (<-chan struct{}, error) {
	if m.config.DryRun {
		ch := make(chan struct{})
		close(ch)
		return ch, nil
	}
	fd, e := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if e != nil {
		return nil, errors.New("cannot subscribe to network changes")
	}
	const groups = 0x1 | 0x10 | 0x40 | 0x100 | 0x400 // LINK, IPv4/IPv6 IFADDR and ROUTE
	if e = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: groups}); e != nil {
		_ = syscall.Close(fd)
		return nil, errors.New("cannot bind network event subscription")
	}
	if e = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 250000}); e != nil {
		_ = syscall.Close(fd)
		return nil, e
	}
	events := make(chan struct{}, 1)
	go func() {
		defer close(events)
		defer syscall.Close(fd)
		buf := make([]byte, 64<<10)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, _, e := syscall.Recvfrom(fd, buf, 0)
			if e == syscall.EAGAIN || e == syscall.EWOULDBLOCK || e == syscall.EINTR {
				continue
			}
			if e != nil {
				return
			}
			select {
			case events <- struct{}{}:
			default:
			}
		}
	}()
	return events, nil
}
