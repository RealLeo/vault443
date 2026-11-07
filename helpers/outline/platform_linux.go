package main

import (
	"errors"
	"net"
	"os"
	"syscall"
)

func privateListeners() (net.Listener, net.PacketConn, error) {
	lf := os.NewFile(3, "private-tcp")
	listener, err := net.FileListener(lf)
	lf.Close()
	if err != nil {
		return nil, nil, errors.New("missing private TCP descriptor")
	}
	uf := os.NewFile(4, "private-udp")
	packet, err := net.FilePacketConn(uf)
	uf.Close()
	if err != nil {
		listener.Close()
		return nil, nil, errors.New("missing private UDP descriptor")
	}
	return listener, packet, nil
}
func physicalControl(c outlineRuntime, _ string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, conn syscall.RawConn) error {
		var result error
		err := conn.Control(func(fd uintptr) {
			if c.Mark != 0 {
				result = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(c.Mark))
			}
			if result == nil && c.Interface != "" {
				result = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.Interface)
			}
		})
		if err != nil {
			return err
		}
		return result
	}
}
