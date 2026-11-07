package main

import (
	"encoding/binary"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

func privateListeners() (net.Listener, net.PacketConn, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, err
	}
	packet, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listener.Addr().(*net.TCPAddr).Port})
	if err != nil {
		listener.Close()
		return nil, nil, err
	}
	return listener, packet, nil
}
func physicalControl(c outlineRuntime, host string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, conn syscall.RawConn) error {
		iface, err := net.InterfaceByName(c.Interface)
		if err != nil {
			return err
		}
		level, option, index := windows.IPPROTO_IPV6, 31, iface.Index // IPV6_UNICAST_IF
		if net.ParseIP(host).To4() != nil {
			level, option = windows.IPPROTO_IP, 31 // IP_UNICAST_IF takes network byte order.
			var b [4]byte
			binary.LittleEndian.PutUint32(b[:], uint32(index))
			index = int(binary.BigEndian.Uint32(b[:]))
		}
		var result error
		err = conn.Control(func(fd uintptr) { result = windows.SetsockoptInt(windows.Handle(fd), level, option, index) })
		if err != nil {
			return err
		}
		return result
	}
}
