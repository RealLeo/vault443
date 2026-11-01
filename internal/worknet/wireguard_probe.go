package worknet

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"vault443/internal/workvpn"
)

var errNoProbeDestination = errors.New("peer has no effective probe destination matching an interface address")

// A probe is an empty UDP datagram injected only into the owned tunnel's
// transmit queue. AF_PACKET avoids opening the destination routes before a
// handshake. It cannot select a physical interface or carry user traffic.
// A response to this UDP port is not required: the authenticated handshake is
// what confirms the peer. Ordinary traffic remains subject to the guard.
func probeWireGuard(iface string, expectedIndex int, config *workvpn.WireGuardConfig, peer workvpn.WireGuardPeer) error {
	link, err := net.InterfaceByName(iface)
	if err != nil || link.Index != expectedIndex {
		return errors.New("work tunnel changed before handshake probe")
	}
	packet, family, err := wireGuardProbePacket(config, peer)
	if err != nil {
		return err
	}
	protocol := uint16(syscall.ETH_P_IP)
	if family == 6 {
		protocol = syscall.ETH_P_IPV6
	}
	protocol = (protocol << 8) | (protocol >> 8)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, int(protocol))
	if err != nil {
		return errors.New("cannot create tunnel handshake probe")
	}
	defer syscall.Close(fd)
	if err = syscall.Sendto(fd, packet, 0, &syscall.SockaddrLinklayer{Ifindex: expectedIndex, Protocol: protocol}); err != nil {
		return errors.New("cannot send tunnel handshake probe")
	}
	return nil
}

func wireGuardProbePacket(config *workvpn.WireGuardConfig, peer workvpn.WireGuardPeer) ([]byte, int, error) {
	var source, dest netip.Addr
	for _, allowed := range peer.AllowedIPs {
		prefix, err := netip.ParsePrefix(allowed)
		if err != nil {
			continue
		}
		candidate := prefix.Addr()
		if prefix.Bits() < candidate.BitLen() {
			candidate = candidate.Next()
		}
		if candidate.IsUnspecified() || candidate.IsLoopback() || candidate.IsMulticast() {
			if candidate.Is4() {
				candidate = netip.MustParseAddr("1.0.0.1")
			} else {
				candidate = netip.MustParseAddr("2001:db8::1")
			}
		}
		for tries := 0; tries < 1024 && prefix.Contains(candidate); tries++ {
			skip := false
			for _, other := range config.Peers {
				if other.PublicKey == peer.PublicKey {
					continue
				}
				for _, cidr := range other.AllowedIPs {
					q, e := netip.ParsePrefix(cidr)
					if e == nil && q.Bits() > prefix.Bits() && q.Contains(candidate) {
						candidate = lastPrefixAddress(q).Next()
						skip = true
						break
					}
				}
				if skip {
					break
				}
			}
			if !skip {
				for _, address := range config.Addresses {
					q, e := netip.ParsePrefix(address)
					if e == nil && q.Addr() == candidate {
						candidate = candidate.Next()
						skip = true
						break
					}
				}
			}
			if !skip {
				break
			}
		}
		if !prefix.Contains(candidate) {
			continue
		}
		for _, address := range config.Addresses {
			a, err := netip.ParsePrefix(address)
			if err == nil && a.Addr().Is4() == candidate.Is4() && a.Addr() != candidate {
				source = a.Addr()
				dest = candidate
				break
			}
		}
		if source.IsValid() {
			break
		}
	}
	if !source.IsValid() {
		return nil, 0, errNoProbeDestination
	}
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 9)
	binary.BigEndian.PutUint16(udp[2:], 9)
	binary.BigEndian.PutUint16(udp[4:], 8)
	if source.Is4() {
		p := make([]byte, 28)
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:], 28)
		p[8] = 64
		p[9] = 17
		s := source.As4()
		d := dest.As4()
		copy(p[12:], s[:])
		copy(p[16:], d[:])
		binary.BigEndian.PutUint16(p[10:], internetChecksum(p[:20]))
		copy(p[20:], udp)
		return p, 4, nil
	}
	p := make([]byte, 48)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], 8)
	p[6] = 17
	p[7] = 64
	s := source.As16()
	d := dest.As16()
	copy(p[8:], s[:])
	copy(p[24:], d[:])
	pseudo := make([]byte, 40+len(udp))
	copy(pseudo, s[:])
	copy(pseudo[16:], d[:])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(udp)))
	pseudo[39] = 17
	copy(pseudo[40:], udp)
	checksum := internetChecksum(pseudo)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], checksum)
	copy(p[40:], udp)
	return p, 6, nil
}
func internetChecksum(p []byte) uint16 {
	sum := uint32(0)
	for len(p) > 1 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) > 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func lastPrefixAddress(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		a := p.Masked().Addr().As4()
		for bit := p.Bits(); bit < 32; bit++ {
			a[bit/8] |= 1 << uint(7-bit%8)
		}
		return netip.AddrFrom4(a)
	}
	a := p.Masked().Addr().As16()
	for bit := p.Bits(); bit < 128; bit++ {
		a[bit/8] |= 1 << uint(7-bit%8)
	}
	return netip.AddrFrom16(a)
}
