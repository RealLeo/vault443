package winplatform

import (
	"net/netip"
	"os"
	"sort"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// DNSGuardEndpoints gives a work-only coordinator fixed bootstrap permissions
// and access to the original DNS servers. FallbackDNS permissions are suppressed
// by Guard whenever a main kill switch is armed; DNS also refuses fallback then.
func (c *Coordinator) DNSGuardEndpoints(uplink winipcfg.LUID) ([]uint64, []Endpoint, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	physical := map[uint64]bool{uint64(uplink): true}
	var endpoints []Endpoint
	for _, text := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		ip := netip.MustParseAddr(text)
		u, e := PhysicalUplink(ip.Is6())
		if e != nil {
			continue
		}
		physical[uint64(u.LUID)] = true
		for _, port := range []uint16{53, 443} {
			endpoints = append(endpoints, Endpoint{App: exe, Address: ip, Port: port, Interface: uint64(u.LUID)})
			if port == 53 {
				endpoints = append(endpoints, Endpoint{App: exe, Address: ip, Port: port, UDP: true, Interface: uint64(u.LUID)})
			}
		}
	}
	servers, err := c.DNS.UnderlayServers(uplink)
	if err != nil {
		return nil, nil, err
	}
	for _, ip := range servers {
		u, e := PhysicalUplink(ip.Is6())
		if e != nil {
			continue
		}
		physical[uint64(u.LUID)] = true
		for _, udp := range []bool{false, true} {
			endpoints = append(endpoints, Endpoint{App: exe, Address: ip, Port: 53, UDP: udp, Interface: uint64(u.LUID), FallbackDNS: true})
		}
	}
	var luids []uint64
	for luid := range physical {
		if luid != 0 {
			luids = append(luids, luid)
		}
	}
	sort.Slice(luids, func(i, j int) bool { return luids[i] < luids[j] })
	return luids, endpoints, nil
}
