package network

import (
	"errors"
	"fmt"
	"net/netip"
)

func chooseFreeSubnets(occupied []netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	free := func(p netip.Prefix) bool {
		for _, q := range occupied {
			if p.Overlaps(q) {
				return false
			}
		}
		return true
	}
	var v4, v6 netip.Prefix
	// Avoid generic Docker/RFC1918 assumptions. Check every candidate against all
	// tables, including connected routes and addresses not in the main table.
	for a := 18; a <= 19 && !v4.IsValid(); a++ {
		for b := 0; b < 256; b++ {
			p := netip.MustParsePrefix(fmt.Sprintf("198.%d.%d.0/30", a, b))
			if free(p) {
				v4 = netip.PrefixFrom(p.Addr().Next(), 30)
				break
			}
		}
	}
	for n := 0; n < 256; n++ {
		p := netip.MustParsePrefix(fmt.Sprintf("fd56:4c54:%x::/64", n))
		if free(p) {
			v6 = netip.PrefixFrom(p.Addr().Next(), 64)
			break
		}
	}
	if !v4.IsValid() || !v6.IsValid() {
		return v4, v6, errors.New("no collision-free TUN subnet available")
	}
	return v4, v6, nil
}
