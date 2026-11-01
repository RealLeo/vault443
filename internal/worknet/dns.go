package worknet

import (
	"context"
	"net/netip"
	"sort"
	"strconv"
	"vault443/internal/network"
)

func workTables() []int {
	t := []int{underlayTable, manualTable, specificTable, fullTable, replyTable}
	for n := dnsTableStart; n <= dnsReverseTable; n++ {
		t = append(t, n)
	}
	return t
}

// resolved binds each split-DNS request to its chosen link. Separate DNS-only
// tables preserve that choice even when two workplaces use the same resolver
// IP. No table contains a default or a physical-interface route.
func installDNSPolicy(ctx context.Context, k network.Kernel, snap network.Snapshot, sessions []*session) error {
	reverse := map[string][]string{}
	for slot, ss := range sessions {
		table := dnsTableStart + slot
		link, present := snap.Link(ss.Interface)
		for _, dns := range ss.DNSServers {
			a, err := netip.ParseAddr(dns)
			if err != nil {
				continue
			}
			f := 4
			if a.Is6() {
				f = 6
			}
			p := netip.PrefixFrom(a, a.BitLen()).String()
			if err = installRoute(ctx, k, table, selected{cidr: p, iface: ss.Interface, active: routeAvailable(ss, p)}); err != nil {
				return err
			}
			if !present {
				continue
			}
			for _, proto := range []string{"udp", "tcp"} {
				if err = ip(k, ctx, f, "rule", "add", "priority", "5180", "oif", ss.Interface, "to", p, "ipproto", proto, "dport", "53", "lookup", strconv.Itoa(table)); err != nil {
					return err
				}
			}
			if !routeAvailable(ss, p) || !a.Is4() {
				continue
			}
			reverse[p] = append(reverse[p], ss.Interface)
			// Linux's strict reverse-path lookup uses root UID and swaps the
			// packet's addresses/ports. A multipath DNS-only result verifies all
			// active owners without changing rp_filter or kernel tunables.
			for _, address := range link.Addresses {
				src, er := netip.ParseAddr(address.Local)
				if er != nil || !src.Is4() {
					continue
				}
				for _, proto := range []string{"udp", "tcp"} {
					if err = ip(k, ctx, 4, "rule", "add", "priority", "5181", "uidrange", "0-0", "from", src.String()+"/32", "to", p, "ipproto", proto, "dport", "53", "lookup", strconv.Itoa(dnsReverseTable)); err != nil {
						return err
					}
				}
			}
		}
	}
	var addresses []string
	for address := range reverse {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	for _, address := range addresses {
		ifaces := reverse[address]
		sort.Strings(ifaces)
		args := []string{"route", "replace", address, "table", strconv.Itoa(dnsReverseTable), "proto", workProtocol}
		last := ""
		for _, iface := range ifaces {
			if iface != last {
				args = append(args, "nexthop", "dev", iface, "weight", "1")
				last = iface
			}
		}
		if err := ip(k, ctx, 4, args...); err != nil {
			return err
		}
	}
	return nil
}
