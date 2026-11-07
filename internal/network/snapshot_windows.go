package network

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"net/netip"
	"strings"
	"vault443/internal/winplatform"
)

// CollectWindows projects native IP Helper observations into the shared policy
// model. The routing decision remains identical to Linux; only execution differs.
func CollectWindows() (Snapshot, error) {
	var s Snapshot
	interfaces, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
	if err != nil {
		return s, err
	}
	addresses, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return s, err
	}
	for _, i := range interfaces {
		l := Link{Index: int(i.InterfaceIndex), Name: i.Alias(), MTU: int(i.MTU)}
		description := strings.ToLower(i.Description())
		if i.Type == 24 {
			l.Kind = "loopback"
		} else if winplatform.IsVPNInterface(&i) || strings.HasPrefix(strings.ToLower(l.Name), "v443") || strings.Contains(description, "wintun") || strings.Contains(description, "wireguard") || strings.Contains(description, "tap-windows") {
			l.Kind = "tun"
		}
		for _, a := range addresses {
			if a.InterfaceLUID != i.InterfaceLUID {
				continue
			}
			ip := a.Address.Addr()
			family := "inet"
			if ip.Is6() {
				family = "inet6"
			}
			l.Addresses = append(l.Addresses, struct {
				Local     string `json:"local"`
				PrefixLen int    `json:"prefixlen"`
				Family    string `json:"family"`
			}{ip.String(), int(a.OnLinkPrefixLength), family})
		}
		s.Links = append(s.Links, l)
	}
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return s, err
	}
	for _, r := range routes {
		p := r.DestinationPrefix.Prefix()
		if !p.IsValid() {
			continue
		}
		i, e := r.InterfaceLUID.Interface()
		if e != nil {
			continue
		}
		family := 4
		if p.Addr().Is6() {
			family = 6
		}
		row := Route{Destination: p.String(), Device: i.Alias(), Metric: int(r.Metric), Family: family}
		if r.NextHop.Addr().IsUnspecified() {
			row.Scope = "link"
		} else {
			row.Gateway = r.NextHop.Addr().String()
		}
		s.Routes = append(s.Routes, row)
	}
	return s, nil
}
func LocalRoutes(s Snapshot) []Route {
	var result []Route
	for _, r := range s.Routes {
		p, ok := r.Prefix()
		if !ok || p.Bits() == 0 || p.Addr().IsLoopback() || p.Addr().IsMulticast() || p.Addr().IsLinkLocalUnicast() || r.Scope != "link" {
			continue
		}
		l, ok := s.Link(r.Device)
		if !ok || l.Kind == "tun" || l.Kind == "loopback" {
			continue
		}
		for _, a := range l.Addresses {
			ip, e := netip.ParseAddr(a.Local)
			if e == nil && netip.PrefixFrom(ip, a.PrefixLen).Masked() == p {
				result = append(result, r)
				break
			}
		}
	}
	return result
}
