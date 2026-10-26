package network

import (
	"context"
	"errors"
	"strings"
)

type dnsSettings struct {
	Servers      []string `json:"servers"`
	Domains      []string `json:"domains"`
	DefaultRoute string   `json:"defaultRoute"`
}

func (m *Manager) readDNS(ctx context.Context, iface string) (dnsSettings, error) {
	var s dnsSettings
	for _, kind := range []string{"dns", "domain", "default-route"} {
		out, e := m.r.Run(ctx, command{Path: "/usr/bin/resolvectl", Args: []string{kind, iface}})
		if e != nil {
			return s, errors.New("cannot inspect external VPN DNS")
		}
		line := strings.TrimSpace(string(out))
		colon := strings.Index(line, ":")
		if colon < 0 {
			return s, errors.New("unexpected resolver response")
		}
		items := strings.Fields(line[colon+1:])
		switch kind {
		case "dns":
			s.Servers = items
		case "domain":
			s.Domains = items
		case "default-route":
			if len(items) != 1 || (items[0] != "yes" && items[0] != "no") {
				return s, errors.New("unexpected DNS default route")
			}
			s.DefaultRoute = items[0]
		}
	}
	return s, nil
}

// Only explicit binding DNS metadata is applied to external interfaces. Normal
// NetworkManager/Pritunl split DNS remains owned by those applications.
func (m *Manager) configureExternalDNS(ctx context.Context, xs []external) error {
	for _, x := range xs {
		if !x.Active || x.Full4 || x.Full6 {
			continue
		}
		b := x.Binding
		if len(b.DNSDomains) == 0 && len(b.DNSServers) == 0 {
			continue
		}
		if len(b.DNSDomains) == 0 || len(b.DNSServers) == 0 {
			return errors.New("split DNS binding needs both servers and domains")
		}
		if _, ok := m.dnsSaved[b.Interface]; !ok {
			old, e := m.readDNS(ctx, b.Interface)
			if e != nil {
				return e
			}
			m.dnsSaved[b.Interface] = old
			if !m.config.DryRun {
				if e = privateWrite(m.config.StateDir, "dns-backup.json", m.dnsSaved); e != nil {
					return errors.New("cannot preserve external DNS settings")
				}
			}
		}
		domains := make([]string, len(b.DNSDomains))
		for i, d := range b.DNSDomains {
			domains[i] = "~" + strings.TrimPrefix(d, "~")
		}
		for _, args := range [][]string{append([]string{"dns", b.Interface}, b.DNSServers...), append([]string{"domain", b.Interface}, domains...), {"default-route", b.Interface, "no"}} {
			if e := m.execute(ctx, command{Path: "/usr/bin/resolvectl", Args: args}); e != nil {
				return errors.New("cannot configure external split DNS")
			}
		}
	}
	return nil
}

func (m *Manager) restoreExternalDNS(ctx context.Context, s Snapshot) error {
	for iface, old := range m.dnsSaved {
		if _, ok := s.Link(iface); !ok {
			continue
		}
		servers := old.Servers
		if len(servers) == 0 {
			servers = []string{""}
		}
		domains := old.Domains
		if len(domains) == 0 {
			domains = []string{""}
		}
		for _, args := range [][]string{append([]string{"dns", iface}, servers...), append([]string{"domain", iface}, domains...), {"default-route", iface, old.DefaultRoute}} {
			if e := m.execute(ctx, command{Path: "/usr/bin/resolvectl", Args: args}); e != nil {
				return errors.New("cannot restore previous external DNS")
			}
		}
	}
	m.dnsSaved = map[string]dnsSettings{}
	if !m.config.DryRun {
		if e := privateWrite(m.config.StateDir, "dns-backup.json", m.dnsSaved); e != nil {
			return errors.New("cannot finish DNS restoration")
		}
	}
	return nil
}
