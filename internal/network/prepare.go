package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"time"

	"vault443/internal/core"
	"vault443/internal/model"
	"vault443/internal/profiles"
)

type preparedConnection struct {
	profile   model.Profile
	uplink    Route
	endpoint  netip.Addr
	endpoints []Endpoint
	resolved  map[string]string
	at        time.Time
}

// Suspend closes Internet access without releasing the persistent guard.
func (m *Manager) Suspend(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verified = false
	m.operationContext = ctx
	defer func() { m.operationContext = nil }()
	guardErr := m.arm(ctx)
	if err := errors.Join(guardErr, m.stopCore(ctx)); err != nil {
		return m.fail(err)
	}
	return m.fail(errors.New("Previous connection is unavailable; traffic remains protected"))
}

// Preparation is read-only with respect to the live session. Bootstrap DNS uses
// its existing narrow marked permission; no candidate user traffic is allowed.
func (m *Manager) PrepareConnect(ctx context.Context, p model.Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prepared = nil
	s, err := collect(ctx, m.r)
	if err != nil {
		return err
	}
	x, err := m.external(ctx, s)
	if err != nil {
		return err
	}
	if anyFull(x) {
		return errors.New("Another VPN provides Internet access; switching is postponed")
	}
	uplink, err := s.Uplink()
	if err != nil {
		return err
	}
	v4, v6, err := ChooseSubnets(s)
	if err != nil {
		return err
	}
	prepared, err := m.resolveProfile(ctx, p, uplink)
	if err != nil {
		return err
	}
	options := core.Options{Interface: TunName, Gateway4: v4, Gateway6: v6, DNSAddress: v4.Addr().Next(), Endpoint: prepared.endpoint, Uplink: uplink.Device, Mark: OuterMark}
	if p.Outline != nil {
		options.LocalPort, options.LocalUser, options.LocalPassword = 1080, "validation", "validation-only-not-a-session"
	}
	data, err := core.Build(p, options)
	if err != nil {
		return err
	}
	if !m.config.DryRun {
		if err = core.CheckBinaryContext(ctx, m.config.XrayPath); err != nil {
			return err
		}
		if err = os.MkdirAll(m.config.RuntimeDir, 0700); err != nil {
			return errors.New("Cannot prepare private configuration")
		}
		dir, e := os.MkdirTemp(m.config.RuntimeDir, ".prepare-")
		if e != nil {
			return errors.New("Cannot prepare private configuration")
		}
		defer os.RemoveAll(dir)
		file, e := core.WriteConfig(dir, data)
		if e != nil {
			return errors.New("Cannot prepare private configuration")
		}
		check, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if e = exec.CommandContext(check, m.config.XrayPath, "run", "-test", "-config", file).Run(); e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("Xray rejected the prepared configuration")
		}
	}
	m.prepared = prepared
	return nil
}

func (m *Manager) resolveProfile(ctx context.Context, p model.Profile, uplink Route) (*preparedConnection, error) {
	result := &preparedConnection{profile: p, uplink: uplink, resolved: map[string]string{}, at: time.Now()}
	addresses := []string{net.JoinHostPort(p.Server, strconv.Itoa(p.Port))}
	if p.Outline != nil {
		addresses = profiles.OutlineTransportEndpoints(p.Outline)
	}
	for _, address := range addresses {
		host, port, _ := net.SplitHostPort(address)
		a, err := netip.ParseAddr(host)
		if m.config.DryRun {
			if err != nil {
				a = netip.MustParseAddr("203.0.113.1")
			}
		} else {
			a, err = m.resolveEndpoint(ctx, host)
			if err != nil {
				return nil, err
			}
		}
		if !result.endpoint.IsValid() {
			result.endpoint = a
		}
		n, _ := strconv.Atoi(port)
		protocols := []string{"tcp"}
		if p.Protocol() == "shadowsocks" {
			protocols = []string{"tcp", "udp"}
		}
		if p.Outline != nil {
			protocols = profiles.OutlinePhysicalEndpoints(p.Outline)[address]
		}
		for _, protocol := range protocols {
			result.endpoints = append(result.endpoints, Endpoint{Address: a.String(), Port: n, Protocol: protocol})
		}
		result.resolved[address] = net.JoinHostPort(a.String(), port)
	}
	return result, nil
}

func (p *preparedConnection) matches(profile model.Profile, uplink Route) bool {
	return p != nil && time.Since(p.at) < 30*time.Second && reflect.DeepEqual(p.profile, profile) && p.uplink.Device == uplink.Device && p.uplink.Gateway == uplink.Gateway
}
