package ipc

import (
	"context"
	"vault443/internal/journal"
	"vault443/internal/worknet"
	"vault443/internal/workvpn"
)

// Only the private bus tests use this inert runtime. It never opens a TUN,
// connects to a VPN, or invokes privileged network tools.
type inertWorkRuntime struct{}

func (*inertWorkRuntime) Run(ctx context.Context, _ uint32, _ workvpn.Profile, _ *journal.Session, notify func(worknet.Status)) error {
	notify(worknet.Status{State: "connecting", Stage: "resolving"})
	<-ctx.Done()
	return ctx.Err()
}
func (*inertWorkRuntime) Forget(context.Context, string) error                 { return nil }
func (*inertWorkRuntime) SetRules(context.Context, []workvpn.RouteRule) error  { return nil }
func (*inertWorkRuntime) SetDNSRules(context.Context, []workvpn.DNSRule) error { return nil }
func (*inertWorkRuntime) Routes() []worknet.RouteInfo                          { return []worknet.RouteInfo{} }
func (*inertWorkRuntime) Snapshot(string) worknet.Status {
	return worknet.Status{State: "disconnected"}
}
