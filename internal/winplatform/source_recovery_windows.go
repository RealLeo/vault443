package winplatform

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

func temporarySourceOwner(owner string) bool {
	if len(owner) != len("source-")+16 || !strings.HasPrefix(owner, "source-") {
		return false
	}
	for _, c := range owner[len("source-"):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// RecoverSources runs before engines/IPC start. Source connections belonged to
// the previous daemon and cannot survive it, unlike durable main or
// work intent. Only exact journal-owned temporary names may be pruned here.
func (c *Coordinator) RecoverSources(ctx context.Context) error {
	var guards, routes []string
	c.Guard.mu.Lock()
	for owner := range c.Guard.parts {
		guards = append(guards, owner)
	}
	c.Guard.mu.Unlock()
	c.Routes.mu.Lock()
	for owner := range c.Routes.owners {
		routes = append(routes, owner)
	}
	c.Routes.mu.Unlock()
	return recoverSourceOwners(ctx, guards, routes, c.Guard.Remove, func(owner string) error { return c.Routes.Set(owner, nil) })
}

func recoverSourceOwners(ctx context.Context, guards, routes []string, removeGuard, removeRoutes func(string) error) error {
	seen := map[string]bool{}
	var owners []string
	for _, journal := range [][]string{guards, routes} {
		for _, owner := range journal {
			if temporarySourceOwner(owner) && !seen[owner] {
				seen[owner] = true
				owners = append(owners, owner)
			}
		}
	}
	sort.Strings(owners)
	var result error
	// Revoke temporary physical exceptions first. Still attempt route cleanup if
	// a guard operation fails, retaining each subsystem's durable failed entry.
	for _, remove := range []func(string) error{removeGuard, removeRoutes} {
		for _, owner := range owners {
			if err := ctx.Err(); err != nil {
				return errors.Join(result, err)
			}
			if err := remove(owner); err != nil {
				result = errors.Join(result, fmt.Errorf("temporary source owner %s: %w", owner, err))
			}
		}
	}
	return result
}
