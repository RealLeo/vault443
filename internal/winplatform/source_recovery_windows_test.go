package winplatform

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestRecoverSourcesRevokesGuardsBeforeUnionRouteCleanup(t *testing.T) {
	const guardOnly = "source-0000000000000001"
	const routeOnly = "source-0000000000000002"
	const both = "source-0000000000000003"
	ignored := []string{"main-endpoints", "work:one", "source-", "source-0123456789abcde", "source-0123456789abcdef0", "source-0123456789abcdeF", "source-0123456789abcdeg"}
	guards := append([]string{both, guardOnly, both}, ignored...)
	routes := append([]string{routeOnly, both}, ignored...)
	guardError := errors.New("injected guard failure")
	routeError := errors.New("injected route failure")
	var calls []string
	err := recoverSourceOwners(context.Background(), guards, routes, func(owner string) error {
		calls = append(calls, "guard:"+owner)
		if owner == guardOnly {
			return guardError
		}
		return nil
	}, func(owner string) error {
		calls = append(calls, "route:"+owner)
		if owner == routeOnly {
			return routeError
		}
		return nil
	})
	if !errors.Is(err, guardError) || !errors.Is(err, routeError) {
		t.Fatalf("startup could overlook a failed cleanup: %v", err)
	}
	want := []string{"guard:" + guardOnly, "guard:" + routeOnly, "guard:" + both, "route:" + guardOnly, "route:" + routeOnly, "route:" + both}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("recovery touched non-temporary intent or changed cleanup order: %v", calls)
	}
}

func TestRecoverSourcesStopsWhenStartupIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := recoverSourceOwners(ctx, []string{"source-0000000000000001", "source-0000000000000002"}, []string{"source-0000000000000001"}, func(string) error {
		calls++
		cancel()
		return nil
	}, func(string) error {
		t.Fatal("cancelled startup proceeded to route cleanup")
		return nil
	})
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("startup cancellation was lost: calls=%d err=%v", calls, err)
	}
}
