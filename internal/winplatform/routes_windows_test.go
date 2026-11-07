package winplatform

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/windows"
)

// These tests change a temporary private journal, never the machine's FIB.
type fakeRouteOps struct {
	rows                 map[string]uint32
	lookupErr, deleteErr error
	adds, deletes        int
}

func (f *fakeRouteOps) Lookup(route OwnedRoute) (uint32, error) {
	if f.lookupErr != nil {
		return 0, f.lookupErr
	}
	if metric, ok := f.rows[route.nativeKey()]; ok {
		return metric, nil
	}
	return 0, windows.ERROR_NOT_FOUND
}
func (f *fakeRouteOps) Add(route OwnedRoute) error {
	if _, exists := f.rows[route.nativeKey()]; exists {
		return windows.ERROR_OBJECT_ALREADY_EXISTS
	}
	f.rows[route.nativeKey()] = route.metric()
	f.adds++
	return nil
}
func (f *fakeRouteOps) Delete(route OwnedRoute) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.rows, route.nativeKey())
	f.deletes++
	return nil
}

func testRoutes(t *testing.T) (*Routes, *fakeRouteOps, OwnedRoute) {
	t.Helper()
	r, err := NewRoutes(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRouteOps{rows: map[string]uint32{}}
	r.ops = f
	return r, f, Route(11, netip.MustParsePrefix("93.184.215.14/32"), netip.MustParseAddr("192.0.2.1"))
}

func assertRouteOwner(t *testing.T, r *Routes, owner string, want int) {
	t.Helper()
	if len(r.owners[owner]) != want {
		t.Fatalf("memory owner %q has %d routes, want %d", owner, len(r.owners[owner]), want)
	}
	reloaded, err := NewRoutes(filepath.Dir(r.path))
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.owners[owner]) != want {
		t.Fatalf("durable owner %q has %d routes, want %d", owner, len(reloaded.owners[owner]), want)
	}
}

func TestRoutesSharedReferenceSurvivesReloadAndFirstOwnerRelease(t *testing.T) {
	r, f, route := testRoutes(t)
	for _, owner := range []string{"source-0123456789abcdef", "main-endpoints"} {
		if err := r.Set(owner, []OwnedRoute{route, route}); err != nil {
			t.Fatal(err)
		}
		assertRouteOwner(t, r, owner, 1)
	}
	if f.adds != 1 {
		t.Fatalf("shared row added %d times", f.adds)
	}
	// Restart must retain the sharing proof, not just this process's refcount.
	reloaded, err := NewRoutes(filepath.Dir(r.path))
	if err != nil {
		t.Fatal(err)
	}
	reloaded.ops = f
	if err = reloaded.Set("source-0123456789abcdef", nil); err != nil {
		t.Fatal(err)
	}
	assertRouteOwner(t, reloaded, "source-0123456789abcdef", 0)
	assertRouteOwner(t, reloaded, "main-endpoints", 1)
	if f.deletes != 0 || len(f.rows) != 1 {
		t.Fatal("releasing temporary owner removed a main endpoint route")
	}
	if err = reloaded.Set("main-endpoints", nil); err != nil {
		t.Fatal(err)
	}
	assertRouteOwner(t, reloaded, "main-endpoints", 0)
	if f.deletes != 1 || len(f.rows) != 0 {
		t.Fatal("last owner did not remove its native row")
	}
}

func TestRoutesPreserveForeignRowsAndMetrics(t *testing.T) {
	for _, metric := range []uint32{7, ownedMetric} {
		t.Run(strconv.FormatUint(uint64(metric), 10), func(t *testing.T) {
			r, f, route := testRoutes(t)
			f.rows[route.nativeKey()] = metric
			if err := r.Set("source-0123456789abcdef", []OwnedRoute{route}); err != nil {
				t.Fatal(err)
			}
			if len(r.owners) != 0 {
				t.Fatal("pre-existing row was claimed without a journal ownership proof")
			}
			if err := r.Set("source-0123456789abcdef", nil); err != nil {
				t.Fatal(err)
			}
			if f.deletes != 0 || f.rows[route.nativeKey()] != metric {
				t.Fatal("foreign route changed during cleanup")
			}
		})
	}
	r, f, route := testRoutes(t)
	if err := r.Set("main-endpoints", []OwnedRoute{route}); err != nil {
		t.Fatal(err)
	}
	f.rows[route.nativeKey()] = 19 // Native owner replaced our metric.
	if err := r.Set("main-endpoints", nil); err != nil {
		t.Fatal(err)
	}
	assertRouteOwner(t, r, "main-endpoints", 0)
	if f.deletes != 0 || f.rows[route.nativeKey()] != 19 {
		t.Fatal("external metric change was deleted as an owned route")
	}
}

func TestRoutesCleanupErrorsRetainDurableOwnershipForRetry(t *testing.T) {
	for _, operation := range []string{"lookup", "delete"} {
		t.Run(operation, func(t *testing.T) {
			r, f, route := testRoutes(t)
			const owner = "source-0123456789abcdef"
			if err := r.Set(owner, []OwnedRoute{route}); err != nil {
				t.Fatal(err)
			}
			transient := errors.New("injected transient route error")
			if operation == "lookup" {
				f.lookupErr = transient
			} else {
				f.deleteErr = transient
			}
			if err := r.Set(owner, nil); !errors.Is(err, transient) {
				t.Fatalf("cleanup lost its error: %v", err)
			}
			assertRouteOwner(t, r, owner, 1)
			if len(f.rows) != 1 {
				t.Fatal("failed native operation removed the route")
			}
			f.lookupErr, f.deleteErr = nil, nil
			if err := r.Set(owner, nil); err != nil {
				t.Fatal(err)
			}
			assertRouteOwner(t, r, owner, 0)
			if len(f.rows) != 0 || f.deletes != 1 {
				t.Fatal("cleanup retry did not remove the retained route")
			}
		})
	}
}

func TestRoutesRejectConflictingOwnedMetric(t *testing.T) {
	r, f, route := testRoutes(t)
	if err := r.Set("main-endpoints", []OwnedRoute{route}); err != nil {
		t.Fatal(err)
	}
	priority := route
	priority.Priority = true
	if err := r.Set("work:test", []OwnedRoute{priority}); err == nil {
		t.Fatal("incompatible metrics shared the same native route")
	}
	assertRouteOwner(t, r, "work:test", 0)
	assertRouteOwner(t, r, "main-endpoints", 1)
	if f.adds != 1 || f.deletes != 0 || f.rows[route.nativeKey()] != ownedMetric {
		t.Fatal("conflicting request changed the original endpoint route")
	}
}
