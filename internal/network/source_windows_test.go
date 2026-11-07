package network

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type sourceTestConn struct {
	net.Conn
	close func() error
}

func (c *sourceTestConn) Close() error { return c.close() }

func TestSourceCloseSerializesAndCachesAllErrors(t *testing.T) {
	closeErr, guardErr, routeErr := errors.New("socket close"), errors.New("guard removal"), errors.New("route release")
	entered, release := make(chan struct{}), make(chan struct{})
	var socketCalls, cleanupCalls atomic.Int32
	var order []string
	conn := &sourceConn{
		Conn: &sourceTestConn{close: func() error {
			socketCalls.Add(1)
			close(entered)
			<-release
			order = append(order, "socket")
			return closeErr
		}},
		cleanup: func() error {
			cleanupCalls.Add(1)
			return cleanupSourceResources(func() error { order = append(order, "guard"); return guardErr },
				func() error { order = append(order, "route"); return routeErr })
		},
	}
	var wg sync.WaitGroup
	results := make([]error, 16)
	for i := range results {
		wg.Add(1)
		go func(index int) { defer wg.Done(); results[index] = conn.Close() }(i)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first Close did not enter")
	}
	if socketCalls.Load() != 1 || cleanupCalls.Load() != 0 {
		t.Fatal("concurrent Close bypassed the first in-flight close")
	}
	close(release)
	wg.Wait()
	if socketCalls.Load() != 1 || cleanupCalls.Load() != 1 || !reflect.DeepEqual(order, []string{"socket", "guard", "route"}) {
		t.Fatalf("close/guard-first/route-attempt order or count changed: sockets=%d cleanup=%d order=%v", socketCalls.Load(), cleanupCalls.Load(), order)
	}
	for _, result := range results {
		if result != results[0] || !errors.Is(result, closeErr) || !errors.Is(result, guardErr) || !errors.Is(result, routeErr) {
			t.Fatal("a concurrent Close lost or replaced its cached combined result", result)
		}
	}
	if conn.Close() != results[0] || socketCalls.Load() != 1 {
		t.Fatal("repeated Close called the socket again")
	}
}

func TestSourceFetchFinalizesTransportClosedAndStillOpenLeases(t *testing.T) {
	var scope sourceFetchLeases
	ctx, cancel := context.WithCancel(context.Background())
	firstErr, secondErr, failedDialErr := errors.New("first cleanup"), errors.New("second cleanup"), errors.New("failed dial cleanup")
	var closes [2]atomic.Int32
	for i, cleanupErr := range []error{firstErr, secondErr} {
		index, err := i, cleanupErr
		lease := &sourceConn{Conn: &sourceTestConn{close: func() error { closes[index].Add(1); return nil }}, cleanup: func() error { return err }}
		if !scope.begin() {
			t.Fatal("new fetch rejected a dial")
		}
		if err := scope.add(lease); err != nil {
			t.Fatal(err)
		}
		scope.pending.Done()
		if index == 0 {
			_ = lease.Close()
		} // net/http ignores this cleanup error.
	}
	scope.recordCleanup(failedDialErr)
	result := scope.finish(cancel)
	if ctx.Err() == nil || closes[0].Load() != 1 || closes[1].Load() != 1 {
		t.Fatal("fetch return did not cancel and finalize every lease exactly once")
	}
	for _, expected := range []error{firstErr, secondErr, failedDialErr} {
		if !errors.Is(result, expected) {
			t.Fatal("fetch finalization lost a cleanup error", expected, result)
		}
	}
	if scope.finish(func() { t.Fatal("finalization ran twice") }) != result {
		t.Fatal("finalization did not cache its error result")
	}
	if scope.begin() {
		t.Fatal("a callback entered after fetch finalization")
	}
}

func TestSourceFetchWaitsForLateDialAndImmediatelyCleansIt(t *testing.T) {
	var scope sourceFetchLeases
	if !scope.begin() {
		t.Fatal("dial admission failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- scope.finish(cancel) }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("finalization did not cancel outstanding dial context")
	}
	if scope.begin() {
		t.Fatal("new asynchronous dial entered while finalizing")
	}
	select {
	case <-finished:
		t.Fatal("fetch returned while an admitted dial could still acquire resources")
	default:
	}
	cleanupErr := errors.New("late lease cleanup")
	var closed, cleaned atomic.Int32
	lease := &sourceConn{Conn: &sourceTestConn{close: func() error { closed.Add(1); return nil }}, cleanup: func() error { cleaned.Add(1); return cleanupErr }}
	result := scope.add(lease)
	if !errors.Is(result, context.Canceled) || !errors.Is(result, cleanupErr) || closed.Load() != 1 || cleaned.Load() != 1 {
		t.Fatal("late successful dial was handed to HTTP instead of immediately cleaned", result)
	}
	scope.pending.Done()
	select {
	case result = <-finished:
		if !errors.Is(result, cleanupErr) || closed.Load() != 1 || cleaned.Load() != 1 {
			t.Fatal("final fetch result lost the late cleanup error or closed twice", result)
		}
	case <-time.After(time.Second):
		t.Fatal("fetch did not finish after the late dial cleanup completed")
	}
}
