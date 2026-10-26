package core

import (
	"context"
	"errors"
	"testing"
)

func TestCanceledStartDoesNotProbeOrLaunchCore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CheckBinaryContext(ctx, "/does-not-exist"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled verification proceeded", err)
	}
	var process Process
	if err := process.Start(ctx, "/does-not-exist", "/private/config"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled start proceeded", err)
	}
	if process.Alive() {
		t.Fatal("canceled start left a core running")
	}
}
