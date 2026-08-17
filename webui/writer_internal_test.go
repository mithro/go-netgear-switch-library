package webui

// writer_internal_test.go: white-box coverage for writer.go's unexported
// defaultGoAheadSleep and goaheadPoECycleComplete helpers -- neither is
// reachable from package webui_test's black-box tests (defaultGoAheadSleep
// is only ever exercised through WithClock-injected fakes there, since a
// real 60s PoE-cycle deadline is too slow for a unit test; the "port
// absent from the parsed rows" case goaheadPoECycleComplete's `now == nil`
// guard exists for has no black-box fake session that produces it without
// also breaking the write's own admin-state verify first). Mirrors
// snmp/writer_cycle_test.go's package-internal defaultSleep coverage
// (TestDefaultSleep*) exactly.

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDefaultGoAheadSleepReturnsCtxErrOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := defaultGoAheadSleep(ctx, 10*time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("defaultGoAheadSleep(cancelled, 10ms) = %v, want context.Canceled", err)
	}
}

func TestDefaultGoAheadSleepZeroDurationCancelledContextReturnsCtxErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := defaultGoAheadSleep(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("defaultGoAheadSleep(cancelled, 0) = %v, want context.Canceled", err)
	}
}

func TestDefaultGoAheadSleepZeroDurationIsNoOpWhenNotCancelled(t *testing.T) {
	if err := defaultGoAheadSleep(context.Background(), 0); err != nil {
		t.Fatalf("defaultGoAheadSleep(0): %v", err)
	}
}

func TestDefaultGoAheadSleepWaitsForDurationWhenNotCancelled(t *testing.T) {
	start := time.Now()
	if err := defaultGoAheadSleep(context.Background(), 10*time.Millisecond); err != nil {
		t.Fatalf("defaultGoAheadSleep(10ms): %v", err)
	}
	if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
		t.Errorf("defaultGoAheadSleep(10ms) returned after %v, want >= 10ms", elapsed)
	}
}

// TestGoaheadPoECycleCompleteNilStatus exercises the `now == nil` guard: a
// port entirely absent from the PoE page's parsed rows (goaheadPoEStatus
// returns nil, nil for that case) can never be considered "back", whatever
// it was doing before.
func TestGoaheadPoECycleCompleteNilStatus(t *testing.T) {
	if goaheadPoECycleComplete(nil, nil) {
		t.Error("goaheadPoECycleComplete(nil, nil) = true, want false")
	}
}
