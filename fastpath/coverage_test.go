package fastpath

// coverage_test.go: direct unit tests for small helpers and the serial
// transport's byte plumbing that the higher-level tests don't drive on every
// branch. Real assertions, not coverage theater.

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDefaultSleep_ZeroReturnsImmediately(t *testing.T) {
	if err := defaultSleep(context.Background(), 0); err != nil {
		t.Fatalf("defaultSleep(0): %v", err)
	}
	if err := defaultSleep(context.Background(), -time.Second); err != nil {
		t.Fatalf("defaultSleep(negative): %v", err)
	}
}

func TestDefaultSleep_PositiveDurationSleeps(t *testing.T) {
	start := time.Now()
	if err := defaultSleep(context.Background(), 2*time.Millisecond); err != nil {
		t.Fatalf("defaultSleep(2ms): %v", err)
	}
	if time.Since(start) < time.Millisecond {
		t.Fatalf("defaultSleep(2ms) returned too fast")
	}
}

func TestDefaultSleep_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := defaultSleep(ctx, 0); err == nil {
		t.Fatalf("defaultSleep(0, cancelled): want ctx err, got nil")
	}
	if err := defaultSleep(ctx, time.Hour); err == nil {
		t.Fatalf("defaultSleep(1h, cancelled): want ctx err, got nil")
	}
}

func TestFormatPointerHelpers(t *testing.T) {
	if got := derefOrEmpty(nil); got != "" {
		t.Fatalf("derefOrEmpty(nil) = %q, want \"\"", got)
	}
	s := "hi"
	if got := derefOrEmpty(&s); got != "hi" {
		t.Fatalf("derefOrEmpty(&s) = %q, want \"hi\"", got)
	}
	if got := formatIntPtr(nil); got != "none" {
		t.Fatalf("formatIntPtr(nil) = %q, want \"none\"", got)
	}
	n := 42
	if got := formatIntPtr(&n); got != "42" {
		t.Fatalf("formatIntPtr(&42) = %q, want \"42\"", got)
	}
	if got := formatStrPtr(nil); got != "none" {
		t.Fatalf("formatStrPtr(nil) = %q, want \"none\"", got)
	}
	if got := formatStrPtr(&s); got != `"hi"` {
		t.Fatalf("formatStrPtr(&s) = %q, want quoted", got)
	}
	if got := formatIntList([]int{1, 2, 3}); got != "[1, 2, 3]" {
		t.Fatalf("formatIntList([1,2,3]) = %q", got)
	}
	if got := formatIntList(nil); got != "[]" {
		t.Fatalf("formatIntList(nil) = %q, want \"[]\"", got)
	}
}

func TestShellDriver_CancelledContextErrorPaths(t *testing.T) {
	tr := &fakeTransport{}
	d := NewShellDriver(tr, ShellDriverConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Setup(ctx); err == nil {
		t.Fatalf("Setup(cancelled): want ctx error, got nil")
	}
	if _, err := d.Run(ctx, "show version"); err == nil {
		t.Fatalf("Run(cancelled): want ctx error, got nil")
	}
	if _, err := d.RunSCPCopy(ctx, "copy scp://x y", "pw"); err == nil {
		t.Fatalf("RunSCPCopy(cancelled): want ctx error, got nil")
	}
	if _, err := d.RunWriteMemory(ctx, "write memory", false); err == nil {
		t.Fatalf("RunWriteMemory(cancelled): want ctx error, got nil")
	}
}

func TestShellDriver_RunNoPromptBeforeEOFErrors(t *testing.T) {
	// The transport returns text that never contains a prompt, then EOF: Run's
	// readUntil must surface an ErrCliTransport-wrapped error, not hang or
	// return the garbage as success.
	tr := &fakeTransport{responder: func(string) string { return "garbage without any prompt\n" }}
	d := NewShellDriver(tr, ShellDriverConfig{})
	if _, err := d.Run(context.Background(), "show version"); err == nil {
		t.Fatalf("Run with no prompt before EOF: want error, got nil")
	} else if !errors.Is(err, ErrCliTransport) {
		t.Fatalf("Run error = %v, want wrapping ErrCliTransport", err)
	}
}

func TestNewSerialTransport_OpenErrorWrapsErrCliTransport(t *testing.T) {
	// A nonexistent device path makes serial.Open fail, exercising
	// NewSerialTransport's config/mode/open + error-wrapping path (the
	// real-device success path needs actual hardware, deferred to slice 11).
	_, err := NewSerialTransport(SerialConfig{
		Device:   "/dev/nonexistent-fastpath-cli-test-tty",
		Username: "admin",
		Password: "x",
	})
	if err == nil {
		t.Fatalf("NewSerialTransport on a bogus device: want error, got nil")
	}
	if !errors.Is(err, ErrCliTransport) {
		t.Fatalf("NewSerialTransport error = %v, want wrapping ErrCliTransport", err)
	}
}

func TestSerialTransport_WriteReadCloseViaFakePort(t *testing.T) {
	port := &fakeSerialPort{}
	tr := &serialTransport{port: port}

	n, err := tr.Write([]byte("show version\r\n"))
	if err != nil || n == 0 {
		t.Fatalf("serialTransport.Write: n=%d err=%v", n, err)
	}
	if len(port.writes) != 1 || port.writes[0] != "show version\r\n" {
		t.Fatalf("fake port did not receive the write: %v", port.writes)
	}

	// A timed-out read (fake returns (0,nil)) surfaces as (0, nil) pre-Close.
	buf := make([]byte, 8)
	if rn, rerr := tr.Read(buf); rn != 0 || rerr != nil {
		t.Fatalf("pre-Close Read: want (0,nil), got (%d,%v)", rn, rerr)
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("serialTransport.Close: %v", err)
	}
	if !port.closed {
		t.Fatalf("Close did not close the underlying port")
	}
}
