package main

// Tests for run and its three helper phases (parseFlags/buildSwitches/
// startAll+stopAll). Hermetic: every started switch is a real loopback
// virtual.VirtualSwitch (see virtual/server.go), no external network, no
// process/os.Exit -- run itself is driven directly, exactly as main.go
// drives it, just with test-controlled stdin/stdout/stderr/stop instead of
// the real ones.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/snmp"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// syncBuffer is a concurrency-safe io.Writer over a bytes.Buffer: run's
// stderr writes happen on the goroutine startRun spawns while a test
// concurrently reads them (e.g. in a failure message before run has
// finished), which would race a plain bytes.Buffer under -race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// startRun runs run(args, stdin, ...) on a background goroutine (run
// blocks until stopped, so it cannot run on the test's own goroutine while
// the test still wants to interact with it) with a piped stdout, so a test
// can read announcement lines as they arrive while the fleet is still up.
// The returned wait func blocks (via sync.Once, so it is safe to call more
// than once -- both explicitly by a test AND by the registered t.Cleanup
// safety net below) until run returns, yielding its exit code exactly
// once.
//
// The registered t.Cleanup ALWAYS keeps draining stdoutR concurrently with
// sending stop: if a test fails (t.Fatalf) before reading every
// announcement line it asked for, run()'s startAll can be blocked mid-
// fleet on an io.Pipe write nobody is reading -- sending stop alone could
// never unstick that (run only reaches its stop-select AFTER startAll
// finishes), so the drain must run concurrently, not after.
func startRun(t *testing.T, args []string, stdin io.Reader) (stdoutR *io.PipeReader, stderrBuf *syncBuffer, stop chan os.Signal, wait func() int) {
	t.Helper()
	stdoutR, stdoutW := io.Pipe()
	stderrBuf = &syncBuffer{}
	stop = make(chan os.Signal, 1)
	raw := make(chan int, 1)
	go func() {
		code := run(args, stdin, stdoutW, stderrBuf, stop)
		_ = stdoutW.Close()
		raw <- code
	}()

	var once sync.Once
	var result int
	wait = func() int {
		once.Do(func() {
			select {
			case result = <-raw:
			case <-time.After(10 * time.Second):
				t.Error("run() did not return within 10s")
			}
		})
		return result
	}
	t.Cleanup(func() {
		drained := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, stdoutR)
			close(drained)
		}()
		select {
		case stop <- os.Interrupt:
		default:
		}
		wait()
		<-drained
	})
	return stdoutR, stderrBuf, stop, wait
}

// readAnnouncements reads exactly n newline-delimited JSON announcement
// lines from r, failing the test if any line is short or unparsable.
func readAnnouncements(t *testing.T, r *io.PipeReader, n int) []announcement {
	t.Helper()
	reader := bufio.NewReader(r)
	out := make([]announcement, 0, n)
	for i := 0; i < n; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading announcement line %d/%d: %v", i+1, n, err)
		}
		var a announcement
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatalf("unmarshal announcement line %d %q: %v", i+1, line, err)
		}
		out = append(out, a)
	}
	return out
}

// stopAndWait sends stop and waits (with a generous timeout, see
// startRun's wait) for run to return, asserting its exit code.
func stopAndWait(t *testing.T, stop chan os.Signal, wait func() int, wantCode int, stderrBuf *syncBuffer) {
	t.Helper()
	stop <- os.Interrupt
	if code := wait(); code != wantCode {
		t.Errorf("run() returned %d, want %d; stderr=%s", code, wantCode, stderrBuf.String())
	}
}

func dialAndClose(t *testing.T, network, addr string) {
	t.Helper()
	conn, err := net.DialTimeout(network, addr, 2*time.Second)
	if err != nil {
		t.Errorf("dial %s %s: %v", network, addr, err)
		return
	}
	_ = conn.Close()
}

// assertPortReleased proves a port is no longer bound by binding it
// ourselves -- if we can, the OS has genuinely released it, not just that
// this process's own handle looks closed.
func assertPortReleased(t *testing.T, network, host string, port int) {
	t.Helper()
	switch network {
	case "udp":
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: port})
		if err != nil {
			t.Errorf("UDP port %d not released after Stop: %v", port, err)
			return
		}
		_ = conn.Close()
	case "tcp":
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			t.Errorf("TCP port %d not released after Stop: %v", port, err)
			return
		}
		_ = ln.Close()
	default:
		t.Fatalf("assertPortReleased: unknown network %q", network)
	}
}

// -- announcement shape + port reachability ---------------------------------

// TestRunAnnouncesStartedSwitchesWithReachablePorts starts a fleet of two
// heterogeneous models over run() itself (gsm7252ps: SNMP+HTTP+SSH+Telnet;
// gsm7228ps: SNMP+HTTP+Telnet, NO SSH -- proving "absent faces omitted" for
// a face some OTHER served model does bind), reads their two announcement
// lines, dials every announced port to prove it is genuinely live (not
// just a nonzero number), then stops the fleet and confirms every port is
// released.
func TestRunAnnouncesStartedSwitchesWithReachablePorts(t *testing.T) {
	stdoutR, stderrBuf, stop, wait := startRun(t, []string{
		"--model", "gsm7252ps",
		"--model", "gsm7228ps",
	}, nil)

	got := readAnnouncements(t, stdoutR, 2)
	byModel := map[string]announcement{}
	for _, a := range got {
		byModel[a.Model] = a
	}

	full, ok := byModel["gsm7252ps"]
	if !ok {
		t.Fatalf("no announcement for gsm7252ps; stderr=%s", stderrBuf.String())
	}
	if full.Host != "127.0.0.1" {
		t.Errorf("gsm7252ps announced host = %q, want 127.0.0.1", full.Host)
	}
	if full.SNMPPort == 0 || full.HTTPPort == 0 || full.SSHPort == 0 || full.TelnetPort == 0 {
		t.Errorf("gsm7252ps announcement missing a bound port: %+v", full)
	}
	if full.NSDPPort != 0 {
		t.Errorf("gsm7252ps NSDPPort = %d, want 0/omitted (model has no BackendNSDP)", full.NSDPPort)
	}
	if full.Community != "public" || full.Password != "password" {
		t.Errorf("gsm7252ps community/password = %q/%q, want public/password", full.Community, full.Password)
	}

	telnetOnly, ok := byModel["gsm7228ps"]
	if !ok {
		t.Fatalf("no announcement for gsm7228ps; stderr=%s", stderrBuf.String())
	}
	if telnetOnly.SSHPort != 0 {
		t.Errorf("gsm7228ps SSHPort = %d, want 0/omitted (model has no BackendSSH)", telnetOnly.SSHPort)
	}
	if telnetOnly.TelnetPort == 0 {
		t.Error("gsm7228ps TelnetPort = 0, want nonzero")
	}

	// Every announced port must actually be reachable while the fleet is up.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snmpClient := snmp.NewGoSNMPClient(net.JoinHostPort(full.Host, strconv.Itoa(full.SNMPPort)), full.Community)
	if _, err := snmpClient.Get(ctx, []string{snmp.SysDescr}); err != nil {
		t.Errorf("SNMP GET against announced gsm7252ps port failed: %v", err)
	}
	dialAndClose(t, "tcp", net.JoinHostPort(full.Host, strconv.Itoa(full.SSHPort)))
	dialAndClose(t, "tcp", net.JoinHostPort(full.Host, strconv.Itoa(full.TelnetPort)))
	dialAndClose(t, "tcp", net.JoinHostPort(telnetOnly.Host, strconv.Itoa(telnetOnly.TelnetPort)))

	resp, err := http.Get("http://" + net.JoinHostPort(full.Host, strconv.Itoa(full.HTTPPort)) + "/")
	if err != nil {
		t.Errorf("HTTP GET against announced gsm7252ps port failed: %v", err)
	} else {
		_ = resp.Body.Close()
	}

	stopAndWait(t, stop, wait, exitOK, stderrBuf)

	// The ports must be genuinely released, not just this process's view of
	// them -- proven by successfully re-binding them ourselves.
	assertPortReleased(t, "udp", full.Host, full.SNMPPort)
	assertPortReleased(t, "tcp", full.Host, full.HTTPPort)
	assertPortReleased(t, "tcp", full.Host, full.SSHPort)
	assertPortReleased(t, "tcp", full.Host, full.TelnetPort)
}

// TestRunAllStartsEveryRegisteredModelIgnoringExplicitModel proves --all
// starts every registered model (not just the ones with an --model flag),
// AND that --all silently ignores an accompanying --model (even a
// nonsense one) rather than merging or erroring, mirroring _cmd_serve's
// own `list(MODELS) if args.all else ...` short-circuit.
func TestRunAllStartsEveryRegisteredModelIgnoringExplicitModel(t *testing.T) {
	want := allModelKeys()
	stdoutR, stderrBuf, stop, wait := startRun(t, []string{
		"--all", "--model", "not-a-real-model-and-must-be-ignored",
	}, nil)

	got := readAnnouncements(t, stdoutR, len(want))
	seen := map[string]bool{}
	for _, a := range got {
		seen[a.Model] = true
	}
	for _, key := range want {
		if !seen[key] {
			t.Errorf("no announcement for registered model %q; stderr=%s", key, stderrBuf.String())
		}
	}
	if seen["not-a-real-model-and-must-be-ignored"] {
		t.Error("announced the bogus --model key; --all must ignore --model entirely")
	}

	stopAndWait(t, stop, wait, exitOK, stderrBuf)
}

// TestRunStopsOnStdinEOF proves the design doc §8.3 stdin-EOF stop trigger
// (a Go-only addition beyond Python's SIGINT/SIGTERM-only serve_forever):
// closing stdin must cleanly stop the fleet exactly like a signal would,
// with no signal ever sent on stop.
func TestRunStopsOnStdinEOF(t *testing.T) {
	stdinR, stdinW := io.Pipe()
	stdoutR, stderrBuf, _, wait := startRun(t, []string{"--model", "gs305ep"}, stdinR)

	got := readAnnouncements(t, stdoutR, 1)
	if got[0].Model != "gs305ep" {
		t.Fatalf("announced model = %q, want gs305ep", got[0].Model)
	}
	if got[0].NSDPPort == 0 {
		t.Error("gs305ep NSDPPort = 0, want nonzero")
	}

	if err := stdinW.Close(); err != nil {
		t.Fatalf("closing stdin write end: %v", err)
	}
	if code := wait(); code != exitOK {
		t.Errorf("run() returned %d after stdin EOF, want %d; stderr=%s", code, exitOK, stderrBuf.String())
	}
}

// -- validation ---------------------------------------------------------

func TestRunValidationErrorsExitTwoWithNoStdout(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"neither --model nor --all", nil},
		{"--port with two models", []string{"--model", "gsm7252ps", "--model", "gs305ep", "--port", "5555"}},
		{"--http-port with two models", []string{"--model", "gsm7252ps", "--model", "gs305ep", "--http-port", "5555"}},
		{"unknown model", []string{"--model", "not-a-real-model"}},
		{"unrecognized positional argument", []string{"--model", "gsm7252ps", "extra-positional"}},
		{"unknown flag", []string{"--this-flag-does-not-exist"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			stderrBuf := &syncBuffer{}
			code := run(tt.args, nil, &stdout, stderrBuf, nil)
			if code != exitUsage {
				t.Errorf("run(%v) = %d, want %d (exitUsage); stderr=%s", tt.args, code, exitUsage, stderrBuf.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("run(%v) wrote to stdout, want none on a validation error: %q", tt.args, stdout.String())
			}
			if stderrBuf.String() == "" {
				t.Errorf("run(%v) wrote nothing to stderr, want an error message", tt.args)
			}
		})
	}
}

func TestRunHelpExitsZeroWithoutStartingAnything(t *testing.T) {
	var stdout bytes.Buffer
	stderrBuf := &syncBuffer{}
	code := run([]string{"--help"}, nil, &stdout, stderrBuf, nil)
	if code != exitOK {
		t.Errorf("run(--help) = %d, want %d (exitOK); stderr=%s", code, exitOK, stderrBuf.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("run(--help) wrote to stdout, want none: %q", stdout.String())
	}
}

// TestRunExitsWithErrorWhenNoSwitchesCouldBeServed pins a single model's
// --port to a UDP port this test occupies FIRST, so the switch's own
// Start() genuinely fails (a real "address already in use", not a fake
// error) -- proving run() reports and exits 1 when the whole (one-switch)
// fleet fails to come up, exactly like _cmd_serve's own `EXIT_OK if served
// else EXIT_ERROR`.
func TestRunExitsWithErrorWhenNoSwitchesCouldBeServed(t *testing.T) {
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("occupying a UDP port: %v", err)
	}
	defer func() { _ = occupied.Close() }()
	port := occupied.LocalAddr().(*net.UDPAddr).Port //nolint:forcetypeassert // net.ListenUDP("udp", ...) always returns a *net.UDPAddr from LocalAddr().

	var stdout bytes.Buffer
	stderrBuf := &syncBuffer{}
	code := run([]string{"--model", "gsm7252ps", "--port", strconv.Itoa(port)}, nil, &stdout, stderrBuf, nil)
	if code != exitError {
		t.Errorf("run() = %d, want %d (exitError); stderr=%s", code, exitError, stderrBuf.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty (nothing started, so no announcement)", stdout.String())
	}
	if !strings.Contains(stderrBuf.String(), "no switches could be served") {
		t.Errorf("stderr = %q, want it to report no switches served", stderrBuf.String())
	}
}

// -- startAll / buildSwitches (unit-level, below the flag-parsing layer) ----

// TestStartAllSkipsAFailingSwitchAndKeepsGoingWithTheRest manufactures a
// REAL Start() failure (two VirtualSwitches pinned, via WithPort, to the
// exact same already-bound UDP port) to prove startAll reports it on
// stderr and continues starting the rest of the fleet, mirroring
// virtual/server.py's serve_forever: "one bad model must not sink the
// fleet". This exercises the failure path run()'s own CLI validation can
// never reach directly, since --port is refused outright for more than one
// model.
func TestStartAllSkipsAFailingSwitchAndKeepsGoingWithTheRest(t *testing.T) {
	occupant, err := virtual.NewVirtualSwitch("gsm7252ps")
	if err != nil {
		t.Fatalf("NewVirtualSwitch(occupant): %v", err)
	}
	if err := occupant.Start(); err != nil {
		t.Fatalf("occupant Start(): %v", err)
	}
	t.Cleanup(func() { _ = occupant.Stop() })

	bad, err := virtual.NewVirtualSwitch("gsm7252ps", virtual.WithPort(occupant.SnmpPort))
	if err != nil {
		t.Fatalf("NewVirtualSwitch(bad): %v", err)
	}
	t.Cleanup(func() { _ = bad.Stop() })

	good, err := virtual.NewVirtualSwitch("gs305ep")
	if err != nil {
		t.Fatalf("NewVirtualSwitch(good): %v", err)
	}
	t.Cleanup(func() { _ = good.Stop() })

	switches := []*servedSwitch{
		{key: "bad-switch", sw: bad},
		{key: "good-switch", sw: good},
	}
	var stdout bytes.Buffer
	stderrBuf := &syncBuffer{}
	cfg := serveConfig{community: "public", httpPassword: "password"}
	started := startAll(switches, cfg, &stdout, stderrBuf)
	t.Cleanup(func() { stopAll(started, stderrBuf) })

	if len(started) != 1 || started[0].key != "good-switch" {
		t.Fatalf("startAll started %v, want exactly [good-switch]; stderr=%s", started, stderrBuf.String())
	}
	if !strings.Contains(stderrBuf.String(), `"bad-switch"`) {
		t.Errorf("stderr = %q, want a report naming the failed switch", stderrBuf.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout announcement lines = %d, want exactly 1 (only for the switch that started): %q", len(lines), stdout.String())
	}
	var a announcement
	if err := json.Unmarshal([]byte(lines[0]), &a); err != nil {
		t.Fatalf("unmarshal sole announcement %q: %v", lines[0], err)
	}
	if a.Model != "good-switch" {
		t.Errorf("sole announcement model = %q, want good-switch", a.Model)
	}
}

// TestBuildSwitchesAbortsImmediatelyOnFirstUnknownModel proves an unknown
// model key aborts the WHOLE construction loop (nothing built at all, not
// even the models before or after it in the list) -- mirroring
// _cmd_serve's own eager `VirtualSwitch(key, ...)` loop where an
// UnknownModelError returns EXIT_USAGE immediately, a different failure
// mode than a model that resolves but fails to bind any face at Start
// (that one is reported-and-skipped by startAll instead, see the sibling
// test above).
func TestBuildSwitchesAbortsImmediatelyOnFirstUnknownModel(t *testing.T) {
	cfg := serveConfig{
		modelKeys:    []string{"gsm7252ps", "not-a-real-model", "gs305ep"},
		host:         "127.0.0.1",
		community:    "public",
		httpPassword: "password",
	}
	stderrBuf := &syncBuffer{}
	switches, code, ok := buildSwitches(cfg, stderrBuf)
	if ok {
		t.Fatal("buildSwitches ok = true, want false for an unknown model key")
	}
	if code != exitUsage {
		t.Errorf("code = %d, want %d (exitUsage)", code, exitUsage)
	}
	if switches != nil {
		t.Errorf("switches = %v, want nil", switches)
	}
	if !strings.Contains(stderrBuf.String(), "not-a-real-model") {
		t.Errorf("stderr = %q, want it to name the bad model", stderrBuf.String())
	}
}

// -- leak proof -----------------------------------------------------------

// TestRunLeavesNoGoroutinesAfterCleanShutdown starts a switch with every
// face this package implements (gsm7252ps: SNMP+HTTP+SSH+Telnet, four real
// listeners/serve-goroutines) through run() itself, stops it via signal,
// and confirms the goroutine count returns to its pre-run baseline --
// proving run()'s defer/stopAll genuinely tears every face down rather
// than leaking a listener or its serve goroutine.
func TestRunLeavesNoGoroutinesAfterCleanShutdown(t *testing.T) {
	before := runtime.NumGoroutine()

	stdoutR, stderrBuf, stop, wait := startRun(t, []string{"--model", "gsm7252ps"}, nil)
	readAnnouncements(t, stdoutR, 1)
	stopAndWait(t, stop, wait, exitOK, stderrBuf)
	// Drain (nothing left, but Close the pipe's read side cleanly) and let
	// the announcement-writer's own goroutine (run's caller here) settle.
	_, _ = io.Copy(io.Discard, stdoutR)

	for i := 0; i < 50; i++ {
		if runtime.NumGoroutine() <= before {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutine count after run()+clean shutdown = %d, want <= %d (baseline)", after, before)
	}
}
