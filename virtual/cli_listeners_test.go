package virtual

// cli_listeners_test.go tests Task 12's real loopback SSH/Telnet CLI
// listeners (sshface.go, telnetface.go) -- the cross-language safety net
// the task brief calls for: every test here drives the REAL fastpath
// client (fastpath.NewSSHTransport/NewTelnetTransport, Tasks 6-7, plus
// ShellDriver/Reader/Writer, Tasks 5/8-10) against a REAL loopback socket a
// listener in THIS package is serving, exactly as a future cross-language
// client (slice 10) will. No internals are peeked at: every assertion goes
// through the same public fastpath API a caller outside this module would
// use.

import (
	"context"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/fastpath"
	"github.com/mithro/go-netgear-switch-library/model"
)

// dialSSHDriver dials host:port with username/password, completes
// ShellDriver.Setup, and returns the ready *fastpath.ShellDriver -- the
// exact sequence a real caller (or fastpath.Reader/Writer, which take a
// fastpath.Session) performs. t.Helper's Fatal calls make every caller's
// own failure point the useful one.
func dialSSHDriver(t *testing.T, port int, username, password string) *fastpath.ShellDriver {
	t.Helper()
	transport, err := fastpath.NewSSHTransport(fastpath.SSHConfig{
		Host:     "127.0.0.1",
		Port:     port,
		Username: username,
		Password: password,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSSHTransport() error = %v", err)
	}
	driver := fastpath.NewShellDriver(transport, fastpath.ShellDriverConfig{})
	if err := driver.Setup(context.Background()); err != nil {
		t.Fatalf("ShellDriver.Setup() over SSH error = %v", err)
	}
	return driver
}

// dialTelnetDriver is dialSSHDriver's Telnet analogue.
func dialTelnetDriver(t *testing.T, port int, username, password string) *fastpath.ShellDriver {
	t.Helper()
	transport, err := fastpath.NewTelnetTransport(fastpath.TelnetConfig{
		Host:     "127.0.0.1",
		Port:     port,
		Username: username,
		Password: password,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewTelnetTransport() error = %v", err)
	}
	driver := fastpath.NewShellDriver(transport, fastpath.ShellDriverConfig{})
	if err := driver.Setup(context.Background()); err != nil {
		t.Fatalf("ShellDriver.Setup() over Telnet error = %v", err)
	}
	return driver
}

// assertGSM7252PSPort1 mirrors cliface_test.go's own in-process assertion
// (TestCliFaceReadRoundTripGSM7252PS) against the SAME seed fact (seed.go:
// 93: port 1 admin+link up, 1000 Mbps) -- proving the real-socket listener
// answers identically to the in-process face it wraps.
func assertGSM7252PSPort1(t *testing.T, ports []model.PortStatus) {
	t.Helper()
	for _, p := range ports {
		if p.Port != 1 {
			continue
		}
		if !p.AdminEnabled || !p.LinkUp {
			t.Errorf("port 1 = %+v, want admin+link up", p)
		}
		if p.SpeedMbps == nil || *p.SpeedMbps != 1000 {
			t.Errorf("port 1 SpeedMbps = %v, want 1000", p.SpeedMbps)
		}
		return
	}
	t.Fatal("port 1 missing from GetPorts")
}

// --- 1. real-client round trip over a real socket (task brief's core proof) --

// TestSSHFaceRoundTripThroughRealFastpathClient starts an SSHFace over a
// seeded gsm7252ps state, dials it with the REAL fastpath SSH client
// (Task 6, through ShellDriver -> Reader), and asserts GetPorts matches the
// seed -- proving the full stack (legacy-KEX SSH handshake, password auth,
// PTY shell, ShellDriver framing, CliFace dispatch, render) works over an
// actual TCP socket exactly as a real cross-language client will.
func TestSSHFaceRoundTripThroughRealFastpathClient(t *testing.T) {
	st := SeedGSM7252PS()
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel() error = %v", err)
	}
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		t.Fatalf("fastpath.CLISpec() error = %v", err)
	}
	face := NewSSHFace(st, spec, "admin", "s3cret", "127.0.0.1")
	port, err := face.Start()
	if err != nil {
		t.Fatalf("SSHFace.Start() error = %v", err)
	}
	defer func() { _ = face.Stop() }()

	driver := dialSSHDriver(t, port, "admin", "s3cret")
	defer func() { _ = driver.Close() }()

	reader, err := fastpath.NewReader(driver, m)
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}
	ports, err := reader.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	assertGSM7252PSPort1(t, ports)
}

// TestSSHFaceWrongPasswordIsRejected proves the fake actually enforces the
// configured credential (not merely accepting any connection) -- an
// SSH-level auth failure, not a CLI-level one.
func TestSSHFaceWrongPasswordIsRejected(t *testing.T) {
	st := SeedGSM7252PS()
	m, _ := model.GetModel("gsm7252ps")
	spec, _ := fastpath.CLISpec(m)
	face := NewSSHFace(st, spec, "admin", "s3cret", "127.0.0.1")
	port, err := face.Start()
	if err != nil {
		t.Fatalf("SSHFace.Start() error = %v", err)
	}
	defer func() { _ = face.Stop() }()

	_, err = fastpath.NewSSHTransport(fastpath.SSHConfig{
		Host: "127.0.0.1", Port: port,
		Username: "admin", Password: "wrong-password",
		Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("NewSSHTransport() with wrong password succeeded, want error")
	}
}

// TestTelnetFaceRoundTripThroughRealFastpathClient is
// TestSSHFaceRoundTripThroughRealFastpathClient's Telnet analogue (Task 7's
// client instead of Task 6's), against a gsm7228ps seed (Telnet-only real
// hardware per the transport dossier, though this Go registry entry also
// carries BackendSSH -- see telnetface.go's own doc comment; using it here
// exercises the model whose real firmware genuinely has no other CLI
// transport).
func TestTelnetFaceRoundTripThroughRealFastpathClient(t *testing.T) {
	st := SeedGSM7228PS()
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("model.GetModel() error = %v", err)
	}
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		t.Fatalf("fastpath.CLISpec() error = %v", err)
	}
	face := NewTelnetFace(st, spec, "admin", "s3cret", "127.0.0.1")
	port, err := face.Start()
	if err != nil {
		t.Fatalf("TelnetFace.Start() error = %v", err)
	}
	defer func() { _ = face.Stop() }()

	driver := dialTelnetDriver(t, port, "admin", "s3cret")
	defer func() { _ = driver.Close() }()

	reader, err := fastpath.NewReader(driver, m)
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}
	ports, err := reader.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) == 0 {
		t.Fatal("GetPorts() returned no ports")
	}
}

// TestTelnetFaceWrongPasswordIsRejected is
// TestSSHFaceWrongPasswordIsRejected's Telnet analogue: the login handshake
// itself must fail closed (the fake closes the connection rather than
// letting a bad credential through), surfacing as Setup's first readUntil
// hitting EOF.
func TestTelnetFaceWrongPasswordIsRejected(t *testing.T) {
	st := SeedGSM7228PS()
	m, _ := model.GetModel("gsm7228ps")
	spec, _ := fastpath.CLISpec(m)
	face := NewTelnetFace(st, spec, "admin", "s3cret", "127.0.0.1")
	port, err := face.Start()
	if err != nil {
		t.Fatalf("TelnetFace.Start() error = %v", err)
	}
	defer func() { _ = face.Stop() }()

	transport, err := fastpath.NewTelnetTransport(fastpath.TelnetConfig{
		Host: "127.0.0.1", Port: port,
		Username: "admin", Password: "wrong-password",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		// A dial/login-transport-level failure is an acceptable outcome
		// too, but the expected shape (telnetLogin itself never confirms
		// the password) is that Setup fails instead -- see below.
		return
	}
	defer func() { _ = transport.Close() }()
	driver := fastpath.NewShellDriver(transport, fastpath.ShellDriverConfig{})
	if err := driver.Setup(context.Background()); err == nil {
		t.Fatal("ShellDriver.Setup() with wrong telnet password succeeded, want error (fake must fail closed)")
	}
}

// --- 2. concurrent connections: independent mode stacks, shared state -----

// TestSSHFaceConcurrentConnectionsIndependentModeStacksSharedState opens TWO
// simultaneous real SSH connections against the SAME SSHFace and proves the
// task brief's core isolation contract: each connection's *CliFace has its
// OWN command-mode stack (driving one deep into `configure`/`interface`
// mode never affects the other, still sitting at EXEC), while a write
// committed on one connection is immediately visible when read back on the
// OTHER -- because both share the ONE underlying *State.
func TestSSHFaceConcurrentConnectionsIndependentModeStacksSharedState(t *testing.T) {
	st := SeedGSM7252PS()
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel() error = %v", err)
	}
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		t.Fatalf("fastpath.CLISpec() error = %v", err)
	}
	face := NewSSHFace(st, spec, "admin", "s3cret", "127.0.0.1")
	port, err := face.Start()
	if err != nil {
		t.Fatalf("SSHFace.Start() error = %v", err)
	}
	defer func() { _ = face.Stop() }()

	ctx := context.Background()
	driverA := dialSSHDriver(t, port, "admin", "s3cret")
	defer func() { _ = driverA.Close() }()
	driverB := dialSSHDriver(t, port, "admin", "s3cret")
	defer func() { _ = driverB.Close() }()

	// A drives itself deep into interface-config mode and stays there.
	if out, err := driverA.Run(ctx, "configure"); err != nil || out != "" {
		t.Fatalf(`A: Run("configure") = (%q, %v), want ("", nil)`, out, err)
	}
	if out, err := driverA.Run(ctx, "interface "+spec.Iface(7)); err != nil || out != "" {
		t.Fatalf(`A: Run("interface %s") = (%q, %v), want ("", nil)`, spec.Iface(7), out, err)
	}

	// B, on its own independent connection, is COMPLETELY unaffected by A's
	// mode: an ordinary show command still answers normally over B, proving
	// B's *CliFace never saw A's "configure"/"interface" commands at all.
	out, err := driverB.Run(ctx, spec.VersionCmd)
	if err != nil {
		t.Fatalf("B: Run(%q) error = %v", spec.VersionCmd, err)
	}
	if out == "" || strings.Contains(out, "Invalid") || strings.Contains(out, "not found") {
		t.Errorf("B: Run(%q) = %q, want a normal show-version reply (B must not be affected by A's mode)", spec.VersionCmd, out)
	}

	// A backs all the way out (mirrors a real shell's "end").
	if out, err := driverA.Run(ctx, "end"); err != nil || out != "" {
		t.Fatalf(`A: Run("end") = (%q, %v), want ("", nil)`, out, err)
	}

	// A commits a real VLAN write via the real fastpath.Writer over its own
	// connection...
	writerA, err := fastpath.NewWriter(driverA, m)
	if err != nil {
		t.Fatalf("NewWriter() error = %v", err)
	}
	const vlanID, vlanName = 50, "concurrent-test"
	if err := writerA.CreateVLAN(ctx, vlanID, vlanName); err != nil {
		t.Fatalf("A: CreateVLAN(%d, %q) error = %v", vlanID, vlanName, err)
	}

	// ...and it is visible reading back over B's SEPARATE connection,
	// proving both share the same underlying *State despite each having its
	// own independent *CliFace/mode stack.
	readerB, err := fastpath.NewReader(driverB, m)
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}
	vlans, err := readerB.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("B: GetVLANs() error = %v", err)
	}
	found := false
	for _, v := range vlans {
		if v.VlanID == vlanID {
			found = true
			if v.Name == nil || *v.Name != vlanName {
				t.Errorf("B: VLAN %d Name = %v, want %q", vlanID, v.Name, vlanName)
			}
		}
	}
	if !found {
		t.Errorf("B: GetVLANs() = %+v, want VLAN %d (created over connection A) present", vlans, vlanID)
	}
}

// --- 3. leak-free Stop() (transport dossier §5) ----------------------------

func countOpenCLIFDs() (count int, ok bool) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	return len(entries), true
}

// waitForGoroutineBaseline polls runtime.NumGoroutine() until it returns to
// (or below) before, giving just-exited goroutines time to actually unwind
// -- mirrors TestHTTPFaceStartStopCyclesLeakNoGoroutinesOrFDs/
// TestSnmpFaceStartStopCyclesLeakNoGoroutinesOrFDs exactly.
func waitForGoroutineBaseline(before int) int {
	for i := 0; i < 50; i++ {
		if runtime.NumGoroutine() <= before {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}

// TestSSHFaceStartStopCyclesLeakNoGoroutinesOrFDs runs 10 start/connect/
// disconnect/stop cycles -- each opening a REAL SSH connection, completing
// Setup, running one command, and closing it before Stop -- and asserts
// neither the goroutine count nor the open-FD count grows past the
// pre-loop baseline: every accepted connection's handler goroutine, and
// the listener socket itself, are actually released, not merely asked to
// be (mirrors TestHTTPFaceStartStopCyclesLeakNoGoroutinesOrFDs, adapted to
// also drive a real per-cycle connection since SSHFace's leak surface is
// per-CONNECTION, not just per-listener).
func TestSSHFaceStartStopCyclesLeakNoGoroutinesOrFDs(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel() error = %v", err)
	}
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		t.Fatalf("fastpath.CLISpec() error = %v", err)
	}

	beforeGoroutines := runtime.NumGoroutine()
	beforeFDs, haveFDs := countOpenCLIFDs()

	for i := 0; i < 10; i++ {
		face := NewSSHFace(SeedGSM7252PS(), spec, "admin", "s3cret", "127.0.0.1")
		port, err := face.Start()
		if err != nil {
			t.Fatalf("cycle %d: Start() error = %v", i, err)
		}
		if port == 0 {
			t.Fatalf("cycle %d: Start() returned port 0", i)
		}

		driver := dialSSHDriver(t, port, "admin", "s3cret")
		if _, err := driver.Run(context.Background(), spec.VersionCmd); err != nil {
			t.Fatalf("cycle %d: Run() error = %v", i, err)
		}
		if err := driver.Close(); err != nil {
			t.Fatalf("cycle %d: driver.Close() error = %v", i, err)
		}

		if err := face.Stop(); err != nil {
			t.Fatalf("cycle %d: Stop() error = %v", i, err)
		}
		// A second Stop must be a harmless no-op (idempotent).
		if err := face.Stop(); err != nil {
			t.Fatalf("cycle %d: second Stop() error = %v", i, err)
		}
	}

	if after := waitForGoroutineBaseline(beforeGoroutines); after > beforeGoroutines {
		t.Errorf("goroutine count after 10 SSH connect/disconnect + start/stop cycles = %d, want <= %d (baseline)", after, beforeGoroutines)
	}
	if haveFDs {
		if afterFDs, ok := countOpenCLIFDs(); ok && afterFDs > beforeFDs {
			t.Errorf("open FD count after 10 cycles = %d, want <= %d (baseline; every socket must be released)", afterFDs, beforeFDs)
		}
	}
}

// TestTelnetFaceStartStopCyclesLeakNoGoroutinesOrFDs is
// TestSSHFaceStartStopCyclesLeakNoGoroutinesOrFDs's Telnet analogue.
func TestTelnetFaceStartStopCyclesLeakNoGoroutinesOrFDs(t *testing.T) {
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("model.GetModel() error = %v", err)
	}
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		t.Fatalf("fastpath.CLISpec() error = %v", err)
	}

	beforeGoroutines := runtime.NumGoroutine()
	beforeFDs, haveFDs := countOpenCLIFDs()

	for i := 0; i < 10; i++ {
		face := NewTelnetFace(SeedGSM7228PS(), spec, "admin", "s3cret", "127.0.0.1")
		port, err := face.Start()
		if err != nil {
			t.Fatalf("cycle %d: Start() error = %v", i, err)
		}
		if port == 0 {
			t.Fatalf("cycle %d: Start() returned port 0", i)
		}

		driver := dialTelnetDriver(t, port, "admin", "s3cret")
		if _, err := driver.Run(context.Background(), spec.VersionCmd); err != nil {
			t.Fatalf("cycle %d: Run() error = %v", i, err)
		}
		if err := driver.Close(); err != nil {
			t.Fatalf("cycle %d: driver.Close() error = %v", i, err)
		}

		if err := face.Stop(); err != nil {
			t.Fatalf("cycle %d: Stop() error = %v", i, err)
		}
		if err := face.Stop(); err != nil {
			t.Fatalf("cycle %d: second Stop() error = %v", i, err)
		}
	}

	if after := waitForGoroutineBaseline(beforeGoroutines); after > beforeGoroutines {
		t.Errorf("goroutine count after 10 Telnet connect/disconnect + start/stop cycles = %d, want <= %d (baseline)", after, beforeGoroutines)
	}
	if haveFDs {
		if afterFDs, ok := countOpenCLIFDs(); ok && afterFDs > beforeFDs {
			t.Errorf("open FD count after 10 cycles = %d, want <= %d (baseline; every socket must be released)", afterFDs, beforeFDs)
		}
	}
}

// TestSSHFaceStopWithoutClientDisconnectingIsStillBounded proves Stop()
// does not hang forever waiting for a client that never disconnects (the
// hazard SSHFace.Stop's own doc comment calls out: srv.Shutdown alone would
// wait indefinitely) -- opens a real connection, completes Setup, and calls
// Stop WITHOUT ever closing the client side first.
func TestSSHFaceStopWithoutClientDisconnectingIsStillBounded(t *testing.T) {
	m, _ := model.GetModel("gsm7252ps")
	spec, _ := fastpath.CLISpec(m)
	face := NewSSHFace(SeedGSM7252PS(), spec, "admin", "s3cret", "127.0.0.1")
	port, err := face.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	driver := dialSSHDriver(t, port, "admin", "s3cret")
	defer func() { _ = driver.Close() }() // closed AFTER Stop, deliberately

	done := make(chan error, 1)
	go func() { done <- face.Stop() }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop() did not return within 10s with a client still connected -- not leak-free/bounded")
	}
}

// TestTelnetFaceStopWithoutClientDisconnectingIsStillBounded is
// TestSSHFaceStopWithoutClientDisconnectingIsStillBounded's Telnet analogue.
func TestTelnetFaceStopWithoutClientDisconnectingIsStillBounded(t *testing.T) {
	m, _ := model.GetModel("gsm7228ps")
	spec, _ := fastpath.CLISpec(m)
	face := NewTelnetFace(SeedGSM7228PS(), spec, "admin", "s3cret", "127.0.0.1")
	port, err := face.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	driver := dialTelnetDriver(t, port, "admin", "s3cret")
	defer func() { _ = driver.Close() }()

	done := make(chan error, 1)
	go func() { done <- face.Stop() }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop() did not return within 10s with a client still connected -- not leak-free/bounded")
	}
}

// TestSSHFaceStopBeforeStartIsNoOp mirrors HTTPFace/SnmpFace's own
// equivalent test.
func TestSSHFaceStopBeforeStartIsNoOp(t *testing.T) {
	m, _ := model.GetModel("gsm7252ps")
	spec, _ := fastpath.CLISpec(m)
	face := NewSSHFace(SeedGSM7252PS(), spec, "admin", "s3cret", "127.0.0.1")
	if err := face.Stop(); err != nil {
		t.Errorf("Stop() before Start() error = %v, want nil (no-op)", err)
	}
}

// --- 3b. bounded Stop() under a concurrent-connect race (regression) ------
//
// TestSSHFaceStopBoundedUnderConcurrentConnectRace below reproduces an
// intermittent `go test ./...` hang (no -race needed; timing-sensitive, so
// -race's own slowdown tends to mask it) root-caused to a genuine goroutine
// dump: `f.wg.Wait()` in Stop blocking forever on the background Serve
// goroutine Start spawns, because Stop raced it and won -- see sshface.go's
// Stop doc comment (gap 1: the listener itself, closed only via gliderlabs'
// own trackListener-gated bookkeeping) for the exact mechanism the fix
// closes. Firing MANY concurrent real SSH dials at Start's freshly-returned
// port, with Stop launched concurrently rather than after any of them
// complete, maximizes the odds of a dial landing in the exact "accepted,
// not yet registered" window the race depends on -- reliably hitting it
// well within a handful of cycles pre-fix (see this task's own
// mutation-verification, not committed: with SSHFace.Stop's direct
// ln.Close()/conns force-close reverted to the old srv.Close()-only body,
// cycle 0 already hangs and dumps goroutine 9 blocked in
// net.(*TCPListener).Accept inside gliderlabs' (*Server).Serve).
//
// TelnetFace's own analogous race (acceptLoop/trackConn, telnetface.go's own
// doc comment) is NARROWER -- a handful of uninterrupted Go instructions
// with no intervening syscall to hand scheduling to another goroutine,
// unlike SSHFace's whole-goroutine-spinup window above -- and
// TestTelnetFaceStopBoundedUnderConcurrentConnectRace below, despite firing
// the same concurrent-dial shape (now with a RAW, uncooperative client; see
// its own doc comment for why a cooperative one cannot even self-heal this
// particular race), essentially never lands in that window by pure timing
// in practice (measured over 6000+ attempts, zero failures pre-fix). It is
// still worth keeping as a broad load/leak smoke test, but the ACTUAL
// mutation-verified regression coverage for TelnetFace's race is
// TestTelnetFaceStopAcceptTrackRaceDeterministic further below, which forces
// the exact interleaving by construction via telnetAcceptTrackHook rather
// than hoping for it.
func TestSSHFaceStopBoundedUnderConcurrentConnectRace(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel() error = %v", err)
	}
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		t.Fatalf("fastpath.CLISpec() error = %v", err)
	}

	// cycles/dialers is deliberately modest: the race this reproduces (see
	// sshface.go's Stop doc comment) was empirically 100% reproducible on
	// cycle 0 pre-fix in every run during this test's own development
	// (including its mutation-verification, not committed) -- a bigger loop
	// buys negligible extra confidence at real cost to every `go test
	// ./virtual/...` invocation (SSH's 2048-bit host-key generation on every
	// Start() dominates this test's runtime).
	const cycles, dialers = 8, 12
	for i := 0; i < cycles; i++ {
		face := NewSSHFace(SeedGSM7252PS(), spec, "admin", "s3cret", "127.0.0.1")
		port, err := face.Start()
		if err != nil {
			t.Fatalf("cycle %d: Start() error = %v", i, err)
		}

		var dialWG sync.WaitGroup
		for j := 0; j < dialers; j++ {
			dialWG.Add(1)
			go func() {
				defer dialWG.Done()
				transport, err := fastpath.NewSSHTransport(fastpath.SSHConfig{
					Host: "127.0.0.1", Port: port,
					Username: "admin", Password: "s3cret",
					Timeout: 2 * time.Second,
				})
				if err != nil {
					return // Stop won the race against this dial -- expected.
				}
				driver := fastpath.NewShellDriver(transport, fastpath.ShellDriverConfig{})
				_ = driver.Setup(context.Background())
				_ = driver.Close()
			}()
		}

		// Launched concurrently with the dialers above, deliberately not
		// synchronized against them, to maximize overlap with each one's
		// own accept/handshake window.
		done := make(chan error, 1)
		go func() { done <- face.Stop() }()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("cycle %d: Stop() error = %v", i, err)
			}
		case <-time.After(5 * time.Second):
			buf := make([]byte, 4<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("cycle %d: Stop() did not return within 5s (not bounded) -- goroutine dump:\n%s", i, buf[:n])
		}
		dialWG.Wait()
	}
}

// TestTelnetFaceStopBoundedUnderConcurrentConnectRace is
// TestSSHFaceStopBoundedUnderConcurrentConnectRace's Telnet analogue --
// TelnetFace's own race is narrower (its listener close was always direct
// and race-free; only the PER-CONNECTION acceptLoop/trackConn race applied,
// see telnetface.go's acceptLoop doc comment), but the reproduction shape
// and the bound this proves are identical.
//
// Deliberately dials with a RAW, UNCOOPERATIVE net.Conn (connect, then never
// write and never close it until this cycle's own cleanup below) rather than
// the real fastpath Telnet client (fastpath.NewTelnetTransport +
// ShellDriver): a COOPERATIVE client's own Close unblocks the server's stuck
// login Read on its own, well within this test's bound, even when a
// connection lands in the race window on pre-fix code -- self-healing the
// very bug this test exists to catch and so never actually failing against
// it (measured against pre-fix code with a cooperative dialer: 61 runs,
// >1200 race-window attempts, zero failures). Stop's bound must hold
// independent of whether the client ever cooperates -- a real client that
// hangs is exactly the scenario TestTelnetFaceStopWithoutClientDisconnectingIsStillBounded
// above already proves for a SINGLE already-established connection; this
// test proves the same thing for a connection Stop races against mid-accept,
// which needs an uncooperative client to actually exercise (a cooperative
// one can rescue Stop even when the race-closing logic under test is
// broken). Note this raw client alone is NOT sufficient to reliably land
// the exact accept/track window by pure timing (see the section-level doc
// comment above -- TestTelnetFaceStopAcceptTrackRaceDeterministic further
// below is what actually mutation-verifies TelnetFace's fix); it removes
// the cooperative client's self-healing so THIS test does not pass for the
// wrong reason, and doubles as a broad concurrent-load/leak smoke test.
// Every dialed conn is force-closed by this test itself at the end of each
// cycle (not left to Stop, whose own force-close is exactly what is under
// test) so the test does not leak.
func TestTelnetFaceStopBoundedUnderConcurrentConnectRace(t *testing.T) {
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("model.GetModel() error = %v", err)
	}
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		t.Fatalf("fastpath.CLISpec() error = %v", err)
	}

	const cycles, dialers = 20, 16
	for i := 0; i < cycles; i++ {
		face := NewTelnetFace(SeedGSM7228PS(), spec, "admin", "s3cret", "127.0.0.1")
		port, err := face.Start()
		if err != nil {
			t.Fatalf("cycle %d: Start() error = %v", i, err)
		}
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

		var mu sync.Mutex
		var rawConns []net.Conn
		var dialWG sync.WaitGroup
		for j := 0; j < dialers; j++ {
			dialWG.Add(1)
			go func() {
				defer dialWG.Done()
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err != nil {
					return // Stop (or the listener already closing) won the race -- expected.
				}
				// Deliberately silent: no write, no close here -- see this
				// test's own doc comment for why a cooperative client cannot
				// exercise the race this test targets.
				mu.Lock()
				rawConns = append(rawConns, conn)
				mu.Unlock()
			}()
		}

		// Launched concurrently with the dialers above, deliberately not
		// synchronized against them, to maximize overlap with each one's
		// own accept/tracking window.
		done := make(chan error, 1)
		go func() { done <- face.Stop() }()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("cycle %d: Stop() error = %v", i, err)
			}
		case <-time.After(5 * time.Second):
			buf := make([]byte, 4<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("cycle %d: Stop() did not return within 5s (not bounded) -- goroutine dump:\n%s", i, buf[:n])
		}
		dialWG.Wait()

		mu.Lock()
		for _, c := range rawConns {
			_ = c.Close()
		}
		mu.Unlock()
	}
}

// TestTelnetFaceStopAcceptTrackRaceDeterministic forces, by construction,
// the EXACT interleaving TestTelnetFaceStopBoundedUnderConcurrentConnectRace
// above can only hope to hit by luck (measured: it essentially never does --
// see that test's own doc comment and telnetAcceptTrackHook's, telnetface.go
// -- because the accept-then-track transition it targets is a handful of
// uninterrupted Go instructions with no intervening syscall to hand
// scheduling to another goroutine, unlike SSHFace's analogous race, which a
// whole background-goroutine-spinup delay makes reliably hittable by pure
// timing). Uses telnetAcceptTrackHook (telnetface.go, a TEST-ONLY
// no-op-by-default seam, same idiom as net/http's own testHookServerServe)
// to pause acceptLoop's own goroutine, holding a just-accepted connection,
// strictly BEFORE trackConn runs -- then runs Stop to completion while it
// stays paused there, and only then releases it. trackConn(conn, true) is
// thus GUARANTEED to run against an f.conns Stop has already cleared to
// nil, exactly the race window sshface.go's Stop doc comment and
// telnetface.go's acceptLoop doc comment describe -- proving the same
// "Stop bounded regardless of client cooperation" property as the stress
// test above, but deterministically rather than by chance.
func TestTelnetFaceStopAcceptTrackRaceDeterministic(t *testing.T) {
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("model.GetModel() error = %v", err)
	}
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		t.Fatalf("fastpath.CLISpec() error = %v", err)
	}
	face := NewTelnetFace(SeedGSM7228PS(), spec, "admin", "s3cret", "127.0.0.1")

	// Assigned BEFORE Start (rather than after, as it might read more
	// naturally): Start's own `go f.acceptLoop(ln)` statement is a Go
	// memory-model synchronization point, so a write sequenced before it is
	// guaranteed visible to acceptLoop's own goroutine without any
	// additional synchronization -- a write sequenced AFTER Start returns
	// has no such guarantee (a plain package-level var, not an atomic), and
	// -race correctly flags that ordering as a data race even though it
	// happens to work in practice (confirmed: an earlier draft of this test
	// assigned the hook after Start and -race caught it immediately).
	hookEntered := make(chan struct{})
	releaseHook := make(chan struct{})
	telnetAcceptTrackHook = func() {
		close(hookEntered)
		<-releaseHook
	}
	defer func() { telnetAcceptTrackHook = nil }()

	port, err := face.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// A raw, uncooperative client -- see the sibling stress test's own doc
	// comment for why a cooperative one (which closes itself) cannot
	// exercise this race: connect, then never write and never close until
	// this test's own cleanup below.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case <-hookEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("acceptLoop never reached telnetAcceptTrackHook -- Accept() did not fire")
	}

	// acceptLoop is now paused inside the hook, holding the just-accepted
	// (but not yet tracked) connection, strictly before trackConn runs.
	done := make(chan error, 1)
	go func() { done <- face.Stop() }()

	// Stop's own critical section (mu.Lock/snapshot/clear/mu.Unlock) is a
	// handful of instructions; unlike the race itself, this margin does not
	// need to be precise, only generous enough for it to have definitely
	// already run -- 200ms is that, on any reasonable machine, without
	// making this test itself flaky.
	time.Sleep(200 * time.Millisecond)
	close(releaseHook)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		buf := make([]byte, 4<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("Stop() did not return within 5s after the accept/track race was forced deterministically -- goroutine dump:\n%s", buf[:n])
	}
}

// TestTelnetFaceStopBeforeStartIsNoOp mirrors
// TestSSHFaceStopBeforeStartIsNoOp.
func TestTelnetFaceStopBeforeStartIsNoOp(t *testing.T) {
	m, _ := model.GetModel("gsm7228ps")
	spec, _ := fastpath.CLISpec(m)
	face := NewTelnetFace(SeedGSM7228PS(), spec, "admin", "s3cret", "127.0.0.1")
	if err := face.Stop(); err != nil {
		t.Errorf("Stop() before Start() error = %v, want nil (no-op)", err)
	}
}

// --- 4. VirtualSwitch wiring (server.go) -----------------------------------

// TestVirtualSwitchBindsSSHAndTelnetFacesForCLIModel proves server.go's
// Start()/Stop() wiring: a CLI-capable model binds BOTH SSHPort and
// TelnetPort concurrently (mirroring how it already binds SnmpPort and
// HTTPPort together), each independently dialable with the real fastpath
// client and the caller-configured credentials (WithCLIUsername/
// WithCLIPassword), and Stop() releases both.
func TestVirtualSwitchBindsSSHAndTelnetFacesForCLIModel(t *testing.T) {
	sw, err := NewVirtualSwitch("gsm7252ps", WithCLIUsername("admin"), WithCLIPassword("s3cret"))
	if err != nil {
		t.Fatalf("NewVirtualSwitch() error = %v", err)
	}
	if err := sw.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = sw.Stop() }()

	if sw.SSHPort == 0 {
		t.Error("SSHPort = 0, want a bound port for a BackendSSH model")
	}
	if sw.TelnetPort == 0 {
		t.Error("TelnetPort = 0, want a bound port for a BackendTelnet model")
	}

	sshDriver := dialSSHDriver(t, sw.SSHPort, "admin", "s3cret")
	defer func() { _ = sshDriver.Close() }()
	telnetDriver := dialTelnetDriver(t, sw.TelnetPort, "admin", "s3cret")
	defer func() { _ = telnetDriver.Close() }()

	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel() error = %v", err)
	}
	sshReader, err := fastpath.NewReader(sshDriver, m)
	if err != nil {
		t.Fatalf("NewReader(ssh) error = %v", err)
	}
	if _, err := sshReader.GetPorts(context.Background()); err != nil {
		t.Errorf("SSH GetPorts() error = %v", err)
	}
	telnetReader, err := fastpath.NewReader(telnetDriver, m)
	if err != nil {
		t.Fatalf("NewReader(telnet) error = %v", err)
	}
	if _, err := telnetReader.GetPorts(context.Background()); err != nil {
		t.Errorf("Telnet GetPorts() error = %v", err)
	}
}
