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
	"os"
	"runtime"
	"strings"
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
	defer face.Stop()

	driver := dialSSHDriver(t, port, "admin", "s3cret")
	defer driver.Close()

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
	defer face.Stop()

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
	defer face.Stop()

	driver := dialTelnetDriver(t, port, "admin", "s3cret")
	defer driver.Close()

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
	defer face.Stop()

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
	defer transport.Close()
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
	defer face.Stop()

	ctx := context.Background()
	driverA := dialSSHDriver(t, port, "admin", "s3cret")
	defer driverA.Close()
	driverB := dialSSHDriver(t, port, "admin", "s3cret")
	defer driverB.Close()

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
	defer driver.Close() // closed AFTER Stop, deliberately -- proving Stop didn't need it first.

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
	defer driver.Close()

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
	defer sw.Stop()

	if sw.SSHPort == 0 {
		t.Error("SSHPort = 0, want a bound port for a BackendSSH model")
	}
	if sw.TelnetPort == 0 {
		t.Error("TelnetPort = 0, want a bound port for a BackendTelnet model")
	}

	sshDriver := dialSSHDriver(t, sw.SSHPort, "admin", "s3cret")
	defer sshDriver.Close()
	telnetDriver := dialTelnetDriver(t, sw.TelnetPort, "admin", "s3cret")
	defer telnetDriver.Close()

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
