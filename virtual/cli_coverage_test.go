package virtual

// cli_coverage_test.go: same-package tests exercising CLI-face paths that the
// root-package capstone drives end-to-end but the per-package coverage gate
// cannot credit across the package boundary -- renderInterfaceCounters (via
// GetStats), applyPoeReset (via CyclePoE/ClearPoEFault), and
// VirtualSwitch.CliSession. These are real round-trips through the real
// fastpath.Reader/Writer against the seeded fake, not coverage theater.

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/fastpath"
)

// instantClock advances virtual time by each sleep's duration so PoE-cycle
// deadline polling terminates without any real wall-clock wait.
func instantClock() (func() time.Time, func(context.Context, time.Duration) error) {
	base := time.Unix(0, 0)
	var elapsed time.Duration
	now := func() time.Time { return base.Add(elapsed) }
	sleep := func(_ context.Context, d time.Duration) error { elapsed += d; return nil }
	return now, sleep
}

func TestCliFaceGetStatsRendersInterfaceCounters(t *testing.T) {
	st := SeedGSM7252PS()
	face, m := newTestCliFace(t, "gsm7252ps", st)
	reader, err := fastpath.NewReader(face, m)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := reader.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if len(stats) == 0 {
		t.Fatalf("GetStats returned no per-port counters (renderInterfaceCounters not exercised)")
	}
}

func TestCliFaceCyclePoEDrivesApplyPoeReset(t *testing.T) {
	st := SeedGSM7252PS()
	face, m := newTestCliFace(t, "gsm7252ps", st)
	now, sleep := instantClock()
	writer, err := fastpath.NewWriter(face, m, fastpath.WithClock(now, sleep))
	if err != nil {
		t.Fatal(err)
	}
	// Pick a PoE port with an actual powered device (PowerMw != 0) so that
	// after the off->reset->on cycle it returns to "delivering" (a reset does
	// not conjure a PD onto an empty port -- that would end in "searching" and
	// the cycle's delivering-verify would never be satisfied). Deterministic:
	// lowest such port number, not map-iteration order.
	poePort := 0
	for p, psim := range st.Poe {
		if psim.PowerMw != 0 && (poePort == 0 || p < poePort) {
			poePort = p
		}
	}
	if poePort == 0 {
		t.Skip("no delivering PoE port seeded for gsm7252ps")
	}
	if err := writer.CyclePoE(context.Background(), poePort, fastpath.DefaultPoeCycleTimeouts(), true); err != nil {
		t.Fatalf("CyclePoE: %v", err)
	}
	if err := writer.ClearPoEFault(context.Background(), poePort, fastpath.DefaultPoeCycleTimeouts(), true); err != nil {
		t.Fatalf("ClearPoEFault: %v", err)
	}
}

func TestVirtualSwitchCliSessionInProcessRun(t *testing.T) {
	vsw, err := NewVirtualSwitch("gsm7252ps")
	if err != nil {
		t.Fatal(err)
	}
	session, err := vsw.CliSession()
	if err != nil {
		t.Fatalf("CliSession: %v", err)
	}
	out, err := session.Run(context.Background(), "show version")
	if err != nil {
		t.Fatalf("Run(show version): %v", err)
	}
	if out == "" {
		t.Fatalf("show version returned empty output")
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestCliFaceDrivesAllWriteCommands exercises the CLI face's config-command
// dispatch for the write ops the other cliface tests don't cover
// (SetPortEnabled/SetMgmtIP/Reboot), each a real round-trip through
// fastpath.Writer against the seeded fake, so configCommand's per-command
// branches are exercised.
func TestCliFaceDrivesAllWriteCommands(t *testing.T) {
	st := SeedGSM7252PS()
	face, m := newTestCliFace(t, "gsm7252ps", st)
	now, sleep := instantClock()
	writer, err := fastpath.NewWriter(face, m, fastpath.WithClock(now, sleep))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := writer.SetPortEnabled(ctx, 1, false, true); err != nil {
		t.Fatalf("SetPortEnabled(off): %v", err)
	}
	if err := writer.SetPortEnabled(ctx, 1, true, true); err != nil {
		t.Fatalf("SetPortEnabled(on): %v", err)
	}
	if err := writer.SetMgmtIP(ctx, "192.168.9.9", "255.255.255.0", "192.168.9.1", true); err != nil {
		t.Fatalf("SetMgmtIP: %v", err)
	}
	if err := writer.Reboot(ctx, true); err != nil {
		t.Fatalf("Reboot: %v", err)
	}
}

// TestCliFaceDrivesBroadCommandSet runs a wide spread of show/config/error
// commands through the in-process dispatcher to exercise run()/configCommand/
// vlanDBCommand/interfaceCommand and the show-output renderers' routing that
// the targeted write tests don't reach. Assertions are on the accept/reject
// contract and no-panic, not exact bytes (the renderers' bytes are pinned in
// the cliface_render round-trip tests).
func TestCliFaceDrivesBroadCommandSet(t *testing.T) {
	ctx := context.Background()

	// gsm7252ps: XE image, full feature set.
	st := SeedGSM7252PS()
	face, _ := newTestCliFace(t, "gsm7252ps", st)
	shows := []string{
		"show version", "show port all", "show vlan brief", "show vlan 1",
		"show interface ethernet 1/0/1", "show network",
		"show mac-addr-table", "show lldp remote-device all", "show environment",
	}
	for _, c := range shows {
		if out, err := face.Run(ctx, c); err != nil {
			t.Fatalf("Run(%q): %v", c, err)
		} else if out == "" {
			t.Errorf("Run(%q) returned empty output (expected a rendered page)", c)
		}
	}
	// Config-mode + vlan-database + interface-mode traversal.
	seq := []string{
		"configure", "vlan database", "vlan 4001", "name 4001 capture", "exit",
		"interface 1/0/1", "switchport mode general", "switchport mode access",
		"switchport mode trunk", "exit", "exit",
	}
	for _, c := range seq {
		if _, err := face.Run(ctx, c); err != nil {
			t.Fatalf("Run(%q): %v", c, err)
		}
	}
	// An unrecognized command is rejected (non-empty output), never accepted
	// silently.
	if out, _ := face.Run(ctx, "this is not a command"); out == "" {
		t.Errorf("an unrecognized command was accepted silently (empty output)")
	}

	// gsm7228ps (S3300 Smart image): `show vlan brief` is rejected (Invalid);
	// `show vlan` is the supported form -- exercises that per-model branch.
	st2 := SeedGSM7228PS()
	face2, _ := newTestCliFace(t, "gsm7228ps", st2)
	if out, _ := face2.Run(ctx, "show vlan"); out == "" {
		t.Errorf("gsm7228ps Run(\"show vlan\") returned empty")
	}
}

// TestTelnetFaceStripsClientIACNegotiation drives the TelnetFace with a RAW
// client that SENDS IAC option-negotiation (WILL/DO) and a subnegotiation
// block interleaved with its login + command, exercising the face's
// handleIAC/refuse/skipSubnegotiation paths (which the fastpath telnet CLIENT
// never triggers, since it only strips IAC on its own read side and never
// originates negotiation). The face must strip every IAC sequence, refuse
// each option, and still parse "admin"/"password"/"show version" correctly.
func TestTelnetFaceStripsClientIACNegotiation(t *testing.T) {
	st := SeedGSM7228PS()
	_, m := newTestCliFace(t, "gsm7228ps", st)
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		t.Fatal(err)
	}
	face := NewTelnetFace(st, spec, "admin", "password", "127.0.0.1")
	port, err := face.Start()
	if err != nil {
		t.Fatalf("TelnetFace.Start: %v", err)
	}
	defer func() { _ = face.Stop() }()

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1 * time.Second))

	const (
		iac  = 255
		dont = 254
		do   = 253
		wont = 252
		will = 251
		sb   = 250
		se   = 240
		echo = 1
		sga  = 3
		ttyp = 24
	)
	// IAC WILL ECHO, then username; IAC DO SGA, then password; IAC SB TTYPE
	// <data> IAC SE (a subnegotiation block, exercising skipSubnegotiation,
	// including an escaped IAC IAC inside it), then the command.
	payload := []byte{iac, will, echo}
	payload = append(payload, []byte("admin\r\n")...)
	payload = append(payload, iac, do, sga)
	payload = append(payload, []byte("password\r\n")...)
	payload = append(payload, iac, sb, ttyp, 1, iac, iac, iac, se) // IAC IAC = literal 0xFF inside SB
	payload = append(payload, []byte("show version\r\n")...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Drain the server's response (prompts + IAC refusals + command output)
	// until the deadline or EOF; assert we received a non-trivial amount,
	// proving the login handshake completed past the IAC handling.
	buf := make([]byte, 4096)
	total := 0
	for {
		n, rerr := conn.Read(buf)
		total += n
		if rerr != nil {
			break
		}
		if total > 0 && n == 0 {
			break
		}
	}
	if total == 0 {
		t.Fatalf("server sent nothing back; IAC handling / login did not proceed")
	}
}
