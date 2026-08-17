package fastpath

// Tests for Writer's remaining write ops (writer.go's Task 10 additions:
// SetPoE/CyclePoE/ClearPoEFault, SetPortEnabled, SetMgmtIP, Reboot) plus
// cert_scp.go's DeployCertificateSCP, driven against scripted Session fakes
// -- reusing newQueuedSession (writer_vlan_test.go, a strict FIFO of canned
// Run responses) for the ops that only ever call Session.Run, and a new
// restSession fake (below) for Reboot/DeployCertificateSCP, which also
// drive RunSCPCopy/RunWriteMemory and need ORDERED cross-method call
// assertions those two extra methods require.
//
// PoE/port/mgmt-IP fixture TEXT below is hand-built (not a captured device
// transcript), via buildRow -- a generic ruler-span-driven row builder
// (reusing parse.go's own unexported rulerSpans, so a synthetic row parses
// through the EXACT SAME header_columns()/iter_table_rows() logic real
// captured output does) -- layered on HEADER/RULER lines copied verbatim
// from the real captured fixtures in testdata/cli/, because each test needs
// a DIFFERENT before/after admin or detect state, not one fixed real
// capture (same rationale as writer_vlan_test.go's vlanBriefFixture/
// pvidFixture).
import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
)

// --- synthetic PoE/port-status/mgmt-IP fixture builders --------------------

// buildRow builds one fixed-width data row by writing each field starting
// at its column's ruler-derived byte offset (via parse.go's own
// rulerSpans), so the row parses correctly through sliceCell/sliceRow
// regardless of cosmetic column-width guesses -- fields beyond len(spans)
// are silently dropped (mirrors a real device never emitting more cells
// than its own ruler declares).
func buildRow(ruler string, fields ...string) string {
	spans := rulerSpans(ruler)
	buf := []byte(strings.Repeat(" ", len(ruler)))
	for i, f := range fields {
		if i >= len(spans) {
			break
		}
		start := spans[i].start
		for len(buf) < start+len(f) {
			buf = append(buf, ' ')
		}
		copy(buf[start:], f)
	}
	return strings.TrimRight(string(buf), " ") + "\n"
}

// portAllHeader/portAllRuler are copied verbatim from
// testdata/cli/gsm7252ps_show_port_all.txt's own header block (its first 4
// lines), reused so portStatusFixture's synthetic rows parse through the
// SAME ruler spans real captured "show port all" output does. Column order
// (matching parse.go's portIntf..portLink constants): Intf, Type, Admin
// Mode, Physical Mode, Physical Status, Link Status, Link Trap, LACP Mode,
// Flow Mode.
const (
	portAllHeader = "\n" +
		"                  Admin   Physical   Physical   Link   Link    LACP    Flow\n" +
		" Intf      Type   Mode     Mode       Status     Status Trap    Mode    Mode\n"
	portAllRuler = "--------- ------ --------- ---------- ---------- ------ ------- ------ -------"
)

// portStatusFixture builds a "show port all" page with a single physical
// port row, admin/link state controlled by the caller.
func portStatusFixture(port int, adminMode, linkStatus string) string {
	row := buildRow(portAllRuler, fmt.Sprintf("1/0/%d", port), "", adminMode, "Auto", "1000 Full", linkStatus, "Enable", "Enable", "Disable")
	return portAllHeader + portAllRuler + "\n" + row
}

// poeStatusHeader/poeStatusRuler are the SAME header/ruler text as the
// package's existing poeFixture const (parse_primitives_test.go, a trimmed
// excerpt of the real captured testdata/cli/m4300_16x_show_poe_port_info_all.txt)
// -- reused rather than re-transcribed, and named distinctly to avoid
// colliding with that existing top-level identifier. 9-column dialect (no
// Temperature column, dossier §2.16). Column order: Intf, High Power, Max
// Power (mW), Class, Power (mW), Output Current (mA), Output Voltage (V),
// Status, Fault Status.
const (
	poeStatusHeader = "        High     Max                      Output  Output\n" +
		"Intf    Power   Power     Class   Power   Current Voltage      Status            Fault\n" +
		"                 (mW)              (mW)     (mA)   (V)                           Status\n"
	poeStatusRuler = "------ ------- -------- -------- -------  ------- -------  ----------------- -----------------"
)

// poeStatusFixture builds a "show poe port info all" page with a single
// port row, its PSE Status text controlled by the caller ("Disabled",
// "Delivering Power", "Searching", "Fault ..." -- parsePoE matches these by
// lower-cased substring, dossier §2.16).
func poeStatusFixture(port int, status string) string {
	row := buildRow(poeStatusRuler, fmt.Sprintf("1/0/%d", port), "Yes", "30000", "4", "3600", "67", "54", status, "No Error")
	return poeStatusHeader + poeStatusRuler + "\n" + row
}

// mgmtIPFixture builds a "show network"/"show ip management" labelled-value
// page (dossier §2.18's labelledValues shape) with the three fields
// SetMgmtIP verifies.
func mgmtIPFixture(address, netmask, gateway string) string {
	return fmt.Sprintf(
		"IP Address..................................... %s\n"+
			"Subnet Mask.................................... %s\n"+
			"Default Gateway................................ %s\n"+
			"Configured IPv4 Protocol....................... Static\n",
		address, netmask, gateway,
	)
}

// --- clock/sleep test seams (mirrors snmp package's writer_cycle_test.go
// incrementingClock/noSleep helpers, package-private duplicates since these
// are test-only) -----------------------------------------------------------

// incrementingClock returns a fake `now` func that jumps forward by step on
// every call -- a bounded, deterministic test runtime with zero real
// sleeping, instead of racing a real wall clock.
func incrementingClock(step time.Duration) func() time.Time {
	t := time.Now()
	return func() time.Time {
		t = t.Add(step)
		return t
	}
}

// noSleep is a Sleep seam that never actually waits.
func noSleep(context.Context, time.Duration) error { return nil }

// ---------------------------------------------------------------------
// SetPoE (dossier §4.6) -- the m4300-24x device-limit gate
// ---------------------------------------------------------------------

func TestWriterSetPoEUnsupportedOnM430024X(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	sess := newQueuedSession() // zero steps -- requirePoE must fire with ZERO session I/O
	w := mustNewWriter(t, sess, m)

	err := w.SetPoE(context.Background(), 5, true, false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("SetPoE error = %v, want ErrUnsupportedCapability", err)
	}
	if !strings.Contains(err.Error(), "poe ?") || !strings.Contains(err.Error(), "Unrecognized command") {
		t.Errorf("SetPoE error = %q, want it to quote the live-probed evidence (%q / %q)", err.Error(), "poe ?", "Unrecognized command")
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want zero -- requirePoE must fire before any session I/O", sess.calls)
	}
}

func TestWriterSetPoEGuardOnlyWhenTurningOff(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	sess := newQueuedSession() // requirePoE passes (PoE-capable); guard fires next with ZERO I/O
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5))

	err := w.SetPoE(context.Background(), 5, false, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetPoE(off, protected, no force) error = %v, want ErrProtectedPort", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want zero", sess.calls)
	}

	// Turning PoE ON is never guarded, even on a protected port without force.
	before := poeStatusFixture(5, "Disabled")
	after := poeStatusFixture(5, "Delivering Power")
	sess2 := newQueuedSession(ok(before), ok(""), ok(""), ok(""), ok(""), ok(""), ok(after))
	w2 := mustNewWriter(t, sess2, m, WithProtectedPorts(5), WithClock(time.Now, noSleep))
	if err := w2.SetPoE(context.Background(), 5, true, false); err != nil {
		t.Fatalf("SetPoE(on, protected, no force): %v", err)
	}
}

func TestWriterSetPoEFullSequenceTurnOn(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := poeStatusFixture(5, "Disabled")
	after := poeStatusFixture(5, "Delivering Power")

	sess := newQueuedSession(
		ok(before),     // before poeStatus -> GetPoE
		ok(""), ok(""), // enter: configure, interface
		ok(""),         // body: poe
		ok(""), ok(""), // unwind: exit x2
		ok(after), // poll: GetPoE, satisfied on first check
	)
	w := mustNewWriter(t, sess, m, WithClock(time.Now, noSleep))

	if err := w.SetPoE(context.Background(), 5, true, false); err != nil {
		t.Fatalf("SetPoE: %v", err)
	}
	wantCmds := []string{
		spec.PoeCmd,
		spec.ConfigureCmd, spec.Interface(5),
		spec.PoeEnableCmd,
		spec.ExitCmd, spec.ExitCmd,
		spec.PoeCmd,
	}
	assertCommands(t, sess, wantCmds)
}

func TestWriterSetPoEFullSequenceTurnOffWithForce(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := poeStatusFixture(5, "Delivering Power")
	after := poeStatusFixture(5, "Disabled")

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""),
		ok(""),
		ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5), WithClock(time.Now, noSleep))

	if err := w.SetPoE(context.Background(), 5, false, true); err != nil {
		t.Fatalf("SetPoE(off, force): %v", err)
	}
	wantCmds := []string{
		spec.PoeCmd,
		spec.ConfigureCmd, spec.Interface(5),
		spec.PoeDisableCmd,
		spec.ExitCmd, spec.ExitCmd,
		spec.PoeCmd,
	}
	assertCommands(t, sess, wantCmds)
}

func TestWriterSetPoEPollsMultipleRoundsBeforeSatisfied(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	before := poeStatusFixture(5, "Disabled")
	stillOffAgain := poeStatusFixture(5, "Disabled") // 1st poll: still Disabled, not yet on -- forces a 2nd round
	after := poeStatusFixture(5, "Delivering Power")

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""), ok(""), ok(""), ok(""),
		ok(stillOffAgain), // 1st poll: still Disabled -- not satisfied
		ok(after),         // 2nd poll: Delivering -- satisfied
	)
	w := mustNewWriter(t, sess, m, WithClock(time.Now, noSleep))

	if err := w.SetPoE(context.Background(), 5, true, false); err != nil {
		t.Fatalf("SetPoE: %v", err)
	}
}

func TestWriterSetPoEVerificationTimeout(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	before := poeStatusFixture(5, "Disabled")
	stillOff := poeStatusFixture(5, "Disabled")

	// incrementingClock jumps forward 100s per call -- the very first
	// deadline check after the write is already past DefaultPoeCycleTimeouts().On.
	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""), ok(""), ok(""), ok(""),
		ok(stillOff),
	)
	w := mustNewWriter(t, sess, m, WithClock(incrementingClock(100*time.Second), noSleep))

	err := w.SetPoE(context.Background(), 5, true, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPoE error = %v, want *model.WriteVerificationError", err)
	}
}

// ---------------------------------------------------------------------
// CyclePoE / ClearPoEFault (dossier §4.6) -- guard-before-device-gate order
// ---------------------------------------------------------------------

func TestWriterCyclePoEUnsupportedOnM430024X(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	sess := newQueuedSession() // port not protected -- guard passes silently, then requirePoE fires
	w := mustNewWriter(t, sess, m)

	err := w.CyclePoE(context.Background(), 5, DefaultPoeCycleTimeouts(), false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("CyclePoE error = %v, want ErrUnsupportedCapability", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want zero", sess.calls)
	}
}

// TestWriterCyclePoEProtectedPortBeforeDeviceGate exercises the pin's exact
// (and slightly surprising) ordering on m4300-24x: guard(port, force) runs
// BEFORE requirePoE (which only fires once poeReset is reached) -- so a
// PROTECTED port without force returns ErrProtectedPort, NOT
// ErrUnsupportedCapability, even on a model that could never serve the op
// anyway.
func TestWriterCyclePoEProtectedPortBeforeDeviceGate(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	sess := newQueuedSession()
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5))

	err := w.CyclePoE(context.Background(), 5, DefaultPoeCycleTimeouts(), false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("CyclePoE(protected, no force) error = %v, want ErrProtectedPort (guard fires before requirePoE)", err)
	}
	if errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("CyclePoE error unexpectedly also wraps ErrUnsupportedCapability: %v", err)
	}
}

func TestWriterCyclePoEGuardUnconditional(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	sess := newQueuedSession()
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5))

	err := w.CyclePoE(context.Background(), 5, DefaultPoeCycleTimeouts(), false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("CyclePoE(protected, no force) error = %v, want ErrProtectedPort", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want zero", sess.calls)
	}
}

func TestWriterCyclePoEFullSequence(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := poeStatusFixture(5, "Delivering Power")
	after := poeStatusFixture(5, "Delivering Power")

	sess := newQueuedSession(
		ok(before),     // before poeStatus
		ok(""), ok(""), // enter
		ok(""),         // body: poe reset
		ok(""), ok(""), // unwind
		ok(after), // poll: recovered (Delivering) on first check
	)
	w := mustNewWriter(t, sess, m, WithClock(time.Now, noSleep))

	timeouts := PoeCycleTimeouts{Off: time.Second, On: time.Second, Poll: 0}
	if err := w.CyclePoE(context.Background(), 5, timeouts, true); err != nil {
		t.Fatalf("CyclePoE: %v", err)
	}
	wantCmds := []string{
		spec.PoeCmd,
		spec.ConfigureCmd, spec.Interface(5),
		spec.PoeResetCmd,
		spec.ExitCmd, spec.ExitCmd,
		spec.PoeCmd,
	}
	assertCommands(t, sess, wantCmds)
}

func TestWriterCyclePoETimeoutHonestlyFails(t *testing.T) {
	// dossier §4.6: "if no powered device is attached, this will
	// legitimately TIME OUT... honestly failing is the documented expected
	// behavior."
	m := mustGetModel(t, "gsm7252ps")
	before := poeStatusFixture(5, "Searching")
	stillSearching := poeStatusFixture(5, "Searching") // never reaches Delivering

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""), ok(""), ok(""), ok(""),
		ok(stillSearching),
	)
	w := mustNewWriter(t, sess, m, WithClock(incrementingClock(100*time.Second), noSleep))

	timeouts := PoeCycleTimeouts{Off: time.Second, On: time.Second, Poll: 0}
	err := w.CyclePoE(context.Background(), 5, timeouts, true)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("CyclePoE error = %v, want *model.WriteVerificationError", err)
	}
}

func TestWriterClearPoEFaultRecoversOnSearching(t *testing.T) {
	// ClearPoEFault's recovery predicate is LOOSER than CyclePoE's: Searching
	// (not just Delivering) counts as "left the fault state".
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := poeStatusFixture(5, "Fault")
	after := poeStatusFixture(5, "Searching")

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""),
		ok(""),
		ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m, WithClock(time.Now, noSleep))

	timeouts := PoeCycleTimeouts{Off: time.Second, On: time.Second, Poll: 0}
	if err := w.ClearPoEFault(context.Background(), 5, timeouts, true); err != nil {
		t.Fatalf("ClearPoEFault: %v", err)
	}
	wantCmds := []string{
		spec.PoeCmd,
		spec.ConfigureCmd, spec.Interface(5),
		spec.PoeResetCmd,
		spec.ExitCmd, spec.ExitCmd,
		spec.PoeCmd,
	}
	assertCommands(t, sess, wantCmds)
}

func TestWriterClearPoEFaultUnsupportedOnM430024X(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	sess := newQueuedSession()
	w := mustNewWriter(t, sess, m)

	err := w.ClearPoEFault(context.Background(), 5, DefaultPoeCycleTimeouts(), true)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("ClearPoEFault error = %v, want ErrUnsupportedCapability", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want zero", sess.calls)
	}
}

// ---------------------------------------------------------------------
// SetPortEnabled (dossier §4.7)
// ---------------------------------------------------------------------

func TestWriterSetPortEnabledGuardOnlyWhenDisabling(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	sess := newQueuedSession()
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5))

	err := w.SetPortEnabled(context.Background(), 5, false, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetPortEnabled(disable, protected, no force) error = %v, want ErrProtectedPort", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want zero", sess.calls)
	}

	before := portStatusFixture(5, "Disable", "Down")
	after := portStatusFixture(5, "Enable", "Up")
	sess2 := newQueuedSession(ok(before), ok(""), ok(""), ok(""), ok(""), ok(""), ok(after))
	w2 := mustNewWriter(t, sess2, m, WithProtectedPorts(5))
	if err := w2.SetPortEnabled(context.Background(), 5, true, false); err != nil {
		t.Fatalf("SetPortEnabled(enable, protected, no force): %v", err)
	}
}

func TestWriterSetPortEnabledFullSequence(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := portStatusFixture(5, "Enable", "Up")
	after := portStatusFixture(5, "Disable", "Down")

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""),
		ok(""),
		ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5))

	if err := w.SetPortEnabled(context.Background(), 5, false, true); err != nil {
		t.Fatalf("SetPortEnabled: %v", err)
	}
	wantCmds := []string{
		spec.PortStatusCmd,
		spec.ConfigureCmd, spec.Interface(5),
		spec.PortDisableCmd,
		spec.ExitCmd, spec.ExitCmd,
		spec.PortStatusCmd,
	}
	assertCommands(t, sess, wantCmds)
}

func TestWriterSetPortEnabledVerificationMismatch(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	before := portStatusFixture(5, "Enable", "Up")
	after := before // unchanged -- the write silently didn't take.

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""), ok(""), ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	err := w.SetPortEnabled(context.Background(), 5, false, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPortEnabled error = %v, want *model.WriteVerificationError", err)
	}
}

// ---------------------------------------------------------------------
// SetHostname -- NOT force-gated, refuses an empty name before any I/O
// ---------------------------------------------------------------------

func TestWriterSetHostnameWritesAndVerifies(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := hostsFixture("old-name")
	after := hostsFixture("new-name")

	sess := newQueuedSession(
		ok(before),
		ok(""), // enter: configure
		ok(""), // hostname new-name
		ok(""), // unwind: exit
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetHostname(context.Background(), "new-name", false); err != nil {
		t.Fatalf("SetHostname: %v", err)
	}
	wantCmds := []string{spec.HostsCmd, spec.ConfigureCmd, spec.HostnameConfig("new-name"), spec.ExitCmd, spec.HostsCmd}
	assertCommands(t, sess, wantCmds)
}

// TestWriterSetHostnameNotForceGated proves force=false succeeds -- renaming
// cannot strand the switch, unlike SetMgmtIP just below.
func TestWriterSetHostnameNotForceGated(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	before := hostsFixture("old-name")
	after := hostsFixture("renamed")
	sess := newQueuedSession(ok(before), ok(""), ok(""), ok(""), ok(after))
	w := mustNewWriter(t, sess, m)

	if err := w.SetHostname(context.Background(), "renamed", false); err != nil {
		t.Fatalf("SetHostname(force=false) = %v, want success (not force-gated)", err)
	}
}

// TestWriterSetHostnameRejectsEmptyName mirrors Python's
// test_empty_hostname_is_refused_not_sent: `hostname` with no argument is
// rejected by the device itself, so this library refuses client-side,
// issuing ZERO session calls -- a plain (non-sentinel) error, mirroring
// Python's bare ValueError.
func TestWriterSetHostnameRejectsEmptyName(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	sess := newQueuedSession()
	w := mustNewWriter(t, sess, m)

	err := w.SetHostname(context.Background(), "   ", false)
	if err == nil {
		t.Fatal("SetHostname(\"   \") = nil, want an error")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("SetHostname(\"   \") error = %q, want it to mention 'must not be empty'", err.Error())
	}
	if errors.Is(err, model.ErrUnsupportedCapability) || errors.Is(err, model.ErrProtectedPort) {
		t.Errorf("SetHostname(\"   \") error = %v, want a PLAIN error (mirroring Python's bare ValueError)", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want zero -- the empty-name check must fire before any session I/O", sess.calls)
	}
}

func TestWriterSetHostnameVerificationFailureRaises(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	stuck := hostsFixture("stuck-name")
	// Device ignores the write: every read (before AND after) answers the
	// same fixture.
	sess := newQueuedSession(ok(stuck), ok(""), ok(""), ok(""), ok(stuck))
	w := mustNewWriter(t, sess, m)

	err := w.SetHostname(context.Background(), "new-name", false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetHostname error = %v, want *model.WriteVerificationError", err)
	}
	if verr.Before != "stuck-name" || verr.After != "stuck-name" {
		t.Errorf("verification error before/after = %v/%v, want stuck-name/stuck-name", verr.Before, verr.After)
	}
}

// ---------------------------------------------------------------------
// SetSyslogEnabled -- NOT force-gated, `logging syslog`/`no logging syslog`
// ---------------------------------------------------------------------

func TestWriterSetSyslogEnabledWritesAndVerifies(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	disabled := "Syslog Logging                      : disabled\n" +
		"Logging Client Local Port           : 514"
	enabled := "Syslog Logging                      : enabled\n" +
		"Logging Client Local Port           : 514"
	emptyHosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----"

	sess := newQueuedSession(
		ok(disabled), ok(emptyHosts), // before := GetSyslog()
		ok(""),                      // enter: configure
		ok(""),                      // logging syslog
		ok(""),                      // unwind: exit
		ok(enabled), ok(emptyHosts), // after := GetSyslog()
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetSyslogEnabled(context.Background(), true, false); err != nil {
		t.Fatalf("SetSyslogEnabled: %v", err)
	}
	wantCmds := []string{
		spec.LoggingCmd, spec.LoggingHostsCmd,
		spec.ConfigureCmd, spec.LoggingSyslog(true), spec.ExitCmd,
		spec.LoggingCmd, spec.LoggingHostsCmd,
	}
	assertCommands(t, sess, wantCmds)
}

// TestWriterSetSyslogEnabledDisableSendsNoLoggingSyslog proves disabling
// sends the NEGATED command ("no logging syslog"), not the positive form.
func TestWriterSetSyslogEnabledDisableSendsNoLoggingSyslog(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	enabled := "Syslog Logging                      : enabled\n" +
		"Logging Client Local Port           : 514"
	disabled := "Syslog Logging                      : disabled\n" +
		"Logging Client Local Port           : 514"
	emptyHosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----"

	sess := newQueuedSession(
		ok(enabled), ok(emptyHosts),
		ok(""), ok(""), ok(""),
		ok(disabled), ok(emptyHosts),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetSyslogEnabled(context.Background(), false, false); err != nil {
		t.Fatalf("SetSyslogEnabled: %v", err)
	}
	if spec.LoggingSyslog(false) != "no logging syslog" {
		t.Fatalf("LoggingSyslog(false) = %q, want %q", spec.LoggingSyslog(false), "no logging syslog")
	}
	wantCmds := []string{
		spec.LoggingCmd, spec.LoggingHostsCmd,
		spec.ConfigureCmd, "no logging syslog", spec.ExitCmd,
		spec.LoggingCmd, spec.LoggingHostsCmd,
	}
	assertCommands(t, sess, wantCmds)
}

// TestWriterSetSyslogEnabledNotForceGated proves force=false succeeds --
// toggling log delivery cannot strand the switch.
func TestWriterSetSyslogEnabledNotForceGated(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	disabled := "Syslog Logging                      : disabled\n" +
		"Logging Client Local Port           : 514"
	enabled := "Syslog Logging                      : enabled\n" +
		"Logging Client Local Port           : 514"
	emptyHosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----"
	sess := newQueuedSession(
		ok(disabled), ok(emptyHosts),
		ok(""), ok(""), ok(""),
		ok(enabled), ok(emptyHosts),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetSyslogEnabled(context.Background(), true, false); err != nil {
		t.Fatalf("SetSyslogEnabled(force=false) = %v, want success (not force-gated)", err)
	}
}

func TestWriterSetSyslogEnabledVerificationFailureRaises(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	stuck := "Syslog Logging                      : disabled\n" +
		"Logging Client Local Port           : 514"
	emptyHosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----"
	// Device ignores the write: every read (before AND after) answers the
	// same fixture.
	sess := newQueuedSession(
		ok(stuck), ok(emptyHosts),
		ok(""), ok(""), ok(""),
		ok(stuck), ok(emptyHosts),
	)
	w := mustNewWriter(t, sess, m)

	err := w.SetSyslogEnabled(context.Background(), true, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetSyslogEnabled error = %v, want *model.WriteVerificationError", err)
	}
	if verr.Before != false || verr.After != false {
		t.Errorf("verification error before/after = %v/%v, want false/false", verr.Before, verr.After)
	}
}

// TestWriterSetSyslogEnabledPropagatesErrorFromBeforeRead proves a session
// failure on the very first (before-read) command short-circuits the write
// before any config-mode command is ever issued.
func TestWriterSetSyslogEnabledPropagatesErrorFromBeforeRead(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	wantErr := errors.New("boom")
	sess := newQueuedSession(queuedStep{err: wantErr})
	w := mustNewWriter(t, sess, m)

	if err := w.SetSyslogEnabled(context.Background(), true, false); !errors.Is(err, wantErr) {
		t.Errorf("SetSyslogEnabled() error = %v, want wrapping %v", err, wantErr)
	}
}

// TestWriterSetSyslogEnabledPropagatesErrorFromAfterRead proves a session
// failure on the RE-READ (after the config command already went out)
// propagates as-is, never swallowed into a fabricated verification result.
func TestWriterSetSyslogEnabledPropagatesErrorFromAfterRead(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	disabled := "Syslog Logging                      : disabled\n" +
		"Logging Client Local Port           : 514"
	emptyHosts := "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----"
	wantErr := errors.New("boom")
	sess := newQueuedSession(
		ok(disabled), ok(emptyHosts),
		ok(""), ok(""), ok(""),
		queuedStep{err: wantErr},
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetSyslogEnabled(context.Background(), true, false); !errors.Is(err, wantErr) {
		t.Errorf("SetSyslogEnabled() error = %v, want wrapping %v", err, wantErr)
	}
}

// ---------------------------------------------------------------------
// AddSyslogCollector / RemoveSyslogCollector -- `logging host "<addr>"
// <kind> <port> <severity>` / `logging host remove <index>` (a SUBCOMMAND,
// never a negation)
// ---------------------------------------------------------------------

// emptySyslogHosts/oneSyslogHost/sparseSyslogHosts are "show logging hosts"
// fixture text, mirroring parse_syslog_test.go's own fixture shape.
const (
	emptySyslogHosts = "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----"
	oneSyslogHost = "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"1     10.1.5.1                 info       514    Active    udp"
	twoSyslogHostAdded = "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"1     10.1.5.1                 info       514    Active    udp\n" +
		"2     10.1.5.9                 info       514    Active    udp"
	// sparseSyslogHosts holds Index 1 and Index 3, nothing at 2 -- the exact
	// shape measured on m4300-24x 10.1.5.13 (2026-08-05).
	sparseSyslogHosts = "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"1     10.1.5.1                 info       514    Active    udp\n" +
		"3     10.1.5.3                 error      601    Active    udp"
	// sparseSyslogHostsIndex3Removed is sparseSyslogHosts with ONLY index 3
	// gone -- index 1 survives untouched, proving the removal addressed the
	// index-3 row and not a position.
	sparseSyslogHostsIndex3Removed = "Index   IP Address/Hostname     Severity    Port   Status  Mode  Auth  Cert#\n" +
		"----- ------------------------ ---------- ------ --------- ----- ----- -----\n" +
		"1     10.1.5.1                 info       514    Active    udp"
)

// TestAddressKind proves the address-kind token dispatches ipv4/ipv6/dns
// the way Python's ipaddress.ip_address-based address_kind does: colon
// presence selects the IPv6 parser family FIRST (so a string with a colon
// that fails to parse is "dns", never silently retried as IPv4), mirroring
// commands.py's own dispatch rather than a bare net.ParseIP().To4() check
// (which would misclassify an IPv4-mapped IPv6 literal).
func TestAddressKind(t *testing.T) {
	cases := []struct {
		address, want string
	}{
		{"10.1.5.1", "ipv4"},
		{"::1", "ipv6"},
		{"2001:db8::1", "ipv6"},
		{"switch.example.com", "dns"},
		{"not:a:valid:ipv6:address:at:all:either", "dns"},
	}
	for _, c := range cases {
		if got := addressKind(c.address); got != c.want {
			t.Errorf("addressKind(%q) = %q, want %q", c.address, got, c.want)
		}
	}
}

func TestWriterAddSyslogCollectorWritesAndVerifies(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	syslogDisabled := "Syslog Logging                      : disabled\n" +
		"Logging Client Local Port           : 514"

	sess := newQueuedSession(
		ok(syslogDisabled), ok(oneSyslogHost), // before := GetSyslog()
		ok(""),                                     // enter: configure
		ok(""),                                     // logging host "10.1.5.9" ipv4 514 info
		ok(""),                                     // unwind: exit
		ok(syslogDisabled), ok(twoSyslogHostAdded), // after := GetSyslog()
	)
	w := mustNewWriter(t, sess, m)

	if err := w.AddSyslogCollector(context.Background(), "10.1.5.9", 514, 6, false); err != nil {
		t.Fatalf("AddSyslogCollector: %v", err)
	}
	cmd, err := spec.LoggingHostAdd("10.1.5.9", 514, 6)
	if err != nil {
		t.Fatalf("LoggingHostAdd: %v", err)
	}
	if cmd != `logging host "10.1.5.9" ipv4 514 info` {
		t.Errorf("LoggingHostAdd = %q, want the exact running-config line", cmd)
	}
	wantCmds := []string{
		spec.LoggingCmd, spec.LoggingHostsCmd,
		spec.ConfigureCmd, cmd, spec.ExitCmd,
		spec.LoggingCmd, spec.LoggingHostsCmd,
	}
	assertCommands(t, sess, wantCmds)
}

// TestWriterAddSyslogCollectorRefusesDuplicateHost proves a host already in
// the table is refused as a PRECONDITION failure, with NO command sent --
// the firmware would otherwise add a second row and silently duplicate
// delivery.
func TestWriterAddSyslogCollectorRefusesDuplicateHost(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	enabled := "Syslog Logging                      : enabled\n" +
		"Logging Client Local Port           : 514"
	sess := newQueuedSession(ok(enabled), ok(oneSyslogHost))
	w := mustNewWriter(t, sess, m)

	err := w.AddSyslogCollector(context.Background(), "10.1.5.1", 514, 6, false)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("AddSyslogCollector(duplicate) error = %v, want wrapping ErrCliCommandRejected", err)
	}
	if len(sess.calls) != 2 {
		t.Fatalf("commands = %v, want exactly the 2 before-read commands -- no write for a refused precondition", sess.calls)
	}
}

// TestWriterAddSyslogCollectorNotForceGated proves force=false succeeds --
// mirrors SetSyslogEnabled's own not-force-gated rationale.
func TestWriterAddSyslogCollectorNotForceGated(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	disabled := "Syslog Logging                      : disabled\n" +
		"Logging Client Local Port           : 514"
	sess := newQueuedSession(
		ok(disabled), ok(emptySyslogHosts),
		ok(""), ok(""), ok(""),
		ok(disabled), ok(oneSyslogHost),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.AddSyslogCollector(context.Background(), "10.1.5.1", 514, 6, false); err != nil {
		t.Fatalf("AddSyslogCollector(force=false) = %v, want success (not force-gated)", err)
	}
}

// TestWriterAddSyslogCollectorVerificationFailureRaises proves a switch
// that accepts the command but does not add the row (or adds it with the
// wrong port/severity) surfaces a *model.WriteVerificationError, never a
// silent success.
func TestWriterAddSyslogCollectorVerificationFailureRaises(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	enabled := "Syslog Logging                      : enabled\n" +
		"Logging Client Local Port           : 514"
	sess := newQueuedSession(
		ok(enabled), ok(emptySyslogHosts),
		ok(""), ok(""), ok(""),
		ok(enabled), ok(emptySyslogHosts), // device ignored the write
	)
	w := mustNewWriter(t, sess, m)

	err := w.AddSyslogCollector(context.Background(), "10.1.5.9", 514, 6, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("AddSyslogCollector error = %v, want *model.WriteVerificationError", err)
	}
}

// TestWriterAddSyslogCollectorInvalidSeverityPropagatesBeforeAnyWrite
// proves an out-of-range severity is rejected by LoggingHostAdd itself
// (model.SyslogSeverityWord), with no command sent.
func TestWriterAddSyslogCollectorInvalidSeverityPropagatesBeforeAnyWrite(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	enabled := "Syslog Logging                      : enabled\n" +
		"Logging Client Local Port           : 514"
	sess := newQueuedSession(ok(enabled), ok(emptySyslogHosts))
	w := mustNewWriter(t, sess, m)

	err := w.AddSyslogCollector(context.Background(), "10.1.5.9", 514, 8, false)
	if err == nil {
		t.Fatal("AddSyslogCollector(severity=8): want error, got nil")
	}
	if len(sess.calls) != 2 {
		t.Fatalf("commands = %v, want exactly the 2 before-read commands -- no write for an invalid severity", sess.calls)
	}
}

// TestWriterAddSyslogCollectorPropagatesErrorFromBeforeRead proves a
// session failure on the very first (before-read) command short-circuits
// the write before any config-mode command is ever issued.
func TestWriterAddSyslogCollectorPropagatesErrorFromBeforeRead(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	wantErr := errors.New("boom")
	sess := newQueuedSession(queuedStep{err: wantErr})
	w := mustNewWriter(t, sess, m)

	if err := w.AddSyslogCollector(context.Background(), "10.1.5.9", 514, 6, false); !errors.Is(err, wantErr) {
		t.Errorf("AddSyslogCollector() error = %v, want wrapping %v", err, wantErr)
	}
}

func TestWriterRemoveSyslogCollectorWritesAndVerifies(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)

	sess := newQueuedSession(
		ok("Syslog Logging                      : enabled\nLogging Client Local Port           : 514"), ok(oneSyslogHost), // before
		ok(""), // enter: configure
		ok(""), // logging host remove 1
		ok(""), // unwind: exit
		ok("Syslog Logging                      : enabled\nLogging Client Local Port           : 514"), ok(emptySyslogHosts), // after
	)
	w := mustNewWriter(t, sess, m)

	if err := w.RemoveSyslogCollector(context.Background(), "10.1.5.1", false); err != nil {
		t.Fatalf("RemoveSyslogCollector: %v", err)
	}
	wantCmds := []string{
		spec.LoggingCmd, spec.LoggingHostsCmd,
		spec.ConfigureCmd, spec.LoggingHostRemove(1), spec.ExitCmd,
		spec.LoggingCmd, spec.LoggingHostsCmd,
	}
	assertCommands(t, sess, wantCmds)
}

// TestWriterRemoveSyslogCollectorAddressesSparseIndexNotPosition is THE
// sparse-index crux test: a table with collectors at Index 1 and Index 3
// (nothing at 2, the exact shape measured on m4300-24x 10.1.5.13,
// 2026-08-05) -- removing the Index-3 host ("10.1.5.3", the SECOND row by
// POSITION) must send `logging host remove 3`, never `logging host remove
// 2` (position-derived) and never `logging host remove 1` (the wrong row).
// Index-1's own collector ("10.1.5.1") must survive untouched.
func TestWriterRemoveSyslogCollectorAddressesSparseIndexNotPosition(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	logging := "Syslog Logging                      : enabled\nLogging Client Local Port           : 514"

	sess := newQueuedSession(
		ok(logging), ok(sparseSyslogHosts), // before
		ok(""),                                          // enter: configure
		ok(""),                                          // logging host remove 3 -- NEVER "remove 2"
		ok(""),                                          // unwind: exit
		ok(logging), ok(sparseSyslogHostsIndex3Removed), // after
	)
	w := mustNewWriter(t, sess, m)

	if err := w.RemoveSyslogCollector(context.Background(), "10.1.5.3", false); err != nil {
		t.Fatalf("RemoveSyslogCollector: %v", err)
	}
	if got := spec.LoggingHostRemove(3); got != "logging host remove 3" {
		t.Fatalf("LoggingHostRemove(3) = %q, want %q", got, "logging host remove 3")
	}
	wantCmds := []string{
		spec.LoggingCmd, spec.LoggingHostsCmd,
		spec.ConfigureCmd, "logging host remove 3", spec.ExitCmd,
		spec.LoggingCmd, spec.LoggingHostsCmd,
	}
	assertCommands(t, sess, wantCmds)
}

// TestWriterRemoveSyslogCollectorRefusesUnknownHost proves a host not in
// the table is refused as a PRECONDITION failure, with NO command sent --
// never a removal for a row that is not there.
func TestWriterRemoveSyslogCollectorRefusesUnknownHost(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	enabled := "Syslog Logging                      : enabled\nLogging Client Local Port           : 514"
	sess := newQueuedSession(ok(enabled), ok(emptySyslogHosts))
	w := mustNewWriter(t, sess, m)

	err := w.RemoveSyslogCollector(context.Background(), "10.9.9.9", false)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("RemoveSyslogCollector(unknown host) error = %v, want wrapping ErrCliCommandRejected", err)
	}
	if len(sess.calls) != 2 {
		t.Fatalf("commands = %v, want exactly the 2 before-read commands -- no write for a refused precondition", sess.calls)
	}
}

// TestWriterRemoveSyslogCollectorNotForceGated proves force=false succeeds
// -- redirecting logs cannot strand a switch.
func TestWriterRemoveSyslogCollectorNotForceGated(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	enabled := "Syslog Logging                      : enabled\nLogging Client Local Port           : 514"
	sess := newQueuedSession(
		ok(enabled), ok(oneSyslogHost),
		ok(""), ok(""), ok(""),
		ok(enabled), ok(emptySyslogHosts),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.RemoveSyslogCollector(context.Background(), "10.1.5.1", false); err != nil {
		t.Fatalf("RemoveSyslogCollector(force=false) = %v, want success (not force-gated)", err)
	}
}

// TestWriterRemoveSyslogCollectorVerificationFailureRaises proves a switch
// that accepts the command but leaves the row in place surfaces a
// *model.WriteVerificationError, never a silent success.
func TestWriterRemoveSyslogCollectorVerificationFailureRaises(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	enabled := "Syslog Logging                      : enabled\nLogging Client Local Port           : 514"
	sess := newQueuedSession(
		ok(enabled), ok(oneSyslogHost),
		ok(""), ok(""), ok(""),
		ok(enabled), ok(oneSyslogHost), // device ignored the removal
	)
	w := mustNewWriter(t, sess, m)

	err := w.RemoveSyslogCollector(context.Background(), "10.1.5.1", false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("RemoveSyslogCollector error = %v, want *model.WriteVerificationError", err)
	}
}

// TestWriterRemoveSyslogCollectorPropagatesErrorFromBeforeRead proves a
// session failure on the very first (before-read) command short-circuits
// the write before any config-mode command is ever issued.
func TestWriterRemoveSyslogCollectorPropagatesErrorFromBeforeRead(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	wantErr := errors.New("boom")
	sess := newQueuedSession(queuedStep{err: wantErr})
	w := mustNewWriter(t, sess, m)

	if err := w.RemoveSyslogCollector(context.Background(), "10.1.5.1", false); !errors.Is(err, wantErr) {
		t.Errorf("RemoveSyslogCollector() error = %v, want wrapping %v", err, wantErr)
	}
}

// ---------------------------------------------------------------------
// SetMgmtIP (dossier §4.8) -- unconditional force + first-mismatch verify
// ---------------------------------------------------------------------

func TestWriterSetMgmtIPForceRequired(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	sess := newQueuedSession()
	w := mustNewWriter(t, sess, m)

	err := w.SetMgmtIP(context.Background(), "10.1.5.9", "255.255.255.0", "10.1.5.1", false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetMgmtIP(no force) error = %v, want ErrProtectedPort", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want zero -- force check must fire before any session I/O", sess.calls)
	}
}

func TestWriterSetMgmtIPExecDialect(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := mgmtIPFixture("10.1.5.9", "255.255.255.0", "10.1.5.1")
	after := mgmtIPFixture("10.1.5.20", "255.255.255.0", "10.1.5.1")

	sess := newQueuedSession(
		ok(before),
		ok(""), // exec cmd: network parms ...
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetMgmtIP(context.Background(), "10.1.5.20", "255.255.255.0", "10.1.5.1", true); err != nil {
		t.Fatalf("SetMgmtIP: %v", err)
	}
	execCmds, configCmds := spec.MgmtIP("10.1.5.20", "255.255.255.0", "10.1.5.1")
	if len(configCmds) != 0 {
		t.Fatalf("test setup: gsm7252ps unexpectedly has configCmds: %v", configCmds)
	}
	wantCmds := append([]string{spec.NetworkCmd}, execCmds...)
	wantCmds = append(wantCmds, spec.NetworkCmd)
	assertCommands(t, sess, wantCmds)
}

func TestWriterSetMgmtIPConfigDialect(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	spec := mustCLISpec(t, m)
	before := mgmtIPFixture("10.1.5.13", "255.255.255.0", "10.1.5.1")
	after := mgmtIPFixture("10.1.5.30", "255.255.255.0", "10.1.5.1")

	execCmds, configCmds := spec.MgmtIP("10.1.5.30", "255.255.255.0", "10.1.5.1")
	if len(execCmds) != 0 {
		t.Fatalf("test setup: m4300-24x unexpectedly has execCmds: %v", execCmds)
	}

	steps := []queuedStep{ok(before)}
	steps = append(steps, ok("")) // enter: configure
	for range configCmds {
		steps = append(steps, ok(""))
	}
	steps = append(steps, ok("")) // unwind: exit
	steps = append(steps, ok(after))
	sess := newQueuedSession(steps...)
	w := mustNewWriter(t, sess, m)

	if err := w.SetMgmtIP(context.Background(), "10.1.5.30", "255.255.255.0", "10.1.5.1", true); err != nil {
		t.Fatalf("SetMgmtIP: %v", err)
	}
	wantCmds := []string{spec.NetworkCmd, spec.ConfigureCmd}
	wantCmds = append(wantCmds, configCmds...)
	wantCmds = append(wantCmds, spec.ExitCmd, spec.NetworkCmd)
	assertCommands(t, sess, wantCmds)
}

func TestWriterSetMgmtIPVerificationStopsAtFirstMismatch(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	before := mgmtIPFixture("10.1.5.9", "255.255.255.0", "10.1.5.1")
	// Both netmask AND gateway fail to read back as requested -- the error
	// must name "netmask" (checked before "gateway"), not "gateway".
	after := mgmtIPFixture("10.1.5.20", "255.255.255.0", "10.1.5.1")

	sess := newQueuedSession(ok(before), ok(""), ok(after))
	w := mustNewWriter(t, sess, m)

	err := w.SetMgmtIP(context.Background(), "10.1.5.20", "255.255.0.0", "10.1.5.254", true)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetMgmtIP error = %v, want *model.WriteVerificationError", err)
	}
	if !strings.Contains(verr.Msg, "netmask") {
		t.Errorf("SetMgmtIP verification message = %q, want it to name the FIRST divergent field (netmask), not gateway", verr.Msg)
	}
	if strings.Contains(verr.Msg, "gateway") {
		t.Errorf("SetMgmtIP verification message = %q, must stop at the first mismatch, not report gateway too", verr.Msg)
	}
}

// ---------------------------------------------------------------------
// Reboot (dossier §4.9) -- unconditional force + transport-error-as-success
// ---------------------------------------------------------------------

// restSession is a Session fake scripting all FOUR Session methods (unlike
// scriptedSession/newQueuedSession above, which only script Run) -- needed
// by Reboot (RunWriteMemory) and DeployCertificateSCP (Run + RunSCPCopy +
// RunWriteMemory), which exercise more than one Session method per call and
// need their cross-method ORDER asserted, not just each method's own calls
// in isolation.
type restCall struct {
	method  string // "Run", "RunSCPCopy", "RunWriteMemory"
	command string
	extra   string // scpPassword (RunSCPCopy) or "prestuff=<bool>" (RunWriteMemory)
}

type restSession struct {
	calls []restCall

	runFn         func(command string) (string, error)
	runSCPCopyFn  func(command, password string) (string, error)
	runWriteMemFn func(command string, prestuff bool) (string, error)
}

func (s *restSession) Run(_ context.Context, command string) (string, error) {
	s.calls = append(s.calls, restCall{method: "Run", command: command})
	if s.runFn != nil {
		return s.runFn(command)
	}
	return "", nil
}

func (s *restSession) RunSCPCopy(_ context.Context, command, scpPassword string) (string, error) {
	s.calls = append(s.calls, restCall{method: "RunSCPCopy", command: command, extra: scpPassword})
	if s.runSCPCopyFn != nil {
		return s.runSCPCopyFn(command, scpPassword)
	}
	return "", nil
}

func (s *restSession) RunWriteMemory(_ context.Context, command string, prestuff bool) (string, error) {
	s.calls = append(s.calls, restCall{method: "RunWriteMemory", command: command, extra: fmt.Sprintf("prestuff=%v", prestuff)})
	if s.runWriteMemFn != nil {
		return s.runWriteMemFn(command, prestuff)
	}
	return "", nil
}

func (s *restSession) Close() error { return nil }

func assertRestCalls(t *testing.T, got []restCall, want []restCall) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("calls = %#v (len %d), want %#v (len %d)", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestWriterRebootForceRequired(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	sess := &restSession{}
	w := mustNewWriter(t, sess, m)

	err := w.Reboot(context.Background(), false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("Reboot(no force) error = %v, want ErrProtectedPort", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("calls = %v, want zero", sess.calls)
	}
}

func TestWriterRebootSuccess(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	sess := &restSession{}
	w := mustNewWriter(t, sess, m)

	if err := w.Reboot(context.Background(), true); err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	assertRestCalls(t, sess.calls, []restCall{
		{method: "RunWriteMemory", command: spec.ReloadCmd, extra: "prestuff=true"},
	})
}

func TestWriterRebootSwallowsCliTransportError(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	sess := &restSession{
		runWriteMemFn: func(string, bool) (string, error) {
			return "", fmt.Errorf("%w: connection reset mid-reload", ErrCliTransport)
		},
	}
	w := mustNewWriter(t, sess, m)

	if err := w.Reboot(context.Background(), true); err != nil {
		t.Fatalf("Reboot: %v, want nil (a dropped session IS the success signal)", err)
	}
}

func TestWriterRebootPropagatesOtherErrors(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	boom := errors.New("boom")
	sess := &restSession{
		runWriteMemFn: func(string, bool) (string, error) { return "", boom },
	}
	w := mustNewWriter(t, sess, m)

	err := w.Reboot(context.Background(), true)
	if !errors.Is(err, boom) {
		t.Fatalf("Reboot error = %v, want it to propagate the non-transport error unchanged", err)
	}
}

// ---------------------------------------------------------------------
// DeployCertificateSCP (dossier §4.10) -- the gsm7228ps device-limit gate
// ---------------------------------------------------------------------

func TestScpSourceURLExactConcatenation(t *testing.T) {
	got := ScpSourceURL("user@host:2222", "/staging", "cert-server.pem")
	want := "scp://user@host:2222/staging/cert-server.pem"
	if got != want {
		t.Errorf("ScpSourceURL = %q, want %q (no extra slash between scpSource and remoteDir)", got, want)
	}
}

func TestDeployCertificateSCPGatedOnGSM7228PS(t *testing.T) {
	m := mustGetModel(t, "gsm7228ps")
	sess := &restSession{}

	err := DeployCertificateSCP(context.Background(), sess, m, "user@host", "pw", "/staging", "cert", false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("DeployCertificateSCP(gsm7228ps) error = %v, want ErrUnsupportedCapability", err)
	}
	if !strings.Contains(err.Error(), "HTTP multipart upload") {
		t.Errorf("DeployCertificateSCP(gsm7228ps) error = %q, want it to quote the mechanism-difference justification", err.Error())
	}
	if len(sess.calls) != 0 {
		t.Fatalf("calls = %v, want zero -- the gate must fire before any session I/O", sess.calls)
	}
}

func TestDeployCertificateSCPFullSequenceModernNoChain(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	sess := &restSession{}

	if err := DeployCertificateSCP(context.Background(), sess, m, "user@host", "pw", "/staging", "cert", false); err != nil {
		t.Fatalf("DeployCertificateSCP: %v", err)
	}
	serverCmd := "copy scp://user@host/staging/cert-server.pem nvram:sslpem-server"
	assertRestCalls(t, sess.calls, []restCall{
		{method: "Run", command: "no ip http secure-server"},
		{method: "RunSCPCopy", command: serverCmd, extra: "pw"},
		{method: "Run", command: "ip http secure-server"},
		{method: "RunWriteMemory", command: "write memory", extra: "prestuff=false"}, // m4300-24x: WritememStuff=false
	})
}

func TestDeployCertificateSCPFullSequenceLegacyWithChain(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	sess := &restSession{}

	if err := DeployCertificateSCP(context.Background(), sess, m, "user@host", "pw", "/staging", "cert", true); err != nil {
		t.Fatalf("DeployCertificateSCP: %v", err)
	}
	serverCmd := "copy scp://user@host/staging/cert-server.pem nvram:sslpem-server"
	rootCmd := "copy scp://user@host/staging/cert-root.pem nvram:sslpem-root"
	assertRestCalls(t, sess.calls, []restCall{
		{method: "Run", command: "no ip http secure-server"},
		{method: "RunSCPCopy", command: serverCmd, extra: "pw"},
		{method: "RunSCPCopy", command: rootCmd, extra: "pw"},
		{method: "Run", command: "ip http secure-server"},
		{method: "RunWriteMemory", command: "write memory", extra: "prestuff=true"}, // gsm7252ps: WritememStuff=true
	})
}

func TestDeployCertificateSCPServerCopyFailurePropagatesAndSkipsRest(t *testing.T) {
	m := mustGetModel(t, "m4300-16x")
	failure := errors.New("scp copy reported a failed transfer")
	sess := &restSession{
		runSCPCopyFn: func(string, string) (string, error) { return "", failure },
	}

	err := DeployCertificateSCP(context.Background(), sess, m, "user@host", "pw", "/staging", "cert", true)
	if !errors.Is(err, failure) {
		t.Fatalf("DeployCertificateSCP error = %v, want it to propagate the SCP failure", err)
	}
	// Only the HTTPS-off Run and the (failed) server RunSCPCopy should have
	// happened -- the root copy, the HTTPS-on Run, and the write memory must
	// never be reached.
	assertRestCalls(t, sess.calls, []restCall{
		{method: "Run", command: "no ip http secure-server"},
		{method: "RunSCPCopy", command: "copy scp://user@host/staging/cert-server.pem nvram:sslpem-server", extra: "pw"},
	})
}
