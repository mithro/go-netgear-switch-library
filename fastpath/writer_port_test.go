package fastpath

// Tests for Writer's SetPortDescription/SetPortSpeed/SetFlowControl
// (writer.go, C3 slice), driven against the same scripted Session fakes
// writer_rest_test.go/writer_vlan_test.go already establish: newQueuedSession
// (a strict FIFO of canned Run responses), portAllHeader/portAllRuler/
// buildRow (the ruler-derived "show port all" row builder), assertCommands,
// mustCLISpec, mustNewWriter, mustGetModel.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// portDescriptionFixture builds a "show port description <iface>" page,
// mirroring the live GSM7252PS transcript parsePortDescription's own doc
// comment quotes (fastpath/parse.go): Interface/ifIndex/Description/MAC
// address/Bit Offset Val, in that order. An empty desc renders the
// Description line with nothing after it (an unset label), exactly as
// parsePortDescription expects.
func portDescriptionFixture(iface string, port int, desc string) string {
	line := fmt.Sprintf("Description..... %s", desc)
	if desc == "" {
		line = "Description....."
	}
	return fmt.Sprintf(
		"Interface....... %s\nifIndex......... %d\n%s\nMAC address..... 00:11:22:33:44:55\nBit Offset Val.. %d\n",
		iface, port, line, port,
	)
}

// portConfigFixture builds a "show port all" page with a single physical
// port row, its Physical Mode and Flow Mode columns controlled by the
// caller -- the two columns SetPortSpeed/SetFlowControl verify against
// (portStatusFixture, writer_rest_test.go, hardcodes both instead).
func portConfigFixture(port int, physicalMode, flowMode string) string {
	row := buildRow(portAllRuler, fmt.Sprintf("1/0/%d", port), "", "Enable", physicalMode, "1000 Full", "Up", "Enable", "Enable", flowMode)
	return portAllHeader + portAllRuler + "\n" + row
}

// ---------------------------------------------------------------------
// SetPortDescription
// ---------------------------------------------------------------------

func TestWriterSetPortDescriptionFullSequence(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	iface := spec.Iface(5)
	before := portDescriptionFixture(iface, 5, "")
	after := portDescriptionFixture(iface, 5, "uplink")

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""),
		ok(""),
		ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetPortDescription(context.Background(), 5, "uplink", false); err != nil {
		t.Fatalf("SetPortDescription: %v", err)
	}
	wantCmds := []string{
		spec.PortDescriptionShow(5),
		spec.ConfigureCmd, spec.Interface(5),
		spec.PortDescription("uplink"),
		spec.ExitCmd, spec.ExitCmd,
		spec.PortDescriptionShow(5),
	}
	assertCommands(t, sess, wantCmds)
}

func TestWriterSetPortDescriptionClearingSendsNoDescription(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	iface := spec.Iface(5)
	before := portDescriptionFixture(iface, 5, "old-label")
	after := portDescriptionFixture(iface, 5, "")

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""),
		ok(""),
		ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetPortDescription(context.Background(), 5, "", false); err != nil {
		t.Fatalf("SetPortDescription(\"\"): %v", err)
	}
	if idx := indexOfCmd(sess.calls, spec.PortNoDescriptionCmd); idx < 0 {
		t.Errorf("commands = %v, want %q (the no-description negation)", sess.calls, spec.PortNoDescriptionCmd)
	}
}

func TestWriterSetPortDescriptionVerificationMismatch(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := portDescriptionFixture(spec.Iface(5), 5, "old")
	after := before // unchanged -- the write silently didn't take.

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""), ok(""), ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	err := w.SetPortDescription(context.Background(), 5, "uplink", false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPortDescription error = %v, want *model.WriteVerificationError", err)
	}
}

func TestWriterSetPortDescriptionGuardBlocksWithoutForce(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	sess := newQueuedSession()
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5))

	err := w.SetPortDescription(context.Background(), 5, "uplink", false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetPortDescription error = %v, want ErrProtectedPort", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want none (blocked before any I/O)", sess.calls)
	}
}

// ---------------------------------------------------------------------
// SetPortSpeed
// ---------------------------------------------------------------------

func TestWriterSetPortSpeedFullSequenceForced(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := portConfigFixture(5, "Auto", "Disable")
	after := portConfigFixture(5, "100 Full", "Disable")

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""),
		ok(""),
		ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	speed := model.ForcedPortSpeed(100, true)
	if err := w.SetPortSpeed(context.Background(), 5, speed, false); err != nil {
		t.Fatalf("SetPortSpeed: %v", err)
	}
	wantCmds := []string{
		spec.PortStatusCmd,
		spec.ConfigureCmd, spec.Interface(5),
		spec.PortSpeed(speed),
		spec.ExitCmd, spec.ExitCmd,
		spec.PortStatusCmd,
	}
	assertCommands(t, sess, wantCmds)
}

func TestWriterSetPortSpeedFullSequenceAuto(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := portConfigFixture(5, "100 Full", "Disable")
	after := portConfigFixture(5, "Auto", "Disable")

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""),
		ok(""),
		ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetPortSpeed(context.Background(), 5, model.AutoPortSpeed(), false); err != nil {
		t.Fatalf("SetPortSpeed(auto): %v", err)
	}
	if idx := indexOfCmd(sess.calls, spec.PortSpeedAutoCmd); idx < 0 {
		t.Errorf("commands = %v, want %q", sess.calls, spec.PortSpeedAutoCmd)
	}
}

// TestWriterSetPortSpeedRefusesForced1000 proves the forced-1000 refusal
// fires BEFORE any command is sent, wrapping ErrCliCommandRejected (mirroring
// Python's CliCommandError) rather than model.ErrUnsupportedCapability -- the
// OP is supported, this one rate simply is not.
func TestWriterSetPortSpeedRefusesForced1000(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	sess := newQueuedSession()
	w := mustNewWriter(t, sess, m)

	err := w.SetPortSpeed(context.Background(), 5, model.ForcedPortSpeed(1000, true), false)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("SetPortSpeed(1000) error = %v, want ErrCliCommandRejected", err)
	}
	if errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("SetPortSpeed(1000) error also wraps ErrUnsupportedCapability, want ONLY ErrCliCommandRejected -- the op is supported, this rate is refused")
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want none: the forced-1000 refusal must never touch the session", sess.calls)
	}
}

// TestWriterSetPortSpeedDeviceRejectsUnsupportedRate proves an
// out-of-range rate this package does NOT pre-validate is sent unchecked,
// and the device's own rejection (any non-empty output) surfaces as
// ErrCliCommandRejected -- "the switch is the only authority worth asking".
func TestWriterSetPortSpeedDeviceRejectsUnsupportedRate(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	before := portConfigFixture(5, "Auto", "Disable")
	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""),
		queuedStep{output: "% Invalid input detected at '^' marker."},
		ok(""), ok(""), // exit unwind after the rejected body command
	)
	w := mustNewWriter(t, sess, m)

	err := w.SetPortSpeed(context.Background(), 5, model.ForcedPortSpeed(2500, true), false)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("SetPortSpeed(2500) error = %v, want ErrCliCommandRejected (the device's own rejection)", err)
	}
	var verr *model.WriteVerificationError
	if errors.As(err, &verr) {
		t.Errorf("SetPortSpeed(2500) error is a *model.WriteVerificationError, want the raw command-rejected error")
	}
}

func TestWriterSetPortSpeedVerificationMismatch(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	before := portConfigFixture(5, "Auto", "Disable")
	after := before // unchanged -- the write silently didn't take.

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""), ok(""), ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	err := w.SetPortSpeed(context.Background(), 5, model.ForcedPortSpeed(100, true), false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPortSpeed error = %v, want *model.WriteVerificationError", err)
	}
}

// TestWriterSetPortSpeedNoSuchPortIsPrecondition proves speedConfig's "no
// such port" branch: a port absent from "show port all" raises
// ErrCliCommandRejected naming it, BEFORE any command is sent (the read
// happens before the write).
func TestWriterSetPortSpeedNoSuchPortIsPrecondition(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	before := portConfigFixture(5, "Auto", "Disable") // only port 5 exists
	sess := newQueuedSession(ok(before))
	w := mustNewWriter(t, sess, m)

	err := w.SetPortSpeed(context.Background(), 99, model.ForcedPortSpeed(100, true), false)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("SetPortSpeed(port 99) error = %v, want ErrCliCommandRejected", err)
	}
	if len(sess.calls) != 1 {
		t.Fatalf("commands = %v, want exactly the one read (no write attempted)", sess.calls)
	}
}

func TestWriterSetPortSpeedGuardBlocksWithoutForce(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	sess := newQueuedSession()
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5))

	err := w.SetPortSpeed(context.Background(), 5, model.ForcedPortSpeed(100, true), false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetPortSpeed error = %v, want ErrProtectedPort", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want none (blocked before any I/O)", sess.calls)
	}
}

// ---------------------------------------------------------------------
// SetFlowControl
// ---------------------------------------------------------------------

func TestWriterSetFlowControlFullSequenceEnable(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := portConfigFixture(5, "Auto", "Disable")
	after := portConfigFixture(5, "Auto", "Enable")

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""),
		ok(""),
		ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetFlowControl(context.Background(), 5, true, false); err != nil {
		t.Fatalf("SetFlowControl: %v", err)
	}
	wantCmds := []string{
		spec.PortStatusCmd,
		spec.ConfigureCmd, spec.Interface(5),
		spec.PortFlowControl(true),
		spec.ExitCmd, spec.ExitCmd,
		spec.PortStatusCmd,
	}
	assertCommands(t, sess, wantCmds)
}

func TestWriterSetFlowControlFullSequenceDisable(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := portConfigFixture(5, "Auto", "Enable")
	after := portConfigFixture(5, "Auto", "Disable")

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""),
		ok(""),
		ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetFlowControl(context.Background(), 5, false, false); err != nil {
		t.Fatalf("SetFlowControl(false): %v", err)
	}
	if idx := indexOfCmd(sess.calls, spec.PortNoFlowControlCmd); idx < 0 {
		t.Errorf("commands = %v, want %q", sess.calls, spec.PortNoFlowControlCmd)
	}
}

func TestWriterSetFlowControlVerificationMismatch(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	before := portConfigFixture(5, "Auto", "Disable")
	after := before // unchanged -- the write silently didn't take.

	sess := newQueuedSession(
		ok(before),
		ok(""), ok(""), ok(""), ok(""), ok(""),
		ok(after),
	)
	w := mustNewWriter(t, sess, m)

	err := w.SetFlowControl(context.Background(), 5, true, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetFlowControl error = %v, want *model.WriteVerificationError", err)
	}
}

// TestWriterSetFlowControlNoSuchPortIsPrecondition proves flowControl's "no
// such port" branch, the SetFlowControl sibling of
// TestWriterSetPortSpeedNoSuchPortIsPrecondition.
func TestWriterSetFlowControlNoSuchPortIsPrecondition(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	before := portConfigFixture(5, "Auto", "Disable") // only port 5 exists
	sess := newQueuedSession(ok(before))
	w := mustNewWriter(t, sess, m)

	err := w.SetFlowControl(context.Background(), 99, true, false)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("SetFlowControl(port 99) error = %v, want ErrCliCommandRejected", err)
	}
	if len(sess.calls) != 1 {
		t.Fatalf("commands = %v, want exactly the one read (no write attempted)", sess.calls)
	}
}

func TestWriterSetFlowControlGuardBlocksWithoutForce(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	sess := newQueuedSession()
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5))

	err := w.SetFlowControl(context.Background(), 5, true, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetFlowControl error = %v, want ErrProtectedPort", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want none (blocked before any I/O)", sess.calls)
	}
}
