package fastpath

// Tests for Writer's VLAN/PVID ops (writer.go): CreateVLAN, DeleteVLAN,
// SetVLANMembership, SetPVID, driven against a SCRIPTED Session -- reusing
// scriptedSession (session_test.go), not a real ShellDriver/Transport --
// via newQueuedSession, a strict FIFO of canned (output, err) responses.
//
// Unlike reader_test.go's fakeCliSession (which routes a response by
// COMMAND TEXT, fine for pure reads), writer tests need the SAME command
// ("show vlan brief", "show vlan 90", ...) to answer differently at
// different points in one call (the before-write snapshot vs. the
// after-write verify-read-back), so responses are queued strictly in call
// ORDER instead. The command sequence itself is asserted separately, after
// the call, via sess.calls against an explicit wantCmds list built from the
// model's own CliModelSpec (never hand-typed literal command strings) --
// this combination lets these tests assert both (a) the EXACT command
// sequence issued (including the mandatory `switchport mode general` step
// and the inMode enter/exit nesting) and (b) verify-after-write behavior,
// per the task's required methodology.
//
// VLAN/PVID fixture TEXT below is hand-built, not a captured device
// transcript (unlike reader_test.go's fixtures): these tests need
// DIFFERENT before/after VLAN states per scenario, not one fixed capture.
// The table SHAPE (ruler-derived fixed-width columns, sliced the same way
// iterTableRows/parseVLANDetail/parsePVIDs already do) is real FASTPATH
// format; only the specific field values are synthetic.
import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// --- synthetic VLAN/PVID fixture builders ----------------------------------

// vlanBriefFixture builds a "show vlan brief"/"show vlan" page listing rows
// (each a [vlanID, name] pair), in the same ruler-delimited column shape
// parseVLANBrief expects (dossier §2.11). Zero rows is a valid, well-formed
// "no VLANs" page (header + ruler + nothing).
func vlanBriefFixture(rows ...[2]string) string {
	var b strings.Builder
	b.WriteString("VLAN ID VLAN Name")
	b.WriteString(strings.Repeat(" ", 25))
	b.WriteString("VLAN Type\n")
	b.WriteString(strings.Repeat("-", 7))
	b.WriteByte(' ')
	b.WriteString(strings.Repeat("-", 34))
	b.WriteByte(' ')
	b.WriteString(strings.Repeat("-", 19))
	b.WriteByte('\n')
	for _, r := range rows {
		fmt.Fprintf(&b, "%-7s %-34s %s\n", r[0], r[1], "Static")
	}
	return b.String()
}

// vlanDetailFixture builds a "show vlan <id>" detail page (header block +
// the Interface/Current/Configured/Tagging table, dossier §2.12), with rows
// built via vlanDetailRow.
func vlanDetailFixture(vlanID int, name string, rows ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nVLAN ID: %d\nVLAN Name: %s\nVLAN Type: Static\n\n", vlanID, name)
	b.WriteString("Interface   Current   Configured   Tagging\n")
	b.WriteString(strings.Repeat("-", 10))
	b.WriteString("  ")
	b.WriteString(strings.Repeat("-", 8))
	b.WriteString("  ")
	b.WriteString(strings.Repeat("-", 11))
	b.WriteString("  ")
	b.WriteString(strings.Repeat("-", 8))
	b.WriteByte('\n')
	for _, r := range rows {
		b.WriteString(r)
	}
	return b.String()
}

// vlanDetailRow builds one physical-port row (1/0/<port>) for
// vlanDetailFixture; column widths (12/10/13) match the ruler
// vlanDetailFixture emits exactly, so cells land in the intended spans.
func vlanDetailRow(port int, current, configured, tagging string) string {
	iface := fmt.Sprintf("1/0/%d", port)
	return fmt.Sprintf("%-12s%-10s%-13s%s\n", iface, current, configured, tagging)
}

// pvidFixture builds a "show vlan port all" page (dossier §2.13) from rows
// built via pvidRow.
func pvidFixture(rows ...string) string {
	var b strings.Builder
	b.WriteString("Interface   Port VLAN ID Configured   Current\n")
	b.WriteString(strings.Repeat("-", 10))
	b.WriteString("  ")
	b.WriteString(strings.Repeat("-", 26))
	b.WriteString("  ")
	b.WriteString(strings.Repeat("-", 10))
	b.WriteByte('\n')
	for _, r := range rows {
		b.WriteString(r)
	}
	return b.String()
}

// pvidRow builds one physical-port row (1/0/<port>) for pvidFixture; column
// widths (12/28) match the ruler pvidFixture emits exactly.
func pvidRow(port, vlan int) string {
	iface := fmt.Sprintf("1/0/%d", port)
	return fmt.Sprintf("%-12s%-28dfiller\n", iface, vlan)
}

// --- queued Session fake ----------------------------------------------------

// queuedStep is one canned (output, err) response, consumed strictly in
// call order regardless of the command text.
type queuedStep struct {
	output string
	err    error
}

// ok is a queuedStep with no error -- ok("") is an ACCEPTED config command
// (empty output, the FASTPATH accept convention, session.go's run); ok(text)
// with text non-empty is either a read's canned page or a REJECTED config
// command (any non-empty output), depending which the test is scripting.
func ok(output string) queuedStep { return queuedStep{output: output} }

// newQueuedSession builds a scriptedSession (session_test.go) whose Run
// serves steps strictly in order, regardless of the command text -- the
// command sequence itself is asserted separately via sess.calls
// (scriptedSession's own recorder). Calling Run past the end of steps
// returns an error naming the overrun, rather than panicking, so a test bug
// (too few scripted steps) fails with a readable message.
func newQueuedSession(steps ...queuedStep) *scriptedSession {
	idx := 0
	sess := &scriptedSession{}
	sess.runFn = func(_ context.Context, command string) (string, error) {
		if idx >= len(steps) {
			return "", fmt.Errorf("newQueuedSession: no more scripted responses (command %q, %d already consumed)", command, idx)
		}
		st := steps[idx]
		idx++
		return st.output, st.err
	}
	return sess
}

func assertCommands(t *testing.T, sess *scriptedSession, want []string) {
	t.Helper()
	if !reflect.DeepEqual(sess.calls, want) {
		t.Errorf("commands = %#v, want %#v", sess.calls, want)
	}
}

func indexOfCmd(xs []string, v string) int {
	for i, x := range xs {
		if x == v {
			return i
		}
	}
	return -1
}

func mustCLISpec(t *testing.T, m *model.SwitchModel) *CliModelSpec {
	t.Helper()
	spec, err := CLISpec(m)
	if err != nil {
		t.Fatalf("CLISpec(%q): %v", m.Key, err)
	}
	return spec
}

func mustNewWriter(t *testing.T, session Session, m *model.SwitchModel, opts ...WriterOption) *Writer {
	t.Helper()
	w, err := NewWriter(session, m, opts...)
	if err != nil {
		t.Fatalf("NewWriter(%q): %v", m.Key, err)
	}
	return w
}

// ---------------------------------------------------------------------
// NewWriter construction gate
// ---------------------------------------------------------------------

func TestWriterNewWriterUnsupportedModel(t *testing.T) {
	m := mustGetModel(t, "gs110emx")
	sess := newQueuedSession()
	if _, err := NewWriter(sess, m); err == nil {
		t.Fatal("NewWriter(gs110emx): want error (no CLI backend), got nil")
	}
}

// ---------------------------------------------------------------------
// CreateVLAN (dossier §4.2)
// ---------------------------------------------------------------------

func TestWriterCreateVLANFullSequence(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)

	beforeBrief := vlanBriefFixture() // no VLANs yet
	afterBrief := vlanBriefFixture([2]string{"90", "sales"})
	afterDetail := vlanDetailFixture(90, "sales")

	sess := newQueuedSession(
		ok(beforeBrief), // before: GetVLANs -> show vlan brief (0 rows, no per-VLAN detail calls)
		ok(""),          // vlan database
		ok(""),          // vlan 90
		ok(""),          // vlan name 90 sales
		ok(""),          // unwind: exit
		ok(afterBrief),  // after: show vlan brief
		ok(afterDetail), // after: show vlan 90
	)
	w := mustNewWriter(t, sess, m)

	if err := w.CreateVLAN(context.Background(), 90, "sales"); err != nil {
		t.Fatalf("CreateVLAN: %v", err)
	}

	wantCmds := []string{
		spec.VlanBriefCmd,
		spec.VlanDatabaseCmd,
		spec.VlanCreate(90),
		spec.VlanName(90, "sales"),
		spec.ExitCmd,
		spec.VlanBriefCmd,
		spec.VlanDetail(90),
	}
	assertCommands(t, sess, wantCmds)
}

func TestWriterCreateVLANVerificationMismatch(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")

	beforeBrief := vlanBriefFixture()
	afterBrief := vlanBriefFixture([2]string{"90", "wrong-name"})
	afterDetail := vlanDetailFixture(90, "wrong-name")

	sess := newQueuedSession(
		ok(beforeBrief),
		ok(""), ok(""), ok(""), ok(""),
		ok(afterBrief), ok(afterDetail),
	)
	w := mustNewWriter(t, sess, m)

	err := w.CreateVLAN(context.Background(), 90, "sales")
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("CreateVLAN error = %v, want *model.WriteVerificationError", err)
	}
}

func TestWriterCreateVLANRejectedIsPropagated(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	beforeBrief := vlanBriefFixture()

	sess := newQueuedSession(
		ok(beforeBrief),
		ok(""),                     // vlan database (entered)
		ok("% Invalid input '90'"), // vlan 90 -- REJECTED
		ok(""),                     // unwind: exit (1 level entered)
	)
	w := mustNewWriter(t, sess, m)

	err := w.CreateVLAN(context.Background(), 90, "sales")
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("CreateVLAN error = %v, want ErrCliCommandRejected", err)
	}
	wantCmds := []string{spec.VlanBriefCmd, spec.VlanDatabaseCmd, spec.VlanCreate(90), spec.ExitCmd}
	assertCommands(t, sess, wantCmds)
}

// ---------------------------------------------------------------------
// DeleteVLAN (dossier §4.3, §6.2)
// ---------------------------------------------------------------------

func TestWriterDeleteVLANMissingIsPrecondition(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	sess := newQueuedSession(ok(vlanBriefFixture())) // no VLANs -> 90 absent

	w := mustNewWriter(t, sess, m)
	err := w.DeleteVLAN(context.Background(), 90, false)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("DeleteVLAN error = %v, want ErrCliCommandRejected", err)
	}
	var verr *model.WriteVerificationError
	if errors.As(err, &verr) {
		t.Fatalf("DeleteVLAN error is a *model.WriteVerificationError, want a precondition error instead")
	}
	assertCommands(t, sess, []string{spec.VlanBriefCmd})
}

func TestWriterDeleteVLANProtectedMemberRequiresForce(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	beforeBrief := vlanBriefFixture([2]string{"90", "iot"})
	beforeDetail := vlanDetailFixture(90, "iot", vlanDetailRow(5, "Include", "Include", "Untagged"))

	sess := newQueuedSession(ok(beforeBrief), ok(beforeDetail))
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5))

	err := w.DeleteVLAN(context.Background(), 90, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("DeleteVLAN error = %v, want ErrProtectedPort", err)
	}
	assertCommands(t, sess, []string{spec.VlanBriefCmd, spec.VlanDetail(90)})

	// force=true bypasses the clash and the delete proceeds to completion.
	afterBrief := vlanBriefFixture() // VLAN gone
	sess2 := newQueuedSession(
		ok(beforeBrief), ok(beforeDetail),
		ok(""), ok(""), ok(""),
		ok(afterBrief),
	)
	w2 := mustNewWriter(t, sess2, m, WithProtectedPorts(5))
	if err := w2.DeleteVLAN(context.Background(), 90, true); err != nil {
		t.Fatalf("DeleteVLAN with force=true: %v", err)
	}
	wantCmds := []string{
		spec.VlanBriefCmd, spec.VlanDetail(90),
		spec.VlanDatabaseCmd, spec.VlanDelete(90), spec.ExitCmd,
		spec.VlanBriefCmd,
	}
	assertCommands(t, sess2, wantCmds)
}

func TestWriterDeleteVLANVerificationMismatch(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	beforeBrief := vlanBriefFixture([2]string{"90", "iot"})
	beforeDetail := vlanDetailFixture(90, "iot")
	// after: VLAN 90 still present -- the delete silently didn't take.
	sess := newQueuedSession(
		ok(beforeBrief), ok(beforeDetail),
		ok(""), ok(""), ok(""),
		ok(beforeBrief), ok(beforeDetail),
	)
	w := mustNewWriter(t, sess, m)

	err := w.DeleteVLAN(context.Background(), 90, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("DeleteVLAN error = %v, want *model.WriteVerificationError", err)
	}
}

// ---------------------------------------------------------------------
// SetVLANMembership (dossier §4.4) -- the switchport-mode-general hazard
// ---------------------------------------------------------------------

func TestWriterSetVLANMembershipSwitchportGeneralMandatory(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	spec := mustCLISpec(t, m)
	if spec.SwitchportGeneralCmd == "" {
		t.Fatal("test setup: m4300-24x spec unexpectedly has no SwitchportGeneralCmd")
	}
	beforeBrief := vlanBriefFixture([2]string{"90", "iot"})
	beforeDetail := vlanDetailFixture(90, "iot", vlanDetailRow(5, "Exclude", "Autodetect", "Untagged"))
	afterDetail := vlanDetailFixture(90, "iot", vlanDetailRow(5, "Include", "Include", "Untagged"))

	sess := newQueuedSession(
		ok(beforeBrief), ok(beforeDetail), // before GetVLANs
		ok(""), ok(""), // enter: configure, interface 1/0/5
		ok(""), ok(""), ok(""), // body: switchport mode general, vlan participation include 90, no vlan tagging 90
		ok(""), ok(""), // unwind: exit x2
		ok(beforeBrief), ok(afterDetail), // after GetVLANs
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetVLANMembership(context.Background(), 90, 5, model.VlanUntagged, false); err != nil {
		t.Fatalf("SetVLANMembership: %v", err)
	}

	wantCmds := []string{
		spec.VlanBriefCmd, spec.VlanDetail(90),
		spec.ConfigureCmd, spec.Interface(5),
		spec.SwitchportGeneralCmd,
		spec.VlanParticipation(90, true),
		spec.VlanTagging(90, false),
		spec.ExitCmd, spec.ExitCmd,
		spec.VlanBriefCmd, spec.VlanDetail(90),
	}
	assertCommands(t, sess, wantCmds)

	// THE hazard this test exists for: switchport mode general MUST
	// precede the vlan participation/tagging commands, not just be present
	// somewhere in the sequence.
	genIdx := indexOfCmd(sess.calls, spec.SwitchportGeneralCmd)
	partIdx := indexOfCmd(sess.calls, spec.VlanParticipation(90, true))
	if genIdx < 0 || partIdx < 0 || genIdx > partIdx {
		t.Fatalf("switchport mode general (idx %d) must precede vlan participation (idx %d); commands = %v", genIdx, partIdx, sess.calls)
	}
}

func TestWriterSetVLANMembershipNoSwitchportGeneralOnGSM7252PS(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	if spec.SwitchportGeneralCmd != "" {
		t.Fatal("test setup: gsm7252ps spec unexpectedly HAS a SwitchportGeneralCmd")
	}
	beforeBrief := vlanBriefFixture([2]string{"90", "iot"})
	beforeDetail := vlanDetailFixture(90, "iot", vlanDetailRow(5, "Exclude", "Autodetect", "Untagged"))
	afterDetail := vlanDetailFixture(90, "iot", vlanDetailRow(5, "Include", "Include", "Tagged"))

	sess := newQueuedSession(
		ok(beforeBrief), ok(beforeDetail),
		ok(""), ok(""), // enter
		ok(""), ok(""), // body: vlan participation include 90, vlan tagging 90 -- NO switchport mode general
		ok(""), ok(""), // unwind
		ok(beforeBrief), ok(afterDetail),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetVLANMembership(context.Background(), 90, 5, model.VlanTagged, false); err != nil {
		t.Fatalf("SetVLANMembership: %v", err)
	}
	wantCmds := []string{
		spec.VlanBriefCmd, spec.VlanDetail(90),
		spec.ConfigureCmd, spec.Interface(5),
		spec.VlanParticipation(90, true),
		spec.VlanTagging(90, true),
		spec.ExitCmd, spec.ExitCmd,
		spec.VlanBriefCmd, spec.VlanDetail(90),
	}
	assertCommands(t, sess, wantCmds)
	for _, c := range sess.calls {
		if c == "switchport mode general" {
			t.Fatalf("gsm7252ps: switchport mode general must never be sent (this XE image rejects it outright); commands = %v", sess.calls)
		}
	}
}

func TestWriterSetVLANMembershipExcludedModeSendsOnlyParticipation(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	spec := mustCLISpec(t, m)
	beforeBrief := vlanBriefFixture([2]string{"90", "iot"})
	beforeDetail := vlanDetailFixture(90, "iot", vlanDetailRow(5, "Include", "Include", "Untagged"))
	afterDetail := vlanDetailFixture(90, "iot", vlanDetailRow(5, "Exclude", "Autodetect", "Untagged"))

	sess := newQueuedSession(
		ok(beforeBrief), ok(beforeDetail),
		ok(""), ok(""), // enter
		ok(""), ok(""), // body: switchport mode general, vlan participation exclude 90 (NO tagging command)
		ok(""), ok(""), // unwind
		ok(beforeBrief), ok(afterDetail),
	)
	w := mustNewWriter(t, sess, m)

	if err := w.SetVLANMembership(context.Background(), 90, 5, model.VlanExcluded, false); err != nil {
		t.Fatalf("SetVLANMembership: %v", err)
	}
	wantCmds := []string{
		spec.VlanBriefCmd, spec.VlanDetail(90),
		spec.ConfigureCmd, spec.Interface(5),
		spec.SwitchportGeneralCmd,
		spec.VlanParticipation(90, false),
		spec.ExitCmd, spec.ExitCmd,
		spec.VlanBriefCmd, spec.VlanDetail(90),
	}
	assertCommands(t, sess, wantCmds)
}

func TestWriterSetVLANMembershipGuardBeforeAnyCommand(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	sess := newQueuedSession() // no steps scripted -- guard must fire with ZERO session I/O
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5))

	err := w.SetVLANMembership(context.Background(), 90, 5, model.VlanTagged, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetVLANMembership error = %v, want ErrProtectedPort", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want zero -- guard must fire before any session I/O", sess.calls)
	}
}

func TestWriterSetVLANMembershipMissingVLANIsPrecondition(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	spec := mustCLISpec(t, m)
	sess := newQueuedSession(ok(vlanBriefFixture())) // no VLANs -> 90 absent
	w := mustNewWriter(t, sess, m)

	err := w.SetVLANMembership(context.Background(), 90, 5, model.VlanTagged, false)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("SetVLANMembership error = %v, want ErrCliCommandRejected", err)
	}
	var verr *model.WriteVerificationError
	if errors.As(err, &verr) {
		t.Fatalf("SetVLANMembership error is a *model.WriteVerificationError, want a precondition error instead")
	}
	assertCommands(t, sess, []string{spec.VlanBriefCmd})
}

func TestWriterSetVLANMembershipVerificationMismatch(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	beforeBrief := vlanBriefFixture([2]string{"90", "iot"})
	beforeDetail := vlanDetailFixture(90, "iot", vlanDetailRow(5, "Exclude", "Autodetect", "Untagged"))
	// after: port 5 STILL excluded -- the write silently didn't take.
	afterDetail := beforeDetail

	sess := newQueuedSession(
		ok(beforeBrief), ok(beforeDetail),
		ok(""), ok(""),
		ok(""), ok(""), ok(""),
		ok(""), ok(""),
		ok(beforeBrief), ok(afterDetail),
	)
	w := mustNewWriter(t, sess, m)

	err := w.SetVLANMembership(context.Background(), 90, 5, model.VlanUntagged, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetVLANMembership error = %v, want *model.WriteVerificationError", err)
	}
}

// TestWriterSetVLANMembershipRejectedBodyCommandUnwinds exercises the
// counted-unwind hazard (session.go's inMode, protocol dossier risk #5)
// through Writer specifically: a rejected body command must still unwind
// BOTH entered config-mode levels (configure + interface), never zero,
// never partial -- and verification must NOT be attempted afterward.
func TestWriterSetVLANMembershipRejectedBodyCommandUnwinds(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	spec := mustCLISpec(t, m)
	beforeBrief := vlanBriefFixture([2]string{"90", "iot"})
	beforeDetail := vlanDetailFixture(90, "iot", vlanDetailRow(5, "Exclude", "Autodetect", "Untagged"))

	sess := newQueuedSession(
		ok(beforeBrief), ok(beforeDetail), // before
		ok(""), ok(""), // enter: configure, interface (both accepted)
		ok("% Unrecognized command"), // switchport mode general -- REJECTED
		ok(""), ok(""),               // unwind: exit x2 (both entered levels, regardless of the rejection)
	)
	w := mustNewWriter(t, sess, m)

	err := w.SetVLANMembership(context.Background(), 90, 5, model.VlanUntagged, false)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("SetVLANMembership error = %v, want ErrCliCommandRejected", err)
	}
	wantCmds := []string{
		spec.VlanBriefCmd, spec.VlanDetail(90),
		spec.ConfigureCmd, spec.Interface(5),
		spec.SwitchportGeneralCmd,
		spec.ExitCmd, spec.ExitCmd,
	}
	assertCommands(t, sess, wantCmds)
}

// ---------------------------------------------------------------------
// SetPVID (dossier §4.5)
// ---------------------------------------------------------------------

// vlan90ExistsSteps returns the queued (VlanBriefCmd, VlanDetail(90))
// responses SetPVID's VLAN-existence precondition (w.vlan) now issues
// BEFORE its own GetPVIDs/write/verify sequence, and the matching leading
// commands for wantCmds -- shared by every SetPVID test below whose target
// VLAN is 90 and must exist for the write to proceed at all (GAP-1 fix,
// parity with Python commit 98fb935).
func vlan90ExistsSteps() []queuedStep {
	return []queuedStep{
		ok(vlanBriefFixture([2]string{"90", "iot"})),
		ok(vlanDetailFixture(90, "iot")),
	}
}

func vlan90ExistsCmds(spec *CliModelSpec) []string {
	return []string{spec.VlanBriefCmd, spec.VlanDetail(90)}
}

func TestWriterSetPVIDFullSequence(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	spec := mustCLISpec(t, m)
	before := pvidFixture(pvidRow(5, 1))
	after := pvidFixture(pvidRow(5, 90))

	sess := newQueuedSession(append(vlan90ExistsSteps(),
		ok(before),     // before GetPVIDs
		ok(""), ok(""), // enter: configure, interface
		ok(""), ok(""), // body: switchport mode general, vlan pvid 90
		ok(""), ok(""), // unwind: exit x2
		ok(after), // after GetPVIDs
	)...)
	w := mustNewWriter(t, sess, m)

	if err := w.SetPVID(context.Background(), 5, 90, false); err != nil {
		t.Fatalf("SetPVID: %v", err)
	}
	wantCmds := append(vlan90ExistsCmds(spec),
		spec.PvidCmd,
		spec.ConfigureCmd, spec.Interface(5),
		spec.SwitchportGeneralCmd,
		spec.VlanPvid(90),
		spec.ExitCmd, spec.ExitCmd,
		spec.PvidCmd,
	)
	assertCommands(t, sess, wantCmds)
}

func TestWriterSetPVIDNoSwitchportGeneralOnGSM7252PS(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	spec := mustCLISpec(t, m)
	before := pvidFixture(pvidRow(5, 1))
	after := pvidFixture(pvidRow(5, 90))

	sess := newQueuedSession(append(vlan90ExistsSteps(),
		ok(before),
		ok(""), ok(""), // enter
		ok(""),         // body: vlan pvid 90 only (NO switchport mode general)
		ok(""), ok(""), // unwind
		ok(after),
	)...)
	w := mustNewWriter(t, sess, m)

	if err := w.SetPVID(context.Background(), 5, 90, false); err != nil {
		t.Fatalf("SetPVID: %v", err)
	}
	wantCmds := append(vlan90ExistsCmds(spec),
		spec.PvidCmd,
		spec.ConfigureCmd, spec.Interface(5),
		spec.VlanPvid(90),
		spec.ExitCmd, spec.ExitCmd,
		spec.PvidCmd,
	)
	assertCommands(t, sess, wantCmds)
}

func TestWriterSetPVIDGuard(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	sess := newQueuedSession() // no steps scripted -- guard must fire with ZERO session I/O
	w := mustNewWriter(t, sess, m, WithProtectedPorts(5))

	err := w.SetPVID(context.Background(), 5, 90, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetPVID error = %v, want ErrProtectedPort", err)
	}
	if len(sess.calls) != 0 {
		t.Fatalf("commands = %v, want zero -- guard must fire before any session I/O", sess.calls)
	}

	// force=true bypasses the guard and the write proceeds to completion.
	before := pvidFixture(pvidRow(5, 1))
	after := pvidFixture(pvidRow(5, 90))
	sess2 := newQueuedSession(append(vlan90ExistsSteps(),
		ok(before),
		ok(""), ok(""), ok(""), ok(""),
		ok(""), ok(""),
		ok(after),
	)...)
	w2 := mustNewWriter(t, sess2, m, WithProtectedPorts(5))
	if err := w2.SetPVID(context.Background(), 5, 90, true); err != nil {
		t.Fatalf("SetPVID with force=true: %v", err)
	}
}

func TestWriterSetPVIDVerificationMismatch(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	before := pvidFixture(pvidRow(5, 1))
	after := before // unchanged -- the write silently didn't take.

	sess := newQueuedSession(append(vlan90ExistsSteps(),
		ok(before),
		ok(""), ok(""), ok(""), ok(""),
		ok(""), ok(""),
		ok(after),
	)...)
	w := mustNewWriter(t, sess, m)

	err := w.SetPVID(context.Background(), 5, 90, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPVID error = %v, want *model.WriteVerificationError", err)
	}
}

// TestWriterSetPVIDMissingVLANIsPrecondition pins the GAP-1 fix (parity
// with Python commit 98fb935): whether the target VLAN must pre-exist used
// to be DELIBERATELY left to the switch (no library-side existence check,
// unlike SetVLANMembership), on the assumption an unknown vlan would come
// back as a command rejection. That assumption does not hold generally --
// MEASURED on a GS728TPP (10.2.5.10, firmware 6.0.1.30) over HTTP/SNMP, the
// equivalent write is silently ACCEPTED and reads back, leaving the port
// pointing at nothing. SetPVID now refuses up front, exactly like
// SetVLANMembership already does, issuing ZERO commands beyond the
// existence check itself.
func TestWriterSetPVIDMissingVLANIsPrecondition(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	spec := mustCLISpec(t, m)
	sess := newQueuedSession(ok(vlanBriefFixture())) // no VLANs -> 999 absent
	w := mustNewWriter(t, sess, m)

	err := w.SetPVID(context.Background(), 5, 999, false)
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Fatalf("SetPVID error = %v, want ErrCliCommandRejected", err)
	}
	var verr *model.WriteVerificationError
	if errors.As(err, &verr) {
		t.Fatalf("SetPVID error is a *model.WriteVerificationError, want a precondition error instead")
	}
	assertCommands(t, sess, []string{spec.VlanBriefCmd})
}
