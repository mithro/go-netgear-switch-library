// writer.go: CliWriter -- shared write-op helpers, the VLAN lifecycle
// (CreateVLAN/DeleteVLAN/SetVLANMembership) and SetPVID (Task 9, dossier
// §4.1-§4.5), plus PoE (SetPoE/CyclePoE/ClearPoEFault), SetPortEnabled,
// SetMgmtIP and Reboot (Task 10, dossier §4.6-§4.9). Ported field-for-field
// from the pinned python-netgear-switch-library @
// 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362, src/netgear_switch/cli_write.py
// (666 lines), dossier (protocol dossier
// docs/superpowers/plans/2026-08-01-slice-07-dossier-cli-protocol.md). Any
// discrepancy between this file and the pin is a bug in this file, not a
// deliberate deviation, unless called out in a comment.
//
// The SCP certificate deploy (dossier §4.10, cli_write.py's module-level
// deploy_certificate_scp) lives in cert_scp.go instead, since it is NOT a
// Writer method at all in the pin -- a standalone function over a raw
// Session -- see that file's doc comment.
//
// The `run`/`inMode` config-mode accept/reject convention this file relies
// on is already ported in session.go (Task 5, mirroring Python
// CliWriter._run/_in_mode) -- see that file's doc comment for the
// counted-unwind hazard (protocol dossier risk #5) `inMode` guards against.
// This file does not duplicate that logic, only drives it.

package fastpath

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// Writer is a model-driven FASTPATH CLI write facade over one already-
// authenticated Session, mirroring Python CliWriter (cli_write.py:207-266
// and onward). Construct with NewWriter; every write op issues its op's
// config-mode command sequence (via run/inMode, session.go) then verifies
// the change via w's own internal Reader -- the SAME session, SAME parsers
// a plain read would use, exactly mirroring Python's CliWriter holding its
// own private CliReader (cli_write.py:227, "self._reader =
// CliReader(session, model)").
type Writer struct {
	session        Session
	spec           *CliModelSpec
	model          *model.SwitchModel
	protectedPorts map[int]bool
	reader         *Reader

	// clock/sleep are the injectable time seam SetPoE/CyclePoE/
	// ClearPoEFault's verify-after-write poll loops use (Task 10, dossier
	// §4.6) -- default to time.Now/defaultSleep, mirroring
	// snmp.Writer.clock/sleep (snmp/writer.go, snmp/writer_cycle.go)
	// exactly, including the WithClock option below. Every other Writer
	// method (VLAN/PVID, Task 9; SetPortEnabled/SetMgmtIP/Reboot, Task 10)
	// ignores these -- their verification is a single immediate read, never
	// a poll.
	clock func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// PoeCycleTimeouts is aliased from snmp.PoeCycleTimeouts, so
// CyclePoE/ClearPoEFault's signatures match the root package's
// BackendWriter interface (write_dispatch.go: `timeouts
// snmp.PoeCycleTimeouts`) EXACTLY -- a future fastpath backend wiring can
// satisfy BackendWriter with zero adapter code. Mirrors the root package's
// own alias.go re-export of the identical type. fastpath already imports
// snmp for parseVersion's DetectModelFromSysDescr reuse (parse.go), so this
// introduces no new cross-package dependency.
type PoeCycleTimeouts = snmp.PoeCycleTimeouts

// DefaultPoeCycleTimeouts returns the production PoE-cycle deadlines (30s
// off / 60s on / 2s poll), mirroring Python's module-level
// _DEFAULT_POE_TIMEOUTS = PoeCycleTimeouts() (cli_write.py) -- the same
// numeric defaults as snmp.DefaultPoeCycleTimeouts, reused directly rather
// than redeclared. SetPoE (whose public signature has no timeouts
// parameter, matching BackendWriter.SetPoE exactly) always polls with
// these; CyclePoE/ClearPoEFault take timeouts as an explicit per-call
// parameter instead (matching BackendWriter.CyclePoE/ClearPoEFault), so a
// caller wanting non-default SetPoE deadlines has no seam for that today --
// same limitation the pin's own Go-facing surface would have if it dropped
// the keyword-only timeouts parameter the same way.
func DefaultPoeCycleTimeouts() PoeCycleTimeouts {
	return snmp.DefaultPoeCycleTimeouts()
}

// defaultSleep is the production Sleep implementation: waits for d (a
// no-op if d <= 0) unless ctx is cancelled first, in which case it returns
// ctx.Err() -- identical to snmp package's defaultSleep (snmp/
// writer_cycle.go), duplicated here rather than exported from snmp since
// it is a private implementation detail of the polling seam, not part of
// that package's public API.
func defaultSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WithClock overrides the Writer's time source and poll-sleep function --
// the injectable clock/sleep seam SetPoE/CyclePoE/ClearPoEFault's poll
// loops use, mirroring Python's set_poe/cycle_poe/clear_poe_fault accepting
// clock=time.monotonic/sleep=time.sleep as per-call keyword arguments, but
// as a Writer-level (constructor-time) option instead -- the identical
// adaptation snmp.WithClock already makes (snmp/writer_cycle.go) for the
// SAME reason: tests inject a fake now/sleep pair to drive the poll state
// machine deterministically with zero real wall-clock delay. Either
// argument may be nil to leave that seam at its default (time.Now /
// defaultSleep).
func WithClock(now func() time.Time, sleep func(ctx context.Context, d time.Duration) error) WriterOption {
	return func(w *Writer) {
		if now != nil {
			w.clock = now
		}
		if sleep != nil {
			w.sleep = sleep
		}
	}
}

// WriterOption configures optional Writer construction parameters (only
// protected-ports today), mirroring the functional-options pattern
// snmp.Writer/snmp.WriterOption already use (snmp/writer.go).
type WriterOption func(*Writer)

// WithProtectedPorts marks ports as protected: every disruptive write to a
// protected port is refused unless force is passed as true, mirroring
// Python's CliWriter(..., protected_ports=frozenset({...})) and this
// package's snmp.WithProtectedPorts sibling exactly.
func WithProtectedPorts(ports ...int) WriterOption {
	return func(w *Writer) {
		for _, p := range ports {
			w.protectedPorts[p] = true
		}
	}
}

// NewWriter constructs a Writer bound to session and m, mirroring Python
// CliWriter.__init__ (cli_write.py:216-227): resolving m's CliModelSpec via
// CLISpec fails immediately -- before any session use -- for a model with
// no CLI backend or no registered spec (the SAME two-stage guard
// NewReader/CLISpec itself documents). Builds its OWN internal Reader on
// the SAME session, reused by every write's verify-after-write read-back.
func NewWriter(session Session, m *model.SwitchModel, opts ...WriterOption) (*Writer, error) {
	spec, err := CLISpec(m)
	if err != nil {
		return nil, err
	}
	reader, err := NewReader(session, m)
	if err != nil {
		return nil, err
	}
	w := &Writer{
		session:        session,
		spec:           spec,
		model:          m,
		protectedPorts: make(map[int]bool),
		reader:         reader,
		clock:          time.Now,
		sleep:          defaultSleep,
	}
	for _, opt := range opts {
		opt(w)
	}
	return w, nil
}

// errCliCommand wraps ErrCliCommandRejected with a formatted message,
// mirroring Python's CliCommandError, which cli_write.py raises from TWO
// distinct call sites with the identical exception type: (1) session.go's
// `run` helper, for an actual device-side rejection (non-empty output);
// (2) library-side PRECONDITION failures below (e.g. "VLAN %d does not
// exist") where no command has been sent at all yet. Both are the same
// sentinel here too, exactly as the Python source uses one exception class
// for both.
func errCliCommand(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrCliCommandRejected, fmt.Sprintf(format, a...))
}

// guard is the single protected-port gate several write ops call: it
// refuses port when port is protected and force is false, mirroring Python
// CliWriter._guard (cli_write.py:235-239, dossier §6.1) verbatim, including
// the message text ("force=True" preserved even though Go's parameter is a
// plain bool, not a keyword argument -- matches snmp.Writer.guard's own
// preserved wording).
func (w *Writer) guard(port int, force bool) error {
	if w.protectedPorts[port] && !force {
		return fmt.Errorf("port %d is protected; pass force=True to override: %w", port, model.ErrProtectedPort)
	}
	return nil
}

// generalMode returns the one-element command slice
// []string{spec.SwitchportGeneralCmd} to prepend to a per-port VLAN write's
// body, or nil on a model with no switchport-mode concept
// (SwitchportGeneralCmd == "", gsm7252ps only), mirroring Python
// CliWriter._general_mode (cli_write.py:268-278, dossier §4.1/§6.6).
//
// MANDATORY prelude, not an optimization: per dossier §4.4 and the live CLI
// finding it quotes, per-port `vlan participation`/`vlan tagging`/`vlan
// pvid` writes are silently INERT (accepted, but non-functional) while a
// port sits in `switchport mode access` -- every per-port VLAN write in
// this file MUST send this first (idempotent, so sending it unconditionally
// on every call is safe) or the write does nothing on real hardware. Sent
// unconditionally on every model that has the command at all; omitted
// entirely on gsm7252ps, whose firmware REJECTS it outright ("%
// Unrecognized command" -- this XE image has no switchport-mode concept).
func (w *Writer) generalMode() []string {
	if w.spec.SwitchportGeneralCmd == "" {
		return nil
	}
	return []string{w.spec.SwitchportGeneralCmd}
}

// vlan returns vlanID's current VLANInfo via w's internal reader, or nil if
// vlanID is absent from the current VLAN table, mirroring Python
// CliWriter._vlan (cli_write.py:281-282): re-runs the FULL GetVLANs (itself
// N+1 round trips, dossier §3.3) and linear-searches for the target VLAN --
// used for both before- and after-write snapshots.
func (w *Writer) vlan(ctx context.Context, vlanID int) (*model.VLANInfo, error) {
	vlans, err := w.reader.GetVLANs(ctx)
	if err != nil {
		return nil, err
	}
	for i := range vlans {
		if vlans[i].VlanID == vlanID {
			return &vlans[i], nil
		}
	}
	return nil, nil
}

// portMode derives port's 3-way model.VlanMode (Excluded/Tagged/Untagged)
// from info's membership sets, mirroring Python CliWriter._port_mode
// (cli_write.py:284-289). info == nil (VLAN absent entirely) or port not a
// member of info.MemberPorts both mean VlanExcluded.
func portMode(info *model.VLANInfo, port int) model.VlanMode {
	if info == nil || !slices.Contains(info.MemberPorts, port) {
		return model.VlanExcluded
	}
	if slices.Contains(info.TaggedPorts, port) {
		return model.VlanTagged
	}
	return model.VlanUntagged
}

// derefOrEmpty returns *s, or "" if s is nil -- mirrors Python's `x or ""`
// idiom CreateVLAN's verification uses to compare an optional VLAN name
// field against a plain string (same helper snmp.Writer's CreateVlan uses).
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// pvidFor returns port's vlan from pvids, or nil if port is absent --
// mirrors Python's `dict(self._reader.get_pvids()).get(port)` (a dict built
// from the (port, vlan) pair list, then `.get`, which returns None for a
// missing key).
func pvidFor(pvids []model.Pvid, port int) *int {
	for _, p := range pvids {
		if p.Port == port {
			v := p.Vlan
			return &v
		}
	}
	return nil
}

// formatIntList renders ports as a Python-`sorted(...)`-style bracketed,
// comma-separated list (e.g. "[1, 2, 10]") for the DeleteVLAN protected-
// port-clash message -- the same rendering snmp.Writer.DeleteVlan's
// sibling helper uses, so the two backends' clash messages read alike.
func formatIntList(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// CreateVLAN creates vlan with the given name and verifies it exists with
// that name afterward. Ported from Python CliWriter.create_vlan
// (cli_write.py:293-315, dossier §4.2).
//
// Command sequence: `vlan database` -> `vlan <vid>` -> `vlan name <vid>
// <name>` -> `exit`. There is deliberately NO force PARAMETER here (unlike
// Python, which accepts `force` but immediately discards it via `del
// force`, "for signature symmetry with delete_vlan" -- Go has no such
// symmetry requirement, and this mirrors the merged snmp.Writer.CreateVlan/
// the root BackendWriter interface's CreateVlan exactly, which also has no
// force parameter): creating an EMPTY VLAN adds no port membership, so it
// is non-disruptive by construction and nothing here is ever refused.
// Verification: re-fetch VLANs, fail if the VLAN doesn't exist OR its name
// doesn't match (comparing `after.Name` via derefOrEmpty against name, so a
// nil Name reads as empty string for comparison purposes, exactly mirroring
// Python's `after.name or ""`).
func (w *Writer) CreateVLAN(ctx context.Context, vlan int, name string) error {
	before, err := w.vlan(ctx, vlan)
	if err != nil {
		return err
	}
	if err := inMode(
		ctx, w.session,
		[]string{w.spec.VlanDatabaseCmd},
		[]string{w.spec.VlanCreate(vlan), w.spec.VlanName(vlan, name)},
		w.spec.ExitCmd,
	); err != nil {
		return err
	}
	after, err := w.vlan(ctx, vlan)
	if err != nil {
		return err
	}
	if after == nil || derefOrEmpty(after.Name) != name {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("VLAN %d was not created with name %q", vlan, name),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// DeleteVLAN destroys vlan and verifies it is gone afterward. Ported from
// Python CliWriter.delete_vlan (cli_write.py:317-343, dossier §4.3).
//
// TWO distinct precondition/safety checks BEFORE any command is sent: (1)
// vlan must exist -- a PRECONDITION failure (errCliCommand-wrapped
// ErrCliCommandRejected, NOT a *model.WriteVerificationError; "no command
// has been sent yet"); (2) unless force, refuse if vlan's member ports
// intersect w.protectedPorts (dossier §6.2 -- a SET-INTERSECTION check,
// distinct from guard's single-port test: destroying a VLAN strips
// membership from EVERY member port at once). Command sequence: `vlan
// database` -> `no vlan <vid>` -> `exit`. Verification: vlan must be gone.
func (w *Writer) DeleteVLAN(ctx context.Context, vlan int, force bool) error {
	before, err := w.vlan(ctx, vlan)
	if err != nil {
		return err
	}
	if before == nil {
		return errCliCommand("VLAN %d does not exist", vlan)
	}
	if !force {
		var clash []int
		for _, p := range before.MemberPorts {
			if w.protectedPorts[p] {
				clash = append(clash, p)
			}
		}
		if len(clash) > 0 {
			sort.Ints(clash)
			return fmt.Errorf(
				"VLAN %d includes protected port(s) %s; pass force=True to delete it anyway: %w",
				vlan, formatIntList(clash), model.ErrProtectedPort,
			)
		}
	}
	if err := inMode(
		ctx, w.session,
		[]string{w.spec.VlanDatabaseCmd},
		[]string{w.spec.VlanDelete(vlan)},
		w.spec.ExitCmd,
	); err != nil {
		return err
	}
	after, err := w.vlan(ctx, vlan)
	if err != nil {
		return err
	}
	if after != nil {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("VLAN %d still exists after %q", vlan, w.spec.VlanDelete(vlan)),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// SetVLANMembership sets port's membership mode (untagged/tagged/excluded)
// within vlan and verifies the target port's own participation read back
// correctly. Ported from Python CliWriter.set_vlan_membership
// (cli_write.py:347-386, dossier §4.4).
//
// guard(port, force) runs FIRST -- protected-port refusal happens BEFORE
// the vlan-exists check and before any command is sent at all, mirroring
// the pin exactly. A missing vlan is a PRECONDITION failure (errCliCommand,
// not a verification error). Command sequence: `configure` -> `interface
// <iface>` -> [`switchport mode general` if the model has one] -> EITHER
// `vlan participation exclude <vid>` (mode == VlanExcluded) OR `vlan
// participation include <vid>` + (`vlan tagging <vid>` if VlanTagged else
// `no vlan tagging <vid>`) -> `exit` `exit`. Verification is DELIBERATELY
// SCOPED to only the target port's own participation (dossier §4.4): a
// general-mode side effect can legitimately move OTHER vlans' membership
// for this port ("not this VLAN's business"), so only portMode(after,
// port) == mode is checked.
func (w *Writer) SetVLANMembership(ctx context.Context, vlan, port int, mode model.VlanMode, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	before, err := w.vlan(ctx, vlan)
	if err != nil {
		return err
	}
	if before == nil {
		return errCliCommand("VLAN %d does not exist", vlan)
	}
	body := w.generalMode()
	if mode == model.VlanExcluded {
		body = append(body, w.spec.VlanParticipation(vlan, false))
	} else {
		body = append(body, w.spec.VlanParticipation(vlan, true))
		body = append(body, w.spec.VlanTagging(vlan, mode == model.VlanTagged))
	}
	if err := inMode(
		ctx, w.session,
		[]string{w.spec.ConfigureCmd, w.spec.Interface(port)},
		body,
		w.spec.ExitCmd,
	); err != nil {
		return err
	}
	after, err := w.vlan(ctx, vlan)
	if err != nil {
		return err
	}
	if after == nil {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("VLAN %d disappeared while setting membership for port %d", vlan, port),
			Before: before,
			After:  after,
		}
	}
	got := portMode(after, port)
	if got != mode {
		return &model.WriteVerificationError{
			Msg: fmt.Sprintf(
				"VLAN %d port %d did not read back as %s (got %s)",
				vlan, port, mode, got,
			),
			Before: portMode(before, port),
			After:  got,
		}
	}
	return nil
}

// SetPVID sets port's default/untagged VLAN (PVID) to vlan and verifies the
// change read back correctly. Ported from Python CliWriter.set_pvid
// (cli_write.py:388-412, dossier §4.5).
//
// guard(port, force) runs FIRST (disruptive, always honours protected
// ports -- unlike SetVLANMembership's "always guarded" too, this matches).
// Whether vlan must pre-exist is DELIBERATELY left to the switch itself (no
// library-side existence check, unlike SetVLANMembership) -- an unknown
// vlan simply comes back as a command rejection from `run` (dossier §4.5).
// Command sequence: `configure` -> `interface <iface>` -> [`switchport
// mode general` if applicable] -> `vlan pvid <vid>` -> `exit` `exit`.
// Verification re-reads the FULL pvid list and checks the exact (port,
// vlan) pair, mirroring Python's dict-based before/after comparison.
func (w *Writer) SetPVID(ctx context.Context, port, vlan int, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	before, err := w.reader.GetPVIDs(ctx)
	if err != nil {
		return err
	}
	body := append(w.generalMode(), w.spec.VlanPvid(vlan))
	if err := inMode(
		ctx, w.session,
		[]string{w.spec.ConfigureCmd, w.spec.Interface(port)},
		body,
		w.spec.ExitCmd,
	); err != nil {
		return err
	}
	after, err := w.reader.GetPVIDs(ctx)
	if err != nil {
		return err
	}
	afterVal := pvidFor(after, port)
	if afterVal == nil || *afterVal != vlan {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("PVID for port %d did not read back as %d (got %s)", port, vlan, formatIntPtr(afterVal)),
			Before: pvidFor(before, port),
			After:  afterVal,
		}
	}
	return nil
}

// formatIntPtr renders p as its decimal value, or "none" if p is nil --
// used only for SetPVID's verification-error message text.
func formatIntPtr(p *int) string {
	if p == nil {
		return "none"
	}
	return strconv.Itoa(*p)
}

// ---------------------------------------------------------------------
// PoE (dossier §4.6) -- the m4300-24x device-limit gate
// ---------------------------------------------------------------------

// requirePoE mirrors Python CliWriter._require_poe (dossier §4.6,
// cli_write.py:419-439): the write-side echo of GetPoE's read-side gate
// (reader.go's unsupportedReadOp, "PoE (model has no PSE ports)") -- the
// SAME underlying hardware fact. This is a REAL device limitation, not a
// missing op to build: the M4300-24X has zero PSE ports and its firmware
// therefore does not carry the `poe` command at ALL, live-probed 2026-07-30
// on 10.1.5.13 ("poe ?" in interface config mode answers "%% Unrecognized
// command", vs full help on the PoE-equipped M4300-16X). SetPoE/CyclePoE/
// ClearPoEFault all reach this before issuing a single command on a gated
// model -- SetPoE calls it FIRST (before its own guard); CyclePoE/
// ClearPoEFault call their shared guard FIRST and only reach this via
// poeReset second, exactly mirroring the pin's differing call order for
// the two shapes (cli_write.py:441-569).
func (w *Writer) requirePoE() error {
	if w.model.PoEPortCount == 0 {
		return fmt.Errorf(
			"model %q has no PSE ports, so its firmware has no 'poe' command (verified live: 'poe ?' -> '%% Unrecognized command'): %w",
			w.model.Key, model.ErrUnsupportedCapability,
		)
	}
	return nil
}

// poeStatus returns port's current PoE status via w's internal reader, or
// nil if the port is absent from the table, mirroring Python
// CliWriter._poe_status (cli_write.py:414-416).
func (w *Writer) poeStatus(ctx context.Context, port int) (*model.PoEStatus, error) {
	statuses, err := w.reader.GetPoE(ctx)
	if err != nil {
		return nil, err
	}
	for i := range statuses {
		if statuses[i].Port == port {
			return &statuses[i], nil
		}
	}
	return nil, nil
}

// portStatus returns port's current operational status via w's internal
// reader, or nil if the port is absent from the table, mirroring Python
// CliWriter._port_status (cli_write.py:596-597, used by SetPortEnabled
// below).
func (w *Writer) portStatus(ctx context.Context, port int) (*model.PortStatus, error) {
	statuses, err := w.reader.GetPorts(ctx)
	if err != nil {
		return nil, err
	}
	for i := range statuses {
		if statuses[i].Port == port {
			return &statuses[i], nil
		}
	}
	return nil, nil
}

// SetPoE sets port's PoE admin state to on and polls until it reads back
// correctly. Ported from Python CliWriter.set_poe (cli_write.py:441-487,
// dossier §4.6).
//
// requirePoE() runs FIRST, before guard -- a gated model (m4300-24x) never
// even reaches the protected-port check. guard(port, force) fires ONLY
// when turning PoE OFF (on == false); enabling PoE is never refused, even
// on a protected port. Command sequence: `configure` -> `interface
// <iface>` -> `poe` (on) or `no poe` (off) -> `exit` `exit`.
//
// Verification POLLS rather than reading once immediately: dossier §4.6
// documents a MEASURED hardware fact -- PoE detect state lags the admin
// write, so an immediate single read can report a WORKING write as a
// failure. Deadline = w.clock() + DefaultPoeCycleTimeouts().Off (turning
// off) or .On (turning on); the loop checks the predicate BEFORE ever
// sleeping.
func (w *Writer) SetPoE(ctx context.Context, port int, on bool, force bool) error {
	if err := w.requirePoE(); err != nil {
		return err
	}
	if !on {
		if err := w.guard(port, force); err != nil {
			return err
		}
	}
	before, err := w.poeStatus(ctx, port)
	if err != nil {
		return err
	}
	if err := inMode(
		ctx, w.session,
		[]string{w.spec.ConfigureCmd, w.spec.Interface(port)},
		[]string{w.spec.PoeAdmin(on)},
		w.spec.ExitCmd,
	); err != nil {
		return err
	}
	timeouts := DefaultPoeCycleTimeouts()
	limit := timeouts.On
	if !on {
		limit = timeouts.Off
	}
	deadline := w.clock().Add(limit)
	for {
		after, err := w.poeStatus(ctx, port)
		if err != nil {
			return err
		}
		if after != nil && after.AdminEnabled == on {
			return nil
		}
		if !w.clock().Before(deadline) {
			return &model.WriteVerificationError{
				Msg:    fmt.Sprintf("PoE admin for port %d did not read back as %v", port, on),
				Before: before,
				After:  after,
			}
		}
		if err := w.sleep(ctx, timeouts.Poll); err != nil {
			return err
		}
	}
}

// poeReset issues the device's own atomic `poe reset` re-arm command on
// port then polls until recovered is satisfied, mirroring Python
// CliWriter._poe_reset (cli_write.py:489-522) -- the shared PoE-recovery-
// polling primitive behind CyclePoE and ClearPoEFault below, parameterized
// by a recovery predicate and a timeout-message format function exactly as
// the pin's own `recovered`/`timeout_message` callback parameters are.
// requirePoE() runs FIRST, before any command -- but AFTER the caller's own
// guard (CyclePoE/ClearPoEFault call guard(port, force) before calling
// this), mirroring the pin's exact ordering. Always uses timeouts.On as
// the deadline, regardless of which caller invokes it (cli_write.py:522,
// "same PoE-recovery-polling helper").
func (w *Writer) poeReset(
	ctx context.Context, port int, timeouts PoeCycleTimeouts,
	recovered func(*model.PoEStatus) bool, timeoutMessage func(time.Duration) string,
) error {
	if err := w.requirePoE(); err != nil {
		return err
	}
	before, err := w.poeStatus(ctx, port)
	if err != nil {
		return err
	}
	if err := inMode(
		ctx, w.session,
		[]string{w.spec.ConfigureCmd, w.spec.Interface(port)},
		[]string{w.spec.PoeResetCmd},
		w.spec.ExitCmd,
	); err != nil {
		return err
	}
	deadline := w.clock().Add(timeouts.On)
	for {
		after, err := w.poeStatus(ctx, port)
		if err != nil {
			return err
		}
		if recovered(after) {
			return nil
		}
		if !w.clock().Before(deadline) {
			return &model.WriteVerificationError{
				Msg:    timeoutMessage(timeouts.On),
				Before: before,
				After:  after,
			}
		}
		if err := w.sleep(ctx, timeouts.Poll); err != nil {
			return err
		}
	}
}

// CyclePoE power-cycles port's PoE via the device's own `poe reset`
// command, polling until it returns to DELIVERING. Ported from Python
// CliWriter.cycle_poe (cli_write.py:524-544, dossier §4.6).
//
// guard(port, force) fires UNCONDITIONALLY and FIRST -- before requirePoE
// (poeReset checks that second) -- exactly mirroring the pin's call order:
// on m4300-24x, cycling a PROTECTED port without force returns
// ErrProtectedPort, not ErrUnsupportedCapability, because guard never gets
// a chance to pass through to the device-limit check. Recovery predicate:
// status present AND status.Delivering(). If no powered device is
// attached, this legitimately TIMES OUT and raises
// *model.WriteVerificationError -- "honestly failing" is the documented
// expected behavior in that case.
func (w *Writer) CyclePoE(ctx context.Context, port int, timeouts PoeCycleTimeouts, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	return w.poeReset(ctx, port, timeouts,
		func(status *model.PoEStatus) bool { return status != nil && status.Delivering() },
		func(timeout time.Duration) string {
			return fmt.Sprintf("PoE port %d did not return to delivering within %s", port, timeout)
		},
	)
}

// ClearPoEFault re-arms port's PoE the same way CyclePoE does, but with a
// looser recovery predicate: detect merely needs to have LEFT the fault
// state (delivering OR searching both count). Ported from Python
// CliWriter.clear_poe_fault (cli_write.py:546-569, dossier §4.6) -- "exactly
// the recovery predicate SnmpWriter.clear_poe_fault uses" (cross-backend
// parity note in the pin).
//
// guard(port, force) fires UNCONDITIONALLY and FIRST, exactly like
// CyclePoE's -- same m4300-24x protected-port-vs-device-limit ordering
// note applies.
func (w *Writer) ClearPoEFault(ctx context.Context, port int, timeouts PoeCycleTimeouts, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	return w.poeReset(ctx, port, timeouts,
		func(status *model.PoEStatus) bool {
			return status != nil && (status.Detect == model.PoEDetectDelivering || status.Detect == model.PoEDetectSearching)
		},
		func(timeout time.Duration) string {
			return fmt.Sprintf("PoE port %d still in FAULT after clear within %s", port, timeout)
		},
	)
}

// ---------------------------------------------------------------------
// SetPortEnabled (dossier §4.7)
// ---------------------------------------------------------------------

// SetPortEnabled sets port's admin state and verifies the change read back
// correctly with a SINGLE immediate read (no polling, unlike PoE). Ported
// from Python CliWriter.set_port_enabled (cli_write.py:573-597, dossier
// §4.7).
//
// guard(port, force) fires ONLY when DISABLING (enabled == false) --
// enabling a port is never refused, symmetric with SetPoE's direction-gated
// guard. Command sequence: `configure` -> `interface <iface>` -> `no
// shutdown` (enabled) or `shutdown` (disabled) -> `exit` `exit`.
func (w *Writer) SetPortEnabled(ctx context.Context, port int, enabled bool, force bool) error {
	if !enabled {
		if err := w.guard(port, force); err != nil {
			return err
		}
	}
	before, err := w.portStatus(ctx, port)
	if err != nil {
		return err
	}
	if err := inMode(
		ctx, w.session,
		[]string{w.spec.ConfigureCmd, w.spec.Interface(port)},
		[]string{w.spec.PortAdmin(enabled)},
		w.spec.ExitCmd,
	); err != nil {
		return err
	}
	after, err := w.portStatus(ctx, port)
	if err != nil {
		return err
	}
	if after == nil || after.AdminEnabled != enabled {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("admin state for port %d did not read back as %v", port, enabled),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// SetMgmtIP (dossier §4.8)
// ---------------------------------------------------------------------

// SetMgmtIP sets the switch's own management IP (address/netmask/gateway)
// and verifies all three fields read back correctly, raising on the FIRST
// divergent field found. Ported from Python CliWriter.set_mgmt_ip
// (cli_write.py:601-644, dossier §4.8).
//
// force=true IS UNCONDITIONALLY REQUIRED -- refused REGARDLESS of
// protectedPorts membership (this op ignores protectedPorts entirely and
// always demands force): "set_mgmt_ip can strand the switch (and drops the
// CLI session it is issued over); pass force=True to proceed" -- unlike the
// SNMP path's placeholder OIDs, these commands are the switch's real
// documented ones, but the op can still strand the switch issuing it, and
// is deliberately NOT live-tested for that reason.
//
// Command dispatch: EXACTLY ONE of execCmds/configCmds is non-empty per
// model (CliModelSpec.MgmtIP, spec.go) -- EXEC commands (if any) run via
// plain run (NOT wrapped in inMode, since they are privileged-EXEC, not
// config-mode); config commands (if any) run inside a `configure` block via
// inMode. Verification checks address/netmask/gateway in that order,
// stopping at the FIRST field that doesn't match -- not a combined
// multi-field report.
func (w *Writer) SetMgmtIP(ctx context.Context, address, netmask, gateway string, force bool) error {
	if !force {
		return fmt.Errorf("set_mgmt_ip can strand the switch (and drops the CLI session it is issued over); pass force=True to proceed: %w", model.ErrProtectedPort)
	}
	execCmds, configCmds := w.spec.MgmtIP(address, netmask, gateway)
	before, err := w.reader.GetMgmtIP(ctx)
	if err != nil {
		return err
	}
	for _, cmd := range execCmds {
		if err := run(ctx, w.session, cmd); err != nil {
			return err
		}
	}
	if len(configCmds) > 0 {
		if err := inMode(ctx, w.session, []string{w.spec.ConfigureCmd}, configCmds, w.spec.ExitCmd); err != nil {
			return err
		}
	}
	after, err := w.reader.GetMgmtIP(ctx)
	if err != nil {
		return err
	}
	fields := [3]struct {
		name string
		want string
		got  *string
	}{
		{"address", address, after.Address},
		{"netmask", netmask, after.Netmask},
		{"gateway", gateway, after.Gateway},
	}
	for _, f := range fields {
		if f.got == nil || *f.got != f.want {
			return &model.WriteVerificationError{
				Msg:    fmt.Sprintf("management %s did not read back as %q (got %s)", f.name, f.want, formatStrPtr(f.got)),
				Before: before,
				After:  after,
			}
		}
	}
	return nil
}

// formatStrPtr renders *p quoted, or "none" if p is nil -- used only for
// SetMgmtIP's verification-error message text, mirroring formatIntPtr's
// SetPVID sibling.
func formatStrPtr(p *string) string {
	if p == nil {
		return "none"
	}
	return strconv.Quote(*p)
}

// ---------------------------------------------------------------------
// Reboot (dossier §4.9)
// ---------------------------------------------------------------------

// Reboot reloads the switch. Ported from Python CliWriter.reboot
// (cli_write.py:646-666, dossier §4.9).
//
// force=true IS UNCONDITIONALLY REQUIRED (same pattern as SetMgmtIP):
// "reboot is disruptive; pass force=True". Command: ReloadCmd ("reload",
// privileged EXEC), issued via session.RunWriteMemory (reused because
// `reload` ALSO prompts a (y/n) confirm, the same interactive shape as
// `write memory`) with prestuff ALWAYS true, regardless of this model's own
// WritememStuff/ScpCertProfile flag (that flag is for the SCP cert
// deploy's `write memory`, cert_scp.go, not this).
//
// ErrCliTransport is EXPLICITLY CAUGHT AND SWALLOWED -- the ONE place in
// this package where a transport-layer error is treated as SUCCESS rather
// than propagated: "a dropped session IS the success signal" (the switch
// tore the session down while rebooting). No read-back verification is
// attempted at all -- impossible by definition, "the switch stops
// answering". Any OTHER error is propagated unchanged.
func (w *Writer) Reboot(ctx context.Context, force bool) error {
	if !force {
		return fmt.Errorf("reboot is disruptive; pass force=True: %w", model.ErrProtectedPort)
	}
	_, err := w.session.RunWriteMemory(ctx, w.spec.ReloadCmd, true)
	if err != nil && errors.Is(err, ErrCliTransport) {
		return nil
	}
	return err
}
