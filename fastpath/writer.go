// writer.go: CliWriter -- shared write-op helpers plus the VLAN lifecycle
// (CreateVLAN/DeleteVLAN/SetVLANMembership) and SetPVID, ported field-for-
// field from the pinned python-netgear-switch-library @
// 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362, src/netgear_switch/cli_write.py
// (666 lines), dossier §4.1-§4.5 (protocol dossier
// docs/superpowers/plans/2026-08-01-slice-07-dossier-cli-protocol.md). Any
// discrepancy between this file and the pin is a bug in this file, not a
// deliberate deviation, unless called out in a comment.
//
// PoE/port-admin/mgmt-IP/reboot (dossier §4.6-§4.9, cli_write.py's
// remaining CliWriter methods) are Task 10's job, added to this SAME Writer
// type in a sibling file -- the constructor, guard, generalMode prelude and
// the vlan()/portMode() before/after-snapshot helpers below are shared by
// both files since VLAN/PVID writes are the first to need them.
//
// The `run`/`inMode` config-mode accept/reject convention this file relies
// on is already ported in session.go (Task 5, mirroring Python
// CliWriter._run/_in_mode) -- see that file's doc comment for the
// counted-unwind hazard (protocol dossier risk #5) `inMode` guards against.
// This file does not duplicate that logic, only drives it.
package fastpath

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
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
