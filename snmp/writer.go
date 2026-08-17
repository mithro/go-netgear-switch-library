package snmp

// writer.go: model-driven Writer for the "simple set" write operations
// (PoE admin, port admin, PVID), ported field-for-field from
// src/netgear_switch/snmp_write.py's SnmpWriter (the normative source; that
// repo is read-only from here). Any discrepancy between this file and the
// Python source is a bug in this file.
//
// Every write here follows the same three-step shape: read "before" via the
// Writer's own internal Reader, issue the SET(s), read "after" via the same
// Reader, and compare -- a mismatch raises *model.WriteVerificationError
// carrying both observed states, never a silent failure. A transport error
// from either the SET or either read propagates unwrapped: only a
// successful round-trip that reads back wrong is a verification error.

import (
	"context"
	"fmt"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
)

// poeAdminOID returns the pethPsePortTable admin-status column instance OID
// for port, mirroring Python's _poe_admin_oid.
func poeAdminOID(port int) string {
	return fmt.Sprintf("%s.3.1.%d", PethPsePortTable, port)
}

// Writer is a model-driven SNMP write facade: every write issues the SET(s)
// then re-reads and verifies via its own internal Reader (never a raw
// client Get/Walk directly), exactly mirroring Python's SnmpWriter holding
// its own private SnmpReader. Ported from snmp_write.py -- see D-WR §2.
type Writer struct {
	client         WriteClient
	model          *model.SwitchModel
	protectedPorts map[int]bool
	reader         *Reader

	// clock/sleep are the injectable time seam CyclePoE/ClearPoEFault's
	// poll loops use (see writer_cycle.go's WithClock); they default to
	// time.Now/defaultSleep and are otherwise unused by every other
	// Writer method.
	clock func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// WriterOption configures optional Writer construction parameters (only
// protected-ports today) via the functional-options pattern already used by
// this codebase's Switch/SwitchOption (see switch.go).
type WriterOption func(*Writer)

// WithProtectedPorts marks ports as protected: every disruptive write to a
// protected port is refused unless force is passed as true, mirroring
// Python's SnmpWriter(..., protected_ports=frozenset({...})).
func WithProtectedPorts(ports ...int) WriterOption {
	return func(w *Writer) {
		for _, p := range ports {
			w.protectedPorts[p] = true
		}
	}
}

// NewWriter constructs a Writer bound to client and m.
//
// m must have an SNMP backend (model.BackendSNMP in m.Backends); a model
// without one returns an error wrapping model.ErrUnsupportedCapability
// BEFORE any I/O -- this is the single capability gate for the whole
// writer (delegated to NewReader, which performs the identical check with
// the identical message), matching Python's _require_snmp being called
// once, in the constructor, before anything else. No method below
// re-checks it.
func NewWriter(c WriteClient, m *model.SwitchModel, opts ...WriterOption) (*Writer, error) {
	reader, err := NewReader(c, m)
	if err != nil {
		return nil, err
	}
	w := &Writer{
		client:         c,
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

// guard is the single protected-port gate every disruptive op calls: it
// refuses port when port is protected and force is false, mirroring
// Python's SnmpWriter._guard. The message text ("force=True") is preserved
// verbatim from the Python source even though Go's parameter is a plain
// bool, not a keyword argument -- see D-WR §2.4's pinned exact strings.
func (w *Writer) guard(port int, force bool) error {
	if w.protectedPorts[port] && !force {
		return fmt.Errorf("port %d is protected; pass force=True to override: %w", port, model.ErrProtectedPort)
	}
	return nil
}

// poeStatus returns port's current PoE status via the internal reader, or
// nil if the port is absent from the walk. Mirrors Python's
// SnmpWriter._poe_status.
func (w *Writer) poeStatus(ctx context.Context, port int) (*model.PoEStatus, error) {
	statuses, err := w.reader.GetPoE(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range statuses {
		if s.Port == port {
			return &s, nil
		}
	}
	return nil, nil
}

// portStatus returns port's current operational status via the internal
// reader, or nil if the port is absent from the walk. Mirrors Python's
// SnmpWriter._port_status.
func (w *Writer) portStatus(ctx context.Context, port int) (*model.PortStatus, error) {
	statuses, err := w.reader.GetPorts(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range statuses {
		if s.Port == port {
			return &s, nil
		}
	}
	return nil, nil
}

// SetPoE sets port's PoE admin state to on and verifies the change read
// back correctly. Ported from Python's SnmpWriter.set_poe -- see D-WR §2.5.
//
// The guard fires ONLY when turning PoE off (turning it on is never
// refused, even on a protected port -- enabling power is not disruptive by
// this library's model). One INTEGER SET (type letter "i": 1=on, 2=off) at
// the pethPsePortTable admin column. Verify: re-read via the internal
// reader's GetPoE; fail if the port vanished from the walk OR its
// AdminEnabled doesn't match the requested on.
func (w *Writer) SetPoE(ctx context.Context, port int, on bool, force bool) error {
	if !on {
		if err := w.guard(port, force); err != nil {
			return err
		}
	}
	before, err := w.poeStatus(ctx, port)
	if err != nil {
		return err
	}
	value := 2
	if on {
		value = 1
	}
	vb, err := NewSetVarbind(poeAdminOID(port), value, "i")
	if err != nil {
		return err
	}
	if err := w.client.Set(ctx, vb); err != nil {
		return err
	}
	after, err := w.poeStatus(ctx, port)
	if err != nil {
		return err
	}
	if after == nil || after.AdminEnabled != on {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("PoE admin for port %d did not read back as %v", port, on),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// SetPortEnabled sets port's ifAdminStatus and verifies the change read
// back correctly. Ported from Python's SnmpWriter.set_port_enabled -- see
// D-WR §2.8.
//
// Structurally identical to SetPoE: the guard fires ONLY when disabling the
// port (enabling is never refused). One INTEGER SET (type letter "i":
// 1=up, 2=down) at ifAdminStatus.<port>. Verify: re-read via the internal
// reader's GetPorts; fail if the port vanished from the walk OR its
// AdminEnabled doesn't match the requested enabled.
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
	value := 2
	if enabled {
		value = 1
	}
	vb, err := NewSetVarbind(fmt.Sprintf("%s.%d", IfAdminStatus, port), value, "i")
	if err != nil {
		return err
	}
	if err := w.client.Set(ctx, vb); err != nil {
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

// SetPVID sets port's default/untagged VLAN (PVID) to vlan and verifies the
// change read back correctly. Ported from Python's SnmpWriter.set_pvid --
// see D-WR §2.9.
//
// The guard is UNCONDITIONAL (any PVID change is disruptive, unlike SetPoE/
// SetPortEnabled's direction-gated guard), and runs BEFORE the VLAN-
// existence precondition below. A missing target VLAN is itself a
// PRECONDITION failure -- an error wrapping model.ErrSNMP (via errSNMP),
// NOT a *model.WriteVerificationError -- and issues ZERO SETs, mirroring
// SetVlanMembership's own existence check (writer_vlan.go) and Python's
// SnmpWriter.set_pvid (snmp_write.py, commit 98fb935). The device will NOT
// catch this itself: MEASURED on a GS728TPP (10.2.5.10, firmware 6.0.1.30,
// 2026-08-03), `dot1qPvid.17 := 4002` for a VLAN that does not exist is
// ACCEPTED, reads back as 4002, and creates no VLAN -- so verify-after-
// write would pass while the port is left pointing at nothing. Only a
// precondition check can catch that.
//
// One Gauge32 SET (type letter "u", NOT "i") at dot1qPvid.<port>. Verify:
// re-read the FULL pvid list via the internal reader's GetPVIDs and check
// the exact (port, vlan) pair is a member -- not just that port's own row
// changed.
func (w *Writer) SetPVID(ctx context.Context, port, vlan int, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	targetVlan, err := w.vlan(ctx, vlan)
	if err != nil {
		return err
	}
	if targetVlan == nil {
		return errSNMP("VLAN %d does not exist", vlan)
	}
	before, err := w.reader.GetPVIDs(ctx)
	if err != nil {
		return err
	}
	vb, err := NewSetVarbind(fmt.Sprintf("%s.%d", Dot1qPvid, port), vlan, "u")
	if err != nil {
		return err
	}
	if err := w.client.Set(ctx, vb); err != nil {
		return err
	}
	after, err := w.reader.GetPVIDs(ctx)
	if err != nil {
		return err
	}
	found := false
	for _, p := range after {
		if p.Port == port && p.Vlan == vlan {
			found = true
			break
		}
	}
	if !found {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("PVID for port %d did not read back as %d", port, vlan),
			Before: before,
			After:  after,
		}
	}
	return nil
}
