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
	"strconv"
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

// SetPortDescription sets port's ifAlias, the standard per-port description
// column, and verifies the change read back correctly. Ported from Python's
// SnmpWriter.set_port_description -- see D-WR §2.14.
//
// WRITABILITY MEASURED 2026-08-03 on a GS728TPP (10.2.5.10, firmware
// 6.0.1.30): a SET of ifAlias.17 was accepted and read straight back through
// GetPorts.
//
// Cosmetic (moves no traffic, cannot strand a switch): the guard fires
// UNCONDITIONALLY the way SetPVID's does -- not direction-gated like SetPoE/
// SetPortEnabled -- but only because a protected-port write is refused by
// convention, not because clearing a label is itself disruptive.
//
// One OctetString SET (type letter "s") at ifAlias.<port>. Unlike Python's
// net-snmp CLI transport, which needed a hex-string workaround to send an
// empty OCTET STRING (`snmpset ... s ""` is refused by the net-snmp CLI
// itself), this package's gosnmp-based WriteClient encodes an empty Go
// string as a genuine empty OctetString PDU directly -- see
// toOctetBytes/toSetPDU (gosnmp.go) -- so no such workaround is needed here.
// Verify: re-read via the internal reader's GetPorts; the reader maps an
// empty alias to nil, so compare on that footing (want is nil when
// description == "").
func (w *Writer) SetPortDescription(ctx context.Context, port int, description string, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	before, err := w.portStatus(ctx, port)
	if err != nil {
		return err
	}
	vb, err := NewSetVarbind(fmt.Sprintf("%s.%d", IfAlias, port), description, "s")
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
	var want *string
	if description != "" {
		want = &description
	}
	if after == nil || !strPtrEqual(after.Description, want) {
		var beforeDesc, afterDesc *string
		if before != nil {
			beforeDesc = before.Description
		}
		if after != nil {
			afterDesc = after.Description
		}
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("description for port %d did not read back as %s", port, quoteOrNone(want)),
			Before: beforeDesc,
			After:  afterDesc,
		}
	}
	return nil
}

// strPtrEqual reports whether a and b are both nil, or both non-nil with the
// same referenced value -- used by SetPortDescription's verify step to
// compare an optional description against the requested one on the same
// footing GetPorts reports it (an empty alias reads back as a nil
// Description, mirroring Python's `after.description != (description or
// None)`).
func strPtrEqual(a, b *string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

// quoteOrNone renders s quoted, or "None" if s is nil -- mirrors Python's
// `{want!r}` repr for an Optional[str] in SetPortDescription's verification
// message.
func quoteOrNone(s *string) string {
	if s == nil {
		return "None"
	}
	return strconv.Quote(*s)
}

// SetHostname sets the switch's host name via the standard MIB-II sysName,
// mirroring Python SnmpWriter.set_hostname (snmp_write.py:956-978).
//
// GROUNDED, unlike SetMgmtIP: sysName was confirmed writable on every SNMP
// model in this fleet on 2026-08-02, by SETting each switch the value it
// already held.
//
// Not force-gated: renaming a switch cannot strand it the way a mgmt-IP
// write can, and it is trivially reversible by writing the old name back.
// force is accepted-but-unused, purely so this method's signature matches
// every other writer.
func (w *Writer) SetHostname(ctx context.Context, name string, _ bool) error {
	before, err := w.reader.GetHostname(ctx)
	if err != nil {
		return err
	}
	vb, err := NewSetVarbind(SysName, name, "s")
	if err != nil {
		return err
	}
	if err := w.client.SetMany(ctx, []SetVarbind{vb}); err != nil {
		return err
	}
	after, err := w.reader.GetHostname(ctx)
	if err != nil {
		return err
	}
	if after != name {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("sysName is %q after writing %q", after, name),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// SetPortSpeed always returns an error wrapping
// model.ErrUnsupportedCapability: this backend cannot configure a port's
// speed. Mirrors Python's SnmpWriter.set_port_speed.
//
// Refused by name rather than approximated. What SNMP offers here is
// ifSpeed/ifHighSpeed, and those report the rate the link NEGOTIATED --
// writing one would be writing a counter, not a setting. The column that
// would genuinely serve this is MAU-MIB's ifMauDefaultType/
// ifMauAutoNegAdminStatus (mib-2.26); no switch here has been walked for it,
// so its presence is UNKNOWN rather than absent, and the 2026-08-03 OID
// sweep does not settle it (that sweep covered the 4526 VENDOR subtree
// only). Use a CLI backend, or establish the MAU subtree first. Every
// parameter is accepted-but-unused, purely so this method's signature
// matches the shared BackendWriter surface (see write_dispatch.go).
func (w *Writer) SetPortSpeed(_ context.Context, _ int, _ model.PortSpeed, _ bool) error {
	return fmt.Errorf(
		"model %q: SNMP exposes only the NEGOTIATED port rate (ifSpeed); no configured speed/duplex column has been located: %w",
		w.model.Key, model.ErrUnsupportedCapability,
	)
}

// SetFlowControl always returns an error wrapping
// model.ErrUnsupportedCapability: this backend cannot configure flow
// control. Mirrors Python's SnmpWriter.set_flow_control.
//
// Refused by name. EtherLike-MIB's dot3PauseAdminMode is the column that
// would serve this, and it is READ on the one model that publishes it (the
// GS728TPP) -- but no SET has ever been issued against it here, so whether
// the agent accepts one is unknown. This library does not offer a write it
// has never seen succeed. Every parameter is accepted-but-unused; see
// SetPortSpeed's doc comment.
func (w *Writer) SetFlowControl(_ context.Context, _ int, _ bool, _ bool) error {
	return fmt.Errorf(
		"model %q: no SNMP flow-control write has been established (dot3PauseAdminMode is read-only in this library): %w",
		w.model.Key, model.ErrUnsupportedCapability,
	)
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
