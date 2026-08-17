package snmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// fakeWriteClient serves canned Rows by exact walked/get-requested base OID
// (a missing key answers an empty walk/get, mirroring a real agent's
// noSuchObject/empty-subtree response) and records every SET it receives,
// both flattened (sets) and per-PDU (calls, so a test can distinguish N
// separate single-varbind SET calls from one set_many call carrying
// multiple varbinds). When apply is true, SetMany also does a "crude
// apply": it overwrites the exact leaf row so a subsequent Walk/Get sees
// the new value -- mirroring test_snmp_write.py's FakeWriteClient.
type fakeWriteClient struct {
	tables map[string][]Row
	sets   []SetVarbind
	calls  [][]SetVarbind
	apply  bool
}

func newFakeWriteClient(tables map[string][]Row, apply bool) *fakeWriteClient {
	if tables == nil {
		tables = map[string][]Row{}
	}
	return &fakeWriteClient{tables: tables, apply: apply}
}

func (f *fakeWriteClient) Get(_ context.Context, oids []string) ([]Row, error) {
	var rows []Row
	for _, oid := range oids {
		rows = append(rows, f.tables[oid]...)
	}
	return rows, nil
}

func (f *fakeWriteClient) Walk(_ context.Context, base string) ([]Row, error) {
	return append([]Row(nil), f.tables[base]...), nil
}

func (f *fakeWriteClient) Set(ctx context.Context, vb SetVarbind) error {
	return f.SetMany(ctx, []SetVarbind{vb})
}

func (f *fakeWriteClient) SetMany(_ context.Context, vbs []SetVarbind) error {
	f.sets = append(f.sets, vbs...)
	f.calls = append(f.calls, append([]SetVarbind(nil), vbs...))
	if !f.apply {
		return nil
	}
	for _, vb := range vbs {
		base := ""
		for k := range f.tables {
			if strings.HasPrefix(vb.OID, k+".") {
				base = k
				break
			}
		}
		if base == "" {
			if idx := strings.LastIndex(vb.OID, "."); idx >= 0 {
				base = vb.OID[:idx]
			}
		}
		rows := f.tables[base]
		next := make([]Row, 0, len(rows)+1)
		for _, r := range rows {
			if r.OID != vb.OID {
				next = append(next, r)
			}
		}
		var iv int64
		switch v := vb.Value.(type) {
		case int:
			iv = int64(v)
		case int64:
			iv = v
		}
		next = append(next, NewIntRow(vb.OID, iv))
		f.tables[base] = next
	}
	return nil
}

// failAfterSetWriteClient wraps fakeWriteClient so every Walk AFTER the
// first SET has been issued fails with failErr -- used to prove a re-read
// transport error propagates unwrapped, not as a *model.WriteVerificationError.
type failAfterSetWriteClient struct {
	*fakeWriteClient
	failErr error
}

func (f *failAfterSetWriteClient) Walk(ctx context.Context, base string) ([]Row, error) {
	if len(f.calls) > 0 {
		return nil, f.failErr
	}
	return f.fakeWriteClient.Walk(ctx, base)
}

func poeTables(admin, detect int64) map[string][]Row {
	return map[string][]Row{
		PethPsePortTable: {
			NewIntRow(fmt.Sprintf("%s.3.1.5", PethPsePortTable), admin),
			NewIntRow(fmt.Sprintf("%s.6.1.5", PethPsePortTable), detect),
		},
	}
}

func portTables(admin, oper int64) map[string][]Row {
	return map[string][]Row{
		IfAdminStatus: {NewIntRow(fmt.Sprintf("%s.5", IfAdminStatus), admin)},
		IfOperStatus:  {NewIntRow(fmt.Sprintf("%s.5", IfOperStatus), oper)},
		IfHighSpeed:   {NewIntRow(fmt.Sprintf("%s.5", IfHighSpeed), 1000)},
		IfName:        {NewStrRow(fmt.Sprintf("%s.5", IfName), "1/0/5")},
	}
}

func pvidTables(port int, vlan int64) map[string][]Row {
	return map[string][]Row{
		Dot1qPvid: {NewIntRow(fmt.Sprintf("%s.%d", Dot1qPvid, port), vlan)},
	}
}

// mergeTables combines any number of OID->rows table maps into one, for
// tests that need both a PVID column (pvidTables) and a VLAN's static rows
// (vlanTables) present on the same fake client -- e.g. SetPVID's
// VLAN-existence precondition (writer.go) needs the target VLAN to be a
// real row, distinct from pvidTables' unrelated "current PVID" value.
// Later maps win on a key collision (none expected among these fixtures).
func mergeTables(maps ...map[string][]Row) map[string][]Row {
	out := map[string][]Row{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// --- NewWriter: the single capability gate ---------------------------------

func TestNewWriterRejectsNonSNMPModel(t *testing.T) {
	_, err := NewWriter(newFakeWriteClient(nil, true), mustModel(t, "gs305ep"))
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("NewWriter error = %v, want ErrUnsupportedCapability", err)
	}
}

func TestNewWriterConstructsForManagedModel(t *testing.T) {
	w, err := NewWriter(newFakeWriteClient(nil, true), mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if w.model.Key != "gsm7252ps" {
		t.Errorf("w.model.Key = %q, want gsm7252ps", w.model.Key)
	}
}

// --- SetPoE -----------------------------------------------------------------

func TestSetPoEOffIssuesCorrectSetAndVerifies(t *testing.T) {
	client := newFakeWriteClient(poeTables(1, 3), true)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetPoE(context.Background(), 5, false, false); err != nil {
		t.Fatalf("SetPoE: %v", err)
	}
	want := []SetVarbind{{OID: fmt.Sprintf("%s.3.1.5", PethPsePortTable), Value: 2, TypeLetter: "i"}}
	if !setVarbindsEqual(client.sets, want) {
		t.Errorf("sets = %+v, want %+v", client.sets, want)
	}
}

func TestSetPoEOnIssuesCorrectSetAndVerifies(t *testing.T) {
	client := newFakeWriteClient(poeTables(2, 1), true)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetPoE(context.Background(), 5, true, false); err != nil {
		t.Fatalf("SetPoE: %v", err)
	}
	want := []SetVarbind{{OID: fmt.Sprintf("%s.3.1.5", PethPsePortTable), Value: 1, TypeLetter: "i"}}
	if !setVarbindsEqual(client.sets, want) {
		t.Errorf("sets = %+v, want %+v", client.sets, want)
	}
}

func TestSetPoEVerificationFailureRaises(t *testing.T) {
	client := newFakeWriteClient(poeTables(1, 3), false) // device ignores the write
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPoE(context.Background(), 5, false, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPoE error = %v, want *model.WriteVerificationError", err)
	}
	if verr.After == nil {
		t.Errorf("verr.After = nil, want a PoEStatus (port still reads admin=on)")
	}
	if verr.Before == nil {
		t.Errorf("verr.Before = nil, want the pre-write PoEStatus")
	}
}

func TestSetPoEProtectedPortBlocksOffWithoutForce(t *testing.T) {
	client := newFakeWriteClient(poeTables(1, 3), true)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPoE(context.Background(), 5, false, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetPoE error = %v, want ErrProtectedPort", err)
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (blocked before any SET)", client.sets)
	}
	if err := w.SetPoE(context.Background(), 5, false, true); err != nil {
		t.Fatalf("SetPoE with force=true: %v", err)
	}
	if len(client.sets) == 0 {
		t.Errorf("sets is empty, want the forced SET to have gone through")
	}
}

func TestSetPoETurningOnNeverGuardedOnProtectedPort(t *testing.T) {
	// Turning PoE ON is never disruptive by this library's model: the guard
	// must NOT fire even on a protected port and even without force.
	client := newFakeWriteClient(poeTables(2, 1), true)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetPoE(context.Background(), 5, true, false); err != nil {
		t.Fatalf("SetPoE(on=true) on protected port without force: %v", err)
	}
}

func TestSetPoEReReadTransportErrorPropagatesUnwrapped(t *testing.T) {
	boom := errors.New("boom: transport down")
	client := &failAfterSetWriteClient{fakeWriteClient: newFakeWriteClient(poeTables(1, 3), true), failErr: boom}
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPoE(context.Background(), 5, false, false)
	if !errors.Is(err, boom) {
		t.Fatalf("SetPoE error = %v, want it to wrap/equal the raw transport error", err)
	}
	var verr *model.WriteVerificationError
	if errors.As(err, &verr) {
		t.Errorf("SetPoE error is a *model.WriteVerificationError, want the raw transport error to propagate as-is")
	}
}

// --- SetPortEnabled ----------------------------------------------------------

func TestSetPortEnabledDisableSetsIfAdmin2(t *testing.T) {
	client := newFakeWriteClient(portTables(1, 1), true)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetPortEnabled(context.Background(), 5, false, true); err != nil {
		t.Fatalf("SetPortEnabled: %v", err)
	}
	want := []SetVarbind{{OID: fmt.Sprintf("%s.5", IfAdminStatus), Value: 2, TypeLetter: "i"}}
	if !setVarbindsEqual(client.sets, want) {
		t.Errorf("sets = %+v, want %+v", client.sets, want)
	}
}

func TestSetPortEnabledEnableSetsIfAdmin1(t *testing.T) {
	client := newFakeWriteClient(portTables(2, 2), true)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetPortEnabled(context.Background(), 5, true, false); err != nil {
		t.Fatalf("SetPortEnabled: %v", err)
	}
	want := []SetVarbind{{OID: fmt.Sprintf("%s.5", IfAdminStatus), Value: 1, TypeLetter: "i"}}
	if !setVarbindsEqual(client.sets, want) {
		t.Errorf("sets = %+v, want %+v", client.sets, want)
	}
}

func TestSetPortEnabledVerificationFailureRaises(t *testing.T) {
	client := newFakeWriteClient(portTables(1, 1), false) // device ignores the write
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPortEnabled(context.Background(), 5, false, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPortEnabled error = %v, want *model.WriteVerificationError", err)
	}
	if verr.Before == nil || verr.After == nil {
		t.Errorf("verr.Before/After = %v/%v, want both populated (port still present, just unchanged)", verr.Before, verr.After)
	}
}

func TestSetPortEnabledProtectedPortBlocksDisableWithoutForce(t *testing.T) {
	client := newFakeWriteClient(portTables(1, 1), true)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPortEnabled(context.Background(), 5, false, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetPortEnabled error = %v, want ErrProtectedPort", err)
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (blocked before any SET)", client.sets)
	}
}

// --- SetPVID -----------------------------------------------------------------

func TestSetPVIDSetsGauge32AndVerifies(t *testing.T) {
	client := newFakeWriteClient(mergeTables(pvidTables(10, 1), vlanTables(90, nil, nil)), true)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetPVID(context.Background(), 10, 90, false); err != nil {
		t.Fatalf("SetPVID: %v", err)
	}
	want := []SetVarbind{{OID: fmt.Sprintf("%s.10", Dot1qPvid), Value: 90, TypeLetter: "u"}}
	if !setVarbindsEqual(client.sets, want) {
		t.Errorf("sets = %+v, want %+v", client.sets, want)
	}
}

func TestSetPVIDVerificationFailureRaises(t *testing.T) {
	client := newFakeWriteClient(mergeTables(pvidTables(10, 1), vlanTables(90, nil, nil)), false) // device ignores the write
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPVID(context.Background(), 10, 90, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPVID error = %v, want *model.WriteVerificationError", err)
	}
	if verr.Before == nil {
		t.Errorf("verr.Before = nil, want the pre-write pvid list")
	}
	if verr.After == nil {
		t.Errorf("verr.After = nil, want the post-write pvid list")
	}
}

func TestSetPVIDGuardIsUnconditional(t *testing.T) {
	// Unlike SetPoE/SetPortEnabled, SetPVID's guard is NOT direction-gated:
	// any PVID change is disruptive, so it always fires on a protected port.
	client := newFakeWriteClient(mergeTables(pvidTables(10, 1), vlanTables(90, nil, nil)), true)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithProtectedPorts(10))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPVID(context.Background(), 10, 90, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetPVID error = %v, want ErrProtectedPort", err)
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (blocked before any SET)", client.sets)
	}
	if err := w.SetPVID(context.Background(), 10, 90, true); err != nil {
		t.Fatalf("SetPVID with force=true: %v", err)
	}
}

// TestSetPVIDMissingVlanIsPreconditionNotVerifyError pins the GAP-1 fix
// (parity with Python commit 98fb935): a PVID pointing at a VLAN the
// switch does not have must be refused BEFORE any SET is attempted, as a
// precondition failure (errSNMP-wrapped model.ErrSNMP), never a
// *model.WriteVerificationError. The device itself will NOT catch this --
// MEASURED on a GS728TPP (10.2.5.10, firmware 6.0.1.30): the equivalent
// raw SET is ACCEPTED and reads back, creating no VLAN -- so only this
// precondition prevents a port being left pointing at nothing. Mirrors
// TestSetVlanMembershipMissingVlanIsPreconditionNotVerifyError exactly.
func TestSetPVIDMissingVlanIsPreconditionNotVerifyError(t *testing.T) {
	client := newFakeWriteClient(pvidTables(10, 1), true) // no VLAN 90 registered
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPVID(context.Background(), 10, 90, true)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("SetPVID error = %v, want wrap of model.ErrSNMP", err)
	}
	var verr *model.WriteVerificationError
	if errors.As(err, &verr) {
		t.Errorf("SetPVID error is a *model.WriteVerificationError, want a precondition ErrSNMP instead")
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (precondition failed before any SET)", client.sets)
	}
}

func TestSetPVIDReReadTransportErrorPropagatesUnwrapped(t *testing.T) {
	boom := errors.New("boom: transport down")
	client := &failAfterSetWriteClient{fakeWriteClient: newFakeWriteClient(mergeTables(pvidTables(10, 1), vlanTables(90, nil, nil)), true), failErr: boom}
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPVID(context.Background(), 10, 90, false)
	if !errors.Is(err, boom) {
		t.Fatalf("SetPVID error = %v, want it to equal/wrap the raw transport error", err)
	}
	var verr *model.WriteVerificationError
	if errors.As(err, &verr) {
		t.Errorf("SetPVID error is a *model.WriteVerificationError, want the raw transport error to propagate as-is")
	}
}

// --- SetPortDescription ------------------------------------------------

// applyIfAlias applies an ifAlias SET into the IfAlias table, mirroring a
// real agent: a non-empty value replaces the row, an empty value OMITS it
// (both mean "no description" to ParsePortStatus -- see its own doc
// comment -- so either representation is a faithful fake).
func applyIfAlias(tables map[string][]Row, vbs []SetVarbind) {
	rows := tables[IfAlias]
	for _, vb := range vbs {
		if !strings.HasPrefix(vb.OID, IfAlias+".") {
			continue
		}
		rows = filterOutSuffix(rows, strings.TrimPrefix(vb.OID, IfAlias))
		if text := toStrValue(vb.Value); text != "" {
			rows = append(rows, NewStrRow(vb.OID, text))
		}
	}
	tables[IfAlias] = rows
}

func TestSetPortDescriptionSetsIfAliasAndVerifies(t *testing.T) {
	client := newScriptedWriteClient(portTables(1, 1), applyIfAlias)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetPortDescription(context.Background(), 5, "uplink", false); err != nil {
		t.Fatalf("SetPortDescription: %v", err)
	}
	want := []SetVarbind{{OID: fmt.Sprintf("%s.5", IfAlias), Value: "uplink", TypeLetter: "s"}}
	if !setVarbindsEqual(client.sets, want) {
		t.Errorf("sets = %+v, want %+v", client.sets, want)
	}
}

func TestSetPortDescriptionClearingSendsEmptyString(t *testing.T) {
	tables := mergeTables(portTables(1, 1), map[string][]Row{
		IfAlias: {NewStrRow(fmt.Sprintf("%s.5", IfAlias), "old-label")},
	})
	client := newScriptedWriteClient(tables, applyIfAlias)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetPortDescription(context.Background(), 5, "", false); err != nil {
		t.Fatalf("SetPortDescription(\"\"): %v", err)
	}
	want := []SetVarbind{{OID: fmt.Sprintf("%s.5", IfAlias), Value: "", TypeLetter: "s"}}
	if !setVarbindsEqual(client.sets, want) {
		t.Errorf("sets = %+v, want %+v", client.sets, want)
	}
}

func TestSetPortDescriptionVerificationFailureRaises(t *testing.T) {
	client := newScriptedWriteClient(portTables(1, 1), nil) // device ignores the write
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPortDescription(context.Background(), 5, "uplink", false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPortDescription error = %v, want *model.WriteVerificationError", err)
	}
}

// TestSetPortDescriptionClearingVerificationFailureRaises exercises the
// quoteOrNone "None" branch: the target description ("") is nil-repr'd in
// the mismatch message when the device silently ignores a clear.
func TestSetPortDescriptionClearingVerificationFailureRaises(t *testing.T) {
	tables := mergeTables(portTables(1, 1), map[string][]Row{
		IfAlias: {NewStrRow(fmt.Sprintf("%s.5", IfAlias), "stuck-label")},
	})
	client := newScriptedWriteClient(tables, nil) // device ignores the write
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPortDescription(context.Background(), 5, "", false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPortDescription(\"\") error = %v, want *model.WriteVerificationError", err)
	}
	if !strings.Contains(err.Error(), "None") {
		t.Errorf("SetPortDescription(\"\") error = %q, want it to mention None (the target was clearing the label)", err.Error())
	}
}

func TestSetPortDescriptionProtectedPortBlocksWithoutForce(t *testing.T) {
	client := newScriptedWriteClient(portTables(1, 1), applyIfAlias)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPortDescription(context.Background(), 5, "uplink", false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetPortDescription error = %v, want ErrProtectedPort", err)
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (blocked before any SET)", client.sets)
	}
	if err := w.SetPortDescription(context.Background(), 5, "uplink", true); err != nil {
		t.Fatalf("SetPortDescription with force=true: %v", err)
	}
}

// --- SetPortSpeed / SetFlowControl: always refused ----------------------

func TestSetPortSpeedAlwaysRefusesByName(t *testing.T) {
	client := newScriptedWriteClient(nil, nil)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetPortSpeed(context.Background(), 5, model.AutoPortSpeed(), false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("SetPortSpeed error = %v, want ErrUnsupportedCapability", err)
	}
	if !strings.Contains(err.Error(), "NEGOTIATED port rate") {
		t.Errorf("SetPortSpeed error = %q, want it to explain the negotiated-vs-configured distinction", err.Error())
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none: SetPortSpeed must never issue a SET", client.sets)
	}
}

func TestSetFlowControlAlwaysRefusesByName(t *testing.T) {
	client := newScriptedWriteClient(nil, nil)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetFlowControl(context.Background(), 5, true, false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("SetFlowControl error = %v, want ErrUnsupportedCapability", err)
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none: SetFlowControl must never issue a SET", client.sets)
	}
}

// setVarbindsEqual compares two []SetVarbind slices for exact equality
// (OID, Value, TypeLetter).
func setVarbindsEqual(a, b []SetVarbind) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
