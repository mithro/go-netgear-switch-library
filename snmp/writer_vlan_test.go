package snmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// --- scriptedWriteClient: a fakeWriteClient variant whose SET-apply logic
// is injected per test, mirroring test_snmp_write.py's per-scenario
// FakeWriteClient subclasses (ApplyingVlanClient, EgressOnlyVlanClient,
// VlanDisappearsClient, ApplyingRowStatusClient, _MgmtApply). A plain
// struct-embedding override of fakeWriteClient's SetMany would NOT work
// here: fakeWriteClient.Set calls its OWN SetMany via a non-virtual Go
// method call, so an embedding override would never fire for a
// single-varbind Set (as DeleteVlan issues) -- only for direct SetMany
// calls. Injecting the apply function into one concrete type sidesteps
// that gotcha entirely. ------------------------------------------------

type scriptedApplyFunc func(tables map[string][]Row, vbs []SetVarbind)

type scriptedWriteClient struct {
	tables map[string][]Row
	sets   []SetVarbind
	calls  [][]SetVarbind
	apply  scriptedApplyFunc
}

func newScriptedWriteClient(tables map[string][]Row, apply scriptedApplyFunc) *scriptedWriteClient {
	if tables == nil {
		tables = map[string][]Row{}
	}
	return &scriptedWriteClient{tables: tables, apply: apply}
}

func (c *scriptedWriteClient) Get(_ context.Context, oids []string) ([]Row, error) {
	var rows []Row
	for _, oid := range oids {
		rows = append(rows, c.tables[oid]...)
	}
	return rows, nil
}

func (c *scriptedWriteClient) Walk(_ context.Context, base string) ([]Row, error) {
	return append([]Row(nil), c.tables[base]...), nil
}

func (c *scriptedWriteClient) Set(ctx context.Context, vb SetVarbind) error {
	return c.SetMany(ctx, []SetVarbind{vb})
}

func (c *scriptedWriteClient) SetMany(_ context.Context, vbs []SetVarbind) error {
	c.sets = append(c.sets, vbs...)
	c.calls = append(c.calls, append([]SetVarbind(nil), vbs...))
	if c.apply != nil {
		c.apply(c.tables, vbs)
	}
	return nil
}

// --- fixture builders --------------------------------------------------

// vlanTables builds a name+egress+untagged table set for one VLAN, with the
// device's egress/untagged octets at the default 8-byte width, mirroring
// test_snmp_write.py's _vlan_tables().
func vlanTables(vid int, member, untagged []int) map[string][]Row {
	return vlanTablesWidth(vid, member, untagged, 8)
}

// vlanTablesWidth is vlanTables with an explicit device bitmap width, for
// tests pinning RMW width preservation (D-REC Topic B) against a real
// measured device width like the GSM7252PS's 79 bytes -- far wider than
// this table's 52-port model formula width of 8.
func vlanTablesWidth(vid int, member, untagged []int, widthBytes int) map[string][]Row {
	return map[string][]Row{
		Dot1qVlanStaticName: {
			NewStrRow(fmt.Sprintf("%s.%d", Dot1qVlanStaticName, vid), "iot"),
		},
		Dot1qVlanStaticEgress: {
			NewBytesRow(fmt.Sprintf("%s.%d", Dot1qVlanStaticEgress, vid), EncodePortBitmap(member, widthBytes)),
		},
		Dot1qVlanStaticUntagged: {
			NewBytesRow(fmt.Sprintf("%s.%d", Dot1qVlanStaticUntagged, vid), EncodePortBitmap(untagged, widthBytes)),
		},
	}
}

// mgmtIPTables builds the standard-MIB rows GetMgmtIP needs, mirroring
// test_snmp_write.py's _mgmt_tables().
func mgmtIPTables(addr, mask, gw string) map[string][]Row {
	return map[string][]Row{
		IPAdEntAddr:    {NewStrRow(IPAdEntAddr+"."+addr, addr)},
		IPAdEntNetmask: {NewStrRow(IPAdEntNetmask+"."+addr, mask)},
		IPRouteDest:    {NewStrRow(IPRouteDest+".0.0.0.0", "0.0.0.0")},
		IPRouteNextHop: {NewStrRow(IPRouteNextHop+".0.0.0.0", gw)},
	}
}

// --- apply functions -----------------------------------------------------

// applyVlanBitmaps applies BOTH the egress and untagged bitmap SETs into
// the read tables, mirroring ApplyingVlanClient.
func applyVlanBitmaps(tables map[string][]Row, vbs []SetVarbind) {
	for _, vb := range vbs {
		switch {
		case strings.HasPrefix(vb.OID, Dot1qVlanStaticEgress+"."):
			tables[Dot1qVlanStaticEgress] = []Row{NewBytesRow(vb.OID, vb.Value.([]byte))}
		case strings.HasPrefix(vb.OID, Dot1qVlanStaticUntagged+"."):
			tables[Dot1qVlanStaticUntagged] = []Row{NewBytesRow(vb.OID, vb.Value.([]byte))}
		}
	}
}

// applyEgressOnly applies the egress SET but silently drops the untagged
// one, mirroring EgressOnlyVlanClient (a buggy device).
func applyEgressOnly(tables map[string][]Row, vbs []SetVarbind) {
	for _, vb := range vbs {
		if strings.HasPrefix(vb.OID, Dot1qVlanStaticEgress+".") {
			tables[Dot1qVlanStaticEgress] = []Row{NewBytesRow(vb.OID, vb.Value.([]byte))}
		}
	}
}

// applyVlanVanishes applies the SET (recorded by the caller) but then wipes
// every VLAN column, simulating the VLAN being concurrently deleted
// mid-write, mirroring VlanDisappearsClient.
func applyVlanVanishes(tables map[string][]Row, _ []SetVarbind) {
	tables[Dot1qVlanStaticName] = nil
	tables[Dot1qVlanStaticEgress] = nil
	tables[Dot1qVlanStaticUntagged] = nil
}

// filterOutSuffix returns rows without any whose OID ends in suffix.
func filterOutSuffix(rows []Row, suffix string) []Row {
	kept := make([]Row, 0, len(rows))
	for _, r := range rows {
		if !strings.HasSuffix(r.OID, suffix) {
			kept = append(kept, r)
		}
	}
	return kept
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	default:
		return 0
	}
}

func toStrValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

// applyRowStatusAndName applies RowStatus createAndGo/destroy plus a Name
// SET into the name table, mirroring _apply_row_status_and_name.
func applyRowStatusAndName(tables map[string][]Row, vbs []SetVarbind) {
	names := tables[Dot1qVlanStaticName]
	for _, vb := range vbs {
		switch {
		case strings.HasPrefix(vb.OID, Dot1qVlanStaticRowStatus+"."):
			vid := strings.TrimPrefix(vb.OID, Dot1qVlanStaticRowStatus+".")
			switch toInt64(vb.Value) {
			case RowStatusDestroy:
				names = filterOutSuffix(names, "."+vid)
			case RowStatusCreateAndGo:
				names = append(names, NewStrRow(fmt.Sprintf("%s.%s", Dot1qVlanStaticName, vid), ""))
			}
		case strings.HasPrefix(vb.OID, Dot1qVlanStaticName+"."):
			vid := strings.TrimPrefix(vb.OID, Dot1qVlanStaticName+".")
			names = filterOutSuffix(names, "."+vid)
			names = append(names, NewStrRow(vb.OID, toStrValue(vb.Value)))
		}
	}
	tables[Dot1qVlanStaticName] = names
}

// newMgmtApply returns an apply func that applies all three mgmt-IP write
// OIDs into the read projection, optionally skipping one field (skip) to
// simulate a device that silently drops that write, mirroring _MgmtApply.
func newMgmtApply(vo VendorOids, skip string) scriptedApplyFunc {
	addr := "10.1.5.20"
	return func(tables map[string][]Row, vbs []SetVarbind) {
		for _, vb := range vbs {
			val := toStrValue(vb.Value)
			switch vb.OID {
			case vo.MgmtWriteAddrUnverified:
				if skip != "address" {
					addr = val
					tables[IPAdEntAddr] = []Row{NewStrRow(IPAdEntAddr+"."+val, val)}
				}
			case vo.MgmtWriteNetmaskUnverified:
				if skip != "netmask" {
					tables[IPAdEntNetmask] = []Row{NewStrRow(IPAdEntNetmask+"."+addr, val)}
				}
			case vo.MgmtWriteGatewayUnverified:
				if skip != "gateway" {
					tables[IPRouteNextHop] = []Row{NewStrRow(IPRouteNextHop+".0.0.0.0", val)}
				}
			}
		}
	}
}

// --- SetVlanMembership ----------------------------------------------------

func TestSetVlanMembershipRMWPreservesOtherPorts(t *testing.T) {
	client := newScriptedWriteClient(vlanTables(90, []int{1, 2, 10}, []int{1, 2}), applyVlanBitmaps)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetVlanMembership(context.Background(), 90, 25, model.VlanTagged, true); err != nil {
		t.Fatalf("SetVlanMembership: %v", err)
	}
	egressOID := fmt.Sprintf("%s.90", Dot1qVlanStaticEgress)
	untaggedOID := fmt.Sprintf("%s.90", Dot1qVlanStaticUntagged)
	var egressSV, untaggedSV *SetVarbind
	for i := range client.sets {
		switch client.sets[i].OID {
		case egressOID:
			egressSV = &client.sets[i]
		case untaggedOID:
			untaggedSV = &client.sets[i]
		}
	}
	if egressSV == nil || untaggedSV == nil {
		t.Fatalf("sets = %+v, want both egress and untagged varbinds", client.sets)
	}
	if egressSV.TypeLetter != "x" {
		t.Errorf("egress TypeLetter = %q, want %q", egressSV.TypeLetter, "x")
	}
	wantEgress := []int{1, 2, 10, 25}
	gotEgress := DecodePortBitmap(egressSV.Value.([]byte))
	if !intSlicesEqual(gotEgress, wantEgress) {
		t.Errorf("egress decoded = %v, want %v (port 25 added, others kept)", gotEgress, wantEgress)
	}
	wantUntagged := []int{1, 2}
	gotUntagged := DecodePortBitmap(untaggedSV.Value.([]byte))
	if !intSlicesEqual(gotUntagged, wantUntagged) {
		t.Errorf("untagged decoded = %v, want %v (25 is tagged only)", gotUntagged, wantUntagged)
	}
}

func TestSetVlanMembershipCatchesDroppedUntaggedWrite(t *testing.T) {
	client := newScriptedWriteClient(vlanTables(90, []int{1, 2, 10}, []int{1, 2}), applyEgressOnly)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetVlanMembership(context.Background(), 90, 25, model.VlanUntagged, true)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetVlanMembership error = %v, want *model.WriteVerificationError", err)
	}
	if !strings.Contains(err.Error(), "untagged") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "untagged")
	}
}

func TestSetVlanMembershipMissingVlanIsPreconditionNotVerifyError(t *testing.T) {
	client := newScriptedWriteClient(nil, applyVlanBitmaps)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetVlanMembership(context.Background(), 90, 25, model.VlanTagged, true)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("SetVlanMembership error = %v, want wrap of model.ErrSNMP", err)
	}
	var verr *model.WriteVerificationError
	if errors.As(err, &verr) {
		t.Errorf("SetVlanMembership error is a *model.WriteVerificationError, want a precondition ErrSNMP instead")
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (precondition failed before any SET)", client.sets)
	}
}

func TestSetVlanMembershipVlanDisappearsAfterWriteRaisesVerificationError(t *testing.T) {
	client := newScriptedWriteClient(vlanTables(90, []int{1, 2, 10}, []int{1, 2}), applyVlanVanishes)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetVlanMembership(context.Background(), 90, 25, model.VlanTagged, true)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetVlanMembership error = %v, want *model.WriteVerificationError", err)
	}
	if !strings.Contains(err.Error(), "disappeared") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "disappeared")
	}
	// verr.After is `any` holding a (*model.VLANInfo)(nil): a type-asserted
	// nil pointer, not a nil interface, per Go's usual "typed nil in an
	// interface" rule -- so this must check the underlying pointer, not
	// compare the interface itself to nil (which would always be false).
	afterVlan, ok := verr.After.(*model.VLANInfo)
	if !ok || afterVlan != nil {
		t.Errorf("verr.After = %#v, want a nil *model.VLANInfo", verr.After)
	}
}

func TestSetVlanMembershipBitmapsAre8BytesFor52PortModel(t *testing.T) {
	client := newScriptedWriteClient(vlanTables(90, []int{1, 2, 10}, []int{1, 2}), applyVlanBitmaps)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps")) // 52-port model
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetVlanMembership(context.Background(), 90, 25, model.VlanTagged, true); err != nil {
		t.Fatalf("SetVlanMembership: %v", err)
	}
	egressOID := fmt.Sprintf("%s.90", Dot1qVlanStaticEgress)
	untaggedOID := fmt.Sprintf("%s.90", Dot1qVlanStaticUntagged)
	for _, sv := range client.sets {
		switch sv.OID {
		case egressOID, untaggedOID:
			if got := len(sv.Value.([]byte)); got != 8 {
				t.Errorf("%s length = %d, want 8", sv.OID, got)
			}
		}
	}
}

// TestSetVlanMembershipRMWPreservesDeviceWidthOf79Bytes proves the D-REC
// Topic B / reconciliation issue #3 fix: when the device reports its
// egress/untagged PortLists at a real measured width (79 bytes, as
// GSM7252PS actually does -- far wider than this 52-port model's formula
// width of 8), SetVlanMembership's read-modify-write must SET back bitmaps
// at that SAME 79-byte width, not re-derive a narrower one via
// EncodePortBitmap(..., 8)/VlanBitmapWidth. A prior version of this method
// re-encoded the already-DECODED `before` port lists at vlanEncodeWidth (8),
// silently narrowing the SET below the device's real fixed PortList width --
// exactly what a stricter Q-BRIDGE agent rejects outright.
func TestSetVlanMembershipRMWPreservesDeviceWidthOf79Bytes(t *testing.T) {
	client := newScriptedWriteClient(vlanTablesWidth(90, []int{1, 2, 10}, []int{1, 2}, 79), applyVlanBitmaps)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetVlanMembership(context.Background(), 90, 25, model.VlanUntagged, true); err != nil {
		t.Fatalf("SetVlanMembership: %v", err)
	}
	egressOID := fmt.Sprintf("%s.90", Dot1qVlanStaticEgress)
	untaggedOID := fmt.Sprintf("%s.90", Dot1qVlanStaticUntagged)
	var egressSV, untaggedSV *SetVarbind
	for i := range client.sets {
		switch client.sets[i].OID {
		case egressOID:
			egressSV = &client.sets[i]
		case untaggedOID:
			untaggedSV = &client.sets[i]
		}
	}
	if egressSV == nil || untaggedSV == nil {
		t.Fatalf("sets = %+v, want both egress and untagged varbinds", client.sets)
	}
	if got := len(egressSV.Value.([]byte)); got != 79 {
		t.Errorf("egress SET width = %d, want 79 (the device's own width preserved)", got)
	}
	if got := len(untaggedSV.Value.([]byte)); got != 79 {
		t.Errorf("untagged SET width = %d, want 79", got)
	}
	wantEgress := []int{1, 2, 10, 25}
	if got := DecodePortBitmap(egressSV.Value.([]byte)); !intSlicesEqual(got, wantEgress) {
		t.Errorf("egress decoded = %v, want %v (port 25 added, others kept)", got, wantEgress)
	}
	wantUntagged := []int{1, 2, 25}
	if got := DecodePortBitmap(untaggedSV.Value.([]byte)); !intSlicesEqual(got, wantUntagged) {
		t.Errorf("untagged decoded = %v, want %v (25 untagged, others kept)", got, wantUntagged)
	}
}

func TestSetVlanMembershipGuardIsUnconditional(t *testing.T) {
	client := newScriptedWriteClient(vlanTables(90, []int{1, 2, 10}, []int{1, 2}), applyVlanBitmaps)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithProtectedPorts(25))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetVlanMembership(context.Background(), 90, 25, model.VlanTagged, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetVlanMembership error = %v, want ErrProtectedPort", err)
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (blocked before any SET)", client.sets)
	}
	if err := w.SetVlanMembership(context.Background(), 90, 25, model.VlanTagged, true); err != nil {
		t.Fatalf("SetVlanMembership with force=true: %v", err)
	}
}

// --- CreateVlan ------------------------------------------------------------

func TestCreateVlanSetsRowStatusAndName(t *testing.T) {
	client := newScriptedWriteClient(nil, applyRowStatusAndName)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.CreateVlan(context.Background(), 200, "guests"); err != nil {
		t.Fatalf("CreateVlan: %v", err)
	}
	wantRowStatus := SetVarbind{OID: fmt.Sprintf("%s.200", Dot1qVlanStaticRowStatus), Value: RowStatusCreateAndGo, TypeLetter: "i"}
	wantName := SetVarbind{OID: fmt.Sprintf("%s.200", Dot1qVlanStaticName), Value: "guests", TypeLetter: "s"}
	if !containsSetVarbind(client.sets, wantRowStatus) {
		t.Errorf("sets = %+v, want to contain %+v", client.sets, wantRowStatus)
	}
	if !containsSetVarbind(client.sets, wantName) {
		t.Errorf("sets = %+v, want to contain %+v", client.sets, wantName)
	}
}

// --- DeleteVlan --------------------------------------------------------

func TestDeleteVlanDestroysAndVerifiesAbsent(t *testing.T) {
	tables := map[string][]Row{
		Dot1qVlanStaticName: {NewStrRow(fmt.Sprintf("%s.200", Dot1qVlanStaticName), "guests")},
	}
	client := newScriptedWriteClient(tables, applyRowStatusAndName)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.DeleteVlan(context.Background(), 200, false); err != nil {
		t.Fatalf("DeleteVlan: %v", err)
	}
	want := []SetVarbind{{OID: fmt.Sprintf("%s.200", Dot1qVlanStaticRowStatus), Value: RowStatusDestroy, TypeLetter: "i"}}
	if !setVarbindsEqual(client.sets, want) {
		t.Errorf("sets = %+v, want %+v", client.sets, want)
	}
}

func TestDeleteVlanProtectedMemberRequiresForce(t *testing.T) {
	// VLAN 90 has member ports {1, 2, 10}; port 1 is protected. Deleting it
	// would strip membership from the protected port.
	tables := vlanTables(90, []int{1, 2, 10}, []int{1, 2})
	client := newScriptedWriteClient(tables, applyRowStatusAndName)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"), WithProtectedPorts(1))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.DeleteVlan(context.Background(), 90, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("DeleteVlan error = %v, want ErrProtectedPort", err)
	}
	wantSubstr := "VLAN 90 includes protected port(s) [1]; pass force=True to delete it anyway"
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("DeleteVlan() error = %q, want it to contain %q", err.Error(), wantSubstr)
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (blocked before any SET)", client.sets)
	}
	if err := w.DeleteVlan(context.Background(), 90, true); err != nil {
		t.Fatalf("DeleteVlan with force=true: %v", err)
	}
	rowStatusOID := fmt.Sprintf("%s.90", Dot1qVlanStaticRowStatus)
	found := false
	for _, s := range client.sets {
		if s.OID == rowStatusOID {
			found = true
		}
	}
	if !found {
		t.Errorf("sets = %+v, want the forced destroy SET to have gone through", client.sets)
	}
}

func TestDeleteVlanMissingVlanIsPreconditionNotVerifyError(t *testing.T) {
	client := newScriptedWriteClient(nil, applyRowStatusAndName)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.DeleteVlan(context.Background(), 999, false)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("DeleteVlan error = %v, want wrap of model.ErrSNMP", err)
	}
	var verr *model.WriteVerificationError
	if errors.As(err, &verr) {
		t.Errorf("DeleteVlan error is a *model.WriteVerificationError, want a precondition ErrSNMP instead")
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (precondition failed before any SET)", client.sets)
	}
}

// --- SetMgmtIP -----------------------------------------------------------

func TestSetMgmtIPRequiresForce(t *testing.T) {
	client := newScriptedWriteClient(mgmtIPTables("10.1.5.20", "255.255.255.0", "10.1.5.1"), nil)
	w, err := NewWriter(client, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetMgmtIP(context.Background(), "10.9.9.9", "255.255.255.0", "10.9.9.1", false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetMgmtIP error = %v, want ErrProtectedPort", err)
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (force-gate fires before any SET)", client.sets)
	}
}

func TestSetMgmtIPEmitsThreeIPAddressSets(t *testing.T) {
	m := mustModel(t, "gsm7252ps")
	vo, err := GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}
	client := newScriptedWriteClient(mgmtIPTables("10.1.5.20", "255.255.255.0", "10.1.5.1"), newMgmtApply(vo, ""))
	w, err := NewWriter(client, m)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetMgmtIP(context.Background(), "10.9.9.9", "255.255.255.0", "10.9.9.1", true); err != nil {
		t.Fatalf("SetMgmtIP: %v", err)
	}
	want := []SetVarbind{
		{OID: vo.MgmtWriteAddrUnverified, Value: "10.9.9.9", TypeLetter: "a"},
		{OID: vo.MgmtWriteNetmaskUnverified, Value: "255.255.255.0", TypeLetter: "a"},
		{OID: vo.MgmtWriteGatewayUnverified, Value: "10.9.9.1", TypeLetter: "a"},
	}
	for _, w := range want {
		if !containsSetVarbind(client.sets, w) {
			t.Errorf("sets = %+v, want to contain %+v", client.sets, w)
		}
	}
}

func TestSetMgmtIPVerifiesGatewayNotJustAddress(t *testing.T) {
	// Device accepts address+netmask but drops the gateway write; verify
	// must catch it and name the gateway field (review item 2).
	m := mustModel(t, "gsm7252ps")
	vo, err := GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}
	client := newScriptedWriteClient(mgmtIPTables("10.1.5.20", "255.255.255.0", "10.1.5.1"), newMgmtApply(vo, "gateway"))
	w, err := NewWriter(client, m)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetMgmtIP(context.Background(), "10.9.9.9", "255.255.255.0", "10.9.9.1", true)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetMgmtIP error = %v, want *model.WriteVerificationError", err)
	}
	if !strings.Contains(err.Error(), "gateway") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "gateway")
	}
}

func TestSetMgmtIPNoVendorModelReturnsUnsupportedCapability(t *testing.T) {
	client := newScriptedWriteClient(mgmtIPTables("10.1.5.20", "255.255.255.0", "10.1.5.1"), nil)
	w, err := NewWriter(client, mustModel(t, "gs728tpp")) // no SNMP vendor OID subtree
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	err = w.SetMgmtIP(context.Background(), "10.9.9.9", "255.255.255.0", "10.9.9.1", true)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("SetMgmtIP error = %v, want wrap of model.ErrUnsupportedCapability", err)
	}
	if len(client.sets) != 0 {
		t.Errorf("sets = %+v, want none (no vendor OIDs to write to)", client.sets)
	}
}

// --- shared helpers --------------------------------------------------------

func intSlicesEqual(a, b []int) bool {
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

func containsSetVarbind(sets []SetVarbind, want SetVarbind) bool {
	for _, s := range sets {
		if s == want {
			return true
		}
	}
	return false
}
