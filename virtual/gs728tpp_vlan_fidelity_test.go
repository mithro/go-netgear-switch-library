package virtual

// gs728tpp_vlan_fidelity_test.go: end-to-end regression coverage for the
// GAP-2 SNMP GetVLANs fix (parity with Python commit 3f25b0b), driven over
// REAL UDP against the virtual gs728tpp fake -- not just the hand-built
// parser fixtures in package snmp's own parse_vlans_test.go. Ported from
// Python's tests/virtual/test_gs728tpp_vlan_fidelity.py at pin b26eb1f
// (test_vlan_1_has_no_static_row_but_is_still_reported and two supporting
// tests that prove the fix is doing real work, not passing vacuously).
//
// Everything asserted here was MEASURED on the real switch
// sw-netgear-gs728tpp.monarto.mithis.com (10.2.5.10, firmware 6.0.1.30),
// 2026-08-02 -- see SeedGS728TPP's own doc comments for the capture
// details. Without the fake carrying both facts (VLAN 1's missing static
// row, the LAG bit on the wire), this fix could never be regression-guarded
// without hardware.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// gs728tppSnmpReader starts an SnmpFace over a freshly-seeded gs728tpp
// State and returns both an snmp.Reader bound to it (for the parsed,
// filtered view) and the raw snmp.Client (for inspecting exactly what is
// on the wire) -- mirroring the Python fixture's `mock`/`_snmp(mock)` pair.
func gs728tppSnmpReader(t *testing.T) (*snmp.Reader, snmp.Client) {
	t.Helper()
	addr, _, _ := startFace(t, SeedGS728TPP())
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))
	m, err := model.GetModel("gs728tpp")
	if err != nil {
		t.Fatalf("model.GetModel(gs728tpp): %v", err)
	}
	reader, err := snmp.NewReader(client, m)
	if err != nil {
		t.Fatalf("snmp.NewReader: %v", err)
	}
	return reader, client
}

// vlanIDsFromWalk extracts the trailing integer index off every row's OID
// from a walk -- the VLAN id, whether the column is single-level (static
// table: <base>.<vid>) or two-level (current table: <base>.<timemark>.
// <vid>) -- mirroring the Python test's `int(r.oid.rsplit(".", 1)[1])`.
func vlanIDsFromWalk(t *testing.T, rows []snmp.Row) map[int]bool {
	t.Helper()
	out := make(map[int]bool, len(rows))
	for _, row := range rows {
		i := strings.LastIndex(row.OID, ".")
		if i < 0 {
			t.Fatalf("row OID %q has no %q", row.OID, ".")
		}
		vid, err := strconv.Atoi(row.OID[i+1:])
		if err != nil {
			t.Fatalf("row OID %q: trailing component not an int: %v", row.OID, err)
		}
		out[vid] = true
	}
	return out
}

// bytesOfRowValue normalizes a Row.Value to []byte, accepting both the
// []byte and string encodings a real OCTET STRING can come back as (see
// GoSNMPClient's normalizeVarbind: "printable" bytes round-trip as string,
// others as []byte) -- the same dual-type tolerance
// vlanBitmapMap/currentVlanBitmapMap apply internally.
func bytesOfRowValue(t *testing.T, v any) []byte {
	t.Helper()
	switch b := v.(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	default:
		t.Fatalf("row value %v is neither []byte nor string (%T)", v, v)
		return nil
	}
}

// TestGS728TPPVLAN1HasNoStaticRowButIsStillReported pins the GAP-2 fix
// (parity with Python commit 3f25b0b / test_vlan_1_has_no_static_row_but_
// is_still_reported), driven end-to-end against the virtual gs728tpp fake:
// VLAN 1 has NO dot1qVlanStaticTable row on the real switch -- only a
// dot1qVlanCurrentTable row -- so a static-table-only reader lost it
// entirely. That was the bug this test regression-guards without hardware.
func TestGS728TPPVLAN1HasNoStaticRowButIsStillReported(t *testing.T) {
	reader, client := gs728tppSnmpReader(t)
	ctx := context.Background()

	staticRows, err := client.Walk(ctx, snmp.Dot1qVlanStaticName)
	if err != nil {
		t.Fatalf("Walk(Dot1qVlanStaticName): %v", err)
	}
	staticIDs := vlanIDsFromWalk(t, staticRows)
	if staticIDs[1] {
		t.Error("the fake must NOT invent a static row for VLAN 1")
	}

	currentRows, err := client.Walk(ctx, snmp.Dot1qVlanCurrentEgress)
	if err != nil {
		t.Fatalf("Walk(Dot1qVlanCurrentEgress): %v", err)
	}
	currentIDs := vlanIDsFromWalk(t, currentRows)
	if !currentIDs[1] {
		t.Fatal("VLAN 1 must have a dot1qVlanCurrentTable row")
	}

	vlans, err := reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs: %v", err)
	}
	reported := make(map[int]bool, len(vlans))
	for _, v := range vlans {
		reported[v.VlanID] = true
	}
	if !reported[1] {
		t.Error("a static-table-only read loses VLAN 1 -- that was the bug")
	}
	if len(reported) != len(currentIDs) {
		t.Errorf("GetVLANs reported %v, want exactly the current-table VLAN set %v", sortedIntKeys(reported), sortedIntKeys(currentIDs))
	}
	for vid := range currentIDs {
		if !reported[vid] {
			t.Errorf("VLAN %d is in dot1qVlanCurrentTable but missing from GetVLANs", vid)
		}
	}
}

// TestGS728TPPVLANStatusMarksTheStaticlessVLANAsOther pins the GAP-2 fix
// (parity with Python commit 3f25b0b / test_vlan_status_marks_the_static_
// less_vlan_as_other): dot1qVlanStatus reads 1 (other) for VLAN 1, the one
// with no static row, and 2 (permanent) for a normally-configured VLAN --
// exactly what the live switch reports.
func TestGS728TPPVLANStatusMarksTheStaticlessVLANAsOther(t *testing.T) {
	_, client := gs728tppSnmpReader(t)
	rows, err := client.Walk(context.Background(), snmp.Dot1qVlanStatus)
	if err != nil {
		t.Fatalf("Walk(Dot1qVlanStatus): %v", err)
	}
	byVlan := map[int]string{}
	for _, row := range rows {
		i := strings.LastIndex(row.OID, ".")
		vid, err := strconv.Atoi(row.OID[i+1:])
		if err != nil {
			t.Fatalf("row OID %q: trailing component not an int: %v", row.OID, err)
		}
		byVlan[vid] = bytesOfRowValueAsIntString(t, row.Value)
	}
	if got := byVlan[1]; got != "1" {
		t.Errorf("dot1qVlanStatus for VLAN 1 = %q, want \"1\" (other) -- what the live switch reports", got)
	}
	if got := byVlan[5]; got != "2" {
		t.Errorf("dot1qVlanStatus for VLAN 5 = %q, want \"2\" (permanent) for a configured VLAN", got)
	}
}

// bytesOfRowValueAsIntString renders an INTEGER row's value as its decimal
// string, accepting whatever concrete numeric type normalizeVarbind used.
func bytesOfRowValueAsIntString(t *testing.T, v any) string {
	t.Helper()
	switch n := v.(type) {
	case int64:
		return strconv.FormatInt(n, 10)
	case int:
		return strconv.Itoa(n)
	default:
		t.Fatalf("dot1qVlanStatus value %v is not an integer type (%T)", v, v)
		return ""
	}
}

// TestGS728TPPLAGBitIsReallyOnTheWireAndReallyFilteredOut pins the GAP-2
// fix (parity with Python commit 3f25b0b / test_the_lag_bit_is_really_on_
// the_wire_and_really_filtered_out): the filter must be doing REAL work.
// Without this the LAG-filtering test could pass against a mock that
// simply never sets the bit -- agreeing with the code while both disagree
// with the switch. Asserts the RAW static egress bitmap for VLAN 5 DOES
// carry bit 1000 (the device's own 126-byte PortList width), then that
// GetVLANs' MemberPorts for that same VLAN does NOT include port 1000.
func TestGS728TPPLAGBitIsReallyOnTheWireAndReallyFilteredOut(t *testing.T) {
	reader, client := gs728tppSnmpReader(t)
	ctx := context.Background()

	rows, err := client.Walk(ctx, snmp.Dot1qVlanStaticEgress)
	if err != nil {
		t.Fatalf("Walk(Dot1qVlanStaticEgress): %v", err)
	}
	var vlan5Raw []byte
	found := false
	for _, row := range rows {
		if strings.HasSuffix(row.OID, ".5") {
			vlan5Raw = bytesOfRowValue(t, row.Value)
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no dot1qVlanStaticEgressPorts row for VLAN 5")
	}
	if len(vlan5Raw) != 126 {
		t.Errorf("VLAN 5 raw egress bitmap width = %d bytes, want 126 (the device's own measured PortList width)", len(vlan5Raw))
	}
	rawMembers := snmp.DecodePortBitmap(vlan5Raw)
	rawHasLAG := false
	for _, p := range rawMembers {
		if p == 1000 {
			rawHasLAG = true
			break
		}
	}
	if !rawHasLAG {
		t.Fatal("raw bit 1000 is NOT set on the wire -- this test would be vacuous against a mock that never sets it")
	}

	vlans, err := reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs: %v", err)
	}
	var vlan5 *model.VLANInfo
	for i := range vlans {
		if vlans[i].VlanID == 5 {
			vlan5 = &vlans[i]
			break
		}
	}
	if vlan5 == nil {
		t.Fatal("VLAN 5 missing from GetVLANs")
	}
	for _, p := range vlan5.MemberPorts {
		if p == 1000 {
			t.Errorf("GetVLANs MemberPorts for VLAN 5 = %v, must NOT contain the phantom LAG port 1000", vlan5.MemberPorts)
		}
	}
	if len(vlan5.MemberPorts) == 0 {
		t.Error("GetVLANs MemberPorts for VLAN 5 is empty -- the filter must keep the real physical members, not just drop the LAG")
	}
}
