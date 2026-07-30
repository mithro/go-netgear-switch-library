package virtual

import (
	"slices"
	"testing"

	"github.com/mithro/go-netgear-switch-library/snmp"
)

// ifOperStatusState builds a minimal gsm7252ps-backed State with exactly
// three ports {1, 2, 10}, admin/link true, so its OIDMap() emits
// ifOperStatus/ifAdminStatus/ifHighSpeed/ifType/ifName rows for exactly
// those three ports (plus the model's unconditional scalars). Mirrors the
// Python test_mibview.py fixture's ".8.2 must sort before .8.10" pin, but
// built from a real State/OIDMap() (this package has no interface seam for
// a fake state -- NewMibView takes a concrete *State).
func ifOperStatusState() *State {
	st := NewState("gsm7252ps")
	st.Ports = map[int]*PortSim{
		1:  NewPortSim("1/0/1", true, true, 1000),
		2:  NewPortSim("1/0/2", true, true, 1000),
		10: NewPortSim("1/0/10", true, true, 1000),
	}
	return st
}

func ifOperStatusOID(port int) []int {
	oid, ok := oidToInts(snmp.IfOperStatus)
	if !ok {
		panic("bad IfOperStatus constant")
	}
	return append(oid, port)
}

func TestMibViewGetExactMatch(t *testing.T) {
	v := NewMibView(ifOperStatusState())

	entry, ok := v.Get(ifOperStatusOID(2))
	if !ok {
		t.Fatalf("Get(ifOperStatus.2) not found")
	}
	if entry.Type != "INTEGER" || entry.Value != "1" {
		t.Errorf("Get(ifOperStatus.2) = {%q,%q}, want {INTEGER,1}", entry.Type, entry.Value)
	}
}

func TestMibViewGetMissingReturnsNotOK(t *testing.T) {
	v := NewMibView(ifOperStatusState())

	if _, ok := v.Get(ifOperStatusOID(99)); ok {
		t.Errorf("Get(ifOperStatus.99) = ok, want not-ok (no such port)")
	}
}

// TestMibViewGetNextUsesNumericOrder pins the critical porting detail: a
// string sort of the OID text would put ".8.10" before ".8.2" (since "1" <
// "2" as characters); the numeric []int sort must not.
func TestMibViewGetNextUsesNumericOrder(t *testing.T) {
	v := NewMibView(ifOperStatusState())

	next, ok := v.GetNext(ifOperStatusOID(2))
	if !ok {
		t.Fatalf("GetNext(ifOperStatus.2) not found")
	}
	want := ifOperStatusOID(10)
	if !slices.Equal(next.OID, want) {
		t.Errorf("GetNext(ifOperStatus.2).OID = %v, want %v (.8.10, not string order)", next.OID, want)
	}
}

func TestMibViewGetNextFromColumnPrefix(t *testing.T) {
	v := NewMibView(ifOperStatusState())

	base, ok := oidToInts(snmp.IfOperStatus) // no trailing port index at all
	if !ok {
		t.Fatalf("bad IfOperStatus constant")
	}
	next, ok := v.GetNext(base)
	if !ok {
		t.Fatalf("GetNext(ifOperStatus column) not found")
	}
	if got := next.OID[len(next.OID)-1]; got != 1 {
		t.Errorf("GetNext(ifOperStatus column) landed on port %d, want first instance (port 1)", got)
	}
}

func TestMibViewGetNextPastEndReturnsNotOK(t *testing.T) {
	v := NewMibView(ifOperStatusState())

	if _, ok := v.GetNext([]int{9, 9, 9, 9, 9, 9, 9, 9, 9, 9}); ok {
		t.Errorf("GetNext(past end) = ok, want not-ok")
	}
}

func TestMibViewIsImplementedTrueByDefault(t *testing.T) {
	// gsm7252ps has PoEPortCount > 0, so nothing is gated as unimplemented.
	v := NewMibView(ifOperStatusState())

	if !v.IsImplemented(ifOperStatusOID(2)) {
		t.Errorf("IsImplemented(ifOperStatus.2) = false, want true (gsm7252ps has no unimplemented roots)")
	}
}

func TestMibViewIsImplementedFalseUnderPoEUnimplementedModel(t *testing.T) {
	// m4300-24x is VERIFIED to have zero PoE ports; its SNMP agent never
	// registers the RFC3621 PoE MIB at all.
	st := NewState("m4300-24x")
	v := NewMibView(st)

	poeOID, ok := oidToInts(snmp.PethPsePortTable)
	if !ok {
		t.Fatalf("bad PethPsePortTable constant")
	}
	if v.IsImplemented(poeOID) {
		t.Errorf("IsImplemented(PethPsePortTable root) = true on m4300-24x, want false")
	}
	deeper := append(append([]int(nil), poeOID...), 3, 1, 1)
	if v.IsImplemented(deeper) {
		t.Errorf("IsImplemented(PethPsePortTable.3.1.1) = true on m4300-24x, want false")
	}

	// A sibling OID outside the unimplemented prefix is unaffected.
	ifAdminOID, ok := oidToInts(snmp.IfAdminStatus)
	if !ok {
		t.Fatalf("bad IfAdminStatus constant")
	}
	if !v.IsImplemented(append(ifAdminOID, 1)) {
		t.Errorf("IsImplemented(ifAdminStatus.1) = false on m4300-24x, want true (unaffected sibling)")
	}
}

// TestMibViewExhaustiveWalkVisitsEverySeededOIDOnce walks the whole
// gsm7252ps seed's real OIDMap via repeated GetNext calls starting from
// (0,), and asserts the walk visits every OIDMap entry exactly once, in
// strictly increasing tuple order, with no gaps or duplicates -- mirrors
// Python's test_walk_real_seeded_oid_map_yields_every_entry_once.
func TestMibViewExhaustiveWalkVisitsEverySeededOIDOnce(t *testing.T) {
	st := SeedGSM7252PS()
	oidMap := st.OIDMap()
	v := NewMibView(st)

	var seen [][]int
	oid := []int{0}
	for {
		next, ok := v.GetNext(oid)
		if !ok {
			break
		}
		seen = append(seen, next.OID)
		oid = next.OID
	}

	if len(seen) != len(oidMap) {
		t.Fatalf("walk visited %d OIDs, want %d (len(oid_map))", len(seen), len(oidMap))
	}

	seenSet := make(map[string]bool, len(seen))
	for i, oid := range seen {
		key := intsToOID(oid)
		if seenSet[key] {
			t.Fatalf("walk visited %v twice", oid)
		}
		seenSet[key] = true
		if i > 0 {
			if cmp := slices.Compare(seen[i-1], oid); cmp >= 0 {
				t.Fatalf("walk order not strictly increasing: %v then %v", seen[i-1], oid)
			}
		}
	}

	for oidStr := range oidMap {
		if !seenSet[oidStr] {
			t.Errorf("walk never visited seeded OID %q", oidStr)
		}
	}
}

// TestMibViewApplyWriteRebuildsImmediately confirms ApplyWrite (the
// committed single-write path, as opposed to ApplyWriteUncommitted) is
// visible to a subsequent Get without any separate Rebuild call.
func TestMibViewApplyWriteRebuildsImmediately(t *testing.T) {
	st := ifOperStatusState()
	v := NewMibView(st)

	pvidOID, ok := oidToInts(snmp.Dot1qPvid)
	if !ok {
		t.Fatalf("bad Dot1qPvid constant")
	}
	oid := append(pvidOID, 1)
	if _, ok := v.Get(oid); ok {
		t.Fatalf("Get(dot1qPvid.1) before any write = ok, want not-ok (no pvids seeded)")
	}

	v.ApplyWrite(snmp.Dot1qPvid+".1", 42)

	entry, ok := v.Get(oid)
	if !ok {
		t.Fatalf("Get(dot1qPvid.1) after ApplyWrite = not-ok, want ok")
	}
	if entry.Value != "42" {
		t.Errorf("Get(dot1qPvid.1) after ApplyWrite = %q, want \"42\"", entry.Value)
	}
}
