package virtual

// mibview.go ports src/netgear_switch/virtual/faces/mibview.py's StateMibView
// (the normative source; that repo is read-only from here -- pin b26eb1f).
// Any discrepancy between this file and the Python source is a bug here.
// See D-VIRT §2 for the full porting dossier this mirrors.
//
// MibView is a pure OID responder over State.OIDMap(): no network, no
// pysnmp/gosnmp dependency here at all (that lives in snmpface.go) -- just a
// numerically sorted (oid []int, type, value) list answering exact-match GET
// and GETNEXT with binary search. Task 15's equivalent later wires this into
// the real gosnmp-codec agent face (snmpface.go, this same package).

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ViewEntry is one MibView row: a numeric OID plus the SNMP type token and
// wire value State.OIDMap() projected for it (see OIDEntry).
type ViewEntry struct {
	OID   []int
	Type  string
	Value string
}

// MibView is a sorted view of a State's OID map supporting GET and GETNEXT.
// Construct with NewMibView; call Rebuild after any write that bypassed
// ApplyWrite/ApplyWriteUncommitted (those two already rebuild appropriately
// themselves).
type MibView struct {
	state   *State
	entries []ViewEntry
}

// NewMibView builds a MibView over state, loading its initial sorted
// snapshot from state.OIDMap().
func NewMibView(state *State) *MibView {
	v := &MibView{state: state}
	v.Rebuild()
	return v
}

// oidToInts parses a dotted-decimal OID string (with or without a leading
// dot) into its component ints. Returns ok=false for anything that isn't
// purely numeric dotted components -- never panics on its own, since
// snmpface.go also feeds this untrusted wire input; Rebuild below is the
// one caller that treats a false ok as an internal-data bug (State.OIDMap()
// is trusted to only ever produce canonical numeric OID strings).
func oidToInts(oid string) ([]int, bool) {
	oid = strings.TrimPrefix(oid, ".")
	if oid == "" {
		return nil, false
	}
	parts := strings.Split(oid, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// intsToOID renders oid's components back to a dotted-decimal string (no
// leading dot), the inverse of oidToInts.
func intsToOID(oid []int) string {
	parts := make([]string, len(oid))
	for i, n := range oid {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}

// Rebuild recomputes the sorted view from the current State.OIDMap().
// Called by NewMibView, by ApplyWrite (every write), and once by a SET
// face's caller after an atomic multi-varbind PDU commits fully (see
// ApplyWriteUncommitted). The sort key is the numeric []int OID compared
// with slices.Compare -- NEVER a lexicographic string compare of the OID
// text, since e.g. ".8.2" must sort before ".8.10".
func (v *MibView) Rebuild() {
	m := v.state.OIDMap()
	entries := make([]ViewEntry, 0, len(m))
	for oid, e := range m {
		ints, ok := oidToInts(oid)
		if !ok {
			panic(fmt.Sprintf("virtual: MibView.Rebuild: State.OIDMap produced non-numeric OID %q", oid))
		}
		entries = append(entries, ViewEntry{OID: ints, Type: e.SnmpType, Value: e.Value})
	}
	slices.SortFunc(entries, func(a, b ViewEntry) int { return slices.Compare(a.OID, b.OID) })
	v.entries = entries
}

// search returns the index of the leftmost entry whose OID is >= oid
// (bisect_left), and whether that entry's OID equals oid exactly. Since
// State.OIDMap() is a map keyed by a canonical OID string, entries can never
// contain a duplicate OID, so this single search doubles as both Get's
// bisect_left+eq check and (via the +1-on-match adjustment in GetNext)
// GetNext's bisect_right.
func (v *MibView) search(oid []int) (int, bool) {
	return slices.BinarySearchFunc(v.entries, oid, func(e ViewEntry, target []int) int {
		return slices.Compare(e.OID, target)
	})
}

// Get performs an exact-match lookup: bisect_left plus an equality check.
// ok=false means "no instance at this exact OID within an IMPLEMENTED
// subtree" (-> the caller's face maps that to NoSuchInstance); callers MUST
// check IsImplemented(oid) FIRST -- see the package doc's three-way
// exception rule (D-VIRT §2.9).
func (v *MibView) Get(oid []int) (entry *ViewEntry, ok bool) {
	i, found := v.search(oid)
	if !found {
		return nil, false
	}
	return &v.entries[i], true
}

// GetNext performs GETNEXT lookup: bisect_right (strictly greater -- GETNEXT
// never returns the same OID it was asked about). ok=false means "past the
// end of the view" (-> the caller's face maps that to EndOfMibView); same
// IsImplemented-first caveat as Get.
func (v *MibView) GetNext(oid []int) (entry *ViewEntry, ok bool) {
	i, found := v.search(oid)
	if found {
		i++
	}
	if i >= len(v.entries) {
		return nil, false
	}
	return &v.entries[i], true
}

// ApplyWrite mutates the underlying state via a single committed write, then
// rebuilds the sorted view so subsequent reads reflect it.
func (v *MibView) ApplyWrite(oid string, value any) {
	v.state.ApplyWrite(oid, value)
	v.Rebuild()
}

// ApplyWriteUncommitted mutates the underlying state WITHOUT rebuilding the
// sorted view. For an atomic multi-varbind SET (snmpface.go's handleSet):
// the comparatively expensive Rebuild is deferred until the whole PDU has
// committed successfully, once, rather than once per varbind. Callers MUST
// call Rebuild themselves once every varbind in the PDU has applied without
// error.
func (v *MibView) ApplyWriteUncommitted(oid string, value any) {
	v.state.ApplyWrite(oid, value)
}

// SnapshotState snapshots the underlying state, for atomic multi-varbind SET
// rollback. See State.Snapshot/RestoreState.
func (v *MibView) SnapshotState() *State {
	return v.state.Snapshot()
}

// RestoreState restores the underlying state in place from a prior
// SnapshotState result, discarding any writes applied since. The sorted
// view itself needs no rebuild after a restore: if the caller took the
// snapshot before making any changes and only ever reaches this on a failed
// atomic SET, the state (and thus the view) is back to exactly what it was
// before that SET began.
func (v *MibView) RestoreState(snapshot *State) {
	v.state.Restore(snapshot)
}

// IsWritableOID is a passthrough to State.IsWritableOID.
func (v *MibView) IsWritableOID(oid string) bool {
	return v.state.IsWritableOID(oid)
}

// LockState is a passthrough to State.LockState: a face's SET handler must
// hold this across a whole atomic write (snapshot, per-varbind apply,
// rebuild), not just the individual State mutations inside it, so no other
// goroutine (another face, or a test reading State directly) ever observes
// a partial write or races with one. See State.LockState's own doc comment
// for the full contract -- this is a Go-only concern with no Python
// equivalent.
func (v *MibView) LockState() { v.state.LockState() }

// UnlockState is a passthrough to State.UnlockState, releasing the lock
// LockState acquired.
func (v *MibView) UnlockState() { v.state.UnlockState() }

// IsImplemented reports false if oid falls under a subtree root this
// model's SNMP agent has no registration for at all (e.g. the RFC3621 PoE
// MIB on a non-PoE model) -- see State.IsOIDImplemented. A face checks this
// BEFORE calling Get/GetNext: a real agent answers noSuchObject for such a
// request rather than this view's flat bisect silently finding whatever
// unrelated OID happens to sort next.
func (v *MibView) IsImplemented(oid []int) bool {
	return v.state.IsOIDImplemented(intsToOID(oid))
}
