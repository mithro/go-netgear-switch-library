package virtual

// Tests for SnmpFace, driven over real UDP against gosnmp clients: the
// package's own GoSNMPClient (snmp.GoSNMPClient) for read/walk-shaped
// assertions, and a raw *gosnmp.GoSNMP handle where a test needs to inspect
// per-varbind wire types/error-index directly (the wrapped client
// deliberately collapses those into Go errors -- see D-VIRT §3, §6.2).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/mithro/go-netgear-switch-library/snmp"
)

// startFace starts an SnmpFace over st with community "public" on
// 127.0.0.1, registering t.Cleanup to stop it, and returns its "host:port"
// address plus the MibView backing it (so a test can inspect state directly
// alongside wire reads).
func startFace(t *testing.T, st *State) (addr string, view *MibView, face *SnmpFace) {
	t.Helper()
	view = NewMibView(st)
	face = NewSnmpFace(view, "public", "127.0.0.1")
	port, err := face.Start()
	if err != nil {
		t.Fatalf("SnmpFace.Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := face.Stop(); err != nil {
			t.Errorf("SnmpFace.Stop() error = %v", err)
		}
	})
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), view, face
}

// rawClient builds a connected, unwrapped *gosnmp.GoSNMP handle for tests
// that need to inspect PDU-level fields (Error/ErrorIndex) or per-varbind
// wire Type/Value directly, registering t.Cleanup to close it.
func rawClient(t *testing.T, addr string) *gosnmp.GoSNMP {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("ParseUint(%q): %v", portStr, err)
	}
	g := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(port),
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
		Retries:   1,
	}
	if err := g.Connect(); err != nil {
		t.Fatalf("raw gosnmp Connect(): %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

// -- GET ----------------------------------------------------------------

func TestSnmpFaceGetPresentValue(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))

	rows, err := client.Get(context.Background(), []string{snmp.IfOperStatus + ".1"})
	if err != nil {
		t.Fatalf("Get(ifOperStatus.1) error = %v", err)
	}
	if len(rows) != 1 || rows[0].Value != int64(1) {
		t.Errorf("Get(ifOperStatus.1) = %+v, want a single INTEGER row with value 1 (port 1 is up)", rows)
	}
}

func TestSnmpFaceGetAbsentInstanceNamesOID(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))

	oid := snmp.IfOperStatus + ".9999" // no such port on gsm7252ps
	_, err := client.Get(context.Background(), []string{oid})
	if err == nil {
		t.Fatalf("Get(%s) error = nil, want an absent-OID error (NoSuchInstance)", oid)
	}
	if !strings.Contains(err.Error(), oid) {
		t.Errorf("Get(%s) error = %v, want it to name the absent OID", oid, err)
	}
}

func TestSnmpFaceGetUnimplementedSubtreeIsNoSuchObject(t *testing.T) {
	// m4300-24x is VERIFIED to have zero PoE ports: the PoE MIB root is
	// never registered at all on this model's real agent.
	addr, _, _ := startFace(t, SeedM4300_24X())
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))

	oid := snmp.PethPsePortTable + ".3.1.1"
	_, err := client.Get(context.Background(), []string{oid})
	if err == nil {
		t.Fatalf("Get(%s) error = nil, want an absent-OID error (NoSuchObject)", oid)
	}
	if !strings.Contains(err.Error(), oid) {
		t.Errorf("Get(%s) error = %v, want it to name the absent OID", oid, err)
	}
}

// TestSnmpFaceGetMultiVarbindMixesPresentAndAbsent uses a raw client
// (rather than snmp.GoSNMPClient, which turns ANY absent varbind in a GET
// response into a whole-call error) to confirm the two varbinds' wire
// types differ per-varbind within the SAME response PDU: present ->
// Integer, absent instance -> NoSuchInstance -- never a PDU-level error
// for either.
func TestSnmpFaceGetMultiVarbindMixesPresentAndAbsent(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	g := rawClient(t, addr)

	presentOID := snmp.IfOperStatus + ".1"
	absentOID := snmp.IfOperStatus + ".9999"
	pkt, err := g.Get([]string{presentOID, absentOID})
	if err != nil {
		t.Fatalf("raw Get() error = %v", err)
	}
	if pkt.Error != gosnmp.NoError {
		t.Fatalf("raw Get() PDU error-status = %s, want NoError (exceptions are per-varbind values)", pkt.Error)
	}
	if len(pkt.Variables) != 2 {
		t.Fatalf("raw Get() returned %d varbinds, want 2", len(pkt.Variables))
	}
	if pkt.Variables[0].Type != gosnmp.Integer {
		t.Errorf("present varbind type = %s, want Integer", pkt.Variables[0].Type)
	}
	if pkt.Variables[1].Type != gosnmp.NoSuchInstance {
		t.Errorf("absent varbind type = %s, want NoSuchInstance", pkt.Variables[1].Type)
	}
}

// TestSnmpFaceGetNextRaw exercises a plain (non-bulk) GETNEXT PDU directly,
// which snmp.GoSNMPClient's Walk never issues (it always uses GETBULK) --
// pinning that the face's GetNextRequest dispatch answers the same
// chained-next-step semantics on its own.
func TestSnmpFaceGetNextRaw(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	g := rawClient(t, addr)

	pkt, err := g.GetNext([]string{snmp.IfOperStatus + ".1"})
	if err != nil {
		t.Fatalf("raw GetNext() error = %v", err)
	}
	if len(pkt.Variables) != 1 {
		t.Fatalf("raw GetNext() returned %d varbinds, want 1", len(pkt.Variables))
	}
	got := pkt.Variables[0]
	if strings.TrimLeft(got.Name, ".") == snmp.IfOperStatus+".1" {
		t.Errorf("GetNext(ifOperStatus.1).Name = %s, want strictly greater than the request", got.Name)
	}
}

// -- Walk / GETBULK -------------------------------------------------------

func TestSnmpFaceWalkVlanNamesYieldsExactly14(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))

	rows, err := client.Walk(context.Background(), snmp.Dot1qVlanStaticName)
	if err != nil {
		t.Fatalf("Walk(dot1qVlanStaticName) error = %v", err)
	}
	if len(rows) != 14 {
		t.Fatalf("Walk(dot1qVlanStaticName) returned %d rows, want 14", len(rows))
	}
	names := make(map[string]bool, len(rows))
	for _, r := range rows {
		s, ok := r.Value.(string)
		if !ok {
			t.Fatalf("row %+v: Value is %T, want string", r, r.Value)
		}
		names[s] = true
	}
	for _, want := range []string{"default", "iot"} {
		if !names[want] {
			t.Errorf("Walk(dot1qVlanStaticName) missing %q; got %v", want, names)
		}
	}
}

// TestSnmpFaceWalkWholeSubtreeVisitsEverySeededOIDOnce walks 1.3.6.1 (the
// whole standard-MIB + vendor space) via GETBULK and checks it terminates
// cleanly and yields every OIDMap entry under that prefix exactly once.
// LLDP (rooted at 1.0.8802) lives outside 1.3.6.1 and must NOT appear.
func TestSnmpFaceWalkWholeSubtreeVisitsEverySeededOIDOnce(t *testing.T) {
	st := SeedGSM7252PS()
	addr, _, _ := startFace(t, st)
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(5*time.Second))

	rows, err := client.Walk(context.Background(), "1.3.6.1")
	if err != nil {
		t.Fatalf("Walk(1.3.6.1) error = %v", err)
	}

	want := map[string]bool{}
	for oid := range st.OIDMap() {
		if strings.HasPrefix(oid, "1.3.6.1.") {
			want[oid] = true
		}
	}
	if len(rows) != len(want) {
		t.Fatalf("Walk(1.3.6.1) returned %d rows, want %d (len of OIDMap filtered to 1.3.6.1.*)", len(rows), len(want))
	}
	got := make(map[string]bool, len(rows))
	for _, r := range rows {
		if got[r.OID] {
			t.Fatalf("Walk(1.3.6.1) visited %s twice", r.OID)
		}
		got[r.OID] = true
		if strings.HasPrefix(r.OID, "1.0.8802.") {
			t.Fatalf("Walk(1.3.6.1) yielded LLDP OID %s, which is outside the 1.3.6.1 subtree", r.OID)
		}
	}
	for oid := range want {
		if !got[oid] {
			t.Errorf("Walk(1.3.6.1) never visited seeded OID %s", oid)
		}
	}
}

// TestSnmpFaceWalkPoERootOnNonPoEModelIsEmptyAndClean confirms a bulkwalk
// of the PoE MIB root on a model with zero PoE ports terminates cleanly
// (the client's Walk treats the resulting NoSuchObject as a benign walk
// terminator) with zero rows, never an error.
func TestSnmpFaceWalkPoERootOnNonPoEModelIsEmptyAndClean(t *testing.T) {
	addr, _, _ := startFace(t, SeedM4300_24X())
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))

	rows, err := client.Walk(context.Background(), snmp.PethPsePortTable)
	if err != nil {
		t.Fatalf("Walk(PethPsePortTable) on m4300-24x error = %v, want nil (clean empty walk)", err)
	}
	if len(rows) != 0 {
		t.Errorf("Walk(PethPsePortTable) on m4300-24x returned %d rows, want 0", len(rows))
	}
}

// TestSnmpFaceGetBulkRowMajorChainingWithEndOfMibViewFill drives a single
// raw GETBULK PDU with 1 non-repeater + 2 repeated columns and
// max-repetitions=3 against a small, fully-enumerable seeded state, and
// asserts the EXACT row-major response layout RFC 3416 mandates:
// [nonRepeaterResult, rep0col1, rep0col2, rep1col1, rep1col2, rep2col1,
// rep2col2]. snmp.GoSNMPClient.Walk never exercises this: it always sends
// a single OID with NonRepeaters=0, so a multi-varbind, mixed
// repeater/non-repeater GETBULK PDU is otherwise untested. Column A (the
// pvid column, 5 real instances) chains through 3 real values; column B is
// deliberately started AT the view's very last entry, so it hits
// EndOfMibView on repetition 0 and every later repetition for that SAME
// column must be FILLED with EndOfMibView rather than re-queried -- proving
// each column's chain state is carried independently.
func TestSnmpFaceGetBulkRowMajorChainingWithEndOfMibViewFill(t *testing.T) {
	st := NewState("gsm7252ps")
	st.Pvids = map[int]int{1: 10, 2: 20, 3: 30, 4: 40, 5: 50}
	addr, _, _ := startFace(t, st)
	g := rawClient(t, addr)

	// Ground truth computed independently of MibView (the thing under
	// test): sort every OIDMap-projected OID numerically to know exactly
	// what "the very first entry" and "the very last entry" in the whole
	// view are, without relying on GetNext/bisect at all.
	oidMap := st.OIDMap()
	all := make([][]int, 0, len(oidMap))
	for oidStr := range oidMap {
		ints, ok := oidToInts(oidStr)
		if !ok {
			t.Fatalf("bad OID %q in OIDMap", oidStr)
		}
		all = append(all, ints)
	}
	slices.SortFunc(all, slices.Compare)
	firstOID := intsToOID(all[0])
	lastOID := intsToOID(all[len(all)-1])

	pvidOID1 := snmp.Dot1qPvid + ".1"
	pvidOID2 := snmp.Dot1qPvid + ".2"
	pvidOID3 := snmp.Dot1qPvid + ".3"

	const nonRepReq = "0.0" // a minimal-but-valid 2-component OID before everything
	colAReq := snmp.Dot1qPvid
	colBReq := lastOID

	pkt, err := g.GetBulk([]string{nonRepReq, colAReq, colBReq}, 1, 3)
	if err != nil {
		t.Fatalf("raw GetBulk() error = %v", err)
	}
	if pkt.Error != gosnmp.NoError {
		t.Fatalf("GetBulk() PDU error-status = %s, want NoError (exceptions are per-varbind values)", pkt.Error)
	}
	if len(pkt.Variables) != 7 { // 1 non-repeater + 2 columns * 3 repetitions
		t.Fatalf("GetBulk() returned %d varbinds, want 7", len(pkt.Variables))
	}

	name := func(i int) string { return strings.TrimLeft(pkt.Variables[i].Name, ".") }

	if got := name(0); got != firstOID {
		t.Errorf("non-repeater result = %s, want %s (the first entry in the whole view)", got, firstOID)
	}

	// Repetition 0: column A -> pvid.1 (real value); column B is already
	// past the end -> EndOfMibView.
	if got := name(1); got != pvidOID1 {
		t.Errorf("rep0 col A = %s, want %s", got, pvidOID1)
	}
	if pkt.Variables[2].Type != gosnmp.EndOfMibView {
		t.Errorf("rep0 col B type = %s, want EndOfMibView", pkt.Variables[2].Type)
	}

	// Repetition 1: column A independently chains to pvid.2; column B
	// stays EndOfMibView (filled, not re-queried against pvid.1/.2/...).
	if got := name(3); got != pvidOID2 {
		t.Errorf("rep1 col A = %s, want %s", got, pvidOID2)
	}
	if pkt.Variables[4].Type != gosnmp.EndOfMibView {
		t.Errorf("rep1 col B type = %s, want EndOfMibView (filled)", pkt.Variables[4].Type)
	}

	// Repetition 2: column A chains to pvid.3; column B still filled.
	if got := name(5); got != pvidOID3 {
		t.Errorf("rep2 col A = %s, want %s", got, pvidOID3)
	}
	if pkt.Variables[6].Type != gosnmp.EndOfMibView {
		t.Errorf("rep2 col B type = %s, want EndOfMibView (filled)", pkt.Variables[6].Type)
	}
}

// -- Type round-trips -----------------------------------------------------

func TestSnmpFaceTypeRoundTrips(t *testing.T) {
	st := SeedGSM7252PS()
	addr, _, _ := startFace(t, st)
	g := rawClient(t, addr)

	get1 := func(oid string) gosnmp.SnmpPDU {
		t.Helper()
		pkt, err := g.Get([]string{oid})
		if err != nil {
			t.Fatalf("raw Get(%s) error = %v", oid, err)
		}
		if len(pkt.Variables) != 1 {
			t.Fatalf("raw Get(%s) returned %d varbinds, want 1", oid, len(pkt.Variables))
		}
		return pkt.Variables[0]
	}
	asInt := func(v any) int64 {
		t.Helper()
		switch n := v.(type) {
		case int:
			return int64(n)
		case uint:
			return int64(n)
		case uint32:
			return int64(n)
		case uint64:
			return int64(n)
		case int64:
			return n
		default:
			t.Fatalf("value %v is not an integer type (%T)", v, v)
			return 0
		}
	}

	t.Run("Gauge32 ifHighSpeed", func(t *testing.T) {
		pdu := get1(snmp.IfHighSpeed + ".1") // port 1: 1000 Mbps
		if pdu.Type != gosnmp.Gauge32 {
			t.Errorf("type = %s, want Gauge32", pdu.Type)
		}
		if got := asInt(pdu.Value); got != 1000 {
			t.Errorf("value = %d, want 1000", got)
		}
	})

	t.Run("Counter64 ifHCInOctets", func(t *testing.T) {
		pdu := get1(snmp.IfHCInOctets + ".1") // port 1: 45747246
		if pdu.Type != gosnmp.Counter64 {
			t.Errorf("type = %s, want Counter64", pdu.Type)
		}
		if got := asInt(pdu.Value); got != 45747246 {
			t.Errorf("value = %d, want 45747246", got)
		}
	})

	t.Run("Counter32 ifInErrors", func(t *testing.T) {
		pdu := get1(snmp.IfInErrors + ".1") // port 1: 0
		if pdu.Type != gosnmp.Counter32 {
			t.Errorf("type = %s, want Counter32", pdu.Type)
		}
		if got := asInt(pdu.Value); got != 0 {
			t.Errorf("value = %d, want 0", got)
		}
	})

	t.Run("IpAddress ipAdEntAddr", func(t *testing.T) {
		pdu := get1(snmp.IPAdEntAddr + "." + st.Mgmt.Address)
		if pdu.Type != gosnmp.IPAddress {
			t.Errorf("type = %s, want IPAddress", pdu.Type)
		}
		if got, ok := pdu.Value.(string); !ok || got != st.Mgmt.Address {
			t.Errorf("value = %v, want %q", pdu.Value, st.Mgmt.Address)
		}
	})

	t.Run("OctetString VLAN bitmap bytes", func(t *testing.T) {
		want := st.OIDMap()[snmp.Dot1qVlanStaticEgress+".1"] // VLAN 1 egress bitmap
		pdu := get1(snmp.Dot1qVlanStaticEgress + ".1")
		if pdu.Type != gosnmp.OctetString {
			t.Errorf("type = %s, want OctetString", pdu.Type)
		}
		got, ok := pdu.Value.([]byte)
		if !ok {
			t.Fatalf("value is %T, want []byte", pdu.Value)
		}
		if string(got) != want.Value {
			t.Errorf("bitmap bytes = %x, want %x", got, []byte(want.Value))
		}
	})

	t.Run("vendor PoE delivered power (mW) Gauge32", func(t *testing.T) {
		v := resolveVendorOids(st.mustModel())
		if v == nil {
			t.Fatalf("gsm7252ps unexpectedly has no vendor OIDs")
		}
		pdu := get1(fmt.Sprintf("%s.1.1", v.PoEPowerMw)) // port 1: 3500mW
		if pdu.Type != gosnmp.Gauge32 {
			t.Errorf("type = %s, want Gauge32", pdu.Type)
		}
		if got := asInt(pdu.Value); got != 3500 {
			t.Errorf("value = %d, want 3500", got)
		}
	})
}

// -- SET -------------------------------------------------------------------

func TestSnmpFaceSetSingleVarbindVisibleOnRebuild(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))
	ctx := context.Background()

	oid := snmp.Dot1qPvid + ".1"
	vb, err := snmp.NewSetVarbind(oid, 42, "i")
	if err != nil {
		t.Fatalf("NewSetVarbind: %v", err)
	}
	if err := client.Set(ctx, vb); err != nil {
		t.Fatalf("Set(%s=42) error = %v", oid, err)
	}

	rows, err := client.Get(ctx, []string{oid})
	if err != nil {
		t.Fatalf("Get(%s) after SET error = %v", oid, err)
	}
	if len(rows) != 1 || rows[0].Value != int64(42) {
		t.Errorf("Get(%s) after SET = %+v, want value 42 (state changed + view rebuilt)", oid, rows)
	}
}

// TestSnmpFaceSetIfAliasVisibleOnRebuild is SetSingleVarbindVisibleOnRebuild's
// sibling for ifAlias (the per-port description column, C3 slice): a SET
// with a non-empty OCTET STRING is visible on the next GET, and clearing it
// (an EMPTY OCTET STRING) removes the row entirely -- an absent ifAlias
// instance is how OIDMap/the reader represent "no description", never a
// fabricated empty string.
func TestSnmpFaceSetIfAliasVisibleOnRebuild(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))
	ctx := context.Background()

	oid := snmp.IfAlias + ".1"
	vb, err := snmp.NewSetVarbind(oid, "uplink", "s")
	if err != nil {
		t.Fatalf("NewSetVarbind: %v", err)
	}
	if err := client.Set(ctx, vb); err != nil {
		t.Fatalf("Set(%s=uplink) error = %v", oid, err)
	}

	rows, err := client.Get(ctx, []string{oid})
	if err != nil {
		t.Fatalf("Get(%s) after SET error = %v", oid, err)
	}
	if len(rows) != 1 || rows[0].Value != "uplink" {
		t.Errorf("Get(%s) after SET = %+v, want a single row with value \"uplink\"", oid, rows)
	}

	clearVb, err := snmp.NewSetVarbind(oid, "", "s")
	if err != nil {
		t.Fatalf("NewSetVarbind (clear): %v", err)
	}
	if err := client.Set(ctx, clearVb); err != nil {
		t.Fatalf("Set(%s=\"\") error = %v", oid, err)
	}
	if _, err := client.Get(ctx, []string{oid}); err == nil {
		t.Errorf("Get(%s) after clearing error = nil, want an absent-OID error (NoSuchInstance)", oid)
	}
}

func TestSnmpFaceSetNotWritableOID(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	g := rawClient(t, addr)

	// ifOperStatus is explicitly NOT writable (D-VIRT §1.8).
	oid := snmp.IfOperStatus + ".1"
	pkt, err := g.Set([]gosnmp.SnmpPDU{{Name: oid, Type: gosnmp.Integer, Value: 2}})
	if err != nil {
		t.Fatalf("raw Set(%s) error = %v", oid, err)
	}
	if pkt.Error != gosnmp.NotWritable {
		t.Errorf("Set(%s) error-status = %s, want NotWritable", oid, pkt.Error)
	}
	if pkt.ErrorIndex != 1 {
		t.Errorf("Set(%s) error-index = %d, want 1", oid, pkt.ErrorIndex)
	}
}

// TestSnmpFaceSetMultiVarbindRollsBackOnSecondFailure pins the whole-PDU
// atomicity contract (D-VIRT §3.5): the first varbind (a writable pvid)
// must be applied-then-rolled-back when the second varbind (not writable)
// fails, so a read-back after the failed SET sees the pvid UNCHANGED, and
// the error-index names the SECOND varbind's 1-based position (2).
func TestSnmpFaceSetMultiVarbindRollsBackOnSecondFailure(t *testing.T) {
	st := SeedGSM7252PS()
	originalPvid := st.Pvids[1]
	addr, _, _ := startFace(t, st)
	g := rawClient(t, addr)

	pvidOID := snmp.Dot1qPvid + ".1"
	notWritableOID := snmp.IfOperStatus + ".1"
	pkt, err := g.Set([]gosnmp.SnmpPDU{
		{Name: pvidOID, Type: gosnmp.Gauge32, Value: uint32(777)},
		{Name: notWritableOID, Type: gosnmp.Integer, Value: 2},
	})
	if err != nil {
		t.Fatalf("raw multi-varbind Set() error = %v", err)
	}
	if pkt.Error != gosnmp.NotWritable {
		t.Fatalf("multi-varbind Set() error-status = %s, want NotWritable", pkt.Error)
	}
	if pkt.ErrorIndex != 2 {
		t.Fatalf("multi-varbind Set() error-index = %d, want 2 (the second varbind)", pkt.ErrorIndex)
	}

	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))
	rows, err := client.Get(context.Background(), []string{pvidOID})
	if err != nil {
		t.Fatalf("Get(%s) after failed SET error = %v", pvidOID, err)
	}
	if rows[0].Value != int64(originalPvid) {
		t.Errorf("pvid after failed multi-varbind SET = %v, want unchanged %d (rolled back)", rows[0].Value, originalPvid)
	}
}

// TestSnmpFaceSetOctetStringAgainstIntColumnIsWrongValue pins the
// mustInt Python-SET-parity fix (see mustInt's doc comment in state.go): a
// raw gosnmp SET whose value arrives as an OctetString (not an
// INTEGER-family wire type) against an INTEGER-typed writable column
// (ifAdminStatus) must fail with wrongValue -- exactly like the Python
// face, whose int(value) raises TypeError for a bytes value -- with the
// correct 1-based error-index and the underlying state left UNCHANGED
// (rollback). The before/after values are read back over the wire (not by
// peeking at the face's MibView/State directly), matching every other
// rollback test in this file, since a direct read of server-side state
// from the test goroutine races with the face's own serve goroutine.
func TestSnmpFaceSetOctetStringAgainstIntColumnIsWrongValue(t *testing.T) {
	st := SeedGSM7252PS()
	addr, _, _ := startFace(t, st)
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))
	ctx := context.Background()

	oid := snmp.IfAdminStatus + ".1"
	before, err := client.Get(ctx, []string{oid})
	if err != nil {
		t.Fatalf("Get(%s) before SET error = %v", oid, err)
	}

	g := rawClient(t, addr)
	pkt, err := g.Set([]gosnmp.SnmpPDU{{Name: oid, Type: gosnmp.OctetString, Value: []byte{0x02}}})
	if err != nil {
		t.Fatalf("raw Set(%s, OctetString) error = %v", oid, err)
	}
	if pkt.Error != gosnmp.WrongValue {
		t.Errorf("Set(%s, OctetString) error-status = %s, want WrongValue", oid, pkt.Error)
	}
	if pkt.ErrorIndex != 1 {
		t.Errorf("Set(%s, OctetString) error-index = %d, want 1", oid, pkt.ErrorIndex)
	}

	after, err := client.Get(ctx, []string{oid})
	if err != nil {
		t.Fatalf("Get(%s) after failed SET error = %v", oid, err)
	}
	if after[0].Value != before[0].Value {
		t.Errorf("ifAdminStatus.1 after failed SET = %v, want unchanged %v (rolled back)", after[0].Value, before[0].Value)
	}
}

// -- Community / drop paths ------------------------------------------------

func TestSnmpFaceWrongCommunityTimesOut(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	client := snmp.NewGoSNMPClient(addr, "not-the-community", snmp.WithTimeout(200*time.Millisecond), snmp.WithRetries(0))

	_, err := client.Get(context.Background(), []string{snmp.IfOperStatus + ".1"})
	if err == nil {
		t.Fatalf("Get() with wrong community = nil error, want a timeout (silent drop)")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "timeout") {
		t.Errorf("Get() with wrong community error = %v, want a timeout-shaped error", err)
	}
}

// TestSnmpFaceDropsMalformedPacket writes raw garbage (not a valid BER/SNMP
// packet at all) directly to the face's UDP port and confirms two things:
// no response at all comes back (a short read-deadline times out, it
// doesn't get a reply), and the face is still alive and correctly serving
// a subsequent valid GET -- i.e. decode failure drops that one datagram
// without derailing the serve loop.
func TestSnmpFaceDropsMalformedPacket(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%q): %v", addr, err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer func() { _ = conn.Close() }()

	garbage := []byte{0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03}
	if _, err := conn.Write(garbage); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1024)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("got a response to malformed input (%d bytes), want no response (silently dropped)", n)
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("Read after malformed packet error = %v, want a read-deadline timeout (no response was sent)", err)
		}
	}

	// The serve loop must still be alive and answering correctly afterward
	// -- one malformed datagram must not derail it.
	client := snmp.NewGoSNMPClient(addr, "public", snmp.WithTimeout(2*time.Second))
	rows, err := client.Get(context.Background(), []string{snmp.IfOperStatus + ".1"})
	if err != nil {
		t.Fatalf("Get() after malformed packet error = %v, want the face to still be serving", err)
	}
	if len(rows) != 1 {
		t.Fatalf("Get() after malformed packet returned %d rows, want 1", len(rows))
	}
}

// TestSnmpFaceDropsV1Packet sends a well-formed SNMPv1 GET (via a raw
// gosnmp handle configured for Version1) and confirms it gets no response
// at all -- this mock is deliberately v2c-only (D-VIRT §3.6), so a v1
// request must be silently dropped exactly like a malformed packet or a
// community mismatch, never answered (and never a PDU-level error, which
// would imply the face understood but rejected the version).
func TestSnmpFaceDropsV1Packet(t *testing.T) {
	addr, _, _ := startFace(t, SeedGSM7252PS())
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("ParseUint(%q): %v", portStr, err)
	}
	g := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(port),
		Community: "public",
		Version:   gosnmp.Version1,
		Timeout:   200 * time.Millisecond,
		Retries:   0,
	}
	if err := g.Connect(); err != nil {
		t.Fatalf("raw v1 gosnmp Connect(): %v", err)
	}
	defer func() { _ = g.Close() }()

	_, err = g.Get([]string{snmp.IfOperStatus + ".1"})
	if err == nil {
		t.Fatalf("v1 Get() error = nil, want a timeout (v1 requests are silently dropped -- this mock is v2c-only)")
	}
}

// -- Lifecycle --------------------------------------------------------------

// countOpenFDs returns the number of open file descriptors this process
// currently holds (via /proc/self/fd, Linux-only) and whether that count
// is available at all. On a platform without /proc, ok is false and the
// caller skips the FD assertion rather than failing on an unsupported OS.
func countOpenFDs(t *testing.T) (count int, ok bool) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	return len(entries), true
}

// TestSnmpFaceStartStopCyclesLeakNoGoroutinesOrFDs runs 10 start/stop
// cycles (each with an extra idempotent second Stop) and asserts NEITHER
// the goroutine count nor the open-file-descriptor count (each cycle's UDP
// socket, via /proc/self/fd) grows past the pre-loop baseline -- i.e. every
// bound port and its serve goroutine are actually released, not just that
// Start/Stop return nil.
func TestSnmpFaceStartStopCyclesLeakNoGoroutinesOrFDs(t *testing.T) {
	st := SeedGSM7252PS()
	beforeGoroutines := runtime.NumGoroutine()
	beforeFDs, haveFDs := countOpenFDs(t)

	for i := 0; i < 10; i++ {
		view := NewMibView(st)
		face := NewSnmpFace(view, "public", "127.0.0.1")
		port, err := face.Start()
		if err != nil {
			t.Fatalf("cycle %d: Start() error = %v", i, err)
		}
		if port == 0 {
			t.Fatalf("cycle %d: Start() returned port 0", i)
		}
		if err := face.Stop(); err != nil {
			t.Fatalf("cycle %d: Stop() error = %v", i, err)
		}
		// A second Stop must be a harmless no-op (idempotent).
		if err := face.Stop(); err != nil {
			t.Fatalf("cycle %d: second Stop() error = %v", i, err)
		}
	}

	// Let any just-exited goroutines actually finish unwinding.
	for i := 0; i < 50; i++ {
		if runtime.NumGoroutine() <= beforeGoroutines {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > beforeGoroutines {
		t.Errorf("goroutine count after 10 start/stop cycles = %d, want <= %d (baseline)", after, beforeGoroutines)
	}

	if haveFDs {
		if afterFDs, ok := countOpenFDs(t); ok && afterFDs > beforeFDs {
			t.Errorf("open FD count after 10 start/stop cycles = %d, want <= %d (baseline; every UDP socket must be released)", afterFDs, beforeFDs)
		}
	}
}

func TestSnmpFaceStopBeforeStartIsNoOp(t *testing.T) {
	face := NewSnmpFace(NewMibView(SeedGSM7252PS()), "public", "127.0.0.1")
	if err := face.Stop(); err != nil {
		t.Errorf("Stop() before Start() error = %v, want nil (no-op)", err)
	}
}
