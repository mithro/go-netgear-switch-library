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
	"runtime"
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

// -- Community / lifecycle -------------------------------------------------

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

func TestSnmpFaceStartStopCyclesLeakNoGoroutinesOrPorts(t *testing.T) {
	st := SeedGSM7252PS()
	before := runtime.NumGoroutine()

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
		if runtime.NumGoroutine() <= before {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutine count after 10 start/stop cycles = %d, want <= %d (baseline)", after, before)
	}
}

func TestSnmpFaceStopBeforeStartIsNoOp(t *testing.T) {
	face := NewSnmpFace(NewMibView(SeedGSM7252PS()), "public", "127.0.0.1")
	if err := face.Stop(); err != nil {
		t.Errorf("Stop() before Start() error = %v, want nil (no-op)", err)
	}
}
