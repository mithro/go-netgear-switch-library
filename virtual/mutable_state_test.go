package virtual

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// newWritableFixture builds a small gsm7252ps-keyed state with just enough
// seeded rows to exercise every ApplyWrite/IsWritableOID branch -- mirrors
// the shape of the Python reference's seed_gsm7252ps() fixture without
// depending on the seed package (out of this task's scope; seeds land in a
// later slice).
func newWritableFixture() *State {
	st := NewState("gsm7252ps")
	st.Ports[1] = NewPortSim("1/0/1", true, true, 1000)
	st.Ports[3] = NewPortSim("1/0/3", true, true, 1000)
	st.Poe[1] = &PoeSim{Admin: true, Detect: 3, PowerMw: 3500}
	st.Vlans[90] = &VlanSim{
		Name:     "iot",
		Member:   map[int]bool{1: true, 2: true, 10: true},
		Untagged: map[int]bool{},
	}
	st.Mgmt = MgmtSim{Address: "10.1.5.22", Netmask: "255.255.255.0", Gateway: "10.1.5.1", Mode: "static"}
	return st
}

func TestApplyWritePoeAdminOffSetsDetectAndLinkDown(t *testing.T) {
	st := newWritableFixture()
	if !st.Poe[1].Admin || st.Poe[1].Detect != 3 {
		t.Fatalf("fixture precondition failed: %+v", st.Poe[1])
	}

	st.ApplyWrite(fmt.Sprintf("%s.3.1.1", snmp.PethPsePortTable), 2) // admin disable
	if st.Poe[1].Admin {
		t.Error("expected admin false after disable write")
	}
	if st.Poe[1].Detect != 1 {
		t.Errorf("Detect = %d, want 1 (unused/disabled)", st.Poe[1].Detect)
	}
	if st.Ports[1].Link {
		t.Error("coherence rule: port link must drop when PoE admin goes off")
	}

	st.ApplyWrite(fmt.Sprintf("%s.3.1.1", snmp.PethPsePortTable), 1) // admin enable
	if !st.Poe[1].Admin {
		t.Error("expected admin true after enable write")
	}
	if st.Poe[1].Detect != 3 {
		t.Errorf("Detect = %d, want 3 (delivering)", st.Poe[1].Detect)
	}
}

func TestApplyWriteIfAdminAndPvid(t *testing.T) {
	st := newWritableFixture()

	st.ApplyWrite(fmt.Sprintf("%s.3", snmp.IfAdminStatus), 2)
	if st.Ports[3].Admin {
		t.Error("expected admin false")
	}
	if st.Ports[3].Link {
		t.Error("coherence rule: admin-down must also clear link")
	}

	st.ApplyWrite(fmt.Sprintf("%s.10", snmp.Dot1qPvid), 90)
	if st.Pvids[10] != 90 {
		t.Errorf("Pvids[10] = %d, want 90", st.Pvids[10])
	}
}

func TestApplyWriteVlanMembershipRMWAndRowStatus(t *testing.T) {
	st := newWritableFixture()

	newEgress := snmp.EncodePortBitmap([]int{1, 2, 10, 25}, 8)
	st.ApplyWrite(fmt.Sprintf("%s.90", snmp.Dot1qVlanStaticEgress), newEgress)
	memberBitmap := snmp.EncodePortBitmap(sliceFromPortSet(st.Vlans[90].Member), 8)
	got := snmp.DecodePortBitmap(memberBitmap)
	if diff := cmp.Diff([]int{1, 2, 10, 25}, got); diff != "" {
		t.Errorf("vlan 90 member mismatch after RMW (-want +got):\n%s", diff)
	}

	// Create VLAN 200 via RowStatus createAndGo, then a name write.
	rowStatusOID := fmt.Sprintf("%s.200", snmp.Dot1qVlanStaticRowStatus)
	st.ApplyWrite(rowStatusOID, snmp.RowStatusCreateAndGo)
	if _, exists := st.Vlans[200]; !exists {
		t.Fatal("expected vlan 200 created by RowStatus createAndGo")
	}
	st.ApplyWrite(fmt.Sprintf("%s.200", snmp.Dot1qVlanStaticName), []byte("guests"))
	if st.Vlans[200].Name != "guests" {
		t.Errorf("Vlans[200].Name = %q, want guests", st.Vlans[200].Name)
	}

	// Destroy it.
	st.ApplyWrite(rowStatusOID, snmp.RowStatusDestroy)
	if _, exists := st.Vlans[200]; exists {
		t.Error("expected vlan 200 destroyed by RowStatus destroy")
	}
}

func TestApplyWriteVlanNameAloneAutoCreatesRow(t *testing.T) {
	st := newWritableFixture()
	if _, exists := st.Vlans[300]; exists {
		t.Fatal("fixture precondition: vlan 300 must not pre-exist")
	}
	st.ApplyWrite(fmt.Sprintf("%s.300", snmp.Dot1qVlanStaticName), "lab")
	vl, exists := st.Vlans[300]
	if !exists {
		t.Fatal("expected a name write alone to create the vlan row")
	}
	if vl.Name != "lab" {
		t.Errorf("Vlans[300].Name = %q, want lab", vl.Name)
	}
}

func TestApplyWriteMgmtIPUpdatesReadProjection(t *testing.T) {
	st := newWritableFixture()
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatal(err)
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		t.Fatal(err)
	}

	st.ApplyWrite(vo.MgmtWriteAddrUnverified, "10.9.9.9")
	if st.Mgmt.Address != "10.9.9.9" {
		t.Errorf("Mgmt.Address = %q, want 10.9.9.9", st.Mgmt.Address)
	}
	found := false
	for k := range st.OIDMap() {
		if len(k) >= len(snmp.IPAdEntAddr+".10.9.9.9") && k[:len(snmp.IPAdEntAddr+".10.9.9.9")] == snmp.IPAdEntAddr+".10.9.9.9" {
			found = true
		}
	}
	if !found {
		t.Error("expected the new address to appear in the ipAdEntAddr read projection")
	}

	st.ApplyWrite(vo.MgmtWriteNetmaskUnverified, "255.255.0.0")
	if st.Mgmt.Netmask != "255.255.0.0" {
		t.Errorf("Mgmt.Netmask = %q, want 255.255.0.0", st.Mgmt.Netmask)
	}
	st.ApplyWrite(vo.MgmtWriteGatewayUnverified, "10.9.9.1")
	if st.Mgmt.Gateway != "10.9.9.1" {
		t.Errorf("Mgmt.Gateway = %q, want 10.9.9.1", st.Mgmt.Gateway)
	}
}

func TestApplyWriteDhcpModeUpdatesReadProjection(t *testing.T) {
	st := newWritableFixture()
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatal(err)
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		t.Fatal(err)
	}

	if st.Mgmt.Mode != "static" {
		t.Fatalf("fixture precondition: Mgmt.Mode = %q, want static", st.Mgmt.Mode)
	}
	if got := st.OIDMap()[vo.DHCPModeUnverified+".0"]; got != (OIDEntry{"INTEGER", "2"}) {
		t.Errorf("dhcp-mode projection = %+v, want static (2)", got)
	}

	st.ApplyWrite(vo.DHCPModeUnverified+".0", 1) // 1 = dhcp
	if st.Mgmt.Mode != "dhcp" {
		t.Errorf("Mgmt.Mode = %q, want dhcp", st.Mgmt.Mode)
	}
	if got := st.OIDMap()[vo.DHCPModeUnverified+".0"]; got != (OIDEntry{"INTEGER", "1"}) {
		t.Errorf("dhcp-mode projection = %+v, want dhcp (1)", got)
	}

	st.ApplyWrite(vo.DHCPModeUnverified+".0", 2) // 2 = static
	if st.Mgmt.Mode != "static" {
		t.Errorf("Mgmt.Mode = %q, want static", st.Mgmt.Mode)
	}
	if got := st.OIDMap()[vo.DHCPModeUnverified+".0"]; got != (OIDEntry{"INTEGER", "2"}) {
		t.Errorf("dhcp-mode projection = %+v, want static (2)", got)
	}
}

// TestApplyWriteSyslogAdminModeUpdatesReadProjection mirrors
// TestApplyWriteDhcpModeUpdatesReadProjection's shape for the syslog
// admin-mode column SetSyslogEnabled writes.
func TestApplyWriteSyslogAdminModeUpdatesReadProjection(t *testing.T) {
	st := newWritableFixture()
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatal(err)
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		t.Fatal(err)
	}

	if st.Syslog.AdminMode != 2 {
		t.Fatalf("fixture precondition: Syslog.AdminMode = %d, want 2 (NewState default)", st.Syslog.AdminMode)
	}
	if got := st.OIDMap()[vo.SyslogAdminMode]; got != (OIDEntry{"INTEGER", "2"}) {
		t.Errorf("syslog admin-mode projection = %+v, want disabled (2)", got)
	}

	st.ApplyWrite(vo.SyslogAdminMode, 1) // 1 = enabled
	if st.Syslog.AdminMode != 1 {
		t.Errorf("Syslog.AdminMode = %d, want 1", st.Syslog.AdminMode)
	}
	if got := st.OIDMap()[vo.SyslogAdminMode]; got != (OIDEntry{"INTEGER", "1"}) {
		t.Errorf("syslog admin-mode projection = %+v, want enabled (1)", got)
	}

	st.ApplyWrite(vo.SyslogAdminMode, 2) // 2 = disabled
	if st.Syslog.AdminMode != 2 {
		t.Errorf("Syslog.AdminMode = %d, want 2", st.Syslog.AdminMode)
	}
}

// TestApplyWriteUnhandledOIDIsSilentNoOp is the documented contract: an OID
// that matches no dispatch branch (or a known column whose instance
// doesn't exist) is a no-op at the state layer -- a verify-after-write
// (GET after SET) is what must catch it.
func TestApplyWriteUnhandledOIDIsSilentNoOp(t *testing.T) {
	st := newWritableFixture()
	before := st.OIDMap()

	st.ApplyWrite("1.2.3.4.5", 1)                                          // nothing matches
	st.ApplyWrite(fmt.Sprintf("%s.9999", snmp.IfAdminStatus), 2)           // known column, absent port
	st.ApplyWrite(fmt.Sprintf("%s.9999", snmp.PethPsePortTable+".3.1"), 2) // PoE column, absent port

	after := st.OIDMap()
	if diff := cmp.Diff(before, after); diff != "" {
		t.Errorf("unhandled/absent-instance writes mutated the read projection (-before +after):\n%s", diff)
	}
}

func TestIsWritableOIDRecognizesKnownColumnsAndScalars(t *testing.T) {
	st := newWritableFixture()
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatal(err)
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		t.Fatal(err)
	}

	trueCases := []string{
		fmt.Sprintf("%s.3", snmp.IfAdminStatus),
		fmt.Sprintf("%s.3.1.1", snmp.PethPsePortTable),
		fmt.Sprintf("%s.10", snmp.Dot1qPvid),
		fmt.Sprintf("%s.90", snmp.Dot1qVlanStaticEgress),
		fmt.Sprintf("%s.90", snmp.Dot1qVlanStaticUntagged),
		// A not-yet-existing VLAN row is still a recognized writable
		// column (RowStatus createAndGo must be allowed through).
		fmt.Sprintf("%s.300", snmp.Dot1qVlanStaticRowStatus),
		fmt.Sprintf("%s.300", snmp.Dot1qVlanStaticName),
		vo.MgmtWriteAddrUnverified,
		vo.MgmtWriteNetmaskUnverified,
		vo.MgmtWriteGatewayUnverified,
		vo.DHCPModeUnverified + ".0",
		vo.SyslogAdminMode,
	}
	for _, oid := range trueCases {
		if !st.IsWritableOID(oid) {
			t.Errorf("IsWritableOID(%q) = false, want true", oid)
		}
	}

	falseCases := []string{
		"1.2.3.4.5",
		fmt.Sprintf("%s.1", snmp.IfOperStatus), // read-only counter
	}
	for _, oid := range falseCases {
		if st.IsWritableOID(oid) {
			t.Errorf("IsWritableOID(%q) = true, want false", oid)
		}
	}
}

func TestIsWritableOIDNoVendorModelShortCircuits(t *testing.T) {
	st := NewState("gs728tpp") // SNMPVendorBase == "" -- no vendor subtree.

	if !st.IsWritableOID(fmt.Sprintf("%s.1", snmp.IfAdminStatus)) {
		t.Error("standard-MIB columns must stay writable on a no-vendor model")
	}
	// A plausible-looking vendor mgmt-IP OID under the fully-managed
	// subtree must NOT be accepted by a model with no vendor subtree at
	// all -- the v == nil short-circuit must return false for everything
	// past the standard-MIB column checks.
	if st.IsWritableOID("1.3.6.1.4.1.4526.10.98.1") {
		t.Error("no-vendor model must not recognize any vendor mgmt-IP/dhcp-mode OID as writable")
	}
}

func TestApplyWriteVendorWritesNoOpOnNoVendorModel(t *testing.T) {
	// A no-vendor model's SNMP mgmt-IP write path is honestly
	// UnsupportedCapabilityError at a higher layer; at the state layer, an
	// OID matching the shape of a vendor mgmt write is simply unhandled
	// (falls through every branch) and is a silent no-op like any other
	// unrecognized OID.
	st := NewState("gs728tpp")
	before := st.OIDMap()
	st.ApplyWrite("1.3.6.1.4.1.4526.10.98.1", "10.9.9.9")
	after := st.OIDMap()
	if diff := cmp.Diff(before, after); diff != "" {
		t.Errorf("vendor-shaped write must no-op on a no-vendor model (-before +after):\n%s", diff)
	}
}

// TestApplyWriteAcceptsAlternateIntLikeValueTypes exercises mustInt's full
// int/str union (mirroring Python's permissive int(value) over the same
// union ApplyWrite accepts), not just the plain `int` literals the other
// tests use. []byte is deliberately NOT in this union -- see
// TestMustIntRejectsByteSlice and mustInt's doc comment: Python's int(value)
// raises TypeError for a bytes argument, so mustInt panics there too.
func TestApplyWriteAcceptsAlternateIntLikeValueTypes(t *testing.T) {
	cases := []struct {
		name  string
		value any
	}{
		{"int", 2},
		{"int32", int32(2)},
		{"int64", int64(2)},
		{"uint", uint(2)},
		{"uint32", uint32(2)},
		{"uint64", uint64(2)},
		{"byte", byte(2)},
		{"numeric string", "2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := newWritableFixture()
			st.ApplyWrite(fmt.Sprintf("%s.3", snmp.IfAdminStatus), c.value)
			if st.Ports[3].Admin {
				t.Errorf("value %v (%T): expected admin false (2 = down)", c.value, c.value)
			}
		})
	}
}

// TestApplyWriteVlanNameAcceptsStringAndBytes exercises asString/asBytes's
// []byte-vs-string handling for the VLAN-name write branch.
func TestApplyWriteVlanNameAcceptsStringAndBytes(t *testing.T) {
	st := newWritableFixture()
	st.ApplyWrite(fmt.Sprintf("%s.90", snmp.Dot1qVlanStaticName), "iot-renamed")
	if st.Vlans[90].Name != "iot-renamed" {
		t.Errorf("string-valued name write: Vlans[90].Name = %q", st.Vlans[90].Name)
	}
	st.ApplyWrite(fmt.Sprintf("%s.90", snmp.Dot1qVlanStaticName), []byte("iot-bytes"))
	if st.Vlans[90].Name != "iot-bytes" {
		t.Errorf("[]byte-valued name write: Vlans[90].Name = %q", st.Vlans[90].Name)
	}
}

func TestMustIntPanicsOnUnconvertibleValue(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected mustInt to panic on an unconvertible value")
		}
	}()
	mustInt("some.oid", struct{}{})
}

// TestMustIntRejectsByteSlice pins the Python-parity fix: a single-byte
// []byte value (the shape an OctetString-typed SET carries) must panic,
// even though it looks superficially int-convertible, because Python's
// int(value) raises TypeError for a bytes argument rather than coercing it.
// See mustInt's doc comment and TestSnmpFaceSetOctetStringAgainstIntColumnIsWrongValue
// for the face-level (wrongValue + rollback) consequence of this.
func TestMustIntRejectsByteSlice(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected mustInt to panic on a []byte value (Python int(bytes) raises TypeError)")
		}
	}()
	mustInt("some.oid", []byte{2})
}

func TestAsBytesAcceptsIntAndPanicsOnUnconvertibleValue(t *testing.T) {
	if diff := cmp.Diff([]byte{0x07}, asBytes("some.oid", 7)); diff != "" {
		t.Errorf("asBytes(int) mismatch (-want +got):\n%s", diff)
	}
	defer func() {
		if recover() == nil {
			t.Error("expected asBytes to panic on an unconvertible value")
		}
	}()
	asBytes("some.oid", struct{}{})
}
