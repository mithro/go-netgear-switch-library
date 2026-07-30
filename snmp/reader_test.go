package snmp

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mithro/go-netgear-switch-library/model"
)

// fakeReaderClient serves canned Rows by EXACT walked/get-requested OID (a
// missing key answers an empty walk, mirroring a real agent's
// noSuchObject/empty-subtree response, never a test-harness error), and
// records every OID it was asked for, in order -- the contract every
// Reader method's walk sequence is asserted against below.
type fakeReaderClient struct {
	tables   map[string][]Row
	walked   []string
	getCalls [][]string
}

func newFakeReaderClient(tables map[string][]Row) *fakeReaderClient {
	return &fakeReaderClient{tables: tables}
}

func (f *fakeReaderClient) Get(_ context.Context, oids []string) ([]Row, error) {
	f.getCalls = append(f.getCalls, append([]string(nil), oids...))
	var rows []Row
	for _, oid := range oids {
		rows = append(rows, f.tables[oid]...)
	}
	return rows, nil
}

func (f *fakeReaderClient) Walk(_ context.Context, base string) ([]Row, error) {
	f.walked = append(f.walked, base)
	return append([]Row(nil), f.tables[base]...), nil
}

// mustModel looks up m by key or fails the test, keeping every test call
// site below a one-liner.
func mustModel(t *testing.T, key string) *model.SwitchModel {
	t.Helper()
	m, err := model.GetModel(key)
	if err != nil {
		t.Fatalf("GetModel(%q): %v", key, err)
	}
	return m
}

// fullReaderTables is one table set exercising every Reader method with
// non-vacuous data, mirroring test_snmp_read.py's module-level
// _full_tables(): keyed by the gsm7252ps vendor OID subtree, and
// deliberately WITHOUT a dhcp-mode row (the subtree is walked, never
// get()'d, so its absence must not raise -- see TestGetMgmtIP*).
func fullReaderTables(t *testing.T) map[string][]Row {
	t.Helper()
	vendor, err := GetVendorOids(mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}
	return map[string][]Row{
		IfAdminStatus:           intRows(IfAdminStatus, map[int]int64{1: 1}),
		IfOperStatus:            intRows(IfOperStatus, map[int]int64{1: 1}),
		IfHighSpeed:             intRows(IfHighSpeed, map[int]int64{1: 1000}),
		IfName:                  strRows(IfName, map[int]string{1: "1/0/1"}),
		IfAlias:                 strRows(IfAlias, map[int]string{1: "uplink"}),
		IfHCInOctets:            intRows(IfHCInOctets, map[int]int64{1: 100}),
		IfHCOutOctets:           intRows(IfHCOutOctets, map[int]int64{1: 200}),
		IfHCInUcast:             intRows(IfHCInUcast, map[int]int64{1: 10}),
		IfHCOutUcast:            intRows(IfHCOutUcast, map[int]int64{1: 20}),
		IfInErrors:              intRows(IfInErrors, map[int]int64{1: 0}),
		IfOutErrors:             intRows(IfOutErrors, map[int]int64{1: 0}),
		Dot1qVlanStaticName:     {NewStrRow(Dot1qVlanStaticName+".5", "net")},
		Dot1qVlanStaticEgress:   {NewBytesRow(Dot1qVlanStaticEgress+".5", []byte{0b11000000})},
		Dot1qVlanStaticUntagged: {NewBytesRow(Dot1qVlanStaticUntagged+".5", []byte{0b01000000})},
		Dot1qPvid:               intRows(Dot1qPvid, map[int]int64{1: 5}),
		LldpRemTable: {
			NewStrRow(lldpBase+".9.75.1.7", "sw-cisco-shed"),
			NewStrRow(lldpBase+".8.75.1.7", "1/xg1.uplink"),
			NewStrRow(lldpBase+".7.75.1.7", "1/xg1"),
		},
		Dot1qTpFdbPort:       {NewIntRow(Dot1qTpFdbPort+".5.200.0.132.137.113.112", 1)},
		Dot1dBasePortIfIndex: intRows(Dot1dBasePortIfIndex, map[int]int64{1: 1}),
		PethPsePortTable: {
			NewIntRow(PethPsePortTable+".3.1.1", 1),
			NewIntRow(PethPsePortTable+".6.1.1", 3),
		},
		vendor.PoEPowerMw:  {NewIntRow(vendor.PoEPowerMw+".1.1", 12800)},
		vendor.BoxFan:      {NewStrRow(vendor.BoxFan+".0", "3500")},
		vendor.BoxPSUPower: {NewStrRow(vendor.BoxPSUPower+".0", "45")},
		vendor.BoxTemp:     {NewStrRow(vendor.BoxTemp+".0", "30")},
		IPAdEntAddr:        {NewStrRow(IPAdEntAddr+".10.1.5.20", "10.1.5.20")},
		IPAdEntNetmask:     {NewStrRow(IPAdEntNetmask+".10.1.5.20", "255.255.255.0")},
		IPRouteDest:        {NewStrRow(IPRouteDest+".0.0.0.0", "0.0.0.0")},
		IPRouteNextHop:     {NewStrRow(IPRouteNextHop+".0.0.0.0", "10.1.5.1")},
		Dot1dBaseBridgeAddress: {
			NewBytesRow(Dot1dBaseBridgeAddress+".0", []byte{0x28, 0xC6, 0x8E, 0x00, 0x00, 0x01}),
		},
		// dhcp-mode vendor OID deliberately absent: see fullReaderTables doc.
	}
}

// --- NewReader: the single capability gate -----------------------------

func TestNewReaderRejectsNonSNMPModel(t *testing.T) {
	// gs305ep is Plus-class: NSDP/HTTP only, no SNMP backend at all. The
	// gate must fire in the constructor itself, before any I/O.
	_, err := NewReader(newFakeReaderClient(nil), mustModel(t, "gs305ep"))
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("NewReader error = %v, want ErrUnsupportedCapability", err)
	}
}

func TestNewReaderConstructsForManagedModel(t *testing.T) {
	r, err := NewReader(newFakeReaderClient(nil), mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if r.model.Key != "gsm7252ps" {
		t.Errorf("r.model.Key = %q, want gsm7252ps", r.model.Key)
	}
}

// --- GetPorts ------------------------------------------------------------

func TestGetPortsWalksSixOIDsInOrderAndJoinsFields(t *testing.T) {
	fc := newFakeReaderClient(fullReaderTables(t))
	r, err := NewReader(fc, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	ports, err := r.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts: %v", err)
	}
	want := []string{IfAdminStatus, IfOperStatus, IfHighSpeed, IfName, IfAlias, IfType}
	if diff := cmp.Diff(want, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
	if len(ports) != 1 {
		t.Fatalf("len(ports) = %d, want 1", len(ports))
	}
	if ports[0].Port != 1 {
		t.Errorf("Port = %d, want 1", ports[0].Port)
	}
	if ports[0].SpeedMbps == nil || *ports[0].SpeedMbps != 1000 {
		t.Errorf("SpeedMbps = %v, want 1000", ports[0].SpeedMbps)
	}
	if deref(ports[0].Description) != "uplink" {
		t.Errorf("Description = %q, want uplink", deref(ports[0].Description))
	}
}

// --- GetStats --------------------------------------------------------------

func TestGetStatsWalksSevenOIDsInOrderAndJoinsFields(t *testing.T) {
	fc := newFakeReaderClient(fullReaderTables(t))
	r, err := NewReader(fc, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	stats, err := r.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	want := []string{IfHCInOctets, IfHCOutOctets, IfHCInUcast, IfHCOutUcast, IfInErrors, IfOutErrors, IfType}
	if diff := cmp.Diff(want, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
	if len(stats) != 1 {
		t.Fatalf("len(stats) = %d, want 1", len(stats))
	}
	s := stats[0]
	if s.Port != 1 || s.RxBytes == nil || *s.RxBytes != 100 || s.TxBytes == nil || *s.TxBytes != 200 ||
		s.RxPackets == nil || *s.RxPackets != 10 || s.TxPackets == nil || *s.TxPackets != 20 ||
		s.RxErrors == nil || *s.RxErrors != 0 || s.TxErrors == nil || *s.TxErrors != 0 {
		t.Errorf("stats[0] = %+v, mismatched expected counters", s)
	}
}

// --- GetVLANs / GetPVIDs -----------------------------------------------

func TestGetVLANsWalksThreeOIDsInOrderAndJoinsFields(t *testing.T) {
	fc := newFakeReaderClient(fullReaderTables(t))
	r, err := NewReader(fc, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	vlans, err := r.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs: %v", err)
	}
	want := []string{Dot1qVlanStaticName, Dot1qVlanStaticEgress, Dot1qVlanStaticUntagged}
	if diff := cmp.Diff(want, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
	if len(vlans) != 1 {
		t.Fatalf("len(vlans) = %d, want 1", len(vlans))
	}
	v := vlans[0]
	if v.VlanID != 5 || deref(v.Name) != "net" {
		t.Errorf("vlan = %+v, want VlanID=5 Name=net", v)
	}
	if diff := cmp.Diff([]int{1, 2}, v.MemberPorts); diff != "" {
		t.Errorf("MemberPorts mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]int{2}, v.UntaggedPorts); diff != "" {
		t.Errorf("UntaggedPorts mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]int{1}, v.TaggedPorts); diff != "" {
		t.Errorf("TaggedPorts mismatch (-want +got):\n%s", diff)
	}
}

func TestGetPVIDsWalksTwoOIDsInOrderAndJoinsFields(t *testing.T) {
	fc := newFakeReaderClient(fullReaderTables(t))
	r, err := NewReader(fc, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	pvids, err := r.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs: %v", err)
	}
	want := []string{Dot1qPvid, IfType}
	if diff := cmp.Diff(want, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]model.Pvid{{Port: 1, Vlan: 5}}, pvids); diff != "" {
		t.Errorf("pvids mismatch (-want +got):\n%s", diff)
	}
}

// --- GetLLDP / GetMACs ---------------------------------------------------

func TestGetLLDPWalksOneOIDAndJoinsColumns(t *testing.T) {
	fc := newFakeReaderClient(fullReaderTables(t))
	r, err := NewReader(fc, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	neighbors, err := r.GetLLDP(context.Background())
	if err != nil {
		t.Fatalf("GetLLDP: %v", err)
	}
	if diff := cmp.Diff([]string{LldpRemTable}, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
	if len(neighbors) != 1 {
		t.Fatalf("len(neighbors) = %d, want 1", len(neighbors))
	}
	n := neighbors[0]
	if n.LocalPort != 1 || deref(n.RemoteSysName) != "sw-cisco-shed" ||
		deref(n.RemotePortDesc) != "1/xg1.uplink" || deref(n.RemotePortID) != "1/xg1" {
		t.Errorf("neighbor = %+v, mismatched expected fields", n)
	}
	if deref(n.RemotePortID) == deref(n.RemotePortDesc) {
		t.Errorf("RemotePortID must differ from RemotePortDesc")
	}
}

func TestGetMACsWalksTwoOIDsInOrderAndJoinsFields(t *testing.T) {
	fc := newFakeReaderClient(fullReaderTables(t))
	r, err := NewReader(fc, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	macs, err := r.GetMACs(context.Background())
	if err != nil {
		t.Fatalf("GetMACs: %v", err)
	}
	want := []string{Dot1qTpFdbPort, Dot1dBasePortIfIndex}
	if diff := cmp.Diff(want, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
	if len(macs) != 1 {
		t.Fatalf("len(macs) = %d, want 1", len(macs))
	}
	m := macs[0]
	if m.Mac != "C8:00:84:89:71:70" || m.Port != 1 || m.VlanID == nil || *m.VlanID != 5 {
		t.Errorf("mac = %+v, mismatched expected fields", m)
	}
}

// --- GetPoE: the zero-PSE guard is the parity-critical case -------------

func TestGetPoEWalksTableThenVendorMwAndJoins(t *testing.T) {
	fc := newFakeReaderClient(fullReaderTables(t))
	m := mustModel(t, "gsm7252ps")
	r, err := NewReader(fc, m)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	vendor, err := GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}
	poe, err := r.GetPoE(context.Background())
	if err != nil {
		t.Fatalf("GetPoE: %v", err)
	}
	want := []string{PethPsePortTable, vendor.PoEPowerMw}
	if diff := cmp.Diff(want, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
	if len(poe) != 1 {
		t.Fatalf("len(poe) = %d, want 1", len(poe))
	}
	if poe[0].Detect != model.PoEDetectDelivering {
		t.Errorf("Detect = %v, want Delivering", poe[0].Detect)
	}
	if poe[0].PowerMw == nil || *poe[0].PowerMw != 12800 {
		t.Errorf("PowerMw = %v, want 12800", poe[0].PowerMw)
	}
}

// TestGetPoERaisesForZeroPSEModelBeforeAnyWalk mirrors
// test_get_poe_raises_for_zero_pse_model: m4300-24x has PoEPortCount == 0.
// GetPoE MUST raise UnsupportedCapabilityError -- consistent with the
// CLI/HTTP readers -- and it must raise BEFORE walking, so even a fake that
// would happily answer the PoE table never gets asked.
func TestGetPoERaisesForZeroPSEModelBeforeAnyWalk(t *testing.T) {
	tables := map[string][]Row{
		PethPsePortTable: {NewIntRow(PethPsePortTable+".3.1.1", 1)},
	}
	fc := newFakeReaderClient(tables)
	r, err := NewReader(fc, mustModel(t, "m4300-24x"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	_, err = r.GetPoE(context.Background())
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("GetPoE error = %v, want ErrUnsupportedCapability", err)
	}
	if len(fc.walked) != 0 {
		t.Errorf("walked = %v, want no walks at all (guard must fire before I/O)", fc.walked)
	}
}

// TestGetPoENoVendorOidsLeavesPowerHonestlyNil mirrors the gs728tpp code
// path: a model WITH PoE but no vendor OID subtree walks only the standard
// table, never a vendor mW column, and every port's PowerMw is nil rather
// than fabricated.
func TestGetPoENoVendorOidsLeavesPowerHonestlyNil(t *testing.T) {
	tables := map[string][]Row{
		PethPsePortTable: {
			NewIntRow(PethPsePortTable+".3.1.1", 1),
			NewIntRow(PethPsePortTable+".6.1.1", 3),
		},
	}
	fc := newFakeReaderClient(tables)
	r, err := NewReader(fc, mustModel(t, "gs728tpp"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	poe, err := r.GetPoE(context.Background())
	if err != nil {
		t.Fatalf("GetPoE: %v", err)
	}
	if diff := cmp.Diff([]string{PethPsePortTable}, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
	if len(poe) != 1 || poe[0].PowerMw != nil {
		t.Errorf("poe = %+v, want one port with PowerMw == nil", poe)
	}
}

// --- GetSensors: raise-vs-empty pair is the parity-critical case --------

// TestGetSensorsRaisesWhenClaimedVendorWalkIsEmpty mirrors
// test_get_sensors_raises_when_claimed_vendor_walk_is_empty: gsm7252ps
// declares a vendor sensor subtree (has_vendor_oids true) but every vendor
// column here walks dry -- this must raise, never silently return [].
func TestGetSensorsRaisesWhenClaimedVendorWalkIsEmpty(t *testing.T) {
	m := mustModel(t, "gsm7252ps")
	fc := newFakeReaderClient(nil)
	r, err := NewReader(fc, m)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	vendor, err := GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}
	_, err = r.GetSensors(context.Background())
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("GetSensors error = %v, want ErrUnsupportedCapability", err)
	}
	want := []string{vendor.BoxFan, vendor.BoxPSUPower, vendor.BoxTemp}
	if diff := cmp.Diff(want, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
}

// TestGetSensorsNoVendorBaseEmptyEntityReturnsEmptySlice is the control for
// the raise above: gs728tpp has NO vendor subtree at all, so an empty
// ENTITY-MIB inventory is the honest (never-claimed-anything) case and must
// return [], not an error.
func TestGetSensorsNoVendorBaseEmptyEntityReturnsEmptySlice(t *testing.T) {
	fc := newFakeReaderClient(nil)
	r, err := NewReader(fc, mustModel(t, "gs728tpp"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	sensors, err := r.GetSensors(context.Background())
	if err != nil {
		t.Fatalf("GetSensors: %v", err)
	}
	if len(sensors) != 0 {
		t.Errorf("sensors = %v, want empty", sensors)
	}
	want := []string{EntPhysicalClass, EntPhysicalName, EntPhysicalDescr}
	if diff := cmp.Diff(want, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
}

func TestGetSensorsWalksVendorColumnsInOrderWithData(t *testing.T) {
	m := mustModel(t, "gsm7252ps")
	fc := newFakeReaderClient(fullReaderTables(t))
	r, err := NewReader(fc, m)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	vendor, err := GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}
	sensors, err := r.GetSensors(context.Background())
	if err != nil {
		t.Fatalf("GetSensors: %v", err)
	}
	want := []string{vendor.BoxFan, vendor.BoxPSUPower, vendor.BoxTemp}
	if diff := cmp.Diff(want, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
	kinds := map[string]bool{}
	for _, s := range sensors {
		kinds[s.Kind] = true
	}
	if !kinds["fan"] || !kinds["power"] || !kinds["temperature"] {
		t.Errorf("kinds = %v, want fan+power+temperature all present", kinds)
	}
}

// --- GetMgmtIP: absent DHCP OID must fall to Unknown, never raise -------

func TestGetMgmtIPWalksSevenOIDsAndAbsentDhcpYieldsUnknown(t *testing.T) {
	m := mustModel(t, "gsm7252ps")
	fc := newFakeReaderClient(fullReaderTables(t))
	r, err := NewReader(fc, m)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	vendor, err := GetVendorOids(m)
	if err != nil {
		t.Fatalf("GetVendorOids: %v", err)
	}
	cfg, err := r.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP: %v", err)
	}
	want := []string{
		IPAdEntAddr, IPAdEntNetmask, IPRouteDest, IPRouteNextHop,
		vendor.DHCPModeUnverified, Dot1dBaseBridgeAddress, IPAddressIfIndex,
	}
	if diff := cmp.Diff(want, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
	if deref(cfg.Address) != "10.1.5.20" {
		t.Errorf("Address = %q, want 10.1.5.20", deref(cfg.Address))
	}
	if deref(cfg.Netmask) != "255.255.255.0" {
		t.Errorf("Netmask = %q, want 255.255.255.0", deref(cfg.Netmask))
	}
	if deref(cfg.Gateway) != "10.1.5.1" {
		t.Errorf("Gateway = %q, want 10.1.5.1", deref(cfg.Gateway))
	}
	if cfg.Mode != model.IPModeUnknown {
		t.Errorf("Mode = %v, want Unknown (dhcp OID absent from fake)", cfg.Mode)
	}
	if deref(cfg.BaseMac) != "28:C6:8E:00:00:01" {
		t.Errorf("BaseMac = %q, want 28:C6:8E:00:00:01", deref(cfg.BaseMac))
	}
}

// TestGetMgmtIPNoVendorBaseSkipsDhcpWalkEntirely mirrors the gs728tpp code
// path: a model with no vendor OID subtree never walks a dhcp-mode OID at
// all (only 6 walks), not merely walks one that happens to answer empty.
func TestGetMgmtIPNoVendorBaseSkipsDhcpWalkEntirely(t *testing.T) {
	fc := newFakeReaderClient(nil)
	r, err := NewReader(fc, mustModel(t, "gs728tpp"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	cfg, err := r.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP: %v", err)
	}
	want := []string{
		IPAdEntAddr, IPAdEntNetmask, IPRouteDest, IPRouteNextHop,
		Dot1dBaseBridgeAddress, IPAddressIfIndex,
	}
	if diff := cmp.Diff(want, fc.walked); diff != "" {
		t.Errorf("walked OIDs mismatch (-want +got):\n%s", diff)
	}
	if cfg.Mode != model.IPModeUnknown {
		t.Errorf("Mode = %v, want Unknown", cfg.Mode)
	}
}

// --- ReadSystemInfo / GetSystemInfo --------------------------------------

// systemInfoTables mirrors test_snmp_read.py's _system_info_tables: a
// sysDescr string plus a fixed, NOT-in-SysObjectIDModels sysObjectID, so
// tests using it exercise the sysDescr fallback path exclusively.
func systemInfoTables(sysDescr string) map[string][]Row {
	return map[string][]Row{
		SysDescr:    {NewStrRow(SysDescr, sysDescr)},
		SysObjectID: {NewStrRow(SysObjectID, "1.3.6.1.4.1.4526.10.100.14")},
	}
}

func TestReadSystemInfoIsOnePDUTwoOIDs(t *testing.T) {
	fc := newFakeReaderClient(systemInfoTables("NETGEAR GSM7252PS"))
	if _, err := ReadSystemInfo(context.Background(), fc); err != nil {
		t.Fatalf("ReadSystemInfo: %v", err)
	}
	if len(fc.getCalls) != 1 {
		t.Fatalf("Get called %d times, want exactly 1 (one PDU)", len(fc.getCalls))
	}
	if diff := cmp.Diff([]string{SysDescr, SysObjectID}, fc.getCalls[0]); diff != "" {
		t.Errorf("Get oids mismatch (-want +got):\n%s", diff)
	}
	if len(fc.walked) != 0 {
		t.Errorf("walked = %v, want none (system info is GET-only)", fc.walked)
	}
}

func TestReadSystemInfoMatchesKnownModelViaSysDescr(t *testing.T) {
	fc := newFakeReaderClient(systemInfoTables("NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6"))
	detected, err := ReadSystemInfo(context.Background(), fc)
	if err != nil {
		t.Fatalf("ReadSystemInfo: %v", err)
	}
	if deref(detected.Key) != "gsm7252ps" {
		t.Errorf("Key = %q, want gsm7252ps", deref(detected.Key))
	}
	if !detected.Matched() {
		t.Errorf("Matched() = false, want true")
	}
	if deref(detected.SysDescr) != "NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6" {
		t.Errorf("SysDescr = %q, mismatched", deref(detected.SysDescr))
	}
	if deref(detected.SysObjectID) != "1.3.6.1.4.1.4526.10.100.14" {
		t.Errorf("SysObjectID = %q, mismatched", deref(detected.SysObjectID))
	}
}

// TestReadSystemInfoSysObjectIDMapHitWinsEvenWithUnmatchableSysDescr mirrors
// the real gsm7228ps (S3300-52X-PoE+) capture: its sysDescr text is
// deliberately unmatchable by DetectModelFromSysDescr (same shape as the
// unregistered S3300-28X), so ONLY the sysObjectID map can auto-detect it --
// and it must win even though sysObjectID detection runs first.
func TestReadSystemInfoSysObjectIDMapHitWinsEvenWithUnmatchableSysDescr(t *testing.T) {
	tables := map[string][]Row{
		SysDescr:    {NewStrRow(SysDescr, "S3300-52X-PoE+ 10.5.1.15, VxWorks 6.9")},
		SysObjectID: {NewStrRow(SysObjectID, "1.3.6.1.4.1.4526.100.10.19")},
	}
	fc := newFakeReaderClient(tables)
	detected, err := ReadSystemInfo(context.Background(), fc)
	if err != nil {
		t.Fatalf("ReadSystemInfo: %v", err)
	}
	if deref(detected.Key) != "gsm7228ps" {
		t.Errorf("Key = %q, want gsm7228ps (via sysObjectID map)", deref(detected.Key))
	}
}

// TestReadSystemInfoUnregisteredModelIsHonestlyUnmatched mirrors
// test_read_system_info_unregistered_model_is_honestly_unmatched:
// sysObjectID is read (carried raw) but never used to guess a model when
// it's not in the map; an unregistered Netgear model name in sysDescr must
// come back Key == nil, never coerced onto some other registered model.
func TestReadSystemInfoUnregisteredModelIsHonestlyUnmatched(t *testing.T) {
	fc := newFakeReaderClient(systemInfoTables("NETGEAR M7300-28G"))
	detected, err := ReadSystemInfo(context.Background(), fc)
	if err != nil {
		t.Fatalf("ReadSystemInfo: %v", err)
	}
	if detected.Key != nil {
		t.Errorf("Key = %v, want nil", *detected.Key)
	}
	if detected.Matched() {
		t.Errorf("Matched() = true, want false")
	}
	if deref(detected.SysDescr) != "NETGEAR M7300-28G" {
		t.Errorf("SysDescr = %q, mismatched", deref(detected.SysDescr))
	}
	if deref(detected.SysObjectID) != "1.3.6.1.4.1.4526.10.100.14" {
		t.Errorf("SysObjectID = %q, mismatched", deref(detected.SysObjectID))
	}
}

func TestReadSystemInfoNoReplyAtAllIsHonestlyUnmatched(t *testing.T) {
	fc := newFakeReaderClient(nil)
	detected, err := ReadSystemInfo(context.Background(), fc)
	if err != nil {
		t.Fatalf("ReadSystemInfo: %v", err)
	}
	if detected.Key != nil || detected.SysDescr != nil || detected.SysObjectID != nil {
		t.Errorf("detected = %+v, want all-nil", detected)
	}
}

func TestReaderGetSystemInfoReusesReadersClient(t *testing.T) {
	fc := newFakeReaderClient(systemInfoTables("NETGEAR GSM7252PS"))
	r, err := NewReader(fc, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	detected, err := r.GetSystemInfo(context.Background())
	if err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}
	if deref(detected.Key) != "gsm7252ps" {
		t.Errorf("Key = %q, want gsm7252ps", deref(detected.Key))
	}
}

// TestReaderGetSystemInfoIsIndependentOfBoundModel mirrors
// test_async_snmp_reader_get_system_info_is_independent_of_bound_model:
// GetSystemInfo reflects what the DEVICE reports, not what model the
// Reader happens to be constructed with -- a Reader (mis)bound to
// gsm7252ps against a device that reports GS110EMX must still detect
// gs110emx.
func TestReaderGetSystemInfoIsIndependentOfBoundModel(t *testing.T) {
	fc := newFakeReaderClient(systemInfoTables("NETGEAR GS110EMX"))
	r, err := NewReader(fc, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	detected, err := r.GetSystemInfo(context.Background())
	if err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}
	if deref(detected.Key) != "gs110emx" {
		t.Errorf("Key = %q, want gs110emx", deref(detected.Key))
	}
}

// --- Full end-to-end: every method against one non-vacuous table set ----

// TestReaderFullTablesEndToEnd mirrors test_get_*_via_reader collectively:
// one fake table set, every Reader method invoked, none vacuously empty.
func TestReaderFullTablesEndToEnd(t *testing.T) {
	fc := newFakeReaderClient(fullReaderTables(t))
	r, err := NewReader(fc, mustModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	ctx := context.Background()

	ports, err := r.GetPorts(ctx)
	if err != nil || len(ports) == 0 {
		t.Fatalf("GetPorts: ports=%v err=%v", ports, err)
	}
	stats, err := r.GetStats(ctx)
	if err != nil || len(stats) == 0 {
		t.Fatalf("GetStats: stats=%v err=%v", stats, err)
	}
	vlans, err := r.GetVLANs(ctx)
	if err != nil || len(vlans) == 0 {
		t.Fatalf("GetVLANs: vlans=%v err=%v", vlans, err)
	}
	pvids, err := r.GetPVIDs(ctx)
	if err != nil || len(pvids) == 0 {
		t.Fatalf("GetPVIDs: pvids=%v err=%v", pvids, err)
	}
	lldp, err := r.GetLLDP(ctx)
	if err != nil || len(lldp) == 0 {
		t.Fatalf("GetLLDP: lldp=%v err=%v", lldp, err)
	}
	macs, err := r.GetMACs(ctx)
	if err != nil || len(macs) == 0 {
		t.Fatalf("GetMACs: macs=%v err=%v", macs, err)
	}
	poe, err := r.GetPoE(ctx)
	if err != nil || len(poe) == 0 {
		t.Fatalf("GetPoE: poe=%v err=%v", poe, err)
	}
	sensors, err := r.GetSensors(ctx)
	if err != nil || len(sensors) == 0 {
		t.Fatalf("GetSensors: sensors=%v err=%v", sensors, err)
	}
	mgmtIP, err := r.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP: %v", err)
	}
	if mgmtIP.Mode != model.IPModeUnknown || deref(mgmtIP.Address) != "10.1.5.20" {
		t.Fatalf("GetMgmtIP = %+v, mismatched expected values", mgmtIP)
	}
}
