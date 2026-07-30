package virtual

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

func TestNewStateDefaults(t *testing.T) {
	st := NewState("gsm7252ps")

	if st.ModelKey != "gsm7252ps" {
		t.Errorf("ModelKey = %q, want gsm7252ps", st.ModelKey)
	}
	if st.NsdpPassword != "password" {
		t.Errorf("NsdpPassword = %q, want password", st.NsdpPassword)
	}
	wantMac := [6]byte{0x28, 0xc6, 0x8e, 0x00, 0x00, 0x01}
	if st.NsdpMac != wantMac {
		t.Errorf("NsdpMac = %x, want %x", st.NsdpMac, wantMac)
	}
	wantMgmt := MgmtSim{Address: "0.0.0.0", Netmask: "0.0.0.0", Gateway: "0.0.0.0", Mode: "dhcp"}
	if st.Mgmt != wantMgmt {
		t.Errorf("Mgmt = %+v, want %+v", st.Mgmt, wantMgmt)
	}
	if st.Ports == nil || st.Vlans == nil || st.Pvids == nil || st.Poe == nil || st.BridgePorts == nil {
		t.Error("expected every map field to start non-nil")
	}
	if st.Sensors == nil || st.EntityComponents == nil || st.Macs == nil || st.Lldp == nil {
		t.Error("expected every slice field to start non-nil")
	}
	if st.HTTPSensors != nil {
		t.Error("HTTPSensors should default to nil (unseeded/agrees-with-SNMP sentinel)")
	}
	if st.Dot1dBaseMacASCII {
		t.Error("Dot1dBaseMacASCII should default to false")
	}
	// NSDP-extra fields default unseeded (nil).
	if st.NsdpQosEngine != nil || st.NsdpPortMirroringDest != nil || st.NsdpIgmpSnoopingEnabled != nil ||
		st.NsdpIgmpSnoopingVlan != nil || st.NsdpBroadcastFiltering != nil || st.NsdpLoopDetection != nil {
		t.Error("expected every NSDP-extra pointer field to default nil (unseeded)")
	}
	if st.UploadedCert != nil || st.ScpCertDeploy != nil {
		t.Error("expected HTTP/CLI-only fields to default nil")
	}
}

func TestNewPortSimDefaultIfType(t *testing.T) {
	p := NewPortSim("1/0/1", true, true, 1000)
	if p.IfType != 6 {
		t.Errorf("IfType = %d, want 6 (ethernetCsmacd)", p.IfType)
	}
	if p.Name != "1/0/1" || !p.Admin || !p.Link || p.Speed != 1000 {
		t.Errorf("unexpected fields: %+v", p)
	}
}

func TestSysinfoSensorsFallsBackToSensors(t *testing.T) {
	st := NewState("gsm7252ps")
	st.Sensors = []SensorSim{{Kind: "fan", Instance: "0", Raw: "2850"}}
	if diff := cmp.Diff(st.Sensors, st.SysinfoSensors()); diff != "" {
		t.Errorf("SysinfoSensors mismatch (-sensors +sysinfo):\n%s", diff)
	}

	st.HTTPSensors = []SensorSim{{Kind: "temperature", Instance: "0", Raw: "29"}}
	if diff := cmp.Diff(st.HTTPSensors, st.SysinfoSensors()); diff != "" {
		t.Errorf("SysinfoSensors mismatch when HTTPSensors set (-http +sysinfo):\n%s", diff)
	}
}

func TestOIDMapBaseMacRawBytes(t *testing.T) {
	st := NewState("gsm7252ps")
	st.NsdpMac = [6]byte{0xe0, 0x91, 0xf5, 0x0c, 0xd6, 0xdb}

	got := st.OIDMap()[snmp.Dot1dBaseBridgeAddress+".0"]
	want := OIDEntry{SnmpType: "OCTETSTR", Value: string(st.NsdpMac[:])}
	if got != want {
		t.Errorf("base MAC entry = %+v, want %+v", got, want)
	}
	if len(got.Value) != 6 {
		t.Errorf("raw base MAC value length = %d, want 6", len(got.Value))
	}
}

func TestOIDMapBaseMacASCIIQuirk(t *testing.T) {
	st := NewState("m4300-24x")
	st.NsdpMac = [6]byte{0x8c, 0x3b, 0xad, 0x6b, 0xbb, 0xe0}
	st.Dot1dBaseMacASCII = true

	got := st.OIDMap()[snmp.Dot1dBaseBridgeAddress+".0"]
	want := OIDEntry{SnmpType: "OCTETSTR", Value: "8C:3B:AD:6B:BB:E0"}
	if got != want {
		t.Errorf("ASCII base MAC entry = %+v, want %+v", got, want)
	}
	if len(got.Value) != 17 {
		t.Errorf("ASCII base MAC length = %d, want 17", len(got.Value))
	}
}

func TestOIDMapSysDescrFallback(t *testing.T) {
	st := NewState("gsm7252ps")
	got := st.OIDMap()[snmp.SysDescr]
	want := OIDEntry{SnmpType: "OCTETSTR", Value: "Netgear GSM7252PS"}
	if got != want {
		t.Errorf("sysDescr fallback = %+v, want %+v", got, want)
	}

	st.SysDescr = "NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6"
	got = st.OIDMap()[snmp.SysDescr]
	if got.Value != st.SysDescr {
		t.Errorf("sysDescr override = %q, want %q", got.Value, st.SysDescr)
	}
}

func TestOIDMapSysObjectIDFallbackVendor(t *testing.T) {
	st := NewState("gsm7252ps")
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatal(err)
	}
	vo, err := snmp.GetVendorOids(m)
	if err != nil {
		t.Fatal(err)
	}

	got := st.OIDMap()[snmp.SysObjectID]
	want := OIDEntry{SnmpType: "OID", Value: vo.Base + ".1"}
	if got != want {
		t.Errorf("sysObjectID vendor fallback = %+v, want %+v", got, want)
	}

	st.SysObjectID = "1.3.6.1.4.1.4526.10.100.14"
	got = st.OIDMap()[snmp.SysObjectID]
	if got.Value != st.SysObjectID {
		t.Errorf("sysObjectID override = %q, want %q", got.Value, st.SysObjectID)
	}
}

func TestOIDMapSysObjectIDFallbackNoVendor(t *testing.T) {
	st := NewState("gs728tpp") // SNMPVendorBase == "" -- no vendor subtree.
	got := st.OIDMap()[snmp.SysObjectID]
	want := OIDEntry{SnmpType: "OID", Value: "1.3.6.1.2.1"}
	if got != want {
		t.Errorf("sysObjectID no-vendor fallback = %+v, want %+v", got, want)
	}
}

func TestOIDMapPortRowsAbsentCountersAndDescription(t *testing.T) {
	st := NewState("gsm7252ps")
	st.Ports[6] = NewPortSim("1/0/6", true, false, 0) // all counters/description nil

	m := st.OIDMap()
	if _, ok := m[colKey(snmp.IfAlias, 6)]; ok {
		t.Error("ifAlias row present for nil Description; want absent")
	}
	for _, base := range []string{snmp.IfHCInOctets, snmp.IfHCOutOctets, snmp.IfHCInUcast, snmp.IfHCOutUcast, snmp.IfInErrors, snmp.IfOutErrors} {
		if _, ok := m[colKey(base, 6)]; ok {
			t.Errorf("stat row %s present for nil counter; want absent", base)
		}
	}
	if got := m[colKey(snmp.IfAdminStatus, 6)]; got != (OIDEntry{"INTEGER", "1"}) {
		t.Errorf("ifAdminStatus = %+v, want up", got)
	}
	if got := m[colKey(snmp.IfOperStatus, 6)]; got != (OIDEntry{"INTEGER", "2"}) {
		t.Errorf("ifOperStatus = %+v, want down", got)
	}
}

func TestOIDMapPortRowsAllColumnsPresent(t *testing.T) {
	st := NewState("gsm7252ps")
	desc := "uplink-to-core"
	rx, tx, rxu, txu, rxe, txe := uint64(45747246), uint64(912689098), uint64(217358), uint64(235430), uint64(1), uint64(2)
	st.Ports[1] = &PortSim{
		Name: "1/0/1", Admin: true, Link: true, Speed: 1000, IfType: 6,
		RxOctets: &rx, TxOctets: &tx, RxUcast: &rxu, TxUcast: &txu, RxErrors: &rxe, TxErrors: &txe,
		Description: &desc,
	}

	m := st.OIDMap()
	cases := []struct {
		key  string
		want OIDEntry
	}{
		{colKey(snmp.IfAdminStatus, 1), OIDEntry{"INTEGER", "1"}},
		{colKey(snmp.IfOperStatus, 1), OIDEntry{"INTEGER", "1"}},
		{colKey(snmp.IfHighSpeed, 1), OIDEntry{"Gauge32", "1000"}},
		{colKey(snmp.IfType, 1), OIDEntry{"INTEGER", "6"}},
		{colKey(snmp.IfName, 1), OIDEntry{"OCTETSTR", "1/0/1"}},
		{colKey(snmp.IfAlias, 1), OIDEntry{"OCTETSTR", "uplink-to-core"}},
		{colKey(snmp.IfHCInOctets, 1), OIDEntry{"Counter64", "45747246"}},
		{colKey(snmp.IfHCOutOctets, 1), OIDEntry{"Counter64", "912689098"}},
		{colKey(snmp.IfHCInUcast, 1), OIDEntry{"Counter64", "217358"}},
		{colKey(snmp.IfHCOutUcast, 1), OIDEntry{"Counter64", "235430"}},
		{colKey(snmp.IfInErrors, 1), OIDEntry{"Counter32", "1"}},
		{colKey(snmp.IfOutErrors, 1), OIDEntry{"Counter32", "2"}},
	}
	for _, c := range cases {
		if got := m[c.key]; got != c.want {
			t.Errorf("%s = %+v, want %+v", c.key, got, c.want)
		}
	}
}

func TestOIDMapVlanRows(t *testing.T) {
	st := NewState("gsm7252ps") // 52 ports -> vlanBitmapWidth == 8
	st.Vlans[90] = &VlanSim{
		Name:     "iot",
		Member:   map[int]bool{1: true, 2: true, 10: true},
		Untagged: map[int]bool{1: true},
	}

	m := st.OIDMap()
	if got := m[colKey(snmp.Dot1qVlanStaticName, 90)]; got != (OIDEntry{"OCTETSTR", "iot"}) {
		t.Errorf("vlan name = %+v", got)
	}
	egress := m[colKey(snmp.Dot1qVlanStaticEgress, 90)]
	if egress.SnmpType != "OCTETSTR" {
		t.Errorf("egress type = %q, want OCTETSTR", egress.SnmpType)
	}
	if len(egress.Value) != 8 {
		t.Errorf("egress bitmap width = %d, want 8", len(egress.Value))
	}
	gotPorts := snmp.DecodePortBitmap([]byte(egress.Value))
	if diff := cmp.Diff([]int{1, 2, 10}, gotPorts); diff != "" {
		t.Errorf("egress bitmap round-trip mismatch (-want +got):\n%s", diff)
	}
	untagged := m[colKey(snmp.Dot1qVlanStaticUntagged, 90)]
	if diff := cmp.Diff([]int{1}, snmp.DecodePortBitmap([]byte(untagged.Value))); diff != "" {
		t.Errorf("untagged bitmap round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestOIDMapPvidRows(t *testing.T) {
	st := NewState("gsm7252ps")
	st.Pvids[10] = 90
	got := st.OIDMap()[colKey(snmp.Dot1qPvid, 10)]
	want := OIDEntry{"Gauge32", "90"}
	if got != want {
		t.Errorf("pvid row = %+v, want %+v", got, want)
	}
}

func TestOIDMapPoeRowsWithVendor(t *testing.T) {
	st := NewState("gsm7252ps")
	st.Poe[1] = &PoeSim{Admin: true, Detect: 3, PowerMw: 3500}

	m := st.OIDMap()
	adminKey := fmt.Sprintf("%s.3.1.1", snmp.PethPsePortTable)
	detectKey := fmt.Sprintf("%s.6.1.1", snmp.PethPsePortTable)
	if got := m[adminKey]; got != (OIDEntry{"INTEGER", "1"}) {
		t.Errorf("poe admin row = %+v", got)
	}
	if got := m[detectKey]; got != (OIDEntry{"INTEGER", "3"}) {
		t.Errorf("poe detect row = %+v", got)
	}

	mdl, _ := model.GetModel("gsm7252ps")
	vo, _ := snmp.GetVendorOids(mdl)
	powerKey := fmt.Sprintf("%s.1.1", vo.PoEPowerMw)
	if got := m[powerKey]; got != (OIDEntry{"Gauge32", "3500"}) {
		t.Errorf("poe power row = %+v", got)
	}
}

func TestOIDMapPoeRowsNoVendorOmitsPowerColumn(t *testing.T) {
	st := NewState("gs728tpp")
	st.Poe[1] = &PoeSim{Admin: true, Detect: 2, PowerMw: 0}

	m := st.OIDMap()
	adminKey := fmt.Sprintf("%s.3.1.1", snmp.PethPsePortTable)
	if _, ok := m[adminKey]; !ok {
		t.Error("expected poe admin row present even with no vendor subtree")
	}
	for k := range m {
		if len(k) >= len("1.3.6.1.4.1.4526") && k[:len("1.3.6.1.4.1.4526")] == "1.3.6.1.4.1.4526" {
			t.Errorf("no-vendor model must not project any 4526 OID, found %q", k)
		}
	}
}

func TestOIDMapSensorRowsSkippedWithoutVendor(t *testing.T) {
	st := NewState("gs728tpp")
	st.Sensors = []SensorSim{{Kind: "fan", Instance: "0", Raw: "2850"}}

	m := st.OIDMap()
	for k, v := range m {
		if v.Value == "2850" {
			t.Errorf("sensor row leaked onto no-vendor model at %q", k)
		}
	}
}

func TestOIDMapSensorRowsWithVendor(t *testing.T) {
	st := NewState("gsm7252ps")
	st.Sensors = []SensorSim{
		{Kind: "fan", Instance: "0", Raw: "2850"},
		{Kind: "power", Instance: "1", Raw: "30"},
		{Kind: "temperature", Instance: "1", Raw: "49"},
	}
	mdl, _ := model.GetModel("gsm7252ps")
	vo, _ := snmp.GetVendorOids(mdl)

	m := st.OIDMap()
	if got := m[vo.BoxFan+".0"]; got != (OIDEntry{"OCTETSTR", "2850"}) {
		t.Errorf("fan row = %+v", got)
	}
	if got := m[vo.BoxPSUPower+".1"]; got != (OIDEntry{"OCTETSTR", "30"}) {
		t.Errorf("power row = %+v", got)
	}
	if got := m[vo.BoxTemp+".1"]; got != (OIDEntry{"OCTETSTR", "49"}) {
		t.Errorf("temperature row = %+v", got)
	}
}

func TestOIDMapEntityRowsUnconditional(t *testing.T) {
	for _, key := range []string{"gs728tpp", "gsm7252ps"} {
		st := NewState(key)
		st.EntityComponents = []EntitySim{
			{Index: 67109185, PhysClass: 6, Name: "Main PowerSupply", Descr: "PowerSupply"},
		}
		m := st.OIDMap()
		if got := m[colKey(snmp.EntPhysicalClass, 67109185)]; got != (OIDEntry{"INTEGER", "6"}) {
			t.Errorf("[%s] entPhysicalClass = %+v", key, got)
		}
		if got := m[colKey(snmp.EntPhysicalName, 67109185)]; got != (OIDEntry{"OCTETSTR", "Main PowerSupply"}) {
			t.Errorf("[%s] entPhysicalName = %+v", key, got)
		}
		if got := m[colKey(snmp.EntPhysicalDescr, 67109185)]; got != (OIDEntry{"OCTETSTR", "PowerSupply"}) {
			t.Errorf("[%s] entPhysicalDescr = %+v", key, got)
		}
	}
}

func TestOIDMapMacFdbDecimalDottedIndex(t *testing.T) {
	st := NewState("gsm7252ps")
	st.Macs = []MacSim{{Vlan: 90, MacBytes: [6]byte{0xC8, 0x00, 0x84, 0x89, 0x71, 0x70}, BridgePort: 10}}
	st.BridgePorts = map[int]int{10: 110, 11: 11}

	m := st.OIDMap()
	wantKey := fmt.Sprintf("%s.90.200.0.132.137.113.112", snmp.Dot1qTpFdbPort)
	if got := m[wantKey]; got != (OIDEntry{"INTEGER", "10"}) {
		t.Errorf("mac fdb row = %+v, want bridge_port 10 at %q (got keys around: check formatting)", got, wantKey)
	}
	if got := m[colKey(snmp.Dot1dBasePortIfIndex, 10)]; got != (OIDEntry{"INTEGER", "110"}) {
		t.Errorf("bridge_port 10 -> ifIndex row = %+v, want 110", got)
	}
	if got := m[colKey(snmp.Dot1dBasePortIfIndex, 11)]; got != (OIDEntry{"INTEGER", "11"}) {
		t.Errorf("bridge_port 11 -> ifIndex row = %+v, want 11", got)
	}
}

func TestOIDMapLldpFourColumns(t *testing.T) {
	st := NewState("gsm7252ps")
	st.Lldp = []LldpSim{{
		TimeMark: 75, LocalPort: 49, RemIdx: 7,
		Chassis: string([]byte{0xC8, 0x00, 0x84, 0x89, 0x71, 0x70}),
		PortID:  "1/xg51", PortDesc: "eth0", SysName: "sw-cisco-shed",
	}}

	m := st.OIDMap()
	idx := "75.49.7"
	cases := []struct {
		key  string
		want string
	}{
		{fmt.Sprintf("%s.1.5.%s", snmp.LldpRemTable, idx), string([]byte{0xC8, 0x00, 0x84, 0x89, 0x71, 0x70})},
		{fmt.Sprintf("%s.1.7.%s", snmp.LldpRemTable, idx), "1/xg51"},
		{fmt.Sprintf("%s.1.8.%s", snmp.LldpRemTable, idx), "eth0"},
		{fmt.Sprintf("%s.1.9.%s", snmp.LldpRemTable, idx), "sw-cisco-shed"},
	}
	if len(cases) != 4 {
		t.Fatal("expected exactly 4 LLDP columns")
	}
	for _, c := range cases {
		got, ok := m[c.key]
		if !ok {
			t.Errorf("missing LLDP row %q", c.key)
			continue
		}
		if got.SnmpType != "OCTETSTR" || got.Value != c.want {
			t.Errorf("%q = %+v, want OCTETSTR %q", c.key, got, c.want)
		}
	}
}

func TestOIDMapMgmtBlock(t *testing.T) {
	st := NewState("gsm7252ps")
	st.Mgmt = MgmtSim{Address: "10.1.5.22", Netmask: "255.255.255.0", Gateway: "10.1.5.1", Mode: "static"}
	mdl, _ := model.GetModel("gsm7252ps")
	vo, _ := snmp.GetVendorOids(mdl)

	m := st.OIDMap()
	if got := m[snmp.IPAdEntAddr+".10.1.5.22"]; got != (OIDEntry{"IPADDR", "10.1.5.22"}) {
		t.Errorf("ipAdEntAddr = %+v", got)
	}
	if got := m[snmp.IPAdEntNetmask+".10.1.5.22"]; got != (OIDEntry{"IPADDR", "255.255.255.0"}) {
		t.Errorf("ipAdEntNetmask = %+v", got)
	}
	if got := m[snmp.IPRouteDest+".0.0.0.0"]; got != (OIDEntry{"IPADDR", "0.0.0.0"}) {
		t.Errorf("ipRouteDest literal = %+v, want 0.0.0.0", got)
	}
	if got := m[snmp.IPRouteNextHop+".0.0.0.0"]; got != (OIDEntry{"IPADDR", "10.1.5.1"}) {
		t.Errorf("ipRouteNextHop = %+v", got)
	}
	if got := m[vo.DHCPModeUnverified+".0"]; got != (OIDEntry{"INTEGER", "2"}) {
		t.Errorf("dhcp-mode static = %+v, want 2", got)
	}

	st.Mgmt.Mode = "dhcp"
	m = st.OIDMap()
	if got := m[vo.DHCPModeUnverified+".0"]; got != (OIDEntry{"INTEGER", "1"}) {
		t.Errorf("dhcp-mode dhcp = %+v, want 1", got)
	}
}

func TestOIDMapMgmtBlockNoVendorOmitsDhcpMode(t *testing.T) {
	st := NewState("gs728tpp")
	st.Mgmt = MgmtSim{Address: "10.2.5.10", Netmask: "255.255.255.0", Gateway: "10.2.5.1", Mode: "static"}

	m := st.OIDMap()
	if got := m[snmp.IPAdEntAddr+".10.2.5.10"]; got != (OIDEntry{"IPADDR", "10.2.5.10"}) {
		t.Errorf("ipAdEntAddr = %+v", got)
	}
	for k := range m {
		if len(k) > len("1.3.6.1.4.1.4526") && k[:len("1.3.6.1.4.1.4526")] == "1.3.6.1.4.1.4526" {
			t.Errorf("no-vendor model must not project a dhcp-mode (or any vendor) OID, found %q", k)
		}
	}
}

func TestVlanBitmapWidthFormula(t *testing.T) {
	for _, key := range []string{"gsm7252ps", "gs728tpp", "m4300-16x", "gs105pe"} {
		m, err := model.GetModel(key)
		if err != nil {
			t.Fatal(err)
		}
		want := (m.PortCount + 7) / 8
		if want < 8 {
			want = 8
		}
		if got := snmp.VlanBitmapWidth(m.PortCount); got != want {
			t.Errorf("[%s] snmp.VlanBitmapWidth = %d, want %d", key, got, want)
		}
	}
}

// TestSliceFromPortSetSortsAndExcludesFalseValues pins sliceFromPortSet's
// contract: only true-valued map entries are members, and the result is
// sorted ascending -- the composition with snmp.EncodePortBitmap that
// OIDMap relies on for the VLAN egress/untagged columns. The underlying
// MSB-first bit-packing/growth logic itself is pinned directly against
// snmp.EncodePortBitmap in the snmp package's own tests.
func TestSliceFromPortSetSortsAndExcludesFalseValues(t *testing.T) {
	got := sliceFromPortSet(map[int]bool{25: true, 1: true, 2: false, 10: true})
	if diff := cmp.Diff([]int{1, 10, 25}, got); diff != "" {
		t.Errorf("sliceFromPortSet mismatch (-want +got):\n%s", diff)
	}

	// Round-trip through snmp.EncodePortBitmap/DecodePortBitmap.
	roundTrip := snmp.EncodePortBitmap(sliceFromPortSet(map[int]bool{1: true, 2: true, 10: true, 25: true}), 8)
	if diff := cmp.Diff([]int{1, 2, 10, 25}, snmp.DecodePortBitmap(roundTrip)); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestIsOIDImplementedDelegatesToSNMP(t *testing.T) {
	noPoE := NewState("m4300-24x")
	if noPoE.IsOIDImplemented(snmp.PethPsePortTable + ".3.1.1") {
		t.Error("expected PoE MIB unimplemented on non-PoE model")
	}

	withPoE := NewState("gsm7252ps")
	if !withPoE.IsOIDImplemented(snmp.PethPsePortTable + ".3.1.1") {
		t.Error("expected PoE MIB implemented on PoE-capable model")
	}
	if !withPoE.IsOIDImplemented(snmp.IfAdminStatus + ".1") {
		t.Error("expected a standard-MIB OID implemented regardless of PoE")
	}
}

// --- Snapshot / Restore -----------------------------------------------

func buildRichState() *State {
	st := NewState("gsm7252ps")
	rx := uint64(100)
	desc := "uplink"
	st.Ports[1] = &PortSim{Name: "1/0/1", Admin: true, Link: true, Speed: 1000, IfType: 6, RxOctets: &rx, Description: &desc}
	st.Vlans[90] = &VlanSim{Name: "iot", Member: map[int]bool{1: true, 2: true}, Untagged: map[int]bool{1: true}}
	st.Pvids[1] = 90
	st.Poe[1] = &PoeSim{Admin: true, Detect: 3, PowerMw: 3500}
	st.Sensors = []SensorSim{{Kind: "fan", Instance: "0", Raw: "2850"}}
	st.EntityComponents = []EntitySim{{Index: 1, PhysClass: 6, Name: "PSU", Descr: "PowerSupply"}}
	st.Macs = []MacSim{{Vlan: 90, MacBytes: [6]byte{1, 2, 3, 4, 5, 6}, BridgePort: 10}}
	st.BridgePorts[10] = 110
	st.Lldp = []LldpSim{{TimeMark: 1, LocalPort: 1, RemIdx: 1, Chassis: "c", PortID: "p", PortDesc: "d", SysName: "s"}}
	st.Mgmt = MgmtSim{Address: "10.1.5.22", Netmask: "255.255.255.0", Gateway: "10.1.5.1", Mode: "static"}
	qos := 1
	st.NsdpQosEngine = &qos
	st.NsdpPortMirroringSources = map[int]bool{1: true}
	cert := "pem-bytes"
	st.UploadedCert = &cert
	st.ScpCertDeploy = &ScpCertDeploySim{Commands: []string{"copy scp://x nvram:sslpem-root"}, Copies: []ScpCopy{{Source: "scp://x", Dest: "nvram:sslpem-root"}}, Saved: true}
	return st
}

func TestSnapshotIsIndependentDeepCopy(t *testing.T) {
	st := buildRichState()
	snap := st.Snapshot()

	// Mutate the original through every kind of shared structure a shallow
	// copy would have left aliased.
	st.Ports[1].Admin = false
	st.Ports[2] = NewPortSim("1/0/2", true, true, 100)
	st.Vlans[90].Member[3] = true
	st.Vlans[200] = &VlanSim{Name: "new"}
	st.Pvids[2] = 1
	st.Poe[1].Admin = false
	st.Sensors[0].Raw = "9999"
	st.Sensors = append(st.Sensors, SensorSim{Kind: "power", Instance: "1", Raw: "1"})
	st.EntityComponents[0].Name = "changed"
	st.Macs[0].BridgePort = 999
	st.BridgePorts[10] = 1
	st.Lldp[0].SysName = "changed"
	st.Mgmt.Address = "192.168.1.1"
	*st.NsdpQosEngine = 2
	st.NsdpPortMirroringSources[2] = true
	*st.UploadedCert = "changed"
	st.ScpCertDeploy.Commands[0] = "changed"
	st.ScpCertDeploy.Saved = false

	// The snapshot must be completely unaffected by every mutation above.
	want := buildRichState()
	if diff := cmp.Diff(want, snap); diff != "" {
		t.Errorf("snapshot mutated by post-snapshot changes to original (-want +snap):\n%s", diff)
	}
}

func TestRestorePreservesPointerIdentity(t *testing.T) {
	st := buildRichState()
	original := buildRichState()
	snap := st.Snapshot()

	type holder struct{ St *State }
	h := holder{St: st}
	stAddr := fmt.Sprintf("%p", st)

	// Mutate st (via the holder, proving the holder's reference is live).
	h.St.Ports[1].Admin = false
	h.St.Vlans[90].Member[3] = true
	h.St.Mgmt.Address = "192.168.1.1"
	delete(h.St.Vlans, 90)

	h.St.Restore(snap)

	if fmt.Sprintf("%p", st) != stAddr {
		t.Fatal("Restore must not change the *State pointer identity")
	}
	if h.St != st {
		t.Fatal("holder must still reference the exact same *State after Restore")
	}
	if diff := cmp.Diff(original, st); diff != "" {
		t.Errorf("state after Restore does not match pre-mutation original (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(original, h.St); diff != "" {
		t.Errorf("holder's view after Restore does not match pre-mutation original (-want +got):\n%s", diff)
	}
}

// TestSnapshotNilFieldsStayNil proves every per-field clone helper passes
// a nil map/slice/pointer straight through as nil rather than fabricating
// an empty non-nil value -- e.g. HTTPSensors' None-vs-empty-list
// significance (see State.HTTPSensors doc) must survive a Snapshot/Restore
// round trip unchanged.
func TestSnapshotNilFieldsStayNil(t *testing.T) {
	st := NewState("gsm7252ps") // HTTPSensors, NsdpQosEngine, etc. are nil.
	snap := st.Snapshot()

	if snap.HTTPSensors != nil {
		t.Error("nil HTTPSensors must stay nil through Snapshot")
	}
	if snap.NsdpQosEngine != nil || snap.NsdpPortMirroringDest != nil ||
		snap.NsdpIgmpSnoopingEnabled != nil || snap.NsdpIgmpSnoopingVlan != nil ||
		snap.NsdpBroadcastFiltering != nil || snap.NsdpLoopDetection != nil {
		t.Error("nil NSDP-extra pointer fields must stay nil through Snapshot")
	}
	if snap.UploadedCert != nil || snap.ScpCertDeploy != nil {
		t.Error("nil HTTP/CLI-only fields must stay nil through Snapshot")
	}

	// Restore from this blank snapshot must also cleanly zero out a richer
	// state's fields, not panic on a nil source.
	rich := buildRichState()
	rich.Restore(snap)
	if rich.HTTPSensors != nil || rich.UploadedCert != nil || rich.ScpCertDeploy != nil {
		t.Error("Restore from a blank snapshot must clear previously-set pointer/slice fields")
	}
}
