package nsdp_test

// Ported field-for-field from tests/protocols/nsdp/test_parsers.py at pin
// 1aa1274 in python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274). Any discrepancy between this file and that pin is a
// bug in this file. LinkSpeed/VLANEngine enum-value coverage lives in
// model/nsdp_test.go (Task 1), not duplicated here.

import (
	"errors"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

// --- test_parse_ipv4_and_mac ---

func TestParseIPv4(t *testing.T) {
	got, err := nsdp.ParseIPv4([]byte{0x0a, 0x01, 0x14, 0x01})
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if got != "10.1.20.1" {
		t.Errorf("ParseIPv4 = %q, want %q", got, "10.1.20.1")
	}
}

func TestParseIPv4WrongLength(t *testing.T) {
	_, err := nsdp.ParseIPv4([]byte{0x0a, 0x01, 0x14})
	if err == nil {
		t.Fatal("ParseIPv4: expected error for 3-byte input, got nil")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("ParseIPv4 error does not wrap model.ErrNSDP: %v", err)
	}
	if !strings.Contains(err.Error(), "IPv4 TLV must be 4 bytes, got 3") {
		t.Errorf("ParseIPv4 error = %q, want to contain %q", err.Error(), "IPv4 TLV must be 4 bytes, got 3")
	}
}

func TestParseMAC(t *testing.T) {
	got, err := nsdp.ParseMAC([]byte{0x00, 0x09, 0x5b, 0xaa, 0xbb, 0xcc})
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	if got != "00:09:5b:aa:bb:cc" {
		t.Errorf("ParseMAC = %q, want %q", got, "00:09:5b:aa:bb:cc")
	}
}

func TestParseMACWrongLength(t *testing.T) {
	_, err := nsdp.ParseMAC([]byte{0x00, 0x09, 0x5b})
	if err == nil || !strings.Contains(err.Error(), "MAC TLV must be 6 bytes, got 3") {
		t.Errorf("ParseMAC error = %v, want to mention 'MAC TLV must be 6 bytes, got 3'", err)
	}
}

// --- test_parse_port_status_3_bytes ---

func TestParsePortStatus(t *testing.T) {
	st, err := nsdp.ParsePortStatus([]byte{0x01, 0x05, 0x01}) // port 1, gigabit
	if err != nil {
		t.Fatalf("ParsePortStatus: %v", err)
	}
	if st.PortID != 1 || st.Speed != model.LinkSpeedGigabit {
		t.Errorf("ParsePortStatus = %+v, want PortID=1 Speed=Gigabit", st)
	}

	down, err := nsdp.ParsePortStatus([]byte{0x03, 0x00, 0x01}) // port 3, down
	if err != nil {
		t.Fatalf("ParsePortStatus: %v", err)
	}
	if down.Speed != model.LinkSpeedDown {
		t.Errorf("ParsePortStatus.Speed = %v, want Down", down.Speed)
	}
}

func TestParsePortStatusWrongLength(t *testing.T) {
	_, err := nsdp.ParsePortStatus([]byte{0x01, 0x05})
	if err == nil || !strings.Contains(err.Error(), "PORT_STATUS TLV must be 3 bytes, got 2") {
		t.Errorf("ParsePortStatus error = %v", err)
	}
}

// --- test_parse_port_statistics_49_bytes / rejects_truncated ---

func portStatisticsFixture() []byte {
	data := make([]byte, 0, 49)
	data = append(data, 0x01)
	data = append(data, 0, 0, 0, 0, 0, 0, 0x03, 0xe8) // rx = 1000
	data = append(data, 0, 0, 0, 0, 0, 0, 0x01, 0xf4) // tx = 500
	data = append(data, 0, 0, 0, 0, 0, 0, 0, 0x03)    // crc = 3
	data = append(data, make([]byte, 24)...)
	return data
}

func TestParsePortStatistics(t *testing.T) {
	stats, err := nsdp.ParsePortStatistics(portStatisticsFixture())
	if err != nil {
		t.Fatalf("ParsePortStatistics: %v", err)
	}
	if stats.PortID != 1 || stats.BytesReceived != 1000 || stats.BytesSent != 500 || stats.CrcErrors != 3 {
		t.Errorf("ParsePortStatistics = %+v, want PortID=1 BytesReceived=1000 BytesSent=500 CrcErrors=3", stats)
	}
}

func TestParsePortStatisticsRejectsTruncated(t *testing.T) {
	// Too short: 25 bytes instead of 49.
	data := portStatisticsFixture()[:25]
	_, err := nsdp.ParsePortStatistics(data)
	if err == nil || !strings.Contains(err.Error(), "PORT_STATISTICS TLV must be 49 bytes, got 25") {
		t.Errorf("ParsePortStatistics error = %v", err)
	}
}

// --- test_parse_port_pvid_3_bytes ---

func TestParsePortPvid(t *testing.T) {
	pv, err := nsdp.ParsePortPvid([]byte{0x05, 0x00, 0x64}) // port 5, vlan 100
	if err != nil {
		t.Fatalf("ParsePortPvid: %v", err)
	}
	if pv.PortID != 5 || pv.VlanID != 100 {
		t.Errorf("ParsePortPvid = %+v, want PortID=5 VlanID=100", pv)
	}
}

func TestParsePortPvidWrongLength(t *testing.T) {
	_, err := nsdp.ParsePortPvid([]byte{0x05, 0x00})
	if err == nil || !strings.Contains(err.Error(), "PORT_PVID TLV must be 3 bytes, got 2") {
		t.Errorf("ParsePortPvid error = %v", err)
	}
}

// --- test_parse_serial_requires_0x01_prefix ---

func TestParseSerial(t *testing.T) {
	got, err := nsdp.ParseSerial([]byte("\x0153H6025EA0083"))
	if err != nil {
		t.Fatalf("ParseSerial: %v", err)
	}
	if got != "53H6025EA0083" {
		t.Errorf("ParseSerial = %q, want %q", got, "53H6025EA0083")
	}
}

func TestParseSerialRejectsBadPrefix(t *testing.T) {
	_, err := nsdp.ParseSerial([]byte("\x0253H6025EA0083"))
	if err == nil || !strings.Contains(err.Error(), "unexpected prefix byte") {
		t.Errorf("ParseSerial error = %v, want to mention 'unexpected prefix byte'", err)
	}
}

func TestParseSerialRejectsEmpty(t *testing.T) {
	_, err := nsdp.ParseSerial(nil)
	if err == nil || !strings.Contains(err.Error(), "unexpected prefix byte") {
		t.Errorf("ParseSerial error = %v, want to mention 'unexpected prefix byte'", err)
	}
}

func TestParseSerialStripsTrailingNulAndReplacesNonASCII(t *testing.T) {
	// Trailing NUL padding is stripped; a non-ASCII byte is replaced, not an
	// error (mirrors Python's decode(..., errors="replace")).
	got, err := nsdp.ParseSerial([]byte{0x01, 'A', 'B', 0xff, 0x00, 0x00})
	if err != nil {
		t.Fatalf("ParseSerial: %v", err)
	}
	if got != "AB�" {
		t.Errorf("ParseSerial = %q, want %q", got, "AB�")
	}
}

// --- test_bitmap_roundtrip_msb_first_1_based (via ParseVlanMembers/ParsePortMirroring) ---

func TestParseVlanMembers8Port(t *testing.T) {
	data := []byte{0x00, 0x64, 0b1111_0000, 0b0001_0000} // vlan 100, member, tagged
	m, err := nsdp.ParseVlanMembers(data, 8)
	if err != nil {
		t.Fatalf("ParseVlanMembers: %v", err)
	}
	if m.VlanID != 100 {
		t.Errorf("VlanID = %d, want 100", m.VlanID)
	}
	assertIntSet(t, "MemberPorts", m.MemberPorts, []int{1, 2, 3, 4})
	assertIntSet(t, "TaggedPorts", m.TaggedPorts, []int{4})
	assertIntSet(t, "UntaggedPorts", m.UntaggedPorts(), []int{1, 2, 3})
}

func TestParseVlanMembersTooShort(t *testing.T) {
	// 8 ports -> bitmap_bytes=1, expected=4; give only 3.
	_, err := nsdp.ParseVlanMembers([]byte{0x00, 0x64, 0x00}, 8)
	if err == nil || !strings.Contains(err.Error(), "VLAN_MEMBERS TLV must be >=4 bytes for 8 ports, got 3") {
		t.Errorf("ParseVlanMembers error = %v", err)
	}
}

func TestParseVlanMembers10Port(t *testing.T) {
	// 10 ports -> bitmap_bytes = ceil(10/8) = 2.
	data := []byte{0x00, 0x5a, 0xC0, 0x40, 0x00, 0x40} // vlan 90, member={1,2,10}, tagged={10}
	m, err := nsdp.ParseVlanMembers(data, 10)
	if err != nil {
		t.Fatalf("ParseVlanMembers: %v", err)
	}
	assertIntSet(t, "MemberPorts", m.MemberPorts, []int{1, 2, 10})
	assertIntSet(t, "TaggedPorts", m.TaggedPorts, []int{10})
}

func assertIntSet(t *testing.T, name string, got, want []int) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", name, got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s = %v, want %v", name, got, want)
			return
		}
	}
}

// --- TestParsePortMirroring (byte vectors lifted from
// gdoc2netcfg/tests/test_nsdp/test_parsers.py::TestParsePortMirroring) ---

func TestParsePortMirroringDisabled(t *testing.T) {
	pm, err := nsdp.ParsePortMirroring([]byte{0x00, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("ParsePortMirroring: %v", err)
	}
	if pm.DestinationPort != 0 || len(pm.SourcePorts) != 0 {
		t.Errorf("ParsePortMirroring = %+v, want disabled", pm)
	}
}

func TestParsePortMirroringEnabledSingleSource(t *testing.T) {
	// Dest port 10, source port 1 (bitmap 0x80 = 10000000).
	pm, err := nsdp.ParsePortMirroring([]byte{0x0a, 0x80, 0x00, 0x00})
	if err != nil {
		t.Fatalf("ParsePortMirroring: %v", err)
	}
	if pm.DestinationPort != 10 {
		t.Errorf("DestinationPort = %d, want 10", pm.DestinationPort)
	}
	assertIntSet(t, "SourcePorts", pm.SourcePorts, []int{1})
}

func TestParsePortMirroringEnabledMultipleSources(t *testing.T) {
	pm, err := nsdp.ParsePortMirroring([]byte{0x0a, 0xc0, 0x00, 0x00})
	if err != nil {
		t.Fatalf("ParsePortMirroring: %v", err)
	}
	if pm.DestinationPort != 10 {
		t.Errorf("DestinationPort = %d, want 10", pm.DestinationPort)
	}
	assertIntSet(t, "SourcePorts", pm.SourcePorts, []int{1, 2})
}

func TestParsePortMirroringEnabledManySources(t *testing.T) {
	pm, err := nsdp.ParsePortMirroring([]byte{0x05, 0xff, 0x00, 0x00})
	if err != nil {
		t.Fatalf("ParsePortMirroring: %v", err)
	}
	if pm.DestinationPort != 5 {
		t.Errorf("DestinationPort = %d, want 5", pm.DestinationPort)
	}
	assertIntSet(t, "SourcePorts", pm.SourcePorts, []int{1, 2, 3, 4, 5, 6, 7, 8})
}

func TestParsePortMirroringVariableWidthBitmap(t *testing.T) {
	// A 5-port GS105PE returns a 3-byte TLV (dest + 2-byte bitmap); a
	// 10-port GS110EMX a 4-byte TLV (dest + 3-byte bitmap). Both must parse,
	// never requiring a fixed width.
	off, err := nsdp.ParsePortMirroring([]byte{0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("ParsePortMirroring: %v", err)
	}
	if off.DestinationPort != 0 || len(off.SourcePorts) != 0 {
		t.Errorf("ParsePortMirroring = %+v, want disabled", off)
	}

	pm, err := nsdp.ParsePortMirroring([]byte{0x05, 0xc0, 0x00})
	if err != nil {
		t.Fatalf("ParsePortMirroring: %v", err)
	}
	if pm.DestinationPort != 5 {
		t.Errorf("DestinationPort = %d, want 5", pm.DestinationPort)
	}
	assertIntSet(t, "SourcePorts", pm.SourcePorts, []int{1, 2})
}

func TestParsePortMirroringRejectsEmpty(t *testing.T) {
	_, err := nsdp.ParsePortMirroring(nil)
	if err == nil || !strings.Contains(err.Error(), "at least 1 byte") {
		t.Errorf("ParsePortMirroring error = %v, want to mention 'at least 1 byte'", err)
	}
}

// --- TestParseIgmpSnooping (byte vectors lifted from
// gdoc2netcfg/tests/test_nsdp/test_parsers.py::TestParseIGMPSnooping) ---

func TestParseIgmpSnoopingEnabled(t *testing.T) {
	got, err := nsdp.ParseIgmpSnooping([]byte{0x00, 0x01, 0x00, 0x01})
	if err != nil {
		t.Fatalf("ParseIgmpSnooping: %v", err)
	}
	if !got.Enabled {
		t.Errorf("Enabled = false, want true")
	}
}

func TestParseIgmpSnoopingDisabled(t *testing.T) {
	got, err := nsdp.ParseIgmpSnooping([]byte{0x00, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("ParseIgmpSnooping: %v", err)
	}
	if got.Enabled {
		t.Errorf("Enabled = true, want false")
	}
}

func TestParseIgmpSnoopingEnabledWithVlan(t *testing.T) {
	got, err := nsdp.ParseIgmpSnooping([]byte{0x00, 0x01, 0x00, 0x0a})
	if err != nil {
		t.Fatalf("ParseIgmpSnooping: %v", err)
	}
	if !got.Enabled || got.VlanID == nil || *got.VlanID != 10 {
		t.Errorf("ParseIgmpSnooping = %+v, want Enabled=true VlanID=10", got)
	}
}

func TestParseIgmpSnoopingEnabledNoVlan(t *testing.T) {
	got, err := nsdp.ParseIgmpSnooping([]byte{0x00, 0x01, 0x00, 0x00})
	if err != nil {
		t.Fatalf("ParseIgmpSnooping: %v", err)
	}
	if !got.Enabled || got.VlanID != nil {
		t.Errorf("ParseIgmpSnooping = %+v, want Enabled=true VlanID=nil", got)
	}
}

func TestParseIgmpSnoopingTooShort(t *testing.T) {
	_, err := nsdp.ParseIgmpSnooping([]byte{0x00})
	if err == nil || !strings.Contains(err.Error(), "2 bytes") {
		t.Errorf("ParseIgmpSnooping error = %v", err)
	}
}

// --- TestParseDeviceNewTags (byte vectors lifted from
// gdoc2netcfg/tests/test_nsdp/test_parsers.py::TestParseDiscoveryResponseNewTags) ---

func newTagsPacket() nsdp.Packet {
	return nsdp.Packet{
		Op:        nsdp.OpReadResponse,
		ClientMAC: make([]byte, 6),
		ServerMAC: []byte{0x00, 0x09, 0x5b, 0xaa, 0xbb, 0xcc},
	}
}

func TestParseDeviceQosEngine(t *testing.T) {
	pkt := newTagsPacket()
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagMAC, []byte{0x00, 0x09, 0x5b, 0xaa, 0xbb, 0xcc})
	pkt.AddTLV(nsdp.TagQOSEngine, []byte{0x02}) // 802.1p mode

	dev, err := nsdp.ParseDevice(pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.QosEngine == nil || *dev.QosEngine != 2 {
		t.Errorf("QosEngine = %v, want 2", dev.QosEngine)
	}
}

func TestParseDevicePortMirroring(t *testing.T) {
	pkt := newTagsPacket()
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagMAC, []byte{0x00, 0x09, 0x5b, 0xaa, 0xbb, 0xcc})
	pkt.AddTLV(nsdp.TagPortMirroring, []byte{0x0a, 0xc0, 0x00, 0x00})

	dev, err := nsdp.ParseDevice(pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.PortMirroring == nil || dev.PortMirroring.DestinationPort != 10 {
		t.Fatalf("PortMirroring = %+v", dev.PortMirroring)
	}
	assertIntSet(t, "SourcePorts", dev.PortMirroring.SourcePorts, []int{1, 2})
}

func TestParseDevicePortMirroringVariableWidthBitmap(t *testing.T) {
	// A 5-port GS105PE returns a 3-byte PORT_MIRRORING TLV (dest + 2-byte
	// bitmap), captured live 2026-07-21 as "00 00 00" (mirroring off).
	pkt := newTagsPacket()
	pkt.AddTLV(nsdp.TagModel, []byte("GS105PE"))
	pkt.AddTLV(nsdp.TagMAC, []byte{0x00, 0x09, 0x5b, 0xaa, 0xbb, 0xcc})
	pkt.AddTLV(nsdp.TagPortMirroring, []byte{0x00, 0x00, 0x00})

	dev, err := nsdp.ParseDevice(pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.PortMirroring == nil || dev.PortMirroring.DestinationPort != 0 || len(dev.PortMirroring.SourcePorts) != 0 {
		t.Errorf("PortMirroring = %+v, want disabled", dev.PortMirroring)
	}
}

func TestParseDeviceIgmpSnooping(t *testing.T) {
	pkt := newTagsPacket()
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagMAC, []byte{0x00, 0x09, 0x5b, 0xaa, 0xbb, 0xcc})
	pkt.AddTLV(nsdp.TagIGMPSnooping, []byte{0x00, 0x01, 0x00, 0x0a})

	dev, err := nsdp.ParseDevice(pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.IgmpSnooping == nil || !dev.IgmpSnooping.Enabled || dev.IgmpSnooping.VlanID == nil || *dev.IgmpSnooping.VlanID != 10 {
		t.Errorf("IgmpSnooping = %+v", dev.IgmpSnooping)
	}
}

func TestParseDeviceBroadcastFiltering(t *testing.T) {
	pkt := newTagsPacket()
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagMAC, []byte{0x00, 0x09, 0x5b, 0xaa, 0xbb, 0xcc})
	pkt.AddTLV(nsdp.TagBroadcastFiltering, []byte{0x01})

	dev, err := nsdp.ParseDevice(pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.BroadcastFiltering == nil || !*dev.BroadcastFiltering {
		t.Errorf("BroadcastFiltering = %v, want true", dev.BroadcastFiltering)
	}
}

func TestParseDeviceLoopDetection(t *testing.T) {
	pkt := newTagsPacket()
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagMAC, []byte{0x00, 0x09, 0x5b, 0xaa, 0xbb, 0xcc})
	pkt.AddTLV(nsdp.TagLoopDetection, []byte{0x00})

	dev, err := nsdp.ParseDevice(pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.LoopDetection == nil || *dev.LoopDetection {
		t.Errorf("LoopDetection = %v, want false", dev.LoopDetection)
	}
}

func TestParseDeviceAllNewTagsTogether(t *testing.T) {
	pkt := newTagsPacket()
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagMAC, []byte{0x00, 0x09, 0x5b, 0xaa, 0xbb, 0xcc})
	pkt.AddTLV(nsdp.TagPortCount, []byte{0x0a})
	pkt.AddTLV(nsdp.TagQOSEngine, []byte{0x01})
	pkt.AddTLV(nsdp.TagPortMirroring, []byte{0x05, 0x80, 0x00, 0x00})
	pkt.AddTLV(nsdp.TagIGMPSnooping, []byte{0x00, 0x01, 0x00, 0x00})
	pkt.AddTLV(nsdp.TagBroadcastFiltering, []byte{0x01})
	pkt.AddTLV(nsdp.TagLoopDetection, []byte{0x01})

	dev, err := nsdp.ParseDevice(pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.QosEngine == nil || *dev.QosEngine != 1 {
		t.Errorf("QosEngine = %v, want 1", dev.QosEngine)
	}
	if dev.PortMirroring == nil || dev.PortMirroring.DestinationPort != 5 {
		t.Errorf("PortMirroring = %+v", dev.PortMirroring)
	}
	if dev.IgmpSnooping == nil || !dev.IgmpSnooping.Enabled {
		t.Errorf("IgmpSnooping = %+v", dev.IgmpSnooping)
	}
	if dev.BroadcastFiltering == nil || !*dev.BroadcastFiltering {
		t.Errorf("BroadcastFiltering = %v, want true", dev.BroadcastFiltering)
	}
	if dev.LoopDetection == nil || !*dev.LoopDetection {
		t.Errorf("LoopDetection = %v, want true", dev.LoopDetection)
	}
}

// --- test_parse_device_aggregates_read_response ---

func TestParseDeviceAggregatesReadResponse(t *testing.T) {
	pkt := nsdp.Packet{
		Op:        nsdp.OpReadResponse,
		ClientMAC: make([]byte, 6),
		ServerMAC: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagPortCount, []byte{0x0a})
	pkt.AddTLV(nsdp.TagIPAddress, []byte{0x0a, 0x01, 0x05, 0x14})
	pkt.AddTLV(nsdp.TagDHCPMode, []byte{0x00})
	pkt.AddTLV(nsdp.TagVLANEngine, []byte{byte(model.VLANEngineAdvanced8021Q)})
	pkt.AddTLV(nsdp.TagPortStatus, []byte{0x01, 0x05, 0x01})
	pkt.AddTLV(nsdp.TagPortPVID, []byte{0x01, 0x00, 0x5a})

	dev, err := nsdp.ParseDevice(pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.Model != "GS110EMX" {
		t.Errorf("Model = %q, want GS110EMX", dev.Model)
	}
	if dev.PortCount == nil || *dev.PortCount != 10 {
		t.Errorf("PortCount = %v, want 10", dev.PortCount)
	}
	if dev.IP == nil || *dev.IP != "10.1.5.20" {
		t.Errorf("IP = %v, want 10.1.5.20", dev.IP)
	}
	if dev.DhcpEnabled == nil || *dev.DhcpEnabled {
		t.Errorf("DhcpEnabled = %v, want false", dev.DhcpEnabled)
	}
	if dev.VlanEngine == nil || *dev.VlanEngine != model.VLANEngineAdvanced8021Q {
		t.Errorf("VlanEngine = %v, want Advanced8021Q", dev.VlanEngine)
	}
	if len(dev.PortStatus) != 1 || dev.PortStatus[0].Speed != model.LinkSpeedGigabit {
		t.Errorf("PortStatus = %+v", dev.PortStatus)
	}
	if len(dev.PortPvids) != 1 || dev.PortPvids[0].VlanID != 90 {
		t.Errorf("PortPvids = %+v", dev.PortPvids)
	}
	// No MAC tag: falls back to the header server_mac.
	if dev.Mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("Mac = %q, want aa:bb:cc:dd:ee:ff (fallback to server_mac)", dev.Mac)
	}
}

func TestParseDeviceRequiresModelTag(t *testing.T) {
	pkt := nsdp.Packet{
		Op:        nsdp.OpReadResponse,
		ClientMAC: make([]byte, 6),
		ServerMAC: make([]byte, 6),
	}
	pkt.AddTLV(nsdp.TagPortStatus, []byte{0x01, 0x05, 0x01})

	_, err := nsdp.ParseDevice(pkt)
	if err == nil || !strings.Contains(err.Error(), "no MODEL tag in NSDP response") {
		t.Errorf("ParseDevice error = %v, want to mention 'no MODEL tag in NSDP response'", err)
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("ParseDevice error does not wrap model.ErrNSDP: %v", err)
	}
}

func TestParseDeviceVlanMembersBeforePortCountUsesCorrectWidth(t *testing.T) {
	// D-NSDP §3.11 / trap #4: VLAN_MEMBERS appearing BEFORE PORT_COUNT in
	// the flat TLV list must still be parsed with the port count learned
	// from the (later-positioned) PORT_COUNT TLV, not the default width 8.
	pkt := newTagsPacket()
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	// 10 ports -> bitmap_bytes = 2. member={1,2,10}, tagged={10}.
	pkt.AddTLV(nsdp.TagVLANMembers, []byte{0x00, 0x5a, 0xC0, 0x40, 0x00, 0x40})
	pkt.AddTLV(nsdp.TagPortCount, []byte{0x0a}) // 10 ports, AFTER VLAN_MEMBERS

	dev, err := nsdp.ParseDevice(pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if len(dev.VlanMembers) != 1 {
		t.Fatalf("VlanMembers = %+v, want 1 entry", dev.VlanMembers)
	}
	assertIntSet(t, "MemberPorts", dev.VlanMembers[0].MemberPorts, []int{1, 2, 10})
	assertIntSet(t, "TaggedPorts", dev.VlanMembers[0].TaggedPorts, []int{10})
}

func TestParseDevicePropagatesInnerParseError(t *testing.T) {
	pkt := newTagsPacket()
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagPortStatus, []byte{0x01, 0x05}) // wrong length: 2, not 3

	_, err := nsdp.ParseDevice(pkt)
	if err == nil || !strings.Contains(err.Error(), "PORT_STATUS TLV must be 3 bytes, got 2") {
		t.Errorf("ParseDevice error = %v, want to propagate the inner parse error", err)
	}
}

// TestParseDeviceFullAggregation exercises every remaining field-mapping
// branch not covered by the tests above: Hostname/Netmask/Gateway/
// FirmwareVersion/SerialNumber/PortStatistics, and an explicit MAC TLV
// (rather than the server_mac fallback).
func TestParseDeviceFullAggregation(t *testing.T) {
	pkt := newTagsPacket()
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagMAC, []byte{0x00, 0x09, 0x5b, 0xaa, 0xbb, 0xcc})
	pkt.AddTLV(nsdp.TagHostname, []byte("switch1"))
	pkt.AddTLV(nsdp.TagNetmask, []byte{0xff, 0xff, 0xff, 0x00})
	pkt.AddTLV(nsdp.TagGateway, []byte{0x0a, 0x01, 0x05, 0x01})
	pkt.AddTLV(nsdp.TagFirmwareVer1, []byte("1.2.3"))
	pkt.AddTLV(nsdp.TagSerialNumber, []byte("\x01SN123"))
	pkt.AddTLV(nsdp.TagPortStatistics, portStatisticsFixture())

	dev, err := nsdp.ParseDevice(pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.Mac != "00:09:5b:aa:bb:cc" {
		t.Errorf("Mac = %q, want explicit MAC tag value, not server_mac fallback", dev.Mac)
	}
	if dev.Hostname == nil || *dev.Hostname != "switch1" {
		t.Errorf("Hostname = %v, want switch1", dev.Hostname)
	}
	if dev.Netmask == nil || *dev.Netmask != "255.255.255.0" {
		t.Errorf("Netmask = %v, want 255.255.255.0", dev.Netmask)
	}
	if dev.Gateway == nil || *dev.Gateway != "10.1.5.1" {
		t.Errorf("Gateway = %v, want 10.1.5.1", dev.Gateway)
	}
	if dev.FirmwareVersion == nil || *dev.FirmwareVersion != "1.2.3" {
		t.Errorf("FirmwareVersion = %v, want 1.2.3", dev.FirmwareVersion)
	}
	if dev.SerialNumber == nil || *dev.SerialNumber != "SN123" {
		t.Errorf("SerialNumber = %v, want SN123", dev.SerialNumber)
	}
	if len(dev.PortStatistics) != 1 || dev.PortStatistics[0].BytesReceived != 1000 {
		t.Errorf("PortStatistics = %+v", dev.PortStatistics)
	}
}

func TestParseDevicePropagatesMACTagError(t *testing.T) {
	pkt := newTagsPacket()
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagMAC, []byte{0x00, 0x09, 0x5b}) // wrong length

	_, err := nsdp.ParseDevice(pkt)
	if err == nil || !strings.Contains(err.Error(), "MAC TLV must be 6 bytes, got 3") {
		t.Errorf("ParseDevice error = %v, want to propagate the MAC parse error", err)
	}
}

func TestParseDevicePropagatesFallbackMACError(t *testing.T) {
	// No MAC tag, and a malformed (wrong-length) server_mac header field:
	// the fallback parse must still surface a wrapped error, not panic.
	pkt := nsdp.Packet{
		Op:        nsdp.OpReadResponse,
		ClientMAC: make([]byte, 6),
		ServerMAC: []byte{0x00, 0x09, 0x5b}, // wrong length
	}
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))

	_, err := nsdp.ParseDevice(pkt)
	if err == nil || !strings.Contains(err.Error(), "MAC TLV must be 6 bytes, got 3") {
		t.Errorf("ParseDevice error = %v, want to propagate the server_mac fallback parse error", err)
	}
}

func TestParseDevicePropagatesNetmaskGatewaySerialVlanMembersPvidErrors(t *testing.T) {
	cases := []struct {
		name    string
		tag     nsdp.Tag
		value   []byte
		wantMsg string
	}{
		{"netmask", nsdp.TagNetmask, []byte{0x01, 0x02}, "IPv4 TLV must be 4 bytes, got 2"},
		{"gateway", nsdp.TagGateway, []byte{0x01, 0x02}, "IPv4 TLV must be 4 bytes, got 2"},
		{"serial_number", nsdp.TagSerialNumber, []byte{0x02, 'x'}, "unexpected prefix byte"},
		{"vlan_members", nsdp.TagVLANMembers, []byte{0x00, 0x01}, "VLAN_MEMBERS TLV must be >=4 bytes for 8 ports, got 2"},
		{"port_pvid", nsdp.TagPortPVID, []byte{0x01, 0x02}, "PORT_PVID TLV must be 3 bytes, got 2"},
		{"port_mirroring", nsdp.TagPortMirroring, []byte{}, "at least 1 byte"},
		{"igmp_snooping", nsdp.TagIGMPSnooping, []byte{0x00}, "2 bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkt := newTagsPacket()
			pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
			pkt.AddTLV(c.tag, c.value)
			_, err := nsdp.ParseDevice(pkt)
			if err == nil || !strings.Contains(err.Error(), c.wantMsg) {
				t.Errorf("ParseDevice error = %v, want to contain %q", err, c.wantMsg)
			}
		})
	}
}
