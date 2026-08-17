package nsdp_test

// Ported field-for-field from tests/test_nsdp_read.py at pin 1aa1274 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274). Any discrepancy between this file and that pin is a
// bug in this file. Go has no separate sync/async split, so only the sync
// (NsdpReader) side is ported -- there is no AsyncNsdpReader twin to test.

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

// cannedReadResponse builds the same canned READ_RESPONSE packet as
// Python's tests/test_nsdp_read.py::_canned_packet, TLV-for-TLV.
func cannedReadResponse() nsdp.Packet {
	pkt := nsdp.Packet{
		Op:        nsdp.OpReadResponse,
		ClientMAC: make([]byte, 6),
		ServerMAC: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagPortCount, []byte{0x0a})
	pkt.AddTLV(nsdp.TagPortStatus, []byte{0x01, 0x05, 0x01}) // port 1, gigabit
	pkt.AddTLV(nsdp.TagPortStatus, []byte{0x03, 0x00, 0x01}) // port 3, down
	pkt.AddTLV(nsdp.TagPortStatus, []byte{0x09, 0xff, 0x01}) // port 9, 10G

	stats := make([]byte, 0, 49)
	stats = append(stats, 0x01)
	stats = appendUint64(stats, 1000)
	stats = appendUint64(stats, 500)
	stats = appendUint64(stats, 2)
	stats = append(stats, make([]byte, 24)...)
	pkt.AddTLV(nsdp.TagPortStatistics, stats)

	vlanMembers := make([]byte, 0, 6)
	vlanMembers = appendUint16(vlanMembers, 90)
	vlanMembers = append(vlanMembers, 0b1100_0000, 0b0100_0000) // members {1,2,10}
	vlanMembers = append(vlanMembers, 0b0000_0000, 0b0100_0000) // tagged {10}
	pkt.AddTLV(nsdp.TagVLANMembers, vlanMembers)

	pkt.AddTLV(nsdp.TagPortPVID, []byte{0x01, 0x00, 0x5a}) // port 1 -> vlan 90
	pkt.AddTLV(nsdp.TagIPAddress, []byte{0x0a, 0x01, 0x05, 0x14})
	pkt.AddTLV(nsdp.TagNetmask, []byte{0xff, 0xff, 0xff, 0x00})
	pkt.AddTLV(nsdp.TagGateway, []byte{0x0a, 0x01, 0x05, 0x01})
	pkt.AddTLV(nsdp.TagDHCPMode, []byte{0x00})
	pkt.AddTLV(nsdp.TagVLANEngine, []byte{byte(model.VLANEngineAdvanced8021Q)})
	pkt.AddTLV(nsdp.TagFirmwareVer1, []byte("1.0.0.7"))
	pkt.AddTLV(nsdp.TagSerialNumber, append([]byte{0x01}, []byte("53H6025EA0083")...))
	pkt.AddTLV(nsdp.TagHostname, []byte("plus-sw"))
	pkt.AddTLV(nsdp.TagQOSEngine, []byte{0x01})                       // port-based
	pkt.AddTLV(nsdp.TagPortMirroring, []byte{0x0a, 0xc0, 0x00, 0x00}) // dest=10, src={1,2}
	pkt.AddTLV(nsdp.TagIGMPSnooping, []byte{0x00, 0x01, 0x00, 0x5a})  // enabled, vlan=90
	pkt.AddTLV(nsdp.TagBroadcastFiltering, []byte{0x01})
	pkt.AddTLV(nsdp.TagLoopDetection, []byte{0x01})
	return pkt
}

func appendUint64(b []byte, v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return append(b, buf...)
}

func appendUint16(b []byte, v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return append(b, buf...)
}

// fakeNsdpClient returns the same canned packet for every Read call,
// recording the requested tag lists -- mirroring Python's FakeNsdpClient.
type fakeNsdpClient struct {
	requested [][]nsdp.Tag
	packet    nsdp.Packet
}

func newFakeNsdpClient() *fakeNsdpClient {
	return &fakeNsdpClient{packet: cannedReadResponse()}
}

func (f *fakeNsdpClient) Read(_ context.Context, tags []nsdp.Tag) (*nsdp.Packet, error) {
	f.requested = append(f.requested, append([]nsdp.Tag(nil), tags...))
	pkt := f.packet
	return &pkt, nil
}

// tagFilteringNsdpClient mimics REAL Plus hardware: it answers a read with
// ONLY the tags requested (never MODEL unsolicited), unlike a naive fake
// that over-serves every tag regardless of the request -- mirroring
// Python's _TagFilteringNsdpClient, which exposes the exact bug a per-op
// read omitting MODEL would trip over on real hardware.
type tagFilteringNsdpClient struct {
	last []nsdp.Tag
}

func (f *tagFilteringNsdpClient) Read(_ context.Context, tags []nsdp.Tag) (*nsdp.Packet, error) {
	f.last = append([]nsdp.Tag(nil), tags...)
	canned := cannedReadResponse()
	byTag := map[nsdp.Tag][][]byte{}
	for _, tlv := range canned.TLVs {
		byTag[tlv.Tag] = append(byTag[tlv.Tag], tlv.Value)
	}
	pkt := &nsdp.Packet{Op: nsdp.OpReadResponse, ClientMAC: make([]byte, 6), ServerMAC: make([]byte, 6)}
	for _, t := range tags {
		for _, v := range byTag[t] {
			pkt.AddTLV(t, v)
		}
	}
	return pkt, nil
}

func containsTag(tags []nsdp.Tag, want nsdp.Tag) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func gs110emx(t *testing.T) *model.SwitchModel {
	t.Helper()
	m, err := model.GetModel("gs110emx")
	if err != nil {
		t.Fatalf("GetModel(gs110emx): %v", err)
	}
	return m
}

// --- test_per_op_reads_request_model_for_real_hardware ---

func TestReader_PerOpReadsRequestModelForRealHardware(t *testing.T) {
	client := &tagFilteringNsdpClient{}
	reader, err := nsdp.NewReader(client, gs110emx(t))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	ctx := context.Background()

	if _, err := reader.GetPorts(ctx); err != nil {
		t.Fatalf("GetPorts: %v", err)
	}
	if !containsTag(client.last, nsdp.TagModel) {
		t.Errorf("GetPorts did not request TagModel: %v", client.last)
	}
	if _, err := reader.GetStats(ctx); err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if !containsTag(client.last, nsdp.TagModel) {
		t.Errorf("GetStats did not request TagModel: %v", client.last)
	}
	if _, err := reader.GetVLANs(ctx); err != nil {
		t.Fatalf("GetVLANs: %v", err)
	}
	if !containsTag(client.last, nsdp.TagModel) {
		t.Errorf("GetVLANs did not request TagModel: %v", client.last)
	}
	if _, err := reader.GetPVIDs(ctx); err != nil {
		t.Fatalf("GetPVIDs: %v", err)
	}
	if !containsTag(client.last, nsdp.TagModel) {
		t.Errorf("GetPVIDs did not request TagModel: %v", client.last)
	}
	if _, err := reader.GetMgmtIP(ctx); err != nil {
		t.Fatalf("GetMgmtIP: %v", err)
	}
	if !containsTag(client.last, nsdp.TagModel) {
		t.Errorf("GetMgmtIP did not request TagModel: %v", client.last)
	}
}

func newTestReader(t *testing.T) *nsdp.Reader {
	t.Helper()
	reader, err := nsdp.NewReader(newFakeNsdpClient(), gs110emx(t))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	return reader
}

// --- test_get_ports_maps_speed_and_link ---

func TestReader_GetPortsMapsSpeedAndLink(t *testing.T) {
	reader := newTestReader(t)
	ports, err := reader.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts: %v", err)
	}
	byPort := map[int]model.PortStatus{}
	for _, p := range ports {
		byPort[p.Port] = p
	}

	p1 := byPort[1]
	if !p1.LinkUp {
		t.Errorf("port 1 LinkUp = false, want true")
	}
	if p1.SpeedMbps == nil || *p1.SpeedMbps != 1000 {
		t.Errorf("port 1 SpeedMbps = %v, want 1000", p1.SpeedMbps)
	}
	if !p1.AdminEnabled {
		t.Errorf("port 1 AdminEnabled = false, want true (NSDP can't read admin; documented true)")
	}
	if p1.Name != nil {
		t.Errorf("port 1 Name = %v, want nil (NSDP PORT_STATUS carries no name)", p1.Name)
	}

	p3 := byPort[3]
	if p3.LinkUp {
		t.Errorf("port 3 LinkUp = true, want false")
	}
	if p3.SpeedMbps != nil {
		t.Errorf("port 3 SpeedMbps = %v, want nil", p3.SpeedMbps)
	}

	p9 := byPort[9]
	if p9.SpeedMbps == nil || *p9.SpeedMbps != 10000 {
		t.Errorf("port 9 SpeedMbps = %v, want 10000", p9.SpeedMbps)
	}
}

// --- test_get_stats_maps_bytes_and_crc_errors ---

func TestReader_GetStatsMapsBytesAndCrcErrors(t *testing.T) {
	reader := newTestReader(t)
	stats, err := reader.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	byPort := map[int]model.PortStats{}
	for _, s := range stats {
		byPort[s.Port] = s
	}
	s1 := byPort[1]
	if s1.RxBytes == nil || *s1.RxBytes != 1000 {
		t.Errorf("port 1 RxBytes = %v, want 1000", s1.RxBytes)
	}
	if s1.TxBytes == nil || *s1.TxBytes != 500 {
		t.Errorf("port 1 TxBytes = %v, want 500", s1.TxBytes)
	}
	if s1.RxErrors == nil || *s1.RxErrors != 2 {
		t.Errorf("port 1 RxErrors = %v, want 2", s1.RxErrors)
	}
	if s1.RxPackets != nil {
		t.Errorf("port 1 RxPackets = %v, want nil (NSDP does not report packet counts)", s1.RxPackets)
	}
	if s1.TxErrors != nil {
		t.Errorf("port 1 TxErrors = %v, want nil", s1.TxErrors)
	}
}

// --- test_get_vlans_and_pvids ---

func TestReader_GetVlansAndPvids(t *testing.T) {
	reader := newTestReader(t)
	ctx := context.Background()
	vlans, err := reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs: %v", err)
	}
	var v90 *model.VLANInfo
	for i := range vlans {
		if vlans[i].VlanID == 90 {
			v90 = &vlans[i]
		}
	}
	if v90 == nil {
		t.Fatalf("VLAN 90 not found in %v", vlans)
	}
	if !equalIntSlices(v90.MemberPorts, []int{1, 2, 10}) {
		t.Errorf("VLAN 90 MemberPorts = %v, want [1 2 10]", v90.MemberPorts)
	}
	if !equalIntSlices(v90.TaggedPorts, []int{10}) {
		t.Errorf("VLAN 90 TaggedPorts = %v, want [10]", v90.TaggedPorts)
	}
	if !equalIntSlices(v90.UntaggedPorts, []int{1, 2}) {
		t.Errorf("VLAN 90 UntaggedPorts = %v, want [1 2]", v90.UntaggedPorts)
	}
	if v90.Name != nil {
		t.Errorf("VLAN 90 Name = %v, want nil (NSDP VLAN_MEMBERS carries no VLAN name)", v90.Name)
	}

	pvids, err := reader.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs: %v", err)
	}
	found := false
	for _, p := range pvids {
		if p == (model.Pvid{Port: 1, Vlan: 90}) {
			found = true
		}
	}
	if !found {
		t.Errorf("GetPVIDs = %v, want to contain {Port:1 Vlan:90}", pvids)
	}
}

func equalIntSlices(a, b []int) bool {
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

// --- test_get_mgmt_ip_static ---

func TestReader_GetMgmtIPStatic(t *testing.T) {
	reader := newTestReader(t)
	mgmt, err := reader.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP: %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.20" {
		t.Errorf("Address = %v, want 10.1.5.20", mgmt.Address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != "255.255.255.0" {
		t.Errorf("Netmask = %v, want 255.255.255.0", mgmt.Netmask)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != "10.1.5.1" {
		t.Errorf("Gateway = %v, want 10.1.5.1", mgmt.Gateway)
	}
	if mgmt.Mode != model.IPModeStatic {
		t.Errorf("Mode = %v, want IPModeStatic", mgmt.Mode)
	}
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("BaseMac = %v, want AA:BB:CC:DD:EE:FF (uppercased)", mgmt.BaseMac)
	}
}

// --- test_get_device_returns_full_device ---

func TestReader_GetDeviceReturnsFullDevice(t *testing.T) {
	reader := newTestReader(t)
	dev, err := reader.GetDevice(context.Background())
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if dev.Model != "GS110EMX" {
		t.Errorf("Model = %q, want GS110EMX", dev.Model)
	}
	if dev.PortCount == nil || *dev.PortCount != 10 {
		t.Errorf("PortCount = %v, want 10", dev.PortCount)
	}
	if dev.FirmwareVersion == nil || *dev.FirmwareVersion != "1.0.0.7" {
		t.Errorf("FirmwareVersion = %v, want 1.0.0.7", dev.FirmwareVersion)
	}
	if dev.SerialNumber == nil || *dev.SerialNumber != "53H6025EA0083" {
		t.Errorf("SerialNumber = %v, want 53H6025EA0083", dev.SerialNumber)
	}
	if dev.Hostname == nil || *dev.Hostname != "plus-sw" {
		t.Errorf("Hostname = %v, want plus-sw", dev.Hostname)
	}
	if dev.DhcpEnabled == nil || *dev.DhcpEnabled {
		t.Errorf("DhcpEnabled = %v, want false", dev.DhcpEnabled)
	}
	if dev.IP == nil || *dev.IP != "10.1.5.20" {
		t.Errorf("IP = %v, want 10.1.5.20", dev.IP)
	}
	if dev.VlanEngine == nil || *dev.VlanEngine != model.VLANEngineAdvanced8021Q {
		t.Errorf("VlanEngine = %v, want VLANEngineAdvanced8021Q", dev.VlanEngine)
	}
	// Raw port-status speed byte is NOT pre-converted to Mbps here.
	if len(dev.PortStatus) == 0 || dev.PortStatus[0].Speed != model.LinkSpeedGigabit {
		t.Errorf("PortStatus[0].Speed = %v, want LinkSpeedGigabit", dev.PortStatus)
	}
	if dev.QosEngine == nil || *dev.QosEngine != 1 {
		t.Errorf("QosEngine = %v, want 1", dev.QosEngine)
	}
	if dev.PortMirroring == nil {
		t.Fatalf("PortMirroring = nil, want non-nil")
	}
	if dev.PortMirroring.DestinationPort != 10 {
		t.Errorf("PortMirroring.DestinationPort = %d, want 10", dev.PortMirroring.DestinationPort)
	}
	if !equalIntSlices(dev.PortMirroring.SourcePorts, []int{1, 2}) {
		t.Errorf("PortMirroring.SourcePorts = %v, want [1 2]", dev.PortMirroring.SourcePorts)
	}
	if dev.IgmpSnooping == nil {
		t.Fatalf("IgmpSnooping = nil, want non-nil")
	}
	if !dev.IgmpSnooping.Enabled {
		t.Errorf("IgmpSnooping.Enabled = false, want true")
	}
	if dev.IgmpSnooping.VlanID == nil || *dev.IgmpSnooping.VlanID != 90 {
		t.Errorf("IgmpSnooping.VlanID = %v, want 90", dev.IgmpSnooping.VlanID)
	}
	if dev.BroadcastFiltering == nil || !*dev.BroadcastFiltering {
		t.Errorf("BroadcastFiltering = %v, want true", dev.BroadcastFiltering)
	}
	if dev.LoopDetection == nil || !*dev.LoopDetection {
		t.Errorf("LoopDetection = %v, want true", dev.LoopDetection)
	}
}

// --- test_unsupported_ops_raise ---

func TestReader_UnsupportedOpsRaise(t *testing.T) {
	reader := newTestReader(t)
	ctx := context.Background()

	t.Run("GetMACs", func(t *testing.T) {
		_, err := reader.GetMACs(ctx)
		requireUnsupported(t, err)
	})
	t.Run("GetLLDP", func(t *testing.T) {
		_, err := reader.GetLLDP(ctx)
		requireUnsupported(t, err)
	})
	t.Run("GetSensors", func(t *testing.T) {
		_, err := reader.GetSensors(ctx)
		requireUnsupported(t, err)
	})
	t.Run("GetPoE", func(t *testing.T) {
		_, err := reader.GetPoE(ctx)
		requireUnsupported(t, err)
	})
	t.Run("GetUsers", func(t *testing.T) {
		_, err := reader.GetUsers(ctx)
		requireUnsupported(t, err)
	})
	t.Run("GetServices", func(t *testing.T) {
		_, err := reader.GetServices(ctx)
		requireUnsupported(t, err)
	})
}

// TestReader_GetUsersGetServicesRefuseByExactMessage mirrors Python's
// nsdp_read.py get_users/get_services refusal text VERBATIM -- byte-
// identical to snmp_read.py's own (see nsdp.NoUsersMsg/NoServicesMsg's doc
// comments): both backends refuse this op the same way, since users is
// deliberately NOT served over SNMP/NSDP even though a vendor table exists.
func TestReader_GetUsersGetServicesRefuseByExactMessage(t *testing.T) {
	reader := newTestReader(t)
	ctx := context.Background()

	_, err := reader.GetUsers(ctx)
	if err == nil || !strings.Contains(err.Error(), nsdp.NoUsersMsg) {
		t.Errorf("GetUsers() error = %v, want it to contain %q", err, nsdp.NoUsersMsg)
	}
	_, err = reader.GetServices(ctx)
	if err == nil || !strings.Contains(err.Error(), nsdp.NoServicesMsg) {
		t.Errorf("GetServices() error = %v, want it to contain %q", err, nsdp.NoServicesMsg)
	}
}

func requireUnsupported(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("error = %v, want to wrap model.ErrUnsupportedCapability", err)
	}
}

// --- test_reader_rejects_non_nsdp_model ---

func TestReader_RejectsNonNsdpModel(t *testing.T) {
	m, err := model.GetModel("gsm7252ps") // SNMP-only
	if err != nil {
		t.Fatalf("GetModel(gsm7252ps): %v", err)
	}
	_, err = nsdp.NewReader(newFakeNsdpClient(), m)
	requireUnsupported(t, err)
}

// erroringNsdpClient always fails Read/Write with errSentinel, to exercise
// every method's error-propagation branch (no Python analogue -- Python's
// tests never exercise a raw transport failure at this layer, but Go
// coverage wants every branch, not just the happy path).
type erroringNsdpClient struct{ err error }

var errSentinel = errors.New("sentinel transport failure")

func (c erroringNsdpClient) Read(context.Context, []nsdp.Tag) (*nsdp.Packet, error) {
	return nil, c.err
}

func (c erroringNsdpClient) Write(context.Context, []nsdp.TLVEntry, string) (*nsdp.Packet, error) {
	return nil, c.err
}

func TestReader_ClientReadErrorPropagates(t *testing.T) {
	reader, err := nsdp.NewReader(erroringNsdpClient{err: errSentinel}, gs110emx(t))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	ctx := context.Background()

	if _, err := reader.GetPorts(ctx); !errors.Is(err, errSentinel) {
		t.Errorf("GetPorts error = %v, want to wrap errSentinel", err)
	}
	if _, err := reader.GetStats(ctx); !errors.Is(err, errSentinel) {
		t.Errorf("GetStats error = %v, want to wrap errSentinel", err)
	}
	if _, err := reader.GetVLANs(ctx); !errors.Is(err, errSentinel) {
		t.Errorf("GetVLANs error = %v, want to wrap errSentinel", err)
	}
	if _, err := reader.GetPVIDs(ctx); !errors.Is(err, errSentinel) {
		t.Errorf("GetPVIDs error = %v, want to wrap errSentinel", err)
	}
	if _, err := reader.GetMgmtIP(ctx); !errors.Is(err, errSentinel) {
		t.Errorf("GetMgmtIP error = %v, want to wrap errSentinel", err)
	}
	if _, err := reader.GetDevice(ctx); !errors.Is(err, errSentinel) {
		t.Errorf("GetDevice error = %v, want to wrap errSentinel", err)
	}
}

// TestReader_GetMgmtIPDhcp covers mapMgmtIP's DHCP branch (the canned
// packet used by every other reader test is static-mode only).
func TestReader_GetMgmtIPDhcp(t *testing.T) {
	client := newFakeNsdpClient()
	for i, tlv := range client.packet.TLVs {
		if tlv.Tag == nsdp.TagDHCPMode {
			client.packet.TLVs[i].Value = []byte{0x01}
		}
	}
	reader, err := nsdp.NewReader(client, gs110emx(t))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	mgmt, err := reader.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP: %v", err)
	}
	if mgmt.Mode != model.IPModeDHCP {
		t.Errorf("Mode = %v, want IPModeDHCP", mgmt.Mode)
	}
}

// portNameNsdpClient returns a fixed packet with two ports -- one described,
// one bare -- for exercising GetPorts' PORT_NAME (0xB000) -> PortStatus.
// Description mapping. It always includes MODEL and MAC (ParseDevice
// requires both).
type portNameNsdpClient struct{}

func (portNameNsdpClient) Read(_ context.Context, _ []nsdp.Tag) (*nsdp.Packet, error) {
	pkt := &nsdp.Packet{Op: nsdp.OpReadResponse, ClientMAC: make([]byte, 6), ServerMAC: make([]byte, 6)}
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagMAC, []byte{0xbc, 0xa5, 0x11, 0xb8, 0xec, 0xf1})
	pkt.AddTLV(nsdp.TagPortCount, []byte{0x02})
	pkt.AddTLV(nsdp.TagPortStatus, []byte{0x01, 0x05, 0x01})                    // port 1, gigabit
	pkt.AddTLV(nsdp.TagPortStatus, []byte{0x02, 0x00, 0x01})                    // port 2, down
	pkt.AddTLV(nsdp.TagPortName, append([]byte{0x01}, []byte("lab-uplink")...)) // port 1 named
	pkt.AddTLV(nsdp.TagPortName, []byte{0x02})                                  // port 2 bare (undescribed)
	return pkt, nil
}

// TestReader_GetPortsMapsPortName proves GetPorts folds PORT_NAME into
// PortStatus.Description -- the operator label, matching every other
// backend's ifAlias-equivalent field, NOT Name (which NSDP never
// populates: PORT_STATUS carries no interface identifier at all) -- a
// described port gets its label, a bare PORT_NAME TLV leaves Description
// nil (mirroring Python _ports' labels.get()).
func TestReader_GetPortsMapsPortName(t *testing.T) {
	reader, err := nsdp.NewReader(portNameNsdpClient{}, gs110emx(t))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	ports, err := reader.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts: %v", err)
	}
	byPort := map[int]model.PortStatus{}
	for _, p := range ports {
		byPort[p.Port] = p
	}
	if p1 := byPort[1]; p1.Description == nil || *p1.Description != "lab-uplink" {
		t.Errorf("port 1 Description = %v, want \"lab-uplink\"", p1.Description)
	}
	if p1 := byPort[1]; p1.Name != nil {
		t.Errorf("port 1 Name = %v, want nil (NSDP PORT_STATUS carries no interface identifier)", p1.Name)
	}
	if p2 := byPort[2]; p2.Description != nil {
		t.Errorf("port 2 Description = %v, want nil (bare PORT_NAME TLV = undescribed)", p2.Description)
	}
}

func TestExportedRefusalMessagesNonEmpty(t *testing.T) {
	for name, msg := range map[string]string{
		"NoMACsMsg":     nsdp.NoMACsMsg,
		"NoLLDPMsg":     nsdp.NoLLDPMsg,
		"NoSensorsMsg":  nsdp.NoSensorsMsg,
		"NoPoEReadMsg":  nsdp.NoPoEReadMsg,
		"NoUsersMsg":    nsdp.NoUsersMsg,
		"NoServicesMsg": nsdp.NoServicesMsg,
	} {
		if msg == "" {
			t.Errorf("%s is empty", name)
		}
	}
}
