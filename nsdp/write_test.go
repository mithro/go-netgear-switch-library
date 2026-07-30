package nsdp_test

// Ported field-for-field from tests/protocols/nsdp/test_write_frame.py at pin
// 1aa1274 in python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274). Any discrepancy between this file and that pin is a
// bug in this file. rebootTLV (unexported -- see write.go's doc comment on
// why) is tested in write_internal_test.go instead of here.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

var writeTestMAC = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

// --- test_build_read_request_has_empty_tlvs_and_read_op ---

func TestBuildReadRequestHasEmptyTLVsAndReadOp(t *testing.T) {
	pkt := nsdp.BuildReadRequest(writeTestMAC, bytes.Repeat([]byte{0xaa}, 6), 5,
		[]nsdp.Tag{nsdp.TagModel, nsdp.TagPortStatus})

	if pkt.Op != nsdp.OpReadRequest {
		t.Errorf("Op = %v, want OpReadRequest", pkt.Op)
	}
	if len(pkt.TLVs) != 2 || pkt.TLVs[0].Tag != nsdp.TagModel || pkt.TLVs[1].Tag != nsdp.TagPortStatus {
		t.Fatalf("TLVs = %+v, want [TagModel, TagPortStatus]", pkt.TLVs)
	}
	for _, tlv := range pkt.TLVs {
		if len(tlv.Value) != 0 {
			t.Errorf("TLV %v has non-empty value %v, want length-0 (read request)", tlv.Tag, tlv.Value)
		}
	}
}

// --- test_build_write_request_prepends_v1_password_tlv ---

func TestBuildWriteRequestPrependsV1PasswordTLV(t *testing.T) {
	pvid, err := nsdp.PvidTLV(1, 90)
	if err != nil {
		t.Fatalf("PvidTLV: %v", err)
	}
	pkt, err := nsdp.BuildWriteRequest(writeTestMAC, bytes.Repeat([]byte{0xaa}, 6), 9, "admin", []nsdp.TLVEntry{pvid})
	if err != nil {
		t.Fatalf("BuildWriteRequest: %v", err)
	}
	if pkt.Op != nsdp.OpWriteRequest {
		t.Errorf("Op = %v, want OpWriteRequest", pkt.Op)
	}
	if len(pkt.TLVs) != 2 {
		t.Fatalf("TLVs = %+v, want 2 entries", pkt.TLVs)
	}
	if pkt.TLVs[0].Tag != nsdp.TagPassword {
		t.Errorf("TLVs[0].Tag = %v, want TagPassword", pkt.TLVs[0].Tag)
	}
	wantPassword, err := nsdp.EncodePasswordV1("admin")
	if err != nil {
		t.Fatalf("EncodePasswordV1: %v", err)
	}
	if !bytes.Equal(pkt.TLVs[0].Value, wantPassword) {
		t.Errorf("TLVs[0].Value = %x, want %x", pkt.TLVs[0].Value, wantPassword)
	}
	// The value TLVs follow the auth TLV, unchanged.
	if pkt.TLVs[1].Tag != nsdp.TagPortPVID {
		t.Errorf("TLVs[1].Tag = %v, want TagPortPVID", pkt.TLVs[1].Tag)
	}

	// And it round-trips on the wire.
	encoded, err := pkt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	back, err := nsdp.DecodePacket(encoded)
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	if back.TLVs[0].Tag != nsdp.TagPassword {
		t.Errorf("round-tripped TLVs[0].Tag = %v, want TagPassword", back.TLVs[0].Tag)
	}
}

func TestBuildWriteRequestRejectsNonASCIIPassword(t *testing.T) {
	_, err := nsdp.BuildWriteRequest(writeTestMAC, bytes.Repeat([]byte{0xaa}, 6), 1, "pa\xffss", nil)
	if err == nil {
		t.Fatal("BuildWriteRequest: expected error for non-ASCII password, got nil")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("BuildWriteRequest error does not wrap model.ErrNSDP: %v", err)
	}
}

// --- test_pvid_tlv_encoding ---

func TestPvidTLVEncoding(t *testing.T) {
	tlv, err := nsdp.PvidTLV(5, 100)
	if err != nil {
		t.Fatalf("PvidTLV: %v", err)
	}
	if tlv.Tag != nsdp.TagPortPVID {
		t.Errorf("Tag = %v, want TagPortPVID", tlv.Tag)
	}
	want := []byte{0x05, 0x00, 0x64}
	if !bytes.Equal(tlv.Value, want) {
		t.Errorf("Value = %x, want %x", tlv.Value, want)
	}
	pv, err := nsdp.ParsePortPvid(tlv.Value)
	if err != nil {
		t.Fatalf("ParsePortPvid: %v", err)
	}
	if pv.VlanID != 100 {
		t.Errorf("round-tripped VlanID = %d, want 100", pv.VlanID)
	}
}

func TestPvidTLVRejectsOutOfRangePort(t *testing.T) {
	_, err := nsdp.PvidTLV(256, 100)
	if err == nil || !strings.Contains(err.Error(), "port must fit a byte") {
		t.Errorf("PvidTLV error = %v, want to mention 'port must fit a byte'", err)
	}
}

func TestPvidTLVRejectsOutOfRangeVlan(t *testing.T) {
	_, err := nsdp.PvidTLV(1, 0x10000)
	if err == nil || !strings.Contains(err.Error(), "vlan must fit a uint16") {
		t.Errorf("PvidTLV error = %v, want to mention 'vlan must fit a uint16'", err)
	}
}

// --- test_vlan_members_tlv_encoding_10_port ---

func TestVlanMembersTLVEncoding10Port(t *testing.T) {
	tlv, err := nsdp.VlanMembersTLV(90, []int{1, 2, 10}, []int{10}, 10)
	if err != nil {
		t.Fatalf("VlanMembersTLV: %v", err)
	}
	if tlv.Tag != nsdp.TagVLANMembers {
		t.Errorf("Tag = %v, want TagVLANMembers", tlv.Tag)
	}
	vlanID := binary.BigEndian.Uint16(tlv.Value[0:2])
	if vlanID != 90 {
		t.Errorf("vlan_id = %d, want 90", vlanID)
	}
	memberBitmap := tlv.Value[2:4] // ceil(10/8) = 2 bytes
	taggedBitmap := tlv.Value[4:6]

	m, err := nsdp.ParseVlanMembers(tlv.Value, 10)
	if err != nil {
		t.Fatalf("ParseVlanMembers: %v", err)
	}
	assertIntSet(t, "MemberPorts", m.MemberPorts, []int{1, 2, 10})
	assertIntSet(t, "TaggedPorts", m.TaggedPorts, []int{10})
	if len(memberBitmap) != 2 || len(taggedBitmap) != 2 {
		t.Errorf("bitmap widths = %d/%d, want 2/2", len(memberBitmap), len(taggedBitmap))
	}
}

func TestVlanMembersTLVGrowsBitmapPastPortCountWidth(t *testing.T) {
	// portCount=8 -> width=1 byte, but a member port (17) needs a 3rd byte:
	// portsToBitmap must grow the buffer to fit it, not truncate/panic,
	// mirroring Python's ports_to_bitmap same growth behavior.
	tlv, err := nsdp.VlanMembersTLV(1, []int{17}, nil, 8)
	if err != nil {
		t.Fatalf("VlanMembersTLV: %v", err)
	}
	// vlan(2) + member(>=3 bytes to hold port 17) + tagged(1 byte, width=8/8=1)
	if len(tlv.Value) < 2+3+1 {
		t.Fatalf("Value = %x, too short to hold a grown member bitmap", tlv.Value)
	}
	member := tlv.Value[2 : len(tlv.Value)-1]
	got := []int{}
	for byteIdx, b := range member {
		for bit := 0; bit < 8; bit++ {
			if b&(0x80>>uint(bit)) != 0 {
				got = append(got, byteIdx*8+bit+1)
			}
		}
	}
	assertIntSet(t, "grown member bitmap ports", got, []int{17})
}

func TestVlanMembersTLVRejectsOutOfRangeVlan(t *testing.T) {
	_, err := nsdp.VlanMembersTLV(0x10000, nil, nil, 8)
	if err == nil || !strings.Contains(err.Error(), "vlan must fit a uint16") {
		t.Errorf("VlanMembersTLV error = %v, want to mention 'vlan must fit a uint16'", err)
	}
}

// --- test_ipv4_and_dhcp_and_reboot_tlvs ---

func TestIPv4TLV(t *testing.T) {
	tlv, err := nsdp.IPv4TLV(nsdp.TagIPAddress, "10.1.5.20")
	if err != nil {
		t.Fatalf("IPv4TLV: %v", err)
	}
	want := []byte{0x0a, 0x01, 0x05, 0x14}
	if !bytes.Equal(tlv.Value, want) {
		t.Errorf("Value = %x, want %x", tlv.Value, want)
	}
	if tlv.Tag != nsdp.TagIPAddress {
		t.Errorf("Tag = %v, want TagIPAddress", tlv.Tag)
	}
}

func TestIPv4TLVRejectsInvalidAddress(t *testing.T) {
	_, err := nsdp.IPv4TLV(nsdp.TagIPAddress, "not-an-ip")
	if err == nil {
		t.Fatal("IPv4TLV: expected error for invalid address, got nil")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("IPv4TLV error does not wrap model.ErrNSDP: %v", err)
	}
}

func TestIPv4TLVRejectsIPv6Address(t *testing.T) {
	// Parses as a valid IP (net.ParseIP succeeds) but isn't IPv4-shaped --
	// must still be rejected, not silently encoded as 16 bytes.
	_, err := nsdp.IPv4TLV(nsdp.TagIPAddress, "::1")
	if err == nil {
		t.Fatal("IPv4TLV: expected error for IPv6 address, got nil")
	}
	if !strings.Contains(err.Error(), "is not an IPv4 address") {
		t.Errorf("IPv4TLV error = %v, want to mention 'is not an IPv4 address'", err)
	}
}

func TestDhcpTLV(t *testing.T) {
	enabled := nsdp.DhcpTLV(true)
	if enabled.Tag != nsdp.TagDHCPMode || !bytes.Equal(enabled.Value, []byte{0x01}) {
		t.Errorf("DhcpTLV(true) = %+v, want Tag=TagDHCPMode Value=[0x01]", enabled)
	}
	disabled := nsdp.DhcpTLV(false)
	if !bytes.Equal(disabled.Value, []byte{0x00}) {
		t.Errorf("DhcpTLV(false).Value = %x, want [0x00]", disabled.Value)
	}
}

// test_result_constants (RESULT_SUCCESS/RESULT_BAD_PASSWORD) is already
// covered by TestResultCodes in protocol_test.go -- not duplicated here.
