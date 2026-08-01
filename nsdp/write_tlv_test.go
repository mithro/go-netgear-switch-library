package nsdp

import (
	"bytes"
	"testing"
)

func TestVLANDestroyTLV(t *testing.T) {
	tlv := VLANDestroyTLV(0x0139) // vlan 313
	if tlv.Tag != TagVLANDestroy {
		t.Fatalf("tag = %#x, want TagVLANDestroy (%#x)", tlv.Tag, TagVLANDestroy)
	}
	if !bytes.Equal(tlv.Value, []byte{0x01, 0x39}) {
		t.Fatalf("value = % x, want 01 39 (big-endian vlan)", tlv.Value)
	}
}

func TestPortNameTLV(t *testing.T) {
	tlv := PortNameTLV(5, "uplink")
	if tlv.Tag != TagPortName {
		t.Fatalf("tag = %#x, want TagPortName (%#x)", tlv.Tag, TagPortName)
	}
	want := append([]byte{0x05}, []byte("uplink")...)
	if !bytes.Equal(tlv.Value, want) {
		t.Fatalf("value = % x, want % x (port byte + utf-8 name)", tlv.Value, want)
	}
}

func TestResultAndErrorConstants(t *testing.T) {
	// The whole-value Result forms are (error byte << 8), matching the pin.
	cases := []struct {
		result, errByte int
	}{
		{ResultBadPasswordV2, ErrorAuthRejected},
		{ResultLockedV2, ErrorLocked},
		{ResultReadOnly, ErrorReadOnly},
		{ResultWriteOnly, ErrorWriteOnly},
		{ResultBadPassword, ErrorDenied},
	}
	for _, c := range cases {
		if c.result>>8 != c.errByte {
			t.Errorf("result %#04x >> 8 = %#x, want error byte %#x", c.result, c.result>>8, c.errByte)
		}
	}
}

func TestPacketErrorAttrRoundTrip(t *testing.T) {
	// A WRITE_RESPONSE blaming TagPassword (0x000A) with a v2-auth-rejected
	// result: error_attr (header bytes 4-5) must survive encode->decode, and
	// ErrorCode must extract the high byte.
	p := Packet{Op: OpWriteResponse, Result: ResultBadPasswordV2, ErrorAttr: uint16(TagPassword), Sequence: 7}
	wire, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodePacket(wire)
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	if got.ErrorAttr != uint16(TagPassword) {
		t.Fatalf("ErrorAttr = %#x, want TagPassword (%#x)", got.ErrorAttr, uint16(TagPassword))
	}
	if got.Result != ResultBadPasswordV2 {
		t.Fatalf("Result = %#04x, want %#04x", got.Result, ResultBadPasswordV2)
	}
	if got.ErrorCode() != ErrorAuthRejected {
		t.Fatalf("ErrorCode() = %#x, want ErrorAuthRejected (%#x)", got.ErrorCode(), ErrorAuthRejected)
	}
	// A request-style packet (ErrorAttr 0) still round-trips with 0.
	req := Packet{Op: OpWriteRequest, Sequence: 1}
	rw, _ := req.Encode()
	rgot, _ := DecodePacket(rw)
	if rgot.ErrorAttr != 0 {
		t.Fatalf("request ErrorAttr = %#x, want 0", rgot.ErrorAttr)
	}
}

func TestBuildWriteRequestV2_TokenFirst(t *testing.T) {
	token := []byte{0xc4, 0xaf, 0x7c, 0x00, 0xa6, 0xc4, 0x1a, 0x7d}
	pvid, _ := PvidTLV(1, 90)
	pkt := BuildWriteRequestV2([]byte{1, 2, 3, 4, 5, 6}, zeroMAC, 3, token, []TLVEntry{pvid})
	if pkt.Op != OpWriteRequest {
		t.Fatalf("op = %v, want WriteRequest", pkt.Op)
	}
	if len(pkt.TLVs) != 2 {
		t.Fatalf("TLV count = %d, want 2 (token + pvid)", len(pkt.TLVs))
	}
	// The AUTH_V2_PASSWORD token MUST be first (load-bearing ordering).
	if pkt.TLVs[0].Tag != TagAuthV2Password {
		t.Fatalf("TLVs[0].Tag = %#x, want TagAuthV2Password FIRST", pkt.TLVs[0].Tag)
	}
	if !bytes.Equal(pkt.TLVs[0].Value, token) {
		t.Fatalf("token = % x, want % x", pkt.TLVs[0].Value, token)
	}
	if pkt.TLVs[1].Tag != TagPortPVID {
		t.Fatalf("TLVs[1].Tag = %#x, want the config TLV (PVID) after the token", pkt.TLVs[1].Tag)
	}
}
