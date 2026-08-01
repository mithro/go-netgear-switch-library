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
