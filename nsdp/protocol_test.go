package nsdp_test

// Ported field-for-field from
// tests/protocols/nsdp/{test_protocol.py,test_auth.py} at pin 1aa1274 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274). Any discrepancy between this file and that pin is a
// bug in this file.

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

// --- test_tag_and_op_values_match_wire_constants ---

func TestOpAndTagValuesMatchWireConstants(t *testing.T) {
	cases := []struct {
		name string
		got  uint16
		want uint16
	}{
		{"OpReadRequest", uint16(nsdp.OpReadRequest), 0x01},
		{"OpWriteRequest", uint16(nsdp.OpWriteRequest), 0x03},
		{"OpWriteResponse", uint16(nsdp.OpWriteResponse), 0x04},
		{"TagModel", uint16(nsdp.TagModel), 0x0001},
		{"TagPassword", uint16(nsdp.TagPassword), 0x000A},
		{"TagReboot", uint16(nsdp.TagReboot), 0x0013},
		{"TagAuthV2Salt", uint16(nsdp.TagAuthV2Salt), 0x0017},
		{"TagAuthV2Password", uint16(nsdp.TagAuthV2Password), 0x001A},
		{"TagPortStatus", uint16(nsdp.TagPortStatus), 0x0C00},
		{"TagPortStatistics", uint16(nsdp.TagPortStatistics), 0x1000},
		{"TagVLANMembers", uint16(nsdp.TagVLANMembers), 0x2800},
		{"TagPortPVID", uint16(nsdp.TagPortPVID), 0x3000},
		{"TagSerialNumber", uint16(nsdp.TagSerialNumber), 0x7800},
		// Every remaining tag from D-NSDP §1.4's 34-entry table.
		{"TagStartOfMark", uint16(nsdp.TagStartOfMark), 0x0000},
		{"TagEndOfMark", uint16(nsdp.TagEndOfMark), 0xFFFF},
		{"TagHostname", uint16(nsdp.TagHostname), 0x0003},
		{"TagMAC", uint16(nsdp.TagMAC), 0x0004},
		{"TagLocation", uint16(nsdp.TagLocation), 0x0005},
		{"TagIPAddress", uint16(nsdp.TagIPAddress), 0x0006},
		{"TagNetmask", uint16(nsdp.TagNetmask), 0x0007},
		{"TagGateway", uint16(nsdp.TagGateway), 0x0008},
		{"TagDHCPMode", uint16(nsdp.TagDHCPMode), 0x000B},
		{"TagActiveFirmware", uint16(nsdp.TagActiveFirmware), 0x000C},
		{"TagFirmwareVer1", uint16(nsdp.TagFirmwareVer1), 0x000D},
		{"TagFirmwareVer2", uint16(nsdp.TagFirmwareVer2), 0x000E},
		{"TagPortCount", uint16(nsdp.TagPortCount), 0x6000},
		{"TagVLANEngine", uint16(nsdp.TagVLANEngine), 0x2000},
		{"TagQOSEngine", uint16(nsdp.TagQOSEngine), 0x3400},
		{"TagPortQOSPriority", uint16(nsdp.TagPortQOSPriority), 0x3800},
		{"TagIngressRateLimit", uint16(nsdp.TagIngressRateLimit), 0x4C00},
		{"TagEgressRateLimit", uint16(nsdp.TagEgressRateLimit), 0x5000},
		{"TagBroadcastFiltering", uint16(nsdp.TagBroadcastFiltering), 0x5400},
		{"TagBroadcastBandwidth", uint16(nsdp.TagBroadcastBandwidth), 0x5800},
		{"TagPortMirroring", uint16(nsdp.TagPortMirroring), 0x5C00},
		{"TagIGMPSnooping", uint16(nsdp.TagIGMPSnooping), 0x6800},
		{"TagBlockUnknownMulticast", uint16(nsdp.TagBlockUnknownMulticast), 0x6C00},
		{"TagIGMPv3HeaderValidation", uint16(nsdp.TagIGMPv3HeaderValidation), 0x7000},
		{"TagIGMPStaticRouterPorts", uint16(nsdp.TagIGMPStaticRouterPorts), 0x8000},
		{"TagLoopDetection", uint16(nsdp.TagLoopDetection), 0x9000},
		{"TagFactoryReset", uint16(nsdp.TagFactoryReset), 0x0400},
		{"OpReadResponse", uint16(nsdp.OpReadResponse), 0x02},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = 0x%04X, want 0x%04X", c.name, c.got, c.want)
		}
	}
}

func TestResultCodes(t *testing.T) {
	if nsdp.ResultSuccess != 0x0000 {
		t.Errorf("ResultSuccess = 0x%04X, want 0x0000", nsdp.ResultSuccess)
	}
	if nsdp.ResultBadPassword != 0x0700 {
		t.Errorf("ResultBadPassword = 0x%04X, want 0x0700", nsdp.ResultBadPassword)
	}
}

// --- test_tlv_encode_decode_roundtrip ---

func TestTLVEncodeDecodeRoundtrip(t *testing.T) {
	tlv := nsdp.TLVEntry{Tag: nsdp.TagModel, Value: []byte("GS110EMX")}
	raw := tlv.Encode()
	want := []byte{0x00, 0x01, 0x00, 0x08}
	want = append(want, []byte("GS110EMX")...)
	if string(raw) != string(want) {
		t.Fatalf("Encode() = % x, want % x", raw, want)
	}
	decoded, consumed, err := nsdp.DecodeTLV(raw)
	if err != nil {
		t.Fatalf("DecodeTLV: %v", err)
	}
	if consumed != 12 {
		t.Errorf("consumed = %d, want 12", consumed)
	}
	if decoded.Tag != nsdp.TagModel {
		t.Errorf("Tag = %v, want TagModel", decoded.Tag)
	}
	if string(decoded.Value) != "GS110EMX" {
		t.Errorf("Value = %q, want GS110EMX", decoded.Value)
	}
}

// --- test_tlv_decode_unknown_tag_kept_as_int ---

func TestTLVDecodeUnknownTagKeptAsRawValue(t *testing.T) {
	raw := []byte{0xAB, 0xCD, 0x00, 0x00}
	decoded, consumed, err := nsdp.DecodeTLV(raw)
	if err != nil {
		t.Fatalf("DecodeTLV: %v", err)
	}
	if decoded.Tag != nsdp.Tag(0xABCD) {
		t.Errorf("Tag = 0x%04X, want 0xABCD", uint16(decoded.Tag))
	}
	if consumed != 4 {
		t.Errorf("consumed = %d, want 4", consumed)
	}
}

// --- test_tlv_decode_truncated_value_raises ---

func TestTLVDecodeTruncatedValueRaisesTypedError(t *testing.T) {
	raw := []byte{0x00, 0x01, 0x00, 0x08} // declares 8 value bytes
	raw = append(raw, []byte("short")...) // only 5 present
	_, _, err := nsdp.DecodeTLV(raw)
	if err == nil {
		t.Fatal("DecodeTLV: expected error, got nil")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("error does not wrap model.ErrNSDP: %v", err)
	}
	if want := "declares"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want substring %q", err.Error(), want)
	}
}

// --- test_tlv_decode_truncated_header_raises ---

func TestTLVDecodeTruncatedHeaderRaisesTypedError(t *testing.T) {
	_, _, err := nsdp.DecodeTLV([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("DecodeTLV: expected error, got nil")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("error does not wrap model.ErrNSDP: %v", err)
	}
	if want := "4-byte header"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want substring %q", err.Error(), want)
	}
}

// --- test_packet_decode_short_data_raises ---

func TestPacketDecodeShortDataRaisesTypedError(t *testing.T) {
	_, err := nsdp.DecodePacket(make([]byte, 10))
	if err == nil {
		t.Fatal("DecodePacket: expected error, got nil")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("error does not wrap model.ErrNSDP: %v", err)
	}
	if want := "32-byte header"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want substring %q", err.Error(), want)
	}
}

// --- test_packet_encode_has_signature_at_offset_0x18_and_end_marker ---

func TestPacketEncodeHasSignatureAtOffsetAndEndMarker(t *testing.T) {
	pkt := nsdp.Packet{
		Op:        nsdp.OpReadRequest,
		ClientMAC: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		ServerMAC: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		Sequence:  42,
	}
	pkt.AddTLV(nsdp.TagModel, nil) // empty value = read request
	raw, err := pkt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if raw[0] != 0x01 {
		t.Errorf("version byte = 0x%02X, want 0x01", raw[0])
	}
	if raw[1] != byte(nsdp.OpReadRequest) {
		t.Errorf("op byte = 0x%02X, want 0x%02X", raw[1], byte(nsdp.OpReadRequest))
	}
	if string(raw[0x18:0x1C]) != "NSDP" {
		t.Errorf("signature at 0x18 = %q, want NSDP", raw[0x18:0x1C])
	}
	endMarker := []byte{0xFF, 0xFF, 0x00, 0x00}
	if string(raw[len(raw)-4:]) != string(endMarker) {
		t.Errorf("packet does not end with end-of-mark: % x", raw[len(raw)-4:])
	}
	wantLen := nsdp.HeaderSize + 4 + 4 // header + one empty TLV + end marker
	if len(raw) != wantLen {
		t.Errorf("len(raw) = %d, want %d", len(raw), wantLen)
	}
}

// --- test_packet_decode_reads_tlvs_until_end_marker_and_ignores_trailing ---

func TestPacketDecodeReadsTLVsUntilEndMarkerAndIgnoresTrailing(t *testing.T) {
	pkt := nsdp.Packet{
		Op:        nsdp.OpReadResponse,
		ClientMAC: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		ServerMAC: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		Sequence:  7,
	}
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagPortCount, []byte{0x0a})
	raw, err := pkt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	raw = append(raw, []byte("garbage-after-eom")...)

	back, err := nsdp.DecodePacket(raw)
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	if back.Op != nsdp.OpReadResponse {
		t.Errorf("Op = %v, want OpReadResponse", back.Op)
	}
	if back.Sequence != 7 {
		t.Errorf("Sequence = %d, want 7", back.Sequence)
	}
	if string(back.ServerMAC) != string([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("ServerMAC = % x", back.ServerMAC)
	}
	if len(back.TLVs) != 2 {
		t.Fatalf("len(TLVs) = %d, want 2", len(back.TLVs))
	}
	if back.TLVs[0].Tag != nsdp.TagModel || string(back.TLVs[0].Value) != "GS110EMX" {
		t.Errorf("TLVs[0] = %+v", back.TLVs[0])
	}
	if back.TLVs[1].Tag != nsdp.TagPortCount || string(back.TLVs[1].Value) != "\x0a" {
		t.Errorf("TLVs[1] = %+v", back.TLVs[1])
	}
}

// --- test_packet_decode_bad_signature_raises ---

func TestPacketDecodeBadSignatureRaisesTypedError(t *testing.T) {
	_, err := nsdp.DecodePacket(make([]byte, 32))
	if err == nil {
		t.Fatal("DecodePacket: expected error, got nil")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("error does not wrap model.ErrNSDP: %v", err)
	}
	if want := "signature"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want substring %q", err.Error(), want)
	}
}

// --- test_write_request_roundtrip ---

func TestWriteRequestRoundtrip(t *testing.T) {
	pkt := nsdp.Packet{
		Op:        nsdp.OpWriteRequest,
		ClientMAC: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		ServerMAC: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		Sequence:  99,
	}
	pkt.AddTLV(nsdp.TagPassword, []byte("secret"))
	pkt.AddTLV(nsdp.TagHostname, []byte("switch01"))
	pkt.AddTLV(nsdp.TagReboot, nil) // empty-value action TLV
	raw, err := pkt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if raw[1] != byte(nsdp.OpWriteRequest) {
		t.Errorf("op byte = 0x%02X, want 0x%02X", raw[1], byte(nsdp.OpWriteRequest))
	}
	if string(raw[0x18:0x1C]) != "NSDP" {
		t.Errorf("signature at 0x18 = %q, want NSDP", raw[0x18:0x1C])
	}

	back, err := nsdp.DecodePacket(raw)
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	if back.Op != nsdp.OpWriteRequest {
		t.Errorf("Op = %v, want OpWriteRequest", back.Op)
	}
	if back.Sequence != 99 {
		t.Errorf("Sequence = %d, want 99", back.Sequence)
	}
	if string(back.ClientMAC) != string([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}) {
		t.Errorf("ClientMAC = % x", back.ClientMAC)
	}
	if string(back.ServerMAC) != string([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Errorf("ServerMAC = % x", back.ServerMAC)
	}
	wantTLVs := []nsdp.TLVEntry{
		{Tag: nsdp.TagPassword, Value: []byte("secret")},
		{Tag: nsdp.TagHostname, Value: []byte("switch01")},
		{Tag: nsdp.TagReboot, Value: []byte{}},
	}
	if len(back.TLVs) != len(wantTLVs) {
		t.Fatalf("len(TLVs) = %d, want %d", len(back.TLVs), len(wantTLVs))
	}
	for i, want := range wantTLVs {
		if back.TLVs[i].Tag != want.Tag || string(back.TLVs[i].Value) != string(want.Value) {
			t.Errorf("TLVs[%d] = %+v, want %+v", i, back.TLVs[i], want)
		}
	}
}

// --- test_packet_decode_hand_built_fixture_independent_of_encode ---

func TestPacketDecodeHandBuiltFixtureIndependentOfEncode(t *testing.T) {
	header := []byte{
		0x01,       // version
		0x04,       // Op.WRITE_RESPONSE
		0x00, 0x00, // result: success
		0x00, 0x00, 0x00, 0x00, // reserved1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // client_mac
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // server_mac
		0x00, 0x00, 0x00, 0x7b, // sequence = 123
		'N', 'S', 'D', 'P', // signature
		0x00, 0x00, 0x00, 0x00, // reserved3
	}
	body := []byte{
		0x00, 0x03, 0x00, 0x04, 's', 'w', '0', '1', // HOSTNAME "sw01"
		0x00, 0x0B, 0x00, 0x01, 0x01, // DHCP_MODE 0x01
	}
	endMarker := []byte{0xFF, 0xFF, 0x00, 0x00}
	raw := append(append(header, body...), endMarker...)

	pkt, err := nsdp.DecodePacket(raw)
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	if pkt.Op != nsdp.OpWriteResponse {
		t.Errorf("Op = %v, want OpWriteResponse", pkt.Op)
	}
	if pkt.Result != 0 {
		t.Errorf("Result = %d, want 0", pkt.Result)
	}
	if pkt.Sequence != 123 {
		t.Errorf("Sequence = %d, want 123", pkt.Sequence)
	}
	if len(pkt.TLVs) != 2 {
		t.Fatalf("len(TLVs) = %d, want 2", len(pkt.TLVs))
	}
	if pkt.TLVs[0].Tag != nsdp.TagHostname || string(pkt.TLVs[0].Value) != "sw01" {
		t.Errorf("TLVs[0] = %+v", pkt.TLVs[0])
	}
	if pkt.TLVs[1].Tag != nsdp.TagDHCPMode || string(pkt.TLVs[1].Value) != "\x01" {
		t.Errorf("TLVs[1] = %+v", pkt.TLVs[1])
	}
}

// --- test_sequence_number_is_a_full_4_byte_field ---

func TestSequenceNumberIsAFull4ByteField(t *testing.T) {
	pkt := nsdp.Packet{
		Op:        nsdp.OpReadRequest,
		ClientMAC: []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
		ServerMAC: []byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
		Sequence:  0x12345678,
	}
	pkt.AddTLV(nsdp.TagModel, nil)
	raw, err := pkt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(raw) < 32 {
		t.Fatalf("len(raw) = %d, want >= 32", len(raw))
	}
	want := []byte{0x12, 0x34, 0x56, 0x78}
	if string(raw[20:24]) != string(want) {
		t.Errorf("raw[20:24] = % x, want % x", raw[20:24], want)
	}
	back, err := nsdp.DecodePacket(raw)
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	if back.Sequence != 0x12345678 {
		t.Errorf("Sequence = 0x%08X, want 0x12345678", back.Sequence)
	}
}

// --- byte-golden vectors, generated by running the pinned Python source
// (protocols/nsdp/protocol.py + auth.py at 1aa1274) over the exact same
// inputs below and transcribing struct.pack's output. These pin the Go
// encoder's byte-for-byte output against the cross-language wire contract,
// not merely against our own decoder (a decode(encode(x))==x roundtrip
// alone couldn't catch a symmetric encode/decode bug).

func TestGoldenVectorReadRequest(t *testing.T) {
	// Python:
	//   pkt = NSDPPacket(op=Op.READ_REQUEST,
	//       client_mac=b"\x00\x00\x00\x00\x00\x01", server_mac=b"\x00"*6,
	//       sequence=1)
	//   pkt.add_tlv(Tag.MODEL); pkt.add_tlv(Tag.PORT_STATUS)
	//   pkt.encode().hex()
	want := mustHex(t, "0101000000000000000000000001000000000000000000014e53445000"+
		"000000000100000c000000ffff0000")

	pkt := nsdp.Packet{
		Op:        nsdp.OpReadRequest,
		ClientMAC: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		ServerMAC: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		Sequence:  1,
	}
	pkt.AddTLV(nsdp.TagModel, nil)
	pkt.AddTLV(nsdp.TagPortStatus, nil)

	got, err := pkt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got  % x\nwant % x", got, want)
	}
}

func TestGoldenVectorWriteRequestWithPassword(t *testing.T) {
	// Python:
	//   pkt = NSDPPacket(op=Op.WRITE_REQUEST,
	//       client_mac=b"\x00\x00\x00\x00\x00\x01",
	//       server_mac=b"\xaa\xbb\xcc\xdd\xee\xff", sequence=0x12345678)
	//   pkt.add_tlv(Tag.PASSWORD, encode_password_v1("admin"))
	//   pkt.add_tlv(Tag.HOSTNAME, b"switch01")
	//   pkt.encode().hex()
	want := mustHex(t, "0103000000000000000000000001aabbccddeeff123456784e534450"+
		"00000000000a00052f100a1b3d000300087377697463683031ffff0000")

	pkt := nsdp.Packet{
		Op:        nsdp.OpWriteRequest,
		ClientMAC: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		ServerMAC: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		Sequence:  0x12345678,
	}
	pw, err := nsdp.EncodePasswordV1("admin")
	if err != nil {
		t.Fatalf("EncodePasswordV1: %v", err)
	}
	pkt.AddTLV(nsdp.TagPassword, pw)
	pkt.AddTLV(nsdp.TagHostname, []byte("switch01"))

	got, err := pkt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got  % x\nwant % x", got, want)
	}

	// Round-trip through DecodePacket too, since the golden bytes are the
	// cross-language contract in both directions.
	back, err := nsdp.DecodePacket(got)
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	if back.Sequence != 0x12345678 {
		t.Errorf("Sequence = 0x%08X, want 0x12345678", back.Sequence)
	}
	if len(back.TLVs) != 2 || string(back.TLVs[0].Value) != string(pw) {
		t.Errorf("TLVs = %+v", back.TLVs)
	}
}

// --- test_v1_key_is_the_documented_string ---

func TestV1KeyIsTheDocumentedString(t *testing.T) {
	if string(nsdp.V1Key) != "NtgrSmartSwitchRock" {
		t.Errorf("V1Key = %q, want NtgrSmartSwitchRock", nsdp.V1Key)
	}
	if len(nsdp.V1Key) != 19 {
		t.Errorf("len(V1Key) = %d, want 19", len(nsdp.V1Key))
	}
}

// --- test_v1_xor_is_its_own_inverse ---

func TestV1XORIsItsOwnInverse(t *testing.T) {
	pw := "s3cr3t-admin"
	enc, err := nsdp.EncodePasswordV1(pw)
	if err != nil {
		t.Fatalf("EncodePasswordV1: %v", err)
	}
	if string(enc) == pw {
		t.Fatal("EncodePasswordV1 did not transform the password")
	}
	again := make([]byte, len(enc))
	for i := range enc {
		again[i] = enc[i] ^ nsdp.V1Key[i%len(nsdp.V1Key)]
	}
	if string(again) != pw {
		t.Errorf("second XOR pass = %q, want %q", again, pw)
	}
}

// --- test_v1_known_vector_from_algorithm ---

func TestV1KnownVectorFromAlgorithm(t *testing.T) {
	// Derived from the algorithm itself (repeating XOR), NOT captured
	// hardware.
	pw := "AAAA"
	enc, err := nsdp.EncodePasswordV1(pw)
	if err != nil {
		t.Fatalf("EncodePasswordV1: %v", err)
	}
	want := make([]byte, 4)
	for i := range want {
		want[i] = 'A' ^ nsdp.V1Key[i]
	}
	if string(enc) != string(want) {
		t.Errorf("EncodePasswordV1(%q) = % x, want % x", pw, enc, want)
	}
	// Cross-checked against the pinned Python source directly.
	wantHex := mustHex(t, "0f352633")
	if string(enc) != string(wantHex) {
		t.Errorf("EncodePasswordV1(%q) = % x, want % x (python-verified)", pw, enc, wantHex)
	}
}

func TestEncodePasswordV1AdminMatchesPython(t *testing.T) {
	// Cross-checked against the pinned Python source directly:
	// encode_password_v1("admin").hex() == "2f100a1b3d".
	got, err := nsdp.EncodePasswordV1("admin")
	if err != nil {
		t.Fatalf("EncodePasswordV1: %v", err)
	}
	want := mustHex(t, "2f100a1b3d")
	if string(got) != string(want) {
		t.Errorf("EncodePasswordV1(admin) = % x, want % x", got, want)
	}
}

func TestEncodePasswordV1RejectsNonASCII(t *testing.T) {
	_, err := nsdp.EncodePasswordV1("café")
	if err == nil {
		t.Fatal("EncodePasswordV1: expected error for non-ASCII password, got nil")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("error does not wrap model.ErrNSDP: %v", err)
	}
}

func TestPasswordTLVBuildsTagPasswordEntry(t *testing.T) {
	tlv, err := nsdp.PasswordTLV("admin")
	if err != nil {
		t.Fatalf("PasswordTLV: %v", err)
	}
	if tlv.Tag != nsdp.TagPassword {
		t.Errorf("Tag = %v, want TagPassword", tlv.Tag)
	}
	want := mustHex(t, "2f100a1b3d")
	if string(tlv.Value) != string(want) {
		t.Errorf("Value = % x, want % x", tlv.Value, want)
	}
}

func TestPasswordTLVRejectsNonASCII(t *testing.T) {
	_, err := nsdp.PasswordTLV("café")
	if err == nil {
		t.Fatal("PasswordTLV: expected error for non-ASCII password, got nil")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("error does not wrap model.ErrNSDP: %v", err)
	}
}

func TestAuthV2TagsRecognisedButUnimplemented(t *testing.T) {
	// Recognised as named constants (wire compatibility) but there is no
	// builder/parser for them anywhere in this package -- see
	// nsdp.AuthV2Unsupported for why.
	if nsdp.TagAuthV2Salt != 0x0017 {
		t.Errorf("TagAuthV2Salt = 0x%04X, want 0x0017", uint16(nsdp.TagAuthV2Salt))
	}
	if nsdp.TagAuthV2Password != 0x001A {
		t.Errorf("TagAuthV2Password = 0x%04X, want 0x001A", uint16(nsdp.TagAuthV2Password))
	}
	if nsdp.AuthV2Unsupported == "" {
		t.Error("AuthV2Unsupported message must not be empty")
	}
}

// --- extra coverage: Op.String, packMAC/Encode length validation, and
// DecodePacket rejecting an unrecognized operation byte. None of these are
// literal Python test ports (Python's dataclass has no analogous MAC-length
// guard, and Op(op_raw) validation is implicit in the enum constructor
// rather than a separately-tested branch), but they exercise behavior this
// port added/made explicit for Go's stricter typing.

func TestOpString(t *testing.T) {
	cases := []struct {
		op   nsdp.Op
		want string
	}{
		{nsdp.OpReadRequest, "READ_REQUEST"},
		{nsdp.OpReadResponse, "READ_RESPONSE"},
		{nsdp.OpWriteRequest, "WRITE_REQUEST"},
		{nsdp.OpWriteResponse, "WRITE_RESPONSE"},
		{nsdp.Op(0x42), "Op(0x42)"},
	}
	for _, c := range cases {
		if got := c.op.String(); got != c.want {
			t.Errorf("Op(0x%02X).String() = %q, want %q", uint8(c.op), got, c.want)
		}
	}
}

func TestPacketEncodeRejectsOverlongMAC(t *testing.T) {
	pkt := nsdp.Packet{
		Op:        nsdp.OpReadRequest,
		ClientMAC: make([]byte, 7),
		ServerMAC: make([]byte, 6),
	}
	if _, err := pkt.Encode(); err == nil || !errors.Is(err, model.ErrNSDP) {
		t.Errorf("Encode with 7-byte ClientMAC: err = %v, want model.ErrNSDP", err)
	}

	pkt2 := nsdp.Packet{
		Op:        nsdp.OpReadRequest,
		ClientMAC: make([]byte, 6),
		ServerMAC: make([]byte, 7),
	}
	if _, err := pkt2.Encode(); err == nil || !errors.Is(err, model.ErrNSDP) {
		t.Errorf("Encode with 7-byte ServerMAC: err = %v, want model.ErrNSDP", err)
	}
}

func TestPacketEncodeZeroPadsShortMAC(t *testing.T) {
	// Mirrors struct.pack's "6s" format zero-padding a too-short bytes
	// object (verified directly against Python: struct.pack('6s', b'ab') ==
	// b'ab\x00\x00\x00\x00').
	pkt := nsdp.Packet{
		Op:        nsdp.OpReadRequest,
		ClientMAC: []byte{0xab},
		ServerMAC: nil,
	}
	raw, err := pkt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	wantClient := []byte{0xab, 0, 0, 0, 0, 0}
	if string(raw[0x08:0x0E]) != string(wantClient) {
		t.Errorf("client_mac = % x, want % x", raw[0x08:0x0E], wantClient)
	}
	wantServer := make([]byte, 6)
	if string(raw[0x0E:0x14]) != string(wantServer) {
		t.Errorf("server_mac = % x, want % x", raw[0x0E:0x14], wantServer)
	}
}

func TestDecodePacketRejectsUnrecognizedOp(t *testing.T) {
	pkt := nsdp.Packet{
		Op:        nsdp.OpReadRequest,
		ClientMAC: make([]byte, 6),
		ServerMAC: make([]byte, 6),
	}
	raw, err := pkt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	raw[1] = 0x42 // corrupt the op byte to a value with no Op constant
	_, err = nsdp.DecodePacket(raw)
	if err == nil {
		t.Fatal("DecodePacket: expected error for unrecognized op byte, got nil")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("error does not wrap model.ErrNSDP: %v", err)
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}
