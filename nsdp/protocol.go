// Package nsdp implements the NETGEAR Switch Discovery Protocol (NSDP) wire
// codec used by NETGEAR's unmanaged-plus "Plus" switches (e.g. GS110EMX,
// GS305EP). It is a pure, zero-dependency codec: no sockets, no I/O.
//
// Ported field-for-field from
// src/netgear_switch/protocols/nsdp/{protocol.py,auth.py} at pin 1aa1274 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274, branch fix/s3300-52x-live-verify). Any discrepancy
// between this package and that pin is a bug in this package, not a
// deliberate deviation, unless called out in a comment.
package nsdp

import (
	"encoding/binary"
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
)

// Signature is the 4-byte magic value at header offset 0x18, required on
// every decoded packet.
var Signature = []byte("NSDP")

// EndMarker is the 4-byte TLV that unconditionally terminates every encoded
// packet: tag 0xFFFF (TagEndOfMark), length 0.
var EndMarker = []byte{0xFF, 0xFF, 0x00, 0x00}

// HeaderSize is the fixed byte length of an NSDP packet header.
const HeaderSize = 32

// macSize is the fixed wire width of the ClientMAC/ServerMAC header fields
// (struct format "6s").
const macSize = 6

// Result codes carried in the header's Result field.
const (
	// ResultSuccess is the only Result value that signals success.
	ResultSuccess = 0x0000
	// ResultBadPassword is returned by a switch that rejected v1 XOR auth
	// (see auth.go's AuthV2Unsupported for what this usually means).
	ResultBadPassword = 0x0700
)

// Op is an NSDP operation code (header byte 0x01). It is a plain numeric
// type, not a validated/closed enum: DecodePacket rejects a wire byte
// outside these four values (mirroring Python's Op(op_raw) constructor,
// which raises ValueError for an unrecognized value), but nothing else in
// this package restricts an Op variable to only these four constants.
type Op uint8

// Op values, mirroring Python protocols.nsdp.protocol.Op.
const (
	OpReadRequest   Op = 0x01
	OpReadResponse  Op = 0x02
	OpWriteRequest  Op = 0x03
	OpWriteResponse Op = 0x04
)

// String renders o as its Python enum member name for error messages, or a
// raw hex value for anything else (e.g. a value read off a malformed wire
// packet before validation rejects it).
func (o Op) String() string {
	switch o {
	case OpReadRequest:
		return "READ_REQUEST"
	case OpReadResponse:
		return "READ_RESPONSE"
	case OpWriteRequest:
		return "WRITE_REQUEST"
	case OpWriteResponse:
		return "WRITE_RESPONSE"
	default:
		return fmt.Sprintf("Op(0x%02X)", uint8(o))
	}
}

func isValidOp(o Op) bool {
	switch o {
	case OpReadRequest, OpReadResponse, OpWriteRequest, OpWriteResponse:
		return true
	default:
		return false
	}
}

// Tag is an NSDP TLV tag identifier (16-bit big-endian on the wire).
//
// Unlike Op, Tag is deliberately NOT a validated/closed enum: an
// unrecognized tag value (uncatalogued in this table, or from newer
// firmware) must round-trip losslessly through DecodeTLV/TLVEntry.Encode
// rather than error, mirroring Python's TLVEntry.decode falling back to the
// raw int when Tag(tag_raw) raises ValueError. Any uint16 value is a valid
// Tag.
type Tag uint16

// Tag values, mirroring Python protocols.nsdp.protocol.Tag (all 34 entries,
// grouped identically for diffability against the Python source; only the
// numeric values matter for wire compatibility).
const (
	// Packet markers
	TagStartOfMark Tag = 0x0000
	TagEndOfMark   Tag = 0xFFFF

	// Device identity
	TagModel        Tag = 0x0001
	TagHostname     Tag = 0x0003
	TagMAC          Tag = 0x0004
	TagLocation     Tag = 0x0005
	TagIPAddress    Tag = 0x0006
	TagNetmask      Tag = 0x0007
	TagGateway      Tag = 0x0008
	TagDHCPMode     Tag = 0x000B
	TagFirmwareVer1 Tag = 0x000D
	TagFirmwareVer2 Tag = 0x000E
	TagPortCount    Tag = 0x6000
	TagSerialNumber Tag = 0x7800

	// Authentication
	TagPassword       Tag = 0x000A
	TagAuthV2Salt     Tag = 0x0017 // recognised, NOT implemented; see auth.go
	TagAuthV2Password Tag = 0x001A // recognised, NOT implemented; see auth.go

	// Port information
	TagPortStatus     Tag = 0x0C00
	TagPortStatistics Tag = 0x1000

	// VLAN
	TagVLANEngine  Tag = 0x2000
	TagVLANMembers Tag = 0x2800
	TagPortPVID    Tag = 0x3000

	// QoS
	TagQOSEngine       Tag = 0x3400
	TagPortQOSPriority Tag = 0x3800

	// Traffic control
	TagIngressRateLimit   Tag = 0x4C00
	TagEgressRateLimit    Tag = 0x5000
	TagBroadcastFiltering Tag = 0x5400
	TagBroadcastBandwidth Tag = 0x5800
	TagPortMirroring      Tag = 0x5C00

	// IGMP
	TagIGMPSnooping           Tag = 0x6800
	TagBlockUnknownMulticast  Tag = 0x6C00
	TagIGMPv3HeaderValidation Tag = 0x7000
	TagIGMPStaticRouterPorts  Tag = 0x8000

	// Other
	TagLoopDetection  Tag = 0x9000
	TagActiveFirmware Tag = 0x000C

	// Actions (write-only)
	TagReboot       Tag = 0x0013
	TagFactoryReset Tag = 0x0400
)

// errNSDP wraps model.ErrNSDP with a formatted message, mirroring the
// python-side ValueError text as closely as Go's error idiom allows.
func errNSDP(format string, a ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, a...), model.ErrNSDP)
}

// TLVEntry is one NSDP TLV: a 2-byte tag, 2-byte length, then that many
// value bytes. Mirrors Python protocols.nsdp.protocol.TLVEntry.
type TLVEntry struct {
	Tag   Tag
	Value []byte
}

// Encode returns the wire form of t: 2-byte tag, 2-byte length, then Value.
func (t TLVEntry) Encode() []byte {
	out := make([]byte, 4+len(t.Value))
	binary.BigEndian.PutUint16(out[0:2], uint16(t.Tag))
	binary.BigEndian.PutUint16(out[2:4], uint16(len(t.Value)))
	copy(out[4:], t.Value)
	return out
}

// DecodeTLV decodes one TLV from the start of data, returning the entry and
// the number of bytes consumed. An unrecognized tag is kept as its raw
// uint16 value (Tag has no validation), never an error. Returns an error
// wrapping model.ErrNSDP if data is shorter than the 4-byte tag+length
// header, or if the declared length exceeds the bytes actually present.
func DecodeTLV(data []byte) (TLVEntry, int, error) {
	if len(data) < 4 {
		return TLVEntry{}, 0, errNSDP("NSDP TLV shorter than its 4-byte header")
	}
	tag := binary.BigEndian.Uint16(data[0:2])
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < 4+length {
		return TLVEntry{}, 0, errNSDP(
			"NSDP TLV declares %d value bytes but only %d are present",
			length, len(data)-4)
	}
	value := make([]byte, length)
	copy(value, data[4:4+length])
	return TLVEntry{Tag: Tag(tag), Value: value}, 4 + length, nil
}

// Packet is a full NSDP datagram: a fixed 32-byte header plus a list of
// TLVs. Mirrors Python protocols.nsdp.protocol.NSDPPacket.
type Packet struct {
	Op        Op
	ClientMAC []byte // exactly 6 bytes on the wire; see packMAC
	ServerMAC []byte // exactly 6 bytes on the wire; see packMAC
	Sequence  uint32 // full 4-byte header field (dossier §1.2: not 2 bytes + 2 reserved)
	Result    uint16
	TLVs      []TLVEntry
}

// AddTLV appends a TLVEntry to p.TLVs, mirroring Python's
// NSDPPacket.add_tlv.
func (p *Packet) AddTLV(tag Tag, value []byte) {
	p.TLVs = append(p.TLVs, TLVEntry{Tag: tag, Value: value})
}

// packMAC returns mac as an exact macSize-byte slice: zero-padded on the
// right if shorter, returned as-is if exactly macSize, or an error wrapping
// model.ErrNSDP if longer.
//
// The short-side zero-padding matches Python's struct.pack "6s" format code
// exactly. The long side does NOT match Python: struct.pack("6s", ...)
// silently truncates a too-long bytes object to macSize bytes (verified
// directly -- struct.pack("6s", b"1234567") == b"123456", no exception).
// This function deliberately diverges there and errors instead: silently
// dropping bytes off a MAC address is exactly the kind of wire-corrupting
// bug this codec should fail fast on rather than reproduce, and no caller
// in this codebase ever legitimately has a >6-byte MAC to encode. See
// docs/cross-language-divergences.md, "Slice 05", for this divergence.
func packMAC(mac []byte, field string) ([]byte, error) {
	if len(mac) > macSize {
		return nil, errNSDP("NSDP %s must be at most %d bytes, got %d", field, macSize, len(mac))
	}
	out := make([]byte, macSize)
	copy(out, mac)
	return out, nil
}

// Encode returns the wire bytes for p: the 32-byte header (version
// hardcoded 0x01, matching Python's encode()), the TLVs in order, then the
// unconditional 4-byte EndMarker (which is not itself a TLVEntry in p.TLVs).
func (p Packet) Encode() ([]byte, error) {
	clientMAC, err := packMAC(p.ClientMAC, "client_mac")
	if err != nil {
		return nil, err
	}
	serverMAC, err := packMAC(p.ServerMAC, "server_mac")
	if err != nil {
		return nil, err
	}

	header := make([]byte, HeaderSize)
	header[0x00] = 0x01 // version: hardcoded, not a settable field
	header[0x01] = byte(p.Op)
	binary.BigEndian.PutUint16(header[0x02:0x04], p.Result)
	// header[0x04:0x08] reserved1: left zero
	copy(header[0x08:0x0E], clientMAC)
	copy(header[0x0E:0x14], serverMAC)
	binary.BigEndian.PutUint32(header[0x14:0x18], p.Sequence)
	copy(header[0x18:0x1C], Signature)
	// header[0x1C:0x20] reserved3: left zero

	out := header
	for _, t := range p.TLVs {
		out = append(out, t.Encode()...)
	}
	out = append(out, EndMarker...)
	return out, nil
}

// DecodePacket decodes a full NSDP datagram, mirroring Python
// NSDPPacket.decode. Returns an error wrapping model.ErrNSDP if data is
// shorter than HeaderSize, the signature doesn't match, the operation byte
// isn't one of the four known Op values, or any contained TLV is malformed.
//
// The TLV loop starts at offset HeaderSize and continues while
// offset+4<=len(data); it stops (without appending) the instant a TLV's tag
// equals TagEndOfMark -- any bytes after that point are never
// validated/consumed, matching Python exactly.
func DecodePacket(data []byte) (Packet, error) {
	if len(data) < HeaderSize {
		return Packet{}, errNSDP("NSDP packet shorter than %d-byte header", HeaderSize)
	}
	header := data[:HeaderSize]

	signature := header[0x18:0x1C]
	if string(signature) != string(Signature) {
		return Packet{}, errNSDP("bad NSDP signature %q", signature)
	}

	opRaw := Op(header[0x01])
	result := binary.BigEndian.Uint16(header[0x02:0x04])
	clientMAC := append([]byte(nil), header[0x08:0x0E]...)
	serverMAC := append([]byte(nil), header[0x0E:0x14]...)
	sequence := binary.BigEndian.Uint32(header[0x14:0x18])

	tlvs := []TLVEntry{}
	offset := HeaderSize
	for offset+4 <= len(data) {
		entry, consumed, err := DecodeTLV(data[offset:])
		if err != nil {
			return Packet{}, err
		}
		if entry.Tag == TagEndOfMark {
			break
		}
		tlvs = append(tlvs, entry)
		offset += consumed
	}

	if !isValidOp(opRaw) {
		return Packet{}, errNSDP("unrecognized NSDP operation code 0x%02X", uint8(opRaw))
	}

	return Packet{
		Op:        opRaw,
		ClientMAC: clientMAC,
		ServerMAC: serverMAC,
		Sequence:  sequence,
		Result:    result,
		TLVs:      tlvs,
	}, nil
}
