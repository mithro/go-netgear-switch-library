package nsdp

// Ported field-for-field from src/netgear_switch/protocols/nsdp/write.py at
// pin 1aa1274 in python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274, branch fix/s3300-52x-live-verify). Any discrepancy
// between this file and that pin is a bug in this file, not a deliberate
// deviation, unless called out in a comment.
//
// UNVERIFIED write path (mirrors the Python module's own house-style
// caveat): this entire NSDP write path -- the WRITE_REQUEST value-TLV
// encodings here plus the v1 XOR auth in auth.go -- is a from-scratch
// addition with ZERO verification against real hardware: the lifted
// gdoc2netcfg/src/nsdp prior art is READ-ONLY, so nothing in it exercises
// writes. It stays UNVERIFIED pending a real capture; verify-after-write at
// the facade layer is the runtime guard against a silently wrong encoding.
// Critically, the reference spec (gdoc2netcfg/docs/nsdp-protocol.md) marks
// PORT_PVID (0x3000) and VLAN_MEMBERS (0x2800) as READ-ONLY (R), unlike
// hostname/ip/netmask/gateway/dhcp_mode/vlan_engine (R/W). Writing
// PVID/VLAN membership via NSDP may therefore be REJECTED by real hardware.
// Do NOT read PvidTLV/VlanMembersTLV's existence here as confirmation those
// tags are writable; their writability is unconfirmed and must be settled
// by a hardware capture.
//
// ResultSuccess/ResultBadPassword (mirroring Python's RESULT_SUCCESS/
// RESULT_BAD_PASSWORD) are already declared in protocol.go.

import (
	"encoding/binary"
	"net"
)

// BuildReadRequest builds a READ_REQUEST packet with one length-0 TLV per
// requested tag ("please read this"), mirroring Python write.build_read_request.
func BuildReadRequest(clientMAC, serverMAC []byte, sequence uint32, tags []Tag) Packet {
	pkt := Packet{
		Op:        OpReadRequest,
		ClientMAC: clientMAC,
		ServerMAC: serverMAC,
		Sequence:  sequence,
	}
	for _, tag := range tags {
		pkt.AddTLV(tag, nil)
	}
	return pkt
}

// BuildWriteRequest builds a WRITE_REQUEST packet, mirroring Python
// write.build_write_request: a v1-XOR-encoded PASSWORD TLV is prepended as
// the FIRST TLV, then the caller's tlvs follow unchanged, in order. Returns
// an error wrapping model.ErrNSDP if password contains a non-ASCII byte (see
// EncodePasswordV1/PasswordTLV in auth.go).
func BuildWriteRequest(clientMAC, serverMAC []byte, sequence uint32, password string, tlvs []TLVEntry) (Packet, error) {
	passwordTLV, err := PasswordTLV(password)
	if err != nil {
		return Packet{}, err
	}
	pkt := Packet{
		Op:        OpWriteRequest,
		ClientMAC: clientMAC,
		ServerMAC: serverMAC,
		Sequence:  sequence,
	}
	pkt.TLVs = append(pkt.TLVs, passwordTLV)
	pkt.TLVs = append(pkt.TLVs, tlvs...)
	return pkt, nil
}

// PvidTLV builds a PORT_PVID TLV (tag 0x3000): port (1 byte) + VLAN ID
// (big-endian uint16), mirroring Python write.pvid_tlv's
// `bytes([port]) + struct.pack(">H", vlan)`.
//
// Unlike Python -- where an out-of-range port/vlan raises only when the
// value is later packed (bytes()/struct.pack ValueError/struct.error) --
// this returns an error wrapping model.ErrNSDP up front if port or vlan
// can't fit their wire width. Silently truncating an out-of-range int to a
// byte/uint16 would produce a wire-corrupting TLV; see the packMAC
// divergence note in protocol.go for the same fail-fast philosophy, and
// docs/cross-language-divergences.md, "Slice 05", for this one.
func PvidTLV(port, vlan int) (TLVEntry, error) {
	if port < 0 || port > 0xFF {
		return TLVEntry{}, errNSDP("NSDP PORT_PVID port must fit a byte (0-255), got %d", port)
	}
	if vlan < 0 || vlan > 0xFFFF {
		return TLVEntry{}, errNSDP("NSDP PORT_PVID vlan must fit a uint16 (0-65535), got %d", vlan)
	}
	value := make([]byte, 3)
	value[0] = byte(port)
	binary.BigEndian.PutUint16(value[1:3], uint16(vlan))
	return TLVEntry{Tag: TagPortPVID, Value: value}, nil
}

// VlanMembersTLV builds a VLAN_MEMBERS TLV (tag 0x2800): VLAN ID (big-endian
// uint16) + a member-port bitmap + a tagged-port bitmap, each
// ceil(portCount/8) bytes wide, mirroring Python write.vlan_members_tlv.
//
// Returns an error wrapping model.ErrNSDP if vlan can't fit a uint16 (see
// PvidTLV's divergence note -- the same fail-fast philosophy applies here).
// members/tagged have no such bound: portsToBitmap grows its buffer to fit
// any port value, exactly matching Python's ports_to_bitmap.
func VlanMembersTLV(vlan int, members, tagged []int, portCount int) (TLVEntry, error) {
	if vlan < 0 || vlan > 0xFFFF {
		return TLVEntry{}, errNSDP("NSDP VLAN_MEMBERS vlan must fit a uint16 (0-65535), got %d", vlan)
	}
	width := (portCount + 7) / 8
	value := make([]byte, 2, 2+2*width)
	binary.BigEndian.PutUint16(value, uint16(vlan))
	value = append(value, portsToBitmap(members, width)...)
	value = append(value, portsToBitmap(tagged, width)...)
	return TLVEntry{Tag: TagVLANMembers, Value: value}, nil
}

// IPv4TLV builds a TLV whose value is dotted's 4-byte IPv4 encoding, for any
// IPv4-shaped tag (IP_ADDRESS/NETMASK/GATEWAY), mirroring Python
// write.ipv4_tlv (which delegates to socket.inet_aton).
//
// Go's net.ParseIP (strict dotted-quad, unlike inet_aton's leniency toward
// abbreviated forms like "10.1.5") is used deliberately: every call site in
// this codebase always passes a full dotted-quad address, so the stricter
// parse is a no-op in practice and fails fast on a malformed address rather
// than guessing at Python's abbreviated-form semantics. See
// docs/cross-language-divergences.md, "Slice 05".
func IPv4TLV(tag Tag, dotted string) (TLVEntry, error) {
	ip := net.ParseIP(dotted)
	if ip == nil {
		return TLVEntry{}, errNSDP("NSDP IPv4 TLV: invalid dotted-quad address %q", dotted)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return TLVEntry{}, errNSDP("NSDP IPv4 TLV: %q is not an IPv4 address", dotted)
	}
	return TLVEntry{Tag: tag, Value: ip4}, nil
}

// DhcpTLV builds a DHCP_MODE TLV (tag 0x000B): b"\x01" if enabled else
// b"\x00", mirroring Python write.dhcp_tlv.
func DhcpTLV(enabled bool) TLVEntry {
	value := []byte{0x00}
	if enabled {
		value[0] = 0x01
	}
	return TLVEntry{Tag: TagDHCPMode, Value: value}
}

// rebootTLV builds an empty-value REBOOT TLV (tag 0x0013), mirroring Python
// write.reboot_tlv.
//
// DEAD CODE, deliberately preserved: D-NSDP §4.1/§6.8 confirm the pinned
// Python reference itself never wires reboot_tlv into any write-facade
// method or NsdpWriter -- it exists there purely as a unit-tested encoder
// with no caller, because a reboot write op is unverified against real
// hardware. This function is kept unexported (not part of this package's
// write-builder API surface) for the same reason: it must not be wired into
// a future BackendWriter.Reboot without a hardware capture confirming the
// tag is honoured. If BackendWriter ever grows a Reboot method, the NSDP
// writer's implementation should return model.ErrUnsupportedCapability, NOT
// call this.
func rebootTLV() TLVEntry {
	return TLVEntry{Tag: TagReboot, Value: []byte{}}
}
