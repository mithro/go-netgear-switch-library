package nsdp

// Ported field-for-field from
// src/netgear_switch/protocols/nsdp/parsers.py at pin 1aa1274 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274, branch fix/s3300-52x-live-verify). Any discrepancy
// between this file and that pin is a bug in this file, not a deliberate
// deviation, unless called out in a comment.
//
// Every parser here is total over the bytes it accepts and returns an error
// wrapping model.ErrNSDP on a wrong length or a bad prefix, so a malformed
// TLV surfaces early rather than producing a silently-wrong value.

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// ParseIPv4 decodes a 4-byte IPv4 TLV value (e.g. IP_ADDRESS/NETMASK/GATEWAY)
// into dotted-quad form, mirroring Python parsers.parse_ipv4 (which delegates
// to socket.inet_ntoa). Returns an error wrapping model.ErrNSDP if data is
// not exactly 4 bytes.
func ParseIPv4(data []byte) (string, error) {
	if len(data) != 4 {
		return "", errNSDP("IPv4 TLV must be 4 bytes, got %d", len(data))
	}
	return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3]), nil
}

// ParseMAC decodes a 6-byte MAC TLV value into lowercase colon-hex form
// ("aa:bb:cc:dd:ee:ff"), mirroring Python parsers.parse_mac. Returns an
// error wrapping model.ErrNSDP if data is not exactly 6 bytes.
func ParseMAC(data []byte) (string, error) {
	if len(data) != 6 {
		return "", errNSDP("MAC TLV must be 6 bytes, got %d", len(data))
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		data[0], data[1], data[2], data[3], data[4], data[5]), nil
}

// ParsePortStatus decodes a 3-byte PORT_STATUS TLV value (tag 0x0C00),
// mirroring Python parsers.parse_port_status: byte 0 is the port ID, byte 1
// is the raw LinkSpeed wire byte (decoded via model.LinkSpeedFromByte, which
// never errors on an unrecognized value), and byte 2 is unused/ignored.
// Returns an error wrapping model.ErrNSDP if data is not exactly 3 bytes.
func ParsePortStatus(data []byte) (model.NsdpPortStatus, error) {
	if len(data) != 3 {
		return model.NsdpPortStatus{}, errNSDP("PORT_STATUS TLV must be 3 bytes, got %d", len(data))
	}
	return model.NsdpPortStatus{
		PortID: int(data[0]),
		Speed:  model.LinkSpeedFromByte(data[1]),
	}, nil
}

// ParsePortStatistics decodes a 49-byte PORT_STATISTICS TLV value (tag
// 0x1000), mirroring Python parsers.parse_port_statistics: byte 0 is the
// port ID, then three big-endian uint64 counters (rx bytes, tx bytes, CRC
// errors) at offset 1 -- 1+24 = 25 of the 49 bytes consumed; the trailing 24
// bytes are unused padding/other counters, not modeled. Returns an error
// wrapping model.ErrNSDP if data is not exactly 49 bytes.
func ParsePortStatistics(data []byte) (model.NsdpPortStatistics, error) {
	if len(data) != 49 {
		return model.NsdpPortStatistics{}, errNSDP("PORT_STATISTICS TLV must be 49 bytes, got %d", len(data))
	}
	return model.NsdpPortStatistics{
		PortID:        int(data[0]),
		BytesReceived: binary.BigEndian.Uint64(data[1:9]),
		BytesSent:     binary.BigEndian.Uint64(data[9:17]),
		CrcErrors:     binary.BigEndian.Uint64(data[17:25]),
	}, nil
}

// ParsePortPvid decodes a 3-byte PORT_PVID TLV value (tag 0x3000), mirroring
// Python parsers.parse_port_pvid: byte 0 is the port ID, bytes 1-2 are the
// big-endian VLAN ID. Returns an error wrapping model.ErrNSDP if data is not
// exactly 3 bytes.
func ParsePortPvid(data []byte) (model.NsdpPortPvid, error) {
	if len(data) != 3 {
		return model.NsdpPortPvid{}, errNSDP("PORT_PVID TLV must be 3 bytes, got %d", len(data))
	}
	return model.NsdpPortPvid{
		PortID: int(data[0]),
		VlanID: int(binary.BigEndian.Uint16(data[1:3])),
	}, nil
}

// ParseSerial decodes a SERIAL_NUMBER TLV value (tag 0x7800), mirroring
// Python parsers.parse_serial: the first byte must be the fixed prefix 0x01,
// and the remaining bytes are ASCII-decoded (non-ASCII bytes replaced with
// U+FFFD, matching Python's errors="replace") with trailing NUL bytes
// stripped. Returns an error wrapping model.ErrNSDP if data is empty or its
// first byte is not 0x01.
func ParseSerial(data []byte) (string, error) {
	if len(data) == 0 || data[0] != 0x01 {
		prefix := data
		if len(prefix) > 1 {
			prefix = prefix[:1]
		}
		return "", errNSDP("SERIAL_NUMBER TLV: unexpected prefix byte %q", prefix)
	}
	return decodeASCII(data[1:]), nil
}

// decodeASCII decodes data as ASCII, replacing any byte >= 0x80 with the
// Unicode replacement character, then trims trailing NUL bytes -- mirroring
// Python's `data.decode("ascii", errors="replace").rstrip("\x00")`, used by
// ParseSerial and by ParseDevice for MODEL/HOSTNAME/FIRMWARE_VER_1.
func decodeASCII(data []byte) string {
	var b strings.Builder
	b.Grow(len(data))
	for _, c := range data {
		if c < 0x80 {
			b.WriteByte(c)
		} else {
			b.WriteRune('�')
		}
	}
	return strings.TrimRight(b.String(), "\x00")
}

// bitmapToPorts decodes a port-membership bitmap: MSB-first, 1-based (byte 0
// bit 0x80 = port 1 ... bit 0x01 = port 8, byte 1 bit 0x80 = port 9, etc.),
// mirroring Python parsers.bitmap_to_ports. The result is sorted ascending
// and non-nil by construction (iterating bytes low-to-high and, within a
// byte, MSB-to-LSB visits ports in strictly increasing order).
//
// This is deliberately a separate, NSDP-local copy of the same algorithm as
// snmp.DecodePortBitmap/EncodePortBitmap (identical MSB-first,
// divmod(port-1,8) bit math) rather than a shared import: the pinned Python
// reference (parsers.py) implements this locally too, importing nothing from
// protocols/snmp -- there is no bitmap utility file for it to share. D-NSDP
// §3.7 settles this explicitly: duplicate to match Python exactly, treating
// unification as a legitimate but separate follow-up cleanup, not a
// requirement of this port.
func bitmapToPorts(bitmap []byte) []int {
	ports := make([]int, 0)
	for byteIdx, byteVal := range bitmap {
		for bit := 0; bit < 8; bit++ {
			if byteVal&(0x80>>uint(bit)) != 0 {
				ports = append(ports, byteIdx*8+bit+1)
			}
		}
	}
	return ports
}

// portsToBitmap is the inverse of bitmapToPorts, mirroring Python
// parsers.ports_to_bitmap: same MSB-first, 1-based layout. The returned
// buffer grows past widthBytes if a port number needs it -- callers never
// pre-size for the actual port count, and an out-of-range port still encodes
// rather than silently being dropped.
func portsToBitmap(ports []int, widthBytes int) []byte {
	data := make([]byte, widthBytes)
	for _, p := range ports {
		byteIdx := (p - 1) / 8
		bit := (p - 1) % 8
		for byteIdx >= len(data) {
			data = append(data, 0)
		}
		data[byteIdx] |= 0x80 >> uint(bit)
	}
	return data
}

// ParseVlanMembers decodes a VLAN_MEMBERS TLV value (tag 0x2800), mirroring
// Python parsers.parse_vlan_members: a big-endian VLAN ID (2 bytes) followed
// by two port bitmaps (member, then tagged), each ceil(portCount/8) bytes
// wide. Returns an error wrapping model.ErrNSDP if data is shorter than
// 2+2*bitmapBytes.
func ParseVlanMembers(data []byte, portCount int) (model.NsdpVlanMembership, error) {
	bitmapBytes := (portCount + 7) / 8
	expected := 2 + bitmapBytes*2
	if len(data) < expected {
		return model.NsdpVlanMembership{}, errNSDP(
			"VLAN_MEMBERS TLV must be >=%d bytes for %d ports, got %d", expected, portCount, len(data))
	}
	member := data[2 : 2+bitmapBytes]
	tagged := data[2+bitmapBytes : 2+bitmapBytes*2]
	return model.NsdpVlanMembership{
		VlanID:      int(binary.BigEndian.Uint16(data[0:2])),
		MemberPorts: bitmapToPorts(member),
		TaggedPorts: bitmapToPorts(tagged),
	}, nil
}

// ParsePortMirroring decodes a PORT_MIRRORING TLV value (tag 0x5C00),
// mirroring Python parsers.parse_port_mirroring: byte 0 is the destination
// port, and every remaining byte (whatever the outer TLV length leaves) is
// fed to bitmapToPorts as the source-port bitmap.
//
// The source bitmap width is deliberately NOT fixed here: real hardware
// varies it by port count (a 5-port GS105PE returns a 2-byte bitmap/3-byte
// TLV; a 10-port GS110EMX a 3-byte bitmap/4-byte TLV, both confirmed live
// 2026-07-21). Hardcoding a fixed width would reintroduce the exact bug the
// Python history documents fixing. Only a fully empty TLV (0 bytes, no
// destination-port byte at all) is rejected.
func ParsePortMirroring(data []byte) (model.NsdpPortMirroring, error) {
	if len(data) == 0 {
		return model.NsdpPortMirroring{}, errNSDP("PORT_MIRRORING TLV must be at least 1 byte, got 0")
	}
	return model.NsdpPortMirroring{
		DestinationPort: int(data[0]),
		SourcePorts:     bitmapToPorts(data[1:]),
	}, nil
}

// ParseIgmpSnooping decodes an IGMP_SNOOPING TLV value (tag 0x6800),
// mirroring Python parsers.parse_igmp_snooping: byte 1 is the enabled flag
// (byte 0 is unused); if at least 4 bytes are present, byte 3 is the VLAN ID
// (0 meaning "no VLAN association", reported as a nil pointer). Returns an
// error wrapping model.ErrNSDP if data is shorter than 2 bytes.
func ParseIgmpSnooping(data []byte) (model.NsdpIgmpSnooping, error) {
	if len(data) < 2 {
		return model.NsdpIgmpSnooping{}, errNSDP("IGMP_SNOOPING TLV must be >= 2 bytes, got %d", len(data))
	}
	out := model.NsdpIgmpSnooping{Enabled: data[1] != 0}
	if len(data) >= 4 && data[3] != 0 {
		out.VlanID = model.Ptr(int(data[3]))
	}
	return out, nil
}

// ParseDevice aggregates a READ_RESPONSE packet's TLVs into an NsdpDevice,
// mirroring Python parsers.parse_device.
//
// Two-pass dispatch: pass 1 scans only for PORT_COUNT (defaulting to 8 if
// absent, matching Python), because VLAN_MEMBERS's bitmap width is
// model-dependent and a VLAN_MEMBERS TLV can appear in the packet BEFORE the
// PORT_COUNT TLV -- a single forward pass risks misparsing an early
// VLAN_MEMBERS TLV with the wrong (default) width. Pass 2 does the real
// per-tag dispatch, using the now-known port count.
//
// Returns an error wrapping model.ErrNSDP if no MODEL tag is present in the
// packet (a required field), or if any individual TLV fails to parse. A
// missing MAC tag is not an error: it falls back to parsing packet.ServerMAC
// (the packet header field).
//
// VLAN_ENGINE's byte is validated against VLANEngine's 0-4 range and errors
// on anything else -- mirroring Python's VLANEngine(tlv.value[0]), an
// IntEnum constructor that raises ValueError for an out-of-range value,
// propagating out of parse_device exactly like any other malformed-TLV
// error. This is deliberately unlike PORT_STATUS's speed byte
// (model.LinkSpeedFromByte), which never errors -- Python's LinkSpeed.from_byte
// explicitly catches its own ValueError and returns DOWN instead, while
// VLANEngine has no such catch.
func ParseDevice(packet Packet) (model.NsdpDevice, error) {
	portCount := 8
	for _, tlv := range packet.TLVs {
		if tlv.Tag == TagPortCount && len(tlv.Value) > 0 {
			portCount = int(tlv.Value[0])
		}
	}

	var (
		modelName          *string
		mac                *string
		hostname           *string
		ip                 *string
		netmask            *string
		gateway            *string
		firmwareVersion    *string
		dhcpEnabled        *bool
		portCountField     *int
		serialNumber       *string
		vlanEngine         *model.VLANEngine
		qosEngine          *int
		portMirroring      *model.NsdpPortMirroring
		igmpSnooping       *model.NsdpIgmpSnooping
		broadcastFiltering *bool
		loopDetection      *bool

		portStatus  []model.NsdpPortStatus
		portStats   []model.NsdpPortStatistics
		vlanMembers []model.NsdpVlanMembership
		pvids       []model.NsdpPortPvid
	)

	for _, tlv := range packet.TLVs {
		switch tlv.Tag {
		case TagModel:
			s := decodeASCII(tlv.Value)
			modelName = &s
		case TagMAC:
			s, err := ParseMAC(tlv.Value)
			if err != nil {
				return model.NsdpDevice{}, err
			}
			mac = &s
		case TagHostname:
			s := decodeASCII(tlv.Value)
			hostname = &s
		case TagIPAddress:
			s, err := ParseIPv4(tlv.Value)
			if err != nil {
				return model.NsdpDevice{}, err
			}
			ip = &s
		case TagNetmask:
			s, err := ParseIPv4(tlv.Value)
			if err != nil {
				return model.NsdpDevice{}, err
			}
			netmask = &s
		case TagGateway:
			s, err := ParseIPv4(tlv.Value)
			if err != nil {
				return model.NsdpDevice{}, err
			}
			gateway = &s
		case TagFirmwareVer1:
			s := decodeASCII(tlv.Value)
			firmwareVersion = &s
		case TagDHCPMode:
			if len(tlv.Value) > 0 {
				dhcpEnabled = model.Ptr(tlv.Value[0] != 0)
			}
		case TagPortCount:
			if len(tlv.Value) > 0 {
				portCountField = model.Ptr(int(tlv.Value[0]))
			}
		case TagSerialNumber:
			s, err := ParseSerial(tlv.Value)
			if err != nil {
				return model.NsdpDevice{}, err
			}
			serialNumber = &s
		case TagVLANEngine:
			if len(tlv.Value) > 0 {
				v := tlv.Value[0]
				if v > 0x04 {
					return model.NsdpDevice{}, errNSDP("VLAN_ENGINE TLV: invalid value %d, want 0-4", v)
				}
				vlanEngine = model.Ptr(model.VLANEngine(v))
			}
		case TagPortStatus:
			st, err := ParsePortStatus(tlv.Value)
			if err != nil {
				return model.NsdpDevice{}, err
			}
			portStatus = append(portStatus, st)
		case TagPortStatistics:
			st, err := ParsePortStatistics(tlv.Value)
			if err != nil {
				return model.NsdpDevice{}, err
			}
			portStats = append(portStats, st)
		case TagVLANMembers:
			vm, err := ParseVlanMembers(tlv.Value, portCount)
			if err != nil {
				return model.NsdpDevice{}, err
			}
			vlanMembers = append(vlanMembers, vm)
		case TagPortPVID:
			pv, err := ParsePortPvid(tlv.Value)
			if err != nil {
				return model.NsdpDevice{}, err
			}
			pvids = append(pvids, pv)
		case TagQOSEngine:
			if len(tlv.Value) > 0 {
				qosEngine = model.Ptr(int(tlv.Value[0]))
			}
		case TagPortMirroring:
			pm, err := ParsePortMirroring(tlv.Value)
			if err != nil {
				return model.NsdpDevice{}, err
			}
			portMirroring = &pm
		case TagIGMPSnooping:
			igmp, err := ParseIgmpSnooping(tlv.Value)
			if err != nil {
				return model.NsdpDevice{}, err
			}
			igmpSnooping = &igmp
		case TagBroadcastFiltering:
			if len(tlv.Value) > 0 {
				broadcastFiltering = model.Ptr(tlv.Value[0] != 0)
			}
		case TagLoopDetection:
			if len(tlv.Value) > 0 {
				loopDetection = model.Ptr(tlv.Value[0] != 0)
			}
		}
	}

	if modelName == nil {
		return model.NsdpDevice{}, errNSDP("no MODEL tag in NSDP response")
	}
	if mac == nil {
		s, err := ParseMAC(packet.ServerMAC)
		if err != nil {
			return model.NsdpDevice{}, err
		}
		mac = &s
	}

	return model.NsdpDevice{
		Model:              *modelName,
		Mac:                *mac,
		Hostname:           hostname,
		IP:                 ip,
		Netmask:            netmask,
		Gateway:            gateway,
		FirmwareVersion:    firmwareVersion,
		DhcpEnabled:        dhcpEnabled,
		PortCount:          portCountField,
		SerialNumber:       serialNumber,
		VlanEngine:         vlanEngine,
		PortStatus:         portStatus,
		PortStatistics:     portStats,
		VlanMembers:        vlanMembers,
		PortPvids:          pvids,
		QosEngine:          qosEngine,
		PortMirroring:      portMirroring,
		IgmpSnooping:       igmpSnooping,
		BroadcastFiltering: broadcastFiltering,
		LoopDetection:      loopDetection,
	}, nil
}
