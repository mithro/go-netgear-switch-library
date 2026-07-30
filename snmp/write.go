package snmp

import (
	"sort"

	"github.com/mithro/go-netgear-switch-library/model"
)

// EncodePortBitmap is the inverse of DecodePortBitmap: a port set -> a
// wire-format VLAN bitmap. Bit 7 (MSB) of byte 0 is port 1; byteIdx, bit =
// divmod(port-1, 8). Ported from protocols/snmp/write.encode_port_bitmap
// (Python) -- see D-WR §1.2.
//
// The buffer grows past widthBytes if a port number needs it -- callers
// never pre-size for the actual port count, and an out-of-range port still
// encodes rather than silently truncating.
func EncodePortBitmap(ports []int, widthBytes int) []byte {
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

// SetPortBit reads bitmap, flips exactly one port's bit (present iff on),
// and re-encodes -- every other port's membership is preserved untouched.
// Ported from protocols/snmp/write.set_port_bit (Python) -- see D-WR §1.3.
//
// widthBytes is an optional model-derived minimum width (e.g.
// VlanBitmapWidth's result); at most one value is honoured, extras are
// ignored. The result's width is max(8, len(bitmap), widthBytes) -- never
// narrower than 8 bytes, never narrower than the input bitmap's own width,
// and at least as wide as the requested width, but a wider input or the
// 8-byte default wins if either is larger: widthBytes only ever widens,
// never narrows.
//
// bitmap is never mutated or aliased into the result: DecodePortBitmap only
// reads it, and EncodePortBitmap always allocates a fresh buffer.
func SetPortBit(bitmap []byte, port int, on bool, widthBytes ...int) []byte {
	requested := 0
	if len(widthBytes) > 0 {
		requested = widthBytes[0]
	}

	current := DecodePortBitmap(bitmap)
	next := make([]int, 0, len(current)+1)
	for _, p := range current {
		if p != port {
			next = append(next, p)
		}
	}
	if on {
		next = append(next, port)
		sort.Ints(next)
	}

	target := len(bitmap)
	if requested > target {
		target = requested
	}
	if target < 8 {
		target = 8
	}
	return EncodePortBitmap(next, target)
}

// MembershipBitmaps computes the (newEgress, newUntagged) bitmaps for one
// port's VLAN membership change, per this mode table (D-WR §1.4):
//
//	mode              egress bit   untagged bit
//	VlanUntagged      on           on
//	VlanTagged        on           off
//	VlanExcluded      off          off
//
// Both bitmaps are computed via two independent SetPortBit calls, each its
// own read-modify-write against the current egress/untagged bitmap
// respectively -- port's bit is the only one that can change in either
// column; every other port's membership is preserved. width is forwarded to
// both calls identically (0 means "no model-derived minimum requested",
// mirroring Python's width_bytes=None).
func MembershipBitmaps(egress, untagged []byte, port int, mode model.VlanMode, width int) (newEgress, newUntagged []byte) {
	inEgress := mode == model.VlanUntagged || mode == model.VlanTagged
	inUntagged := mode == model.VlanUntagged
	newEgress = SetPortBit(egress, port, inEgress, width)
	newUntagged = SetPortBit(untagged, port, inUntagged, width)
	return newEgress, newUntagged
}

// VlanBitmapWidth is the wire byte-width of a dot1q VLAN egress/untagged
// bitmap for a model with portCount ports: max(8, ceil(portCount/8)).
// dot1qVlanStaticEgressPorts/UntaggedPorts are packed 8 ports/byte,
// MSB-first (port 1 = bit 7 of byte 0); the Q-BRIDGE MIB's own default
// PortList width is 8 bytes (64 ports), so a model with more ports needs a
// wider bitmap or a SET's wire length won't match what the device expects.
// Ported from protocols/snmp/write.vlan_bitmap_width (Python) -- see D-WR
// §1.5.
func VlanBitmapWidth(portCount int) int {
	w := (portCount + 7) / 8
	if w < 8 {
		return 8
	}
	return w
}
