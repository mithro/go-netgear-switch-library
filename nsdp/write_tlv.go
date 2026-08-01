package nsdp

// write_tlv.go: standalone value-TLV builders for the write TLVs the
// 1841111->7ebfe5d re-pin added, ported from pin protocols/nsdp/write.py's
// vlan_destroy_tlv / port_name_tlv (both pure, no I/O). They mirror the pin's
// own standalone-function structure; the Writer wiring that calls them
// (DeleteVlan via VLAN_DESTROY, a per-port description write) is the remaining
// NSDP-v2/tag-surface reconciliation step -- see the progress ledger.

import "encoding/binary"

// VLANDestroyTLV builds the write-only VLAN-destroy action TLV (0x2C00): a
// 2-byte big-endian VLAN id. Ported from pin write.py vlan_destroy_tlv,
// GROUNDED in ngadmin's ngadmin_VLANDestroy (newShortAttr(ATTR_VLAN_DESTROY,
// vlan)). Un-exercised on hardware; verify-after-write is the runtime guard.
func VLANDestroyTLV(vlan int) TLVEntry {
	var v [2]byte
	binary.BigEndian.PutUint16(v[:], uint16(vlan)) //nolint:gosec // VLAN IDs are always well under 65536
	return TLVEntry{Tag: TagVLANDestroy, Value: v[:]}
}

// PortNameTLV builds the per-port description write TLV (0xB000): the 1-based
// port byte followed by the UTF-8 name. Same shape as the read encoding.
// Ported from pin write.py port_name_tlv; un-exercised on hardware.
func PortNameTLV(port int, name string) TLVEntry {
	return TLVEntry{Tag: TagPortName, Value: append([]byte{byte(port)}, name...)} //nolint:gosec // port is a 1-based port number, always well under 256
}
