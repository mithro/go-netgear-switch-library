package virtual

// state_switchport.go: the FASTPATH vendor SWITCHPORT per-port state the
// mock carries for a model whose registry entry says
// SnmpVlanWrite == model.SNMPVlanWriteFastpathSwitchport (the M4300s), ported
// field-for-field from src/netgear_switch/virtual/state.py's
// _all_vlans_bitmap/_vlan_bitmap_bytes/_vlans_in_bitmap module functions and
// VirtualSwitchState's _switchport_model/_access_mode_ports/
// _reject_if_readonly_qbridge/_switchport_defaults/_apply_switchport/
// _reconcile_qbridge_membership/_refuse_vlan_creation_if_unsupported methods
// (the normative source; that repo is read-only from here, pin b26eb1f).
// Any discrepancy between this file and the Python source is a bug here.

import (
	"fmt"
	"sort"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// isSwitchportModel reports whether m's VLAN membership is owned by
// switchport mode, mirroring Python VirtualSwitchState._switchport_model
// (state.py:670-673).
func isSwitchportModel(m *model.SwitchModel) bool {
	return m.SnmpVlanWrite == model.SNMPVlanWriteFastpathSwitchport
}

// allVlansBitmap returns a switchport allowed-VLAN bitmap with VLANs
// 1..4093 set, mirroring Python state._all_vlans_bitmap (state.py:54-65).
// Matches the real M4300 default: a live read of the allowed-VLAN column
// returned 4093 VLANs set in a 512-byte map.
func allVlansBitmap() []byte {
	data := make([]byte, snmp.SwitchportVlanBitmapBytes)
	for vlan := 1; vlan < 4094; vlan++ {
		data[(vlan-1)/8] |= 0x80 >> uint((vlan-1)%8) //nolint:gosec // bit offset is always 0-7
	}
	return data
}

// vlanBitmapBytes encodes vlans (a member-iff-true set) into a 512-byte
// switchport bitmap, mirroring Python state._vlan_bitmap_bytes
// (state.py:68-75).
func vlanBitmapBytes(vlans map[int]bool) []byte {
	data := make([]byte, snmp.SwitchportVlanBitmapBytes)
	for vlan, present := range vlans {
		if !present {
			continue
		}
		data[(vlan-1)/8] |= 0x80 >> uint((vlan-1)%8) //nolint:gosec // bit offset is always 0-7
	}
	return data
}

// vlansInBitmap decodes a switchport VLAN bitmap (MSB-first, VLAN 1 = bit 7
// of byte 0), mirroring Python state._vlans_in_bitmap (state.py:78-85).
func vlansInBitmap(bitmap []byte) map[int]bool {
	out := map[int]bool{}
	for i, b := range bitmap {
		for off := 0; off < 8; off++ {
			if b&(0x80>>uint(off)) != 0 {
				out[i*8+off+1] = true
			}
		}
	}
	return out
}

// switchportDefaults seeds port's switchport row on first touch, mirroring
// Python VirtualSwitchState._switchport_defaults (state.py:717-734).
//
// Defaults are the live-measured factory shape of an untouched M4300 port:
// mode access(1), access VLAN 1, native VLAN 1, all 4093 VLANs allowed, and
// general-mode participation = untagged in VLAN 1 / tagged nowhere (column 7
// read VLAN 1 and column 8 read empty on EVERY port of both M4300 SKUs).
func (s *State) switchportDefaults(port int) {
	if _, ok := s.SwitchportMode[port]; !ok {
		s.SwitchportMode[port] = snmp.SwitchportModeAccess
	}
	if _, ok := s.SwitchportAccessVlan[port]; !ok {
		s.SwitchportAccessVlan[port] = 1
	}
	if _, ok := s.SwitchportNativeVlan[port]; !ok {
		s.SwitchportNativeVlan[port] = 1
	}
	if _, ok := s.SwitchportAllowedVlans[port]; !ok {
		// Real hardware ships every VLAN allowed (4093 of them on the M4300).
		s.SwitchportAllowedVlans[port] = allVlansBitmap()
	}
	if _, ok := s.SwitchportGeneralUntagged[port]; !ok {
		s.SwitchportGeneralUntagged[port] = map[int]bool{1: true}
	}
	if _, ok := s.SwitchportGeneralTagged[port]; !ok {
		s.SwitchportGeneralTagged[port] = map[int]bool{}
	}
}

// accessModePorts returns the physical ports currently in switchport access
// mode, mirroring Python VirtualSwitchState._access_mode_ports
// (state.py:675-684). Sorted ascending -- a deliberate Go-side determinism
// choice; Python's property yields dict-insertion order, which the pin
// itself never asserts on (test_switchport_vlan_write.py only checks the
// list is non-empty, never its order).
func (s *State) accessModePorts() []int {
	for port := range s.Ports {
		s.switchportDefaults(port)
	}
	var out []int
	for p, m := range s.SwitchportMode {
		if m == snmp.SwitchportModeAccess {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// rejectIfReadonlyQbridge refuses a Q-BRIDGE egress PortList write exactly
// as FASTPATH 12.x does, mirroring Python
// VirtualSwitchState._reject_if_readonly_qbridge (state.py:686-715).
//
// The rule was pinned down live on 2026-07-30 with a deterministic A/B/A on
// m4300-16x @10.1.5.20 (fw 12.0.19.15): flipping ONE port (1/0/1) between
// general and access mode and issuing BYTE-IDENTICAL writes to an unrelated
// throwaway VLAN each time gave general->noError, access->commitFailed,
// general->noError, trunk->noError, access->commitFailed, general->noError.
// So dot1qVlanStaticEgressPorts is writable only while NO interface on the
// switch is in access mode -- switch-wide, not per-VLAN. Panics with an
// error wrapping errCommitFailed (see snmpface.go's applyUncommitted, which
// maps that to gosnmp.CommitFailed) when at least one port is access-mode;
// a no-op otherwise, and always a no-op on a non-switchport model.
func (s *State) rejectIfReadonlyQbridge(column string, vid int) {
	if !isSwitchportModel(s.mustModel()) {
		return
	}
	access := s.accessModePorts()
	if len(access) > 0 {
		panic(fmt.Errorf(
			"%s.%d: the Q-BRIDGE egress PortList is read-only while any interface is in switchport access mode (ports %v are) -- a real FASTPATH 12.x agent answers commitFailed here, even for a byte-identical value. Write the switchport mode / access VLAN / native VLAN / allowed-VLAN columns instead: %w",
			column, vid, access, errCommitFailed,
		))
	}
}

// applySwitchport recomputes VLAN membership from port's switchport config,
// mirroring Python VirtualSwitchState._apply_switchport (state.py:736-788).
//
// Reproduces the derivation established live on 2026-07-30 against BOTH
// M4300 SKUs (m4300-24x @10.1.5.13 fw 12.0.13.8 port 1/0/8; m4300-16x
// @10.1.5.20 fw 12.0.19.15 port 1/0/1) by writing the vendor columns and
// re-reading the Q-BRIDGE mirrors after every single step:
//
//   - access(1)  -> untagged member of the access VLAN (col3) and NOTHING
//     else; it also drives the PVID.
//   - trunk(2)   -> untagged member of the native VLAN (col4), PLUS a
//     TAGGED member of (allowed(col6) INTERSECT existing VLANs) - {native};
//     the PVID becomes the native VLAN. The native VLAN is an untagged
//     member EVEN WHEN it is not in the allowed list (proved by removing
//     VLAN 1 from col6 while native stayed 1: the port stayed untagged in
//     VLAN 1).
//   - general(3) -> membership is the col7/col8 participation lists, which
//     answer notWritable; the PVID is configured independently (live: a
//     general-mode port read access VLAN 10 while its PVID was 1).
func (s *State) applySwitchport(port int) {
	s.switchportDefaults(port)
	mode := s.SwitchportMode[port]
	var untagged, tagged map[int]bool
	switch mode {
	case snmp.SwitchportModeAccess:
		untagged = map[int]bool{s.SwitchportAccessVlan[port]: true}
		tagged = map[int]bool{}
		s.Pvids[port] = s.SwitchportAccessVlan[port]
	case snmp.SwitchportModeTrunk:
		native := s.SwitchportNativeVlan[port]
		untagged = map[int]bool{native: true}
		allowed := vlansInBitmap(s.SwitchportAllowedVlans[port])
		tagged = map[int]bool{}
		for vid := range allowed {
			if vid == native {
				continue
			}
			if _, exists := s.Vlans[vid]; exists {
				tagged[vid] = true
			}
		}
		s.Pvids[port] = native
	default: // snmp.SwitchportModeGeneral
		untagged = map[int]bool{}
		for v, present := range s.SwitchportGeneralUntagged[port] {
			if present {
				untagged[v] = true
			}
		}
		tagged = map[int]bool{}
		for v, present := range s.SwitchportGeneralTagged[port] {
			if present && !untagged[v] {
				tagged[v] = true
			}
		}
		// PVID is NOT derived in general mode -- see the doc comment above.
	}
	for vid, vsim := range s.Vlans {
		switch {
		case untagged[vid]:
			vsim.Member[port] = true
			vsim.Untagged[port] = true
		case tagged[vid]:
			vsim.Member[port] = true
			delete(vsim.Untagged, port)
		default:
			delete(vsim.Member, port)
			delete(vsim.Untagged, port)
		}
	}
}

// reconcileQbridgeMembership folds an ACCEPTED Q-BRIDGE egress write back
// into switchport config, mirroring Python
// VirtualSwitchState._reconcile_qbridge_membership (state.py:790-820).
//
// Only reachable when no port is in access mode (see
// rejectIfReadonlyQbridge). On the m4300-16x such a write is just another
// front end for the same configuration, VERIFIED live: adding 1/0/1 to a
// VLAN while that port was TRUNK made the allowed-VLAN column (col6) gain
// the VLAN and the port became a TAGGED member, and removing it again
// cleared the col6 bit; doing the same while the port was GENERAL instead
// updated the col7 untagged list and the port became an UNTAGGED member.
// Keeping the vendor columns in step is what stops the mock drifting into a
// state no real switch can be in.
func (s *State) reconcileQbridgeMembership(vid int, incoming map[int]bool) {
	for port := range s.Ports {
		s.switchportDefaults(port)
		switch s.SwitchportMode[port] {
		case snmp.SwitchportModeTrunk:
			allowed := vlansInBitmap(s.SwitchportAllowedVlans[port])
			if incoming[port] {
				allowed[vid] = true
			} else {
				delete(allowed, vid)
			}
			s.SwitchportAllowedVlans[port] = vlanBitmapBytes(allowed)
		case snmp.SwitchportModeGeneral:
			// The egress write auto-UNTAGS on this firmware (col7 gained
			// the VLAN) -- the same class of side effect the S3300 shows.
			if incoming[port] {
				s.SwitchportGeneralUntagged[port][vid] = true
			} else {
				delete(s.SwitchportGeneralUntagged[port], vid)
				delete(s.SwitchportGeneralTagged[port], vid)
			}
		}
		s.applySwitchport(port)
	}
}

// refuseVlanCreationIfUnsupported reproduces a device that will not create
// a dot1qVlanStaticTable row, mirroring Python
// VirtualSwitchState._refuse_vlan_creation_if_unsupported (state.py:
// 1176-1192).
//
// MEASURED on the GS728TPP (10.2.5.10, firmware 6.0.1.30): every documented
// creation mechanism answers inconsistentValue, while the SAME table's data
// columns accept writes and destroy(6) works. Panics with an error wrapping
// errInconsistentValue (mapped to gosnmp.InconsistentValue by snmpface.go's
// applyUncommitted) when model.SwitchModel.SNMPCanCreateVLAN is false; a
// no-op otherwise.
func (s *State) refuseVlanCreationIfUnsupported(oid string) {
	if !s.mustModel().SNMPCanCreateVLAN {
		panic(fmt.Errorf(
			"%s: this agent refuses VLAN row creation (inconsistentValue at %s): %w",
			s.ModelKey, oid, errInconsistentValue,
		))
	}
}
