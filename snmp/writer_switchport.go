package snmp

// writer_switchport.go: the FASTPATH vendor SWITCHPORT control plane for
// SetVlanMembership, ported field-for-field from
// src/netgear_switch/snmp_write.py's _plan_switchport_membership/
// _SwitchportPlan/_switchport_divergence/_set_vlan_switchport/_port_membership
// and protocols/snmp/oids.py's switchport OID block (the normative source;
// that repo is read-only from here, pin b26eb1f). Any discrepancy between
// this file and the Python source is a bug in this file.
//
// This is the writable membership control plane for m4300-24x/m4300-16x
// (model.SwitchModel.SnmpVlanWrite == model.SNMPVlanWriteFastpathSwitchport):
// on FASTPATH 12.x the standard Q-BRIDGE dot1qVlanStaticEgress/UntaggedPorts
// PortLists are READ-ONLY MIRRORS (a SET commitFails even for a
// byte-identical value), because per-port SWITCHPORT MODE owns VLAN
// membership -- see snmp_write.py:59-82 (registry.py's own field docstring,
// mirrored on model.SwitchModel.SnmpVlanWrite) for the live evidence.

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/mithro/go-netgear-switch-library/model"
)

// defaultVlan is the 802.1Q default VLAN a port falls back to when the
// requested change would otherwise leave it untagged in NO VLAN, mirroring
// Python snmp_write._DEFAULT_VLAN (snmp_write.py:52-58). That state is
// simply not expressible on this hardware: an access port always has an
// access VLAN, and a trunk always has a native VLAN -- VERIFIED live on the
// M4300-24X (10.1.5.13, FASTPATH 12.0.13.8) where SET
// switchport-native-vlan.1/0/8 := 0 and := 4094 BOTH answered commitFailed,
// as did := a VLAN id that does not exist.
const defaultVlan = 1

// intSet is a small set-of-VLAN-ids helper used only by the switchport plan
// below, mirroring the frozenset[int] arithmetic Python's
// _plan_switchport_membership/_switchport_divergence perform directly. Kept
// local to this file rather than promoted to a package-wide type: nothing
// else in package snmp needs set algebra, only sorted []int (see
// DecodePortBitmap/DecodeVlanBitmap).
type intSet map[int]bool

func newIntSet(vals ...int) intSet {
	s := make(intSet, len(vals))
	for _, v := range vals {
		s[v] = true
	}
	return s
}

func setFromSlice(vals []int) intSet { return newIntSet(vals...) }

func (s intSet) union(other intSet) intSet {
	out := make(intSet, len(s)+len(other))
	for v := range s {
		out[v] = true
	}
	for v := range other {
		out[v] = true
	}
	return out
}

func (s intSet) minus(other intSet) intSet {
	out := make(intSet, len(s))
	for v := range s {
		if !other[v] {
			out[v] = true
		}
	}
	return out
}

func (s intSet) has(v int) bool { return s[v] }

func (s intSet) equal(other intSet) bool {
	if len(s) != len(other) {
		return false
	}
	for v := range s {
		if !other[v] {
			return false
		}
	}
	return true
}

// sorted returns s's members as an ascending []int, mirroring Python's
// sorted(frozenset) at every message-formatting call site below.
func (s intSet) sorted() []int {
	out := make([]int, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// vlanBitmap encodes vlan ids into a switchport VLAN bitmap (512 B, 4096
// VLANs), mirroring Python snmp_write._vlan_bitmap (snmp_write.py:67-76).
// Same MSB-first convention as a PortList (VLAN 1 = bit 7 of byte 0) but
// indexed by VLAN id, not port.
func vlanBitmap(vlans []int) []byte {
	data := make([]byte, SwitchportVlanBitmapBytes)
	for _, vlan := range vlans {
		data[(vlan-1)/8] |= 0x80 >> uint((vlan-1)%8) //nolint:gosec // bit offset is always 0-7
	}
	return data
}

// DecodeVlanBitmap is the inverse of vlanBitmap: which VLAN ids a
// switchport bitmap names, mirroring Python snmp_write.decode_vlan_bitmap
// (snmp_write.py:79-86). Returned in ascending order (Python returns a
// frozenset; every caller here sorts before formatting or comparing
// anyway -- see intSet.sorted).
func DecodeVlanBitmap(bitmap []byte) []int {
	out := make([]int, 0)
	for i, b := range bitmap {
		for off := 0; off < 8; off++ {
			if b&(0x80>>uint(off)) != 0 {
				out = append(out, i*8+off+1)
			}
		}
	}
	return out
}

// editVlanBits READ-MODIFY-WRITEs a switchport VLAN bitmap: flip ONLY the
// named bits, mirroring Python snmp_write._edit_vlan_bits (snmp_write.py:
// 89-110). Never a blanket overwrite: the allowed-VLAN column routinely
// permits VLANs that do not exist yet (a factory-default M4300 port allows
// all 4093 of them), and only the bits for VLANs that exist contribute to
// membership -- so rebuilding the map from the port's current membership
// would silently revoke the operator's "allow future VLANs too" intent.
// Preserves the device's own byte width, growing only if a named VLAN needs
// it.
func editVlanBits(bitmap []byte, add, remove []int) []byte {
	data := append([]byte(nil), bitmap...)
	highest := 1
	for _, v := range add {
		if v > highest {
			highest = v
		}
	}
	for _, v := range remove {
		if v > highest {
			highest = v
		}
	}
	need := (highest-1)/8 + 1
	if need < SwitchportVlanBitmapBytes {
		need = SwitchportVlanBitmapBytes
	}
	if len(data) < need {
		data = append(data, make([]byte, need-len(data))...)
	}
	for _, vlan := range add {
		data[(vlan-1)/8] |= 0x80 >> uint((vlan-1)%8) //nolint:gosec // bit offset is always 0-7
	}
	for _, vlan := range remove {
		data[(vlan-1)/8] &^= 0x80 >> uint((vlan-1)%8) //nolint:gosec // bit offset is always 0-7
	}
	return data
}

// portMembership returns port's CURRENT (tagged, untagged) VLAN ids across
// every VLAN row, mirroring Python snmp_write._port_membership
// (snmp_write.py:113-125). Read from the standard Q-BRIDGE mirrors, which
// report the truth on FASTPATH regardless of which switchport mode produced
// it -- so this works whether the port is access, trunk or general.
func portMembership(vlans []model.VLANInfo, port int) (tagged, untagged intSet) {
	tagged = intSet{}
	untagged = intSet{}
	for _, v := range vlans {
		if slices.Contains(v.TaggedPorts, port) {
			tagged[v.VlanID] = true
		}
		if slices.Contains(v.UntaggedPorts, port) {
			untagged[v.VlanID] = true
		}
	}
	return tagged, untagged
}

// SwitchportPlan is the exact membership a switchport write intends, plus
// the SETs to get there -- mirroring Python snmp_write._SwitchportPlan
// (snmp_write.py:128-134).
type SwitchportPlan struct {
	UntaggedVlan int
	TaggedVlans  []int // ascending
	Varbinds     []SetVarbind
}

// PlanSwitchportMembership plans a PRECISE, NON-DESTRUCTIVE membership
// change on the FASTPATH switchport control plane, mirroring Python
// snmp_write._plan_switchport_membership (snmp_write.py:137-280).
//
// How membership is actually derived on FASTPATH 12.x -- established live
// on 2026-07-30 against BOTH M4300 SKUs (m4300-24x @10.1.5.13 fw 12.0.13.8
// port 1/0/8; m4300-16x @10.1.5.20 fw 12.0.19.15 port 1/0/1), by writing the
// vendor columns and re-reading the Q-BRIDGE mirrors after every step:
//
//   - access(1)  -> untagged member of the access VLAN (col3) and NOTHING
//     else; col4/col6 are stored but not in force.
//   - trunk(2)   -> untagged member of the native VLAN (col4) plus a TAGGED
//     member of (allowed(col6) INTERSECT existing VLANs) - {native}. The
//     native VLAN is an untagged member even when it is NOT in the allowed
//     list (proved by removing VLAN 1 from col6 while native stayed 1).
//   - general(3) -> membership comes from col7/col8, which answer
//     notWritable, so this mode cannot be driven over SNMP.
//
// So trunk mode is a precise control plane for "exactly one untagged VLAN
// plus an arbitrary tagged set", and that is what this plans:
//
//   - TAGGED   V -> tagged = current tagged + V, untagged unchanged (minus V)
//   - UNTAGGED V -> untagged = V, tagged = current tagged - V
//   - EXCLUDED V -> BOTH sets minus V, every other VLAN left alone
//
// then expresses the result minimally: access mode when nothing is tagged
// (the idiomatic form, and what the switch's own CLI produces), else trunk
// mode with col4 = the untagged VLAN and col6 read-modify-written.
//
// Two requests cannot be honoured and are REFUSED rather than approximated
// (precondition failure -- no SET is attempted, error wraps
// model.ErrUnsupportedCapability):
//
//   - a desired state with MORE THAN ONE untagged VLAN. Reachable in
//     practice: a general-mode port can be untagged in several VLANs
//     (observed live on m4300-16x port 1/0/1, untagged in both 1 and 4007),
//     and trunk/access mode can only hold one.
//   - excluding a port from its ONLY untagged VLAN while it is a TAGGED
//     member of the default VLAN, because the fallback below would then
//     have to demote that VLAN from tagged to untagged -- a change to a
//     VLAN the caller never named.
//
// Excluding a port from its only untagged VLAN otherwise falls back to
// defaultVlan (see its own doc comment: the hardware has no "untagged
// nowhere" state), which is the ONE unrequested membership this plan can
// produce.
func PlanSwitchportMembership(vlanID, port int, mode model.VlanMode, currentMode *int, currentAllowed []byte, currentTagged, currentUntagged []int, existingVlans []int) (*SwitchportPlan, error) {
	curTagged := setFromSlice(currentTagged)
	curUntagged := setFromSlice(currentUntagged)
	target := newIntSet(vlanID)

	var wantTagged, wantUntagged intSet
	switch mode {
	case model.VlanTagged:
		wantTagged = curTagged.union(target)
		wantUntagged = curUntagged.minus(target)
	case model.VlanUntagged:
		wantTagged = curTagged.minus(target)
		wantUntagged = target
	default: // model.VlanExcluded
		wantTagged = curTagged.minus(target)
		wantUntagged = curUntagged.minus(target)
	}

	if len(wantUntagged) > 1 {
		sortedWant := wantUntagged.sorted()
		return nil, fmt.Errorf(
			"port %d is currently an untagged member of VLANs %v; the FASTPATH switchport control plane holds at most ONE untagged VLAN per port (access VLAN / trunk native VLAN), and the per-VLAN participation columns that could express several answer notWritable. Refusing rather than silently dropping %v: %w",
			port, curUntagged.sorted(), sortedWant[1:], model.ErrUnsupportedCapability,
		)
	}

	var untaggedVlan int
	switch {
	case len(wantUntagged) == 1:
		untaggedVlan = wantUntagged.sorted()[0]
	case wantTagged.has(defaultVlan):
		return nil, fmt.Errorf(
			"excluding port %d from VLAN %d would leave it untagged in no VLAN, which this hardware cannot express, and the fallback (VLAN %d) is a TAGGED member here -- honouring the request would silently demote VLAN %d from tagged to untagged. Give the port an explicit untagged VLAN first: %w",
			port, vlanID, defaultVlan, defaultVlan, model.ErrUnsupportedCapability,
		)
	default:
		untaggedVlan = defaultVlan
	}

	var varbinds []SetVarbind
	if len(wantTagged) > 0 {
		var allowed []byte
		if currentMode != nil && *currentMode == SwitchportModeTrunk {
			// Already trunk: col6 IS this port's membership definition, so
			// read-modify-write it. Because trunk membership is
			// (allowed INTERSECT existing) - {native}, the bits that must be
			// right are exactly those of EXISTING VLANs; bits for VLANs that
			// do not exist yet are left ALONE, preserving an operator's
			// "allow future VLANs too" intent.
			add := wantTagged.union(newIntSet(untaggedVlan))
			remove := setFromSlice(existingVlans).minus(wantTagged).minus(newIntSet(untaggedVlan))
			allowed = editVlanBits(currentAllowed, add.sorted(), remove.sorted())
		} else {
			// Coming FROM access/general, col6 is stale and not in force (it
			// is all 4093 VLANs on a factory-default port). Carrying it into
			// trunk mode is what used to hand the port every VLAN on the
			// switch, so rebuild it from the membership the port actually
			// has.
			allowed = vlanBitmap(wantTagged.union(newIntSet(untaggedVlan)).sorted())
		}
		allowedVb, err := NewSetVarbind(fmt.Sprintf("%s.%d", FastpathSwitchportAllowedVlans, port), allowed, "x")
		if err != nil {
			return nil, err
		}
		nativeVb, err := NewSetVarbind(fmt.Sprintf("%s.%d", FastpathSwitchportNativeVlan, port), untaggedVlan, "u")
		if err != nil {
			return nil, err
		}
		modeVb, err := NewSetVarbind(fmt.Sprintf("%s.%d", FastpathSwitchportMode, port), SwitchportModeTrunk, "i")
		if err != nil {
			return nil, err
		}
		// One PDU per varbind, DATA columns before the MODE selector: the
		// mode decides which columns are in force, so landing col6/col4
		// first means membership never passes through a wrong intermediate
		// state.
		varbinds = []SetVarbind{allowedVb, nativeVb, modeVb}
	} else {
		// Nothing tagged: one untagged VLAN is exactly what access mode is.
		// col6/col4 are deliberately left untouched -- access mode ignores
		// them.
		accessVb, err := NewSetVarbind(fmt.Sprintf("%s.%d", FastpathSwitchportAccessVlan, port), untaggedVlan, "u")
		if err != nil {
			return nil, err
		}
		modeVb, err := NewSetVarbind(fmt.Sprintf("%s.%d", FastpathSwitchportMode, port), SwitchportModeAccess, "i")
		if err != nil {
			return nil, err
		}
		varbinds = []SetVarbind{accessVb, modeVb}
	}
	return &SwitchportPlan{
		UntaggedVlan: untaggedVlan,
		TaggedVlans:  wantTagged.sorted(),
		Varbinds:     varbinds,
	}, nil
}

// switchportDivergence compares port's FULL membership against plan after
// the SETs applied; "" means no divergence, mirroring Python
// snmp_write._switchport_divergence (snmp_write.py:283-312) returning
// str | None.
//
// Verification deliberately covers EVERY VLAN, not just the requested one:
// the whole point of the plan is that VLANs the caller never named keep
// their membership, and a per-VLAN check cannot see that being violated.
// Reads the standard Q-BRIDGE mirrors, so a device that ACKs the vendor SETs
// without changing membership still fails.
func switchportDivergence(plan *SwitchportPlan, vlanID, port int, after []model.VLANInfo) string {
	found := false
	for _, v := range after {
		if v.VlanID == vlanID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Sprintf("VLAN %d disappeared while setting membership for port %d", vlanID, port)
	}
	gotTagged, gotUntagged := portMembership(after, port)
	wantUntagged := newIntSet(plan.UntaggedVlan)
	if !gotUntagged.equal(wantUntagged) {
		return fmt.Sprintf(
			"port %d should be an untagged member of VLAN %d only, but reads back untagged in %v",
			port, plan.UntaggedVlan, gotUntagged.sorted(),
		)
	}
	wantTagged := setFromSlice(plan.TaggedVlans)
	if !gotTagged.equal(wantTagged) {
		gained := gotTagged.minus(wantTagged).sorted()
		lost := wantTagged.minus(gotTagged).sorted()
		msg := fmt.Sprintf(
			"port %d tagged membership did not verify: wanted %v, got %v",
			port, wantTagged.sorted(), gotTagged.sorted(),
		)
		if len(gained) > 0 {
			msg += fmt.Sprintf("; UNREQUESTED membership gained in %v", gained)
		}
		if len(lost) > 0 {
			msg += fmt.Sprintf("; membership LOST in %v", lost)
		}
		return msg
	}
	return ""
}

// switchportVlanBitmap returns a switchport VLAN-list column's octets for
// port, or an all-zero SwitchportVlanBitmapBytes-byte map if the device
// reports nothing, mirroring Python SnmpWriter._switchport_vlan_bitmap
// (snmp_write.py:648-654).
func (w *Writer) switchportVlanBitmap(ctx context.Context, baseOID string, port int) ([]byte, error) {
	rows, err := w.client.Get(ctx, []string{fmt.Sprintf("%s.%d", baseOID, port)})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if b, ok := row.Value.([]byte); ok {
			return b, nil
		}
	}
	return make([]byte, SwitchportVlanBitmapBytes), nil
}

// switchportMode returns port's switchport mode column, or nil if the
// device has no row, mirroring Python SnmpWriter._switchport_mode
// (snmp_write.py:656-661).
func (w *Writer) switchportMode(ctx context.Context, port int) (*int, error) {
	rows, err := w.client.Get(ctx, []string{fmt.Sprintf("%s.%d", FastpathSwitchportMode, port)})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if v, ok := row.Value.(int64); ok {
			mode := int(v)
			return &mode, nil
		}
	}
	return nil, nil
}

// setVlanSwitchport sets VLAN membership through the FASTPATH vendor
// SWITCHPORT table, mirroring Python SnmpWriter._set_vlan_switchport
// (snmp_write.py:607-646).
//
// All of the reasoning, the live evidence and the refusal cases live in
// PlanSwitchportMembership; this just reads the port's current state,
// applies the plan and verifies it. Verification reads the standard
// Q-BRIDGE mirrors back (switchportDivergence), so a switch that accepted
// the vendor SETs without actually changing membership -- or that changed a
// VLAN nobody asked about -- still raises WriteVerificationError.
func (w *Writer) setVlanSwitchport(ctx context.Context, vlanID, port int, mode model.VlanMode, before *model.VLANInfo, vlans []model.VLANInfo) error {
	currentTagged, currentUntagged := portMembership(vlans, port)
	currentMode, err := w.switchportMode(ctx, port)
	if err != nil {
		return err
	}
	currentAllowed, err := w.switchportVlanBitmap(ctx, FastpathSwitchportAllowedVlans, port)
	if err != nil {
		return err
	}
	existingVlans := make([]int, len(vlans))
	for i, v := range vlans {
		existingVlans[i] = v.VlanID
	}
	plan, err := PlanSwitchportMembership(vlanID, port, mode, currentMode, currentAllowed, currentTagged.sorted(), currentUntagged.sorted(), existingVlans)
	if err != nil {
		return err
	}
	for _, vb := range plan.Varbinds {
		// One PDU per varbind, DATA columns before the MODE selector -- see
		// PlanSwitchportMembership's own doc comment. Verified live in this
		// order.
		if err := w.client.Set(ctx, vb); err != nil {
			return err
		}
	}
	after, err := w.reader.GetVLANs(ctx)
	if err != nil {
		return err
	}
	if problem := switchportDivergence(plan, vlanID, port, after); problem != "" {
		var afterVlan *model.VLANInfo
		for i := range after {
			if after[i].VlanID == vlanID {
				afterVlan = &after[i]
				break
			}
		}
		return &model.WriteVerificationError{Msg: problem, Before: before, After: afterVlan}
	}
	return nil
}
