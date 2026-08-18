package snmp

// writer_vlan.go: VLAN lifecycle (SetVlanMembership/CreateVlan/DeleteVlan)
// and the switch's own management-IP write, ported field-for-field from
// src/netgear_switch/snmp_write.py's SnmpWriter (the normative source; see
// D-WR §2.10-§2.13). Any discrepancy between this file and the Python
// source is a bug in this file.

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// vlanEncodeWidth is the width_bytes Python's encode_port_bitmap defaults
// to when re-encoding a `before` VLANInfo's already-decoded port lists back
// to wire bitmaps -- used ONLY as SetVlanMembership's fallback when a fresh
// rawBitmap walk reports nothing for a column (no device octets to
// preserve the width of). The model-derived VlanBitmapWidth is threaded in
// separately, one level down, via MembershipBitmaps' width parameter (see
// SetVlanMembership below), exactly mirroring Python's two-stage
// encode_port_bitmap(...) then membership_bitmaps(..., width_bytes=...).
const vlanEncodeWidth = 8

// vlan returns vlanID's current VLANInfo via the internal reader, or nil if
// absent from the walk. Mirrors Python's SnmpWriter._vlan.
func (w *Writer) vlan(ctx context.Context, vlanID int) (*model.VLANInfo, error) {
	vlans, err := w.reader.GetVLANs(ctx)
	if err != nil {
		return nil, err
	}
	for _, v := range vlans {
		if v.VlanID == vlanID {
			return &v, nil
		}
	}
	return nil, nil
}

// rawBitmap returns vlanID's RAW device octets for the baseOID column
// (Dot1qVlanStaticEgress or Dot1qVlanStaticUntagged) -- the exact bytes the
// device reported, width intact -- or nil if the walk did not report this
// VLAN at all. Ported from Python's SnmpWriter._raw_bitmap (D-REC Topic B,
// reconciliation issue #3): VLANInfo carries DECODED port sets, so
// re-encoding a bitmap from it would size the buffer to the highest port in
// use rather than to the width the device actually uses. Netgear switches
// report a PortList covering LAG and CPU pseudo-ports too -- measured live,
// 79 bytes on a GSM7252PS and 131 bytes on an M4300-24X, both far wider than
// max(8, ceil(port_count/8)) -- so only a fresh walk of the raw column (not
// the already-decoded `before` snapshot) can recover that width. Accepts
// both a []byte and a string-typed OCTET STRING value (see the type switch
// below) -- a deliberate hardening beyond the pinned Python source, which
// (like this function until now) only handled the []byte case.
func (w *Writer) rawBitmap(ctx context.Context, baseOID string, vlanID int) ([]byte, error) {
	rows, err := w.client.Walk(ctx, baseOID)
	if err != nil {
		return nil, err
	}
	suffix := fmt.Sprintf(".%d", vlanID)
	for _, row := range rows {
		if strings.HasSuffix(row.OID, suffix) {
			switch v := row.Value.(type) {
			case []byte:
				return v, nil
			case string:
				// Deliberate hardening beyond the pinned Python source:
				// Python's SnmpWriter._raw_bitmap only handles the bytes
				// case too (the same []byte-only asymmetry versus the
				// reader exists there), but vlanBitmapMap (parse.go) --
				// this same column, read for GetVLANs -- already accepts
				// a string-typed OCTET STRING off the wire (some
				// SNMP libraries/devices surface it that way) and
				// converts it directly to []byte. Mirror that here so a
				// string-typed raw column still preserves the device's
				// real wire width instead of silently falling through to
				// the caller's narrower vlanEncodeWidth re-encode.
				return []byte(v), nil
			}
		}
	}
	return nil, nil
}

// physical returns the switch's physical (ethernetCsmacd) ports via a
// fresh IfType walk, or nil when the agent does not surface ifType at all
// -- mirrors physicalPorts' "no ifType walk -> keep everything" contract
// (see ParseVlans/ParsePortStatus, which use the same helper on the read
// side).
//
// SetVlanMembership's verification decodes the bitmap it just SENT and
// compares it with what GetVLANs reads back -- and GetVLANs now drops LAG
// bridge-ports from VLAN membership (ParseVlans, parity with Python commit
// 3f25b0b). Without the same filter here the two sides would disagree by
// exactly those bits, and every membership write on a switch with a LAG in
// the VLAN would raise a bogus WriteVerificationError. MEASURED: the
// GSM7252PS seed (virtual.SeedGSM7252PS) has a real "lag 1" LAG at ifIndex
// 418/419, a member of several VLANs -- this is the normal case there, not
// an edge case.
func (w *Writer) physical(ctx context.Context) (map[int]bool, error) {
	ifTypes, err := w.client.Walk(ctx, IfType)
	if err != nil {
		return nil, err
	}
	return physicalPorts(ifTypes)
}

// SetVlanMembership sets port's membership mode (untagged/tagged/excluded)
// within vlanID and verifies BOTH written columns (egress member_ports AND
// untagged_ports) read back correctly. Ported from Python's
// SnmpWriter.set_vlan_membership -- see D-WR §2.10, the richest write op.
//
// The guard fires UNCONDITIONALLY (any membership change is disruptive),
// BEFORE the VLAN-existence check. A missing VLAN is a PRECONDITION
// failure -- an error wrapping model.ErrSNMP, NOT a
// *model.WriteVerificationError -- and issues ZERO SETs (D-WR §2.10 step
// 2). The read-modify-write feeds MembershipBitmaps the device's OWN RAW
// egress/untagged octets (a fresh rawBitmap walk of each column, NOT a
// re-encode of the already-decoded `before` snapshot) so it preserves
// their exact wire width -- that is what rawBitmap is for (D-REC Topic B,
// reconciliation issue #3: a prior version of this method re-encoded
// `before`'s decoded port lists at vlanEncodeWidth/VlanBitmapWidth,
// silently narrowing the SET below the device's real fixed PortList width,
// e.g. 79 bytes on a GSM7252PS -- a stricter Q-BRIDGE agent rejects that
// outright). VlanBitmapWidth(w.model.PortCount) is still passed through as
// a floor, mirroring Python's width_bytes=vlan_bitmap_width(self.model):
// it only ever WIDENS, never narrows, so it can't undo the raw bitmap's
// width. Falls back to re-encoding `before`'s decoded port list at
// vlanEncodeWidth only if a column's raw walk reported no octets at all.
// ONE SetMany call, two "x" (hex/octet-string) varbinds for the same vlan
// (egress then untagged) -- the atomic-multi-varbind-SET case. Verification
// checks, in order: (1) after == nil (VLAN vanished) is its own branch; (2)
// egress (MemberPorts) matches the exact bitmap just written (re-decoded,
// not re-derived from mode); (3) untagged_ports likewise -- catching a
// device that silently drops just one of the two SETs.
func (w *Writer) SetVlanMembership(ctx context.Context, vlanID, port int, mode model.VlanMode, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	// Fetch every VLAN once (mirrors Python's `vlans = self._reader.get_vlans()`
	// at the top of set_vlan_membership): the switchport dialect below needs
	// the FULL list (existing_vlans, and every VLAN's current membership of
	// `port`), not just the target VLAN.
	vlans, err := w.reader.GetVLANs(ctx)
	if err != nil {
		return err
	}
	var before *model.VLANInfo
	for i := range vlans {
		if vlans[i].VlanID == vlanID {
			before = &vlans[i]
			break
		}
	}
	if before == nil {
		// Precondition failure: no SET has been attempted, so this is NOT a
		// verification divergence.
		return errSNMP("VLAN %d does not exist", vlanID)
	}
	if w.model.SnmpVlanWrite == model.SNMPVlanWriteFastpathSwitchport {
		// FASTPATH 12.x (both M4300 SKUs): the Q-BRIDGE PortLists below are
		// read-only mirrors on this dialect -- membership must go through
		// the vendor switchport table instead. See writer_switchport.go's
		// PlanSwitchportMembership for the full derivation and live
		// evidence, mirroring Python SnmpWriter.set_vlan_membership's own
		// dispatch (snmp_write.py:673-675).
		return w.setVlanSwitchport(ctx, vlanID, port, mode, before, vlans)
	}
	rawEgress, err := w.rawBitmap(ctx, Dot1qVlanStaticEgress, vlanID)
	if err != nil {
		return err
	}
	rawUntagged, err := w.rawBitmap(ctx, Dot1qVlanStaticUntagged, vlanID)
	if err != nil {
		return err
	}
	egressBitmap := rawEgress
	if egressBitmap == nil {
		egressBitmap = EncodePortBitmap(before.MemberPorts, vlanEncodeWidth)
	}
	untaggedBitmap := rawUntagged
	if untaggedBitmap == nil {
		untaggedBitmap = EncodePortBitmap(before.UntaggedPorts, vlanEncodeWidth)
	}
	width := VlanBitmapWidth(w.model.PortCount)
	newEgress, newUntagged := MembershipBitmaps(egressBitmap, untaggedBitmap, port, mode, width)
	egressVb, err := NewSetVarbind(fmt.Sprintf("%s.%d", Dot1qVlanStaticEgress, vlanID), newEgress, "x")
	if err != nil {
		return err
	}
	untaggedVb, err := NewSetVarbind(fmt.Sprintf("%s.%d", Dot1qVlanStaticUntagged, vlanID), newUntagged, "x")
	if err != nil {
		return err
	}
	if w.model.SnmpVlanSplitMembershipWrites {
		// Egress FIRST, then untagged, in SEPARATE PDUs: this firmware
		// (verified live on the S3300-52X-PoE+, 10.1.5.11) auto-untags a
		// port when its egress bit is set, and that side effect overrides
		// an untagged varbind in the SAME PDU -- see
		// model.SwitchModel.SnmpVlanSplitMembershipWrites's own doc comment
		// for the live before/after evidence. Mirrors Python
		// SnmpWriter.set_vlan_membership (snmp_write.py:702-708).
		if err := w.client.Set(ctx, egressVb); err != nil {
			return err
		}
		if err := w.client.Set(ctx, untaggedVb); err != nil {
			return err
		}
	} else {
		// One atomic PDU everywhere else -- the device applies both or
		// neither.
		if err := w.client.SetMany(ctx, []SetVarbind{egressVb, untaggedVb}); err != nil {
			return err
		}
	}
	after, err := w.vlan(ctx, vlanID)
	if err != nil {
		return err
	}
	// Compare on the same footing GetVLANs reports -- physical ports only
	// (see the physical method's doc comment).
	keep, err := w.physical(ctx)
	if err != nil {
		return err
	}
	wantEgress := filterPhysical(DecodePortBitmap(newEgress), keep)
	wantUntagged := filterPhysical(DecodePortBitmap(newUntagged), keep)
	if after == nil {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("VLAN %d disappeared while setting membership for port %d", vlanID, port),
			Before: before,
			After:  after,
		}
	}
	if !slices.Equal(after.MemberPorts, wantEgress) {
		return &model.WriteVerificationError{
			Msg: fmt.Sprintf(
				"VLAN %d egress (member_ports) for port %d did not verify: wanted %v, got %v",
				vlanID, port, wantEgress, after.MemberPorts,
			),
			Before: before,
			After:  after,
		}
	}
	if !slices.Equal(after.UntaggedPorts, wantUntagged) {
		return &model.WriteVerificationError{
			Msg: fmt.Sprintf(
				"VLAN %d untagged_ports for port %d did not verify: wanted %v, got %v",
				vlanID, port, wantUntagged, after.UntaggedPorts,
			),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// NoVLANCreateMsg is why an SNMP VLAN create is refused on a model whose
// agent cannot do it, mirroring Python snmp_write._NO_VLAN_CREATE
// (pin b26eb1f / commit f8a890f). Exported so
// capabilities/support_snmp.go can reuse the SAME text this writer's own
// refusal raises -- one definition, not a parallel guess (mirroring
// Python's `from .snmp_write import _NO_VLAN_CREATE`).
const NoVLANCreateMsg = "this model's SNMP agent cannot create a VLAN: every RowStatus mechanism " +
	"(createAndGo, createAndGo+name in one PDU, createAndWait->name->active, the name column alone, " +
	"and createAndGo carrying an egress PortList) is answered inconsistentValue -- measured on the " +
	"device. Membership, PVID and delete DO work over SNMP; create a VLAN over the HTTP backend"

// requireSNMPVLANCreation refuses a VLAN create BEFORE sending anything on
// a model whose SNMP agent cannot do it, mirroring Python
// snmp_write._require_snmp_vlan_creation. MEASURED on the GS728TPP
// (10.2.5.10, firmware 6.0.1.30, 2026-08-03): every documented RowStatus
// creation mechanism answers inconsistentValue -- see
// model.SwitchModel.SNMPCanCreateVLAN's own doc comment for the full
// per-mechanism list.
func requireSNMPVLANCreation(m *model.SwitchModel) error {
	if !m.SNMPCanCreateVLAN {
		return fmt.Errorf("model %q: %s: %w", m.Key, NoVLANCreateMsg, model.ErrUnsupportedCapability)
	}
	return nil
}

// CreateVlan creates vlanID with the given name and verifies it exists with
// that name afterward. Ported from Python's SnmpWriter.create_vlan -- see
// D-WR §2.11.
//
// requireSNMPVLANCreation is checked FIRST (pin b26eb1f / commit f8a890f):
// a model whose agent cannot create a VLAN row at all (model.SwitchModel.
// SNMPCanCreateVLAN == false, e.g. gs728tpp) is refused honestly before any
// SET is attempted, rather than sending a createAndGo the device will
// answer inconsistentValue to.
//
// CreateVlan NEVER guards on protected ports: creating an EMPTY VLAN adds
// no port membership, so it is non-disruptive by construction -- there is
// no `force` parameter (unlike DeleteVlan) since nothing here is ever
// refused (other than the capability gate above). One SetMany PDU, two
// varbinds: RowStatus createAndGo (int 4, type "i") + Name (type "s", plain
// string -- NOT "x" like the VLAN membership bitmaps). Verify: VLAN exists
// AND its name equals the requested name exactly, treating a nil Name the
// same as empty string (mirrors Python's `after.name or ""`).
func (w *Writer) CreateVlan(ctx context.Context, vlanID int, name string) error {
	if err := requireSNMPVLANCreation(w.model); err != nil {
		return err
	}
	before, err := w.vlan(ctx, vlanID)
	if err != nil {
		return err
	}
	rowStatusVb, err := NewSetVarbind(fmt.Sprintf("%s.%d", Dot1qVlanStaticRowStatus, vlanID), RowStatusCreateAndGo, "i")
	if err != nil {
		return err
	}
	nameVb, err := NewSetVarbind(fmt.Sprintf("%s.%d", Dot1qVlanStaticName, vlanID), name, "s")
	if err != nil {
		return err
	}
	if err := w.client.SetMany(ctx, []SetVarbind{rowStatusVb, nameVb}); err != nil {
		return err
	}
	after, err := w.vlan(ctx, vlanID)
	if err != nil {
		return err
	}
	if after == nil || derefOrEmpty(after.Name) != name {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("VLAN %d was not created with name %q", vlanID, name),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// DeleteVlan destroys vlanID and verifies it is gone afterward. Ported from
// Python's SnmpWriter.delete_vlan -- see D-WR §2.12.
//
// Existence precondition mirrors SetVlanMembership's: `before == nil` is a
// PRECONDITION failure (model.ErrSNMP-wrapped, NOT
// *model.WriteVerificationError) with ZERO SETs issued. This is the ONLY
// writer method whose protected-port guard is a SET-INTERSECTION check
// (before.MemberPorts ∩ w.protectedPorts), not a single-port w.guard call --
// destroying a VLAN strips membership from EVERY member port at once, so
// ALL of them must be checked against the protected set, not just one. The
// refusal message's sorted-clash-set wording is BYTE-IDENTICAL to the
// facade-level duplicate of this same guard (D-WR §3.3) -- both copies
// must stay in sync. Single-varbind SET: RowStatus destroy (int 6, type
// "i"). Verify: after MUST be nil (VLAN gone); if it still exists, raises
// *model.WriteVerificationError.
func (w *Writer) DeleteVlan(ctx context.Context, vlanID int, force bool) error {
	before, err := w.vlan(ctx, vlanID)
	if err != nil {
		return err
	}
	if before == nil {
		return errSNMP("VLAN %d does not exist", vlanID)
	}
	if !force {
		var clash []int
		for _, p := range before.MemberPorts {
			if w.protectedPorts[p] {
				clash = append(clash, p)
			}
		}
		if len(clash) > 0 {
			sort.Ints(clash)
			return fmt.Errorf(
				"VLAN %d includes protected port(s) %s; pass force=True to delete it anyway: %w",
				vlanID, formatIntList(clash), model.ErrProtectedPort,
			)
		}
	}
	vb, err := NewSetVarbind(fmt.Sprintf("%s.%d", Dot1qVlanStaticRowStatus, vlanID), RowStatusDestroy, "i")
	if err != nil {
		return err
	}
	if err := w.client.Set(ctx, vb); err != nil {
		return err
	}
	after, err := w.vlan(ctx, vlanID)
	if err != nil {
		return err
	}
	if after != nil {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("VLAN %d still exists after destroy", vlanID),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// SetMgmtIP sets the switch's own management IP (address/netmask/gateway)
// and verifies all three fields read back correctly, naming whichever
// diverged. Ported from Python's SnmpWriter.set_mgmt_ip -- see D-WR §2.13,
// the highest strand-risk op in the whole write surface.
//
// force-gated UNCONDITIONALLY, independent of w.protectedPorts: force=false
// ALWAYS refuses (reusing model.ErrProtectedPort even though no specific
// port is involved -- a deliberate, if slightly odd, type choice preserved
// from the Python source), since a bad mgmt-IP write can strand the ENTIRE
// switch, not just one port. This check runs BEFORE resolving vendor OIDs,
// so a no-vendor-subtree model (e.g. gs728tpp) with force=false still gets
// the force-gate message, not ErrUnsupportedCapability. Only once force is
// true does GetVendorOids run, propagating its
// model.ErrUnsupportedCapability uncaught for a no-vendor-subtree model.
// One SetMany, three "a" (IpAddress) varbinds against the UNVERIFIED vendor
// mgmt-write OIDs. DHCP-mode switching is intentionally NOT offered here
// (even its read OID is unverified). Verifies address, netmask, then
// gateway independently, in that order, raising on the first field that
// diverges.
func (w *Writer) SetMgmtIP(ctx context.Context, address, netmask, gateway string, force bool) error {
	if !force {
		return fmt.Errorf(
			"set_mgmt_ip can strand the switch and uses UNVERIFIED OIDs; pass force=True to proceed: %w",
			model.ErrProtectedPort,
		)
	}
	vo, err := GetVendorOids(w.model)
	if err != nil {
		return err
	}
	before, err := w.reader.GetMgmtIP(ctx)
	if err != nil {
		return err
	}
	addrVb, err := NewSetVarbind(vo.MgmtWriteAddrUnverified, address, "a")
	if err != nil {
		return err
	}
	netmaskVb, err := NewSetVarbind(vo.MgmtWriteNetmaskUnverified, netmask, "a")
	if err != nil {
		return err
	}
	gatewayVb, err := NewSetVarbind(vo.MgmtWriteGatewayUnverified, gateway, "a")
	if err != nil {
		return err
	}
	if err := w.client.SetMany(ctx, []SetVarbind{addrVb, netmaskVb, gatewayVb}); err != nil {
		return err
	}
	after, err := w.reader.GetMgmtIP(ctx)
	if err != nil {
		return err
	}
	fields := [3]struct {
		name string
		want string
		got  *string
	}{
		{"address", address, after.Address},
		{"netmask", netmask, after.Netmask},
		{"gateway", gateway, after.Gateway},
	}
	for _, f := range fields {
		if f.got == nil || *f.got != f.want {
			return &model.WriteVerificationError{
				Msg: fmt.Sprintf(
					"management %s did not read back as %q (got %q)",
					f.name, f.want, derefOrEmpty(f.got),
				),
				Before: before,
				After:  after,
			}
		}
	}
	return nil
}

// derefOrEmpty returns *s, or "" if s is nil -- mirrors Python's `x or ""`
// idiom used to compare an optional VLAN/mgmt-IP string field against a
// plain string.
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// formatIntList renders ports as a Python-`sorted(...)`-style bracketed,
// comma-separated list (e.g. "[1, 2, 10]") for the protected-port-clash
// message -- this exact rendering must stay byte-identical between
// DeleteVlan's guard here and the facade-level duplicate (D-WR §3.3).
func formatIntList(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
