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
// to wire bitmaps -- the model-derived VlanBitmapWidth is threaded in
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

// SetVlanMembership sets port's membership mode (untagged/tagged/excluded)
// within vlanID and verifies BOTH written columns (egress member_ports AND
// untagged_ports) read back correctly. Ported from Python's
// SnmpWriter.set_vlan_membership -- see D-WR §2.10, the richest write op.
//
// The guard fires UNCONDITIONALLY (any membership change is disruptive),
// BEFORE the VLAN-existence check. A missing VLAN is a PRECONDITION
// failure -- an error wrapping model.ErrSNMP, NOT a
// *model.WriteVerificationError -- and issues ZERO SETs (D-WR §2.10 step
// 2). The read-modify-write re-encodes the CURRENTLY READ egress/untagged
// bitmaps from the SAME `before` snapshot used for the existence check (no
// second read), widened via VlanBitmapWidth(w.model.PortCount) -- always
// model-derived, never the input bitmap's own default width alone. ONE
// SetMany call, two "x" (hex/octet-string) varbinds for the same vlan
// (egress then untagged) -- the atomic-multi-varbind-SET case. Verification
// checks, in order: (1) after == nil (VLAN vanished) is its own branch; (2)
// egress (MemberPorts) matches the exact bitmap just written (re-decoded,
// not re-derived from mode); (3) untagged_ports likewise -- catching a
// device that silently drops just one of the two SETs.
func (w *Writer) SetVlanMembership(ctx context.Context, vlanID, port int, mode model.VlanMode, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	before, err := w.vlan(ctx, vlanID)
	if err != nil {
		return err
	}
	if before == nil {
		return errSNMP("VLAN %d does not exist", vlanID)
	}
	width := VlanBitmapWidth(w.model.PortCount)
	newEgress, newUntagged := MembershipBitmaps(
		EncodePortBitmap(before.MemberPorts, vlanEncodeWidth),
		EncodePortBitmap(before.UntaggedPorts, vlanEncodeWidth),
		port, mode, width,
	)
	egressVb, err := NewSetVarbind(fmt.Sprintf("%s.%d", Dot1qVlanStaticEgress, vlanID), newEgress, "x")
	if err != nil {
		return err
	}
	untaggedVb, err := NewSetVarbind(fmt.Sprintf("%s.%d", Dot1qVlanStaticUntagged, vlanID), newUntagged, "x")
	if err != nil {
		return err
	}
	if err := w.client.SetMany(ctx, []SetVarbind{egressVb, untaggedVb}); err != nil {
		return err
	}
	after, err := w.vlan(ctx, vlanID)
	if err != nil {
		return err
	}
	wantEgress := DecodePortBitmap(newEgress)
	wantUntagged := DecodePortBitmap(newUntagged)
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

// CreateVlan creates vlanID with the given name and verifies it exists with
// that name afterward. Ported from Python's SnmpWriter.create_vlan -- see
// D-WR §2.11.
//
// CreateVlan NEVER guards on protected ports: creating an EMPTY VLAN adds
// no port membership, so it is non-disruptive by construction -- there is
// no `force` parameter (unlike DeleteVlan) since nothing here is ever
// refused. One SetMany PDU, two varbinds: RowStatus createAndGo (int 4,
// type "i") + Name (type "s", plain string -- NOT "x" like the VLAN
// membership bitmaps). Verify: VLAN exists AND its name equals the
// requested name exactly, treating a nil Name the same as empty string
// (mirrors Python's `after.name or ""`).
func (w *Writer) CreateVlan(ctx context.Context, vlanID int, name string) error {
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
