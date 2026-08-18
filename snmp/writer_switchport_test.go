package snmp

// writer_switchport_test.go: pure-logic unit tests for
// PlanSwitchportMembership/switchportDivergence, mirroring the derivation
// assertions in Python's tests/virtual/test_switchport_vlan_write.py (pin
// b26eb1f) -- specifically the access/trunk/general derivation, the
// tagged/excluded/untagged plan shapes, and the two refusal
// (UnsupportedCapabilityError) cases. Full end-to-end round trips against
// the m4300/gsm7228ps/gs728tpp fakes live in package virtual
// (virtual/switchport_test.go), since GetVLANs' read path needs a real (or
// fake) SNMP agent behind it, not a hand-scripted table.

import (
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func mustPlan(t *testing.T, vlanID, port int, mode model.VlanMode, currentMode *int, currentAllowed []byte, currentTagged, currentUntagged, existingVlans []int) *SwitchportPlan {
	t.Helper()
	plan, err := PlanSwitchportMembership(vlanID, port, mode, currentMode, currentAllowed, currentTagged, currentUntagged, existingVlans)
	if err != nil {
		t.Fatalf("PlanSwitchportMembership: unexpected error: %v", err)
	}
	return plan
}

func intPtr(v int) *int { return &v }

// varbind looks up the SetVarbind for oid in vbs, failing the test if
// absent.
func varbind(t *testing.T, vbs []SetVarbind, oid string) SetVarbind {
	t.Helper()
	for _, vb := range vbs {
		if vb.OID == oid {
			return vb
		}
	}
	t.Fatalf("varbinds = %+v, want one for OID %q", vbs, oid)
	return SetVarbind{}
}

// TestPlanSwitchportMembershipUntaggedWithNothingTaggedUsesAccessMode
// mirrors Python's test_untagged_on_a_port_with_nothing_tagged_uses_access_
// mode: when no tagged VLAN needs preserving, one untagged VLAN IS access
// mode -- the idiomatic form, and what the switch's own CLI produces.
func TestPlanSwitchportMembershipUntaggedWithNothingTaggedUsesAccessMode(t *testing.T) {
	plan := mustPlan(t, 2, 5, model.VlanUntagged, nil, nil, nil, nil, []int{1, 2})
	if plan.UntaggedVlan != 2 {
		t.Errorf("UntaggedVlan = %d, want 2", plan.UntaggedVlan)
	}
	if len(plan.TaggedVlans) != 0 {
		t.Errorf("TaggedVlans = %v, want empty", plan.TaggedVlans)
	}
	if len(plan.Varbinds) != 2 {
		t.Fatalf("Varbinds = %+v, want exactly 2 (access VLAN + mode)", plan.Varbinds)
	}
	accessVb := varbind(t, plan.Varbinds, FastpathSwitchportAccessVlan+".5")
	if accessVb.Value != 2 || accessVb.TypeLetter != "u" {
		t.Errorf("access varbind = %+v, want {Value:2 TypeLetter:u}", accessVb)
	}
	modeVb := varbind(t, plan.Varbinds, FastpathSwitchportMode+".5")
	if modeVb.Value != SwitchportModeAccess || modeVb.TypeLetter != "i" {
		t.Errorf("mode varbind = %+v, want {Value:%d TypeLetter:i}", modeVb, SwitchportModeAccess)
	}
}

// TestPlanSwitchportMembershipTaggedGrantsOnlyRequestedVlan mirrors
// Python's test_tagged_grants_membership_in_the_requested_vlan_only: the
// bug this replaces flipped the port to trunk while the factory allowed
// list still held all 4093 VLANs. The rebuilt allowed list must name
// exactly {untagged, requested}, not "everything".
func TestPlanSwitchportMembershipTaggedGrantsOnlyRequestedVlan(t *testing.T) {
	// Coming from access (currentMode nil, i.e. not trunk): col6 is stale
	// and must be REBUILT from the port's actual membership, not
	// read-modify-written.
	plan := mustPlan(t, 2, 5, model.VlanTagged, nil, nil, nil, []int{1}, []int{1, 2, 3})
	if plan.UntaggedVlan != 1 {
		t.Errorf("UntaggedVlan = %d, want 1 (unchanged)", plan.UntaggedVlan)
	}
	if !intSlicesEqual(plan.TaggedVlans, []int{2}) {
		t.Errorf("TaggedVlans = %v, want [2]", plan.TaggedVlans)
	}
	if len(plan.Varbinds) != 3 {
		t.Fatalf("Varbinds = %+v, want exactly 3 (allowed, native, mode)", plan.Varbinds)
	}
	allowedVb := varbind(t, plan.Varbinds, FastpathSwitchportAllowedVlans+".5")
	gotAllowed := DecodeVlanBitmap(allowedVb.Value.([]byte))
	if !intSlicesEqual(gotAllowed, []int{1, 2}) {
		t.Errorf("allowed decoded = %v, want [1 2] (native + the one requested VLAN, NOT every VLAN)", gotAllowed)
	}
	nativeVb := varbind(t, plan.Varbinds, FastpathSwitchportNativeVlan+".5")
	if nativeVb.Value != 1 || nativeVb.TypeLetter != "u" {
		t.Errorf("native varbind = %+v, want {Value:1 TypeLetter:u}", nativeVb)
	}
	modeVb := varbind(t, plan.Varbinds, FastpathSwitchportMode+".5")
	if modeVb.Value != SwitchportModeTrunk || modeVb.TypeLetter != "i" {
		t.Errorf("mode varbind = %+v, want {Value:%d TypeLetter:i}", modeVb, SwitchportModeTrunk)
	}
}

// TestPlanSwitchportMembershipTaggedPreservesAllowancesForAbsentVlans
// mirrors Python's test_allowed_vlan_write_preserves_allowances_for_absent_
// vlans: already-trunk RMW must only touch bits for VLANs that EXIST --
// bits for VLANs that don't exist yet (a factory-default port allows all
// 4093) must survive untouched, preserving "allow future VLANs too".
func TestPlanSwitchportMembershipTaggedPreservesAllowancesForAbsentVlans(t *testing.T) {
	currentAllowed := vlanBitmap([]int{1, 2, 4007, 4008}) // 4007/4008 don't exist
	plan := mustPlan(t, 5, 9, model.VlanTagged, intPtr(SwitchportModeTrunk), currentAllowed, []int{2}, []int{1}, []int{1, 2, 5})
	if !intSlicesEqual(plan.TaggedVlans, []int{2, 5}) {
		t.Errorf("TaggedVlans = %v, want [2 5]", plan.TaggedVlans)
	}
	allowedVb := varbind(t, plan.Varbinds, FastpathSwitchportAllowedVlans+".9")
	gotAllowed := DecodeVlanBitmap(allowedVb.Value.([]byte))
	if !intSlicesEqual(gotAllowed, []int{1, 2, 5, 4007, 4008}) {
		t.Errorf("allowed decoded = %v, want [1 2 5 4007 4008] (the absent VLANs' allowances must survive)", gotAllowed)
	}
}

// TestPlanSwitchportMembershipExcludedRemovesOnlyNamedVlan mirrors Python's
// test_excluded_removes_only_the_named_vlan -- THE regression this whole
// change exists for. EXCLUDED used to be "access mode on VLAN 1", which
// destroyed every other membership; it must instead read-modify-write the
// allowed list, dropping exactly the named VLAN's bit.
func TestPlanSwitchportMembershipExcludedRemovesOnlyNamedVlan(t *testing.T) {
	currentAllowed := vlanBitmap([]int{1, 2, 5})
	plan := mustPlan(t, 2, 9, model.VlanExcluded, intPtr(SwitchportModeTrunk), currentAllowed, []int{2, 5}, []int{1}, []int{1, 2, 5})
	if plan.UntaggedVlan != 1 {
		t.Errorf("UntaggedVlan = %d, want 1 (unchanged)", plan.UntaggedVlan)
	}
	if !intSlicesEqual(plan.TaggedVlans, []int{5}) {
		t.Errorf("TaggedVlans = %v, want [5] (other tagged VLANs must survive)", plan.TaggedVlans)
	}
	allowedVb := varbind(t, plan.Varbinds, FastpathSwitchportAllowedVlans+".9")
	gotAllowed := DecodeVlanBitmap(allowedVb.Value.([]byte))
	if !intSlicesEqual(gotAllowed, []int{1, 5}) {
		t.Errorf("allowed decoded = %v, want [1 5] (2's bit cleared, 1/5 survive)", gotAllowed)
	}
}

// TestPlanSwitchportMembershipExcludingUntaggedVlanFallsBackToDefault
// mirrors Python's test_excluding_the_untagged_vlan_keeps_the_tagged_ones:
// excluding a port from its ONLY untagged VLAN has to put it somewhere --
// the hardware has no "untagged nowhere" state -- so it falls back to VLAN
// 1, and that fallback must NOT cost the port its tagged VLANs.
func TestPlanSwitchportMembershipExcludingUntaggedVlanFallsBackToDefault(t *testing.T) {
	currentAllowed := vlanBitmap([]int{1, 5, 7})
	plan := mustPlan(t, 7, 9, model.VlanExcluded, intPtr(SwitchportModeTrunk), currentAllowed, []int{5}, []int{7}, []int{1, 5, 7})
	if plan.UntaggedVlan != 1 {
		t.Errorf("UntaggedVlan = %d, want 1 (the defaultVlan fallback)", plan.UntaggedVlan)
	}
	if !intSlicesEqual(plan.TaggedVlans, []int{5}) {
		t.Errorf("TaggedVlans = %v, want [5] (tagged membership must survive the fallback)", plan.TaggedVlans)
	}
}

// TestPlanSwitchportMembershipRefusesTwoUntaggedVlans mirrors Python's
// test_refuses_a_request_needing_two_untagged_vlans: a general-mode port
// really can be untagged in several VLANs, and access/trunk mode can only
// hold one -- refuse rather than silently drop the extras.
func TestPlanSwitchportMembershipRefusesTwoUntaggedVlans(t *testing.T) {
	_, err := PlanSwitchportMembership(99, 1, model.VlanTagged, nil, nil, nil, []int{1, 4007}, []int{1, 4007, 99})
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("error = %v, want wrapping model.ErrUnsupportedCapability", err)
	}
	if !containsSubstr(err.Error(), "at most ONE untagged") {
		t.Errorf("error = %q, want it to mention the one-untagged-VLAN limit", err.Error())
	}
}

// TestPlanSwitchportMembershipRefusesWhenFallbackWouldDemoteTaggedVlan
// mirrors Python's test_excluded_refuses_when_the_fallback_would_demote_a_
// tagged_vlan: if the port is a TAGGED member of the fallback VLAN,
// honouring the request would silently flip THAT VLAN to untagged -- a
// change nobody asked for. Refused as a precondition failure (no SET is
// even constructed) instead of approximated.
func TestPlanSwitchportMembershipRefusesWhenFallbackWouldDemoteTaggedVlan(t *testing.T) {
	_, err := PlanSwitchportMembership(7, 9, model.VlanExcluded, nil, nil, []int{1}, []int{7}, []int{1, 7})
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("error = %v, want wrapping model.ErrUnsupportedCapability", err)
	}
	if !containsSubstr(err.Error(), "untagged in no VLAN") {
		t.Errorf("error = %q, want it to explain the hardware cannot express untagged-in-no-VLAN", err.Error())
	}
}

func containsSubstr(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}

// --- switchportDivergence -------------------------------------------------

func TestSwitchportDivergenceNoneWhenMembershipMatches(t *testing.T) {
	plan := &SwitchportPlan{UntaggedVlan: 1, TaggedVlans: []int{2}}
	after := []model.VLANInfo{
		{VlanID: 1, MemberPorts: []int{9}, TaggedPorts: nil, UntaggedPorts: []int{9}},
		{VlanID: 2, MemberPorts: []int{9}, TaggedPorts: []int{9}, UntaggedPorts: nil},
	}
	if got := switchportDivergence(plan, 2, 9, after); got != "" {
		t.Errorf("switchportDivergence = %q, want \"\" (matches)", got)
	}
}

func TestSwitchportDivergenceDetectsVanishedVlan(t *testing.T) {
	plan := &SwitchportPlan{UntaggedVlan: 1}
	after := []model.VLANInfo{{VlanID: 5}}
	got := switchportDivergence(plan, 2, 9, after)
	if !containsSubstr(got, "disappeared") {
		t.Errorf("switchportDivergence = %q, want it to mention the VLAN disappeared", got)
	}
}

func TestSwitchportDivergenceDetectsUnrequestedGain(t *testing.T) {
	plan := &SwitchportPlan{UntaggedVlan: 1, TaggedVlans: []int{2}}
	after := []model.VLANInfo{
		{VlanID: 1, MemberPorts: []int{9}, UntaggedPorts: []int{9}},
		{VlanID: 2, MemberPorts: []int{9}, TaggedPorts: []int{9}},
		// Port 9 is ALSO a tagged member of VLAN 3, which nobody asked for
		// -- the old all-4093 trunk over-grant this verification exists to
		// catch.
		{VlanID: 3, MemberPorts: []int{9}, TaggedPorts: []int{9}},
	}
	got := switchportDivergence(plan, 2, 9, after)
	if !containsSubstr(got, "UNREQUESTED") {
		t.Errorf("switchportDivergence = %q, want it to flag UNREQUESTED membership gained", got)
	}
}
