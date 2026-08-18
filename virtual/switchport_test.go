package virtual

// switchport_test.go: end-to-end round trips of the FASTPATH switchport
// VLAN-membership control plane (m4300-24x) and the gsm7228ps split-PDU
// auto-untag quirk, driven over a REAL SnmpFace via snmp.Writer/snmp.Reader
// -- never a scripted mock -- exercising exactly the seam the pin's own
// tests/virtual/test_switchport_vlan_write.py drives (pin b26eb1f): the
// vendor switchport OIDs get written, State.applySwitchport (state_
// switchport.go) derives Q-BRIDGE membership from them, and the writer's
// own verify-after-write reads it back. Also covers the GS728TPP SNMP
// VLAN-creation refusal (model.SwitchModel.SNMPCanCreateVLAN == false).

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// switchportHarness wires a real snmp.Reader/snmp.Writer directly to a
// live SnmpFace serving st -- bypassing any higher-level facade, exactly
// like the pin's own tests always drive SnmpReader/SnmpWriter directly
// ("never through the SyncSwitch facade, whose per-backend dispatch would
// prove nothing about SNMP").
type switchportHarness struct {
	reader *snmp.Reader
	writer *snmp.Writer
}

func newSwitchportHarness(t *testing.T, modelKey string, st *State) *switchportHarness {
	t.Helper()
	addr, _, _ := startFace(t, st)
	client := snmp.NewGoSNMPClient(addr, "public")
	m, err := model.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q): %v", modelKey, err)
	}
	reader, err := snmp.NewReader(client, m)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	writer, err := snmp.NewWriter(client, m)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	return &switchportHarness{reader: reader, writer: writer}
}

// membership returns (tagged, untagged) VLAN ids for port, read from the
// Q-BRIDGE mirrors -- the same footing set_vlan_membership's own
// verify-after-write compares against.
func (h *switchportHarness) membership(t *testing.T, port int) (tagged, untagged map[int]bool) {
	t.Helper()
	vlans, err := h.reader.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs: %v", err)
	}
	tagged, untagged = map[int]bool{}, map[int]bool{}
	for _, v := range vlans {
		for _, p := range v.TaggedPorts {
			if p == port {
				tagged[v.VlanID] = true
			}
		}
		for _, p := range v.UntaggedPorts {
			if p == port {
				untagged[v.VlanID] = true
			}
		}
	}
	return tagged, untagged
}

func (h *switchportHarness) pvid(t *testing.T, port int) (int, bool) {
	t.Helper()
	pvids, err := h.reader.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs: %v", err)
	}
	for _, p := range pvids {
		if p.Port == port {
			return p.Vlan, true
		}
	}
	return 0, false
}

func setEqual(got map[int]bool, want ...int) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !got[w] {
			return false
		}
	}
	return true
}

// TestSwitchportModelsRouteThroughTheVendorControlPlane confirms
// SetVlanMembership on an m4300 fake is a NO-OP on the Q-BRIDGE PortLists
// and instead lands on the FASTPATH vendor switchport columns -- port 24
// (SeedM4300_24X: access mode, access VLAN 10, tagged nowhere) written
// UNTAGGED into a fresh VLAN must move mode/accessVlan (or native, per the
// trunk-vs-access rule), never leave the Q-BRIDGE mirrors as the sole
// change vector.
func TestSwitchportEndToEndFiveStepTranscript(t *testing.T) {
	st := SeedM4300_24X()
	h := newSwitchportHarness(t, "m4300-24x", st)
	ctx := context.Background()
	const port = 24 // SeedM4300_24X: access(1), access VLAN 10, tagged nowhere

	tagged, untagged := h.membership(t, port)
	if !setEqual(tagged) || !setEqual(untagged, 10) {
		t.Fatalf("precondition: membership = tagged=%v untagged=%v, want tagged={} untagged={10}", tagged, untagged)
	}

	// Two throwaway VLANs, created over SNMP (m4300-24x's agent CAN create
	// VLAN rows -- unlike gs728tpp, see the create-refusal tests below).
	for _, vid := range []int{4007, 4008} {
		if err := h.writer.CreateVlan(ctx, vid, "AGENT"); err != nil {
			t.Fatalf("CreateVlan(%d): %v", vid, err)
		}
	}

	type step struct {
		vlan         int
		mode         model.VlanMode
		wantTagged   []int
		wantUntagged []int
	}
	transcript := []step{
		// TAGGED 4007: nothing untagged changes; port gains a tagged VLAN
		// and (coming from access mode) the port becomes trunk with col6
		// rebuilt to exactly {native, 4007} -- not "every VLAN" (the bug
		// this plan replaces).
		{4007, model.VlanTagged, []int{4007}, []int{10}},
		{4008, model.VlanTagged, []int{4007, 4008}, []int{10}},
		// EXCLUDED 4007: drops exactly that VLAN, the other tagged VLAN
		// and the untagged VLAN survive untouched.
		{4007, model.VlanExcluded, []int{4008}, []int{10}},
		// UNTAGGED 4008: nothing left tagged -> collapses to access mode;
		// the port's PREVIOUS untagged VLAN (10) is replaced, not kept.
		{4008, model.VlanUntagged, nil, []int{4008}},
		// EXCLUDED 4008 (the port's only untagged VLAN, no tagged VLAN 1
		// to protect): falls back to the default VLAN 1.
		{4008, model.VlanExcluded, nil, []int{1}},
	}
	for i, st := range transcript {
		if err := h.writer.SetVlanMembership(ctx, st.vlan, port, st.mode, true); err != nil {
			t.Fatalf("step %d: SetVlanMembership(%d, %d, %v): %v", i, st.vlan, port, st.mode, err)
		}
		gotTagged, gotUntagged := h.membership(t, port)
		if !setEqual(gotTagged, st.wantTagged...) {
			t.Errorf("step %d (%v %d): tagged = %v, want %v", i, st.mode, st.vlan, gotTagged, st.wantTagged)
		}
		if !setEqual(gotUntagged, st.wantUntagged...) {
			t.Errorf("step %d (%v %d): untagged = %v, want %v", i, st.mode, st.vlan, gotUntagged, st.wantUntagged)
		}
	}
}

// TestSwitchportEndToEndAccessModeVerbatim mirrors Python's
// test_untagged_on_a_port_with_nothing_tagged_uses_access_mode: writing a
// single UNTAGGED VLAN onto a port with nothing tagged lands in access
// mode (the idiomatic minimal form), and the vendor mode/access-VLAN
// columns read back exactly that -- not trunk.
func TestSwitchportEndToEndAccessModeVerbatim(t *testing.T) {
	st := SeedM4300_24X()
	h := newSwitchportHarness(t, "m4300-24x", st)
	ctx := context.Background()
	const port = 24
	const vid = 4009

	if err := h.writer.CreateVlan(ctx, vid, "AGENT"); err != nil {
		t.Fatalf("CreateVlan: %v", err)
	}
	if err := h.writer.SetVlanMembership(ctx, vid, port, model.VlanUntagged, true); err != nil {
		t.Fatalf("SetVlanMembership: %v", err)
	}
	if st.SwitchportMode[port] != snmpSwitchportModeAccess(t) {
		t.Errorf("SwitchportMode[%d] = %d, want access(%d)", port, st.SwitchportMode[port], snmpSwitchportModeAccess(t))
	}
	if st.SwitchportAccessVlan[port] != vid {
		t.Errorf("SwitchportAccessVlan[%d] = %d, want %d", port, st.SwitchportAccessVlan[port], vid)
	}
	pvid, ok := h.pvid(t, port)
	if !ok || pvid != vid {
		t.Errorf("PVID for port %d = (%d, %v), want (%d, true) (untagged VLAN drives PVID in access mode)", port, pvid, ok, vid)
	}
}

// TestSwitchportEndToEndTrunkModeVerbatim mirrors Python's
// test_set_vlan_membership_untagged_via_switchport: a port with real
// pre-existing tagged VLANs (port 1, a captured trunk uplink) moved
// UNTAGGED into a fresh VLAN must become trunk mode with that VLAN as the
// NATIVE VLAN, preserving every prior tagged membership.
func TestSwitchportEndToEndTrunkModeVerbatim(t *testing.T) {
	st := SeedM4300_24X()
	h := newSwitchportHarness(t, "m4300-24x", st)
	ctx := context.Background()
	const port = 1 // SeedM4300_24X's real captured uplink trunk
	const vid = 4010

	wasTagged, _ := h.membership(t, port)
	if len(wasTagged) < 2 {
		t.Fatalf("precondition: port %d tagged = %v, want the seed's real multi-VLAN trunk membership", port, wasTagged)
	}
	if err := h.writer.CreateVlan(ctx, vid, "AGENT"); err != nil {
		t.Fatalf("CreateVlan: %v", err)
	}

	if err := h.writer.SetVlanMembership(ctx, vid, port, model.VlanUntagged, true); err != nil {
		t.Fatalf("SetVlanMembership: %v", err)
	}

	if st.SwitchportMode[port] != snmpSwitchportModeTrunk(t) {
		t.Errorf("SwitchportMode[%d] = %d, want trunk(%d)", port, st.SwitchportMode[port], snmpSwitchportModeTrunk(t))
	}
	if st.SwitchportNativeVlan[port] != vid {
		t.Errorf("SwitchportNativeVlan[%d] = %d, want %d", port, st.SwitchportNativeVlan[port], vid)
	}
	gotTagged, gotUntagged := h.membership(t, port)
	if !setEqual(gotUntagged, vid) {
		t.Errorf("untagged = %v, want {%d} only", gotUntagged, vid)
	}
	for v := range wasTagged {
		if !gotTagged[v] {
			t.Errorf("port %d lost prior tagged membership in VLAN %d", port, v)
		}
	}
	pvid, ok := h.pvid(t, port)
	if !ok || pvid != vid {
		t.Errorf("PVID for port %d = (%d, %v), want (%d, true) (native VLAN drives PVID in trunk mode)", port, pvid, ok, vid)
	}
}

// TestSwitchportEndToEndGeneralModeMembershipIsIndependentOfEffectiveState
// mirrors Python's _in_general_mode helper plus
// test_switchport_columns_are_not_a_mirror_of_effective_membership:
// general(3) mode cannot be driven over SNMP (its participation columns
// answer notWritable), so this is set directly on State, exactly the
// device-config shape only a CLI could produce -- and confirms
// applySwitchport derives membership from col7/col8, not from whatever
// the port used to carry.
func TestSwitchportEndToEndGeneralModeMembershipIsIndependentOfEffectiveState(t *testing.T) {
	st := SeedM4300_24X()
	const port = 24
	st.SwitchportMode[port] = snmpSwitchportModeGeneral(t)
	st.SwitchportGeneralUntagged[port] = map[int]bool{1: true, 5: true}
	st.SwitchportGeneralTagged[port] = map[int]bool{90: true}
	st.applySwitchport(port)

	h := newSwitchportHarness(t, "m4300-24x", st)
	tagged, untagged := h.membership(t, port)
	if !setEqual(untagged, 1, 5) {
		t.Errorf("untagged = %v, want {1, 5} (from col7, not the port's old access-mode VLAN 10)", untagged)
	}
	if !setEqual(tagged, 90) {
		t.Errorf("tagged = %v, want {90} (from col8)", tagged)
	}
}

// TestSwitchportEndToEndQBridgeEgressRejectedWhileAccessModePortExists
// mirrors Python's test_qbridge_egress_write_is_rejected_while_a_port_is_
// in_access_mode: a raw SET of dot1qVlanStaticEgressPorts on an
// m4300-24x -- byte-identical to the value just read -- must fail with a
// commitFailed, live-proven on FASTPATH 12.x, because at least one port is
// access-mode (every port in SeedM4300_24X's own switchport table is
// access or trunk).
func TestSwitchportEndToEndQBridgeEgressRejectedWhileAccessModePortExists(t *testing.T) {
	st := SeedM4300_24X()
	addr, _, _ := startFace(t, st)
	client := snmp.NewGoSNMPClient(addr, "public")
	vid := 1
	rows, err := client.Get(context.Background(), []string{snmp.Dot1qVlanStaticEgress + ".1"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("Get(egress.1) = %+v, %v", rows, err)
	}
	raw, ok := rows[0].Value.([]byte)
	if !ok {
		t.Fatalf("egress.1 value = %T, want []byte", rows[0].Value)
	}
	vb, err := snmp.NewSetVarbind(snmp.Dot1qVlanStaticEgress+".1", raw, "x")
	if err != nil {
		t.Fatalf("NewSetVarbind: %v", err)
	}
	err = client.Set(context.Background(), vb)
	if err == nil {
		t.Fatalf("Set(egress.%d, byte-identical) error = nil, want a commitFailed-shaped SnmpError (an access-mode port makes the whole column read-only)", vid)
	}
	if !errors.Is(err, model.ErrSNMP) {
		t.Errorf("Set error = %v, want wrapping model.ErrSNMP", err)
	}
}

// TestSwitchportEndToEndPerPortParticipationBitmapsAreReadOnly mirrors
// Python's test_per_port_vlan_bitmaps_are_read_only: the switchport
// tagged/untagged VLAN bitmaps (columns 7/8) answer notWritable live, in
// every switchport mode.
func TestSwitchportEndToEndPerPortParticipationBitmapsAreReadOnly(t *testing.T) {
	st := SeedM4300_24X()
	addr, _, _ := startFace(t, st)
	client := snmp.NewGoSNMPClient(addr, "public")
	const port = 24
	for _, base := range []string{snmp.FastpathSwitchportTaggedVlans, snmp.FastpathSwitchportUntaggedVlans} {
		rows, err := client.Get(context.Background(), []string{colOID(base, port)})
		if err != nil || len(rows) != 1 {
			t.Fatalf("Get(%s): rows=%+v err=%v", base, rows, err)
		}
		cur, ok := rows[0].Value.([]byte)
		if !ok {
			t.Fatalf("%s value = %T, want []byte", base, rows[0].Value)
		}
		if len(cur) != snmp.SwitchportVlanBitmapBytes {
			t.Errorf("%s len = %d, want %d", base, len(cur), snmp.SwitchportVlanBitmapBytes)
		}
		vb, err := snmp.NewSetVarbind(colOID(base, port), cur, "x")
		if err != nil {
			t.Fatalf("NewSetVarbind: %v", err)
		}
		if err := client.Set(context.Background(), vb); err == nil {
			t.Errorf("Set(%s.%d) error = nil, want a notWritable-shaped SnmpError", base, port)
		}
	}
}

// TestSwitchportEndToEndNativeVlanMustBeExisting mirrors Python's
// test_native_vlan_must_be_an_existing_vlan: col4 (native VLAN) is
// writable, but only to an EXISTING VLAN in 1..4093 -- := 0, := 4094, and
// := a non-existent VLAN id all answer commitFailed live, which is why the
// writer can never express "untagged in no VLAN".
func TestSwitchportEndToEndNativeVlanMustBeExisting(t *testing.T) {
	st := SeedM4300_24X()
	addr, _, _ := startFace(t, st)
	client := snmp.NewGoSNMPClient(addr, "public")
	const port = 1
	for _, bad := range []int{0, 4094, 4007} { // 4007 absent from SeedM4300_24X's VLANs
		vb, err := snmp.NewSetVarbind(colOID(snmp.FastpathSwitchportNativeVlan, port), bad, "u")
		if err != nil {
			t.Fatalf("NewSetVarbind: %v", err)
		}
		if err := client.Set(context.Background(), vb); err == nil {
			t.Errorf("Set(native.%d, %d) error = nil, want a commitFailed-shaped SnmpError", port, bad)
		}
	}
}

// colOID formats a "<base>.<index>" OID column key, matching
// state_oidmap.go's own colKey (unexported there; duplicated here since
// tests live in the same package and colKey already exists -- use it
// directly instead).
func colOID(base string, index int) string { return colKey(base, index) }

func snmpSwitchportModeAccess(t *testing.T) int  { t.Helper(); return snmp.SwitchportModeAccess }
func snmpSwitchportModeTrunk(t *testing.T) int   { t.Helper(); return snmp.SwitchportModeTrunk }
func snmpSwitchportModeGeneral(t *testing.T) int { t.Helper(); return snmp.SwitchportModeGeneral }

// --- GSM7228PS (S3300) same-PDU auto-untag ordering quirk ------------------

// TestSwitchportEndToEndGSM7228PSSplitPDUKeepsTaggedMembership mirrors
// Python's test_writer_splits_pdus_so_tagged_membership_survives_on_s3300:
// the library's TAGGED write must survive on the quirky Smart firmware
// (model.SwitchModel.SnmpVlanSplitMembershipWrites == true), because
// snmp.Writer.SetVlanMembership sends the egress and untagged PortLists in
// TWO separate PDUs rather than one atomic SetMany.
func TestSwitchportEndToEndGSM7228PSSplitPDUKeepsTaggedMembership(t *testing.T) {
	st := SeedGSM7228PS()
	h := newSwitchportHarness(t, "gsm7228ps", st)
	const port = 1
	const vid = 4089 // seeded empty VLAN -- see SeedGSM7228PS

	if err := h.writer.SetVlanMembership(context.Background(), vid, port, model.VlanTagged, true); err != nil {
		t.Fatalf("SetVlanMembership: %v", err)
	}
	tagged, untagged := h.membership(t, port)
	if !tagged[vid] {
		t.Errorf("port %d not tagged in VLAN %d after a TAGGED write", port, vid)
	}
	if untagged[vid] {
		t.Errorf("port %d IS untagged in VLAN %d -- the split-PDU auto-untag side effect leaked through (the whole point of SnmpVlanSplitMembershipWrites)", port, vid)
	}
}

// TestSwitchportEndToEndGSM7228PSSamePduClobbersUntaggedIntent mirrors
// Python's test_mock_reproduces_same_pdu_untagged_clobber: a raw client
// that (unlike snmp.Writer) sends BOTH columns in one atomic SetMany loses
// the untagged intent -- the fake's auto-untag side effect wins, exactly
// as the real S3300-52X-PoE+ does -- and issuing the SAME two writes as
// separate SETs instead sticks. This directly exercises State.ApplyWrite's
// PDUEgressWrites bookkeeping (state.go/state_switchport.go), independent
// of the writer split-PDU fix the previous test already covers.
func TestSwitchportEndToEndGSM7228PSSamePduClobbersUntaggedIntent(t *testing.T) {
	st := SeedGSM7228PS()
	addr, _, _ := startFace(t, st)
	client := snmp.NewGoSNMPClient(addr, "public")
	ctx := context.Background()
	const port = 1
	const vid = 4089

	egressRows, err := client.Get(ctx, []string{colOID(snmp.Dot1qVlanStaticEgress, vid)})
	if err != nil || len(egressRows) != 1 {
		t.Fatalf("Get(egress.%d): rows=%+v err=%v", vid, egressRows, err)
	}
	untaggedRows, err := client.Get(ctx, []string{colOID(snmp.Dot1qVlanStaticUntagged, vid)})
	if err != nil || len(untaggedRows) != 1 {
		t.Fatalf("Get(untagged.%d): rows=%+v err=%v", vid, untaggedRows, err)
	}
	egressRaw, _ := egressRows[0].Value.([]byte)
	untaggedRaw, _ := untaggedRows[0].Value.([]byte)
	wantEgress := snmp.SetPortBit(egressRaw, port, true)
	wantUntagged := snmp.SetPortBit(untaggedRaw, port, false)

	egressVb, err := snmp.NewSetVarbind(colOID(snmp.Dot1qVlanStaticEgress, vid), wantEgress, "x")
	if err != nil {
		t.Fatalf("NewSetVarbind: %v", err)
	}
	untaggedVb, err := snmp.NewSetVarbind(colOID(snmp.Dot1qVlanStaticUntagged, vid), wantUntagged, "x")
	if err != nil {
		t.Fatalf("NewSetVarbind: %v", err)
	}

	// ONE PDU: the egress side effect wins, so the port stays untagged.
	if err := client.SetMany(ctx, []snmp.SetVarbind{egressVb, untaggedVb}); err != nil {
		t.Fatalf("SetMany: %v", err)
	}
	afterRows, err := client.Get(ctx, []string{colOID(snmp.Dot1qVlanStaticUntagged, vid)})
	if err != nil || len(afterRows) != 1 {
		t.Fatalf("Get(untagged.%d) after one PDU: rows=%+v err=%v", vid, afterRows, err)
	}
	afterOne, _ := afterRows[0].Value.([]byte)
	if !bitSet(afterOne, port) {
		t.Fatalf("after ONE PDU: port %d not in untagged bitmap -- the fake must clobber like the real S3300", port)
	}

	// TWO PDUs, egress first: the untagged write sticks.
	if err := client.Set(ctx, egressVb); err != nil {
		t.Fatalf("Set(egress): %v", err)
	}
	if err := client.Set(ctx, untaggedVb); err != nil {
		t.Fatalf("Set(untagged): %v", err)
	}
	afterRows2, err := client.Get(ctx, []string{colOID(snmp.Dot1qVlanStaticUntagged, vid)})
	if err != nil || len(afterRows2) != 1 {
		t.Fatalf("Get(untagged.%d) after two PDUs: rows=%+v err=%v", vid, afterRows2, err)
	}
	afterTwo, _ := afterRows2[0].Value.([]byte)
	if bitSet(afterTwo, port) {
		t.Errorf("after TWO PDUs (egress first): port %d still in untagged bitmap, want it cleared", port)
	}
}

func bitSet(bitmap []byte, port int) bool {
	for _, p := range snmp.DecodePortBitmap(bitmap) {
		if p == port {
			return true
		}
	}
	return false
}

// --- GS728TPP SNMP VLAN-creation refusal -----------------------------------

// TestSwitchportEndToEndGS728TPPRefusesVLANCreation mirrors Python's
// test_snmp_refuses_vlan_creation_the_way_the_switch_does: the writer must
// refuse BY NAME before sending anything (model.ErrUnsupportedCapability),
// AND the fake must independently refuse the raw row-status SET too --
// proving the refusal is a property of the MODELLED DEVICE, not only of
// the writer's own guard -- with the row never created either way.
func TestSwitchportEndToEndGS728TPPRefusesVLANCreation(t *testing.T) {
	st := SeedGS728TPP()
	h := newSwitchportHarness(t, "gs728tpp", st)
	ctx := context.Background()
	const vid = 4007

	err := h.writer.CreateVlan(ctx, vid, "nope")
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("CreateVlan error = %v, want wrapping model.ErrUnsupportedCapability", err)
	}

	// The fake refuses the raw row-status SET too, independent of the
	// writer's own guard.
	addr, _, _ := startFace(t, SeedGS728TPP())
	client := snmp.NewGoSNMPClient(addr, "public")
	vb, err := snmp.NewSetVarbind(colOID(snmp.Dot1qVlanStaticRowStatus, vid), snmp.RowStatusCreateAndGo, "i")
	if err != nil {
		t.Fatalf("NewSetVarbind: %v", err)
	}
	if err := client.Set(ctx, vb); err == nil {
		t.Fatal("raw createAndGo SET on gs728tpp error = nil, want an inconsistentValue-shaped SnmpError")
	} else if !errors.Is(err, model.ErrSNMP) {
		t.Errorf("raw createAndGo SET error = %v, want wrapping model.ErrSNMP", err)
	}

	vlans, err := h.reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs: %v", err)
	}
	for _, v := range vlans {
		if v.VlanID == vid {
			t.Fatalf("VLAN %d exists after a refused creation attempt", vid)
		}
	}
}

// TestSwitchportEndToEndGS728TPPStillDeletesAndRewritesMembership mirrors
// Python's test_snmp_delete_and_membership_still_work: creation is the
// ONLY thing refused on this model -- proving it is not a wholesale
// read-only table. Membership and destroy(6) both still work.
func TestSwitchportEndToEndGS728TPPStillDeletesAndRewritesMembership(t *testing.T) {
	st := SeedGS728TPP()
	h := newSwitchportHarness(t, "gs728tpp", st)
	ctx := context.Background()

	vlans, err := h.reader.GetVLANs(ctx)
	if err != nil || len(vlans) == 0 {
		t.Fatalf("GetVLANs() = %+v, %v, want at least one seeded VLAN", vlans, err)
	}
	existing := vlans[0].VlanID
	var port int
	for p := range st.Ports {
		port = p
		break
	}
	if err := h.writer.SetVlanMembership(ctx, existing, port, model.VlanTagged, true); err != nil {
		t.Fatalf("SetVlanMembership on an EXISTING VLAN: %v", err)
	}
	if err := h.writer.DeleteVlan(ctx, existing, true); err != nil {
		t.Fatalf("DeleteVlan on an EXISTING VLAN: %v", err)
	}
	after, err := h.reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs: %v", err)
	}
	for _, v := range after {
		if v.VlanID == existing {
			t.Fatalf("VLAN %d still exists after DeleteVlan", existing)
		}
	}
}

// --- seed fidelity: the switchport columns and the captured VLAN
// membership are TWO INDEPENDENTLY measured things (principle 5) ----------

// membershipSnapshot returns a deep copy of every VLAN's (member, untagged)
// port sets, for comparing state before/after a re-derivation.
func membershipSnapshot(st *State) map[int][2]map[int]bool {
	out := make(map[int][2]map[int]bool, len(st.Vlans))
	for vid, vsim := range st.Vlans {
		out[vid] = [2]map[int]bool{
			cloneIntBoolMap(vsim.Member),
			cloneIntBoolMap(vsim.Untagged),
		}
	}
	return out
}

func membershipSnapshotsEqual(a, b map[int][2]map[int]bool) (equal bool, diff string) {
	if len(a) != len(b) {
		return false, fmt.Sprintf("vlan count %d != %d", len(a), len(b))
	}
	for vid, av := range a {
		bv, ok := b[vid]
		if !ok {
			return false, fmt.Sprintf("VLAN %d missing after re-derivation", vid)
		}
		if !intBoolMapEqual(av[0], bv[0]) {
			return false, fmt.Sprintf("VLAN %d member: before=%v after=%v", vid, sliceFromPortSet(av[0]), sliceFromPortSet(bv[0]))
		}
		if !intBoolMapEqual(av[1], bv[1]) {
			return false, fmt.Sprintf("VLAN %d untagged: before=%v after=%v", vid, sliceFromPortSet(av[1]), sliceFromPortSet(bv[1]))
		}
	}
	return true, ""
}

func intBoolMapEqual(a, b map[int]bool) bool {
	an, bn := sliceFromPortSet(a), sliceFromPortSet(b)
	return intSlicesEqualForTest(an, bn)
}

func intSlicesEqualForTest(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// testSeededSwitchportColumnsReproduceCapturedMembership mirrors Python's
// test_seeded_switchport_columns_reproduce_the_captured_membership: the
// seed carries TWO separately-measured things -- the VLAN membership from
// the committed hardware capture, and the vendor switchport columns read
// off the real switch. Nothing computes one from the other at seed time.
// So re-deriving membership from the columns (applySwitchport) and getting
// the captured membership back byte for byte, PVIDs included, for every
// physical port, can only happen if applySwitchport's rule is the one the
// hardware actually implements -- this is what would have caught the
// historical bug (modelling trunk as "tagged in every allowed VLAN,
// untagged nowhere") immediately.
func testSeededSwitchportColumnsReproduceCapturedMembership(t *testing.T, seed func() *State) {
	t.Helper()
	st := seed()
	before := membershipSnapshot(st)
	pvidsBefore := map[int]int{}
	var physical []int
	for port, sim := range st.Ports {
		if sim.IfType == 6 {
			physical = append(physical, port)
			pvidsBefore[port] = st.Pvids[port]
		}
	}
	if len(physical) == 0 {
		t.Fatal("seed must have physical ports")
	}
	for _, port := range physical {
		st.applySwitchport(port)
	}
	after := membershipSnapshot(st)
	if equal, diff := membershipSnapshotsEqual(before, after); !equal {
		t.Errorf("re-derived membership != captured membership: %s", diff)
	}
	for _, port := range physical {
		if pvidsBefore[port] != st.Pvids[port] {
			t.Errorf("port %d PVID: before=%d after=%d", port, pvidsBefore[port], st.Pvids[port])
		}
	}
}

func TestSeededSwitchportColumnsReproduceCapturedMembershipM4300_24X(t *testing.T) {
	testSeededSwitchportColumnsReproduceCapturedMembership(t, SeedM4300_24X)
}

func TestSeededSwitchportColumnsReproduceCapturedMembershipM4300_16X(t *testing.T) {
	testSeededSwitchportColumnsReproduceCapturedMembership(t, SeedM4300_16X)
}
