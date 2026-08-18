package virtual

// Tests for State.NsdpTlvs/ApplyNsdpWrite, mirroring
// tests/virtual/test_nsdp_state.py's intents (D-NSDP §9.4): strict per-tag
// gating (a PORT_STATUS-only request must not also yield MODEL), correct
// per-port speed/VLAN/PVID/mgmt-IP projection, and write-then-read-back
// mutation of PVID/VLAN-membership/mgmt-IP.

import (
	"reflect"
	"slices"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

// deviceFrom builds a minimal READ_RESPONSE packet around tlvs and parses
// it, the same round-trip a real NsdpFace/UDPClient pair performs -- the
// closest Go analogue to test_nsdp_state.py's own `_device_from` helper.
func deviceFrom(t *testing.T, tlvs []nsdp.TLVEntry) model.NsdpDevice {
	t.Helper()
	pkt := nsdp.Packet{
		Op:        nsdp.OpReadResponse,
		ClientMAC: make([]byte, 6),
		ServerMAC: make([]byte, 6),
		TLVs:      tlvs,
	}
	dev, err := nsdp.ParseDevice(pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	return dev
}

func TestNsdpTlvsStrictTagGatingOmitsUnrequestedIdentity(t *testing.T) {
	st := SeedGS110EMX()

	// A PORT_STATUS-only request must NOT also return MODEL: NsdpTlvs
	// answers with ONLY the tags actually requested (D-NSDP §7.1's STRICT
	// rule -- the pinned Python source's own docstring first line claiming
	// "MODEL/MAC/PORT_COUNT always included" is stale prose the CODE and
	// its own test both contradict; see NsdpTlvs's doc comment).
	tlvs := st.NsdpTlvs(map[nsdp.Tag]bool{nsdp.TagPortStatus: true})
	for _, tlv := range tlvs {
		if tlv.Tag == nsdp.TagModel {
			t.Fatal("PORT_STATUS-only request unexpectedly included a MODEL TLV")
		}
	}
}

func TestNsdpTlvsProjectsPortsAndIdentity(t *testing.T) {
	st := SeedGS110EMX()

	tlvs := st.NsdpTlvs(map[nsdp.Tag]bool{
		nsdp.TagModel:      true,
		nsdp.TagPortCount:  true,
		nsdp.TagPortStatus: true,
	})
	tags := map[nsdp.Tag]bool{}
	for _, tlv := range tlvs {
		tags[tlv.Tag] = true
	}
	if !tags[nsdp.TagModel] {
		t.Error("combined request missing MODEL")
	}
	if !tags[nsdp.TagPortCount] {
		t.Error("combined request missing PORT_COUNT")
	}

	dev := deviceFrom(t, tlvs)
	ports := map[int]model.NsdpPortStatus{}
	for _, p := range dev.PortStatus {
		ports[p.PortID] = p
	}
	// Seed mirrors the real capture: 6/8/9/10 up, the rest down.
	if ports[1].Speed != model.LinkSpeedDown {
		t.Errorf("port 1 speed = %v, want DOWN (link is down)", ports[1].Speed)
	}
	if ports[8].Speed != model.LinkSpeedGigabit {
		t.Errorf("port 8 speed = %v, want GIGABIT", ports[8].Speed)
	}
	if ports[9].Speed != model.LinkSpeedTenGigabit {
		t.Errorf("port 9 speed = %v, want TEN_GIGABIT", ports[9].Speed)
	}
}

// TestNsdpTlvsPortStatusEmitsSeededFlowControlByte is the [NSDP-FC]
// regression test: PORT_STATUS TLV byte 2 must be DERIVED from
// PortSim.FlowControl (mirroring pin state.py:1489-1499's `1 if
// sim.flow_control else 0`), not a hardcoded constant. A State whose ports
// disagree on FlowControl must emit disagreeing bytes -- a hardcoded 0x01
// would pass every currently-seeded model (all three NSDP Plus-family
// seeds have FlowControl: true on every port) without ever proving this.
func TestNsdpTlvsPortStatusEmitsSeededFlowControlByte(t *testing.T) {
	st := NewState("gs110emx")
	st.Ports[1] = &PortSim{Name: "g1", Admin: true, Link: true, Speed: 1000, FlowControl: true}
	st.Ports[2] = &PortSim{Name: "g2", Admin: true, Link: true, Speed: 1000, FlowControl: false}

	tlvs := st.NsdpTlvs(map[nsdp.Tag]bool{nsdp.TagModel: true, nsdp.TagPortStatus: true})
	byPort := map[int]nsdp.TLVEntry{}
	for _, tlv := range tlvs {
		if tlv.Tag != nsdp.TagPortStatus {
			continue
		}
		byPort[int(tlv.Value[0])] = tlv
	}
	if len(byPort[1].Value) != 3 || byPort[1].Value[2] != 0x01 {
		t.Errorf("port 1 (FlowControl=true) PORT_STATUS byte 2 = %+v, want 0x01", byPort[1].Value)
	}
	if len(byPort[2].Value) != 3 || byPort[2].Value[2] != 0x00 {
		t.Errorf("port 2 (FlowControl=false) PORT_STATUS byte 2 = %+v, want 0x00", byPort[2].Value)
	}

	// Round-trip through the real parser too, proving the *bool decode
	// path (nsdp.ParsePortStatus / model.NsdpPortStatus.FlowControl) agrees
	// with the raw byte assertions above.
	dev := deviceFrom(t, tlvs)
	decoded := map[int]model.NsdpPortStatus{}
	for _, p := range dev.PortStatus {
		decoded[p.PortID] = p
	}
	if decoded[1].FlowControl == nil || !*decoded[1].FlowControl {
		t.Errorf("decoded port 1 FlowControl = %v, want non-nil true", decoded[1].FlowControl)
	}
	if decoded[2].FlowControl == nil || *decoded[2].FlowControl {
		t.Errorf("decoded port 2 FlowControl = %v, want non-nil false", decoded[2].FlowControl)
	}
}

func TestNsdpTlvsProjectsVlansAndPvidsAndMgmt(t *testing.T) {
	st := SeedGS110EMX()

	dev := deviceFrom(t, st.NsdpTlvs(map[nsdp.Tag]bool{
		nsdp.TagModel:       true,
		nsdp.TagPortCount:   true,
		nsdp.TagVLANMembers: true,
		nsdp.TagPortPVID:    true,
		nsdp.TagIPAddress:   true,
		nsdp.TagNetmask:     true,
		nsdp.TagGateway:     true,
		nsdp.TagDHCPMode:    true,
	}))

	var v90 *model.NsdpVlanMembership
	for i := range dev.VlanMembers {
		if dev.VlanMembers[i].VlanID == 90 {
			v90 = &dev.VlanMembers[i]
		}
	}
	if v90 == nil {
		t.Fatal("VLAN 90 not found among projected VLAN_MEMBERS")
	}
	if want := []int{1, 2, 10}; !slices.Equal(v90.MemberPorts, want) {
		t.Errorf("VLAN 90 MemberPorts = %v, want %v", v90.MemberPorts, want)
	}
	if want := []int{1, 2}; !slices.Equal(v90.UntaggedPorts(), want) {
		t.Errorf("VLAN 90 UntaggedPorts() = %v, want %v", v90.UntaggedPorts(), want)
	}

	if dev.IP == nil || *dev.IP != "10.1.5.25" {
		t.Errorf("IP = %v, want 10.1.5.25", dev.IP)
	}
	if dev.DhcpEnabled == nil || *dev.DhcpEnabled {
		t.Error("DhcpEnabled should be false (this seed's mgmt mode is static)")
	}

	found := false
	for _, p := range dev.PortPvids {
		if p.PortID == 1 && p.VlanID == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("PortPvids = %+v, want (port=1, vlan=1) among them", dev.PortPvids)
	}
}

func TestApplyNsdpWritePvidAndMembershipAndMgmt(t *testing.T) {
	st := SeedGS110EMX()

	// bytes([5]) + struct.pack(">H", 90)
	st.ApplyNsdpWrite(nsdp.TagPortPVID, []byte{5, 0x00, 0x5A})
	if st.Pvids[5] != 90 {
		t.Errorf("Pvids[5] = %d, want 90", st.Pvids[5])
	}

	// Move port 10 to untagged on VLAN 90 (members {1,2,10}, tagged {} ->
	// UntaggedPorts() == members, since nothing is in the tagged bitmap).
	tlv, err := nsdp.VlanMembersTLV(90, []int{1, 2, 10}, nil, 10)
	if err != nil {
		t.Fatalf("VlanMembersTLV: %v", err)
	}
	st.ApplyNsdpWrite(nsdp.TagVLANMembers, tlv.Value)
	want := map[int]bool{1: true, 2: true, 10: true}
	if !reflect.DeepEqual(st.Vlans[90].Untagged, want) {
		t.Errorf("Vlans[90].Untagged = %v, want %v", st.Vlans[90].Untagged, want)
	}
	if !reflect.DeepEqual(st.Vlans[90].Member, want) {
		t.Errorf("Vlans[90].Member = %v, want %v", st.Vlans[90].Member, want)
	}

	ipTLV, err := nsdp.IPv4TLV(nsdp.TagIPAddress, "10.9.9.9")
	if err != nil {
		t.Fatalf("IPv4TLV: %v", err)
	}
	st.ApplyNsdpWrite(nsdp.TagIPAddress, ipTLV.Value)
	if st.Mgmt.Address != "10.9.9.9" {
		t.Errorf("Mgmt.Address = %q, want 10.9.9.9", st.Mgmt.Address)
	}
}

// TestApplyNsdpWriteVlanMembersPreservesExistingName proves the
// name-preservation rule D-NSDP §7.1 calls out: rewriting an EXISTING
// VLAN's membership via NSDP must keep that VLAN's Name (never blank it),
// since the wire's VLAN_MEMBERS TLV carries no name field at all.
func TestApplyNsdpWriteVlanMembersPreservesExistingName(t *testing.T) {
	st := SeedGS305EP() // VLAN 1 here is named "default"
	if st.Vlans[1].Name != "default" {
		t.Fatalf("precondition: Vlans[1].Name = %q, want default", st.Vlans[1].Name)
	}

	tlv, err := nsdp.VlanMembersTLV(1, []int{1, 2}, nil, 5)
	if err != nil {
		t.Fatalf("VlanMembersTLV: %v", err)
	}
	st.ApplyNsdpWrite(nsdp.TagVLANMembers, tlv.Value)
	if st.Vlans[1].Name != "default" {
		t.Errorf("Vlans[1].Name = %q after write, want preserved default", st.Vlans[1].Name)
	}
}

// TestApplyNsdpWriteUnknownAndReadOnlyTagsAreNoOps pins the "REBOOT /
// FACTORY_RESET / unknown: deliberate no-op" rule: a write TLV for any of
// these tags must leave State entirely unchanged.
func TestApplyNsdpWriteUnknownAndReadOnlyTagsAreNoOps(t *testing.T) {
	st := SeedGS110EMX()
	before := st.Snapshot()

	st.ApplyNsdpWrite(nsdp.TagReboot, nil)
	st.ApplyNsdpWrite(nsdp.TagFactoryReset, nil)
	st.ApplyNsdpWrite(nsdp.Tag(0xBEEF), []byte{1, 2, 3}) // wholly unrecognized tag

	if !reflect.DeepEqual(st, before) {
		t.Error("REBOOT/FACTORY_RESET/unknown write mutated state, want a no-op")
	}
}

// TestApplyNsdpWriteTooShortValueIsANoOp pins this package's deliberate
// Go-safety divergence (docs/cross-language-divergences.md, "Slice 05",
// entry 4): a too-short value for a known tag must be a safe no-op, never
// a panic that would crash NsdpFace's background serve goroutine.
func TestApplyNsdpWriteTooShortValueIsANoOp(t *testing.T) {
	st := SeedGS110EMX()
	// Seeded Mode is already "static" (see SeedGS110EMX), which would make
	// an empty-DHCP_MODE-still-static assertion below pass even if the
	// no-op guard were missing entirely (it'd merely re-set the same
	// value). Force Mode to "dhcp" first so the assertion actually proves
	// ApplyNsdpWrite left Mode UNTOUCHED, not merely unchanged-by-coincidence.
	st.Mgmt.Mode = "dhcp"
	before := st.Snapshot()

	st.ApplyNsdpWrite(nsdp.TagPortPVID, []byte{5}) // needs 3 bytes, has 1
	st.ApplyNsdpWrite(nsdp.TagVLANMembers, []byte{0x00})
	st.ApplyNsdpWrite(nsdp.TagIPAddress, []byte{1, 2}) // needs 4 bytes
	st.ApplyNsdpWrite(nsdp.TagDHCPMode, nil)
	st.ApplyNsdpWrite(nsdp.TagDHCPMode, []byte{}) // empty-but-non-nil, same contract

	if !reflect.DeepEqual(st.Pvids, before.Pvids) {
		t.Error("too-short PORT_PVID value mutated Pvids, want a no-op")
	}
	if !reflect.DeepEqual(st.Vlans, before.Vlans) {
		t.Error("too-short VLAN_MEMBERS value mutated Vlans, want a no-op")
	}
	if st.Mgmt.Address != before.Mgmt.Address {
		t.Error("too-short IP_ADDRESS value mutated Mgmt.Address, want a no-op")
	}
	// An empty DHCP_MODE value must be a no-op like every other too-short
	// value for a known tag (docs/cross-language-divergences.md, "Slice
	// 05", entry 4): it must NOT fall through to the "static" branch.
	if st.Mgmt.Mode != "dhcp" {
		t.Errorf("Mgmt.Mode after empty DHCP_MODE value = %q, want dhcp (unchanged, a no-op)", st.Mgmt.Mode)
	}
}

// TestNsdpTlvsProjectsPortNames proves the fake serves PORT_NAME (0xB000) as
// one TLV per port ALWAYS -- the seeded description for port 8 ("rumpus") and a
// bare port-only TLV for every undescribed port (matching real GS110EMX row
// counts). The description is the SAME per-port field the HTTP/SNMP projections
// use (single source of truth).
func TestNsdpTlvsProjectsPortNames(t *testing.T) {
	st := SeedGS110EMX()
	tlvs := st.NsdpTlvs(map[nsdp.Tag]bool{nsdp.TagPortName: true})
	if len(tlvs) != len(st.Ports) {
		t.Fatalf("PORT_NAME TLV count = %d, want one per port (%d)", len(tlvs), len(st.Ports))
	}
	byPort := map[int][]byte{}
	for _, tlv := range tlvs {
		if tlv.Tag != nsdp.TagPortName {
			t.Fatalf("projected tag = %#x, want TagPortName", tlv.Tag)
		}
		byPort[int(tlv.Value[0])] = tlv.Value[1:]
	}
	if got := string(byPort[8]); got != "rumpus" {
		t.Errorf("port 8 PORT_NAME = %q, want rumpus", got)
	}
	for _, port := range []int{1, 2, 6, 9, 10} {
		if len(byPort[port]) != 0 {
			t.Errorf("port %d PORT_NAME = %q, want bare (undescribed)", port, byPort[port])
		}
	}
}

// TestApplyNsdpWriteVLANDestroyResetsPvids covers the VLAN_DESTROY (0x2C00)
// apply the virtual fake needs so a Go-lib DeleteVlan round-trips: the VLAN is
// removed AND every PVID that pointed at it drops back to VLAN 1 (a PVID may
// not name a VLAN that no longer exists).
func TestApplyNsdpWriteVLANDestroyResetsPvids(t *testing.T) {
	st := SeedGS110EMX()
	st.Pvids[3] = 90 // point a PVID at VLAN 90 so we can prove it resets
	if _, ok := st.Vlans[90]; !ok {
		t.Fatal("precondition: VLAN 90 must exist in the seed")
	}
	st.ApplyNsdpWrite(nsdp.TagVLANDestroy, []byte{0x00, 0x5A}) // vlan 90, 2-byte BE
	if _, ok := st.Vlans[90]; ok {
		t.Error("VLAN 90 still present after VLAN_DESTROY, want removed")
	}
	if st.Pvids[3] != 1 {
		t.Errorf("Pvids[3] = %d after destroying its VLAN, want reset to 1", st.Pvids[3])
	}
}

// TestApplyNsdpWriteVLANDestroyUnknownVlanIsNoOp: destroying a VLAN the switch
// does not have changes nothing (mirrors Python's `if pop(...) is not None`).
func TestApplyNsdpWriteVLANDestroyUnknownVlanIsNoOp(t *testing.T) {
	st := SeedGS110EMX()
	before := st.Snapshot()
	st.ApplyNsdpWrite(nsdp.TagVLANDestroy, []byte{0x0F, 0xA0}) // vlan 4000, absent
	if !reflect.DeepEqual(st, before) {
		t.Error("destroying a non-existent VLAN mutated state, want a no-op")
	}
}

// TestApplyNsdpWritePortName covers the PORT_NAME (0xB000) apply: a described
// write sets the port's Description; a bare port-only write clears it to nil.
func TestApplyNsdpWritePortName(t *testing.T) {
	st := SeedGS110EMX()
	st.ApplyNsdpWrite(nsdp.TagPortName, append([]byte{0x02}, []byte("uplink")...))
	if st.Ports[2].Description == nil || *st.Ports[2].Description != "uplink" {
		t.Errorf("port 2 Description = %v, want \"uplink\"", st.Ports[2].Description)
	}
	st.ApplyNsdpWrite(nsdp.TagPortName, []byte{0x02}) // bare -> clears
	if st.Ports[2].Description != nil {
		t.Errorf("port 2 Description = %v after bare write, want nil", st.Ports[2].Description)
	}
}
