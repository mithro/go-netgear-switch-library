package nsdp_test

// Ported field-for-field from tests/test_nsdp_write.py at pin 1aa1274 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274). Any discrepancy between this file and that pin is a
// bug in this file. Go has no separate sync/async split, so only the sync
// (NsdpWriter) side is ported.

import (
	"context"
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

// fakeNsdpWriteClient is a tiny stateful NSDP mock: applies writes so
// verify-after-write passes, mirroring Python's FakeNsdpWriteClient.
// apply=false makes writes a no-op (device ignores them) so the writer's
// verify step is forced to raise a *model.WriteVerificationError.
type fakeNsdpWriteClient struct {
	pvids map[int]int
	// vlans maps vlan ID -> (members, tagged) port sets.
	vlans map[int]*vlanSets
	mgmt  struct {
		ip, mask, gw string
		dhcp         bool
	}
	writes [][]nsdp.Tag
	apply  bool
}

type vlanSets struct {
	members map[int]bool
	tagged  map[int]bool
}

func newFakeNsdpWriteClient(apply bool) *fakeNsdpWriteClient {
	c := &fakeNsdpWriteClient{
		pvids: map[int]int{1: 1, 2: 1},
		vlans: map[int]*vlanSets{
			90: {members: map[int]bool{1: true, 2: true}, tagged: map[int]bool{}},
		},
		apply: apply,
	}
	c.mgmt.ip = "10.1.5.20"
	c.mgmt.mask = "255.255.255.0"
	c.mgmt.gw = "10.1.5.1"
	c.mgmt.dhcp = false
	return c
}

func (c *fakeNsdpWriteClient) Read(_ context.Context, _ []nsdp.Tag) (*nsdp.Packet, error) {
	pkt := &nsdp.Packet{Op: nsdp.OpReadResponse, ClientMAC: make([]byte, 6), ServerMAC: bytesOf(0xaa, 6)}
	pkt.AddTLV(nsdp.TagModel, []byte("GS110EMX"))
	pkt.AddTLV(nsdp.TagPortCount, []byte{0x0a})
	for port, vlan := range c.pvids {
		pkt.AddTLV(nsdp.TagPortPVID, []byte{byte(port), byte(vlan >> 8), byte(vlan)})
	}
	for vlan, sets := range c.vlans {
		member := setToBitmap(sets.members, 2)
		tagged := setToBitmap(sets.tagged, 2)
		value := []byte{byte(vlan >> 8), byte(vlan)}
		value = append(value, member...)
		value = append(value, tagged...)
		pkt.AddTLV(nsdp.TagVLANMembers, value)
	}
	ip := parseDottedQuad(c.mgmt.ip)
	pkt.AddTLV(nsdp.TagIPAddress, ip)
	pkt.AddTLV(nsdp.TagNetmask, parseDottedQuad(c.mgmt.mask))
	pkt.AddTLV(nsdp.TagGateway, parseDottedQuad(c.mgmt.gw))
	dhcpByte := byte(0x00)
	if c.mgmt.dhcp {
		dhcpByte = 0x01
	}
	pkt.AddTLV(nsdp.TagDHCPMode, []byte{dhcpByte})
	return pkt, nil
}

func (c *fakeNsdpWriteClient) Write(_ context.Context, tlvs []nsdp.TLVEntry, _ string) (*nsdp.Packet, error) {
	tags := make([]nsdp.Tag, len(tlvs))
	for i, t := range tlvs {
		tags[i] = t.Tag
	}
	c.writes = append(c.writes, tags)
	if c.apply {
		for _, t := range tlvs {
			c.applyTLV(t)
		}
	}
	return &nsdp.Packet{Op: nsdp.OpWriteResponse, ClientMAC: make([]byte, 6), Result: nsdp.ResultSuccess}, nil
}

func (c *fakeNsdpWriteClient) applyTLV(t nsdp.TLVEntry) {
	switch t.Tag {
	case nsdp.TagPortPVID:
		port := int(t.Value[0])
		vlan := int(t.Value[1])<<8 | int(t.Value[2])
		c.pvids[port] = vlan
	case nsdp.TagVLANMembers:
		m, err := nsdp.ParseVlanMembers(t.Value, 10)
		if err != nil {
			return
		}
		c.vlans[m.VlanID] = &vlanSets{members: toSet(m.MemberPorts), tagged: toSet(m.TaggedPorts)}
	case nsdp.TagVLANDestroy:
		vlan := int(t.Value[0])<<8 | int(t.Value[1])
		delete(c.vlans, vlan)
	case nsdp.TagIPAddress:
		c.mgmt.ip = formatDottedQuad(t.Value)
	case nsdp.TagNetmask:
		c.mgmt.mask = formatDottedQuad(t.Value)
	case nsdp.TagGateway:
		c.mgmt.gw = formatDottedQuad(t.Value)
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func setToBitmap(set map[int]bool, width int) []byte {
	out := make([]byte, width)
	for p := range set {
		idx := (p - 1) / 8
		bit := (p - 1) % 8
		for idx >= len(out) {
			out = append(out, 0)
		}
		out[idx] |= 0x80 >> uint(bit)
	}
	return out
}

func toSet(ports []int) map[int]bool {
	out := make(map[int]bool, len(ports))
	for _, p := range ports {
		out[p] = true
	}
	return out
}

func parseDottedQuad(s string) []byte {
	out := make([]byte, 4)
	var octet, idx int
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out[idx] = byte(octet)
			idx++
			octet = 0
			continue
		}
		octet = octet*10 + int(s[i]-'0')
	}
	return out
}

func formatDottedQuad(b []byte) string {
	return itoa(int(b[0])) + "." + itoa(int(b[1])) + "." + itoa(int(b[2])) + "." + itoa(int(b[3]))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func newTestWriter(t *testing.T, client *fakeNsdpWriteClient, opts ...nsdp.WriterOption) *nsdp.Writer {
	t.Helper()
	w, err := nsdp.NewWriter(client, gs110emx(t), "admin", opts...)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	return w
}

// --- test_set_pvid_writes_and_verifies ---

func TestWriter_SetPVIDWritesAndVerifies(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)
	if err := w.SetPVID(context.Background(), 1, 90, false); err != nil {
		t.Fatalf("SetPVID: %v", err)
	}
	if client.pvids[1] != 90 {
		t.Errorf("pvids[1] = %d, want 90", client.pvids[1])
	}
	if len(client.writes) != 1 || len(client.writes[0]) != 1 || client.writes[0][0] != nsdp.TagPortPVID {
		t.Errorf("writes = %v, want one write with [TagPortPVID]", client.writes)
	}
}

// --- test_set_pvid_verification_failure_raises ---

func TestWriter_SetPVIDVerificationFailureRaises(t *testing.T) {
	client := newFakeNsdpWriteClient(false) // device ignores the write
	w := newTestWriter(t, client)
	err := w.SetPVID(context.Background(), 1, 90, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPVID error = %v, want *model.WriteVerificationError", err)
	}
}

// TestWriter_SetPVIDMissingVlanIsPreconditionNotVerifyError pins the GAP-1
// fix (parity with Python commit 98fb935): a PVID pointing at a VLAN the
// switch does not have must be refused BEFORE any write is attempted, as a
// precondition failure (errNSDP-wrapped model.ErrNSDP), never a
// *model.WriteVerificationError. newFakeNsdpWriteClient only ever
// registers VLAN 90 (see its vlans map above), so VLAN 999 is absent by
// construction.
func TestWriter_SetPVIDMissingVlanIsPreconditionNotVerifyError(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)
	err := w.SetPVID(context.Background(), 1, 999, false)
	if !errors.Is(err, model.ErrNSDP) {
		t.Fatalf("SetPVID error = %v, want to wrap model.ErrNSDP", err)
	}
	var verr *model.WriteVerificationError
	if errors.As(err, &verr) {
		t.Errorf("SetPVID error is a *model.WriteVerificationError, want a precondition ErrNSDP instead")
	}
	if len(client.writes) != 0 {
		t.Errorf("writes = %v, want none (precondition failed before any write)", client.writes)
	}
}

// --- test_set_vlan_membership_rmw_tagged ---

func TestWriter_SetVlanMembershipRMWTagged(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)
	if err := w.SetVlanMembership(context.Background(), 90, 10, model.VlanTagged, false); err != nil {
		t.Fatalf("SetVlanMembership: %v", err)
	}
	sets := client.vlans[90]
	if !sets.members[10] {
		t.Errorf("port 10 not in members: %v", sets.members)
	}
	if !sets.tagged[10] {
		t.Errorf("port 10 not in tagged: %v", sets.tagged)
	}
	if !sets.members[1] || !sets.members[2] {
		t.Errorf("existing members not preserved (read-modify-write): %v", sets.members)
	}
}

// --- test_set_vlan_membership_excluded_removes_port ---

func TestWriter_SetVlanMembershipExcludedRemovesPort(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)
	if err := w.SetVlanMembership(context.Background(), 90, 1, model.VlanExcluded, false); err != nil {
		t.Fatalf("SetVlanMembership: %v", err)
	}
	sets := client.vlans[90]
	if sets.members[1] {
		t.Errorf("port 1 still in members: %v", sets.members)
	}
	if !sets.members[2] {
		t.Errorf("port 2 removed from members, want preserved: %v", sets.members)
	}
}

// --- test_protected_port_blocks_pvid_without_force ---

func TestWriter_ProtectedPortBlocksPvidWithoutForce(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client, nsdp.WithProtectedPorts(1))

	err := w.SetPVID(context.Background(), 1, 90, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetPVID error = %v, want to wrap model.ErrProtectedPort", err)
	}
	if len(client.writes) != 0 {
		t.Errorf("writes = %v, want none sent", client.writes)
	}

	if err := w.SetPVID(context.Background(), 1, 90, true); err != nil { // force bypasses
		t.Fatalf("SetPVID with force: %v", err)
	}
	if client.pvids[1] != 90 {
		t.Errorf("pvids[1] = %d, want 90", client.pvids[1])
	}
}

// --- test_set_mgmt_ip_requires_force_and_verifies_all_three ---

func TestWriter_SetMgmtIPRequiresForceAndVerifiesAllThree(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)

	err := w.SetMgmtIP(context.Background(), "10.9.9.9", "255.255.255.0", "10.9.9.1", false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetMgmtIP without force error = %v, want to wrap model.ErrProtectedPort", err)
	}

	if err := w.SetMgmtIP(context.Background(), "10.9.9.9", "255.255.255.0", "10.9.9.1", true); err != nil {
		t.Fatalf("SetMgmtIP with force: %v", err)
	}
	if client.mgmt.ip != "10.9.9.9" {
		t.Errorf("mgmt.ip = %q, want 10.9.9.9", client.mgmt.ip)
	}
	if client.mgmt.gw != "10.9.9.1" {
		t.Errorf("mgmt.gw = %q, want 10.9.9.1", client.mgmt.gw)
	}
}

// --- test_unsupported_writes_raise ---

func TestWriter_UnsupportedWritesRaise(t *testing.T) {
	ctx := context.Background()

	t.Run("SetPoE", func(t *testing.T) {
		w := newTestWriter(t, newFakeNsdpWriteClient(true))
		requireUnsupported(t, w.SetPoE(ctx, 1, true, false))
	})
	t.Run("SetPortEnabled", func(t *testing.T) {
		w := newTestWriter(t, newFakeNsdpWriteClient(true))
		requireUnsupported(t, w.SetPortEnabled(ctx, 1, false, false))
	})
}

// --- VLAN create/delete over NSDP (ported from test_nsdp_write.py's
// test_create_vlan_* / test_delete_vlan_*) ---

// wroteTags reports whether the fake recorded a single-TLV write whose one
// tag equals want -- the Go analogue of Python's `[Tag.X] in client.writes`.
func wroteTags(writes [][]nsdp.Tag, want nsdp.Tag) bool {
	for _, w := range writes {
		if len(w) == 1 && w[0] == want {
			return true
		}
	}
	return false
}

// TestWriter_CreateVlanWritesEmptyMembership: create = write VLAN_MEMBERS for
// an id the switch does not list yet (there is no separate "add VLAN" action).
func TestWriter_CreateVlanWritesEmptyMembership(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)
	if err := w.CreateVlan(context.Background(), 4013, "throwaway"); err != nil {
		t.Fatalf("CreateVlan: %v", err)
	}
	sets, ok := client.vlans[4013]
	if !ok {
		t.Fatalf("VLAN 4013 not created; vlans = %v", client.vlans)
	}
	if len(sets.members) != 0 || len(sets.tagged) != 0 {
		t.Errorf("VLAN 4013 created with members=%v tagged=%v, want both empty", sets.members, sets.tagged)
	}
	if !wroteTags(client.writes, nsdp.TagVLANMembers) {
		t.Errorf("writes = %v, want one [TagVLANMembers] write", client.writes)
	}
}

// TestWriter_CreateVlanIdempotent: an id already listed is a no-op return --
// no write at all, and the existing VLAN's members are untouched.
func TestWriter_CreateVlanIdempotent(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)
	if err := w.CreateVlan(context.Background(), 90, "already-there"); err != nil {
		t.Fatalf("CreateVlan(existing): %v", err)
	}
	if len(client.writes) != 0 {
		t.Errorf("writes = %v, want none (VLAN 90 already listed)", client.writes)
	}
	sets := client.vlans[90]
	if !sets.members[1] || !sets.members[2] || len(sets.members) != 2 {
		t.Errorf("VLAN 90 members = %v, want {1,2} untouched", sets.members)
	}
}

// TestWriter_CreateVlanVerificationFailure: a device that ignores the write
// (apply=false) fails the read-back verify with *model.WriteVerificationError.
func TestWriter_CreateVlanVerificationFailure(t *testing.T) {
	w := newTestWriter(t, newFakeNsdpWriteClient(false))
	err := w.CreateVlan(context.Background(), 4013, "throwaway")
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("CreateVlan error = %v, want *model.WriteVerificationError", err)
	}
}

// TestWriter_DeleteVlanUsesDestroyTagAndNeedsForce: force-gated (wraps
// model.ErrProtectedPort, no write) then, with force, writes VLAN_DESTROY and
// the VLAN is gone.
func TestWriter_DeleteVlanUsesDestroyTagAndNeedsForce(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)
	ctx := context.Background()

	err := w.DeleteVlan(ctx, 90, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("DeleteVlan without force error = %v, want to wrap model.ErrProtectedPort", err)
	}
	if len(client.writes) != 0 {
		t.Errorf("writes = %v, want none before force", client.writes)
	}

	if err := w.DeleteVlan(ctx, 90, true); err != nil {
		t.Fatalf("DeleteVlan(force): %v", err)
	}
	if _, ok := client.vlans[90]; ok {
		t.Errorf("VLAN 90 still present after delete; vlans = %v", client.vlans)
	}
	if !wroteTags(client.writes, nsdp.TagVLANDestroy) {
		t.Errorf("writes = %v, want a [TagVLANDestroy] write", client.writes)
	}
}

// TestWriter_DeleteVlanVerificationFailure: a device that ignores the destroy
// (apply=false) fails the read-back verify with *model.WriteVerificationError.
func TestWriter_DeleteVlanVerificationFailure(t *testing.T) {
	w := newTestWriter(t, newFakeNsdpWriteClient(false))
	err := w.DeleteVlan(context.Background(), 90, true)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("DeleteVlan error = %v, want *model.WriteVerificationError", err)
	}
}

// --- test_reader_rejects_non_nsdp_model (writer side) ---

func TestWriter_RejectsNonNsdpModel(t *testing.T) {
	m, err := model.GetModel("gsm7252ps") // SNMP-only
	if err != nil {
		t.Fatalf("GetModel(gsm7252ps): %v", err)
	}
	_, err = nsdp.NewWriter(newFakeNsdpWriteClient(true), m, "admin")
	requireUnsupported(t, err)
}

// The following have no direct Python analogue -- Python's test suite never
// exercises a raw transport failure or a not-yet-seen PVID at this layer,
// but Go coverage wants every branch, and these also pin behavior this
// port's Go-specific helpers (pvidLookup, membershipOK, mgmtIPMatches)
// depend on.

// TestWriter_ClientErrorPropagates covers every write method's
// before-read/write/after-read error-propagation branch.
func TestWriter_ClientErrorPropagates(t *testing.T) {
	client := erroringNsdpClient{err: errSentinel}
	w := newTestWriterWithClient(t, client)
	ctx := context.Background()

	if err := w.SetPVID(ctx, 1, 90, false); !errors.Is(err, errSentinel) {
		t.Errorf("SetPVID error = %v, want to wrap errSentinel", err)
	}
	if err := w.SetVlanMembership(ctx, 90, 10, model.VlanTagged, false); !errors.Is(err, errSentinel) {
		t.Errorf("SetVlanMembership error = %v, want to wrap errSentinel", err)
	}
	if err := w.SetMgmtIP(ctx, "10.9.9.9", "255.255.255.0", "10.9.9.1", true); !errors.Is(err, errSentinel) {
		t.Errorf("SetMgmtIP error = %v, want to wrap errSentinel", err)
	}
}

func newTestWriterWithClient(t *testing.T, client nsdp.WriteClient) *nsdp.Writer {
	t.Helper()
	w, err := nsdp.NewWriter(client, gs110emx(t), "admin")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	return w
}

// TestWriter_SetPVIDBeforeValueNilForUnseenPort covers pvidLookup's
// not-found branch: a port absent from the pvid table both before and
// after the (ignored) write reports Before/After as nil, not a fabricated
// zero value.
func TestWriter_SetPVIDBeforeValueNilForUnseenPort(t *testing.T) {
	client := newFakeNsdpWriteClient(false) // device ignores the write
	w := newTestWriter(t, client)
	err := w.SetPVID(context.Background(), 3, 90, false) // port 3 not in {1,2}
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPVID error = %v, want *model.WriteVerificationError", err)
	}
	if verr.Before != nil {
		t.Errorf("Before = %v, want nil", verr.Before)
	}
	if verr.After != nil {
		t.Errorf("After = %v, want nil", verr.After)
	}
}

// TestWriter_SetVlanMembershipGuardBlocksWithoutForce covers
// SetVlanMembership's own guard error-passthrough branch (guard() itself
// is already exercised by the PVID tests).
func TestWriter_SetVlanMembershipGuardBlocksWithoutForce(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client, nsdp.WithProtectedPorts(10))
	err := w.SetVlanMembership(context.Background(), 90, 10, model.VlanTagged, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetVlanMembership error = %v, want to wrap model.ErrProtectedPort", err)
	}
	if len(client.writes) != 0 {
		t.Errorf("writes = %v, want none sent", client.writes)
	}
}

// TestWriter_SetVlanMembershipVerificationFailureRaises covers the
// membershipOK-false branch: the device ignores the write, so the port's
// membership never actually changes.
func TestWriter_SetVlanMembershipVerificationFailureRaises(t *testing.T) {
	client := newFakeNsdpWriteClient(false) // device ignores the write
	w := newTestWriter(t, client)
	err := w.SetVlanMembership(context.Background(), 90, 10, model.VlanTagged, false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetVlanMembership error = %v, want *model.WriteVerificationError", err)
	}
}

// TestWriter_SetVlanMembershipExcludedOnMissingVlanIsOK covers
// membershipOK's after==nil special case: excluding a port from a VLAN
// that doesn't exist (and never gets created, since the device ignores the
// write) is trivially satisfied.
func TestWriter_SetVlanMembershipExcludedOnMissingVlanIsOK(t *testing.T) {
	client := newFakeNsdpWriteClient(false) // device ignores the write; VLAN 200 never created
	w := newTestWriter(t, client)
	if err := w.SetVlanMembership(context.Background(), 200, 1, model.VlanExcluded, false); err != nil {
		t.Fatalf("SetVlanMembership: %v", err)
	}
}

// TestWriter_SetVlanMembershipRejectsOutOfRangeVlan covers
// VlanMembersTLV's error-propagation branch.
func TestWriter_SetVlanMembershipRejectsOutOfRangeVlan(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)
	err := w.SetVlanMembership(context.Background(), 70000, 1, model.VlanTagged, false)
	if !errors.Is(err, model.ErrNSDP) {
		t.Fatalf("SetVlanMembership error = %v, want to wrap model.ErrNSDP", err)
	}
	if len(client.writes) != 0 {
		t.Errorf("writes = %v, want none sent (TLV build failed before any write)", client.writes)
	}
}

// TestWriter_SetMgmtIPRejectsInvalidAddress covers IPv4TLV's
// error-propagation branch.
func TestWriter_SetMgmtIPRejectsInvalidAddress(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)
	err := w.SetMgmtIP(context.Background(), "not-an-ip", "255.255.255.0", "10.9.9.1", true)
	if !errors.Is(err, model.ErrNSDP) {
		t.Fatalf("SetMgmtIP error = %v, want to wrap model.ErrNSDP", err)
	}
}

// TestWriter_SetMgmtIPVerificationFailureRaises covers mgmtIPMatches'
// false branch: the device ignores the write, so nothing reads back as
// requested.
func TestWriter_SetMgmtIPVerificationFailureRaises(t *testing.T) {
	client := newFakeNsdpWriteClient(false) // device ignores the write
	w := newTestWriter(t, client)
	err := w.SetMgmtIP(context.Background(), "10.9.9.9", "255.255.255.0", "10.9.9.1", true)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetMgmtIP error = %v, want *model.WriteVerificationError", err)
	}
}

// readOKWriteErrClient reads normally (delegating to inner) but always
// fails Write with errSentinel -- covers each write method's own
// client.Write error-propagation branch specifically (distinct from
// TestWriter_ClientErrorPropagates, which fails at the earlier before-read
// stage and so never reaches the Write call at all).
type readOKWriteErrClient struct{ inner *fakeNsdpWriteClient }

func (c readOKWriteErrClient) Read(ctx context.Context, tags []nsdp.Tag) (*nsdp.Packet, error) {
	return c.inner.Read(ctx, tags)
}

func (c readOKWriteErrClient) Write(context.Context, []nsdp.TLVEntry, string) (*nsdp.Packet, error) {
	return nil, errSentinel
}

func TestWriter_WriteCallErrorPropagates(t *testing.T) {
	client := readOKWriteErrClient{inner: newFakeNsdpWriteClient(true)}
	w := newTestWriterWithClient(t, client)
	ctx := context.Background()

	if err := w.SetPVID(ctx, 1, 90, false); !errors.Is(err, errSentinel) {
		t.Errorf("SetPVID error = %v, want to wrap errSentinel", err)
	}
	if err := w.SetVlanMembership(ctx, 90, 10, model.VlanTagged, false); !errors.Is(err, errSentinel) {
		t.Errorf("SetVlanMembership error = %v, want to wrap errSentinel", err)
	}
	if err := w.SetMgmtIP(ctx, "10.9.9.9", "255.255.255.0", "10.9.9.1", true); !errors.Is(err, errSentinel) {
		t.Errorf("SetMgmtIP error = %v, want to wrap errSentinel", err)
	}
}

// TestWriter_SetPVIDRejectsOutOfRangePort covers PvidTLV's
// error-propagation branch inside SetPVID.
func TestWriter_SetPVIDRejectsOutOfRangePort(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)
	err := w.SetPVID(context.Background(), 256, 90, false)
	if !errors.Is(err, model.ErrNSDP) {
		t.Fatalf("SetPVID error = %v, want to wrap model.ErrNSDP", err)
	}
	if len(client.writes) != 0 {
		t.Errorf("writes = %v, want none sent (TLV build failed before any write)", client.writes)
	}
}

// TestWriter_SetVlanMembershipRMWUntagged covers membersAfter's
// VlanUntagged branch (adds to members, removes from tagged) -- distinct
// from the VlanTagged/VlanExcluded branches already covered above.
func TestWriter_SetVlanMembershipRMWUntagged(t *testing.T) {
	client := newFakeNsdpWriteClient(true)
	w := newTestWriter(t, client)
	if err := w.SetVlanMembership(context.Background(), 90, 10, model.VlanUntagged, false); err != nil {
		t.Fatalf("SetVlanMembership: %v", err)
	}
	sets := client.vlans[90]
	if !sets.members[10] {
		t.Errorf("port 10 not in members: %v", sets.members)
	}
	if sets.tagged[10] {
		t.Errorf("port 10 in tagged, want untagged: %v", sets.tagged)
	}
}

func TestExportedNoPortAdminMsg(t *testing.T) {
	if nsdp.NoPortAdminMsg == "" {
		t.Error("NoPortAdminMsg is empty")
	}
}
