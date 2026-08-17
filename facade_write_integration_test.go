// facade_write_integration_test.go: the slice-04 write capstone -- every
// facade write method (switch_write.go) driven end-to-end against a REAL
// virtual.VirtualSwitch over real UDP, proving the whole write seam
// (write_dispatch.go's writeVia, backend_snmp_write.go's buildSNMPWriter/
// buildSNMPWriteClient, snmp.Writer's SET+verify methods, and the virtual
// fake's coherent ApplyWrite) is wired together correctly -- never a
// vacuous pass. Per Task 6's brief and D-WR (docs/superpowers/plans/
// 2026-07-30-slice-04-dossier-snmp-write.md) §4-5, mirroring the Python
// reference's tests/virtual/test_snmp_write_face.py (writer-level "live"
// tests) and tests/test_write_equivalence.py (single-facade snapshot
// assertions, per D-FAC §4.2's already-noted Go-port equivalent: Go has no
// sync/async split to compare across).
//
// package netgearswitch_test (external), same package as
// facade_integration_test.go -- this file reuses that file's
// startVirtualSwitch/derefStr/derefInt/containsInt/facadeTestTimeout
// helpers directly rather than redefining them, and adds only the
// write-specific helpers this file needs (writableFacadeFor and small
// GetVLANs/GetPoE/GetPorts single-row lookups).
package netgearswitch_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// writableFacadeFor constructs a *netgearswitch.Switch bound to modelKey,
// talking to vsw's live SNMP face, with BOTH the read community (via
// WithSNMPCommunity) and the write community (via
// WithSNMPWriteCommunityResolver) configured to "public" -- the virtual
// fake's single SNMP community string serves both reads and writes (see
// virtual/server.go's WithCommunity option, which defaults to "public" and
// is never overridden by startVirtualSwitch), unlike facade_integration_
// test.go's read-only facadeFor, which never configures a write-community
// resolver at all (D-WR §3.4: the write-community gate is a SEPARATE,
// stricter check than the read-side one, and is resolved lazily on first
// write -- exercising that resolution path for real is part of what this
// capstone proves). Additional opts are appended after the two community
// options, so a caller can layer e.g. WithProtectedPorts on top.
func writableFacadeFor(t *testing.T, vsw *virtual.VirtualSwitch, modelKey string, opts ...netgearswitch.SwitchOption) *netgearswitch.Switch {
	t.Helper()
	m, err := netgearswitch.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q) error = %v", modelKey, err)
	}
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	base := []netgearswitch.SwitchOption{
		netgearswitch.WithSNMPCommunity("public"),
		netgearswitch.WithSNMPWriteCommunityResolver(func() (*string, error) {
			c := "public"
			return &c, nil
		}),
	}
	sw, err := netgearswitch.New(m, host, append(base, opts...)...)
	if err != nil {
		t.Fatalf("New(%q) error = %v", modelKey, err)
	}
	return sw
}

// getVlan returns vlanID's VLANInfo from a live sw.GetVLANs() dispatch,
// failing the test if it is absent.
func getVlan(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, vlanID int) netgearswitch.VLANInfo {
	t.Helper()
	vlans, err := sw.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	for _, v := range vlans {
		if v.VlanID == vlanID {
			return v
		}
	}
	t.Fatalf("no vlan %d in GetVLANs() result (vlans = %v)", vlanID, vlans)
	return netgearswitch.VLANInfo{}
}

// getPoE returns port's PoEStatus from a live sw.GetPoE() dispatch, failing
// the test if it is absent.
func getPoE(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, port int) netgearswitch.PoEStatus {
	t.Helper()
	statuses, err := sw.GetPoE(ctx)
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	for _, s := range statuses {
		if s.Port == port {
			return s
		}
	}
	t.Fatalf("no PoE port %d in GetPoE() result", port)
	return netgearswitch.PoEStatus{}
}

// getPort returns port's PortStatus from a live sw.GetPorts() dispatch,
// failing the test if it is absent.
func getPort(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, port int) netgearswitch.PortStatus {
	t.Helper()
	ports, err := sw.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	for _, p := range ports {
		if p.Port == port {
			return p
		}
	}
	t.Fatalf("no port %d in GetPorts() result", port)
	return netgearswitch.PortStatus{}
}

// withoutPort returns a sorted copy of ports with port removed (a no-op if
// port was absent).
func withoutPort(ports []int, port int) []int {
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p != port {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// withPort returns a sorted copy of ports with port added (removing any
// existing occurrence first, so the result never has a duplicate).
func withPort(ports []int, port int) []int {
	out := append(withoutPort(ports, port), port)
	slices.Sort(out)
	return out
}

// TestFacadeWriteIntegration_SetPVIDVisibleInGetPVIDs proves SetPVID's
// write+verify round trip end-to-end: SnmpWriter.SetPVID (D-WR §2.9)
// refuses up front unless vlan already exists (GAP-1 fix, parity with
// Python commit 98fb935 -- vlan=41 is one of gsm7252ps's seeded VLANs, see
// virtual.SeedGSM7252PS), then issues a single Gauge32 SET at
// dot1qPvid.<port> and re-reads the FULL PVID list to verify -- this test
// checks the facade surfaces that exact (port, vlan) pair afterward via its
// own independent GetPVIDs() call.
func TestFacadeWriteIntegration_SetPVIDVisibleInGetPVIDs(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := writableFacadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	const port, vlan = 6, 41

	if err := sw.SetPVID(ctx, port, vlan, netgearswitch.Write{}); err != nil {
		t.Fatalf("SetPVID() error = %v", err)
	}

	pvids, err := sw.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	found := false
	for _, p := range pvids {
		if p.Port == port && p.Vlan == vlan {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetPVIDs() = %v, want (port=%d, vlan=%d) present after SetPVID", pvids, port, vlan)
	}
}

// TestFacadeWriteIntegration_SetVlanMembershipRoundTripPreservesOtherPorts
// drives SetVlanMembership through all three VlanMode values against the
// real vlan 90 ("iot") on a live VirtualSwitch, proving the read-modify-
// write (D-WR §2.10) preserves every OTHER port's membership exactly: the
// baseline ("every port except testPort") is computed from a live read
// BEFORE any write (never hardcoded from the seed literal, so this test
// stays correct even if the seed data changes), and every subsequent
// GetVLANs() read is checked against that baseline plus/minus testPort per
// the mode's truth table (D-WR §1.4): untagged (member+untagged),
// tagged (member, not untagged), excluded (neither).
func TestFacadeWriteIntegration_SetVlanMembershipRoundTripPreservesOtherPorts(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := writableFacadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	const vlanID = 90
	const testPort = 6

	initial := getVlan(ctx, t, sw, vlanID)
	baseMembers := withoutPort(initial.MemberPorts, testPort)
	baseUntagged := withoutPort(initial.UntaggedPorts, testPort)

	cases := []struct {
		name         string
		mode         netgearswitch.VlanMode
		wantMembers  []int
		wantUntagged []int
	}{
		{"untagged", netgearswitch.VlanUntagged, withPort(baseMembers, testPort), withPort(baseUntagged, testPort)},
		{"tagged", netgearswitch.VlanTagged, withPort(baseMembers, testPort), baseUntagged},
		{"excluded", netgearswitch.VlanExcluded, baseMembers, baseUntagged},
	}

	for _, tc := range cases {
		if err := sw.SetVlanMembership(ctx, vlanID, testPort, tc.mode, netgearswitch.Write{}); err != nil {
			t.Fatalf("SetVlanMembership(vlan=%d, port=%d, mode=%s) error = %v", vlanID, testPort, tc.name, err)
		}
		got := getVlan(ctx, t, sw, vlanID)
		if !slices.Equal(got.MemberPorts, tc.wantMembers) {
			t.Errorf("%s: MemberPorts = %v, want %v (every other port's membership must be preserved)", tc.name, got.MemberPorts, tc.wantMembers)
		}
		if !slices.Equal(got.UntaggedPorts, tc.wantUntagged) {
			t.Errorf("%s: UntaggedPorts = %v, want %v (every other port's membership must be preserved)", tc.name, got.UntaggedPorts, tc.wantUntagged)
		}
	}
}

// TestFacadeWriteIntegration_CreateVlanThenDeleteVlan proves CreateVlan
// (D-WR §2.11: RowStatus createAndGo + Name, never guarded) and DeleteVlan
// (D-WR §2.12: RowStatus destroy, verifies absence) round-trip against a
// live VirtualSwitch: vlan 3999 does not exist in any model's seed data, so
// its appearance and later disappearance are unambiguous, non-vacuous
// proof that both writes actually reached the fake.
func TestFacadeWriteIntegration_CreateVlanThenDeleteVlan(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := writableFacadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	const vlanID = 3999
	const name = "gotest"

	if err := sw.CreateVlan(ctx, vlanID, name, netgearswitch.Write{}); err != nil {
		t.Fatalf("CreateVlan() error = %v", err)
	}

	created := getVlan(ctx, t, sw, vlanID)
	if created.Name == nil || *created.Name != name {
		t.Errorf("created vlan %d Name = %s, want %q", vlanID, derefStr(created.Name), name)
	}

	if err := sw.DeleteVlan(ctx, vlanID, netgearswitch.Write{}); err != nil {
		t.Fatalf("DeleteVlan() error = %v", err)
	}

	vlans, err := sw.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	for _, v := range vlans {
		if v.VlanID == vlanID {
			t.Fatalf("vlan %d still present after DeleteVlan(): %+v, want it gone", vlanID, v)
		}
	}
}

// TestFacadeWriteIntegration_SetPoEOffThenOnCoherence proves SetPoE's
// write+verify round trip (D-WR §2.5) against the virtual fake's coherence
// rule (D-VIRT, restated at D-WR §4.1): admin-off synchronously forces
// detect to unused/disabled AND the port's link down; admin-on synchronously
// restores detect to delivering. Port 1 on gsm7252ps starts PoE-delivering
// (pinned by facade_integration_test.go's capstone), so this exercises a
// genuine off->on transition, not a no-op toggle.
func TestFacadeWriteIntegration_SetPoEOffThenOnCoherence(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := writableFacadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	const port = 1

	if err := sw.SetPoE(ctx, port, false, netgearswitch.Write{}); err != nil {
		t.Fatalf("SetPoE(off) error = %v", err)
	}
	poeOff := getPoE(ctx, t, sw, port)
	if poeOff.AdminEnabled {
		t.Error("after SetPoE(off): AdminEnabled = true, want false")
	}
	if poeOff.Delivering() {
		t.Errorf("after SetPoE(off): Detect = %v, want NOT delivering (coherence: admin-off -> unused/disabled)", poeOff.Detect)
	}
	portOff := getPort(ctx, t, sw, port)
	if portOff.LinkUp {
		t.Errorf("after SetPoE(off): port %d LinkUp = true, want false (coherence: admin-off forces link down)", port)
	}

	if err := sw.SetPoE(ctx, port, true, netgearswitch.Write{}); err != nil {
		t.Fatalf("SetPoE(on) error = %v", err)
	}
	poeOn := getPoE(ctx, t, sw, port)
	if !poeOn.AdminEnabled {
		t.Error("after SetPoE(on): AdminEnabled = false, want true")
	}
	if !poeOn.Delivering() {
		t.Errorf("after SetPoE(on): Detect = %v, want Delivering (coherence: admin-on -> delivering)", poeOn.Detect)
	}
}

// TestFacadeWriteIntegration_CyclePoEShortTimeoutsCompletesAgainstCoherentFake
// proves CyclePoE's off->on re-arm (D-WR §2.6-§2.7) terminates fast against
// the virtual fake even with SHORT injected timeouts: the fake's ApplyWrite
// coherence transitions synchronously in the same round trip as each SET
// (D-WR §4.4), so both poll loops' FIRST check (before ever sleeping)
// already observes the post-SET state -- this test asserts the whole
// operation completes well under one second, proving no real poll-interval
// sleep was ever needed, not just that it eventually succeeds.
func TestFacadeWriteIntegration_CyclePoEShortTimeoutsCompletesAgainstCoherentFake(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := writableFacadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	const port = 3
	timeouts := netgearswitch.PoeCycleTimeouts{Off: 2 * time.Second, On: 2 * time.Second, Poll: 10 * time.Millisecond}

	start := time.Now()
	err := sw.CyclePoE(ctx, port, netgearswitch.Write{}, netgearswitch.WithCycleTimeouts(timeouts))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("CyclePoE() error = %v", err)
	}
	if elapsed > time.Second {
		t.Errorf("CyclePoE() took %s, want well under the 2s/2s timeouts (the coherent fake transitions synchronously, so both poll phases should succeed on their first check with no real sleeps)", elapsed)
	}

	poe := getPoE(ctx, t, sw, port)
	if !poe.AdminEnabled {
		t.Error("after CyclePoE: AdminEnabled = false, want true")
	}
	if !poe.Delivering() {
		t.Errorf("after CyclePoE: Detect = %v, want Delivering", poe.Detect)
	}
}

// TestFacadeWriteIntegration_DeleteVlanProtectedPortRefusalThenForce proves
// the FACADE-LEVEL protected-port guard (guardVLANDeleteMembers, D-WR §3.3)
// end-to-end: a Switch constructed WithProtectedPorts covering one of vlan
// 90's real member ports (port 11, pinned by facade_integration_test.go's
// capstone) must refuse DeleteVlan without force -- via a REAL GetVLANs
// dispatch, not a canned fixture -- and must proceed once force=true is
// passed, actually removing the VLAN from the live fake.
func TestFacadeWriteIntegration_DeleteVlanProtectedPortRefusalThenForce(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	const protectedPort = 11 // pinned member of vlan 90 (facade_integration_test.go)
	sw := writableFacadeFor(t, vsw, "gsm7252ps", netgearswitch.WithProtectedPorts(protectedPort))

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	const vlanID = 90

	err := sw.DeleteVlan(ctx, vlanID, netgearswitch.Write{Force: false})
	if err == nil {
		t.Fatal("DeleteVlan(force=false) error = nil, want a protected-port refusal")
	}
	if !errors.Is(err, netgearswitch.ErrProtectedPort) {
		t.Fatalf("DeleteVlan(force=false) error = %v, want wrapping ErrProtectedPort", err)
	}
	wantSubstr := fmt.Sprintf("VLAN %d includes protected port(s)", vlanID)
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("DeleteVlan(force=false) error = %q, want it to contain %q", err.Error(), wantSubstr)
	}
	// Still present -- the refused delete must not have mutated anything.
	_ = getVlan(ctx, t, sw, vlanID)

	if err := sw.DeleteVlan(ctx, vlanID, netgearswitch.Write{Force: true}); err != nil {
		t.Fatalf("DeleteVlan(force=true) error = %v, want nil (force bypasses the guard)", err)
	}
	vlans, err := sw.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	for _, v := range vlans {
		if v.VlanID == vlanID {
			t.Fatalf("vlan %d still present after DeleteVlan(force=true): %+v, want it gone", vlanID, v)
		}
	}
}

// TestFacadeWriteIntegration_SetMgmtIPForceRoundTrip proves SetMgmtIP's
// unconditional force-gate (D-WR §2.13: force=false ALWAYS refuses,
// independent of protected_ports) and its three-field verify-after-write,
// end-to-end against gsm7252ps -- a model WITH a vendor OID subtree (D-WR
// §5.2's "gsm7252ps has vendor base" note), so the vendor mgmt-write OIDs
// resolve and the fake's ApplyWrite (virtual/state.go) accepts them,
// projecting the new values back into the standard MIB-II OIDs GetMgmtIP
// reads (virtual/state_oidmap.go derives IPAdEntAddr/IPAdEntNetmask/
// IPRouteNextHop directly from the same s.Mgmt fields the vendor write
// mutates).
func TestFacadeWriteIntegration_SetMgmtIPForceRoundTrip(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := writableFacadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	const address, netmask, gateway = "10.1.5.99", "255.255.255.0", "10.1.5.1"

	err := sw.SetMgmtIP(ctx, address, netmask, gateway, netgearswitch.Write{Force: false})
	if err == nil {
		t.Fatal("SetMgmtIP(force=false) error = nil, want the unconditional force-gate refusal")
	}
	if !errors.Is(err, netgearswitch.ErrProtectedPort) {
		t.Fatalf("SetMgmtIP(force=false) error = %v, want wrapping ErrProtectedPort", err)
	}

	if err := sw.SetMgmtIP(ctx, address, netmask, gateway, netgearswitch.Write{Force: true}); err != nil {
		t.Fatalf("SetMgmtIP(force=true) error = %v, want nil", err)
	}

	mgmt, err := sw.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != address {
		t.Errorf("GetMgmtIP().Address = %s, want %q", derefStr(mgmt.Address), address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != netmask {
		t.Errorf("GetMgmtIP().Netmask = %s, want %q", derefStr(mgmt.Netmask), netmask)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != gateway {
		t.Errorf("GetMgmtIP().Gateway = %s, want %q", derefStr(mgmt.Gateway), gateway)
	}
}

// TestFacadeWriteIntegration_SetHostnameNotForceGatedRoundTrip proves
// SetHostname over the facade's default (SNMP) backend, end-to-end against
// gsm7252ps: UNLIKE SetMgmtIP just above, force=false succeeds (renaming
// cannot strand a switch), and the new name is visible through GetHostname
// immediately after.
func TestFacadeWriteIntegration_SetHostnameNotForceGatedRoundTrip(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := writableFacadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	original, err := sw.GetHostname(ctx)
	if err != nil {
		t.Fatalf("GetHostname() (before) error = %v", err)
	}

	if err := sw.SetHostname(ctx, "ngsw-facade-test", netgearswitch.Write{Force: false}); err != nil {
		t.Fatalf("SetHostname(force=false) error = %v, want nil (not force-gated)", err)
	}
	got, err := sw.GetHostname(ctx)
	if err != nil {
		t.Fatalf("GetHostname() (after) error = %v", err)
	}
	if got != "ngsw-facade-test" {
		t.Errorf("GetHostname() = %q, want %q", got, "ngsw-facade-test")
	}

	if err := sw.SetHostname(ctx, original, netgearswitch.Write{Force: false}); err != nil {
		t.Fatalf("SetHostname(restore) error = %v", err)
	}
}

// TestFacadeWriteIntegration_WriteVerificationFailureOnAbsentInstancePort
// mirrors the Python-pinned write-verification-failure scenario (D-WR §5.2/
// task brief): ifAdminStatus.<port> is a recognized WRITABLE COLUMN
// (virtual/state.go's IsWritableOID matches by OID prefix, never checking
// whether the port instance actually exists -- see
// TestIsWritableOIDRecognizesKnownColumnsAndScalars/
// TestApplyWriteUnhandledOIDIsSilentNoOp in virtual/mutable_state_test.go),
// so a SET against a port number with no row in the mock's state (gsm7252ps
// has 52 physical ports; port 9999 has none) is ACCEPTED at the wire level
// (no notWritable error) and silently no-ops (ApplyWrite's existence check
// finds nothing to mutate) -- exactly the "face accepts, state no-ops"
// shape only a verify-after-write re-read can catch. SetPortEnabled's own
// verify (D-WR §2.8) does precisely that: after == nil (the port never
// existed to read back) raises *model.WriteVerificationError, never a
// silent false-success.
func TestFacadeWriteIntegration_WriteVerificationFailureOnAbsentInstancePort(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := writableFacadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	const absentPort = 9999

	err := sw.SetPortEnabled(ctx, absentPort, false, netgearswitch.Write{})
	if err == nil {
		t.Fatal("SetPortEnabled() on an absent-instance port error = nil, want a WriteVerificationError")
	}

	var verr *netgearswitch.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPortEnabled() error = %v (%T), want errors.As to succeed against *netgearswitch.WriteVerificationError", err, err)
	}
	if !strings.Contains(verr.Error(), "did not read back as false") {
		t.Errorf("WriteVerificationError.Error() = %q, want it to mention the requested state", verr.Error())
	}
}
