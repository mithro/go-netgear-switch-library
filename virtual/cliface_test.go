package virtual

// Tests for CliFace, driven over the REAL fastpath.Reader/fastpath.Writer
// (Tasks 8-10) against a SEEDED VirtualSwitchState -- mirroring the
// "drive the mock through the real client, not by peeking at internals"
// convention snmpface_test.go/nsdpface_test.go/httpface_test.go already
// use, adapted to the CLI face's in-process (no-socket) Session instead of
// a network client.
//
// Three things this suite is REQUIRED to prove (task-11-brief.md):
//  1. Every read op returns data matching the seed (round-trip).
//  2. Cross-protocol visibility: a CLI write is then visible via the SNMP
//     oid_map() projection of the SAME State.
//  3. Access-mode inertness: a per-port VLAN write WITHOUT
//     "switchport mode general" does NOT change state; WITH it, it does.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/fastpath"
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// newTestCliFace builds a CliFace + its model.SwitchModel for modelKey over
// st, failing the test immediately on any registry/spec lookup error --
// every error path here would mean this test itself is misconfigured, not
// that the code under test is broken.
func newTestCliFace(t *testing.T, modelKey string, st *State) (*CliFace, *model.SwitchModel) {
	t.Helper()
	m, err := model.GetModel(modelKey)
	if err != nil {
		t.Fatalf("model.GetModel(%q) error = %v", modelKey, err)
	}
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		t.Fatalf("fastpath.CLISpec(%q) error = %v", modelKey, err)
	}
	return NewCliFace(st, spec), m
}

func sortedCopy(in []int) []int {
	out := append([]int(nil), in...)
	sort.Ints(out)
	return out
}

func assertIntSlice(t *testing.T, label string, got, want []int) {
	t.Helper()
	got, want = sortedCopy(got), sortedCopy(want)
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", label, got, want)
		}
	}
}

// --- 1. read round-trip: fastpath.Reader vs seeded State -------------------

func TestCliFaceReadRoundTripGSM7252PS(t *testing.T) {
	st := SeedGSM7252PS()
	face, m := newTestCliFace(t, "gsm7252ps", st)
	reader, err := fastpath.NewReader(face, m)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	ctx := context.Background()

	t.Run("GetPorts", func(t *testing.T) {
		ports, err := reader.GetPorts(ctx)
		if err != nil {
			t.Fatalf("GetPorts: %v", err)
		}
		byPort := make(map[int]model.PortStatus, len(ports))
		for _, p := range ports {
			byPort[p.Port] = p
		}
		// Port 1: admin+link up, 1000 Mbps (seed.go:93).
		p1, ok := byPort[1]
		if !ok {
			t.Fatal("port 1 missing from GetPorts")
		}
		if !p1.AdminEnabled || !p1.LinkUp {
			t.Errorf("port 1 = %+v, want admin+link up", p1)
		}
		if p1.SpeedMbps == nil || *p1.SpeedMbps != 1000 {
			t.Errorf("port 1 SpeedMbps = %v, want 1000", p1.SpeedMbps)
		}
		// Port 6: admin up, link DOWN (seed.go:98) -- speed must be nil,
		// never a fabricated value, mirroring parsePortStatus's own
		// "only consult Physical Status when Link Status is up" rule.
		p6, ok := byPort[6]
		if !ok {
			t.Fatal("port 6 missing from GetPorts")
		}
		if p6.LinkUp {
			t.Errorf("port 6 LinkUp = true, want false (seed.go:98)")
		}
		if p6.SpeedMbps != nil {
			t.Errorf("port 6 SpeedMbps = %v, want nil (link down)", *p6.SpeedMbps)
		}
		// Port 49: the 10G uplink (seed.go:141).
		p49, ok := byPort[49]
		if !ok {
			t.Fatal("port 49 missing from GetPorts")
		}
		if p49.SpeedMbps == nil || *p49.SpeedMbps != 10000 {
			t.Errorf("port 49 SpeedMbps = %v, want 10000", p49.SpeedMbps)
		}
		// Pseudo-ports (CPU 417 / lag 1 418) must be ABSENT, exactly as
		// every other backend's physical-port filter drops them.
		if _, present := byPort[417]; present {
			t.Errorf("GetPorts includes pseudo-port 417 (CPU Interface), want dropped")
		}
		if _, present := byPort[418]; present {
			t.Errorf("GetPorts includes pseudo-port 418 (lag 1), want dropped")
		}
	})

	t.Run("GetVLANs", func(t *testing.T) {
		vlans, err := reader.GetVLANs(ctx)
		if err != nil {
			t.Fatalf("GetVLANs: %v", err)
		}
		byID := make(map[int]model.VLANInfo, len(vlans))
		for _, v := range vlans {
			byID[v.VlanID] = v
		}
		seedVlan := st.Vlans[90] // "iot" (seed.go:167)
		got, ok := byID[90]
		if !ok {
			t.Fatal("VLAN 90 missing from GetVLANs")
		}
		if got.Name == nil || *got.Name != "iot" {
			t.Errorf("VLAN 90 Name = %v, want \"iot\"", got.Name)
		}
		// Filtered to PHYSICAL ports only: seedVlan.Member also carries lag
		// 1/lag 2 pseudo-port ifIndexes (418, 419), but "show vlan <id>"
		// prints those as literal "lag N" rows, which fastpath's own
		// physPort() (the SAME rule parsePortStatus/GetPorts already
		// applies) does not resolve to a physical port number -- so LAG
		// membership is invisible to GetVLANs over CLI, exactly as it is
		// to GetPorts. This mirrors real hardware: a per-VLAN CLI page has
		// no numeric ifIndex column to recover a LAG's membership from.
		physical := func(ports []int) []int {
			var out []int
			for _, p := range ports {
				if sim, ok := st.Ports[p]; ok && sim.IfType == 6 {
					out = append(out, p)
				}
			}
			return out
		}
		wantMember := physical(sliceFromPortSet(seedVlan.Member))
		wantUntagged := physical(sliceFromPortSet(portSetFromSlice(sortedCopy(intersect(seedVlan.Member, seedVlan.Untagged)))))
		wantTagged := physical(sliceFromPortSet(portSetFromSlice(sortedCopy(subtract(seedVlan.Member, seedVlan.Untagged)))))
		assertIntSlice(t, "VLAN 90 MemberPorts", got.MemberPorts, wantMember)
		assertIntSlice(t, "VLAN 90 TaggedPorts", got.TaggedPorts, wantTagged)
		assertIntSlice(t, "VLAN 90 UntaggedPorts", got.UntaggedPorts, wantUntagged)

		// VLAN 1's ConfiguredOnly ports (50, 51 -- seed.go:157) must be
		// ABSENT from MemberPorts: real "show vlan 1" reports them
		// "Current: Exclude", exactly like vlanPortCfg_vlan1.html does
		// (seed.go's own doc comment on VlanSim.ConfiguredOnly).
		v1 := byID[1]
		for _, p := range []int{50, 51} {
			for _, m := range v1.MemberPorts {
				if m == p {
					t.Errorf("VLAN 1 MemberPorts contains ConfiguredOnly port %d, want absent (Current: Exclude)", p)
				}
			}
		}
	})

	t.Run("GetPVIDs", func(t *testing.T) {
		pvids, err := reader.GetPVIDs(ctx)
		if err != nil {
			t.Fatalf("GetPVIDs: %v", err)
		}
		byPort := make(map[int]int, len(pvids))
		for _, p := range pvids {
			byPort[p.Port] = p.Vlan
		}
		for port, want := range st.Pvids {
			got, ok := byPort[port]
			if !ok {
				t.Errorf("port %d missing from GetPVIDs", port)
				continue
			}
			if got != want {
				t.Errorf("port %d PVID = %d, want %d", port, got, want)
			}
		}
	})

	t.Run("GetMACs", func(t *testing.T) {
		macs, err := reader.GetMACs(ctx)
		if err != nil {
			t.Fatalf("GetMACs: %v", err)
		}
		if len(macs) != len(st.Macs) {
			t.Fatalf("GetMACs len = %d, want %d", len(macs), len(st.Macs))
		}
		// seed.go:253 -- BridgePort 10 joins through BridgePorts[10]=110
		// (seed.go:258), NOT the bare bridge-port number, proving the
		// renderer/parser round trip uses the join.
		var found bool
		for _, e := range macs {
			if e.Mac == "C8:00:84:89:71:70" {
				found = true
				if e.Port != 110 {
					t.Errorf("MAC C8:00:84:89:71:70 Port = %d, want 110 (joined via BridgePorts, not bare 10)", e.Port)
				}
				if e.VlanID == nil || *e.VlanID != 90 {
					t.Errorf("MAC C8:00:84:89:71:70 VlanID = %v, want 90", e.VlanID)
				}
			}
		}
		if !found {
			t.Error("MAC C8:00:84:89:71:70 not found in GetMACs")
		}
	})

	t.Run("GetLLDP", func(t *testing.T) {
		nbrs, err := reader.GetLLDP(ctx)
		if err != nil {
			t.Fatalf("GetLLDP: %v", err)
		}
		if len(nbrs) != 1 {
			t.Fatalf("GetLLDP len = %d, want 1", len(nbrs))
		}
		n := nbrs[0]
		if n.LocalPort != 49 {
			t.Errorf("LLDP LocalPort = %d, want 49", n.LocalPort)
		}
		if n.RemoteChassisID == nil || *n.RemoteChassisID != "C8:00:84:89:71:70" {
			t.Errorf("LLDP RemoteChassisID = %v, want C8:00:84:89:71:70", n.RemoteChassisID)
		}
		if n.RemoteSysName == nil || *n.RemoteSysName != "sw-cisco-shed" {
			t.Errorf("LLDP RemoteSysName = %v, want sw-cisco-shed", n.RemoteSysName)
		}
	})

	t.Run("GetPoE", func(t *testing.T) {
		poe, err := reader.GetPoE(ctx)
		if err != nil {
			t.Fatalf("GetPoE: %v", err)
		}
		byPort := make(map[int]model.PoEStatus, len(poe))
		for _, p := range poe {
			byPort[p.Port] = p
		}
		// Port 1: Detect 3 (delivering), PowerMw 3500 (seed.go:178).
		p1 := byPort[1]
		if p1.Detect != model.PoEDetectDelivering {
			t.Errorf("PoE port 1 Detect = %v, want delivering", p1.Detect)
		}
		if p1.PowerMw == nil || *p1.PowerMw != 3500 {
			t.Errorf("PoE port 1 PowerMw = %v, want 3500", p1.PowerMw)
		}
		// Port 6: Detect 6 (otherFault, seed.go:183) -- must surface as
		// "fault" (substring match on the rendered Status text).
		p6 := byPort[6]
		if p6.Detect != model.PoEDetectFault {
			t.Errorf("PoE port 6 Detect = %v, want fault (raw RFC3621 6=otherFault)", p6.Detect)
		}
		// Port 10: Detect 2 (searching, seed.go:187).
		p10 := byPort[10]
		if p10.Detect != model.PoEDetectSearching {
			t.Errorf("PoE port 10 Detect = %v, want searching", p10.Detect)
		}
	})

	t.Run("GetSensors", func(t *testing.T) {
		sensors, err := reader.GetSensors(ctx)
		if err != nil {
			t.Fatalf("GetSensors: %v", err)
		}
		if len(sensors) != len(st.Sensors) {
			t.Fatalf("GetSensors len = %d, want %d (State.Sensors, not HTTPSensors)", len(sensors), len(st.Sensors))
		}
		for _, s := range sensors {
			if s.Kind == "temperature" {
				t.Errorf("GetSensors has a temperature entry %+v, want none (gsm7252ps's Sensors carries none -- see seed.go's own doc comment)", s)
			}
		}
	})

	t.Run("GetMgmtIP", func(t *testing.T) {
		mgmt, err := reader.GetMgmtIP(ctx)
		if err != nil {
			t.Fatalf("GetMgmtIP: %v", err)
		}
		if mgmt.Address == nil || *mgmt.Address != st.Mgmt.Address {
			t.Errorf("MgmtIP Address = %v, want %s", mgmt.Address, st.Mgmt.Address)
		}
		if mgmt.Mode != model.IPModeStatic {
			t.Errorf("MgmtIP Mode = %v, want static", mgmt.Mode)
		}
	})

	t.Run("Identify", func(t *testing.T) {
		id, err := reader.Identify(ctx)
		if err != nil {
			t.Fatalf("Identify: %v", err)
		}
		if id.Key == nil || *id.Key != "gsm7252ps" {
			t.Errorf("Identify Key = %v, want gsm7252ps", id.Key)
		}
	})
}

func TestCliFaceReadRoundTripM430024X(t *testing.T) {
	st := SeedM4300_24X()
	face, m := newTestCliFace(t, "m4300-24x", st)
	reader, err := fastpath.NewReader(face, m)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	ctx := context.Background()

	t.Run("GetMgmtIP uses Method dialect label", func(t *testing.T) {
		mgmt, err := reader.GetMgmtIP(ctx)
		if err != nil {
			t.Fatalf("GetMgmtIP: %v", err)
		}
		if mgmt.Mode != model.IPModeStatic {
			t.Errorf("MgmtIP Mode = %v, want static (parsed via the M4300 \"Method\" label fallback)", mgmt.Mode)
		}
		if mgmt.Address == nil || *mgmt.Address != "10.1.5.13" {
			t.Errorf("MgmtIP Address = %v, want 10.1.5.13", mgmt.Address)
		}
	})

	t.Run("GetSensors includes temperature", func(t *testing.T) {
		sensors, err := reader.GetSensors(ctx)
		if err != nil {
			t.Fatalf("GetSensors: %v", err)
		}
		var sawTemp bool
		for _, s := range sensors {
			if s.Kind == "temperature" {
				sawTemp = true
				if s.Value != 49 {
					t.Errorf("temperature sensor Value = %v, want 49 (seed.go)", s.Value)
				}
			}
		}
		if !sawTemp {
			t.Error("GetSensors has no temperature entry, want one (m4300-24x seed carries one)")
		}
	})

	t.Run("GetPoE unsupported (no PSE ports)", func(t *testing.T) {
		_, err := reader.GetPoE(ctx)
		if !errors.Is(err, model.ErrUnsupportedCapability) {
			t.Fatalf("GetPoE error = %v, want ErrUnsupportedCapability (m4300-24x has PoEPortCount 0)", err)
		}
	})

	t.Run("Identify", func(t *testing.T) {
		id, err := reader.Identify(ctx)
		if err != nil {
			t.Fatalf("Identify: %v", err)
		}
		if id.Key == nil || *id.Key != "m4300-24x" {
			t.Errorf("Identify Key = %v, want m4300-24x", id.Key)
		}
	})
}

// --- 2. cross-protocol visibility: CLI write visible via SNMP oid_map -----

func TestCliFaceWriteVisibleOverSNMPOidMap(t *testing.T) {
	st := SeedGSM7252PS()
	face, m := newTestCliFace(t, "gsm7252ps", st)
	writer, err := fastpath.NewWriter(face, m)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ctx := context.Background()

	const port = 7       // port 7 currently PVID 90 (seed.go:174)
	const targetVlan = 4 // move it to VLAN 4 instead
	if st.Pvids[port] == targetVlan {
		t.Fatalf("test setup: port %d already has PVID %d", port, targetVlan)
	}

	if err := writer.SetPVID(ctx, port, targetVlan, false); err != nil {
		t.Fatalf("SetPVID: %v", err)
	}

	// Visible over the CLI's own read-back (fastpath.Reader).
	reader, err := fastpath.NewReader(face, m)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	pvids, err := reader.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs: %v", err)
	}
	var cliSaw bool
	for _, p := range pvids {
		if p.Port == port {
			cliSaw = true
			if p.Vlan != targetVlan {
				t.Errorf("CLI GetPVIDs port %d PVID = %d, want %d", port, p.Vlan, targetVlan)
			}
		}
	}
	if !cliSaw {
		t.Fatalf("port %d missing from CLI GetPVIDs after SetPVID", port)
	}

	// Visible over the SAME State's SNMP oid_map() projection, proving the
	// CLI write mutated the SHARED VirtualSwitchState, not some CLI-face-
	// private copy.
	oidMap := st.OIDMap()
	oid := fmt.Sprintf("%s.%d", snmp.Dot1qPvid, port)
	entry, ok := oidMap[oid]
	if !ok {
		t.Fatalf("oid_map has no entry for %s after CLI SetPVID", oid)
	}
	if entry.Value != fmt.Sprintf("%d", targetVlan) {
		t.Errorf("oid_map[%s] = %q, want %q (SNMP dot1qPvid must see the CLI write)", oid, entry.Value, fmt.Sprintf("%d", targetVlan))
	}
}

// --- 3. access-mode inertness ------------------------------------------

// TestCliFaceAccessModeInertness is the load-bearing contract test (dossier
// §3.1, brief's core requirement): `vlan participation` is ACCEPTED
// (empty output) but COMPLETELY INERT while a port sits outside
// "switchport mode general"/"trunk", and takes effect once
// "switchport mode general" is issued. Driven with RAW CliFace.Run calls
// (bypassing fastpath.Writer, which ALWAYS prepends "switchport mode
// general" as a mandatory prelude -- see writer.go's generalMode doc
// comment -- so driving through Writer here would never be able to
// observe the inert path at all), verified via the REAL fastpath.Reader.
//
// Uses m4300-24x port 3, whose default switchport mode is NOT explicitly
// seeded ("" -- PortSim.SwitchportMode's Go zero value) but resolves to
// "locked" (not general) via the MEASURED VlanMembershipLockedPorts set
// seed.go populates for every one of that model's 24 ports, citing a live
// probe: "EVERY port on this switch is switchport mode access or trunk"
// (seed.go's own doc comment on SeedM4300_24X). This is the SAME live
// finding CliFace.general() falls back to, so this test exercises measured
// per-model data, not a fabricated port state.
func TestCliFaceAccessModeInertness(t *testing.T) {
	st := SeedM4300_24X()
	face, m := newTestCliFace(t, "m4300-24x", st)
	ctx := context.Background()

	const port, iface, vid = 3, "1/0/3", 4 // VLAN 4 = "wifi" (seed.go:589); port 3 not currently a member
	if st.Vlans[vid].Member[port] {
		t.Fatalf("test setup: port %d already a member of VLAN %d", port, vid)
	}
	if !st.VlanMembershipLockedPorts[port] {
		t.Fatalf("test setup: port %d not locked in seed (measured access/trunk default)", port)
	}

	reader, err := fastpath.NewReader(face, m)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	memberOf := func(vlan int) bool {
		vlans, err := reader.GetVLANs(ctx)
		if err != nil {
			t.Fatalf("GetVLANs: %v", err)
		}
		for _, v := range vlans {
			if v.VlanID == vlan {
				for _, p := range v.MemberPorts {
					if p == port {
						return true
					}
				}
			}
		}
		return false
	}

	run := func(cmd string) string {
		out, err := face.Run(ctx, cmd)
		if err != nil {
			t.Fatalf("Run(%q): %v", cmd, err)
		}
		return out
	}

	// Phase 1: WITHOUT "switchport mode general" -- accepted, but inert.
	if out := run("configure"); out != "" {
		t.Fatalf(`Run("configure") = %q, want "" (accepted)`, out)
	}
	if out := run("interface " + iface); out != "" {
		t.Fatalf(`Run("interface %s") = %q, want "" (accepted)`, iface, out)
	}
	if out := run(fmt.Sprintf("vlan participation include %d", vid)); out != "" {
		t.Fatalf(`Run("vlan participation include %d") = %q, want "" (ACCEPTED contract, even though inert)`, vid, out)
	}
	if out := run("end"); out != "" {
		t.Fatalf(`Run("end") = %q, want ""`, out)
	}
	if memberOf(vid) {
		t.Fatalf("port %d became a member of VLAN %d WITHOUT switchport mode general -- inertness contract violated", port, vid)
	}
	if st.Vlans[vid].Member[port] {
		t.Fatalf("VlanSim.Member[%d] mutated directly WITHOUT switchport mode general", port)
	}

	// Phase 2: WITH "switchport mode general" first -- now takes effect.
	run("configure")
	run("interface " + iface)
	if out := run("switchport mode general"); out != "" {
		t.Fatalf(`Run("switchport mode general") = %q, want "" (accepted)`, out)
	}
	if out := run(fmt.Sprintf("vlan participation include %d", vid)); out != "" {
		t.Fatalf(`Run("vlan participation include %d") = %q, want ""`, vid, out)
	}
	run("end")
	if !memberOf(vid) {
		t.Fatalf("port %d did NOT become a member of VLAN %d WITH switchport mode general", port, vid)
	}
}

// TestCliFaceWriterBypassesInertnessViaMandatoryGeneralMode is the
// complementary positive case: fastpath.Writer.SetVLANMembership (the
// PRODUCTION write path, unlike the raw-Run drive above) unconditionally
// sends "switchport mode general" first (writer.go's generalMode, dossier
// §4.1/§4.4's mandatory prelude), so it succeeds even against a port whose
// measured seeded default is access/trunk-locked -- proving the mock's
// inertness (proven inert above) is exactly what the writer's mandatory
// prelude was built to defeat, on the SAME seed/port this file's access-
// mode test uses.
func TestCliFaceWriterBypassesInertnessViaMandatoryGeneralMode(t *testing.T) {
	st := SeedM4300_24X()
	face, m := newTestCliFace(t, "m4300-24x", st)
	ctx := context.Background()

	const port, vid = 3, 4
	if !st.VlanMembershipLockedPorts[port] {
		t.Fatalf("test setup: port %d not locked in seed", port)
	}

	writer, err := fastpath.NewWriter(face, m)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := writer.SetVLANMembership(ctx, vid, port, model.VlanUntagged, false); err != nil {
		t.Fatalf("SetVLANMembership: %v", err)
	}
	if !st.Vlans[vid].Member[port] {
		t.Fatalf("port %d not a member of VLAN %d after Writer.SetVLANMembership (mandatory general-mode prelude should have made this succeed)", port, vid)
	}
	if st.Ports[port].SwitchportMode != "general" {
		t.Errorf("PortSim.SwitchportMode = %q, want \"general\" (Writer's mandatory prelude)", st.Ports[port].SwitchportMode)
	}
}

// --- misc dispatch contract coverage ---------------------------------

// TestCliFaceAcceptRejectContract exercises the empty/non-empty CONTRACT
// itself (dossier §3.1): an accepted config command answers EMPTY;
// anything the switch would reject answers non-empty text.
func TestCliFaceAcceptRejectContract(t *testing.T) {
	st := SeedGSM7252PS() // gsm7252ps: hasSwitchportModes() == false
	face, _ := newTestCliFace(t, "gsm7252ps", st)
	ctx := context.Background()

	run := func(cmd string) string {
		out, err := face.Run(ctx, cmd)
		if err != nil {
			t.Fatalf("Run(%q): %v", cmd, err)
		}
		return out
	}

	if out := run("configure"); out != "" {
		t.Fatalf(`Run("configure") = %q, want "" (accepted)`, out)
	}
	if out := run("interface 1/0/1"); out != "" {
		t.Fatalf(`Run("interface 1/0/1") = %q, want "" (accepted)`, out)
	}
	// gsm7252ps has NO switchport-mode concept -- must be REJECTED.
	if out := run("switchport mode general"); out == "" {
		t.Fatal(`Run("switchport mode general") on gsm7252ps = "", want non-empty (rejected: no switchport-mode concept)`)
	}
	run("end")

	// "vlan database" -> "vlan 500" (new VLAN) must be ACCEPTED.
	if out := run("vlan database"); out != "" {
		t.Fatalf(`Run("vlan database") = %q, want ""`, out)
	}
	if out := run("vlan 500"); out != "" {
		t.Fatalf(`Run("vlan 500") = %q, want "" (accepted)`, out)
	}
	if _, ok := st.Vlans[500]; !ok {
		t.Error("VLAN 500 not created")
	}
	// "vlan name <nonexistent> foo" must be REJECTED (ERROR text).
	if out := run("vlan name 999 foo"); out == "" {
		t.Fatal(`Run("vlan name 999 foo") = "", want non-empty (VLAN 999 does not exist)`)
	}
	// "no vlan 1" (deleting the default VLAN) must be REJECTED.
	if out := run("no vlan 1"); out == "" {
		t.Fatal(`Run("no vlan 1") = "", want non-empty (default VLAN cannot be deleted)`)
	}
	run("end")

	// An unrecognized command must answer non-empty fallback text.
	if out := run("frobnicate the whatsit"); out == "" {
		t.Fatal(`Run("frobnicate the whatsit") = "", want non-empty fallback text`)
	}
}

// TestCliFaceModeStackExitEnd exercises the mode stack itself (dossier
// §3.3/§3.4): "exit" pops one level (a no-op at EXEC), "end" always
// returns straight to EXEC regardless of depth.
func TestCliFaceModeStackExitEnd(t *testing.T) {
	st := SeedGSM7252PS()
	face, _ := newTestCliFace(t, "gsm7252ps", st)
	ctx := context.Background()

	run := func(cmd string) string {
		out, err := face.Run(ctx, cmd)
		if err != nil {
			t.Fatalf("Run(%q): %v", cmd, err)
		}
		return out
	}

	// "exit" at EXEC is a no-op, still accepted.
	if out := run("exit"); out != "" {
		t.Fatalf(`Run("exit") at EXEC = %q, want ""`, out)
	}

	run("configure")
	run("interface 1/0/1")
	if face.mode() != cliModeInterface {
		t.Fatalf("mode() = %q, want %q", face.mode(), cliModeInterface)
	}
	run("end")
	if face.mode() != "exec" {
		t.Fatalf(`mode() after "end" = %q, want "exec"`, face.mode())
	}
	if face.ifacePort != nil {
		t.Errorf("ifacePort after \"end\" = %v, want nil", face.ifacePort)
	}
}

// --- SCP stand-in + write-memory/reload ---------------------------------

func TestCliFaceRunSCPCopyAndRunWriteMemory(t *testing.T) {
	st := SeedM4300_24X()
	face, _ := newTestCliFace(t, "m4300-24x", st)
	ctx := context.Background()

	out, err := face.RunSCPCopy(ctx, "copy scp://user@host/cert.pem nvram:sslpem-server", "scppass")
	if err != nil {
		t.Fatalf("RunSCPCopy: %v", err)
	}
	if out == "" {
		t.Error("RunSCPCopy success output is empty, want a confirmation string")
	}
	if st.ScpCertDeploy == nil || len(st.ScpCertDeploy.Copies) != 1 {
		t.Fatalf("ScpCertDeploy.Copies = %+v, want 1 entry", st.ScpCertDeploy)
	}
	if st.ScpCertDeploy.Copies[0].Dest != "nvram:sslpem-server" {
		t.Errorf("ScpCertDeploy.Copies[0].Dest = %q, want nvram:sslpem-server", st.ScpCertDeploy.Copies[0].Dest)
	}

	// Bad syntax -> REJECTED (non-empty text), never an error.
	out, err = face.RunSCPCopy(ctx, "copy onlyonearg", "x")
	if err != nil {
		t.Fatalf("RunSCPCopy(bad syntax): %v", err)
	}
	if out == "" {
		t.Error("RunSCPCopy(bad syntax) output empty, want rejection text")
	}

	if _, err := face.RunWriteMemory(ctx, "write memory", false); err != nil {
		t.Fatalf("RunWriteMemory(write memory): %v", err)
	}
	if !st.ScpCertDeploy.Saved {
		t.Error("ScpCertDeploy.Saved = false after RunWriteMemory(write memory)")
	}

	before := st.Reboots
	if _, err := face.RunWriteMemory(ctx, "reload", true); err != nil {
		t.Fatalf("RunWriteMemory(reload): %v", err)
	}
	if st.Reboots != before+1 {
		t.Errorf("State.Reboots = %d, want %d", st.Reboots, before+1)
	}
}

// TestCliFaceReboot exercises fastpath.Writer.Reboot end-to-end (through
// RunWriteMemory, prestuff=true unconditionally per writer.go's own doc
// comment) against State.Reboots.
func TestCliFaceReboot(t *testing.T) {
	st := SeedGSM7252PS()
	face, m := newTestCliFace(t, "gsm7252ps", st)
	writer, err := fastpath.NewWriter(face, m)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	before := st.Reboots
	if err := writer.Reboot(context.Background(), true); err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if st.Reboots != before+1 {
		t.Errorf("State.Reboots = %d, want %d", st.Reboots, before+1)
	}
}

// --- render fidelity: full column set vs cli_fastpath.py (fix round 1) ----

// TestCliFaceRenderPortsFullColumnSet asserts render_ports emits the FULL
// 9-column shape (cli_fastpath.py:133-163), not just the 6 the parser
// itself consults -- Link Trap/LACP Mode/Flow Mode must be present as
// literal "Enable"/"Enable"/"Disable" trailing columns.
func TestCliFaceRenderPortsFullColumnSet(t *testing.T) {
	st := SeedGSM7252PS()
	face, _ := newTestCliFace(t, "gsm7252ps", st)
	out := face.renderPorts()

	for _, header := range []string{"LACP", "Flow"} {
		if !strings.Contains(out, header) {
			t.Errorf("renderPorts output missing header %q:\n%s", header, out)
		}
	}
	// Port 1 (admin+link up) row must carry all 9 cells, ending in the
	// fixed "Enable Enable Disable" (Link Trap/LACP Mode/Flow Mode) tail.
	var portLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "1/0/1 ") {
			portLine = line
			break
		}
	}
	if portLine == "" {
		t.Fatalf("no row for 1/0/1 in renderPorts output:\n%s", out)
	}
	fields := strings.Fields(portLine)
	if len(fields) < 3 || fields[len(fields)-3] != "Enable" || fields[len(fields)-2] != "Enable" || fields[len(fields)-1] != "Disable" {
		t.Errorf("port 1 row = %q, want trailing \"Enable Enable Disable\" (Link Trap/LACP Mode/Flow Mode)", portLine)
	}
}

// TestCliFaceRenderPoEModelGating asserts render_poe's M4300 vs gsm7252ps
// Temperature-column gating (cli_fastpath.py:303-326, parse.go's own
// documented 9-vs-10-column real-fixture divergence): m4300-16x (PoE
// present) OMITS "Temperature"; gsm7252ps INCLUDES it.
func TestCliFaceRenderPoEModelGating(t *testing.T) {
	gsm := SeedGSM7252PS()
	gsmFace, _ := newTestCliFace(t, "gsm7252ps", gsm)
	gsmOut := gsmFace.renderPoE()
	if !strings.Contains(gsmOut, "Temperature") {
		t.Errorf("gsm7252ps renderPoE missing \"Temperature\" column:\n%s", gsmOut)
	}

	m16 := SeedM4300_16X()
	m16Face, _ := newTestCliFace(t, "m4300-16x", m16)
	m16Out := m16Face.renderPoE()
	if strings.Contains(m16Out, "Temperature") {
		t.Errorf("m4300-16x renderPoE includes \"Temperature\" column, want omitted (M4300 image has no PoE Temperature column)\n%s", m16Out)
	}
	// Both must still carry the three parser-required-by-name columns.
	for _, hdr := range []string{"Intf", "Power (mW)", "Status"} {
		if !strings.Contains(m16Out, hdr) {
			t.Errorf("m4300-16x renderPoE missing required header %q:\n%s", hdr, m16Out)
		}
	}
}

// TestCliFaceRenderVlanDetailVLANType asserts render_vlan_detail's
// "VLAN Type:" line is "Default" for VLAN 1 and "Static" for every other
// VLAN (cli_fastpath.py:185) -- the earlier renderer hardcoded "Static"
// unconditionally, a real bug this test pins against regressing.
func TestCliFaceRenderVlanDetailVLANType(t *testing.T) {
	st := SeedGSM7252PS()
	face, _ := newTestCliFace(t, "gsm7252ps", st)

	out1 := face.renderVlanDetail(1)
	if !strings.Contains(out1, "VLAN Type: Default") {
		t.Errorf("renderVlanDetail(1) missing \"VLAN Type: Default\":\n%s", out1)
	}
	if strings.Contains(out1, "VLAN Type: Static") {
		t.Errorf("renderVlanDetail(1) says \"VLAN Type: Static\", want \"Default\":\n%s", out1)
	}

	out90 := face.renderVlanDetail(90)
	if !strings.Contains(out90, "VLAN Type: Static") {
		t.Errorf("renderVlanDetail(90) missing \"VLAN Type: Static\":\n%s", out90)
	}
}

// TestCliFacePoeCliStatusLagRequiresPolling ports the hardware-measured
// PoeSim.CliStatusLagReads quirk (state.go, MEASURED on M4300-16X
// 10.1.5.20, FASTPATH 12.0.19.15, 2026-07-30): a just-re-enabled PoE port
// reports "Disabled" for ONE extra `show poe port info all` read before
// catching up, so fastpath.Writer.SetPoE's verification poll loop is
// genuinely exercised (not satisfied by the very first read) -- driven
// with a fake clock/sleep (WithClock) so this test takes no real wall
// time.
func TestCliFacePoeCliStatusLagRequiresPolling(t *testing.T) {
	st := SeedGSM7252PS()
	face, m := newTestCliFace(t, "gsm7252ps", st)
	ctx := context.Background()

	const port = 6 // starts Detect=6/PowerMw 0 (seed.go:183); force a clean off->on transition
	st.Poe[port].Admin = false
	st.Poe[port].CliStatusLagReads = 0

	now := time.Now()
	var sleeps int
	writer, err := fastpath.NewWriter(face, m, fastpath.WithClock(
		func() time.Time { return now },
		func(_ context.Context, d time.Duration) error {
			sleeps++
			now = now.Add(d)
			return nil
		},
	))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	if err := writer.SetPoE(ctx, port, true, false); err != nil {
		t.Fatalf("SetPoE: %v", err)
	}
	if sleeps == 0 {
		t.Error("SetPoE never polled/slept -- the CLI status lag (CliStatusLagReads) was not exercised; a bug here would let SetPoE silently pass without ever driving the poll loop")
	}
	if !st.Poe[port].Admin {
		t.Error("PoeSim.Admin = false after SetPoE(on=true)")
	}
	if st.Poe[port].CliStatusLagReads != 0 {
		t.Errorf("CliStatusLagReads = %d after SetPoE succeeded, want 0 (fully consumed)", st.Poe[port].CliStatusLagReads)
	}
}

// --- helpers -------------------------------------------------------------

func intersect(a, b map[int]bool) []int {
	var out []int
	for p := range a {
		if a[p] && b[p] {
			out = append(out, p)
		}
	}
	return out
}

func subtract(a, b map[int]bool) []int {
	var out []int
	for p := range a {
		if a[p] && !b[p] {
			out = append(out, p)
		}
	}
	return out
}
