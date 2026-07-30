// facade_nsdp_integration_test.go: the slice-05 capstone -- the root
// netgearswitch facade's NSDP backend (backend_nsdp.go, Switch.NSDPDevice)
// driven end-to-end against REAL virtual.VirtualSwitch(gs110emx)/(gs305ep)
// instances over real UDP, proving the facade's NSDP dispatch seam
// (dispatch.go/write_dispatch.go -> backend_nsdp.go's buildNSDPReader/
// buildNSDPWriter -> nsdp.Reader/nsdp.Writer) is wired correctly on top of
// the already-capstoned nsdp package (see nsdp/reader_test.go, writer_test.go
// and virtual/nsdpface_test.go, whose pinned seed values this file reuses
// verbatim) -- never a vacuous pass. Per Task 7's brief and D-NSDP
// (docs/superpowers/plans/2026-07-30-slice-05-dossier-nsdp.md) §8.
//
// package netgearswitch_test (external), same package as
// facade_integration_test.go -- this file reuses that file's
// startVirtualSwitch/derefStr/facadeTestTimeout helpers directly.
package netgearswitch_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/nsdp"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// nsdpFacadeFor constructs a *netgearswitch.Switch bound to modelKey, talking
// to vsw's live NSDP face over a real (non-default) UDP port via an injected
// nsdp.Client (WithNSDPClient) -- the NSDP analogue of facade_integration_
// test.go's facadeFor: proves the facade's default-vs-injected NSDP client
// seam (backend_nsdp.go's buildNSDPClient) works with an already-built
// client, exactly the shape a caller pointing at a VirtualSwitch's ephemeral
// NsdpPort needs (package nsdp's own client separates host/port, so the
// facade's "host" string can't carry vsw's ephemeral port the way SNMP's
// "host:port" convention does -- WithNSDPClient sidesteps that entirely, per
// D-NSDP §10.2/Task 7's brief).
func nsdpFacadeFor(t *testing.T, vsw *virtual.VirtualSwitch, modelKey string, opts ...netgearswitch.SwitchOption) *netgearswitch.Switch {
	t.Helper()
	m, err := netgearswitch.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q) error = %v", modelKey, err)
	}
	client, err := nsdp.NewUDPClient(vsw.Host,
		nsdp.WithServerPort(vsw.NsdpPort),
		nsdp.WithClientPort(0),
		nsdp.WithTimeout(facadeTestTimeout),
	)
	if err != nil {
		t.Fatalf("nsdp.NewUDPClient() error = %v", err)
	}
	base := []netgearswitch.SwitchOption{netgearswitch.WithNSDPClient(client)}
	sw, err := netgearswitch.New(m, vsw.Host, append(base, opts...)...)
	if err != nil {
		t.Fatalf("New(%q) error = %v", modelKey, err)
	}
	return sw
}

// withNSDPPassword resolves the SHARED httpPassword cell to password --
// this is what backend_nsdp.go's buildNSDPWriter consumes for NSDP v1 write
// auth (D-NSDP §8.2: the ONE web-admin password feeds both HTTP and NSDP,
// so there is no separate WithNSDPPassword option -- see backend_nsdp_test.go
// for the unit-level proof of that wiring).
func withNSDPPassword(password string) netgearswitch.SwitchOption {
	return netgearswitch.WithHTTPPasswordResolver(func() (*string, error) {
		p := password
		return &p, nil
	})
}

// --- gs110emx: every supported read, non-vacuous vs SeedGS110EMX() --------

func TestFacadeNSDPIntegration_GS110EMXEveryReadNonVacuousVsSeed(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs110emx")
	sw := nsdpFacadeFor(t, vsw, "gs110emx")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	// --- GetPorts: link/speed only -- NSDP PORT_STATUS carries no name/
	// description, so AdminEnabled is always true and Description/Name are
	// always nil (mirroring nsdp.Reader's mapPorts contract exactly) even
	// though the seed's port 8 has a "rumpus" description at the State
	// layer -- that field simply isn't on the NSDP wire.
	ports, err := sw.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != 10 {
		t.Fatalf("len(GetPorts()) = %d, want 10", len(ports))
	}
	wantSpeed := map[int]int{6: 100, 8: 1000, 9: 10000, 10: 10000}
	for _, p := range ports {
		if !p.AdminEnabled {
			t.Errorf("port %d AdminEnabled = false, want true (NSDP always reports true)", p.Port)
		}
		if p.Description != nil {
			t.Errorf("port %d Description = %v, want nil (NSDP has no description tag)", p.Port, *p.Description)
		}
		wantMbps, linkUp := wantSpeed[p.Port]
		if p.LinkUp != linkUp {
			t.Errorf("port %d LinkUp = %v, want %v", p.Port, p.LinkUp, linkUp)
		}
		if linkUp {
			if p.SpeedMbps == nil || *p.SpeedMbps != wantMbps {
				t.Errorf("port %d SpeedMbps = %v, want %d", p.Port, derefInt(p.SpeedMbps), wantMbps)
			}
		} else if p.SpeedMbps != nil {
			t.Errorf("port %d SpeedMbps = %d, want nil (link down)", p.Port, *p.SpeedMbps)
		}
	}

	// --- GetStats: byte counters + CRC-as-RxErrors, no packet counters ---
	stats, err := sw.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	if len(stats) != 10 {
		t.Fatalf("len(GetStats()) = %d, want 10", len(stats))
	}
	var port9Stats *netgearswitch.PortStats
	for i := range stats {
		if stats[i].RxPackets != nil || stats[i].TxPackets != nil {
			t.Errorf("port %d has non-nil packet counters, want nil (NSDP has no packet counters)", stats[i].Port)
		}
		if stats[i].TxErrors != nil {
			t.Errorf("port %d TxErrors = %v, want nil (NSDP has no TX error counter)", stats[i].Port, *stats[i].TxErrors)
		}
		if stats[i].Port == 9 {
			port9Stats = &stats[i]
		}
	}
	if port9Stats == nil {
		t.Fatal("no port 9 in GetStats() result")
	}
	if port9Stats.RxBytes == nil || *port9Stats.RxBytes != 2_963_140_428_936 {
		t.Errorf("port 9 RxBytes = %v, want 2963140428936", port9Stats.RxBytes)
	}
	if port9Stats.TxBytes == nil || *port9Stats.TxBytes != 1_189_358_575_871 {
		t.Errorf("port 9 TxBytes = %v, want 1189358575871", port9Stats.TxBytes)
	}

	// --- GetVLANs: vlan 1 (untagged 1-8, tagged 9-10) + vlan 90 ---
	vlans, err := sw.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	vlan1 := findVlan(t, vlans, 1)
	if !equalIntSet(vlan1.UntaggedPorts, []int{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Errorf("vlan 1 UntaggedPorts = %v, want {1..8}", vlan1.UntaggedPorts)
	}
	if !equalIntSet(vlan1.TaggedPorts, []int{9, 10}) {
		t.Errorf("vlan 1 TaggedPorts = %v, want {9,10}", vlan1.TaggedPorts)
	}
	vlan90 := findVlan(t, vlans, 90)
	if !equalIntSet(vlan90.MemberPorts, []int{1, 2, 10}) {
		t.Errorf("vlan 90 MemberPorts = %v, want {1,2,10}", vlan90.MemberPorts)
	}
	if !equalIntSet(vlan90.UntaggedPorts, []int{1, 2}) {
		t.Errorf("vlan 90 UntaggedPorts = %v, want {1,2}", vlan90.UntaggedPorts)
	}

	// --- GetPVIDs: every port -> vlan 1 ---
	pvids, err := sw.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	if len(pvids) != 10 {
		t.Fatalf("len(GetPVIDs()) = %d, want 10", len(pvids))
	}
	for _, p := range pvids {
		if p.Vlan != 1 {
			t.Errorf("port %d PVID = %d, want 1", p.Port, p.Vlan)
		}
	}

	// --- GetMgmtIP: static 10.1.5.25/24 via 10.1.5.1 ---
	mgmt, err := sw.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Mode != netgearswitch.IPModeStatic {
		t.Errorf("GetMgmtIP().Mode = %v, want IPModeStatic", mgmt.Mode)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.25" {
		t.Errorf("GetMgmtIP().Address = %s, want 10.1.5.25", derefStr(mgmt.Address))
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != "10.1.5.1" {
		t.Errorf("GetMgmtIP().Gateway = %s, want 10.1.5.1", derefStr(mgmt.Gateway))
	}
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "BC:A5:11:B8:EC:F1" {
		t.Errorf("GetMgmtIP().BaseMac = %s, want BC:A5:11:B8:EC:F1 (upper-cased)", derefStr(mgmt.BaseMac))
	}
}

func findVlan(t *testing.T, vlans []netgearswitch.VLANInfo, id int) netgearswitch.VLANInfo {
	t.Helper()
	for _, v := range vlans {
		if v.VlanID == id {
			return v
		}
	}
	t.Fatalf("no vlan %d in GetVLANs() result", id)
	return netgearswitch.VLANInfo{}
}

func equalIntSet(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[int]bool{}
	for _, v := range got {
		seen[v] = true
	}
	for _, v := range want {
		if !seen[v] {
			return false
		}
	}
	return true
}

// --- gs110emx: unsupported reads raise -------------------------------------

func TestFacadeNSDPIntegration_GS110EMXUnsupportedReadsRaise(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs110emx")
	sw := nsdpFacadeFor(t, vsw, "gs110emx")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	// GetMACs is gated at the facade level BEFORE any dispatch (gs110emx has
	// no SNMP backend, so HasMACTable() is false) -- never even reaches NSDP.
	if _, err := sw.GetMACs(ctx); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetMACs() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	// GetLLDP/GetSensors/GetPoE: NSDP itself raises ErrUnsupportedCapability
	// for each (no LLDP/sensor/PoE tags exist), HTTP has no Go backend yet
	// in this slice, so the dispatch loop's last-recorded error is HTTP's
	// "no backend implementation yet" -- still ErrUnsupportedCapability,
	// still naming the model.
	if _, err := sw.GetLLDP(ctx); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetLLDP() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if _, err := sw.GetSensors(ctx); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetSensors() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if _, err := sw.GetPoE(ctx); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetPoE() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
}

// --- gs110emx: SetPVID/SetVlanMembership write+verify round-trip ----------

func TestFacadeNSDPIntegration_GS110EMXSetPVIDAndVlanMembershipRoundTrip(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs110emx")
	sw := nsdpFacadeFor(t, vsw, "gs110emx", withNSDPPassword("password")) // matches virtual.NewState's default NsdpPassword

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	if err := sw.SetPVID(ctx, 5, 90, netgearswitch.Write{}); err != nil {
		t.Fatalf("SetPVID(5, 90) error = %v", err)
	}
	pvids, err := sw.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	found := false
	for _, p := range pvids {
		if p.Port == 5 {
			if p.Vlan != 90 {
				t.Errorf("port 5 PVID = %d, want 90", p.Vlan)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("no port 5 in GetPVIDs() result after SetPVID")
	}

	if err := sw.SetVlanMembership(ctx, 90, 3, netgearswitch.VlanTagged, netgearswitch.Write{}); err != nil {
		t.Fatalf("SetVlanMembership(90, 3, tagged) error = %v", err)
	}
	vlans, err := sw.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	vlan90 := findVlan(t, vlans, 90)
	if !containsInt(vlan90.MemberPorts, 3) {
		t.Errorf("vlan 90 MemberPorts = %v, want to contain 3", vlan90.MemberPorts)
	}
	if !containsInt(vlan90.TaggedPorts, 3) {
		t.Errorf("vlan 90 TaggedPorts = %v, want to contain 3 (set tagged)", vlan90.TaggedPorts)
	}
}

// --- gs110emx: auth-failure path (wrong NSDP password -> typed error) -----

func TestFacadeNSDPIntegration_GS110EMXWrongPasswordRaisesTypedError(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs110emx")
	sw := nsdpFacadeFor(t, vsw, "gs110emx", withNSDPPassword("wrong-password"))

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	err := sw.SetPVID(ctx, 5, 90, netgearswitch.Write{})
	if err == nil {
		t.Fatal("SetPVID() with wrong password error = nil, want an error")
	}
	if !errors.Is(err, netgearswitch.ErrNSDP) {
		t.Errorf("SetPVID() error = %v, want wrapping ErrNSDP", err)
	}
	if errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Error("SetPVID() with wrong password must NOT be treated as an UnsupportedCapability skip -- it must propagate immediately (D-FAC rule 5)")
	}
	if !strings.Contains(err.Error(), "bad password") {
		t.Errorf("SetPVID() error = %q, want it to mention bad password", err.Error())
	}
}

// --- gs110emx: NSDPDevice() full aggregation --------------------------------

func TestFacadeNSDPIntegration_GS110EMXNSDPDeviceFullAggregation(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs110emx")
	sw := nsdpFacadeFor(t, vsw, "gs110emx")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	dev, err := sw.NSDPDevice(ctx)
	if err != nil {
		t.Fatalf("NSDPDevice() error = %v", err)
	}
	if dev.Model != "GS110EMX" {
		t.Errorf("NSDPDevice().Model = %q, want GS110EMX", dev.Model)
	}
	if dev.Mac != "bc:a5:11:b8:ec:f1" {
		t.Errorf("NSDPDevice().Mac = %q, want bc:a5:11:b8:ec:f1", dev.Mac)
	}
	if dev.Hostname == nil || *dev.Hostname != "sw-netgear-gs110emx1" {
		t.Errorf("NSDPDevice().Hostname = %s, want sw-netgear-gs110emx1", derefStr(dev.Hostname))
	}
	if dev.SerialNumber == nil || *dev.SerialNumber != "53H60253A0032" {
		t.Errorf("NSDPDevice().SerialNumber = %s, want 53H60253A0032", derefStr(dev.SerialNumber))
	}
	if dev.FirmwareVersion == nil || *dev.FirmwareVersion != "1.0.1.4" {
		t.Errorf("NSDPDevice().FirmwareVersion = %s, want 1.0.1.4", derefStr(dev.FirmwareVersion))
	}
	if dev.PortCount == nil || *dev.PortCount != 10 {
		t.Errorf("NSDPDevice().PortCount = %v, want 10", derefInt(dev.PortCount))
	}
	if dev.QosEngine == nil || *dev.QosEngine != 1 {
		t.Errorf("NSDPDevice().QosEngine = %v, want 1 (port-based)", derefInt(dev.QosEngine))
	}
	if dev.PortMirroring == nil {
		t.Fatal("NSDPDevice().PortMirroring = nil, want populated")
	}
	if dev.PortMirroring.DestinationPort != 10 {
		t.Errorf("NSDPDevice().PortMirroring.DestinationPort = %d, want 10", dev.PortMirroring.DestinationPort)
	}
	if !equalIntSet(dev.PortMirroring.SourcePorts, []int{1, 2}) {
		t.Errorf("NSDPDevice().PortMirroring.SourcePorts = %v, want {1,2}", dev.PortMirroring.SourcePorts)
	}
	if dev.IgmpSnooping == nil || !dev.IgmpSnooping.Enabled {
		t.Fatal("NSDPDevice().IgmpSnooping = nil/disabled, want enabled")
	}
	if dev.IgmpSnooping.VlanID == nil || *dev.IgmpSnooping.VlanID != 90 {
		t.Errorf("NSDPDevice().IgmpSnooping.VlanID = %v, want 90", dev.IgmpSnooping)
	}
	if dev.BroadcastFiltering == nil || !*dev.BroadcastFiltering {
		t.Error("NSDPDevice().BroadcastFiltering = false/nil, want true")
	}
	if dev.LoopDetection == nil || !*dev.LoopDetection {
		t.Error("NSDPDevice().LoopDetection = false/nil, want true")
	}
	if len(dev.PortStatus) != 10 {
		t.Errorf("len(NSDPDevice().PortStatus) = %d, want 10", len(dev.PortStatus))
	}
	if len(dev.VlanMembers) != 2 {
		t.Errorf("len(NSDPDevice().VlanMembers) = %d, want 2 (vlans 1 and 90)", len(dev.VlanMembers))
	}
}

func TestFacadeNSDPIntegration_GS110EMXNSDPDeviceRequiresNSDPBackendModel(t *testing.T) {
	// gsm7252ps is SNMP-only (no NSDP backend at all): NSDPDevice must
	// bypass dispatch and refuse directly, never attempting any I/O.
	m, err := netgearswitch.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("GetModel(\"gsm7252ps\") error = %v", err)
	}
	sw, err := netgearswitch.New(m, "127.0.0.1:1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()
	_, err = sw.NSDPDevice(ctx)
	if !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Fatalf("NSDPDevice() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
}

// --- gs305ep: every supported read, non-vacuous vs SeedGS305EP() ----------

func TestFacadeNSDPIntegration_GS305EPEveryReadNonVacuousVsSeed(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs305ep")
	sw := nsdpFacadeFor(t, vsw, "gs305ep")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	ports, err := sw.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != 5 {
		t.Fatalf("len(GetPorts()) = %d, want 5", len(ports))
	}
	for _, p := range ports {
		wantLink := p.Port == 1
		if p.LinkUp != wantLink {
			t.Errorf("port %d LinkUp = %v, want %v", p.Port, p.LinkUp, wantLink)
		}
		if wantLink && (p.SpeedMbps == nil || *p.SpeedMbps != 1000) {
			t.Errorf("port %d SpeedMbps = %v, want 1000", p.Port, derefInt(p.SpeedMbps))
		}
	}

	stats, err := sw.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	var port1Stats *netgearswitch.PortStats
	for i := range stats {
		if stats[i].Port == 1 {
			port1Stats = &stats[i]
		}
	}
	if port1Stats == nil {
		t.Fatal("no port 1 in GetStats() result")
	}
	if port1Stats.RxBytes == nil || *port1Stats.RxBytes != 1_000_000 {
		t.Errorf("port 1 RxBytes = %v, want 1000000", port1Stats.RxBytes)
	}
	if port1Stats.TxBytes == nil || *port1Stats.TxBytes != 2_000_000 {
		t.Errorf("port 1 TxBytes = %v, want 2000000", port1Stats.TxBytes)
	}

	vlans, err := sw.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	vlan1 := findVlan(t, vlans, 1)
	if !equalIntSet(vlan1.MemberPorts, []int{1, 2, 3, 4, 5}) {
		t.Errorf("vlan 1 MemberPorts = %v, want {1..5}", vlan1.MemberPorts)
	}
	if !equalIntSet(vlan1.TaggedPorts, []int{1, 2}) {
		t.Errorf("vlan 1 TaggedPorts = %v, want {1,2}", vlan1.TaggedPorts)
	}
	vlan90 := findVlan(t, vlans, 90)
	if !equalIntSet(vlan90.MemberPorts, []int{1, 2}) {
		t.Errorf("vlan 90 MemberPorts = %v, want {1,2}", vlan90.MemberPorts)
	}
	if len(vlan90.TaggedPorts) != 0 {
		t.Errorf("vlan 90 TaggedPorts = %v, want empty", vlan90.TaggedPorts)
	}

	pvids, err := sw.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	wantPvids := map[int]int{1: 90, 2: 90, 3: 1, 4: 1, 5: 1}
	if len(pvids) != len(wantPvids) {
		t.Fatalf("len(GetPVIDs()) = %d, want %d", len(pvids), len(wantPvids))
	}
	for _, p := range pvids {
		if p.Vlan != wantPvids[p.Port] {
			t.Errorf("port %d PVID = %d, want %d", p.Port, p.Vlan, wantPvids[p.Port])
		}
	}

	// gs305ep's seed leaves Mgmt at NewState's own default (0.0.0.0/dhcp,
	// NsdpMac 28:c6:8e:00:00:01) rather than inventing plausible values the
	// real device never had (SeedGS305EP's own doc comment) -- still a
	// genuinely populated, non-nil MgmtIP, just the honest "never
	// configured" default.
	mgmt, err := sw.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Mode != netgearswitch.IPModeDHCP {
		t.Errorf("GetMgmtIP().Mode = %v, want IPModeDHCP", mgmt.Mode)
	}
	if mgmt.Address == nil || *mgmt.Address != "0.0.0.0" {
		t.Errorf("GetMgmtIP().Address = %s, want 0.0.0.0", derefStr(mgmt.Address))
	}
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "28:C6:8E:00:00:01" {
		t.Errorf("GetMgmtIP().BaseMac = %s, want 28:C6:8E:00:00:01", derefStr(mgmt.BaseMac))
	}
}

// --- gs305ep: unsupported reads raise (PoE included: NSDP has no PoE tag,
// HTTP unimplemented in this slice, even though this model HAS PoE ports) --

func TestFacadeNSDPIntegration_GS305EPUnsupportedReadsRaise(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs305ep")
	sw := nsdpFacadeFor(t, vsw, "gs305ep")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	if _, err := sw.GetMACs(ctx); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetMACs() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if _, err := sw.GetLLDP(ctx); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetLLDP() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if _, err := sw.GetSensors(ctx); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetSensors() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if _, err := sw.GetPoE(ctx); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetPoE() error = %v, want wrapping ErrUnsupportedCapability (NSDP has no PoE tag; HTTP not implemented until slice 06)", err)
	}
}

// --- gs305ep: Snapshot populates NSDP-served fields, degrades the rest ----

func TestFacadeNSDPIntegration_GS305EPSnapshotPopulatesNSDPFields(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs305ep")
	sw := nsdpFacadeFor(t, vsw, "gs305ep")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	data, err := sw.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() error = %v, want nil (a capability gap degrades, it does not fail Snapshot)", err)
	}
	if data.Model != "gs305ep" {
		t.Errorf("Snapshot().Model = %q, want gs305ep", data.Model)
	}
	if len(data.Ports) != 5 {
		t.Errorf("Snapshot().Ports len = %d, want 5 (served by NSDP)", len(data.Ports))
	}
	if len(data.Stats) != 5 {
		t.Errorf("Snapshot().Stats len = %d, want 5 (served by NSDP)", len(data.Stats))
	}
	if len(data.Vlans) != 2 {
		t.Errorf("Snapshot().Vlans len = %d, want 2 (served by NSDP)", len(data.Vlans))
	}
	if len(data.Pvids) != 5 {
		t.Errorf("Snapshot().Pvids len = %d, want 5 (served by NSDP)", len(data.Pvids))
	}
	if data.MgmtIP == nil {
		t.Error("Snapshot().MgmtIP is nil, want populated (served by NSDP)")
	}
	// HTTP-only surfaces (no Go HTTP backend until slice 06): every one of
	// these degrades to empty, even though gs305ep DOES have real PoE ports
	// at the hardware level -- NSDP just can't serve that field.
	if len(data.Lldp) != 0 {
		t.Errorf("Snapshot().Lldp = %v, want empty", data.Lldp)
	}
	if len(data.Macs) != 0 {
		t.Errorf("Snapshot().Macs = %v, want empty", data.Macs)
	}
	if len(data.PoE) != 0 {
		t.Errorf("Snapshot().PoE = %v, want empty (NSDP has no PoE tag)", data.PoE)
	}
	if len(data.Sensors) != 0 {
		t.Errorf("Snapshot().Sensors = %v, want empty", data.Sensors)
	}
}
