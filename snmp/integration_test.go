// Package snmp_test holds the SNMP read-core capstone: GoSNMPClient +
// Reader driven against a REAL virtual.VirtualSwitch's SNMP face over real
// UDP, proving every read method this slice adds is non-vacuous against
// genuine hardware-capture-derived seed data -- never a vacuous []==[]
// pass. Ported from the Python reference's
// tests/test_snmp_integration.py, per D-SNMP §6.14 and Task 13's brief.
//
// package snmp_test (external, not the internal `snmp` package) so this
// test exercises the package's public API exactly as an external caller
// would, and can import both `snmp` and `virtual` (which itself imports
// `snmp`) without an import cycle -- a plain `package snmp` file could not
// also import `virtual`.
package snmp_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// testTimeout bounds every ctx used against a live virtual-switch face in
// this file: generous enough for a loopback UDP round trip under `make
// test`'s CPU/memory-jailed environment, short enough that a genuine
// deadlock still fails the test instead of hanging the suite.
const testTimeout = 10 * time.Second

// startSwitch builds and starts a virtual.VirtualSwitch for modelKey,
// registering t.Cleanup to stop it (Go's nearest equivalent to the Python
// reference's `with VirtualSwitch(...) as sw:`/conftest.py fixture).
func startSwitch(t *testing.T, modelKey string) *virtual.VirtualSwitch {
	t.Helper()
	sw, err := virtual.NewVirtualSwitch(modelKey)
	if err != nil {
		t.Fatalf("virtual.NewVirtualSwitch(%q) error = %v", modelKey, err)
	}
	if err := sw.Start(); err != nil {
		t.Fatalf("VirtualSwitch.Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Errorf("VirtualSwitch.Stop() error = %v", err)
		}
	})
	return sw
}

// readerAndClientFor builds a snmp.GoSNMPClient + snmp.Reader wired to sw's
// live SNMP face for modelKey.
func readerAndClientFor(t *testing.T, sw *virtual.VirtualSwitch, modelKey string) (*snmp.Reader, *snmp.GoSNMPClient) {
	t.Helper()
	m, err := model.GetModel(modelKey)
	if err != nil {
		t.Fatalf("model.GetModel(%q) error = %v", modelKey, err)
	}
	client := snmp.NewGoSNMPClient(fmt.Sprintf("%s:%d", sw.Host, sw.SnmpPort), "public")
	reader, err := snmp.NewReader(client, m)
	if err != nil {
		t.Fatalf("snmp.NewReader(%q) error = %v", modelKey, err)
	}
	return reader, client
}

// TestGSM7252PSCapstoneEveryReadOpIsNonVacuousAndPinnedToSeedData is the
// D-SNMP §6.14 capstone: every Reader method, driven over a real UDP
// round-trip against VirtualSwitch("gsm7252ps"), must return non-empty
// (never vacuously "passing" on an empty result) AND match the exact pins
// transcribed from the real hardware capture (D-VIRT §4.1).
func TestGSM7252PSCapstoneEveryReadOpIsNonVacuousAndPinnedToSeedData(t *testing.T) {
	sw := startSwitch(t, "gsm7252ps")
	reader, client := readerAndClientFor(t, sw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// --- GetPorts: port1 name/description pin, plus an honestly-nil ifAlias ---
	ports, err := reader.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) == 0 {
		t.Fatal("GetPorts() returned no ports, want non-empty")
	}
	port1 := findPort(t, ports, 1)
	if port1.Name == nil || *port1.Name != "1/0/1" {
		t.Errorf("port1.Name = %s, want \"1/0/1\"", derefStr(port1.Name))
	}
	if port1.Description == nil || *port1.Description != "eth0.rpi5-pmod" {
		t.Errorf("port1.Description = %s, want \"eth0.rpi5-pmod\"", derefStr(port1.Description))
	}
	foundNilDesc := false
	for _, p := range ports {
		if p.Description == nil {
			foundNilDesc = true
			break
		}
	}
	if !foundNilDesc {
		t.Error("every port has a non-nil Description; want at least one honestly-nil (never-configured) ifAlias")
	}

	// --- GetStats: non-vacuous ---
	stats, err := reader.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	populated := 0
	for _, s := range stats {
		if s.RxBytes != nil {
			populated++
		}
	}
	if populated == 0 {
		t.Error("GetStats(): no port has a non-nil RxBytes, want at least one populated")
	}

	// --- GetVLANs: vlan 90 "iot", member contains port 11 but NOT port 10 ---
	vlans, err := reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	if len(vlans) == 0 {
		t.Fatal("GetVLANs() returned no VLANs, want non-empty")
	}
	vlan90 := findVlan(t, vlans, 90)
	if vlan90.Name == nil || *vlan90.Name != "iot" {
		t.Errorf("vlan90.Name = %s, want \"iot\"", derefStr(vlan90.Name))
	}
	if !containsInt(vlan90.MemberPorts, 11) {
		t.Errorf("vlan90.MemberPorts = %v, want it to contain port 11", vlan90.MemberPorts)
	}
	if containsInt(vlan90.MemberPorts, 10) {
		t.Errorf("vlan90.MemberPorts = %v, want it to NOT contain port 10", vlan90.MemberPorts)
	}

	// --- GetPVIDs: non-vacuous ---
	pvids, err := reader.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	if len(pvids) == 0 {
		t.Fatal("GetPVIDs() returned no pvids, want non-empty")
	}

	// --- GetMgmtIP: address/mode/base-MAC pins ---
	mgmt, err := reader.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.22" {
		t.Errorf("mgmt.Address = %s, want \"10.1.5.22\"", derefStr(mgmt.Address))
	}
	if mgmt.Mode != model.IPModeStatic {
		t.Errorf("mgmt.Mode = %v, want IPModeStatic", mgmt.Mode)
	}
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "E0:91:F5:0C:D6:DB" {
		t.Errorf("mgmt.BaseMac = %s, want \"E0:91:F5:0C:D6:DB\"", derefStr(mgmt.BaseMac))
	}

	// --- GetPoE: port1 delivering 3500 mW ---
	poe, err := reader.GetPoE(ctx)
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	if len(poe) == 0 {
		t.Fatal("GetPoE() returned no ports, want non-empty")
	}
	poe1 := findPoe(t, poe, 1)
	if !poe1.Delivering() {
		t.Errorf("poe1.Detect = %v, want Delivering", poe1.Detect)
	}
	if poe1.PowerMw == nil || *poe1.PowerMw != 3500 {
		t.Errorf("poe1.PowerMw = %s, want 3500", derefInt(poe1.PowerMw))
	}

	// --- GetSensors: non-vacuous ---
	sensors, err := reader.GetSensors(ctx)
	if err != nil {
		t.Fatalf("GetSensors() error = %v", err)
	}
	if len(sensors) == 0 {
		t.Fatal("GetSensors() returned no sensors, want non-empty")
	}

	// --- GetMACs: the non-identity bridge-port -> ifIndex join proof ---
	// (bridge_port 10 -> ifIndex 110, D-VIRT §4.1's deliberate regression
	// trap: a reader that forgot the dot1dBasePortIfIndex join, or fell
	// back to the bare bridge-port number, would surface .Port == 10 here.)
	macs, err := reader.GetMACs(ctx)
	if err != nil {
		t.Fatalf("GetMACs() error = %v", err)
	}
	if len(macs) == 0 {
		t.Fatal("GetMACs() returned no entries, want non-empty")
	}
	mac := findMac(t, macs, "C8:00:84:89:71:70")
	if mac.Port != 110 {
		t.Errorf("MAC C8:00:84:89:71:70 joined to port %d, want 110 (bridge_port 10 -> ifIndex 110, never the bare bridge port)", mac.Port)
	}

	// --- GetLLDP: remote_port_id distinct from remote_port_desc, sys_name pin ---
	lldp, err := reader.GetLLDP(ctx)
	if err != nil {
		t.Fatalf("GetLLDP() error = %v", err)
	}
	if len(lldp) == 0 {
		t.Fatal("GetLLDP() returned no neighbors, want non-empty")
	}
	nb := lldp[0]
	if nb.RemotePortID == nil || *nb.RemotePortID != "1/xg51" {
		t.Errorf("lldp[0].RemotePortID = %s, want \"1/xg51\"", derefStr(nb.RemotePortID))
	}
	if nb.RemotePortDesc == nil || *nb.RemotePortDesc != "eth0" {
		t.Errorf("lldp[0].RemotePortDesc = %s, want \"eth0\"", derefStr(nb.RemotePortDesc))
	}
	if nb.RemotePortID != nil && nb.RemotePortDesc != nil && *nb.RemotePortID == *nb.RemotePortDesc {
		t.Error("lldp[0].RemotePortID == RemotePortDesc, want them distinct")
	}
	if nb.RemoteSysName == nil || *nb.RemoteSysName != "sw-cisco-shed" {
		t.Errorf("lldp[0].RemoteSysName = %s, want \"sw-cisco-shed\"", derefStr(nb.RemoteSysName))
	}

	// --- ReadSystemInfo: model detection ---
	detected, err := snmp.ReadSystemInfo(ctx, client)
	if err != nil {
		t.Fatalf("ReadSystemInfo() error = %v", err)
	}
	if detected.Key == nil || *detected.Key != "gsm7252ps" {
		t.Errorf("ReadSystemInfo().Key = %s, want \"gsm7252ps\"", derefStr(detected.Key))
	}
}

// TestM4300_24XASCIIBaseMacEndToEnd pins the VERIFIED M4300-24X wire quirk
// (D-VIRT §1.3/§4.3): dot1dBaseBridgeAddress answers as 17-char ASCII
// colon-hex TEXT rather than 6 raw OCTET STRING bytes, end-to-end through a
// live mock SNMP agent, real UDP transport and the Reader/parser stack --
// not just a synthetic unit-test row.
func TestM4300_24XASCIIBaseMacEndToEnd(t *testing.T) {
	sw := startSwitch(t, "m4300-24x")
	reader, _ := readerAndClientFor(t, sw, "m4300-24x")

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	mgmt, err := reader.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "8C:3B:AD:6B:BB:E0" {
		t.Errorf("mgmt.BaseMac = %s, want \"8C:3B:AD:6B:BB:E0\" (VERIFIED M4300-24X ASCII colon-hex dot1dBaseBridgeAddress quirk)", derefStr(mgmt.BaseMac))
	}
}

// TestM4300_24XGetPoEIsUnsupportedCapability pins the 0-PSE-port guard
// (D-VIRT §4.3: poe={} VERIFIED no PoE) end-to-end: GetPoE must raise
// BEFORE any walk, consistent with the CLI/HTTP readers (never a silent
// []), against a real live mock agent, not just a FakeClient.
func TestM4300_24XGetPoEIsUnsupportedCapability(t *testing.T) {
	sw := startSwitch(t, "m4300-24x")
	reader, _ := readerAndClientFor(t, sw, "m4300-24x")

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	_, err := reader.GetPoE(ctx)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("GetPoE() on m4300-24x (0 PSE ports) error = %v, want wrapping model.ErrUnsupportedCapability", err)
	}
}

// TestDetectModelBySysObjectIDFirstAgainstGSM7228PS pins sysObjectID-first
// model detection end-to-end: gsm7228ps's real captured sysDescr text
// ("S3300-52X-PoE+ ...") is DELIBERATELY unmatchable by the sysDescr text
// heuristic (same shape as the unregistered S3300-28X, per
// model/registry.go's gsm7228ps doc comment) -- only the authoritative
// sysObjectID map identifies it, so a passing key here proves
// ReadSystemInfo really does try sysObjectID FIRST, not sysDescr.
func TestDetectModelBySysObjectIDFirstAgainstGSM7228PS(t *testing.T) {
	sw := startSwitch(t, "gsm7228ps")
	client := snmp.NewGoSNMPClient(fmt.Sprintf("%s:%d", sw.Host, sw.SnmpPort), "public")

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	detected, err := snmp.ReadSystemInfo(ctx, client)
	if err != nil {
		t.Fatalf("ReadSystemInfo() error = %v", err)
	}
	if detected.Key == nil || *detected.Key != "gsm7228ps" {
		t.Errorf("ReadSystemInfo().Key = %s, want \"gsm7228ps\"", derefStr(detected.Key))
	}
	if detected.SysObjectID == nil || *detected.SysObjectID != "1.3.6.1.4.1.4526.100.10.19" {
		t.Errorf("ReadSystemInfo().SysObjectID = %s, want \"1.3.6.1.4.1.4526.100.10.19\"", derefStr(detected.SysObjectID))
	}
}

// --- small lookup/dereference helpers shared by the tests above -----------

func findPort(t *testing.T, ports []model.PortStatus, port int) model.PortStatus {
	t.Helper()
	for _, p := range ports {
		if p.Port == port {
			return p
		}
	}
	t.Fatalf("no port %d in GetPorts() result", port)
	return model.PortStatus{}
}

func findVlan(t *testing.T, vlans []model.VLANInfo, vlanID int) model.VLANInfo {
	t.Helper()
	for _, v := range vlans {
		if v.VlanID == vlanID {
			return v
		}
	}
	t.Fatalf("no vlan %d in GetVLANs() result", vlanID)
	return model.VLANInfo{}
}

func findPoe(t *testing.T, poe []model.PoEStatus, port int) model.PoEStatus {
	t.Helper()
	for _, p := range poe {
		if p.Port == port {
			return p
		}
	}
	t.Fatalf("no PoE port %d in GetPoE() result", port)
	return model.PoEStatus{}
}

func findMac(t *testing.T, macs []model.MacEntry, mac string) model.MacEntry {
	t.Helper()
	for _, m := range macs {
		if m.Mac == mac {
			return m
		}
	}
	t.Fatalf("no MAC %q in GetMACs() result", mac)
	return model.MacEntry{}
}

func containsInt(xs []int, want int) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func derefStr(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func derefInt(p *int) string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%d", *p)
}
