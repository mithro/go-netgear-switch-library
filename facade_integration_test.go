// facade_integration_test.go: the slice-03 capstone -- the root netgearswitch
// facade (Switch/New/Snapshot/Identify/DetectModel) driven end-to-end against
// a REAL virtual.VirtualSwitch over real UDP, proving the facade's dispatch
// seam (dispatch.go/backend_snmp.go/snapshot.go/detect.go) is wired correctly
// on top of the already-capstoned snmp.Reader (see snmp/integration_test.go,
// whose pinned literal values this file reuses verbatim rather than
// re-deriving them from the hardware capture) -- never a vacuous pass. Per
// Task 4's brief and D-FAC (docs/superpowers/plans/
// 2026-07-30-slice-03-dossier-facade.md).
//
// package netgearswitch_test (external) so this exercises the facade exactly
// as an external caller would, and can import both the root module and
// `virtual` (which itself imports `snmp`) without an import cycle.
package netgearswitch_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// facadeTestTimeout mirrors snmp/integration_test.go's testTimeout: generous
// enough for a loopback UDP round trip under `make test`'s CPU/memory-jailed
// environment, short enough that a genuine deadlock still fails the test.
const facadeTestTimeout = 10 * time.Second

// startVirtualSwitch builds and starts a virtual.VirtualSwitch for modelKey,
// registering t.Cleanup to stop it -- the same helper shape as
// snmp/integration_test.go's startSwitch (duplicated here rather than shared
// across packages, since Go test helpers aren't exported).
func startVirtualSwitch(t *testing.T, modelKey string) *virtual.VirtualSwitch {
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

// facadeFor constructs a *netgearswitch.Switch bound to modelKey, talking to
// vsw's live SNMP face over "host:port" -- proving the facade's default SNMP
// client builder (backend_snmp.go's buildSNMPClient -> snmp.NewGoSNMPClient)
// accepts a "host:port" address, not just a bare host.
func facadeFor(t *testing.T, vsw *virtual.VirtualSwitch, modelKey string) *netgearswitch.Switch {
	t.Helper()
	m, err := netgearswitch.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q) error = %v", modelKey, err)
	}
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	sw, err := netgearswitch.New(m, host, netgearswitch.WithSNMPCommunity("public"))
	if err != nil {
		t.Fatalf("New(%q) error = %v", modelKey, err)
	}
	return sw
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

// TestFacadeIntegration_GSM7252PSEveryReadMatchesSNMPCapstonePins drives
// every facade read method against a live gsm7252ps VirtualSwitch and checks
// the SAME literal pin values snmp/integration_test.go's
// TestGSM7252PSCapstoneEveryReadOpIsNonVacuousAndPinnedToSeedData already
// verified at the snmp.Reader layer -- this time through the FULL facade
// dispatch seam (Switch.readVia -> backend_snmp.go's buildSNMPReader ->
// snmp.NewReader), proving the facade adds no vacuous indirection: what the
// reader returns is exactly what the facade surfaces.
func TestFacadeIntegration_GSM7252PSEveryReadMatchesSNMPCapstonePins(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := facadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	// --- GetPorts: port1 name/description pin, plus an honestly-nil ifAlias ---
	ports, err := sw.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) == 0 {
		t.Fatal("GetPorts() returned no ports, want non-empty")
	}
	var port1 *netgearswitch.PortStatus
	foundNilDesc := false
	for i := range ports {
		if ports[i].Port == 1 {
			port1 = &ports[i]
		}
		if ports[i].Description == nil {
			foundNilDesc = true
		}
	}
	if port1 == nil {
		t.Fatal("no port 1 in GetPorts() result")
	}
	if port1.Name == nil || *port1.Name != "1/0/1" {
		t.Errorf("port1.Name = %s, want \"1/0/1\"", derefStr(port1.Name))
	}
	if port1.Description == nil || *port1.Description != "eth0.rpi5-pmod" {
		t.Errorf("port1.Description = %s, want \"eth0.rpi5-pmod\"", derefStr(port1.Description))
	}
	if !foundNilDesc {
		t.Error("every port has a non-nil Description; want at least one honestly-nil (never-configured) ifAlias")
	}

	// --- GetStats: non-vacuous ---
	stats, err := sw.GetStats(ctx)
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
	vlans, err := sw.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	var vlan90 *netgearswitch.VLANInfo
	for i := range vlans {
		if vlans[i].VlanID == 90 {
			vlan90 = &vlans[i]
		}
	}
	if vlan90 == nil {
		t.Fatal("no vlan 90 in GetVLANs() result")
	}
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
	pvids, err := sw.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	if len(pvids) == 0 {
		t.Fatal("GetPVIDs() returned no pvids, want non-empty")
	}

	// --- GetMgmtIP: address/mode/base-MAC pins ---
	mgmt, err := sw.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.22" {
		t.Errorf("mgmt.Address = %s, want \"10.1.5.22\"", derefStr(mgmt.Address))
	}
	if mgmt.Mode != netgearswitch.IPModeStatic {
		t.Errorf("mgmt.Mode = %v, want IPModeStatic", mgmt.Mode)
	}
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "E0:91:F5:0C:D6:DB" {
		t.Errorf("mgmt.BaseMac = %s, want \"E0:91:F5:0C:D6:DB\"", derefStr(mgmt.BaseMac))
	}

	// --- GetPoE: port1 delivering 3500 mW ---
	poe, err := sw.GetPoE(ctx)
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	var poe1 *netgearswitch.PoEStatus
	for i := range poe {
		if poe[i].Port == 1 {
			poe1 = &poe[i]
		}
	}
	if poe1 == nil {
		t.Fatal("no PoE port 1 in GetPoE() result")
	}
	if !poe1.Delivering() {
		t.Errorf("poe1.Detect = %v, want Delivering", poe1.Detect)
	}
	if poe1.PowerMw == nil || *poe1.PowerMw != 3500 {
		t.Errorf("poe1.PowerMw = %s, want 3500", derefInt(poe1.PowerMw))
	}

	// --- GetSensors: non-vacuous ---
	sensors, err := sw.GetSensors(ctx)
	if err != nil {
		t.Fatalf("GetSensors() error = %v", err)
	}
	if len(sensors) == 0 {
		t.Fatal("GetSensors() returned no sensors, want non-empty")
	}

	// --- GetMACs: the non-identity bridge-port -> ifIndex join proof ---
	macs, err := sw.GetMACs(ctx)
	if err != nil {
		t.Fatalf("GetMACs() error = %v", err)
	}
	var mac *netgearswitch.MacEntry
	for i := range macs {
		if macs[i].Mac == "C8:00:84:89:71:70" {
			mac = &macs[i]
		}
	}
	if mac == nil {
		t.Fatal("no MAC C8:00:84:89:71:70 in GetMACs() result")
	}
	if mac.Port != 110 {
		t.Errorf("MAC C8:00:84:89:71:70 joined to port %d, want 110 (bridge_port 10 -> ifIndex 110, never the bare bridge port)", mac.Port)
	}

	// --- GetLLDP: remote_port_id distinct from remote_port_desc, sys_name pin ---
	lldp, err := sw.GetLLDP(ctx)
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

	// --- Identify: model detection, deliberately bypassing s.model's gate ---
	detected, err := sw.Identify(ctx)
	if err != nil {
		t.Fatalf("Identify() error = %v", err)
	}
	if detected.Key == nil || *detected.Key != "gsm7252ps" {
		t.Errorf("Identify().Key = %s, want \"gsm7252ps\"", derefStr(detected.Key))
	}
}

// TestFacadeIntegration_GSM7252PSSnapshotFullyPopulated proves Snapshot on a
// fully-managed, all-backends-served model (gsm7252ps: SNMP serves every op)
// populates EVERY SwitchData field non-vacuously -- the "everything present"
// counterpart to the m4300-24x/gs110emx degrade tests below, so this file
// pins both ends of Snapshot's per-field degrade-to-empty behavior (D-FAC
// §2.12), not just the failure side.
func TestFacadeIntegration_GSM7252PSSnapshotFullyPopulated(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := facadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	data, err := sw.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}

	if data.Model != "gsm7252ps" {
		t.Errorf("Snapshot().Model = %q, want \"gsm7252ps\"", data.Model)
	}
	if data.Host == "" {
		t.Error("Snapshot().Host is empty, want the host:port this Switch was constructed with")
	}
	if len(data.Ports) == 0 {
		t.Error("Snapshot().Ports is empty, want populated")
	}
	if len(data.Stats) == 0 {
		t.Error("Snapshot().Stats is empty, want populated")
	}
	if len(data.Vlans) == 0 {
		t.Error("Snapshot().Vlans is empty, want populated")
	}
	if len(data.Pvids) == 0 {
		t.Error("Snapshot().Pvids is empty, want populated")
	}
	if len(data.Lldp) == 0 {
		t.Error("Snapshot().Lldp is empty, want populated")
	}
	if len(data.Macs) == 0 {
		t.Error("Snapshot().Macs is empty, want populated")
	}
	if len(data.PoE) == 0 {
		t.Error("Snapshot().PoE is empty, want populated")
	}
	if len(data.Sensors) == 0 {
		t.Error("Snapshot().Sensors is empty, want populated")
	}
	if data.MgmtIP == nil {
		t.Error("Snapshot().MgmtIP is nil, want populated")
	}
}

// TestFacadeIntegration_M4300_24XSnapshotDegradesPoEWhileGetPoEErrors proves
// the D-FAC §2.12 degrade contract on a REAL (if partial-capability) model:
// m4300-24x has 0 PSE ports, so GetPoE() itself must fail wrapping
// ErrUnsupportedCapability (mirroring snmp/integration_test.go's
// TestM4300_24XGetPoEIsUnsupportedCapability one layer up, through the
// facade), while Snapshot -- which calls the SAME dispatch path internally --
// must degrade that one field to an empty slice and still return every OTHER
// field populated, with no error at all.
func TestFacadeIntegration_M4300_24XSnapshotDegradesPoEWhileGetPoEErrors(t *testing.T) {
	vsw := startVirtualSwitch(t, "m4300-24x")
	sw := facadeFor(t, vsw, "m4300-24x")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	_, err := sw.GetPoE(ctx)
	if !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Fatalf("GetPoE() on m4300-24x (0 PSE ports) error = %v, want wrapping ErrUnsupportedCapability", err)
	}

	data, err := sw.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() error = %v, want nil (a capability gap degrades, it does not fail Snapshot)", err)
	}
	if len(data.PoE) != 0 {
		t.Errorf("Snapshot().PoE = %v, want empty (m4300-24x has 0 PSE ports)", data.PoE)
	}
	// Every other field is well within m4300-24x's real SNMP capability, so
	// Snapshot must not have degraded those too -- otherwise this test would
	// pass vacuously even if Snapshot degraded EVERYTHING to empty.
	if len(data.Ports) == 0 {
		t.Error("Snapshot().Ports is empty, want populated (m4300-24x serves get_ports over SNMP)")
	}
	if len(data.Stats) == 0 {
		t.Error("Snapshot().Stats is empty, want populated (m4300-24x serves get_stats over SNMP)")
	}
	if len(data.Sensors) == 0 {
		t.Error("Snapshot().Sensors is empty, want populated (m4300-24x serves get_sensors over SNMP)")
	}
	if data.MgmtIP == nil {
		t.Error("Snapshot().MgmtIP is nil, want populated (m4300-24x serves get_mgmt_ip over SNMP)")
	}
}

// TestFacadeIntegration_GS110EMXNSDPServesReadsHTTPStillDegrades supersedes
// this test's slice-03/04 predecessor (formerly
// TestFacadeIntegration_GS110EMXHonestFailure, which asserted EVERY read
// failed with ErrUnsupportedCapability because neither of gs110emx's two
// backends -- NSDP, HTTP -- had a Go implementation yet). Slice 05 added the
// NSDP backend (backend_nsdp.go), so that premise is now HALF false: gs110emx
// is genuinely {NSDP, HTTP}-only (no SNMP backend at all -- see
// model/registry.go), and NSDP now serves ports/stats/vlans/pvids/mgmt-ip for
// real. The HTTP backend is fully implemented too (webui/backend_http.go),
// but MACs/LLDP/Sensors/PoE still fail/degrade on THIS model regardless: its
// own web UI genuinely has no page for any of the four (capabilities.Matrix
// marks all four Unsupported on HTTP, not just NSDP -- an exhaustive-tag-
// sweep-confirmed hardware gap on this specific SKU, the same standard
// NSDP's own Unsupported verdicts here already carry). This test proves
// BOTH halves of that updated contract against a REAL live gs110emx
// VirtualSwitch: NSDP-servable reads succeed and Snapshot populates their
// fields, while the four reads with no page on either backend still
// fail/degrade exactly as before -- Snapshot's per-field degrade behavior
// (D-FAC §2.12) is honest in BOTH directions, not just the "everything
// fails" one.
// See facade_nsdp_integration_test.go for the full per-field capstone this
// test deliberately does not re-derive in detail.
func TestFacadeIntegration_GS110EMXNSDPServesReadsHTTPStillDegrades(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs110emx")
	sw := nsdpFacadeFor(t, vsw, "gs110emx")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	ports, err := sw.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() on gs110emx error = %v, want nil (NSDP now serves this op)", err)
	}
	if len(ports) == 0 {
		t.Error("GetPorts() on gs110emx returned no ports, want the 10-port NSDP seed")
	}

	// GetMACs is gated at the facade level before any dispatch (gs110emx has
	// no SNMP backend, so HasMACTable() is false); GetLLDP/GetSensors/GetPoE
	// resolve to NSDP (gs110emx's default backend: NSDP+HTTP, NSDP wins) and
	// NSDP itself raises ErrUnsupportedCapability for each -- under
	// single-backend dispatch (D-REC Topic A) this is a hard stop, never a
	// fall-through attempt at HTTP: an honest ErrUnsupportedCapability naming
	// NSDP. HTTP is fully implemented and registered, but that fall-through
	// would not have helped here anyway -- gs110emx's web UI has no page for
	// any of these three ops either (capabilities.Matrix marks all three
	// Unsupported on HTTP too, the same hardware gap NSDP's own verdict
	// reflects).
	if _, err := sw.GetMACs(ctx); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetMACs() on gs110emx error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if _, err := sw.GetLLDP(ctx); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetLLDP() on gs110emx error = %v, want wrapping ErrUnsupportedCapability", err)
	}

	data, err := sw.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() on gs110emx error = %v, want nil (every field either populates or honestly degrades)", err)
	}
	// NSDP-served fields: now populated, unlike the pre-slice-05 contract.
	if len(data.Ports) == 0 {
		t.Error("Snapshot().Ports is empty, want populated (gs110emx serves get_ports over NSDP as of slice 05)")
	}
	if len(data.Stats) == 0 {
		t.Error("Snapshot().Stats is empty, want populated (NSDP)")
	}
	if len(data.Vlans) == 0 {
		t.Error("Snapshot().Vlans is empty, want populated (NSDP)")
	}
	if len(data.Pvids) == 0 {
		t.Error("Snapshot().Pvids is empty, want populated (NSDP)")
	}
	if data.MgmtIP == nil {
		t.Error("Snapshot().MgmtIP is nil, want populated (NSDP)")
	}
	// These fields degrade to empty under Snapshot's default (NSDP) dispatch
	// AND would still degrade even given an explicit HTTP request: gs110emx's
	// web UI genuinely has no page for any of them (capabilities.Matrix marks
	// all three Unsupported on HTTP too, not just NSDP).
	if len(data.Lldp) != 0 {
		t.Errorf("Snapshot().Lldp = %v, want empty (no HTTP page for get_lldp on gs110emx)", data.Lldp)
	}
	if len(data.Macs) != 0 {
		t.Errorf("Snapshot().Macs = %v, want empty (gs110emx has no MAC table on any backend)", data.Macs)
	}
	if len(data.PoE) != 0 {
		t.Errorf("Snapshot().PoE = %v, want empty (NSDP has no PoE tag; no HTTP page for get_poe on gs110emx either)", data.PoE)
	}
	if len(data.Sensors) != 0 {
		t.Errorf("Snapshot().Sensors = %v, want empty (no HTTP page for get_sensors on gs110emx)", data.Sensors)
	}
	if data.Model != "gs110emx" {
		t.Errorf("Snapshot().Model = %q, want \"gs110emx\"", data.Model)
	}
}

// TestFacadeIntegration_DetectModelLiveBySysObjectIDAgainstGSM7228PS proves
// the free-function DetectModel discovery entry point (detect.go) works
// end-to-end against a live virtual switch for gsm7228ps -- whose real
// captured sysDescr text is DELIBERATELY unmatchable by the sysDescr-text
// heuristic (model/registry.go's own doc comment), so a passing Key here
// proves DetectModel really does try sysObjectID FIRST, exactly mirroring
// snmp/integration_test.go's
// TestDetectModelBySysObjectIDFirstAgainstGSM7228PS one layer down, through
// the facade's own DetectModel wrapper instead of calling snmp.ReadSystemInfo
// directly.
func TestFacadeIntegration_DetectModelLiveBySysObjectIDAgainstGSM7228PS(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	detected, err := netgearswitch.DetectModel(ctx, host, netgearswitch.WithDetectCommunity("public"))
	if err != nil {
		t.Fatalf("DetectModel() error = %v", err)
	}
	if detected.Key == nil || *detected.Key != "gsm7228ps" {
		t.Errorf("DetectModel().Key = %s, want \"gsm7228ps\"", derefStr(detected.Key))
	}
	if detected.SysObjectID == nil || *detected.SysObjectID != "1.3.6.1.4.1.4526.100.10.19" {
		t.Errorf("DetectModel().SysObjectID = %s, want \"1.3.6.1.4.1.4526.100.10.19\"", derefStr(detected.SysObjectID))
	}
}

// TestFacadeIntegration_IdentifyReflectsDeviceNotBoundModel proves
// Switch.Identify's D-FAC §2.11 bypass end-to-end: a facade constructed
// bound to "gsm7252ps" (this test's model argument to New), but actually
// talking to a live gsm7228ps virtual switch, must have Identify() report the
// DEVICE's real model (gsm7228ps via sysObjectID), never the model the
// facade happens to have been constructed with -- proving Identify truly
// bypasses s.model's own SNMP-backend gate/dispatch entirely rather than
// just happening to agree with it.
func TestFacadeIntegration_IdentifyReflectsDeviceNotBoundModel(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	sw := facadeFor(t, vsw, "gsm7252ps") // deliberately bound to the WRONG model

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	detected, err := sw.Identify(ctx)
	if err != nil {
		t.Fatalf("Identify() error = %v", err)
	}
	if detected.Key == nil || *detected.Key != "gsm7228ps" {
		t.Errorf("Identify().Key = %s, want \"gsm7228ps\" (the DEVICE's real model, not the bound \"gsm7252ps\")", derefStr(detected.Key))
	}
}

// --- small lookup helpers shared by the tests above -----------------------

func containsInt(xs []int, want int) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
