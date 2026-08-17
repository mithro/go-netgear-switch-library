package virtual

// Grounding tests for the five capture-grounded seeds (Task 11), mirroring
// the intents of the Python reference's tests/virtual/test_state_seed.py
// and tests/virtual/test_m4300_seeds.py: every port/PVID/VLAN-membership/
// PoE-port/sensor/mgmt-IP value each seed defines is checked against a
// committed real-hardware capture (see testdata/captures/), plus a set of
// specific pins that exercise the OIDMap -> snmp-parser round-trip end to
// end (Task 5-9's read ops fed by this virtual state, ahead of the SNMP
// face itself in a later slice).
//
// gs728tpp has no committed capture JSON at the pinned Python revision (see
// testdata/captures/README.md) -- it is grounded only by direct structural
// assertions against the values already transcribed into seed.go, not by
// assertSeedMatchesCapture.

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// --- capture-parity harness (D-VIRT-equivalent of tests/capture_parity.py) -----

// captureFixture mirrors a committed capture file's top-level shape (see
// testdata/captures/README.md): {model, host, snapshot, note}. Snapshot is
// a model.SwitchData-shaped JSON object -- the same field names as this
// library's model.SwitchData JSON tags -- so it parses directly via
// encoding/json, including Pvid's custom UnmarshalJSON for the [port,vlan]
// 2-element array shape.
type captureFixture struct {
	Model    string           `json:"model"`
	Host     string           `json:"host"`
	Snapshot model.SwitchData `json:"snapshot"`
	Note     string           `json:"note"`
}

func loadCaptureSnapshot(t *testing.T, path string) model.SwitchData {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading capture %s: %v", path, err)
	}
	var fx captureFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("parsing capture %s: %v", path, err)
	}
	return fx.Snapshot
}

// assertSeedMatchesCapture is the Go port of the Python reference's
// capture_parity.assert_seed_matches_capture: a deliberately ONE-WAY check
// that every port/PVID/VLAN-membership/PoE-port/sensor/mgmt-IP+base-MAC
// value the SEED itself defines is literally true of the given real
// capture. The seed may cover only a representative SUBSET of a large real
// device, so the reverse direction (every capture row appears in the seed)
// is never checked; a seed key absent from the capture entirely is a
// fabrication and fails loudly.
//
// Deliberately EXCLUDES the MAC/FDB table, LLDP neighbours, and per-port
// byte/packet counters: inherently volatile point-in-time facts, not
// durable ground truth a mock seed should be pinned to (mirrors the Python
// harness's own documented exclusion exactly).
func assertSeedMatchesCapture(t *testing.T, seed *State, path string) {
	t.Helper()
	capture := loadCaptureSnapshot(t, path)
	assertPortsMatchCapture(t, seed, capture)
	assertPoeMatchesCapture(t, seed, capture)
	assertVlansMatchCapture(t, seed, capture)
	assertPvidsMatchCapture(t, seed, capture)
	assertSensorsMatchCapture(t, seed, capture)
	assertMgmtMatchesCapture(t, seed, capture)
}

func assertPortsMatchCapture(t *testing.T, seed *State, capture model.SwitchData) {
	t.Helper()
	realPorts := make(map[int]model.PortStatus, len(capture.Ports))
	for _, p := range capture.Ports {
		realPorts[p.Port] = p
	}
	for port, sim := range seed.Ports {
		r, ok := realPorts[port]
		if !ok {
			t.Errorf("seed port %d absent from capture", port)
			continue
		}
		if sim.Name != derefStr(r.Name) {
			t.Errorf("port %d name = %q, want %q", port, sim.Name, derefStr(r.Name))
		}
		if sim.Admin != r.AdminEnabled {
			t.Errorf("port %d admin = %v, want %v", port, sim.Admin, r.AdminEnabled)
		}
		if sim.Link != r.LinkUp {
			t.Errorf("port %d link = %v, want %v", port, sim.Link, r.LinkUp)
		}
		if !speedsEquivalent(sim.Speed, r.SpeedMbps) {
			t.Errorf("port %d speed = %d, want %s", port, sim.Speed, derefIntDebug(r.SpeedMbps))
		}
		if !strPtrEqual(sim.Description, r.Description) {
			t.Errorf("port %d description = %s, want %s", port, strPtrDebug(sim.Description), strPtrDebug(r.Description))
		}
	}
}

func assertPoeMatchesCapture(t *testing.T, seed *State, capture model.SwitchData) {
	t.Helper()
	if len(seed.Poe) == 0 {
		if len(capture.PoE) != 0 {
			t.Errorf("seed has no PoE but the capture does (%d ports)", len(capture.PoE))
		}
		return
	}
	realPoe := make(map[int]model.PoEStatus, len(capture.PoE))
	for _, p := range capture.PoE {
		realPoe[p.Port] = p
	}
	for port, psim := range seed.Poe {
		r, ok := realPoe[port]
		if !ok {
			t.Errorf("seed PoE port %d absent from capture", port)
			continue
		}
		if psim.Admin != r.AdminEnabled {
			t.Errorf("PoE port %d admin = %v, want %v", port, psim.Admin, r.AdminEnabled)
		}
		// Mirror ParsePoe exactly: a detect code outside RFC3621's 1-4 (e.g.
		// the gsm7252ps's "Other Fault" code 6 on port 6) maps to UNKNOWN,
		// never a fabricated/zero-value PoEDetect.
		detect, ok := snmp.DetectMap[int64(psim.Detect)]
		if !ok {
			detect = model.PoEDetectUnknown
		}
		if detect != r.Detect {
			t.Errorf("PoE port %d detect = %v, want %v", port, detect, r.Detect)
		}
		powerMw := 0
		if r.PowerMw != nil {
			powerMw = *r.PowerMw
		}
		if psim.PowerMw != powerMw {
			t.Errorf("PoE port %d power_mw = %d, want %d", port, psim.PowerMw, powerMw)
		}
	}
}

func assertVlansMatchCapture(t *testing.T, seed *State, capture model.SwitchData) {
	t.Helper()
	realVlans := make(map[int]model.VLANInfo, len(capture.Vlans))
	for _, v := range capture.Vlans {
		realVlans[v.VlanID] = v
	}
	for vid, vsim := range seed.Vlans {
		r, ok := realVlans[vid]
		if !ok {
			t.Errorf("seed VLAN %d absent from capture", vid)
			continue
		}
		if vsim.Name != derefStr(r.Name) {
			t.Errorf("VLAN %d name = %q, want %q", vid, vsim.Name, derefStr(r.Name))
		}
		// The capture is an SNMP walk, so its member_ports came from
		// dot1qVlanStaticEgressPorts -- the STATIC (configured) table.
		// Compare it against the seed's CONFIGURED set, not its current
		// Member set: on the real GSM7252PS, VLAN 1's static bitmap
		// includes 1/0/50 and 1/0/51 while vlanStatus.html/show vlan report
		// them Current: Exclude, so the two views differ by exactly those
		// ports (see VlanSim.ConfiguredOnly, and Python's
		// tests/capture_parity.py._assert_vlans_match, which this mirrors).
		configured := vsim.Configured()
		if !intSetEqualsSlice(configured, r.MemberPorts) {
			t.Errorf("VLAN %d member_ports = %v, want %v", vid, sortedSetKeys(configured), r.MemberPorts)
		}
		if !intSetEqualsSlice(vsim.Untagged, r.UntaggedPorts) {
			t.Errorf("VLAN %d untagged_ports = %v, want %v", vid, sortedSetKeys(vsim.Untagged), r.UntaggedPorts)
		}
		tagged := sortedSetKeys(diffSet(configured, vsim.Untagged))
		if !intSliceEqual(tagged, r.TaggedPorts) {
			t.Errorf("VLAN %d tagged_ports = %v, want %v", vid, tagged, r.TaggedPorts)
		}
	}
}

func assertPvidsMatchCapture(t *testing.T, seed *State, capture model.SwitchData) {
	t.Helper()
	realPvids := make(map[int]int, len(capture.Pvids))
	for _, pv := range capture.Pvids {
		realPvids[pv.Port] = pv.Vlan
	}
	for port, pvid := range seed.Pvids {
		r, ok := realPvids[port]
		if !ok || r != pvid {
			t.Errorf("port %d pvid = %d, want %d (present in capture=%v)", port, pvid, r, ok)
		}
	}
}

func assertSensorsMatchCapture(t *testing.T, seed *State, capture model.SwitchData) {
	t.Helper()
	type sensorKey struct{ kind, instance string }
	realSensors := make(map[sensorKey]float64, len(capture.Sensors))
	for _, s := range capture.Sensors {
		// capture sensor "name" is "{kind}{instance}" -- strip the kind
		// prefix back off to key by (kind, instance), matching SensorSim.
		instance := strings.TrimPrefix(s.Name, s.Kind)
		realSensors[sensorKey{s.Kind, instance}] = s.Value
	}
	for _, ssim := range seed.Sensors {
		key := sensorKey{ssim.Kind, ssim.Instance}
		if ssim.Raw == "Not Supported" {
			if _, ok := realSensors[key]; ok {
				t.Errorf("sensor %+v seeded unsupported but captured", key)
			}
			continue
		}
		v, ok := realSensors[key]
		if !ok {
			t.Errorf("seed sensor %+v absent from capture", key)
			continue
		}
		raw, err := strconv.ParseFloat(ssim.Raw, 64)
		if err != nil {
			t.Errorf("sensor %+v raw %q not numeric: %v", key, ssim.Raw, err)
			continue
		}
		if raw != v {
			t.Errorf("sensor %+v value = %v, want %v", key, raw, v)
		}
	}
}

func assertMgmtMatchesCapture(t *testing.T, seed *State, capture model.SwitchData) {
	t.Helper()
	if capture.MgmtIP == nil {
		t.Fatal("capture has no mgmt_ip section")
	}
	expectedBaseMac := macColonHex(seed.NsdpMac)
	realBaseMac := derefStr(capture.MgmtIP.BaseMac)
	if expectedBaseMac != realBaseMac {
		t.Errorf("base_mac = %q, want %q", expectedBaseMac, realBaseMac)
	}
	if capture.MgmtIP.Address == nil {
		// No real static address was ever discovered on this capture; the
		// seed's default blank Mgmt is an honest placeholder, not a claim to
		// reproduce a specific real address (e.g. SeedM4300_16X) -- nothing
		// further to check.
		return
	}
	if seed.Mgmt.Address != *capture.MgmtIP.Address {
		t.Errorf("mgmt address = %q, want %q", seed.Mgmt.Address, *capture.MgmtIP.Address)
	}
	if capture.MgmtIP.Netmask != nil && seed.Mgmt.Netmask != *capture.MgmtIP.Netmask {
		t.Errorf("mgmt netmask = %q, want %q", seed.Mgmt.Netmask, *capture.MgmtIP.Netmask)
	}
	if capture.MgmtIP.Gateway != nil && seed.Mgmt.Gateway != *capture.MgmtIP.Gateway {
		t.Errorf("mgmt gateway = %q, want %q", seed.Mgmt.Gateway, *capture.MgmtIP.Gateway)
	}
}

// --- small comparison/debug helpers -----------------------------------------

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefIntDebug(p *int) string {
	if p == nil {
		return "<nil>"
	}
	return strconv.Itoa(*p)
}

func strPtrDebug(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%q", *p)
}

func strPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// speedsEquivalent mirrors the Python harness's `(sim.speed or None) ==
// (real["speed_mbps"] or None)`: a zero seed speed (down/unspecified) is
// equivalent to an absent/zero capture speed, never a strict 0-vs-nil
// mismatch.
func speedsEquivalent(seedSpeed int, capturedSpeed *int) bool {
	realSpeed := 0
	if capturedSpeed != nil {
		realSpeed = *capturedSpeed
	}
	if seedSpeed == 0 {
		return realSpeed == 0
	}
	return seedSpeed == realSpeed
}

func sortedSetKeys(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for k, present := range set {
		if present {
			out = append(out, k)
		}
	}
	sort.Ints(out)
	return out
}

func intSetEqualsSlice(set map[int]bool, want []int) bool {
	return intSliceEqual(sortedSetKeys(set), sortedInts(want))
}

func sortedInts(in []int) []int {
	out := append([]int(nil), in...)
	sort.Ints(out)
	return out
}

func intSliceEqual(a, b []int) bool {
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

func diffSet(member, untagged map[int]bool) map[int]bool {
	out := make(map[int]bool, len(member))
	for k, present := range member {
		if present && !untagged[k] {
			out[k] = true
		}
	}
	return out
}

func macColonHex(mac [6]byte) string {
	parts := make([]string, len(mac))
	for i, b := range mac {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// rowsFor builds the []snmp.Row a real transport would hand back for a
// column walk rooted at base, from a State.OIDMap() result -- the Go
// equivalent of the Python reference's per-test `rows(base)` closure.
// Unlike that Python closure (which passes oid_map()'s plain string values
// straight through, relying on Python's permissive int(row.value)), this
// normalizes each value to the exact type snmp.Row's contract requires
// (int64 for the INTEGER-family SNMP types, string otherwise) -- the Go
// parsers are stricter than the Python reference's coercing int(), so this
// conversion step is where that fidelity has to happen.
func rowsFor(m map[string]OIDEntry, base string) []snmp.Row {
	prefix := base + "."
	var out []snmp.Row
	for oid, e := range m {
		if oid != base && !strings.HasPrefix(oid, prefix) {
			continue
		}
		out = append(out, toSnmpRow(oid, e))
	}
	return out
}

func toSnmpRow(oid string, e OIDEntry) snmp.Row {
	switch e.SnmpType {
	case "INTEGER", "Gauge32", "Counter32", "Counter64":
		n, err := strconv.ParseInt(e.Value, 10, 64)
		if err != nil {
			panic(fmt.Sprintf("seed_test: OIDMap entry %s type %s value %q not integer: %v", oid, e.SnmpType, e.Value, err))
		}
		return snmp.NewIntRow(oid, n)
	default:
		return snmp.NewStrRow(oid, e.Value)
	}
}

func vendorOidsFor(t *testing.T, modelKey string) snmp.VendorOids {
	t.Helper()
	mdl, err := model.GetModel(modelKey)
	if err != nil {
		t.Fatalf("model.GetModel(%q): %v", modelKey, err)
	}
	v, err := snmp.GetVendorOids(mdl)
	if err != nil {
		t.Fatalf("snmp.GetVendorOids(%q): %v", modelKey, err)
	}
	return v
}

const (
	captureGSM7252PS = "testdata/captures/gsm7252ps.json"
	captureGSM7228PS = "testdata/captures/gsm7228ps.json"
	captureM430024X  = "testdata/captures/m4300-24x.json"
	captureM430016X  = "testdata/captures/m4300-16x.json"
)

// --- gsm7252ps ---------------------------------------------------------------

func TestSeedGSM7252PSBuildsCoherentOIDMap(t *testing.T) {
	m := SeedGSM7252PS().OIDMap()
	if _, ok := m[snmp.IfOperStatus+".1"]; !ok {
		t.Error("ifOperStatus.1 missing from OIDMap")
	}
	v := vendorOidsFor(t, "gsm7252ps")
	prefix := v.PoEPowerMw + "."
	found := false
	for k, e := range m {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if n, err := strconv.Atoi(e.Value); err == nil && n > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one delivering PoE port with vendor mW > 0")
	}
}

func TestSeedGSM7252PSRoundtripsThroughParsers(t *testing.T) {
	m := SeedGSM7252PS().OIDMap()
	v := vendorOidsFor(t, "gsm7252ps")

	vlans, err := snmp.ParseVlans(
		rowsFor(m, snmp.Dot1qVlanStaticName),
		rowsFor(m, snmp.Dot1qVlanStaticEgress),
		rowsFor(m, snmp.Dot1qVlanStaticUntagged),
		rowsFor(m, snmp.IfType),
		rowsFor(m, snmp.Dot1qVlanCurrentEgress),
		rowsFor(m, snmp.Dot1qVlanCurrentUntagged),
	)
	if err != nil {
		t.Fatalf("ParseVlans: %v", err)
	}
	ids := map[int]bool{}
	for _, vv := range vlans {
		ids[vv.VlanID] = true
	}
	if !ids[1] || !ids[90] {
		t.Errorf("parsed VLAN IDs = %v, want a superset of {1, 90}", ids)
	}

	mgmt, err := snmp.ParseMgmtIP(
		rowsFor(m, snmp.IPAdEntAddr),
		rowsFor(m, snmp.IPAdEntNetmask),
		rowsFor(m, snmp.IPRouteDest),
		rowsFor(m, snmp.IPRouteNextHop),
		rowsFor(m, v.DHCPModeUnverified),
		rowsFor(m, snmp.Dot1dBaseBridgeAddress),
		nil,
	)
	if err != nil {
		t.Fatalf("ParseMgmtIP: %v", err)
	}
	if derefStr(mgmt.Address) != "10.1.5.22" {
		t.Errorf("mgmt.Address = %s, want 10.1.5.22", strPtrDebug(mgmt.Address))
	}
	if derefStr(mgmt.Gateway) != "10.1.5.1" {
		t.Errorf("mgmt.Gateway = %s, want 10.1.5.1", strPtrDebug(mgmt.Gateway))
	}
	if derefStr(mgmt.BaseMac) != "E0:91:F5:0C:D6:DB" {
		t.Errorf("mgmt.BaseMac = %s, want E0:91:F5:0C:D6:DB", strPtrDebug(mgmt.BaseMac))
	}
}

func TestSeedGSM7252PSEmitsNonemptyStatsMacsLldp(t *testing.T) {
	m := SeedGSM7252PS().OIDMap()

	stats, err := snmp.ParsePortStats(snmp.PortStatsCols{
		InOctets:  rowsFor(m, snmp.IfHCInOctets),
		OutOctets: rowsFor(m, snmp.IfHCOutOctets),
		InUcast:   rowsFor(m, snmp.IfHCInUcast),
		OutUcast:  rowsFor(m, snmp.IfHCOutUcast),
		InErrors:  rowsFor(m, snmp.IfInErrors),
		OutErrors: rowsFor(m, snmp.IfOutErrors),
	})
	if err != nil {
		t.Fatalf("ParsePortStats: %v", err)
	}
	nonNil := 0
	for _, s := range stats {
		if s.RxBytes != nil {
			nonNil++
		}
	}
	if nonNil < 2 {
		t.Errorf("ports with non-nil RxBytes = %d, want >= 2", nonNil)
	}

	macs, err := snmp.ParseMacs(rowsFor(m, snmp.Dot1qTpFdbPort), rowsFor(m, snmp.Dot1dBasePortIfIndex))
	if err != nil {
		t.Fatalf("ParseMacs: %v", err)
	}
	if len(macs) < 2 {
		t.Errorf("len(macs) = %d, want >= 2", len(macs))
	}

	lldp, err := snmp.ParseLldp(rowsFor(m, snmp.LldpRemTable))
	if err != nil {
		t.Fatalf("ParseLldp: %v", err)
	}
	if len(lldp) < 1 {
		t.Fatalf("len(lldp) = %d, want >= 1", len(lldp))
	}
	if derefStr(lldp[0].RemoteSysName) != "sw-cisco-shed" {
		t.Errorf("lldp[0].RemoteSysName = %s, want sw-cisco-shed", strPtrDebug(lldp[0].RemoteSysName))
	}
	if derefStr(lldp[0].RemotePortID) != "1/xg51" {
		t.Errorf("lldp[0].RemotePortID = %s, want 1/xg51", strPtrDebug(lldp[0].RemotePortID))
	}
	if derefStr(lldp[0].RemotePortDesc) != "eth0" {
		t.Errorf("lldp[0].RemotePortDesc = %s, want eth0", strPtrDebug(lldp[0].RemotePortDesc))
	}
	if derefStr(lldp[0].RemotePortID) == derefStr(lldp[0].RemotePortDesc) {
		t.Error("RemotePortID and RemotePortDesc must be distinct (proves the two LLDP-MIB columns don't collapse together)")
	}
}

// TestSeedGSM7252PSEmitsNonemptyPortsPvidsPoeSensors exercises the four
// remaining SNMP read ops (ports, pvids, poe, sensors) and pins the
// specific values D-VIRT's Task 11 grounding section calls out: 54 parsed
// ports (52 physical + CPU ifIndex 417 + lag ifIndex 418 -- SNMP reports
// every ifIndex; only the web UI is physical-only, so ifTypes is
// deliberately passed nil/empty here to skip that filtering), port 1's
// speed/description, port 6's down-link/absent-description, 52 PVIDs incl.
// (1, 90), 48 PoE ports with port 1 delivering 3500mW, and the box sensors
// matching the capture value-for-value.
func TestSeedGSM7252PSEmitsNonemptyPortsPvidsPoeSensors(t *testing.T) {
	m := SeedGSM7252PS().OIDMap()
	v := vendorOidsFor(t, "gsm7252ps")

	ports, err := snmp.ParsePortStatus(
		rowsFor(m, snmp.IfAdminStatus),
		rowsFor(m, snmp.IfOperStatus),
		rowsFor(m, snmp.IfHighSpeed),
		rowsFor(m, snmp.IfName),
		rowsFor(m, snmp.IfAlias),
		nil,
	)
	if err != nil {
		t.Fatalf("ParsePortStatus: %v", err)
	}
	if len(ports) != 54 {
		t.Errorf("len(ports) = %d, want 54 (52 physical + CPU 417 + lag 418)", len(ports))
	}
	byPort := make(map[int]model.PortStatus, len(ports))
	for _, p := range ports {
		byPort[p.Port] = p
	}
	p1 := byPort[1]
	if !p1.AdminEnabled || !p1.LinkUp {
		t.Errorf("port 1 admin/link = %v/%v, want true/true", p1.AdminEnabled, p1.LinkUp)
	}
	if p1.SpeedMbps == nil || *p1.SpeedMbps != 1000 {
		t.Errorf("port 1 speed = %s, want 1000", derefIntDebug(p1.SpeedMbps))
	}
	if derefStr(p1.Description) != "eth0.rpi5-pmod" {
		t.Errorf("port 1 description = %s, want eth0.rpi5-pmod", strPtrDebug(p1.Description))
	}
	p6 := byPort[6]
	if p6.LinkUp {
		t.Error("port 6 should be link-down")
	}
	if p6.Description != nil {
		t.Errorf("port 6 description = %s, want nil (no ifAlias configured)", strPtrDebug(p6.Description))
	}

	pvids, err := snmp.ParsePvids(rowsFor(m, snmp.Dot1qPvid), nil)
	if err != nil {
		t.Fatalf("ParsePvids: %v", err)
	}
	if len(pvids) != 52 {
		t.Errorf("len(pvids) = %d, want 52", len(pvids))
	}
	has190 := false
	for _, pv := range pvids {
		if pv.Port == 1 && pv.Vlan == 90 {
			has190 = true
		}
	}
	if !has190 {
		t.Error("expected (port=1, vlan=90) in pvids")
	}

	poe, err := snmp.ParsePoe(rowsFor(m, snmp.PethPsePortTable), rowsFor(m, v.PoEPowerMw))
	if err != nil {
		t.Fatalf("ParsePoe: %v", err)
	}
	if len(poe) != 48 {
		t.Errorf("len(poe) = %d, want 48", len(poe))
	}
	var poe1 *model.PoEStatus
	for i := range poe {
		if poe[i].Port == 1 {
			poe1 = &poe[i]
		}
	}
	if poe1 == nil {
		t.Fatal("PoE port 1 missing")
	}
	if !poe1.Delivering() {
		t.Errorf("PoE port 1 detect = %v, want delivering", poe1.Detect)
	}
	if poe1.PowerMw == nil || *poe1.PowerMw != 3500 {
		t.Errorf("PoE port 1 power_mw = %s, want 3500", derefIntDebug(poe1.PowerMw))
	}

	sensors, err := snmp.ParseBoxSensors([]snmp.SensorColumn{
		{Kind: "fan", Unit: "RPM", Rows: rowsFor(m, v.BoxFan)},
		{Kind: "power", Unit: "W", Rows: rowsFor(m, v.BoxPSUPower)},
		{Kind: "temperature", Unit: "C", Rows: rowsFor(m, v.BoxTemp)},
	})
	if err != nil {
		t.Fatalf("ParseBoxSensors: %v", err)
	}
	got := make(map[string]float64, len(sensors))
	kinds := map[string]bool{}
	for _, s := range sensors {
		got[s.Name] = s.Value
		kinds[s.Kind] = true
	}
	want := map[string]float64{
		"fan0": 2850, "fan2": 2350,
		"power0": 49, "power1": 30, "power2": 32, "power3": 31,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("box sensors mismatch (-want +got):\n%s", diff)
	}
	if len(kinds) != 2 || !kinds["fan"] || !kinds["power"] {
		t.Errorf("sensor kinds = %v, want exactly {fan, power} (no temperature on this face)", kinds)
	}
}

func TestSeedGSM7252PSMatchesCaptureStrictly(t *testing.T) {
	assertSeedMatchesCapture(t, SeedGSM7252PS(), captureGSM7252PS)
}

// TestSeedGSM7252PSStatsMatchCapture pins per-port byte/packet counters
// against the capture directly: the generic assertSeedMatchesCapture
// harness skips counters as generally volatile, but this seed IS a
// snapshot of this exact fixed fixture, so pinning them is deterministic.
// Checked one-way: every physical port the seed carries counters for
// matches the capture; the two non-physical placeholders (CPU 417, lag
// 418) carry no seeded counters and are not required to.
func TestSeedGSM7252PSStatsMatchCapture(t *testing.T) {
	capture := loadCaptureSnapshot(t, captureGSM7252PS)
	realStats := make(map[int]model.PortStats, len(capture.Stats))
	for _, s := range capture.Stats {
		realStats[s.Port] = s
	}
	state := SeedGSM7252PS()
	checked := 0
	for port, sim := range state.Ports {
		if sim.RxOctets == nil {
			continue // CPU/lag placeholders carry no seeded counters.
		}
		r, ok := realStats[port]
		if !ok {
			t.Errorf("port %d missing from capture stats", port)
			continue
		}
		if *sim.RxOctets != derefU64(r.RxBytes) || *sim.TxOctets != derefU64(r.TxBytes) ||
			*sim.RxUcast != derefU64(r.RxPackets) || *sim.TxUcast != derefU64(r.TxPackets) {
			t.Errorf("port %d counters mismatch: seed rx=%d tx=%d rxp=%d txp=%d, capture rx=%v tx=%v rxp=%v txp=%v",
				port, *sim.RxOctets, *sim.TxOctets, *sim.RxUcast, *sim.TxUcast, r.RxBytes, r.TxBytes, r.RxPackets, r.TxPackets)
		}
		checked++
	}
	if checked != 52 {
		t.Errorf("checked %d ports, want all 52 physical ports pinned", checked)
	}
}

func TestSeedGSM7252PSVlan90MatchesCapture(t *testing.T) {
	capture := loadCaptureSnapshot(t, captureGSM7252PS)
	state := SeedGSM7252PS()

	var realVlan90 *model.VLANInfo
	for i := range capture.Vlans {
		if capture.Vlans[i].VlanID == 90 {
			realVlan90 = &capture.Vlans[i]
		}
	}
	if realVlan90 == nil {
		t.Fatal("capture has no VLAN 90")
	}
	if derefStr(realVlan90.Name) != "iot" || state.Vlans[90].Name != "iot" {
		t.Errorf("VLAN 90 name: capture=%s seed=%s, want iot", derefStr(realVlan90.Name), state.Vlans[90].Name)
	}
	for _, port := range []int{1, 2} {
		if !intSliceContains(realVlan90.UntaggedPorts, port) {
			t.Errorf("capture VLAN 90 untagged_ports missing port %d", port)
		}
		if !state.Vlans[90].Untagged[port] {
			t.Errorf("seed VLAN 90 untagged missing port %d", port)
		}
	}
	realPvids := make(map[int]int, len(capture.Pvids))
	for _, pv := range capture.Pvids {
		realPvids[pv.Port] = pv.Vlan
	}
	if realPvids[1] != 90 || state.Pvids[1] != 90 {
		t.Errorf("port 1 pvid: capture=%d seed=%d, want 90", realPvids[1], state.Pvids[1])
	}
	if realPvids[2] != 90 || state.Pvids[2] != 90 {
		t.Errorf("port 2 pvid: capture=%d seed=%d, want 90", realPvids[2], state.Pvids[2])
	}
}

// --- gsm7228ps ---------------------------------------------------------------

func TestSeedGSM7228PSMatchesCaptureStrictly(t *testing.T) {
	assertSeedMatchesCapture(t, SeedGSM7228PS(), captureGSM7228PS)
}

// --- m4300-24x ---------------------------------------------------------------

func TestSeedM4300_24XMatchesCaptureStrictly(t *testing.T) {
	assertSeedMatchesCapture(t, SeedM4300_24X(), captureM430024X)
}

func TestSeedM4300_24XHasNoPoeAndWireProjectsEmptyTable(t *testing.T) {
	capture := loadCaptureSnapshot(t, captureM430024X)
	if len(capture.PoE) != 0 {
		t.Fatalf("capture PoE = %d entries, want 0 (ground truth: no PoE on this model)", len(capture.PoE))
	}

	state := SeedM4300_24X()
	if len(state.Poe) != 0 {
		t.Errorf("state.Poe = %d entries, want 0", len(state.Poe))
	}
	m := state.OIDMap()
	v := vendorOidsFor(t, "m4300-24x")
	poe, err := snmp.ParsePoe(rowsFor(m, snmp.PethPsePortTable), rowsFor(m, v.PoEPowerMw))
	if err != nil {
		t.Fatalf("ParsePoe: %v", err)
	}
	if len(poe) != 0 {
		t.Errorf("OIDMap -> ParsePoe round-trip = %d entries, want 0", len(poe))
	}
}

// TestSeedM4300_24XAsciiBaseMacWireQuirkMatchesCapture proves the M4300-24X
// ASCII-text dot1dBaseBridgeAddress quirk round-trips end to end through
// the mock's wire projection (not just the parsed VALUE, already covered by
// TestSeedM4300_24XMatchesCaptureStrictly) -- this is the wire-SHAPE proof.
func TestSeedM4300_24XAsciiBaseMacWireQuirkMatchesCapture(t *testing.T) {
	capture := loadCaptureSnapshot(t, captureM430024X)
	state := SeedM4300_24X()
	m := state.OIDMap()

	entry := m[snmp.Dot1dBaseBridgeAddress+".0"]
	if entry.SnmpType != "OCTETSTR" {
		t.Errorf("wire type = %s, want OCTETSTR", entry.SnmpType)
	}
	if entry.Value != derefStr(capture.MgmtIP.BaseMac) {
		t.Errorf("wire value = %q, want %q (capture base_mac)", entry.Value, derefStr(capture.MgmtIP.BaseMac))
	}
	if len(entry.Value) != 17 {
		t.Errorf("wire value length = %d, want 17 (ASCII colon-hex text)", len(entry.Value))
	}
}

// --- m4300-16x ---------------------------------------------------------------

func TestSeedM4300_16XMatchesCaptureStrictly(t *testing.T) {
	// This model's captured mgmt_ip.address is None -- assertMgmtMatchesCapture
	// honestly skips the address/netmask/gateway checks in that case.
	assertSeedMatchesCapture(t, SeedM4300_16X(), captureM430016X)
}

func TestSeedM4300_16XHasPoeOnAll16PortsWithTwoDelivering(t *testing.T) {
	capture := loadCaptureSnapshot(t, captureM430016X)
	if len(capture.PoE) != 16 {
		t.Fatalf("capture PoE = %d entries, want 16", len(capture.PoE))
	}

	state := SeedM4300_16X()
	if len(state.Poe) != 16 {
		t.Errorf("state.Poe = %d entries, want 16", len(state.Poe))
	}
	m := state.OIDMap()
	v := vendorOidsFor(t, "m4300-16x")
	poe, err := snmp.ParsePoe(rowsFor(m, snmp.PethPsePortTable), rowsFor(m, v.PoEPowerMw))
	if err != nil {
		t.Fatalf("ParsePoe: %v", err)
	}
	delivering := map[int]bool{}
	for _, p := range poe {
		if p.Delivering() {
			delivering[p.Port] = true
		}
	}
	if len(delivering) != 2 || !delivering[11] || !delivering[12] {
		t.Errorf("delivering PoE ports = %v, want exactly {11, 12}", delivering)
	}
}

func TestSeedM4300_16XBaseMacMatchesCaptureRawBytesForm(t *testing.T) {
	state := SeedM4300_16X()
	if state.Dot1dBaseMacASCII {
		t.Error("Dot1dBaseMacASCII should be false (only the M4300-24X quirk is verified)")
	}
	m := state.OIDMap()
	entry := m[snmp.Dot1dBaseBridgeAddress+".0"]
	if entry.SnmpType != "OCTETSTR" {
		t.Errorf("wire type = %s, want OCTETSTR", entry.SnmpType)
	}
	if len(entry.Value) != 6 {
		t.Errorf("wire value length = %d, want 6 (raw bytes, not the 17-char ASCII form)", len(entry.Value))
	}
}

// --- VLANPortListWidth: real per-model measured Q-BRIDGE PortList widths
// (D-REC Topic B) -----------------------------------------------------------

// TestSeededVLANPortListWidthMatchesRealMeasuredValues pins the exact
// live-measured widths transcribed from the pinned seed.py's
// vlan_portlist_width field for the five managed-model seeds -- 79
// (gsm7252ps), 45 (gsm7228ps), 131 (both M4300s), 126 (gs728tpp) -- and
// proves each is not just a stored field but ACTUALLY the byte width
// OIDMap emits for dot1qVlanStaticEgressPorts/UntaggedPorts (Task 3's
// principle-5 fidelity fix: the mock must be an independent source of
// truth for the wire width, not a re-derivation of snmp.VlanBitmapWidth's
// formula). gs728tpp's check vlan is 5 ("net"), not 1: VLAN 1 there has no
// dot1qVlanStaticTable row at all (VlanSim.NoStaticRow, GAP-2 fix parity
// with Python commit 3f25b0b) so it emits no static bitmap to measure.
func TestSeededVLANPortListWidthMatchesRealMeasuredValues(t *testing.T) {
	cases := []struct {
		name      string
		seed      *State
		wantWidth int
		vlanID    int
	}{
		{"gsm7252ps", SeedGSM7252PS(), 79, 1},
		{"gsm7228ps", SeedGSM7228PS(), 45, 5},
		{"m4300-24x", SeedM4300_24X(), 131, 1},
		{"m4300-16x", SeedM4300_16X(), 131, 1},
		{"gs728tpp", SeedGS728TPP(), 126, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.seed.VLANPortListWidth == nil {
				t.Fatalf("VLANPortListWidth = nil, want %d", c.wantWidth)
			}
			if got := *c.seed.VLANPortListWidth; got != c.wantWidth {
				t.Errorf("VLANPortListWidth = %d, want %d", got, c.wantWidth)
			}
			m := c.seed.OIDMap()
			egress := m[colKey(snmp.Dot1qVlanStaticEgress, c.vlanID)]
			if got := len(egress.Value); got != c.wantWidth {
				t.Errorf("OIDMap egress bitmap width for vlan %d = %d, want %d", c.vlanID, got, c.wantWidth)
			}
			untagged := m[colKey(snmp.Dot1qVlanStaticUntagged, c.vlanID)]
			if got := len(untagged.Value); got != c.wantWidth {
				t.Errorf("OIDMap untagged bitmap width for vlan %d = %d, want %d", c.vlanID, got, c.wantWidth)
			}
		})
	}
}

// --- gs728tpp: no committed capture JSON at this pin (see
// testdata/captures/README.md) -- grounded directly against the values
// transcribed into seed.go from the pinned seed.py. --------------------------

func TestSeedGS728TPPEntityComponentsPresent(t *testing.T) {
	state := SeedGS728TPP()
	want := []EntitySim{
		{Index: 67109185, PhysClass: 6, Name: "Main PowerSupply", Descr: "PowerSupply"},
		{Index: 67109186, PhysClass: 6, Name: "Redundant PowerSupply", Descr: "PowerSupply"},
		{Index: 67109249, PhysClass: 7, Name: "Fan1", Descr: "Fan"},
		{Index: 67109250, PhysClass: 7, Name: "Fan2", Descr: "Fan"},
	}
	if diff := cmp.Diff(want, state.EntityComponents); diff != "" {
		t.Errorf("EntityComponents mismatch (-want +got):\n%s", diff)
	}
}

func TestSeedGS728TPPSensorsEmpty(t *testing.T) {
	state := SeedGS728TPP()
	if len(state.Sensors) != 0 {
		t.Errorf("Sensors = %v, want empty (this agent implements zero Netgear vendor OIDs)", state.Sensors)
	}
	if len(state.HTTPSensors) == 0 {
		t.Error("HTTPSensors should be non-empty (the HTTP sysInfo page reports live health, unlike SNMP)")
	}
}

func TestSeedGS728TPPSysObjectIDIsRealCapturedValue(t *testing.T) {
	state := SeedGS728TPP()
	const want = "1.3.6.1.4.1.4526.100.4.27"
	if state.SysObjectID != want {
		t.Errorf("SysObjectID = %q, want %q", state.SysObjectID, want)
	}
}

func TestSeedGS728TPPPoeAllSearchingOverSNMP(t *testing.T) {
	state := SeedGS728TPP()
	if len(state.Poe) != 24 {
		t.Fatalf("len(Poe) = %d, want 24", len(state.Poe))
	}
	m := state.OIDMap()
	// This model has SNMPVendorBase == "" -- no vendor mW column exists at
	// all, so ParsePoe's power_mw walk is legitimately empty and every port
	// must come back with PowerMw == nil, never a fabricated 0.
	poe, err := snmp.ParsePoe(rowsFor(m, snmp.PethPsePortTable), nil)
	if err != nil {
		t.Fatalf("ParsePoe: %v", err)
	}
	if len(poe) != 24 {
		t.Fatalf("len(poe) = %d, want 24", len(poe))
	}
	for _, p := range poe {
		if p.Delivering() {
			t.Errorf("PoE port %d unexpectedly delivering on this idle unit", p.Port)
		}
		if p.PowerMw != nil {
			t.Errorf("PoE port %d PowerMw = %d, want nil (no vendor mW column on this model)", p.Port, *p.PowerMw)
		}
	}
}

func TestSeedGS728TPPMgmtAddress(t *testing.T) {
	state := SeedGS728TPP()
	if state.Mgmt.Address != "10.2.5.10" {
		t.Errorf("Mgmt.Address = %q, want 10.2.5.10", state.Mgmt.Address)
	}
}

// --- Plus-model seeds (slice 05: gs110emx / gs305ep / gs105pe) -----------------
//
// None of these three has a committed testdata/captures/*.json at this pin
// (see seed.go's package doc comment for exactly why each one doesn't), so
// -- like gs728tpp above -- they are grounded only by direct structural
// pins against the values transcribed into seed.go, not by
// assertSeedMatchesCapture. Mirrors test_nsdp_state.py's
// test_seed_has_plus_shape intent (D-NSDP §9.4).

func TestSeedGS110EMXHasPlusShape(t *testing.T) {
	st := SeedGS110EMX()
	if st.ModelKey != "gs110emx" {
		t.Errorf("ModelKey = %q, want gs110emx", st.ModelKey)
	}
	if st.Serial == "" {
		t.Error("Serial should be non-empty")
	}
	if st.Firmware == "" {
		t.Error("Firmware should be non-empty")
	}
	if len(st.Ports) != 10 {
		t.Errorf("len(Ports) = %d, want 10", len(st.Ports))
	}
	// Transcribed from gs110emx_pvid.html: every port is PVID 1.
	if st.Pvids[1] != 1 {
		t.Errorf("Pvids[1] = %d, want 1", st.Pvids[1])
	}
	if len(st.Poe) != 0 {
		t.Errorf("len(Poe) = %d, want 0 (registry PoEPortCount 0)", len(st.Poe))
	}
}

func TestSeedGS110EMXPortLinkAndSpeed(t *testing.T) {
	st := SeedGS110EMX()
	wantLink := map[int]bool{1: false, 2: false, 3: false, 4: false, 5: false, 6: true, 7: false, 8: true, 9: true, 10: true}
	wantSpeed := map[int]int{6: 100, 8: 1000, 9: 10000, 10: 10000}
	for port := 1; port <= 10; port++ {
		p, ok := st.Ports[port]
		if !ok {
			t.Fatalf("Ports[%d] missing", port)
		}
		if p.Link != wantLink[port] {
			t.Errorf("Ports[%d].Link = %v, want %v", port, p.Link, wantLink[port])
		}
		if p.Speed != wantSpeed[port] {
			t.Errorf("Ports[%d].Speed = %d, want %d", port, p.Speed, wantSpeed[port])
		}
	}
	if st.Ports[8].Description == nil || *st.Ports[8].Description != "rumpus" {
		t.Errorf("Ports[8].Description = %v, want \"rumpus\"", st.Ports[8].Description)
	}
}

func TestSeedGS110EMXNsdpExtraFields(t *testing.T) {
	st := SeedGS110EMX()
	if st.NsdpMac != [6]byte{0xbc, 0xa5, 0x11, 0xb8, 0xec, 0xf1} {
		t.Errorf("NsdpMac = %x, want bc:a5:11:b8:ec:f1", st.NsdpMac)
	}
	if st.NsdpQosEngine == nil || *st.NsdpQosEngine != 1 {
		t.Errorf("NsdpQosEngine = %v, want 1", st.NsdpQosEngine)
	}
	if st.NsdpPortMirroringDest == nil || *st.NsdpPortMirroringDest != 10 {
		t.Errorf("NsdpPortMirroringDest = %v, want 10", st.NsdpPortMirroringDest)
	}
	if want := (map[int]bool{1: true, 2: true}); !reflect.DeepEqual(st.NsdpPortMirroringSources, want) {
		t.Errorf("NsdpPortMirroringSources = %v, want %v", st.NsdpPortMirroringSources, want)
	}
	if st.NsdpIgmpSnoopingEnabled == nil || !*st.NsdpIgmpSnoopingEnabled {
		t.Error("NsdpIgmpSnoopingEnabled should be true")
	}
	if st.NsdpIgmpSnoopingVlan == nil || *st.NsdpIgmpSnoopingVlan != 90 {
		t.Errorf("NsdpIgmpSnoopingVlan = %v, want 90", st.NsdpIgmpSnoopingVlan)
	}
	if st.NsdpBroadcastFiltering == nil || !*st.NsdpBroadcastFiltering {
		t.Error("NsdpBroadcastFiltering should be true")
	}
	if st.NsdpLoopDetection == nil || !*st.NsdpLoopDetection {
		t.Error("NsdpLoopDetection should be true")
	}
}

// TestSeedGS305EPHasIncompleteNsdpIdentity pins the GENUINE gap in the
// pinned Python reference (D-NSDP §7.3/§10.6#7): seed_gs305ep passes no
// model_name/serial/firmware/hostname/nsdp_mac/nsdp_password/QoS/
// mirroring/IGMP/broadcast/loop-detection kwargs at all, so every one of
// them -- and Mgmt -- must still read back exactly NewState's own
// defaults. A seed that "helpfully" filled these in would silently diverge
// from this pin and defeat a future Go<->Python cross-fake-equivalence
// test; this test exists specifically to catch that regression.
func TestSeedGS305EPHasIncompleteNsdpIdentity(t *testing.T) {
	st := SeedGS305EP()
	blank := NewState("gs305ep")

	if st.ModelName != blank.ModelName {
		t.Errorf("ModelName = %q, want %q (NewState default)", st.ModelName, blank.ModelName)
	}
	if st.Serial != blank.Serial {
		t.Errorf("Serial = %q, want %q (NewState default)", st.Serial, blank.Serial)
	}
	if st.Firmware != blank.Firmware {
		t.Errorf("Firmware = %q, want %q (NewState default)", st.Firmware, blank.Firmware)
	}
	if st.Hostname != blank.Hostname {
		t.Errorf("Hostname = %q, want %q (NewState default)", st.Hostname, blank.Hostname)
	}
	if st.NsdpMac != blank.NsdpMac {
		t.Errorf("NsdpMac = %x, want %x (NewState default)", st.NsdpMac, blank.NsdpMac)
	}
	if st.NsdpPassword != blank.NsdpPassword {
		t.Errorf("NsdpPassword = %q, want %q (NewState default)", st.NsdpPassword, blank.NsdpPassword)
	}
	if st.Mgmt != blank.Mgmt {
		t.Errorf("Mgmt = %+v, want %+v (NewState default)", st.Mgmt, blank.Mgmt)
	}
	if st.NsdpQosEngine != nil || st.NsdpPortMirroringDest != nil || st.NsdpIgmpSnoopingEnabled != nil ||
		st.NsdpIgmpSnoopingVlan != nil || st.NsdpBroadcastFiltering != nil || st.NsdpLoopDetection != nil {
		t.Error("every NSDP-extra field should be nil/unseeded on gs305ep")
	}
}

func TestSeedGS305EPPortsVlansPoe(t *testing.T) {
	st := SeedGS305EP()
	if len(st.Ports) != 5 {
		t.Errorf("len(Ports) = %d, want 5", len(st.Ports))
	}
	if st.Ports[3].Admin {
		t.Error("Ports[3].Admin should be false")
	}
	if !st.Ports[1].Link || st.Ports[1].Speed != 1000 {
		t.Errorf("Ports[1] = %+v, want Link=true Speed=1000", st.Ports[1])
	}
	if want := (map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true}); !reflect.DeepEqual(st.Vlans[1].Member, want) {
		t.Errorf("Vlans[1].Member = %v, want %v", st.Vlans[1].Member, want)
	}
	if st.Vlans[1].Name != "default" {
		t.Errorf("Vlans[1].Name = %q, want default", st.Vlans[1].Name)
	}
	if st.Vlans[90].Name != "iot" {
		t.Errorf("Vlans[90].Name = %q, want iot", st.Vlans[90].Name)
	}
	if len(st.Poe) != 4 {
		t.Errorf("len(Poe) = %d, want 4", len(st.Poe))
	}
	if st.Poe[1].PowerMw != 12_800 {
		t.Errorf("Poe[1].PowerMw = %d, want 12800", st.Poe[1].PowerMw)
	}
}

func TestSeedGS105PEHasPlusShape(t *testing.T) {
	st := SeedGS105PE()
	if st.ModelKey != "gs105pe" {
		t.Errorf("ModelKey = %q, want gs105pe", st.ModelKey)
	}
	if len(st.Ports) != 5 {
		t.Errorf("len(Ports) = %d, want 5", len(st.Ports))
	}
	if len(st.Poe) != 0 {
		t.Errorf("len(Poe) = %d, want 0 (registry PoEPortCount 0 -- pass-through only)", len(st.Poe))
	}
	if len(st.Macs) != 0 || len(st.Lldp) != 0 || len(st.Sensors) != 0 {
		t.Error("gs105pe should have no MAC/FDB, LLDP, or box sensors over any face")
	}
}

func TestSeedGS105PEPortMirroringOffFixture(t *testing.T) {
	st := SeedGS105PE()
	// dest=0/no sources: the exact "off" shape that historically exposed a
	// fixed-width PORT_MIRRORING parser bug (D-NSDP §3.9/§10.6#3) -- pinned
	// here as a regression fixture, per SeedGS105PE's own doc comment.
	if st.NsdpPortMirroringDest == nil || *st.NsdpPortMirroringDest != 0 {
		t.Errorf("NsdpPortMirroringDest = %v, want a non-nil 0", st.NsdpPortMirroringDest)
	}
	if len(st.NsdpPortMirroringSources) != 0 {
		t.Errorf("NsdpPortMirroringSources = %v, want empty", st.NsdpPortMirroringSources)
	}
}

func TestSeedGS105PEMgmtAndVlans(t *testing.T) {
	st := SeedGS105PE()
	wantMgmt := MgmtSim{Address: "10.1.5.30", Netmask: "255.255.255.0", Gateway: "10.1.5.1", Mode: "dhcp"}
	if st.Mgmt != wantMgmt {
		t.Errorf("Mgmt = %+v, want %+v", st.Mgmt, wantMgmt)
	}
	if want := (map[int]int{1: 41, 2: 41, 3: 90, 4: 41, 5: 1}); !reflect.DeepEqual(st.Pvids, want) {
		t.Errorf("Pvids = %v, want %v", st.Pvids, want)
	}
	if want := (map[int]bool{3: true, 5: true}); !reflect.DeepEqual(st.Vlans[90].Member, want) {
		t.Errorf("Vlans[90].Member = %v, want %v", st.Vlans[90].Member, want)
	}
}

// --- BuildState ---------------------------------------------------------------

// TestBuildStateDispatchesSeededModels covers every model with a
// hand-authored seed: the five SNMP-capable models from slice 02, plus (as
// of slice 05) the three NSDP/HTTP-only Plus models gs110emx/gs305ep/
// gs105pe, whose own seeds land in this slice -- see
// TestBuildStateBlankForUnseededModels below for this list's counterpart.
func TestBuildStateDispatchesSeededModels(t *testing.T) {
	for _, key := range []string{
		"gsm7252ps", "gsm7228ps", "m4300-24x", "m4300-16x", "gs728tpp",
		"gs110emx", "gs305ep", "gs105pe",
	} {
		st := BuildState(key)
		if st.ModelKey != key {
			t.Errorf("BuildState(%q).ModelKey = %q", key, st.ModelKey)
		}
		if len(st.Ports) == 0 {
			t.Errorf("BuildState(%q) should be seeded (non-empty Ports)", key)
		}
	}
}

// TestBuildStateBlankForUnseededModels covers a wholly-unregistered model
// key: it gets a blank-but-valid State, mirroring the Python reference's
// _build_state (which never validates the key itself; that is
// model.GetModel's job at a higher layer). gs110emx/gs305ep/gs105pe used to
// belong in this list (their seeds were out of scope before slice 05); now
// that SeedGS110EMX/SeedGS305EP/SeedGS105PE exist, they instead assert
// non-blank in TestBuildStateDispatchesSeededModels above.
func TestBuildStateBlankForUnseededModels(t *testing.T) {
	for _, key := range []string{"not-a-real-model"} {
		st := BuildState(key)
		if st.ModelKey != key {
			t.Errorf("BuildState(%q).ModelKey = %q", key, st.ModelKey)
		}
		if len(st.Ports) != 0 || len(st.Vlans) != 0 || len(st.Pvids) != 0 || len(st.Poe) != 0 {
			t.Errorf("BuildState(%q) should be blank: ports=%d vlans=%d pvids=%d poe=%d",
				key, len(st.Ports), len(st.Vlans), len(st.Pvids), len(st.Poe))
		}
	}
}

// --- misc small helpers -------------------------------------------------------

func derefU64(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

func intSliceContains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
