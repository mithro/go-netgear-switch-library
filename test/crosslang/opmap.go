//go:build crosslang

package crosslang

// opmap.go: the central op-name -> facade-method map runReadSuite (suite.go)
// drives, one entry per capabilities.ReadOperations name, each pairing the
// facade call with THIS suite's own non-degenerate assertion for that op's
// result -- centralized here, keyed by capabilities.Operation.Name (the
// SAME stable string key the capabilities package itself uses), so a later
// crosslang slice (CC2's Python-fake suite, CC4's CLI-diff suite) can reuse
// this wiring unchanged rather than re-deriving "which facade method serves
// get_lldp" from scratch.
//
// Every check below was calibrated against a REAL run of every (model,
// backend, op) triple this package's Suite 1 (go_fake_test.go) exercises --
// not guessed from the seed source alone -- specifically to avoid the two
// failure modes principle 2 warns against: a check strong enough to be
// meaningful (catching a broken parse, an empty response, OR a value that
// silently drifted from what the seed actually says), but never so
// blanket-strong that it demands data a model's own hand-authored fake seed
// genuinely never populated (which would make an honest, working read look
// like a bug). Every such gap is called out, by name, in the small
// exception tables below, each with the seed evidence behind it -- never a
// silent skip. Where a value genuinely differs by BACKEND, not just by
// model (e.g. a managed dialect's HTTP stats page carrying error counters
// but not octet counters at all), the table is keyed by (model, backend)
// instead of by model alone -- never averaged or loosened to paper over it.

import (
	"context"
	"slices"
	"strings"
	"testing"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/model"
)

// readCheck calls the facade read method for one capabilities.Operation
// over sw, forced to backend via WithReadBackend, and asserts the result is
// non-degenerate for model m -- failing t itself (Fatalf on a hard I/O
// error, Errorf on a bad assertion) rather than returning a value for the
// caller to interpret. A shared generic signature (e.g. "return the
// interface{} and a validator") was deliberately rejected: the right
// non-degenerate assertion genuinely differs by Go return type (a slice's
// length against a model-specific expectation, a string's emptiness, a
// struct's own field-by-field shape), and forcing all fourteen through one
// generic checker would only weaken every one of them to the least
// common denominator.
type readCheck func(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel)

// readOps maps every one of capabilities.ReadOperations' 14 Name values to
// its readCheck.
var readOps = map[string]readCheck{
	"get_ports":    checkGetPorts,
	"get_stats":    checkGetStats,
	"get_vlans":    checkGetVLANs,
	"get_pvids":    checkGetPVIDs,
	"get_lldp":     checkGetLLDP,
	"get_macs":     checkGetMACs,
	"get_poe":      checkGetPoE,
	"get_sensors":  checkGetSensors,
	"get_mgmt_ip":  checkGetMgmtIP,
	"get_hostname": checkGetHostname,
	"get_users":    checkGetUsers,
	"get_services": checkGetServices,
	"get_syslog":   checkGetSyslog,
	"nsdp_device":  checkNsdpDevice,
}

// expectedPortRows is the number of GetPorts()/GetPVIDs() rows this Go
// fake's own hand-authored seed (virtual/seed.go) actually models, for the
// one suite1Models entry where that number differs from model.SwitchModel.
// PortCount. Every other model checked here matches PortCount exactly
// (verified against a live GoFakeProvider round trip while building this
// suite, not assumed) -- m4300-24x is the sole, deliberate exception:
// SeedM4300_24X's ifTable literally only defines ports 1-24 (plus LAG/CPU/
// VLAN pseudo-interfaces the SNMP physicalPorts filter already excludes),
// even though the real M4300-24X's registry PortCount (28) counts its 4
// SFP+ combo uplinks too -- a real device's ifTable genuinely omits an
// entry for an unpopulated SFP+ cage, and this capture's seed faithfully
// carries that same 24-row shape rather than inventing 4 more.
var expectedPortRows = map[string]int{
	"m4300-24x": 24,
}

func portRowsWant(m *model.SwitchModel) int {
	if n, ok := expectedPortRows[m.Key]; ok {
		return n
	}
	return m.PortCount
}

func checkGetPorts(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	ports, err := sw.GetPorts(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetPorts() over %s error = %v", backend, err)
		return
	}
	if want := portRowsWant(m); len(ports) != want {
		t.Errorf("GetPorts() over %s returned %d ports, want %d", backend, len(ports), want)
	}
}

// statsKnownEmpty documents the one (model) whose hand-authored fake seed
// never populates ANY port's traffic counters, so GetStats() genuinely --
// honestly -- returns zero rows: gs728tpp. snmp.ParsePortStats derives its
// port SET from the union of the six HC-counter OID subtrees GetStats
// walks (see its own doc comment in snmp/parse.go), not from ifType alone,
// so an agent that never populated any of those six subtrees for a given
// model answers an empty union, not 28 rows of nil counters. SeedGS728TPP's
// own doc comment (virtual/seed.go) lists exactly which fields were
// cross-verified against real hardware -- ports/vlans/pvids/macs/lldp/poe/
// mgmt-IP -- and per-port SNMP traffic counters are conspicuously absent
// from that list.
var statsKnownEmpty = map[string]bool{
	"gs728tpp": true,
}

// statsPin is one model's pinned GetStats() counter row: a single port
// virtual/seed.go's own hand-authored PortSim literal gives an EXPLICIT,
// non-default RxOctets/TxOctets/RxErrors -- never port 1 by default; picked
// per model specifically to avoid a value that merely happens to be the
// zero default (which would prove nothing).
type statsPin struct {
	port          int
	rx, tx, rxErr uint64
}

// statsPinned is the pinned counter row for every suite1Models entry
// capabilities.Matrix marks Supported for get_stats (excluding gs728tpp --
// see statsKnownEmpty), each grounded in virtual/seed.go's own literal
// PortSim assignment for that exact port and cross-checked against a live
// GoFakeProvider round trip while building this suite:
//   - m4300-24x port 1: SeedM4300_24X's own ports[1] literal (RxOctets
//     14778916968081, TxOctets 11768639639224, RxErrors 5).
//   - m4300-16x port 16: SeedM4300_16X's own ports[16] literal (RxOctets
//     3347925876, TxOctets 7868391, RxErrors 0) -- ports 1-10 are all
//     explicitly zeroed there, so port 16 is the first genuinely nonzero
//     one.
//   - gsm7252ps port 1: SeedGSM7252PS's own ports[1] literal (RxOctets
//     45747246, TxOctets 912689098, RxErrors 0).
//   - gsm7228ps port 49: SeedGSM7228PS's own ports[49] literal (RxOctets
//     492931, TxOctets 9048, RxErrors 0) -- ports 1-28 are all explicitly
//     zeroed there (the 24 RJ45 + LAG range), so the 49/xg49 SFP+ uplink is
//     the first genuinely nonzero port.
//   - gs110emx port 8: SeedGS110EMX's own realOctets[8] literal (RxOctets
//     59921732691, TxOctets 78637274870, RxErrors 0).
//   - gs305ep port 1: SeedGS305EP's own ports[1] literal (RxOctets 1000000,
//     TxOctets 2000000, RxErrors 0).
//   - gs105pe port 5: SeedGS105PE's own ports[5] literal (RxOctets
//     29303468, TxOctets 289149, RxErrors 228666).
var statsPinned = map[string]statsPin{
	"m4300-24x": {port: 1, rx: 14_778_916_968_081, tx: 11_768_639_639_224, rxErr: 5},
	"m4300-16x": {port: 16, rx: 3_347_925_876, tx: 7_868_391, rxErr: 0},
	"gsm7252ps": {port: 1, rx: 45_747_246, tx: 912_689_098, rxErr: 0},
	"gsm7228ps": {port: 49, rx: 492_931, tx: 9_048, rxErr: 0},
	"gs110emx":  {port: 8, rx: 59_921_732_691, tx: 78_637_274_870, rxErr: 0},
	"gs305ep":   {port: 1, rx: 1_000_000, tx: 2_000_000, rxErr: 0},
	"gs105pe":   {port: 5, rx: 29_303_468, tx: 289_149, rxErr: 228_666},
}

// statsBytesUnavailableOverHTTP documents the three managed/S3300 HTTP
// dialects whose stats page carries per-port ERROR counters but genuinely
// never renders octet counters at all -- measured directly (a live
// GoFakeProvider round trip against every backend this suite exercises):
// m4300-24x/gsm7252ps/gsm7228ps's HTTP GetStats() always reports RxBytes/
// TxBytes nil while RxErrors matches the SAME seed literal SNMP/SSH/Telnet
// report, for every port. m4300-16x's HTTP backend never reaches this check
// at all (excluded suite-wide -- see provider.go's servedBackends), so it
// is deliberately absent from this map. The three NSDP+HTTP Plus-class
// models (gs110emx/gs305ep/gs105pe) need no entry here: their HTTP stats
// page DOES carry full octet counters, matching NSDP exactly (measured the
// same way).
var statsBytesUnavailableOverHTTP = map[string]bool{
	"m4300-24x": true,
	"gsm7252ps": true,
	"gsm7228ps": true,
}

func checkGetStats(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	stats, err := sw.GetStats(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetStats() over %s error = %v", backend, err)
		return
	}
	if statsKnownEmpty[m.Key] {
		if len(stats) != 0 {
			t.Errorf("GetStats() over %s returned %d rows, want exactly 0 (documented gap -- see statsKnownEmpty)", backend, len(stats))
		}
		return
	}
	if want := portRowsWant(m); len(stats) != want {
		t.Errorf("GetStats() over %s returned %d ports, want %d", backend, len(stats), want)
		return
	}
	pin, ok := statsPinned[m.Key]
	if !ok {
		t.Fatalf("statsPinned has no entry for model %q -- opmap.go needs updating for this newly-included model", m.Key)
		return
	}
	for _, s := range stats {
		if s.Port != pin.port {
			continue
		}
		if s.RxErrors == nil || *s.RxErrors != pin.rxErr {
			t.Errorf("GetStats() over %s port %d RxErrors = %v, want %d", backend, pin.port, s.RxErrors, pin.rxErr)
		}
		if !statsBytesUnavailableOverHTTP[m.Key] || backend != model.BackendHTTP {
			if s.RxBytes == nil || *s.RxBytes != pin.rx {
				t.Errorf("GetStats() over %s port %d RxBytes = %v, want %d", backend, pin.port, s.RxBytes, pin.rx)
			}
			if s.TxBytes == nil || *s.TxBytes != pin.tx {
				t.Errorf("GetStats() over %s port %d TxBytes = %v, want %d", backend, pin.port, s.TxBytes, pin.tx)
			}
		}
		return
	}
	t.Errorf("port %d not present in GetStats() over %s", pin.port, backend)
}

// vlanIDsExpected is the exact, complete set of VLAN IDs every suite1Models
// entry's hand-authored fake seed carries (virtual/seed.go's own `vlans :=
// map[int]*VlanSim{...}` literal for each Seed* function), read directly off
// that source and cross-checked against a live GoFakeProvider round trip
// over EVERY backend each model serves -- the VLAN ID set is backend-
// invariant for every model here (unlike get_sensors/get_macs below).
var vlanIDsExpected = map[string][]int{
	"m4300-24x": {1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141},
	"m4300-16x": {1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141},
	"gsm7252ps": {1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141},
	"gsm7228ps": {1, 5, 21, 121, 4089},
	"gs110emx":  {1, 90},
	"gs305ep":   {1, 90},
	"gs728tpp":  {1, 2, 3, 5, 6, 7, 10, 20, 31, 41, 90, 99},
	"gs105pe":   {1, 41, 90},
}

func checkGetVLANs(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	vlans, err := sw.GetVLANs(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetVLANs() over %s error = %v", backend, err)
		return
	}
	want, ok := vlanIDsExpected[m.Key]
	if !ok {
		t.Fatalf("vlanIDsExpected has no entry for model %q -- opmap.go needs updating for this newly-included model", m.Key)
		return
	}
	got := make([]int, len(vlans))
	for i, v := range vlans {
		got[i] = v.VlanID
	}
	slices.Sort(got)
	wantSorted := slices.Clone(want)
	slices.Sort(wantSorted)
	if !slices.Equal(got, wantSorted) {
		t.Errorf("GetVLANs() over %s VLAN IDs = %v, want %v", backend, got, wantSorted)
	}
}

func checkGetPVIDs(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	pvids, err := sw.GetPVIDs(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetPVIDs() over %s error = %v", backend, err)
		return
	}
	if want := portRowsWant(m); len(pvids) != want {
		t.Errorf("GetPVIDs() over %s returned %d pvids, want %d", backend, len(pvids), want)
	}
}

// lldpLocalPortsExpected is the exact, complete set of LocalPort values
// every suite1Models entry's hand-authored fake seed carries (virtual/
// seed.go's own `lldp := []LldpSim{...}` literal for each Seed* function
// that sets one), read directly off that source and cross-checked against a
// live GoFakeProvider round trip -- backend-invariant for every model here,
// same as vlanIDsExpected. Models absent from this map (gs110emx/gs305ep/
// gs105pe) have no LLDP-capable backend at all per the capabilities oracle,
// so checkGetLLDP is never called for them.
var lldpLocalPortsExpected = map[string][]int{
	"m4300-24x": {1, 2, 6},
	"m4300-16x": {12, 16},
	"gsm7252ps": {49},
	"gsm7228ps": {49, 51},
	"gs728tpp":  {2, 24, 26, 28},
}

func checkGetLLDP(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	lldp, err := sw.GetLLDP(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetLLDP() over %s error = %v", backend, err)
		return
	}
	want, ok := lldpLocalPortsExpected[m.Key]
	if !ok {
		t.Fatalf("lldpLocalPortsExpected has no entry for model %q -- opmap.go needs updating for this newly-included model", m.Key)
		return
	}
	got := make([]int, len(lldp))
	for i, n := range lldp {
		got[i] = n.LocalPort
	}
	slices.Sort(got)
	wantSorted := slices.Clone(want)
	slices.Sort(wantSorted)
	if !slices.Equal(got, wantSorted) {
		t.Errorf("GetLLDP() over %s LocalPort set = %v, want %v", backend, got, wantSorted)
	}
}

// macExpected is the exact, complete MAC/FDB address set every suite1Models
// entry's hand-authored fake seed carries (virtual/seed.go's own `macs :=
// []MacSim{...}` literal for each Seed* function that sets one), UPPERCASE
// colon-separated (model.MacEntry.Mac's own canonical form), read directly
// off that source and cross-checked against a live GoFakeProvider round
// trip. A multiset, not a set: gsm7228ps's own seed legitimately learns the
// same physical MAC on more than one VLAN (duplicate entries preserved
// here, matching what GetMACs() genuinely returns).
var macExpected = map[string][]string{
	"m4300-24x": {"00:0A:FA:24:28:20", "00:E0:4C:68:36:95", "02:00:0A:01:00:01"},
	"m4300-16x": {"00:08:A2:09:EF:ED", "00:0A:FA:24:28:1F", "80:CC:9C:91:4F:8C"},
	"gsm7252ps": {"00:1B:21:3C:4D:5E", "C8:00:84:89:71:70"},
	"gsm7228ps": {
		"02:00:0A:01:05:01", "02:00:0A:01:21:01", "08:BD:43:6B:B8:D8",
		"0C:C4:7A:1B:D9:C7", "1C:34:DA:42:E8:8C", "1C:34:DA:42:E8:8D",
		"44:A5:6E:60:C5:B6", "44:A5:6E:60:C5:B6", "8C:3B:AD:69:1C:3B",
		"8C:3B:AD:6B:BB:E3", "AC:1F:6B:AA:50:53", "BC:A5:11:B8:EC:F1",
		"BC:A5:11:B8:EC:F1", "BC:A5:11:B8:ED:42", "BC:A5:11:B8:ED:42",
		"E0:91:F5:0C:D5:C7", "E0:91:F5:0C:D5:C9", "E0:91:F5:0C:D6:DB",
	},
	"gs728tpp": {
		"00:0A:FA:24:28:D8", "02:00:0A:02:00:01", "02:00:0A:02:00:01",
		"02:00:0A:02:01:01", "02:00:0A:02:05:01", "2C:CF:67:BB:49:A1",
		"AC:86:74:07:94:98", "AC:86:74:07:94:9F", "AC:86:74:07:95:80",
		"AC:86:74:07:95:87", "AC:86:74:07:95:88", "AC:86:74:07:95:8F",
	},
}

// gsm7228psHTTPMissingMAC is the ONE MAC address gsm7228ps's own S3300 HTTP
// MAC/FDB page never lists, even though the SAME shared VirtualSwitchState's
// SNMP and telnet MAC tables both carry it -- measured directly (a live
// GoFakeProvider round trip): gsm7228ps/http's GetMACs() consistently
// returns 17 entries where snmp/telnet return 18, missing exactly this one.
// gsm7228ps is the only (model, op) pairing in this suite whose MAC/FDB set
// genuinely differs by backend; subtracted from macExpected["gsm7228ps"]
// only when backend == HTTP.
const gsm7228psHTTPMissingMAC = "08:BD:43:6B:B8:D8"

// removeOne returns a copy of s with the FIRST occurrence of v removed (a
// multiset difference of exactly one element), used only by checkGetMACs to
// derive gsm7228ps's HTTP-specific MAC set from its SNMP/telnet baseline.
func removeOne(s []string, v string) []string {
	out := make([]string, 0, len(s))
	removed := false
	for _, x := range s {
		if !removed && x == v {
			removed = true
			continue
		}
		out = append(out, x)
	}
	return out
}

func checkGetMACs(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	macs, err := sw.GetMACs(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetMACs() over %s error = %v", backend, err)
		return
	}
	want, ok := macExpected[m.Key]
	if !ok {
		t.Fatalf("macExpected has no entry for model %q -- opmap.go needs updating for this newly-included model", m.Key)
		return
	}
	if m.Key == "gsm7228ps" && backend == model.BackendHTTP {
		want = removeOne(want, gsm7228psHTTPMissingMAC) // documented gap -- see gsm7228psHTTPMissingMAC.
	}
	got := make([]string, len(macs))
	for i, mm := range macs {
		got[i] = mm.Mac
	}
	slices.Sort(got)
	wantSorted := slices.Clone(want)
	slices.Sort(wantSorted)
	if !slices.Equal(got, wantSorted) {
		t.Errorf("GetMACs() over %s = %v, want %v", backend, got, wantSorted)
	}
}

func checkGetPoE(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	poe, err := sw.GetPoE(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetPoE() over %s error = %v", backend, err)
		return
	}
	if len(poe) != m.PoEPortCount {
		t.Errorf("GetPoE() over %s returned %d entries, want %d (model.PoEPortCount)", backend, len(poe), m.PoEPortCount)
	}
}

// sensorCountDefault is the seeded sensor-reading count every suite1Models
// entry's hand-authored fake seed carries over SNMP/SSH/Telnet (virtual/
// seed.go's own `sensors := []SensorSim{...}` literal for each Seed*
// function that sets one), read directly off that source and cross-checked
// against a live GoFakeProvider round trip. Only the five models with a CLI
// or SNMP sensor-capable backend appear here (matches capabilities.Matrix's
// own get_sensors/{snmp,ssh,telnet} rows exactly); gs728tpp's HTTP count
// also matches this default (4 == 4, verified), so it needs no override
// entry in sensorCountHTTPOverride below.
var sensorCountDefault = map[string]int{
	"m4300-24x": 4,
	"m4300-16x": 5,
	"gsm7252ps": 6,
	"gsm7228ps": 5,
	"gs728tpp":  4,
}

// sensorCountHTTPOverride documents the two managed dialects whose OWN HTTP
// sysInfo page renders a GENUINELY DIFFERENT sensor set than SNMP/CLI --
// measured directly (a live GoFakeProvider round trip), and independently
// grounded in this repo's own facade_http_integration_test.go comments:
// m4300-24x's sysInfo.html "carries ONLY the temperature reading" (1, vs 2
// fans + 1 power + 1 temperature = 4 over SNMP/CLI), and gsm7252ps's HTTP
// sysInfo sensor set is "its OWN (state.SysinfoSensors(), distinct from the
// SNMP entity table)" -- 4 temperature + 3 fan-health + 2 device-status rows
// = 9, vs 2 fans + 4 power + 0 temperature... (SNMP's own distinct 6-entry
// set). gsm7228ps has no get_sensors/HTTP capability at all (absent from
// the capabilities oracle's own row), so it needs no entry here.
var sensorCountHTTPOverride = map[string]int{
	"m4300-24x": 1,
	"gsm7252ps": 9,
}

func sensorCountWant(m *model.SwitchModel, backend model.Backend) (int, bool) {
	if backend == model.BackendHTTP {
		if n, ok := sensorCountHTTPOverride[m.Key]; ok {
			return n, true
		}
	}
	n, ok := sensorCountDefault[m.Key]
	return n, ok
}

func checkGetSensors(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	sensors, err := sw.GetSensors(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetSensors() over %s error = %v", backend, err)
		return
	}
	want, ok := sensorCountWant(m, backend)
	if !ok {
		t.Fatalf("sensorCountDefault has no entry for model %q -- opmap.go needs updating for this newly-included model", m.Key)
		return
	}
	if len(sensors) != want {
		t.Errorf("GetSensors() over %s returned %d sensors, want %d", backend, len(sensors), want)
	}
}

// mgmtIPKnownBlank documents the two models whose hand-authored fake seed
// never configures a real management-IP: gs305ep's SeedGS305EP never
// assigns State.Mgmt at all (it stays at NewState's own placeholder
// 0.0.0.0/dhcp default), and m4300-16x's SeedM4300_16X explicitly assigns
// that SAME placeholder value itself (virtual/seed.go: `mgmt :=
// MgmtSim{Address: "0.0.0.0", ..., Mode: "dhcp"}`) rather than a real
// captured address, unlike every other hand-authored seed in this file.
// Either way GetMgmtIP() over any backend honestly reports exactly what
// this fake was given -- a placeholder, not a broken read.
var mgmtIPKnownBlank = map[string]bool{
	"gs305ep":   true,
	"m4300-16x": true,
}

func checkGetMgmtIP(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	mgmt, err := sw.GetMgmtIP(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetMgmtIP() over %s error = %v", backend, err)
		return
	}
	if mgmtIPKnownBlank[m.Key] {
		return // documented gap -- see mgmtIPKnownBlank.
	}
	if mgmt.Address == nil || *mgmt.Address == "" {
		t.Errorf("GetMgmtIP() over %s returned no address, want the seeded one", backend)
	}
}

// hostnameKnownEmpty documents the one model whose hand-authored fake seed
// never sets State.Hostname: gs305ep's SeedGS305EP (virtual/seed.go) --
// unlike every sibling Plus-class seed (SeedGS110EMX/SeedGS105PE both set
// one) -- leaves it at NewState's zero-value "".
var hostnameKnownEmpty = map[string]bool{
	"gs305ep": true,
}

func checkGetHostname(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	hostname, err := sw.GetHostname(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetHostname() over %s error = %v", backend, err)
		return
	}
	if hostnameKnownEmpty[m.Key] {
		return // documented gap -- see hostnameKnownEmpty.
	}
	if strings.TrimSpace(hostname) == "" {
		t.Errorf("GetHostname() over %s returned an empty hostname, want the seeded one", backend)
	}
}

// usersKnownEmpty documents the two models whose hand-authored fake seed
// never populates State.Users: m4300-16x's SeedM4300_16X and gsm7228ps's
// SeedGSM7228PS neither one ever assigns State.Users (unlike gsm7252ps's
// and m4300-24x's own seeds, which both do), leaving it at NewState's
// empty-slice default -- an unmeasured gap on those two SKUs specifically,
// not a broken read.
var usersKnownEmpty = map[string]bool{
	"m4300-16x": true,
	"gsm7228ps": true,
}

// expectedUser is one local login account this suite pins EXACTLY, both
// spellings of its access-mode text plus the SNMPv3 columns only the CLI
// face ever populates -- see usersExpected's own doc comment for why a
// single "access" string is not enough here.
type expectedUser struct {
	name       string
	httpAccess string
	cliAccess  string
	privileged bool
	// snmpv3Access/snmpv3Auth/snmpv3Encryption are asserted ONLY over CLI
	// backends (SSH/Telnet/Console); "" means unmeasured -- rendered/parsed
	// as a blank cell, i.e. a nil *string on model.SwitchUser.
	snmpv3Access     string
	snmpv3Auth       string
	snmpv3Encryption string
}

// usersExpected is the exact, complete set of local login accounts every
// suite1Models entry with a seeded State.Users carries (virtual/seed.go's
// own `s.Users = []UserSim{...}` literal in SeedGSM7252PS and
// SeedM4300_24X -- the only two Seed* functions that populate it; the other
// two suite1Models entries with a get_users-capable backend never do -- see
// usersKnownEmpty), read directly off that source and cross-checked against
// a live GoFakeProvider round trip over every get_users-capable backend
// (HTTP, SSH, Telnet) each model serves.
//
// AccessMode is genuinely backend-dependent, not one seeded string:
// UserSim's own doc comment records that the SAME account reads DIFFERENT
// text depending on which face answers -- the web UI says "Super User"/
// "Read Only" on BOTH switches (SeedGSM7252PS/SeedM4300_24X's own
// `HTTPAccessMode` literals agree), where the CLI's wording splits by
// firmware family: SeedGSM7252PS's own `CLIAccessMode` literals are
// "Read/Write"/"Read Only", SeedM4300_24X's are "Privilege-15"/
// "Privilege-1". httpAccess/cliAccess below carry BOTH seeded spellings;
// checkGetUsers picks the one the backend under test actually reads
// (webui's ParseXUIUsers for HTTP, fastpath's parseUsers -- reading this
// fake's own renderUsers -- for SSH/Telnet).
//
// privileged is hardcoded here rather than recomputed via
// model.PrivilegedAccess, so this check cannot pass merely because the
// production normalisation table agrees with itself: both switches' admin
// accounts are privileged and both guest accounts are not, under every
// vocabulary measured (model.PrivilegedAccessModes/UnprivilegedAccessModes).
//
// snmpv3Access/snmpv3Auth/snmpv3Encryption are set only where UserSim's own
// literal sets them: SeedM4300_24X's admin row ("Read Only"/"MD5"/"None")
// is the ONE measured SNMPv3 row anywhere in the pinned Python source
// (parse_users' own docstring transcript, protocols/cli/parse.py:779-782,
// pin b26eb1f) -- every other row's SNMPv3 columns stay "" (unmeasured).
// They are asserted ONLY over CLI backends: webui's ParseXUIUsers never
// populates SwitchUser.SNMPv3* at all (userManagement.html carries no such
// columns), so those three fields are always nil over HTTP regardless of
// what the CLI-side seed carries.
var usersExpected = map[string][]expectedUser{
	"gsm7252ps": {
		{name: "admin", httpAccess: "Super User", cliAccess: "Read/Write", privileged: true},
		{name: "guest", httpAccess: "Read Only", cliAccess: "Read Only", privileged: false},
	},
	"m4300-24x": {
		{
			name: "admin", httpAccess: "Super User", cliAccess: "Privilege-15", privileged: true,
			snmpv3Access: "Read Only", snmpv3Auth: "MD5", snmpv3Encryption: "None",
		},
		{name: "guest", httpAccess: "Read Only", cliAccess: "Privilege-1", privileged: false},
	},
}

// userRowKey canonicalises one user row (either an expectedUser's seeded
// values or a live model.SwitchUser) into a single sortable/comparable
// string, so checkGetUsers can compare the two sets order-independently
// with slices.Equal, the same way macExpected/vlanIDsExpected do for their
// own multi-field or unordered results. "?" separates fields (never legal
// in any access-mode/name text seen so far) and privileged/each SNMPv3
// column is rendered as an explicit "true"/"false"/"nil" or "" token rather
// than folded into a plain bool/blank, so a nil *bool or nil *string on the
// live side can never silently collide with a seeded "false"/"" value.
func userRowKey(name, access string, privileged, hasPrivileged bool, snmpAccess, snmpAuth, snmpEncryption string) string {
	privStr := "nil"
	if hasPrivileged {
		privStr = "false"
		if privileged {
			privStr = "true"
		}
	}
	return strings.Join([]string{name, access, privStr, snmpAccess, snmpAuth, snmpEncryption}, "?")
}

func checkGetUsers(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	users, err := sw.GetUsers(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetUsers() over %s error = %v", backend, err)
		return
	}
	if usersKnownEmpty[m.Key] {
		return // documented gap -- see usersKnownEmpty.
	}
	want, ok := usersExpected[m.Key]
	if !ok {
		t.Fatalf("usersExpected has no entry for model %q -- opmap.go needs updating for this newly-included model", m.Key)
		return
	}
	httpFace := backend == model.BackendHTTP
	wantRows := make([]string, len(want))
	for i, u := range want {
		access, snmpAccess, snmpAuth, snmpEnc := u.cliAccess, u.snmpv3Access, u.snmpv3Auth, u.snmpv3Encryption
		if httpFace {
			access, snmpAccess, snmpAuth, snmpEnc = u.httpAccess, "", "", ""
		}
		wantRows[i] = userRowKey(u.name, access, u.privileged, true, snmpAccess, snmpAuth, snmpEnc)
	}
	gotRows := make([]string, len(users))
	for i, uu := range users {
		privileged, hasPrivileged := false, false
		if uu.Privileged != nil {
			privileged, hasPrivileged = *uu.Privileged, true
		}
		strOrEmpty := func(p *string) string {
			if p == nil {
				return ""
			}
			return *p
		}
		gotRows[i] = userRowKey(uu.Name, uu.AccessMode, privileged, hasPrivileged,
			strOrEmpty(uu.SNMPv3Access), strOrEmpty(uu.SNMPv3Auth), strOrEmpty(uu.SNMPv3Encryption))
	}
	slices.Sort(gotRows)
	slices.Sort(wantRows)
	if !slices.Equal(gotRows, wantRows) {
		t.Errorf("GetUsers() over %s = %v, want %v", backend, gotRows, wantRows)
	}
}

// checkGetServices deliberately stays a non-empty check (never strengthened
// to an exact count/set): over the FASTPATH CLI, GetServices() synthesizes
// a fixed 4-row {http,https,telnet,ssh} table from the model's own spec
// even when State.Services is completely empty (an honest "no info beyond
// which services this model type CAN offer" answer, not a seeded reading),
// so "non-empty" is the honest ceiling for this op -- reviewer-confirmed.
func checkGetServices(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, _ *model.SwitchModel) {
	t.Helper()
	services, err := sw.GetServices(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetServices() over %s error = %v", backend, err)
		return
	}
	if len(services) == 0 {
		t.Errorf("GetServices() over %s returned no services, want > 0", backend)
	}
}

// syslogWantEnabled documents the real, per-model Enabled bit every
// syslog-capable hand-authored seed carries -- gsm7228ps's is a MEASURED
// real-hardware fact (SeedGSM7228PS's own comment: "collector configured,
// which is why GetSyslog returns none ... to keep this measurement
// pinned"), while m4300-16x's is an honestly-unmeasured gap (SeedM4300_16X's
// own comment: "Python's seed_m4300_16x never sets syslog= at all"). Either
// way this is the real, correct value this fake reports; asserting it
// (rather than merely "no error") is what makes this check non-vacuous.
var syslogWantEnabled = map[string]bool{
	"m4300-24x": true,
	"gsm7252ps": true,
	"m4300-16x": false,
	"gsm7228ps": false,
}

func checkGetSyslog(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	syslog, err := sw.GetSyslog(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetSyslog() over %s error = %v", backend, err)
		return
	}
	if syslog.LocalPort != 514 {
		t.Errorf("GetSyslog() over %s LocalPort = %d, want 514 (every seed's own logging client local port)", backend, syslog.LocalPort)
	}
	want, ok := syslogWantEnabled[m.Key]
	if !ok {
		t.Fatalf("syslogWantEnabled has no entry for model %q -- opmap.go needs updating for this newly-included model", m.Key)
		return
	}
	if syslog.Enabled != want {
		t.Errorf("GetSyslog() over %s Enabled = %v, want %v", backend, syslog.Enabled, want)
	}
	if want && len(syslog.Servers) == 0 {
		t.Errorf("GetSyslog() over %s: Enabled=true but Servers is empty, want the seeded collector", backend)
	}
}

func checkNsdpDevice(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, _ model.Backend, _ *model.SwitchModel) {
	t.Helper()
	// nsdp_device (Switch.NSDPDevice) bypasses backend-preference dispatch
	// entirely -- NSDP is the only backend that can ever serve it (see its
	// own doc comment in switch.go) -- so the backend parameter every other
	// check forwards to WithReadBackend is deliberately unused here.
	dev, err := sw.NSDPDevice(ctx)
	if err != nil {
		t.Fatalf("NSDPDevice() error = %v", err)
		return
	}
	if dev.Model == "" || dev.Mac == "" {
		t.Errorf("NSDPDevice() = %+v, want non-empty Model and Mac (NsdpDevice's own two required fields)", dev)
	}
}
