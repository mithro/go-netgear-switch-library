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
// meaningful (ruling out a broken parse/empty response), but never so
// blanket-strong that it demands data a model's own hand-authored fake seed
// genuinely never populated (which would make an honest, working read look
// like a bug). Every such gap is called out, by name, in the small
// exception tables below, each with the seed evidence behind it -- never a
// silent skip.

import (
	"context"
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

func checkGetStats(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, m *model.SwitchModel) {
	t.Helper()
	stats, err := sw.GetStats(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetStats() over %s error = %v", backend, err)
		return
	}
	if statsKnownEmpty[m.Key] {
		return // documented gap -- see statsKnownEmpty.
	}
	if len(stats) == 0 {
		t.Errorf("GetStats() over %s returned no ports, want > 0", backend)
	}
}

func checkGetVLANs(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, _ *model.SwitchModel) {
	t.Helper()
	vlans, err := sw.GetVLANs(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetVLANs() over %s error = %v", backend, err)
		return
	}
	if len(vlans) == 0 {
		t.Errorf("GetVLANs() over %s returned no VLANs, want > 0 (every seed carries at least VLAN 1)", backend)
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

func checkGetLLDP(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, _ *model.SwitchModel) {
	t.Helper()
	lldp, err := sw.GetLLDP(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetLLDP() over %s error = %v", backend, err)
		return
	}
	if len(lldp) == 0 {
		t.Errorf("GetLLDP() over %s returned no neighbors, want > 0", backend)
	}
}

func checkGetMACs(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, _ *model.SwitchModel) {
	t.Helper()
	macs, err := sw.GetMACs(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetMACs() over %s error = %v", backend, err)
		return
	}
	if len(macs) == 0 {
		t.Errorf("GetMACs() over %s returned no MAC entries, want > 0", backend)
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

func checkGetSensors(ctx context.Context, t *testing.T, sw *netgearswitch.Switch, backend model.Backend, _ *model.SwitchModel) {
	t.Helper()
	sensors, err := sw.GetSensors(ctx, netgearswitch.WithReadBackend(backend))
	if err != nil {
		t.Fatalf("GetSensors() over %s error = %v", backend, err)
		return
	}
	if len(sensors) == 0 {
		t.Errorf("GetSensors() over %s returned no sensors, want > 0", backend)
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
	if len(users) == 0 {
		t.Errorf("GetUsers() over %s returned no users, want > 0", backend)
	}
}

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
