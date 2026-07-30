// switch_read_test.go: tests for the SNMP BackendBuilder (backend_snmp.go),
// the read methods + GetMacs's require_mac_table gate + Identify's dispatch
// bypass (switch.go), and Snapshot's per-field degrade semantics
// (snapshot.go). See D-FAC §1.5, §2.5, §2.9, §2.11, §2.12 for the exact
// semantics under test; reuses switch_test.go's fakeModel/
// withRegisteredBackend/clearBackendRegistry fixtures (same package).

package netgearswitch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// --- test fixtures ---------------------------------------------------------

// stubReader is a fully-configurable BackendReader test double: each method
// returns its own preset value/error pair independently, so a single fixture
// can model "this backend serves ports+vlans but not macs/lldp/sensors"
// (Snapshot's per-field degrade tests) without needing a new type per case.
type stubReader struct {
	ports      []model.PortStatus
	portsErr   error
	stats      []model.PortStats
	statsErr   error
	vlans      []model.VLANInfo
	vlansErr   error
	pvids      []model.Pvid
	pvidsErr   error
	lldp       []model.LLDPNeighbor
	lldpErr    error
	macs       []model.MacEntry
	macsErr    error
	poe        []model.PoEStatus
	poeErr     error
	sensors    []model.Sensor
	sensorsErr error
	mgmtIP     model.MgmtIPConfig
	mgmtIPErr  error
}

func (s *stubReader) GetPorts(context.Context) ([]model.PortStatus, error) {
	if s.portsErr != nil {
		return nil, s.portsErr
	}
	return s.ports, nil
}
func (s *stubReader) GetStats(context.Context) ([]model.PortStats, error) {
	if s.statsErr != nil {
		return nil, s.statsErr
	}
	return s.stats, nil
}
func (s *stubReader) GetVlans(context.Context) ([]model.VLANInfo, error) {
	if s.vlansErr != nil {
		return nil, s.vlansErr
	}
	return s.vlans, nil
}
func (s *stubReader) GetPvids(context.Context) ([]model.Pvid, error) {
	if s.pvidsErr != nil {
		return nil, s.pvidsErr
	}
	return s.pvids, nil
}
func (s *stubReader) GetLldp(context.Context) ([]model.LLDPNeighbor, error) {
	if s.lldpErr != nil {
		return nil, s.lldpErr
	}
	return s.lldp, nil
}
func (s *stubReader) GetMacs(context.Context) ([]model.MacEntry, error) {
	if s.macsErr != nil {
		return nil, s.macsErr
	}
	return s.macs, nil
}
func (s *stubReader) GetPoe(context.Context) ([]model.PoEStatus, error) {
	if s.poeErr != nil {
		return nil, s.poeErr
	}
	return s.poe, nil
}
func (s *stubReader) GetSensors(context.Context) ([]model.Sensor, error) {
	if s.sensorsErr != nil {
		return nil, s.sensorsErr
	}
	return s.sensors, nil
}
func (s *stubReader) GetMgmtIP(context.Context) (model.MgmtIPConfig, error) {
	if s.mgmtIPErr != nil {
		return model.MgmtIPConfig{}, s.mgmtIPErr
	}
	return s.mgmtIP, nil
}

// wrapUnsupported/wrapCredential build an error that errors.Is-matches the
// named sentinel, mirroring how real backend code wraps it.
func wrapUnsupported(msg string) error {
	return fmt.Errorf("%s: %w", msg, model.ErrUnsupportedCapability)
}

func wrapCredential(msg string) error {
	return fmt.Errorf("%s: %w", msg, model.ErrCredential)
}

// --- fakeSNMPClient: a minimal snmp.Client double for backend_snmp.go/Identify tests

// fakeSNMPClient answers Get/Walk from a fixed table keyed by OID, recording
// nothing -- just enough for buildSNMPReader/Identify tests that need a real
// snmp.Client without a live agent.
type fakeSNMPClient struct {
	table map[string][]snmp.Row
}

func (f *fakeSNMPClient) Get(_ context.Context, oids []string) ([]snmp.Row, error) {
	var rows []snmp.Row
	for _, oid := range oids {
		rows = append(rows, f.table[oid]...)
	}
	return rows, nil
}

func (f *fakeSNMPClient) Walk(_ context.Context, base string) ([]snmp.Row, error) {
	return append([]snmp.Row(nil), f.table[base]...), nil
}

// sysInfoTable builds a fakeSNMPClient table answering SysDescr/SysObjectID
// with sysDescr text that DetectModelFromSysDescr matches to modelKey (every
// registered model's DisplayName is unique-ish text the fallback heuristic
// keys off; using the exact DisplayName guarantees a match without needing
// to know the heuristic's internals).
func sysInfoTable(t *testing.T, modelKey string) map[string][]snmp.Row {
	t.Helper()
	m, err := model.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q): %v", modelKey, err)
	}
	return map[string][]snmp.Row{
		snmp.SysDescr:    {snmp.NewStrRow(snmp.SysDescr, m.DisplayName)},
		snmp.SysObjectID: {snmp.NewStrRow(snmp.SysObjectID, "1.3.6.1.4.1.99999.1.1")}, // deliberately unregistered OID: forces the sysDescr fallback path
	}
}

// --- GetPorts/GetStats/GetVlans/GetPvids/GetLldp/GetPoe/GetSensors/GetMgmtIP: plain delegation ---

func TestSwitch_GetPorts_DelegatesToBackend(t *testing.T) {
	clearBackendRegistry(t)
	want := []model.PortStatus{{Port: 1, AdminEnabled: true}}
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{ports: want}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	got, err := sw.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(got) != 1 || got[0].Port != 1 {
		t.Fatalf("GetPorts() = %v, want %v", got, want)
	}
}

func TestSwitch_GetPorts_PropagatesBackendError(t *testing.T) {
	clearBackendRegistry(t)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{portsErr: wrapCredential("boom")}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	if _, err := sw.GetPorts(context.Background()); !errors.Is(err, model.ErrCredential) {
		t.Fatalf("GetPorts() error = %v, want wrapping ErrCredential", err)
	}
}

func TestSwitch_GetStats_DelegatesToBackend(t *testing.T) {
	clearBackendRegistry(t)
	want := []model.PortStats{{Port: 1, RxBytes: model.Ptr(uint64(42))}}
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{stats: want}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	got, err := sw.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	if len(got) != 1 || *got[0].RxBytes != 42 {
		t.Fatalf("GetStats() = %v, want %v", got, want)
	}
}

func TestSwitch_GetStats_PropagatesBackendError(t *testing.T) {
	clearBackendRegistry(t)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{statsErr: wrapCredential("boom")}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	if _, err := sw.GetStats(context.Background()); !errors.Is(err, model.ErrCredential) {
		t.Fatalf("GetStats() error = %v, want wrapping ErrCredential", err)
	}
}

func TestSwitch_GetVlans_DelegatesToBackend(t *testing.T) {
	clearBackendRegistry(t)
	want := []model.VLANInfo{{VlanID: 5}}
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{vlans: want}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	got, err := sw.GetVlans(context.Background())
	if err != nil {
		t.Fatalf("GetVlans() error = %v", err)
	}
	if len(got) != 1 || got[0].VlanID != 5 {
		t.Fatalf("GetVlans() = %v, want %v", got, want)
	}
}

func TestSwitch_GetVlans_PropagatesBackendError(t *testing.T) {
	clearBackendRegistry(t)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{vlansErr: wrapCredential("boom")}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	if _, err := sw.GetVlans(context.Background()); !errors.Is(err, model.ErrCredential) {
		t.Fatalf("GetVlans() error = %v, want wrapping ErrCredential", err)
	}
}

func TestSwitch_GetPvids_DelegatesToBackend(t *testing.T) {
	clearBackendRegistry(t)
	want := []model.Pvid{{Port: 1, Vlan: 5}}
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{pvids: want}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	got, err := sw.GetPvids(context.Background())
	if err != nil {
		t.Fatalf("GetPvids() error = %v", err)
	}
	if len(got) != 1 || got[0] != (model.Pvid{Port: 1, Vlan: 5}) {
		t.Fatalf("GetPvids() = %v, want %v", got, want)
	}
}

func TestSwitch_GetPvids_PropagatesBackendError(t *testing.T) {
	clearBackendRegistry(t)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{pvidsErr: wrapCredential("boom")}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	if _, err := sw.GetPvids(context.Background()); !errors.Is(err, model.ErrCredential) {
		t.Fatalf("GetPvids() error = %v, want wrapping ErrCredential", err)
	}
}

func TestSwitch_GetLldp_DelegatesToBackend(t *testing.T) {
	clearBackendRegistry(t)
	want := []model.LLDPNeighbor{{LocalPort: 1, RemoteSysName: model.Ptr("neighbor")}}
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{lldp: want}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	got, err := sw.GetLldp(context.Background())
	if err != nil {
		t.Fatalf("GetLldp() error = %v", err)
	}
	if len(got) != 1 || *got[0].RemoteSysName != "neighbor" {
		t.Fatalf("GetLldp() = %v, want %v", got, want)
	}
}

func TestSwitch_GetPoe_DelegatesToBackend(t *testing.T) {
	clearBackendRegistry(t)
	want := []model.PoEStatus{{Port: 1, Detect: model.PoEDetectDelivering}}
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{poe: want}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	got, err := sw.GetPoe(context.Background())
	if err != nil {
		t.Fatalf("GetPoe() error = %v", err)
	}
	if len(got) != 1 || !got[0].Delivering() {
		t.Fatalf("GetPoe() = %v, want %v", got, want)
	}
}

func TestSwitch_GetSensors_DelegatesToBackend(t *testing.T) {
	clearBackendRegistry(t)
	want := []model.Sensor{{Name: "fan1", Kind: "fan", Value: 3500, Unit: "RPM"}}
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{sensors: want}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	got, err := sw.GetSensors(context.Background())
	if err != nil {
		t.Fatalf("GetSensors() error = %v", err)
	}
	if len(got) != 1 || got[0].Name != "fan1" {
		t.Fatalf("GetSensors() = %v, want %v", got, want)
	}
}

func TestSwitch_GetMgmtIP_DelegatesToBackend(t *testing.T) {
	clearBackendRegistry(t)
	want := model.MgmtIPConfig{Mode: model.IPModeStatic, Address: model.Ptr("10.0.0.1")}
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{mgmtIP: want}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	got, err := sw.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if got.Mode != model.IPModeStatic || *got.Address != "10.0.0.1" {
		t.Fatalf("GetMgmtIP() = %v, want %v", got, want)
	}
}

// --- GetMacs: require_mac_table gate ---------------------------------------

func TestSwitch_GetMacs_NoMacTable_GatesBeforeDispatch(t *testing.T) {
	clearBackendRegistry(t)
	withRegisteredBackend(t, model.BackendNSDP, func(_ *Switch) (BackendReader, error) {
		t.Fatal("NSDP builder invoked: require_mac_table must gate BEFORE dispatch")
		return nil, nil
	})
	withRegisteredBackend(t, model.BackendHTTP, func(_ *Switch) (BackendReader, error) {
		t.Fatal("HTTP builder invoked: require_mac_table must gate BEFORE dispatch")
		return nil, nil
	})

	// No SNMP backend => HasMACTable() is false.
	m := fakeModel("gs305ep-like", model.BackendNSDP, model.BackendHTTP)
	sw := mustSwitch(t, m, "10.0.0.1")

	_, err := sw.GetMacs(context.Background())
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("GetMacs() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "mac") {
		t.Fatalf("GetMacs() error = %q, want it to mention the MAC/FDB table", err.Error())
	}
}

func TestSwitch_GetMacs_HasMacTable_Dispatches(t *testing.T) {
	clearBackendRegistry(t)
	want := []model.MacEntry{{Mac: "00:11:22:33:44:55", Port: 1}}
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{macs: want}, nil
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw := mustSwitch(t, m, "10.0.0.1")

	got, err := sw.GetMacs(context.Background())
	if err != nil {
		t.Fatalf("GetMacs() error = %v", err)
	}
	if len(got) != 1 || got[0].Mac != want[0].Mac {
		t.Fatalf("GetMacs() = %v, want %v", got, want)
	}
}

// --- Snapshot: per-field degrade semantics (D-FAC §2.12) --------------------

func TestSnapshot_PopulatesModelAndHost(t *testing.T) {
	clearBackendRegistry(t) // no backends registered at all: every field must degrade, not panic/error out
	m := fakeModel("fake", model.BackendSNMP)
	sw := mustSwitch(t, m, "10.0.0.7")

	data, err := sw.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if data.Model != "fake" || data.Host != "10.0.0.7" {
		t.Fatalf("Snapshot() model/host = %q/%q, want fake/10.0.0.7", data.Model, data.Host)
	}
}

func TestSnapshot_DegradesUnsupportedFieldsToEmptyAndFallsThroughToSecondBackend(t *testing.T) {
	clearBackendRegistry(t)
	// Mirrors D-FAC's pinned test_snapshot_on_plus_model_uses_nsdp_and_skips_unsupported_sections:
	// NSDP serves ports but raises Unsupported for macs/lldp/sensors/poe;
	// HTTP fills the poe gap NSDP left. gs305ep is a real {NSDP,HTTP} model.
	nsdpPorts := []model.PortStatus{{Port: 1, AdminEnabled: true}}
	withRegisteredBackend(t, model.BackendNSDP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{
			ports:      nsdpPorts,
			macsErr:    wrapUnsupported("nsdp has no macs"),
			lldpErr:    wrapUnsupported("nsdp has no lldp"),
			sensorsErr: wrapUnsupported("nsdp has no sensors"),
			poeErr:     wrapUnsupported("nsdp has no poe"),
			mgmtIPErr:  wrapUnsupported("nsdp mgmt ip gap for this test"),
		}, nil
	})
	httpPoe := []model.PoEStatus{{Port: 1, Detect: model.PoEDetectDelivering}}
	withRegisteredBackend(t, model.BackendHTTP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{poe: httpPoe, mgmtIPErr: wrapUnsupported("http mgmt ip gap for this test")}, nil
	})

	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("GetModel(gs305ep): %v", err)
	}
	sw := mustSwitch(t, m, "10.0.0.9")

	data, err := sw.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if len(data.Ports) != 1 {
		t.Fatalf("Snapshot().Ports = %v, want NSDP's one port", data.Ports)
	}
	if len(data.Macs) != 0 {
		t.Fatalf("Snapshot().Macs = %v, want empty (degraded)", data.Macs)
	}
	if len(data.Lldp) != 0 {
		t.Fatalf("Snapshot().Lldp = %v, want empty (degraded)", data.Lldp)
	}
	if len(data.Sensors) != 0 {
		t.Fatalf("Snapshot().Sensors = %v, want empty (degraded)", data.Sensors)
	}
	if len(data.PoE) != 1 || !data.PoE[0].Delivering() {
		t.Fatalf("Snapshot().PoE = %v, want HTTP's one delivering port (NSDP gap filled by HTTP)", data.PoE)
	}
	if data.MgmtIP != nil {
		t.Fatalf("Snapshot().MgmtIP = %v, want nil (degraded)", data.MgmtIP)
	}
}

func TestSnapshot_MgmtIPPopulatedOnSuccess(t *testing.T) {
	clearBackendRegistry(t)
	want := model.MgmtIPConfig{Mode: model.IPModeDHCP, Address: model.Ptr("10.0.0.5")}
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{mgmtIP: want}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	data, err := sw.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if data.MgmtIP == nil || data.MgmtIP.Mode != model.IPModeDHCP || *data.MgmtIP.Address != "10.0.0.5" {
		t.Fatalf("Snapshot().MgmtIP = %v, want populated %v", data.MgmtIP, want)
	}
}

func TestSnapshot_PropagatesCredentialErrorInsteadOfDegrading(t *testing.T) {
	clearBackendRegistry(t)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return nil, wrapCredential("no SNMP read community configured")
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	_, err := sw.Snapshot(context.Background())
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("Snapshot() error = %v, want wrapping ErrCredential (must NOT be swallowed as a degrade)", err)
	}
}

// TestSnapshot_LaterFieldCredentialErrorPropagates proves a non-Unsupported
// error from a field OTHER than the first one built (ports) still aborts
// Snapshot -- not just a builder-construction failure (the sibling test
// above), but an op-level error from a field several fields into the
// sequence (macs, which uses the ungated getMacsNoGate path).
func TestSnapshot_LaterFieldCredentialErrorPropagates(t *testing.T) {
	clearBackendRegistry(t)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{macsErr: wrapCredential("boom")}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	_, err := sw.Snapshot(context.Background())
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("Snapshot() error = %v, want wrapping ErrCredential", err)
	}
}

// TestSnapshot_MgmtIPCredentialErrorPropagates exercises mgmt_ip's own
// snapshotDegradePtr helper's non-Unsupported branch specifically, since
// mgmt_ip is NOT tuple-shaped like every other field (D-FAC §2.12) and so
// has its own degrade helper with its own propagate-vs-degrade branch to
// verify independently.
func TestSnapshot_MgmtIPCredentialErrorPropagates(t *testing.T) {
	clearBackendRegistry(t)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{mgmtIPErr: wrapCredential("boom")}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	_, err := sw.Snapshot(context.Background())
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("Snapshot() error = %v, want wrapping ErrCredential", err)
	}
}

func TestSnapshot_MacsFieldBypassesMacTableGateUnlikeGetMacs(t *testing.T) {
	clearBackendRegistry(t)
	// A model with only NSDP (no SNMP): HasMACTable() is false, so the
	// public GetMacs() must gate. But Snapshot's macs field calls the
	// UNGATED path (getMacsNoGate), so if the (fake, hypothetical) NSDP
	// reader actually answers get_macs, Snapshot must reflect that answer --
	// proving Snapshot never applies GetMacs's require_mac_table guard
	// (D-FAC §2.12/trap #5).
	macs := []model.MacEntry{{Mac: "AA:BB:CC:DD:EE:FF", Port: 2}}
	withRegisteredBackend(t, model.BackendNSDP, func(_ *Switch) (BackendReader, error) {
		return &stubReader{macs: macs}, nil
	})

	m := fakeModel("no-snmp", model.BackendNSDP)
	sw := mustSwitch(t, m, "10.0.0.1")

	if _, err := sw.GetMacs(context.Background()); !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("GetMacs() error = %v, want wrapping ErrUnsupportedCapability (gated, no MAC table)", err)
	}

	data, err := sw.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if len(data.Macs) != 1 || data.Macs[0].Mac != macs[0].Mac {
		t.Fatalf("Snapshot().Macs = %v, want %v (ungated dispatch must reach the NSDP fake)", data.Macs, macs)
	}
}

func TestSnapshot_ContextCancelledFailsFast(t *testing.T) {
	clearBackendRegistry(t)
	called := false
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		called = true
		return &stubReader{}, nil
	})
	sw := mustSwitch(t, fakeModel("fake", model.BackendSNMP), "10.0.0.1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := sw.Snapshot(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Snapshot() error = %v, want wrapping context.Canceled", err)
	}
	if called {
		t.Fatal("Snapshot() must fail fast on an already-cancelled context, never build a backend")
	}
}

// --- Identify: dispatch-bypass semantics (D-FAC §2.11) ----------------------

func TestIdentify_BypassesModelSNMPGate(t *testing.T) {
	// gs305ep-like model has NO SNMP backend at all -- Identify must still
	// work via the injected client, proving it never checks
	// s.model.HasBackend(model.BackendSNMP).
	m := fakeModel("gs305ep-like", model.BackendNSDP, model.BackendHTTP)
	client := &fakeSNMPClient{table: sysInfoTable(t, "gsm7252ps")}
	sw := mustSwitch(t, m, "10.0.0.1", WithSNMPClient(client))

	got, err := sw.Identify(context.Background())
	if err != nil {
		t.Fatalf("Identify() error = %v", err)
	}
	if !got.Matched() || *got.Key != "gsm7252ps" {
		t.Fatalf("Identify() = %+v, want matched key gsm7252ps", got)
	}
}

func TestIdentify_ReflectsDeviceNotBoundModel(t *testing.T) {
	// sw is BOUND to gsm7252ps, but the device on the wire reports xs748t's
	// sysDescr: Identify must reflect the DEVICE, never s.model.
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("GetModel: %v", err)
	}
	client := &fakeSNMPClient{table: sysInfoTable(t, "xs748t")}
	sw := mustSwitch(t, m, "10.0.0.1", WithSNMPClient(client))

	got, err := sw.Identify(context.Background())
	if err != nil {
		t.Fatalf("Identify() error = %v", err)
	}
	if !got.Matched() || *got.Key != "xs748t" {
		t.Fatalf("Identify() = %+v, want matched key xs748t (the device), not gsm7252ps (the bound model)", got)
	}
}

func TestIdentify_NoInjectedClientNoCommunity_ReturnsCredentialError(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	sw := mustSwitch(t, m, "10.0.0.1")

	_, err := sw.Identify(context.Background())
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("Identify() error = %v, want wrapping ErrCredential", err)
	}
}

func TestIdentify_DoesNotPopulateReaderCache(t *testing.T) {
	m := fakeModel("gs305ep-like", model.BackendNSDP)
	client := &fakeSNMPClient{table: sysInfoTable(t, "gsm7252ps")}
	sw := mustSwitch(t, m, "10.0.0.1", WithSNMPClient(client))

	if _, err := sw.Identify(context.Background()); err != nil {
		t.Fatalf("Identify() error = %v", err)
	}
	sw.mu.Lock()
	_, cached := sw.readerCache[model.BackendSNMP]
	sw.mu.Unlock()
	if cached {
		t.Fatal("Identify() populated s.readerCache[SNMP]; it must bypass the reader cache entirely")
	}
}

func TestIdentify_ContextCancelledFailsFast(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	sw := mustSwitch(t, m, "10.0.0.1", WithSNMPClient(&fakeSNMPClient{}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := sw.Identify(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Identify() error = %v, want wrapping context.Canceled", err)
	}
}

// --- backend_snmp.go: buildSNMPReader/buildSNMPClient/requireSNMPCommunity --

func TestBuildSNMPReader_NoCommunityNoInjectedClient_ReturnsCredentialError(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	sw := mustSwitch(t, m, "10.0.0.1")

	_, err := buildSNMPReader(sw)
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("buildSNMPReader() error = %v, want wrapping ErrCredential", err)
	}
}

func TestBuildSNMPReader_EmptyStringCommunityIsAccepted(t *testing.T) {
	// The read-side gate rejects only nil, NOT "" -- unlike the write/HTTP
	// gates (D-FAC §1.5, trap #1). WithSNMPCommunity("") must NOT raise
	// ErrCredential here.
	m := fakeModel("fake", model.BackendSNMP)
	sw := mustSwitch(t, m, "10.0.0.1", WithSNMPCommunity(""))

	_, err := buildSNMPReader(sw)
	if err != nil {
		t.Fatalf("buildSNMPReader() error = %v, want nil (empty community is accepted on the read side)", err)
	}
}

func TestBuildSNMPReader_UsesInjectedClientAsIs(t *testing.T) {
	clearBackendRegistry(t) // exercise the REAL registered SNMP builder, not a fake one
	client := &fakeSNMPClient{table: map[string][]snmp.Row{
		snmp.IfAdminStatus: {snmp.NewIntRow(snmp.IfAdminStatus+".1", 1)},
		snmp.IfOperStatus:  {snmp.NewIntRow(snmp.IfOperStatus+".1", 1)},
		snmp.IfHighSpeed:   {snmp.NewIntRow(snmp.IfHighSpeed+".1", 1000)},
		snmp.IfName:        {snmp.NewStrRow(snmp.IfName+".1", "1/0/1")},
		snmp.IfAlias:       {snmp.NewStrRow(snmp.IfAlias+".1", "uplink")},
	}}
	RegisterBackend(model.BackendSNMP, buildSNMPReader)

	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("GetModel: %v", err)
	}
	sw := mustSwitch(t, m, "10.0.0.1", WithSNMPClient(client))

	ports, err := sw.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != 1 || ports[0].Port != 1 {
		t.Fatalf("GetPorts() = %v, want one port using the injected fake client's data", ports)
	}
}

func TestBuildSNMPReader_NonSNMPModelIsUnsupported(t *testing.T) {
	m := fakeModel("plus-like", model.BackendNSDP)
	sw := mustSwitch(t, m, "10.0.0.1", WithSNMPCommunity("public"))

	_, err := buildSNMPReader(sw)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("buildSNMPReader() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
}

func TestSNMPBackendRegisteredAtInit(t *testing.T) {
	backendRegistryMu.RLock()
	_, ok := backendRegistry[model.BackendSNMP]
	backendRegistryMu.RUnlock()
	if !ok {
		t.Fatal("model.BackendSNMP has no builder registered; backend_snmp.go's init() must register one")
	}
}

// --- shared helpers ---------------------------------------------------------

func mustSwitch(t *testing.T, m *model.SwitchModel, host string, opts ...SwitchOption) *Switch {
	t.Helper()
	sw, err := New(m, host, opts...)
	if err != nil {
		t.Fatalf("New(%q, %q) error = %v", m.Key, host, err)
	}
	return sw
}
