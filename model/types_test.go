package model_test

import (
	"encoding/json"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func TestPoEDetectValues(t *testing.T) {
	cases := []struct {
		got  model.PoEDetect
		want string
	}{
		{model.PoEDetectDisabled, "disabled"},
		{model.PoEDetectSearching, "searching"},
		{model.PoEDetectDelivering, "delivering"},
		{model.PoEDetectFault, "fault"},
		{model.PoEDetectUnknown, "unknown"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("got %q, want %q", string(c.got), c.want)
		}
	}
}

func TestVlanModeValues(t *testing.T) {
	cases := []struct {
		got  model.VlanMode
		want string
	}{
		{model.VlanUntagged, "untagged"},
		{model.VlanTagged, "tagged"},
		{model.VlanExcluded, "excluded"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("got %q, want %q", string(c.got), c.want)
		}
	}
}

func TestIPModeValues(t *testing.T) {
	cases := []struct {
		got  model.IPMode
		want string
	}{
		{model.IPModeDHCP, "dhcp"},
		{model.IPModeStatic, "static"},
		{model.IPModeUnknown, "unknown"},
	}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("got %q, want %q", string(c.got), c.want)
		}
	}
}

func TestPoEStatusDelivering(t *testing.T) {
	delivering := model.PoEStatus{Detect: model.PoEDetectDelivering}
	if !delivering.Delivering() {
		t.Error("expected Delivering() true for PoEDetectDelivering")
	}

	searching := model.PoEStatus{Detect: model.PoEDetectSearching}
	if searching.Delivering() {
		t.Error("expected Delivering() false for PoEDetectSearching")
	}
}

func TestDetectedModelMatched(t *testing.T) {
	matched := model.DetectedModel{Key: model.Ptr("gs305ep")}
	if !matched.Matched() {
		t.Error("expected Matched() true when Key is non-nil")
	}

	unmatched := model.DetectedModel{}
	if unmatched.Matched() {
		t.Error("expected Matched() false when Key is nil")
	}
}

func TestPtr(t *testing.T) {
	got := model.Ptr(42)
	if got == nil || *got != 42 {
		t.Fatalf("Ptr(42) = %v, want pointer to 42", got)
	}
}

func TestPortStatusMarshalJSON(t *testing.T) {
	ps := model.PortStatus{
		Port:         1,
		Name:         model.Ptr("1/0/1"),
		AdminEnabled: true,
		LinkUp:       false,
		SpeedMbps:    nil,
		Description:  nil,
	}

	b, err := json.Marshal(ps)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := `{"port":1,"name":"1/0/1","admin_enabled":true,"link_up":false,"speed_mbps":null,"description":null,"full_duplex":null,"flow_control":null,"speed_config":null}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
	}
}

// TestPortStatusSpeedConfigMarshalJSON pins the nested SpeedConfig shape
// once populated (§B: full_duplex/flow_control/speed_config additions).
func TestPortStatusSpeedConfigMarshalJSON(t *testing.T) {
	forced := model.ForcedPortSpeed(100, true)
	ps := model.PortStatus{
		Port:         2,
		Name:         model.Ptr("1/0/2"),
		AdminEnabled: true,
		LinkUp:       true,
		SpeedMbps:    model.Ptr(100),
		FullDuplex:   model.Ptr(true),
		FlowControl:  model.Ptr(false),
		SpeedConfig:  &forced,
	}

	b, err := json.Marshal(ps)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := `{"port":2,"name":"1/0/2","admin_enabled":true,"link_up":true,"speed_mbps":100,"description":null,"full_duplex":true,"flow_control":false,"speed_config":{"autonegotiate":false,"speed_mbps":100,"full_duplex":true}}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
	}
}

// TestAutoPortSpeed pins the invariant shape for an auto-negotiating
// PortSpeed: SpeedMbps and FullDuplex both nil, mirroring Python's
// PortSpeed.auto()/__post_init__ invariant.
func TestAutoPortSpeed(t *testing.T) {
	ps := model.AutoPortSpeed()
	if !ps.Autonegotiate {
		t.Error("expected Autonegotiate true")
	}
	if ps.SpeedMbps != nil {
		t.Errorf("expected SpeedMbps nil, got %v", *ps.SpeedMbps)
	}
	if ps.FullDuplex != nil {
		t.Errorf("expected FullDuplex nil, got %v", *ps.FullDuplex)
	}
	if got, want := ps.String(), "auto"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestForcedPortSpeed pins the invariant shape for a forced PortSpeed:
// both SpeedMbps and FullDuplex set, mirroring Python's
// PortSpeed.forced()/__post_init__ invariant.
func TestForcedPortSpeed(t *testing.T) {
	cases := []struct {
		name       string
		mbps       int
		fullDuplex bool
		wantStr    string
	}{
		{"full duplex", 1000, true, "1000M full-duplex"},
		{"half duplex", 100, false, "100M half-duplex"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ps := model.ForcedPortSpeed(c.mbps, c.fullDuplex)
			if ps.Autonegotiate {
				t.Error("expected Autonegotiate false")
			}
			if ps.SpeedMbps == nil || *ps.SpeedMbps != c.mbps {
				t.Errorf("SpeedMbps = %v, want %d", ps.SpeedMbps, c.mbps)
			}
			if ps.FullDuplex == nil || *ps.FullDuplex != c.fullDuplex {
				t.Errorf("FullDuplex = %v, want %v", ps.FullDuplex, c.fullDuplex)
			}
			if got := ps.String(); got != c.wantStr {
				t.Errorf("String() = %q, want %q", got, c.wantStr)
			}
		})
	}
}

// TestPrivilegedAccess exercises every word in the three (deliberately
// disagreeing) vocabularies from §A.3, plus case-insensitivity/whitespace
// trimming and the honest nil for an unmeasured word.
func TestPrivilegedAccess(t *testing.T) {
	cases := []struct {
		accessMode string
		want       *bool
	}{
		{"privilege-15", model.Ptr(true)},
		{"read/write", model.Ptr(true)},
		{"super user", model.Ptr(true)},
		{"Super User", model.Ptr(true)}, // case-insensitive
		{"  read/write  ", model.Ptr(true)},
		{"privilege-1", model.Ptr(false)},
		{"read only", model.Ptr(false)},
		{"no access", model.Ptr(false)},
		{"Read Only", model.Ptr(false)},
		{"nonsense-level", nil},
		{"", nil},
	}
	for _, c := range cases {
		t.Run(c.accessMode, func(t *testing.T) {
			got := model.PrivilegedAccess(c.accessMode)
			if c.want == nil {
				if got != nil {
					t.Errorf("PrivilegedAccess(%q) = %v, want nil", c.accessMode, *got)
				}
				return
			}
			if got == nil || *got != *c.want {
				t.Errorf("PrivilegedAccess(%q) = %v, want %v", c.accessMode, got, *c.want)
			}
		})
	}
}

// TestPrivilegedUnprivilegedAccessModesDisjoint guards against the two
// vocab sets ever overlapping, which would make PrivilegedAccess
// ambiguous.
func TestPrivilegedUnprivilegedAccessModesDisjoint(t *testing.T) {
	for k := range model.PrivilegedAccessModes {
		if _, ok := model.UnprivilegedAccessModes[k]; ok {
			t.Errorf("%q present in both PrivilegedAccessModes and UnprivilegedAccessModes", k)
		}
	}
}

// TestSwitchUserConstruction exercises the SwitchUser shape, including the
// nilable SNMPv3 columns.
func TestSwitchUserConstruction(t *testing.T) {
	u := model.SwitchUser{
		Name:             "admin",
		AccessMode:       "Super User",
		Privileged:       model.PrivilegedAccess("Super User"),
		SNMPv3Access:     model.Ptr("read-write"),
		SNMPv3Auth:       model.Ptr("MD5"),
		SNMPv3Encryption: model.Ptr("DES"),
	}
	if u.Privileged == nil || !*u.Privileged {
		t.Errorf("expected Privileged true, got %v", u.Privileged)
	}

	guest := model.SwitchUser{
		Name:       "guest",
		AccessMode: "Read Only",
		Privileged: model.PrivilegedAccess("Read Only"),
	}
	if guest.Privileged == nil || *guest.Privileged {
		t.Errorf("expected Privileged false, got %v", guest.Privileged)
	}
	if guest.SNMPv3Access != nil {
		t.Errorf("expected SNMPv3Access nil, got %v", *guest.SNMPv3Access)
	}
}

// TestServiceStatusConstruction exercises ServiceStatus, including the
// genuinely-absent Port case (measured: gsm7252ps omits the SSH Port
// line).
func TestServiceStatusConstruction(t *testing.T) {
	withPort := model.ServiceStatus{Name: "ssh", Enabled: true, Port: model.Ptr(22)}
	if withPort.Port == nil || *withPort.Port != 22 {
		t.Errorf("Port = %v, want 22", withPort.Port)
	}

	withoutPort := model.ServiceStatus{Name: "ssh", Enabled: true}
	if withoutPort.Port != nil {
		t.Errorf("Port = %v, want nil", *withoutPort.Port)
	}
}

// TestSyslogSeverityRoundTrip exercises SyslogSeverity/SyslogSeverityWord/
// SyslogSeverityLabel across the full 0-7 range, including the
// "informational" alias mapping to the same number as "info" but NOT
// being the canonical word/label back out (§A.5).
func TestSyslogSeverityRoundTrip(t *testing.T) {
	for level := 0; level <= 7; level++ {
		word, err := model.SyslogSeverityWord(level)
		if err != nil {
			t.Fatalf("SyslogSeverityWord(%d): %v", level, err)
		}
		label, err := model.SyslogSeverityLabel(level)
		if err != nil {
			t.Fatalf("SyslogSeverityLabel(%d): %v", level, err)
		}

		gotFromWord, err := model.SyslogSeverity(word)
		if err != nil {
			t.Fatalf("SyslogSeverity(%q): %v", word, err)
		}
		if gotFromWord != level {
			t.Errorf("SyslogSeverity(%q) = %d, want %d", word, gotFromWord, level)
		}

		// Case-insensitive on the label too (label is title-case).
		gotFromLabel, err := model.SyslogSeverity(label)
		if err != nil {
			t.Fatalf("SyslogSeverity(%q): %v", label, err)
		}
		if gotFromLabel != level {
			t.Errorf("SyslogSeverity(%q) = %d, want %d", label, gotFromLabel, level)
		}
	}

	// "informational" is a same-severity alias for "info" (severity 6)
	// but is not itself the canonical word or label.
	got, err := model.SyslogSeverity("informational")
	if err != nil {
		t.Fatalf("SyslogSeverity(informational): %v", err)
	}
	if got != 6 {
		t.Errorf("SyslogSeverity(informational) = %d, want 6", got)
	}
	if word, _ := model.SyslogSeverityWord(6); word != "info" {
		t.Errorf("SyslogSeverityWord(6) = %q, want %q", word, "info")
	}
}

// TestSyslogSeverityUnknownErrors verifies every syslog-severity func
// returns an error -- NEVER a silently-defaulted 0/"" -- on input this
// library has not measured, matching Python's ValueError-on-unknown
// behaviour.
func TestSyslogSeverityUnknownErrors(t *testing.T) {
	if _, err := model.SyslogSeverity("bogus"); err == nil {
		t.Error("SyslogSeverity(bogus): expected error, got nil")
	}
	if _, err := model.SyslogSeverityWord(8); err == nil {
		t.Error("SyslogSeverityWord(8): expected error, got nil")
	}
	if _, err := model.SyslogSeverityWord(-1); err == nil {
		t.Error("SyslogSeverityWord(-1): expected error, got nil")
	}
	if _, err := model.SyslogSeverityLabel(8); err == nil {
		t.Error("SyslogSeverityLabel(8): expected error, got nil")
	}
	if _, err := model.SyslogSeverityLabel(-1); err == nil {
		t.Error("SyslogSeverityLabel(-1): expected error, got nil")
	}
}

// TestSyslogServerIndexSparse documents that Index is representable both
// present and absent, and that two servers may hold non-contiguous
// indices (measured on m4300-24x: Index 1 and 3, nothing at 2) -- Index
// must never be derived from slice position.
func TestSyslogServerIndexSparse(t *testing.T) {
	servers := []model.SyslogServer{
		{Host: "10.1.5.1", Port: 514, Severity: 6, Active: true, Index: model.Ptr(1)},
		{Host: "10.1.5.2", Port: 514, Severity: 6, Active: true, Index: model.Ptr(3)},
		{Host: "10.1.5.3", Port: 514, Severity: 4, Active: false, Index: nil},
	}
	if *servers[0].Index != 1 {
		t.Errorf("servers[0].Index = %d, want 1", *servers[0].Index)
	}
	if *servers[1].Index != 3 {
		t.Errorf("servers[1].Index = %d, want 3", *servers[1].Index)
	}
	if servers[2].Index != nil {
		t.Errorf("servers[2].Index = %v, want nil", *servers[2].Index)
	}
}

// TestSyslogConfigConstruction exercises SyslogConfig, including JSON
// round-tripping of its nested Servers slice.
func TestSyslogConfigConstruction(t *testing.T) {
	cfg := model.SyslogConfig{
		Enabled:   true,
		LocalPort: 514,
		Servers: []model.SyslogServer{
			{Host: "10.1.5.1", Port: 514, Severity: 6, Active: true, Index: model.Ptr(1)},
		},
	}

	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var round model.SyslogConfig
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if round.Enabled != cfg.Enabled || round.LocalPort != cfg.LocalPort {
		t.Errorf("got %+v, want %+v", round, cfg)
	}
	if len(round.Servers) != 1 || round.Servers[0].Host != "10.1.5.1" || *round.Servers[0].Index != 1 {
		t.Errorf("Servers round-trip mismatch: %+v", round.Servers)
	}
}

func TestPvidMarshalJSON(t *testing.T) {
	p := model.Pvid{Port: 1, Vlan: 100}

	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := `[1,100]`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
	}
}

func TestPvidUnmarshalJSON(t *testing.T) {
	var p model.Pvid
	if err := json.Unmarshal([]byte(`[1,100]`), &p); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if p.Port != 1 || p.Vlan != 100 {
		t.Errorf("got %+v, want {Port:1 Vlan:100}", p)
	}
}

func TestPvidUnmarshalJSONInvalid(t *testing.T) {
	var p model.Pvid
	if err := json.Unmarshal([]byte(`"not-a-pair"`), &p); err == nil {
		t.Fatal("expected error unmarshalling non-array into Pvid, got nil")
	}
}

func TestSwitchDataPvidsSliceMarshal(t *testing.T) {
	sd := model.SwitchData{
		Model: "gs305ep",
		Host:  "10.0.0.1",
		Pvids: []model.Pvid{{Port: 1, Vlan: 100}},
	}

	b, err := json.Marshal(sd.Canonical())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal into map: %v", err)
	}

	wantPvids := `[[1,100]]`
	if string(got["pvids"]) != wantPvids {
		t.Errorf("pvids: got %s, want %s", got["pvids"], wantPvids)
	}
}

// TestSwitchDataCanonicalEmptyArrays verifies that a SwitchData whose slice
// fields were never initialised (nil) marshals its Canonical() copy with
// empty JSON arrays ("[]"), never JSON null, matching the Python reference's
// default-empty-tuple behaviour.
func TestSwitchDataCanonicalEmptyArrays(t *testing.T) {
	sd := model.SwitchData{Model: "x", Host: "h"}

	b, err := json.Marshal(sd.Canonical())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := `{"model":"x","host":"h","ports":[],"poe":[],"vlans":[],"pvids":[],"lldp":[],"macs":[],"sensors":[],"stats":[],"mgmt_ip":null}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
	}
}

// TestSwitchDataRawZeroValueMarshalsNull documents that marshalling a
// SwitchData directly (without Canonical()) produces JSON null for
// uninitialised slices, per Go's default encoding/json behaviour -- callers
// MUST call Canonical() before marshalling for Python-parity output.
func TestSwitchDataRawZeroValueMarshalsNull(t *testing.T) {
	sd := model.SwitchData{Model: "x", Host: "h"}

	b, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal into map: %v", err)
	}
	if string(got["ports"]) != "null" {
		t.Errorf("ports: got %s, want null (raw zero-value SwitchData)", got["ports"])
	}
}

func TestSwitchDataCanonicalRoundTrip(t *testing.T) {
	sd := model.SwitchData{
		Model: "gs305ep",
		Host:  "10.0.0.1",
		Ports: []model.PortStatus{{Port: 1, AdminEnabled: true}},
	}

	b, err := json.Marshal(sd.Canonical())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var round model.SwitchData
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if round.Model != sd.Model || round.Host != sd.Host {
		t.Errorf("got %+v, want Model=%q Host=%q", round, sd.Model, sd.Host)
	}
	if len(round.Ports) != 1 || round.Ports[0].Port != 1 || !round.Ports[0].AdminEnabled {
		t.Errorf("Ports round-trip mismatch: %+v", round.Ports)
	}
	// Fields that were empty on sd must round-trip as empty (non-nil) slices.
	if round.PoE == nil || len(round.PoE) != 0 {
		t.Errorf("PoE: got %+v, want empty non-nil slice", round.PoE)
	}
}

func TestSwitchDataCanonicalDoesNotMutateOriginal(t *testing.T) {
	sd := model.SwitchData{Model: "x", Host: "h"}
	_ = sd.Canonical()

	if sd.Ports != nil {
		t.Errorf("Canonical() mutated original Ports: %+v", sd.Ports)
	}
}
