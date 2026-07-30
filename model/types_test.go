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

func TestIpModeValues(t *testing.T) {
	cases := []struct {
		got  model.IpMode
		want string
	}{
		{model.IpModeDHCP, "dhcp"},
		{model.IpModeStatic, "static"},
		{model.IpModeUnknown, "unknown"},
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

	want := `{"port":1,"name":"1/0/1","admin_enabled":true,"link_up":false,"speed_mbps":null,"description":null}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
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
