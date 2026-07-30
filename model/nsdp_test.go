package model_test

import (
	"encoding/json"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func TestLinkSpeedValues(t *testing.T) {
	cases := []struct {
		got  model.LinkSpeed
		want int
	}{
		{model.LinkSpeedDown, 0x00},
		{model.LinkSpeedHalf10M, 0x01},
		{model.LinkSpeedFull10M, 0x02},
		{model.LinkSpeedHalf100M, 0x03},
		{model.LinkSpeedFull100M, 0x04},
		{model.LinkSpeedGigabit, 0x05},
		{model.LinkSpeedTenGigabit, 0xFF},
	}
	for _, c := range cases {
		if int(c.got) != c.want {
			t.Errorf("got %d, want %d", int(c.got), c.want)
		}
	}
}

func TestLinkSpeedFromByte(t *testing.T) {
	cases := []struct {
		in   byte
		want model.LinkSpeed
	}{
		{0x00, model.LinkSpeedDown},
		{0x01, model.LinkSpeedHalf10M},
		{0x02, model.LinkSpeedFull10M},
		{0x03, model.LinkSpeedHalf100M},
		{0x04, model.LinkSpeedFull100M},
		{0x05, model.LinkSpeedGigabit},
		{0xFF, model.LinkSpeedTenGigabit},
		// Unknown/undocumented bytes (e.g. unassigned 2.5G/5G codes) must
		// report Down, never error.
		{0x77, model.LinkSpeedDown},
		{0x06, model.LinkSpeedDown},
	}
	for _, c := range cases {
		if got := model.LinkSpeedFromByte(c.in); got != c.want {
			t.Errorf("LinkSpeedFromByte(0x%02X) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestLinkSpeedMbps(t *testing.T) {
	cases := []struct {
		in   model.LinkSpeed
		want int
	}{
		{model.LinkSpeedDown, 0},
		{model.LinkSpeedHalf10M, 10},
		{model.LinkSpeedFull10M, 10},
		{model.LinkSpeedHalf100M, 100},
		{model.LinkSpeedFull100M, 100},
		{model.LinkSpeedGigabit, 1000},
		{model.LinkSpeedTenGigabit, 10000},
	}
	for _, c := range cases {
		if got := c.in.SpeedMbps(); got != c.want {
			t.Errorf("%v.SpeedMbps() = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestLinkSpeedMbpsUnrecognizedValueIsZero(t *testing.T) {
	// A LinkSpeed value constructed directly (bypassing FromByte) that isn't
	// in the lookup table must still report 0 Mbps, never panic.
	unknown := model.LinkSpeed(0x42)
	if got := unknown.SpeedMbps(); got != 0 {
		t.Errorf("SpeedMbps() for unrecognized LinkSpeed = %d, want 0", got)
	}
}

func TestLinkSpeedJSONMarshalsAsRawInt(t *testing.T) {
	// Python's jsonify emits IntEnum.value (a raw int), not the member
	// name, so the Go port must marshal as a bare number too.
	ps := model.NsdpPortStatus{PortID: 3, Speed: model.LinkSpeedGigabit}

	b, err := json.Marshal(ps)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := `{"port_id":3,"speed":5}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
	}
}

func TestVLANEngineValues(t *testing.T) {
	cases := []struct {
		got  model.VLANEngine
		want int
	}{
		{model.VLANEngineDisabled, 0},
		{model.VLANEngineBasicPort, 1},
		{model.VLANEngineAdvancedPort, 2},
		{model.VLANEngineBasic8021Q, 3},
		{model.VLANEngineAdvanced8021Q, 4},
	}
	for _, c := range cases {
		if int(c.got) != c.want {
			t.Errorf("got %d, want %d", int(c.got), c.want)
		}
	}
}

func TestNsdpPortStatisticsMarshalJSON(t *testing.T) {
	stats := model.NsdpPortStatistics{
		PortID:        2,
		BytesReceived: 1000,
		BytesSent:     2000,
		CrcErrors:     5,
	}

	b, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := `{"port_id":2,"bytes_received":1000,"bytes_sent":2000,"crc_errors":5}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
	}
}

func TestNsdpVlanMembershipUntaggedPorts(t *testing.T) {
	m := model.NsdpVlanMembership{
		VlanID:      100,
		MemberPorts: []int{1, 2, 3, 4},
		TaggedPorts: []int{2, 4},
	}

	got := m.UntaggedPorts()
	want := []int{1, 3}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestNsdpVlanMembershipUntaggedPortsAllTagged(t *testing.T) {
	m := model.NsdpVlanMembership{
		VlanID:      1,
		MemberPorts: []int{1, 2},
		TaggedPorts: []int{1, 2},
	}

	got := m.UntaggedPorts()
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestNsdpVlanMembershipUntaggedPortsNoTagged(t *testing.T) {
	m := model.NsdpVlanMembership{
		VlanID:      1,
		MemberPorts: []int{1, 2, 3},
	}

	got := m.UntaggedPorts()
	want := []int{1, 2, 3}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestNsdpVlanMembershipMarshalJSONOmitsUntaggedPorts(t *testing.T) {
	// UntaggedPorts is a derived method, not a stored field -- it must never
	// appear as a JSON key, matching Python's untagged_ports being a
	// @property (dataclasses.fields() -- what jsonify walks -- never sees
	// properties).
	m := model.NsdpVlanMembership{
		VlanID:      100,
		MemberPorts: []int{1, 2},
		TaggedPorts: []int{2},
	}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := `{"vlan_id":100,"member_ports":[1,2],"tagged_ports":[2]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
	}
}

func TestNsdpPortPvidMarshalJSON(t *testing.T) {
	p := model.NsdpPortPvid{PortID: 1, VlanID: 100}

	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := `{"port_id":1,"vlan_id":100}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
	}
}

func TestNsdpPortMirroringMarshalJSON(t *testing.T) {
	m := model.NsdpPortMirroring{DestinationPort: 8, SourcePorts: []int{1, 2}}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	want := `{"destination_port":8,"source_ports":[1,2]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
	}
}

func TestNsdpIgmpSnoopingMarshalJSON(t *testing.T) {
	enabled := model.NsdpIgmpSnooping{Enabled: true, VlanID: model.Ptr(5)}
	b, err := json.Marshal(enabled)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"enabled":true,"vlan_id":5}`; string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
	}

	noVlan := model.NsdpIgmpSnooping{Enabled: false}
	b, err = json.Marshal(noVlan)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"enabled":false,"vlan_id":null}`; string(b) != want {
		t.Errorf("got  %s\nwant %s", string(b), want)
	}
}

func TestNsdpDeviceMarshalJSONMinimal(t *testing.T) {
	// Only Model/Mac are required; every other field must marshal as JSON
	// null/empty rather than a fabricated zero value.
	d := model.NsdpDevice{Model: "gs305ep", Mac: "aa:bb:cc:dd:ee:ff"}

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal into map: %v", err)
	}

	if string(got["model"]) != `"gs305ep"` {
		t.Errorf("model: got %s", got["model"])
	}
	if string(got["mac"]) != `"aa:bb:cc:dd:ee:ff"` {
		t.Errorf("mac: got %s", got["mac"])
	}
	for _, key := range []string{
		"hostname", "ip", "netmask", "gateway", "firmware_version",
		"dhcp_enabled", "port_count", "serial_number", "vlan_engine",
		"qos_engine", "port_mirroring", "igmp_snooping",
		"broadcast_filtering", "loop_detection",
	} {
		if string(got[key]) != "null" {
			t.Errorf("%s: got %s, want null", key, got[key])
		}
	}
}

func TestNsdpDeviceMarshalJSONFull(t *testing.T) {
	d := model.NsdpDevice{
		Model:           "gs305ep",
		Mac:             "aa:bb:cc:dd:ee:ff",
		Hostname:        model.Ptr("switch1"),
		IP:              model.Ptr("10.0.0.1"),
		Netmask:         model.Ptr("255.255.255.0"),
		Gateway:         model.Ptr("10.0.0.254"),
		FirmwareVersion: model.Ptr("1.0.0"),
		DhcpEnabled:     model.Ptr(true),
		PortCount:       model.Ptr(5),
		SerialNumber:    model.Ptr("SN123"),
		VlanEngine:      func() *model.VLANEngine { v := model.VLANEngineBasic8021Q; return &v }(),
		PortStatus: []model.NsdpPortStatus{
			{PortID: 1, Speed: model.LinkSpeedGigabit},
		},
		PortStatistics: []model.NsdpPortStatistics{
			{PortID: 1, BytesReceived: 10, BytesSent: 20, CrcErrors: 0},
		},
		VlanMembers: []model.NsdpVlanMembership{
			{VlanID: 1, MemberPorts: []int{1, 2}, TaggedPorts: []int{2}},
		},
		PortPvids: []model.NsdpPortPvid{
			{PortID: 1, VlanID: 1},
		},
		QosEngine:          model.Ptr(1),
		PortMirroring:      &model.NsdpPortMirroring{DestinationPort: 5, SourcePorts: []int{1}},
		IgmpSnooping:       &model.NsdpIgmpSnooping{Enabled: true, VlanID: model.Ptr(1)},
		BroadcastFiltering: model.Ptr(true),
		LoopDetection:      model.Ptr(false),
	}

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var round model.NsdpDevice
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if round.Model != d.Model || round.Mac != d.Mac {
		t.Errorf("got Model=%q Mac=%q, want Model=%q Mac=%q", round.Model, round.Mac, d.Model, d.Mac)
	}
	if round.VlanEngine == nil || *round.VlanEngine != model.VLANEngineBasic8021Q {
		t.Errorf("VlanEngine round-trip mismatch: %+v", round.VlanEngine)
	}
	if len(round.PortStatus) != 1 || round.PortStatus[0].Speed != model.LinkSpeedGigabit {
		t.Errorf("PortStatus round-trip mismatch: %+v", round.PortStatus)
	}
	if len(round.VlanMembers) != 1 || len(round.VlanMembers[0].UntaggedPorts()) != 1 {
		t.Errorf("VlanMembers round-trip mismatch: %+v", round.VlanMembers)
	}
	if round.PortMirroring == nil || round.PortMirroring.DestinationPort != 5 {
		t.Errorf("PortMirroring round-trip mismatch: %+v", round.PortMirroring)
	}
	if round.IgmpSnooping == nil || !round.IgmpSnooping.Enabled || round.IgmpSnooping.VlanID == nil || *round.IgmpSnooping.VlanID != 1 {
		t.Errorf("IgmpSnooping round-trip mismatch: %+v", round.IgmpSnooping)
	}
}
