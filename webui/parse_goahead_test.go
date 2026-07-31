package webui_test

import (
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// --- gs728tpp GoAhead "wcd" XML API: grounded in real captures of the
// --- live switch 10.2.5.10 (test_parse.py lines 511-631). ---

// TestParseGoAheadPorts pins webui.ParseGoAheadPorts (test_parse.py::test_goahead_ports).
func TestParseGoAheadPorts(t *testing.T) {
	ports, err := webui.ParseGoAheadPorts(readFixture(t, "gs728tpp_ports.xml"))
	if err != nil {
		t.Fatalf("ParseGoAheadPorts() error = %v", err)
	}
	byPort := make(map[int]model.PortStatus, len(ports))
	for _, p := range ports {
		byPort[p.Port] = p
	}
	if len(byPort) != 28 {
		t.Fatalf("len(ports) = %d, want 28 (g1..g28; the 8 LAG rows are not ports)", len(byPort))
	}
	p1 := byPort[1]
	if !p1.AdminEnabled || p1.LinkUp || p1.SpeedMbps != nil {
		t.Errorf("ports[1] = %+v, want admin-up, link-down, speed nil", p1)
	}
	if p1.Name == nil || *p1.Name != "g1" {
		t.Errorf("ports[1].Name = %v, want \"g1\"", p1.Name)
	}
	if p2 := byPort[2]; !p2.LinkUp || p2.SpeedMbps == nil || *p2.SpeedMbps != 1000 {
		t.Errorf("ports[2] = %+v, want link-up 1000Mbps", p2)
	}
	if p5 := byPort[5]; p5.SpeedMbps == nil || *p5.SpeedMbps != 100 {
		t.Errorf("ports[5].SpeedMbps = %v, want 100", p5.SpeedMbps)
	}
}

// TestParseGoAheadPVIDs pins webui.ParseGoAheadPVIDs (test_parse.py::test_goahead_pvids).
func TestParseGoAheadPVIDs(t *testing.T) {
	pvids, err := webui.ParseGoAheadPVIDs(readFixture(t, "gs728tpp_pvids_membership.xml"))
	if err != nil {
		t.Fatalf("ParseGoAheadPVIDs() error = %v", err)
	}
	if len(pvids) != 28 {
		t.Fatalf("len(pvids) = %d, want 28", len(pvids))
	}
	byPort := make(map[int]int, len(pvids))
	for _, p := range pvids {
		byPort[p.Port] = p.Vlan
	}
	want := map[int]int{1: 10, 3: 5, 2: 1}
	for port, vlan := range want {
		if byPort[port] != vlan {
			t.Errorf("pvids[%d] = %d, want %d", port, byPort[port], vlan)
		}
	}
}

// TestParseGoAheadVlans pins webui.ParseGoAheadVlans (test_parse.py::test_goahead_vlans).
func TestParseGoAheadVlans(t *testing.T) {
	membership := readFixture(t, "gs728tpp_pvids_membership.xml")
	vlans, err := webui.ParseGoAheadVlans(readFixture(t, "gs728tpp_vlans.xml"), membership)
	if err != nil {
		t.Fatalf("ParseGoAheadVlans() error = %v", err)
	}
	byID := make(map[int]model.VLANInfo, len(vlans))
	for _, v := range vlans {
		byID[v.VlanID] = v
	}
	wantIDs := []int{1, 2, 3, 5, 6, 7, 10, 20, 31, 41, 90, 99}
	if len(byID) != len(wantIDs) {
		t.Fatalf("len(vlans) = %d, want %d", len(byID), len(wantIDs))
	}
	v5 := byID[5]
	if v5.Name == nil || *v5.Name != "net" {
		t.Errorf("vlans[5].Name = %v, want \"net\"", v5.Name)
	}
	if !equalInts(v5.UntaggedPorts, []int{3, 5, 12, 23}) {
		t.Errorf("vlans[5].UntaggedPorts = %v, want [3 5 12 23]", v5.UntaggedPorts)
	}
	memberSet := make(map[int]bool, len(v5.MemberPorts))
	for _, p := range v5.MemberPorts {
		memberSet[p] = true
	}
	for _, p := range []int{3, 5, 12, 23} {
		if !memberSet[p] {
			t.Errorf("vlans[5].MemberPorts missing untagged port %d", p)
		}
	}
	untaggedSet := map[int]bool{3: true, 5: true, 12: true, 23: true}
	var wantTagged []int
	for _, p := range v5.MemberPorts {
		if !untaggedSet[p] {
			wantTagged = append(wantTagged, p)
		}
	}
	if !equalInts(v5.TaggedPorts, wantTagged) {
		t.Errorf("vlans[5].TaggedPorts = %v, want %v (member minus untagged)", v5.TaggedPorts, wantTagged)
	}
	if len(byID[3].MemberPorts) != 0 {
		t.Errorf("vlans[3].MemberPorts = %v, want empty (Auto Video has no members)", byID[3].MemberPorts)
	}
}

// TestParseGoAheadMacs pins webui.ParseGoAheadMacs (test_parse.py::test_goahead_macs).
func TestParseGoAheadMacs(t *testing.T) {
	macs, err := webui.ParseGoAheadMacs(readFixture(t, "gs728tpp_macs.xml"))
	if err != nil {
		t.Fatalf("ParseGoAheadMacs() error = %v", err)
	}
	if len(macs) == 0 {
		t.Fatal("expected dynamic MAC entries")
	}
	found := false
	for _, m := range macs {
		if m.Port < 1 || m.Port > 28 {
			t.Errorf("mac %s has out-of-range port %d", m.Mac, m.Port)
		}
		if m.Mac != stringsToUpper(m.Mac) {
			t.Errorf("mac %s is not upper-cased", m.Mac)
		}
		if m.Mac == "2C:CF:67:BB:49:A1" && m.Port == 2 && m.VlanID != nil && *m.VlanID == 1 {
			found = true
		}
	}
	if !found {
		t.Error("expected (2C:CF:67:BB:49:A1, port 2, vlan 1) in the FDB")
	}
}

func stringsToUpper(s string) string {
	out := []rune(s)
	for i, r := range out {
		if r >= 'a' && r <= 'z' {
			out[i] = r - 32
		}
	}
	return string(out)
}

// TestParseGoAheadPoE pins webui.ParseGoAheadPoE (test_parse.py::test_goahead_poe).
func TestParseGoAheadPoE(t *testing.T) {
	poe, err := webui.ParseGoAheadPoE(readFixture(t, "gs728tpp_poe.xml"))
	if err != nil {
		t.Fatalf("ParseGoAheadPoE() error = %v", err)
	}
	byPort := make(map[int]model.PoEStatus, len(poe))
	for _, p := range poe {
		byPort[p.Port] = p
	}
	if len(byPort) != 24 {
		t.Fatalf("len(poe) = %d, want 24 (24 PoE+ ports)", len(byPort))
	}
	p1 := byPort[1]
	if !p1.AdminEnabled || p1.Detect != model.PoEDetectSearching || p1.PowerMw == nil || *p1.PowerMw != 0 {
		t.Errorf("poe[1] = %+v, want admin-enabled, Searching, 0mW", p1)
	}
}

// TestParseGoAheadLLDP pins webui.ParseGoAheadLLDP (test_parse.py::test_goahead_lldp).
func TestParseGoAheadLLDP(t *testing.T) {
	nb, err := webui.ParseGoAheadLLDP(readFixture(t, "gs728tpp_lldp.xml"))
	if err != nil {
		t.Fatalf("ParseGoAheadLLDP() error = %v", err)
	}
	byPort := make(map[int]model.LLDPNeighbor, len(nb))
	for _, n := range nb {
		byPort[n.LocalPort] = n
	}
	wantPorts := []int{2, 24, 26, 28}
	if len(byPort) != len(wantPorts) {
		t.Fatalf("len(nb) = %d, want %d", len(byPort), len(wantPorts))
	}
	n2 := byPort[2]
	if n2.RemoteSysName == nil || *n2.RemoteSysName != "reterm1" {
		t.Errorf("nb[2].RemoteSysName = %v, want \"reterm1\"", n2.RemoteSysName)
	}
	if n2.RemoteChassisID == nil || *n2.RemoteChassisID != "2C:CF:67:BB:49:A1" {
		t.Errorf("nb[2].RemoteChassisID = %v, want \"2C:CF:67:BB:49:A1\"", n2.RemoteChassisID)
	}
	if n2.RemotePortID == nil || *n2.RemotePortID != "2C:CF:67:BB:49:A1" {
		t.Errorf("nb[2].RemotePortID = %v, want \"2C:CF:67:BB:49:A1\"", n2.RemotePortID)
	}
	if n2.RemotePortDesc == nil || *n2.RemotePortDesc != "eth0" {
		t.Errorf("nb[2].RemotePortDesc = %v, want \"eth0\"", n2.RemotePortDesc)
	}
}

// TestParseGoAheadSensors pins webui.ParseGoAheadSensors (test_parse.py::test_goahead_sensors).
func TestParseGoAheadSensors(t *testing.T) {
	sensors, err := webui.ParseGoAheadSensors(readFixture(t, "gs728tpp_device_info_and_sensors.xml"))
	if err != nil {
		t.Fatalf("ParseGoAheadSensors() error = %v", err)
	}
	byKindName := make(map[[2]string]model.Sensor, len(sensors))
	for _, s := range sensors {
		byKindName[[2]string{s.Kind, s.Name}] = s
	}
	if s, ok := byKindName[[2]string{"fan", "Fan1"}]; !ok || s.Value != 1.0 || s.Unit != "state" {
		t.Errorf("Fan1 = %+v, ok=%v, want value 1.0 unit state", s, ok)
	}
	if s, ok := byKindName[[2]string{"fan", "Fan2"}]; !ok || s.Value != 1.0 {
		t.Errorf("Fan2 = %+v, ok=%v, want value 1.0", s, ok)
	}
	if _, ok := byKindName[[2]string{"fan", "Fan3"}]; ok {
		t.Error("Fan3 should be absent (status 5) and skipped")
	}
	if s, ok := byKindName[[2]string{"power", "Main PS"}]; !ok || s.Value != 1.0 {
		t.Errorf("Main PS = %+v, ok=%v, want value 1.0", s, ok)
	}
	for _, s := range sensors {
		if s.Kind == "temperature" {
			t.Errorf("unexpected temperature sensor %+v -- tempSensorValue is 0 on this unit, must not be fabricated", s)
		}
	}
}

// TestParseGoAheadMgmtIP pins webui.ParseGoAheadMgmtIP (test_parse.py::test_goahead_mgmt_ip).
func TestParseGoAheadMgmtIP(t *testing.T) {
	mgmt, err := webui.ParseGoAheadMgmtIP(readFixture(t, "gs728tpp_mgmt_ip.xml"))
	if err != nil {
		t.Fatalf("ParseGoAheadMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.2.5.10" {
		t.Errorf("Address = %v, want \"10.2.5.10\"", mgmt.Address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != "255.255.255.0" {
		t.Errorf("Netmask = %v, want \"255.255.255.0\"", mgmt.Netmask)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != "10.2.5.1" {
		t.Errorf("Gateway = %v, want \"10.2.5.1\"", mgmt.Gateway)
	}
	if mgmt.Mode != model.IPModeUnknown {
		t.Errorf("Mode = %v, want IPModeUnknown", mgmt.Mode)
	}
	if mgmt.BaseMac != nil {
		t.Errorf("BaseMac = %v, want nil (that's on the SystemInfo page, not here)", mgmt.BaseMac)
	}
}

// TestParseGoAheadBaseMACFromSystemInfo pins webui.ParseGoAheadBaseMAC
// (test_parse.py::test_goahead_base_mac_from_systeminfo).
func TestParseGoAheadBaseMACFromSystemInfo(t *testing.T) {
	mac, ok, err := webui.ParseGoAheadBaseMAC(readFixture(t, "gs728tpp_device_info_and_sensors.xml"))
	if err != nil {
		t.Fatalf("ParseGoAheadBaseMAC() error = %v", err)
	}
	if !ok || mac != "B0:39:56:77:54:29" {
		t.Errorf("got (%q, %v), want (\"B0:39:56:77:54:29\", true)", mac, ok)
	}
}

// TestGoAheadRejectsWrongPageAndDTD pins the two failure shapes
// (test_parse.py::test_goahead_rejects_wrong_page_and_dtd): a page that
// isn't a wcd response, and a DTD/entity payload smuggled inside the data
// block (XXE hardening, source lines 2441-2447).
func TestGoAheadRejectsWrongPageAndDTD(t *testing.T) {
	if _, err := webui.ParseGoAheadPorts("<html>not a wcd response</html>"); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("wrong page: error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
	evil := `<DeviceConfiguration><!DOCTYPE x [<!ENTITY a "b">]><Standard802_3List/></DeviceConfiguration>`
	if _, err := webui.ParseGoAheadPorts(evil); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("DTD payload: error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}

// TestParseGoAheadMgmtIPRejectsMalformedPage and TestParseGoAheadPVIDsRejectsMalformedPage
// pin the "wrong page" failure shape across the remaining section-based parsers.
func TestParseGoAheadMgmtIPRejectsMalformedPage(t *testing.T) {
	if _, err := webui.ParseGoAheadMgmtIP("<html>nope</html>"); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}

func TestParseGoAheadPVIDsRejectsMalformedPage(t *testing.T) {
	if _, err := webui.ParseGoAheadPVIDs("<html>nope</html>"); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}
