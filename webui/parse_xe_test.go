package webui_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// malformedPage is declared in parse_standard_test.go and shared across the
// webui_test package.

// --- XE_FASTPATH (gsm7252ps): grounded in a real capture from 10.1.5.22 ---

// TestParseXERowsGroupsByInstancePrefix pins webui.ParseXERows against the
// real capture (test_parse.py::test_parse_xe_rows_groups_by_instance_prefix):
// the trailing digit in the instance prefix is a ROW COUNT, not a port --
// port identity always comes from the row's own cells.
func TestParseXERowsGroupsByInstancePrefix(t *testing.T) {
	rows := webui.ParseXERows(readFixture(t, "gsm7252ps_portsConfiguration.html"))
	if len(rows) != 52 {
		t.Fatalf("len(rows) = %d, want 52", len(rows))
	}
	if rows[0]["1_2_1"] != "1/0/1" {
		t.Errorf("rows[0][1_2_1] = %q, want \"1/0/1\"", rows[0]["1_2_1"])
	}
	if rows[0]["1_2_13"] != "1" {
		t.Errorf("rows[0][1_2_13] = %q, want \"1\"", rows[0]["1_2_13"])
	}
	if rows[51]["1_2_1"] != "1/0/52" {
		t.Errorf("rows[51][1_2_1] = %q, want \"1/0/52\"", rows[51]["1_2_1"])
	}
	if rows[51]["1_2_13"] != "52" {
		t.Errorf("rows[51][1_2_13] = %q, want \"52\"", rows[51]["1_2_13"])
	}
	for i, r := range rows {
		if r["1_2_1"] == "" {
			t.Errorf("rows[%d] has no 1_2_1 cell -- the blank global template row leaked in", i)
		}
	}
}

// TestParseXEPortStatusMatchesCapture pins webui.ParseXEPortStatus against
// the real capture (test_parse.py::test_parse_xe_port_status_matches_capture).
func TestParseXEPortStatusMatchesCapture(t *testing.T) {
	ports, err := webui.ParseXEPortStatus(readFixture(t, "gsm7252ps_portsConfiguration.html"))
	if err != nil {
		t.Fatalf("ParseXEPortStatus() error = %v", err)
	}
	if len(ports) != 52 {
		t.Fatalf("len(ports) = %d, want 52", len(ports))
	}
	byPort := make(map[int]model.PortStatus, len(ports))
	for _, p := range ports {
		byPort[p.Port] = p
	}
	if byPort[1].Name == nil || *byPort[1].Name != "1/0/1" {
		t.Errorf("ports[1].Name = %v, want \"1/0/1\"", byPort[1].Name)
	}
	if !byPort[1].AdminEnabled || !byPort[1].LinkUp || byPort[1].SpeedMbps == nil || *byPort[1].SpeedMbps != 1000 {
		t.Errorf("ports[1] = %+v, want admin/link up, speed 1000", byPort[1])
	}
	if byPort[50].SpeedMbps == nil || *byPort[50].SpeedMbps != 10000 {
		t.Errorf("ports[50].SpeedMbps = %v, want 10000 (\"10G Full \")", byPort[50].SpeedMbps)
	}
	if byPort[52].LinkUp || byPort[52].SpeedMbps != nil {
		t.Errorf("ports[52] = (link_up=%v, speed=%v), want (false, nil)", byPort[52].LinkUp, byPort[52].SpeedMbps)
	}
	if byPort[23].SpeedMbps != nil {
		t.Errorf("ports[23].SpeedMbps = %v, want nil (down)", byPort[23].SpeedMbps)
	}
	if byPort[47].SpeedMbps == nil || *byPort[47].SpeedMbps != 1000 {
		t.Errorf("ports[47].SpeedMbps = %v, want 1000", byPort[47].SpeedMbps)
	}
	wantDown := map[int]bool{6: true, 8: true, 10: true, 12: true, 15: true, 19: true, 21: true, 23: true,
		28: true, 29: true, 34: true, 35: true, 36: true, 39: true, 40: true, 43: true, 44: true, 48: true, 52: true}
	for p, s := range byPort {
		if s.LinkUp == wantDown[p] {
			t.Errorf("port %d link_up = %v, want %v", p, s.LinkUp, !wantDown[p])
		}
	}
}

func TestParseXEPortStatusRejectsMalformedPage(t *testing.T) {
	if _, err := webui.ParseXEPortStatus(malformedPage); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}

// TestParseXEStatsArePacketsNotBytes pins webui.ParseXEStats (test_parse.py::
// test_parse_xe_stats_are_packets_not_bytes).
func TestParseXEStatsArePacketsNotBytes(t *testing.T) {
	stats, err := webui.ParseXEStats(readFixture(t, "gsm7252ps_portStatistics.html"))
	if err != nil {
		t.Fatalf("ParseXEStats() error = %v", err)
	}
	if len(stats) != 52 {
		t.Fatalf("len(stats) = %d, want 52", len(stats))
	}
	byPort := make(map[int]model.PortStats, len(stats))
	for _, s := range stats {
		byPort[s.Port] = s
	}
	s1 := byPort[1]
	if s1.RxBytes != nil || s1.TxBytes != nil {
		t.Errorf("stats[1] bytes = (%v, %v), want (nil, nil)", s1.RxBytes, s1.TxBytes)
	}
	if s1.RxPackets == nil || *s1.RxPackets != 287280 {
		t.Errorf("stats[1].RxPackets = %v, want 287280", s1.RxPackets)
	}
	if s1.TxPackets == nil || *s1.TxPackets != 155832097 {
		t.Errorf("stats[1].TxPackets = %v, want 155832097", s1.TxPackets)
	}
	if s1.RxErrors == nil || *s1.RxErrors != 0 || s1.TxErrors == nil || *s1.TxErrors != 0 {
		t.Errorf("stats[1] errors = (%v, %v), want (0, 0)", s1.RxErrors, s1.TxErrors)
	}
	if byPort[51].RxPackets == nil || *byPort[51].RxPackets != 11421062 {
		t.Errorf("stats[51].RxPackets = %v, want 11421062", byPort[51].RxPackets)
	}
	if p := byPort[52]; p.RxPackets == nil || *p.RxPackets != 0 || p.TxPackets == nil || *p.TxPackets != 0 {
		t.Errorf("stats[52] = %+v, want (0, 0)", p)
	}
}

// TestParseXEPVIDsUseConfiguredColumn pins webui.ParseXEPVIDs (test_parse.py::
// test_parse_xe_pvids_use_the_configured_column): the Current PVID column
// disagrees with SNMP on trunk ports 50/51 -- must read Configured instead.
func TestParseXEPVIDsUseConfiguredColumn(t *testing.T) {
	pvids, err := webui.ParseXEPVIDs(readFixture(t, "gsm7252ps_portPvidConfiguration.html"))
	if err != nil {
		t.Fatalf("ParseXEPVIDs() error = %v", err)
	}
	if len(pvids) != 52 {
		t.Fatalf("len(pvids) = %d, want 52", len(pvids))
	}
	byPort := make(map[int]int, len(pvids))
	for _, p := range pvids {
		byPort[p.Port] = p.Vlan
	}
	want := map[int]int{1: 90, 46: 4, 47: 5, 48: 5, 49: 1, 50: 1, 51: 1, 52: 1}
	for port, vlan := range want {
		if byPort[port] != vlan {
			t.Errorf("pvids[%d] = %d, want %d", port, byPort[port], vlan)
		}
	}
}

// TestParseXEVlansExpandPhysicalPortsOnly pins webui.ParseXEVlans
// (test_parse.py::test_parse_xe_vlans_expand_physical_ports_only).
func TestParseXEVlansExpandPhysicalPortsOnly(t *testing.T) {
	vlans, err := webui.ParseXEVlans(readFixture(t, "gsm7252ps_vlanStatus.html"))
	if err != nil {
		t.Fatalf("ParseXEVlans() error = %v", err)
	}
	byID := make(map[int]model.VLANInfo, len(vlans))
	for _, v := range vlans {
		byID[v.VlanID] = v
	}
	wantIDs := []int{1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141}
	if len(byID) != len(wantIDs) {
		t.Fatalf("len(vlans) = %d, want %d", len(byID), len(wantIDs))
	}
	for _, id := range wantIDs {
		if _, ok := byID[id]; !ok {
			t.Errorf("missing VLAN %d", id)
		}
	}
	if byID[1].Name == nil || *byID[1].Name != "default" {
		t.Errorf("vlans[1].Name = %v, want \"default\"", byID[1].Name)
	}
	if byID[4].Name == nil || *byID[4].Name != "wifi" {
		t.Errorf("vlans[4].Name = %v, want \"wifi\"", byID[4].Name)
	}
	if !equalInts(byID[4].MemberPorts, []int{11, 12, 46, 49}) {
		t.Errorf("vlans[4].MemberPorts = %v, want [11 12 46 49]", byID[4].MemberPorts)
	}
	if !equalInts(byID[121].MemberPorts, []int{46, 47, 49}) {
		t.Errorf("vlans[121].MemberPorts = %v, want [46 47 49] (lags must not appear)", byID[121].MemberPorts)
	}
	if len(byID[7].MemberPorts) != 0 {
		t.Errorf("vlans[7].MemberPorts = %v, want empty", byID[7].MemberPorts)
	}
	if len(byID[4].TaggedPorts) != 0 || len(byID[4].UntaggedPorts) != 0 {
		t.Errorf("vlans[4] tagged/untagged = %v/%v, want both empty", byID[4].TaggedPorts, byID[4].UntaggedPorts)
	}
}

func TestParseXEStatsPvidsVlansRejectMalformedPages(t *testing.T) {
	if _, err := webui.ParseXEStats(malformedPage); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("ParseXEStats error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
	if _, err := webui.ParseXEPVIDs(malformedPage); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("ParseXEPVIDs error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
	if _, err := webui.ParseXEVlans(malformedPage); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("ParseXEVlans error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}

// TestParseXEMacsSkipNonPhysicalInterfaces pins webui.ParseXEMacs
// (test_parse.py::test_parse_xe_macs_skip_non_physical_interfaces).
func TestParseXEMacsSkipNonPhysicalInterfaces(t *testing.T) {
	macs, err := webui.ParseXEMacs(readFixture(t, "gsm7252ps_basicAddressTable.html"))
	if err != nil {
		t.Fatalf("ParseXEMacs() error = %v", err)
	}
	if len(macs) != 231 {
		t.Fatalf("len(macs) = %d, want 231", len(macs))
	}
	byMac := make(map[string]model.MacEntry, len(macs))
	for _, m := range macs {
		byMac[m.Mac] = m
	}
	got, ok := byMac["88:A2:9E:80:87:9B"]
	if !ok || got.Port != 1 || got.VlanID == nil || *got.VlanID != 90 {
		t.Errorf("macs[88:A2:9E:80:87:9B] = %+v, want port 1 vlan 90", got)
	}
	if _, ok := byMac["E0:91:F5:0C:D6:DB"]; ok {
		t.Error("ParseXEMacs() kept the switch's own base MAC (service port 0/5/1)")
	}
	if _, ok := byMac["E0:91:F5:0C:D5:C9"]; ok {
		t.Error("ParseXEMacs() kept a lag-learned MAC")
	}
	for _, m := range macs {
		if m.Port < 1 || m.Port > 52 {
			t.Errorf("mac %s has out-of-range port %d", m.Mac, m.Port)
		}
	}
}

// TestParseXEMacsRefuseTruncatedPage pins the pagination guard
// (test_parse.py::test_parse_xe_macs_refuse_truncated_page).
func TestParseXEMacsRefuseTruncatedPage(t *testing.T) {
	html := readFixture(t, "gsm7252ps_basicAddressTable.html")
	if _, err := webui.ParseXEMacs(html); err != nil {
		t.Fatalf("ParseXEMacs(real capture) error = %v, want nil (not truncated)", err)
	}
	truncated := strings.Replace(html, `NAME=v_1_1_1 VALUE="242"`, `NAME=v_1_1_1 VALUE="1213"`, 1)
	_, err := webui.ParseXEMacs(truncated)
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) || !strings.Contains(err.Error(), "paginates") {
		t.Errorf("ParseXEMacs(truncated) error = %v, want an ErrHTTPUnexpectedPage mentioning pagination", err)
	}
}

// TestPoePowerToMwFirmwareVariance mirrors test_parse.py::
// test_poe_power_to_mw_firmware_variance via ParseXEPoE's public surface --
// exercised directly through the small synthetic pages below since
// poePowerToMw itself is unexported.
func TestPoePowerToMwFirmwareVariance(t *testing.T) {
	mk := func(output string) string {
		return `NAME=1.0.1.v_1_2_1 VALUE="1/0/1"` +
			`NAME=1.0.1.v_1_2_2 VALUE="Enable"` +
			`NAME=1.0.1.v_1_2_15 VALUE="` + output + `"` +
			`NAME=1.0.1.v_1_2_17 VALUE="Delivering power"`
	}
	cases := map[string]*int{
		"3500": intPtr(3500), // gsm7252ps: integer mW, as-is
		"4.60": intPtr(4600), // M4300-16X: decimal watts -> mW
		"0":    intPtr(0),
		"0.00": intPtr(0),
		"":     nil,
		"--":   nil,
	}
	for input, want := range cases {
		poe, err := webui.ParseXEPoE(mk(input))
		if err != nil {
			t.Fatalf("ParseXEPoE(%q) error = %v", input, err)
		}
		got := poe[0].PowerMw
		switch {
		case want == nil && got != nil:
			t.Errorf("poePowerToMw(%q) = %d, want nil", input, *got)
		case want != nil && (got == nil || *got != *want):
			t.Errorf("poePowerToMw(%q) = %v, want %d", input, got, *want)
		}
	}
}

func intPtr(v int) *int { return &v }

// TestParseXEPoEMatchesCapture pins webui.ParseXEPoE (test_parse.py::
// test_parse_xe_poe_matches_capture).
func TestParseXEPoEMatchesCapture(t *testing.T) {
	poe, err := webui.ParseXEPoE(readFixture(t, "gsm7252ps_poeInterfaceConfiguration.html"))
	if err != nil {
		t.Fatalf("ParseXEPoE() error = %v", err)
	}
	if len(poe) != 48 {
		t.Fatalf("len(poe) = %d, want 48", len(poe))
	}
	byPort := make(map[int]model.PoEStatus, len(poe))
	for _, p := range poe {
		byPort[p.Port] = p
	}
	if p := byPort[1]; !p.AdminEnabled || p.Detect != model.PoEDetectDelivering || p.PowerMw == nil || *p.PowerMw != 3500 {
		t.Errorf("poe[1] = %+v, want admin=true delivering 3500mW", p)
	}
	if p := byPort[48]; p.Detect != model.PoEDetectSearching || p.PowerMw == nil || *p.PowerMw != 0 {
		t.Errorf("poe[48] = %+v, want searching 0mW", p)
	}
	if byPort[6].Detect != model.PoEDetectFault {
		t.Errorf("poe[6].Detect = %v, want Fault (\"Other Fault\")", byPort[6].Detect)
	}
}

// TestParseXELLDPMatchesCapture pins webui.ParseXELLDP (test_parse.py::
// test_parse_xe_lldp_matches_capture).
func TestParseXELLDPMatchesCapture(t *testing.T) {
	nb, err := webui.ParseXELLDP(readFixture(t, "gsm7252ps_lldpRemoteInventory.html"))
	if err != nil {
		t.Fatalf("ParseXELLDP() error = %v", err)
	}
	if len(nb) != 31 {
		t.Fatalf("len(nb) = %d, want 31", len(nb))
	}
	byPort := make(map[int]model.LLDPNeighbor, len(nb))
	for _, n := range nb {
		byPort[n.LocalPort] = n
	}
	n1 := byPort[1]
	if n1.RemoteSysName == nil || *n1.RemoteSysName != "rpi5-pmod" {
		t.Errorf("nb[1].RemoteSysName = %v, want \"rpi5-pmod\"", n1.RemoteSysName)
	}
	if n1.RemoteChassisID == nil || *n1.RemoteChassisID != "88:A2:9E:80:87:9B" {
		t.Errorf("nb[1].RemoteChassisID = %v, want \"88:A2:9E:80:87:9B\"", n1.RemoteChassisID)
	}
	if n1.RemotePortID == nil || *n1.RemotePortID != "88:A2:9E:80:87:9B" {
		t.Errorf("nb[1].RemotePortID = %v, want \"88:A2:9E:80:87:9B\"", n1.RemotePortID)
	}
	if n1.RemotePortDesc != nil {
		t.Errorf("nb[1].RemotePortDesc = %v, want nil (no such column)", n1.RemotePortDesc)
	}
	n49 := byPort[49]
	if n49.RemoteSysName == nil || *n49.RemoteSysName != "sw-netgear-m4300-24x" {
		t.Errorf("nb[49].RemoteSysName = %v, want \"sw-netgear-m4300-24x\"", n49.RemoteSysName)
	}
	if n49.RemoteChassisID == nil || *n49.RemoteChassisID != "8C:3B:AD:6B:BB:E0" {
		t.Errorf("nb[49].RemoteChassisID = %v, want \"8C:3B:AD:6B:BB:E0\"", n49.RemoteChassisID)
	}
	if n49.RemotePortID == nil || *n49.RemotePortID != "1/0/2" {
		t.Errorf("nb[49].RemotePortID = %v, want \"1/0/2\"", n49.RemotePortID)
	}
}

func TestParseXEMacsPoeLLDPRejectMalformedPages(t *testing.T) {
	if _, err := webui.ParseXEMacs(malformedPage); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("ParseXEMacs error = %v", err)
	}
	if _, err := webui.ParseXEPoE(malformedPage); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("ParseXEPoE error = %v", err)
	}
	if _, err := webui.ParseXELLDP(malformedPage); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("ParseXELLDP error = %v", err)
	}
}

// --- gsm7252ps sysInfo.html: format (B) plain label/value tables ---

// TestParseXELabelledValues pins webui.ParseXELabelledValues (test_parse.py::
// test_parse_xe_labelled_values): this page carries NO v_ cells at all.
func TestParseXELabelledValues(t *testing.T) {
	fields := webui.ParseXELabelledValues(readFixture(t, "gsm7252ps_sysInfo.html"))
	want := map[string]string{
		"System MAC Address":     "E0:91:F5:0C:D6:DB",
		"IPv4 Network Interface": "10.1.5.22/255.255.255.0",
		"System Up Time":         "13 days 7 hours 44 mins 6 secs",
		"Serial Number":          "2BW20A47000CC",
		"Firmware Version":       "10.0.0.53",
		"System Name":            "sw-netgear-gsm7252ps-s1.welland.mithis.com",
	}
	for k, v := range want {
		if fields[k] != v {
			t.Errorf("fields[%q] = %q, want %q", k, fields[k], v)
		}
	}
	if !strings.HasPrefix(fields["Product Name"], "GSM7252PS 48-Port GE L2+") {
		t.Errorf("fields[Product Name] = %q, want prefix \"GSM7252PS 48-Port GE L2+\"", fields["Product Name"])
	}
}

// TestParseXEMgmtIP pins webui.ParseXEMgmtIP (test_parse.py::test_parse_xe_mgmt_ip).
func TestParseXEMgmtIP(t *testing.T) {
	mgmt, err := webui.ParseXEMgmtIP(readFixture(t, "gsm7252ps_sysInfo.html"))
	if err != nil {
		t.Fatalf("ParseXEMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.22" {
		t.Errorf("Address = %v, want \"10.1.5.22\"", mgmt.Address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != "255.255.255.0" {
		t.Errorf("Netmask = %v, want \"255.255.255.0\"", mgmt.Netmask)
	}
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "E0:91:F5:0C:D6:DB" {
		t.Errorf("BaseMac = %v, want \"E0:91:F5:0C:D6:DB\"", mgmt.BaseMac)
	}
	if mgmt.Mode != model.IPModeUnknown {
		t.Errorf("Mode = %v, want IPModeUnknown", mgmt.Mode)
	}
	if mgmt.Gateway != nil {
		t.Errorf("Gateway = %v, want nil", mgmt.Gateway)
	}
}

// TestParseXESensors pins webui.ParseXESensors (test_parse.py::test_parse_xe_sensors).
func TestParseXESensors(t *testing.T) {
	sensors := webui.ParseXESensors(readFixture(t, "gsm7252ps_sysInfo.html"))
	temps := make(map[string]float64)
	fans := make(map[string]float64)
	power := make(map[string]float64)
	for _, s := range sensors {
		switch s.Kind {
		case "temperature":
			temps[s.Name] = s.Value
			if s.Unit != "C" {
				t.Errorf("temperature sensor %s unit = %q, want \"C\"", s.Name, s.Unit)
			}
		case "fan":
			fans[s.Name] = s.Value
			if s.Unit != "state" {
				t.Errorf("fan sensor %s unit = %q, want \"state\"", s.Name, s.Unit)
			}
		case "power":
			power[s.Name] = s.Value
			if s.Unit != "state" {
				t.Errorf("power sensor %s unit = %q, want \"state\"", s.Name, s.Unit)
			}
		}
	}
	wantTemps := map[string]float64{"System": 29.0, "CPU": 49.0, "MAC-A": 32.0, "MAC-B": 31.0}
	if len(temps) != len(wantTemps) {
		t.Errorf("temps = %v, want %v", temps, wantTemps)
	}
	for k, v := range wantTemps {
		if temps[k] != v {
			t.Errorf("temps[%q] = %v, want %v", k, temps[k], v)
		}
	}
	wantFans := map[string]float64{"Fan1/PWR": 1.0, "Fan2/CPU": 1.0, "Fan3/SYS": 1.0}
	if len(fans) != len(wantFans) {
		t.Errorf("fans = %v, want %v", fans, wantFans)
	}
	wantPower := map[string]float64{"RPS": 1.0, "Power Module": 1.0}
	if len(power) != len(wantPower) {
		t.Errorf("power = %v, want %v", power, wantPower)
	}
}

func TestParseXESysinfoParsersRejectMalformedPage(t *testing.T) {
	if fields := webui.ParseXELabelledValues(malformedPage); len(fields) != 0 {
		t.Errorf("ParseXELabelledValues(malformed) = %v, want empty", fields)
	}
	if sensors := webui.ParseXESensors(malformedPage); len(sensors) != 0 {
		t.Errorf("ParseXESensors(malformed) = %v, want empty", sensors)
	}
	if _, err := webui.ParseXEMgmtIP(malformedPage); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("ParseXEMgmtIP(malformed) error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}

// --- S3300-52X (gsm7228ps): grounded in a real capture from 10.1.5.11 ---
//
// xePortFromIface/expandS3300PortList are unexported; they are exercised
// indirectly (and exhaustively, incl. the "1/gN"/"1/xgN"/lag-range shapes
// test_parse.py's test_xe_port_from_iface_handles_fastpath_and_s3300_naming/
// test_expand_s3300_port_list_ranges_and_lags pin directly in Python)
// through ParseXEPortStatus/ParseS3300Macs/ParseS3300Vlans below, which
// route every input through them.

// TestParseS3300MacsMatchesCapturePhysicalEntries pins webui.ParseS3300Macs
// (test_parse.py::test_parse_s3300_macs_matches_capture_physical_entries).
func TestParseS3300MacsMatchesCapturePhysicalEntries(t *testing.T) {
	macs, err := webui.ParseS3300Macs(readFixture(t, "gsm7228ps_basicAddressTable.html"))
	if err != nil {
		t.Fatalf("ParseS3300Macs() error = %v", err)
	}
	if len(macs) != 17 {
		t.Fatalf("len(macs) = %d, want 17", len(macs))
	}
	ports := make(map[int]bool)
	macSet := make(map[string]bool)
	for _, m := range macs {
		ports[m.Port] = true
		macSet[m.Mac] = true
	}
	if len(ports) != 1 || !ports[51] {
		t.Errorf("ports = %v, want only {51}", ports)
	}
	if macSet["08:BD:43:6B:B8:D8"] {
		t.Error("ParseS3300Macs() kept the switch's own base MAC (learned on \"c1\")")
	}
}

func TestParseS3300MacsRejectsTruncatedPage(t *testing.T) {
	html := readFixture(t, "gsm7228ps_basicAddressTable.html")
	truncated := strings.Replace(html, `NAME=v_1_1_1 VALUE="18"`, `NAME=v_1_1_1 VALUE="9000"`, 1)
	if _, err := webui.ParseS3300Macs(truncated); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}

// TestParseS3300MgmtIsBaseMacOnly pins webui.ParseS3300Mgmt (test_parse.py::
// test_parse_s3300_mgmt_is_base_mac_only).
func TestParseS3300MgmtIsBaseMacOnly(t *testing.T) {
	mgmt, err := webui.ParseS3300Mgmt(readFixture(t, "gsm7228ps_sysInfo.html"))
	if err != nil {
		t.Fatalf("ParseS3300Mgmt() error = %v", err)
	}
	if mgmt.Mode != model.IPModeUnknown {
		t.Errorf("Mode = %v, want IPModeUnknown", mgmt.Mode)
	}
	if mgmt.Address != nil || mgmt.Netmask != nil || mgmt.Gateway != nil {
		t.Errorf("Address/Netmask/Gateway = %v/%v/%v, want all nil", mgmt.Address, mgmt.Netmask, mgmt.Gateway)
	}
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "08:BD:43:6B:B8:D8" {
		t.Errorf("BaseMac = %v, want \"08:BD:43:6B:B8:D8\"", mgmt.BaseMac)
	}
}

func TestParseS3300MgmtRejectsPageWithoutBaseMac(t *testing.T) {
	if _, err := webui.ParseS3300Mgmt("<html><body>no mac here</body></html>"); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}

// TestParseS3300VlansMembershipMatchesCapture pins webui.ParseS3300Vlans
// (test_parse.py::test_parse_s3300_vlans_membership_matches_capture).
func TestParseS3300VlansMembershipMatchesCapture(t *testing.T) {
	vlans, err := webui.ParseS3300Vlans(readFixture(t, "gsm7228ps_vlanStatus.html"))
	if err != nil {
		t.Fatalf("ParseS3300Vlans() error = %v", err)
	}
	byID := make(map[int]model.VLANInfo, len(vlans))
	for _, v := range vlans {
		byID[v.VlanID] = v
	}
	wantIDs := []int{1, 5, 21, 121, 4089}
	if len(byID) != len(wantIDs) {
		t.Fatalf("len(vlans) = %d, want %d", len(byID), len(wantIDs))
	}
	if byID[5].Name == nil || *byID[5].Name != "net" {
		t.Errorf("vlans[5].Name = %v, want \"net\"", byID[5].Name)
	}
	if byID[121].Name == nil || *byID[121].Name != "t-fpgas" {
		t.Errorf("vlans[121].Name = %v, want \"t-fpgas\"", byID[121].Name)
	}
	if len(byID[5].TaggedPorts) != 0 || len(byID[5].UntaggedPorts) != 0 {
		t.Errorf("vlans[5] tagged/untagged not empty: %v/%v", byID[5].TaggedPorts, byID[5].UntaggedPorts)
	}
}

// TestS3300SharesXEParsersForPortsStatsPvidsPoeLldp pins that the six
// non-divergent S3300 reads use the XE parsers unchanged (test_parse.py::
// test_s3300_shares_xe_parsers_for_ports_stats_pvids_poe_lldp).
func TestS3300SharesXEParsersForPortsStatsPvidsPoeLldp(t *testing.T) {
	ports, err := webui.ParseXEPortStatus(readFixture(t, "gsm7228ps_portsConfiguration.html"))
	if err != nil {
		t.Fatalf("ParseXEPortStatus(s3300) error = %v", err)
	}
	if len(ports) != 52 {
		t.Fatalf("len(ports) = %d, want 52", len(ports))
	}
	pvids, err := webui.ParseXEPVIDs(readFixture(t, "gsm7228ps_portPvidConfiguration.html"))
	if err != nil {
		t.Fatalf("ParseXEPVIDs(s3300) error = %v", err)
	}
	if len(pvids) == 0 {
		t.Error("ParseXEPVIDs(s3300) returned no rows")
	}
	poe, err := webui.ParseXEPoE(readFixture(t, "gsm7228ps_poeInterfaceConfiguration.html"))
	if err != nil {
		t.Fatalf("ParseXEPoE(s3300) error = %v", err)
	}
	if len(poe) == 0 {
		t.Error("ParseXEPoE(s3300) returned no rows")
	}
	stats, err := webui.ParseXEStats(readFixture(t, "gsm7228ps_portStatistics.html"))
	if err != nil {
		t.Fatalf("ParseXEStats(s3300) error = %v", err)
	}
	if len(stats) != 52 {
		t.Errorf("len(stats) = %d, want 52", len(stats))
	}
	lldp, err := webui.ParseXELLDP(readFixture(t, "gsm7228ps_lldpRemoteInventory.html"))
	if err != nil {
		t.Fatalf("ParseXELLDP(s3300) error = %v", err)
	}
	if len(lldp) == 0 {
		t.Error("ParseXELLDP(s3300) returned no rows")
	}
}

// --- FASTPATH "VLAN Membership" page (shared by all four managed models) ---

// fastpathMembershipCase mirrors test_http_vlan_membership.py's _CAPTURES
// table -- real live captures, cross-checked against `show vlan` output.
type fastpathMembershipCase struct {
	fixture     string
	vlanID      int
	tagged      []int
	untagged    []int
	gridPorts   int
	slots       int
	cfgTagged   []int
	cfgUntagged []int
}

var fastpathMembershipCases = []fastpathMembershipCase{
	{
		fixture:     "gsm7252ps_vlanPortCfg_vlan1.html",
		vlanID:      1,
		tagged:      []int{6},
		untagged:    []int{8, 10, 15, 19, 21, 22, 26, 28, 29, 34, 35, 36, 39, 40, 49, 52},
		gridPorts:   52,
		slots:       116,
		cfgTagged:   []int{6},
		cfgUntagged: []int{8, 10, 15, 19, 21, 22, 26, 28, 29, 34, 35, 36, 39, 40, 49, 50, 51, 52},
	},
	{
		fixture:     "gsm7252ps_vlanPortCfg_vlan141.html",
		vlanID:      141,
		tagged:      []int{46, 47, 49},
		untagged:    []int{},
		gridPorts:   52,
		slots:       116,
		cfgTagged:   []int{46, 47, 49},
		cfgUntagged: []int{50, 51},
	},
	{
		fixture:     "gsm7228ps_vlanPortCfg_vlan5.html",
		vlanID:      5,
		tagged:      []int{49, 50, 51, 52},
		untagged:    []int{41},
		gridPorts:   52,
		slots:       78,
		cfgTagged:   []int{49, 50, 51, 52},
		cfgUntagged: []int{41},
	},
	{
		fixture:     "m4300_vlanportcfg_vlan1.html",
		vlanID:      1,
		tagged:      []int{5},
		untagged:    []int{1, 2, 7, 8},
		gridPorts:   24,
		slots:       153,
		cfgTagged:   []int{5},
		cfgUntagged: []int{1, 2, 7, 8},
	},
	{
		fixture:     "m4300_16x_vlanportcfg_vlan4.html",
		vlanID:      4,
		tagged:      []int{9, 10, 12, 13, 14, 15, 16},
		untagged:    []int{11},
		gridPorts:   16,
		slots:       145,
		cfgTagged:   []int{9, 10, 12, 13, 14, 15, 16},
		cfgUntagged: []int{11},
	},
}

// TestParseFastpathMembershipMatchesLiveCaptures pins webui.ParseFastpathMembership
// against every real capture in test_http_vlan_membership.py's _CAPTURES
// table -- all four managed models, both firmware grid generations.
func TestParseFastpathMembershipMatchesLiveCaptures(t *testing.T) {
	for _, c := range fastpathMembershipCases {
		t.Run(c.fixture, func(t *testing.T) {
			page, err := webui.ParseFastpathMembership(readFixture(t, c.fixture))
			if err != nil {
				t.Fatalf("ParseFastpathMembership() error = %v", err)
			}
			if page.VlanID == nil || *page.VlanID != c.vlanID {
				t.Errorf("VlanID = %v, want %d", page.VlanID, c.vlanID)
			}
			if !equalInts(page.TaggedPorts, c.tagged) {
				t.Errorf("TaggedPorts = %v, want %v", page.TaggedPorts, c.tagged)
			}
			if !equalInts(page.UntaggedPorts, c.untagged) {
				t.Errorf("UntaggedPorts = %v, want %v", page.UntaggedPorts, c.untagged)
			}
			if len(page.PortSlots) != c.gridPorts {
				t.Errorf("len(PortSlots) = %d, want %d", len(page.PortSlots), c.gridPorts)
			}
			if got := len(strings.Split(page.HiddenMem, ",")); got != c.slots {
				t.Errorf("len(HiddenMem slots) = %d, want %d", got, c.slots)
			}
			var cfgTagged, cfgUntagged []int
			for p, m := range page.Configured {
				switch m {
				case model.VlanTagged:
					cfgTagged = append(cfgTagged, p)
				case model.VlanUntagged:
					cfgUntagged = append(cfgUntagged, p)
				}
			}
			sortInts(cfgTagged)
			sortInts(cfgUntagged)
			if !equalInts(cfgTagged, c.cfgTagged) {
				t.Errorf("Configured tagged = %v, want %v", cfgTagged, c.cfgTagged)
			}
			if !equalInts(cfgUntagged, c.cfgUntagged) {
				t.Errorf("Configured untagged = %v, want %v", cfgUntagged, c.cfgUntagged)
			}
			for port := 1; port <= c.gridPorts; port++ {
				if _, ok := page.PortSlots[port]; !ok {
					t.Errorf("PortSlots missing port %d", port)
				}
			}
		})
	}
}

// TestFastpathMembershipLagIfnamesAreNotMistakenForPorts mirrors
// test_http_vlan_membership.py::test_fixture_lag_ifnames_are_not_mistaken_for_ports.
func TestFastpathMembershipLagIfnamesAreNotMistakenForPorts(t *testing.T) {
	page, err := webui.ParseFastpathMembership(readFixture(t, "gsm7252ps_vlanPortCfg_vlan141.html"))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !equalInts(page.TaggedPorts, []int{46, 47, 49}) {
		t.Errorf("TaggedPorts = %v, want [46 47 49]", page.TaggedPorts)
	}
	for _, p := range page.TaggedPorts {
		if p == 1 || p == 2 {
			t.Errorf("TaggedPorts wrongly contains LAG-derived port %d", p)
		}
	}
}

// TestFastpathMembershipCurrentAndConfiguredViewsDiffer mirrors
// test_http_vlan_membership.py::test_fixture_current_and_configured_views_differ_on_real_hardware.
func TestFastpathMembershipCurrentAndConfiguredViewsDiffer(t *testing.T) {
	page, err := webui.ParseFastpathMembership(readFixture(t, "gsm7252ps_vlanPortCfg_vlan1.html"))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	for _, p := range []int{50, 51} {
		for _, u := range page.UntaggedPorts {
			if u == p {
				t.Errorf("port %d should be excluded from the CURRENT untagged view", p)
			}
		}
		if page.Configured[p] != model.VlanUntagged {
			t.Errorf("Configured[%d] = %v, want VlanUntagged", p, page.Configured[p])
		}
	}
}

// TestHiddenMemEditTouchesExactlyOneSlot mirrors test_http_vlan_membership.py::
// test_hidden_mem_edit_touches_exactly_one_slot.
func TestHiddenMemEditTouchesExactlyOneSlot(t *testing.T) {
	page, err := webui.ParseFastpathMembership(readFixture(t, "gsm7252ps_vlanPortCfg_vlan1.html"))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	edited, err := webui.FastpathHiddenMemWith(page, 7, model.VlanTagged)
	if err != nil {
		t.Fatalf("FastpathHiddenMemWith() error = %v", err)
	}
	oldCodes := strings.Split(page.HiddenMem, ",")
	newCodes := strings.Split(edited, ",")
	if len(newCodes) != len(oldCodes) {
		t.Fatalf("len(newCodes) = %d, want %d", len(newCodes), len(oldCodes))
	}
	changed := 0
	changedIdx := -1
	for i := range oldCodes {
		if oldCodes[i] != newCodes[i] {
			changed++
			changedIdx = i
		}
	}
	if changed != 1 {
		t.Fatalf("changed %d slots, want exactly 1", changed)
	}
	if changedIdx != page.PortSlots[7] {
		t.Errorf("changed slot %d, want %d (port 7's slot)", changedIdx, page.PortSlots[7])
	}
	if newCodes[page.PortSlots[7]] != "1" {
		t.Errorf("newCodes[slot] = %q, want \"1\" (Tagged)", newCodes[page.PortSlots[7]])
	}
}

// TestHiddenMemEditRefusesPortTheGridNeverShowed mirrors
// test_http_vlan_membership.py::test_hidden_mem_edit_refuses_a_port_the_grid_never_showed.
func TestHiddenMemEditRefusesPortTheGridNeverShowed(t *testing.T) {
	page, err := webui.ParseFastpathMembership(readFixture(t, "m4300_vlanportcfg_vlan1.html"))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	_, err = webui.FastpathHiddenMemWith(page, 99, model.VlanTagged)
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) || !strings.Contains(err.Error(), "not on this switch") {
		t.Errorf("error = %v, want an ErrHTTPUnexpectedPage mentioning \"not on this switch\"", err)
	}
}

// TestFastpathMembershipActionMatchesSpecPostPath mirrors the fixture
// test's page.action assertion against HTTP_SPECS[model].vlan_membership_post_path.
func TestFastpathMembershipActionMatchesSpecPostPath(t *testing.T) {
	cases := map[string]string{
		"gsm7252ps_vlanPortCfg_vlan1.html": "/switching/dot1q/vlan_port_cfg_rw.html",
		"gsm7228ps_vlanPortCfg_vlan5.html": "/switching/dot1q/vlan_port_cfg_rw.html",
		"m4300_vlanportcfg_vlan1.html":     "/v1/switching/dot1q/vlan_port_cfg_rw.html",
		"m4300_16x_vlanportcfg_vlan4.html": "/v1/switching/dot1q/vlan_port_cfg_rw.html",
	}
	for fixture, want := range cases {
		page, err := webui.ParseFastpathMembership(readFixture(t, fixture))
		if err != nil {
			t.Fatalf("%s: error = %v", fixture, err)
		}
		if page.Action != want {
			t.Errorf("%s: Action = %q, want %q", fixture, page.Action, want)
		}
	}
}

func TestParseFastpathMembershipRejectsMalformedPage(t *testing.T) {
	if _, err := webui.ParseFastpathMembership(malformedPage); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}

func TestParseFastpathErr(t *testing.T) {
	if _, ok := webui.ParseFastpathErr(`<input name="err_flag" value="0">`); ok {
		t.Error("err_flag=0 should report ok=false")
	}
	if _, ok := webui.ParseFastpathErr(`<html>no err_flag here</html>`); ok {
		t.Error("absent err_flag should report ok=false")
	}
	msg, ok := webui.ParseFastpathErr(`<input name="err_flag" value="1"><input name="err_msg" value="Unable to set VLAN membership for VLAN ( 4004 )">`)
	if !ok || msg != "Unable to set VLAN membership for VLAN ( 4004 )" {
		t.Errorf("got (%q, %v), want the err_msg text", msg, ok)
	}
	msg, ok = webui.ParseFastpathErr(`<input name="err_flag" value="1">`)
	if !ok || msg != "err_flag=1 with no err_msg" {
		t.Errorf("got (%q, %v), want the generic fallback", msg, ok)
	}
}

// --- XUI generic management-IP reader (shared by all four managed models) ---

// TestParseXUIMgmtIPGSM72xx pins webui.ParseXUIMgmtIP against the real
// gsm7228ps ipConfiguration.html capture (test_http_read.py::
// test_gsm7228ps_reads_are_grounded_not_refused's mgmt assertions).
func TestParseXUIMgmtIPGSM72xx(t *testing.T) {
	mgmt, err := webui.ParseXUIMgmtIP(readFixture(t, "gsm7228ps_ipConfiguration.html"),
		"v_1_1_1", "v_1_2_1", "v_1_3_1", "v_1_18_1", "ipConfiguration.html")
	if err != nil {
		t.Fatalf("ParseXUIMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.11" {
		t.Errorf("Address = %v, want \"10.1.5.11\"", mgmt.Address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != "255.255.255.0" {
		t.Errorf("Netmask = %v, want \"255.255.255.0\"", mgmt.Netmask)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != "10.1.5.1" {
		t.Errorf("Gateway = %v, want \"10.1.5.1\"", mgmt.Gateway)
	}
	if mgmt.Mode != model.IPModeDHCP {
		t.Errorf("Mode = %v, want IPModeDHCP", mgmt.Mode)
	}
	if mgmt.BaseMac != nil {
		t.Errorf("BaseMac = %v, want nil (merged separately by the reader)", mgmt.BaseMac)
	}
}

// TestParseXUIMgmtIPM4300 pins webui.ParseXUIMgmtIP against the real
// m4300_mgmtVlanIpv4Configuration.html capture (test_http_read.py::
// test_m4300_http_mgmt_and_sensors).
func TestParseXUIMgmtIPM4300(t *testing.T) {
	mgmt, err := webui.ParseXUIMgmtIP(readFixture(t, "m4300_mgmtVlanIpv4Configuration.html"),
		"v_1_6_1", "v_1_7_1", "v_1_71_1", "v_1_5_3", "mgmtVlanIpv4Configuration.html")
	if err != nil {
		t.Fatalf("ParseXUIMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.13" {
		t.Errorf("Address = %v, want \"10.1.5.13\"", mgmt.Address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != "255.255.255.0" {
		t.Errorf("Netmask = %v, want \"255.255.255.0\"", mgmt.Netmask)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != "10.1.5.1" {
		t.Errorf("Gateway = %v, want \"10.1.5.1\"", mgmt.Gateway)
	}
	if mgmt.Mode != model.IPModeDHCP {
		t.Errorf("Mode = %v, want IPModeDHCP", mgmt.Mode)
	}
}

// TestParseXUIMgmtIPHandlesSelectDisabledAndCheckboxInputs exercises
// xuiInputs's three special-cased shapes on a synthetic page: a <select>
// contributes its SELECTED <option>'s value (falling back to the first
// option otherwise), a DISABLED input is dropped (a browser never submits
// it), and a checkbox is dropped entirely (xuiInputs has no row-selection
// concept, unlike fastpathFormFields).
func TestParseXUIMgmtIPHandlesSelectDisabledAndCheckboxInputs(t *testing.T) {
	html := `<FORM ACTION="/ipConfiguration.html/a0"><input name="applet_port" value="x"></FORM>` +
		`<FORM ACTION="/ipConfiguration.html/a1">` +
		`<input type=hidden name="v_1_1_1" value="10.1.5.11">` +
		`<input type=hidden name="v_1_2_1" value="255.255.255.0">` +
		`<input type=hidden name="v_1_3_1" value="10.1.5.1">` +
		`<select name="v_1_18_1"><option value="None">None</option><option value="DHCP" selected>DHCP</option></select>` +
		`<input type=checkbox name="gecb1">` +
		`<input type=submit name="v_3_1_1" value="APPLY" disabled>` +
		`</FORM>`
	mgmt, err := webui.ParseXUIMgmtIP(html, "v_1_1_1", "v_1_2_1", "v_1_3_1", "v_1_18_1", "ipConfiguration.html")
	if err != nil {
		t.Fatalf("ParseXUIMgmtIP() error = %v", err)
	}
	if mgmt.Mode != model.IPModeDHCP {
		t.Errorf("Mode = %v, want IPModeDHCP (from the <select>'s SELECTED option)", mgmt.Mode)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.11" {
		t.Errorf("Address = %v, want \"10.1.5.11\"", mgmt.Address)
	}
}

// TestParseXUIMgmtIPMissingFieldNamesTheGap exercises the "wrong
// management-IP page for this model" error path when an expected field
// name is absent from the form.
func TestParseXUIMgmtIPMissingFieldNamesTheGap(t *testing.T) {
	html := `<FORM ACTION="/x/a1"><input type=hidden name="v_1_1_1" value="10.1.5.11"></FORM>`
	_, err := webui.ParseXUIMgmtIP(html, "v_1_1_1", "v_1_2_1", "v_1_3_1", "v_1_18_1", "x")
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
	if !strings.Contains(err.Error(), "v_1_2_1") {
		t.Errorf("error = %q, want it to name the missing field v_1_2_1", err.Error())
	}
}

func TestParseXUIMgmtIPRejectsMalformedPage(t *testing.T) {
	if _, err := webui.ParseXUIMgmtIP(malformedPage, "v_1_1_1", "v_1_2_1", "v_1_3_1", "v_1_18_1", ""); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}

func sortInts(s []int) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
