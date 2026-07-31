package webui_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// TestParseM4300PortStatusMatchesLiveCapture pins webui.ParseM4300PortStatus
// against a real M4300-24X capture (test_http_read.py::
// test_m4300_http_ports_match_live_snmp): 24 physical ports, live
// cross-checked against SNMP with zero mismatches on (link_up, speed_mbps).
func TestParseM4300PortStatusMatchesLiveCapture(t *testing.T) {
	ports, err := webui.ParseM4300PortStatus(readFixture(t, "m4300_ports.html"))
	if err != nil {
		t.Fatalf("ParseM4300PortStatus() error = %v", err)
	}
	if len(ports) != 24 {
		t.Fatalf("len(ports) = %d, want 24", len(ports))
	}
	byPort := make(map[int]model.PortStatus, len(ports))
	for _, p := range ports {
		byPort[p.Port] = p
	}
	if got := byPort[1].Name; got == nil || *got != "1/0/1" {
		t.Errorf("ports[1].Name = %v, want \"1/0/1\"", got)
	}
	if !byPort[1].LinkUp || byPort[1].SpeedMbps == nil || *byPort[1].SpeedMbps != 10000 {
		t.Errorf("ports[1] = (link_up=%v, speed=%v), want (true, 10000)", byPort[1].LinkUp, byPort[1].SpeedMbps)
	}
	if !byPort[3].LinkUp || byPort[3].SpeedMbps == nil || *byPort[3].SpeedMbps != 1000 {
		t.Errorf("ports[3] = (link_up=%v, speed=%v), want (true, 1000)", byPort[3].LinkUp, byPort[3].SpeedMbps)
	}
	if byPort[4].LinkUp || byPort[4].SpeedMbps != nil {
		t.Errorf("ports[4] = (link_up=%v, speed=%v), want (false, nil)", byPort[4].LinkUp, byPort[4].SpeedMbps)
	}
}

// TestParseM4300PortStatusRejectsMalformedPage mirrors the M4300 sibling of
// test_parse_xe_port_status_rejects_malformed_page.
func TestParseM4300PortStatusRejectsMalformedPage(t *testing.T) {
	if _, err := webui.ParseM4300PortStatus("<html><body>Not Found</body></html>"); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("ParseM4300PortStatus(malformed) error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}

// TestParseM4300StatsAreFramesNotBytes pins webui.ParseM4300Stats against
// the real capture (test_http_read.py::test_m4300_http_stats_are_frames_not_bytes):
// this UI reports FRAME counts, never octets.
func TestParseM4300StatsAreFramesNotBytes(t *testing.T) {
	stats, err := webui.ParseM4300Stats(readFixture(t, "m4300_portstats.html"))
	if err != nil {
		t.Fatalf("ParseM4300Stats() error = %v", err)
	}
	if len(stats) != 24 {
		t.Fatalf("len(stats) = %d, want 24", len(stats))
	}
	byPort := make(map[int]model.PortStats, len(stats))
	for _, s := range stats {
		byPort[s.Port] = s
	}
	if got := byPort[1].RxPackets; got == nil || *got != 17057817472 {
		t.Errorf("stats[1].RxPackets = %v, want 17057817472", got)
	}
	if byPort[1].RxBytes != nil || byPort[1].TxBytes != nil {
		t.Errorf("stats[1] bytes = (%v, %v), want (nil, nil)", byPort[1].RxBytes, byPort[1].TxBytes)
	}
}

// TestParseM4300VlansExpandPhysicalPortsOnly pins webui.ParseM4300Vlans
// against the real capture (test_http_read.py::
// test_m4300_http_vlans_expand_physical_ports_only): the "lag 1 - lag 128"
// range must not be expanded into 128 phantom ports on a 24-port switch.
func TestParseM4300VlansExpandPhysicalPortsOnly(t *testing.T) {
	vlans, err := webui.ParseM4300Vlans(readFixture(t, "m4300_vlanstatus.html"))
	if err != nil {
		t.Fatalf("ParseM4300Vlans() error = %v", err)
	}
	if len(vlans) != 14 {
		t.Fatalf("len(vlans) = %d, want 14", len(vlans))
	}
	byID := make(map[int]model.VLANInfo, len(vlans))
	for _, v := range vlans {
		byID[v.VlanID] = v
	}
	v1 := byID[1]
	if v1.Name == nil || *v1.Name != "default" {
		t.Errorf("vlans[1].Name = %v, want \"default\"", v1.Name)
	}
	want := []int{1, 2, 5, 7, 8}
	if !equalInts(v1.MemberPorts, want) {
		t.Errorf("vlans[1].MemberPorts = %v, want %v", v1.MemberPorts, want)
	}
	for _, v := range vlans {
		for _, p := range v.MemberPorts {
			if p > 24 {
				t.Errorf("vlan %d has member port %d > 24 -- a LAG range was wrongly expanded", v.VlanID, p)
			}
		}
		if len(v.TaggedPorts) != 0 || len(v.UntaggedPorts) != 0 {
			t.Errorf("vlan %d TaggedPorts/UntaggedPorts = %v/%v, want empty (this page cannot distinguish them)",
				v.VlanID, v.TaggedPorts, v.UntaggedPorts)
		}
	}
}

// TestParseM4300PVIDs pins webui.ParseM4300PVIDs against the real capture
// (test_http_read.py::test_m4300_http_pvids_and_macs).
func TestParseM4300PVIDs(t *testing.T) {
	pvids, err := webui.ParseM4300PVIDs(readFixture(t, "m4300_pvid.html"))
	if err != nil {
		t.Fatalf("ParseM4300PVIDs() error = %v", err)
	}
	if len(pvids) != 24 {
		t.Fatalf("len(pvids) = %d, want 24", len(pvids))
	}
	for _, p := range pvids {
		if p.Port == 3 && p.Vlan != 5 {
			t.Errorf("pvids[3] = %d, want 5", p.Vlan)
		}
	}
}

// TestParseM4300MacsRefusesTruncatedPage pins webui.ParseM4300Macs against
// the real (UNMODIFIED) capture: the switch states 1213 FDB entries but the
// page renders only ~20, so this must error naming the pagination trap
// (test_http_read.py::test_m4300_http_macs_refuse_truncated_page).
func TestParseM4300MacsRefusesTruncatedPage(t *testing.T) {
	_, err := webui.ParseM4300Macs(readFixture(t, "m4300_addresstable.html"))
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Fatalf("ParseM4300Macs() error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
	if !strings.Contains(err.Error(), "paginates") {
		t.Errorf("ParseM4300Macs() error = %q, want it to mention pagination", err.Error())
	}
}

// TestParseM4300MacsSkipsNonPhysicalInterfaces mirrors test_http_read.py::
// test_m4300_http_macs_skip_non_physical_interfaces: the FDB's Intf cell
// holds "lag 1"/"vlan 1"/the "0/15/1" service port alongside physical
// entries -- all three non-physical shapes must be skipped, not
// mis-attributed to a phantom port. The real capture's own pagination
// guard (1213 stated) is neutralised by lowering the stated total so the
// rendered rows can be inspected directly.
func TestParseM4300MacsSkipsNonPhysicalInterfaces(t *testing.T) {
	html := readFixture(t, "m4300_addresstable.html")
	trimmed := strings.Replace(html, `NAME=v_1_1_1 VALUE="1213"`, `NAME=v_1_1_1 VALUE="20"`, 1)
	rows := webui.ParseCheetahRows(trimmed)
	nonPhysical := make(map[string]bool)
	for _, r := range rows {
		if _, ok := r["SwitchingmacAddrGroup_MacAddress"]; !ok {
			continue
		}
		if intf, ok := r["SwitchingmacAddrGroup_Intf"]; ok {
			if !isPhysicalUnitSlotPort(intf) {
				nonPhysical[strings.ToUpper(r["SwitchingmacAddrGroup_MacAddress"])] = true
			}
		}
	}
	if len(nonPhysical) == 0 {
		t.Fatal("fixture should contain lag/vlan/service entries")
	}
	macs, err := webui.ParseM4300Macs(trimmed)
	if err != nil {
		t.Fatalf("ParseM4300Macs() error = %v", err)
	}
	for _, m := range macs {
		if nonPhysical[m.Mac] {
			t.Errorf("ParseM4300Macs() kept non-physical MAC %s", m.Mac)
		}
	}
}

func isPhysicalUnitSlotPort(intf string) bool {
	parts := strings.Split(strings.TrimSpace(intf), "/")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// TestParseM4300Sysinfo pins webui.ParseM4300Sysinfo against the real
// capture: "IPv4 Management Address" renders addr/netmask inside a link,
// "System MAC Address" a plain cell, mode is always Unknown (this page
// carries no DHCP/static indicator). Grounded directly in
// webui/testdata/http/m4300_sysinfo.html (test_http_read.py::
// test_m4300_http_mgmt_and_sensors pins the same base MAC via the reader).
func TestParseM4300Sysinfo(t *testing.T) {
	mgmt, err := webui.ParseM4300Sysinfo(readFixture(t, "m4300_sysinfo.html"))
	if err != nil {
		t.Fatalf("ParseM4300Sysinfo() error = %v", err)
	}
	if mgmt.Mode != model.IPModeUnknown {
		t.Errorf("Mode = %v, want IPModeUnknown", mgmt.Mode)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.13" {
		t.Errorf("Address = %v, want \"10.1.5.13\"", mgmt.Address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != "255.255.255.0" {
		t.Errorf("Netmask = %v, want \"255.255.255.0\"", mgmt.Netmask)
	}
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "8C:3B:AD:6B:BB:E0" {
		t.Errorf("BaseMac = %v, want \"8C:3B:AD:6B:BB:E0\"", mgmt.BaseMac)
	}
	if mgmt.Gateway != nil {
		t.Errorf("Gateway = %v, want nil (this page carries no gateway)", mgmt.Gateway)
	}
}

// TestParseM4300SysinfoRejectsMalformedPage mirrors the shape of
// test_parse_xe_sysinfo_parsers_reject_malformed_page for the M4300 sibling.
func TestParseM4300SysinfoRejectsMalformedPage(t *testing.T) {
	if _, err := webui.ParseM4300Sysinfo("<html><body>Not Found</body></html>"); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("ParseM4300Sysinfo(malformed) error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}

// TestParseM4300Sensors pins webui.ParseM4300Sensors against the real
// capture (test_http_read.py::test_m4300_http_mgmt_and_sensors: "any(s.kind
// == temperature and s.value > 0 for s in temps)").
func TestParseM4300Sensors(t *testing.T) {
	sensors := webui.ParseM4300Sensors(readFixture(t, "m4300_sysinfo.html"))
	found := false
	for _, s := range sensors {
		if s.Kind != "temperature" {
			t.Errorf("ParseM4300Sensors() returned kind %q, want only \"temperature\" (fan block excluded)", s.Kind)
		}
		if s.Kind == "temperature" && s.Value > 0 {
			found = true
		}
	}
	if !found {
		t.Error("ParseM4300Sensors() found no positive temperature reading")
	}
}

// TestParseM4300SensorsExcludesTemperatureLimits pins the isTempLimitRE
// exclusion directly: a synthetic "Max Operating Temperature" row must
// never be reported as a live sensor reading.
func TestParseM4300SensorsExcludesTemperatureLimits(t *testing.T) {
	html := `<td>MAC</td><td>53 &#8451;</td>` +
		`<td>Max Operating Temperature</td><td>81 &#8451;</td>`
	sensors := webui.ParseM4300Sensors(html)
	for _, s := range sensors {
		if strings.Contains(strings.ToLower(s.Name), "max") {
			t.Errorf("ParseM4300Sensors() reported a threshold row as a sensor: %+v", s)
		}
	}
	if len(sensors) != 1 || sensors[0].Value != 53 {
		t.Errorf("ParseM4300Sensors() = %+v, want exactly one 53C MAC reading", sensors)
	}
}

// TestParseCheetahRowsUnescapesValues pins the HTML-entity-unescape trap
// the M4300 dialect's comment sig calls out: interface names arrive as
// "1&#x2F;0&#x2F;1" and must decode to "1/0/1".
func TestParseCheetahRowsUnescapesValues(t *testing.T) {
	html := `<TD><INPUT xid=1_2_10 TYPE=hidden NAME=1.0.24.v_1_2_10 VALUE="1&#x2F;0&#x2F;1"></TD><!-- baseinterfaceListing_Interfaces -->`
	rows := webui.ParseCheetahRows(html)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if got := rows[0]["baseinterfaceListing_Interfaces"]; got != "1/0/1" {
		t.Errorf("unescaped value = %q, want \"1/0/1\"", got)
	}
}

func equalInts(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
