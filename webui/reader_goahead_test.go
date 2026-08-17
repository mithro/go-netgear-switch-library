package webui_test

// reader_goahead_test.go: Reader coverage for the GOAHEAD_XML dialect
// (gs728tpp). NOT present in tests/test_http_read.py at pin 1841111 --
// that file's own gs728tpp coverage gap is real (grep confirms no
// "gs728tpp" mention anywhere in it); the closest Python coverage is
// test_parse.py's direct parser-level pins (mirrored in Go by
// parse_goahead_test.go). Since the Go port has the complete real capture
// set for this model (webui/testdata/http/gs728tpp_*.xml) and gs728tpp's
// spec ships ReadsVerified=true, this file closes that gap at the READER
// level: every GetVLANs/GetMgmtIP GoAhead-dialect branch in reader.go
// (ParseGoAheadVlans, the base-MAC SystemInfo merge, ...) would otherwise
// go completely unexercised through the public Reader API. Expected values
// are the SAME ones parse_goahead_test.go already pins at the parser level.

import (
	"context"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

func gs728tppPages(t *testing.T) map[string]any {
	t.Helper()
	spec := webui.HTTPSpecs["gs728tpp"]
	return map[string]any{
		spec.DashboardPath:  readFixture(t, "gs728tpp_ports.xml"),
		spec.VlanConfigPath: readFixture(t, "gs728tpp_vlans.xml"),
		spec.PvidPath:       readFixture(t, "gs728tpp_pvids_membership.xml"),
		spec.MacTablePath:   readFixture(t, "gs728tpp_macs.xml"),
		spec.PoEStatusPath:  readFixture(t, "gs728tpp_poe.xml"),
		spec.LLDPPath:       readFixture(t, "gs728tpp_lldp.xml"),
		spec.SysinfoPath:    readFixture(t, "gs728tpp_device_info_and_sensors.xml"),
		spec.MgmtIPPath:     readFixture(t, "gs728tpp_mgmt_ip.xml"),
	}
}

// TestGS728TPPGetPorts mirrors parse_goahead_test.go::TestParseGoAheadPorts
// through the Reader's dialect dispatch (parsePorts's isGoAheadDialect
// branch).
func TestGS728TPPGetPorts(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs728tppPages(t)), "gs728tpp")
	ports, err := r.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	byPort := make(map[int]model.PortStatus, len(ports))
	for _, p := range ports {
		byPort[p.Port] = p
	}
	if len(byPort) != 28 {
		t.Fatalf("len(ports) = %d, want 28", len(byPort))
	}
	p1 := byPort[1]
	if !p1.AdminEnabled || p1.LinkUp {
		t.Errorf("ports[1] = %+v, want admin-up, link-down", p1)
	}
	if p2 := byPort[2]; !p2.LinkUp || p2.SpeedMbps == nil || *p2.SpeedMbps != 1000 {
		t.Errorf("ports[2] = %+v, want link-up 1000Mbps", p2)
	}
}

// TestGS728TPPGetStatsUnsupported: this model's per-port stats page is
// unreachable behind unresolvable JS nav (StatsPath == "" in the spec), so
// GetStats must raise rather than silently return an empty slice -- SNMP
// is the source for this model.
func TestGS728TPPGetStatsUnsupported(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs728tppPages(t)), "gs728tpp")
	_, err := r.GetStats(context.Background())
	wantUnsupported(t, err, "GetStats")
}

// TestGS728TPPGetPoE mirrors parse_goahead_test.go::TestParseGoAheadPoE.
func TestGS728TPPGetPoE(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs728tppPages(t)), "gs728tpp")
	poe, err := r.GetPoE(context.Background())
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	byPort := make(map[int]model.PoEStatus, len(poe))
	for _, p := range poe {
		byPort[p.Port] = p
	}
	if len(byPort) != 24 {
		t.Fatalf("len(poe) = %d, want 24", len(byPort))
	}
	p1 := byPort[1]
	if !p1.AdminEnabled || p1.Detect != model.PoEDetectSearching || p1.PowerMw == nil || *p1.PowerMw != 0 {
		t.Errorf("poe[1] = %+v, want admin-enabled, Searching, 0mW", p1)
	}
}

// TestGS728TPPGetPVIDs mirrors parse_goahead_test.go::TestParseGoAheadPVIDs.
func TestGS728TPPGetPVIDs(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs728tppPages(t)), "gs728tpp")
	pvids, err := r.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	if len(pvids) != 28 {
		t.Fatalf("len(pvids) = %d, want 28", len(pvids))
	}
	got := make(map[int]int, len(pvids))
	for _, p := range pvids {
		got[p.Port] = p.Vlan
	}
	want := map[int]int{1: 10, 3: 5, 2: 1}
	for port, vlan := range want {
		if got[port] != vlan {
			t.Errorf("pvids[%d] = %d, want %d", port, got[port], vlan)
		}
	}
}

// TestGS728TPPGetVLANs exercises reader.go's GOAHEAD_XML branch of
// GetVLANs (fetch VlanConfigPath + PvidPath, combine via
// ParseGoAheadVlans) -- otherwise unreached by any Reader-level test.
// Mirrors parse_goahead_test.go::TestParseGoAheadVlans's expected values.
func TestGS728TPPGetVLANs(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs728tppPages(t)), "gs728tpp")
	vlans, err := r.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
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
	if len(byID[3].MemberPorts) != 0 {
		t.Errorf("vlans[3].MemberPorts = %v, want empty (Auto Video has no members)", byID[3].MemberPorts)
	}
}

// TestGS728TPPGetMACs mirrors parse_goahead_test.go::TestParseGoAheadMacs.
func TestGS728TPPGetMACs(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs728tppPages(t)), "gs728tpp")
	macs, err := r.GetMACs(context.Background())
	if err != nil {
		t.Fatalf("GetMACs() error = %v", err)
	}
	if len(macs) == 0 {
		t.Fatal("expected dynamic MAC entries")
	}
	found := false
	for _, m := range macs {
		if m.Port < 1 || m.Port > 28 {
			t.Errorf("mac %s has out-of-range port %d", m.Mac, m.Port)
		}
		if m.Mac == "2C:CF:67:BB:49:A1" && m.Port == 2 && m.VlanID != nil && *m.VlanID == 1 {
			found = true
		}
	}
	if !found {
		t.Error("expected (2C:CF:67:BB:49:A1, port 2, vlan 1) in the FDB")
	}
}

// TestGS728TPPGetLLDP mirrors parse_goahead_test.go::TestParseGoAheadLLDP.
func TestGS728TPPGetLLDP(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs728tppPages(t)), "gs728tpp")
	nb, err := r.GetLLDP(context.Background())
	if err != nil {
		t.Fatalf("GetLLDP() error = %v", err)
	}
	byPort := make(map[int]model.LLDPNeighbor, len(nb))
	for _, n := range nb {
		byPort[n.LocalPort] = n
	}
	if len(byPort) != 4 {
		t.Fatalf("len(lldp) = %d, want 4", len(byPort))
	}
	n2 := byPort[2]
	if n2.RemoteSysName == nil || *n2.RemoteSysName != "reterm1" {
		t.Errorf("lldp[2].RemoteSysName = %v, want \"reterm1\"", n2.RemoteSysName)
	}
}

// TestGS728TPPGetSensors mirrors parse_goahead_test.go::TestParseGoAheadSensors.
func TestGS728TPPGetSensors(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs728tppPages(t)), "gs728tpp")
	sensors, err := r.GetSensors(context.Background())
	if err != nil {
		t.Fatalf("GetSensors() error = %v", err)
	}
	byKindName := make(map[[2]string]model.Sensor, len(sensors))
	for _, s := range sensors {
		byKindName[[2]string{s.Kind, s.Name}] = s
	}
	if s, ok := byKindName[[2]string{"fan", "Fan1"}]; !ok || s.Value != 1.0 || s.Unit != "state" {
		t.Errorf("Fan1 = %+v, ok=%v, want value 1.0 unit state", s, ok)
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

// TestGS728TPPGetMgmtIP exercises reader.go's GetMgmtIP GoAhead branch end
// to end -- the IPConf page carries no MAC row, so GetMgmtIP must fetch
// SysinfoPath separately and merge in ParseGoAheadBaseMAC's result. Mirrors
// parse_goahead_test.go::TestParseGoAheadMgmtIP +
// TestParseGoAheadBaseMACFromSystemInfo combined through the Reader.
func TestGS728TPPGetMgmtIP(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs728tppPages(t)), "gs728tpp")
	mgmt, err := r.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
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
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "B0:39:56:77:54:29" {
		t.Errorf("BaseMac = %v, want \"B0:39:56:77:54:29\" (merged from the SystemInfo page)", mgmt.BaseMac)
	}
}

// TestGS728TPPGetHostname exercises reader.go's GetHostname GoAhead branch:
// DeviceBasicInfo/deviceName, a DIFFERENT page shape from GS110EMX/GS105PE's
// HTTPSysInfo form scrape (the GoAhead identity data is XML). Mirrors
// parse_goahead_test.go's own ParseGoAheadHostname pin through the Reader.
func TestGS728TPPGetHostname(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs728tppPages(t)), "gs728tpp")
	got, err := r.GetHostname(context.Background())
	if err != nil {
		t.Fatalf("GetHostname() error = %v", err)
	}
	if got != "sw-netgear-gs728tpp" {
		t.Errorf("GetHostname() = %q, want %q", got, "sw-netgear-gs728tpp")
	}
}
