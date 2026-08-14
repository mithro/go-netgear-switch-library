package webui_test

// reader_test.go: TDD coverage for webui.Reader (reader.go), ported
// scenario-for-scenario from tests/test_http_read.py at pin 1841111 in
// python-netgear-switch-library. Every fixture referenced here is the SAME
// capture the Python test file reads (copied into webui/testdata/http by
// earlier tasks); every expected value below was cross-checked against that
// file's own assertions.
//
// fakeSession mirrors Python's _FakeSession: an in-memory webui.Session that
// serves captured fixtures per path. A page value is either a plain string
// or a func(map[string]string) string for the FASTPATH VLAN-Membership
// endpoint, which serves a DIFFERENT page per "vlanId" -- a fake that
// ignored the form would hand every VLAN the captured VLAN's membership,
// exactly the mislabelling the reader's wrong-VLAN guard exists to catch.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

type readerFakeSession struct {
	pages map[string]any // string or func(map[string]string) string
}

func newFakeSession(pages map[string]any) *readerFakeSession {
	return &readerFakeSession{pages: pages}
}

func (s *readerFakeSession) resolve(path string, data map[string]string) (string, error) {
	page, ok := s.pages[path]
	if !ok {
		return "", fmt.Errorf("fakeSession: no page registered for %q", path)
	}
	switch p := page.(type) {
	case string:
		return p, nil
	case func(map[string]string) string:
		return p(data), nil
	default:
		return "", fmt.Errorf("fakeSession: page %q has unexpected value type %T", path, page)
	}
}

func (s *readerFakeSession) Login(_ context.Context) error { return nil }

func (s *readerFakeSession) GetPage(_ context.Context, path string) (string, error) {
	return s.resolve(path, nil)
}

func (s *readerFakeSession) PostForm(_ context.Context, path string, data map[string]string) (string, error) {
	return s.resolve(path, data)
}

func (s *readerFakeSession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	return "", fmt.Errorf("fakeSession: PostMultipart(%q) not supported by this fake", path)
}

func (s *readerFakeSession) PostXML(_ context.Context, path string, _ string) (string, error) {
	return s.resolve(path, nil)
}

var _ webui.Session = (*readerFakeSession)(nil)

// membershipResponder mirrors Python's _membership(*names) helper: a
// VLAN-Membership responder over the captured pages in names, keyed by the
// VLAN each capture actually shows. The GET (no "vlanId" in the posted
// form) serves the FIRST one, mirroring real firmware rendering whichever
// VLAN the session last selected. A VLAN with no matching capture fails the
// test loudly (via t.Fatalf) rather than being faked.
func membershipResponder(t *testing.T, names ...string) func(map[string]string) string {
	t.Helper()
	bodies := make([]string, len(names))
	byVID := make(map[int]string, len(names))
	for i, n := range names {
		body := readFixture(t, n)
		bodies[i] = body
		page, err := webui.ParseFastpathMembership(body)
		if err != nil {
			t.Fatalf("membershipResponder(%q): ParseFastpathMembership: %v", n, err)
		}
		if page.VlanID == nil {
			t.Fatalf("membershipResponder(%q): capture has no vlan id", n)
		}
		byVID[*page.VlanID] = body
	}
	return func(data map[string]string) string {
		requested, ok := data["vlanId"]
		if !ok || requested == "" {
			return bodies[0]
		}
		vid, err := strconv.Atoi(requested)
		if err != nil {
			t.Fatalf("membershipResponder: unparseable vlanId %q", requested)
		}
		body, ok := byVID[vid]
		if !ok {
			t.Fatalf("membershipResponder: no capture for vlanId=%d", vid)
		}
		return body
	}
}

func mustGetModel(t *testing.T, key string) *model.SwitchModel {
	t.Helper()
	m, err := model.GetModel(key)
	if err != nil {
		t.Fatalf("model.GetModel(%q): %v", key, err)
	}
	return m
}

func mustNewReader(t *testing.T, session webui.Session, modelKey string) *webui.Reader {
	t.Helper()
	r, err := webui.NewReader(session, mustGetModel(t, modelKey))
	if err != nil {
		t.Fatalf("webui.NewReader(%q): %v", modelKey, err)
	}
	return r
}

func wantUnsupported(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("%s: error = %v, want model.ErrUnsupportedCapability", what, err)
	}
}

// --- gs305ep (STANDARD dialect) -- test_http_read.py::_pages + its consumers ---

func gs305epPages(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"/dashboard.cgi":        readFixture(t, "gs305ep_dashboard.html"),
		"/portStatistics.cgi":   readFixture(t, "gs305ep_portstats.html"),
		"/getPoePortStatus.cgi": readFixture(t, "gs305ep_poestatus.html"),
		"/portPVID.cgi":         readFixture(t, "gs305ep_pvid.html"),
		"/8021qCf.cgi":          readFixture(t, "gs305ep_vlancfg.html"),
		"/8021qMembe.cgi":       readFixture(t, "gs305ep_membership.html"),
	}
}

// TestGS305EPGetPortsAndPoE mirrors test_http_read.py::test_get_ports_and_poe.
func TestGS305EPGetPortsAndPoE(t *testing.T) {
	ctx := context.Background()
	r := mustNewReader(t, newFakeSession(gs305epPages(t)), "gs305ep")

	ports, err := r.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	byPort := make(map[int]model.PortStatus, len(ports))
	for _, p := range ports {
		byPort[p.Port] = p
	}
	if !byPort[1].LinkUp {
		t.Errorf("ports[1].LinkUp = false, want true")
	}

	poe, err := r.GetPoE(ctx)
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	byPoEPort := make(map[int]model.PoEStatus, len(poe))
	for _, p := range poe {
		byPoEPort[p.Port] = p
	}
	if byPoEPort[1].Detect != model.PoEDetectDelivering {
		t.Errorf("poe[1].Detect = %v, want PoEDetectDelivering", byPoEPort[1].Detect)
	}
	if byPoEPort[1].PowerMw == nil || *byPoEPort[1].PowerMw != 12800 {
		t.Errorf("poe[1].PowerMw = %v, want 12800", byPoEPort[1].PowerMw)
	}
}

// TestGS305EPGetPVIDs mirrors test_http_read.py::test_get_pvids.
func TestGS305EPGetPVIDs(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs305epPages(t)), "gs305ep")
	pvids, err := r.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	got := make(map[int]int, len(pvids))
	for _, p := range pvids {
		got[p.Port] = p.Vlan
	}
	want := map[int]int{1: 90, 2: 1}
	for port, vlan := range want {
		if got[port] != vlan {
			t.Errorf("pvids[%d] = %d, want %d", port, got[port], vlan)
		}
	}
}

// TestGS305EPGetStats mirrors test_http_read.py::test_get_stats.
func TestGS305EPGetStats(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs305epPages(t)), "gs305ep")
	stats, err := r.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	byPort := make(map[int]model.PortStats, len(stats))
	for _, s := range stats {
		byPort[s.Port] = s
	}
	check := func(port int, rx, tx, rxErr uint64) {
		s := byPort[port]
		if s.RxBytes == nil || *s.RxBytes != rx {
			t.Errorf("stats[%d].RxBytes = %v, want %d", port, s.RxBytes, rx)
		}
		if s.TxBytes == nil || *s.TxBytes != tx {
			t.Errorf("stats[%d].TxBytes = %v, want %d", port, s.TxBytes, tx)
		}
		if s.RxErrors == nil || *s.RxErrors != rxErr {
			t.Errorf("stats[%d].RxErrors = %v, want %d", port, s.RxErrors, rxErr)
		}
	}
	check(1, 1000000, 2000000, 0)
	check(2, 500, 750, 3)
}

// TestGS305EPGetVLANs mirrors test_http_read.py::test_get_vlans.
func TestGS305EPGetVLANs(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs305epPages(t)), "gs305ep")
	vlans, err := r.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	byID := make(map[int]model.VLANInfo, len(vlans))
	for _, v := range vlans {
		byID[v.VlanID] = v
	}
	if _, ok := byID[1]; !ok {
		t.Error("vlans missing id 1")
	}
	v90, ok := byID[90]
	if !ok {
		t.Fatal("vlans missing id 90")
	}
	if !equalInts(v90.TaggedPorts, []int{1}) {
		t.Errorf("vlan90.TaggedPorts = %v, want [1]", v90.TaggedPorts)
	}
	if !equalInts(v90.UntaggedPorts, []int{2, 3}) {
		t.Errorf("vlan90.UntaggedPorts = %v, want [2 3]", v90.UntaggedPorts)
	}
	if !equalInts(v90.MemberPorts, []int{1, 2, 3}) {
		t.Errorf("vlan90.MemberPorts = %v, want [1 2 3]", v90.MemberPorts)
	}
}

// TestGS305EPMACTableUnsupportedOnPlus mirrors test_http_read.py::
// test_mac_table_unsupported_on_plus.
func TestGS305EPMACTableUnsupportedOnPlus(t *testing.T) {
	ctx := context.Background()
	r := mustNewReader(t, newFakeSession(gs305epPages(t)), "gs305ep")
	_, err := r.GetMACs(ctx)
	wantUnsupported(t, err, "GetMACs")
	_, err = r.GetSensors(ctx)
	wantUnsupported(t, err, "GetSensors")
	_, err = r.GetLLDP(ctx)
	wantUnsupported(t, err, "GetLLDP")
}

// --- gsm7228ps (S3300 dialect) -- test_http_read.py::_gsm7228ps_pages ---

func gsm7228psPages(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"/portsConfiguration.html":               readFixture(t, "gsm7228ps_portsConfiguration.html"),
		"/portStatistics.html":                   readFixture(t, "gsm7228ps_portStatistics.html"),
		"/poeInterfaceConfiguration.html":        readFixture(t, "gsm7228ps_poeInterfaceConfiguration.html"),
		"/vlanStatus.html":                       readFixture(t, "gsm7228ps_vlanStatus.html"),
		"/portPvidConfiguration.html":            readFixture(t, "gsm7228ps_portPvidConfiguration.html"),
		"/basicAddressTable.html":                readFixture(t, "gsm7228ps_basicAddressTable.html"),
		"/lldpRemoteInventory.html":              readFixture(t, "gsm7228ps_lldpRemoteInventory.html"),
		"/base/system/management/sysInfo.html":   readFixture(t, "gsm7228ps_sysInfo.html"),
		"/ipConfiguration.html":                  readFixture(t, "gsm7228ps_ipConfiguration.html"),
		"/switching/dot1q/vlan_port_cfg.html":    membershipResponder(t, "gsm7228ps_vlanPortCfg_vlan5.html"),
		"/switching/dot1q/vlan_port_cfg_rw.html": membershipResponder(t, "gsm7228ps_vlanPortCfg_vlan5.html"),
	}
}

// TestGSM7228PSReadsAreGroundedNotRefused mirrors test_http_read.py::
// test_gsm7228ps_reads_are_grounded_not_refused: gsm7228ps GRADUATED
// (reads_verified=True at this pin) so construction must succeed.
func TestGSM7228PSReadsAreGroundedNotRefused(t *testing.T) {
	ctx := context.Background()
	r := mustNewReader(t, newFakeSession(gsm7228psPages(t)), "gsm7228ps")

	ports, err := r.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != 52 {
		t.Errorf("len(ports) = %d, want 52", len(ports))
	}

	poe, err := r.GetPoE(ctx)
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	if len(poe) != 48 {
		t.Errorf("len(poe) = %d, want 48", len(poe))
	}

	vlanStatus := readFixture(t, "gsm7228ps_vlanStatus.html")
	vlans, err := webui.ParseS3300Vlans(vlanStatus)
	if err != nil {
		t.Fatalf("ParseS3300Vlans() error = %v", err)
	}
	gotIDs := make(map[int]bool, len(vlans))
	for _, v := range vlans {
		gotIDs[v.VlanID] = true
	}
	for _, want := range []int{1, 5, 21, 121, 4089} {
		if !gotIDs[want] {
			t.Errorf("vlan ids = %v, missing %d", gotIDs, want)
		}
	}

	member5, err := r.ReadFastpathMembership(ctx, 5)
	if err != nil {
		t.Fatalf("ReadFastpathMembership(5) error = %v", err)
	}
	if !equalInts(member5.TaggedPorts, []int{49, 50, 51, 52}) {
		t.Errorf("member5.TaggedPorts = %v, want [49 50 51 52]", member5.TaggedPorts)
	}
	if !equalInts(member5.UntaggedPorts, []int{41}) {
		t.Errorf("member5.UntaggedPorts = %v, want [41]", member5.UntaggedPorts)
	}

	macs, err := r.GetMACs(ctx)
	if err != nil {
		t.Fatalf("GetMACs() error = %v", err)
	}
	if len(macs) != 17 {
		t.Errorf("len(macs) = %d, want 17 (base MAC on CPU \"c1\" is skipped)", len(macs))
	}

	mgmt, err := r.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.11" {
		t.Errorf("mgmt.Address = %v, want \"10.1.5.11\"", mgmt.Address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != "255.255.255.0" {
		t.Errorf("mgmt.Netmask = %v, want \"255.255.255.0\"", mgmt.Netmask)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != "10.1.5.1" {
		t.Errorf("mgmt.Gateway = %v, want \"10.1.5.1\"", mgmt.Gateway)
	}
	if mgmt.Mode != model.IPModeDHCP {
		t.Errorf("mgmt.Mode = %v, want IPModeDHCP", mgmt.Mode)
	}
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "08:BD:43:6B:B8:D8" {
		t.Errorf("mgmt.BaseMac = %v, want \"08:BD:43:6B:B8:D8\"", mgmt.BaseMac)
	}

	_, err = r.GetSensors(ctx)
	wantUnsupported(t, err, "GetSensors") // S3300 sysInfo has no live fan/temp table
}

// --- gs110emx (GS110EMX dialect) -- test_http_read.py::_gs110emx_pages ---

func gs110emxPages(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"/iss/specific/sysInfo.html":          readFixture(t, "gs110emx_sysinfo.html"),
		"/iss/specific/interface_stats.html":  readFixture(t, "gs110emx_interface_stats.html"),
		"/iss/specific/port_settings.html":    readFixture(t, "gs110emx_port_settings.html"),
		"/iss/specific/vlan_pvidsetting.html": readFixture(t, "gs110emx_pvid.html"),
		"/iss/specific/Cf8021q.html":          readFixture(t, "gs110emx_cf8021q.html"),
		"/iss/specific/vlanMembership.html":   readFixture(t, "gs110emx_vlanmembership.html"),
	}
}

// TestGS110EMXReadsAreGroundedNotRefused mirrors test_http_read.py::
// test_gs110emx_reads_are_grounded_not_refused.
func TestGS110EMXReadsAreGroundedNotRefused(t *testing.T) {
	mustNewReader(t, newFakeSession(gs110emxPages(t)), "gs110emx")
}

// TestGS110EMXGetStatsUsesRealHardwareRowShape mirrors test_http_read.py::
// test_gs110emx_get_stats_uses_real_hardware_row_shape.
func TestGS110EMXGetStatsUsesRealHardwareRowShape(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs110emxPages(t)), "gs110emx")
	stats, err := r.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	byPort := make(map[int]model.PortStats, len(stats))
	for _, s := range stats {
		byPort[s.Port] = s
	}
	checkTx := func(port int, want uint64) {
		if s := byPort[port]; s.TxBytes == nil || *s.TxBytes != want {
			t.Errorf("stats[%d].TxBytes = %v, want %d", port, s.TxBytes, want)
		}
	}
	checkRx := func(port int, want uint64) {
		if s := byPort[port]; s.RxBytes == nil || *s.RxBytes != want {
			t.Errorf("stats[%d].RxBytes = %v, want %d", port, s.RxBytes, want)
		}
	}
	checkRx(1, 0)
	checkTx(1, 0)
	checkTx(6, 70892018242)
	checkRx(8, 59921732691)
	checkTx(8, 78637274870)
	checkRx(9, 2963140428936)
	checkTx(10, 3027396511187)
	for _, s := range stats {
		if s.RxErrors == nil || *s.RxErrors != 0 {
			t.Errorf("stats[%d].RxErrors = %v, want 0", s.Port, s.RxErrors)
		}
		if s.RxPackets != nil || s.TxPackets != nil {
			t.Errorf("stats[%d] packet counters = (%v,%v), want (nil,nil)", s.Port, s.RxPackets, s.TxPackets)
		}
	}
}

// TestGS110EMXGetMgmtIPFromSysinfo mirrors test_http_read.py::
// test_gs110emx_get_mgmt_ip_from_sysinfo.
func TestGS110EMXGetMgmtIPFromSysinfo(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs110emxPages(t)), "gs110emx")
	mgmt, err := r.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.25" {
		t.Errorf("Address = %v, want \"10.1.5.25\"", mgmt.Address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != "255.255.255.0" {
		t.Errorf("Netmask = %v, want \"255.255.255.0\"", mgmt.Netmask)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != "10.1.5.1" {
		t.Errorf("Gateway = %v, want \"10.1.5.1\"", mgmt.Gateway)
	}
	if mgmt.Mode != model.IPModeStatic {
		t.Errorf("Mode = %v, want IPModeStatic", mgmt.Mode)
	}
	// Uppercased to match the SNMP/NSDP backends' base_mac formatting -- the
	// real captured page text is lowercase ("bc:a5:11:b8:ec:f1").
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "BC:A5:11:B8:EC:F1" {
		t.Errorf("BaseMac = %v, want \"BC:A5:11:B8:EC:F1\"", mgmt.BaseMac)
	}
}

// TestGS110EMXHTTPPortsGroundedInRealCapture mirrors test_http_read.py::
// test_gs110emx_http_ports_grounded_in_real_capture.
func TestGS110EMXHTTPPortsGroundedInRealCapture(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs110emxPages(t)), "gs110emx")
	ports, err := r.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	byPort := make(map[int]model.PortStatus, len(ports))
	for _, p := range ports {
		byPort[p.Port] = p
	}
	if len(byPort) != 10 {
		t.Fatalf("len(ports) = %d, want 10", len(byPort))
	}
	checkUp := func(port, wantSpeed int) {
		p := byPort[port]
		if !p.LinkUp || p.SpeedMbps == nil || *p.SpeedMbps != wantSpeed {
			t.Errorf("ports[%d] = (link_up=%v, speed=%v), want (true, %d)", port, p.LinkUp, p.SpeedMbps, wantSpeed)
		}
	}
	checkUp(6, 100)
	checkUp(8, 1000)
	checkUp(9, 10000)
	checkUp(10, 10000)
	if p := byPort[1]; p.LinkUp || p.SpeedMbps != nil {
		t.Errorf("ports[1] = (link_up=%v, speed=%v), want (false, nil)", p.LinkUp, p.SpeedMbps)
	}
	if byPort[8].Name == nil || *byPort[8].Name != "rumpus" {
		t.Errorf("ports[8].Name = %v, want \"rumpus\"", byPort[8].Name)
	}
}

// TestGS110EMXHTTPPVIDsGroundedInRealCapture mirrors test_http_read.py::
// test_gs110emx_http_pvids_grounded_in_real_capture.
func TestGS110EMXHTTPPVIDsGroundedInRealCapture(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs110emxPages(t)), "gs110emx")
	pvids, err := r.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	if len(pvids) != 10 {
		t.Fatalf("len(pvids) = %d, want 10", len(pvids))
	}
	for _, p := range pvids {
		if p.Vlan != 1 {
			t.Errorf("pvids[port=%d] = %d, want 1", p.Port, p.Vlan)
		}
	}
}

// TestGS110EMXHTTPVlansGroundedInRealCapture mirrors test_http_read.py::
// test_gs110emx_http_vlans_grounded_in_real_capture.
func TestGS110EMXHTTPVlansGroundedInRealCapture(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs110emxPages(t)), "gs110emx")
	vlans, err := r.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	byID := make(map[int]model.VLANInfo, len(vlans))
	for _, v := range vlans {
		byID[v.VlanID] = v
	}
	wantIDs := []int{1, 4, 5, 6, 7, 10, 20, 21, 41, 90, 99, 121}
	for _, id := range wantIDs {
		if _, ok := byID[id]; !ok {
			t.Errorf("vlans missing id %d", id)
		}
	}
	v1 := byID[1]
	if !equalInts(v1.UntaggedPorts, []int{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Errorf("vlan1.UntaggedPorts = %v, want [1..8]", v1.UntaggedPorts)
	}
	if !equalInts(v1.TaggedPorts, []int{9, 10}) {
		t.Errorf("vlan1.TaggedPorts = %v, want [9 10]", v1.TaggedPorts)
	}
	if !equalInts(v1.MemberPorts, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
		t.Errorf("vlan1.MemberPorts = %v, want [1..10]", v1.MemberPorts)
	}
}

// TestGS110EMXHTTPPoEAndL2TablesUnsupported mirrors test_http_read.py::
// test_gs110emx_http_poe_and_l2_tables_unsupported.
func TestGS110EMXHTTPPoEAndL2TablesUnsupported(t *testing.T) {
	ctx := context.Background()
	r := mustNewReader(t, newFakeSession(gs110emxPages(t)), "gs110emx")
	if _, err := r.GetPoE(ctx); true {
		wantUnsupported(t, err, "GetPoE")
	}
	if _, err := r.GetMACs(ctx); true {
		wantUnsupported(t, err, "GetMACs")
	}
	if _, err := r.GetLLDP(ctx); true {
		wantUnsupported(t, err, "GetLLDP")
	}
	if _, err := r.GetSensors(ctx); true {
		wantUnsupported(t, err, "GetSensors")
	}
}

// --- gs105pe (GS105PE dialect) -- test_http_read.py::_gs105pe_pages ---

func gs105pePages(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"/status.cgi":         readFixture(t, "gs105pe_status.html"),
		"/portStatistics.cgi": readFixture(t, "gs105pe_portstats.html"),
		"/portPVID.cgi":       readFixture(t, "gs105pe_pvid.html"),
		"/8021qCf.cgi":        readFixture(t, "gs105pe_vlancfg.html"),
		"/8021qMembe.cgi":     readFixture(t, "gs105pe_membership.html"),
		"/switch_info.cgi":    readFixture(t, "gs105pe_switch_info.html"),
	}
}

// TestGS105PEHTTPPortsMatchLiveNSDP mirrors test_http_read.py::
// test_gs105pe_http_ports_match_live_nsdp.
func TestGS105PEHTTPPortsMatchLiveNSDP(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs105pePages(t)), "gs105pe")
	ports, err := r.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	type want struct {
		up    bool
		speed *int
	}
	wantFor := map[int]want{
		1: {false, nil},
		2: {false, nil},
		3: {true, model.Ptr(100)},
		4: {false, nil},
		5: {true, model.Ptr(1000)},
	}
	for _, p := range ports {
		w, ok := wantFor[p.Port]
		if !ok {
			t.Errorf("unexpected port %d", p.Port)
			continue
		}
		if p.LinkUp != w.up {
			t.Errorf("ports[%d].LinkUp = %v, want %v", p.Port, p.LinkUp, w.up)
		}
		gotSpeed := "nil"
		if p.SpeedMbps != nil {
			gotSpeed = fmt.Sprintf("%d", *p.SpeedMbps)
		}
		wantSpeed := "nil"
		if w.speed != nil {
			wantSpeed = fmt.Sprintf("%d", *w.speed)
		}
		if gotSpeed != wantSpeed {
			t.Errorf("ports[%d].SpeedMbps = %s, want %s", p.Port, gotSpeed, wantSpeed)
		}
	}
}

// TestGS105PEHTTPPVIDsMatchLiveNSDP mirrors test_http_read.py::
// test_gs105pe_http_pvids_match_live_nsdp.
func TestGS105PEHTTPPVIDsMatchLiveNSDP(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs105pePages(t)), "gs105pe")
	pvids, err := r.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	got := make(map[int]int, len(pvids))
	for _, p := range pvids {
		got[p.Port] = p.Vlan
	}
	want := map[int]int{1: 41, 2: 41, 3: 90, 4: 41, 5: 1}
	for port, vlan := range want {
		if got[port] != vlan {
			t.Errorf("pvids[%d] = %d, want %d", port, got[port], vlan)
		}
	}
}

// TestGS105PEHTTPStatsDecodeHiddenCounterHalves mirrors test_http_read.py::
// test_gs105pe_http_stats_decode_hidden_counter_halves.
func TestGS105PEHTTPStatsDecodeHiddenCounterHalves(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs105pePages(t)), "gs105pe")
	stats, err := r.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	byPort := make(map[int]model.PortStats, len(stats))
	for _, s := range stats {
		byPort[s.Port] = s
	}
	check := func(port int, rx, tx uint64) {
		s := byPort[port]
		if s.RxBytes == nil || *s.RxBytes != rx || s.TxBytes == nil || *s.TxBytes != tx {
			var gotRx, gotTx uint64
			if s.RxBytes != nil {
				gotRx = *s.RxBytes
			}
			if s.TxBytes != nil {
				gotTx = *s.TxBytes
			}
			t.Errorf("stats[%d] = (%d,%d), want (%d,%d)", port, gotRx, gotTx, rx, tx)
		}
	}
	check(3, 0, 11625519)
	check(5, 33619588, 495898)
	check(1, 0, 0)
}

// TestGS105PEHTTPMgmtIPMatchesLiveNSDP mirrors test_http_read.py::
// test_gs105pe_http_mgmt_ip_matches_live_nsdp.
func TestGS105PEHTTPMgmtIPMatchesLiveNSDP(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs105pePages(t)), "gs105pe")
	mgmt, err := r.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.30" {
		t.Errorf("Address = %v, want \"10.1.5.30\"", mgmt.Address)
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
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "38:94:ED:B7:CD:E0" {
		t.Errorf("BaseMac = %v, want \"38:94:ED:B7:CD:E0\"", mgmt.BaseMac)
	}
}

// TestGS105PEHTTPPoEUnsupportedNoPSE mirrors test_http_read.py::
// test_gs105pe_http_poe_unsupported_no_pse.
func TestGS105PEHTTPPoEUnsupportedNoPSE(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gs105pePages(t)), "gs105pe")
	_, err := r.GetPoE(context.Background())
	wantUnsupported(t, err, "GetPoE")
}

// --- m4300-24x (M4300 dialect) -- test_http_read.py::_m4300_pages ---

func m4300Pages(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"/v1/portsConfiguration.html":               readFixture(t, "m4300_ports.html"),
		"/v1/portStatistics.html":                   readFixture(t, "m4300_portstats.html"),
		"/v1/vlanStatus.html":                       readFixture(t, "m4300_vlanstatus.html"),
		"/v1/portPvidConfiguration.html":            readFixture(t, "m4300_pvid.html"),
		"/v1/basicAddressTable.html":                readFixture(t, "m4300_addresstable.html"),
		"/v1/base/system/management/sysInfo.html":   readFixture(t, "m4300_sysinfo.html"),
		"/v1/lldpRemoteInventory.html":              readFixture(t, "m4300_lldpRemoteInventory.html"),
		"/v1/mgmtVlanIpv4Configuration.html":        readFixture(t, "m4300_mgmtVlanIpv4Configuration.html"),
		"/v1/switching/dot1q/vlan_port_cfg.html":    membershipResponder(t, "m4300_vlanportcfg_vlan1.html"),
		"/v1/switching/dot1q/vlan_port_cfg_rw.html": membershipResponder(t, "m4300_vlanportcfg_vlan1.html"),
	}
}

// TestM4300HTTPPortsMatchLiveSNMP mirrors test_http_read.py::
// test_m4300_http_ports_match_live_snmp.
func TestM4300HTTPPortsMatchLiveSNMP(t *testing.T) {
	r := mustNewReader(t, newFakeSession(m4300Pages(t)), "m4300-24x")
	ports, err := r.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	byPort := make(map[int]model.PortStatus, len(ports))
	for _, p := range ports {
		byPort[p.Port] = p
	}
	if len(byPort) != 24 {
		t.Fatalf("len(ports) = %d, want 24", len(byPort))
	}
	if byPort[1].Name == nil || *byPort[1].Name != "1/0/1" {
		t.Errorf("ports[1].Name = %v, want \"1/0/1\"", byPort[1].Name)
	}
	if !byPort[1].LinkUp || byPort[1].SpeedMbps == nil || *byPort[1].SpeedMbps != 10000 {
		t.Errorf("ports[1] = (up=%v, speed=%v), want (true, 10000)", byPort[1].LinkUp, byPort[1].SpeedMbps)
	}
	if !byPort[3].LinkUp || byPort[3].SpeedMbps == nil || *byPort[3].SpeedMbps != 1000 {
		t.Errorf("ports[3] = (up=%v, speed=%v), want (true, 1000)", byPort[3].LinkUp, byPort[3].SpeedMbps)
	}
	if byPort[4].LinkUp || byPort[4].SpeedMbps != nil {
		t.Errorf("ports[4] = (up=%v, speed=%v), want (false, nil)", byPort[4].LinkUp, byPort[4].SpeedMbps)
	}
}

// TestM4300HTTPStatsAreFramesNotBytes mirrors test_http_read.py::
// test_m4300_http_stats_are_frames_not_bytes.
func TestM4300HTTPStatsAreFramesNotBytes(t *testing.T) {
	r := mustNewReader(t, newFakeSession(m4300Pages(t)), "m4300-24x")
	stats, err := r.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	if len(stats) != 24 {
		t.Fatalf("len(stats) = %d, want 24", len(stats))
	}
	byPort := make(map[int]model.PortStats, len(stats))
	for _, s := range stats {
		byPort[s.Port] = s
	}
	s1 := byPort[1]
	if s1.RxPackets == nil || *s1.RxPackets != 17057817472 {
		t.Errorf("stats[1].RxPackets = %v, want 17057817472", s1.RxPackets)
	}
	if s1.RxBytes != nil || s1.TxBytes != nil {
		t.Errorf("stats[1] byte counters = (%v,%v), want (nil,nil) -- this UI reports frames, never octets", s1.RxBytes, s1.TxBytes)
	}
}

// TestM4300HTTPVlansExpandPhysicalPortsOnly mirrors test_http_read.py::
// test_m4300_http_vlans_expand_physical_ports_only.
func TestM4300HTTPVlansExpandPhysicalPortsOnly(t *testing.T) {
	ctx := context.Background()
	vlanStatus := readFixture(t, "m4300_vlanstatus.html")
	vlans, err := webui.ParseM4300Vlans(vlanStatus)
	if err != nil {
		t.Fatalf("ParseM4300Vlans() error = %v", err)
	}
	byID := make(map[int]model.VLANInfo, len(vlans))
	for _, v := range vlans {
		byID[v.VlanID] = v
	}
	if len(byID) != 14 {
		t.Fatalf("len(vlans) = %d, want 14", len(byID))
	}
	v1 := byID[1]
	if v1.Name == nil || *v1.Name != "default" {
		t.Errorf("vlans[1].Name = %v, want \"default\"", v1.Name)
	}
	if !equalInts(v1.MemberPorts, []int{1, 2, 5, 7, 8}) {
		t.Errorf("vlans[1].MemberPorts = %v, want [1 2 5 7 8]", v1.MemberPorts)
	}
	for _, v := range byID {
		for _, p := range v.MemberPorts {
			if p > 24 {
				t.Errorf("vlan %d member_ports contains out-of-range port %d (LAG range wrongly expanded?)", v.VlanID, p)
			}
		}
	}

	r := mustNewReader(t, newFakeSession(m4300Pages(t)), "m4300-24x")
	member1, err := r.ReadFastpathMembership(ctx, 1)
	if err != nil {
		t.Fatalf("ReadFastpathMembership(1) error = %v", err)
	}
	if !equalInts(member1.TaggedPorts, []int{5}) {
		t.Errorf("member1.TaggedPorts = %v, want [5]", member1.TaggedPorts)
	}
	if !equalInts(member1.UntaggedPorts, []int{1, 2, 7, 8}) {
		t.Errorf("member1.UntaggedPorts = %v, want [1 2 7 8]", member1.UntaggedPorts)
	}
	union := make(map[int]bool)
	for _, p := range member1.TaggedPorts {
		union[p] = true
	}
	for _, p := range member1.UntaggedPorts {
		union[p] = true
	}
	for _, p := range v1.MemberPorts {
		if !union[p] {
			t.Errorf("member1 tagged|untagged missing vlanStatus member port %d", p)
		}
	}
}

// TestM4300HTTPPVIDsAndMacs mirrors test_http_read.py::
// test_m4300_http_pvids_and_macs.
func TestM4300HTTPPVIDsAndMacs(t *testing.T) {
	r := mustNewReader(t, newFakeSession(m4300Pages(t)), "m4300-24x")
	pvids, err := r.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	if len(pvids) != 24 {
		t.Fatalf("len(pvids) = %d, want 24", len(pvids))
	}
	got := make(map[int]int, len(pvids))
	for _, p := range pvids {
		got[p.Port] = p.Vlan
	}
	if got[3] != 5 {
		t.Errorf("pvids[3] = %d, want 5", got[3])
	}
}

// TestM4300HTTPMacsRefuseTruncatedPage mirrors test_http_read.py::
// test_m4300_http_macs_refuse_truncated_page.
func TestM4300HTTPMacsRefuseTruncatedPage(t *testing.T) {
	r := mustNewReader(t, newFakeSession(m4300Pages(t)), "m4300-24x")
	_, err := r.GetMACs(context.Background())
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Fatalf("GetMACs() error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
	if !strings.Contains(err.Error(), "paginates") {
		t.Errorf("GetMACs() error = %q, want it to mention \"paginates\"", err.Error())
	}
}

// TestM4300HTTPMgmtAndSensors mirrors test_http_read.py::
// test_m4300_http_mgmt_and_sensors.
func TestM4300HTTPMgmtAndSensors(t *testing.T) {
	ctx := context.Background()
	r := mustNewReader(t, newFakeSession(m4300Pages(t)), "m4300-24x")
	mgmt, err := r.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
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
	// The BASE MAC still comes from sysInfo: the mgmt page's own v_4_4_1 is
	// the management INTERFACE's MAC (...:BB:E3), one off from this.
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "8C:3B:AD:6B:BB:E0" {
		t.Errorf("BaseMac = %v, want \"8C:3B:AD:6B:BB:E0\"", mgmt.BaseMac)
	}

	sensors, err := r.GetSensors(ctx)
	if err != nil {
		t.Fatalf("GetSensors() error = %v", err)
	}
	found := false
	for _, s := range sensors {
		if s.Kind == "temperature" && s.Value > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected at least one temperature sensor with value > 0")
	}
}

// TestM4300HTTPLLDPMatchesLiveSNMP mirrors test_http_read.py::
// test_m4300_http_lldp_matches_live_snmp.
func TestM4300HTTPLLDPMatchesLiveSNMP(t *testing.T) {
	r := mustNewReader(t, newFakeSession(m4300Pages(t)), "m4300-24x")
	lldp, err := r.GetLLDP(context.Background())
	if err != nil {
		t.Fatalf("GetLLDP() error = %v", err)
	}
	if len(lldp) != 11 {
		t.Fatalf("len(lldp) = %d, want 11", len(lldp))
	}
	byPort := make(map[int]model.LLDPNeighbor, len(lldp))
	for _, n := range lldp {
		byPort[n.LocalPort] = n
	}
	if n := byPort[1]; n.RemoteSysName == nil || *n.RemoteSysName != "manage-sw-netgear-m4300-16x-poe-s2" {
		t.Errorf("lldp[1].RemoteSysName = %v, want \"manage-sw-netgear-m4300-16x-poe-s2\"", n.RemoteSysName)
	}
	if n := byPort[1]; n.RemoteChassisID == nil || *n.RemoteChassisID != "8C:3B:AD:69:1C:38" {
		t.Errorf("lldp[1].RemoteChassisID = %v, want \"8C:3B:AD:69:1C:38\"", n.RemoteChassisID)
	}
	if n := byPort[2]; n.RemoteSysName == nil || !strings.HasPrefix(*n.RemoteSysName, "sw-netgear-gsm7252ps") {
		t.Errorf("lldp[2].RemoteSysName = %v, want prefix \"sw-netgear-gsm7252ps\"", n.RemoteSysName)
	}
	if n := byPort[19]; n.RemoteSysName == nil || *n.RemoteSysName != "big-storage" {
		t.Errorf("lldp[19].RemoteSysName = %v, want \"big-storage\"", n.RemoteSysName)
	}
}

// --- gsm7252ps (XE_FASTPATH dialect) -- test_http_read.py::_gsm7252ps_pages ---

func gsm7252psPages(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"/portsConfiguration.html":             readFixture(t, "gsm7252ps_portsConfiguration.html"),
		"/portStatistics.html":                 readFixture(t, "gsm7252ps_portStatistics.html"),
		"/portPvidConfiguration.html":          readFixture(t, "gsm7252ps_portPvidConfiguration.html"),
		"/vlanStatus.html":                     readFixture(t, "gsm7252ps_vlanStatus.html"),
		"/basicAddressTable.html":              readFixture(t, "gsm7252ps_basicAddressTable.html"),
		"/poeInterfaceConfiguration.html":      readFixture(t, "gsm7252ps_poeInterfaceConfiguration.html"),
		"/lldpRemoteInventory.html":            readFixture(t, "gsm7252ps_lldpRemoteInventory.html"),
		"/base/system/management/sysInfo.html": readFixture(t, "gsm7252ps_sysInfo.html"),
		"/ipConfiguration.html":                readFixture(t, "gsm7252ps_ipConfiguration.html"),
		"/switching/dot1q/vlan_port_cfg.html": membershipResponder(t,
			"gsm7252ps_vlanPortCfg_vlan1.html", "gsm7252ps_vlanPortCfg_vlan141.html"),
		"/switching/dot1q/vlan_port_cfg_rw.html": membershipResponder(t,
			"gsm7252ps_vlanPortCfg_vlan1.html", "gsm7252ps_vlanPortCfg_vlan141.html"),
	}
}

// TestGSM7252PSEveryReadOpIsServedOverHTTP mirrors test_http_read.py::
// test_gsm7252ps_every_read_op_is_served_over_http: FULL PARITY, no op
// raises model.ErrUnsupportedCapability for this model.
func TestGSM7252PSEveryReadOpIsServedOverHTTP(t *testing.T) {
	ctx := context.Background()
	r := mustNewReader(t, newFakeSession(gsm7252psPages(t)), "gsm7252ps")

	ports, err := r.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != 52 {
		t.Fatalf("len(ports) = %d, want 52", len(ports))
	}
	byPort := make(map[int]model.PortStatus, len(ports))
	for _, p := range ports {
		byPort[p.Port] = p
	}
	if !byPort[1].LinkUp || byPort[1].SpeedMbps == nil || *byPort[1].SpeedMbps != 1000 {
		t.Errorf("ports[1] = (up=%v, speed=%v), want (true, 1000)", byPort[1].LinkUp, byPort[1].SpeedMbps)
	}
	if byPort[52].LinkUp {
		t.Errorf("ports[52].LinkUp = true, want false")
	}

	stats, err := r.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	byStatsPort := make(map[int]model.PortStats, len(stats))
	for _, s := range stats {
		byStatsPort[s.Port] = s
	}
	if byStatsPort[1].RxPackets == nil || *byStatsPort[1].RxPackets != 287280 {
		t.Errorf("stats[1].RxPackets = %v, want 287280", byStatsPort[1].RxPackets)
	}
	if byStatsPort[1].RxBytes != nil {
		t.Errorf("stats[1].RxBytes = %v, want nil (this page has no octet column)", byStatsPort[1].RxBytes)
	}

	pvids, err := r.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	pvidByPort := make(map[int]int, len(pvids))
	for _, p := range pvids {
		pvidByPort[p.Port] = p.Vlan
	}
	if pvidByPort[1] != 90 {
		t.Errorf("pvids[1] = %d, want 90", pvidByPort[1])
	}

	vlans, err := webui.ParseXEVlans(readFixture(t, "gsm7252ps_vlanStatus.html"))
	if err != nil {
		t.Fatalf("ParseXEVlans() error = %v", err)
	}
	byVID := make(map[int]model.VLANInfo, len(vlans))
	for _, v := range vlans {
		byVID[v.VlanID] = v
	}
	wantVIDs := []int{1, 4, 5, 6, 7, 10, 20, 21, 41, 89, 90, 99, 121, 141}
	for _, id := range wantVIDs {
		if _, ok := byVID[id]; !ok {
			t.Errorf("vlans missing id %d", id)
		}
	}
	if !equalInts(byVID[4].MemberPorts, []int{11, 12, 46, 49}) {
		t.Errorf("vlan4.MemberPorts = %v, want [11 12 46 49]", byVID[4].MemberPorts)
	}
	member1, err := r.ReadFastpathMembership(ctx, 1)
	if err != nil {
		t.Fatalf("ReadFastpathMembership(1) error = %v", err)
	}
	if !equalInts(member1.TaggedPorts, []int{6}) {
		t.Errorf("member1.TaggedPorts = %v, want [6]", member1.TaggedPorts)
	}
	union := make(map[int]bool)
	for _, p := range member1.TaggedPorts {
		union[p] = true
	}
	for _, p := range member1.UntaggedPorts {
		union[p] = true
	}
	for _, p := range byVID[1].MemberPorts {
		if !union[p] {
			t.Errorf("member1 tagged|untagged missing vlanStatus member port %d", p)
		}
	}

	macs, err := r.GetMACs(ctx)
	if err != nil {
		t.Fatalf("GetMACs() error = %v", err)
	}
	if len(macs) != 231 {
		t.Errorf("len(macs) = %d, want 231", len(macs))
	}
	for _, m := range macs {
		if m.Port < 1 || m.Port > 52 {
			t.Errorf("mac %s has out-of-range port %d", m.Mac, m.Port)
		}
	}

	poe, err := r.GetPoE(ctx)
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	if len(poe) != 48 {
		t.Fatalf("len(poe) = %d, want 48", len(poe))
	}
	byPoEPort := make(map[int]model.PoEStatus, len(poe))
	for _, p := range poe {
		byPoEPort[p.Port] = p
	}
	if byPoEPort[1].Detect != model.PoEDetectDelivering {
		t.Errorf("poe[1].Detect = %v, want PoEDetectDelivering", byPoEPort[1].Detect)
	}
	if byPoEPort[1].PowerMw == nil || *byPoEPort[1].PowerMw != 3500 {
		t.Errorf("poe[1].PowerMw = %v, want 3500", byPoEPort[1].PowerMw)
	}

	lldp, err := r.GetLLDP(ctx)
	if err != nil {
		t.Fatalf("GetLLDP() error = %v", err)
	}
	byLLDPPort := make(map[int]model.LLDPNeighbor, len(lldp))
	for _, n := range lldp {
		byLLDPPort[n.LocalPort] = n
	}
	if n := byLLDPPort[49]; n.RemoteSysName == nil || *n.RemoteSysName != "sw-netgear-m4300-24x" {
		t.Errorf("lldp[49].RemoteSysName = %v, want \"sw-netgear-m4300-24x\"", n.RemoteSysName)
	}

	sensors, err := r.GetSensors(ctx)
	if err != nil {
		t.Fatalf("GetSensors() error = %v", err)
	}
	wantTemps := map[string]bool{"System": true, "CPU": true, "MAC-A": true, "MAC-B": true}
	gotTemps := make(map[string]bool)
	hasFan := false
	for _, s := range sensors {
		if s.Kind == "temperature" {
			gotTemps[s.Name] = true
		}
		if s.Kind == "fan" {
			hasFan = true
		}
	}
	for name := range wantTemps {
		if !gotTemps[name] {
			t.Errorf("sensors missing temperature %q", name)
		}
	}
	if !hasFan {
		t.Error("expected at least one fan sensor")
	}

	mgmt, err := r.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
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
	if mgmt.Gateway == nil || *mgmt.Gateway != "10.1.5.1" {
		t.Errorf("Gateway = %v, want \"10.1.5.1\"", mgmt.Gateway)
	}
	if mgmt.Mode != model.IPModeDHCP {
		t.Errorf("Mode = %v, want IPModeDHCP", mgmt.Mode)
	}
}

// TestReadFastpathMembershipPostsWhenBaseGETShowsAnotherVLAN exercises
// ReadFastpathMembership's OTHER branch: the base GET shows whichever VLAN
// the firmware last selected (VLAN 1 in this capture set), so asking for a
// DIFFERENT VLAN (141) must POST the browser's own re-render form and
// re-parse the response -- the "member1"-style calls elsewhere in this file
// all happen to match the base GET directly and so never reach this branch.
func TestReadFastpathMembershipPostsWhenBaseGETShowsAnotherVLAN(t *testing.T) {
	r := mustNewReader(t, newFakeSession(gsm7252psPages(t)), "gsm7252ps")
	member141, err := r.ReadFastpathMembership(context.Background(), 141)
	if err != nil {
		t.Fatalf("ReadFastpathMembership(141) error = %v", err)
	}
	if member141.VlanID == nil || *member141.VlanID != 141 {
		t.Fatalf("member141.VlanID = %v, want 141", member141.VlanID)
	}
	if !equalInts(member141.TaggedPorts, []int{46, 47, 49}) {
		t.Errorf("member141.TaggedPorts = %v, want [46 47 49]", member141.TaggedPorts)
	}
}

// --- the reads_verified construction gate -- test_http_read.py::
// --- test_http_reader_refuses_unverified_model ---

// TestNewReaderRefusesUnverifiedModel mirrors test_http_read.py::
// test_http_reader_refuses_unverified_model: the reads_verified gate is
// exercised by temporarily flipping a real model's shipped spec to
// ReadsVerified=false (every shipped spec is true at this pin, so no model
// is unverified in production -- this proves the gate still fires when a
// spec says its reads are unverified).
func TestNewReaderRefusesUnverifiedModel(t *testing.T) {
	spec := webui.HTTPSpecs["gsm7228ps"]
	original := spec.ReadsVerified
	spec.ReadsVerified = false
	defer func() { spec.ReadsVerified = original }()

	_, err := webui.NewReader(newFakeSession(nil), mustGetModel(t, "gsm7228ps"))
	wantUnsupported(t, err, "NewReader(unverified model)")
}

// TestNewReaderConstructionFailsBeforeAnySessionUse asserts the gate fires
// with NO session interaction at all: a fakeSession backed by a nil pages
// map errors on the first GetPage/PostForm call, so a successful gate check
// with this session proves construction never touched the session.
func TestNewReaderConstructionFailsBeforeAnySessionUse(t *testing.T) {
	spec := webui.HTTPSpecs["gsm7228ps"]
	original := spec.ReadsVerified
	spec.ReadsVerified = false
	defer func() { spec.ReadsVerified = original }()

	session := newFakeSession(nil)
	if _, err := webui.NewReader(session, mustGetModel(t, "gsm7228ps")); err == nil {
		t.Fatal("NewReader(unverified) = nil error, want an error")
	}
}

// equalInts is defined in parse_m4300_test.go and shared across the
// webui_test package.

func TestExportedSupportsSensorsAndMgmtIPPath(t *testing.T) {
	spec, err := webui.HTTPSpec(mustGetModel(t, "gsm7252ps"))
	if err != nil {
		t.Fatalf("HTTPSpec: %v", err)
	}
	if !webui.SupportsSensors(spec) {
		t.Error("SupportsSensors(gsm7252ps spec) = false, want true (FASTPATH dialect with a sysInfo page)")
	}
	if webui.MgmtIPPath(spec) == "" {
		t.Error("MgmtIPPath(gsm7252ps spec) is empty, want a page path")
	}
}
