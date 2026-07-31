package webui_test

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// TestParseGS105PEPortStatus round-trips webui.ParseGS105PEPortStatus
// against gs105pe_status.html, a real capture from a live GS105PE
// (10.1.5.30, 2026-07-21): ports 3 (100M) and 5 (1G) up, rest down --
// IDENTICAL to what the NSDP backend reports for this same switch (mirrors
// test_http_read.py::test_gs105pe_http_ports_match_live_nsdp).
func TestParseGS105PEPortStatus(t *testing.T) {
	ports, err := webui.ParseGS105PEPortStatus(readFixture(t, "gs105pe_status.html"))
	if err != nil {
		t.Fatalf("ParseGS105PEPortStatus() error = %v", err)
	}
	type want struct {
		linkUp bool
		speed  *int
	}
	got := map[int]want{}
	for _, p := range ports {
		got[p.Port] = want{p.LinkUp, p.SpeedMbps}
		if p.Name != nil {
			t.Errorf("port %d Name = %v, want nil (no description column)", p.Port, p.Name)
		}
	}
	if len(got) != 5 {
		t.Fatalf("got %d ports, want 5", len(got))
	}
	wants := map[int]want{
		1: {false, nil},
		2: {false, nil},
		3: {true, model.Ptr(100)},
		4: {false, nil},
		5: {true, model.Ptr(1000)},
	}
	for port, w := range wants {
		g := got[port]
		if g.linkUp != w.linkUp {
			t.Errorf("port %d LinkUp = %v, want %v", port, g.linkUp, w.linkUp)
		}
		switch {
		case w.speed == nil && g.speed != nil:
			t.Errorf("port %d SpeedMbps = %v, want nil", port, *g.speed)
		case w.speed != nil && (g.speed == nil || *g.speed != *w.speed):
			t.Errorf("port %d SpeedMbps = %v, want %d", port, g.speed, *w.speed)
		}
	}
}

// TestParseGS105PEPVIDs round-trips webui.ParseGS105PEPVIDs against
// gs105pe_pvid.html, a real capture (mirrors test_http_read.py::
// test_gs105pe_http_pvids_match_live_nsdp).
func TestParseGS105PEPVIDs(t *testing.T) {
	pvids, err := webui.ParseGS105PEPVIDs(readFixture(t, "gs105pe_pvid.html"))
	if err != nil {
		t.Fatalf("ParseGS105PEPVIDs() error = %v", err)
	}
	by := map[int]int{}
	for _, p := range pvids {
		by[p.Port] = p.Vlan
	}
	want := map[int]int{1: 41, 2: 41, 3: 90, 4: 41, 5: 1}
	if len(by) != len(want) {
		t.Fatalf("got %d PVID rows, want %d", len(by), len(want))
	}
	for port, vlan := range want {
		if by[port] != vlan {
			t.Errorf("PVIDs[%d] = %d, want %d", port, by[port], vlan)
		}
	}
}

// TestParseGS105PEStatsDecodesHiddenCounterHalves round-trips
// webui.ParseGS105PEStats against gs105pe_portstats.html: the VISIBLE <td>
// cells are JS-populated and unreliable, the real counters are hidden
// (hi, lo) 32-bit pairs (mirrors test_http_read.py::
// test_gs105pe_http_stats_decode_hidden_counter_halves).
func TestParseGS105PEStatsDecodesHiddenCounterHalves(t *testing.T) {
	stats, err := webui.ParseGS105PEStats(readFixture(t, "gs105pe_portstats.html"))
	if err != nil {
		t.Fatalf("ParseGS105PEStats() error = %v", err)
	}
	by := map[int]model.PortStats{}
	for _, s := range stats {
		by[s.Port] = s
	}
	if len(by) != 5 {
		t.Fatalf("got %d ports, want 5", len(by))
	}
	cases := []struct {
		port             int
		rxBytes, txBytes uint64
	}{
		{1, 0, 0},
		{3, 0, 11625519},
		{5, 33619588, 495898},
	}
	for _, c := range cases {
		s := by[c.port]
		if s.RxBytes == nil || *s.RxBytes != c.rxBytes {
			t.Errorf("port %d RxBytes = %v, want %d", c.port, s.RxBytes, c.rxBytes)
		}
		if s.TxBytes == nil || *s.TxBytes != c.txBytes {
			t.Errorf("port %d TxBytes = %v, want %d", c.port, s.TxBytes, c.txBytes)
		}
	}
}

// TestParseGS105PEStatsCombinesHiLoAsShiftThirtyTwo pins the EXACT
// combination formula (hi*2**32+lo in the Python source, hi<<32 | lo here)
// against a synthetic row whose halves would give a visibly wrong answer
// under any other shift width (e.g. the 16-bit-halves misreading the task
// brief's own prompt momentarily entertained) -- 1<<32 alone must land at
// 4294967296, not 65536.
func TestParseGS105PEStatsCombinesHiLoAsShiftThirtyTwo(t *testing.T) {
	html := `<table><tr class="portID" name="portID">` +
		`<td sel="text">1</td>` +
		`<td sel="text"><input type="hidden" value="1"><input type="hidden" value="5"></td>` +
		`<td sel="text"><input type="hidden" value="0"><input type="hidden" value="0"></td>` +
		`<td sel="text"><input type="hidden" value="0"><input type="hidden" value="0"></td>` +
		`</tr></table>`
	stats, err := webui.ParseGS105PEStats(html)
	if err != nil {
		t.Fatalf("ParseGS105PEStats() error = %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("got %d ports, want 1", len(stats))
	}
	const want = uint64(1)<<32 | 5 // 4294967301
	if got := *stats[0].RxBytes; got != want {
		t.Errorf("RxBytes = %d, want %d (hi=1,lo=5 -> hi*2**32+lo)", got, want)
	}
}

func TestParseGS105PEPortStatusRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParseGS105PEPortStatus(malformedPage)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS105PEPortStatusRejectsShortRow(t *testing.T) {
	html := `<table><tr class="portID"><td></td><td>1</td></tr></table>`
	_, err := webui.ParseGS105PEPortStatus(html)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS105PEPortStatusRejectsUnparseablePortNumber(t *testing.T) {
	html := `<table><tr class="portID"><td></td><td>NaN</td><td>Up</td><td>Auto</td><td>100M</td></tr></table>`
	_, err := webui.ParseGS105PEPortStatus(html)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS105PEPVIDsRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParseGS105PEPVIDs(malformedPage)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS105PEPVIDsRejectsShortRow(t *testing.T) {
	html := `<table><tr class="portID"><td></td><td>1</td></tr></table>`
	_, err := webui.ParseGS105PEPVIDs(html)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS105PEPVIDsRejectsUnparseableRow(t *testing.T) {
	html := `<table><tr class="portID"><td></td><td>NaN</td><td>NaN</td></tr></table>`
	_, err := webui.ParseGS105PEPVIDs(html)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS105PEStatsRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParseGS105PEStats(malformedPage)
	wantErrUnexpectedPage(t, err)
}

// TestParseGS105PEStatsRejectsTooFewHalves exercises the ">=6 halves" guard
// with a row carrying only 2 (one pair) of the required 3 pairs.
func TestParseGS105PEStatsRejectsTooFewHalves(t *testing.T) {
	html := `<table><tr class="portID" name="portID">` +
		`<td sel="text">1</td>` +
		`<input type="hidden" value="0"><input type="hidden" value="0">` +
		`</tr></table>`
	_, err := webui.ParseGS105PEStats(html)
	wantErrUnexpectedPage(t, err)
}

// TestParseGS105PEStatsRejectsUnparseablePort exercises the "row without a
// parseable port number" branch (an empty row).
func TestParseGS105PEStatsRejectsUnparseablePort(t *testing.T) {
	html := `<table><tr class="portID" name="portID"></tr></table>`
	_, err := webui.ParseGS105PEStats(html)
	wantErrUnexpectedPage(t, err)
}

// TestParseVLANIDsAndMembershipSharedWithGS105PE confirms parse_standard.go's
// generic ParseVLANIDs/ParseMembership/ParseSelectedVlan -- not a
// GS105PE-specific parser -- correctly read the real GS105PE
// 8021qCf.cgi/8021qMembe.cgi captures, since those two pages are
// byte-identical in shape to gs305ep's (see this package's dossier note).
func TestParseVLANIDsAndMembershipSharedWithGS105PE(t *testing.T) {
	ids, err := webui.ParseVLANIDs(readFixture(t, "gs105pe_vlancfg.html"))
	if err != nil {
		t.Fatalf("ParseVLANIDs(gs105pe) error = %v", err)
	}
	want := []int{1, 41, 90}
	if len(ids) != len(want) {
		t.Fatalf("ParseVLANIDs(gs105pe) = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Errorf("ParseVLANIDs(gs105pe)[%d] = %d, want %d", i, ids[i], want[i])
		}
	}

	membHTML := readFixture(t, "gs105pe_membership.html")
	mem, err := webui.ParseMembership(membHTML, 5)
	if err != nil {
		t.Fatalf("ParseMembership(gs105pe) error = %v", err)
	}
	// hiddenMem "33331" -> ports 1..5: 3=X,3=X,3=X,3=X,1=U
	want5 := map[int]model.VlanMode{
		1: model.VlanExcluded,
		2: model.VlanExcluded,
		3: model.VlanExcluded,
		4: model.VlanExcluded,
		5: model.VlanUntagged,
	}
	for port, mode := range want5 {
		if mem[port] != mode {
			t.Errorf("mem[%d] = %v, want %v", port, mem[port], mode)
		}
	}
	if got, ok := webui.ParseSelectedVlan(membHTML); !ok || got != 1 {
		t.Errorf("ParseSelectedVlan(gs105pe) = (%d, %v), want (1, true)", got, ok)
	}

	if got, ok := webui.ParseCSRFHash(readFixture(t, "gs105pe_pvid.html")); !ok || got != "18007" {
		t.Errorf("ParseCSRFHash(gs105pe_pvid) = (%q, %v), want (\"18007\", true)", got, ok)
	}
}

// TestParseGS105PESysInfo pins webui.ParseGS105PESysInfo against the real
// captured gs105pe_switch_info.html, GROUNDED against dossier D-HTTP-P §2.5:
// this unit is live-confirmed DHCP (matching its NSDP read), and its mgmt-IP
// input names are LOWERCASE (ip_address/subnet_mask/gateway_address) --
// contrast GS110EMX's uppercase IP_ADDRESS/etc despite the identical login
// scheme.
func TestParseGS105PESysInfo(t *testing.T) {
	info, err := webui.ParseGS105PESysInfo(readFixture(t, "gs105pe_switch_info.html"))
	if err != nil {
		t.Fatalf("ParseGS105PESysInfo() error = %v", err)
	}
	want := webui.HTTPSysInfo{
		ProductName:     "GS105PE",
		SwitchName:      "poe-micro3",
		SerialNumber:    "61W19753A00A8",
		MacAddress:      "38:94:ED:B7:CD:E0",
		FirmwareVersion: "V1.6.0.4",
		IPMode:          model.IPModeDHCP,
		IPAddress:       "10.1.5.30",
		SubnetMask:      "255.255.255.0",
		GatewayAddress:  "10.1.5.1",
	}
	if info != want {
		t.Errorf("ParseGS105PESysInfo() = %+v, want %+v", info, want)
	}
}

// TestParseGS105PESysInfoRejectsMalformedPage mirrors the "missing expected
// field(s)" error shape ParseSysInfo also uses (parse_gs110emx_test.go::
// TestParseSysInfoRejectsMalformedPage).
func TestParseGS105PESysInfoRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParseGS105PESysInfo(malformedPage)
	wantErrUnexpectedPage(t, err)
}
