package webui_test

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

const gambitToken = "dhrelggkcbjfjgcfnbcfeekfbajfkejgpfkehbnfgbbaigdaggifhedafagfjehbdfljdbhk" +
	"dgcahblfgbgalehadftkkjegeaje"

// TestParseLoginRandGS110EMX pins ParseLoginRand against the real captured
// GS110EMX login page (test_parse.py::test_parse_login_rand_gs110emx),
// whose `id='rand'` uses single quotes -- exercising the mixed-quote
// tolerance ParseLoginRand shares with the gs305ep synthetic fixture.
func TestParseLoginRandGS110EMX(t *testing.T) {
	got, ok := webui.ParseLoginRand(readFixture(t, "gs110emx_login.html"))
	if !ok || got != "1172334327" {
		t.Errorf("ParseLoginRand() = (%q, %v), want (\"1172334327\", true)", got, ok)
	}
}

// TestParseGambitToken pins webui.ParseGambitToken against two real
// captures: the /redirect.html response and sysInfo.html, both of which
// carry the identical Gambit field (test_parse.py::test_parse_gambit_token).
func TestParseGambitToken(t *testing.T) {
	if got, ok := webui.ParseGambitToken(readFixture(t, "gs110emx_redirect.html")); !ok || got != gambitToken {
		t.Errorf("ParseGambitToken(redirect) = (%q, %v), want (%q, true)", got, ok, gambitToken)
	}
	if got, ok := webui.ParseGambitToken(readFixture(t, "gs110emx_sysinfo.html")); !ok || got != gambitToken {
		t.Errorf("ParseGambitToken(sysinfo) = (%q, %v), want (%q, true)", got, ok, gambitToken)
	}
}

// TestParseGambitTokenAbsentOrEmpty mirrors test_parse.py::
// test_parse_gambit_token_absent_or_empty: ok=false when the field is
// wholly absent, but ok=true with value="" when it is present-but-empty (a
// rejected login) -- both are the caller's "falsy" signal, but they are
// distinguishable shapes.
func TestParseGambitTokenAbsentOrEmpty(t *testing.T) {
	if _, ok := webui.ParseGambitToken("<html>no token here</html>"); ok {
		t.Errorf("ParseGambitToken(absent) ok = true, want false")
	}
	got, ok := webui.ParseGambitToken(`<input type="hidden" name="Gambit" value="">`)
	if !ok || got != "" {
		t.Errorf(`ParseGambitToken(empty) = (%q, %v), want ("", true)`, got, ok)
	}
}

// TestParseGS110EMXPortStatus round-trips webui.ParseGS110EMXPortStatus
// against gs110emx_port_settings.html (a real capture), checking port 1
// (down, no description) and port 8 (up, "1000M Full", description
// "rumpus") -- the exact real-hardware values grounding this dialect (see
// dossier D-HTTP-P §2.4).
func TestParseGS110EMXPortStatus(t *testing.T) {
	ports, err := webui.ParseGS110EMXPortStatus(readFixture(t, "gs110emx_port_settings.html"))
	if err != nil {
		t.Fatalf("ParseGS110EMXPortStatus() error = %v", err)
	}
	by := map[int]model.PortStatus{}
	for _, p := range ports {
		by[p.Port] = p
	}
	if len(by) != 10 {
		t.Fatalf("got %d ports, want 10 (the real GS110EMX's port count)", len(by))
	}
	p1 := by[1]
	if p1.LinkUp {
		t.Errorf("port 1 LinkUp = true, want false")
	}
	if !p1.AdminEnabled {
		t.Errorf("port 1 AdminEnabled = false, want true (Auto mode, not Disable)")
	}
	if p1.SpeedMbps != nil {
		t.Errorf("port 1 SpeedMbps = %v, want nil (link down)", p1.SpeedMbps)
	}
	if p1.Name != nil {
		t.Errorf("port 1 Name = %v, want nil (blank description)", p1.Name)
	}
	p8 := by[8]
	if !p8.LinkUp {
		t.Errorf("port 8 LinkUp = false, want true")
	}
	if p8.SpeedMbps == nil || *p8.SpeedMbps != 1000 {
		t.Errorf("port 8 SpeedMbps = %v, want 1000 (\"1000M Full\")", p8.SpeedMbps)
	}
	if p8.Name == nil || *p8.Name != "rumpus" {
		t.Errorf("port 8 Name = %v, want \"rumpus\"", p8.Name)
	}
}

// TestParseGS110EMXPVIDs round-trips webui.ParseGS110EMXPVIDs against
// gs110emx_pvid.html (a real capture): ports 1/2 both carry PVID 1.
func TestParseGS110EMXPVIDs(t *testing.T) {
	pvids, err := webui.ParseGS110EMXPVIDs(readFixture(t, "gs110emx_pvid.html"))
	if err != nil {
		t.Fatalf("ParseGS110EMXPVIDs() error = %v", err)
	}
	by := map[int]int{}
	for _, p := range pvids {
		by[p.Port] = p.Vlan
	}
	if len(by) != 10 {
		t.Fatalf("got %d PVID rows, want 10", len(by))
	}
	if by[1] != 1 || by[2] != 1 {
		t.Errorf("PVIDs[1]=%d PVIDs[2]=%d, want 1, 1", by[1], by[2])
	}
}

// TestParseGS110EMXVlanIDs pins webui.ParseGS110EMXVlanIDs against
// gs110emx_cf8021q.html (a real capture): the 12 configured VLAN IDs
// (matching test_http_read.py::test_gs110emx_http_vlans_grounded_in_real_capture).
func TestParseGS110EMXVlanIDs(t *testing.T) {
	ids, err := webui.ParseGS110EMXVlanIDs(readFixture(t, "gs110emx_cf8021q.html"))
	if err != nil {
		t.Fatalf("ParseGS110EMXVlanIDs() error = %v", err)
	}
	want := []int{1, 4, 5, 6, 7, 10, 20, 21, 41, 90, 99, 121}
	if len(ids) != len(want) {
		t.Fatalf("ParseGS110EMXVlanIDs() = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Errorf("ParseGS110EMXVlanIDs()[%d] = %d, want %d", i, ids[i], want[i])
		}
	}
}

// TestParseInterfaceStatsGS110EMX round-trips webui.ParseInterfaceStats
// against gs110emx_interface_stats.html (a real capture), the parser that
// MUST tolerate the never-closed real-hardware row shape -- ParsePortStats
// (the gs305ep CLOSED-row parser) would swallow all 10 rows into a single
// match if fed this fixture (mirrors test_parse.py::
// test_parse_interface_stats_gs110emx).
func TestParseInterfaceStatsGS110EMX(t *testing.T) {
	stats, err := webui.ParseInterfaceStats(readFixture(t, "gs110emx_interface_stats.html"))
	if err != nil {
		t.Fatalf("ParseInterfaceStats() error = %v", err)
	}
	by := map[int]model.PortStats{}
	for _, s := range stats {
		by[s.Port] = s
	}
	if len(by) != 10 {
		t.Fatalf("got %d ports, want 10", len(by))
	}
	cases := []struct {
		port             int
		rxBytes, txBytes uint64
	}{
		{1, 0, 0},
		{6, 0, 70892018242},
		{8, 59921732691, 78637274870},
		{9, 2963140428936, 1189358575871},
		{10, 1195417274187, 3027396511187},
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
	for port, s := range by {
		if s.RxErrors == nil || *s.RxErrors != 0 {
			t.Errorf("port %d RxErrors = %v, want 0", port, s.RxErrors)
		}
		if s.TxErrors != nil {
			t.Errorf("port %d TxErrors = %v, want nil", port, s.TxErrors)
		}
		if s.RxPackets != nil || s.TxPackets != nil {
			t.Errorf("port %d packet counts = %v/%v, want nil/nil", port, s.RxPackets, s.TxPackets)
		}
	}
}

func TestParseInterfaceStatsRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParseInterfaceStats(malformedPage)
	wantErrUnexpectedPage(t, err)
}

func TestParseInterfaceStatsRejectsShortRow(t *testing.T) {
	html := `<table><tr class="portID"><td>1</td></tr></table>`
	_, err := webui.ParseInterfaceStats(html)
	wantErrUnexpectedPage(t, err)
}

func TestParseInterfaceStatsRejectsUnparseablePortNumber(t *testing.T) {
	html := `<table><tr class="portID"><td>NaN</td><td>0</td><td>0</td><td>0</td></tr></table>`
	_, err := webui.ParseInterfaceStats(html)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS110EMXPVIDsRejectsShortRow(t *testing.T) {
	html := `<table><tr class="portID"><td></td><td>1</td></tr></table>`
	_, err := webui.ParseGS110EMXPVIDs(html)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS110EMXPVIDsRejectsUnparseableRow(t *testing.T) {
	html := `<table><tr class="portID"><td></td><td>NaN</td><td>NaN</td></tr></table>`
	_, err := webui.ParseGS110EMXPVIDs(html)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS110EMXPortStatusRejectsUnparseablePortNumber(t *testing.T) {
	html := `<table><tr class="portID"><td></td><td>NaN</td><td></td><td>Up</td><td>Auto</td><td>1000M</td></tr></table>`
	_, err := webui.ParseGS110EMXPortStatus(html)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS110EMXPortStatusRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParseGS110EMXPortStatus(malformedPage)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS110EMXPVIDsRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParseGS110EMXPVIDs(malformedPage)
	wantErrUnexpectedPage(t, err)
}

func TestParseGS110EMXVlanIDsRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParseGS110EMXVlanIDs(malformedPage)
	wantErrUnexpectedPage(t, err)
}

// TestParseGS110EMXPortStatusRejectsShortRow exercises the open-row splitter
// with a single truncated row (fewer than 6 <td> columns).
func TestParseGS110EMXPortStatusRejectsShortRow(t *testing.T) {
	html := `<table><tr class="portID"><td></td><td>1</td></tr></table>`
	_, err := webui.ParseGS110EMXPortStatus(html)
	wantErrUnexpectedPage(t, err)
}

// TestParseGS110EMXPortFormFields exercises the write-echo helper against a
// small synthetic two-row open-row page, confirming PORT_NO keys each row's
// hidden-field map and that a row without a parseable PORT_NO is skipped
// rather than erroring the whole page.
func TestParseGS110EMXPortFormFields(t *testing.T) {
	html := `<table>` +
		`<tr class="portID"><input type="hidden" name="PORT_NO" value="1"><input type="hidden" name="FLOW_CONTROL_MODE" value="4">` +
		`<tr class="portID"><input type="hidden" name="PORT_NO" value="2"><input type="hidden" name="FLOW_CONTROL_MODE" value="0">` +
		`</table>`
	fields, err := webui.ParseGS110EMXPortFormFields(html)
	if err != nil {
		t.Fatalf("ParseGS110EMXPortFormFields() error = %v", err)
	}
	if len(fields) != 2 {
		t.Fatalf("got %d ports, want 2", len(fields))
	}
	if fields[1]["FLOW_CONTROL_MODE"] != "4" {
		t.Errorf("fields[1][FLOW_CONTROL_MODE] = %q, want \"4\"", fields[1]["FLOW_CONTROL_MODE"])
	}
	if fields[2]["FLOW_CONTROL_MODE"] != "0" {
		t.Errorf("fields[2][FLOW_CONTROL_MODE] = %q, want \"0\"", fields[2]["FLOW_CONTROL_MODE"])
	}
}

func TestParseGS110EMXPortFormFieldsRejectsPageWithoutPortNo(t *testing.T) {
	_, err := webui.ParseGS110EMXPortFormFields(malformedPage)
	wantErrUnexpectedPage(t, err)
}

// TestSpeedTextToMbpsFractionalGig confirms the fractional-gig speed form
// (GS110EMX's NBASE-T ports negotiate "2.5G"/"5G") is read correctly via
// ParseGS110EMXPortStatus rather than backtracking past the decimal point --
// see dossier D-HTTP-P §2.1/§8.1 trap: matching only `(\d+)` would misread
// "2.5G" as "5G" -> 5000.
func TestSpeedTextToMbpsFractionalGig(t *testing.T) {
	html := `<table><tr class="portID">` +
		`<td></td><td>9</td><td></td><td>Up</td><td>Auto</td><td>2.5G Full</td></tr></table>`
	ports, err := webui.ParseGS110EMXPortStatus(html)
	if err != nil {
		t.Fatalf("ParseGS110EMXPortStatus() error = %v", err)
	}
	if len(ports) != 1 || ports[0].SpeedMbps == nil || *ports[0].SpeedMbps != 2500 {
		t.Errorf("ports = %+v, want a single port with SpeedMbps=2500", ports)
	}
}
