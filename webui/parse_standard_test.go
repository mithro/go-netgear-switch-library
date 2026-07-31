package webui_test

import (
	"errors"
	"os"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// readFixture reads a captured/synthetic HTTP fixture from testdata/http,
// mirroring the Python reference tests' `_FIX = Path(...) / "fixtures" /
// "http"` helper.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/http/" + name)
	if err != nil {
		t.Fatalf("readFixture(%q): %v", name, err)
	}
	return string(data)
}

// TestParseLoginRandAndHash pins webui.ParseLoginRand/ParseCSRFHash against
// the synthetic gs305ep login page (test_parse.py::
// test_parse_login_rand_and_hash).
func TestParseLoginRandAndHash(t *testing.T) {
	html := readFixture(t, "gs305ep_login.html")
	if got, ok := webui.ParseLoginRand(html); !ok || got != "9917" {
		t.Errorf("ParseLoginRand() = (%q, %v), want (\"9917\", true)", got, ok)
	}
	if got, ok := webui.ParseCSRFHash(html); !ok || got != "abc123def" {
		t.Errorf("ParseCSRFHash() = (%q, %v), want (\"abc123def\", true)", got, ok)
	}
	if _, ok := webui.ParseLoginRand("<html>no rand here</html>"); ok {
		t.Errorf("ParseLoginRand(no rand) ok = true, want false")
	}
}

// TestParsePortStatus pins webui.ParsePortStatus against the synthetic
// gs305ep_dashboard.html fixture (test_parse.py::test_parse_port_status).
func TestParsePortStatus(t *testing.T) {
	html := readFixture(t, "gs305ep_dashboard.html")
	ports, err := webui.ParsePortStatus(html)
	if err != nil {
		t.Fatalf("ParsePortStatus() error = %v", err)
	}
	by := map[int]model.PortStatus{}
	for _, p := range ports {
		by[p.Port] = p
	}
	if len(by) != 3 {
		t.Fatalf("got %d ports, want 3", len(by))
	}
	p1 := by[1]
	if !p1.LinkUp || !p1.AdminEnabled || p1.SpeedMbps == nil || *p1.SpeedMbps != 1000 {
		t.Errorf("port 1 = %+v, want link_up admin_enabled speed=1000", p1)
	}
	if p1.Name == nil || *p1.Name != "Port 1" {
		t.Errorf("port 1 name = %v, want \"Port 1\"", p1.Name)
	}
	if by[2].LinkUp {
		t.Errorf("port 2 link_up = true, want false")
	}
	if by[3].AdminEnabled {
		t.Errorf("port 3 admin_enabled = true, want false")
	}
}

// TestParsePortStats pins webui.ParsePortStats against gs305ep_portstats.html
// (test_parse.py::test_parse_port_stats).
func TestParsePortStats(t *testing.T) {
	html := readFixture(t, "gs305ep_portstats.html")
	stats, err := webui.ParsePortStats(html)
	if err != nil {
		t.Fatalf("ParsePortStats() error = %v", err)
	}
	by := map[int]model.PortStats{}
	for _, s := range stats {
		by[s.Port] = s
	}
	if got := *by[1].RxBytes; got != 1_000_000 {
		t.Errorf("port 1 RxBytes = %d, want 1000000", got)
	}
	if got := *by[1].TxBytes; got != 2_000_000 {
		t.Errorf("port 1 TxBytes = %d, want 2000000", got)
	}
	if got := *by[2].RxErrors; got != 3 {
		t.Errorf("port 2 RxErrors = %d, want 3", got)
	}
	if by[1].RxPackets != nil || by[1].TxPackets != nil || by[1].TxErrors != nil {
		t.Errorf("port 1 packet/tx-error fields should be nil, got %+v", by[1])
	}
}

// TestParsePoEStatusMapsDetect pins webui.ParsePoEStatus against
// gs305ep_poestatus.html (test_parse.py::test_parse_poe_status_maps_detect).
func TestParsePoEStatusMapsDetect(t *testing.T) {
	html := readFixture(t, "gs305ep_poestatus.html")
	poe, err := webui.ParsePoEStatus(html)
	if err != nil {
		t.Fatalf("ParsePoEStatus() error = %v", err)
	}
	by := map[int]model.PoEStatus{}
	for _, p := range poe {
		by[p.Port] = p
	}
	if by[1].Detect != model.PoEDetectDelivering {
		t.Errorf("port 1 Detect = %v, want Delivering", by[1].Detect)
	}
	if by[1].PowerMw == nil || *by[1].PowerMw != 12800 {
		t.Errorf("port 1 PowerMw = %v, want 12800", by[1].PowerMw)
	}
	if !by[1].AdminEnabled {
		t.Errorf("port 1 AdminEnabled = false, want true")
	}
	if by[2].Detect != model.PoEDetectSearching {
		t.Errorf("port 2 Detect = %v, want Searching", by[2].Detect)
	}
	if by[3].Detect != model.PoEDetectDisabled {
		t.Errorf("port 3 Detect = %v, want Disabled", by[3].Detect)
	}
	if by[3].AdminEnabled {
		t.Errorf("port 3 AdminEnabled = true, want false")
	}
	if by[4].Detect != model.PoEDetectFault {
		t.Errorf("port 4 Detect = %v, want Fault", by[4].Detect)
	}
}

// TestParseMembershipWireCodes pins webui.ParseMembership/ParseSelectedVlan
// against gs305ep_membership.html: hiddenMem "21133" -> ports 1..5:
// 2=T,1=U,1=U,3=X,3=X (test_parse.py::test_parse_membership_wire_codes).
func TestParseMembershipWireCodes(t *testing.T) {
	html := readFixture(t, "gs305ep_membership.html")
	mem, err := webui.ParseMembership(html, 5)
	if err != nil {
		t.Fatalf("ParseMembership() error = %v", err)
	}
	want := map[int]model.VlanMode{
		1: model.VlanTagged,
		2: model.VlanUntagged,
		3: model.VlanUntagged,
		4: model.VlanExcluded,
		5: model.VlanExcluded,
	}
	for port, mode := range want {
		if mem[port] != mode {
			t.Errorf("mem[%d] = %v, want %v", port, mem[port], mode)
		}
	}
	if got, ok := webui.ParseSelectedVlan(html); !ok || got != 90 {
		t.Errorf("ParseSelectedVlan() = (%d, %v), want (90, true)", got, ok)
	}
}

// TestParsePVIDsAndVlanIDs pins webui.ParsePVIDs/ParseVLANIDs against
// gs305ep_pvid.html/gs305ep_vlancfg.html (test_parse.py::
// test_parse_pvids_and_vlan_ids).
func TestParsePVIDsAndVlanIDs(t *testing.T) {
	pvids, err := webui.ParsePVIDs(readFixture(t, "gs305ep_pvid.html"))
	if err != nil {
		t.Fatalf("ParsePVIDs() error = %v", err)
	}
	want := []model.Pvid{{Port: 1, Vlan: 90}, {Port: 2, Vlan: 1}}
	if len(pvids) != len(want) {
		t.Fatalf("ParsePVIDs() = %+v, want %+v", pvids, want)
	}
	for i := range want {
		if pvids[i] != want[i] {
			t.Errorf("ParsePVIDs()[%d] = %+v, want %+v", i, pvids[i], want[i])
		}
	}
	ids, err := webui.ParseVLANIDs(readFixture(t, "gs305ep_vlancfg.html"))
	if err != nil {
		t.Fatalf("ParseVLANIDs() error = %v", err)
	}
	wantIDs := []int{1, 90}
	if len(ids) != len(wantIDs) || ids[0] != wantIDs[0] || ids[1] != wantIDs[1] {
		t.Errorf("ParseVLANIDs() = %v, want %v", ids, wantIDs)
	}
}

// --- malformed/unexpected page -> error wrapping model.ErrHTTPUnexpectedPage
// (never silent/empty), mirroring test_parse.py's matching malformed-page
// tests.

const malformedPage = "<html><body>Not Found</body></html>"

func wantErrUnexpectedPage(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want one wrapping model.ErrHTTPUnexpectedPage")
	}
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want wrapping model.ErrHTTPUnexpectedPage", err)
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want also wrapping model.ErrHTTP (specializes it)", err)
	}
}

func TestParsePortStatusRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParsePortStatus(malformedPage)
	wantErrUnexpectedPage(t, err)
}

func TestParsePortStatusRejectsShortRow(t *testing.T) {
	shortRow := `<html><table><tr class="portID"><td>1</td></tr></table></html>`
	_, err := webui.ParsePortStatus(shortRow)
	wantErrUnexpectedPage(t, err)
}

func TestParsePortStatusRejectsUnparseablePortNumber(t *testing.T) {
	html := `<html><table><tr class="portID"><td></td><td>NaN</td><td>Up</td><td>Enable</td><td>x</td></tr></table></html>`
	_, err := webui.ParsePortStatus(html)
	wantErrUnexpectedPage(t, err)
}

func TestParsePortStatsRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParsePortStats(malformedPage)
	wantErrUnexpectedPage(t, err)
}

func TestParsePortStatsRejectsShortRow(t *testing.T) {
	html := `<html><table><tr class="portID"><td>1</td></tr></table></html>`
	_, err := webui.ParsePortStats(html)
	wantErrUnexpectedPage(t, err)
}

func TestParsePortStatsRejectsUnparseablePortNumber(t *testing.T) {
	html := `<html><table><tr class="portID"><td>NaN</td><td>1</td><td>2</td><td>3</td></tr></table></html>`
	_, err := webui.ParsePortStats(html)
	wantErrUnexpectedPage(t, err)
}

// TestParsePortStatsIgnoresNegativeCounter confirms a counter cell that
// (implausibly) carries a leading "-" -- the same `-?\d+` regex Python's
// _int matches -- is treated as absent (nil) rather than wrapped into an
// unsigned model.PortStats field, since Go's model has no signed-counter
// representation to put it in.
func TestParsePortStatsIgnoresNegativeCounter(t *testing.T) {
	html := `<html><table><tr class="portID"><td>1</td><td>-5</td><td>10</td><td>0</td></tr></table></html>`
	stats, err := webui.ParsePortStats(html)
	if err != nil {
		t.Fatalf("ParsePortStats() error = %v", err)
	}
	if stats[0].RxBytes != nil {
		t.Errorf("RxBytes = %v, want nil for a negative counter cell", stats[0].RxBytes)
	}
	if stats[0].TxBytes == nil || *stats[0].TxBytes != 10 {
		t.Errorf("TxBytes = %v, want 10", stats[0].TxBytes)
	}
}

func TestParsePoEStatusRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParsePoEStatus(malformedPage)
	wantErrUnexpectedPage(t, err)
}

func TestParsePoEStatusRejectsShortRow(t *testing.T) {
	html := `<html><table><tr class="portID"><td>1</td></tr></table></html>`
	_, err := webui.ParsePoEStatus(html)
	wantErrUnexpectedPage(t, err)
}

// TestParsePoEStatusUnknownDetectText confirms an unrecognized detect-state
// cell maps to model.PoEDetectUnknown rather than erroring the whole page.
func TestParsePoEStatusUnknownDetectText(t *testing.T) {
	html := `<html><table><tr class="portID"><td>1</td><td>Bogus</td><td>0</td></tr></table></html>`
	poe, err := webui.ParsePoEStatus(html)
	if err != nil {
		t.Fatalf("ParsePoEStatus() error = %v", err)
	}
	if poe[0].Detect != model.PoEDetectUnknown {
		t.Errorf("Detect = %v, want Unknown", poe[0].Detect)
	}
	if !poe[0].AdminEnabled {
		t.Errorf("AdminEnabled = false, want true (Unknown is not Disabled)")
	}
}

func TestParsePVIDsRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParsePVIDs(malformedPage)
	wantErrUnexpectedPage(t, err)
}

// TestParsePVIDsRejectsRowsWithoutSelCells mirrors test_parse.py::
// test_parse_pvids_rejects_rows_without_sel_cells: portID rows present but
// missing sel="text"/sel="input" cells (wrong shape).
func TestParsePVIDsRejectsRowsWithoutSelCells(t *testing.T) {
	html := `<html><table>` +
		`<tr class="portID"><td>1</td><td>90</td></tr>` +
		`<tr class="portID"><td>2</td><td>1</td></tr>` +
		`</table></html>`
	_, err := webui.ParsePVIDs(html)
	wantErrUnexpectedPage(t, err)
}

func TestParseVLANIDsRejectsMalformedPage(t *testing.T) {
	_, err := webui.ParseVLANIDs(malformedPage)
	wantErrUnexpectedPage(t, err)
}

func TestParseMembershipRejectsMissingHiddenMem(t *testing.T) {
	_, err := webui.ParseMembership(malformedPage, 5)
	wantErrUnexpectedPage(t, err)
}

func TestParseMembershipRejectsUnknownWireCode(t *testing.T) {
	html := `<input name="hiddenMem" id="hiddenMem" value="99999" type="hidden">`
	_, err := webui.ParseMembership(html, 5)
	wantErrUnexpectedPage(t, err)
}

// TestParseSelectedVlanAbsent confirms ok=false (never a fabricated value)
// when the page carries no selected <option>.
func TestParseSelectedVlanAbsent(t *testing.T) {
	if got, ok := webui.ParseSelectedVlan(malformedPage); ok {
		t.Errorf("ParseSelectedVlan(malformed) = (%d, true), want ok=false", got)
	}
}

// TestParseSelectedVlanSelectedAfterValue exercises the second (fallback)
// attribute-order branch: `value=` before `selected`.
func TestParseSelectedVlanSelectedAfterValue(t *testing.T) {
	html := `<option value="41" selected>VLAN 41</option>`
	got, ok := webui.ParseSelectedVlan(html)
	if !ok || got != 41 {
		t.Errorf("ParseSelectedVlan() = (%d, %v), want (41, true)", got, ok)
	}
}

// TestParseCSRFHashAbsent confirms ok=false when no hash input is present.
func TestParseCSRFHashAbsent(t *testing.T) {
	if got, ok := webui.ParseCSRFHash(malformedPage); ok {
		t.Errorf("ParseCSRFHash(malformed) = (%q, true), want ok=false", got)
	}
}
