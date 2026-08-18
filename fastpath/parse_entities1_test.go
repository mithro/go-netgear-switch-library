package fastpath

// Tests for the entity parsers added in this file's companion parse.go
// additions: parseVersion (dossier §2.9), parsePortStatus (§2.10),
// parseVLANBrief (§2.11), parseVLANDetail (§2.12), parsePVIDs (§2.13).
//
// Every expected value below was NOT hand-derived: it was produced by
// running the pinned python-netgear-switch-library @ b26eb1f parsers
// (src/netgear_switch/protocols/cli/parse.py) against the byte-identical
// copies of its own test fixtures in testdata/cli/ (see that directory's
// README.md for exact provenance), via:
//
//	uv run --project <pin worktree> python3 <ground-truth script>
//
// dumping parse_version/parse_port_status/parse_vlan_brief/
// parse_vlan_detail/parse_pvids output as JSON for every fixture this file
// reads. The literal tables below are a transcription of that JSON output,
// not independent reasoning about what the fixtures "should" parse to.

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// readCLIFixture reads a captured FASTPATH CLI fixture from testdata/cli,
// mirroring the pinned Python reference tests' `_FIX = Path(...) /
// "fixtures" / "cli"` helper (tests/protocols/cli/test_cli_parse.py).
func readCLIFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/cli/" + name)
	if err != nil {
		t.Fatalf("readCLIFixture(%q): %v", name, err)
	}
	return string(data)
}

func strPtrOrNil(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// ---------------------------------------------------------------------
// parseVersion (dossier §2.9)
// ---------------------------------------------------------------------

func TestParseVersion(t *testing.T) {
	models := model.Models()
	cases := []struct {
		name      string
		fixture   string
		wantKey   *string
		wantDescr string
	}{
		{
			name:      "gsm7252ps",
			fixture:   "gsm7252ps_show_version.txt",
			wantKey:   model.Ptr("gsm7252ps"),
			wantDescr: "GSM7252PS 48-Port GE L2+ Managed Stackable PoE Switch with 2 10GE SFP+ ports, 10.0.0.53, <not found>",
		},
		{
			name:      "m4300-24x",
			fixture:   "m4300_24x_show_version.txt",
			wantKey:   model.Ptr("m4300-24x"),
			wantDescr: "M4300-24X ProSAFE 20-port 10GBASE-T and 4-port 10G combo, 12.0.13.8, B1.0.0.15",
		},
		{
			name:      "m4300-16x",
			fixture:   "m4300_16x_show_version.txt",
			wantKey:   model.Ptr("m4300-16x"),
			wantDescr: "M4300-16X ProSAFE 16-port 10GBASE-T with PoE/PoE+ support, 12.0.19.15, B1.0.0.18",
		},
		{
			// The S3300-52X-PoE+ sysDescr does NOT whole-word match the
			// registered "gsm7228ps"/"s3300" tokens (same shape as the
			// documented "S3300-28X" non-match case, snmp/parse.go
			// DetectModelFromSysDescr) -- ground-truthed against the pin:
			// parse_version(...).key is None for this exact fixture, even
			// though a human reading the sysDescr would recognize the
			// device. Honesty over guessing.
			name:      "gsm7228ps unmatched sysDescr (S3300-52X-PoE+ != registered token)",
			fixture:   "gsm7228ps_show_version.txt",
			wantKey:   nil,
			wantDescr: "S3300-52X-PoE+ ProSAFE 48-Port Gigabit Stackable Smart Switch with PoE+ and 4 10G uplinks",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseVersion(readCLIFixture(t, tc.fixture), models)
			gotKey, wantKey := strPtrOrNil(got.Key), strPtrOrNil(tc.wantKey)
			if gotKey != wantKey {
				t.Errorf("Key = %q, want %q", gotKey, wantKey)
			}
			if got.SysDescr == nil || *got.SysDescr != tc.wantDescr {
				t.Errorf("SysDescr = %s, want %q", strPtrOrNil(got.SysDescr), tc.wantDescr)
			}
			if got.SysObjectID != nil {
				t.Errorf("SysObjectID = %q, want nil (CLI exposes no sysObjectID)", *got.SysObjectID)
			}
		})
	}
}

// ---------------------------------------------------------------------
// parsePortStatus (dossier §2.10)
// ---------------------------------------------------------------------

// wantPort is a compact literal shape for one expected model.PortStatus
// row; has/speed together encode the *int SpeedMbps field (has=false ->
// nil, never a fabricated 0). physMode is the raw "show port all" Physical
// Mode column text for this port, transcribed directly from the fixture
// file (ground truth, not re-derived via the code under test): "auto"
// (every port across all four fixtures this suite reads that column for
// reports exactly "Auto") or "10g" (a forced "10G Full" port -- the
// LAG-member/SFP-uplink rows each fixture has). FullDuplex/FlowControl are
// NOT separate wantPort fields: every fixture's Physical Status duplex text
// is "Full" wherever present (never "Half"), so FullDuplex == link exactly;
// and every fixture's Flow Mode column reads "Disable" for every physical
// port row, so FlowControl is always non-nil false -- both computed in
// wantPorts below rather than hand-transcribed 144 times each.
type wantPort struct {
	port     int
	name     string
	admin    bool
	link     bool
	speed    int
	has      bool
	physMode string
}

func wantPorts(ws []wantPort) []model.PortStatus {
	out := make([]model.PortStatus, len(ws))
	for i, w := range ws {
		name := w.name
		var speed *int
		if w.has {
			v := w.speed
			speed = &v
		}
		var fullDuplex *bool
		if w.link {
			v := true
			fullDuplex = &v
		}
		flowControl := model.Ptr(false)
		var speedConfig *model.PortSpeed
		switch w.physMode {
		case "auto":
			v := model.AutoPortSpeed()
			speedConfig = &v
		case "10g":
			v := model.ForcedPortSpeed(10000, true)
			speedConfig = &v
		default:
			panic(fmt.Sprintf("wantPorts: port %d has unrecognized physMode %q", w.port, w.physMode))
		}
		out[i] = model.PortStatus{
			Port:         w.port,
			Name:         &name,
			AdminEnabled: w.admin,
			LinkUp:       w.link,
			SpeedMbps:    speed,
			Description:  nil,
			FullDuplex:   fullDuplex,
			FlowControl:  flowControl,
			SpeedConfig:  speedConfig,
		}
	}
	return out
}

func TestParsePortStatus(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		want    []wantPort
	}{
		{
			name:    "gsm7252ps 52 physical ports, 1/0/N names",
			fixture: "gsm7252ps_show_port_all.txt",
			want: []wantPort{
				{1, "1/0/1", true, true, 1000, true, "auto"},
				{2, "1/0/2", true, true, 1000, true, "auto"},
				{3, "1/0/3", true, true, 1000, true, "auto"},
				{4, "1/0/4", true, true, 1000, true, "auto"},
				{5, "1/0/5", true, true, 1000, true, "auto"},
				{6, "1/0/6", true, false, 0, false, "auto"},
				{7, "1/0/7", true, true, 1000, true, "auto"},
				{8, "1/0/8", true, false, 0, false, "auto"},
				{9, "1/0/9", true, true, 100, true, "auto"},
				{10, "1/0/10", true, false, 0, false, "auto"},
				{11, "1/0/11", true, true, 1000, true, "auto"},
				{12, "1/0/12", true, false, 0, false, "auto"},
				{13, "1/0/13", true, true, 1000, true, "auto"},
				{14, "1/0/14", true, true, 1000, true, "auto"},
				{15, "1/0/15", true, false, 0, false, "auto"},
				{16, "1/0/16", true, true, 1000, true, "auto"},
				{17, "1/0/17", true, true, 1000, true, "auto"},
				{18, "1/0/18", true, true, 1000, true, "auto"},
				{19, "1/0/19", true, false, 0, false, "auto"},
				{20, "1/0/20", true, true, 1000, true, "auto"},
				{21, "1/0/21", true, false, 0, false, "auto"},
				{22, "1/0/22", true, true, 1000, true, "auto"},
				{23, "1/0/23", true, false, 0, false, "auto"},
				{24, "1/0/24", true, true, 1000, true, "auto"},
				{25, "1/0/25", true, true, 1000, true, "auto"},
				{26, "1/0/26", true, true, 100, true, "auto"},
				{27, "1/0/27", true, true, 1000, true, "auto"},
				{28, "1/0/28", true, false, 0, false, "auto"},
				{29, "1/0/29", true, false, 0, false, "auto"},
				{30, "1/0/30", true, true, 1000, true, "auto"},
				{31, "1/0/31", true, true, 1000, true, "auto"},
				{32, "1/0/32", true, true, 1000, true, "auto"},
				{33, "1/0/33", true, true, 1000, true, "auto"},
				{34, "1/0/34", true, false, 0, false, "auto"},
				{35, "1/0/35", true, false, 0, false, "auto"},
				{36, "1/0/36", true, false, 0, false, "auto"},
				{37, "1/0/37", true, true, 1000, true, "auto"},
				{38, "1/0/38", true, true, 1000, true, "auto"},
				{39, "1/0/39", true, false, 0, false, "auto"},
				{40, "1/0/40", true, false, 0, false, "auto"},
				{41, "1/0/41", true, true, 100, true, "auto"},
				{42, "1/0/42", true, true, 1000, true, "auto"},
				{43, "1/0/43", true, false, 0, false, "auto"},
				{44, "1/0/44", true, false, 0, false, "auto"},
				{45, "1/0/45", true, true, 100, true, "auto"},
				{46, "1/0/46", true, true, 1000, true, "auto"},
				{47, "1/0/47", true, true, 1000, true, "auto"},
				{48, "1/0/48", true, false, 0, false, "auto"},
				// A "PC Mbr" Type value (port 50) must not shift the
				// Admin/Link/Physical Status columns.
				{49, "1/0/49", true, true, 10000, true, "10g"},
				{50, "1/0/50", true, true, 10000, true, "10g"},
				{51, "1/0/51", true, true, 10000, true, "10g"},
				{52, "1/0/52", true, false, 0, false, "10g"},
			},
		},
		{
			name:    "m4300-24x 24 physical ports, lag/vlan pseudo-ifaces dropped",
			fixture: "m4300_24x_show_port_all.txt",
			want: []wantPort{
				{1, "1/0/1", true, true, 10000, true, "auto"},
				{2, "1/0/2", true, true, 10000, true, "auto"},
				{3, "1/0/3", true, true, 1000, true, "auto"},
				{4, "1/0/4", true, false, 0, false, "auto"},
				{5, "1/0/5", true, false, 0, false, "auto"},
				{6, "1/0/6", true, false, 0, false, "auto"},
				{7, "1/0/7", true, false, 0, false, "auto"},
				{8, "1/0/8", true, false, 0, false, "auto"},
				{9, "1/0/9", true, true, 1000, true, "auto"},
				{10, "1/0/10", true, true, 1000, true, "auto"},
				{11, "1/0/11", true, false, 0, false, "auto"},
				{12, "1/0/12", true, false, 0, false, "auto"},
				{13, "1/0/13", true, false, 0, false, "auto"},
				{14, "1/0/14", true, false, 0, false, "auto"},
				{15, "1/0/15", true, false, 0, false, "auto"},
				{16, "1/0/16", true, false, 0, false, "auto"},
				{17, "1/0/17", true, false, 0, false, "auto"},
				{18, "1/0/18", true, false, 0, false, "auto"},
				{19, "1/0/19", true, true, 10000, true, "auto"},
				{20, "1/0/20", true, true, 10000, true, "auto"},
				{21, "1/0/21", true, true, 10000, true, "10g"},
				{22, "1/0/22", true, true, 10000, true, "10g"},
				{23, "1/0/23", true, true, 10000, true, "10g"},
				{24, "1/0/24", true, true, 10000, true, "10g"},
			},
		},
		{
			// This fixture's raw text has an explicit "lag 1" data row
			// (testdata/cli/m4300_16x_show_port_all.txt) -- exercises
			// physPort's pseudo-interface rejection directly (not just
			// via absence).
			name:    "m4300-16x 16 physical ports, explicit lag 1 row dropped",
			fixture: "m4300_16x_show_port_all.txt",
			want: []wantPort{
				{1, "1/0/1", true, false, 0, false, "auto"},
				{2, "1/0/2", true, false, 0, false, "auto"},
				{3, "1/0/3", true, false, 0, false, "auto"},
				{4, "1/0/4", true, false, 0, false, "auto"},
				{5, "1/0/5", true, false, 0, false, "auto"},
				{6, "1/0/6", true, false, 0, false, "auto"},
				{7, "1/0/7", true, false, 0, false, "auto"},
				{8, "1/0/8", true, false, 0, false, "auto"},
				{9, "1/0/9", true, true, 10000, true, "auto"},
				{10, "1/0/10", true, false, 0, false, "auto"},
				{11, "1/0/11", true, false, 0, false, "auto"},
				{12, "1/0/12", true, true, 1000, true, "auto"},
				{13, "1/0/13", true, false, 0, false, "auto"},
				{14, "1/0/14", true, true, 10000, true, "auto"},
				{15, "1/0/15", true, false, 0, false, "auto"},
				{16, "1/0/16", true, true, 10000, true, "auto"},
			},
		},
		{
			// Smart-firmware iface names: "1/gN" (1-48 access) and
			// "1/xgN" (49-52 10G uplinks) -- confirms parsePortStatus
			// resolves both dialects via physPort, not just "1/0/N".
			name:    "gsm7228ps 52 ports, Smart-firmware 1/gN + 1/xgN names",
			fixture: "gsm7228ps_port_all.txt",
			want: []wantPort{
				{1, "1/g1", true, false, 0, false, "auto"},
				{2, "1/g2", true, false, 0, false, "auto"},
				{3, "1/g3", true, false, 0, false, "auto"},
				{4, "1/g4", true, false, 0, false, "auto"},
				{5, "1/g5", true, false, 0, false, "auto"},
				{6, "1/g6", true, false, 0, false, "auto"},
				{7, "1/g7", true, false, 0, false, "auto"},
				{8, "1/g8", true, false, 0, false, "auto"},
				{9, "1/g9", true, false, 0, false, "auto"},
				{10, "1/g10", true, false, 0, false, "auto"},
				{11, "1/g11", true, false, 0, false, "auto"},
				{12, "1/g12", true, false, 0, false, "auto"},
				{13, "1/g13", true, false, 0, false, "auto"},
				{14, "1/g14", true, false, 0, false, "auto"},
				{15, "1/g15", true, false, 0, false, "auto"},
				{16, "1/g16", true, false, 0, false, "auto"},
				{17, "1/g17", true, false, 0, false, "auto"},
				{18, "1/g18", true, false, 0, false, "auto"},
				{19, "1/g19", true, false, 0, false, "auto"},
				{20, "1/g20", true, false, 0, false, "auto"},
				{21, "1/g21", true, false, 0, false, "auto"},
				{22, "1/g22", true, false, 0, false, "auto"},
				{23, "1/g23", true, false, 0, false, "auto"},
				{24, "1/g24", true, false, 0, false, "auto"},
				{25, "1/g25", true, false, 0, false, "auto"},
				{26, "1/g26", true, false, 0, false, "auto"},
				{27, "1/g27", true, false, 0, false, "auto"},
				{28, "1/g28", true, false, 0, false, "auto"},
				{29, "1/g29", true, false, 0, false, "auto"},
				{30, "1/g30", true, false, 0, false, "auto"},
				{31, "1/g31", true, false, 0, false, "auto"},
				{32, "1/g32", true, false, 0, false, "auto"},
				{33, "1/g33", true, false, 0, false, "auto"},
				{34, "1/g34", true, false, 0, false, "auto"},
				{35, "1/g35", true, false, 0, false, "auto"},
				{36, "1/g36", true, false, 0, false, "auto"},
				{37, "1/g37", true, false, 0, false, "auto"},
				{38, "1/g38", true, false, 0, false, "auto"},
				{39, "1/g39", true, false, 0, false, "auto"},
				{40, "1/g40", true, false, 0, false, "auto"},
				{41, "1/g41", true, false, 0, false, "auto"},
				{42, "1/g42", true, false, 0, false, "auto"},
				{43, "1/g43", true, false, 0, false, "auto"},
				{44, "1/g44", true, false, 0, false, "auto"},
				{45, "1/g45", true, false, 0, false, "auto"},
				{46, "1/g46", true, false, 0, false, "auto"},
				{47, "1/g47", true, false, 0, false, "auto"},
				{48, "1/g48", true, false, 0, false, "auto"},
				{49, "1/xg49", true, true, 1000, true, "auto"},
				{50, "1/xg50", true, false, 0, false, "auto"},
				{51, "1/xg51", true, true, 10000, true, "10g"},
				{52, "1/xg52", true, false, 0, false, "10g"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePortStatus(readCLIFixture(t, tc.fixture))
			want := wantPorts(tc.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("parsePortStatus(%s) mismatch:\n got %d ports: %+v\nwant %d ports: %+v",
					tc.fixture, len(got), got, len(want), want)
			}
		})
	}
}

// ---------------------------------------------------------------------
// parseVLANBrief (dossier §2.11)
// ---------------------------------------------------------------------

func TestParseVLANBrief(t *testing.T) {
	stdVlans := []vlanBriefRow{
		{1, "default"}, {4, "wifi"}, {5, "net"}, {6, "pwr"}, {7, "store"},
		{10, "int"}, {20, "roam"}, {21, "fpgas"}, {41, "sm"}, {89, "sdr"},
		{90, "iot"}, {99, "guest"}, {121, "t-fpgas"}, {141, "t-sm"},
	}
	cases := []struct {
		name    string
		fixture string
		want    []vlanBriefRow
	}{
		{"gsm7252ps show vlan brief", "gsm7252ps_show_vlan_brief.txt", stdVlans},
		{"m4300-24x show vlan (command renamed, same shape)", "m4300_24x_show_vlan.txt", stdVlans},
		{"m4300-16x show vlan", "m4300_16x_show_vlan.txt", stdVlans},
		{
			// gsm7228ps's Smart firmware rejects the literal "show vlan
			// brief"; CliModelSpec.vlan_brief_cmd is overridden to "show
			// vlan" for this model (dossier §1.6) -- this is the fixture
			// of THAT command's actual output.
			name:    "gsm7228ps show vlan (vlan_brief_cmd override)",
			fixture: "gsm7228ps_vlan.txt",
			want: []vlanBriefRow{
				{1, "Default"}, {5, "net"}, {21, "fpgas"}, {121, "t-fpgas"}, {4089, "Auto-Video"},
			},
		},
		{
			// The rejected command itself: no ruler at all in the
			// output ("Invalid input. Please specify an integer in the
			// range 1 to 4093."), so iterTableRows finds nothing and
			// parseVLANBrief returns nil cleanly -- not a panic/error.
			name:    "gsm7228ps show vlan brief (rejected by Smart firmware)",
			fixture: "gsm7228ps_vlan_brief.txt",
			want:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseVLANBrief(readCLIFixture(t, tc.fixture))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseVLANBrief(%s) = %+v, want %+v", tc.fixture, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------
// parseVLANDetail (dossier §2.12)
// ---------------------------------------------------------------------

func sortedInts(vs ...int) []int {
	out := append([]int(nil), vs...)
	sort.Ints(out)
	return out
}

func TestParseVLANDetail(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		vlan    *string // name parameter threaded from the "show vlan brief" pass
		want    model.VLANInfo
	}{
		{
			name:    "gsm7252ps VLAN 90, brief-pass name overrides page name",
			fixture: "gsm7252ps_show_vlan_90.txt",
			vlan:    model.Ptr("iot"),
			want: model.VLANInfo{
				VlanID: 90,
				Name:   model.Ptr("iot"),
				MemberPorts: sortedInts(
					1, 2, 3, 4, 5, 7, 9, 11, 12, 13, 14, 16, 17, 18, 20, 22, 23, 24, 25, 26,
					27, 30, 31, 32, 33, 37, 38, 41, 42, 43, 44, 46, 47, 49,
				),
				TaggedPorts: sortedInts(11, 12, 46, 47, 49),
				UntaggedPorts: sortedInts(
					1, 2, 3, 4, 5, 7, 9, 13, 14, 16, 17, 18, 20, 22, 23, 24, 25, 26, 27,
					30, 31, 32, 33, 37, 38, 41, 42, 43, 44,
				),
			},
		},
		{
			// Passing nil for the name parameter falls back to the
			// page's own "VLAN Name:" line -- this fixture's own line
			// happens to also read "iot", so this pins that the fallback
			// path itself parses correctly, not just that the override
			// wins when given.
			name:    "gsm7252ps VLAN 90, nil name falls back to page's own VLAN Name: line",
			fixture: "gsm7252ps_show_vlan_90.txt",
			vlan:    nil,
			want: model.VLANInfo{
				VlanID: 90,
				Name:   model.Ptr("iot"),
				MemberPorts: sortedInts(
					1, 2, 3, 4, 5, 7, 9, 11, 12, 13, 14, 16, 17, 18, 20, 22, 23, 24, 25, 26,
					27, 30, 31, 32, 33, 37, 38, 41, 42, 43, 44, 46, 47, 49,
				),
				TaggedPorts: sortedInts(11, 12, 46, 47, 49),
				UntaggedPorts: sortedInts(
					1, 2, 3, 4, 5, 7, 9, 13, 14, 16, 17, 18, 20, 22, 23, 24, 25, 26, 27,
					30, 31, 32, 33, 37, 38, 41, 42, 43, 44,
				),
			},
		},
		{
			name:    "m4300-24x VLAN 5",
			fixture: "m4300_24x_show_vlan_5.txt",
			vlan:    model.Ptr("net"),
			want: model.VLANInfo{
				VlanID:        5,
				Name:          model.Ptr("net"),
				MemberPorts:   sortedInts(1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14),
				TaggedPorts:   sortedInts(1, 2),
				UntaggedPorts: sortedInts(3, 4, 5, 9, 10, 11, 12, 13, 14),
			},
		},
		{
			name:    "m4300-24x VLAN 90",
			fixture: "m4300_24x_show_vlan_90.txt",
			vlan:    model.Ptr("iot"),
			want: model.VLANInfo{
				VlanID:        90,
				Name:          model.Ptr("iot"),
				MemberPorts:   sortedInts(1, 2, 5, 6),
				TaggedPorts:   sortedInts(1, 2, 5),
				UntaggedPorts: sortedInts(6),
			},
		},
		{
			// The default VLAN 1 page also has ~128 "lag N" rows
			// (testdata/cli/m4300_16x_show_vlan_1.txt) -- exercises the
			// same pseudo-interface drop as port-status, on this parser.
			name:    "m4300-16x VLAN 1 (default), lag rows dropped",
			fixture: "m4300_16x_show_vlan_1.txt",
			vlan:    model.Ptr("default"),
			want: model.VLANInfo{
				VlanID:        1,
				Name:          model.Ptr("default"),
				MemberPorts:   sortedInts(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
				TaggedPorts:   sortedInts(11, 12),
				UntaggedPorts: sortedInts(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 14, 15, 16),
			},
		},
		{
			name:    "m4300-16x VLAN 4",
			fixture: "m4300_16x_show_vlan_4.txt",
			vlan:    model.Ptr("wifi"),
			want: model.VLANInfo{
				VlanID:        4,
				Name:          model.Ptr("wifi"),
				MemberPorts:   sortedInts(9, 10, 11, 12, 13, 14, 15, 16),
				TaggedPorts:   sortedInts(9, 10, 12, 13, 14, 15, 16),
				UntaggedPorts: sortedInts(11),
			},
		},
		{
			name:    "m4300-16x VLAN 5",
			fixture: "m4300_16x_show_vlan_5.txt",
			vlan:    model.Ptr("net"),
			want: model.VLANInfo{
				VlanID:        5,
				Name:          model.Ptr("net"),
				MemberPorts:   sortedInts(9, 10, 11, 12, 13, 14, 15, 16),
				TaggedPorts:   sortedInts(9, 10, 11, 13, 14, 15, 16),
				UntaggedPorts: sortedInts(12),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseVLANDetail(readCLIFixture(t, tc.fixture), tc.vlan)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseVLANDetail(%s) = %+v, want %+v", tc.fixture, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------
// parsePVIDs (dossier §2.13)
// ---------------------------------------------------------------------

func pvids(pairs ...int) []model.Pvid {
	if len(pairs)%2 != 0 {
		panic("pvids: odd number of arguments")
	}
	out := make([]model.Pvid, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, model.Pvid{Port: pairs[i], Vlan: pairs[i+1]})
	}
	return out
}

func TestParsePVIDs(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		want    []model.Pvid
	}{
		{
			name:    "gsm7252ps 52 ports, Configured column not Current",
			fixture: "gsm7252ps_show_vlan_port_all.txt",
			want: pvids(
				1, 90, 2, 90, 3, 90, 4, 90, 5, 90, 6, 1, 7, 90, 8, 1, 9, 90, 10, 1,
				11, 4, 12, 4, 13, 90, 14, 90, 15, 1, 16, 90, 17, 90, 18, 90, 19, 1, 20, 90,
				21, 1, 22, 90, 23, 90, 24, 90, 25, 90, 26, 90, 27, 90, 28, 1, 29, 1, 30, 90,
				31, 90, 32, 90, 33, 90, 34, 1, 35, 1, 36, 1, 37, 90, 38, 90, 39, 1, 40, 1,
				41, 90, 42, 90, 43, 90, 44, 90, 45, 20, 46, 4, 47, 5, 48, 5, 49, 1, 50, 1,
				51, 1, 52, 1,
			),
		},
		{
			name:    "m4300-24x 24 ports",
			fixture: "m4300_24x_show_vlan_port_all.txt",
			want: pvids(
				1, 1, 2, 1, 3, 5, 4, 5, 5, 5, 6, 90, 7, 1, 8, 1, 9, 5, 10, 5,
				11, 5, 12, 5, 13, 5, 14, 5, 15, 10, 16, 10, 17, 10, 18, 10, 19, 10, 20, 10,
				21, 10, 22, 10, 23, 10, 24, 10,
			),
		},
		{
			name:    "m4300-16x 16 ports",
			fixture: "m4300_16x_show_vlan_port_all.txt",
			want: pvids(
				1, 1, 2, 1, 3, 1, 4, 1, 5, 1, 6, 1, 7, 1, 8, 1, 9, 1, 10, 1,
				11, 4, 12, 5, 13, 1, 14, 1, 15, 1, 16, 1,
			),
		},
		{
			name:    "gsm7228ps 52 ports, Smart-firmware 1/gN + 1/xgN names",
			fixture: "gsm7228ps_vlan_port_all.txt",
			want: pvids(
				1, 21, 2, 21, 3, 21, 4, 21, 5, 21, 6, 21, 7, 21, 8, 21, 9, 21, 10, 21,
				11, 21, 12, 21, 13, 21, 14, 21, 15, 21, 16, 21, 17, 21, 18, 21, 19, 21, 20, 21,
				21, 21, 22, 21, 23, 21, 24, 21, 25, 21, 26, 21, 27, 21, 28, 21, 29, 21, 30, 21,
				31, 21, 32, 21, 33, 21, 34, 21, 35, 21, 36, 21, 37, 21, 38, 21, 39, 21, 40, 21,
				41, 5, 42, 21, 43, 21, 44, 21, 45, 21, 46, 21, 47, 21, 48, 121, 49, 1, 50, 1,
				51, 1, 52, 1,
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePVIDs(readCLIFixture(t, tc.fixture))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parsePVIDs(%s) = %+v, want %+v", tc.fixture, got, tc.want)
			}
		})
	}
}
