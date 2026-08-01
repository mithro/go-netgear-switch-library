package fastpath

// Tests for the entity parsers added in this file's companion parse.go
// additions: parseMacTable (dossier §2.14), parseLLDP (§2.15), parsePoE
// (§2.16), parseEnvironment (§2.17), parseMgmtIP (§2.18),
// parseInterfaceCounters (§2.19).
//
// Every expected value below was NOT hand-derived: it was produced by
// running the pinned python-netgear-switch-library @
// 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362 parsers
// (src/netgear_switch/protocols/cli/parse.py) against the byte-identical
// copies of its own test fixtures in testdata/cli/ (see that directory's
// README.md for exact provenance), via a script that imports
// netgear_switch.protocols.cli.parse directly (run with `uv run python3`
// from the pin worktree) and dumps parse_mac_table/parse_lldp/parse_poe/
// parse_environment/parse_mgmt_ip/parse_interface_counters output (plus
// header_columns for the two PoE column shapes) as JSON for every fixture
// this file reads. The literal tables below are a transcription of that
// JSON output, not independent reasoning about what the fixtures "should"
// parse to. Values were cross-checked against the pin's own
// tests/protocols/cli/test_cli_parse.py assertions, which agree exactly.

import (
	"reflect"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// ---------------------------------------------------------------------
// parseMacTable (dossier §2.14)
// ---------------------------------------------------------------------

type wantMac struct {
	mac  string
	port int
	vlan int
}

func macEntries(ws []wantMac) []model.MacEntry {
	out := make([]model.MacEntry, len(ws))
	for i, w := range ws {
		v := w.vlan
		out[i] = model.MacEntry{Mac: w.mac, Port: w.port, VlanID: &v}
	}
	return out
}

func TestParseMacTable(t *testing.T) {
	t.Run("gsm7252ps 13 FDB rows, full literal compare", func(t *testing.T) {
		got := parseMacTable(readCLIFixture(t, "gsm7252ps_show_mac_addr_table.txt"))
		want := macEntries([]wantMac{
			{"02:00:0A:01:01:01", 49, 1},
			{"44:A5:6E:60:C5:B6", 49, 1},
			{"8C:3B:AD:6B:BB:E0", 49, 1},
			// A LAG entry: the IfIndex column (418), not the interface text.
			{"E0:91:F5:0C:D5:C9", 418, 1},
			{"06:0D:6D:E4:7B:E9", 11, 4},
			{"88:3D:24:B5:0E:9F", 11, 4},
			{"38:94:ED:B7:CD:E0", 47, 5},
			{"E0:91:F5:0C:D5:C7", 418, 5},
			// The CPU/Management row: "CPU Interface:  0/5/1" internal
			// spaces must not corrupt slicing -> ifIndex 417.
			{"E0:91:F5:0C:D6:DB", 417, 5},
			{"00:08:A2:09:EF:ED", 31, 90},
			{"2C:CF:67:BB:47:61", 3, 90},
			{"B8:27:EB:0A:EE:D6", 9, 90},
			{"44:A5:6E:60:C5:B6", 49, 121},
		})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parseMacTable(gsm7252ps) = %+v, want %+v", got, want)
		}
	})

	t.Run("gsm7228ps 17 FDB rows, Smart-firmware ifIndex 313 CPU row", func(t *testing.T) {
		got := parseMacTable(readCLIFixture(t, "gsm7228ps_mac_table.txt"))
		want := macEntries([]wantMac{
			{"E0:91:F5:0C:D5:C9", 51, 1},
			{"02:00:0A:01:05:01", 51, 5},
			{"08:BD:43:6B:B8:D8", 313, 5},
			{"0C:C4:7A:1B:D9:C7", 51, 5},
			{"1C:34:DA:42:E8:8C", 51, 5},
			{"1C:34:DA:42:E8:8D", 51, 5},
			{"44:A5:6E:60:C5:B6", 51, 5},
			{"8C:3B:AD:69:1C:3B", 51, 5},
			{"8C:3B:AD:6B:BB:E3", 51, 5},
			{"AC:1F:6B:AA:50:53", 51, 5},
			{"BC:A5:11:B8:EC:F1", 51, 5},
			{"BC:A5:11:B8:ED:42", 51, 5},
			{"E0:91:F5:0C:D6:DB", 51, 5},
			{"02:00:0A:01:21:01", 51, 121},
			{"44:A5:6E:60:C5:B6", 51, 121},
			{"BC:A5:11:B8:EC:F1", 51, 121},
			{"BC:A5:11:B8:ED:42", 51, 121},
		})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parseMacTable(gsm7228ps) = %+v, want %+v", got, want)
		}
	})

	t.Run("m4300-24x 645 rows, spot-checked (too large to transcribe fully)", func(t *testing.T) {
		got := parseMacTable(readCLIFixture(t, "m4300_24x_show_mac_addr_table.txt"))
		if len(got) != 645 {
			t.Fatalf("len = %d, want 645", len(got))
		}
		wantFirst := macEntries([]wantMac{{"02:00:0A:01:01:01", 1, 1}})[0]
		if !reflect.DeepEqual(got[0], wantFirst) {
			t.Errorf("got[0] = %+v, want %+v", got[0], wantFirst)
		}
		wantLast := macEntries([]wantMac{{"BC:A5:11:B8:ED:42", 1, 121}})[0]
		if !reflect.DeepEqual(got[len(got)-1], wantLast) {
			t.Errorf("got[last] = %+v, want %+v", got[len(got)-1], wantLast)
		}
	})

	t.Run("m4300-16x 481 rows (Address Entries Currently in Use header count)", func(t *testing.T) {
		got := parseMacTable(readCLIFixture(t, "m4300_16x_show_mac_addr_table.txt"))
		if len(got) != 481 {
			t.Fatalf("len = %d, want 481", len(got))
		}
		wantFirst := macEntries([]wantMac{{"00:0A:FA:24:28:1F", 16, 1}})[0]
		if !reflect.DeepEqual(got[0], wantFirst) {
			t.Errorf("got[0] = %+v, want %+v", got[0], wantFirst)
		}
		wantLast := macEntries([]wantMac{{"BC:A5:11:B8:ED:42", 9, 121}})[0]
		if !reflect.DeepEqual(got[len(got)-1], wantLast) {
			t.Errorf("got[last] = %+v, want %+v", got[len(got)-1], wantLast)
		}
	})
}

// ---------------------------------------------------------------------
// parseLLDP (dossier §2.15)
// ---------------------------------------------------------------------

type wantLLDP struct {
	port      int
	sysName   string
	chassisID string
	portID    string
}

func lldpEntries(ws []wantLLDP) []model.LLDPNeighbor {
	out := make([]model.LLDPNeighbor, len(ws))
	for i, w := range ws {
		sysName, chassisID, portID := w.sysName, w.chassisID, w.portID
		out[i] = model.LLDPNeighbor{
			LocalPort:       w.port,
			RemoteSysName:   &sysName,
			RemotePortDesc:  nil, // no port-description column on this command
			RemoteChassisID: &chassisID,
			RemotePortID:    &portID,
		}
	}
	return out
}

func TestParseLLDP(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		want    []wantLLDP
	}{
		{
			// 1/0/6 is printed with NO neighbour at all (bare interface,
			// blank trailing cells) -- must be dropped, not zero-valued.
			name:    "gsm7252ps 12 neighbours, down/no-neighbour row dropped",
			fixture: "gsm7252ps_show_lldp_remote_device_all.txt",
			want: []wantLLDP{
				{1, "rpi5-pmod", "88:A2:9E:80:87:9B", "88:A2:9E:80:87:9B"},
				{2, "rpi4-pmod", "E4:5F:01:9F:35:9C", "E4:5F:01:9F:35:9C"},
				{3, "reterm2", "2C:CF:67:BB:47:61", "2C:CF:67:BB:47:61"},
				{4, "rpi3b-gwifi", "B8:27:EB:EC:C2:C9", "B8:27:EB:EC:C2:C9"},
				{5, "rpi4-usbdev", "E4:5F:01:9C:0A:F1", "E4:5F:01:9C:0A:F1"},
				{7, "rpib-sdcard", "B8:27:EB:41:07:29", "B8:27:EB:41:07:29"},
				{9, "rpib-serial", "B8:27:EB:0A:EE:D6", "B8:27:EB:0A:EE:D6"},
				// A neighbour whose Port ID is a plain interface name, not a MAC.
				{33, "rpi4-kindle", "E4:5F:01:A1:55:31", "eth0"},
				{47, "poe-micro3", "38:94:ED:B7:CD:E0", "5"},
				{49, "sw-netgear-m43 ...", "8C:3B:AD:6B:BB:E0", "1/0/2"},
				{50, "sw-netgear-gsm ...", "E0:91:F5:0C:D5:C7", "1/0/49"},
				{51, "sw-netgear-gsm ...", "E0:91:F5:0C:D5:C7", "1/0/51"},
			},
		},
		{
			name:    "m4300-24x 10 neighbours",
			fixture: "m4300_24x_show_lldp_remote_device_all.txt",
			want: []wantLLDP{
				{1, "manage-sw-netg ...", "8C:3B:AD:69:1C:38", "1/0/14"},
				{2, "sw-netgear-gsm ...", "E0:91:F5:0C:D6:DB", "1/0/49"},
				{9, "sw-bb-25g.net. ...", "1C:34:DA:42:E8:8C", "1C:34:DA:42:E8:8D"},
				{10, "sw-bb-25g.net. ...", "1C:34:DA:42:E8:8C", "1C:34:DA:42:E8:8C"},
				{19, "big-storage", "0C:C4:7A:F4:10:E4", "0C:C4:7A:F4:10:E4"},
				{20, "big-storage", "0C:C4:7A:F4:10:E4", "0C:C4:7A:F4:10:E5"},
				{21, "sw-bb-25g.net. ...", "1C:34:DA:42:E8:8C", "1C:34:DA:30:D9:3D"},
				{22, "sw-bb-25g.net. ...", "1C:34:DA:42:E8:8C", "1C:34:DA:30:D9:3F"},
				{23, "sw-bb-25g.net. ...", "1C:34:DA:42:E8:8C", "1C:34:DA:30:D9:3E"},
				{24, "sw-bb-25g.net. ...", "1C:34:DA:42:E8:8C", "1C:34:DA:30:D9:40"},
			},
		},
		{
			// Port 16 has TWO remote devices -- both rows are kept
			// (LocalPort is not unique).
			name:    "m4300-16x 4 neighbour rows, port 16 has two devices",
			fixture: "m4300_16x_show_lldp_remote_device_all.txt",
			want: []wantLLDP{
				{12, "puck06", "62:C0:EB:01:59:14", "62:C0:EB:01:59:14"},
				{14, "sw-netgear-m43 ...", "8C:3B:AD:6B:BB:E0", "1/0/1"},
				{16, "ten64.welland. ...", "00:0A:FA:24:28:25", "00:0A:FA:24:28:1F"},
				{16, "ten64.welland. ...", "00:0A:FA:24:28:25", "02:00:0A:01:00:01"},
			},
		},
		{
			// Only the two 10G uplinks have neighbours; all 48 "1/gN"
			// access ports print with no remote device and are dropped.
			name:    "gsm7228ps only uplinks (1/xg49, 1/xg51) have neighbours",
			fixture: "gsm7228ps_lldp.txt",
			want: []wantLLDP{
				{49, "sw-netgear-gsm ...", "E0:91:F5:0C:D6:DB", "1/0/48"},
				{51, "sw-netgear-gsm ...", "E0:91:F5:0C:D5:C7", "1/0/50"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLLDP(readCLIFixture(t, tc.fixture))
			want := lldpEntries(tc.want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("parseLLDP(%s) = %+v, want %+v", tc.fixture, got, want)
			}
		})
	}
}

// ---------------------------------------------------------------------
// parsePoE (dossier §2.16) -- protocol dossier risk #1: columns MUST be
// located by header name, not fixed index, because M4300 firmware omits
// the "Temperature" column gsm7252ps prints.
// ---------------------------------------------------------------------

// TestParseHeaderColumnsPoEColumnShapes pins the underlying fact parsePoE's
// header-name lookup depends on: the gsm7252ps prints a "Temperature"
// column the m4300-16x omits entirely, with a different total column
// count (10 vs 9) -- a fixed-index parser would silently misread every
// column after the divergence point on one of the two shapes.
func TestParseHeaderColumnsPoEColumnShapes(t *testing.T) {
	gsm := headerColumns(readCLIFixture(t, "gsm7252ps_show_poe_port_info_all.txt"), "")
	wantGsm := []string{
		"Intf", "High Power", "Max Power (mW)", "Class", "Power (mW)",
		"Output Current (mA)", "Output Voltage (V)", "Temperature", "Status",
		"Fault Status",
	}
	if !reflect.DeepEqual(gsm, wantGsm) {
		t.Errorf("headerColumns(gsm7252ps poe) = %v, want %v", gsm, wantGsm)
	}

	m16 := headerColumns(readCLIFixture(t, "m4300_16x_show_poe_port_info_all.txt"), "")
	wantM16 := []string{
		"Intf", "High Power", "Max Power (mW)", "Class", "Power (mW)",
		"Output Current (mA)", "Output Voltage (V)", "Status", "Fault Status",
	}
	if !reflect.DeepEqual(m16, wantM16) {
		t.Errorf("headerColumns(m4300-16x poe) = %v, want %v", m16, wantM16)
	}
	for _, h := range m16 {
		if h == "Temperature" {
			t.Fatalf("m4300-16x header columns must NOT contain Temperature: %v", m16)
		}
	}
}

type wantPoE struct {
	port   int
	detect model.PoEDetect
	power  int
	admin  bool
}

func poeEntries(ws []wantPoE) []model.PoEStatus {
	out := make([]model.PoEStatus, len(ws))
	for i, w := range ws {
		p := w.power
		out[i] = model.PoEStatus{Port: w.port, AdminEnabled: w.admin, Detect: w.detect, PowerMw: &p}
	}
	return out
}

func TestParsePoE(t *testing.T) {
	t.Run("gsm7252ps 15 rows, Temperature column present but unused", func(t *testing.T) {
		got := parsePoE(readCLIFixture(t, "gsm7252ps_show_poe_port_info_all.txt"))
		want := poeEntries([]wantPoE{
			{1, model.PoEDetectDelivering, 3600, true},
			{2, model.PoEDetectDelivering, 3000, true},
			{3, model.PoEDetectDelivering, 3400, true},
			{4, model.PoEDetectDelivering, 8300, true},
			{5, model.PoEDetectDelivering, 6000, true},
			{6, model.PoEDetectSearching, 0, true},
			{7, model.PoEDetectDelivering, 4100, true},
			{8, model.PoEDetectDelivering, 1500, true},
			{9, model.PoEDetectDelivering, 3800, true},
			{10, model.PoEDetectSearching, 0, true},
			{11, model.PoEDetectDelivering, 4400, true},
			{45, model.PoEDetectSearching, 0, true},
			{46, model.PoEDetectDelivering, 4300, true},
			{47, model.PoEDetectDelivering, 1900, true},
			{48, model.PoEDetectSearching, 0, true},
		})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parsePoE(gsm7252ps) = %+v, want %+v", got, want)
		}
	})

	t.Run("m4300-16x 16 rows, NO Temperature column -- the header-name regression fixture", func(t *testing.T) {
		got := parsePoE(readCLIFixture(t, "m4300_16x_show_poe_port_info_all.txt"))
		want := poeEntries([]wantPoE{
			{1, model.PoEDetectSearching, 0, true},
			{2, model.PoEDetectSearching, 0, true},
			{3, model.PoEDetectSearching, 0, true},
			{4, model.PoEDetectSearching, 0, true},
			{5, model.PoEDetectSearching, 0, true},
			{6, model.PoEDetectSearching, 0, true},
			{7, model.PoEDetectSearching, 0, true},
			{8, model.PoEDetectSearching, 0, true},
			{9, model.PoEDetectSearching, 0, true},
			{10, model.PoEDetectSearching, 0, true},
			{11, model.PoEDetectSearching, 0, true},
			{12, model.PoEDetectDelivering, 4600, true},
			{13, model.PoEDetectSearching, 0, true},
			{14, model.PoEDetectSearching, 0, true},
			{15, model.PoEDetectSearching, 0, true},
			{16, model.PoEDetectSearching, 0, true},
		})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parsePoE(m4300-16x) = %+v, want %+v", got, want)
		}
	})

	t.Run("gsm7228ps 48 PoE access ports, Smart-firmware 1/gN names", func(t *testing.T) {
		got := parsePoE(readCLIFixture(t, "gsm7228ps_poe.txt"))
		if len(got) != 48 {
			t.Fatalf("len = %d, want 48", len(got))
		}
		byPort := make(map[int]model.PoEStatus, len(got))
		for _, p := range got {
			byPort[p.Port] = p
		}
		wantSome := poeEntries([]wantPoE{
			{1, model.PoEDetectSearching, 0, true},
			{44, model.PoEDetectDelivering, 400, true},
			{46, model.PoEDetectDelivering, 0, true},
			{48, model.PoEDetectDelivering, 700, true},
		})
		for _, w := range wantSome {
			got, ok := byPort[w.Port]
			if !ok {
				t.Errorf("port %d missing from parsePoE(gsm7228ps) result", w.Port)
				continue
			}
			if !reflect.DeepEqual(got, w) {
				t.Errorf("port %d = %+v, want %+v", w.Port, got, w)
			}
		}
	})
}

// ---------------------------------------------------------------------
// parseEnvironment (dossier §2.17)
// ---------------------------------------------------------------------

func sensor(name, kind string, value float64, unit string) model.Sensor {
	return model.Sensor{Name: name, Kind: kind, Value: value, Unit: unit}
}

func TestParseEnvironment(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		want    []model.Sensor
	}{
		{
			name:    "gsm7252ps: Power supplies: header, all three sub-tables",
			fixture: "gsm7252ps_show_environment.txt",
			want: []model.Sensor{
				sensor("CPU", "temperature", 49.0, "C"),
				sensor("System", "temperature", 30.0, "C"),
				sensor("MAC-A", "temperature", 33.0, "C"),
				sensor("MAC-B", "temperature", 31.0, "C"),
				// Fan-2 reports "Not Supported" -> absent, not zero.
				sensor("Fan-1", "fan", 3150.0, "RPM"),
				sensor("Fan-3", "fan", 2750.0, "RPM"),
				sensor("AC", "power", 1.0, "state"),
				sensor("PS-2", "power", 1.0, "state"),
			},
		},
		{
			name:    "m4300-24x: Power Modules: header (not Power supplies:)",
			fixture: "m4300_24x_show_environment.txt",
			want: []model.Sensor{
				sensor("MAC", "temperature", 46.0, "C"),
				sensor("Fan-1", "fan", 5280.0, "RPM"),
				sensor("Fan-2", "fan", 4560.0, "RPM"),
				sensor("Internal AC-1", "power", 1.0, "state"),
			},
		},
		{
			// Both fans report "-" (non-numeric) Speed -> absent entirely,
			// not a zero-value Sensor.
			name:    "m4300-16x: both fans non-numeric Speed -> no fan sensors",
			fixture: "m4300_16x_show_environment.txt",
			want: []model.Sensor{
				sensor("MAC", "temperature", 46.0, "C"),
				sensor("System", "temperature", 46.0, "C"),
				sensor("Internal AC-1", "power", 1.0, "state"),
			},
		},
		{
			name:    "gsm7228ps",
			fixture: "gsm7228ps_environment.txt",
			want: []model.Sensor{
				sensor("Thermal Diode 2", "temperature", 40.0, "C"),
				sensor("FAN-1", "fan", 4945.0, "RPM"),
				sensor("FAN-2", "fan", 5357.0, "RPM"),
				sensor("FAN-3", "fan", 5378.0, "RPM"),
				sensor("AC-1", "power", 1.0, "state"),
				// A non-"Operational" state degrades to 0.0, not a
				// separate "unknown" state.
				sensor("RPS4000", "power", 0.0, "state"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseEnvironment(readCLIFixture(t, tc.fixture))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseEnvironment(%s) = %+v, want %+v", tc.fixture, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------
// parseMgmtIP (dossier §2.18)
// ---------------------------------------------------------------------

func TestParseMgmtIP(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		want    model.MgmtIPConfig
	}{
		{
			name:    "gsm7252ps: Configured IPv4 Protocol label",
			fixture: "gsm7252ps_show_network.txt",
			want: model.MgmtIPConfig{
				Mode:    model.IPModeDHCP,
				Address: model.Ptr("10.1.5.22"),
				Netmask: model.Ptr("255.255.255.0"),
				Gateway: model.Ptr("10.1.5.1"),
				BaseMac: model.Ptr("E0:91:F5:0C:D6:DB"),
			},
		},
		{
			name:    "m4300-24x: Method label (show ip management dialect)",
			fixture: "m4300_24x_show_ip_management.txt",
			want: model.MgmtIPConfig{
				Mode:    model.IPModeDHCP,
				Address: model.Ptr("10.1.5.13"),
				Netmask: model.Ptr("255.255.255.0"),
				Gateway: model.Ptr("10.1.5.1"),
				BaseMac: model.Ptr("8C:3B:AD:6B:BB:E0"),
			},
		},
		{
			name:    "m4300-16x: Method label",
			fixture: "m4300_16x_show_ip_management.txt",
			want: model.MgmtIPConfig{
				Mode:    model.IPModeDHCP,
				Address: model.Ptr("10.1.5.20"),
				Netmask: model.Ptr("255.255.255.0"),
				Gateway: model.Ptr("10.1.5.1"),
				BaseMac: model.Ptr("8C:3B:AD:69:1C:38"),
			},
		},
		{
			name:    "gsm7228ps",
			fixture: "gsm7228ps_network.txt",
			want: model.MgmtIPConfig{
				Mode:    model.IPModeDHCP,
				Address: model.Ptr("10.1.5.11"),
				Netmask: model.Ptr("255.255.255.0"),
				Gateway: model.Ptr("10.1.5.1"),
				BaseMac: model.Ptr("08:BD:43:6B:B8:D8"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMgmtIP(readCLIFixture(t, tc.fixture))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseMgmtIP(%s) = %+v, want %+v", tc.fixture, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------
// parseInterfaceCounters (dossier §2.19)
// ---------------------------------------------------------------------

func u64(v uint64) *uint64 { return &v }

func TestParseInterfaceCounters(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		port    int
		want    model.PortStats
	}{
		{
			name:    "gsm7252ps: non-zero counters",
			fixture: "gsm7252ps_show_interface_ethernet_1_0_1.txt",
			port:    1,
			want: model.PortStats{
				Port:      1,
				RxBytes:   u64(7114270),
				TxBytes:   u64(139445046),
				RxPackets: u64(32835),
				TxPackets: u64(34679),
				RxErrors:  u64(0),
				TxErrors:  u64(0),
			},
		},
		{
			name:    "m4300-24x: very large (>1e12) 64-bit counter values",
			fixture: "m4300_24x_show_interface_ethernet_1_0_1.txt",
			port:    1,
			want: model.PortStats{
				Port:      1,
				RxBytes:   u64(15294247267585),
				TxBytes:   u64(11908661422462),
				RxPackets: u64(17643540356),
				TxPackets: u64(16762689317),
				RxErrors:  u64(6),
				TxErrors:  u64(0),
			},
		},
		{
			name:    "m4300-16x: every counter zero (down port)",
			fixture: "m4300_16x_show_interface_ethernet_1_0_1.txt",
			port:    1,
			want: model.PortStats{
				Port:      1,
				RxBytes:   u64(0),
				TxBytes:   u64(0),
				RxPackets: u64(0),
				TxPackets: u64(0),
				RxErrors:  u64(0),
				TxErrors:  u64(0),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseInterfaceCounters(readCLIFixture(t, tc.fixture), tc.port)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseInterfaceCounters(%s, %d) = %+v, want %+v", tc.fixture, tc.port, got, tc.want)
			}
		})
	}
}
