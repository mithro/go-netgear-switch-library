package fmtx

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// The expected strings below were captured VERBATIM (via repr()) from a
// live run of the pinned Python source's cli/format.py functions, given
// the exact inputs constructed here -- not hand-derived -- so any
// divergence in this port's column widths, dash placeholders, or word
// choices shows up as a test failure. See
// .tmp-verify/gen_expected.py (not part of this commit) for the
// generating script; the Python outputs are reproduced here as the
// source of truth for byte parity.

func TestPortsTableMatchesPython(t *testing.T) {
	ports := []model.PortStatus{
		{Port: 1, Name: model.Ptr("uplink"), AdminEnabled: true, LinkUp: true, SpeedMbps: model.Ptr(1000), Description: nil, FullDuplex: model.Ptr(true)},
		{Port: 22, Name: nil, AdminEnabled: false, LinkUp: false, SpeedMbps: nil, Description: model.Ptr("spare")},
	}
	want := "Port  Name    Link  Admin     Speed  Description\n" +
		"1     uplink  up    enabled   1000   -          \n" +
		"22    -       down  disabled  -      spare      "
	if got := PortsTable(ports); got != want {
		t.Errorf("PortsTable() =\n%q\nwant\n%q", got, want)
	}
}

func TestPoeTableMatchesPython(t *testing.T) {
	poe := []model.PoEStatus{
		{Port: 1, AdminEnabled: true, Detect: model.PoEDetectDelivering, PowerMw: model.Ptr(15400)},
		{Port: 2, AdminEnabled: false, Detect: model.PoEDetectDisabled, PowerMw: nil},
	}
	want := "Port  Admin     Detect      Power(mW)\n" +
		"1     enabled   delivering  15400    \n" +
		"2     disabled  disabled    -        "
	if got := PoeTable(poe); got != want {
		t.Errorf("PoeTable() =\n%q\nwant\n%q", got, want)
	}
}

func TestVlansTableMatchesPython(t *testing.T) {
	vlans := []model.VLANInfo{
		{VlanID: 1, Name: model.Ptr("default"), MemberPorts: []int{1, 2, 3}, TaggedPorts: []int{}, UntaggedPorts: []int{1, 2, 3}},
		{VlanID: 100, Name: nil, MemberPorts: []int{}, TaggedPorts: []int{}, UntaggedPorts: []int{}},
	}
	want := "VLAN  Name     Untagged  Tagged\n" +
		"1     default  1,2,3     -     \n" +
		"100   -        -         -     "
	if got := VlansTable(vlans); got != want {
		t.Errorf("VlansTable() =\n%q\nwant\n%q", got, want)
	}
}

func TestPvidsTableMatchesPython(t *testing.T) {
	pvids := []model.Pvid{{Port: 1, Vlan: 1}, {Port: 22, Vlan: 100}}
	want := "Port  PVID\n" +
		"1     1   \n" +
		"22    100 "
	if got := PvidsTable(pvids); got != want {
		t.Errorf("PvidsTable() =\n%q\nwant\n%q", got, want)
	}
}

func TestLldpTableMatchesPython(t *testing.T) {
	neighbors := []model.LLDPNeighbor{
		{LocalPort: 1, RemoteSysName: model.Ptr("switch2"), RemotePortDesc: model.Ptr("eth0"), RemoteChassisID: model.Ptr("AA:BB:CC:DD:EE:FF"), RemotePortID: model.Ptr("1")},
		{LocalPort: 2},
	}
	want := "Port  Neighbor  RemotePortId  RemotePortDesc  ChassisID        \n" +
		"1     switch2   1             eth0            AA:BB:CC:DD:EE:FF\n" +
		"2     -         -             -               -                "
	if got := LldpTable(neighbors); got != want {
		t.Errorf("LldpTable() =\n%q\nwant\n%q", got, want)
	}
}

func TestMacsTableMatchesPython(t *testing.T) {
	entries := []model.MacEntry{
		{Mac: "AA:BB:CC:DD:EE:FF", Port: 1, VlanID: model.Ptr(1)},
		{Mac: "11:22:33:44:55:66", Port: 2, VlanID: nil},
	}
	want := "MAC                Port  VLAN\n" +
		"AA:BB:CC:DD:EE:FF  1     1   \n" +
		"11:22:33:44:55:66  2     -   "
	if got := MacsTable(entries); got != want {
		t.Errorf("MacsTable() =\n%q\nwant\n%q", got, want)
	}
}

func TestStatsTableMatchesPython(t *testing.T) {
	stats := []model.PortStats{
		{
			Port:      1,
			RxBytes:   func() *uint64 { v := uint64(123456789); return &v }(),
			TxBytes:   func() *uint64 { v := uint64(987654321); return &v }(),
			RxPackets: func() *uint64 { v := uint64(1000); return &v }(),
			TxPackets: func() *uint64 { v := uint64(2000); return &v }(),
			RxErrors:  func() *uint64 { v := uint64(0); return &v }(),
			TxErrors:  nil,
		},
	}
	want := "Port  RxBytes    TxBytes    RxPackets  TxPackets  RxErrors  TxErrors\n" +
		"1     123456789  987654321  1000       2000       0         -       "
	if got := StatsTable(stats); got != want {
		t.Errorf("StatsTable() =\n%q\nwant\n%q", got, want)
	}
}

func TestSensorsTableMatchesPython(t *testing.T) {
	sensors := []model.Sensor{
		{Name: "Fan1", Kind: "fan", Value: 3300.0, Unit: "rpm"},
		{Name: "Temp1", Kind: "temperature", Value: 45.678912, Unit: "C"},
		{Name: "PSU1", Kind: "power", Value: 0.0, Unit: "W"},
	}
	want := "Sensor  Kind         Value    Unit\n" +
		"Fan1    fan          3300     rpm \n" +
		"Temp1   temperature  45.6789  C   \n" +
		"PSU1    power        0        W   "
	if got := SensorsTable(sensors); got != want {
		t.Errorf("SensorsTable() =\n%q\nwant\n%q", got, want)
	}
}

func TestUsersTableMatchesPython(t *testing.T) {
	users := []model.SwitchUser{
		{Name: "admin", AccessMode: "Privilege-15", Privileged: model.Ptr(true)},
		{Name: "guest", AccessMode: "Read Only", Privileged: model.Ptr(false)},
	}
	want := "user   access mode   privileged\n" +
		"admin  Privilege-15  True      \n" +
		"guest  Read Only     False     "
	if got := UsersTable(users); got != want {
		t.Errorf("UsersTable() =\n%q\nwant\n%q", got, want)
	}
}

func TestServicesTableMatchesPython(t *testing.T) {
	services := []model.ServiceStatus{
		{Name: "http", Enabled: true, Port: model.Ptr(80)},
		{Name: "ssh", Enabled: false, Port: nil},
	}
	want := "service  enabled  port\n" +
		"http     True     80  \n" +
		"ssh      False    -   "
	if got := ServicesTable(services); got != want {
		t.Errorf("ServicesTable() =\n%q\nwant\n%q", got, want)
	}
}

func TestSyslogTextNoServersMatchesPython(t *testing.T) {
	cfg := model.SyslogConfig{Enabled: false, LocalPort: 514, Servers: nil}
	want := "enabled:    False\nlocal port: 514\ncollectors: none"
	if got := SyslogText(cfg); got != want {
		t.Errorf("SyslogText() =\n%q\nwant\n%q", got, want)
	}
}

func TestSyslogTextWithServersMatchesPython(t *testing.T) {
	cfg := model.SyslogConfig{
		Enabled:   true,
		LocalPort: 514,
		Servers:   []model.SyslogServer{{Host: "10.0.0.1", Port: 514, Severity: 6, Active: true}},
	}
	want := "enabled:    True\n" +
		"local port: 514\n" +
		"collectors:\n" +
		"collector  port  severity  active\n" +
		"10.0.0.1   514   6         True  "
	if got := SyslogText(cfg); got != want {
		t.Errorf("SyslogText() =\n%q\nwant\n%q", got, want)
	}
}

func TestDetectedModelTextMatchedMatchesPython(t *testing.T) {
	d := model.DetectedModel{
		Key:         model.Ptr("gsm7252ps"),
		SysDescr:    model.Ptr("descr text"),
		SysObjectID: model.Ptr("1.3.6.1.4.1.4526.100.10.1"),
	}
	want := "key:           gsm7252ps\n" +
		"sys_descr:     descr text\n" +
		"sys_object_id: 1.3.6.1.4.1.4526.100.10.1"
	if got := DetectedModelText(d); got != want {
		t.Errorf("DetectedModelText() =\n%q\nwant\n%q", got, want)
	}
}

func TestDetectedModelTextUnmatchedMatchesPython(t *testing.T) {
	want := "key:           (unmatched)\n" +
		"sys_descr:     -\n" +
		"sys_object_id: -"
	if got := DetectedModelText(model.DetectedModel{}); got != want {
		t.Errorf("DetectedModelText(zero) =\n%q\nwant\n%q", got, want)
	}
}

func TestMgmtIPTextMatchesPython(t *testing.T) {
	cfg := model.MgmtIPConfig{
		Mode:    model.IPModeStatic,
		Address: model.Ptr("10.0.0.5"),
		Netmask: model.Ptr("255.255.255.0"),
		Gateway: model.Ptr("10.0.0.1"),
		BaseMac: model.Ptr("AA:BB:CC:DD:EE:FF"),
	}
	want := "mode:    static\n" +
		"address: 10.0.0.5\n" +
		"netmask: 255.255.255.0\n" +
		"gateway: 10.0.0.1\n" +
		"mac:     AA:BB:CC:DD:EE:FF"
	if got := MgmtIPText(cfg); got != want {
		t.Errorf("MgmtIPText() =\n%q\nwant\n%q", got, want)
	}
}

func TestHostnameTextMatchesPython(t *testing.T) {
	if got := HostnameText("sw-1"); got != "sw-1" {
		t.Errorf("HostnameText() = %q, want %q", got, "sw-1")
	}
}

func TestSnapshotTextMatchesPython(t *testing.T) {
	ports := []model.PortStatus{
		{Port: 1, Name: model.Ptr("uplink"), AdminEnabled: true, LinkUp: true, SpeedMbps: model.Ptr(1000), FullDuplex: model.Ptr(true)},
		{Port: 22, Description: model.Ptr("spare")},
	}
	poe := []model.PoEStatus{
		{Port: 1, AdminEnabled: true, Detect: model.PoEDetectDelivering, PowerMw: model.Ptr(15400)},
		{Port: 2, Detect: model.PoEDetectDisabled},
	}
	vlans := []model.VLANInfo{
		{VlanID: 1, Name: model.Ptr("default"), UntaggedPorts: []int{1, 2, 3}},
		{VlanID: 100},
	}
	pvids := []model.Pvid{{Port: 1, Vlan: 1}, {Port: 22, Vlan: 100}}
	lldp := []model.LLDPNeighbor{
		{LocalPort: 1, RemoteSysName: model.Ptr("switch2"), RemotePortDesc: model.Ptr("eth0"), RemoteChassisID: model.Ptr("AA:BB:CC:DD:EE:FF"), RemotePortID: model.Ptr("1")},
		{LocalPort: 2},
	}
	macs := []model.MacEntry{
		{Mac: "AA:BB:CC:DD:EE:FF", Port: 1, VlanID: model.Ptr(1)},
		{Mac: "11:22:33:44:55:66", Port: 2},
	}
	sensors := []model.Sensor{
		{Name: "Fan1", Kind: "fan", Value: 3300.0, Unit: "rpm"},
		{Name: "Temp1", Kind: "temperature", Value: 45.678912, Unit: "C"},
		{Name: "PSU1", Kind: "power", Value: 0.0, Unit: "W"},
	}
	mgmt := model.MgmtIPConfig{
		Mode:    model.IPModeStatic,
		Address: model.Ptr("10.0.0.5"),
		Netmask: model.Ptr("255.255.255.0"),
		Gateway: model.Ptr("10.0.0.1"),
		BaseMac: model.Ptr("AA:BB:CC:DD:EE:FF"),
	}

	data := model.SwitchData{
		Model: "gsm7252ps", Host: "10.0.0.5",
		Ports: ports, PoE: poe, Vlans: vlans, Pvids: pvids, Lldp: lldp, Macs: macs, Sensors: sensors,
		MgmtIP: &mgmt,
	}
	want := "# gsm7252ps @ 10.0.0.5\n" +
		"## Ports\n" +
		"Port  Name    Link  Admin     Speed  Description\n" +
		"1     uplink  up    enabled   1000   -          \n" +
		"22    -       down  disabled  -      spare      \n" +
		"## PoE\n" +
		"Port  Admin     Detect      Power(mW)\n" +
		"1     enabled   delivering  15400    \n" +
		"2     disabled  disabled    -        \n" +
		"## VLANs\n" +
		"VLAN  Name     Untagged  Tagged\n" +
		"1     default  1,2,3     -     \n" +
		"100   -        -         -     \n" +
		"## PVIDs\n" +
		"Port  PVID\n" +
		"1     1   \n" +
		"22    100 \n" +
		"## LLDP\n" +
		"Port  Neighbor  RemotePortId  RemotePortDesc  ChassisID        \n" +
		"1     switch2   1             eth0            AA:BB:CC:DD:EE:FF\n" +
		"2     -         -             -               -                \n" +
		"## MACs\n" +
		"MAC                Port  VLAN\n" +
		"AA:BB:CC:DD:EE:FF  1     1   \n" +
		"11:22:33:44:55:66  2     -   \n" +
		"## Sensors\n" +
		"Sensor  Kind         Value    Unit\n" +
		"Fan1    fan          3300     rpm \n" +
		"Temp1   temperature  45.6789  C   \n" +
		"PSU1    power        0        W   \n" +
		"## Mgmt IP\n" +
		"mode:    static\n" +
		"address: 10.0.0.5\n" +
		"netmask: 255.255.255.0\n" +
		"gateway: 10.0.0.1\n" +
		"mac:     AA:BB:CC:DD:EE:FF"
	if got := SnapshotText(data); got != want {
		t.Errorf("SnapshotText() =\n%q\nwant\n%q", got, want)
	}
}

func TestSnapshotTextNoMgmtIPMatchesPython(t *testing.T) {
	data := model.SwitchData{Model: "gsm7252ps", Host: "10.0.0.5"}
	want := "# gsm7252ps @ 10.0.0.5\n" +
		"## Ports\n" +
		"Port  Name  Link  Admin  Speed  Description\n" +
		"## PoE\n" +
		"Port  Admin  Detect  Power(mW)\n" +
		"## VLANs\n" +
		"VLAN  Name  Untagged  Tagged\n" +
		"## PVIDs\n" +
		"Port  PVID\n" +
		"## LLDP\n" +
		"Port  Neighbor  RemotePortId  RemotePortDesc  ChassisID\n" +
		"## MACs\n" +
		"MAC  Port  VLAN\n" +
		"## Sensors\n" +
		"Sensor  Kind  Value  Unit"
	if got := SnapshotText(data); got != want {
		t.Errorf("SnapshotText(no mgmt) =\n%q\nwant\n%q", got, want)
	}
}

func TestNsdpDeviceText(t *testing.T) {
	// No Python cli/format.py NsdpDevice fixture is available without
	// constructing the protocols.nsdp.types module (out of scope for a
	// quick cross-check), so this exercises the port directly against
	// format.py's nsdp_device_text source text instead of a captured
	// Python run: every field or() a "-", plus PortCount's `is None`
	// (not falsy) check.
	full := model.NsdpDevice{
		Model:           "GS110EMX",
		Mac:             "AA:BB:CC:DD:EE:FF",
		Hostname:        model.Ptr("switch1"),
		IP:              model.Ptr("10.0.0.5"),
		Netmask:         model.Ptr("255.255.255.0"),
		Gateway:         model.Ptr("10.0.0.1"),
		FirmwareVersion: model.Ptr("1.0.0.1"),
		SerialNumber:    model.Ptr("SN123"),
		PortCount:       model.Ptr(10),
	}
	want := "model:    GS110EMX\n" +
		"mac:      AA:BB:CC:DD:EE:FF\n" +
		"hostname: switch1\n" +
		"ip:       10.0.0.5\n" +
		"netmask:  255.255.255.0\n" +
		"gateway:  10.0.0.1\n" +
		"firmware: 1.0.0.1\n" +
		"serial:   SN123\n" +
		"ports:    10"
	if got := NsdpDeviceText(full); got != want {
		t.Errorf("NsdpDeviceText() =\n%q\nwant\n%q", got, want)
	}

	empty := model.NsdpDevice{Model: "GS110EMX", Mac: "AA:BB:CC:DD:EE:FF"}
	want2 := "model:    GS110EMX\n" +
		"mac:      AA:BB:CC:DD:EE:FF\n" +
		"hostname: -\n" +
		"ip:       -\n" +
		"netmask:  -\n" +
		"gateway:  -\n" +
		"firmware: -\n" +
		"serial:   -\n" +
		"ports:    -"
	if got := NsdpDeviceText(empty); got != want2 {
		t.Errorf("NsdpDeviceText(empty) =\n%q\nwant\n%q", got, want2)
	}

	zeroPorts := model.NsdpDevice{Model: "GS110EMX", Mac: "AA:BB:CC:DD:EE:FF", PortCount: model.Ptr(0)}
	got := NsdpDeviceText(zeroPorts)
	if got[len(got)-1] != '0' {
		t.Errorf("NsdpDeviceText(PortCount=0) = %q, want it to end in the digit 0, not a dash (is-None check, not falsy)", got)
	}
}
