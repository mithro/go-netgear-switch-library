package virtual

// web_gsm7252ps.go ports src/netgear_switch/virtual/web_gsm7252ps.py (the
// normative source; that repo is read-only from here -- pin b26eb1f,
// branch go-port-pin-b26eb1f). Any discrepancy between this file and that
// pin is a bug here, unless called out in a comment. See
// docs/superpowers/plans/2026-07-31-slice-06-dossier-http-readwrite-face.md
// §4 for the porting dossier this mirrors.
//
// GSM7252PS "XE FASTPATH" page renderers driven by *State.
//
// Reproduces the real page encoding rather than a convenient one. Every data
// cell is a hidden input whose NAME carries the ROW INSTANCE and whose
// id/xid carry the COLUMN COORDINATE, with NO field-name comment --
//
//	<TD class="def alt0" p="1.0.520" id=1_2_10><INPUT xid=1_2_10 TYPE=hidden
//	     NAME=1.0.52.v_1_2_10 VALUE="Link Up">Link Up</TD>
//
// which is exactly what webui.ParseXERows reads back, so the mock exercises
// the same column-coordinate-addressed parsing path real hardware does.
//
// sysInfo.html is NOT an XE page (see RenderXESysinfo): it uses plain
// bold-label/value cells and three status tables, which is what
// webui.ParseXELabelledValues/ParseXEMgmtIP/ParseXESensors read.
//
// See web_fastpath_xui.go's doc comment for why this is plain
// fmt.Sprintf/strings.Builder composition, not a fixture-marker template.

import (
	"fmt"
	"strconv"
	"strings"
)

func xeIface(port int) string {
	return fmt.Sprintf("1/0/%d", port)
}

func xeCell(instance, xid, value string) string {
	return fmt.Sprintf(
		"<TD class=\"def alt0\" p=\"%s0\" id=%s><INPUT xid=%s TYPE=hidden NAME=%s.v_%s VALUE=\"%s\">%s</TD>\n",
		instance, xid, xid, instance, xid, value, value)
}

// xeHeaderCol is one XE page header cell (xid, text), kept as an ordered
// slice (not a map) so header column order is deterministic -- see
// fastpathButton's doc comment for why the whole package does this.
type xeHeaderCol struct {
	XID  string
	Text string
}

func xeHeader(cols []xeHeaderCol) string {
	var b strings.Builder
	for _, c := range cols {
		fmt.Fprintf(&b, "<TD class=\"def_TH alt0\" id=%s>%s</TD>\n", c.XID, c.Text)
	}
	return b.String()
}

// xeSpeedText mirrors Python web_gsm7252ps._speed_text: the real firmware's
// Physical Status text ("1000 Mbps" / "10G Full ").
func xeSpeedText(mbps int) string {
	if mbps >= 1000 && mbps%1000 == 0 {
		return fmt.Sprintf("%dG Full ", mbps/1000)
	}
	return fmt.Sprintf("%d Mbps", mbps)
}

func xePage(body string) string {
	return "<html><body><form>\n<table>\n" + body + "</table></form></body></html>\n"
}

// xePhysicalPorts returns just the PHYSICAL ports, in order -- the real XE
// port/statistics/PVID/PoE pages list only physical ports, so rendering the
// extras (LAG/CPU/VLAN interfaces the SNMP-keyed seeds also carry) would
// make the HTTP reader report interfaces the web UI never shows. Mirrors
// Python web_gsm7252ps._physical_ports.
func xePhysicalPorts(state *State) []int {
	portCount := state.mustModel().PortCount
	var out []int
	for _, p := range sortedIntKeys(state.Ports) {
		if p <= portCount {
			out = append(out, p)
		}
	}
	return out
}

// The per-row selection checkbox names, taken from the LIVE pages (they
// differ per firmware and per page, which is why the writer scrapes them).
const (
	xePortsCheckbox = "gecb5"
	xePoECheckbox   = "gecb234"
)

// RenderXEPorts renders /portsConfiguration.html -- per-port admin/link/
// speed + ifindex, using the GSM7252PS's own iface/checkbox/path. Mirrors
// Python web_gsm7252ps.render_ports's default-argument call shape.
func RenderXEPorts(state *State, errMsg string) string {
	return RenderXEPortsWith(state, errMsg, xeIface, xePortsCheckbox, "/portsConfiguration.html")
}

// RenderXEPortsWith is the full parametrized form RenderXEPorts and the
// M4300/S3300 renderers share -- this IS the write page as well as the read
// page (set_port_enabled), so it is rendered with the real XUI scaffolding:
// two forms, <TR p=...> rows each carrying their own gecb checkbox, the
// redirection block and the CANCEL/APPLY buttons. Mirrors Python
// web_gsm7252ps.render_ports.
func RenderXEPortsWith(state *State, errMsg string, iface func(int) string, checkbox, path string) string {
	body := xeHeader([]xeHeaderCol{
		{"1_2_1", "Port"},
		{"1_2_6", "Admin <br/> Mode"},
		{"1_2_9", "Physical Status"},
		{"1_2_10", "Link Status"},
		{"1_2_13", "ifindex"},
	})
	ports := xePhysicalPorts(state)
	for index, port := range ports {
		sim := state.Ports[port]
		inst := fastpathInstance(index, len(ports))
		cells := xeCell(inst, "1_2_1", iface(port))
		cells += xeCell(inst, "1_2_6", enableDisable(sim.Admin))
		// A down port's Physical Status reads "Unknown" on real hardware.
		physStatus := "Unknown"
		if sim.Link {
			physStatus = xeSpeedText(sim.Speed)
		}
		cells += xeCell(inst, "1_2_9", physStatus)
		cells += xeCell(inst, "1_2_10", linkUpDown(sim.Link))
		cells += xeCell(inst, "1_2_13", strconv.Itoa(port))
		body += fastpathRow(inst, cells, checkbox)
	}
	return fastpathPage(path, fastpathNavRows()+"<table>\n"+body+"</table>\n",
		[]fastpathButton{{XID: "2_1_1", Label: "CANCEL"}, {XID: "2_1_2", Label: "APPLY"}},
		errMsg, "NetGear - Port Configuration")
}

func enableDisable(admin bool) string {
	if admin {
		return "Enable"
	}
	return "Disable"
}

func linkUpDown(link bool) string {
	if link {
		return "Link Up"
	}
	return "Link Down"
}

// ApplyXEPorts applies a portsConfiguration.html POST for the GSM7252PS's
// own checkbox; returns the firmware err_msg. Mirrors Python
// web_gsm7252ps.apply_ports's default-argument call shape.
func ApplyXEPorts(state *State, form map[string]string) string {
	return ApplyXEPortsWith(state, form, xePortsCheckbox)
}

// ApplyXEPortsWith is the full parametrized form the M4300/S3300 appliers
// share. Mirrors Python web_gsm7252ps.apply_ports.
func ApplyXEPortsWith(state *State, form map[string]string, checkbox string) string {
	return ApplyFastpathPortAdmin(state, form, checkbox, xePhysicalPorts(state))
}

// RenderXEPortStatistics renders /portStatistics.html -- PACKET counters
// (this page has no octets). Mirrors Python
// web_gsm7252ps.render_port_statistics.
func RenderXEPortStatistics(state *State) string {
	body := xeHeader([]xeHeaderCol{
		{"1_1_103", "Interface"},
		{"1_1_2", "Total Packets received without Errors"},
		{"1_1_3", "Packets received with Errors"},
		{"1_1_5", "Packets transmitted without Errors"},
		{"1_1_6", "Transmit Packet Errors"},
	})
	ports := xePhysicalPorts(state)
	for row, port := range ports {
		sim := state.Ports[port]
		inst := fastpathInstance(row, len(ports))
		body += xeCell(inst, "1_1_103", xeIface(port))
		body += xeCell(inst, "1_1_2", strconv.FormatUint(u64OrZero(sim.RxUcast), 10))
		body += xeCell(inst, "1_1_3", strconv.FormatUint(u64OrZero(sim.RxErrors), 10))
		body += xeCell(inst, "1_1_5", strconv.FormatUint(u64OrZero(sim.TxUcast), 10))
		body += xeCell(inst, "1_1_6", strconv.FormatUint(u64OrZero(sim.TxErrors), 10))
	}
	return xePage(body)
}

// RenderXEPvids renders /portPvidConfiguration.html -- Configured + Current
// PVID columns. Mirrors Python web_gsm7252ps.render_pvids.
func RenderXEPvids(state *State) string {
	body := xeHeader([]xeHeaderCol{
		{"1_2_1", "Interface"},
		{"1_2_4", "Configured <br/> PVID"},
		{"1_2_9", "Current <br/> PVID"},
	})
	physical := map[int]bool{}
	for _, p := range xePhysicalPorts(state) {
		physical[p] = true
	}
	var rows []int
	for _, p := range sortedIntKeys(state.Pvids) {
		if physical[p] {
			rows = append(rows, p)
		}
	}
	for row, port := range rows {
		inst := fastpathInstance(row, len(rows))
		body += xeCell(inst, "1_2_1", xeIface(port))
		body += xeCell(inst, "1_2_4", strconv.Itoa(state.Pvids[port]))
		body += xeCell(inst, "1_2_9", strconv.Itoa(state.Pvids[port]))
	}
	return xePage(body)
}

// xeVlanEgressParts renders a VLAN's egress port list in the real
// firmware's format ("1/0/N, lag K"), including the lag entries that must
// NOT be expanded into physical ports. Shared by RenderXEVlans and (via its
// own iface func) RenderS3300Vlans.
func xeVlanEgressParts(vsim *VlanSim, portCount int, iface func(int) string) string {
	var physical, lags []int
	for _, p := range sortedIntKeys(vsim.Member) {
		if p <= portCount {
			physical = append(physical, p)
		} else {
			lags = append(lags, p)
		}
	}
	parts := make([]string, 0, len(physical)+len(lags))
	for _, p := range physical {
		parts = append(parts, iface(p))
	}
	for i := range lags {
		parts = append(parts, fmt.Sprintf("lag %d", i+1))
	}
	return strings.Join(parts, ", ")
}

// RenderXEVlans renders /vlanStatus.html -- VLANs with their egress port
// list. Mirrors Python web_gsm7252ps.render_vlans.
func RenderXEVlans(state *State) string {
	portCount := state.mustModel().PortCount
	body := xeHeader([]xeHeaderCol{
		{"1_1_1", "VLAN <br/> ID"},
		{"1_1_2", "VLAN Name"},
		{"1_1_3", "VLAN Type"},
		{"1_1_4", "Member Ports"},
	})
	vids := sortedIntKeys(state.Vlans)
	for row, vid := range vids {
		vsim := state.Vlans[vid]
		inst := fastpathInstance(row, len(vids))
		body += xeCell(inst, "1_1_1", strconv.Itoa(vid))
		body += xeCell(inst, "1_1_2", vsim.Name)
		body += xeCell(inst, "1_1_3", vlanDefaultOrStatic(vid))
		body += xeCell(inst, "1_1_4", xeVlanEgressParts(vsim, portCount, xeIface))
	}
	return xePage(body)
}

func vlanDefaultOrStatic(vid int) string {
	if vid == 1 {
		return "Default"
	}
	return "Static"
}

// RenderXEMacTable renders /basicAddressTable.html -- the learned MAC/FDB
// table. The "Total MAC Addresses" scalar the real page carries is
// rendered too, with the true row count. Mirrors Python
// web_gsm7252ps.render_mac_table.
func RenderXEMacTable(state *State) string {
	body := fmt.Sprintf(
		"<TR id=1_1 class=deftestme>\n"+
			"<TD class=defleft id=1_1_1>Total MAC Addresses</TD>\n"+
			"<TD class=defright id=1_1_1><INPUT xid=1_1_1 TYPE=hidden "+
			"NAME=v_1_1_1 VALUE=\"%d\"></TD>\n</TR>\n", len(state.Macs))
	body += xeHeader([]xeHeaderCol{
		{"1_2_1", "VLAN ID"},
		{"1_2_3", "MAC Address"},
		{"1_2_4", "Port"},
		{"1_2_6", "status"},
	})
	for row, entry := range state.Macs {
		inst := fastpathInstance(row, len(state.Macs))
		mac := formatMacUpper(entry.MacBytes)
		// The page names the INTERFACE an address was learned on (the
		// ifIndex-keyed port), not the raw bridge-port index.
		port := entry.BridgePort
		if p, ok := state.BridgePorts[entry.BridgePort]; ok {
			port = p
		}
		body += xeCell(inst, "1_2_1", strconv.Itoa(entry.Vlan))
		body += xeCell(inst, "1_2_3", mac)
		body += xeCell(inst, "1_2_4", xeIface(port))
		body += xeCell(inst, "1_2_6", "Learned")
	}
	return xePage(body)
}

func formatMacUpper(raw [6]byte) string {
	parts := make([]string, 6)
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// xeDetectText mirrors Python web_gsm7252ps._DETECT_TEXT: RFC3621
// pethPsePortDetectionStatus -> the real page's Status text. Only the codes
// the virtual state actually uses are mapped; anything else renders as the
// firmware's catch-all fault text rather than a fabricated status.
func xeDetectText(detect int) string {
	switch detect {
	case 1:
		return "Disabled"
	case 2:
		return "Searching"
	case 3:
		return "Delivering power"
	default:
		return "Other Fault"
	}
}

// RenderXEPoE renders /poeInterfaceConfiguration.html for the GSM7252PS's
// own watts/iface/checkbox/reset-label/path. Mirrors Python
// web_gsm7252ps.render_poe's default-argument call shape.
func RenderXEPoE(state *State, errMsg string) string {
	return RenderXEPoEWith(state, false, errMsg, xeIface, xePoECheckbox, "RESET", "/poeInterfaceConfiguration.html")
}

// RenderXEPoEWith is the full parametrized form the M4300/S3300 renderers
// share -- per-port PoE admin/status/power. watts selects the "Output
// Power" cell format to MATCH the emulated firmware: the gsm7252ps renders
// integer milliwatts (watts=false, e.g. "3500"); the M4300-16X renders
// watts with two decimals (watts=true, e.g. "4.60"). Both decode back to
// the same milliwatts via webui's PoE power parser.
//
// Also the WRITE page (set_poe/cycle_poe/clear_poe_fault), so it carries
// the real scaffolding INCLUDING the hidden write-only "Port Reset" column
// v_1_2_20 that every row renders as "Reset" on real hardware, and the
// extra RESET button v_2_1_3 its APPLY-sibling page does not have. Mirrors
// Python web_gsm7252ps.render_poe.
func RenderXEPoEWith(state *State, watts bool, errMsg string, iface func(int) string, checkbox, resetLabel, path string) string {
	body := xeHeader([]xeHeaderCol{
		{"1_2_1", "Port"},
		{"1_2_2", "Admin <br/> Mode"},
		{"1_2_15", "Ouput <br/> Power <br/> (mW)"}, //nolint:misspell // sic -- the real firmware's own header typo, preserved verbatim (matches Python web_gsm7252ps.render_poe's literal header text)
		{"1_2_17", "Status"},
	})
	ports := sortedIntKeys(state.Poe)
	for index, port := range ports {
		sim := state.Poe[port]
		inst := fastpathInstance(index, len(ports))
		cells := xeCell(inst, "1_2_1", iface(port))
		cells += xeCell(inst, "1_2_2", enableDisable(sim.Admin))
		var cell string
		if watts {
			cell = fmt.Sprintf("%.2f", float64(sim.PowerMw)/1000)
		} else {
			cell = strconv.Itoa(sim.PowerMw)
		}
		cells += xeCell(inst, "1_2_15", cell)
		cells += xeCell(inst, "1_2_17", xeDetectText(sim.Detect))
		cells += xeCell(inst, "1_2_20", "Reset")
		body += fastpathRow(inst, cells, checkbox)
	}
	return fastpathPage(path, fastpathNavRows()+"<table>\n"+body+"</table>\n",
		[]fastpathButton{
			// LIVE: the M4300s label this button "Power Cycle Port(s)" while
			// the gsm72xx pages label it "RESET".
			{XID: "2_1_3", Label: resetLabel},
			{XID: "2_1_1", Label: "CANCEL"},
			{XID: "2_1_2", Label: "APPLY"},
		}, errMsg, "NetGear - PoE Port Configuration")
}

// xePoERWColumns is this page's read-write columns, in the order the
// firmware reports failures for them, mapped to the xeleName it prints.
// Mirrors Python web_gsm7252ps._POE_RW_COLUMNS.
var xePoERWColumns = []struct{ column, label string }{
	{"v_1_2_2", "Admin <br/> Mode"},
	{"v_1_2_20", "Port Reset"},
}

// xeNoListUnitRefusal is the refusal a real GSM7252PS answers when the POST
// omits the list unit. Mirrors Python web_gsm7252ps._no_list_unit_refusal.
func xeNoListUnitRefusal(form map[string]string, prefix string) string {
	var lines []string
	for _, c := range xePoERWColumns {
		if v, ok := form[prefix+c.column]; ok {
			lines = append(lines, fmt.Sprintf("Error! Failed to Set '%s' with '%s'", c.label, v))
		}
	}
	return strings.Join(lines, "\r\n")
}

// ApplyXEPoE applies a poeInterfaceConfiguration.html POST for the
// GSM7252PS's own checkbox with unit_required=true. Mirrors Python
// web_gsm7252ps.apply_poe's default-argument call shape.
func ApplyXEPoE(state *State, form map[string]string) string {
	return ApplyXEPoEWith(state, form, xePoECheckbox, true)
}

// ApplyXEPoEWith is the full parametrized form the M4300/S3300 appliers
// share. Two distinct operations share the page, exactly as on hardware:
// APPLY (v_2_1_2) writes the Admin Mode column, RESET (v_2_1_3) consumes
// the write-only v_1_2_20 column and re-runs detection. Only CHECKED rows
// are touched.
//
// unitRequired reproduces a MEASURED per-firmware difference, not a guess.
// The GSM7252PS PoE rows carry no hidden Unit key column, so its firmware
// takes the list scope from the page's urlListUnit field and refuses the
// whole row without it (unitRequired=true -- this model's own renderer).
// The gsm7228ps and both M4300 PoE pages DO render a per-row v_1_2_21
// "Unit" key and accept the same body with no page-level unit at all, so
// those callers pass false. Mirrors Python web_gsm7252ps.apply_poe.
func ApplyXEPoEWith(state *State, form map[string]string, checkbox string, unitRequired bool) string {
	if !fastpathIsApply(form) {
		return ""
	}
	ports := sortedIntKeys(state.Poe)
	button, _ := fastpathPressed(form, "v_2_1_3", "v_2_1_2")
	for _, prefix := range fastpathCheckedRows(form, checkbox) {
		if unitRequired && !fastpathHasListUnit(form) {
			return xeNoListUnitRefusal(form, prefix)
		}
		parts := strings.Split(prefix, ".")
		if len(parts) < 2 {
			continue
		}
		row0, err := strconv.Atoi(parts[1])
		if err != nil || row0 < 0 || row0 >= len(ports) {
			continue
		}
		sim := state.Poe[ports[row0]]
		if button == "v_2_1_3" {
			value, hasValue := form[prefix+"v_1_2_20"]
			if hasValue && value != "Reset" && value != "None" {
				return fmt.Sprintf("Error! Failed to Set 'Port Reset' with '%s'", value)
			}
			if value == "Reset" {
				// Re-arm detection: a faulted port leaves FAULT, an idle
				// one stays Searching, a powered one comes back up.
				if sim.PowerMw != 0 {
					sim.Detect = 3
				} else {
					sim.Detect = 2
				}
			}
			continue
		}
		admin, ok := form[prefix+"v_1_2_2"]
		if !ok {
			continue
		}
		if admin != "Enable" && admin != "Disable" {
			return fmt.Sprintf("Error! Failed to Set 'Admin <br/> Mode' with '%s'", admin)
		}
		sim.Admin = admin == "Enable"
		if !sim.Admin {
			sim.Detect = 1
		} else if sim.Detect == 1 {
			sim.Detect = 2
		}
	}
	return ""
}

// RenderXELLDP renders /lldpRemoteInventory.html -- LLDP neighbours. This
// page has NO remote-port-DESCRIPTION column, so LldpSim.PortDesc is
// deliberately not rendered. Mirrors Python web_gsm7252ps.render_lldp.
func RenderXELLDP(state *State) string {
	body := xeHeader([]xeHeaderCol{
		{"1_1_1", "Port"},
		{"1_1_7", "MAC Address"},
		{"1_1_8", "System Name"},
		{"1_1_9", "Remote Port ID"},
	})
	for row, nb := range state.Lldp {
		inst := fastpathInstance(row, len(state.Lldp))
		chassis := formatChassisHex(nb.Chassis)
		body += xeCell(inst, "1_1_1", xeIface(nb.LocalPort))
		body += xeCell(inst, "1_1_7", chassis)
		body += xeCell(inst, "1_1_8", nb.SysName)
		body += xeCell(inst, "1_1_9", nb.PortID)
	}
	return xePage(body)
}

func formatChassisHex(chassis string) string {
	parts := make([]string, 0, len(chassis))
	for _, c := range []byte(chassis) {
		parts = append(parts, fmt.Sprintf("%02X", c))
	}
	return strings.Join(parts, ":")
}

func xeStatusTable(title string, rows []xeStatusRow) string {
	header := "" +
		"<td class=\"messageTableHeaderBorder messageTableHeaderVerticalBorder\">Unit ID</td>\n" +
		"<td class=\"messageTableHeaderBorder messageTableHeaderVerticalBorder\">1</td>\n"
	var body strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&body, "<tr>\n<td class=\"messageTableWhiteBorder font10Bold\">%s</td>\n"+
			"<td class=\"messageTableWhiteBorder font10\">%s</td>\n</tr>\n", r.Label, r.Value)
	}
	return fmt.Sprintf(
		"<tr><td colspan=\"3\"><script>tbhdr('%s','x')</script></td></tr>\n"+
			"<tr class=\"white10Bold\">\n%s</tr>\n%s", title, header, body.String())
}

type xeStatusRow struct{ Label, Value string }

// RenderXESysinfo renders /base/system/management/sysInfo.html -- mgmt IP,
// base MAC and the three status tables. Renders the model's HTTP sysInfo
// sensor set (state.SysinfoSensors()), which on this device is DIFFERENT
// from its SNMP set. Mirrors Python web_gsm7252ps.render_sysinfo.
func RenderXESysinfo(state *State) string {
	mac := formatMacUpper(state.NsdpMac)
	sensors := state.SysinfoSensors()
	var temps, fans, device []xeStatusRow
	for _, s := range sensors {
		switch s.Kind {
		case "temperature":
			value := "N/A"
			if isASCIIDigitsFastpath(s.Raw) {
				value = s.Raw + "&degC"
			}
			temps = append(temps, xeStatusRow{s.Instance, value})
		case "fan":
			fans = append(fans, xeStatusRow{s.Instance, s.Raw})
		}
	}
	device = append(device, xeStatusRow{"Firmware Version", state.Firmware}, xeStatusRow{"Serial Number", state.Serial})
	for _, s := range sensors {
		if s.Kind == "power" {
			device = append(device, xeStatusRow{s.Instance, s.Raw})
		}
	}
	return "<html><body><form>\n<table>\n" +
		"<tr><td class=\"font10Bold\">Product Name</td>" +
		"<td class=\"font10\">" + state.ModelName + "</td></tr>\n" +
		"<tr><td class=\"font10Bold\">System Name</td>" +
		"<td><INPUT class=\"input\" type=\"TEXT\" name=\"sysName\" " +
		"VALUE=\"" + state.Hostname + "\"></td></tr>\n" +
		"<tr><td class=\"font10Bold\">IPv4 Network Interface</td>" +
		"<td class=\"font10\"><a href=\"/ipConfiguration.html\">" +
		state.Mgmt.Address + "/" + state.Mgmt.Netmask + "</a></td></tr>\n" +
		"<tr><td class=\"font10Bold\">System MAC Address</td>" +
		"<td class=\"font10\">" + mac + "</td></tr>\n" +
		xeStatusTable("FAN Status", fans) +
		xeStatusTable("Temperature Status", temps) +
		xeStatusTable("Device Status", device) +
		"</table></form></body></html>\n"
}
