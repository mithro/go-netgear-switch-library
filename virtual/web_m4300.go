package virtual

// web_m4300.go ports src/netgear_switch/virtual/web_m4300.py (the
// normative source; that repo is read-only from here -- pin 1841111,
// branch go-port-pin-1841111). Any discrepancy between this file and that
// pin is a bug here, unless called out in a comment. See
// docs/superpowers/plans/2026-07-31-slice-06-dossier-http-readwrite-face.md
// §4 for the porting dossier this mirrors.
//
// M4300 "Cheetah /v1" page renderers driven by *State.
//
// Reproduces the real page encoding rather than a convenient one: every
// value is a hidden input whose NAME carries the ROW INSTANCE, followed by
// an HTML comment naming the field --
//
//	<TD id=1_2_10><INPUT xid=1_2_10 TYPE=hidden NAME=1.0.24.v_1_2_10
//	     VALUE="Link Up">Link Up</TD><!-- baseport_LinkStatus2 -->
//
// which is exactly what webui.ParseCheetahRows reads back, so the mock
// exercises the same field-name-addressed parsing path real hardware does.
// Interface names are HTML-escaped ("1&#x2F;0&#x2F;1") because the real
// firmware escapes them.

import (
	"fmt"
	"strconv"
)

const m4300EscapedSlash = "&#x2F;"

// m4300Iface renders "1/0/<port>" with the slashes HTML-escaped, as real
// firmware emits. Mirrors Python web_m4300._iface.
func m4300Iface(port int) string {
	return fmt.Sprintf("1%s0%s%d", m4300EscapedSlash, m4300EscapedSlash, port)
}

// m4300Cell mirrors Python web_m4300._cell: a Cheetah field-comment cell.
func m4300Cell(instance, xid, value, field string) string {
	return fmt.Sprintf(
		"<TD class=\"def\" id=%s><INPUT xid=%s TYPE=hidden NAME=%s.v_%s VALUE=\"%s\">%s</TD><!-- %s -->\n",
		xid, xid, instance, xid, value, value, field)
}

// m4300SpeedText mirrors Python web_m4300._speed_text (distinct from
// xeSpeedText's "N Mbps"/"NG Full " -- this dialect renders "NM Full"/
// "NG Full", no trailing space).
func m4300SpeedText(mbps int) string {
	if mbps >= 1000 && mbps%1000 == 0 {
		return fmt.Sprintf("%dG Full", mbps/1000)
	}
	return fmt.Sprintf("%dM Full", mbps)
}

func m4300Page(body string) string {
	return "<html><body><form>\n" + body + "</form></body></html>\n"
}

// m4300PhysicalPorts returns just the PHYSICAL ports, in order -- the real
// portsConfiguration/portStatistics/portPvidConfiguration pages list ONLY
// physical ports. Mirrors Python web_m4300._physical_ports.
func m4300PhysicalPorts(state *State) []int {
	portCount := state.mustModel().PortCount
	var out []int
	for _, p := range sortedIntKeys(state.Ports) {
		if p <= portCount {
			out = append(out, p)
		}
	}
	return out
}

// The M4300 ports page's per-row selection checkbox, from the LIVE pages on
// BOTH SKUs: "1.<row>.<count>.gecb_1_2" -- a third spelling, different again
// from gsm7252ps's gecb5 and gsm7228ps's gecb10.
const (
	m4300PortsCheckbox = "gecb_1_2"
	m4300PoECheckbox   = "gecb_1_2"
)

// RenderM4300Ports renders /v1/portsConfiguration.html -- per-port
// admin/link/speed. Mirrors Python web_m4300.render_ports.
func RenderM4300Ports(state *State, errMsg string) string {
	body := ""
	ports := m4300PhysicalPorts(state)
	for index, port := range ports {
		sim := state.Ports[port]
		inst := fastpathInstance(index, len(ports))
		cells := m4300Cell(inst, "1_2_1", m4300Iface(port), "baseinterfaceListing_Interfaces")
		cells += m4300Cell(inst, "1_2_6", enableDisable(sim.Admin), "baseport_AdminMode")
		cells += m4300Cell(inst, "1_2_10", linkUpDown(sim.Link), "baseport_LinkStatus2")
		physStatus := ""
		if sim.Link {
			physStatus = m4300SpeedText(sim.Speed)
		}
		cells += m4300Cell(inst, "1_2_9", physStatus, "baseport_PhysicalStatus")
		cells += m4300Cell(inst, "1_2_13", strconv.Itoa(port), "baseport_ifIndex")
		body += fastpathRow(inst, cells, m4300PortsCheckbox)
	}
	return fastpathPage("/v1/portsConfiguration.html", fastpathNavRows()+"<table>\n"+body+"</table>\n",
		[]fastpathButton{{XID: "2_1_1", Label: "Cancel"}, {XID: "2_1_2", Label: "Apply"}},
		errMsg, "NETGEAR -  Port Configuration")
}

// ApplyM4300Ports applies a /v1/portsConfiguration.html POST; returns the
// firmware err_msg. Mirrors Python web_m4300.apply_ports.
func ApplyM4300Ports(state *State, form map[string]string) string {
	return ApplyFastpathPortAdmin(state, form, m4300PortsCheckbox, m4300PhysicalPorts(state))
}

// RenderM4300PoE renders /v1/poeInterfaceConfiguration.html (M4300-16X
// only; the 24X has no PoE and its spec leaves the path unset). The cell
// grid is byte-identical to the gsm7252ps XE page, so that renderer is
// reused -- but with THREE M4300-specific differences, each live-measured:
// the power column is decimal watts, the row checkbox is gecb_1_2, and the
// reset button reads "Power Cycle Port(s)" rather than "RESET". Mirrors
// Python web_m4300.render_poe.
func RenderM4300PoE(state *State, errMsg string) string {
	return RenderXEPoEWith(state, true, errMsg, m4300Iface, m4300PoECheckbox,
		"Power Cycle Port(s)", "/v1/poeInterfaceConfiguration.html")
}

// ApplyM4300PoE mirrors Python web_m4300.apply_poe: unit_required=false --
// like the gsm7228ps and unlike the gsm7252ps, this firmware's PoE rows
// carry their own hidden v_1_2_21 "Unit" key, so the apply lands with no
// page-level unit field.
func ApplyM4300PoE(state *State, form map[string]string) string {
	return ApplyXEPoEWith(state, form, m4300PoECheckbox, false)
}

// RenderM4300PortStatistics renders /v1/portStatistics.html -- FRAME
// counters (this UI has no octets). The virtual state stores octet
// counters, so the frame columns are seeded from the packet counters when
// present and 0 otherwise. Mirrors Python web_m4300.render_port_statistics.
//
// The row instance is the LITERAL "1.<port>.24" (not a row-index/count
// pair) -- reproduced exactly as the real capture shows, even though "24"
// does not track the actual rendered row count; this page is read-only, so
// no writer depends on that number being accurate.
func RenderM4300PortStatistics(state *State) string {
	body := ""
	for _, port := range m4300PhysicalPorts(state) {
		sim := state.Ports[port]
		inst := fmt.Sprintf("1.%d.24", port)
		body += m4300Cell(inst, "1_2_1", m4300Iface(port), "baseinterfaceListing_Interfaces")
		body += m4300Cell(inst, "1_2_2", strconv.Itoa(port), "baseport_ifIndex")
		body += m4300Cell(inst, "1_3_1", strconv.FormatUint(u64OrZero(sim.RxUcast), 10), "basePortStats_TotalFramesRx")
		body += m4300Cell(inst, "1_3_2", strconv.FormatUint(u64OrZero(sim.TxUcast), 10), "basePortStats_TotalFramesTx")
		body += m4300Cell(inst, "1_3_3", strconv.FormatUint(u64OrZero(sim.RxErrors), 10), "basePortStats_TotalErrorFramesRx")
		body += m4300Cell(inst, "1_3_4", strconv.FormatUint(u64OrZero(sim.TxErrors), 10), "basePortStats_TotalErrorFramesTx")
	}
	return m4300Page(body)
}

// RenderM4300Pvids renders /v1/portPvidConfiguration.html -- per-port PVID.
// Mirrors Python web_m4300.render_pvids.
func RenderM4300Pvids(state *State) string {
	body := ""
	physical := map[int]bool{}
	for _, p := range m4300PhysicalPorts(state) {
		physical[p] = true
	}
	for _, port := range sortedIntKeys(state.Pvids) {
		if !physical[port] {
			continue
		}
		inst := fmt.Sprintf("1.%d.24", port)
		body += m4300Cell(inst, "1_2_1", m4300Iface(port), "baseinterfaceListing_Interfaces")
		body += m4300Cell(inst, "1_2_2", strconv.Itoa(port), "baseport_ifIndex")
		body += m4300Cell(inst, "1_4_1", strconv.Itoa(state.Pvids[port]), "SwitchingVlanPortConfig_Pvid")
	}
	return m4300Page(body)
}

// RenderM4300Vlans renders /v1/vlanStatus.html -- VLANs with their egress
// port list. The egress list is rendered in the real firmware's format,
// including the "lag N" entries that must NOT be expanded into physical
// ports. Mirrors Python web_m4300.render_vlans.
func RenderM4300Vlans(state *State) string {
	portCount := state.mustModel().PortCount
	body := ""
	for _, vid := range sortedIntKeys(state.Vlans) {
		vsim := state.Vlans[vid]
		inst := fmt.Sprintf("1.%d.30", vid)
		body += m4300Cell(inst, "1_5_1", strconv.Itoa(vid), "SwitchingVlanStaticConfig_VlanIndex")
		body += m4300Cell(inst, "1_5_2", vsim.Name, "SwitchingVlanStaticConfig_VlanName")
		egress := xeVlanEgressParts(vsim, portCount, m4300Iface)
		body += m4300Cell(inst, "1_5_4", egress, "SwitchingVlanCurrentConfig_VlanCurrentEgressPortList")
	}
	return m4300Page(body)
}

// RenderM4300MacTable renders /v1/basicAddressTable.html -- the learned
// MAC/FDB table. Mirrors Python web_m4300.render_mac_table.
func RenderM4300MacTable(state *State) string {
	body := ""
	for i, entry := range state.Macs {
		inst := fmt.Sprintf("1.%d.40", i+1)
		mac := formatMacUpper(entry.MacBytes)
		body += m4300Cell(inst, "1_6_1", mac, "SwitchingmacAddrGroup_MacAddress")
		body += m4300Cell(inst, "1_6_2", m4300Iface(entry.BridgePort), "SwitchingmacAddrGroup_Intf")
		body += m4300Cell(inst, "1_6_3", strconv.Itoa(entry.Vlan), "SwitchingmacAddrGroup_vlanIndex")
	}
	return m4300Page(body)
}

// RenderM4300Sysinfo renders /v1/base/system/management/sysInfo.html --
// mgmt IP, base MAC and the temperature block. Plain labelled cells (this
// page has no xid cells). Mirrors Python web_m4300.render_sysinfo.
func RenderM4300Sysinfo(state *State) string {
	mac := formatMacUpper(state.NsdpMac)
	var temps string
	// Real firmware labels the temperature row with a TEXT name ("MAC"),
	// and webui.ParseM4300Sensors' label group is [A-Za-z ] accordingly.
	for _, s := range state.Sensors {
		if s.Kind == "temperature" && isASCIIDigitsFastpath(s.Raw) {
			temps += fmt.Sprintf("<tr><td>MAC</td><td>%s &#8451;</td></tr>\n", s.Raw)
		}
	}
	return "<html><body><table>\n" +
		"<tr><td>IPv4 Management Address</td>" +
		"<td><a href='/v1/mgmtVlanIpv4Configuration.html'>" + state.Mgmt.Address +
		"/" + state.Mgmt.Netmask + "</a></td></tr>\n" +
		"<tr><td>System MAC Address</td><td>" + mac + "</td></tr>\n" +
		temps +
		"</table></body></html>\n"
}
