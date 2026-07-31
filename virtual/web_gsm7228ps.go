package virtual

// web_gsm7228ps.go ports src/netgear_switch/virtual/web_gsm7228ps.py (the
// normative source; that repo is read-only from here -- pin 1841111,
// branch go-port-pin-1841111). Any discrepancy between this file and that
// pin is a bug here, unless called out in a comment. See
// docs/superpowers/plans/2026-07-31-slice-06-dossier-http-readwrite-face.md
// §4 for the porting dossier this mirrors.
//
// S3300-52X-PoE+ (gsm7228ps) "XE FASTPATH" page renderers from state.
//
// The S3300 Smart-Managed-Pro web UI shares the sibling gsm7252ps Cheetah XE
// cell grid for ports/stats/PVIDs/VLANs/PoE/LLDP, so those pages are
// rendered by the exact gsm7252ps renderers (RenderXEPortStatistics,
// RenderXEPvids, RenderXELLDP -- called directly by httpface.go, no wrapper
// needed here) -- the reader keys off the ifindex/port columns, which are
// identical. Only three pages differ and are rendered here, matching the
// real captures in webui/testdata/http/gsm7228ps_*.html and the
// S3300-specific parsers:
//
//   - basicAddressTable.html -- the MAC/FDB columns are SHIFTED (VLAN in
//     v_1_2_2, not v_1_2_1) and the port ifName is HTML-entity-escaped in
//     the Smart firmware's "1/gN"/"1/xgN" form ("&#x2F;" = "/"); the
//     switch's own base MAC is learned on the CPU interface, rendered
//     "c1" / status "Management", which webui.ParseS3300Macs skips as
//     non-physical.
//   - sysInfo.html -- exposes only the "Base MAC Address" (no IPv4 mgmt
//     address on the statically-reachable page), which is all
//     webui.ParseS3300Mgmt reads.
//
// Sensors are NOT served as a live table: the S3300 sysInfo has no
// fan/temp readings, so get_sensors over HTTP is unsupported (SNMP only).

import (
	"fmt"
	"strconv"
	"strings"
)

// The S3300's per-row selection checkboxes, from the LIVE 10.1.5.11 pages:
// they are NOT the gsm7252ps spellings even though the grid is otherwise
// identical.
const (
	s3300PortsCheckbox = "gecb10"
	s3300PoECheckbox   = "gecb164"
)

// s3300Iface is the S3300 ifName for a port number: "1/gN" (1-48), "1/xgN"
// (49-52), and "c1" for the CPU/management interface (any other ifIndex,
// e.g. the one the switch's own base MAC is learned on). Mirrors Python
// web_gsm7228ps._s3300_iface.
func s3300Iface(port int) string {
	switch {
	case port >= 1 && port <= 48:
		return fmt.Sprintf("1/g%d", port)
	case port >= 49 && port <= 52:
		return fmt.Sprintf("1/xg%d", port)
	default:
		return "c1"
	}
}

// RenderS3300Ports renders /portsConfiguration.html in the Smart firmware's
// spelling -- same XE grid as gsm7252ps, but the Port cell is
// "1/g12"/"1/xg49", not "1/0/12". Mirrors Python web_gsm7228ps.render_ports.
func RenderS3300Ports(state *State, errMsg string) string {
	return RenderXEPortsWith(state, errMsg, s3300Iface, s3300PortsCheckbox, "/portsConfiguration.html")
}

// ApplyS3300Ports mirrors Python web_gsm7228ps.apply_ports.
func ApplyS3300Ports(state *State, form map[string]string) string {
	return ApplyXEPortsWith(state, form, s3300PortsCheckbox)
}

// RenderS3300PoE renders /poeInterfaceConfiguration.html in the Smart
// firmware's spelling. Mirrors Python web_gsm7228ps.render_poe.
func RenderS3300PoE(state *State, errMsg string) string {
	return RenderXEPoEWith(state, false, errMsg, s3300Iface, s3300PoECheckbox, "RESET", "/poeInterfaceConfiguration.html")
}

// ApplyS3300PoE mirrors Python web_gsm7228ps.apply_poe: unitRequired=false
// -- this firmware's PoE rows carry their own hidden v_1_2_21 "Unit" key,
// so the row is self-identifying and the apply lands with no page-level
// unit field.
func ApplyS3300PoE(state *State, form map[string]string) string {
	return ApplyXEPoEWith(state, form, s3300PoECheckbox, false)
}

// RenderS3300Vlans renders /vlanStatus.html -- VLANs with their egress port
// list (S3300 ifNames), with LAG ifIndexes rendered "lag N" -- not expanded
// into physical ports. Mirrors Python web_gsm7228ps.render_vlans.
func RenderS3300Vlans(state *State) string {
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
		body += xeCell(inst, "1_1_4", xeVlanEgressParts(vsim, portCount, s3300Iface))
	}
	return xePage(body)
}

// s3300EscapeSlash renders "/" as the "&#x2F;" entity the real S3300 page
// emits in the MAC-table port cell -- webui.ParseXERows html-unescapes it
// back. Mirrors Python web_gsm7228ps._escape_slash.
func s3300EscapeSlash(text string) string {
	return strings.ReplaceAll(text, "/", "&#x2F;")
}

// RenderS3300MacTable renders /basicAddressTable.html -- the learned
// MAC/FDB table (S3300 columns): VLAN in v_1_2_2, MAC in v_1_2_3, escaped
// port ifName in v_1_2_4, status in v_1_2_5 -- the shifted layout
// webui.ParseS3300Macs reads. Mirrors Python web_gsm7228ps.render_mac_table.
func RenderS3300MacTable(state *State) string {
	body := fmt.Sprintf(
		"<TR id=1_1 class=deftestme>\n"+
			"<TD class=defleft id=1_1_1>Total MAC Addresses</TD>\n"+
			"<TD class=defright id=1_1_1><INPUT xid=1_1_1 TYPE=hidden "+
			"NAME=v_1_1_1 VALUE=\"%d\"></TD>\n</TR>\n", len(state.Macs))
	body += xeHeader([]xeHeaderCol{
		{"1_2_2", "VLAN ID"},
		{"1_2_3", "MAC Address"},
		{"1_2_4", "Port"},
		{"1_2_5", "status"},
	})
	for row, entry := range state.Macs {
		inst := fastpathInstance(row, len(state.Macs))
		mac := formatMacUpper(entry.MacBytes)
		port := entry.BridgePort
		if p, ok := state.BridgePorts[entry.BridgePort]; ok {
			port = p
		}
		iface := s3300EscapeSlash(s3300Iface(port))
		status := "Learned"
		if s3300Iface(port) == "c1" {
			status = "Management"
		}
		body += xeCell(inst, "1_2_2", strconv.Itoa(entry.Vlan))
		body += xeCell(inst, "1_2_3", mac)
		body += xeCell(inst, "1_2_4", iface)
		body += xeCell(inst, "1_2_5", status)
	}
	return xePage(body)
}

// RenderS3300Sysinfo renders /base/system/management/sysInfo.html -- Base
// MAC Address only. The S3300 Smart UI's statically-reachable sysInfo
// exposes the switch's base MAC but NOT the IPv4 management address (that
// page is behind a JS-only menu), and carries no live fan/temp sensor
// table. Mirrors Python web_gsm7228ps.render_sysinfo.
func RenderS3300Sysinfo(state *State) string {
	mac := formatMacUpper(state.NsdpMac)
	return "<html><body><form>\n<table>\n" +
		"<tr><td class=\"defaultFontBold\" aid=\"1_1_1_left\">Product Name</td>" +
		"<td class=\"defaultFont\" aid=\"1_1_1_right\">" + state.ModelName + "</td></tr>\n" +
		"<tr><td class=\"defaultFontBold\" aid=\"1_16_1_left\">Base MAC Address</td>" +
		"<td class=\"defaultFont\" aid=\"1_16_1_right\">" + mac + "</td></tr>\n" +
		"<tr><td class=\"defaultFontBold\">Temperature traps range</td>" +
		"<td class=\"defaultFont\"> 0 to 90 degrees (Celsius)</td></tr>\n" +
		"</table></form></body></html>\n"
}
