package virtual

// web_gs105pe.go ports src/netgear_switch/virtual/web_gs105pe.py (the
// normative source; that repo is read-only from here -- pin 1841111,
// branch go-port-pin-1841111). Any discrepancy between this file and that
// pin is a bug here, unless called out in a comment. See
// docs/superpowers/plans/2026-07-31-slice-06-dossier-http-readwrite-face.md
// §4.2/§9.3 for the porting dossier this mirrors.
//
// GS105PE web-UI page renderers driven by State. Structurally faithful to
// the REAL captured pages (see webui/testdata/http/gs105pe_*.html) -- same
// row markers, same column order, and critically the same two quirks real
// firmware has, so the mock exercises exactly the code paths real hardware
// does:
//
//   - portStatistics.cgi leaves the first counter's <td> EMPTY and carries
//     every counter as a hidden (hi, lo) 32-bit pair (see
//     webui.ParseGS105PEStats), and writes its rows as
//     <tr class="portID" name="portID"> -- an extra attribute the other
//     pages lack.
//   - 8021qMembe.cgi carries a per-page CSRF hash and marks the currently
//     selected VLAN with <option ... selected>; the reader reuses that page
//     for the selected VLAN rather than re-POSTing it (which makes real
//     hardware drop the connection).
//
// Byte-for-byte fidelity to the capture is deliberately NOT attempted here
// (that is what the fixture-driven parser tests in webui/parse_gs105pe_test.go
// prove); this face's job is to serve the SAME STATE the NSDP face serves, so
// the HTTP<->NSDP cross-verification is meaningful. Unlike web_gs110emx.go
// (a byte-faithful fixture transcription with embedded JS), this module has
// no captured-fixture chrome to preserve, so plain string concatenation/
// fmt.Sprintf is used exactly as web.py's own (also non-fixture-based)
// STANDARD-dialect renderer does in httpface.go's renderStandardPage.
//
// NO apply_* functions exist here (mirroring the Python module exactly):
// this model's own dispatch never reaches a write path -- see
// httpface.go's dispatchApplyAndRender doc comment for why gs105pe's known
// paths are all intercepted by this file's read-only renderers before the
// generic STANDARD apply/render fallback would ever run.

import (
	"fmt"
	"strconv"
	"strings"
)

// gs105peVirtualCSRFHash mirrors Python web_gs105pe.VIRTUAL_CSRF_HASH: the
// mock's fixed CSRF token. Real firmware regenerates this per page load; the
// reader only has to scrape it and echo it back, so a constant is enough to
// exercise that round trip. Distinct from web.py's "virtualhash" (dossier
// §4.1's three-distinct-CSRF-literals table) -- gs105pe's 8021qCf.cgi/
// 8021qMembe.cgi carry this one specifically.
const gs105peVirtualCSRFHash = "18007"

// gs105peSpeedText converts state speed (Mbps) to status.cgi speed text,
// the inverse of webui.speedTextToMbps so a state -> page -> reader round
// trip reproduces the state value exactly. Mirrors Python
// web_gs105pe._speed_text.
func gs105peSpeedText(mbps int) string {
	if mbps >= 1000 && mbps%1000 == 0 {
		return strconv.Itoa(mbps/1000) + "G"
	}
	return strconv.Itoa(mbps) + "M"
}

// RenderGS105PEStatus renders GET /status.cgi -- per-port link + speed, the
// columns webui.ParseGS105PEPortStatus reads ([1]=port, [2]=link,
// [4]=speed). Mirrors Python web_gs105pe.render_status.
func RenderGS105PEStatus(state *State) string {
	var rows strings.Builder
	for _, port := range sortedIntKeys(state.Ports) {
		sim := state.Ports[port]
		link := "Down"
		if sim.Link {
			link = "Up"
		}
		speed := "No Speed"
		if sim.Link {
			speed = gs105peSpeedText(sim.Speed)
		}
		fmt.Fprintf(&rows, "<tr class=\"portID\">\n"+
			"<td class=\"def firstCol def_center\"><input type=\"checkbox\"></td>\n"+
			"<td class=\"def\" sel=\"text\">%d</td>\n"+
			"<td class=\"def\" sel=\"text\">%s</td>\n"+
			"<td class=\"def\" sel=\"text\">Auto</td>\n"+
			"<td class=\"def\" sel=\"text\">%s</td>\n"+
			"<td class=\"def\" sel=\"text\">Disable</td>\n"+
			"<td class=\"def\" sel=\"text\">16349</td>\n",
			port, link, speed)
	}
	return "<html><body><form method=post action=status.cgi>" +
		"<table id=\"tbl1\">\n" + rows.String() + "</table></form></body></html>\n"
}

// gs105peHalves renders one 64-bit counter as its (hi, lo) 32-bit hidden
// half-pair, mirroring Python web_gs105pe.render_port_statistics's nested
// halves() closure -- the wire shape webui.ParseGS105PEStats reassembles via
// hi<<32 | lo.
func gs105peHalves(value uint64) string {
	return fmt.Sprintf("<input type=\"hidden\" value=\"%d\">\n<input type=\"hidden\" value=\"%d\">\n",
		value>>32, value&0xFFFFFFFF)
}

// RenderGS105PEPortStatistics renders GET /portStatistics.cgi -- reproduces
// the real page's quirks: rows are <tr class="portID" name="portID">, the
// Bytes-Received cell is rendered EMPTY, and each counter is a hidden
// (hi, lo) 32-bit pair. Mirrors Python web_gs105pe.render_port_statistics.
func RenderGS105PEPortStatistics(state *State) string {
	var rows strings.Builder
	for _, port := range sortedIntKeys(state.Ports) {
		sim := state.Ports[port]
		rx, tx, crc := u64OrZero(sim.RxOctets), u64OrZero(sim.TxOctets), u64OrZero(sim.RxErrors)
		rows.WriteString(`<tr class="portID" name="portID">` + "\n")
		fmt.Fprintf(&rows, "<td class=\"def firstCol\" sel=\"text\">%d</td>\n", port)
		rows.WriteString("<td class=\"def\" sel=\"text\">\n</td>\n")
		rows.WriteString(gs105peHalves(rx))
		fmt.Fprintf(&rows, "<td class=\"def\" sel=\"text\">%d\n</td>\n", tx)
		rows.WriteString(gs105peHalves(tx))
		fmt.Fprintf(&rows, "<td class=\"def\" sel=\"text\">%d\n</td>\n", crc)
		rows.WriteString(gs105peHalves(crc))
	}
	return "<html><body><form method=post action=portStatistics.cgi>" +
		"<table id=\"tbl1\">\n" + rows.String() + "</table></form></body></html>\n"
}

// RenderGS105PEPvid renders GET /portPVID.cgi -- [1]=port, [2]=PVID. Mirrors
// Python web_gs105pe.render_pvid.
func RenderGS105PEPvid(state *State) string {
	var rows strings.Builder
	for _, port := range sortedIntKeys(state.Pvids) {
		pvid := state.Pvids[port]
		fmt.Fprintf(&rows, "<tr class=\"portID\">\n"+
			"<td class=\"def firstCol def_center\"><input type=\"checkbox\"></td>\n"+
			"<td class=\"def\" sel=\"text\">%d</td>\n"+
			"<td class=\"def\" sel=\"input\">%d</td>\n",
			port, pvid)
	}
	return "<html><body><form method=post action=portPVID.cgi>" +
		"<table id=\"tbl1\">\n" + rows.String() + "</table></form></body></html>\n"
}

// RenderGS105PEVlanConfig renders GET /8021qCf.cgi -- the VLAN list as
// vlanckN checkboxes (the shape gs305ep's webui.ParseVLANIDs reads, which
// gs105pe shares). Mirrors Python web_gs105pe.render_vlan_config.
func RenderGS105PEVlanConfig(state *State) string {
	var boxes strings.Builder
	for i, vid := range sortedIntKeys(state.Vlans) {
		fmt.Fprintf(&boxes, "<input type=\"checkbox\" name=\"vlanck%d\" value=\"%d\">\n", i+1, vid)
	}
	return "<html><body><form method=post action=8021qCf.cgi>" +
		fmt.Sprintf("<input type=\"hidden\" name=\"hash\" value=\"%s\">\n", gs105peVirtualCSRFHash) +
		boxes.String() + "</form></body></html>\n"
}

// RenderGS105PEVlanMembership renders GET/POST /8021qMembe.cgi -- the
// per-port hiddenMem wire codes (1=untagged, 2=tagged, 3=excluded) for
// selectedVid, plus the CSRF hash and a <option ... selected> marking which
// VLAN is shown. Mirrors Python web_gs105pe.render_vlan_membership.
func RenderGS105PEVlanMembership(state *State, selectedVid int) string {
	portCount := state.mustModel().PortCount
	vsim := state.Vlans[selectedVid]
	codes := make([]byte, portCount)
	for i := range portCount {
		port := i + 1
		switch {
		case vsim != nil && vsim.Untagged[port]:
			codes[i] = '1'
		case vsim != nil && vsim.Member[port]:
			codes[i] = '2'
		default:
			codes[i] = '3'
		}
	}
	var opts strings.Builder
	for _, vid := range sortedIntKeys(state.Vlans) {
		selected := ""
		if vid == selectedVid {
			selected = " selected"
		}
		fmt.Fprintf(&opts, "<option value=\"%d\"%s>%d</option>\n", vid, selected, vid)
	}
	return "<html><body><form method=post action=8021qMembe.cgi>" +
		fmt.Sprintf("<input type=\"hidden\" name=\"hash\" value=\"%s\">\n", gs105peVirtualCSRFHash) +
		"<select name=\"VLAN_ID\" id=\"vlanIdOption\">\n" + opts.String() + "</select>\n" +
		fmt.Sprintf("<input name=\"hiddenMem\" id=\"hiddenMem\" value=\"%s\" type=\"hidden\">\n", string(codes)) +
		"</form></body></html>\n"
}

// RenderGS105PESwitchInfo renders GET /switch_info.cgi -- device identity +
// mgmt-IP, in the labelled-cell and lowercase-input shape
// webui.ParseGS105PESysInfo reads. Mirrors Python web_gs105pe.render_switch_info.
func RenderGS105PESwitchInfo(state *State) string {
	mac := formatGS105PEMac(state.NsdpMac)
	dhcpSelected := state.Mgmt.Mode == "dhcp"
	productName := state.ModelName
	if productName == "" {
		productName = "GS105PE"
	}
	disableSelected, enableSelected := " selected", ""
	if dhcpSelected {
		disableSelected, enableSelected = "", " selected"
	}
	var b strings.Builder
	b.WriteString("<html><body><form method=post action=switch_info.cgi>")
	b.WriteString("<table>\n")
	fmt.Fprintf(&b, "<tr><td>Product Name</td><td>%s</td></tr>\n", productName)
	fmt.Fprintf(&b, "<tr><td>Serial Number</td><td>%s</td></tr>\n", state.Serial)
	fmt.Fprintf(&b, "<tr><td>MAC Address</td><td>%s</td></tr>\n", mac)
	fmt.Fprintf(&b, "<tr><td>Firmware Version</td><td>%s</td></tr>\n", state.Firmware)
	b.WriteString("</table>\n")
	fmt.Fprintf(&b, "<input type=\"text\" name=\"switch_name\" value=\"%s\">\n", state.Hostname)
	b.WriteString("<select name=\"dhcpMode\" id=\"dhcpMode\">\n")
	fmt.Fprintf(&b, "<option value=\"0\"%s>Disable</option>\n", disableSelected)
	fmt.Fprintf(&b, "<option value=\"1\"%s>Enable</option>\n", enableSelected)
	b.WriteString("</select>\n")
	fmt.Fprintf(&b, "<input type=\"text\" name=\"ip_address\" value=\"%s\">\n", state.Mgmt.Address)
	fmt.Fprintf(&b, "<input type=\"text\" name=\"subnet_mask\" value=\"%s\">\n", state.Mgmt.Netmask)
	fmt.Fprintf(&b, "<input type=\"text\" name=\"gateway_address\" value=\"%s\">\n", state.Mgmt.Gateway)
	b.WriteString("</form></body></html>\n")
	return b.String()
}

// formatGS105PEMac upper-cases and colon-joins a 6-byte MAC, mirroring
// Python web_gs105pe.render_switch_info's inline ":".join(f"{b:02X}" ...)
// (uppercase hex -- contrast web_gs110emx.formatGS110EMXMac's lowercase).
func formatGS105PEMac(raw [6]byte) string {
	parts := make([]string, 6)
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
