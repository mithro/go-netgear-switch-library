package virtual

// web_gs110emx.go ports src/netgear_switch/virtual/web_gs110emx.py (the
// normative source; that repo is read-only from here -- pin 1841111,
// branch go-port-pin-1841111). Any discrepancy between this file and that
// pin is a bug here, unless called out in a comment. See
// docs/superpowers/plans/2026-07-31-slice-06-dossier-http-readwrite-face.md
// §4.2/§9.3 for the porting dossier this mirrors.
//
// Byte-faithful GS110EMX web-UI page templates (Gambit token session). The
// literal HTML in web_gs110emx_templates.go is the REAL captured content
// from a physical GS110EMX (webui/testdata/http/gs110emx_*.html) with only
// the dynamic values swapped for __MARKER__ placeholders -- everything else
// (JS boilerplate, attribute names, and critically the malformed
// NEVER-CLOSED <tr class="portID"> rows on interface_stats.html/
// port_settings.html/vlan_pvidsetting.html -- see webui's splitOpenRows doc
// comment) is copied byte-for-byte from the capture, so the mock is
// byte-equivalent to real hardware whenever seeded with the same values.
//
// Substitution is plain strings.ReplaceAll (NEVER text/template or
// fmt.Sprintf): the captured pages' inline JavaScript is full of literal
// {/} characters that would collide with text/template's {{...}} delimiters
// and require escaping every literal % for fmt.Sprintf -- dossier §4.8/§9.3.
//
// One known, deliberate byte-level deviation (ported as-is, not "fixed"):
// the real capture's LAST portID row (port 10) is followed by 2 fewer
// whitespace characters before </table> than every other row -- a capture
// idiosyncrasy of the real device, not a parsing-relevant difference.
// RenderGS110EMXInterfaceStats renders every row (including the last) with
// the same trailing whitespace for simplicity, so a byte-diff against the
// original 10-port capture differs by exactly those 2 bytes.

import (
	"fmt"
	"strconv"
	"strings"
)

// RenderGS110EMXLogin renders the GET / login page, byte-identical to
// gs110emx_login.html but for the rand nonce. Mirrors Python
// web_gs110emx.render_login.
func RenderGS110EMXLogin(rand string) string {
	return strings.ReplaceAll(gs110emxLogin, "__RAND__", rand)
}

// RenderGS110EMXRedirect renders the POST /redirect.html login response,
// byte-identical to gs110emx_redirect.html but for the Gambit token.
// token=="" (a rejected login) renders a Gambit field with an empty value,
// which webui.ParseGambitToken reads back as falsy. Mirrors Python
// web_gs110emx.render_redirect.
func RenderGS110EMXRedirect(token string) string {
	return strings.ReplaceAll(gs110emxRedirect, "__GAMBIT__", token)
}

// formatGS110EMXMac lower-cases and colon-joins a 6-byte MAC, mirroring
// Python web_gs110emx._format_mac.
func formatGS110EMXMac(raw [6]byte) string {
	parts := make([]string, 6)
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// RenderGS110EMXSysinfo renders GET /iss/specific/sysInfo.html?Gambit=<token>,
// byte-identical to gs110emx_sysinfo.html but for the state-driven device
// identity/mgmt-IP fields. dhcpSelect mirrors the captured page's
// data-select-value attribute (0=static/Disable, 1=DHCP/Enable) -- see
// webui.ParseSysInfo's read-side grounding of this convention. Mirrors
// Python web_gs110emx.render_sysinfo.
func RenderGS110EMXSysinfo(state *State, token string) string {
	dhcpSelect := "0"
	if state.Mgmt.Mode == "dhcp" {
		dhcpSelect = "1"
	}
	productName := state.ModelName
	if productName == "" {
		productName = "GS110EMX"
	}
	replacer := strings.NewReplacer(
		"__GAMBIT__", token,
		"__PRODUCT_NAME__", productName,
		"__SWITCH_NAME__", state.Hostname,
		"__SERIAL__", state.Serial,
		"__MAC__", formatGS110EMXMac(state.NsdpMac),
		"__FIRMWARE__", state.Firmware,
		"__DHCP_SELECT__", dhcpSelect,
		"__IP__", state.Mgmt.Address,
		"__NETMASK__", state.Mgmt.Netmask,
		"__GATEWAY__", state.Mgmt.Gateway,
	)
	return replacer.Replace(gs110emxSysinfo)
}

// speedMbpsToGS110EMXText converts state speed (Mbps) to port_settings.html
// speed text, the inverse of webui.speedTextToMbps so a round trip (state ->
// HTTP page -> reader) reproduces the state value, and HTTP speed_mbps
// equals the NSDP backend's for the same state. Mirrors Python
// web_gs110emx._speed_mbps_to_text.
func speedMbpsToGS110EMXText(mbps int) string {
	if mbps >= 1000 && mbps%1000 == 0 {
		return strconv.Itoa(mbps/1000) + "G Full"
	}
	return strconv.Itoa(mbps) + "M Full"
}

// RenderGS110EMXPortSettings renders GET port_settings.html -- port
// link/speed/description from state, so the HTTP port-status read matches
// the NSDP PORT_STATUS read on this switch. Mirrors Python
// web_gs110emx.render_port_settings.
func RenderGS110EMXPortSettings(state *State, token string) string {
	var rows strings.Builder
	for _, port := range sortedIntKeys(state.Ports) {
		sim := state.Ports[port]
		desc := sim.Name
		if sim.Description != nil {
			desc = *sim.Description
		}
		link := "Down"
		if sim.Link {
			link = "Up"
		}
		// The mode cell IS the admin state on this model (its Physical Mode
		// select's only "off" option is Disable) -- see
		// webui.ParseGS110EMXPortStatus.
		mode := "Disable"
		physMode := "6"
		if sim.Admin {
			mode = "Auto"
			physMode = "1"
		}
		speed := "No Speed"
		if sim.Link {
			speed = speedMbpsToGS110EMXText(sim.Speed)
		}
		row := strings.NewReplacer(
			"__PORT__", strconv.Itoa(port),
			"__DESC__", desc,
			"__LINK__", link,
			"__MODE__", mode,
			"__PHYSMODE__", physMode,
			"__SPEED__", speed,
		).Replace(gs110emxPortSettingsRow)
		rows.WriteString(row)
	}
	return strings.ReplaceAll(gs110emxPortSettingsPrefix, "__GAMBIT__", token) +
		rows.String() + gs110emxPortSettingsSuffix
}

// gs110emxCtrlModeDisable mirrors Python web_gs110emx._EMX_CTRL_MODE_DISABLE
// -- the GS110EMX's PORT_CTRL_MODE wire value for "Disable" (from the
// firmware's own function.js: PHYSICAL_MODE 1 "Auto" -> 1, PHYSICAL_MODE 6
// "Disable" -> 3).
const gs110emxCtrlModeDisable = "3"

// ApplyGS110EMXPortSettings applies a port_settings.html POST; returns the
// page's reply BODY. Mirrors Python web_gs110emx.apply_port_settings: the
// real page answers an AJAX apply with a bare "SUCCESS" (its own JS checks
// resText != "SUCCESS"), not a re-rendered page. PORT_NO is the
// SEMICOLON-TERMINATED selected-port list its saveSelectedPorts() builds
// ("3;"), and a body that sends a bare number selects nothing and applies
// nothing -- reproduced here, because that is exactly the mistake that a
// lenient mock would have hidden (it was caught on real hardware instead).
func ApplyGS110EMXPortSettings(state *State, form map[string]string) string {
	if form["ACTION"] != "apply" {
		return "SUCCESS"
	}
	raw := form["PORT_NO"]
	if !strings.HasSuffix(raw, ";") {
		return "SUCCESS" // nothing selected -- the switch applies nothing
	}
	enabled := form["PORT_CTRL_MODE"] != gs110emxCtrlModeDisable
	for _, part := range strings.Split(raw, ";") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" || !isAllDigits(trimmed) {
			continue
		}
		port, err := strconv.Atoi(trimmed)
		if err != nil {
			continue
		}
		if sim, ok := state.Ports[port]; ok {
			sim.Admin = enabled
		}
	}
	return "SUCCESS"
}

// RenderGS110EMXPvid renders GET vlan_pvidsetting.html -- per-port PVID from
// state. Mirrors Python web_gs110emx.render_pvid.
func RenderGS110EMXPvid(state *State, token string) string {
	var rows strings.Builder
	for _, port := range sortedIntKeys(state.Pvids) {
		pvid := state.Pvids[port]
		row := strings.NewReplacer(
			"__PORT__", strconv.Itoa(port),
			"__PVID__", strconv.Itoa(pvid),
		).Replace(gs110emxPvidRow)
		rows.WriteString(row)
	}
	return strings.ReplaceAll(gs110emxPvidPrefix, "__GAMBIT__", token) +
		rows.String() + gs110emxPvidSuffix
}

// RenderGS110EMXCf8021q renders GET Cf8021q.html -- the VLAN list (with
// member ports) from state. The reader only scrapes the VID column
// (webui.ParseGS110EMXVlanIDs); the member list is rendered for fidelity.
// Mirrors Python web_gs110emx.render_cf8021q.
func RenderGS110EMXCf8021q(state *State, token string) string {
	var rows strings.Builder
	for _, vid := range sortedIntKeys(state.Vlans) {
		vsim := state.Vlans[vid]
		members := make([]string, 0, len(vsim.Member))
		for _, p := range sortedIntKeys(vsim.Member) {
			members = append(members, strconv.Itoa(p))
		}
		row := strings.NewReplacer(
			"__VID__", strconv.Itoa(vid),
			"__MEMBERS__", strings.Join(members, " ")+" ",
		).Replace(gs110emxCf8021qRow)
		rows.WriteString(row)
	}
	return strings.ReplaceAll(gs110emxCf8021qPrefix, "__GAMBIT__", token) +
		rows.String() + gs110emxCf8021qSuffix
}

// RenderGS110EMXVlanMembership renders POST vlanMembership.html
// (VLAN_ID=<selectedVid>) -- the per-port hiddenMem wire codes (1=untagged,
// 2=tagged, 3=excluded) for the selected VLAN, plus the full VLAN <option>
// list. The wire codes are the SAME scheme gs305ep's 8021qMembe.cgi uses, so
// webui.ParseMembership reads it back and the resulting VLANInfo matches the
// NSDP VLAN_MEMBERS read. Mirrors Python web_gs110emx.render_vlan_membership.
func RenderGS110EMXVlanMembership(state *State, token string, selectedVid int) string {
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
		fmt.Fprintf(&opts, `<option value = "%d">%d </option>`+"\n", vid, vid)
	}
	return strings.NewReplacer(
		"__GAMBIT__", token,
		"__VLAN_OPTIONS__", opts.String(),
		"__HIDDENMEM__", string(codes),
	).Replace(gs110emxVlanmemPage)
}

// RenderGS110EMXInterfaceStats renders GET
// /iss/specific/interface_stats.html?Gambit=<token> -- byte-identical to
// gs110emx_interface_stats.html but for the per-port counters. The real
// device NEVER closes a <tr class="portID"> with </tr> (rows run on until
// the next <tr> or the table close); this reproduces that exact
// malformed-but-real shape row-for-row, which is why
// webui.ParseInterfaceStats (not gs305ep's ParsePortStats) is needed to read
// it back. Missing counters (nil) render as 0, matching the real device's
// own zeroed idle-port rows. Mirrors Python
// web_gs110emx.render_interface_stats.
func RenderGS110EMXInterfaceStats(state *State, token string) string {
	var rows strings.Builder
	for _, port := range sortedIntKeys(state.Ports) {
		sim := state.Ports[port]
		rows.WriteString(`<tr class="portID"> ` + "\n")
		row := strings.NewReplacer(
			"__PORT__", strconv.Itoa(port),
			"__RX__", strconv.FormatUint(u64OrZero(sim.RxOctets), 10),
			"__TX__", strconv.FormatUint(u64OrZero(sim.TxOctets), 10),
			"__CRC__", strconv.FormatUint(u64OrZero(sim.RxErrors), 10),
		).Replace(gs110emxStatsRow)
		rows.WriteString(row)
	}
	return strings.ReplaceAll(gs110emxStatsPrefix, "__GAMBIT__", token) +
		rows.String() + gs110emxStatsSuffix
}
