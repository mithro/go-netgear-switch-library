package virtual

// web_fastpath_vlan.go ports src/netgear_switch/virtual/web_fastpath_vlan.py
// (the normative source; that repo is read-only from here -- pin b26eb1f,
// branch go-port-pin-b26eb1f). Any discrepancy between this file and that
// pin is a bug here, unless called out in a comment. See
// docs/superpowers/plans/2026-07-31-slice-06-dossier-http-readwrite-face.md
// §4/§5 for the porting dossier this mirrors.
//
// The managed FASTPATH "VLAN Membership" page, rendered from + applied to
// *State. Reproduces switching/dot1q/vlan_port_cfg.html (GET) and its
// ..._rw.html form target (POST, used for BOTH a VLAN-select re-render and
// an apply) as the real firmware serves them. Grounded in live captures
// taken 2026-07-30 from all four managed switches (webui/testdata/http/
// *vlan[Pp]ort[Cc]fg*.html), read back by webui.ParseFastpathMembership.
//
// Behaviours reproduced because hardware does them, each something a
// lenient mock would hide:
//
//   - Two different views of the same VLAN. hiddenTagged/hiddenUnTagged are
//     the CURRENT (operational) egress lists; hiddenMem and the port grid
//     are the CONFIGURED participation. They genuinely differ -- see
//     VlanSim.ConfiguredOnly, seeded from the real GSM7252PS.
//   - submt is the apply flag. submt=0 (what the VLAN <select>'s
//     screen_refresh() posts) re-renders WITHOUT applying; only submt=16
//     (0x10, what submitform() sets) writes.
//   - The page shows whichever VLAN vlanId selected, and an unknown VLAN
//     falls back to the lowest.
//   - Two grid encodings, two index bases. Older firmware (gsm7252ps) emits
//     toggleImageFirst(this,<0-based slot>,...) + grey_[btu].gif; newer
//     (S3300/M4300) emits togImg(this,<1-based slot>,...) + switch_*.png.
//   - LAG pseudo-interfaces occupy hiddenMem slots after the physical ports
//     and are rendered in their own grid table.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/webui"
)

// fastpathVlanApplyFlag mirrors Python web_fastpath_vlan._APPLY:
// submitform() in the firmware's rollover.js sets submt = 0x10 before
// submitting; anything else is a read-only re-render (screen_refresh()).
const fastpathVlanApplyFlag = "16"

// fastpathVlanGifImg maps a hiddenMem wire code -> the older gsm7252ps
// grid's image basename. Mirrors Python web_fastpath_vlan._GIF_IMG.
var fastpathVlanGifImg = map[string]string{"1": "grey_t", "2": "grey_u", "3": "grey_b"}

// fastpathVlanPngImg maps a hiddenMem wire code -> the newer S3300/M4300
// grid's image basename. Mirrors Python web_fastpath_vlan._PNG_IMG.
var fastpathVlanPngImg = map[string]string{"1": "tagged", "2": "untagged", "3": "blank"}

// fastpathVlanLagBase is the 0-based hiddenMem slot where the LAG
// pseudo-interfaces start: the number of PHYSICAL ports the page renders --
// NOT model.PortCount (the registry gives the M4300-24X 28 while the real
// switch's grid renders 24 cells). Mirrors Python web_fastpath_vlan._lag_base.
func fastpathVlanLagBase(state *State) int {
	return len(xePhysicalPorts(state))
}

// fastpathVlanEsc HTML-entity-escapes an ifName list the way the newer
// firmware does. Mirrors Python web_fastpath_vlan._esc.
func fastpathVlanEsc(text string, page *VlanMembershipPageSim) string {
	if page.Escape {
		return strings.ReplaceAll(text, "/", "&#x2F;")
	}
	return text
}

// fastpathVlanIface is the ifName the model's grid uses for a physical
// port: the S3300's Smart firmware writes "1/gN"/"1/xgN"; every other
// model writes the FASTPATH "1/0/N". Mirrors Python
// web_fastpath_vlan._iface.
func fastpathVlanIface(spec *webui.HTTPModelSpec, port int) string {
	if spec.HTMLDialect == webui.HTMLDialectS3300 {
		return s3300Iface(port)
	}
	return fmt.Sprintf("1/0/%d", port)
}

// fastpathVlanCodes is the full hiddenMem code list for vid: one per slot.
// Physical ports come from the VLAN's CONFIGURED sets (hiddenMem is the
// configured view); the LAG slots that follow are rendered Excluded unless
// the seed put a LAG ifIndex in the VLAN. Mirrors Python
// web_fastpath_vlan._codes.
func fastpathVlanCodes(state *State, vid int) []string {
	page := state.VlanMembershipPage
	portCount := state.mustModel().PortCount
	codes := make([]string, page.Slots)
	for i := range codes {
		codes[i] = "3"
	}
	vsim, ok := state.Vlans[vid]
	if !ok {
		return codes
	}
	configured := vsim.Configured()
	for _, port := range xePhysicalPorts(state) {
		if !configured[port] {
			continue
		}
		if port-1 >= len(codes) {
			continue
		}
		if vsim.Untagged[port] || vsim.ConfiguredOnly[port] {
			codes[port-1] = "2"
		} else {
			codes[port-1] = "1"
		}
	}
	var lags []int
	for _, p := range sortedIntKeys(configured) {
		if p > portCount {
			lags = append(lags, p)
		}
	}
	base := fastpathVlanLagBase(state)
	for i, lag := range lags {
		slot := base + i
		if slot < len(codes) {
			if vsim.Untagged[lag] {
				codes[slot] = "2"
			} else {
				codes[slot] = "1"
			}
		}
	}
	return codes
}

// fastpathVlanIfaceLists returns (hiddenTagged, hiddenUnTagged) -- the
// CURRENT egress ifName lists. Built from Member/Untagged only,
// deliberately EXCLUDING ConfiguredOnly: that is precisely the divergence
// real firmware shows. LAG members are rendered with the model's own LAG
// slot ("0/3/N" or "0/13/N"). Mirrors Python web_fastpath_vlan._iface_lists.
func fastpathVlanIfaceLists(state *State, spec *webui.HTTPModelSpec, vid int) (tagged, untagged string) {
	page := state.VlanMembershipPage
	portCount := state.mustModel().PortCount
	vsim, ok := state.Vlans[vid]
	if !ok {
		return "", ""
	}
	var taggedList, untaggedList []string
	for _, port := range xePhysicalPorts(state) {
		if !vsim.Member[port] {
			continue
		}
		name := fastpathVlanIface(spec, port)
		if vsim.Untagged[port] {
			untaggedList = append(untaggedList, name)
		} else {
			taggedList = append(taggedList, name)
		}
	}
	var lags []int
	for _, p := range sortedIntKeys(vsim.Member) {
		if p > portCount {
			lags = append(lags, p)
		}
	}
	for i, lag := range lags {
		name := fmt.Sprintf("0/%d/%d", page.LagSlot, i+1)
		if vsim.Untagged[lag] {
			untaggedList = append(untaggedList, name)
		} else {
			taggedList = append(taggedList, name)
		}
	}
	tail := ""
	if page.TrailingComma {
		tail = ","
	}
	taggedStr := strings.Join(taggedList, ",")
	if len(taggedList) > 0 {
		taggedStr += tail
	}
	untaggedStr := strings.Join(untaggedList, ",")
	if len(untaggedList) > 0 {
		untaggedStr += tail
	}
	return fastpathVlanEsc(taggedStr, page), fastpathVlanEsc(untaggedStr, page)
}

// fastpathVlanGridGif renders the older gsm7252ps grid: toggleImageFirst +
// grey_[btu].gif cells, with the physical unit table and the LAG table
// each labelled by their first row cell ("Port" / "LAG"). Mirrors Python
// web_fastpath_vlan._grid_gif.
func fastpathVlanGridGif(state *State, codes []string) string {
	page := state.VlanMembershipPage
	base := fastpathVlanLagBase(state)
	ports := xePhysicalPorts(state)

	var portHeaders, portCells strings.Builder
	for _, p := range ports {
		fmt.Fprintf(&portHeaders, "<td>%d</td>\n", p)
		fastpathVlanGifCell(&portCells, p-1, p, "1", codes)
	}
	// Real firmware numbers LAG grid cells with their internal interface
	// ids (418..481 on the captured GSM7252PS), NOT 1..64.
	const lagIDBase = 418
	numLags := page.Slots - base
	var lagHeaders, lagCells strings.Builder
	for i := 0; i < numLags; i++ {
		fmt.Fprintf(&lagHeaders, "<td>%d</td>\n", i+1)
		fastpathVlanGifCell(&lagCells, base+i, lagIDBase+i, "25", codes)
	}
	return "<table class=\"tableStyle\" id=\"unit1tb\"><tbody>\n" +
		"<tr class=\"font10Bold messageTableWhite\">\n<td >Port</td>\n" +
		portHeaders.String() +
		"</tr>\n<tr class=\"messageTableGrey\">\n<td>&nbsp;</td>\n" +
		portCells.String() +
		"</tr>\n</tbody></table>\n" +
		"<table class=\"tableStyle\" id=\"unit25tb\"><tbody>\n" +
		"<tr class=\"font10Bold messageTableWhite\">\n<td >LAG</td>\n" +
		lagHeaders.String() +
		"</tr>\n<tr class=\"messageTableGrey\">\n<td>&nbsp;</td>\n" +
		lagCells.String() +
		"</tr>\n</tbody></table>\n"
}

func fastpathVlanGifCell(b *strings.Builder, slot, intf int, unit string, codes []string) {
	img := fastpathVlanGifImg[codes[slot]]
	fmt.Fprintf(b, "<td><a style=\"cursor: pointer\" onClick=\"toggleImageFirst("+
		"this,%d,0,'img_unit%s',%d);return false\" >"+
		"<img src=\"/base/images/%s.gif\" name=\"imx\" id=\"%d\"></a></td>\n",
		slot, unit, intf, img, intf)
}

// fastpathVlanGridPng renders the newer S3300/M4300 grid: aid='port-<ifName>'
// + togImg cells with a 1-BASED hiddenMem index, and
// switch_<state>[_bottom]_inactive.png images (_bottom on the even ports).
// Mirrors Python web_fastpath_vlan._grid_png.
func fastpathVlanGridPng(state *State, spec *webui.HTTPModelSpec, codes []string) string {
	page := state.VlanMembershipPage
	base := fastpathVlanLagBase(state)
	var out strings.Builder
	out.WriteString("<table class='tableStyle tableWidthAuto' id='unit1tb'>\n" +
		"<tr class='fontTableTitle' id='unit1_view'>\n" +
		"<td class='intStyle'>Ports</td>\n")
	for _, port := range xePhysicalPorts(state) {
		bottom := ""
		if port%2 == 0 {
			bottom = "_bottom"
		}
		fmt.Fprintf(&out, "<td><div class='titleUp'>%d</div>\n<div class='panel'>"+
			"<a href='javascript:void(0)'><img class='panPad' "+
			"aid='port-%s' "+
			"src='/base/images/switch_%s%s"+
			"_inactive.png' name='imx' onclick='onClick(this); "+
			"togImg(this,%d,0,\"hiddenMem\"); enablebtn(1);'/></a></div></td>\n",
			port, fastpathVlanIface(spec, port), fastpathVlanPngImg[codes[port-1]], bottom, port)
	}
	out.WriteString("</tr>\n</table>\n")
	out.WriteString("<table class='tableStyle tableWidthAuto' id='unit2tb'>\n" +
		"<tr class='fontTableTitle'>\n<td class='intStyle'>LAG</td>\n")
	for i := 0; i < page.Slots-base; i++ {
		slot1 := base + i + 1
		fmt.Fprintf(&out, "<td><div class='titleUp'>%d</div>\n<div class='panel'>"+
			"<a href='javascript:void(0)'><img class='panPad' aid='lag %d' "+
			"src='/base/images/switch_%s_inactive.png' "+
			"name='imx' onclick='onClick(this); "+
			"togImg(this,%d,0,\"hiddenMem\"); enablebtn(1);'/></a></div></td>\n",
			i+1, i+1, fastpathVlanPngImg[codes[slot1-1]], slot1)
	}
	out.WriteString("</tr>\n</table>\n")
	return out.String()
}

// fastpathVlanShownVlan is which VLAN this render is for. A vlanId naming a
// VLAN the switch does not have falls back to the lowest one, exactly as
// the firmware's <select> does. Mirrors Python web_fastpath_vlan._shown_vlan.
func fastpathVlanShownVlan(state *State, form map[string]string) int {
	requested := form["vlanId"]
	if isASCIIDigitsFastpath(requested) {
		if v, err := strconv.Atoi(requested); err == nil {
			if _, ok := state.Vlans[v]; ok {
				return v
			}
		}
	}
	ids := sortedIntKeys(state.Vlans)
	if len(ids) == 0 {
		return 1
	}
	return ids[0]
}

// FastpathVlanRefusal is the err_msg this apply would be refused with, or
// "" if allowed. Reproduces the M4300 firmware's precondition: a port whose
// switchport mode is access or trunk cannot be given explicit VLAN
// membership, and the web UI reports that as err_flag=1 + err_msg on an
// otherwise-200 page rather than an HTTP error. Mirrors Python
// web_fastpath_vlan.refusal.
func FastpathVlanRefusal(state *State, form map[string]string) string {
	if form["submt"] != fastpathVlanApplyFlag || len(state.VlanMembershipLockedPorts) == 0 {
		return ""
	}
	vid := fastpathVlanShownVlan(state, form)
	codes := fastpathVlanFormCodes(form)
	vsim := state.Vlans[vid]
	for port := range state.VlanMembershipLockedPorts {
		if !state.VlanMembershipLockedPorts[port] {
			continue
		}
		var code string
		if port > 0 && port <= len(codes) {
			code = codes[port-1]
		}
		if code != "1" && code != "2" && code != "3" {
			continue
		}
		var was string
		switch {
		case vsim == nil || !vsim.Configured()[port]:
			was = "3"
		case vsim.Untagged[port] || vsim.ConfiguredOnly[port]:
			was = "2"
		default:
			was = "1"
		}
		if code != was {
			return fmt.Sprintf("Unable to set VLAN membership for VLAN ( %d )", vid)
		}
	}
	return ""
}

// fastpathVlanFormCodes splits a submitted hiddenMem field into its
// non-empty wire codes, mirroring Python's
// `[c for c in form.get("hiddenMem", "").split(",") if c != ""]`.
func fastpathVlanFormCodes(form map[string]string) []string {
	var out []string
	for _, c := range strings.Split(form["hiddenMem"], ",") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// RenderFastpathVlanMembership renders the VLAN Membership page for the
// VLAN form selected. Mirrors Python web_fastpath_vlan.render_membership.
func RenderFastpathVlanMembership(state *State, spec *webui.HTTPModelSpec, form map[string]string, errMsg string) string {
	page := state.VlanMembershipPage
	vid := fastpathVlanShownVlan(state, form)
	codes := fastpathVlanCodes(state, vid)
	hiddenMem := strings.Join(codes, ",")
	if page.TrailingComma {
		hiddenMem += ","
	}
	tagged, untagged := fastpathVlanIfaceLists(state, spec, vid)
	vsim := state.Vlans[vid]
	var options strings.Builder
	for _, v := range sortedIntKeys(state.Vlans) {
		selected := ""
		if v == vid {
			selected = " SELECTED"
		}
		fmt.Fprintf(&options, "<OPTION class=\"selectfield\" value=\"%d\"%s>%d\n", v, selected, v)
	}
	csrf := ""
	if page.CSRF {
		csrf = "<INPUT TYPE=\"hidden\" NAME=\"CSRFToken\" ID=\"CSRFToken\" VALUE=\"virtualcsrf\">\n"
	}
	grid := fastpathVlanGridPng(state, spec, codes)
	if page.Grid == "gif" {
		grid = fastpathVlanGridGif(state, codes)
	}
	action := spec.VlanMembershipPostPath
	errFlag := "0"
	if errMsg != "" {
		errFlag = "1"
	}
	vlanName := ""
	if vsim != nil {
		vlanName = vsim.Name
	}
	vlanType := "Static"
	if vid == 1 {
		vlanType = "Default"
	}
	return "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n" +
		"<HTML><HEAD><TITLE>VLAN Configuration</TITLE></HEAD>\n" +
		"<body onLoad='check_error()'>\n" +
		"<FORM method=\"post\" ACTION=\"" + action + "\">\n" +
		"<table class=\"tableStyle\" id=\"tbl1\">\n<tr><td>VLAN ID</td><td>\n" +
		"<SELECT name=\"vlanId\" class=\"select\" onChange=\"screen_refresh()\">\n" +
		options.String() + "</SELECT></td>\n" +
		"<td>Group Operation</td><td><SELECT name=\"select\" class=\"select\" " +
		"id=\"groupOpera\" onChange=\"imgtag('groupOpera');enableImage()\">\n" +
		"<OPTION value=\"UntagAll\" selected=\"selected\" >Untag All</option>\n" +
		"<OPTION value=\"TagAll\" >Tag All</option>\n" +
		"<OPTION value=\"RemoveAll\" >Remove All</option>\n" +
		"</SELECT></td></tr>\n" +
		"<tr><td>VLAN Name</td><td><INPUT name=\"vlan_name\" type=\"text\" " +
		"class=\"inputDisabled\" READONLY VALUE=\"" + vlanName + "\"></td></tr>\n" +
		"<tr><td>VLAN Type</td><td><INPUT name=\"vlan_type\" type=\"text\" " +
		"class=\"inputDisabled\" READONLY VALUE=\"" + vlanType + "\"></td></tr>\n" +
		"</table>\n" + grid +
		"<INPUT TYPE=\"hidden\" NAME=\"err_flag\" VALUE=\"" + errFlag + "\">\n" +
		"<INPUT TYPE=\"hidden\" NAME=\"err_msg\" VALUE=\"" + errMsg + "\">\n" +
		"<INPUT TYPE=\"hidden\" NAME=\"hiddenTagged\" id=\"hiddenTagged\" VALUE=\"" + tagged + "\">\n" +
		"<INPUT TYPE=\"hidden\" NAME=\"hiddenUnTagged\" id=\"hiddenUnTagged\" VALUE=\"" + untagged + "\">\n" +
		"<INPUT TYPE=\"hidden\" NAME=\"hiddenMem\" id=\"hiddenMem\" VALUE=\"" + hiddenMem + "\">\n" +
		"<INPUT TYPE=\"hidden\" id=\"submt\" NAME=\"submt\" VALUE=\"0\">\n" +
		"<INPUT TYPE=\"hidden\" id=\"cncel\" NAME=\"cncel\" VALUE=\"\">\n" +
		"<INPUT TYPE=\"hidden\" id=\"port_id\" NAME=\"port_id\" VALUE=\"0\">\n" +
		"<INPUT TYPE=\"hidden\" id=\"click_id\" NAME=\"click_id\" VALUE=\"0\">\n" +
		"<INPUT TYPE=\"hidden\" NAME=\"selectedPorts\" id=\"selectedPorts\" VALUE=\"\">\n" +
		"<INPUT TYPE=\"hidden\" NAME=\"ignoreMouseUp\" id=\"ignoreMouseUp\" VALUE=\"\">\n" +
		"<INPUT TYPE=\"hidden\" NAME=\"mouseX\" id=\"mouseX\" VALUE=\"\">\n" +
		"<INPUT TYPE=\"hidden\" NAME=\"mouseY\" id=\"mouseY\" VALUE=\"\">\n" +
		"<INPUT TYPE=\"hidden\" NAME=\"processedClick\" id=\"processedClick\" VALUE=\"\">\n" +
		csrf + "</FORM></body></HTML>\n"
}

// ApplyFastpathVlanMembership applies a membership POST -- but ONLY when
// submt is the apply flag. submt=0 is the VLAN <select>'s own re-render
// POST and must not mutate anything. A port set Excluded loses its CURRENT
// membership too; a port set tagged/untagged becomes a current member.
// ConfiguredOnly is cleared for a port the caller explicitly set. Mirrors
// Python web_fastpath_vlan.apply_membership.
func ApplyFastpathVlanMembership(state *State, form map[string]string) {
	if form["submt"] != fastpathVlanApplyFlag || FastpathVlanRefusal(state, form) != "" {
		return
	}
	if state.VlanMembershipPage == nil {
		return
	}
	vid := fastpathVlanShownVlan(state, form)
	vsim, ok := state.Vlans[vid]
	if !ok {
		return
	}
	codes := fastpathVlanFormCodes(form)
	portCount := state.mustModel().PortCount
	for _, port := range xePhysicalPorts(state) {
		var code string
		if port-1 < len(codes) {
			code = codes[port-1]
		}
		if code != "1" && code != "2" && code != "3" {
			continue
		}
		delete(vsim.ConfiguredOnly, port)
		switch code {
		case "3": // excluded: only participation is dropped, Untagged bit stays.
			delete(vsim.Member, port)
		case "2": // untagged
			vsim.Member[port] = true
			vsim.Untagged[port] = true
		default: // "1" tagged
			vsim.Member[port] = true
			delete(vsim.Untagged, port)
		}
	}
	// LAG slots: the mock models LAGs only as ifIndexes above the physical
	// port count, so an apply that clears a LAG slot removes that LAG.
	var lags []int
	for _, p := range sortedIntKeys(vsim.Configured()) {
		if p > portCount {
			lags = append(lags, p)
		}
	}
	base := fastpathVlanLagBase(state)
	for i, lag := range lags {
		slot := base + i
		var code string
		if slot < len(codes) {
			code = codes[slot]
		}
		if code == "3" {
			delete(vsim.Member, lag)
			delete(vsim.ConfiguredOnly, lag)
		}
	}
}
