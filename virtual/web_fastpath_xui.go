package virtual

// web_fastpath_xui.go ports src/netgear_switch/virtual/web_fastpath_xui.py
// (the normative source; that repo is read-only from here -- pin 1841111,
// branch go-port-pin-1841111). Any discrepancy between this file and that
// pin is a bug here, unless called out in a comment. See
// docs/superpowers/plans/2026-07-31-slice-06-dossier-http-readwrite-face.md
// §4 for the porting dossier this mirrors.
//
// The FASTPATH "XUI" write-form scaffolding shared by every managed model.
// Every managed page (portsConfiguration.html, poeInterfaceConfiguration.
// html, ipConfiguration.html, mgmtVlanIpv4Configuration.html) is wrapped in
// the SAME structure on real firmware, and the mock reproduces it exactly
// because each piece is load-bearing for webui.Writer/webui.ParseXUIListPage:
//
//   - TWO <FORM>s. The first, "<page>.html/a0", is the applet/redirect form
//     and carries no data; the SECOND, "<page>.html/a1", is the read+write
//     form. A parser that grabbed the first form would find nothing (see
//     webui's xuiFormRE, which matches only a "/a1" ACTION).
//   - Repeating rows are <TR p="<unit>.<row0>.<count>0"> and their fields are
//     named "<unit>.<row0>.<count>.v_1_2_<column>" -- the row index is
//     0-based and the count is the RENDERED row count, not the port count (a
//     52-port switch's PoE page has 48 rows). Each row also carries its own
//     gecb* checkbox, and the firmware applies ONLY the rows whose checkbox
//     is submitted.
//   - A trailing "redirection elements" block -- submit_flag/submit_target/
//     err_flag/err_msg/clazz_information -- and a xuiButtonsDiv holding the
//     page's buttons as DISABLED hidden inputs.
//   - An apply is submit_flag=8 (the firmware's own xui_operation_submit = 8);
//     a refusal comes back as HTTP 200 with err_flag=1 and a human err_msg.
//
// All of it live-captured 2026-07-30 from gsm7252ps 10.1.5.22, gsm7228ps
// 10.1.5.11, m4300-24x 10.1.5.13 and m4300-16x 10.1.5.20:49152.
//
// Renderer strategy: plain fmt.Sprintf/strings.Builder string composition,
// mirroring Python's own f-string functions verbatim -- NOT the embedded-
// fixture-plus-strings.NewReplacer marker style web_gs110emx.go uses.
// The normative source for THIS file (web_fastpath_xui.py, and its callers
// web_m4300.py/web_gsm7252ps.py/web_gsm7228ps.py) is itself small composable
// functions building variable-length tables, not a captured whole-page
// template with markers -- there is no fixed-shape fixture to substitute
// into. web_gs105pe.go already established this same precedent in this
// package for exactly the same reason (see its own doc comment).

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/webui"
)

// fastpathSubmitApply is the firmware's own apply flag (see the package doc
// comment), mirroring Python web_fastpath_xui.SUBMIT_APPLY.
const fastpathSubmitApply = "8"

// fastpathInstance is the row field-name prefix, WITHOUT its trailing dot,
// mirroring Python web_fastpath_xui.instance. Every caller in this package
// uses unit 1 (the only unit any of these switches ever renders), so unlike
// the Python function this Go port hardcodes it rather than threading an
// unused parameter through every call site.
func fastpathInstance(row0, count int) string {
	return fmt.Sprintf("1.%d.%d", row0, count)
}

// fastpathRow wraps cells in the real <TR p="..."> row, with its own
// checkbox. checkbox differs per firmware on real hardware (gecb5 on
// gsm7252ps's ports page, gecb10 on gsm7228ps's, gecb_1_2 on the M4300s), so
// the caller passes the one that model renders -- the writer scrapes it
// rather than constructing it, and a mock that always used one spelling
// would hide a scrape that had hard-coded another. Mirrors Python
// web_fastpath_xui.row.
func fastpathRow(inst, cells, checkbox string) string {
	return fmt.Sprintf(
		"<TR p=\"%s0\" id=1_2>\n"+
			"<td class=\"def geRight\">"+
			"<INPUT id=\"1_2_null\" type=\"checkbox\" name=\"%s.%s\" xgc ></td>\n"+
			"%s</TR>\n",
		inst, inst, checkbox, cells)
}

// The page's list-NAVIGATION block field names -- see fastpathNavRows'
// doc comment. Mirrors Python web_fastpath_xui.LIST_UNIT_FIELDS/
// LIST_TYPE_FILTER.
var fastpathListUnitFields = [...]string{"v_1_1_1", "v_1_3_1"}

const fastpathListTypeFilter = "v_1_1_2"

// fastpathNavRows renders the page's two class=deftestme list-navigation
// rows, mirroring Python web_fastpath_xui.nav_rows (unit="1",
// type_filter="^Physical$" -- the only values any caller in this package
// ever passes, so hardcoded here exactly as fastpathInstance hardcodes
// unit=1).
func fastpathNavRows() string {
	return "<TR id=1_1 class=deftestme>\n" +
		"<TD class=defright id=1_1_1><INPUT xid=1_1_1 TYPE=hidden " +
		"NAME=v_1_1_1 VALUE=\"1\"></TD>\n" +
		"<TD id=1_1_2 style=\"display:none\"><INPUT xid=1_1_2 TYPE=hidden " +
		"NAME=" + fastpathListTypeFilter + " VALUE=\"^Physical$\"></TD>\n" +
		"<td id=\"1_1_null\"><INPUT type=\"text\" " +
		"id=\"inputBox_interface_1_1_null\" name=\"inputBox_interface_1_1_null\" " +
		"SIZE=\"10\" MAXLENGTH=\"10\" VALUE=\"\"></td>\n" +
		"</TR>\n" +
		"<TR id=1_3 class=deftestme>\n" +
		"<TD class=defright id=1_3_1><INPUT xid=1_3_1 TYPE=hidden " +
		"NAME=v_1_3_1 VALUE=\"1\"></TD>\n" +
		"<td id=\"1_3_null\"><INPUT type=\"text\" " +
		"id=\"inputBox_interface_1_3_null\" name=\"inputBox_interface_1_3_null\" " +
		"SIZE=\"10\" MAXLENGTH=\"10\" VALUE=\"\"></td>\n" +
		"</TR>\n"
}

// fastpathHasListUnit reports whether this POST carries one of the page's
// urlListUnit aliases, mirroring Python web_fastpath_xui.has_list_unit.
func fastpathHasListUnit(form map[string]string) bool {
	for _, name := range fastpathListUnitFields {
		if form[name] != "" {
			return true
		}
	}
	return false
}

func fastpathHiddenInput(name, value string) string {
	return fmt.Sprintf("<INPUT TYPE=\"hidden\" NAME=\"%s\" XC=hidden VALUE=\"%s\">\n", name, value)
}

// fastpathButton is one page button: xid ("2_1_2") plus its rendered label
// ("Apply"). An ordered slice (not a map) so button HTML order is
// deterministic across runs -- Go map iteration order is randomized, which
// would make otherwise-identical renders diff-noisy for no functional
// reason (parsers key buttons by name via a regex scan, never by position).
type fastpathButton struct {
	XID   string
	Label string
}

func fastpathButtons(buttons []fastpathButton) string {
	var cells strings.Builder
	for _, b := range buttons {
		fmt.Fprintf(&cells, "<TD id=%s><INPUT xid=%s DISABLED TYPE=hidden "+
			"NAME=v_%s VALUE=\"%s\"></TD>\n", b.XID, b.XID, b.XID, b.Label)
	}
	return "<div id=\"xuiButtonsDiv\"><table><tr>\n" + cells.String() + "</tr></table></div>\n"
}

// fastpathPage renders one complete XUI page: both forms, the body, the
// redirection block and the buttons. errMsg non-empty renders the refusal
// the way the firmware does -- HTTP 200 with err_flag=1. Mirrors Python
// web_fastpath_xui.page.
func fastpathPage(path, body string, buttons []fastpathButton, errMsg, title string) string {
	name := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		name = path[idx+1:]
	}
	errFlag := "0"
	if errMsg != "" {
		errFlag = "1"
	}
	return "<HTML>\n<HEAD><TITLE>" + title + "</TITLE></HEAD>\n<BODY CLASS=page>\n" +
		"<FORM method=post ACTION=\"" + path + "/a0\">\n" +
		"<INPUT TYPE=\"hidden\" NAME=\"applet_port\" XC=hidden VALUE=\"\">\n" +
		"</FORM>\n" +
		"<FORM method=post ACTION=\"" + path + "/a1\">\n" +
		"<table>\n" +
		body +
		"</table>\n" +
		fastpathHiddenInput("submit_flag", "0") +
		fastpathHiddenInput("submit_target", name) +
		fastpathHiddenInput("err_flag", errFlag) +
		fastpathHiddenInput("err_msg", errMsg) +
		fastpathHiddenInput("clazz_information", name) +
		fastpathButtons(buttons) +
		"</FORM>\n</BODY>\n</HTML>\n"
}

// fastpathCheckedRows returns the row prefixes whose gecb checkbox the
// submitted form carries -- the whole selection rule on real hardware:
// fields for an unchecked row are ignored even when present. Mirrors Python
// web_fastpath_xui.checked_rows.
func fastpathCheckedRows(form map[string]string, checkbox string) []string {
	suffix := "." + checkbox
	var out []string
	for name := range form {
		if strings.HasSuffix(name, suffix) {
			out = append(out, name[:len(name)-len(suffix)+1])
		}
	}
	return out
}

// fastpathIsApply reports whether this POST is an APPLY (submit_flag=8)
// rather than a reload, mirroring Python web_fastpath_xui.is_apply.
func fastpathIsApply(form map[string]string) bool {
	return form["submit_flag"] == fastpathSubmitApply
}

// fastpathPressed returns which of candidates (button field names) this
// POST carries, mirroring Python web_fastpath_xui.pressed. ok=false if
// none of them are present.
func fastpathPressed(form map[string]string, candidates ...string) (string, bool) {
	for _, c := range candidates {
		if _, ok := form[c]; ok {
			return c, true
		}
	}
	return "", false
}

// --- management-IP pages ----------------------------------------------------
//
// Two shapes, one per Cheetah family; see webui.XuiMgmtIPFields for the
// measured field maps and for why they cannot share one page constant.

func fastpathLabelled(xid, label, value string) string {
	return fmt.Sprintf(
		"<TR id=%s class=deftestme>\n"+
			"<TD class=defleft id=%s>%s</TD>\n"+
			"<TD class=defright id=%s><INPUT xid=%s TYPE=hidden "+
			"NAME=v_%s VALUE=\"%s\"></TD>\n</TR>\n",
		xid, xid, label, xid, xid, xid, value)
}

// stripVPrefix removes a leading "v_" from a field name, mirroring Python's
// `.removeprefix("v_")` calls in render_mgmt_ip/apply's button-xid lookups.
func stripVPrefix(s string) string {
	return strings.TrimPrefix(s, "v_")
}

// RenderFastpathMgmtIP renders the model's management-IP page from
// state.Mgmt, mirroring Python web_fastpath_xui.render_mgmt_ip. Caller must
// have already checked spec.MgmtIPFields != nil and spec.MgmtIPPath != "".
func RenderFastpathMgmtIP(state *State, spec *webui.HTTPModelSpec, errMsg string) string {
	fields := spec.MgmtIPFields
	path := spec.MgmtIPPath
	mode := fields.StaticValue
	if state.Mgmt.Mode == "dhcp" {
		mode = fields.DHCPValue
	}
	body := fastpathLabelled(stripVPrefix(fields.Mode), "Configuration Method", mode) +
		fastpathLabelled(stripVPrefix(fields.Address), "IP Address", state.Mgmt.Address) +
		fastpathLabelled(stripVPrefix(fields.Netmask), "Subnet Mask", state.Mgmt.Netmask) +
		fastpathLabelled(stripVPrefix(fields.Gateway), "Default Gateway", state.Mgmt.Gateway)
	return fastpathPage(path, body,
		[]fastpathButton{{XID: stripVPrefix(fields.ApplyButton), Label: "APPLY"}},
		errMsg, "NETGEAR - IPv4 Network Interface Configuration")
}

// fastpathBadIPv4 reports whether text is not a well-formed dotted-quad,
// mirroring Python web_fastpath_xui._bad_ipv4.
func fastpathBadIPv4(text string) bool {
	parts := strings.Split(text, ".")
	if len(parts) != 4 {
		return true
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || p == "" || !isASCIIDigitsFastpath(p) || n < 0 || n > 255 {
			return true
		}
	}
	return false
}

func isASCIIDigitsFastpath(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ApplyFastpathMgmtIP applies a management-IP form, returning the firmware's
// err_msg ("" = ok), mirroring Python web_fastpath_xui.apply_mgmt_ip.
// Reproduces the real page's validator rather than accepting anything: the
// firmware answers a malformed address with HTTP 200 + err_flag=1 + a human
// "IP address should be in x.x.x.x form" message.
func ApplyFastpathMgmtIP(state *State, spec *webui.HTTPModelSpec, form map[string]string) string {
	fields := spec.MgmtIPFields
	if !fastpathIsApply(form) {
		return ""
	}
	for _, fl := range []struct{ field, label string }{
		{fields.Address, "IP Address"},
		{fields.Netmask, "Subnet Mask"},
		{fields.Gateway, "Default Gateway"},
	} {
		value, ok := form[fl.field]
		if ok && fastpathBadIPv4(value) {
			return fmt.Sprintf(
				"Error: Unable to set '%s' with '%s'. IP address should be in x.x.x.x form with each octet(x) in the range 0-255.",
				fl.label, value)
		}
	}
	mode, hasMode := form[fields.Mode]
	if hasMode && mode == fields.DHCPValue {
		state.Mgmt.Mode = "dhcp"
		return ""
	}
	if hasMode && mode == fields.StaticValue {
		state.Mgmt.Mode = "static"
	}
	if v, ok := form[fields.Address]; ok {
		state.Mgmt.Address = v
	}
	if v, ok := form[fields.Netmask]; ok {
		state.Mgmt.Netmask = v
	}
	if v, ok := form[fields.Gateway]; ok {
		state.Mgmt.Gateway = v
	}
	return ""
}

// ApplyFastpathPortAdmin applies portsConfiguration.html's Admin Mode
// column, honouring the per-row checkboxes. Returns the firmware err_msg
// ("" = accepted). Mirrors Python web_fastpath_xui.apply_port_admin.
func ApplyFastpathPortAdmin(state *State, form map[string]string, checkbox string, ports []int) string {
	if !fastpathIsApply(form) {
		return ""
	}
	for _, prefix := range fastpathCheckedRows(form, checkbox) {
		value, ok := form[prefix+"v_1_2_6"]
		if !ok {
			continue
		}
		if value != "Enable" && value != "Disable" {
			return fmt.Sprintf("Error! Failed to Set 'Admin <br/> Mode' with '%s'", value)
		}
		parts := strings.Split(prefix, ".")
		if len(parts) < 2 {
			continue
		}
		row0, err := strconv.Atoi(parts[1])
		if err != nil || row0 < 0 || row0 >= len(ports) {
			continue
		}
		if p, exists := state.Ports[ports[row0]]; exists {
			p.Admin = value == "Enable"
		}
	}
	return ""
}
