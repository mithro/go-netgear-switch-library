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

// --- userManagement.html ------------------------------------------------
//
// The login-account grid. LIVE-CAPTURED 2026-08-03 from gsm7252ps 10.1.5.22
// and m4300-24x 10.1.5.13; column labels are those pages' own header
// cells. Mirrors Python web_fastpath_xui.py's _USER_HEADERS/render_users
// (source lines 321-363).
//
// The password columns are rendered because the real pages render them,
// and rendering what the device renders is the point -- but note WHAT they
// hold: gsm7252ps emits a literal "********" and the M4300 emits "", so
// neither page discloses anything, and a reader that tried to report a
// password would find only asterisks. This mock reproduces the gsm7252ps
// spelling on every model, exactly as the Python source does.
var xuiUserHeaders = []xeHeaderCol{
	{"1_1_2", "User Name"},
	{"1_1_13", "Edit Password"},
	{"1_1_3", "Password"},
	{"1_1_4", "Confirm   Password"},
	{"1_1_5", "Access   Mode"},
	{"1_1_6", "Lockout   Status"},
	{"1_1_7", "Password   Expiration   Date"},
}

// RenderXUIUsers renders userManagement.html from state.Users, mirroring
// Python web_fastpath_xui.render_users. Shared by both managed dialects
// (gsm7252ps and the M4300s): userManagement.html's row-grid coordinates
// are identical on both live-captured pages (webui.ParseXUIUsers's
// xuiUserNameCoord/xuiUserAccessModeCoord), so one renderer serves both,
// exactly as one parser reads both. A model whose State.Users is empty
// (m4300-16x/gsm7228ps -- unmeasured, see SeedM4300_16X/SeedGSM7228PS)
// renders a header-only page with zero data rows, which webui.ParseXUIUsers
// then honestly refuses ("no user rows on page") rather than this mock
// fabricating accounts it was never seeded with.
func RenderXUIUsers(state *State, path string) string {
	var body strings.Builder
	body.WriteString("<TR>\n")
	body.WriteString(xeHeader(xuiUserHeaders))
	body.WriteString("</TR>\n")
	count := len(state.Users)
	for row0, u := range state.Users {
		inst := fastpathInstance(row0, count)
		body.WriteString("<TR>\n")
		body.WriteString(xeCell(inst, "1_1_1", strconv.Itoa(row0)))
		body.WriteString(xeCell(inst, "1_1_2", u.Name))
		body.WriteString(xeCell(inst, "1_1_13", "Disable"))
		body.WriteString(xeCell(inst, "1_1_3", "********"))
		body.WriteString(xeCell(inst, "1_1_4", "********"))
		// Verbatim from state: this page's wording is NOT the CLI's.
		body.WriteString(xeCell(inst, "1_1_5", u.HTTPAccessMode))
		body.WriteString(xeCell(inst, "1_1_6", "FALSE"))
		body.WriteString(xeCell(inst, "1_1_7", ""))
		body.WriteString("</TR>\n")
	}
	return fastpathPage(path, body.String(),
		[]fastpathButton{{XID: "3_1_1", Label: "CANCEL"}, {XID: "3_2_1", Label: "APPLY"}},
		"", "NetGear - User Management")
}

// --- management-service pages --------------------------------------------
//
// Two shapes, MIXED WITHIN A MODEL -- measured 2026-08-03, see
// webui.serviceFieldsTable for the full map. gsm7252ps renders all four as
// XUI; m4300 renders http/https as a plain named form and ssh/telnet as
// XUI. This mock reproduces that split rather than picking one, because a
// fake that served only XUI would let a parser that had never learned the
// plain form pass. Mirrors Python web_fastpath_xui.py's
// _SERVICE_XUI_COORDS/_SERVICE_FORM_FIELDS/render_service_xui/
// render_service_form (source lines 244-308).

// xeServiceXUICoord is the XUI admin coordinate for one service, and the
// port coordinate where the real page prints one ("" = telnet's page
// prints NO port on either switch -- the CLI reports it, the page does
// not, so this mock must not invent one).
type xeServiceXUICoord struct {
	Admin string
	Port  string
}

var xeServiceXUICoords = map[string]xeServiceXUICoord{
	"http":   {Admin: "1_1_1", Port: ""},
	"https":  {Admin: "1_1_1", Port: "1_4_1"},
	"ssh":    {Admin: "1_1_1", Port: "1_10_1"},
	"telnet": {Admin: "2_5_1", Port: ""},
}

// xeServiceFormField is the plain-form radio group and port input name for
// one service (only http/https have a measured plain-form page).
type xeServiceFormField struct {
	Radio    string
	PortName string
}

var xeServiceFormFields = map[string]xeServiceFormField{
	"http":  {Radio: "httpAdmin", PortName: "httpPort"},
	"https": {Radio: "sslAdmin", PortName: "httpsPort"},
}

// RenderXUIServicePage renders one service's config page in the XUI
// labelled-scalar shape, mirroring Python render_service_xui. sim.CLIPort
// is deliberately never consulted here: it is CLI-only state, extending
// beyond Python's own ServiceSim -- see ServiceSim's doc comment.
func RenderXUIServicePage(state *State, path, service string) string {
	sim := state.Services[service]
	coord := xeServiceXUICoords[service]
	body := fastpathLabelled(coord.Admin, strings.ToUpper(service)+" Admin Mode", enableWordShort(sim.Enabled))
	if coord.Port != "" && sim.Port != nil {
		body += fastpathLabelled(coord.Port, strings.ToUpper(service)+" Port", strconv.Itoa(*sim.Port))
	}
	return fastpathPage(path, body,
		[]fastpathButton{{XID: "4_5_1", Label: "CANCEL"}, {XID: "4_5_2", Label: "APPLY"}},
		"", "NetGear - "+strings.ToUpper(service)+" Configuration")
}

// RenderFormServicePage renders one service's config page in the PLAIN
// NAMED FORM shape (the M4300's http/https pages), mirroring Python
// render_service_form.
//
// Reproduces the firmware's double-checked radio group verbatim: BOTH
// radios carry a checked attribute, spelled `checked="checked"` on the
// first and a bare uppercase `CHECKED` on the second, and a browser takes
// the LAST. A mock that marked only the true one would let a first-match
// parser pass here and then misreport every real switch -- see
// webui.checkedRadio's doc comment for the same trap on the reader side.
func RenderFormServicePage(state *State, path, service string) string {
	sim := state.Services[service]
	fields := xeServiceFormFields[service]
	selected := enableWordShort(sim.Enabled)
	other := enableWordShort(!sim.Enabled)
	radios := fmt.Sprintf(
		"<INPUT type=\"radio\" name=\"%s\" id=\"%s%s\" value=\"%s\" checked=\"checked\" disabled=\"disabled\" >\n"+
			"<INPUT type=\"radio\" name=\"%s\" id=\"%s%s\" value=\"%s\" disabled=\"disabled\" CHECKED>\n",
		fields.Radio, fields.Radio, other, other,
		fields.Radio, fields.Radio, selected, selected)
	port := ""
	if sim.Port != nil {
		port = fmt.Sprintf(
			"<INPUT TYPE=\"TEXT\" class=\"input\" id=\"%s\" name=\"%s\" SIZE=\"17\" MAXLENGTH=\"5\" VALUE=\"%d\">\n",
			fields.PortName, fields.PortName, *sim.Port)
	}
	return "<HTML>\n<HEAD><TITLE>NETGEAR</TITLE></HEAD>\n<BODY CLASS=page>\n" +
		"<FORM method=post ACTION=\"" + path + "\">\n" + radios + port +
		"<INPUT TYPE=\"hidden\" id=\"submt\" NAME=\"submt\" VALUE=\"\">\n" +
		"<INPUT TYPE=\"hidden\" NAME=\"err_flag\" VALUE=\"0\">\n" +
		"</FORM>\n</BODY>\n</HTML>\n"
}

// --- syslogConfiguration.html --------------------------------------------
//
// One page shape for every managed model. LIVE-CAPTURED 2026-08-03 from all
// four (gsm7252ps 10.1.5.22, gsm7228ps 10.1.5.11, m4300-24x 10.1.5.13,
// m4300-16x 10.1.5.20): the two families differ only in extras -- the
// M4300s add Cheetah "<!-- baselogCfg_* -->" comments and two scalars the
// GSMs lack -- while every coordinate webui.ParseXUISyslog reads is
// identical, which is why one renderer serves all four.
//
// The blank g_2_1_* TEMPLATE row is rendered ON PURPOSE. Real firmware
// emits it above the data rows, its fields named v_g_2_1_N with NO instance
// prefix, and a parser that mistook it for a collector would report a
// phantom row with an empty host. Leaving it out of the mock would make
// that bug untestable.

// syslogHeaders is syslogConfiguration.html's per-collector-row column
// header set, mirroring Python web_fastpath_xui._SYSLOG_HEADERS. Order
// matters (see fastpathButton's doc comment for why this package always
// uses an ordered slice, not a map, for rendered HTML).
var syslogHeaders = []xeHeaderCol{
	{"2_1_7", "IP Address Type"},
	{"2_1_1", "Host Address"},
	{"2_1_2", "Status"},
	{"2_1_3", "Port"},
	{"2_1_4", "Severity Filter"},
}

// syslogTemplateCols is the template row's cells, in the SAME order the
// live page renders them ("2_1_6", then syslogHeaders in order), mirroring
// Python's `("2_1_6", *_SYSLOG_HEADERS)`.
var syslogTemplateCols = []string{"2_1_6", "2_1_7", "2_1_1", "2_1_2", "2_1_3", "2_1_4"}

// syslogSeverityWords is the severity WORD the web UI prints for each
// standard number -- the inverse of model.SyslogSeverityNames, Title-cased
// as the pages render it ("Info" on all four switches, where SNMP's column
// reads 6). Written out rather than derived, so the mock is an INDEPENDENT
// source: a renderer that inverted the reader's own table could only ever
// agree with it. Mirrors Python web_fastpath_xui._SYSLOG_SEVERITY_WORDS.
var syslogSeverityWords = map[int]string{
	0: "Emergency",
	1: "Alert",
	2: "Critical",
	3: "Error",
	4: "Warning",
	5: "Notice",
	6: "Info",
	7: "Debug",
}

// fastpathXUICell renders one data cell of an XUI row grid, shaped as the
// live syslogConfiguration.html/userManagement.html pages emit it,
// mirroring Python web_fastpath_xui._xui_cell. text=false renders the
// value into the hidden input only, not as visible cell text -- what the
// real pages do for their action/index columns and for the Severity Filter
// cell.
func fastpathXUICell(inst, xid, value string, text bool) string {
	shown := ""
	if text {
		shown = value
	}
	return fmt.Sprintf(
		"<TD class=\"def alt0\" p=\"1.0.10\" id=%s><INPUT xid=%s TYPE=hidden NAME=%s.v_%s VALUE=\"%s\">%s</TD>\n",
		xid, xid, inst, xid, value, shown)
}

// RenderXUISyslog renders syslogConfiguration.html from state.Syslog,
// mirroring Python web_fastpath_xui.render_syslog. Counters (Messages
// Received/Relayed/Ignored) are rendered as the live pages do but are NOT
// part of model.SyslogConfig; they exist so the page the mock serves has
// the same field set as the real one.
func RenderXUISyslog(state *State, path string) string {
	sim := state.Syslog
	adminWord := "Disable"
	if sim.AdminMode == 1 {
		adminWord = "Enable"
	}

	var body strings.Builder
	body.WriteString(fastpathLabelled("1_1_1", "Admin Status", adminWord))
	body.WriteString(fastpathLabelled("1_2_1", "Local UDP Port", strconv.Itoa(sim.LocalPort)))
	body.WriteString(fastpathLabelled("1_3_1", "Messages Received", "9583"))
	body.WriteString(fastpathLabelled("1_5_1", "Messages Relayed", "15"))
	body.WriteString(fastpathLabelled("1_4_1", "Messages Ignored", "0"))
	body.WriteString("<TR>\n")
	body.WriteString(xeHeader(syslogHeaders))
	body.WriteString("</TR>\n")
	// The template row: instance-less field names, so it is not a data row.
	body.WriteString("<TR id=g_2_1>\n")
	for _, xid := range syslogTemplateCols {
		fmt.Fprintf(&body, "<TD><INPUT xid=g_%s TYPE=hidden NAME=v_g_%s VALUE=\"\"></TD>\n", xid, xid)
	}
	// VALUE="" -- the real page renders every template cell empty. "Add" is
	// the element LABEL, not the input's value, and a mock that pre-filled
	// it would let a writer that forgot to set the row-status pass.
	body.WriteString("<TD style=\"display:none\"><INPUT xid=g_2_1_5 TYPE=hidden NAME=v_g_2_1_5 VALUE=\"\"></TD>\n")
	body.WriteString("</TR>\n")

	count := len(sim.Collectors)
	for row0, c := range sim.Collectors {
		inst := fastpathInstance(row0, count)
		status := ""
		if c.Status == 1 {
			status = "Active"
		}
		// The REAL row shape: <TR p="..."> plus the row's own gecb
		// checkbox. It used to be a bare <TR>, which webui.ParseXUIListPage
		// skips entirely -- so the page read fine through ParseXERows
		// while offering the WRITER no rows at all to address.
		fmt.Fprintf(&body, "<TR p=\"%s0\" id=2_1>\n"+
			"<td class=\"def alt0 geRight\"><INPUT id=\"2_1_null\" type=\"checkbox\" name=\"%s.gecb_2_1\" xgc ></td>\n",
			inst, inst)
		body.WriteString(fastpathXUICell(inst, "2_1_6", strconv.Itoa(c.Index), false))
		body.WriteString(fastpathXUICell(inst, "2_1_7", "IPv4", true))
		body.WriteString(fastpathXUICell(inst, "2_1_1", c.Host, true))
		body.WriteString(fastpathXUICell(inst, "2_1_2", status, true))
		body.WriteString(fastpathXUICell(inst, "2_1_3", strconv.Itoa(c.Port), true))
		body.WriteString(fastpathXUICell(inst, "2_1_4", syslogSeverityWords[c.Severity], false))
		// Empty, as the live row is: 2_1_5 is WRITE-only, so the page
		// renders no value in it (2_1_2 is the readable "Active" mirror).
		body.WriteString(fastpathXUICell(inst, "2_1_5", "", false))
		body.WriteString("</TR>\n")
	}

	return fastpathPage(path, body.String(),
		[]fastpathButton{
			{XID: "4_1_1", Label: "Add"},
			{XID: "4_3_1", Label: "Delete"},
			{XID: "4_4_1", Label: "Cancel"},
			{XID: "4_2_1", Label: "Apply"},
		},
		"", "NetGear - Syslog Configuration")
}
