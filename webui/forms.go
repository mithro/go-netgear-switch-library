package webui

// Ported field-for-field from src/netgear_switch/protocols/http/forms.py at
// pin 1841111 in python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1841111). Any discrepancy between this file and that pin is a
// bug in this file, not a deliberate deviation, unless called out in a
// comment.
//
// Every write-form encoder here is pure (no I/O): it builds the POST body a
// browser would submit, given the page state a caller (the eventual
// http_write.go Writer, Part 2) already scraped. Each Plus-CGI form requires
// the page's CSRF `hash` field (scraped by the caller via ParseCSRFHash just
// before POSTing) -- forms.go never scrapes, only encodes, mirroring the
// Python source's module docstring.
//
// Covers (dossier D-HTTP-P §3):
//   - §3.1 Plus-CGI PoE (gs305ep): PoeApplyForm, PoeResetForm
//   - §3.2 Plus-CGI PVID/VLAN (gs305ep, gs105pe): PvidForm,
//     MembershipHiddenMem, MembershipForm, VlanAddForm, VlanDeleteForm,
//     RebootForm
//   - §3.3 FASTPATH VLAN Membership (NEW at 1841111): FastpathMembershipForm
//   - §3.4 FASTPATH XUI generic apply (NEW at 1841111): XuiRowApplyForm,
//     XuiFormApplyForm
//   - §3.5 GS110EMX port-admin (NEW at 1841111): GS110EMXPortAdminForm

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// plusVlanWireCode mirrors Python forms._WIRE: the Plus-CGI (8021qMembe.cgi)
// per-port hiddenMem wire code MembershipHiddenMem encodes,
// 1=Untagged/2=Tagged/3=Excluded -- the same map parse_standard.go's
// wireToMode decodes. NEVER share this with the FASTPATH VLAN-membership
// page's codes (modeToFastpathMem, parse_xe.go), which are the INVERSE.
var plusVlanWireCode = map[model.VlanMode]string{
	model.VlanUntagged: "1",
	model.VlanTagged:   "2",
	model.VlanExcluded: "3",
}

// PoeApplyForm builds the Plus-CGI PoEPortConfig.cgi "Apply" POST body,
// mirroring Python forms.poe_apply_form (source lines 24-36). portID/port{n}
// fields are 0-based (port-1). isEPX must be HTTPModelSpec.IsEPXPoE for the
// model (only true for gs305ep) -- it selects the POW_LIMT_TYP code.
func PoeApplyForm(port int, on, isEPX bool, csrfHash string) map[string]string {
	admin := "0"
	if on {
		admin = "1"
	}
	limitType := "0"
	if isEPX {
		limitType = "2"
	}
	return map[string]string{
		"ACTION":         "Apply",
		"portID":         strconv.Itoa(port - 1),
		"ADMIN_MODE":     admin,
		"PORT_PRIO":      "0",
		"POW_MOD":        "3",
		"POW_LIMT_TYP":   limitType,
		"DETEC_TYP":      "2",
		"DISCONNECT_TYP": "2",
		"hash":           csrfHash,
	}
}

// PoeResetForm builds the Plus-CGI PoEPortConfig.cgi "Reset" (power-cycle)
// POST body, mirroring Python forms.poe_reset_form (source lines 39-40).
// port{n} is 0-based (port-1).
func PoeResetForm(port int, csrfHash string) map[string]string {
	return map[string]string{
		"ACTION":                      "Reset",
		fmt.Sprintf("port%d", port-1): "checked",
		"hash":                        csrfHash,
	}
}

// PvidForm builds the Plus-CGI portPVID.cgi POST body, mirroring Python
// forms.pvid_form (source lines 43-44). port{n} is 0-based (port-1).
func PvidForm(port, vlan int, csrfHash string) map[string]string {
	return map[string]string{
		fmt.Sprintf("port%d", port-1): "checked",
		"pvid":                        strconv.Itoa(vlan),
		"hash":                        csrfHash,
	}
}

// MembershipHiddenMem builds the 8021qMembe.cgi hiddenMem wire-code string
// for ports 1..portCount, mirroring Python forms.membership_hidden_mem
// (source lines 47-50). A port with no entry in states defaults to
// model.VlanExcluded, not Untagged -- a deliberate "unmentioned means
// removed" rule.
func MembershipHiddenMem(states map[int]model.VlanMode, portCount int) string {
	var b strings.Builder
	b.Grow(portCount)
	for p := 1; p <= portCount; p++ {
		mode, ok := states[p]
		if !ok {
			mode = model.VlanExcluded
		}
		b.WriteString(plusVlanWireCode[mode])
	}
	return b.String()
}

// MembershipForm builds the Plus-CGI 8021qMembe.cgi apply POST body,
// mirroring Python forms.membership_form (source lines 53-54).
func MembershipForm(vlan int, hiddenMem, csrfHash string) map[string]string {
	return map[string]string{
		"VLAN_ID":   strconv.Itoa(vlan),
		"hiddenMem": hiddenMem,
		"hash":      csrfHash,
	}
}

// VlanAddForm builds the Plus-CGI 8021qCf.cgi "Add" POST body, mirroring
// Python forms.vlan_add_form (source lines 251-256 in the earlier §3.2
// listing).
func VlanAddForm(vlan int, csrfHash string) map[string]string {
	return map[string]string{
		"ACTION":     "Add",
		"ADD_VLANID": strconv.Itoa(vlan),
		"status":     "Enable",
		"hash":       csrfHash,
	}
}

// VlanDeleteForm builds the Plus-CGI 8021qCf.cgi "Delete" POST body,
// mirroring Python forms.vlan_delete_form. checkboxIndex is the vlanckN
// checkbox index the VLAN's row was scraped at (ParseVLANIDs does not
// preserve this -- the caller re-scrapes the page's own checkbox names).
func VlanDeleteForm(vlan, checkboxIndex int, csrfHash string) map[string]string {
	return map[string]string{
		"ACTION":                               "Delete",
		fmt.Sprintf("vlanck%d", checkboxIndex): strconv.Itoa(vlan),
		"status":                               "Enable",
		"hash":                                 csrfHash,
	}
}

// RebootForm builds the Plus-CGI device_reboot.cgi POST body, mirroring
// Python forms.reboot_form: just the CSRF hash.
func RebootForm(csrfHash string) map[string]string {
	return map[string]string{"hash": csrfHash}
}

// fastpathMemApply/fastpathMemNoop mirror Python forms._FASTPATH_MEM_APPLY/
// _FASTPATH_MEM_NOOP: the FASTPATH VLAN-Membership page's own rollover.js
// sets submt from JavaScript as `elements['submt'].value = 0x10` then
// submits -- i.e. the DECIMAL string "16" on the wire (JS stringifies the
// hex literal to its decimal text). Leaving it at "0" is what the VLAN
// <select>'s onChange handler (screen_refresh()) posts, and that is a pure
// re-render -- which is exactly why the same endpoint can be used to READ
// another VLAN's membership without applying anything.
const (
	fastpathMemApply = "16"
	fastpathMemNoop  = "0"
)

// FastpathMembershipForm builds the POST body for the FASTPATH VLAN
// Membership page (switching/dot1q/vlan_port_cfg_rw.html), mirroring Python
// forms.fastpath_membership_form (source lines 66-99, dossier §3.3).
//
// Starts from page.Fields -- every field the device itself rendered,
// verbatim -- so nothing the browser sends is dropped (the M4300-16X
// rejects a POST that omits its per-page CSRFToken with 403 Forbidden) and
// nothing is invented. Only four fields the browser's own handlers touch
// are overridden:
//
//   - vlanId -- which VLAN to show/apply (the <select>'s value).
//   - hiddenTagged/hiddenUnTagged -- CLEARED, exactly as the firmware's
//     screen_refresh()/resethidden() do before submitting. They are OUTPUT
//     fields (the device re-renders them); echoing stale values back is not
//     what the browser does.
//   - submt -- "16" to apply, "0" for a read-only re-render.
//
// hiddenMem overrides the membership codes (use FastpathHiddenMemWith,
// parse_xe.go); nil keeps what the page rendered, which is required for a
// read (posting a DIFFERENT VLAN's codes with apply=false is precisely what
// the browser does when you pick another VLAN, and the firmware ignores
// them).
func FastpathMembershipForm(page FastpathMembership, vlan int, hiddenMem *string, apply bool) map[string]string {
	body := make(map[string]string, len(page.Fields)+4)
	for k, v := range page.Fields {
		body[k] = v
	}
	body["vlanId"] = strconv.Itoa(vlan)
	body["hiddenTagged"] = ""
	body["hiddenUnTagged"] = ""
	if apply {
		body["submt"] = fastpathMemApply
	} else {
		body["submt"] = fastpathMemNoop
	}
	if hiddenMem != nil {
		body["hiddenMem"] = *hiddenMem
	}
	return body
}

// XUIOperationSubmit/XUIOperationReload mirror Python forms.
// XUI_OPERATION_SUBMIT/XUI_OPERATION_RELOAD: the firmware publishes these
// itself, in /scripts/_xeobj_jsvars.js (`xui_operation_submit = 8;
// xui_operation_reload = 1;`), and every page's per-button metadata names
// the submit flag (`xeData.xt_2_1_2 = "8"` for APPLY on
// portsConfiguration, etc.). onclickSubmit writes it into the form's
// submit_flag before submitting. NOT the same flag as the VLAN-membership
// page's separate submt field.
const (
	XUIOperationSubmit = "8"
	XUIOperationReload = "1"
)

// XuiRowApplyForm builds the POST body that applies changes to exactly ONE
// row of an XUI list page, mirroring Python forms.xui_row_apply_form
// (source lines 116-186, dossier §3.4).
//
// Only that row's fields are sent (plus its gecb checkbox, the page's
// tokens, its list-navigation block, the form's redirection block and the
// clicked button) -- deliberately NARROWER than a browser, which submits
// every row's hidden inputs and lets the firmware apply only the checked
// ones. That is a SAFETY property, not mere efficiency: a body that never
// mentions the other rows cannot change them even under a firmware bug
// that ignores checkboxes. LIVE-PROVEN on all four managed switches: after
// this exact body, re-reading the whole table showed ONLY the target row's
// cell changed, every other row byte-identical.
//
// page.Nav IS sent, and that is not decoration -- it is the difference
// between a write that lands and one the firmware refuses (the 1841111
// gsm7252ps PoE-write unlock, dossier §1.6 item 3): omitting it produced
// err_flag=1 even for a no-op write.
//
// changes is keyed by bare column ("v_1_2_6"); the row's own
// "<unit>.<row0>.<count>." prefix is prepended here so a caller can never
// address the wrong row. A column the row does not render, or a button the
// page did not render, returns an error wrapping model.ErrHTTP rather than
// being silently added -- mirroring the Python source's uncaught KeyError
// on either dict access.
//
// omit drops the named bare columns from this row's echoed fields, for the
// columns the clicked BUTTON disables (the page's own per-button "shed
// list" metadata). A column the row does not render is silently ignored
// when named in omit -- "do not send this", not "this column must exist"
// (models differ in which columns exist).
func XuiRowApplyForm(page XuiListPage, row XuiRow, changes map[string]string, button string, omit []string) (map[string]string, error) {
	body := make(map[string]string, len(page.Tokens)+len(page.Nav)+len(row.Fields)+len(page.Hidden)+4)
	for k, v := range page.Tokens {
		body[k] = v
	}
	for k, v := range page.Nav {
		body[k] = v
	}
	dropped := make(map[string]bool, len(omit))
	for _, column := range omit {
		dropped[row.Prefix+column] = true
	}
	for k, v := range row.Fields {
		if !dropped[k] {
			body[k] = v
		}
	}
	for column, value := range changes {
		name := row.Prefix + column
		if _, ok := row.Fields[name]; !ok {
			return nil, errHTTP("xui_row_apply_form: row %q does not render column %q", row.Prefix, column)
		}
		body[name] = value
	}
	if row.Checkbox != nil {
		body[*row.Checkbox] = "on"
	}
	for k, v := range page.Hidden {
		body[k] = v
	}
	body["submit_flag"] = XUIOperationSubmit
	body["err_flag"] = "0"
	body["err_msg"] = ""
	buttonValue, ok := page.Buttons[button]
	if !ok {
		return nil, errHTTP("xui_row_apply_form: page %q has no button %q", page.Action, button)
	}
	body[button] = buttonValue
	return body, nil
}

// XuiFormApplyForm builds the POST body that applies changes to an XUI
// *detail* page (flat, non-repeating fields), mirroring Python
// forms.xui_form_apply_form (source lines 189-201, dossier §3.4).
//
// Starts from every field the device rendered -- so the M4300-16X's
// per-page CSRFToken (whose absence it answers with 403 Forbidden) rides
// along without this builder having to know about it -- and overrides only
// the named fields. An unknown field, or a button the page did not render,
// returns an error wrapping model.ErrHTTP rather than being invented,
// mirroring the Python source's uncaught KeyError.
func XuiFormApplyForm(page XuiFormPage, changes map[string]string, button string) (map[string]string, error) {
	body := make(map[string]string, len(page.Fields)+len(page.Hidden)+4)
	for k, v := range page.Fields {
		body[k] = v
	}
	for name, value := range changes {
		if _, ok := page.Fields[name]; !ok {
			return nil, errHTTP("xui_form_apply_form: page %q does not render field %q", page.Action, name)
		}
		body[name] = value
	}
	for k, v := range page.Hidden {
		body[k] = v
	}
	body["submit_flag"] = XUIOperationSubmit
	body["err_flag"] = "0"
	body["err_msg"] = ""
	buttonValue, ok := page.Buttons[button]
	if !ok {
		return nil, errHTTP("xui_form_apply_form: page %q has no button %q", page.Action, button)
	}
	body[button] = buttonValue
	return body, nil
}

// emxCtrlModeAuto/emxCtrlModeDisable mirror Python forms.
// _EMX_CTRL_MODE_AUTO/_EMX_CTRL_MODE_DISABLE: the GS110EMX port_settings.html
// page has no separate enable/disable control -- its "Physical Mode" select
// is `0=(blank) 1=Auto 6=Disable`, and its own sendPortStatusForm()
// translates that selection into the triple actually POSTed:
// PHYSICAL_MODE 1 -> PORT_CTRL_MODE=1 (enabled/auto), PHYSICAL_MODE 6 ->
// PORT_CTRL_MODE=3 (disabled). Harvested from the firmware's own
// /function.js on a live GS110EMX (10.1.5.25, 2026-07-31).
const (
	emxCtrlModeAuto    = "1"
	emxCtrlModeDisable = "3"
)

// emxDHCPOn/emxDHCPOff mirror Python forms.EMX_DHCP_ON/EMX_DHCP_OFF: the
// GS110EMX sysInfo page's dhcp_mode select value -- 1 = Enable (DHCP), 2 =
// Disable (static). Read off the live page's own `<select name="dhcp_mode">`,
// whose current value the page carries as `<tr data-select-value="N">` -- the
// options themselves have no `selected` attribute, so it is the row
// attribute that says which one is in force (see webui.ParseSysInfo's
// dhcpSelectValueRE, the read-side twin of this encoding).
const (
	emxDHCPOn  = "1"
	emxDHCPOff = "2"
)

// GS110EMXSwitchInfoForm builds the GS110EMX sysInfo.html POST body -- the
// WHOLE form, per the page's own submitSwitchInfoForm() JS (read from the
// live switch's /function.js, 2026-08-05), mirroring Python
// forms.gs110emx_switch_info_form (source lines 285-328).
//
// EVERY OTHER FIELD MUST BE ECHOED FROM THE PAGE: this one form carries the
// management addressing as well as the name, so a caller who omits or
// guesses dhcpMode/ipAddress/subnetMask/gatewayAddress does not merely fail
// to rename the switch -- it reconfigures the address it is talking to and
// strands the device. That is why this builder takes all of them and has no
// defaults.
//
// The Gambit session token is added by the transport, as for every other
// request on this model.
func GS110EMXSwitchInfoForm(switchName, dhcpMode, ipAddress, subnetMask, gatewayAddress string) map[string]string {
	return map[string]string{
		"switch_name": switchName,
		"dhcp_mode":   dhcpMode,
		// The page's checkbox, disabled unless DHCP is being turned on; "0"
		// is its value in the served markup and means "do not re-request a
		// lease". Sending "1" would make the switch renew and possibly move.
		"refresh":         "0",
		"IP_ADDRESS":      ipAddress,
		"SUBNET_MASK":     subnetMask,
		"GATEWAY_ADDRESS": gatewayAddress,
		"refreshFlag":     "0",
		"errMsg":          "",
		"ACTION":          "Apply",
	}
}

// GS110EMXPortAdminForm builds the GS110EMX port_settings.html admin-mode
// POST body, mirroring Python forms.gs110emx_port_admin_form (source lines
// 268-289, dossier §3.5). The Gambit session token is added by the
// TRANSPORT layer, not by this encoder -- consistent with every other POST
// on this model.
//
// flowControlMode must be ECHOED from the port's own current row (see
// ParseGS110EMXPortFormFields), never defaulted -- the page always sends
// it, so omitting it (or guessing) would rewrite the port's flow control as
// a side effect of an admin-mode change.
func GS110EMXPortAdminForm(port int, enabled bool, flowControlMode string) map[string]string {
	ctrlMode := emxCtrlModeDisable
	if enabled {
		ctrlMode = emxCtrlModeAuto
	}
	return map[string]string{
		// SEMICOLON-TERMINATED, not a bare number: the page's own
		// saveSelectedPorts() builds "selectedPorts" as "<n>;" per checked
		// row and POSTs that string as PORT_NO. A bare "3" is accepted with
		// HTTP 200 and applies NOTHING -- caught live on 10.1.5.25 by the
		// verify-after-write, which is exactly what that check is for.
		"PORT_NO":           fmt.Sprintf("%d;", port),
		"PORT_CTRL_MODE":    ctrlMode,
		"PORT_CTRL_DUPLEX":  "0",
		"PORT_CTRL_SPEED":   "0",
		"FLOW_CONTROL_MODE": flowControlMode,
		"ACTION":            "apply",
	}
}
