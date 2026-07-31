package webui_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// TestPoeApplyFormGroundedFields pins webui.PoeApplyForm against
// test_forms.py::test_poe_apply_form_grounded_fields, including the 0-based
// portID and the is_epx-selected POW_LIMT_TYP code.
func TestPoeApplyFormGroundedFields(t *testing.T) {
	f := webui.PoeApplyForm(2, true, true, "h")
	want := map[string]string{
		"ACTION":         "Apply",
		"portID":         "1",
		"ADMIN_MODE":     "1",
		"PORT_PRIO":      "0",
		"POW_MOD":        "3",
		"POW_LIMT_TYP":   "2",
		"DETEC_TYP":      "2",
		"DISCONNECT_TYP": "2",
		"hash":           "h",
	}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("PoeApplyForm()[%q] = %q, want %q", k, f[k], v)
		}
	}
	off := webui.PoeApplyForm(2, false, false, "h")
	if off["ADMIN_MODE"] != "0" {
		t.Errorf("ADMIN_MODE = %q, want \"0\"", off["ADMIN_MODE"])
	}
	if off["POW_LIMT_TYP"] != "0" {
		t.Errorf("POW_LIMT_TYP = %q, want \"0\" (non-EPx)", off["POW_LIMT_TYP"])
	}
}

// TestPoeResetForm pins webui.PoeResetForm against test_forms.py::
// test_poe_reset_form.
func TestPoeResetForm(t *testing.T) {
	f := webui.PoeResetForm(3, "h")
	if f["ACTION"] != "Reset" {
		t.Errorf("ACTION = %q, want \"Reset\"", f["ACTION"])
	}
	if f["port2"] != "checked" {
		t.Errorf("port2 = %q, want \"checked\"", f["port2"])
	}
	if f["hash"] != "h" {
		t.Errorf("hash = %q, want \"h\"", f["hash"])
	}
}

// TestPvidForm pins webui.PvidForm against test_forms.py::test_pvid_form.
func TestPvidForm(t *testing.T) {
	f := webui.PvidForm(2, 90, "h")
	if f["port1"] != "checked" {
		t.Errorf("port1 = %q, want \"checked\"", f["port1"])
	}
	if f["pvid"] != "90" {
		t.Errorf("pvid = %q, want \"90\"", f["pvid"])
	}
}

// TestMembershipHiddenMemEncodesWireCodes pins webui.MembershipHiddenMem
// against test_forms.py::test_membership_hidden_mem_encodes_wire_codes:
// ports not listed default to Excluded (3).
func TestMembershipHiddenMemEncodesWireCodes(t *testing.T) {
	states := map[int]model.VlanMode{
		1: model.VlanTagged,
		2: model.VlanUntagged,
		5: model.VlanExcluded,
	}
	got := webui.MembershipHiddenMem(states, 5)
	if got != "21333" {
		t.Errorf("MembershipHiddenMem() = %q, want \"21333\"", got)
	}
}

// TestMembershipFormGroundedFields pins webui.MembershipForm against
// test_forms.py::test_membership_form_grounded_fields.
func TestMembershipFormGroundedFields(t *testing.T) {
	f := webui.MembershipForm(90, "12333", "h")
	if f["VLAN_ID"] != "90" || f["hiddenMem"] != "12333" || f["hash"] != "h" {
		t.Errorf("MembershipForm() = %v, want VLAN_ID=90 hiddenMem=12333 hash=h", f)
	}
}

// TestVlanAddDeleteAndReboot pins webui.VlanAddForm/VlanDeleteForm/
// RebootForm against test_forms.py::test_vlan_add_and_delete_and_reboot.
func TestVlanAddDeleteAndReboot(t *testing.T) {
	if got := webui.VlanAddForm(90, "h")["ADD_VLANID"]; got != "90" {
		t.Errorf("VlanAddForm()[ADD_VLANID] = %q, want \"90\"", got)
	}
	d := webui.VlanDeleteForm(90, 1, "h")
	if d["ACTION"] != "Delete" {
		t.Errorf("VlanDeleteForm()[ACTION] = %q, want \"Delete\"", d["ACTION"])
	}
	if d["vlanck1"] != "90" {
		t.Errorf("VlanDeleteForm()[vlanck1] = %q, want \"90\"", d["vlanck1"])
	}
	got := webui.RebootForm("h")
	if len(got) != 1 || got["hash"] != "h" {
		t.Errorf("RebootForm() = %v, want {\"hash\": \"h\"}", got)
	}
}

// --- FASTPATH VLAN Membership form (NEW at 1841111) -------------------------

// TestReadFormNeverCarriesTheApplyFlag pins webui.FastpathMembershipForm
// against test_http_vlan_membership.py::test_read_form_never_carries_the_
// apply_flag: a read (apply=false) posts submt=0, clears the two output
// ifName lists and leaves hiddenMem unchanged.
func TestReadFormNeverCarriesTheApplyFlag(t *testing.T) {
	page, err := webui.ParseFastpathMembership(readFixture(t, "gsm7252ps_vlanPortCfg_vlan1.html"))
	if err != nil {
		t.Fatalf("ParseFastpathMembership() error = %v", err)
	}
	body := webui.FastpathMembershipForm(page, 141, nil, false)
	if body["submt"] != "0" {
		t.Errorf("submt = %q, want \"0\"", body["submt"])
	}
	if body["vlanId"] != "141" {
		t.Errorf("vlanId = %q, want \"141\"", body["vlanId"])
	}
	if body["hiddenTagged"] != "" || body["hiddenUnTagged"] != "" {
		t.Errorf("hiddenTagged/hiddenUnTagged = %q/%q, want both \"\"", body["hiddenTagged"], body["hiddenUnTagged"])
	}
	if body["hiddenMem"] != page.HiddenMem {
		t.Errorf("hiddenMem = %q, want page.HiddenMem unchanged for a read", body["hiddenMem"])
	}
}

// TestApplyFormCarriesEveryFieldThePageRendered pins webui.
// FastpathMembershipForm against test_http_vlan_membership.py::
// test_apply_form_carries_every_field_the_page_rendered: the M4300-16X
// answers 403 to a POST that drops its per-page CSRFToken, so the form must
// echo every field the page rendered.
func TestApplyFormCarriesEveryFieldThePageRendered(t *testing.T) {
	page, err := webui.ParseFastpathMembership(readFixture(t, "m4300_16x_vlanportcfg_vlan4.html"))
	if err != nil {
		t.Fatalf("ParseFastpathMembership() error = %v", err)
	}
	body := webui.FastpathMembershipForm(page, 4, &page.HiddenMem, true)
	if body["submt"] != "16" {
		t.Errorf("submt = %q, want \"16\"", body["submt"])
	}
	if body["CSRFToken"] != page.Fields["CSRFToken"] {
		t.Errorf("CSRFToken = %q, want %q", body["CSRFToken"], page.Fields["CSRFToken"])
	}
	for name := range page.Fields {
		if _, ok := body[name]; !ok {
			t.Errorf("body missing field %q the page rendered", name)
		}
	}
}

// --- FASTPATH XUI generic apply (NEW at 1841111) ----------------------------

// TestXuiRowApplyFormRefusesAColumnTheRowDoesNotRender pins
// webui.XuiRowApplyForm against test_http_xui_writes.py::
// test_xui_row_apply_form_refuses_a_column_the_row_does_not_render.
func TestXuiRowApplyFormRefusesAColumnTheRowDoesNotRender(t *testing.T) {
	page, err := webui.ParseXUIListPage(readFixture(t, "gsm7252ps_portsConfiguration.html"), "")
	if err != nil {
		t.Fatalf("ParseXUIListPage() error = %v", err)
	}
	_, err = webui.XuiRowApplyForm(page, page.Rows[0], map[string]string{"v_1_2_99": "x"}, "v_2_1_2", nil)
	if !errors.Is(err, model.ErrHTTP) {
		t.Fatalf("error = %v, want model.ErrHTTP", err)
	}
	if got := err.Error(); !strings.Contains(got, "v_1_2_99") {
		t.Errorf("error = %q, want it to name the missing column v_1_2_99", got)
	}
}

// TestXuiRowApplyFormCarriesOnlyTheTargetRow pins webui.XuiRowApplyForm
// against test_http_xui_writes.py::
// test_xui_row_apply_form_carries_only_the_target_row: only the target
// row's fields (plus its checkbox, tokens, nav, hidden and the clicked
// button) are sent, and no other row is mentioned at all.
func TestXuiRowApplyFormCarriesOnlyTheTargetRow(t *testing.T) {
	page, err := webui.ParseXUIListPage(readFixture(t, "gsm7252ps_portsConfiguration.html"), "")
	if err != nil {
		t.Fatalf("ParseXUIListPage() error = %v", err)
	}
	body, err := webui.XuiRowApplyForm(page, page.Rows[35], map[string]string{"v_1_2_6": "Disable"}, "v_2_1_2", nil)
	if err != nil {
		t.Fatalf("XuiRowApplyForm() error = %v", err)
	}
	if body["1.35.52.v_1_2_6"] != "Disable" {
		t.Errorf("1.35.52.v_1_2_6 = %q, want \"Disable\"", body["1.35.52.v_1_2_6"])
	}
	if body["1.35.52.gecb5"] != "on" {
		t.Errorf("1.35.52.gecb5 = %q, want \"on\"", body["1.35.52.gecb5"])
	}
	if body["submit_flag"] != "8" {
		t.Errorf("submit_flag = %q, want \"8\"", body["submit_flag"])
	}
	if body["v_2_1_2"] != "APPLY" {
		t.Errorf("v_2_1_2 = %q, want \"APPLY\"", body["v_2_1_2"])
	}
	for k := range body {
		if strings.HasPrefix(k, "1.") && !strings.HasPrefix(k, "1.35.") {
			t.Errorf("body mentions a foreign row field %q", k)
		}
	}
}

// TestXuiFormApplyFormEchoesThePagesCSRFToken pins webui.XuiFormApplyForm
// against test_http_xui_writes.py::
// test_xui_form_apply_form_echoes_the_pages_csrf_token.
func TestXuiFormApplyFormEchoesThePagesCSRFToken(t *testing.T) {
	page, err := webui.ParseXUIFormPage(readFixture(t, "m4300_16x_mgmtVlanIpv4Configuration.html"), "")
	if err != nil {
		t.Fatalf("ParseXUIFormPage() error = %v", err)
	}
	body, err := webui.XuiFormApplyForm(page, map[string]string{"v_1_6_1": "10.0.0.9"}, "v_3_1_1")
	if err != nil {
		t.Fatalf("XuiFormApplyForm() error = %v", err)
	}
	if body["CSRFToken"] != page.Fields["CSRFToken"] {
		t.Errorf("CSRFToken = %q, want %q", body["CSRFToken"], page.Fields["CSRFToken"])
	}
	if body["v_1_6_1"] != "10.0.0.9" {
		t.Errorf("v_1_6_1 = %q, want \"10.0.0.9\"", body["v_1_6_1"])
	}
	if body["submit_flag"] != "8" {
		t.Errorf("submit_flag = %q, want \"8\"", body["submit_flag"])
	}
	if body["v_3_1_1"] != "Apply" {
		t.Errorf("v_3_1_1 = %q, want \"Apply\"", body["v_3_1_1"])
	}
}

// TestXuiFormApplyFormRefusesAnUnknownButton exercises the "page has no
// button" error path, mirroring the Python source's uncaught KeyError on
// `page.buttons[button]`.
func TestXuiFormApplyFormRefusesAnUnknownButton(t *testing.T) {
	page, err := webui.ParseXUIFormPage(readFixture(t, "gsm7228ps_ipConfiguration.html"), "")
	if err != nil {
		t.Fatalf("ParseXUIFormPage() error = %v", err)
	}
	_, err = webui.XuiFormApplyForm(page, nil, "v_9_9_9")
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want model.ErrHTTP", err)
	}
}

// --- GS110EMX port-admin form (NEW at 1841111) ------------------------------

// TestGS110EMXPortNoMustBeSemicolonTerminated pins
// webui.GS110EMXPortAdminForm against test_http_xui_writes.py::
// test_gs110emx_port_no_must_be_semicolon_terminated.
func TestGS110EMXPortNoMustBeSemicolonTerminated(t *testing.T) {
	body := webui.GS110EMXPortAdminForm(3, false, "4")
	if body["PORT_NO"] != "3;" {
		t.Errorf("PORT_NO = %q, want \"3;\"", body["PORT_NO"])
	}
	if body["PORT_CTRL_MODE"] != "3" {
		t.Errorf("PORT_CTRL_MODE = %q, want \"3\" (disabled)", body["PORT_CTRL_MODE"])
	}
	if body["FLOW_CONTROL_MODE"] != "4" {
		t.Errorf("FLOW_CONTROL_MODE = %q, want echoed \"4\"", body["FLOW_CONTROL_MODE"])
	}
	enabled := webui.GS110EMXPortAdminForm(3, true, "4")
	if enabled["PORT_CTRL_MODE"] != "1" {
		t.Errorf("PORT_CTRL_MODE = %q, want \"1\" (auto/enabled)", enabled["PORT_CTRL_MODE"])
	}
	if enabled["ACTION"] != "apply" {
		t.Errorf("ACTION = %q, want \"apply\"", enabled["ACTION"])
	}
}
