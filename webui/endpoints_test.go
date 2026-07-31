package webui_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// TestLoginSchemeValues pins all 5 LoginScheme members verbatim against
// protocols/http/endpoints.py::LoginScheme.
func TestLoginSchemeValues(t *testing.T) {
	cases := []struct {
		got  webui.LoginScheme
		want string
	}{
		{webui.LoginSchemeMergeHashCGI, "merge_hash_cgi"},
		{webui.LoginSchemeGambit, "gambit"},
		{webui.LoginSchemeCheetahForm, "cheetah_form"},
		{webui.LoginSchemeCheetahV1, "cheetah_v1"},
		{webui.LoginSchemeXMLAPI, "xml_api"},
	}
	seen := map[webui.LoginScheme]bool{}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("LoginScheme = %q, want %q", c.got, c.want)
		}
		seen[c.got] = true
	}
	if len(seen) != 5 {
		t.Errorf("got %d distinct LoginScheme values, want 5", len(seen))
	}
}

// TestHTMLDialectValues pins all 7 HTMLDialect members verbatim against
// protocols/http/endpoints.py::HTMLDialect. The source defines 7 members
// (STANDARD, GS110EMX, GS105PE, M4300, XE_FASTPATH, S3300, GOAHEAD_XML) --
// the dossier's "6 values" section header undercounts its own S3300 entry.
func TestHTMLDialectValues(t *testing.T) {
	cases := []struct {
		got  webui.HTMLDialect
		want string
	}{
		{webui.HTMLDialectStandard, "standard"},
		{webui.HTMLDialectGS110EMX, "gs110emx"},
		{webui.HTMLDialectGS105PE, "gs105pe"},
		{webui.HTMLDialectM4300, "m4300"},
		{webui.HTMLDialectXEFastpath, "xe_fastpath"},
		{webui.HTMLDialectS3300, "s3300"},
		{webui.HTMLDialectGoAheadXML, "goahead_xml"},
	}
	seen := map[webui.HTMLDialect]bool{}
	for _, c := range cases {
		if string(c.got) != c.want {
			t.Errorf("HTMLDialect = %q, want %q", c.got, c.want)
		}
		seen[c.got] = true
	}
	if len(seen) != 7 {
		t.Errorf("got %d distinct HTMLDialect values, want 7", len(seen))
	}
}

// TestEveryHTTPModelHasASpec mirrors test_endpoints.py::
// test_every_http_model_has_a_spec: every registry model carrying
// BackendHTTP must resolve through HTTPSpec without error.
func TestEveryHTTPModelHasASpec(t *testing.T) {
	for _, m := range model.Models() {
		if !m.HasBackend(model.BackendHTTP) {
			continue
		}
		if _, err := webui.HTTPSpec(m); err != nil {
			t.Errorf("model %q has HTTP backend but HTTPSpec failed: %v", m.Key, err)
		}
	}
}

// TestHTTPSpecRejectsModelWithoutHTTPBackend mirrors test_endpoints.py::
// test_http_spec_rejects_model_without_http_backend.
func TestHTTPSpecRejectsModelWithoutHTTPBackend(t *testing.T) {
	var snmpOnly []*model.SwitchModel
	for _, m := range model.Models() {
		if !m.HasBackend(model.BackendHTTP) {
			snmpOnly = append(snmpOnly, m)
		}
	}
	if len(snmpOnly) == 0 {
		t.Fatal("registry has no SNMP-only model left to check")
	}
	for _, m := range snmpOnly {
		spec, err := webui.HTTPSpec(m)
		if err == nil {
			t.Errorf("HTTPSpec(%q) = %+v, nil, want an error", m.Key, spec)
			continue
		}
		if !errors.Is(err, model.ErrUnsupportedCapability) {
			t.Errorf("HTTPSpec(%q) error = %v, want errors.Is(..., model.ErrUnsupportedCapability)", m.Key, err)
		}
	}
}

// TestHTTPSpecsKeysAreCanonical confirms HTTPSpecs is keyed by canonical
// model_key only -- "s3300" (the gsm7228ps alias) must NOT appear as its
// own key, mirroring Python's _SPECS/HTTP_SPECS (aliases resolve only
// inside get_model/GetModel, never as their own registry entry).
func TestHTTPSpecsKeysAreCanonical(t *testing.T) {
	if _, ok := webui.HTTPSpecs["s3300"]; ok {
		t.Error(`HTTPSpecs["s3300"] exists; the alias must resolve via model.GetModel, not appear as its own key`)
	}
	want := map[string]bool{
		"gs305ep": true, "gs110emx": true, "gsm7228ps": true, "gs105pe": true,
		"m4300-24x": true, "m4300-16x": true, "gsm7252ps": true, "gs728tpp": true,
	}
	if len(webui.HTTPSpecs) != len(want) {
		t.Errorf("len(HTTPSpecs) = %d, want %d", len(webui.HTTPSpecs), len(want))
	}
	for k, spec := range webui.HTTPSpecs {
		if !want[k] {
			t.Errorf("unexpected HTTPSpecs key %q", k)
		}
		if spec.ModelKey != k {
			t.Errorf("HTTPSpecs[%q].ModelKey = %q, want %q", k, spec.ModelKey, k)
		}
	}
}

func mustSpec(t *testing.T, key string) *webui.HTTPModelSpec {
	t.Helper()
	m, err := model.GetModel(key)
	if err != nil {
		t.Fatalf("model.GetModel(%q): %v", key, err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec(%q): %v", key, err)
	}
	return spec
}

// TestGS305EPSpec mirrors test_endpoints.py::
// test_gs305ep_spec_is_grounded_merge_hash plus the full field table from
// dossier §1.5 / source lines 376-395.
func TestGS305EPSpec(t *testing.T) {
	s := mustSpec(t, "gs305ep")
	if s.Scheme != webui.LoginSchemeMergeHashCGI {
		t.Errorf("Scheme = %v, want LoginSchemeMergeHashCGI", s.Scheme)
	}
	checkBool(t, "SchemeVerified", s.SchemeVerified, true)
	checkStr(t, "LoginPath", s.LoginPath, "/login.cgi")
	checkStr(t, "PasswordField", s.PasswordField, "password")
	checkStr(t, "CookieName", s.CookieName, "SID")
	checkBool(t, "NeedsRand", s.NeedsRand, true)
	checkStr(t, "DashboardPath", s.DashboardPath, "/dashboard.cgi")
	checkStr(t, "StatsPath", s.StatsPath, "/portStatistics.cgi")
	checkStr(t, "PoEConfigPath", s.PoEConfigPath, "/PoEPortConfig.cgi")
	checkStr(t, "PoEStatusPath", s.PoEStatusPath, "/getPoePortStatus.cgi")
	checkStr(t, "VlanConfigPath", s.VlanConfigPath, "/8021qCf.cgi")
	checkStr(t, "VlanMembershipPath", s.VlanMembershipPath, "/8021qMembe.cgi")
	checkStr(t, "PvidPath", s.PvidPath, "/portPVID.cgi")
	checkStr(t, "RebootPath", s.RebootPath, "/device_reboot.cgi")
	checkStr(t, "LogoutPath", s.LogoutPath, "/logout.cgi")
	checkBool(t, "IsEPXPoE", s.IsEPXPoE, true)
	checkBool(t, "ReadsVerified", s.ReadsVerified, true)
	if s.HTMLDialect != webui.HTMLDialectStandard {
		t.Errorf("HTMLDialect = %v, want HTMLDialectStandard", s.HTMLDialect)
	}
	// Everything else is default/absent.
	checkStr(t, "SysinfoPath", s.SysinfoPath, "")
	checkStr(t, "MacTablePath", s.MacTablePath, "")
	checkStr(t, "LLDPPath", s.LLDPPath, "")
	checkStr(t, "PortConfigPath", s.PortConfigPath, "")
	checkStr(t, "CertUploadPath", s.CertUploadPath, "")
	checkBool(t, "Secure", s.Secure, false)
	if s.WebPort != nil {
		t.Errorf("WebPort = %v, want nil", *s.WebPort)
	}
	if s.MgmtIPFields != nil {
		t.Errorf("MgmtIPFields = %+v, want nil", s.MgmtIPFields)
	}
}

// TestGS110EMXSpec mirrors test_endpoints.py::
// test_gs110emx_gambit_scheme_and_reads_grounded plus source lines
// 397-497, including the 1841111 PortConfigPath/RebootPath/LogoutPath
// additions.
func TestGS110EMXSpec(t *testing.T) {
	s := mustSpec(t, "gs110emx")
	if s.Scheme != webui.LoginSchemeGambit {
		t.Errorf("Scheme = %v, want LoginSchemeGambit", s.Scheme)
	}
	checkBool(t, "SchemeVerified", s.SchemeVerified, true)
	checkStr(t, "LoginPath", s.LoginPath, "/")
	checkStr(t, "LoginPostPath", s.LoginPostPath, "/redirect.html")
	checkStr(t, "PasswordField", s.PasswordField, "LoginPassword")
	checkStr(t, "CookieName", s.CookieName, "")
	checkStr(t, "SessionTokenField", s.SessionTokenField, "Gambit")
	checkBool(t, "NeedsRand", s.NeedsRand, true)
	checkStr(t, "SysinfoPath", s.SysinfoPath, "/iss/specific/sysInfo.html")
	checkStr(t, "StatsPath", s.StatsPath, "/iss/specific/interface_stats.html")
	checkStr(t, "DashboardPath", s.DashboardPath, "/iss/specific/port_settings.html")
	// 1841111 addition: same page as DashboardPath, different write mechanism.
	checkStr(t, "PortConfigPath", s.PortConfigPath, "/iss/specific/port_settings.html")
	checkStr(t, "VlanConfigPath", s.VlanConfigPath, "/iss/specific/Cf8021q.html")
	checkStr(t, "VlanMembershipPath", s.VlanMembershipPath, "/iss/specific/vlanMembership.html")
	checkStr(t, "PvidPath", s.PvidPath, "/iss/specific/vlan_pvidsetting.html")
	checkStr(t, "RebootPath", s.RebootPath, "/iss/specific/sys_reload.html")
	checkStr(t, "LogoutPath", s.LogoutPath, "/iss/specific/logout.html")
	checkStr(t, "PoEConfigPath", s.PoEConfigPath, "")
	checkStr(t, "PoEStatusPath", s.PoEStatusPath, "")
	checkStr(t, "MacTablePath", s.MacTablePath, "")
	checkStr(t, "LLDPPath", s.LLDPPath, "")
	checkBool(t, "IsEPXPoE", s.IsEPXPoE, false)
	checkBool(t, "ReadsVerified", s.ReadsVerified, true)
	if s.HTMLDialect != webui.HTMLDialectGS110EMX {
		t.Errorf("HTMLDialect = %v, want HTMLDialectGS110EMX", s.HTMLDialect)
	}
}

// TestGSM7228PSSpec mirrors test_endpoints.py::
// test_gsm7228ps_cheetah_form_snmp_preferred plus the full field table from
// dossier §1.5 / source lines 499-592, including the 1841111
// PortConfigPath/MgmtIPPath/MgmtIPFields/VlanMembership additions and the
// full 22-key CertUploadFormFields table.
func TestGSM7228PSSpec(t *testing.T) {
	s := mustSpec(t, "gsm7228ps")
	if s.Scheme != webui.LoginSchemeCheetahForm {
		t.Errorf("Scheme = %v, want LoginSchemeCheetahForm", s.Scheme)
	}
	checkStr(t, "LoginPath", s.LoginPath, "/base/cheetah_login.html")
	checkStr(t, "PasswordField", s.PasswordField, "pwd")
	checkStr(t, "UsernameField", s.UsernameField, "uname")
	checkStr(t, "Username", s.Username, "admin")
	checkStr(t, "CookieName", s.CookieName, "SID")
	checkBool(t, "NeedsRand", s.NeedsRand, false)
	checkStr(t, "DashboardPath", s.DashboardPath, "/portsConfiguration.html")
	checkStr(t, "PortConfigPath", s.PortConfigPath, "/portsConfiguration.html")
	checkStr(t, "StatsPath", s.StatsPath, "/portStatistics.html")
	checkStr(t, "SysinfoPath", s.SysinfoPath, "/base/system/management/sysInfo.html")
	checkStr(t, "MgmtIPPath", s.MgmtIPPath, "/ipConfiguration.html")
	checkStr(t, "MacTablePath", s.MacTablePath, "/basicAddressTable.html")
	checkStr(t, "LLDPPath", s.LLDPPath, "/lldpRemoteInventory.html")
	checkStr(t, "PoEConfigPath", s.PoEConfigPath, "/poeInterfaceConfiguration.html")
	checkStr(t, "PoEStatusPath", s.PoEStatusPath, "/poeInterfaceConfiguration.html")
	checkStr(t, "VlanConfigPath", s.VlanConfigPath, "/vlanStatus.html")
	checkStr(t, "VlanMembershipPath", s.VlanMembershipPath, "/switching/dot1q/vlan_port_cfg.html")
	checkStr(t, "VlanMembershipPostPath", s.VlanMembershipPostPath, "/switching/dot1q/vlan_port_cfg_rw.html")
	checkStr(t, "PvidPath", s.PvidPath, "/portPvidConfiguration.html")
	checkStr(t, "RebootPath", s.RebootPath, "")
	checkStr(t, "LogoutPath", s.LogoutPath, "")
	checkBool(t, "IsEPXPoE", s.IsEPXPoE, false)
	checkBool(t, "ReadsVerified", s.ReadsVerified, true)
	if s.HTMLDialect != webui.HTMLDialectS3300 {
		t.Errorf("HTMLDialect = %v, want HTMLDialectS3300", s.HTMLDialect)
	}
	checkStr(t, "CertUploadPath", s.CertUploadPath, "/http_file_download.html/a1")
	checkStr(t, "CertUploadFileField", s.CertUploadFileField, ".v_1_3_1_handle")

	if s.MgmtIPFields == nil {
		t.Fatal("MgmtIPFields = nil, want non-nil")
	}
	want := webui.XuiMgmtIPFields{
		Address: "v_1_1_1", Netmask: "v_1_2_1", Gateway: "v_1_3_1",
		Mode: "v_1_18_1", StaticValue: "None", DHCPValue: "DHCP",
		ApplyButton: "v_3_1_1",
	}
	if *s.MgmtIPFields != want {
		t.Errorf("MgmtIPFields = %+v, want %+v", *s.MgmtIPFields, want)
	}

	wantFields := map[string]string{
		"v_1_1_3":           "HTTP",
		"v_1_1_2":           "SSL Server Certificate PEM File",
		"v_1_2_1":           "",
		"v_1_3_2":           " not in progress",
		"v_1_3_3":           "",
		"v_1_3_4":           "",
		"v_1_9_1":           "image1",
		"v_1_9_5":           "",
		"v_1_9_2":           "1",
		"v_1_9_3":           "Enable",
		"v_1_19_1":          "32",
		"v_1_20_1":          "",
		"v_1_200_1":         "",
		"v_2_3_1":           " not in progress",
		"v_2_4_3":           "None",
		"v_2_4_2":           " not in progress",
		"v_4_1_1":           "",
		"submit_flag":       "8",
		"submit_target":     "http_file_download.html",
		"err_flag":          "0",
		"err_msg":           "",
		"clazz_information": "http_file_download.html",
	}
	if len(s.CertUploadFormFields) != len(wantFields) {
		t.Errorf("len(CertUploadFormFields) = %d, want %d (source has 22 keys, not the dossier's claimed 19)",
			len(s.CertUploadFormFields), len(wantFields))
	}
	for k, want := range wantFields {
		if got := s.CertUploadFormFields[k]; got != want {
			t.Errorf("CertUploadFormFields[%q] = %q, want %q", k, got, want)
		}
	}
}

// TestGS105PESpec mirrors test_endpoints.py::
// test_gs105pe_spec_live_verified_real_paths.
func TestGS105PESpec(t *testing.T) {
	s := mustSpec(t, "gs105pe")
	if s.Scheme != webui.LoginSchemeMergeHashCGI {
		t.Errorf("Scheme = %v, want LoginSchemeMergeHashCGI", s.Scheme)
	}
	checkBool(t, "SchemeVerified", s.SchemeVerified, true)
	checkStr(t, "LoginPath", s.LoginPath, "/login.cgi")
	checkStr(t, "PasswordField", s.PasswordField, "password")
	checkStr(t, "CookieName", s.CookieName, "SID")
	checkBool(t, "NeedsRand", s.NeedsRand, true)
	checkBool(t, "ReadsVerified", s.ReadsVerified, true)
	if s.HTMLDialect != webui.HTMLDialectGS105PE {
		t.Errorf("HTMLDialect = %v, want HTMLDialectGS105PE", s.HTMLDialect)
	}
	checkStr(t, "DashboardPath", s.DashboardPath, "/status.cgi")
	checkStr(t, "SysinfoPath", s.SysinfoPath, "/switch_info.cgi")
	checkStr(t, "StatsPath", s.StatsPath, "/portStatistics.cgi")
	checkStr(t, "PvidPath", s.PvidPath, "/portPVID.cgi")
	checkStr(t, "VlanConfigPath", s.VlanConfigPath, "/8021qCf.cgi")
	checkStr(t, "VlanMembershipPath", s.VlanMembershipPath, "/8021qMembe.cgi")
	checkStr(t, "RebootPath", s.RebootPath, "/device_reboot.cgi")
	checkStr(t, "LogoutPath", s.LogoutPath, "/logout.cgi")
	// confirmed 404 on real hardware: PoE pass-through, not a PSE.
	checkStr(t, "PoEStatusPath", s.PoEStatusPath, "")
	checkStr(t, "PoEConfigPath", s.PoEConfigPath, "")
	checkStr(t, "PortConfigPath", s.PortConfigPath, "")
	checkBool(t, "IsEPXPoE", s.IsEPXPoE, false)
}

// TestM430024XSpec mirrors test_endpoints.py::
// test_m4300_spec_live_verified_cheetah_v1, plus the 1841111 LLDPPath
// correction (source lines 632-720).
func TestM430024XSpec(t *testing.T) {
	s := mustSpec(t, "m4300-24x")
	if s.Scheme != webui.LoginSchemeCheetahV1 {
		t.Errorf("Scheme = %v, want LoginSchemeCheetahV1", s.Scheme)
	}
	checkBool(t, "SchemeVerified", s.SchemeVerified, true)
	checkBool(t, "ReadsVerified", s.ReadsVerified, true)
	checkBool(t, "NeedsReferer", s.NeedsReferer, true)
	checkStr(t, "UsernameField", s.UsernameField, "uname")
	checkStr(t, "Username", s.Username, "admin")
	checkStr(t, "LoginPostPath", s.LoginPostPath, "/v1/base/cheetah_login.html")
	checkStr(t, "DashboardPath", s.DashboardPath, "/v1/portsConfiguration.html")
	checkStr(t, "PortConfigPath", s.PortConfigPath, "/v1/portsConfiguration.html")
	checkStr(t, "StatsPath", s.StatsPath, "/v1/portStatistics.html")
	checkStr(t, "SysinfoPath", s.SysinfoPath, "/v1/base/system/management/sysInfo.html")
	checkStr(t, "MgmtIPPath", s.MgmtIPPath, "/v1/mgmtVlanIpv4Configuration.html")
	checkStr(t, "VlanConfigPath", s.VlanConfigPath, "/v1/vlanStatus.html")
	checkStr(t, "VlanMembershipPath", s.VlanMembershipPath, "/v1/switching/dot1q/vlan_port_cfg.html")
	checkStr(t, "VlanMembershipPostPath", s.VlanMembershipPostPath, "/v1/switching/dot1q/vlan_port_cfg_rw.html")
	checkStr(t, "PvidPath", s.PvidPath, "/v1/portPvidConfiguration.html")
	checkStr(t, "MacTablePath", s.MacTablePath, "/v1/basicAddressTable.html")
	// 1841111 correction: was "" ("no chassis/port-id table"), now the real page.
	checkStr(t, "LLDPPath", s.LLDPPath, "/v1/lldpRemoteInventory.html")
	if s.HTMLDialect != webui.HTMLDialectM4300 {
		t.Errorf("HTMLDialect = %v, want HTMLDialectM4300", s.HTMLDialect)
	}
	// no PoE on the 24X.
	checkStr(t, "PoEStatusPath", s.PoEStatusPath, "")
	checkStr(t, "PoEConfigPath", s.PoEConfigPath, "")
	checkStr(t, "CookieName", s.CookieName, "SID")
	checkBool(t, "Secure", s.Secure, false)
	if s.WebPort != nil {
		t.Errorf("WebPort = %v, want nil", *s.WebPort)
	}
	if s.MgmtIPFields == nil {
		t.Fatal("MgmtIPFields = nil, want non-nil")
	}
	want := webui.XuiMgmtIPFields{
		Address: "v_1_6_1", Netmask: "v_1_7_1", Gateway: "v_1_71_1",
		Mode: "v_1_5_3", StaticValue: "Disable", DHCPValue: "Enable",
		ApplyButton: "v_3_1_1",
	}
	if *s.MgmtIPFields != want {
		t.Errorf("MgmtIPFields = %+v, want %+v", *s.MgmtIPFields, want)
	}
}

// TestM430016XSpec mirrors test_endpoints.py::
// test_m4300_16x_spec_https_on_49152: overridden fields diverge from the
// 24X, everything else (login flow + /v1/ read paths) is inherited
// unchanged (source lines 722-762).
func TestM430016XSpec(t *testing.T) {
	s := mustSpec(t, "m4300-16x")
	checkBool(t, "Secure", s.Secure, true)
	if s.WebPort == nil || *s.WebPort != 49152 {
		t.Errorf("WebPort = %v, want *49152", s.WebPort)
	}
	checkBool(t, "ReadsVerified", s.ReadsVerified, true)
	checkStr(t, "CookieName", s.CookieName, "SIDSSL")
	checkStr(t, "PoEStatusPath", s.PoEStatusPath, "/v1/poeInterfaceConfiguration.html")
	checkStr(t, "PoEConfigPath", s.PoEConfigPath, "/v1/poeInterfaceConfiguration.html")

	// Inherited unchanged from the 24X.
	if s.Scheme != webui.LoginSchemeCheetahV1 {
		t.Errorf("Scheme = %v, want LoginSchemeCheetahV1", s.Scheme)
	}
	checkBool(t, "NeedsReferer", s.NeedsReferer, true)
	checkStr(t, "LoginPostPath", s.LoginPostPath, "/v1/base/cheetah_login.html")
	checkStr(t, "DashboardPath", s.DashboardPath, "/v1/portsConfiguration.html")
	if s.HTMLDialect != webui.HTMLDialectM4300 {
		t.Errorf("HTMLDialect = %v, want HTMLDialectM4300", s.HTMLDialect)
	}

	// The 24X keeps its own SID cookie, plain HTTP, and has no PoE.
	m24 := mustSpec(t, "m4300-24x")
	checkBool(t, "24X Secure", m24.Secure, false)
	if m24.WebPort != nil {
		t.Errorf("24X WebPort = %v, want nil", *m24.WebPort)
	}
	checkStr(t, "24X CookieName", m24.CookieName, "SID")
	checkStr(t, "24X PoEStatusPath", m24.PoEStatusPath, "")
}

// TestGSM7252PSSpec mirrors test_endpoints.py::
// test_gsm7252ps_spec_xe_fastpath, including the 1841111 PoEConfigPath
// correction and PortConfigPath addition (source lines 776-856).
func TestGSM7252PSSpec(t *testing.T) {
	s := mustSpec(t, "gsm7252ps")
	if s.Scheme != webui.LoginSchemeCheetahForm {
		t.Errorf("Scheme = %v, want LoginSchemeCheetahForm", s.Scheme)
	}
	checkBool(t, "SchemeVerified", s.SchemeVerified, true)
	checkBool(t, "ReadsVerified", s.ReadsVerified, true)
	checkStr(t, "LoginPath", s.LoginPath, "/base/cheetah_login.html")
	checkStr(t, "UsernameField", s.UsernameField, "uname")
	checkStr(t, "Username", s.Username, "admin")
	checkStr(t, "PasswordField", s.PasswordField, "pwd")
	checkStr(t, "CookieName", s.CookieName, "SID")
	checkBool(t, "NeedsRand", s.NeedsRand, false)
	checkBool(t, "NeedsReferer", s.NeedsReferer, false)
	checkStr(t, "DashboardPath", s.DashboardPath, "/portsConfiguration.html")
	checkStr(t, "PortConfigPath", s.PortConfigPath, "/portsConfiguration.html")
	checkStr(t, "StatsPath", s.StatsPath, "/portStatistics.html")
	checkStr(t, "PvidPath", s.PvidPath, "/portPvidConfiguration.html")
	checkStr(t, "VlanConfigPath", s.VlanConfigPath, "/vlanStatus.html")
	checkStr(t, "VlanMembershipPath", s.VlanMembershipPath, "/switching/dot1q/vlan_port_cfg.html")
	checkStr(t, "VlanMembershipPostPath", s.VlanMembershipPostPath, "/switching/dot1q/vlan_port_cfg_rw.html")
	checkStr(t, "MacTablePath", s.MacTablePath, "/basicAddressTable.html")
	checkStr(t, "PoEStatusPath", s.PoEStatusPath, "/poeInterfaceConfiguration.html")
	// 1841111 correction: was "" ("form refuses every write"), now writable.
	checkStr(t, "PoEConfigPath", s.PoEConfigPath, "/poeInterfaceConfiguration.html")
	checkStr(t, "LLDPPath", s.LLDPPath, "/lldpRemoteInventory.html")
	checkStr(t, "SysinfoPath", s.SysinfoPath, "/base/system/management/sysInfo.html")
	checkStr(t, "MgmtIPPath", s.MgmtIPPath, "/ipConfiguration.html")
	if s.HTMLDialect != webui.HTMLDialectXEFastpath {
		t.Errorf("HTMLDialect = %v, want HTMLDialectXEFastpath", s.HTMLDialect)
	}
	if s.MgmtIPFields == nil {
		t.Fatal("MgmtIPFields = nil, want non-nil")
	}
	// Shares the same field map as gsm7228ps.
	gsm7228 := mustSpec(t, "gsm7228ps")
	if *s.MgmtIPFields != *gsm7228.MgmtIPFields {
		t.Errorf("gsm7252ps.MgmtIPFields = %+v, want same as gsm7228ps %+v", *s.MgmtIPFields, *gsm7228.MgmtIPFields)
	}
}

// TestGS728TPPSpec mirrors test_endpoints.py::
// test_gs728tpp_spec_goahead_xml.
func TestGS728TPPSpec(t *testing.T) {
	s := mustSpec(t, "gs728tpp")
	if s.Scheme != webui.LoginSchemeXMLAPI {
		t.Errorf("Scheme = %v, want LoginSchemeXMLAPI", s.Scheme)
	}
	checkBool(t, "SchemeVerified", s.SchemeVerified, true)
	checkBool(t, "ReadsVerified", s.ReadsVerified, true)
	if s.HTMLDialect != webui.HTMLDialectGoAheadXML {
		t.Errorf("HTMLDialect = %v, want HTMLDialectGoAheadXML", s.HTMLDialect)
	}
	checkStr(t, "LoginPath", s.LoginPath, "/")
	checkStr(t, "Username", s.Username, "admin")
	checkStr(t, "UsernameField", s.UsernameField, "user")
	checkStr(t, "CookieName", s.CookieName, "sessionID")
	checkStr(t, "StatsPath", s.StatsPath, "") // per-port stats not available via HTTP
	checkStr(t, "VlanMembershipPath", s.VlanMembershipPath, "")
	checkStr(t, "CertUploadPath", s.CertUploadPath, "wcd")
	checkStr(t, "CertUploadFileField", s.CertUploadFileField, "") // no multipart part

	wcd := map[string]struct {
		needle string
		query  string
	}{
		"portConfiguration_master":    {"portConfiguration_master", s.DashboardPath},
		"PortPvidConf_master":         {"PortPvidConf_master", s.PvidPath},
		"VlanConfBasic_master":        {"VlanConfBasic_master", s.VlanConfigPath},
		"PoeInterfaceConf_master":     {"PoeInterfaceConf_master", s.PoEStatusPath},
		"DynamicAddresses_master":     {"DynamicAddresses_master", s.MacTablePath},
		"NeighborsInformation_master": {"NeighborsInformation_master", s.LLDPPath},
		"SystemInfo_master":           {"SystemInfo_master", s.SysinfoPath},
		"IPConf_master":               {"IPConf_master", s.MgmtIPPath},
	}
	for name, c := range wcd {
		t.Run(name, func(t *testing.T) {
			if c.query == "" {
				t.Fatalf("%s: query is empty", name)
			}
			if !strings.HasPrefix(c.query, "wcd?{file=") {
				t.Errorf("%s: query %q does not start with %q", name, c.query, "wcd?{file=")
			}
			if !strings.Contains(c.query, c.needle) {
				t.Errorf("%s: query %q does not contain %q", name, c.query, c.needle)
			}
		})
	}
}

func checkStr(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", field, got, want)
	}
}

func checkBool(t *testing.T, field string, got, want bool) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", field, got, want)
	}
}
