package capabilities

// support_http_test.go: pins httpSupport against Python's _http_support and
// _http_path_for (capabilities.py:516-659).

import (
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

func mustHTTPSpec(t *testing.T, key string) (*model.SwitchModel, *webui.HTTPModelSpec) {
	t.Helper()
	m := mustModelSnmp(t, key)
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec(%q): %v", key, err)
	}
	return m, spec
}

func TestHTTPSupportUnverifiedGate(t *testing.T) {
	m, spec := mustHTTPSpec(t, "gsm7252ps")
	// Synthesize an UNVERIFIED spec rather than mutating package state --
	// see this task's Interfaces note on why httpSupport takes spec directly.
	unverified := *spec
	unverified.ReadsVerified = false
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	support, reason := httpSupport(m, &unverified, op)
	if support != SupportUnverified {
		t.Errorf("httpSupport(unverified spec, get_ports) = %v, want SupportUnverified", support)
	}
	if !strings.Contains(reason, "UNVERIFIED") {
		t.Errorf("httpSupport(unverified spec, get_ports) reason = %q, want it to contain UNVERIFIED", reason)
	}
}

func TestHTTPSupportCertUploadKnownUnimplementedFoldsToUnsupported(t *testing.T) {
	// m4300-24x/m4300-16x/gsm7252ps take a cert over SCP, not HTTP. Python's
	// real facade raises NotImplementedError for this case but the ORACLE
	// still reports a single Support.UNSUPPORTED -- no distinct verdict, even
	// though Go has model.ErrKnownUnimplemented as a first-class sentinel.
	for key := range webui.CertUploadKnownUnimplemented {
		m, spec := mustHTTPSpec(t, key)
		op, err := OperationByName("upload_certificate")
		if err != nil {
			t.Fatalf("OperationByName(upload_certificate): %v", err)
		}
		support, reason := httpSupport(m, spec, op)
		if support != SupportUnsupported {
			t.Errorf("httpSupport(%s, upload_certificate) = %v, want SupportUnsupported", key, support)
		}
		if !strings.Contains(reason, "upload_certificate_scp") {
			t.Errorf("httpSupport(%s, upload_certificate) reason = %q, want it to mention upload_certificate_scp", key, reason)
		}
	}
}

func TestHTTPSupportNoPageIsUnsupported(t *testing.T) {
	// gs305ep's HTTPModelSpec has no MgmtIPPath and no SysinfoPath fallback
	// (its dialect has no mgmt-IP page at all).
	m, spec := mustHTTPSpec(t, "gs305ep")
	op, err := OperationByName("get_mgmt_ip")
	if err != nil {
		t.Fatalf("OperationByName(get_mgmt_ip): %v", err)
	}
	support, reason := httpSupport(m, spec, op)
	if support != SupportUnsupported {
		t.Errorf("httpSupport(gs305ep, get_mgmt_ip) = %v, want SupportUnsupported", support)
	}
	if reason == "" {
		t.Error("httpSupport(gs305ep, get_mgmt_ip) reason is empty")
	}
}

func TestHTTPSupportSensorsGate(t *testing.T) {
	// gsm7228ps (S3300 dialect) has a SysinfoPath but NO live sensor table
	// (webui.SupportsSensors deliberately excludes the S3300 dialect).
	m, spec := mustHTTPSpec(t, "gsm7228ps")
	op, err := OperationByName("get_sensors")
	if err != nil {
		t.Fatalf("OperationByName(get_sensors): %v", err)
	}
	support, _ := httpSupport(m, spec, op)
	if support != SupportUnsupported {
		t.Errorf("httpSupport(gsm7228ps, get_sensors) = %v, want SupportUnsupported", support)
	}
}

func TestHTTPSupportSetMgmtIPNeedsBothPageAndFields(t *testing.T) {
	// gs110emx: verify set_mgmt_ip requires BOTH MgmtIPPath and MgmtIPFields.
	m, spec := mustHTTPSpec(t, "gs110emx")
	op, err := OperationByName("set_mgmt_ip")
	if err != nil {
		t.Fatalf("OperationByName(set_mgmt_ip): %v", err)
	}
	support, _ := httpSupport(m, spec, op)
	if support != SupportUnsupported {
		t.Errorf("httpSupport(gs110emx, set_mgmt_ip) = %v, want SupportUnsupported (no XUI mgmt-IP write page)", support)
	}
}

func TestHTTPSupportCSRFGate(t *testing.T) {
	op, err := OperationByName("create_vlan")
	if err != nil {
		t.Fatalf("OperationByName(create_vlan): %v", err)
	}
	// gsm7252ps: XE_FASTPATH dialect, no CSRF hash on its write pages.
	m, spec := mustHTTPSpec(t, "gsm7252ps")
	support, reason := httpSupport(m, spec, op)
	if support != SupportUnsupported {
		t.Errorf("httpSupport(gsm7252ps, create_vlan) = %v, want SupportUnsupported (no CSRF hash)", support)
	}
	if !strings.Contains(reason, "CSRF") {
		t.Errorf("httpSupport(gsm7252ps, create_vlan) reason = %q, want it to mention CSRF", reason)
	}
	// gs305ep: STANDARD dialect, has the CSRF hash.
	m2, spec2 := mustHTTPSpec(t, "gs305ep")
	support2, _ := httpSupport(m2, spec2, op)
	if support2 != SupportSupported {
		t.Errorf("httpSupport(gs305ep, create_vlan) = %v, want SupportSupported (CSRF hash present)", support2)
	}
	// gs728tpp: GoAhead XML-API dialect, exempt from the CSRF gate entirely
	// (its writer never scrapes a token).
	m3, spec3 := mustHTTPSpec(t, "gs728tpp")
	support3, reason3 := httpSupport(m3, spec3, op)
	if support3 != SupportSupported {
		t.Errorf("httpSupport(gs728tpp, create_vlan) = %v, want SupportSupported (XML-API dialect is CSRF-exempt)", support3)
	}
	if reason3 != "" {
		t.Errorf("httpSupport(gs728tpp, create_vlan) reason = %q, want empty", reason3)
	}
}

func TestHTTPSupportXMLAPIWrites(t *testing.T) {
	m, spec := mustHTTPSpec(t, "gs728tpp")
	for _, opName := range []string{
		"set_vlan_membership", "set_port_enabled", "set_poe", "set_pvid",
		"create_vlan", "delete_vlan", "cycle_poe", "clear_poe_fault",
		"set_port_description", "set_hostname", "set_port_speed",
	} {
		op, err := OperationByName(opName)
		if err != nil {
			t.Fatalf("OperationByName(%q): %v", opName, err)
		}
		support, reason := httpSupport(m, spec, op)
		if support != SupportSupported {
			t.Errorf("httpSupport(gs728tpp, %s) = %v, want SupportSupported (grounded XML-API write)", opName, support)
		}
		if reason != "" {
			t.Errorf("httpSupport(gs728tpp, %s) reason = %q, want empty", opName, reason)
		}
	}
	// set_flow_control has no grounded XML-API body builder, unlike the ops
	// above -- xmlAPIWrites deliberately omits it.
	flowCtl, err := OperationByName("set_flow_control")
	if err != nil {
		t.Fatalf("OperationByName(set_flow_control): %v", err)
	}
	if path := httpPathFor(spec, flowCtl); path != "" {
		t.Errorf("httpPathFor(gs728tpp, set_flow_control) = %q, want \"\" (no XML-API write body)", path)
	}
}

func TestHTTPSupportGetHostnameGate(t *testing.T) {
	op, err := OperationByName("get_hostname")
	if err != nil {
		t.Fatalf("OperationByName(get_hostname): %v", err)
	}
	// gs110emx, gs105pe and gs728tpp (GoAhead) all carry the field.
	for _, key := range []string{"gs110emx", "gs105pe", "gs728tpp"} {
		m, spec := mustHTTPSpec(t, key)
		support, reason := httpSupport(m, spec, op)
		if support != SupportSupported {
			t.Errorf("httpSupport(%s, get_hostname) = %v, want SupportSupported", key, support)
		}
		if reason != "" {
			t.Errorf("httpSupport(%s, get_hostname) reason = %q, want empty", key, reason)
		}
	}
	// gs305ep (STANDARD dialect) has no identity-page host-name field.
	m, spec := mustHTTPSpec(t, "gs305ep")
	support, reason := httpSupport(m, spec, op)
	if support != SupportUnsupported {
		t.Errorf("httpSupport(gs305ep, get_hostname) = %v, want SupportUnsupported", support)
	}
	if reason == "" {
		t.Error("httpSupport(gs305ep, get_hostname) reason is empty")
	}
}

func TestHTTPSupportGetUsersGate(t *testing.T) {
	op, err := OperationByName("get_users")
	if err != nil {
		t.Fatalf("OperationByName(get_users): %v", err)
	}
	m, spec := mustHTTPSpec(t, "gsm7252ps")
	support, reason := httpSupport(m, spec, op)
	if support != SupportSupported {
		t.Errorf("httpSupport(gsm7252ps, get_users) = %v, want SupportSupported", support)
	}
	if reason != "" {
		t.Errorf("httpSupport(gsm7252ps, get_users) reason = %q, want empty", reason)
	}
	// gsm7228ps: its own users page 404s, so UsersPath is unset.
	m2, spec2 := mustHTTPSpec(t, "gsm7228ps")
	support2, reason2 := httpSupport(m2, spec2, op)
	if support2 != SupportUnsupported {
		t.Errorf("httpSupport(gsm7228ps, get_users) = %v, want SupportUnsupported", support2)
	}
	if reason2 == "" {
		t.Error("httpSupport(gsm7228ps, get_users) reason is empty")
	}
}

func TestHTTPSupportGetServicesAllOrNothing(t *testing.T) {
	op, err := OperationByName("get_services")
	if err != nil {
		t.Fatalf("OperationByName(get_services): %v", err)
	}
	// gsm7252ps names all four service pages.
	m, spec := mustHTTPSpec(t, "gsm7252ps")
	support, _ := httpSupport(m, spec, op)
	if support != SupportSupported {
		t.Errorf("httpSupport(gsm7252ps, get_services) = %v, want SupportSupported", support)
	}
	// gsm7228ps names only two of the four -- all-or-nothing means refused.
	m2, spec2 := mustHTTPSpec(t, "gsm7228ps")
	support2, reason2 := httpSupport(m2, spec2, op)
	if support2 != SupportUnsupported {
		t.Errorf("httpSupport(gsm7228ps, get_services) = %v, want SupportUnsupported (not all 4 pages)", support2)
	}
	if reason2 == "" {
		t.Error("httpSupport(gsm7228ps, get_services) reason is empty")
	}
}

func TestHTTPSupportSetHostnameGS110EMXOnly(t *testing.T) {
	op, err := OperationByName("set_hostname")
	if err != nil {
		t.Fatalf("OperationByName(set_hostname): %v", err)
	}
	m, spec := mustHTTPSpec(t, "gs110emx")
	support, reason := httpSupport(m, spec, op)
	if support != SupportSupported {
		t.Errorf("httpSupport(gs110emx, set_hostname) = %v, want SupportSupported", support)
	}
	if reason != "" {
		t.Errorf("httpSupport(gs110emx, set_hostname) reason = %q, want empty", reason)
	}
	// gs105pe's switch_info.cgi carries the same field but its own
	// CSRF-hash envelope, which has not been driven -- deliberately not
	// offered.
	m2, spec2 := mustHTTPSpec(t, "gs105pe")
	support2, reason2 := httpSupport(m2, spec2, op)
	if support2 != SupportUnsupported {
		t.Errorf("httpSupport(gs105pe, set_hostname) = %v, want SupportUnsupported", support2)
	}
	if reason2 == "" {
		t.Error("httpSupport(gs105pe, set_hostname) reason is empty")
	}
}

func TestHTTPSupportRemoveSyslogCollectorM4300Only(t *testing.T) {
	op, err := OperationByName("remove_syslog_collector")
	if err != nil {
		t.Fatalf("OperationByName(remove_syslog_collector): %v", err)
	}
	m, spec := mustHTTPSpec(t, "m4300-24x")
	support, reason := httpSupport(m, spec, op)
	if support != SupportSupported {
		t.Errorf("httpSupport(m4300-24x, remove_syslog_collector) = %v, want SupportSupported", support)
	}
	if reason != "" {
		t.Errorf("httpSupport(m4300-24x, remove_syslog_collector) reason = %q, want empty", reason)
	}
	// gsm7252ps (XE_FASTPATH, not M4300) has no grounded template row.
	m2, spec2 := mustHTTPSpec(t, "gsm7252ps")
	support2, reason2 := httpSupport(m2, spec2, op)
	if support2 != SupportUnsupported {
		t.Errorf("httpSupport(gsm7252ps, remove_syslog_collector) = %v, want SupportUnsupported", support2)
	}
	if reason2 == "" {
		t.Error("httpSupport(gsm7252ps, remove_syslog_collector) reason is empty")
	}
}

func TestHTTPSupportDefaultSupported(t *testing.T) {
	m, spec := mustHTTPSpec(t, "gsm7252ps")
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	support, reason := httpSupport(m, spec, op)
	if support != SupportSupported {
		t.Errorf("httpSupport(gsm7252ps, get_ports) = %v, want SupportSupported", support)
	}
	if reason != "" {
		t.Errorf("httpSupport(gsm7252ps, get_ports) reason = %q, want empty", reason)
	}
}
