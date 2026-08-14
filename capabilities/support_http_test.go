package capabilities

// support_http_test.go: pins httpSupport against Python's _http_support and
// _http_path_for (capabilities.py:243-311).

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
