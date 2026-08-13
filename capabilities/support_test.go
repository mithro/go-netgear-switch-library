package capabilities

// support_test.go: pins the top-level dispatcher (For/BackendsFor/ForKey/
// Matrix) against Python's support()/backends_for()/matrix()
// (capabilities.py:344-414) and the 6 remaining test_capabilities.py
// invariants not already covered by Tasks 4-7's per-backend tests:
// test_no_backend_is_reported_before_the_operation,
// test_console_is_named_as_a_transport_not_a_missing_cli,
// test_backend_fixed_operations, test_backends_are_in_facade_preference_order,
// test_matrix_covers_every_model_and_carries_no_absent_backends,
// test_every_refusal_states_a_reason.

import (
	"reflect"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func TestBackendsForOrder(t *testing.T) {
	// Pins two concrete models' order, mirroring Python's
	// test_backends_are_in_facade_preference_order EXACTLY -- plus a third
	// case (gsm7228ps) this plan's Task 1 fix makes newly correct: telnet
	// only, no SSH.
	cases := []struct {
		key  string
		want []model.Backend
	}{
		{"m4300-24x", []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendSSH, model.BackendTelnet}},
		{"gs110emx", []model.Backend{model.BackendNSDP, model.BackendHTTP}},
		{"gsm7228ps", []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendTelnet}},
	}
	for _, c := range cases {
		m := mustModelSnmp(t, c.key)
		got := BackendsFor(m)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("BackendsFor(%s) = %v, want %v", c.key, got, c.want)
		}
	}
}

func TestForNoBackendReportedBeforeOperation(t *testing.T) {
	m := mustModelSnmp(t, "gs110emx") // NSDP+HTTP only, no SNMP
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	got := For(m, model.BackendSNMP, op)
	if got.Support != SupportNoBackend {
		t.Errorf("For(gs110emx, SNMP, get_ports).Support = %v, want SupportNoBackend", got.Support)
	}
	if !strings.Contains(got.Reason, "snmp") {
		t.Errorf("For(gs110emx, SNMP, get_ports).Reason = %q, want it to mention the snmp backend", got.Reason)
	}
}

func TestForConsoleIsNamedAsTransportNotMissingCLI(t *testing.T) {
	m := mustModelSnmp(t, "gsm7252ps")
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	got := For(m, model.BackendConsole, op)
	if got.Support != SupportNoBackend {
		t.Errorf("For(gsm7252ps, CONSOLE, get_ports).Support = %v, want SupportNoBackend", got.Support)
	}
	if !strings.Contains(got.Reason, "serial transport") {
		t.Errorf("For(gsm7252ps, CONSOLE, get_ports).Reason = %q, want it to mention 'serial transport'", got.Reason)
	}
	sshCap := For(m, model.BackendSSH, op)
	if !sshCap.Supported() {
		t.Errorf("For(gsm7252ps, SSH, get_ports) = %v, want Supported", sshCap.Support)
	}
}

func TestForBackendFixedOperations(t *testing.T) {
	for _, m := range model.Models() {
		for _, backend := range BackendsFor(m) {
			for _, op := range Operations {
				if op.Backends == nil {
					continue
				}
				restricted := true
				for _, b := range op.Backends {
					if b == backend {
						restricted = false
						break
					}
				}
				if !restricted {
					continue
				}
				got := For(m, backend, op)
				if got.Support != SupportUnsupported {
					t.Errorf("For(%s, %s, %s).Support = %v, want SupportUnsupported (backend-restricted op)",
						m.Key, backend, op.Name, got.Support)
				}
				if !strings.Contains(got.Reason, op.Name) {
					t.Errorf("For(%s, %s, %s).Reason = %q, want it to mention the op name",
						m.Key, backend, op.Name, got.Reason)
				}
			}
		}
	}
}

func TestForKeyMatchesForByObject(t *testing.T) {
	byKey, err := ForKey("gsm7252ps", model.BackendSNMP, "get_ports")
	if err != nil {
		t.Fatalf("ForKey: %v", err)
	}
	m := mustModelSnmp(t, "gsm7252ps")
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	byObject := For(m, model.BackendSNMP, op)
	// Capability is not ==-comparable (Operation.Backends is a slice) -- see
	// this plan's "Deliberate divergences" note 4.
	if !reflect.DeepEqual(byKey, byObject) {
		t.Errorf("ForKey(...) = %+v, want equal to For(...) = %+v", byKey, byObject)
	}
}

func TestForKeyUnknownKeyOrOpNameErrors(t *testing.T) {
	if _, err := ForKey("not-a-real-model", model.BackendSNMP, "get_ports"); err == nil {
		t.Errorf("ForKey(unknown model key, ...) = nil error, want non-nil")
	}
	if _, err := ForKey("gsm7252ps", model.BackendSNMP, "not_a_real_op"); err == nil {
		t.Errorf("ForKey(..., unknown op name) = nil error, want non-nil")
	}
}

func TestMatrixCoversEveryModelAndCarriesNoAbsentBackends(t *testing.T) {
	caps, err := Matrix(nil, nil)
	if err != nil {
		t.Fatalf("Matrix(nil, nil): %v", err)
	}
	seen := map[string]bool{}
	wantLen := 0
	for _, m := range model.Models() {
		seen[m.Key] = false
		wantLen += len(BackendsFor(m)) * len(Operations)
	}
	for _, c := range caps {
		if c.Support == SupportNoBackend {
			t.Errorf("Matrix() row %+v has Support == SupportNoBackend, want none", c)
		}
		if _, ok := seen[c.ModelKey]; !ok {
			t.Errorf("Matrix() row has unexpected ModelKey %q", c.ModelKey)
		}
		seen[c.ModelKey] = true
	}
	for key, wasSeen := range seen {
		if !wasSeen {
			t.Errorf("Matrix() has no rows for model %q", key)
		}
	}
	if len(caps) != wantLen {
		t.Errorf("len(Matrix()) = %d, want %d", len(caps), wantLen)
	}
}

func TestEveryRefusalStatesAReason(t *testing.T) {
	caps, err := Matrix(nil, nil)
	if err != nil {
		t.Fatalf("Matrix(nil, nil): %v", err)
	}
	for _, c := range caps {
		if c.Supported() {
			if c.Reason != "" {
				t.Errorf("%s/%s/%s: Supported but Reason = %q, want empty", c.ModelKey, c.Backend, c.Operation.Name, c.Reason)
			}
		} else if c.Reason == "" {
			t.Errorf("%s/%s/%s: %v but Reason is empty", c.ModelKey, c.Backend, c.Operation.Name, c.Support)
		}
	}
}
