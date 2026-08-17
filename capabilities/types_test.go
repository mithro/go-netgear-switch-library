package capabilities

// types_test.go: pins the Operations table's shape against the pinned
// Python capabilities.py (b26eb1f) verbatim -- counts, names, kinds, and the
// backend-restricted operations.

import (
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func TestOperationTableShape(t *testing.T) {
	if len(ReadOperations) != 14 {
		t.Errorf("len(ReadOperations) = %d, want 14", len(ReadOperations))
	}
	if len(WriteOperations) != 18 {
		t.Errorf("len(WriteOperations) = %d, want 18", len(WriteOperations))
	}
	if len(Operations) != 32 {
		t.Errorf("len(Operations) = %d, want 32", len(Operations))
	}
	for _, op := range ReadOperations {
		if op.Kind != OperationKindRead {
			t.Errorf("ReadOperations: %q has Kind %q, want %q", op.Name, op.Kind, OperationKindRead)
		}
	}
	for _, op := range WriteOperations {
		if op.Kind != OperationKindWrite {
			t.Errorf("WriteOperations: %q has Kind %q, want %q", op.Name, op.Kind, OperationKindWrite)
		}
	}
}

func TestOperationNamesExactAndOrdered(t *testing.T) {
	wantRead := []string{
		"get_ports", "get_stats", "get_vlans", "get_pvids", "get_lldp",
		"get_macs", "get_poe", "get_sensors", "get_mgmt_ip", "get_hostname",
		"get_users", "get_services", "get_syslog", "nsdp_device",
	}
	wantWrite := []string{
		"set_port_enabled", "set_poe", "cycle_poe", "clear_poe_fault",
		"set_port_description", "set_port_speed", "set_flow_control",
		"set_pvid", "set_vlan_membership", "create_vlan", "delete_vlan",
		"set_mgmt_ip", "set_hostname", "set_syslog_enabled",
		"add_syslog_collector", "remove_syslog_collector",
		"upload_certificate", "upload_certificate_scp",
	}
	for i, want := range wantRead {
		if ReadOperations[i].Name != want {
			t.Errorf("ReadOperations[%d].Name = %q, want %q", i, ReadOperations[i].Name, want)
		}
	}
	for i, want := range wantWrite {
		if WriteOperations[i].Name != want {
			t.Errorf("WriteOperations[%d].Name = %q, want %q", i, WriteOperations[i].Name, want)
		}
	}
}

func TestBackendRestrictedOperations(t *testing.T) {
	nsdpDevice, err := OperationByName("nsdp_device")
	if err != nil {
		t.Fatalf("OperationByName(nsdp_device): %v", err)
	}
	if len(nsdpDevice.Backends) != 1 || nsdpDevice.Backends[0] != model.BackendNSDP {
		t.Errorf("nsdp_device.Backends = %v, want [NSDP]", nsdpDevice.Backends)
	}

	upCert, err := OperationByName("upload_certificate")
	if err != nil {
		t.Fatalf("OperationByName(upload_certificate): %v", err)
	}
	if len(upCert.Backends) != 1 || upCert.Backends[0] != model.BackendHTTP {
		t.Errorf("upload_certificate.Backends = %v, want [HTTP]", upCert.Backends)
	}

	upScp, err := OperationByName("upload_certificate_scp")
	if err != nil {
		t.Fatalf("OperationByName(upload_certificate_scp): %v", err)
	}
	wantScp := map[model.Backend]bool{model.BackendSSH: true, model.BackendTelnet: true, model.BackendConsole: true}
	if len(upScp.Backends) != 3 {
		t.Errorf("upload_certificate_scp.Backends = %v, want 3 entries (SSH, TELNET, CONSOLE)", upScp.Backends)
	}
	for _, b := range upScp.Backends {
		if !wantScp[b] {
			t.Errorf("upload_certificate_scp.Backends contains unexpected %v", b)
		}
	}

	getPorts, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	if getPorts.Backends != nil {
		t.Errorf("get_ports.Backends = %v, want nil (unrestricted)", getPorts.Backends)
	}

	setPortDescription, err := OperationByName("set_port_description")
	if err != nil {
		t.Fatalf("OperationByName(set_port_description): %v", err)
	}
	if setPortDescription.Backends != nil {
		t.Errorf("set_port_description.Backends = %v, want nil (unrestricted)", setPortDescription.Backends)
	}

	wantBackends := map[string]map[model.Backend]bool{
		"get_users":               {model.BackendHTTP: true, model.BackendSSH: true, model.BackendTelnet: true, model.BackendConsole: true},
		"get_services":            {model.BackendHTTP: true, model.BackendSSH: true, model.BackendTelnet: true, model.BackendConsole: true},
		"get_syslog":              {model.BackendSNMP: true, model.BackendHTTP: true, model.BackendSSH: true, model.BackendTelnet: true, model.BackendConsole: true},
		"set_port_speed":          {model.BackendHTTP: true, model.BackendSSH: true, model.BackendTelnet: true, model.BackendConsole: true},
		"set_flow_control":        {model.BackendSSH: true, model.BackendTelnet: true, model.BackendConsole: true},
		"set_hostname":            {model.BackendSNMP: true, model.BackendNSDP: true, model.BackendHTTP: true, model.BackendSSH: true, model.BackendTelnet: true, model.BackendConsole: true},
		"set_syslog_enabled":      {model.BackendSNMP: true, model.BackendSSH: true, model.BackendTelnet: true, model.BackendConsole: true},
		"add_syslog_collector":    {model.BackendSSH: true, model.BackendTelnet: true, model.BackendConsole: true},
		"remove_syslog_collector": {model.BackendSNMP: true, model.BackendHTTP: true, model.BackendSSH: true, model.BackendTelnet: true, model.BackendConsole: true},
	}
	for name, want := range wantBackends {
		op, err := OperationByName(name)
		if err != nil {
			t.Fatalf("OperationByName(%s): %v", name, err)
		}
		if len(op.Backends) != len(want) {
			t.Errorf("%s.Backends = %v, want %d entries", name, op.Backends, len(want))
			continue
		}
		for _, b := range op.Backends {
			if !want[b] {
				t.Errorf("%s.Backends contains unexpected %v", name, b)
			}
		}
	}
}

func TestOperationByNameUnknown(t *testing.T) {
	_, err := OperationByName("get_nonsense")
	if !errors.Is(err, ErrUnknownOperation) {
		t.Errorf("OperationByName(get_nonsense) error = %v, want wrapping ErrUnknownOperation", err)
	}
}

func TestCapabilitySupported(t *testing.T) {
	c := Capability{Support: SupportSupported}
	if !c.Supported() {
		t.Error("Capability{Support: SupportSupported}.Supported() = false, want true")
	}
	c.Support = SupportUnsupported
	if c.Supported() {
		t.Error("Capability{Support: SupportUnsupported}.Supported() = true, want false")
	}
}

// TestPoEOpsMembership and TestNoPSE exercise poeOps/noPSE directly. Both are
// unexported helpers Tasks 4 and 7 (snmpSupport/cliSupport) consume from
// their own files -- pinned here too, at the point they are introduced, so
// this package never carries an unreferenced-at-HEAD helper between the two
// tasks' commits.
func TestPoEOpsMembership(t *testing.T) {
	want := []string{"get_poe", "set_poe", "cycle_poe", "clear_poe_fault"}
	if len(poeOps) != len(want) {
		t.Errorf("len(poeOps) = %d, want %d", len(poeOps), len(want))
	}
	for _, name := range want {
		if !poeOps[name] {
			t.Errorf("poeOps[%q] = false, want true", name)
		}
	}
}

func TestNoPSE(t *testing.T) {
	m, err := model.GetModel("m4300-24x") // PoEPortCount == 0
	if err != nil {
		t.Fatalf("GetModel(m4300-24x): %v", err)
	}
	support, reason := noPSE(m)
	if support != SupportUnsupported {
		t.Errorf("noPSE(m4300-24x) support = %v, want SupportUnsupported", support)
	}
	if reason == "" {
		t.Error("noPSE(m4300-24x) reason is empty")
	}
}
