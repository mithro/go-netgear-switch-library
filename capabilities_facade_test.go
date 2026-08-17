package netgearswitch_test

// capabilities_facade_test.go: pins two cross-package invariants the
// capabilities package itself cannot check (it must not import the root
// netgearswitch package -- that would cycle back through alias.go):
//
//  1. every capabilities.Operation.Name maps onto a real method on
//     *netgearswitch.Switch, mirroring Python's test_operations_are_facade_
//     methods.
//  2. the root package's curated re-export subset (Task 9's alias.go
//     additions) actually compiles and behaves identically to calling
//     capabilities.X directly.

import (
	"reflect"
	"testing"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/capabilities"
	"github.com/mithro/go-netgear-switch-library/model"
)

// operationFacadeMethod maps each capabilities.Operation.Name to the real
// *netgearswitch.Switch method name it corresponds to.
var operationFacadeMethod = map[string]string{
	"get_ports":               "GetPorts",
	"get_stats":               "GetStats",
	"get_vlans":               "GetVLANs",
	"get_pvids":               "GetPVIDs",
	"get_lldp":                "GetLLDP",
	"get_macs":                "GetMACs",
	"get_poe":                 "GetPoE",
	"get_sensors":             "GetSensors",
	"get_mgmt_ip":             "GetMgmtIP",
	"get_hostname":            "GetHostname",
	"get_users":               "GetUsers",
	"get_services":            "GetServices",
	"get_syslog":              "GetSyslog",
	"nsdp_device":             "NSDPDevice",
	"set_port_enabled":        "SetPortEnabled",
	"set_poe":                 "SetPoE",
	"cycle_poe":               "CyclePoE",
	"clear_poe_fault":         "ClearPoEFault",
	"set_port_description":    "SetPortDescription",
	"set_port_speed":          "SetPortSpeed",
	"set_flow_control":        "SetFlowControl",
	"set_pvid":                "SetPVID",
	"set_vlan_membership":     "SetVlanMembership",
	"create_vlan":             "CreateVlan",
	"delete_vlan":             "DeleteVlan",
	"set_mgmt_ip":             "SetMgmtIP",
	"set_hostname":            "SetHostname",
	"set_syslog_enabled":      "SetSyslogEnabled",
	"add_syslog_collector":    "AddSyslogCollector",
	"remove_syslog_collector": "RemoveSyslogCollector",
	"upload_certificate":      "UploadCertificate",
	"upload_certificate_scp":  "UploadCertificateSCP",
}

func TestOperationsAreFacadeMethods(t *testing.T) {
	switchType := reflect.TypeOf((*netgearswitch.Switch)(nil))
	for _, op := range capabilities.Operations {
		methodName, mapped := operationFacadeMethod[op.Name]
		if !mapped {
			t.Errorf("operation %q has no entry in operationFacadeMethod", op.Name)
			continue
		}
		if _, ok := switchType.MethodByName(methodName); !ok {
			t.Errorf("capabilities operation %q -> *Switch.%s, but no such method exists", op.Name, methodName)
		}
	}
	for _, op := range capabilities.ReadOperations {
		if op.Kind != capabilities.OperationKindRead {
			t.Errorf("ReadOperations: %q has Kind %v, want OperationKindRead", op.Name, op.Kind)
		}
	}
	for _, op := range capabilities.WriteOperations {
		if op.Kind != capabilities.OperationKindWrite {
			t.Errorf("WriteOperations: %q has Kind %v, want OperationKindWrite", op.Name, op.Kind)
		}
	}
}

func TestRootPackageReExportsMatchCapabilitiesPackage(t *testing.T) {
	m, err := netgearswitch.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("GetModel: %v", err)
	}
	viaRoot := netgearswitch.For(m, netgearswitch.BackendSNMP, capabilities.Operations[0])
	viaPkg := capabilities.For(m, model.BackendSNMP, capabilities.Operations[0])
	if !reflect.DeepEqual(viaRoot, viaPkg) {
		t.Errorf("netgearswitch.For(...) = %+v, want equal to capabilities.For(...) = %+v", viaRoot, viaPkg)
	}

	rootBackends := netgearswitch.BackendsFor(m)
	pkgBackends := capabilities.BackendsFor(m)
	if !reflect.DeepEqual(rootBackends, pkgBackends) {
		t.Errorf("netgearswitch.BackendsFor(...) = %v, want equal to capabilities.BackendsFor(...) = %v", rootBackends, pkgBackends)
	}

	if len(netgearswitch.Operations) != len(capabilities.Operations) {
		t.Errorf("len(netgearswitch.Operations) = %d, want %d", len(netgearswitch.Operations), len(capabilities.Operations))
	}

	rootCap, err := netgearswitch.ForKey("gsm7252ps", netgearswitch.BackendSNMP, "get_ports")
	if err != nil {
		t.Fatalf("netgearswitch.ForKey: %v", err)
	}
	if !rootCap.Supported() {
		t.Errorf("netgearswitch.ForKey(gsm7252ps, SNMP, get_ports).Supported() = false, want true")
	}
}
