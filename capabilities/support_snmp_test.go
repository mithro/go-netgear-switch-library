package capabilities

// support_snmp_test.go: pins snmpSupport's branches against Python's
// _snmp_support (capabilities.py:419-466).

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func mustModelSnmp(t *testing.T, key string) *model.SwitchModel {
	t.Helper()
	m, err := model.GetModel(key)
	if err != nil {
		t.Fatalf("GetModel(%q): %v", key, err)
	}
	return m
}

func TestSNMPSupportNoPSE(t *testing.T) {
	// m4300-24x: SNMP model with PoEPortCount == 0.
	m := mustModelSnmp(t, "m4300-24x")
	for _, opName := range []string{"get_poe", "set_poe", "cycle_poe", "clear_poe_fault"} {
		op, err := OperationByName(opName)
		if err != nil {
			t.Fatalf("OperationByName(%q): %v", opName, err)
		}
		support, reason := snmpSupport(m, op)
		if support != SupportUnsupported {
			t.Errorf("snmpSupport(m4300-24x, %s) = %v, want SupportUnsupported", opName, support)
		}
		if reason == "" {
			t.Errorf("snmpSupport(m4300-24x, %s) reason is empty", opName)
		}
	}
}

func TestSNMPSupportSetMgmtIPNoVendorOIDs(t *testing.T) {
	// gs728tpp: SNMP model with SNMPVendorBase == "" (no 4526 subtree).
	m := mustModelSnmp(t, "gs728tpp")
	op, err := OperationByName("set_mgmt_ip")
	if err != nil {
		t.Fatalf("OperationByName(set_mgmt_ip): %v", err)
	}
	support, reason := snmpSupport(m, op)
	if support != SupportUnsupported {
		t.Errorf("snmpSupport(gs728tpp, set_mgmt_ip) = %v, want SupportUnsupported", support)
	}
	if reason == "" {
		t.Error("snmpSupport(gs728tpp, set_mgmt_ip) reason is empty")
	}
}

func TestSNMPSupportDefaultSupported(t *testing.T) {
	m := mustModelSnmp(t, "m4300-24x")
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	support, reason := snmpSupport(m, op)
	if support != SupportSupported {
		t.Errorf("snmpSupport(m4300-24x, get_ports) = %v, want SupportSupported", support)
	}
	if reason != "" {
		t.Errorf("snmpSupport(m4300-24x, get_ports) reason = %q, want empty", reason)
	}
}

func TestSNMPSupportCannotCreateVLAN(t *testing.T) {
	// gs728tpp: the one model with SNMPCanCreateVLAN == false.
	m := mustModelSnmp(t, "gs728tpp")
	if m.SNMPCanCreateVLAN {
		t.Fatalf("gs728tpp.SNMPCanCreateVLAN = true, want false (test assumption broken)")
	}
	op, err := OperationByName("create_vlan")
	if err != nil {
		t.Fatalf("OperationByName(create_vlan): %v", err)
	}
	support, reason := snmpSupport(m, op)
	if support != SupportUnsupported {
		t.Errorf("snmpSupport(gs728tpp, create_vlan) = %v, want SupportUnsupported", support)
	}
	if reason == "" {
		t.Error("snmpSupport(gs728tpp, create_vlan) reason is empty")
	}

	// Every other SNMP model can create a VLAN.
	m2 := mustModelSnmp(t, "m4300-24x")
	support2, reason2 := snmpSupport(m2, op)
	if support2 != SupportSupported {
		t.Errorf("snmpSupport(m4300-24x, create_vlan) = %v, want SupportSupported", support2)
	}
	if reason2 != "" {
		t.Errorf("snmpSupport(m4300-24x, create_vlan) reason = %q, want empty", reason2)
	}
}

func TestSNMPSupportSyslogNoVendorOIDs(t *testing.T) {
	// gs728tpp: SNMPVendorBase == "" (no 4526 subtree), so the logging
	// columns (get_syslog/set_syslog_enabled/remove_syslog_collector) are
	// all refused the same way set_mgmt_ip's vendor-only write columns are.
	m := mustModelSnmp(t, "gs728tpp")
	for _, opName := range []string{"get_syslog", "set_syslog_enabled", "remove_syslog_collector"} {
		op, err := OperationByName(opName)
		if err != nil {
			t.Fatalf("OperationByName(%q): %v", opName, err)
		}
		support, reason := snmpSupport(m, op)
		if support != SupportUnsupported {
			t.Errorf("snmpSupport(gs728tpp, %s) = %v, want SupportUnsupported", opName, support)
		}
		if reason == "" {
			t.Errorf("snmpSupport(gs728tpp, %s) reason is empty", opName)
		}
	}

	// A model with a vendor OID subtree serves all three normally.
	m2 := mustModelSnmp(t, "m4300-24x")
	for _, opName := range []string{"get_syslog", "set_syslog_enabled", "remove_syslog_collector"} {
		op, err := OperationByName(opName)
		if err != nil {
			t.Fatalf("OperationByName(%q): %v", opName, err)
		}
		support, reason := snmpSupport(m2, op)
		if support != SupportSupported {
			t.Errorf("snmpSupport(m4300-24x, %s) = %v, want SupportSupported", opName, support)
		}
		if reason != "" {
			t.Errorf("snmpSupport(m4300-24x, %s) reason = %q, want empty", opName, reason)
		}
	}
}

func TestSNMPSupportUnverifiedFlagIgnored(t *testing.T) {
	// m7300 has Verified == false but IS an SNMP model with real PoE/vendor
	// derivation rules that must still run normally -- see this plan's
	// "Deliberate divergences" note 5: Verified is never read by the oracle.
	m := mustModelSnmp(t, "m7300")
	op, err := OperationByName("get_ports")
	if err != nil {
		t.Fatalf("OperationByName(get_ports): %v", err)
	}
	support, _ := snmpSupport(m, op)
	if support != SupportSupported {
		t.Errorf("snmpSupport(m7300, get_ports) = %v, want SupportSupported (Verified must not gate this)", support)
	}
}
