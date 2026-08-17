package capabilities

// support_snmp.go: the SNMP-backend derivation, ported field-for-field from
// src/netgear_switch/capabilities.py's _snmp_support (pin go-port-pin-b26eb1f,
// lines 419-466). Any discrepancy between this file and that pin is a bug in
// this file.

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// snmpSupport derives the SNMP-backend verdict for (m, op). SnmpReader/
// SnmpWriter serve almost everything from standard MIBs; the model-dependent
// refusals below are the guards they raise themselves -- this function reads
// the SAME model/snmp package data those guards read, never a parallel rule.
func snmpSupport(m *model.SwitchModel, op Operation) (Support, string) {
	if poeOps[op.Name] && m.PoEPortCount == 0 {
		return noPSE(m)
	}
	if op.Name == "create_vlan" && !m.SNMPCanCreateVLAN {
		// Reuse the writer's OWN refusal text (snmp.Writer.CreateVlan,
		// snmp/writer_vlan.go's requireSNMPVLANCreation, pin b26eb1f /
		// commit f8a890f) so the table and the code that enforces it cannot
		// drift apart -- mirroring Python's capabilities.py importing
		// _NO_VLAN_CREATE from snmp_write.py rather than duplicating it.
		return SupportUnsupported, fmt.Sprintf("model %q: %s", m.Key, snmp.NoVLANCreateMsg)
	}
	if op.Name == "set_mgmt_ip" && !snmp.HasVendorOids(m) {
		// SNMP writer's set_mgmt_ip writes the vendor mgmt-IP columns, so a
		// model whose agent registers no 4526 subtree at all has nothing to
		// write. The READ path has a standard-MIB fallback; the write does
		// not.
		return SupportUnsupported, fmt.Sprintf(
			"model %q registers no Netgear vendor OID subtree, and the management-IP write columns are vendor-only",
			m.Key)
	}
	if op.Name == "get_macs" && !m.HasMACTable() {
		// Unreachable today: HasMACTable() IS "has an SNMP backend", and this
		// function only runs when backend == SNMP. Kept defensively, mirroring
		// Python's own "# pragma: no cover" comment on the identical branch.
		return SupportUnsupported, fmt.Sprintf("model %q has no MAC/FDB table", m.Key)
	}
	if (op.Name == "get_syslog" || op.Name == "set_syslog_enabled" || op.Name == "remove_syslog_collector") && !snmp.HasVendorOids(m) {
		// Logging lives at <vendor base>.14 on both vendor families, so a
		// model whose agent registers no 4526 subtree at all (gs728tpp -- a
		// walk of 1.3.6.1.4.1.4526 answers noSuchObject) has nothing to read
		// OR write. Reader.GetSyslog and Writer.SetSyslogEnabled/
		// RemoveSyslogCollector all refuse by name for the same reason: an
		// empty result would be indistinguishable from a switch with no
		// collectors, and a write has no column to land in.
		return SupportUnsupported, fmt.Sprintf(
			"model %q registers no Netgear vendor OID subtree, and the logging columns are vendor-only",
			m.Key)
	}
	return SupportSupported, ""
}
