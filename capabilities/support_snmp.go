package capabilities

// support_snmp.go: the SNMP-backend derivation, ported field-for-field from
// src/netgear_switch/capabilities.py's _snmp_support (pin go-port-pin-a9e0ebc,
// lines 197-219). Any discrepancy between this file and that pin is a bug in
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
	return SupportSupported, ""
}
