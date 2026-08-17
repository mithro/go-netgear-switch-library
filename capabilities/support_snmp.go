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

// noVLANCreateMsg is why an SNMP VLAN create is refused on a model whose
// agent cannot do it (model.SwitchModel.SNMPCanCreateVLAN == false),
// translated from Python's snmp_write._NO_VLAN_CREATE (this codebase's
// reason text is never asserted byte-identical to Python's -- see this
// package's plan's "Deliberate divergences" note 2).
//
// Unlike the NSDP refusal messages in support_nsdp.go, this is NOT reused
// from a snmp package writer constant: snmp.Writer.CreateVlan
// (snmp/writer_vlan.go) does not itself enforce this gate yet -- it
// attempts the RowStatus create SET unconditionally, for every model. That
// is a real, pre-existing gap this capabilities-oracle refresh surfaces but
// does not close (wiring model.SwitchModel.SNMPCanCreateVLAN into
// snmp.Writer.CreateVlan, mirroring Python's snmp_write._require_snmp_vlan_
// creation, is tracked follow-up work). The oracle still asserts the
// correct verdict here because it derives from model.SwitchModel.
// SNMPCanCreateVLAN -- the SAME registry fact Python's model.
// snmp_can_create_vlan carries -- not from what the writer currently does.
const noVLANCreateMsg = "this model's SNMP agent cannot create a VLAN: every RowStatus mechanism " +
	"(createAndGo, createAndGo+name in one PDU, createAndWait->name->active, the name column alone, " +
	"and createAndGo carrying an egress PortList) is answered inconsistentValue -- measured on the " +
	"device. Membership, PVID and delete DO work over SNMP; create a VLAN over the HTTP backend"

// snmpSupport derives the SNMP-backend verdict for (m, op). SnmpReader/
// SnmpWriter serve almost everything from standard MIBs; the model-dependent
// refusals below are the guards they raise themselves -- this function reads
// the SAME model/snmp package data those guards read, never a parallel rule.
func snmpSupport(m *model.SwitchModel, op Operation) (Support, string) {
	if poeOps[op.Name] && m.PoEPortCount == 0 {
		return noPSE(m)
	}
	if op.Name == "create_vlan" && !m.SNMPCanCreateVLAN {
		// Reuse the writer's own refusal text so the table and the code
		// that (eventually) enforces it cannot drift apart -- see
		// noVLANCreateMsg's own doc comment for the current caveat.
		return SupportUnsupported, fmt.Sprintf("model %q: %s", m.Key, noVLANCreateMsg)
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
