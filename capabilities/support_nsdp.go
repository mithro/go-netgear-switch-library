package capabilities

// support_nsdp.go: the NSDP-backend derivation, ported field-for-field from
// src/netgear_switch/capabilities.py's _nsdp_support (pin go-port-pin-a9e0ebc,
// lines 222-240). Any discrepancy between this file and that pin is a bug in
// this file.
//
// WARNING (R1, dossier): create_vlan/delete_vlan are DELIBERATELY absent
// from nsdpRefusals below -- nsdp/writer.go's CreateVlan/DeleteVlan are real,
// verified-after-write NSDP implementations (see that file's own doc
// comment: "VLAN create/delete ARE implemented here"). Do not add either to
// this map without first confirming nsdp.Writer has regressed.

import (
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

// nsdpRefusals maps an operation name to the reader's/writer's own message
// constant, so a change to what NSDP refuses updates this table in the same
// edit as the constant itself -- mirrors Python's _nsdp_support refusals
// dict verbatim (capabilities.py:227-236).
var nsdpRefusals = map[string]string{
	"get_macs":         nsdp.NoMACsMsg,
	"get_lldp":         nsdp.NoLLDPMsg,
	"get_sensors":      nsdp.NoSensorsMsg,
	"get_poe":          nsdp.NoPoEReadMsg,
	"set_poe":          nsdp.NoPoEWriteMsg,
	"cycle_poe":        nsdp.NoPoEWriteMsg,
	"clear_poe_fault":  nsdp.NoPoEWriteMsg,
	"set_port_enabled": nsdp.NoPortAdminMsg,
}

// nsdpSupport derives the NSDP-backend verdict for op. m is unused today
// (kept for signature symmetry with snmpSupport/httpSupport/cliSupport, and
// because Python's _nsdp_support(model, op) also accepts an unused model
// parameter) -- NSDP's refusals are a flat, model-independent lookup by
// operation name.
func nsdpSupport(_ *model.SwitchModel, op Operation) (Support, string) {
	if reason, ok := nsdpRefusals[op.Name]; ok {
		return SupportUnsupported, reason
	}
	return SupportSupported, ""
}
