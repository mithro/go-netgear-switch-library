package capabilities

// support_cli.go: the CLI-backend (SSH/Telnet/Console) derivation, ported
// field-for-field from src/netgear_switch/capabilities.py's _cli_support
// (pin go-port-pin-a9e0ebc, lines 314-341), plus the Python _dispatch
// module's cli_reads_supported/cli_writes_supported (_dispatch.py:202-234),
// which Go has no direct equivalent of yet -- re-derived here directly from
// fastpath.CLISpec rather than duplicated as a separate exported helper,
// since nothing else in this codebase needs it today. Any discrepancy
// between this file and the pin is a bug in this file.

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/fastpath"
	"github.com/mithro/go-netgear-switch-library/model"
)

// cliReadsSupported reports whether m's CLI reads are dispatchable: it has a
// CLI backend AND that backend's CliModelSpec.ReadsVerified is true.
// Mirrors Python's cli_reads_supported. Returns the resolved spec too (nil
// on failure) so cliWritesSupported/cliSupport need not look it up twice.
func cliReadsSupported(m *model.SwitchModel) (bool, *fastpath.CliModelSpec) {
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		return false, nil
	}
	return spec.ReadsVerified, spec
}

// cliWritesSupported additionally requires cliReadsSupported(m) AND
// WritesVerified -- verification is layered: a write can't be honestly
// verified by reading back through an unverified reader. Mirrors Python's
// cli_writes_supported.
func cliWritesSupported(m *model.SwitchModel) bool {
	ok, spec := cliReadsSupported(m)
	return ok && spec.WritesVerified
}

// cliSupport derives the CLI-backend verdict for (m, op).
func cliSupport(m *model.SwitchModel, op Operation) (Support, string) {
	readsOK, _ := cliReadsSupported(m)
	if op.Kind == OperationKindRead && !readsOK {
		return SupportUnverified, fmt.Sprintf("model %q CLI reads are UNVERIFIED-pending cross-verify", m.Key)
	}
	if op.Kind == OperationKindWrite && !cliWritesSupported(m) {
		return SupportUnverified, fmt.Sprintf("model %q CLI writes are UNVERIFIED-pending a live write run", m.Key)
	}
	if op.Name == "upload_certificate_scp" {
		// The facade's real dispatch gate is fastpath.ScpProfile itself --
		// ask it rather than re-listing which models have a copy-scp
		// profile, mirroring Python's identical comment on this branch.
		if _, err := fastpath.ScpProfile(m); err != nil {
			return SupportUnsupported, err.Error()
		}
		return SupportSupported, ""
	}
	if poeOps[op.Name] && m.PoEPortCount == 0 {
		return noPSE(m)
	}
	if op.Name == "get_macs" && !m.HasMACTable() {
		// Same "currently unreachable" caveat as snmpSupport's identical
		// branch: every model with a CLI backend today also has SNMP.
		return SupportUnsupported, fmt.Sprintf("model %q CLI has no MAC/FDB table", m.Key)
	}
	return SupportSupported, ""
}
