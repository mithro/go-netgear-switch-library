// Package capabilities answers one question -- can model M do operation O
// over backend B, and why not? -- without touching a switch. It is a pure,
// stateless oracle: every verdict is derived from the SAME registry/spec
// objects the real dispatch path (dispatch.go, write_dispatch.go) reads --
// model.SwitchModel fields, webui.HTTPModelSpec endpoint paths,
// fastpath.CliModelSpec verification flags, fastpath.ScpProfile -- never a
// parallel hand-written table, so this package can never quietly disagree
// with what dispatch actually does.
//
// Ported field-for-field from src/netgear_switch/capabilities.py (pinned
// worktree go-port-pin-a9e0ebc). Any discrepancy between this package and
// that pin is a bug in this package, not a deliberate deviation, unless
// called out in a comment.
//
// types.go: the capability data model -- Support/OperationKind/Operation/
// Capability plus the fixed 21-entry Operations table, ported field-for-
// field from capabilities.py lines 62-180.
package capabilities

import (
	"errors"
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
)

// Support is how a (model, backend, operation) triple is served -- or
// refused. Values are chosen to equal Python's Support enum's .value
// strings byte-for-byte (load-bearing for the golden-fixture cross-check in
// capabilities/matrix_parity_test.go).
type Support string

const (
	// SupportSupported means the backend implements this operation for this model.
	SupportSupported Support = "supported"
	// SupportNoBackend means the model does not have this backend at all --
	// what dispatch.go's resolveBackend refuses before any operation is
	// considered.
	SupportNoBackend Support = "no-backend"
	// SupportUnsupported means the model has the backend, but that backend
	// cannot serve this operation -- either the protocol has no such notion
	// (NSDP has no PoE tag) or the device genuinely lacks the hardware (no
	// PSE ports). Never a stand-in for "not implemented yet" (principle 2).
	SupportUnsupported Support = "unsupported"
	// SupportUnverified means the operation is implemented, but gated off
	// because the backend's per-model spec is not yet cross-verified against
	// live hardware (HTTPModelSpec.ReadsVerified /
	// CliModelSpec.ReadsVerified/WritesVerified).
	SupportUnverified Support = "unverified"
)

// OperationKind is whether an Operation reads or writes device state.
type OperationKind string

// OperationKind values, mirroring Python's OperationKind enum.
const (
	OperationKindRead  OperationKind = "read"
	OperationKindWrite OperationKind = "write"
)

// Operation is one facade operation, as exposed by *netgearswitch.Switch.
// Name is the operation's Python-derived snake_case identifier (e.g.
// "get_ports"), NOT the Go facade method name (e.g. GetPorts) -- see this
// plan's "Deliberate divergences" note 3 for why: it keeps this table a
// stable doc/lookup key independent of Go naming, and keeps the golden-
// fixture cross-check (capabilities/matrix_parity_test.go) a trivial exact
// string match against the pinned Python's own Operation.name values.
type Operation struct {
	Name    string
	Kind    OperationKind
	Summary string
	// Backends restricts which backends can EVER serve this operation,
	// for the few that bypass normal per-model backend membership
	// (nsdp_device is NSDP-only; certificate upload is HTTP or CLI-over-SCP).
	// nil means "any backend the model has". A non-nil Backends is always
	// non-empty in practice -- treat nil and non-nil-empty as the same
	// "unrestricted" state only via the nil check, never len() == 0, since
	// this codebase never constructs the latter.
	Backends []model.Backend
}

var cliBackends = []model.Backend{model.BackendSSH, model.BackendTelnet, model.BackendConsole}

// ReadOperations are the 10 read-kind operations, in the pinned Python
// source's exact order (capabilities.py:104-122).
var ReadOperations = []Operation{
	{Name: "get_ports", Kind: OperationKindRead, Summary: "Per-port link/admin status"},
	{Name: "get_stats", Kind: OperationKindRead, Summary: "Per-port octet/packet counters"},
	{Name: "get_vlans", Kind: OperationKindRead, Summary: "VLAN list with tagged/untagged members"},
	{Name: "get_pvids", Kind: OperationKindRead, Summary: "Per-port PVID"},
	{Name: "get_lldp", Kind: OperationKindRead, Summary: "LLDP neighbour table"},
	{Name: "get_macs", Kind: OperationKindRead, Summary: "MAC/FDB forwarding table"},
	{Name: "get_poe", Kind: OperationKindRead, Summary: "Per-port PoE status and power draw"},
	{Name: "get_sensors", Kind: OperationKindRead, Summary: "Fan/PSU/temperature sensors"},
	{Name: "get_mgmt_ip", Kind: OperationKindRead, Summary: "Management IP configuration"},
	{Name: "nsdp_device", Kind: OperationKindRead, Summary: "Full NSDP device record", Backends: []model.Backend{model.BackendNSDP}},
}

// WriteOperations are the 11 write-kind operations, in the pinned Python
// source's exact order (capabilities.py:124-150).
var WriteOperations = []Operation{
	{Name: "set_port_enabled", Kind: OperationKindWrite, Summary: "Bring a port up or down"},
	{Name: "set_poe", Kind: OperationKindWrite, Summary: "Enable or disable PoE on a port"},
	{Name: "cycle_poe", Kind: OperationKindWrite, Summary: "Power-cycle a PoE port"},
	{Name: "clear_poe_fault", Kind: OperationKindWrite, Summary: "Clear a latched PoE fault"},
	{Name: "set_pvid", Kind: OperationKindWrite, Summary: "Set a port's PVID"},
	{Name: "set_vlan_membership", Kind: OperationKindWrite, Summary: "Set a port tagged/untagged/excluded on a VLAN"},
	{Name: "create_vlan", Kind: OperationKindWrite, Summary: "Create a VLAN"},
	{Name: "delete_vlan", Kind: OperationKindWrite, Summary: "Delete a VLAN"},
	{Name: "set_mgmt_ip", Kind: OperationKindWrite, Summary: "Set the management IP/mask/gateway"},
	{Name: "upload_certificate", Kind: OperationKindWrite, Summary: "Upload an HTTPS certificate over the web UI", Backends: []model.Backend{model.BackendHTTP}},
	{Name: "upload_certificate_scp", Kind: OperationKindWrite, Summary: "Deploy an HTTPS certificate via FASTPATH copy scp://", Backends: cliBackends},
}

// Operations is ReadOperations followed by WriteOperations, 21 entries
// total, mirroring Python's OPERATIONS = READ_OPERATIONS + WRITE_OPERATIONS.
var Operations = append(append([]Operation{}, ReadOperations...), WriteOperations...)

var byName = func() map[string]Operation {
	m := make(map[string]Operation, len(Operations))
	for _, op := range Operations {
		m[op.Name] = op
	}
	return m
}()

// ErrUnknownOperation is wrapped by OperationByName's error on a miss; match
// with errors.Is.
var ErrUnknownOperation = errors.New("unknown operation")

// OperationByName looks an Operation up by its facade method name (e.g.
// "get_ports"), mirroring Python's operation(name). On a miss it returns an
// error wrapping ErrUnknownOperation, matching model.GetModel's own
// lookup-miss convention (fmt.Errorf("%s: %w", key, Err...)) rather than
// Python's KeyError.
func OperationByName(name string) (Operation, error) {
	op, ok := byName[name]
	if !ok {
		return Operation{}, fmt.Errorf("%s: %w", name, ErrUnknownOperation)
	}
	return op, nil
}

// Capability is the verdict for one (model, backend, operation) triple,
// mirroring Python's frozen Capability dataclass. Not ==-comparable (see
// this plan's "Deliberate divergences" note 4) because Operation.Backends is
// a slice; use reflect.DeepEqual in tests that compare two Capability values.
type Capability struct {
	ModelKey  string
	Backend   model.Backend
	Operation Operation
	Support   Support
	// Reason is empty when Support == SupportSupported; otherwise the
	// reason, phrased the way the corresponding reader/writer phrases its
	// own refusal (see this plan's "Deliberate divergences" note 2 for why
	// this text is NOT byte-identical to Python's).
	Reason string
}

// Supported reports whether c.Support == SupportSupported.
func (c Capability) Supported() bool {
	return c.Support == SupportSupported
}

// poeOps is the set of operations gated by a model having zero PSE ports,
// mirroring Python's _POE_OPS. Shared by the SNMP (Task 4) and CLI (Task 7)
// derivations -- NSDP and HTTP gate PoE differently (NSDP: no tag at all,
// unconditionally; HTTP: a missing page, which already naturally resolves
// to UNSUPPORTED via httpPathFor without needing this set).
var poeOps = map[string]bool{
	"get_poe": true, "set_poe": true, "cycle_poe": true, "clear_poe_fault": true,
}

// noPSE returns the UNSUPPORTED verdict for a PoE op on a model with zero
// PSE ports, mirroring Python's _no_pse.
func noPSE(m *model.SwitchModel) (Support, string) {
	return SupportUnsupported, fmt.Sprintf("%s has no PSE ports, so it has no PoE to report or set", m.DisplayName)
}
