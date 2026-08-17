package capabilities

// support.go: the top-level dispatcher -- For/BackendsFor/ForKey/Matrix --
// ported field-for-field from src/netgear_switch/capabilities.py's
// support()/backends_for()/matrix() (pin go-port-pin-b26eb1f, lines
// 692-762). Any discrepancy between this file and that pin is a bug in this
// file. Unchanged in substance by the b26eb1f refresh -- these three
// functions are op/operation-table agnostic, so growing the Operations
// table from 21 to 32 entries required no edits here.
//
// Naming: Python's free function support(model, backend, op) cannot be
// named Support in Go (the type Support already claims that identifier) --
// this port uses For. operation(name) becomes OperationByName (types.go);
// matrix(models=None, operations=OPERATIONS) becomes Matrix with nil-slice
// defaults, since Go has no keyword-default arguments.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// backendOrder is the model's backends in the facade's default-preference
// order, mirroring Python's LOCALLY-restated tuple in backends_for
// (capabilities.py:388-395) -- deliberately NOT dispatch.go's
// backendPreference (which only lists 4 backends and is used for a
// different purpose, real default-backend RESOLUTION). Python re-states its
// own copy rather than importing sync_api._BACKEND_PREFERENCE; this mirrors
// that same deliberate duplication-by-convention.
var backendOrder = []model.Backend{
	model.BackendSNMP, model.BackendNSDP, model.BackendHTTP,
	model.BackendSSH, model.BackendTelnet, model.BackendConsole,
}

// BackendsFor returns m's backends in the facade's default-preference
// order, mirroring Python's backends_for.
func BackendsFor(m *model.SwitchModel) []model.Backend {
	out := make([]model.Backend, 0, len(backendOrder))
	for _, b := range backendOrder {
		if m.HasBackend(b) {
			out = append(out, b)
		}
	}
	return out
}

// backendRestricts reports whether op.Backends is set and does NOT include
// backend.
func backendRestricts(op Operation, backend model.Backend) bool {
	if op.Backends == nil {
		return false
	}
	for _, b := range op.Backends {
		if b == backend {
			return false
		}
	}
	return true
}

// sortedBackendNames renders backends as a sorted, comma-joined string of
// their (Go-lowercase) names, for reason text -- mirrors Python's
// ", ".join(sorted(b.name for b in ...)) shape, but in this codebase's own
// established lowercase Backend spelling (see this plan's "Deliberate
// divergences" note 1).
func sortedBackendNames(backends []model.Backend) string {
	names := make([]string, len(backends))
	for i, b := range backends {
		names[i] = string(b)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// For is the verdict for one (model, backend, operation) triple, mirroring
// Python's support(). Never errors: m and op are already-resolved concrete
// values, so there is nothing left to look up that can fail -- unlike
// Python's support(), which accepts raw string keys and can raise. Use
// ForKey for the string-based entry point.
func For(m *model.SwitchModel, backend model.Backend, op Operation) Capability {
	if !m.HasBackend(backend) {
		reason := fmt.Sprintf("model %q has no %s backend (it has: %s)", m.Key, backend, sortedBackendNames(m.Backends))
		if backend == model.BackendConsole {
			// CONSOLE is never a member of any model's Backends (it is a
			// transport for the CLI backend, not a network backend) -- say
			// so explicitly, rather than implying the CLI is absent on a
			// model whose SSH/Telnet works fine.
			reason = "CONSOLE is a serial transport for the CLI backend, not a network backend; a model's CLI support is its SSH/TELNET entry"
		}
		return Capability{ModelKey: m.Key, Backend: backend, Operation: op, Support: SupportNoBackend, Reason: reason}
	}

	if backendRestricts(op, backend) {
		reason := fmt.Sprintf("%s is served only over %s", op.Name, sortedBackendNames(op.Backends))
		return Capability{ModelKey: m.Key, Backend: backend, Operation: op, Support: SupportUnsupported, Reason: reason}
	}

	var support Support
	var reason string
	switch backend {
	case model.BackendSNMP:
		support, reason = snmpSupport(m, op)
	case model.BackendNSDP:
		support, reason = nsdpSupport(m, op)
	case model.BackendHTTP:
		spec, err := webui.HTTPSpec(m)
		if err != nil {
			// Defensive: cannot happen for any of the 10 currently
			// registered models (every one with an HTTP backend has a
			// matching webui.HTTPSpecs entry) -- if it ever does, fold it
			// into UNSUPPORTED with the underlying error's own text rather
			// than panicking or silently claiming SUPPORTED.
			support, reason = SupportUnsupported, err.Error()
		} else {
			support, reason = httpSupport(m, spec, op)
		}
	default: // SSH, Telnet -- Console is always caught by the NO_BACKEND check above
		support, reason = cliSupport(m, op)
	}
	return Capability{ModelKey: m.Key, Backend: backend, Operation: op, Support: support, Reason: reason}
}

// ForKey is For's string-keyed convenience entry point, mirroring Python's
// support() accepting a model key or an Operation name interchangeably.
// Unlike For, ForKey can fail (an unknown model key or operation name).
func ForKey(modelKey string, backend model.Backend, opName string) (Capability, error) {
	m, err := model.GetModel(modelKey)
	if err != nil {
		return Capability{}, err
	}
	op, err := OperationByName(opName)
	if err != nil {
		return Capability{}, err
	}
	return For(m, backend, op), nil
}

// Matrix returns every verdict for modelKeys x their backends x operations.
// modelKeys == nil defaults to every registered model (model.Models()'s
// canonical order); operations == nil defaults to Operations (all 21). Only
// backends a model actually has are included (via BackendsFor), so the
// result never carries a SupportNoBackend row. Mirrors Python's matrix().
func Matrix(modelKeys []string, operations []Operation) ([]Capability, error) {
	keys := modelKeys
	if keys == nil {
		for _, m := range model.Models() {
			keys = append(keys, m.Key)
		}
	}
	ops := operations
	if ops == nil {
		ops = Operations
	}
	var out []Capability
	for _, key := range keys {
		m, err := model.GetModel(key)
		if err != nil {
			return nil, err
		}
		for _, backend := range BackendsFor(m) {
			for _, op := range ops {
				out = append(out, For(m, backend, op))
			}
		}
	}
	return out, nil
}
