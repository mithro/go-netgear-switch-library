//go:build crosslang

package crosslang

// triples.go: the capability-matrix-driven (model, backend, operation)
// enumerator. It never re-derives support itself -- every verdict comes
// straight from capabilities.Matrix, the same cross-verified oracle
// capabilities/matrix_parity_test.go checks against the pinned Python
// reference -- so a triple this harness runs is, by construction, exactly
// one the oracle says the model/backend pairing genuinely supports.

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/capabilities"
	"github.com/mithro/go-netgear-switch-library/model"
)

// Triple is one (model, backend, operation) this harness will drive: the
// capabilities oracle marks it Supported, AND the running Provider actually
// serves that backend (see servedBackends).
type Triple struct {
	ModelKey string
	Backend  model.Backend
	Op       capabilities.Operation
}

// String renders t as "model/backend/op", used for subtest names.
func (t Triple) String() string {
	return fmt.Sprintf("%s/%s/%s", t.ModelKey, t.Backend, t.Op.Name)
}

// triples returns every (backend, op) pair from ops that capabilities.
// Matrix marks SupportSupported for modelKey, restricted to backends
// present in served (a provider that does not serve a given backend at
// all -- e.g. this slice's own documented m4300-16x/HTTP exclusion, or a
// future provider with no CLI listener -- never gets asked to run a triple
// it cannot reach). ops is normally capabilities.ReadOperations or
// capabilities.WriteOperations (never capabilities.Operations wholesale --
// callers pick the kind they want up front).
func triples(modelKey string, ops []capabilities.Operation, served map[model.Backend]int) ([]Triple, error) {
	caps, err := capabilities.Matrix([]string{modelKey}, ops)
	if err != nil {
		return nil, err
	}
	var out []Triple
	for _, c := range caps {
		if c.Support != capabilities.SupportSupported {
			continue
		}
		if _, ok := served[c.Backend]; !ok {
			continue
		}
		out = append(out, Triple{ModelKey: modelKey, Backend: c.Backend, Op: c.Operation})
	}
	return out, nil
}
