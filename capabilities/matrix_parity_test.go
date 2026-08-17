package capabilities

// matrix_parity_test.go: the capstone faithfulness gate. Pins Matrix(nil,
// nil)'s verdicts against a golden fixture generated directly from the
// pinned Python capabilities.py (go-port-pin-b26eb1f's matrix()):
//
//	uv run --extra async --extra http python3 -c "
//	import json
//	from netgear_switch.capabilities import matrix
//	rows = [
//	    {
//	        'model_key': c.model_key,
//	        'backend': c.backend.name.lower(),
//	        'operation': c.operation.name,
//	        'support': c.support.value,
//	        'reason_nonempty': bool(c.reason),
//	    }
//	    for c in matrix()
//	]
//	rows.sort(key=lambda r: (r['model_key'], r['backend'], r['operation']))
//	print(json.dumps(rows, indent=2))
//	" > testdata/python_matrix_b26eb1f.json
//
// run from the pinned worktree
// (python-netgear-switch-library/.claude/worktrees/go-port-pin-b26eb1f), with
// the output redirected into THIS repo (the pin is read-only). See
// testdata/python_matrix_b26eb1f.json.
//
// Deliberately does NOT compare reason text byte-for-byte -- this plan's
// Global Constraints document why (Go and Python's reason prose has already
// diverged in confirmed, legitimate ways, e.g. nsdpSweepEvidence's wording).
// What this DOES pin, per (model_key, backend, operation) triple: the
// Support verdict itself, and whether a reason is present at all.

import (
	"encoding/json"
	"os"
	"testing"
)

type pythonMatrixRow struct {
	ModelKey       string `json:"model_key"`
	Backend        string `json:"backend"`
	Operation      string `json:"operation"`
	Support        string `json:"support"`
	ReasonNonEmpty bool   `json:"reason_nonempty"`
}

func loadPythonMatrixFixture(t *testing.T) []pythonMatrixRow {
	t.Helper()
	data, err := os.ReadFile("testdata/python_matrix_b26eb1f.json")
	if err != nil {
		t.Fatalf("reading golden fixture: %v", err)
	}
	var rows []pythonMatrixRow
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("parsing golden fixture: %v", err)
	}
	return rows
}

func TestGoMatrixMatchesPinnedPythonMatrix(t *testing.T) {
	pythonRows := loadPythonMatrixFixture(t)

	goCaps, err := Matrix(nil, nil)
	if err != nil {
		t.Fatalf("Matrix(nil, nil): %v", err)
	}
	if len(goCaps) != len(pythonRows) {
		t.Fatalf("len(Matrix()) = %d, want %d (pinned Python row count) -- "+
			"if the difference is a multiple of 32 (the op count), check "+
			"model/registry.go's per-model backend counts against the pinned "+
			"registry.py first",
			len(goCaps), len(pythonRows))
	}

	type key struct{ modelKey, backend, operation string }
	byKey := make(map[key]pythonMatrixRow, len(pythonRows))
	for _, r := range pythonRows {
		byKey[key{r.ModelKey, r.Backend, r.Operation}] = r
	}

	seen := make(map[key]bool, len(goCaps))
	for _, c := range goCaps {
		k := key{c.ModelKey, string(c.Backend), c.Operation.Name}
		want, ok := byKey[k]
		if !ok {
			t.Errorf("Go Matrix() has row %s/%s/%s with no counterpart in the pinned Python fixture",
				c.ModelKey, c.Backend, c.Operation.Name)
			continue
		}
		seen[k] = true
		if string(c.Support) != want.Support {
			t.Errorf("%s/%s/%s: Go Support = %q, pinned Python Support = %q",
				c.ModelKey, c.Backend, c.Operation.Name, c.Support, want.Support)
		}
		if (c.Reason != "") != want.ReasonNonEmpty {
			t.Errorf("%s/%s/%s: Go reason-non-empty = %v, pinned Python reason-non-empty = %v",
				c.ModelKey, c.Backend, c.Operation.Name, c.Reason != "", want.ReasonNonEmpty)
		}
	}
	for k := range byKey {
		if !seen[k] {
			t.Errorf("pinned Python fixture has row %s/%s/%s with no counterpart in Go Matrix()",
				k.modelKey, k.backend, k.operation)
		}
	}
}
