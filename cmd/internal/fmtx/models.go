package fmtx

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// ModelRow is the JSON shape for one row of the `models` listing,
// mirroring cli/main.py's `_ModelRow` TypedDict field-for-field (key,
// display_name, class, ports, backends, verified) IN THAT ORDER --
// Go's encoding/json marshals struct fields in declaration order, so this
// field order is load-bearing for JSON byte parity, not just cosmetic.
type ModelRow struct {
	Key         string   `json:"key"`
	DisplayName string   `json:"display_name"`
	Class       string   `json:"class"`
	Ports       int      `json:"ports"`
	Backends    []string `json:"backends"`
	Verified    bool     `json:"verified"`
}

// ModelRows builds the `models` listing rows from the registry, mirroring
// cli/main.py's `_cmd_models` row-building comprehension exactly: each
// model's backends are rendered as their lowercase wire values, SORTED
// (`sorted(b.value for b in m.backends)` -- the registry's own
// SwitchModel.Backends order is arbitrary/unordered-in-meaning, see
// model/registry.go's doc comment, so sorting here is required for a
// deterministic, Python-matching listing, not optional cleanup).
func ModelRows(models []*model.SwitchModel) []ModelRow {
	rows := make([]ModelRow, len(models))
	for i, m := range models {
		backends := make([]string, len(m.Backends))
		for j, b := range m.Backends {
			backends[j] = string(b)
		}
		sort.Strings(backends)
		rows[i] = ModelRow{
			Key:         m.Key,
			DisplayName: m.DisplayName,
			Class:       string(m.Class),
			Ports:       m.PortCount,
			Backends:    backends,
			Verified:    m.Verified,
		}
	}
	return rows
}

// ModelsText renders the `models` listing as ngsw's non-JSON output,
// mirroring cli/main.py's `_cmd_models` else-branch EXACTLY:
//
//	f"{row['key']:<12} {row['display_name']:<24} "
//	f"{'+'.join(row['backends'])}{suffix}"
//
// i.e. FIXED-width columns (key padded to 12, display_name to 24, a
// single literal space between each), backends joined by "+", and a
// "  [UNVERIFIED]" suffix on any model whose Verified flag is false
// (registry.py's `verified` field -- an UNVERIFIED-pending-capture model,
// see model/registry.go). This is a DIFFERENT layout mechanism from every
// other renderer in this package: it does NOT use the generic table()
// column-fitting helper (whose widths are computed FROM the data), it
// uses two hardcoded widths -- ported as such, not "improved" into a
// table() call, to keep the exact column boundaries Python's `ngsw
// models` output has always had.
func ModelsText(rows []ModelRow) string {
	lines := make([]string, len(rows))
	for i, row := range rows {
		suffix := ""
		if !row.Verified {
			suffix = "  [UNVERIFIED]"
		}
		lines[i] = fmt.Sprintf("%s %s %s%s",
			ljust(row.Key, 12), ljust(row.DisplayName, 24), strings.Join(row.Backends, "+"), suffix)
	}
	return strings.Join(lines, "\n")
}
