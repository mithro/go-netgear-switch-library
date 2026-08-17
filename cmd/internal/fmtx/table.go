// Package fmtx is pure output formatting for the ngsw CLI/MCP server:
// JSON (BYTE-PARITY with Python's json.dumps) and human-readable tables.
// Ported from src/netgear_switch/cli/format.py (the normative source;
// that repo is read-only from here). Any discrepancy between this file
// and the pinned Python source is a bug in this file.
//
// Every renderer is a pure model object(s) -> string map (matching
// format.py's own module doc comment: "the whole module is
// unit-testable without a switch or network"), so the whole package is
// unit-testable with hand-derived expected strings and no live switch.
package fmtx

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// table renders headers+rows exactly like Python's format._table: column
// widths are max(header, cell) measured by RUNE count (utf8.RuneCountInString,
// NOT byte length -- Python's str.__len__/ljust count code points, so a
// UTF-8 multi-byte cell, e.g. a port description with an accented
// character, must not desync column padding from a byte-length count),
// cells left-justified (padded with ASCII spaces to that width), and
// columns joined by exactly two literal spaces. ljust is applied to EVERY
// column including the last -- Python's `cell.ljust(widths[i])` never
// special-cases the final column, so a row whose last cell is shorter
// than that column's widest cell DOES get trailing spaces; this is
// reproduced deliberately (no rstrip anywhere) for byte parity.
func table(headers []string, rows [][]string) string {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if n := utf8.RuneCountInString(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}

	render := func(cells []string) string {
		parts := make([]string, len(cells))
		for i, c := range cells {
			parts[i] = ljust(c, widths[i])
		}
		return strings.Join(parts, "  ")
	}

	lines := make([]string, 0, 1+len(rows))
	lines = append(lines, render(headers))
	for _, row := range rows {
		lines = append(lines, render(row))
	}
	return strings.Join(lines, "\n")
}

// ljust left-justifies s to width RUNES by appending ASCII spaces,
// mirroring Python's str.ljust (which also counts code points, not
// bytes). A string already at or past width is returned unchanged
// (Python's ljust never truncates).
func ljust(s string, width int) string {
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

// pyBool renders a bool the way Python's str(bool) (and therefore every
// f"{x}" interpolation of a bool) does: "True"/"False", capitalised --
// NOT Go's strconv.FormatBool, which is lowercase "true"/"false" and
// would silently break byte parity everywhere format.py interpolates a
// bool directly (users_table's privileged, services_table's enabled,
// syslog_text's enabled/active).
func pyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// strOrDash renders an optional string the way format.py's `x or "-"`
// pattern does: BOTH a nil pointer AND a present-but-empty string are
// treated as absent (Python's `or` is a falsy check, not an `is None`
// check) and render as "-".
func strOrDash(s *string) string {
	if s == nil || *s == "" {
		return "-"
	}
	return *s
}

// intOrDash renders an optional int the way format.py's `"-" if x is None
// else str(x)` pattern does: ONLY a nil pointer renders as "-" -- a
// present zero value renders as "0", never "-" (this is an `is None`
// check, not a falsy check, unlike strOrDash).
func intOrDash(v *int) string {
	if v == nil {
		return "-"
	}
	return strconv.Itoa(*v)
}

// uint64OrDash is intOrDash's *uint64 twin, for PortStats' counter fields
// (rx/tx bytes/packets/errors), which are unsigned in this codebase but
// Optional[int] in Python -- same `is None`-check semantics as intOrDash.
func uint64OrDash(v *uint64) string {
	if v == nil {
		return "-"
	}
	return strconv.FormatUint(*v, 10)
}

// boolOrDash renders an optional bool the way format.py's `"-" if x is
// None else str(x)` pattern does for SwitchUser.Privileged: an `is None`
// check (not falsy -- a present `false` renders as "False", never "-"),
// with Python's True/False capitalisation via pyBool.
func boolOrDash(v *bool) string {
	if v == nil {
		return "-"
	}
	return pyBool(*v)
}

// formatPorts renders a port set the way format.py's `_ports` helper
// does: sorted ascending, comma-joined, or "-" when empty. This codebase's
// port-set fields (VLANInfo.UntaggedPorts/TaggedPorts) are already stored
// canonically sorted (see model/types.go), but formatPorts still sorts a
// defensive copy -- exactly mirroring `_ports`, which always calls
// sorted() on its frozenset[int] input regardless of any caller-side
// ordering guarantee, and costing nothing extra for an already-sorted
// slice.
func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return "-"
	}
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	parts := make([]string, len(sorted))
	for i, p := range sorted {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// enabledWord renders a bool as "enabled"/"disabled" -- ports_table's and
// poe_table's Admin column wording (distinct from pyBool's True/False and
// from linkWord's up/down).
func enabledWord(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// linkWord renders a bool as "up"/"down" -- ports_table's Link column
// wording.
func linkWord(b bool) string {
	if b {
		return "up"
	}
	return "down"
}
