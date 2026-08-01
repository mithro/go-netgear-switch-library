// Package fastpath (this file): the FASTPATH CLI table/ruler parser
// PRIMITIVES -- the shared engine every entity parser (show version, show
// port all, show vlan ..., show mac-addr-table, show lldp remote-device
// all, show poe port info all, show environment, ...) is built from. Entity
// parsers themselves are a later task; this file has none.
//
// Ported field-for-field from the pinned
// python-netgear-switch-library @ 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362,
// src/netgear_switch/protocols/cli/parse.py, "Primitives" section
// (parse.py:57-204). FASTPATH prints two output shapes device-side (module
// docstring, parse.py:12-25):
//
//   - Labelled scalars: "Label.......... value" dotted-leader lines --
//     handled by labelledValues.
//   - Fixed-width tables: a header, a "----" ruler line, then data rows
//     whose columns are aligned to the ruler. The ruler is the single
//     source of truth for column boundaries -- NOT strings.Fields()/
//     str.split(), which would corrupt any cell that legitimately contains
//     spaces ("Delivering Power", "CPU Interface:  0/5/1", "Not
//     Supported") -- so rulerSpans/iterTableRows slice strictly by the
//     ruler's dash-group spans.
//
// THE HAZARD this file exists to get right: Python's row[start:end]
// silently CLAMPS start/end to len(row) when a data row is shorter than the
// ruler it's sliced against (a down port's blank Physical Status column, a
// bare LLDP interface row with no neighbour yet). Go's native row[start:end]
// slicing PANICS on the same out-of-range input. sliceCell reproduces
// Python's clamp explicitly (see its own doc comment) so every parser built
// on top of it can never panic on a short row.
package fastpath

import (
	"regexp"
	"strconv"
	"strings"
)

// Primitive regexes, quoted verbatim from parse.py:57-69 (Python inline
// flags -> Go (?i)-prefix; none of these five need one). Go's RE2 engine
// supports every construct these patterns use (non-greedy quantifiers,
// anchors, character classes, bounded repetition) with no semantic
// difference from Python's re module here.
var (
	// labelRE: label = group 1 (non-greedy, stops at the FIRST run of 2+
	// dots), value = group 2 (non-greedy, trailing whitespace stripped by
	// \s*$). Mirrors Python _LABEL_RE (parse.py:57).
	labelRE = regexp.MustCompile(`^\s*(.+?)\s*\.{2,}\s*(.*?)\s*$`)
	// rulerRE: a ruler line is 2+ dashes, optionally surrounded by/mixed
	// with more dash/space/tab runs -- "----  ----   ----" matches, a line
	// with any other character does not. Mirrors Python _RULER_RE
	// (parse.py:58).
	rulerRE = regexp.MustCompile(`^[ \t]*-{2,}[- \t]*$`)
	// physIfaceRE: ONLY matches "unit/0/port" (the slot must be literal 0)
	// -- captures (unit, port); group 2 is the port number. Mirrors Python
	// _PHYS_IFACE_RE (parse.py:61).
	physIfaceRE = regexp.MustCompile(`^(\d+)/0/(\d+)$`)
	// smartIfaceRE: "unit/gN" or "unit/xgN" (the "x" is optional) --
	// captures the port number in group 1. Mirrors Python _SMART_IFACE_RE
	// (parse.py:64).
	smartIfaceRE = regexp.MustCompile(`^\d+/x?g(\d+)$`)
	// macTextRE: exactly XX:XX:XX:XX:XX:XX, hex pairs, colon-separated.
	// Mirrors Python _MAC_TEXT_RE (parse.py:66); not used by any primitive
	// in this file -- reserved for the mac-addr-table entity parser (later
	// task), included here because the dossier requires every §2.1 regex
	// quoted verbatim in this file.
	macTextRE = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)
	// whitespaceRE collapses any run of whitespace to a single space,
	// mirroring the `re.sub(r"\s+", " ", ...)` call inside Python
	// header_columns (parse.py:181).
	whitespaceRE = regexp.MustCompile(`\s+`)
)

// splitLines splits already newline-normalized CLI output into lines,
// matching Python's text.splitlines() for text that contains only "\n" line
// endings (which is all this package ever sees: the CLI transport's
// ShellDriver normalizes "\r\n"/"\r" to "\n" before any parser runs --
// transport/cli/session.py:234). The one behavioral difference from a plain
// strings.Split(text, "\n") that matters is a lone trailing "\n": Python's
// splitlines does NOT emit a trailing empty-string element for it, so a
// single TrimSuffix before splitting reproduces that. "" (the empty string)
// maps to nil (Python: []), not []string{""}.
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// labelledValues parses "Label.......... value" dotted-leader lines into a
// map, mirroring Python labelled_values (parse.py:72-85) EXACTLY: later
// duplicate labels overwrite earlier ones (only the last wins); a blank
// value ("Bootcode Version...........") maps to "" -- it is never omitted
// from the map.
func labelledValues(text string) map[string]string {
	out := make(map[string]string)
	for _, line := range splitLines(text) {
		m := labelRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out[strings.TrimSpace(m[1])] = strings.TrimSpace(m[2])
	}
	return out
}

// rulerSpan is one table column's byte-offset span within a ruler/data row,
// mirroring one element of Python _ruler_spans' tuple[int, int | None]
// return list. end == -1 stands in for Python's None (an open span running
// to end-of-row) -- unambiguous, since every real span start is >= 0 and a
// non-final column's end is always > its own start.
type rulerSpan struct {
	start int
	end   int // -1 means "to end of row" (Python's None)
}

// rulerSpans derives column (start, end) spans from a "----" ruler line,
// mirroring Python _ruler_spans (parse.py:88-112) EXACTLY, including its
// central subtlety: a column's end is the NEXT column's dash-run START, NOT
// this column's own dash-run end -- so inter-column padding immediately
// after a column's own dashes belongs to the cell on the left. Using each
// dash-run's own end as the boundary instead (the naive reading) would
// corrupt any cell whose header text overhangs past its own ruler's dashes.
// The last column's end is -1 (runs to end-of-line). Byte-indexed: FASTPATH
// output is ASCII, so byte slicing matches Python's character slicing here.
func rulerSpans(ruler string) []rulerSpan {
	var starts []int
	n := len(ruler)
	for i := 0; i < n; {
		if ruler[i] == '-' {
			start := i
			for i < n && ruler[i] == '-' {
				i++
			}
			starts = append(starts, start)
		} else {
			i++
		}
	}
	spans := make([]rulerSpan, len(starts))
	for idx, start := range starts {
		end := -1
		if idx+1 < len(starts) {
			end = starts[idx+1]
		}
		spans[idx] = rulerSpan{start: start, end: end}
	}
	return spans
}

// sliceCell returns row's span cell, clamped and stripped, mirroring Python
// _slice_cell (parse.py:115-117) EXACTLY -- this is where the module's
// central hazard is defused. Python's row[start:end] silently CLAMPS start
// and end to len(row) when row is a short line (a down port's blank
// Physical Status column, a bare LLDP interface row with no neighbour yet)
// and, once start > end after that clamp, returns "" rather than raising.
// Go's native row[start:end] slicing PANICS on out-of-range indices, so
// both bounds are clamped to len(row) here first, and start>end (which can
// only happen when the row is shorter than span.start) is handled by
// returning "" instead of slicing -- reproducing Python's exact behavior,
// never a panic.
func sliceCell(row string, span rulerSpan) string {
	n := len(row)
	start := span.start
	if start > n {
		start = n
	}
	end := span.end
	if end < 0 || end > n {
		end = n
	}
	if start > end {
		return ""
	}
	return strings.TrimSpace(row[start:end])
}

// sliceRow slices row by spans (ruler columns), mirroring Python
// _slice_row (parse.py:119-120).
func sliceRow(spans []rulerSpan, row string) []string {
	cells := make([]string, len(spans))
	for i, span := range spans {
		cells[i] = sliceCell(row, span)
	}
	return cells
}

// findAfterAndRuler scans lines for the shared iterTableRows/headerColumns
// preamble: optionally skip forward to the first line containing after
// (used to disambiguate "show environment"'s three sub-tables), then skip
// forward from there to the first ruler line. Returns the ruler's line
// index, or ok=false if lines runs out before a ruler is found (mirroring
// Python's `idx >= len(lines)` guard, shared verbatim by both functions:
// parse.py:130-135 / parse.py:159-164). after=="" mirrors Python's
// after=None (no skip) -- an unambiguous sentinel: FASTPATH never calls
// with a genuinely empty disambiguator, and Python's own `after not in
// line` check is a no-op for after="" anyway (the empty string is a
// substring of every line).
func findAfterAndRuler(lines []string, after string) (idx int, ok bool) {
	idx = 0
	if after != "" {
		for idx < len(lines) && !strings.Contains(lines[idx], after) {
			idx++
		}
	}
	for idx < len(lines) && !rulerRE.MatchString(lines[idx]) {
		idx++
	}
	return idx, idx < len(lines)
}

// iterTableRows yields every data row (as sliced, stripped cells) of a
// fixed-width table, mirroring Python iter_table_rows (parse.py:125-146).
// The table is the block of lines following the first ruler line found by
// findAfterAndRuler; iteration stops at the first blank line or the next
// ruler line after the table body (that terminating line is not included).
// Returns nil (Python: an empty generator) if no ruler is found at all, or
// if the table has zero data rows -- neither is an error.
func iterTableRows(text string, after string) [][]string {
	lines := splitLines(text)
	idx, ok := findAfterAndRuler(lines, after)
	if !ok {
		return nil
	}
	spans := rulerSpans(lines[idx])
	var rows [][]string
	for _, line := range lines[idx+1:] {
		if strings.TrimSpace(line) == "" || rulerRE.MatchString(line) {
			break
		}
		rows = append(rows, sliceRow(spans, line))
	}
	return rows
}

// headerColumns reconstructs each table column's header name, in order,
// mirroring Python header_columns (parse.py:149-182). FASTPATH table
// headers often wrap over two or three physical lines ("High Power" / "Max
// Power (mW)" / "Output Current (mA)" stacked above the ruler); each header
// line is sliced by the SAME ruler spans that slice the data rows, and the
// per-column pieces are joined with a single space and whitespace-collapsed
// -- empty pieces are dropped from the join so a column whose header text
// only occupies one of several header lines doesn't pick up stray leading/
// trailing spaces. Returns nil (Python: []) if no ruler is found.
func headerColumns(text string, after string) []string {
	lines := splitLines(text)
	idx, ok := findAfterAndRuler(lines, after)
	if !ok {
		return nil
	}
	spans := rulerSpans(lines[idx])
	// Header lines: the contiguous run of non-blank, non-ruler lines
	// directly above the ruler.
	start := idx - 1
	for start >= 0 && strings.TrimSpace(lines[start]) != "" && !rulerRE.MatchString(lines[start]) {
		start--
	}
	headerLines := lines[start+1 : idx]
	names := make([]string, len(spans))
	for i, span := range spans {
		var pieces []string
		for _, hl := range headerLines {
			if p := sliceCell(hl, span); p != "" {
				pieces = append(pieces, p)
			}
		}
		names[i] = whitespaceRE.ReplaceAllString(strings.Join(pieces, " "), " ")
	}
	return names
}

// parseInt is the integer value of text with surrounding whitespace
// trimmed, or ok=false for empty/non-numeric text, mirroring Python _int
// (parse.py:185-189): never a fabricated zero for absent/unparseable text.
func parseInt(text string) (int, bool) {
	v, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		return 0, false
	}
	return v, true
}

// physPort is the physical port number encoded in a FASTPATH ifName, or
// ok=false if iface names something else, mirroring Python _phys_port
// (parse.py:192-204): "1/0/7" -> 7 (Fully Managed FASTPATH line, tried
// FIRST via physIfaceRE); "1/g7" -> 7 / "1/xg49" -> 49 (Smart-firmware
// S3300-52X gsm7228ps, tried SECOND via smartIfaceRE as fallback). "lag 1",
// "vlan 5", "CPU Interface: ..." -> ok=false for both patterns. Model-
// agnostic: applied to every table row regardless of which CliModelSpec
// issued the command, since both interface-naming dialects are always
// tried.
func physPort(iface string) (int, bool) {
	s := strings.TrimSpace(iface)
	if m := physIfaceRE.FindStringSubmatch(s); m != nil {
		port, err := strconv.Atoi(m[2])
		return port, err == nil
	}
	if m := smartIfaceRE.FindStringSubmatch(s); m != nil {
		port, err := strconv.Atoi(m[1])
		return port, err == nil
	}
	return 0, false
}
