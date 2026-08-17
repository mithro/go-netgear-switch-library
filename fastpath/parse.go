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
	"sort"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
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

// ---------------------------------------------------------------------
// Entity parsers, part 1: show version / show port all / show vlan brief
// (or its per-model rename) / show vlan <id> / show vlan port all.
// Ported field-for-field from the pinned python-netgear-switch-library @
// 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362,
// src/netgear_switch/protocols/cli/parse.py (parse.py:212-386), dossier
// §2.9-§2.13.
// ---------------------------------------------------------------------

var (
	// vlanHeaderRE / vlanNameRE: the "VLAN ID: 90" / "VLAN Name: iot"
	// scalar header lines atop a "show vlan <id>" detail page. Mirrors
	// Python _VLAN_HEADER_RE / _VLAN_NAME_RE (parse.py:333-334) exactly.
	vlanHeaderRE = regexp.MustCompile(`VLAN ID:\s*(\d+)`)
	vlanNameRE   = regexp.MustCompile(`VLAN Name:\s*(.*)`)
	// speedRE parses a "show port all" Physical Status cell like "1000
	// Full"/"10G Full" into (value, unit). Mirrors Python _SPEED_RE
	// (parse.py:243), applied via re.match() (Python only anchors at
	// position 0, not end-of-string) -- the leading ^ here reproduces
	// that anchoring, since Go's FindStringSubmatch searches anywhere in
	// the string by default.
	speedRE = regexp.MustCompile(`^(\d+)\s*([GgMm]?)`)
)

// Column indices for parsePortStatus, mirroring Python's
// _PORT_INTF.._PORT_LINK (parse.py:248-249): header is "Intf | Type |
// Admin Mode | Physical Mode | Physical Status | Link Status | Link Trap |
// LACP Mode | Flow Mode". These six are FIXED offsets -- safe because
// nothing before "Flow Mode" has ever been observed to move. Flow Mode
// itself is NOT among them: see portFlowHeader below.
const (
	portIntf = iota
	portType
	portAdmin
	portPhysMode
	portPhysStatus
	portLink
)

// portFlowHeader is the (lower-cased) substring parsePortStatus locates the
// Flow Mode column BY HEADER NAME with, mirroring Python's
// _PORT_FLOW_HEADER (parse.py:261) EXACTLY -- and the reasoning is the
// point, not just the value. Flow Mode used to be read as cells[-1] ("the
// last column, so an omitted intermediate column cannot shift it"), which
// is exactly backwards for a firmware that APPENDS one: the M4300 images'
// table ends "... | LACP Mode | Flow Mode | Stack Capable", so cells[-1]
// there is "Yes"/"No" from Stack Capable, and every M4300 port would report
// FlowControl=false no matter what its Flow Mode said -- a bug that would
// have turned into a false verify-after-write the moment anyone enabled
// flow control. Locating the column by header name, wherever it sits,
// is what defuses that.
const portFlowHeader = "flow"

// speedMbps converts a "show port all" Physical Status cell to megabits
// per second, or ok=false if it doesn't start with a number (a down
// port's blank cell), mirroring Python _speed_mbps (parse.py:246-256):
// "1000 Full" -> 1000, "10G Full" -> 10000, "" -> not ok (never a
// fabricated 0). Only an exact "G"/"g" unit multiplies by 1000; "M"/"m"
// and no suffix both leave the value as-is (Mbps assumed) -- the Python
// unit check is `.upper() == "G"`, so "m" is captured by the regex but is
// a semantic no-op multiplier, reproduced here the same way.
func speedMbps(physStatus string) (int, bool) {
	m := speedRE.FindStringSubmatch(strings.TrimSpace(physStatus))
	if m == nil {
		return 0, false
	}
	value, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	if strings.ToUpper(m[2]) == "G" {
		return value * 1000, true
	}
	return value, true
}

// duplexText reports FULL/HALF from a "show port all" Physical Status (or
// Physical Mode) cell, e.g. "1000 Full" -> (true, true), mirroring Python
// _duplex (parse.py:279-290): blank/neither-substring text -> ok=false,
// never a fabricated false.
func duplexText(text string) (bool, bool) {
	t := strings.ToLower(strings.TrimSpace(text))
	if strings.Contains(t, "full") {
		return true, true
	}
	if strings.Contains(t, "half") {
		return false, true
	}
	return false, false
}

// findFlowColumn returns the index of the first header name containing
// portFlowHeader (case-insensitively), or ok=false if none does -- mirrors
// Python's `next((i for i, name in enumerate(header_columns(text)) if
// _PORT_FLOW_HEADER in name.lower()), None)` (parse.py:335-342).
func findFlowColumn(names []string) (int, bool) {
	for i, n := range names {
		if strings.Contains(strings.ToLower(n), portFlowHeader) {
			return i, true
		}
	}
	return 0, false
}

// parsePhysicalMode decodes a "show port all" Physical Mode cell into the
// port's CONFIGURED model.PortSpeed, or nil, mirroring Python
// parse_physical_mode (parse.py:293-318) EXACTLY. This is the column
// set_port_speed verifies itself against, and it is a DIFFERENT column from
// Physical Status: Physical Mode is what the port is SET to, Physical
// Status what it negotiated -- on a down port the first still reads
// "Auto"/"100 Full" while the second is blank. "" (blank cell) and any text
// neither "Auto" nor a decodable "<rate> <duplex>" pair both yield nil --
// never a guess at a word no measured firmware emits.
func parsePhysicalMode(cell string) *model.PortSpeed {
	text := strings.TrimSpace(cell)
	if text == "" {
		return nil
	}
	if strings.ToLower(text) == "auto" {
		v := model.AutoPortSpeed()
		return &v
	}
	// Same "<rate> <duplex>" shape Physical Status uses, so this goes
	// through the same two measured parsers rather than a second regex.
	rate, rateOK := speedMbps(text)
	duplex, duplexOK := duplexText(text)
	if !rateOK || !duplexOK {
		return nil
	}
	v := model.ForcedPortSpeed(rate, duplex)
	return &v
}

// parseVersion identifies a switch's model from "show version" output,
// mirroring Python parse_version (parse.py:212-230) EXACTLY. Label map:
// "System Description" (primary), falling back to "Machine Model" if
// absent/blank. SysObjectID is ALWAYS nil -- "the CLI exposes no
// sysObjectID". Model matching REUSES the SNMP backend's
// snmp.DetectModelFromSysDescr so CLI and SNMP identify a switch
// identically; the Python reference imports this lazily inside the
// function to avoid a module-level cross-protocol import (parse.py:213)
// -- the Go port expresses the same "reuse, don't duplicate" constraint
// as an ordinary package import instead, since there is no import-cycle
// risk here (fastpath does not import anything that imports fastpath).
func parseVersion(text string, models []*model.SwitchModel) model.DetectedModel {
	fields := labelledValues(text)
	descr := fields["System Description"]
	if descr == "" {
		descr = fields["Machine Model"]
	}
	var key *string
	if descr != "" {
		key = snmp.DetectModelFromSysDescr(&descr, models)
	}
	var sysDescr *string
	if descr != "" {
		sysDescr = &descr
	}
	return model.DetectedModel{Key: key, SysDescr: sysDescr, SysObjectID: nil}
}

// parsePortStatus parses "show port all" into one model.PortStatus per
// physical port, mirroring Python parse_port_status (parse.py:321-377)
// EXACTLY. "lag N" rows are skipped (physPort returns ok=false for them,
// not filtered by name). speedMbps/FullDuplex are only consulted when Link
// Status is exactly "up" -- EVEN IF Physical Status happens to carry stale
// text on a down port, defensive: link down implies neither a negotiated
// rate nor a negotiated duplex is meaningful; both come from the SAME
// Physical Status cell ("1000 Full" carries speed and duplex together).
// FlowControl comes from the Flow Mode column, located BY HEADER NAME (see
// portFlowHeader) -- NOT gated on link_up, unlike the two fields above: a
// down port still has a configured Flow Mode. SpeedConfig comes from
// Physical Mode (parsePhysicalMode) and is likewise reported whether the
// port is up or down -- it is a setting, not a negotiation result.
// Description is ALWAYS nil: "this command carries no ifAlias column"
// (honest omission, not a bug).
func parsePortStatus(text string) []model.PortStatus {
	flowCol, flowOK := findFlowColumn(headerColumns(text, ""))
	var out []model.PortStatus
	for _, cells := range iterTableRows(text, "") {
		if len(cells) <= portLink {
			continue
		}
		port, ok := physPort(cells[portIntf])
		if !ok {
			continue
		}
		linkUp := strings.ToLower(cells[portLink]) == "up"
		var speed *int
		var fullDuplex *bool
		if linkUp {
			if v, ok := speedMbps(cells[portPhysStatus]); ok {
				speed = &v
			}
			if v, ok := duplexText(cells[portPhysStatus]); ok {
				fullDuplex = &v
			}
		}
		var flowControl *bool
		if flowOK && flowCol < len(cells) {
			v := strings.ToLower(strings.TrimSpace(cells[flowCol])) == "enable"
			flowControl = &v
		}
		name := cells[portIntf]
		out = append(out, model.PortStatus{
			Port:         port,
			Name:         &name,
			AdminEnabled: strings.ToLower(cells[portAdmin]) == "enable",
			LinkUp:       linkUp,
			SpeedMbps:    speed,
			Description:  nil,
			FullDuplex:   fullDuplex,
			FlowControl:  flowControl,
			SpeedConfig:  parsePhysicalMode(cells[portPhysMode]),
		})
	}
	return out
}

// parsePortDescription parses the "Description" field of `show port
// description <iface>`, mirroring Python parse_port_description EXACTLY.
//
// GROUNDED in live output from a GSM7252PS (10.1.5.22, 2026-08-03):
//
//	Interface....... 1/0/8
//	ifIndex......... 8
//	Description.....
//	MAC address..... E0:91:F5:0C:D6:DD
//	Bit Offset Val.. 8
//
// Returns nil for an unset description (the label is present with an empty
// value, exactly as above) so it matches what every other backend reports
// for an absent label, rather than a pointer to "". This command exists
// because "show port all" carries NO description column -- which is why
// parsePortStatus honestly reports Description=nil and why a CLI
// description write has to verify itself through here instead.
func parsePortDescription(text string) (*string, error) {
	value, ok := labelledValues(text)["Description"]
	if !ok {
		return nil, errCliCommand("show port description: no 'Description' field in the output")
	}
	if value == "" {
		return nil, nil
	}
	return &value, nil
}

// Column indices for parseVLANBrief, mirroring Python's
// _VLAN_BRIEF_ID/_VLAN_BRIEF_NAME (parse.py:301): header is "VLAN ID |
// VLAN Name | VLAN Type" -- only the first two columns are consulted.
const (
	vlanBriefID = iota
	vlanBriefName
)

// vlanBriefRow is one row of "show vlan brief" (gsm7252ps) or its
// model-renamed equivalent "show vlan" (M4300/gsm7228ps, dossier
// §1.5-§1.6) -- VLAN id + name only, NO membership data (that requires a
// follow-up "show vlan <id>" per VLAN via parseVLANDetail, dossier §3.3).
// Mirrors Python parse_vlan_brief's list[tuple[int, str]] return shape.
type vlanBriefRow struct {
	vlan int
	name string
}

// parseVLANBrief parses a VLAN summary table into one vlanBriefRow per
// VLAN, mirroring Python parse_vlan_brief (parse.py:299-312) EXACTLY. A
// row whose VLAN ID cell doesn't parse as an integer is skipped; name
// defaults to "" if the row is short rather than panicking. When the
// device output isn't a table at all (e.g. gsm7228ps's Smart firmware
// rejecting the literal "show vlan brief" with a plain-text error --
// testdata/cli/gsm7228ps_vlan_brief.txt), iterTableRows finds no ruler and
// yields nothing, so this returns nil cleanly -- not an error.
func parseVLANBrief(text string) []vlanBriefRow {
	var out []vlanBriefRow
	for _, cells := range iterTableRows(text, "") {
		if len(cells) == 0 {
			continue
		}
		vid, ok := parseInt(cells[vlanBriefID])
		if !ok {
			continue
		}
		name := ""
		if len(cells) > vlanBriefName {
			name = cells[vlanBriefName]
		}
		out = append(out, vlanBriefRow{vlan: vid, name: name})
	}
	return out
}

// Column indices for parseVLANDetail, mirroring Python's
// _VLAN_D_IFACE/_VLAN_D_CURRENT/_VLAN_D_TAGGING (parse.py:323): header is
// "Interface | Current | Configured | Tagging" -- Configured (index 2) is
// DELIBERATELY skipped, only Current and Tagging are consulted.
const (
	vlanDIface = iota
	vlanDCurrent
	vlanDConfigured
	vlanDTagging
)

// sortedIntKeys returns the keys of set in ascending order, non-nil even
// when set is empty -- the canonical shape model.VLANInfo's port-set
// fields require ("sorted ascending, never nil", model/types.go).
func sortedIntKeys(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// parseVLANDetail parses a single "show vlan <id>" detail page into a
// model.VLANInfo, mirroring Python parse_vlan_detail (parse.py:321-358)
// EXACTLY. VlanID defaults to 0 if the "VLAN ID:" header line is absent
// (never panics). name, when non-nil, OVERRIDES the page's own "VLAN
// Name:" line -- this is how CliReader.GetVLANs (a later task) merges the
// "show vlan brief" pass's name with each per-VLAN detail page (dossier
// §2.12/§3.3); when nil, the page's own name is used (nil if that line is
// itself absent). A row's port is an egress member only when Current
// (case-insensitively) equals exactly "include" -- "exclude" (or anything
// else) drops the row entirely, not merely from one of the two sets.
// "lag N" rows drop out via physPort returning ok=false.
func parseVLANDetail(text string, name *string) model.VLANInfo {
	var vlanID int
	if m := vlanHeaderRE.FindStringSubmatch(text); m != nil {
		vlanID, _ = strconv.Atoi(m[1])
	}
	var pageName *string
	if m := vlanNameRE.FindStringSubmatch(text); m != nil {
		pn := strings.TrimSpace(m[1])
		pageName = &pn
	}
	resolvedName := pageName
	if name != nil {
		resolvedName = name
	}

	tagged := make(map[int]bool)
	untagged := make(map[int]bool)
	for _, cells := range iterTableRows(text, "") {
		if len(cells) <= vlanDTagging {
			continue
		}
		port, ok := physPort(cells[vlanDIface])
		if !ok {
			continue
		}
		if strings.ToLower(cells[vlanDCurrent]) != "include" {
			continue
		}
		if strings.ToLower(cells[vlanDTagging]) == "tagged" {
			tagged[port] = true
		} else {
			untagged[port] = true
		}
	}
	member := make(map[int]bool, len(tagged)+len(untagged))
	for p := range tagged {
		member[p] = true
	}
	for p := range untagged {
		member[p] = true
	}

	return model.VLANInfo{
		VlanID:        vlanID,
		Name:          resolvedName,
		MemberPorts:   sortedIntKeys(member),
		TaggedPorts:   sortedIntKeys(tagged),
		UntaggedPorts: sortedIntKeys(untagged),
	}
}

// Column indices for parsePVIDs, mirroring Python's
// _PVID_IFACE/_PVID_CONFIGURED (parse.py:373): header is "Interface | Port
// VLAN ID Configured | Current | Acceptable Frame Types | Ingress
// Filtering Configured | Ingress Filtering Current | GVRP | Default
// Priority" -- deliberately the CONFIGURED column (index 1), not Current
// (index 2): "matching what dot1qPvid reports over SNMP" (the persistent
// value, not any transient current value).
const (
	pvidIface = iota
	pvidConfigured
)

// parsePVIDs parses "show vlan port all" into one model.Pvid per physical
// port, mirroring Python parse_pvids (parse.py:371-386) EXACTLY -- the
// SAME model.Pvid type the merged SNMP/NSDP/HTTP backends already use
// (model/types.go), so a caller never has to distinguish which backend
// produced a PVID list. "lag N" rows drop out via physPort returning
// ok=false.
func parsePVIDs(text string) []model.Pvid {
	var out []model.Pvid
	for _, cells := range iterTableRows(text, "") {
		if len(cells) <= pvidConfigured {
			continue
		}
		port, ok := physPort(cells[pvidIface])
		if !ok {
			continue
		}
		pvid, ok := parseInt(cells[pvidConfigured])
		if !ok {
			continue
		}
		out = append(out, model.Pvid{Port: port, Vlan: pvid})
	}
	return out
}

// ---------------------------------------------------------------------
// Entity parsers, part 2: show mac-addr-table / show lldp remote-device
// all / show poe port info all / show environment / show network (or
// show ip management) / show interface ethernet <iface>. Ported
// field-for-field from the pinned python-netgear-switch-library @
// 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362,
// src/netgear_switch/protocols/cli/parse.py (parse.py:398-676), dossier
// §2.14-§2.19.
// ---------------------------------------------------------------------

// Column indices for parseMacTable, mirroring Python's
// _MAC_VLAN/_MAC_ADDR/_MAC_IFINDEX (parse.py:716): header is "VLAN ID |
// MAC Address | Interface | IfIndex | Status" -- the Interface column
// (index 2) is DELIBERATELY skipped; MacEntry.Port comes from IfIndex
// (index 3), not any interface-name parsing.
const (
	macVlan = iota
	macAddr
	_ // Interface (unused)
	macIfindex
)

// parseMacTable parses "show mac-addr-table" into one model.MacEntry per
// FDB row, mirroring Python parse_mac_table (parse.py:718-731) EXACTLY.
// Port is the IfIndex column value itself -- "49 for 1/0/49, 418 for lag
// 1, 417 for the CPU/Management row -- the same ifIndex the SNMP FDB join
// yields" -- NEVER a _phys_port-derived physical port number, so LAG and
// CPU rows are kept, not dropped. A malformed MAC (fails macTextRE after
// upper-casing) silently drops the row rather than erroring. VlanID may be
// nil only if that cell fails to parse as an int; a row is dropped only
// when IfIndex itself fails to parse.
func parseMacTable(text string) []model.MacEntry {
	var out []model.MacEntry
	for _, cells := range iterTableRows(text, "") {
		if len(cells) <= macIfindex {
			continue
		}
		mac := strings.ToUpper(strings.TrimSpace(cells[macAddr]))
		if !macTextRE.MatchString(mac) {
			continue
		}
		ifindex, ok := parseInt(cells[macIfindex])
		if !ok {
			continue
		}
		var vlan *int
		if v, ok := parseInt(cells[macVlan]); ok {
			vlan = &v
		}
		out = append(out, model.MacEntry{Mac: mac, Port: ifindex, VlanID: vlan})
	}
	return out
}

// Column indices for parseLLDP, mirroring Python's
// _LLDP_IFACE/_LLDP_CHASSIS/_LLDP_PORTID/_LLDP_SYSNAME (parse.py:746):
// header is "Local Interface | RemID | Chassis ID | Port ID | System
// Name" -- RemID (index 1) is DELIBERATELY never read.
const (
	lldpIface = iota
	_         // RemID (unused)
	lldpChassis
	lldpPortID
	lldpSysName
)

// parseLLDP parses "show lldp remote-device all" into one
// model.LLDPNeighbor per neighbour row, mirroring Python parse_lldp
// (parse.py:748-766) EXACTLY. A local-interface row printed with NO
// neighbour (a bare "1/0/6" with empty trailing cells) is dropped by the
// blank-Chassis-ID check -- not a zero-valued neighbour. RemotePortDesc is
// ALWAYS nil: "this command has no port-description column (SNMP's
// lldpRemPortDesc is the source for it)". Chassis ID is uppercased to
// match the SNMP/HTTP backends. "lag N"/pseudo-interface local ports are
// dropped via physPort returning ok=false.
func parseLLDP(text string) []model.LLDPNeighbor {
	var out []model.LLDPNeighbor
	for _, cells := range iterTableRows(text, "") {
		if len(cells) == 0 {
			continue
		}
		localPort, ok := physPort(cells[lldpIface])
		if !ok {
			continue
		}
		if len(cells) <= lldpSysName || strings.TrimSpace(cells[lldpChassis]) == "" {
			continue
		}
		var sysName, chassisID, portID *string
		if v := strings.TrimSpace(cells[lldpSysName]); v != "" {
			sysName = &v
		}
		if v := strings.ToUpper(strings.TrimSpace(cells[lldpChassis])); v != "" {
			chassisID = &v
		}
		if v := strings.TrimSpace(cells[lldpPortID]); v != "" {
			portID = &v
		}
		out = append(out, model.LLDPNeighbor{
			LocalPort:       localPort,
			RemoteSysName:   sysName,
			RemotePortDesc:  nil,
			RemoteChassisID: chassisID,
			RemotePortID:    portID,
		})
	}
	return out
}

// PoE header-name column labels parsePoE resolves by NAME, not fixed
// index, mirroring Python's _POE_INTF_HDR/_POE_OUTPUT_MW_HDR/
// _POE_STATUS_HDR (parse.py:791-793). This is THE fix the dossier calls
// out (§2.16 risk #1, "a REAL bug fixed live" per the pinned git log): the
// M4300 firmware OMITS the "Temperature" column gsm7252ps prints, shifting
// every fixed index after it -- so every column consulted here MUST be
// located via headerColumns, never a hardcoded position.
const (
	poeIntfHdr     = "Intf"
	poeOutputMwHdr = "Power (mW)" // the live draw, NOT "Max Power (mW)"
	poeStatusHdr   = "Status"     // the PSE state, NOT "Fault Status"
)

// poeDetectText maps a (lower-cased) PoE Status substring to its
// model.PoEDetect value, tried in this EXACT order, mirroring Python's
// _POE_DETECT_TEXT dict (parse.py:795-800): matching is SUBSTRING, not
// equality -- real device text is "Delivering Power" (contains
// "delivering"), "Searching", "Disabled", or anything containing "Fault".
// Python 3.7+ dict iteration order is insertion order (delivering,
// searching, disabled, fault); a Go map must not be relied on for
// iteration order, so this is an explicit ordered slice instead.
var poeDetectText = []struct {
	substr string
	detect model.PoEDetect
}{
	{"delivering", model.PoEDetectDelivering},
	{"searching", model.PoEDetectSearching},
	{"disabled", model.PoEDetectDisabled},
	{"fault", model.PoEDetectFault},
}

// indexOf returns the index of target in names, or ok=false if absent,
// mirroring Python list.index()'s "found or not" outcome (parsePoE
// catches the ValueError it would raise; this returns ok=false instead).
func indexOf(names []string, target string) (int, bool) {
	for i, n := range names {
		if n == target {
			return i, true
		}
	}
	return 0, false
}

// parsePoE parses "show poe port info all" into one model.PoEStatus per
// PSE port, mirroring Python parse_poe (parse.py:802-831) EXACTLY. If ANY
// of the three required header names (Intf/Power (mW)/Status) is missing,
// returns nil (Python: []) rather than erroring -- a silent-but-honest
// degrade. There is NO admin column on this device output: AdminEnabled is
// INFERRED as "detect is not Disabled" (documented inference, not a
// fabricated field) -- "a searching/delivering PSE port is
// administratively on".
func parsePoE(text string) []model.PoEStatus {
	names := headerColumns(text, "")
	intfI, ok := indexOf(names, poeIntfHdr)
	if !ok {
		return nil
	}
	mwI, ok := indexOf(names, poeOutputMwHdr)
	if !ok {
		return nil
	}
	statusI, ok := indexOf(names, poeStatusHdr)
	if !ok {
		return nil
	}
	last := intfI
	if mwI > last {
		last = mwI
	}
	if statusI > last {
		last = statusI
	}
	var out []model.PoEStatus
	for _, cells := range iterTableRows(text, "") {
		if len(cells) <= last {
			continue
		}
		port, ok := physPort(cells[intfI])
		if !ok {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(cells[statusI]))
		detect := model.PoEDetectUnknown
		for _, d := range poeDetectText {
			if strings.Contains(status, d.substr) {
				detect = d.detect
				break
			}
		}
		var powerMw *int
		if v, ok := parseInt(cells[mwI]); ok {
			powerMw = &v
		}
		out = append(out, model.PoEStatus{
			Port:         port,
			AdminEnabled: detect != model.PoEDetectDisabled,
			Detect:       detect,
			PowerMw:      powerMw,
		})
	}
	return out
}

// Column indices for parseEnvironment's three independently-scanned
// sub-tables, mirroring Python's _ENV_TEMP_DESC/_ENV_TEMP_VALUE/
// _ENV_FAN_DESC/_ENV_FAN_SPEED/_ENV_PSU_DESC/_ENV_PSU_STATE
// (parse.py:858-860).
const (
	envTempDesc  = 2
	envTempValue = 3
	envFanDesc   = 2
	envFanSpeed  = 4
	envPsuDesc   = 2
	envPsuState  = 4
)

// parseEnvironment parses "show environment" into a flat []model.Sensor
// spanning all three of its sub-tables (Temperature Sensors / Fans / Power
// supplies), mirroring Python parse_environment (parse.py:862-905)
// EXACTLY. THREE INDEPENDENT calls to iterTableRows, each with a different
// after= substring -- each re-scans from line 0 to find its own marker
// then its own ruler, so the sub-tables are located completely separately,
// never by continuing from where the previous scan left off. Emission
// order is FIXED: all temperature sensors, then all fans, then all power
// sensors (never interleaved). A fan reporting non-numeric text ("Not
// Supported", "-") is SKIPPED entirely -- absent, not a zero-value Sensor.
// PSU health is a synthetic float flag: 1.0 if state case-insensitively
// equals exactly "operational", else 0.0 for ANY other state text. The PSU
// sub-table header text varies by firmware ("Power supplies:" on
// gsm7252ps/gsm7228ps vs "Power Modules:" on M4300 12.0.13.8+) -- resolved
// by a plain substring containment check on the WHOLE input text before
// the third iterTableRows call.
func parseEnvironment(text string) []model.Sensor {
	var out []model.Sensor
	for _, cells := range iterTableRows(text, "Temperature Sensors:") {
		if len(cells) <= envTempValue {
			continue
		}
		value, ok := parseInt(cells[envTempValue])
		if !ok {
			continue
		}
		out = append(out, model.Sensor{
			Name:  strings.TrimSpace(cells[envTempDesc]),
			Kind:  "temperature",
			Value: float64(value),
			Unit:  "C",
		})
	}
	for _, cells := range iterTableRows(text, "Fans:") {
		if len(cells) <= envFanSpeed {
			continue
		}
		rpm, ok := parseInt(cells[envFanSpeed])
		if !ok {
			continue // "Not Supported"/"-" -- absent, not zero
		}
		out = append(out, model.Sensor{
			Name:  strings.TrimSpace(cells[envFanDesc]),
			Kind:  "fan",
			Value: float64(rpm),
			Unit:  "RPM",
		})
	}
	psuAfter := "Power Modules:"
	if strings.Contains(text, "Power supplies:") {
		psuAfter = "Power supplies:"
	}
	for _, cells := range iterTableRows(text, psuAfter) {
		if len(cells) <= envPsuState {
			continue
		}
		state := strings.ToLower(strings.TrimSpace(cells[envPsuState]))
		value := 0.0
		if state == "operational" {
			value = 1.0
		}
		out = append(out, model.Sensor{
			Name:  strings.TrimSpace(cells[envPsuDesc]),
			Kind:  "power",
			Value: value,
			Unit:  "state",
		})
	}
	return out
}

// parseMgmtIP parses "show network" (or M4300's "show ip management") into
// a model.MgmtIPConfig, mirroring Python parse_mgmt_ip (parse.py:934-951)
// EXACTLY. "show network" labels the mode field "Configured IPv4
// Protocol"; M4300's "show ip management" labels the SAME concept
// "Method" -- EITHER label is accepted ("Configured IPv4 Protocol" tried
// first). Mode: exact match "DHCP" (case-normalized) -> DHCP; any OTHER
// non-empty text -> Static; empty/absent -> Unknown. Address/Netmask/
// Gateway are nil if the field is empty/absent (never an empty-string
// pointer). BaseMac is validated against macTextRE after uppercasing --
// an unparseable MAC becomes nil, never a raw invalid string.
func parseMgmtIP(text string) model.MgmtIPConfig {
	fields := labelledValues(text)
	proto := fields["Configured IPv4 Protocol"]
	if proto == "" {
		proto = fields["Method"]
	}
	proto = strings.ToUpper(strings.TrimSpace(proto))
	mode := model.IPModeUnknown
	switch {
	case proto == "DHCP":
		mode = model.IPModeDHCP
	case proto != "":
		mode = model.IPModeStatic
	}
	mac := strings.ToUpper(strings.TrimSpace(fields["Burned In MAC Address"]))
	var baseMac *string
	if macTextRE.MatchString(mac) {
		baseMac = &mac
	}
	var address, netmask, gateway *string
	if v := fields["IP Address"]; v != "" {
		address = &v
	}
	if v := fields["Subnet Mask"]; v != "" {
		netmask = &v
	}
	if v := fields["Default Gateway"]; v != "" {
		gateway = &v
	}
	return model.MgmtIPConfig{
		Mode:    mode,
		Address: address,
		Netmask: netmask,
		Gateway: gateway,
		BaseMac: baseMac,
	}
}

// parseUint64 is the uint64 value of text with surrounding whitespace
// trimmed, or ok=false for empty/non-numeric/negative text. Traffic
// counters are the only field in this package wide enough to need this
// (rather than parseInt): FASTPATH 64-bit octet counters can exceed
// math.MaxInt32 (dossier §2.19, e.g. an M4300 rx_bytes of
// 15294247267585), and model.PortStats' counter fields are *uint64 to
// match the SNMP/NSDP/HTTP backends' own ifHCInOctets/ifHCOutOctets shape.
// Mirrors Python _int's "unparseable -> None, never a fabricated 0"
// contract for this field width.
func parseUint64(text string) (uint64, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(text), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// interfaceCounterLabels are the "show interface ethernet <iface>" label
// lines parseInterfaceCounters reads, mirroring Python's inline label
// strings (parse.py:968-985), aligned to the SNMP backend's GetStats
// fields (ifHCInOctets, ifHCOutOctets, ifHCInUcastPkts, ifHCOutUcastPkts,
// ifInErrors, ifOutErrors respectively).
const (
	counterRxBytesLabel   = "Total Packets Received (Octets)"
	counterTxBytesLabel   = "Total Packets Transmitted (Octets)"
	counterRxPacketsLabel = "Unicast Packets Received"
	counterTxPacketsLabel = "Unicast Packets Transmitted"
	counterRxErrorsLabel  = "Total Packets Received with MAC Errors"
	counterTxErrorsLabel  = "Total Transmit Errors"
)

// parseInterfaceCounters parses "show interface ethernet <iface>" into a
// model.PortStats, mirroring Python parse_interface_counters
// (parse.py:976-986) EXACTLY. port is a CALLER-SUPPLIED parameter, not
// derived from the text -- "the command output carries no interface
// number" (the caller is CliReader.GetStats, a later task, which already
// knows the physical port it queried this text for). Any missing/
// unparseable field yields nil, never a fabricated 0.
func parseInterfaceCounters(text string, port int) model.PortStats {
	fields := labelledValues(text)
	get := func(label string) *uint64 {
		if v, ok := parseUint64(fields[label]); ok {
			return &v
		}
		return nil
	}
	return model.PortStats{
		Port:      port,
		RxBytes:   get(counterRxBytesLabel),
		TxBytes:   get(counterTxBytesLabel),
		RxPackets: get(counterRxPacketsLabel),
		TxPackets: get(counterTxPacketsLabel),
		RxErrors:  get(counterRxErrorsLabel),
		TxErrors:  get(counterTxErrorsLabel),
	}
}

// ---------------------------------------------------------------------
// show users / show ip http / show telnetcon / show ip ssh -- local login
// accounts and management-service state. Ported field-for-field from the
// pinned python-netgear-switch-library @ b26eb1f, src/netgear_switch/
// protocols/cli/parse.py's parse_users (parse.py:772-809) and
// parse_services (parse.py:707-764).
//
// PRINCIPLE-5 NOTE: unlike every other entity parser in this file, these two
// have NO captured device-transcript FIXTURE FILE on the Python side (no
// tests/fixtures/cli/*users*.txt or *_ip_http*.txt exists at this pin) --
// only an inline docstring transcript in parse_users's own doc comment plus
// the live-verified value tables recorded in the Python commit messages that
// introduced these two ops (4619e3c "feat(cli): read the switch's local user
// accounts", 2c7ddff "feat(cli): read which management services are
// enabled"). The parser LOGIC below is still a faithful field-for-field
// port; the fixture-test data used to exercise it (parse_test.go) is
// labelled per the same caveat rather than claimed as a captured device
// capture.
// ---------------------------------------------------------------------

// enabledText reports whether text is one of FASTPATH's two spellings of
// "on", mirroring Python _enabled (parse.py:702-704): "FASTPATH spells this
// two ways: 'Enabled' and 'Enable'." "yes" is also accepted, mirroring
// Python's exact set literal, even though no FASTPATH command measured so
// far actually emits it.
func enabledText(text string) bool {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "enabled", "enable", "yes":
		return true
	default:
		return false
	}
}

// parseUsers parses "show users" into the switch's local login accounts,
// mirroring Python parse_users (parse.py:772-809) EXACTLY. Sliced by the
// ruler rather than split on whitespace: an access mode legitimately
// contains a space ("Read Only", "Read/Write"), and a naive split would
// tear it in half. The ACCESS-MODE VOCABULARY differs by firmware -- see
// model.PrivilegedAccessModes -- so the raw text is preserved on
// SwitchUser.AccessMode and only the normalised Privileged flag interprets
// it. A row with a blank first cell (the account-count summary line some
// firmware images print below the table) is skipped, never fabricated into
// a nameless account.
func parseUsers(text string) []model.SwitchUser {
	var out []model.SwitchUser
	for _, cells := range iterTableRows(text, "") {
		if len(cells) == 0 || strings.TrimSpace(cells[0]) == "" {
			continue
		}
		padded := append(append([]string{}, cells...), "", "", "", "")
		name := strings.TrimSpace(padded[0])
		access := strings.TrimSpace(padded[1])
		snmpAccess := strings.TrimSpace(padded[2])
		snmpAuth := strings.TrimSpace(padded[3])
		snmpEnc := strings.TrimSpace(padded[4])
		u := model.SwitchUser{
			Name:       name,
			AccessMode: access,
			Privileged: model.PrivilegedAccess(access),
		}
		if snmpAccess != "" {
			u.SNMPv3Access = model.Ptr(snmpAccess)
		}
		if snmpAuth != "" {
			u.SNMPv3Auth = model.Ptr(snmpAuth)
		}
		if snmpEnc != "" {
			u.SNMPv3Encryption = model.Ptr(snmpEnc)
		}
		out = append(out, u)
	}
	return out
}

// parseServices parses the three commands FASTPATH splits management-
// service state across into the four model.ServiceStatus values, mirroring
// Python parse_services (parse.py:707-764) EXACTLY, including its return
// ORDER (http, https, telnet, ssh -- NOT the webui package's http/https/
// ssh/telnet order; the two backends genuinely disagree here, and this Go
// port preserves that rather than "fixing" it, per the pinned Python
// source's own literal return-list order).
//
// httpText ("show ip http") carries BOTH the plain and secure web servers.
// telnetText ("show telnetcon" -- NOT "show telnet", which reports the
// switch as an outbound telnet CLIENT) reports the INBOUND server. sshText
// ("show ip ssh") writes its labels WITH a trailing colon before the dotted
// leader ("Administrative Mode: ......... Enabled"), unlike every other
// FASTPATH scalar command -- labelledValues's regex captures the colon as
// part of the label, so it is stripped explicitly here before lookup.
func parseServices(httpText, telnetText, sshText string) []model.ServiceStatus {
	httpFields := labelledValues(httpText)
	telnetFields := labelledValues(telnetText)
	sshRaw := labelledValues(sshText)
	sshFields := make(map[string]string, len(sshRaw))
	for k, v := range sshRaw {
		sshFields[strings.TrimSpace(strings.TrimSuffix(k, ":"))] = v
	}
	return []model.ServiceStatus{
		{Name: "http", Enabled: enabledText(httpFields["HTTP Mode (Unsecure)"]), Port: parseIntPtr(httpFields["HTTP Port"])},
		{Name: "https", Enabled: enabledText(httpFields["HTTP Mode (Secure)"]), Port: parseIntPtr(httpFields["Secure Port"])},
		{Name: "telnet", Enabled: enabledText(telnetFields["Telnet Server Admin Mode"]), Port: parseIntPtr(telnetFields["Telnet Server Port"])},
		{Name: "ssh", Enabled: enabledText(sshFields["Administrative Mode"]), Port: parseIntPtr(sshFields["SSH Port"])},
	}
}

// parseIntPtr returns a pointer to the integer value of text, or nil when
// text is empty/unparseable, mirroring Python's `_int(...)` returning None
// for a label the firmware never printed -- e.g. the gsm7252ps prints no
// "SSH Port" line at all, so that port is honestly nil rather than assumed
// to be 22.
func parseIntPtr(text string) *int {
	v, ok := parseInt(text)
	if !ok {
		return nil
	}
	return model.Ptr(v)
}
