package webui

// Ported field-for-field from
// src/netgear_switch/protocols/http/parse.py at pin b26eb1f in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-b26eb1f). Any discrepancy between this file and that pin is a
// bug in this file, not a deliberate deviation, unless called out in a
// comment.
//
// This file carries the shared low-level scanning helpers (source lines
// 58-85), the two generic token scrapers (parse_login_rand/parse_csrf_hash,
// lines 106-115) and the HTMLDialectStandard (gs305ep) dialect's own
// dashboard.cgi/portStatistics.cgi/getPoePortStatus.cgi/portPVID.cgi/
// 8021qCf.cgi/8021qMembe.cgi parsers (lines 135-201, 1600-1698). Per the
// source module docstring, these gs305ep parsers match only SYNTHETIC
// fixtures headed "UNVERIFIED-pending-capture" -- their column offsets are a
// same-family guess, not a live capture, so confirm against a real GS305EP
// before relying on them in production. GS105PE reuses ParseVLANIDs,
// ParseMembership, ParseSelectedVlan, ParseLoginRand and ParseCSRFHash
// verbatim (its 8021qCf.cgi/8021qMembe.cgi/login.cgi pages share this exact
// shape byte-for-byte with gs305ep -- see parse_gs105pe.go and dossier
// D-HTTP-P §2.5) but has its own port-status/PVID/stats parsers (its
// portID rows never close, unlike gs305ep's).
//
// Two deliberate failure shapes, preserved from the source (see its module
// docstring):
//   - A *token* scrape (ParseLoginRand/ParseCSRFHash/ParseSelectedVlan)
//     returns ok=false when the value is absent; the caller decides whether
//     that is fatal.
//   - A *table/page* parser that cannot find the structure the page is
//     documented to always contain returns an error wrapping
//     model.ErrHTTPUnexpectedPage naming what was expected -- these pages
//     are never legitimately empty on a real switch, so a missing structure
//     means the wrong page came back, never silently swallowed into an
//     empty slice/map.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// rowRE mirrors Python parse._ROW_RE: a CLOSED `<tr class="portID">...</tr>`
// row, the gs305ep CGI shape. Contrast gs110emxRowStartRE/gs105peRowStartRE
// (parse_gs110emx.go/parse_gs105pe.go), whose real firmware never closes the
// row.
var rowRE = regexp.MustCompile(`(?is)<tr\s+class="portID">(.*?)</tr>`)

// tdRE/tagRE mirror Python parse._TD_RE/_TAG_RE, used by cells to strip a
// row down to its per-column plain text.
var (
	tdRE  = regexp.MustCompile(`(?is)<td[^>]*>(.*?)</td>`)
	tagRE = regexp.MustCompile(`<[^>]+>`)
)

// intRE mirrors Python parse._int's `-?\d+` search pattern.
var intRE = regexp.MustCompile(`-?\d+`)

// wireToMode mirrors Python parse._WIRE_TO_MODE: the Plus-CGI
// (8021qMembe.cgi) per-port hiddenMem wire code, 1=Untagged/2=Tagged/
// 3=Excluded. NEVER share this with the FASTPATH "VLAN Membership" page's
// codes, which are the INVERSE (1=Tagged/2=Untagged) -- see dossier §8.1
// trap 2.
var wireToMode = map[byte]model.VlanMode{
	'1': model.VlanUntagged,
	'2': model.VlanTagged,
	'3': model.VlanExcluded,
}

// detectText mirrors Python parse._DETECT_TEXT: getPoePortStatus.cgi's
// lower-cased detect-state cell text -> model.PoEDetect. An unmatched value
// maps to model.PoEDetectUnknown (the map's zero-value miss), not an error --
// this cell's exact text vocabulary is not exhaustively documented.
var detectText = map[string]model.PoEDetect{
	"delivering": model.PoEDetectDelivering,
	"searching":  model.PoEDetectSearching,
	"disabled":   model.PoEDetectDisabled,
	"fault":      model.PoEDetectFault,
}

// cells mirrors Python parse._cells: every `<td>`'s inner HTML in rowHTML,
// tags stripped and whitespace trimmed, in document order.
func cells(rowHTML string) []string {
	matches := tdRE.FindAllStringSubmatch(rowHTML, -1)
	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = strings.TrimSpace(tagRE.ReplaceAllString(m[1], ""))
	}
	return out
}

// parseIntCell mirrors Python parse._int for fields the Go model types as a
// plain int (port numbers, PVIDs, VLAN IDs, PoE milliwatts): the value of
// the first `-?\d+` match in text, or ok=false if none.
func parseIntCell(text string) (int, bool) {
	m := intRE.FindString(text)
	if m == "" {
		return 0, false
	}
	v, err := strconv.Atoi(m)
	if err != nil {
		return 0, false
	}
	return v, true
}

// intCellPtr adapts parseIntCell to an optional (*int) model field, nil when
// absent -- e.g. PoEStatus.PowerMw.
func intCellPtr(text string) *int {
	v, ok := parseIntCell(text)
	if !ok {
		return nil
	}
	return model.Ptr(v)
}

// parseUint64Cell is parseIntCell's counterpart for the Go model's uint64
// traffic counters (model.PortStats.RxBytes etc.), which Python's arbitrary-
// precision `_int` doesn't need to distinguish from a plain int. A negative
// match (the same `-?\d+` regex Python uses) is treated as absent -- no
// capture on record produces one, and model.PortStats has no signed-counter
// representation to put it in.
func parseUint64Cell(text string) (uint64, bool) {
	m := intRE.FindString(text)
	if m == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(m, 10, 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return uint64(v), true
}

// uint64CellPtr adapts parseUint64Cell to an optional (*uint64) model field,
// nil when absent.
func uint64CellPtr(text string) *uint64 {
	v, ok := parseUint64Cell(text)
	if !ok {
		return nil
	}
	return model.Ptr(v)
}

// errUnexpectedPage wraps model.ErrHTTPUnexpectedPage with a formatted
// message, mirroring Python parse.py raising HttpUnexpectedPageError (the
// Go port's model.ErrHTTPUnexpectedPage specializes model.ErrHTTP -- see
// dossier §2 intro) -- the "page/table" parser failure shape: these pages
// are never legitimately empty on a real switch, so a missing structure
// means the wrong page came back, not "empty switch".
func errUnexpectedPage(format string, a ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, a...), model.ErrHTTPUnexpectedPage)
}

var loginRandRE = regexp.MustCompile(`id=["']rand["'][^>]*value=["']([^"']*)["']`)

// ParseLoginRand scrapes the login nonce from `<input id="rand" ...
// value="...">`, mirroring Python parse.parse_login_rand (source lines
// 106-109). Shared by every LoginSchemeMergeHashCGI/LoginSchemeGambit model
// (gs305ep, gs105pe, gs110emx) -- the login page shape is identical across
// all three. ok=false means the page carries no such field; the caller
// decides whether that is fatal.
func ParseLoginRand(html string) (string, bool) {
	m := loginRandRE.FindStringSubmatch(html)
	if m == nil {
		return "", false
	}
	return m[1], true
}

var csrfHashRE = regexp.MustCompile(`name=["']hash["'][^>]*value=["']([^"']*)["']`)

// ParseCSRFHash scrapes the Plus-CGI per-page CSRF token from
// `<input name="hash" value="...">`, mirroring Python parse.parse_csrf_hash
// (source lines 112-115). Every Plus-CGI write form (gs305ep, gs105pe)
// carries this on the page it is submitted from. ok=false means absent.
func ParseCSRFHash(html string) (string, bool) {
	m := csrfHashRE.FindStringSubmatch(html)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ParsePortStatus parses gs305ep's dashboard.cgi CLOSED `portID` rows:
// [1]=port, [2]=link/speed text (`"up" in text.lower()` => link_up, then the
// leading digits of that same cell as speed_mbps IF up), [3]=admin
// (lower-cased, starts with "enable"), [4]=name (empty => nil). Mirrors
// Python parse.parse_port_status (source lines 135-166). Requires >=5 `<td>`s
// per row; 0 rows or a short row is an error wrapping
// model.ErrHTTPUnexpectedPage.
func ParsePortStatus(html string) ([]model.PortStatus, error) {
	rows := rowRE.FindAllStringSubmatch(html, -1)
	if len(rows) == 0 {
		return nil, errUnexpectedPage(`dashboard.cgi: expected <tr class="portID"> rows, found none`)
	}
	out := make([]model.PortStatus, 0, len(rows))
	for _, m := range rows {
		c := cells(m[1])
		if len(c) < 5 {
			return nil, errUnexpectedPage("dashboard.cgi: expected >=5 <td> columns per portID row, got %d", len(c))
		}
		port, ok := parseIntCell(c[1])
		if !ok {
			return nil, errUnexpectedPage("dashboard.cgi: could not parse a port number from column %q", c[1])
		}
		linkUp := strings.Contains(strings.ToLower(c[2]), "up")
		var speed *int
		if linkUp {
			speed = intCellPtr(c[2])
		}
		var name *string
		if c[4] != "" {
			name = model.Ptr(c[4])
		}
		out = append(out, model.PortStatus{
			Port:         port,
			Name:         name,
			AdminEnabled: strings.HasPrefix(strings.ToLower(c[3]), "enable"),
			LinkUp:       linkUp,
			SpeedMbps:    speed,
		})
	}
	return out, nil
}

// ParsePortStats parses gs305ep's portStatistics.cgi CLOSED `portID` rows:
// [0]=port, [1]=rx_bytes, [2]=tx_bytes, [3]=rx_errors (CRC). Mirrors Python
// parse.parse_port_stats (source lines 169-201). RxPackets/TxPackets/
// TxErrors stay nil -- this page has no such columns.
func ParsePortStats(html string) ([]model.PortStats, error) {
	rows := rowRE.FindAllStringSubmatch(html, -1)
	if len(rows) == 0 {
		return nil, errUnexpectedPage(`portStatistics.cgi: expected <tr class="portID"> rows, found none`)
	}
	out := make([]model.PortStats, 0, len(rows))
	for _, m := range rows {
		c := cells(m[1])
		if len(c) < 4 {
			return nil, errUnexpectedPage("portStatistics.cgi: expected >=4 <td> columns per portID row, got %d", len(c))
		}
		port, ok := parseIntCell(c[0])
		if !ok {
			return nil, errUnexpectedPage("portStatistics.cgi: could not parse a port number from column %q", c[0])
		}
		out = append(out, model.PortStats{
			Port:     port,
			RxBytes:  uint64CellPtr(c[1]),
			TxBytes:  uint64CellPtr(c[2]),
			RxErrors: uint64CellPtr(c[3]),
		})
	}
	return out, nil
}

// ParsePoEStatus parses gs305ep's getPoePortStatus.cgi CLOSED `portID` rows:
// [0]=port, [1]=detect-state text (mapped via detectText, unmatched =>
// model.PoEDetectUnknown), [2]=power_mw (bare int, no unit disambiguation
// needed on this page). AdminEnabled = detect is not Disabled. Mirrors
// Python parse.parse_poe_status (source lines 1600-1630).
func ParsePoEStatus(html string) ([]model.PoEStatus, error) {
	rows := rowRE.FindAllStringSubmatch(html, -1)
	if len(rows) == 0 {
		return nil, errUnexpectedPage(`getPoePortStatus.cgi: expected <tr class="portID"> rows, found none`)
	}
	out := make([]model.PoEStatus, 0, len(rows))
	for _, m := range rows {
		c := cells(m[1])
		if len(c) < 3 {
			return nil, errUnexpectedPage("getPoePortStatus.cgi: expected >=3 <td> columns per portID row, got %d", len(c))
		}
		port, ok := parseIntCell(c[0])
		if !ok {
			return nil, errUnexpectedPage("getPoePortStatus.cgi: could not parse a port number from column %q", c[0])
		}
		detect, known := detectText[strings.ToLower(c[1])]
		if !known {
			detect = model.PoEDetectUnknown
		}
		out = append(out, model.PoEStatus{
			Port:         port,
			AdminEnabled: detect != model.PoEDetectDisabled,
			Detect:       detect,
			PowerMw:      intCellPtr(c[2]),
		})
	}
	return out, nil
}

// pvidPairRE mirrors Python parse.parse_pvids's finditer pattern: a
// `sel="text"` cell (the port) immediately followed by a `sel="input"` cell
// (the PVID), scanned across the WHOLE page rather than tied to individual
// row boundaries (the row-existence check above is a page-sanity
// precondition only).
var pvidPairRE = regexp.MustCompile(`(?s)<td[^>]*sel="text"[^>]*>(\d+).*?</td>\s*<td[^>]*sel="input"[^>]*>(\d+)</td>`)

// ParsePVIDs parses gs305ep's portPVID.cgi: NOT column-index based like
// ParsePortStatus -- it scans for `<td sel="text">(\d+)...</td>\s*
// <td sel="input">(\d+)</td>` pairs directly across the whole page (still
// requiring portID rows to exist first, as a page-sanity precondition).
// Mirrors Python parse.parse_pvids (source lines 1633-1652).
func ParsePVIDs(html string) ([]model.Pvid, error) {
	if !rowRE.MatchString(html) {
		return nil, errUnexpectedPage(`portPVID.cgi: expected <tr class="portID"> rows, found none`)
	}
	matches := pvidPairRE.FindAllStringSubmatch(html, -1)
	if len(matches) == 0 {
		return nil, errUnexpectedPage(`portPVID.cgi: expected <td sel="text"> and <td sel="input"> cells in portID rows, found none matching`)
	}
	out := make([]model.Pvid, 0, len(matches))
	for _, m := range matches {
		port, err1 := strconv.Atoi(m[1])
		pvid, err2 := strconv.Atoi(m[2])
		if err1 != nil || err2 != nil {
			return nil, errUnexpectedPage("portPVID.cgi: could not parse port/PVID pair %q/%q", m[1], m[2])
		}
		out = append(out, model.Pvid{Port: port, Vlan: pvid})
	}
	return out, nil
}

var vlanckRE = regexp.MustCompile(`name="vlanck\d+"[^>]*value="(\d+)"`)

// ParseVLANIDs parses gs305ep's (and gs105pe's, sharing the identical page
// shape) 8021qCf.cgi VLAN checkboxes: every `name="vlanckN" value="VID"`
// input's value, deduplicated and sorted ascending. Mirrors Python
// parse.parse_vlan_ids (source lines 1655-1662).
func ParseVLANIDs(html string) ([]int, error) {
	matches := vlanckRE.FindAllStringSubmatch(html, -1)
	if len(matches) == 0 {
		return nil, errUnexpectedPage(`8021qCf.cgi: expected at least one name="vlanckN" checkbox, found none`)
	}
	seen := make(map[int]bool, len(matches))
	for _, m := range matches {
		if v, err := strconv.Atoi(m[1]); err == nil {
			seen[v] = true
		}
	}
	out := make([]int, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Ints(out)
	return out, nil
}

var (
	selectedVlanValueFirstRE   = regexp.MustCompile(`<option[^>]*selected[^>]*value="(\d+)"`)
	selectedVlanSelectedLastRE = regexp.MustCompile(`<option[^>]*value="(\d+)"[^>]*selected`)
)

// ParseSelectedVlan scrapes 8021qMembe.cgi's currently-selected
// `<option ... selected ... value="N">` in the VLAN dropdown (gs305ep and
// gs105pe share this page shape): tries `selected` before `value=` first,
// then the reverse attribute order. Mirrors Python parse.parse_selected_vlan
// (source lines 1665-1671). ok=false means no selected option was found.
func ParseSelectedVlan(html string) (int, bool) {
	if m := selectedVlanValueFirstRE.FindStringSubmatch(html); m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil {
			return v, true
		}
	}
	if m := selectedVlanSelectedLastRE.FindStringSubmatch(html); m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil {
			return v, true
		}
	}
	return 0, false
}

var (
	hiddenMemByIDRE   = regexp.MustCompile(`id="hiddenMem"[^>]*value="([^"]*)"`)
	hiddenMemByNameRE = regexp.MustCompile(`name="hiddenMem"[^>]*value="([^"]*)"`)
)

// ParseMembership parses 8021qMembe.cgi's `hiddenMem` input value: one WIRE
// CODE character per port, 1=Untagged/2=Tagged/3=Excluded (wireToMode).
// Tries `id="hiddenMem"` first, falls back to `name="hiddenMem"`. Mirrors
// Python parse.parse_membership (source lines 1674-1698). Requires
// len(raw) >= portCount; an unknown code character is an error naming the
// offending port. Returns {port: VlanMode} for 1..portCount.
func ParseMembership(html string, portCount int) (map[int]model.VlanMode, error) {
	m := hiddenMemByIDRE.FindStringSubmatch(html)
	if m == nil {
		m = hiddenMemByNameRE.FindStringSubmatch(html)
	}
	if m == nil {
		return nil, errUnexpectedPage("8021qMembe.cgi: expected a hiddenMem input with the per-port wire codes, found none")
	}
	raw := m[1]
	if len(raw) < portCount {
		return nil, errUnexpectedPage("8021qMembe.cgi: hiddenMem value %q has fewer than port_count=%d codes", raw, portCount)
	}
	result := make(map[int]model.VlanMode, portCount)
	for i := range portCount {
		ch := raw[i]
		mode, ok := wireToMode[ch]
		if !ok {
			return nil, errUnexpectedPage("8021qMembe.cgi: unknown VLAN wire code %q at port %d", string(ch), i+1)
		}
		result[i+1] = mode
	}
	return result, nil
}
