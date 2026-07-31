package webui

// Ported field-for-field from
// src/netgear_switch/protocols/http/parse.py at pin 1841111 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1841111). Any discrepancy between this file and that pin is a
// bug in this file, not a deliberate deviation, unless called out in a
// comment.
//
// This file carries the HTMLDialectGS110EMX dialect's parsers, GROUNDED in
// real captures from a physical GS110EMX (webui/testdata/http/
// gs110emx_*.html) -- source lines 66 (_OPEN_ROW_RE), 118-132
// (parse_gambit_token), 204-270 (parse_interface_stats/
// _speed_text_to_mbps), 273-360 (parse_gs110emx_port_status/pvids/
// vlan_ids), 2308-2338 (parse_gs110emx_port_form_fields).
//
// # RE2 has no general lookahead -- the manual open-row split
//
// Real GS110EMX firmware NEVER closes a `<tr class="portID">` row with
// `</tr>` (verified in every gs110emx_*.html capture -- only the enclosing
// table's own closing tags exist between port rows). Python's
// _OPEN_ROW_RE cuts each row at the next `<tr` or `</table>` using a
// zero-width lookahead: `r'<tr class="portID">(.*?)(?=<tr|</table>)'`. Go's
// regexp package (RE2) does not support lookahead at all, so this is NOT a
// literal regex port: splitOpenRows below reproduces the exact same
// semantics by finding every occurrence of the row-start pattern, then for
// each one slicing its content up to whichever comes first in the
// remaining text -- a literal "<tr" substring (ANY tag starting with those
// three characters, not only another portID row) or a literal "</table>"
// substring. This is the single trickiest regex-compat trap in the parser
// set (dossier D-HTTP-P §7.2/§8.1 trap 1) -- see splitOpenRows's own doc
// comment for why this is a faithful, not merely approximate, port of
// Python's non-greedy-`.*?`-plus-lookahead behavior under re.findall's
// leftmost-non-overlapping search order.
//
// parse_gs105pe.go's ParseGS105PE* parsers reuse splitOpenRows with their
// own row-start pattern (gs105peRowStartRE) -- GS105PE's real firmware has
// the identical "never closes the row" quirk, just with an extra optional
// trailing attribute on the open tag.

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// gs110emxRowStartRE is the START half of Python's _OPEN_ROW_RE: the literal
// opening tag, with no trailing-attribute tolerance (GS110EMX's own capture
// never carries one; contrast gs105peRowStartRE).
var gs110emxRowStartRE = regexp.MustCompile(`<tr class="portID">`)

// splitOpenRows reproduces Python's `<row-start>(.*?)(?=<tr|</table>)`
// open-row pattern without RE2 lookahead support (see this file's header
// comment). For every non-overlapping match of startRE (found the same way
// Python's re.findall would, leftmost-first), the row's content runs from
// the end of that match to whichever comes first in the remaining text: the
// next literal "<tr" substring or the next literal "</table>" substring.
// This is exactly equivalent to Python's non-greedy `.*?` plus lookahead:
// the lookahead only tests for "<tr"/"</table>" without consuming, so
// Python's next findall search resumes at that same cut point -- and when
// the next real row immediately follows (the common case), startRE matches
// again at that exact position, reproducing Python's per-row boundaries
// precisely. An intervening non-portID "<tr" (or "</table>") correctly
// terminates the PREVIOUS row's content either way, whether or not it goes
// on to start a new match.
func splitOpenRows(html string, startRE *regexp.Regexp) []string {
	starts := startRE.FindAllStringIndex(html, -1)
	rows := make([]string, 0, len(starts))
	for _, s := range starts {
		rest := html[s[1]:]
		cut := len(rest)
		if i := strings.Index(rest, "<tr"); i >= 0 && i < cut {
			cut = i
		}
		if i := strings.Index(rest, "</table>"); i >= 0 && i < cut {
			cut = i
		}
		rows = append(rows, rest[:cut])
	}
	return rows
}

var gambitTokenRE = regexp.MustCompile(`name=["']Gambit["'][^>]*value=["']([^"']*)["']`)

// ParseGambitToken scrapes the GS110EMX post-login session token, mirroring
// Python parse.parse_gambit_token (source lines 118-132): the
// `/redirect.html` POST response's auto-submit form carries
// `<input type="hidden" name="Gambit" value="...">` -- that value is the
// session identity every subsequent request must carry. Returns ok=false if
// the page has no such field at all, and ok=true with value="" if it has one
// with an empty value (a rejected login) -- a caller checking `!ok ||
// value == ""` catches either shape, exactly like Python's `if not token`.
func ParseGambitToken(html string) (string, bool) {
	m := gambitTokenRE.FindStringSubmatch(html)
	if m == nil {
		return "", false
	}
	return m[1], true
}

var speedRE = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)\s*([GM])`)

// speedTextToMbps converts port-status speed text to Mbps ("10G Full" ->
// 10000, "2.5G" -> 2500, "1000M Full" -> 1000, "No Speed" -> ok=false),
// mirroring Python parse._speed_text_to_mbps (source lines 249-270). Shared
// by ParseGS110EMXPortStatus and parse_gs105pe.go's
// ParseGS105PEPortStatus. The FRACTIONAL form matters: the GS110EMX's
// NBASE-T ports negotiate "2.5G"/"5G" with multi-gig clients -- matching
// only `(\d+)` would backtrack past the "2." in "2.5G" and misread it as
// "5G" -> 5000.
func speedTextToMbps(text string) (int, bool) {
	m := speedRE.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	value, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	if strings.EqualFold(m[2], "G") {
		value *= 1000
	}
	return int(value), true
}

// ParseGS110EMXPortStatus parses GS110EMX's port_settings.html OPEN
// `portID` rows (see splitOpenRows): [1]=port#, [2]=description (empty =>
// nil), [3]=link ("up" exact match, trimmed+lowered), [4]=admin-mode cell
// (AdminEnabled = c[4] lower-cased != "disable" -- this is the SPEED/MODE
// cell doubling as admin state, not a hardcoded true: NSDP genuinely cannot
// see admin state and always reports true, so the two backends are only
// compared on port/link_up/speed_mbps), [5]=speed text via speedTextToMbps
// IF link is up. Mirrors Python parse.parse_gs110emx_port_status (source
// lines 273-317). GROUNDED in gs110emx_port_settings.html (a real capture).
func ParseGS110EMXPortStatus(html string) ([]model.PortStatus, error) {
	rows := splitOpenRows(html, gs110emxRowStartRE)
	if len(rows) == 0 {
		return nil, errUnexpectedPage(`port_settings.html: expected <tr class="portID"> rows, found none`)
	}
	out := make([]model.PortStatus, 0, len(rows))
	for _, row := range rows {
		c := cells(row)
		if len(c) < 6 {
			return nil, errUnexpectedPage("port_settings.html: expected >=6 <td> columns per portID row, got %d", len(c))
		}
		port, ok := parseIntCell(c[1])
		if !ok {
			return nil, errUnexpectedPage("port_settings.html: could not parse a port number from column %q", c[1])
		}
		linkUp := strings.ToLower(strings.TrimSpace(c[3])) == "up"
		var speed *int
		if linkUp {
			if v, ok := speedTextToMbps(c[5]); ok {
				speed = model.Ptr(v)
			}
		}
		var name *string
		if c[2] != "" {
			name = model.Ptr(c[2])
		}
		out = append(out, model.PortStatus{
			Port:         port,
			Name:         name,
			AdminEnabled: strings.ToLower(strings.TrimSpace(c[4])) != "disable",
			LinkUp:       linkUp,
			SpeedMbps:    speed,
		})
	}
	return out, nil
}

// ParseGS110EMXPVIDs parses GS110EMX's vlan_pvidsetting.html OPEN `portID`
// rows: [1]=port#, [2]=PVID. Mirrors Python parse.parse_gs110emx_pvids
// (source lines 320-343). GROUNDED in gs110emx_pvid.html (a real capture).
func ParseGS110EMXPVIDs(html string) ([]model.Pvid, error) {
	rows := splitOpenRows(html, gs110emxRowStartRE)
	if len(rows) == 0 {
		return nil, errUnexpectedPage(`vlan_pvidsetting.html: expected <tr class="portID"> rows, found none`)
	}
	out := make([]model.Pvid, 0, len(rows))
	for _, row := range rows {
		c := cells(row)
		if len(c) < 3 {
			return nil, errUnexpectedPage("vlan_pvidsetting.html: expected >=3 <td> columns per portID row, got %d", len(c))
		}
		port, portOK := parseIntCell(c[1])
		pvid, pvidOK := parseIntCell(c[2])
		if !portOK || !pvidOK {
			return nil, errUnexpectedPage("vlan_pvidsetting.html: could not parse port/PVID from row %v", c)
		}
		out = append(out, model.Pvid{Port: port, Vlan: pvid})
	}
	return out, nil
}

var gs110emxVlanIDRowRE = regexp.MustCompile(`(?s)<tr class="vlanID tableTr">.*?<td class="def">\s*(\d+)\s*</td>`)

// ParseGS110EMXVlanIDs parses GS110EMX's Cf8021q.html (Advanced 802.1Q)
// VLAN list: each `<tr class="vlanID tableTr">` row's first
// `<td class="def">` cell is the VID, deduplicated and sorted ascending.
// Mirrors Python parse.parse_gs110emx_vlan_ids (source lines 346-360).
// GROUNDED in gs110emx_cf8021q.html (a real capture).
func ParseGS110EMXVlanIDs(html string) ([]int, error) {
	matches := gs110emxVlanIDRowRE.FindAllStringSubmatch(html, -1)
	if len(matches) == 0 {
		return nil, errUnexpectedPage(`Cf8021q.html: expected <tr class="vlanID tableTr"> rows with a VID cell, found none`)
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

// ParseInterfaceStats parses GS110EMX's interface_stats.html OPEN `portID`
// rows: [0]=port, [1]=bytes received, [2]=bytes sent, [3]=CRC error packets.
// Mirrors Python parse.parse_interface_stats (source lines 204-246).
// GROUNDED in gs110emx_interface_stats.html. The page exposes no packet
// counts and only ONE combined error column (mapped to RxErrors, matching
// the same column-4 -> rx_errors convention ParsePortStats uses for
// gs305ep); TxErrors/RxPackets/TxPackets stay nil -- this model's HTTP UI
// never reports them.
func ParseInterfaceStats(html string) ([]model.PortStats, error) {
	rows := splitOpenRows(html, gs110emxRowStartRE)
	if len(rows) == 0 {
		return nil, errUnexpectedPage(`interface_stats.html: expected <tr class="portID"> rows, found none`)
	}
	out := make([]model.PortStats, 0, len(rows))
	for _, row := range rows {
		c := cells(row)
		if len(c) < 4 {
			return nil, errUnexpectedPage("interface_stats.html: expected >=4 <td> columns per portID row, got %d", len(c))
		}
		port, ok := parseIntCell(c[0])
		if !ok {
			return nil, errUnexpectedPage("interface_stats.html: could not parse a port number from column %q", c[0])
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

// emxHiddenRE mirrors Python parse._EMX_HIDDEN_RE: every
// `name="..." value="..."` hidden-input pair inside a port row, in whatever
// order they appear.
var emxHiddenRE = regexp.MustCompile(`(?i)<input[^>]*name="(\w+)"[^>]*value="([^"]*)"`)

// ParseGS110EMXPortFormFields returns {port: {field: value}} from
// port_settings.html's per-port OPEN rows (reusing gs110emxRowStartRE/
// splitOpenRows -- the same "never closes a row" shape
// ParseGS110EMXPortStatus handles), mirroring Python
// parse.parse_gs110emx_port_form_fields (source lines 2308-2338). Used to
// echo a port's CURRENT FLOW_CONTROL_MODE back on an admin-mode write
// exactly as the page's own JS does -- inventing a value there would
// silently rewrite the port's flow control as a side effect of enabling it.
// A row without a parseable PORT_NO hidden input is skipped (not an error);
// zero such rows across the whole page is.
func ParseGS110EMXPortFormFields(html string) (map[int]map[string]string, error) {
	rows := splitOpenRows(html, gs110emxRowStartRE)
	out := make(map[int]map[string]string)
	for _, row := range rows {
		fields := make(map[string]string)
		for _, m := range emxHiddenRE.FindAllStringSubmatch(row, -1) {
			fields[m[1]] = m[2]
		}
		if port, ok := parseIntCell(fields["PORT_NO"]); ok {
			out[port] = fields
		}
	}
	if len(out) == 0 {
		return nil, errUnexpectedPage(`port_settings.html: no <tr class="portID"> rows with a PORT_NO`)
	}
	return out, nil
}

// labeledCell mirrors Python parse._labeled_cell: sysInfo.html's
// `<td>Label</td><td>value</td>` row shape, trimmed. Shared by ParseSysInfo
// (this file) and parse_gs105pe.go's ParseGS105PESysInfo -- both dialects'
// identity rows use the exact same two-cell shape, differing only in which
// labels/field names carry the mgmt-IP values (see each function's doc
// comment).
func labeledCell(html, label string) (string, bool) {
	re := regexp.MustCompile(`<td[^>]*>` + regexp.QuoteMeta(label) + `</td>\s*<td[^>]*>([^<]*)</td>`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		return "", false
	}
	return strings.TrimSpace(m[1]), true
}

// namedInputValue mirrors Python parse._named_input_value: sysInfo.html's
// `<input name="NAME" ... value="...">` fields. Shared the same way as
// labeledCell.
func namedInputValue(html, name string) (string, bool) {
	re := regexp.MustCompile(`name=["']` + regexp.QuoteMeta(name) + `["'][^>]*value=["']([^"']*)["']`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// dhcpSelectValueRE mirrors Python parse.parse_sysinfo's inline
// `<tr data-select-value="(\d+)">` scrape wrapping the DHCP-mode <select>.
var dhcpSelectValueRE = regexp.MustCompile(`<tr data-select-value="(\d+)"`)

// ParseSysInfo parses GS110EMX's sysInfo.html -> device identity + mgmt-IP
// config, mirroring Python parse.parse_sysinfo (source lines 2360-2400,
// dossier §2.4). GROUNDED in gs110emx_sysinfo.html (a real capture) -- see
// HTTPSysInfo (types.go) for field provenance, including the ip_mode
// data-select-value inference caveat. Returns an error wrapping
// model.ErrHTTPUnexpectedPage naming whichever field(s) are missing rather
// than fabricating a partial result -- this page is never legitimately
// missing any of these on a real switch.
func ParseSysInfo(html string) (HTTPSysInfo, error) {
	productName, okProduct := labeledCell(html, "Product Name")
	serialNumber, okSerial := labeledCell(html, "Serial Number")
	macAddress, okMAC := labeledCell(html, "MAC Address")
	firmwareVersion, okFirmware := labeledCell(html, "Firmware Version")
	switchName, okSwitchName := namedInputValue(html, "switch_name")
	ipAddress, okIP := namedInputValue(html, "IP_ADDRESS")
	subnetMask, okMask := namedInputValue(html, "SUBNET_MASK")
	gatewayAddress, okGateway := namedInputValue(html, "GATEWAY_ADDRESS")

	var missing []string
	for _, f := range []struct {
		name string
		ok   bool
	}{
		{"Product Name", okProduct},
		{"Serial Number", okSerial},
		{"MAC Address", okMAC},
		{"Firmware Version", okFirmware},
		{"switch_name", okSwitchName},
		{"IP_ADDRESS", okIP},
		{"SUBNET_MASK", okMask},
		{"GATEWAY_ADDRESS", okGateway},
	} {
		if !f.ok {
			missing = append(missing, f.name)
		}
	}
	dhcpSelect := dhcpSelectValueRE.FindStringSubmatch(html)
	if dhcpSelect == nil {
		missing = append(missing, "DHCP data-select-value")
	}
	if len(missing) > 0 {
		return HTTPSysInfo{}, errUnexpectedPage("sysInfo.html: missing expected field(s): %s", strings.Join(missing, ", "))
	}
	ipMode := model.IPModeStatic
	if dhcpSelect[1] == "1" {
		ipMode = model.IPModeDHCP
	}
	return HTTPSysInfo{
		ProductName:     productName,
		SwitchName:      switchName,
		SerialNumber:    serialNumber,
		MacAddress:      macAddress,
		FirmwareVersion: firmwareVersion,
		IPMode:          ipMode,
		IPAddress:       ipAddress,
		SubnetMask:      subnetMask,
		GatewayAddress:  gatewayAddress,
	}, nil
}
