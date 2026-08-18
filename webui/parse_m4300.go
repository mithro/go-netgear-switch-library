package webui

// Ported field-for-field from
// src/netgear_switch/protocols/http/parse.py at pin b26eb1f in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-b26eb1f). Any discrepancy between this file and that pin is a
// bug in this file, not a deliberate deviation, unless called out in a
// comment.
//
// This file carries the HTMLDialectM4300 dialect's own parsers -- source
// lines 540-838 (_CHEETAH_CELL_RE, parse_cheetah_rows,
// parse_m4300_port_status/stats/pvids/vlans/macs/sysinfo/sensors) -- plus
// _FASTPATH_IFACE_RE/_expand_port_list (source lines 665-699), which are
// shared with parse_xe.go's XE_FASTPATH/S3300 vlan-member-list parsers
// (both dialects render the SAME "1/0/N - 1/0/M, lag K" egress-list syntax).
// GROUNDED in real M4300-24X captures (webui/testdata/http/m4300_*.html),
// live cross-verified against SNMP on 10.1.5.13 (dossier D-HTTP-P §2.6).
//
// # Cheetah field-comment addressing
//
// Every M4300 /v1 data cell is a hidden input whose NAME encodes the row
// INSTANCE, immediately followed by an HTML comment naming the field
// SEMANTICALLY:
//
//	<TD ... id=1_2_10><INPUT xid=1_2_10 TYPE=hidden NAME=1.0.24.v_1_2_10
//	     VALUE="Link Up">Link Up</TD><!-- baseport_LinkStatus2 -->
//
// This is the opposite addressing scheme from parse_xe.go's XE_FASTPATH
// dialect (coordinate-only, no comment) -- M4300 cells are immune to column
// reorder because they address BY NAME, not by position.

import (
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// unescapeHTML wraps stdlib html.UnescapeString. Every exported parser in
// this file and its XE_FASTPATH/GoAhead siblings takes its raw page text as
// a parameter literally named "html" (mirroring Python's html: str, and the
// existing ParsePortStatus(html string) convention) -- calling html.
// UnescapeString directly inside such a function would try to call a method
// on the shadowing string parameter instead of the stdlib package, so every
// call site in these three files goes through this indirection instead.
func unescapeHTML(s string) string {
	return html.UnescapeString(s)
}

// sortedPortSet renders a port-number set as a canonical ascending slice
// (never nil, even when empty), matching model.VLANInfo's "Port sets are
// canonical: sorted ascending, never nil" contract.
func sortedPortSet(ports map[int]bool) []int {
	out := make([]int, 0, len(ports))
	for p := range ports {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// cheetahCellRE mirrors Python parse._CHEETAH_CELL_RE.
var cheetahCellRE = regexp.MustCompile(`(?i)NAME=([0-9.]+)\.v_[0-9_]+ VALUE="([^"]*)"[^<]*(?:</TD>)?<!-- (\w+) -->`)

// ParseCheetahRows groups an M4300 Cheetah page's cells into one map per row
// instance, in first-seen order, keyed by the trailing comment's field name.
// Mirrors Python parse.parse_cheetah_rows (source lines 546-557). Cheetah
// HTML-escapes cell values (interface names arrive as "1&#x2F;0&#x2F;1"),
// so every value is unescaped and trimmed before being stored. Returns an
// empty slice (never an error) for a page with no such cells -- the caller
// decides whether that is fatal.
func ParseCheetahRows(htmlStr string) []map[string]string {
	order := make([]string, 0)
	rows := make(map[string]map[string]string)
	for _, m := range cheetahCellRE.FindAllStringSubmatch(htmlStr, -1) {
		instance, value, field := m[1], m[2], m[3]
		row, ok := rows[instance]
		if !ok {
			row = make(map[string]string)
			rows[instance] = row
			order = append(order, instance)
		}
		row[field] = strings.TrimSpace(unescapeHTML(value))
	}
	out := make([]map[string]string, 0, len(order))
	for _, inst := range order {
		out = append(out, rows[inst])
	}
	return out
}

// cheetahInt mirrors Python parse._cheetah_int: the leading -?\d+ of
// row[field], or ok=false if field is absent from row or carries no digits.
func cheetahInt(row map[string]string, field string) (int, bool) {
	v, ok := row[field]
	if !ok {
		return 0, false
	}
	return parseIntCell(v)
}

// m4300PortFromRow is the port-number fallback shared by
// ParseM4300Stats/ParseM4300PVIDs: baseport_ifIndex when present, else the
// trailing component of baseinterfaceListing_Interfaces (this page keys
// some rows by interface name instead of ifIndex). Mirrors Python's
// `_int(name.rsplit("/", 1)[-1]) if "/" in name else _int(name)` exactly --
// using the WHOLE name instead of only its last "/"-separated segment would
// misread "1/0/24" as unit "1", not port 24.
func m4300PortFromRow(r map[string]string) (int, bool) {
	if port, ok := cheetahInt(r, "baseport_ifIndex"); ok {
		return port, true
	}
	name := r["baseinterfaceListing_Interfaces"]
	seg := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		seg = name[idx+1:]
	}
	return parseIntCell(seg)
}

// ParseM4300PortStatus parses M4300 portsConfiguration.html -> per-port
// status. baseport_ifIndex is the port number (matching the SNMP backend's
// ifIndex keying), baseinterfaceListing_Interfaces the name ("1/0/1"),
// baseport_AdminMode the admin state, baseport_LinkStatus2 the link
// ("Link Up"/"Link Down") and baseport_PhysicalStatus the speed text.
// Mirrors Python parse.parse_m4300_port_status (source lines 564-598).
// GROUNDED in m4300_ports.html.
func ParseM4300PortStatus(htmlStr string) ([]model.PortStatus, error) {
	var rows []map[string]string
	for _, r := range ParseCheetahRows(htmlStr) {
		if _, ok := r["baseport_LinkStatus2"]; ok {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return nil, errUnexpectedPage("portsConfiguration.html: no baseport_* cells found")
	}
	out := make([]model.PortStatus, 0, len(rows))
	for _, r := range rows {
		port, ok := cheetahInt(r, "baseport_ifIndex")
		if !ok {
			return nil, errUnexpectedPage("portsConfiguration.html: row without baseport_ifIndex")
		}
		linkUp := strings.Contains(strings.ToLower(r["baseport_LinkStatus2"]), "up")
		var name *string
		if v := r["baseinterfaceListing_Interfaces"]; v != "" {
			name = model.Ptr(v)
		}
		var speed *int
		if linkUp {
			if v, ok := speedTextToMbps(r["baseport_PhysicalStatus"]); ok {
				speed = model.Ptr(v)
			}
		}
		out = append(out, model.PortStatus{
			Port:         port,
			Name:         name,
			AdminEnabled: strings.ToLower(r["baseport_AdminMode"]) == "enable",
			LinkUp:       linkUp,
			SpeedMbps:    speed,
		})
	}
	return out, nil
}

// ParseM4300Stats parses M4300 portStatistics.html -> per-port FRAME
// counters. This page reports FRAMES, not octets
// (basePortStats_TotalFramesRx/Tx), so RxBytes/TxBytes are honestly nil and
// the counts land in RxPackets/TxPackets -- a byte-level comparison against
// SNMP is impossible for this model, but a packet-level one is not. Mirrors
// Python parse.parse_m4300_stats (source lines 601-638). GROUNDED in
// m4300_portstats.html.
func ParseM4300Stats(htmlStr string) ([]model.PortStats, error) {
	var rows []map[string]string
	for _, r := range ParseCheetahRows(htmlStr) {
		if _, ok := r["basePortStats_TotalFramesRx"]; ok {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return nil, errUnexpectedPage("portStatistics.html: no basePortStats_* cells found")
	}
	out := make([]model.PortStats, 0, len(rows))
	for _, r := range rows {
		port, ok := m4300PortFromRow(r)
		if !ok {
			return nil, errUnexpectedPage("portStatistics.html: row without an identifiable port")
		}
		var rxPkts, txPkts, rxErrs, txErrs *uint64
		if v, ok := cheetahInt(r, "basePortStats_TotalFramesRx"); ok {
			rxPkts = model.Ptr(uint64(v))
		}
		if v, ok := cheetahInt(r, "basePortStats_TotalFramesTx"); ok {
			txPkts = model.Ptr(uint64(v))
		}
		if v, ok := cheetahInt(r, "basePortStats_TotalErrorFramesRx"); ok {
			rxErrs = model.Ptr(uint64(v))
		}
		if v, ok := cheetahInt(r, "basePortStats_TotalErrorFramesTx"); ok {
			txErrs = model.Ptr(uint64(v))
		}
		out = append(out, model.PortStats{
			Port:      port,
			RxPackets: rxPkts,
			TxPackets: txPkts,
			RxErrors:  rxErrs,
			TxErrors:  txErrs,
		})
	}
	return out, nil
}

// ParseM4300PVIDs parses M4300 portPvidConfiguration.html -> (port, pvid)
// pairs. Mirrors Python parse.parse_m4300_pvids (source lines 641-662). A
// row without a parseable pair is silently skipped (not a per-row error);
// an empty final result IS an error. GROUNDED in m4300_pvid.html.
func ParseM4300PVIDs(htmlStr string) ([]model.Pvid, error) {
	var rows []map[string]string
	for _, r := range ParseCheetahRows(htmlStr) {
		if _, ok := r["SwitchingVlanPortConfig_Pvid"]; ok {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return nil, errUnexpectedPage("portPvidConfiguration.html: no SwitchingVlanPortConfig_Pvid cells")
	}
	out := make([]model.Pvid, 0, len(rows))
	for _, r := range rows {
		port, portOK := m4300PortFromRow(r)
		pvid, pvidOK := cheetahInt(r, "SwitchingVlanPortConfig_Pvid")
		if !portOK || !pvidOK {
			continue
		}
		out = append(out, model.Pvid{Port: port, Vlan: pvid})
	}
	if len(out) == 0 {
		return nil, errUnexpectedPage("portPvidConfiguration.html: no (port, pvid) pair could be parsed")
	}
	return out, nil
}

// fastpathIfaceRE mirrors Python parse._FASTPATH_IFACE_RE: a bare
// "unit/slot/port" interface name, shared by BOTH FASTPATH web dialects
// (M4300 Cheetah /v1 and the GSM7252PS/S3300 XE pages) -- both render
// physical interfaces as "1/0/7" and non-physical ones as "lag 3"/"vlan 5".
var fastpathIfaceRE = regexp.MustCompile(`(\d+)/(\d+)/(\d+)`)

// fastpathIfaceFullMatch emulates Python's fastpathIfaceRE.fullmatch(s):
// Go's regexp has no fullmatch primitive, so this searches once and then
// verifies the match consumed the entire (already-trimmed) string.
func fastpathIfaceFullMatch(s string) []string {
	m := fastpathIfaceRE.FindStringSubmatch(s)
	if m == nil || m[0] != s {
		return nil
	}
	return m
}

// isTempLimitRE mirrors Python parse._IS_TEMP_LIMIT_RE: the M4300
// temperature block mixes a live reading ("MAC 53 C") with the box's static
// datasheet THRESHOLD ("Max Operating Temperature 81 C"); returning the
// threshold as a Sensor would make a "hottest sensor" alarm read 81C
// forever, so limit rows are excluded.
var isTempLimitRE = regexp.MustCompile(`(?i)\b(max|maximum|threshold|limit)\b`)

// expandPortList mirrors Python parse._expand_port_list: M4300/GSM7252PS
// FASTPATH egress-list syntax ("1/0/1 - 1/0/2, 1/0/5, lag 1 - lag 128") ->
// the set of PHYSICAL port numbers, sorted ascending. Only unit/slot/port
// entries are physical; "lag N" entries are link-aggregation groups and are
// SKIPPED (expanding them once turned "lag 1 - lag 128" into 128 phantom
// ports on a 24-port switch). A range expands only when both ends share
// (unit, slot) and p1 <= p2. Mirrors source lines 677-699.
func expandPortList(raw string) []int {
	ports := make(map[int]bool)
	for _, part := range strings.Split(raw, ",") {
		ends := fastpathIfaceRE.FindAllStringSubmatch(part, -1)
		if len(ends) == 0 {
			continue // "lag N" and any other non-physical interface
		}
		if strings.Contains(part, "-") && len(ends) == 2 {
			u1, s1, p1 := ends[0][1], ends[0][2], ends[0][3]
			u2, s2, p2 := ends[1][1], ends[1][2], ends[1][3]
			pi1, err1 := strconv.Atoi(p1)
			pi2, err2 := strconv.Atoi(p2)
			if u1 == u2 && s1 == s2 && err1 == nil && err2 == nil && pi1 <= pi2 {
				for p := pi1; p <= pi2; p++ {
					ports[p] = true
				}
				continue
			}
		}
		for _, e := range ends {
			if p, err := strconv.Atoi(e[3]); err == nil {
				ports[p] = true
			}
		}
	}
	return sortedPortSet(ports)
}

// ParseM4300Vlans parses M4300 vlanStatus.html -> VLANs with their egress
// member ports. This page does NOT distinguish tagged from untagged, so
// both TaggedPorts and UntaggedPorts are left EMPTY -- only MemberPorts is
// populated (see the reader's docs, Task 6). Mirrors Python
// parse.parse_m4300_vlans (source lines 702-737). GROUNDED in
// m4300_vlanstatus.html.
func ParseM4300Vlans(htmlStr string) ([]model.VLANInfo, error) {
	var rows []map[string]string
	for _, r := range ParseCheetahRows(htmlStr) {
		if _, ok := r["SwitchingVlanStaticConfig_VlanIndex"]; ok {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return nil, errUnexpectedPage("vlanStatus.html: no SwitchingVlanStaticConfig_VlanIndex cells")
	}
	out := make([]model.VLANInfo, 0, len(rows))
	for _, r := range rows {
		vid, ok := cheetahInt(r, "SwitchingVlanStaticConfig_VlanIndex")
		if !ok {
			continue
		}
		var name *string
		if v := r["SwitchingVlanStaticConfig_VlanName"]; v != "" {
			name = model.Ptr(v)
		}
		out = append(out, model.VLANInfo{
			VlanID:        vid,
			Name:          name,
			MemberPorts:   expandPortList(r["SwitchingVlanCurrentConfig_VlanCurrentEgressPortList"]),
			TaggedPorts:   []int{},
			UntaggedPorts: []int{},
		})
	}
	if len(out) == 0 {
		return nil, errUnexpectedPage("vlanStatus.html: no VLAN row could be parsed")
	}
	return out, nil
}

// m4300MacTotalRE finds basicAddressTable.html's page-level scalar stating
// the TRUE FDB size (SwitchingFdbStats_ActiveAddrEntries), outside the
// row-instance cells parse_cheetah_rows groups.
var m4300MacTotalRE = regexp.MustCompile(`NAME=v_1_1_1 VALUE="(\d+)"`)

// ParseM4300Macs parses M4300 basicAddressTable.html -> the MAC/FDB table
// (one page). Mirrors Python parse.parse_m4300_macs (source lines 740-789).
// GROUNDED in m4300_addresstable.html. Two real-hardware traps avoided:
//
//  1. The Intf cell is not always physical -- "lag 1"/"vlan 1"/the "0/15/1"
//     service port all appear and are SKIPPED (only a fullmatch on
//     unit/slot/port yields a port).
//  2. This page is PAGINATED: the true FDB size lives in a page-level
//     scalar (NAME=v_1_1_1), separate from the rendered rows. If it exceeds
//     the rendered row count, this returns an error naming SNMP as the
//     complete source rather than a silently truncated FDB.
func ParseM4300Macs(htmlStr string) ([]model.MacEntry, error) {
	var rows []map[string]string
	for _, r := range ParseCheetahRows(htmlStr) {
		if _, ok := r["SwitchingmacAddrGroup_MacAddress"]; ok {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return nil, errUnexpectedPage("basicAddressTable.html: no SwitchingmacAddrGroup_MacAddress cells found")
	}
	out := make([]model.MacEntry, 0, len(rows))
	for _, r := range rows {
		mac := strings.ToUpper(strings.TrimSpace(r["SwitchingmacAddrGroup_MacAddress"]))
		if mac == "" {
			continue
		}
		iface := fastpathIfaceFullMatch(strings.TrimSpace(r["SwitchingmacAddrGroup_Intf"]))
		if iface == nil {
			continue // lag N / vlan N / service port: no physical port
		}
		port, err := strconv.Atoi(iface[3])
		if err != nil {
			continue
		}
		var vlanID *int
		if v, ok := cheetahInt(r, "SwitchingmacAddrGroup_vlanIndex"); ok {
			vlanID = model.Ptr(v)
		}
		out = append(out, model.MacEntry{Mac: mac, Port: port, VlanID: vlanID})
	}
	if m := m4300MacTotalRE.FindStringSubmatch(htmlStr); m != nil {
		total, err := strconv.Atoi(m[1])
		if err == nil && total > len(rows) {
			return nil, errUnexpectedPage(
				"basicAddressTable.html: the switch reports %d FDB entries but this page renders only %d -- "+
					"the web UI paginates the MAC table. Use the SNMP backend for the complete FDB rather than a silently truncated page.",
				total, len(rows))
		}
	}
	return out, nil
}

var (
	m4300MgmtAddrRE = regexp.MustCompile(`(?is)IPv4 Management Address</td>.*?>([0-9.]+)\s*/\s*([0-9.]+)<`)
	m4300MgmtMacRE  = regexp.MustCompile(`System MAC Address</td>\s*<td[^>]*>\s*([0-9A-Fa-f:]{17})`)
)

// ParseM4300Sysinfo parses M4300 sysInfo.html -> management IP + base MAC.
// "IPv4 Management Address" renders as addr/netmask inside a link; "System
// MAC Address" is a plain labelled cell. The page reports no DHCP/static
// indicator, so Mode is honestly model.IPModeUnknown rather than guessed --
// matching what the SNMP backend reports for this model. Mirrors Python
// parse.parse_m4300_sysinfo (source lines 792-816). GROUNDED in
// m4300_sysinfo.html.
func ParseM4300Sysinfo(htmlStr string) (model.MgmtIPConfig, error) {
	var addr, netmask *string
	if m := m4300MgmtAddrRE.FindStringSubmatch(htmlStr); m != nil {
		addr, netmask = model.Ptr(m[1]), model.Ptr(m[2])
	}
	macM := m4300MgmtMacRE.FindStringSubmatch(htmlStr)
	if addr == nil && macM == nil {
		return model.MgmtIPConfig{}, errUnexpectedPage(
			"sysInfo.html: neither IPv4 Management Address nor System MAC Address found")
	}
	var baseMac *string
	if macM != nil {
		baseMac = model.Ptr(strings.ToUpper(macM[1]))
	}
	return model.MgmtIPConfig{
		Mode:    model.IPModeUnknown,
		Address: addr,
		Netmask: netmask,
		Gateway: nil,
		BaseMac: baseMac,
	}, nil
}

var m4300SensorRE = regexp.MustCompile(`<td[^>]*>([A-Za-z ]{2,28})</td>\s*<td[^>]*>\s*(\d+)\s*&#8451;`)

// ParseM4300Sensors parses M4300 sysInfo.html -> TEMPERATURE sensors only.
// Threshold rows in the same block ("Max Operating Temperature 81") are a
// static datasheet LIMIT, not a reading, and are excluded (isTempLimitRE).
// The FAN block is deliberately NOT returned: it reports a non-numeric
// state ("Fan-1 OK") and model.Sensor.Value is a required float -- SNMP is
// the honest source for fan RPM on this model. Mirrors Python
// parse.parse_m4300_sensors (source lines 819-838). GROUNDED in
// m4300_sysinfo.html.
func ParseM4300Sensors(htmlStr string) []model.Sensor {
	out := make([]model.Sensor, 0)
	for _, m := range m4300SensorRE.FindAllStringSubmatch(htmlStr, -1) {
		label, celsius := m[1], m[2]
		if isTempLimitRE.MatchString(label) {
			continue
		}
		v, err := strconv.ParseFloat(celsius, 64)
		if err != nil {
			continue
		}
		out = append(out, model.Sensor{
			Name:  strings.TrimSpace(label),
			Kind:  "temperature",
			Value: v,
			Unit:  "C",
		})
	}
	return out
}
