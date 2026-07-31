package webui

// Ported field-for-field from
// src/netgear_switch/protocols/http/parse.py at pin 1841111 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1841111). Any discrepancy between this file and that pin is a
// bug in this file, not a deliberate deviation, unless called out in a
// comment.
//
// This file carries three related things, all sharing the same
// coordinate-addressed "XE" hidden-input cell grid:
//
//   - HTMLDialectXEFastpath (gsm7252ps) parsers -- source lines 841-1598:
//     _XE_CELL_RE/parse_xe_rows, port_status/stats/pvids/vlans/macs/poe/
//     lldp, and the "format (B)" plain label/value sysInfo.html readers
//     (labelled_values/mgmt_ip/sensors). Cells here carry NO trailing
//     field-name comment (contrast parse_m4300.go's Cheetah dialect) --
//     only a numeric COLUMN COORDINATE ("1_2_10"), scraped once per page
//     from that page's own visible header row and hardcoded as a constant.
//   - HTMLDialectS3300 (gsm7228ps) parsers for the three pages that diverge
//     from the gsm7252ps sibling (shifted MAC-table columns + escaped
//     "1/gN"/"1/xgN" ifNames, a sysInfo page carrying only the base MAC) --
//     source lines 1069-1296. Every OTHER S3300 read (ports/stats/pvids/
//     poe/lldp) reuses the XE_FASTPATH functions in this same file
//     UNCHANGED -- see parse_xe_port_status et al.'s doc comments.
//   - The FASTPATH "VLAN Membership" page parser, parse_fastpath_membership
//     (source lines 1719-2046) -- the single most intricate parser in the
//     reference, shared by ALL FOUR managed models (gsm7252ps, gsm7228ps,
//     m4300-24x, m4300-16x), plus the full generic XUI form-page helpers
//     (source lines 2048-2306): ParseXUIMgmtIP, and (added by Task 4, once
//     webui/types.go's XuiListPage/XuiFormPage existed for them to return)
//     ParseXUIListPage/ParseXUIFormPage -- the row-repeating/flat page
//     readers the eventual Writer's echo-back (forms.go's
//     XuiRowApplyForm/XuiFormApplyForm) depends on.

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// ---------------------------------------------------------------------------
// XE_FASTPATH cell grid (gsm7252ps; shared verbatim by most S3300 reads)
// ---------------------------------------------------------------------------

// xeCellRE mirrors Python parse._XE_CELL_RE.
var xeCellRE = regexp.MustCompile(`(?i)NAME=(\d+(?:\.\d+)+)\.v_(\d+_\d+_\d+) VALUE="([^"]*)"`)

// ParseXERows groups an XE page's cells into one map per row instance, in
// first-seen (page) order, keyed by the column COORDINATE ("1_2_10"). Cells
// with no instance prefix -- the blank "global"/template row and page-level
// scalars like "Total MAC Addresses" -- are deliberately not rows and are
// skipped. Mirrors Python parse.parse_xe_rows (source lines 871-884).
func ParseXERows(htmlStr string) []map[string]string {
	order := make([]string, 0)
	rows := make(map[string]map[string]string)
	for _, m := range xeCellRE.FindAllStringSubmatch(htmlStr, -1) {
		instance, coord, value := m[1], m[2], m[3]
		row, ok := rows[instance]
		if !ok {
			row = make(map[string]string)
			rows[instance] = row
			order = append(order, instance)
		}
		row[coord] = strings.TrimSpace(unescapeHTML(value))
	}
	out := make([]map[string]string, 0, len(order))
	for _, inst := range order {
		out = append(out, rows[inst])
	}
	return out
}

// xeSmartIfaceRE mirrors Python parse._XE_SMART_IFACE_RE: the S3300-52X
// Smart-firmware physical port name ("1/g7" ports 1-48, "1/xg49" uplinks
// 49-52) -- the trailing integer IS the port number, verified against SNMP.
var xeSmartIfaceRE = regexp.MustCompile(`1/x?g(\d+)`)

func xeSmartIfaceFullMatch(s string) []string {
	m := xeSmartIfaceRE.FindStringSubmatch(s)
	if m == nil || m[0] != s {
		return nil
	}
	return m
}

// xePortFromIface mirrors Python parse._xe_port_from_iface: "1/0/7"
// (M4300/GSM7252PS) -> 7, or "1/g7"/"1/xg49" (S3300-52X Smart firmware) ->
// 7/49. Only a full physical-port name yields a port; "lag 3"/"vlan 5" etc
// yield ok=false.
func xePortFromIface(text string) (int, bool) {
	t := strings.TrimSpace(text)
	if m := fastpathIfaceFullMatch(t); m != nil {
		port, err := strconv.Atoi(m[3])
		return port, err == nil
	}
	if m := xeSmartIfaceFullMatch(t); m != nil {
		port, err := strconv.Atoi(m[1])
		return port, err == nil
	}
	return 0, false
}

// portsConfiguration.html column map, from the capture's own header row.
const (
	xePortIface      = "1_2_1"
	xePortAdmin      = "1_2_6"
	xePortPhysStatus = "1_2_9"
	xePortLink       = "1_2_10"
	xePortIfindex    = "1_2_13"
)

// ParseXEPortStatus parses GSM7252PS (and, unchanged, S3300) portsConfiguration.html
// -> per-port status. Ifindex (column 13) is the port number, matching the
// SNMP backend's ifIndex keying. Speed comes from Physical Status (column 9,
// the NEGOTIATED result), NOT Physical Mode (column 8, the CONFIGURED mode,
// reads "Auto" on an auto-negotiating port). Mirrors Python
// parse.parse_xe_port_status (source lines 919-959). GROUNDED in
// gsm7252ps_portsConfiguration.html and gsm7228ps_portsConfiguration.html.
func ParseXEPortStatus(htmlStr string) ([]model.PortStatus, error) {
	var rows []map[string]string
	for _, r := range ParseXERows(htmlStr) {
		if _, ok := r[xePortLink]; ok {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return nil, errUnexpectedPage("portsConfiguration.html: no XE port rows (no v_%s link-status cells) found", xePortLink)
	}
	out := make([]model.PortStatus, 0, len(rows))
	for _, r := range rows {
		name := r[xePortIface]
		port, ok := 0, false
		if v, present := r[xePortIfindex]; present {
			port, ok = parseIntCell(v)
		}
		if !ok {
			port, ok = xePortFromIface(name)
		}
		if !ok {
			return nil, errUnexpectedPage("portsConfiguration.html: row without an identifiable port: %v", r)
		}
		linkUp := strings.Contains(strings.ToLower(r[xePortLink]), "up")
		var namePtr *string
		if name != "" {
			namePtr = model.Ptr(name)
		}
		var speed *int
		if linkUp {
			if v, ok := speedTextToMbps(r[xePortPhysStatus]); ok {
				speed = model.Ptr(v)
			}
		}
		out = append(out, model.PortStatus{
			Port:         port,
			Name:         namePtr,
			AdminEnabled: strings.ToLower(r[xePortAdmin]) == "enable",
			LinkUp:       linkUp,
			SpeedMbps:    speed,
		})
	}
	return out, nil
}

// portStatistics.html column map, from the capture's own header row.
const (
	xeStatsIface  = "1_1_103"
	xeStatsRxPkts = "1_1_2"
	xeStatsRxErrs = "1_1_3"
	xeStatsTxPkts = "1_1_5"
	xeStatsTxErrs = "1_1_6"
)

// ParseXEStats parses GSM7252PS/S3300 portStatistics.html -> per-port PACKET
// counters. This page carries no octet column, so RxBytes/TxBytes are
// honestly nil. The Interface column is required (not just used): the LLDP
// page reuses the same 1_1_* coordinate space, so requiring it keeps a
// wrong page from parsing into plausible garbage. Mirrors Python
// parse.parse_xe_stats (source lines 978-1020).
func ParseXEStats(htmlStr string) ([]model.PortStats, error) {
	var rows []map[string]string
	for _, r := range ParseXERows(htmlStr) {
		if _, ok := r[xeStatsIface]; !ok {
			continue
		}
		if _, ok := r[xeStatsRxPkts]; !ok {
			continue
		}
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return nil, errUnexpectedPage("portStatistics.html: no XE counter rows (no v_%s interface cells) found", xeStatsIface)
	}
	out := make([]model.PortStats, 0, len(rows))
	for _, r := range rows {
		port, ok := xePortFromIface(r[xeStatsIface])
		if !ok {
			continue // a non-physical interface (lag/vlan) has no port number
		}
		out = append(out, model.PortStats{
			Port:      port,
			RxPackets: uint64CellPtr(r[xeStatsRxPkts]),
			TxPackets: uint64CellPtr(r[xeStatsTxPkts]),
			RxErrors:  uint64CellPtr(r[xeStatsRxErrs]),
			TxErrors:  uint64CellPtr(r[xeStatsTxErrs]),
		})
	}
	if len(out) == 0 {
		return nil, errUnexpectedPage("portStatistics.html: no physical-port counter row could be parsed")
	}
	return out, nil
}

// portPvidConfiguration.html column map, from the capture's own header row.
const (
	xePvidIface      = "1_2_1"
	xePvidConfigured = "1_2_4"
)

// ParseXEPVIDs parses GSM7252PS/S3300 portPvidConfiguration.html -> (port,
// pvid) pairs. Uses the CONFIGURED PVID column (4), not Current (9): on the
// real capture the two disagree on trunk-member ports, and SNMP's
// dot1qPvid matches the CONFIGURED column. Mirrors Python
// parse.parse_xe_pvids (source lines 1031-1057).
func ParseXEPVIDs(htmlStr string) ([]model.Pvid, error) {
	out := make([]model.Pvid, 0)
	for _, r := range ParseXERows(htmlStr) {
		ifaceText, ok1 := r[xePvidIface]
		pvidText, ok2 := r[xePvidConfigured]
		if !ok1 || !ok2 {
			continue
		}
		port, portOK := xePortFromIface(ifaceText)
		pvid, pvidOK := parseIntCell(pvidText)
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

// vlanStatus.html column map, from the capture's own header row.
const (
	xeVlanID      = "1_1_1"
	xeVlanName    = "1_1_2"
	xeVlanType    = "1_1_3"
	xeVlanMembers = "1_1_4"
)

// expandS3300PortList mirrors Python parse._expand_s3300_port_list:
// S3300-52X egress-list syntax ("1/g1 - 1/g40, 1/xg49 - 1/xg52, lag 1 -
// lag 26"), where a range may even MIX the two physical prefixes
// ("1/g48 - 1/xg52") -> the set of PHYSICAL port numbers, sorted ascending.
// "lag N" is skipped exactly as expandPortList skips it. Mirrors source
// lines 1069-1091.
func expandS3300PortList(raw string) []int {
	ports := make(map[int]bool)
	for _, part := range strings.Split(raw, ",") {
		ends := xeSmartIfaceRE.FindAllStringSubmatch(part, -1)
		if len(ends) == 0 {
			continue
		}
		if strings.Contains(part, "-") && len(ends) == 2 {
			p1, err1 := strconv.Atoi(ends[0][1])
			p2, err2 := strconv.Atoi(ends[1][1])
			if err1 == nil && err2 == nil && p1 <= p2 {
				for p := p1; p <= p2; p++ {
					ports[p] = true
				}
				continue
			}
		}
		for _, e := range ends {
			if p, err := strconv.Atoi(e[1]); err == nil {
				ports[p] = true
			}
		}
	}
	return sortedPortSet(ports)
}

// xeVlanRows is the shared body of ParseXEVlans/ParseS3300Vlans, differing
// only in how the Member Ports cell is expanded. An empty member cell is
// real (a VLAN with no members), so an empty slice is reported rather than
// treated as a parse failure; neither page distinguishes tagged from
// untagged, so those stay empty. Mirrors Python parse._xe_vlan_rows (source
// lines 1094-1125).
func xeVlanRows(htmlStr string, expand func(string) []int) ([]model.VLANInfo, error) {
	out := make([]model.VLANInfo, 0)
	for _, r := range ParseXERows(htmlStr) {
		vidText, ok1 := r[xeVlanID]
		_, ok2 := r[xeVlanType]
		membersText, ok3 := r[xeVlanMembers]
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		vid, ok := parseIntCell(vidText)
		if !ok {
			continue
		}
		var name *string
		if v := r[xeVlanName]; v != "" {
			name = model.Ptr(v)
		}
		out = append(out, model.VLANInfo{
			VlanID:        vid,
			Name:          name,
			MemberPorts:   expand(membersText),
			TaggedPorts:   []int{},
			UntaggedPorts: []int{},
		})
	}
	if len(out) == 0 {
		return nil, errUnexpectedPage("vlanStatus.html: no XE VLAN row could be parsed")
	}
	return out, nil
}

// ParseXEVlans parses GSM7252PS vlanStatus.html -> VLANs with their egress
// member ports, using the FASTPATH "1/0/N" egress-list syntax
// (expandPortList). Mirrors Python parse.parse_xe_vlans (source lines
// 1128-1135).
func ParseXEVlans(htmlStr string) ([]model.VLANInfo, error) {
	return xeVlanRows(htmlStr, expandPortList)
}

// ParseS3300Vlans parses gsm7228ps vlanStatus.html -> VLANs with their
// egress member ports. The page shape is the sibling gsm7252ps XE page
// exactly, but the Member Ports cell uses the Smart firmware's
// "1/gN"/"1/xgN" ifNames (expandS3300PortList) instead of "1/0/N" --
// expandPortList would read them as empty. Mirrors Python
// parse.parse_s3300_vlans (source lines 1138-1148).
func ParseS3300Vlans(htmlStr string) ([]model.VLANInfo, error) {
	return xeVlanRows(htmlStr, expandS3300PortList)
}

// basicAddressTable.html column map (gsm7252ps), from the capture's own
// header row, plus the page-level scalar stating the true FDB size.
const (
	xeMacVlan = "1_2_1"
	xeMacAddr = "1_2_3"
	xeMacPort = "1_2_4"
)

var (
	xeMacTotalRE = regexp.MustCompile(`NAME=v_1_1_1 VALUE="(\d+)"`)
	macTextRE    = regexp.MustCompile(`(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}`)
)

func macTextFullMatch(s string) bool {
	m := macTextRE.FindString(s)
	return m != "" && m == s
}

// ParseXEMacs parses GSM7252PS basicAddressTable.html -> the MAC/FDB table.
// Physical ports on this firmware are ONLY <unit>/0/<port> (slot MUST be
// "0"); "lag N" and any other slot (a service/CPU interface -- e.g. the
// switch's own base MAC, learned on 0/5/1) are SKIPPED. Refuses a
// paginated (truncated) page the same way parse_m4300_macs does. Mirrors
// Python parse.parse_xe_macs (source lines 1163-1209). GROUNDED in
// gsm7252ps_basicAddressTable.html.
func ParseXEMacs(htmlStr string) ([]model.MacEntry, error) {
	var rows []map[string]string
	for _, r := range ParseXERows(htmlStr) {
		if _, ok := r[xeMacAddr]; !ok {
			continue
		}
		if _, ok := r[xeMacPort]; !ok {
			continue
		}
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return nil, errUnexpectedPage("basicAddressTable.html: no XE MAC rows (no v_%s address cells) found", xeMacAddr)
	}
	out := make([]model.MacEntry, 0, len(rows))
	for _, r := range rows {
		mac := strings.ToUpper(strings.TrimSpace(r[xeMacAddr]))
		if !macTextFullMatch(mac) {
			continue
		}
		iface := fastpathIfaceFullMatch(strings.TrimSpace(r[xeMacPort]))
		if iface == nil || iface[2] != "0" {
			continue // "lag N" or a service/CPU interface (e.g. 0/5/1)
		}
		port, err := strconv.Atoi(iface[3])
		if err != nil {
			continue
		}
		var vlanID *int
		if v, ok := parseIntCell(r[xeMacVlan]); ok {
			vlanID = model.Ptr(v)
		}
		out = append(out, model.MacEntry{Mac: mac, Port: port, VlanID: vlanID})
	}
	if err := checkMacPagination(htmlStr, len(rows)); err != nil {
		return nil, err
	}
	return out, nil
}

func checkMacPagination(htmlStr string, rendered int) error {
	m := xeMacTotalRE.FindStringSubmatch(htmlStr)
	if m == nil {
		return nil
	}
	total, err := strconv.Atoi(m[1])
	if err != nil || total <= rendered {
		return nil
	}
	return errUnexpectedPage(
		"basicAddressTable.html: the switch reports %d FDB entries but this page renders only %d -- "+
			"the web UI paginates the MAC table. Use the SNMP backend for the complete FDB rather than a silently truncated page.",
		total, rendered)
}

// S3300-52X basicAddressTable.html column map: the Smart-Managed-Pro
// firmware SHIFTS the columns relative to the gsm7252ps XE page (VLAN is
// v_1_2_2, not v_1_2_1) and HTML-entity-escapes the port ifName
// ("1&#x2F;xg51" -- ParseXERows already unescapes each cell).
const (
	s3300MacVlan = "1_2_2"
	s3300MacAddr = "1_2_3"
	s3300MacPort = "1_2_4"
)

// ParseS3300Macs parses gsm7228ps basicAddressTable.html -> the MAC/FDB
// table. Same XE grid as gsm7252ps but with the columns SHIFTED (see above)
// and port names in the Smart firmware's "1/gN"/"1/xgN" form. The switch's
// own base MAC is learned on the CPU interface (rendered "c1", status
// "Management"), which xePortFromIface does not resolve to a physical
// port -- skipped, the same base-MAC omission ParseXEMacs makes. Mirrors
// Python parse.parse_s3300_macs (source lines 1223-1268). GROUNDED in
// gsm7228ps_basicAddressTable.html.
func ParseS3300Macs(htmlStr string) ([]model.MacEntry, error) {
	var rows []map[string]string
	for _, r := range ParseXERows(htmlStr) {
		if _, ok := r[s3300MacAddr]; !ok {
			continue
		}
		if _, ok := r[s3300MacPort]; !ok {
			continue
		}
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return nil, errUnexpectedPage("basicAddressTable.html: no S3300 MAC rows (no v_%s address cells) found", s3300MacAddr)
	}
	out := make([]model.MacEntry, 0, len(rows))
	for _, r := range rows {
		mac := strings.ToUpper(strings.TrimSpace(r[s3300MacAddr]))
		if !macTextFullMatch(mac) {
			continue
		}
		port, ok := xePortFromIface(r[s3300MacPort])
		if !ok {
			continue // CPU/management interface ("c1"): not a physical port
		}
		var vlanID *int
		if v, ok := parseIntCell(r[s3300MacVlan]); ok {
			vlanID = model.Ptr(v)
		}
		out = append(out, model.MacEntry{Mac: mac, Port: port, VlanID: vlanID})
	}
	if err := checkMacPagination(htmlStr, len(rows)); err != nil {
		return nil, err
	}
	return out, nil
}

var s3300BaseMacRE = regexp.MustCompile(`Base MAC Address</td>\s*<td[^>]*>\s*([0-9A-Fa-f:]{17})`)

// ParseS3300Mgmt parses gsm7228ps sysInfo.html -> base MAC ONLY (no IPv4
// address). This page carries only the switch's "Base MAC Address"; the
// real IPv4 management address is on /ipConfiguration.html instead, read
// via the shared ParseXUIMgmtIP. Mirrors Python parse.parse_s3300_mgmt
// (source lines 1271-1295). GROUNDED in gsm7228ps_sysInfo.html.
func ParseS3300Mgmt(htmlStr string) (model.MgmtIPConfig, error) {
	m := s3300BaseMacRE.FindStringSubmatch(htmlStr)
	if m == nil {
		return model.MgmtIPConfig{}, errUnexpectedPage("sysInfo.html: no Base MAC Address cell found")
	}
	return model.MgmtIPConfig{
		Mode:    model.IPModeUnknown,
		BaseMac: model.Ptr(strings.ToUpper(m[1])),
	}, nil
}

// poeInterfaceConfiguration.html column map, from the capture's own header
// row. Shared unchanged by gsm7252ps, gsm7228ps AND both M4300 SKUs -- this
// particular page uses the same XE coordinate grid on all four managed
// models (dossier D-HTTP-P §2.6/§2.7).
const (
	xePoeIface  = "1_2_1"
	xePoeAdmin  = "1_2_2"
	xePoeOutput = "1_2_15" // "Output Power" cell; unit VARIES -- see poePowerToMw
	xePoeStatus = "1_2_17"
)

// poePowerToMw mirrors Python parse._poe_power_to_mw: FIRMWARE VARIANCE,
// both grounded in real captures -- gsm7252ps renders integer MILLIWATTS
// ("3500" == 3500 mW); the M4300-16X renders WATTS with two decimals
// ("4.60" == 4600 mW) despite a shared "(mW)" column header (a firmware
// label bug). The decimal point disambiguates. Empty/absent -> ok=false;
// "0"/"0.00" -> 0.
func poePowerToMw(text string) (int, bool) {
	m := poePowerRE.FindString(text)
	if m == "" {
		return 0, false
	}
	if strings.Contains(m, ".") {
		v, err := strconv.ParseFloat(m, 64)
		if err != nil {
			return 0, false
		}
		return int(math.Round(v * 1000)), true
	}
	v, err := strconv.Atoi(m)
	if err != nil {
		return 0, false
	}
	return v, true
}

var poePowerRE = regexp.MustCompile(`-?\d+(?:\.\d+)?`)

// ParseXEPoE parses poeInterfaceConfiguration.html -> per-port PoE status,
// shared unchanged by gsm7252ps, gsm7228ps and both M4300 SKUs. PowerMw is
// normalised to milliwatts by poePowerToMw so it matches the SNMP vendor mW
// OID; the Status column's text is matched against the shared detectText
// vocabulary ("Other Fault" -> Fault, where SNMP's own detect map has no
// code and honestly reports Unknown). Mirrors Python parse.parse_xe_poe
// (source lines 1313-1353).
func ParseXEPoE(htmlStr string) ([]model.PoEStatus, error) {
	var rows []map[string]string
	for _, r := range ParseXERows(htmlStr) {
		if _, ok := r[xePoeIface]; !ok {
			continue
		}
		if _, ok := r[xePoeStatus]; !ok {
			continue
		}
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return nil, errUnexpectedPage("poeInterfaceConfiguration.html: no XE PoE rows (no v_%s status cells) found", xePoeStatus)
	}
	out := make([]model.PoEStatus, 0, len(rows))
	for _, r := range rows {
		port, ok := xePortFromIface(r[xePoeIface])
		if !ok {
			continue
		}
		status := strings.ToLower(r[xePoeStatus])
		detect := model.PoEDetectUnknown
		for k, v := range detectText {
			if strings.Contains(status, k) {
				detect = v
				break
			}
		}
		var power *int
		if v, ok := poePowerToMw(r[xePoeOutput]); ok {
			power = model.Ptr(v)
		}
		out = append(out, model.PoEStatus{
			Port:         port,
			AdminEnabled: strings.ToLower(r[xePoeAdmin]) == "enable",
			Detect:       detect,
			PowerMw:      power,
		})
	}
	if len(out) == 0 {
		return nil, errUnexpectedPage("poeInterfaceConfiguration.html: no PoE port row could be parsed")
	}
	return out, nil
}

// lldpRemoteInventory.html column map, from the capture's own header row.
// Shared unchanged by gsm7252ps, gsm7228ps and both M4300 SKUs.
const (
	xeLLDPLocalIface = "1_1_1"
	xeLLDPChassis    = "1_1_7"
	xeLLDPSysName    = "1_1_8"
	xeLLDPPortID     = "1_1_9"
)

// ParseXELLDP parses lldpRemoteInventory.html -> LLDP neighbours.
// RemotePortDesc is honestly nil for every neighbour: this page has no such
// column (SNMP's lldpRemPortDesc is the source). An LLDP table with no rows
// is LEGITIMATELY empty, so this returns an empty (not nil) slice rather
// than erroring -- but a page that is not this page at all (no local-
// interface cells AND no "lldp" substring anywhere) still errors. Mirrors
// Python parse.parse_xe_lldp (source lines 1369-1402).
func ParseXELLDP(htmlStr string) ([]model.LLDPNeighbor, error) {
	rows := ParseXERows(htmlStr)
	var neighbours []map[string]string
	for _, r := range rows {
		if _, ok := r[xeLLDPLocalIface]; ok {
			neighbours = append(neighbours, r)
		}
	}
	if len(neighbours) == 0 && !strings.Contains(strings.ToLower(htmlStr), "lldp") {
		return nil, errUnexpectedPage("lldpRemoteInventory.html: no XE LLDP rows and no LLDP table found")
	}
	out := make([]model.LLDPNeighbor, 0, len(neighbours))
	for _, r := range neighbours {
		port, ok := xePortFromIface(r[xeLLDPLocalIface])
		if !ok {
			continue
		}
		var sysName, chassis, portID *string
		if v := r[xeLLDPSysName]; v != "" {
			sysName = model.Ptr(v)
		}
		if v := r[xeLLDPChassis]; v != "" {
			chassis = model.Ptr(strings.ToUpper(v))
		}
		if v := r[xeLLDPPortID]; v != "" {
			portID = model.Ptr(v)
		}
		out = append(out, model.LLDPNeighbor{
			LocalPort:       port,
			RemoteSysName:   sysName,
			RemotePortDesc:  nil, // no such column on this page
			RemoteChassisID: chassis,
			RemotePortID:    portID,
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// gsm7252ps/gsm7228ps sysInfo.html: format (B), plain label/value tables.
// Not XE-generated: this page carries no v_ cells at all -- its values are
// plain table cells (a bold LABEL cell followed by its value cell(s)).
// ---------------------------------------------------------------------------

var (
	xeLabelRowRE   = regexp.MustCompile(`(?is)<td[^>]*class="[^"]*font10Bold[^"]*"[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)(?:</td>|$)`)
	xeInputValueRE = regexp.MustCompile(`(?i)<INPUT[^>]*VALUE="([^"]*)"`)
	xeTrRE         = regexp.MustCompile(`(?is)<tr[^>]*>(.*?)</tr>`)
)

// xeText mirrors Python parse._xe_text: a sysInfo value cell's text is the
// <INPUT VALUE="..."> content if the cell is an editable field (System
// Name/Location/Contact), else its tag-stripped text.
func xeText(cellHTML string) string {
	if m := xeInputValueRE.FindStringSubmatch(cellHTML); m != nil {
		return strings.TrimSpace(unescapeHTML(m[1]))
	}
	return strings.TrimSpace(unescapeHTML(tagRE.ReplaceAllString(cellHTML, "")))
}

// ParseXELabelledValues parses sysInfo.html -> {label: first value cell} for
// every bold-labelled row (identity, mgmt IP, and the first UNIT column of
// the status tables). Returns an empty map for a page with none -- the
// caller decides whether that is fatal. Mirrors Python
// parse.parse_xe_labelled_values (source lines 1436-1450).
func ParseXELabelledValues(htmlStr string) map[string]string {
	out := make(map[string]string)
	for _, m := range xeLabelRowRE.FindAllStringSubmatch(htmlStr, -1) {
		label := strings.TrimSpace(unescapeHTML(tagRE.ReplaceAllString(m[1], "")))
		if label == "" {
			continue
		}
		out[label] = xeText(m[2])
	}
	return out
}

// xeSysinfoSection mirrors Python parse._xe_sysinfo_section: the slice of
// sysInfo.html belonging to one status table, from its own
// tbhdr('Title',...) script call to the next one (or EOF) -- keeps the
// three same-shaped tables (Temperature/FAN/Device Status) apart.
func xeSysinfoSection(htmlStr, title string) string {
	marker := "tbhdr('" + title + "'"
	start := strings.Index(htmlStr, marker)
	if start < 0 {
		return ""
	}
	rest := htmlStr[start+1:]
	if nxt := strings.Index(rest, "tbhdr('"); nxt >= 0 {
		return htmlStr[start : start+1+nxt]
	}
	return htmlStr[start:]
}

// xeStatusRow is one DATA row of a sysInfo.html status table: a label
// (column 0) and its per-unit values (columns 1..N).
type xeStatusRow struct {
	Label  string
	Values []string
}

// xeStatusRows mirrors Python parse._xe_status_rows: one (label, per-unit
// values) pair per DATA row of a status table section, dropping the header
// row (messageTableHeader cell class).
func xeStatusRows(section string) []xeStatusRow {
	var out []xeStatusRow
	for _, m := range xeTrRE.FindAllStringSubmatch(section, -1) {
		rowHTML := m[1]
		if strings.Contains(rowHTML, "messageTableHeader") {
			continue
		}
		c := cells(rowHTML)
		unescaped := make([]string, len(c))
		for i, v := range c {
			unescaped[i] = unescapeHTML(v)
		}
		if len(unescaped) < 2 || unescaped[0] == "" {
			continue
		}
		out = append(out, xeStatusRow{Label: unescaped[0], Values: unescaped[1:]})
	}
	return out
}

// xeSensorName mirrors Python parse._xe_sensor_name: the bare page label on
// unit 1, suffixed "unit N" on any other (a stacked switch).
func xeSensorName(label string, unit int) string {
	if unit == 1 {
		return label
	}
	return fmt.Sprintf("%s unit %d", label, unit)
}

var (
	xeHealthyText = map[string]bool{"ok": true, "operational": true}
	xeAbsentText  = map[string]bool{"": true, "na": true, "n/a": true, "not supported": true, "-": true}
	xePowerRows   = map[string]bool{"RPS": true, "Power Module": true}
)

// xeStateSensors mirrors Python parse._xe_state_sensors: FAN/Device-Status
// rows report health AS TEXT, never a number, so they are reported with
// unit="state" (1.0 healthy, 0.0 any other REPORTED state); a slot that
// reports nothing at all is SKIPPED, not reported as 0.0.
func xeStateSensors(section, kind string, only map[string]bool) []model.Sensor {
	out := make([]model.Sensor, 0)
	for _, row := range xeStatusRows(section) {
		label, values := row.Label, row.Values
		if only != nil && !only[label] {
			continue
		}
		for i, raw := range values {
			unit := i + 1
			text := strings.ToLower(strings.TrimSpace(raw))
			if xeAbsentText[text] {
				continue
			}
			v := 0.0
			if xeHealthyText[text] {
				v = 1.0
			}
			out = append(out, model.Sensor{
				Name:  xeSensorName(label, unit),
				Kind:  kind,
				Value: v,
				Unit:  "state",
			})
		}
	}
	return out
}

// ParseXESensors parses gsm7252ps sysInfo.html -> box sensors. Three
// blocks: Temperature Status (real numeric readings; "N/A" is absent, not
// zero, and skipped), FAN Status ("OK"/"NA" per fan, reported as
// unit="state" health flags, never RPM) and Device Status (only the RPS and
// Power Module rows, as kind="power" state flags -- the firmware/serial
// rows in that same table are identity, not sensors). Returns an empty
// slice for a page with none of those tables. Mirrors Python
// parse.parse_xe_sensors (source lines 1529-1565). GROUNDED in
// gsm7252ps_sysInfo.html.
func ParseXESensors(htmlStr string) []model.Sensor {
	out := make([]model.Sensor, 0)
	for _, row := range xeStatusRows(xeSysinfoSection(htmlStr, "Temperature Status")) {
		label, values := row.Label, row.Values
		for i, raw := range values {
			unit := i + 1
			celsius, ok := parseIntCell(raw)
			if !ok {
				continue // "N/A" -- absent, not zero
			}
			out = append(out, model.Sensor{
				Name:  xeSensorName(label, unit),
				Kind:  "temperature",
				Value: float64(celsius),
				Unit:  "C",
			})
		}
	}
	out = append(out, xeStateSensors(xeSysinfoSection(htmlStr, "FAN Status"), "fan", nil)...)
	out = append(out, xeStateSensors(xeSysinfoSection(htmlStr, "Device Status"), "power", xePowerRows)...)
	return out
}

var xeMgmtIfaceRE = regexp.MustCompile(`^\s*([0-9.]+)\s*/\s*([0-9.]+)`)

// ParseXEMgmtIP parses gsm7252ps sysInfo.html -> management IP + base MAC.
// "IPv4 Network Interface" renders as addr/netmask inside a link to
// ipConfiguration.html; "System MAC Address" is a plain labelled cell. The
// page reports neither a gateway nor a DHCP/static indicator, so those stay
// nil/Unknown rather than guessed. Mirrors Python parse.parse_xe_mgmt_ip
// (source lines 1568-1597). GROUNDED in gsm7252ps_sysInfo.html.
func ParseXEMgmtIP(htmlStr string) (model.MgmtIPConfig, error) {
	fields := ParseXELabelledValues(htmlStr)
	var addr, netmask *string
	if m := xeMgmtIfaceRE.FindStringSubmatch(fields["IPv4 Network Interface"]); m != nil {
		addr, netmask = model.Ptr(m[1]), model.Ptr(m[2])
	}
	mac := strings.ToUpper(strings.TrimSpace(fields["System MAC Address"]))
	if !macTextFullMatch(mac) {
		mac = ""
	}
	if addr == nil && mac == "" {
		return model.MgmtIPConfig{}, errUnexpectedPage(
			"sysInfo.html: neither IPv4 Network Interface nor System MAC Address found")
	}
	var baseMac *string
	if mac != "" {
		baseMac = model.Ptr(mac)
	}
	return model.MgmtIPConfig{
		Mode:    model.IPModeUnknown,
		Address: addr,
		Netmask: netmask,
		BaseMac: baseMac,
	}, nil
}

// ---------------------------------------------------------------------------
// FASTPATH "VLAN Membership" page -- parse_fastpath_membership (NEW at
// 1841111). The single most intricate parser in the reference; shared by
// ALL FOUR managed models (gsm7252ps, gsm7228ps, m4300-24x, m4300-16x).
// ---------------------------------------------------------------------------

// FastpathMembership is one VLAN's membership as read off
// switching/dot1q/vlan_port_cfg.html, mirroring Python types.
// FastpathMembership (dossier D-HTTP-P §5.3). TaggedPorts/UntaggedPorts are
// the CURRENT (operational) egress view (from hiddenTagged/hiddenUnTagged);
// Configured is the CONFIGURED participation the write form actually
// submits (from hiddenMem + the port grid). The two views can legitimately
// DISAGREE on real hardware (e.g. gsm7252ps VLAN 1 ports 50/51 are
// Current: Exclude / Configured: Include) -- reads report the current
// view, writes set+verify the configured view.
type FastpathMembership struct {
	VlanID        *int
	VlanIDs       []int
	Name          *string
	VlanType      *string
	TaggedPorts   []int
	UntaggedPorts []int
	// HiddenMem is the raw hiddenMem field verbatim (a comma-separated wire
	// code list, one entry per grid slot).
	HiddenMem string
	// PortSlots maps a physical port -> its 0-based slot in HiddenMem's
	// comma list, read off the page's own grid -- NEVER computed as
	// port-1: the grid interleaves LAG pseudo-interfaces and the two
	// firmware generations index differently.
	PortSlots map[int]int
	// Configured maps a physical port -> its CONFIGURED VlanMode (decoded
	// from HiddenMem at that port's slot, cross-checked against the grid's
	// own rendered state -- see ParseFastpathMembership).
	Configured map[int]model.VlanMode
	// Fields carries every rendered form field verbatim (including the
	// M4300-16X's per-page CSRFToken), for byte-faithful re-POSTing.
	Fields map[string]string
	// Action is the page's own vlan_port_cfg_rw.html POST target.
	Action string
}

// fastpathMemToMode mirrors Python parse._FASTPATH_MEM_TO_MODE: the
// hiddenMem wire code, 1=Tagged/2=Untagged/3=Excluded -- THE INVERSE of the
// Plus-class 8021qMembe.cgi map (wireToMode, parse_standard.go:
// 1=Untagged/2=Tagged/3=Excluded). NEVER share these two maps.
var fastpathMemToMode = map[string]model.VlanMode{
	"1": model.VlanTagged,
	"2": model.VlanUntagged,
	"3": model.VlanExcluded,
}

var modeToFastpathMem = map[model.VlanMode]string{
	model.VlanTagged:   "1",
	model.VlanUntagged: "2",
	model.VlanExcluded: "3",
}

var (
	fastpathMemActionRE = regexp.MustCompile(`(?i)<form\s+method="?post"?\s+ACTION="([^"]*vlan_port_cfg_rw\.html)"`)
	inputRE             = regexp.MustCompile(`(?i)<input\b([^>]*)>`)
	bareAttrRE          = regexp.MustCompile(`([\w.-]+)(\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?`)
	selectRE            = regexp.MustCompile(`(?is)<select\b([^>]*)>(.*?)</select>`)
	optionRE            = regexp.MustCompile(`(?i)<option\b([^>]*)>`)
	vlanIDSelectRE      = regexp.MustCompile(`(?is)<select[^>]*name="vlanId"[^>]*>(.*?)</select>`)
)

// Grid style A -- gsm7252ps (older XE firmware): a per-cell
// toggleImageFirst(this,<0-based slot>,0,'img_unit<N>',<interface number>)
// handler followed by the cell image whose *_[btu].gif suffix carries the
// state.
var (
	fastpathGridARE     = regexp.MustCompile(`(?s)toggleImageFirst\(this,(\d+),\d+,'img_unit\d+',(\d+)\).*?<img src="/base/images/(?:grey|blue)_([btu])\.gif" name="imx"`)
	fastpathGridTableRE = regexp.MustCompile(`(?is)<table[^>]*id="unit\d+tb"[^>]*>(.*?)</table>`)
	fastpathGridLabelRE = regexp.MustCompile(`<td[^>]*>\s*([A-Za-z]+)\s*</td>`)
)

// Grid style B -- gsm7228ps/S3300 + both M4300s (newer jQuery firmware):
// the cell carries the interface's ifName in aid and a
// togImg(this,<1-based slot>,0,"hiddenMem") handler; the state is in the
// image filename.
var fastpathGridBRE = regexp.MustCompile(`aid='port-([^']+)'[^>]*?src='[^']*/switch_([a-z]+?)(?:_bottom)?_[a-z]+\.png'[^>]*?name='imx'[^>]*?togImg\(this,(\d+),\d+,"hiddenMem"\)`)

var fastpathImgToMode = map[string]model.VlanMode{
	"t":        model.VlanTagged,
	"u":        model.VlanUntagged,
	"b":        model.VlanExcluded,
	"tagged":   model.VlanTagged,
	"untagged": model.VlanUntagged,
	"blank":    model.VlanExcluded,
}

// tagAttrs mirrors Python parse._tag_attrs: the attribute map of one tag's
// inner text, lower-cased keys. Valueless (boolean) attributes are recorded
// with an empty value -- real firmware writes
// <OPTION class="selectfield" value="4" SELECTED>, so a key=value-only
// scrape would read the page as having NO selected VLAN. First occurrence
// wins for a bare attribute; last occurrence wins for a valued one --
// exactly Python's setdefault-vs-assign asymmetry.
func tagAttrs(raw string) map[string]string {
	out := make(map[string]string)
	for _, m := range bareAttrRE.FindAllStringSubmatch(raw, -1) {
		key := strings.ToLower(m[1])
		if m[2] == "" {
			if _, exists := out[key]; !exists {
				out[key] = ""
			}
			continue
		}
		switch {
		case m[3] != "":
			out[key] = m[3]
		case m[4] != "":
			out[key] = m[4]
		case m[5] != "":
			out[key] = m[5]
		default:
			out[key] = ""
		}
	}
	return out
}

var (
	fastpathPhysicalUSPRE   = regexp.MustCompile(`^(\d+)/(\d+)/(\d+)$`)
	fastpathPhysicalSmartRE = regexp.MustCompile(`^(\d+)/x?g(\d+)$`)
)

// fastpathPhysicalPort mirrors Python parse._fastpath_physical_port: the
// physical port number in a FASTPATH ifName, or ok=false if it is not a
// physical port. Unit 0 marks a non-physical interface (LAGs render as
// "0/<slot>/<n>") -- a bare \d+/\d+/\d+ match would wrongly turn "0/3/64"
// into "port 64", the same class of bug _expand_port_list's lag-skip
// guards against.
func fastpathPhysicalPort(ifname string) (int, bool) {
	text := strings.TrimSpace(unescapeHTML(ifname))
	if m := fastpathPhysicalUSPRE.FindStringSubmatch(text); m != nil {
		unit, _ := strconv.Atoi(m[1])
		slot, _ := strconv.Atoi(m[2])
		port, err := strconv.Atoi(m[3])
		if err == nil && unit != 0 && slot == 0 {
			return port, true
		}
		return 0, false
	}
	if m := fastpathPhysicalSmartRE.FindStringSubmatch(text); m != nil {
		port, err := strconv.Atoi(m[2])
		return port, err == nil
	}
	return 0, false
}

// fastpathIfaceList mirrors Python parse._fastpath_iface_list: a
// hiddenTagged/hiddenUnTagged value (a comma-separated ifName list,
// HTML-entity-escaped and sometimes with a trailing comma) -> physical port
// numbers, sorted ascending. LAG entries are skipped.
func fastpathIfaceList(raw string) []int {
	ports := make(map[int]bool)
	for _, part := range strings.Split(unescapeHTML(raw), ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		if port, ok := fastpathPhysicalPort(part); ok {
			ports[port] = true
		}
	}
	return sortedPortSet(ports)
}

// selectedOption returns the tagAttrs of the <option> with a "selected"
// attribute in options, falling back to the first option -- what a browser
// submits when the firmware marks none selected. nil if options is empty.
func selectedOption(options []map[string]string) map[string]string {
	for _, o := range options {
		if _, ok := o["selected"]; ok {
			return o
		}
	}
	if len(options) > 0 {
		return options[0]
	}
	return nil
}

// fastpathFormFields mirrors Python parse._fastpath_form_fields: every
// named <input>/<select> in the membership form, verbatim -- unlike
// xuiInputs, nothing is filtered (this page must be byte-faithful on
// re-POST, including the M4300-16X's CSRFToken).
func fastpathFormFields(block string) map[string]string {
	fields := make(map[string]string)
	for _, m := range inputRE.FindAllStringSubmatch(block, -1) {
		attrs := tagAttrs(m[1])
		if name, ok := attrs["name"]; ok && name != "" {
			fields[name] = attrs["value"]
		}
	}
	for _, m := range selectRE.FindAllStringSubmatch(block, -1) {
		name := tagAttrs(m[1])["name"]
		if name == "" {
			continue
		}
		var options []map[string]string
		for _, o := range optionRE.FindAllStringSubmatch(m[2], -1) {
			options = append(options, tagAttrs(o[1]))
		}
		chosen := selectedOption(options)
		if chosen != nil {
			fields[name] = chosen["value"]
		} else {
			fields[name] = ""
		}
	}
	return fields
}

// fastpathGrid mirrors Python parse._fastpath_grid: the port grid ->
// {physical port: (0-based hiddenMem slot, rendered mode)}, handling both
// firmware generations. Errors if neither shape is present -- the page
// always renders a grid on real hardware.
func fastpathGrid(block string) (map[int]int, map[int]model.VlanMode, error) {
	slots := make(map[int]int) // physical port -> 0-based hiddenMem slot
	modes := make(map[int]model.VlanMode)
	for _, m := range fastpathGridBRE.FindAllStringSubmatch(block, -1) {
		name, state, slot1Text := m[1], m[2], m[3]
		port, ok := fastpathPhysicalPort(name)
		mode, known := fastpathImgToMode[state]
		if !ok || !known {
			continue
		}
		slot1, err := strconv.Atoi(slot1Text)
		if err != nil {
			continue
		}
		// 1-BASED on this firmware: rollover.js's togImg() computes
		// j = (index - 1) * 2 into the comma-separated hiddenMem string.
		slots[port] = slot1 - 1
		modes[port] = mode
	}
	if len(slots) > 0 {
		return slots, modes, nil
	}
	for _, tm := range fastpathGridTableRE.FindAllStringSubmatch(block, -1) {
		table := tm[1]
		label := fastpathGridLabelRE.FindStringSubmatch(table)
		if label == nil || !strings.EqualFold(label[1], "port") {
			continue // the LAG pseudo-unit table, or a table with no row label
		}
		for _, gm := range fastpathGridARE.FindAllStringSubmatch(table, -1) {
			slot0Text, intfText, state := gm[1], gm[2], gm[3]
			mode, known := fastpathImgToMode[state]
			if !known {
				continue
			}
			slot0, err1 := strconv.Atoi(slot0Text)
			intf, err2 := strconv.Atoi(intfText)
			if err1 != nil || err2 != nil {
				continue
			}
			// 0-BASED on this firmware: toggleImage() computes j = 2*index.
			slots[intf] = slot0
			modes[intf] = mode
		}
	}
	if len(slots) == 0 {
		return nil, nil, errUnexpectedPage(
			"vlan_port_cfg.html: no port-membership grid could be parsed (neither the toggleImageFirst/grey_*.gif nor the togImg/switch_*.png shape)")
	}
	return slots, modes, nil
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// fastpathVlanSelect mirrors Python parse._fastpath_vlan_select: the
// vlanId <select> -> (currently-shown VLAN, every VLAN offered). Scoped to
// that ONE select on purpose -- the page also carries an unrelated
// name="select" Group-Operation menu. Case-INSENSITIVE SELECTED match
// (real firmware writes the attribute bare and the tag uppercase).
func fastpathVlanSelect(block string) (*int, []int, error) {
	m := vlanIDSelectRE.FindStringSubmatch(block)
	if m == nil {
		return nil, nil, errUnexpectedPage(
			`vlan_port_cfg.html: no <select name="vlanId"> -- cannot tell which VLAN this page is showing`)
	}
	var selected *int
	ids := make(map[int]bool)
	for _, om := range optionRE.FindAllStringSubmatch(m[1], -1) {
		attrs := tagAttrs(om[1])
		value := attrs["value"]
		if !isASCIIDigits(value) {
			continue
		}
		v, _ := strconv.Atoi(value)
		ids[v] = true
		if _, ok := attrs["selected"]; ok {
			selected = model.Ptr(v)
		}
	}
	sorted := make([]int, 0, len(ids))
	for v := range ids {
		sorted = append(sorted, v)
	}
	sort.Ints(sorted)
	return selected, sorted, nil
}

var (
	fastpathErrFlagRE = regexp.MustCompile(`(?i)name="err_flag"[^>]*value="([^"]*)"`)
	fastpathErrMsgRE  = regexp.MustCompile(`(?i)name="err_msg"[^>]*value="([^"]*)"`)
)

// ParseFastpathErr scrapes every FASTPATH write-form page's own error
// banner: err_flag/err_msg hidden fields, checked by the page's own JS
// check_error(). The page still returns HTTP 200 on a refused write --
// this scrape is the ONLY signal. ok=false means the page reports success.
// Mirrors Python parse.parse_fastpath_err (source lines 1931-1946).
func ParseFastpathErr(htmlStr string) (string, bool) {
	flag := fastpathErrFlagRE.FindStringSubmatch(htmlStr)
	if flag == nil {
		return "", false
	}
	trimmed := strings.TrimSpace(flag[1])
	if trimmed == "" || trimmed == "0" {
		return "", false
	}
	msg := fastpathErrMsgRE.FindStringSubmatch(htmlStr)
	text := ""
	if msg != nil {
		text = strings.TrimSpace(unescapeHTML(msg[1]))
	}
	if text != "" {
		return text, true
	}
	return fmt.Sprintf("err_flag=%s with no err_msg", flag[1]), true
}

// ParseFastpathMembership parses FASTPATH
// switching/dot1q/vlan_port_cfg.html -> one VLAN's membership. Errors if
// the page is not this page (no _rw.html form, no hiddenMem, no port grid)
// or if it carries a wire code / grid state this parser does not know --
// never a silently partial result. Mirrors Python
// parse.parse_fastpath_membership (source lines 1949-2012). Shared by all
// four managed models.
func ParseFastpathMembership(htmlStr string) (FastpathMembership, error) {
	loc := fastpathMemActionRE.FindStringSubmatchIndex(htmlStr)
	if loc == nil {
		return FastpathMembership{}, errUnexpectedPage(
			"vlan_port_cfg.html: no <form ACTION=...vlan_port_cfg_rw.html> -- this is not the FASTPATH VLAN Membership page")
	}
	actionRaw := htmlStr[loc[2]:loc[3]]
	block := htmlStr[loc[1]:]
	fields := fastpathFormFields(block)
	hiddenMem, ok := fields["hiddenMem"]
	if !ok {
		return FastpathMembership{}, errUnexpectedPage("vlan_port_cfg.html: form carries no hiddenMem field")
	}
	codes := strings.Split(hiddenMem, ",")
	slots, rendered, err := fastpathGrid(block)
	if err != nil {
		return FastpathMembership{}, err
	}
	ports := make([]int, 0, len(slots))
	for p := range slots {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	portSlots := make(map[int]int, len(ports))
	configured := make(map[int]model.VlanMode, len(ports))
	for _, port := range ports {
		slot := slots[port]
		if slot >= len(codes) {
			return FastpathMembership{}, errUnexpectedPage(
				"vlan_port_cfg.html: port %d's grid slot %d is past the end of hiddenMem (%d codes)", port, slot, len(codes))
		}
		mode, known := fastpathMemToMode[codes[slot]]
		if !known {
			return FastpathMembership{}, errUnexpectedPage(
				"vlan_port_cfg.html: unknown hiddenMem code %q at slot %d (port %d)", codes[slot], slot, port)
		}
		if mode != rendered[port] {
			return FastpathMembership{}, errUnexpectedPage(
				"vlan_port_cfg.html: port %d renders as %s but hiddenMem slot %d says %s -- grid/hiddenMem mismatch, refusing to trust the slot mapping",
				port, rendered[port], slot, mode)
		}
		portSlots[port] = slot
		configured[port] = mode
	}
	selected, vlanIDs, err := fastpathVlanSelect(block)
	if err != nil {
		return FastpathMembership{}, err
	}
	var name, vlanType *string
	if v := unescapeHTML(fields["vlan_name"]); v != "" {
		name = model.Ptr(v)
	}
	if v := unescapeHTML(fields["vlan_type"]); v != "" {
		vlanType = model.Ptr(v)
	}
	return FastpathMembership{
		VlanID:        selected,
		VlanIDs:       vlanIDs,
		Name:          name,
		VlanType:      vlanType,
		TaggedPorts:   fastpathIfaceList(fields["hiddenTagged"]),
		UntaggedPorts: fastpathIfaceList(fields["hiddenUnTagged"]),
		HiddenMem:     hiddenMem,
		PortSlots:     portSlots,
		Configured:    configured,
		Fields:        fields,
		Action:        unescapeHTML(actionRaw),
	}, nil
}

// FastpathHiddenMemWith mirrors Python parse.fastpath_hidden_mem_with:
// page.HiddenMem with just port's code replaced by mode. Every other slot
// -- including LAG pseudo-interfaces the library does not model -- is
// preserved VERBATIM, so an apply cannot silently rewrite an interface the
// caller never mentioned. Errors if the page never rendered port.
func FastpathHiddenMemWith(page FastpathMembership, port int, mode model.VlanMode) (string, error) {
	slot, ok := page.PortSlots[port]
	if !ok {
		ports := make([]int, 0, len(page.PortSlots))
		for p := range page.PortSlots {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		return "", errUnexpectedPage(
			"vlan_port_cfg.html: port %d is not on this switch's membership grid (it renders ports %v)", port, ports)
	}
	codes := strings.Split(page.HiddenMem, ",")
	codes[slot] = modeToFastpathMem[mode]
	return strings.Join(codes, ","), nil
}

// ---------------------------------------------------------------------------
// FASTPATH "XE"/Cheetah XUI generic form pages (source lines 2048-2306).
// Every one of these pages carries TWO <FORM>s: the first (.../a0) is the
// applet/redirect form and holds no data; the SECOND (.../a1) is the
// read+write form everything here is scoped to. ParseXUIListPage/
// ParseXUIFormPage return the XuiListPage/XuiFormPage row-repeating/flat
// types (webui/types.go) the eventual Writer's echo-back (forms.go's
// XuiRowApplyForm/XuiFormApplyForm) consumes; ParseXUIMgmtIP needs only the
// flat field map, not either wrapper type.
// ---------------------------------------------------------------------------

var xuiFormRE = regexp.MustCompile(`(?i)<FORM\b[^>]*ACTION="([^"]*/a1)"`)

// xuiFormBlock mirrors Python parse._xui_form_block: (action, inner HTML) of
// the page's SECOND <FORM ACTION=".../a1">, or an error -- scoping to this
// form specifically matters because the first form (/a0) carries
// applet_port/applet_unit/dbgopt fields that must never leak into a read.
// action is the captured ACTION="..." target (unescaped, matching Python's
// unescape(m.group(1))) -- ParseXUIMgmtIP discards it (it has no use for the
// write-form target), but ParseXUIListPage/ParseXUIFormPage need it.
func xuiFormBlock(htmlStr, page string) (action, block string, err error) {
	loc := xuiFormRE.FindStringSubmatchIndex(htmlStr)
	if loc == nil {
		return "", "", errUnexpectedPage(
			`%s: no <FORM ACTION="...(/a1)"> -- this is not a FASTPATH XUI write page (wrong URL, or the session bounced to the login page)`, page)
	}
	return unescapeHTML(htmlStr[loc[2]:loc[3]]), htmlStr[loc[1]:], nil
}

// xuiInputsWithCheckboxes mirrors Python parse._xui_inputs: ({name: value},
// [checkbox names]) for one XUI form block, deliberately NOT unescaped (each
// caller unescapes only the fields it actually consumes) and deliberately
// NOT fastpathFormFields -- two kinds must be separated out or an echoed
// body would say something the browser never says:
//   - DISABLED inputs (every button) are dropped -- a browser never submits
//     them, the firmware enables the one clicked button itself.
//   - a checkbox carries no `value` attribute, so echoing it as "" would
//     silently SELECT that row; row selection is the one thing these pages
//     key their writes off, so it is returned separately.
func xuiInputsWithCheckboxes(block string) (fields map[string]string, checkboxes []string) {
	fields = make(map[string]string)
	for _, m := range inputRE.FindAllStringSubmatch(block, -1) {
		attrs := tagAttrs(m[1])
		name := attrs["name"]
		if name == "" {
			continue
		}
		if _, disabled := attrs["disabled"]; disabled {
			continue
		}
		if strings.EqualFold(attrs["type"], "checkbox") {
			checkboxes = append(checkboxes, name)
			continue
		}
		fields[name] = attrs["value"]
	}
	for _, m := range selectRE.FindAllStringSubmatch(block, -1) {
		attrs := tagAttrs(m[1])
		name := attrs["name"]
		if name == "" {
			continue
		}
		if _, disabled := attrs["disabled"]; disabled {
			continue
		}
		var options []map[string]string
		for _, o := range optionRE.FindAllStringSubmatch(m[2], -1) {
			options = append(options, tagAttrs(o[1]))
		}
		chosen := selectedOption(options)
		if chosen != nil {
			fields[name] = chosen["value"]
		} else {
			fields[name] = ""
		}
	}
	return fields, checkboxes
}

// xuiInputs is xuiInputsWithCheckboxes without the checkbox list, for
// callers (ParseXUIMgmtIP) that have no use for row selection.
func xuiInputs(block string) map[string]string {
	fields, _ := xuiInputsWithCheckboxes(block)
	return fields
}

// xuiRowRE mirrors Python parse._XUI_ROW_RE: the repeating rows of a list
// page. `p="1.35.520"` is the row's coordinate attribute; the field NAMES
// use the "1.35.52." prefix (same digits, no trailing column index), which
// is why the prefix is taken from a field name (xuiRowFieldRE) rather than
// from `p` itself.
var xuiRowRE = regexp.MustCompile(`(?is)<TR\s+p="[\d.]+"[^>]*>(.*?)</TR>`)

// xuiRowFieldRE mirrors Python parse._XUI_ROW_FIELD_RE: a row-instance data
// field name, capturing the "<unit>.<row0>.<count>." prefix separately from
// the bare "v_<a>_<b>_<c>" column.
var xuiRowFieldRE = regexp.MustCompile(`^((?:\d+\.)+)(v_\d+_\d+_\d+)$`)

// xuiHiddenNames mirrors Python parse._XUI_HIDDEN_NAMES: the trailing
// "redirection elements" block every XUI form ends with.
var xuiHiddenNames = [...]string{"submit_flag", "submit_target", "err_flag", "err_msg", "clazz_information"}

// xuiButtonsDivRE mirrors Python parse._XUI_BUTTONS_DIV_RE: the page's
// buttons live in their own trailing <div id="xuiButtonsDiv">. Scoped to
// that div ON PURPOSE rather than matched by name shape: the button fields
// are named v_2_1_N/v_3_1_N depending on the page, and on gsm7228ps's
// ipConfiguration.html v_2_1_1 is NOT a button at all -- it is the
// Management VLAN ID data field. A name-shaped guess would have classified
// a real setting as a button and dropped it from every echoed body.
var xuiButtonsDivRE = regexp.MustCompile(`(?is)<div id="xuiButtonsDiv"[^>]*>(.*?)</div>`)

// xuiTokenRE mirrors Python parse._XUI_TOKEN_RE: page-level fields that are
// NOT data cells and must ride along on every apply. Today that is exactly
// the per-page CSRFToken the AV-era M4300-16X issues and whose absence it
// answers with 403; matched by name rather than by "not a v_* field" so a
// future data field cannot be swept in by accident.
var xuiTokenRE = regexp.MustCompile(`(?i)^CSRFToken$`)

// xuiNavRowRE mirrors Python parse._XUI_NAV_ROW_RE: the page's
// list-NAVIGATION rows -- the "Go To Port" bars the firmware emits above and
// below the table, marked class=deftestme.
var xuiNavRowRE = regexp.MustCompile(`(?is)<TR\b[^>]*\bclass=["']?deftestme["']?[^>]*>(.*?)</TR>`)

// xuiPageFieldRE mirrors Python parse._XUI_PAGE_FIELD_RE: a page-level
// (unprefixed) data field name, e.g. "v_1_1_1". Deliberately excludes the
// global "apply to all rows" row's "v_g_1_2_*" twins -- echoing those back
// is itself refused (live 2026-07-30 on gsm7252ps 10.1.5.22: a PoE apply
// that carried them answered err_flag=1, because the global row's cells
// render EMPTY and the firmware tries to apply them to every port).
var xuiPageFieldRE = regexp.MustCompile(`^v_\d+_\d+_\d+$`)

// xuiButtons mirrors Python parse._xui_buttons: the page's button fields ->
// their labels ("v_2_1_2" -> "APPLY"). Kept even though the inputs are
// rendered DISABLED (so a browser would not submit them), because the
// firmware's own xuiProcessButtonActions calls xuiShed(3, ...) to ENABLE the
// clicked button before form.submit() -- so the real POST does carry
// exactly one of these, with the label as its value. The labels are NOT
// interchangeable between models: the same v_2_1_3 reads "RESET" on
// gsm7252ps/gsm7228ps and "Power Cycle Port(s)" on both M4300s (live
// 2026-07-30), which is why the value is echoed from the page instead of
// being a constant.
func xuiButtons(htmlStr string) map[string]string {
	div := xuiButtonsDivRE.FindStringSubmatch(htmlStr)
	if div == nil {
		return map[string]string{}
	}
	out := make(map[string]string)
	for _, m := range inputRE.FindAllStringSubmatch(div[1], -1) {
		attrs := tagAttrs(m[1])
		if name := attrs["name"]; name != "" {
			out[name] = unescapeHTML(attrs["value"])
		}
	}
	return out
}

// ParseXUIListPage parses a FASTPATH XUI table page -> its write form + one
// XuiRow per row, mirroring Python parse.parse_xui_list_page (source lines
// 2178-2233, dossier §2.8). page names the page in any returned error
// ("" defaults to "XUI list page").
//
// Raises (returns an error wrapping model.ErrHTTPUnexpectedPage) only when
// the write form is missing. An EMPTY row slice is NOT an error and is not
// swallowed either -- it is a real, meaningful answer the caller
// interprets: the M4300-24X genuinely has no PoE, and its
// /v1/poeInterfaceConfiguration.html proves it with an HTTP 200 of 28152
// bytes carrying the correct <TITLE>NETGEAR -  PoE Port Configuration</TITLE>,
// the full button set and ZERO <TR p="..."> rows (live 2026-07-30 on
// 10.1.5.13). A 404 would have been a missing page; this is a present page
// with no PSE ports.
func ParseXUIListPage(htmlStr, page string) (XuiListPage, error) {
	if page == "" {
		page = "XUI list page"
	}
	action, block, err := xuiFormBlock(htmlStr, page)
	if err != nil {
		return XuiListPage{}, err
	}
	rows := make([]XuiRow, 0)
	for _, m := range xuiRowRE.FindAllStringSubmatch(block, -1) {
		rowFields, checkboxes := xuiInputsWithCheckboxes(m[1])
		prefix := ""
		for name := range rowFields {
			if pm := xuiRowFieldRE.FindStringSubmatch(name); pm != nil {
				prefix = pm[1]
				break
			}
		}
		if prefix == "" {
			continue // a spacer/label row, not a data row
		}
		var checkbox *string
		for _, cb := range checkboxes {
			if strings.HasPrefix(cb, prefix) {
				c := cb
				checkbox = &c
				break
			}
		}
		fields := make(map[string]string, len(rowFields))
		for k, v := range rowFields {
			fields[k] = unescapeHTML(v)
		}
		rows = append(rows, XuiRow{Prefix: prefix, Checkbox: checkbox, Fields: fields})
	}
	formFields, _ := xuiInputsWithCheckboxes(xuiRowRE.ReplaceAllString(block, ""))
	nav := make(map[string]string)
	for _, m := range xuiNavRowRE.FindAllStringSubmatch(block, -1) {
		rowFields, _ := xuiInputsWithCheckboxes(m[1])
		for n, v := range rowFields {
			if xuiPageFieldRE.MatchString(n) {
				nav[n] = unescapeHTML(v)
			}
		}
	}
	hidden := make(map[string]string)
	for _, n := range xuiHiddenNames {
		if v, ok := formFields[n]; ok {
			hidden[n] = v // NOT unescaped -- matches Python's dict comprehension here (unlike tokens/row fields/nav)
		}
	}
	tokens := make(map[string]string)
	for n, v := range formFields {
		if xuiTokenRE.MatchString(n) {
			tokens[n] = unescapeHTML(v)
		}
	}
	return XuiListPage{
		Action:  action,
		Hidden:  hidden,
		Buttons: xuiButtons(block),
		Rows:    rows,
		Tokens:  tokens,
		Nav:     nav,
	}, nil
}

// ParseXUIFormPage parses a FASTPATH XUI detail page -> its write form's
// flat field map, mirroring Python parse.parse_xui_form_page (source lines
// 2236-2246, dossier §2.8). page names the page in any returned error ("" =
// "XUI page").
func ParseXUIFormPage(htmlStr, page string) (XuiFormPage, error) {
	if page == "" {
		page = "XUI page"
	}
	action, block, err := xuiFormBlock(htmlStr, page)
	if err != nil {
		return XuiFormPage{}, err
	}
	fields, _ := xuiInputsWithCheckboxes(block)
	hidden := make(map[string]string, len(xuiHiddenNames))
	for _, n := range xuiHiddenNames {
		if v, ok := fields[n]; ok {
			hidden[n] = v // NOT unescaped, popped straight from fields -- see ParseXUIListPage
			delete(fields, n)
		}
	}
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		out[k] = unescapeHTML(v)
	}
	return XuiFormPage{
		Action:  action,
		Hidden:  hidden,
		Buttons: xuiButtons(block),
		Fields:  out,
	}, nil
}

var xuiIPMode = map[string]model.IPMode{
	"none":    model.IPModeStatic,
	"manual":  model.IPModeStatic,
	"disable": model.IPModeStatic,
	"dhcp":    model.IPModeDHCP,
	"enable":  model.IPModeDHCP,
	"bootp":   model.IPModeDHCP,
}

// ParseXUIMgmtIP parses a FASTPATH XUI management-IP page (gsm7228ps/
// gsm7252ps's ipConfiguration.html, both M4300 SKUs'
// mgmtVlanIpv4Configuration.html) -> model.MgmtIPConfig (without base MAC).
// Field names are passed in rather than assumed: the two Cheetah families
// put the same four values under different names, and one of those names
// means different things on two switches of the SAME family (see
// endpoints.go's XuiMgmtIPFields). BaseMac is always nil here -- neither
// family's mgmt page carries the switch's base MAC; the caller (Task 6's
// Reader) merges it in from the sysinfo page separately. Mirrors Python
// parse.parse_xui_mgmt_ip (source lines 2266-2305).
func ParseXUIMgmtIP(htmlStr string, addressField, netmaskField, gatewayField, modeField, page string) (model.MgmtIPConfig, error) {
	if page == "" {
		page = "XUI management-IP page"
	}
	_, block, err := xuiFormBlock(htmlStr, page)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	fields := xuiInputs(block)
	var missing []string
	for _, f := range []string{addressField, netmaskField, gatewayField} {
		if _, ok := fields[f]; !ok {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return model.MgmtIPConfig{}, errUnexpectedPage(
			"%s: no %v field(s) -- wrong management-IP page for this model?", page, missing)
	}
	mode, known := xuiIPMode[strings.ToLower(strings.TrimSpace(unescapeHTML(fields[modeField])))]
	if !known {
		mode = model.IPModeUnknown
	}
	addr := strings.TrimSpace(unescapeHTML(fields[addressField]))
	netmask := strings.TrimSpace(unescapeHTML(fields[netmaskField]))
	gateway := strings.TrimSpace(unescapeHTML(fields[gatewayField]))
	out := model.MgmtIPConfig{Mode: mode}
	if addr != "" {
		out.Address = model.Ptr(addr)
	}
	if netmask != "" {
		out.Netmask = model.Ptr(netmask)
	}
	if gateway != "" {
		out.Gateway = model.Ptr(gateway)
	}
	return out, nil
}
