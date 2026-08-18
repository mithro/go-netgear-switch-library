package webui

// Ported field-for-field from
// src/netgear_switch/protocols/http/parse.py at pin b26eb1f in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-b26eb1f). Any discrepancy between this file and that pin is a
// bug in this file, not a deliberate deviation, unless called out in a
// comment.
//
// This file carries the HTMLDialectGoAheadXML dialect's parsers -- source
// lines 2420-2771 -- the ONLY dialect that is real XML parsing rather than
// regex scraping. GS728TPP's "wcd" response is a template of BIND=
// placeholders (NOT well-formed XML -- unclosed <script>/<link>, a literal
// class=xui" typo in the captured markup) followed by a clean
// <DeviceConfiguration> data block; only that trailing block is parsed.
// GROUNDED in real gs728tpp captures (webui/testdata/http/gs728tpp_*.xml).
//
// # XXE/entity-expansion hardening
//
// goaheadDataBlock rejects the sliced block outright if it contains
// "<!DOCTYPE" or "<!ENTITY" BEFORE calling encoding/xml.Unmarshal -- slicing
// to <DeviceConfiguration> already excludes the XML prolog where a DTD
// would normally live, so this catches one embedded INSIDE the data block.
// Go's encoding/xml, like Python's stdlib ElementTree/expat, does not
// resolve external entities, so this is belt-and-braces rather than the
// only defence -- but it is kept explicit to mirror the source 1:1.
//
// # Generic element tree
//
// Go's encoding/xml is normally driven by a fixed set of struct tags, but
// these parsers need Python ElementTree's dynamic find(tag)/findall(tag)/
// .text shape (section names and child tags are runtime strings, not
// compile-time struct fields). xmlNode (below) is a small generic recursive
// element -- its Nodes field (tag `xml:",any"`) captures every direct child
// element regardless of name, and its Content field (tag `xml:",chardata"`)
// captures exactly the element's own direct text, never text belonging to a
// nested child -- reproducing ElementTree.find/.text precisely.

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// xmlNode is a generic recursive XML element, standing in for Python
// ElementTree.Element: Nodes holds every direct child element (in document
// order), Content holds the element's own direct character data.
type xmlNode struct {
	XMLName xml.Name
	Content string    `xml:",chardata"`
	Nodes   []xmlNode `xml:",any"`
}

// find mirrors ElementTree.Element.find(tag): the first direct child whose
// local name is tag, or nil.
func (n *xmlNode) find(tag string) *xmlNode {
	for i := range n.Nodes {
		if n.Nodes[i].XMLName.Local == tag {
			return &n.Nodes[i]
		}
	}
	return nil
}

// findAll mirrors ElementTree.Element.findall(tag): every direct child
// whose local name is tag, in document order.
func (n *xmlNode) findAll(tag string) []*xmlNode {
	var out []*xmlNode
	for i := range n.Nodes {
		if n.Nodes[i].XMLName.Local == tag {
			out = append(out, &n.Nodes[i])
		}
	}
	return out
}

// gtext mirrors Python parse._gtext: (el.find(tag).text or "").strip(), or
// "" if the child is absent.
func gtext(n *xmlNode, tag string) string {
	c := n.find(tag)
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.Content)
}

// goaheadDataBlock mirrors Python parse._goahead_data_block: slices out and
// parses just the <DeviceConfiguration>...</DeviceConfiguration> block (the
// surrounding wcd template is NOT well-formed XML and is never parsed).
func goaheadDataBlock(body string) (*xmlNode, error) {
	start := strings.Index(body, "<DeviceConfiguration>")
	end := strings.Index(body, "</DeviceConfiguration>")
	if start < 0 || end < 0 {
		return nil, errUnexpectedPage("wcd response: no <DeviceConfiguration> data block found")
	}
	block := body[start : end+len("</DeviceConfiguration>")]
	if strings.Contains(block, "<!DOCTYPE") || strings.Contains(block, "<!ENTITY") {
		return nil, errUnexpectedPage("wcd response: DTD/entity declaration in data block rejected")
	}
	var root xmlNode
	if err := xml.Unmarshal([]byte(block), &root); err != nil {
		return nil, errUnexpectedPage("wcd response: <DeviceConfiguration> is not valid XML: %v", err)
	}
	return &root, nil
}

// goaheadSection mirrors Python parse._goahead_section: the <name
// type="section"> element of a wcd data block, or an error.
func goaheadSection(body, name string) (*xmlNode, error) {
	root, err := goaheadDataBlock(body)
	if err != nil {
		return nil, err
	}
	sec := root.find(name)
	if sec == nil {
		return nil, errUnexpectedPage("wcd response: no <%s> section (wrong page?)", name)
	}
	return sec, nil
}

var goaheadPortRE = regexp.MustCompile(`^g(\d+)$`)

// goaheadPortNum mirrors Python parse._goahead_port_num: "g24" -> 24. A LAG
// ("LAG3") or any non-physical interface name yields ok=false so callers
// skip it rather than mis-attributing it.
func goaheadPortNum(name string) (int, bool) {
	m := goaheadPortRE.FindStringSubmatch(strings.TrimSpace(name))
	if m == nil {
		return 0, false
	}
	return parseIntCell(m[1])
}

// goaheadDuplexOper mirrors Python parse._GOAHEAD_DUPLEX_OPER: duplexOperMode
// -> FullDuplex, DECODED AGAINST SNMP rather than guessed. Measured on the
// live GS728TPP (10.2.5.10, firmware 6.0.1.30, 2026-08-03) by reading this
// page and dot3StatsDuplexStatus for all 28 ports at once: every link-UP
// port reads 2 here and 3 (fullDuplex) there, every link-DOWN port reads 4
// here and 1 (unknown) there. 4 therefore maps to nothing (not false):
// nothing is claimed about codes 1 and 3 either -- that fleet had no
// half-duplex link to observe, and inventing the rest of an enum from one
// observation is how a plausible-but-wrong mapping gets in. An unmapped
// code (comma-ok false) yields nil, the honest answer for "not known". NOT
// the same enum as duplexAdminMode, where the page's own JS uses 2=half/
// 3=full (see goaheadSpeedConfig below, which decodes that field instead).
var goaheadDuplexOper = map[string]bool{"2": true}

// goaheadFlowControl mirrors Python parse._GOAHEAD_FLOW_CONTROL:
// flowControlOperType -> FlowControl. Measured in the same read: every port
// reads 2 here while dot3PauseOperMode reads 1 (disabled), so 2 is disabled
// -- consistent with this UI's usual 1=enabled/2=disabled pairing
// (adminState, linkState). Every port on that switch had flow control off,
// so "1 means enabled" is inference from the UI's convention rather than
// observation, and any other code stays nil (comma-ok false).
var goaheadFlowControl = map[string]bool{"1": true, "2": false}

// goaheadSpeedConfig decodes the CONFIGURED speed of one Standard802_3List
// Entry, mirroring Python _goahead_speed_config (parse.py:2820-2844)
// EXACTLY -- decoded exactly as the page's own JS decodes it for display:
//
//	if (field.autoNegotiationAdminEnabled == "1") str = "Auto";
//	else str = field.speedAdmin + "M" + (duplexAdminMode=="3" ? " Full" : " Half");
//
// autoNegotiationAdminEnabled is authoritative and speedAdmin is IGNORED
// while it is "1" -- not a detail one could skip: in the live capture every
// auto-negotiating port carries speedAdmin 1000 alongside
// autoNegotiationAdminEnabled 1, so decoding on the rate alone would report
// the whole switch as forced to 1000.
func goaheadSpeedConfig(e *xmlNode) *model.PortSpeed {
	autoneg := gtext(e, "autoNegotiationAdminEnabled")
	if autoneg == "1" {
		v := model.AutoPortSpeed()
		return &v
	}
	if autoneg != "2" {
		return nil // neither code the page knows: honestly unknown
	}
	rate, rateOK := parseIntCell(gtext(e, "speedAdmin"))
	duplexCode := gtext(e, "duplexAdminMode")
	if !rateOK || (duplexCode != "2" && duplexCode != "3") {
		return nil
	}
	v := model.ForcedPortSpeed(rate, duplexCode == "3")
	return &v
}

// ParseGoAheadPorts parses GS728TPP's Standard802_3List section -> per-port
// status. Only physical g<n> ports are returned; LAG aggregation rows are
// skipped. SpeedMbps is the negotiated speedOper while the link is up, and
// honestly nil on a down port. This is the ONE dialect whose PortStatus
// populates Description (interfaceDescription). duplexOperMode and
// flowControlOperType are decoded against SNMP rather than against a guess
// -- see goaheadDuplexOper/goaheadFlowControl. Mirrors Python
// parse.parse_goahead_ports (source lines 2847-2884). GROUNDED in
// gs728tpp_ports.xml.
func ParseGoAheadPorts(body string) ([]model.PortStatus, error) {
	sec, err := goaheadSection(body, "Standard802_3List")
	if err != nil {
		return nil, err
	}
	out := make([]model.PortStatus, 0)
	for _, e := range sec.findAll("Entry") {
		port, ok := goaheadPortNum(gtext(e, "interfaceName"))
		if !ok {
			continue // a LAG/aggregation row, not a physical port
		}
		linkUp := gtext(e, "linkState") == "1"
		var speed *int
		if linkUp {
			if v, ok := parseIntCell(gtext(e, "speedOper")); ok {
				speed = model.Ptr(v)
			}
		}
		var name, desc *string
		if v := gtext(e, "interfaceName"); v != "" {
			name = model.Ptr(v)
		}
		if v := gtext(e, "interfaceDescription"); v != "" {
			desc = model.Ptr(v)
		}
		var fullDuplex *bool
		if v, ok := goaheadDuplexOper[gtext(e, "duplexOperMode")]; ok {
			fullDuplex = model.Ptr(v)
		}
		var flowControl *bool
		if v, ok := goaheadFlowControl[gtext(e, "flowControlOperType")]; ok {
			flowControl = model.Ptr(v)
		}
		out = append(out, model.PortStatus{
			Port:         port,
			Name:         name,
			AdminEnabled: gtext(e, "adminState") == "1",
			LinkUp:       linkUp,
			SpeedMbps:    speed,
			Description:  desc,
			FullDuplex:   fullDuplex,
			FlowControl:  flowControl,
			SpeedConfig:  goaheadSpeedConfig(e),
		})
	}
	if len(out) == 0 {
		return nil, errUnexpectedPage("Standard802_3List: no physical-port Entry rows found")
	}
	return out, nil
}

// ParseGoAheadPVIDs parses GS728TPP's VLANInterfaceList section -> (port,
// pvid) pairs, physical ports only. Mirrors Python parse.parse_goahead_pvids
// (source lines 2520-2534). GROUNDED in gs728tpp_pvids_membership.xml.
func ParseGoAheadPVIDs(body string) ([]model.Pvid, error) {
	sec, err := goaheadSection(body, "VLANInterfaceList")
	if err != nil {
		return nil, err
	}
	out := make([]model.Pvid, 0)
	for _, iface := range sec.findAll("Interface") {
		port, portOK := goaheadPortNum(gtext(iface, "interfaceName"))
		pvid, pvidOK := parseIntCell(gtext(iface, "PVID"))
		if !portOK || !pvidOK {
			continue
		}
		out = append(out, model.Pvid{Port: port, Vlan: pvid})
	}
	if len(out) == 0 {
		return nil, errUnexpectedPage("VLANInterfaceList: no (port, pvid) pair could be parsed")
	}
	return out, nil
}

// ParseGoAheadVlanNames parses GS728TPP's VLANList section ->
// {vlan_id: name-or-nil}. Mirrors Python parse.parse_goahead_vlan_names
// (source lines 2537-2548). GROUNDED in gs728tpp_vlans.xml.
func ParseGoAheadVlanNames(body string) (map[int]*string, error) {
	sec, err := goaheadSection(body, "VLANList")
	if err != nil {
		return nil, err
	}
	names := make(map[int]*string)
	for _, v := range sec.findAll("VLAN") {
		vid, ok := parseIntCell(gtext(v, "VLANID"))
		if !ok {
			continue
		}
		if n := gtext(v, "VLANName"); n != "" {
			names[vid] = model.Ptr(n)
		} else {
			names[vid] = nil
		}
	}
	if len(names) == 0 {
		return nil, errUnexpectedPage("VLANList: no VLAN row could be parsed")
	}
	return names, nil
}

// GoAheadMembership is one VLAN's tagged/untagged physical-port sets, built
// from GS728TPP's per-port inline JoinVLANList -- see
// ParseGoAheadPortVlanMembership.
type GoAheadMembership struct {
	Tagged   []int
	Untagged []int
}

// ParseGoAheadPortVlanMembership parses GS728TPP's VLANInterfaceList
// section -> {vlan_id: {tagged, untagged}}, built from each physical port's
// inline JoinVLANList (taggingMode 1=untagged, 2=tagged), which carries the
// complete per-port membership -- so no separate per-VLAN membership
// request is needed on this model. Mirrors Python
// parse.parse_goahead_port_vlan_membership (source lines 2551-2576).
// GROUNDED in gs728tpp_pvids_membership.xml.
func ParseGoAheadPortVlanMembership(body string) (map[int]GoAheadMembership, error) {
	sec, err := goaheadSection(body, "VLANInterfaceList")
	if err != nil {
		return nil, err
	}
	tagged := make(map[int]map[int]bool)
	untagged := make(map[int]map[int]bool)
	for _, iface := range sec.findAll("Interface") {
		port, ok := goaheadPortNum(gtext(iface, "interfaceName"))
		jvl := iface.find("JoinVLANList")
		if !ok || jvl == nil {
			continue
		}
		for _, ve := range jvl.findAll("VLANEntry") {
			vid, ok := parseIntCell(gtext(ve, "VLANID"))
			if !ok {
				continue
			}
			bucket := tagged
			if gtext(ve, "taggingMode") == "1" {
				bucket = untagged
			}
			if bucket[vid] == nil {
				bucket[vid] = make(map[int]bool)
			}
			bucket[vid][port] = true
		}
	}
	vids := make(map[int]bool)
	for v := range tagged {
		vids[v] = true
	}
	for v := range untagged {
		vids[v] = true
	}
	out := make(map[int]GoAheadMembership, len(vids))
	for vid := range vids {
		out[vid] = GoAheadMembership{
			Tagged:   sortedPortSet(tagged[vid]),
			Untagged: sortedPortSet(untagged[vid]),
		}
	}
	return out, nil
}

// ParseGoAheadVlans combines ParseGoAheadVlanNames + names, giving the full
// VLANInfo list (MemberPorts = tagged | untagged). Mirrors Python
// parse.parse_goahead_vlans (source lines 2579-2596). GROUNDED in
// gs728tpp_vlans.xml + gs728tpp_pvids_membership.xml.
func ParseGoAheadVlans(vlansBody, membershipBody string) ([]model.VLANInfo, error) {
	names, err := ParseGoAheadVlanNames(vlansBody)
	if err != nil {
		return nil, err
	}
	membership, err := ParseGoAheadPortVlanMembership(membershipBody)
	if err != nil {
		return nil, err
	}
	vids := make(map[int]bool, len(names))
	for v := range names {
		vids[v] = true
	}
	for v := range membership {
		vids[v] = true
	}
	sortedVIDs := sortedPortSet(vids)
	out := make([]model.VLANInfo, 0, len(sortedVIDs))
	for _, vid := range sortedVIDs {
		m := membership[vid]
		tagged := m.Tagged
		if tagged == nil {
			tagged = []int{}
		}
		untagged := m.Untagged
		if untagged == nil {
			untagged = []int{}
		}
		memberSet := make(map[int]bool, len(tagged)+len(untagged))
		for _, p := range tagged {
			memberSet[p] = true
		}
		for _, p := range untagged {
			memberSet[p] = true
		}
		out = append(out, model.VLANInfo{
			VlanID:        vid,
			Name:          names[vid],
			MemberPorts:   sortedPortSet(memberSet),
			TaggedPorts:   tagged,
			UntaggedPorts: untagged,
		})
	}
	return out, nil
}

// ParseGoAheadMacs parses GS728TPP's ForwardingTable section -> the dynamic
// MAC/FDB table. Only entries learned on a physical g<n> port are returned;
// a LAG aggregation carries no port number and is skipped. An empty table
// is legitimate (a freshly-booted switch) -- never an error. Mirrors Python
// parse.parse_goahead_macs (source lines 2599-2615). GROUNDED in
// gs728tpp_macs.xml.
func ParseGoAheadMacs(body string) ([]model.MacEntry, error) {
	sec, err := goaheadSection(body, "ForwardingTable")
	if err != nil {
		return nil, err
	}
	out := make([]model.MacEntry, 0)
	for _, e := range sec.findAll("Entry") {
		port, ok := goaheadPortNum(gtext(e, "interfaceName"))
		if !ok {
			continue
		}
		mac := strings.ToUpper(gtext(e, "MACAddress"))
		if !macTextFullMatch(mac) {
			continue
		}
		var vlanID *int
		if v, ok := parseIntCell(gtext(e, "VLANID")); ok {
			vlanID = model.Ptr(v)
		}
		out = append(out, model.MacEntry{Mac: mac, Port: port, VlanID: vlanID})
	}
	return out, nil
}

// goaheadPoeDetect mirrors Python parse._GOAHEAD_POE_DETECT: the
// detectionStatus wire code. Code 5 (Test) has no RFC3621 detect
// equivalent and is honestly PoEDetectUnknown, not invented.
var goaheadPoeDetect = map[string]model.PoEDetect{
	"1": model.PoEDetectDisabled,
	"2": model.PoEDetectSearching,
	"3": model.PoEDetectDelivering,
	"4": model.PoEDetectFault,
	"6": model.PoEDetectFault, // OtherFault -- still a fault
}

// ParseGoAheadPoE parses GS728TPP's PoEPSEInterfaceList section -> per-port
// PoE status. PowerMw is outputPower (the live draw, mW). Mirrors Python
// parse.parse_goahead_poe (source lines 2618-2644). GROUNDED in
// gs728tpp_poe.xml.
func ParseGoAheadPoE(body string) ([]model.PoEStatus, error) {
	sec, err := goaheadSection(body, "PoEPSEInterfaceList")
	if err != nil {
		return nil, err
	}
	out := make([]model.PoEStatus, 0)
	for _, iface := range sec.findAll("Interface") {
		port, ok := goaheadPortNum(gtext(iface, "interfaceName"))
		if !ok {
			continue
		}
		detect, known := goaheadPoeDetect[gtext(iface, "detectionStatus")]
		if !known {
			detect = model.PoEDetectUnknown
		}
		var power *int
		if v, ok := parseIntCell(gtext(iface, "outputPower")); ok {
			power = model.Ptr(v)
		}
		out = append(out, model.PoEStatus{
			Port:         port,
			AdminEnabled: gtext(iface, "adminEnable") == "1",
			Detect:       detect,
			PowerMw:      power,
		})
	}
	if len(out) == 0 {
		return nil, errUnexpectedPage("PoEPSEInterfaceList: no PoE port row could be parsed")
	}
	return out, nil
}

var macColonHexRE = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`)

// canonLLDPID mirrors Python parse._canon_lldp_id: a MAC-address subtype id
// (colon-hex, six octets) is upper-cased -- the same canonical form the
// SNMP parser emits -- so the two backends' values are LITERALLY equal.
// Any other id (a plain interface-name string) is returned unchanged.
func canonLLDPID(text string) string {
	if macColonHexRE.MatchString(text) {
		return strings.ToUpper(text)
	}
	return text
}

// ParseGoAheadLLDP parses GS728TPP's LLDPMEDNeighborList section -> LLDP
// neighbours. An empty neighbour list is LEGITIMATE (a switch with no
// neighbours), so this returns an empty (not nil) slice rather than
// erroring -- but a missing section still errors (wrong page).
// Chassis/port-id MACs are canonicalized to upper-case (canonLLDPID) so
// they equal the SNMP reader's formatting exactly. Mirrors Python
// parse.parse_goahead_lldp (source lines 2662-2685). GROUNDED in
// gs728tpp_lldp.xml.
func ParseGoAheadLLDP(body string) ([]model.LLDPNeighbor, error) {
	sec, err := goaheadSection(body, "LLDPMEDNeighborList")
	if err != nil {
		return nil, err
	}
	out := make([]model.LLDPNeighbor, 0)
	for _, ne := range sec.findAll("NeighborEntry") {
		port, ok := goaheadPortNum(gtext(ne, "interfaceName"))
		if !ok {
			continue
		}
		var sysName, portDesc, chassis, portID *string
		if v := gtext(ne, "systemName"); v != "" {
			sysName = model.Ptr(v)
		}
		if v := gtext(ne, "portDescription"); v != "" {
			portDesc = model.Ptr(v)
		}
		if v := canonLLDPID(gtext(ne, "deviceID")); v != "" {
			chassis = model.Ptr(v)
		}
		if v := canonLLDPID(gtext(ne, "advertisedPortID")); v != "" {
			portID = model.Ptr(v)
		}
		out = append(out, model.LLDPNeighbor{
			LocalPort:       port,
			RemoteSysName:   sysName,
			RemotePortDesc:  portDesc,
			RemoteChassisID: chassis,
			RemotePortID:    portID,
		})
	}
	return out, nil
}

// goaheadAbsentStatus mirrors Python parse._GOAHEAD_ABSENT_STATUS:
// Diagnostics-status codes meaning the slot is ABSENT (unpopulated fan bay,
// no redundant PSU) -- reported as nothing, not as a failed sensor.
var goaheadAbsentStatus = map[string]bool{"": true, "5": true}

// goaheadStateSensor mirrors Python parse._goahead_state_sensor: one
// unit="state" health-flag Sensor for a Diagnostics status field, or nil
// for an absent slot.
func goaheadStateSensor(entry *xmlNode, tag, name, kind string) *model.Sensor {
	raw := gtext(entry, tag)
	if goaheadAbsentStatus[raw] {
		return nil
	}
	v := 0.0
	if raw == "1" {
		v = 1.0
	}
	return &model.Sensor{Name: name, Kind: kind, Value: v, Unit: "state"}
}

// ParseGoAheadSensors parses GS728TPP's DiagnosticsUnitList section -> box
// sensors. Fans and PSUs report a health STATUS code (1=OK), not RPM/watts,
// so they are emitted as unit="state" flags; an absent slot (status 5) is
// skipped. tempSensorValue is emitted as a numeric temperature only when it
// is a positive reading -- a captured 0 with status 2 is not a real
// reading and is not fabricated as 0C. Mirrors Python
// parse.parse_goahead_sensors (source lines 2701-2725). GROUNDED in
// gs728tpp_device_info_and_sensors.xml.
func ParseGoAheadSensors(body string) ([]model.Sensor, error) {
	sec, err := goaheadSection(body, "DiagnosticsUnitList")
	if err != nil {
		return nil, err
	}
	out := make([]model.Sensor, 0)
	entry := sec.find("Entry")
	if entry == nil {
		return out, nil
	}
	for n := 1; n <= 5; n++ {
		if s := goaheadStateSensor(entry, fmt.Sprintf("fan%dStatus", n), fmt.Sprintf("Fan%d", n), "fan"); s != nil {
			out = append(out, *s)
		}
	}
	if s := goaheadStateSensor(entry, "mainPSStatus", "Main PS", "power"); s != nil {
		out = append(out, *s)
	}
	if s := goaheadStateSensor(entry, "redundantPSStatus", "Redundant PS", "power"); s != nil {
		out = append(out, *s)
	}
	if temp, ok := parseIntCell(gtext(entry, "tempSensorValue")); ok && temp > 0 {
		out = append(out, model.Sensor{Name: "Temperature", Kind: "temperature", Value: float64(temp), Unit: "C"})
	}
	return out, nil
}

// ParseGoAheadBaseMAC parses GS728TPP's SystemInfo (DeviceBasicInfo)
// section -> the switch's base MAC. DeviceBasicInfo/MacAddre (sic --
// preserving the firmware's own field-name typo verbatim) carries the
// switch's own base MAC, uppercased to match the SNMP/NSDP formatting.
// ok=false means absent, never fabricated. Mirrors Python
// parse.parse_goahead_base_mac (source lines 2728-2739). GROUNDED in
// gs728tpp_device_info_and_sensors.xml.
func ParseGoAheadBaseMAC(body string) (string, bool, error) {
	sec, err := goaheadSection(body, "DeviceBasicInfo")
	if err != nil {
		return "", false, err
	}
	mac := strings.ToUpper(gtext(sec, "MacAddre"))
	if mac == "" {
		return "", false, nil
	}
	return mac, true, nil
}

// ParseGoAheadHostname parses GS728TPP's SystemInfo (DeviceBasicInfo)
// section -> the switch's host name. DeviceBasicInfo/deviceName IS the host
// name, not merely a cosmetic label: MEASURED on the live switch (10.2.5.10,
// firmware 6.0.1.30, 2026-08-03) it reads "sw-netgear-gs728tpp", byte-for-
// byte what SNMP reports through sysName.
//
// Returns the raw value including "". An empty name is a REAL state on a
// switch that has never been named, so it must not be turned into an absent
// marker, which the caller would read as "this backend cannot tell you".
// Mirrors Python parse.parse_goahead_hostname (source lines 3109-3121).
func ParseGoAheadHostname(body string) (string, error) {
	sec, err := goaheadSection(body, "DeviceBasicInfo")
	if err != nil {
		return "", err
	}
	return gtext(sec, "deviceName"), nil
}

// ParseGoAheadMgmtIP parses GS728TPP's IPConf_master.xml wcd response ->
// management IP + gateway. IPv4InterfaceList/ifEntry carries the
// address/netmask (on the mgmt VLAN interface); IPv4GatewayList/GWEntry the
// default gateway. The page carries no DHCP/static indicator and no base
// MAC (that is on the SystemInfo page), so Mode is Unknown and BaseMac is
// nil rather than guessed. Mirrors Python parse.parse_goahead_mgmt_ip
// (source lines 2742-2771). GROUNDED in gs728tpp_mgmt_ip.xml.
func ParseGoAheadMgmtIP(body string) (model.MgmtIPConfig, error) {
	root, err := goaheadDataBlock(body)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	var addr, netmask, gateway *string
	if ifaceList := root.find("IPv4InterfaceList"); ifaceList != nil {
		if ent := ifaceList.find("ifEntry"); ent != nil {
			if v := gtext(ent, "IPAddr"); v != "" {
				addr = model.Ptr(v)
			}
			if v := gtext(ent, "subnetMask"); v != "" {
				netmask = model.Ptr(v)
			}
		}
	}
	if gwList := root.find("IPv4GatewayList"); gwList != nil {
		if ge := gwList.find("GWEntry"); ge != nil {
			if v := gtext(ge, "IPAddr"); v != "" {
				gateway = model.Ptr(v)
			}
		}
	}
	if addr == nil && gateway == nil {
		return model.MgmtIPConfig{}, errUnexpectedPage("IPConf: no IPv4 interface address or gateway found")
	}
	return model.MgmtIPConfig{
		Mode:    model.IPModeUnknown,
		Address: addr,
		Netmask: netmask,
		Gateway: gateway,
	}, nil
}
