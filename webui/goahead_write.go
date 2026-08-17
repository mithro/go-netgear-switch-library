package webui

// goahead_write.go: pure (I/O-free) builders for the GoAhead "wcd" XML write
// bodies webui.Writer's GoAhead-dialect (gs728tpp) ops need, ported
// field-for-field from src/netgear_switch/protocols/http/goahead.py at pin
// b26eb1f in python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-b26eb1f). Any discrepancy between this file and that pin is a
// bug in this file, not a deliberate deviation, unless called out in a
// comment.
//
// The GS728TPP web UI is not an HTML form UI: every page reads through
// "GET wcd?{file=...}{Object}" and writes through a single "POST wcd" whose
// body is an XML document. Its site map has exactly one POST target -- "wcd"
// -- repeated for all 100-odd pages, so the object name and the action verb
// in the body, not the URL, are what select the operation. The wire shape is
// GROUNDED, not inferred -- see goahead.py's own module doc comment for the
// live-capture provenance (VlanMembership_jq.htm, portConfiguration_master_
// jq.htm, and the GS728TPPUpdater certificate-import envelope this repo's
// cert.go already ports).
//
// goaheadWrapped renders the flat shapes (an Entry/Interface/VLAN element
// with a handful of scalar child elements, no further nesting) every
// builder here needs except one: vlanMembershipBody's VLAN/MembershipList/
// VLANMember shape is genuinely two levels deep, which is what Python
// goahead.py's fully general recursive Node renderer exists for. Rather
// than porting that generality for ONE caller, vlanMembershipBody just
// writes its one extra level of nesting directly -- Go's static typing
// makes a dynamic dict-shaped recursion awkward, and there is no second
// caller here to justify it.
//
// checkGoAheadStatus below reuses cert.go's uploadStatusRE/
// uploadStatusStringRE regexes deliberately: Python's _check_goahead_status
// (http_write.py) is explicitly documented as reusing the SAME convention
// its own certificate-upload check uses ("the same convention the GS728TPP
// certificate upload already checks"), so this Go port shares the regexes
// rather than duplicating them.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// interfacePhysical is interfaceType's value for every physical-port object
// this file builds ("1" -- "2" would be a LAG), mirroring Python's
// goahead.INTERFACE_PHYSICAL. Only physical-port writes are built here.
const interfacePhysical = "1"

// goaheadEscaper XML-escapes an element's text content, mirroring Python's
// xml.sax.saxutils.escape with the goahead.py module's extra
// {'"': "&quot;", "'": "&apos;"} entity table (the framework escapes quotes
// too, not just the three required XML characters).
var goaheadEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&apos;",
)

// keyValue is one ordered element-name/text-value pair for goaheadWrapped.
type keyValue struct{ key, value string }

// goaheadWrapped renders one "<tag><k1>v1</k1><k2>v2</k2>...</tag>"
// element, fields in the caller-given order, mirroring the flat-mapping
// case of Python goahead._render (see this file's doc comment for why the
// general recursive case is not needed here). tag varies by object --
// "Entry" for Standard802_3List, "Interface" for PoEPSEInterfaceList/
// VLANInterfaceList, "VLAN"/"VLANMember" for the VLAN objects -- unlike
// Python's _render, which derives the element name from the single dict
// key at each level instead of a caller-given tag.
func goaheadWrapped(tag string, fields []keyValue) string {
	var b strings.Builder
	b.WriteByte('<')
	b.WriteString(tag)
	b.WriteByte('>')
	for _, f := range fields {
		b.WriteByte('<')
		b.WriteString(f.key)
		b.WriteByte('>')
		b.WriteString(goaheadEscaper.Replace(f.value))
		b.WriteString("</")
		b.WriteString(f.key)
		b.WriteByte('>')
	}
	b.WriteString("</")
	b.WriteString(tag)
	b.WriteByte('>')
	return b.String()
}

// goaheadEntry is goaheadWrapped("Entry", fields) -- Standard802_3List's own
// child element name (portConfigBody/portSpeedBody).
func goaheadEntry(fields []keyValue) string { return goaheadWrapped("Entry", fields) }

// goaheadAdminCode is the GoAhead wire code shared by PoEPSEInterfaceList's
// adminEnable and Standard802_3List's adminState: 1 = enabled/up, 2 =
// disabled/down -- the same codes the READ side already decodes (see
// webui/parse_goahead.go's `gtext(e, "adminState") == "1"` /
// `gtext(iface, "adminEnable") == "1"`). Mirrors Python's inline
// `"1" if x else "2"` at each of poe_admin_body/port_config_body's call
// sites, extracted here since both need the identical mapping.
func goaheadAdminCode(enabled bool) string {
	if enabled {
		return "1"
	}
	return "2"
}

// goaheadWriteBody renders one "POST wcd" body, mirroring Python
// goahead.write_body: obj is the page's object name ("Standard802_3List"),
// action the verb ("set"), and entry the already-rendered single child
// element (goaheadEntry's output) -- narrower than Python's write_body(obj,
// action, children: Sequence[Node]), which accepts an arbitrary list of
// children; every call site in this file has exactly one.
func goaheadWriteBody(obj, action, entry string) string {
	return "<?xml version='1.0' encoding='utf-8'?>" +
		"<DeviceConfiguration>" +
		fmt.Sprintf("<%s action=%q>", obj, action) +
		entry +
		fmt.Sprintf("</%s>", obj) +
		"</DeviceConfiguration>"
}

// portInterfaceName renders port the way this UI's wcd objects key on it
// ("17" -> "g17"), mirroring Python goahead.port_interface_name -- the
// inverse of goaheadPortNum (parse_goahead.go), which the read side already
// relies on.
func portInterfaceName(port int) string {
	return fmt.Sprintf("g%d", port)
}

// portConfigBody builds the Standard802_3List body that sets a port's admin
// state and/or description, mirroring Python goahead.port_config_body
// EXACTLY: adminEnabled/description are each a *bool/*string "leave alone"
// sentinel (nil = omitted element) -- SetPortEnabled sends only adminState,
// SetPortDescription sends only interfaceDescription, and a well-formed
// write never carries both. description is a *string (not a bare string
// with an empty-string sentinel) because an EMPTY description IS a real
// value here -- it clears the label -- so "leave alone" and "clear" must be
// distinguishable, mirroring Python's `description: str | None = None`.
func portConfigBody(portName string, portID int, adminEnabled *bool, description *string) string {
	fields := []keyValue{
		{"interfaceName", portName},
		{"interfaceType", interfacePhysical},
		{"interfaceID", strconv.Itoa(portID)},
	}
	if adminEnabled != nil {
		fields = append(fields, keyValue{"adminState", goaheadAdminCode(*adminEnabled)})
	}
	if description != nil {
		fields = append(fields, keyValue{"interfaceDescription", *description})
	}
	return goaheadWriteBody("Standard802_3List", "set", goaheadEntry(fields))
}

// deviceBasicInfoBody builds the DeviceBasicInfo body that sets the switch's
// host name, mirroring Python http_write.set_hostname's inline
// goahead.write_body("DeviceBasicInfo", "set", [{"deviceName": name}]) call.
//
// Unlike portConfigBody/portSpeedBody's Standard802_3List (a repeated-list
// section whose one child is keyed "Entry", wrapping its fields --
// goaheadEntry), DeviceBasicInfo is a SCALAR section: write_body's children
// list here is `[{"deviceName": name}]`, so _render emits the field
// DIRECTLY as a child of <DeviceBasicInfo>, with NO <Entry> wrapper at all.
// Getting that wrong would post a shape this object does not expect. The
// page's own JS rejects '&' in this field client-side; the value is
// XML-escaped here, and the switch's own verdict is what checkGoAheadStatus
// reports.
func deviceBasicInfoBody(name string) string {
	entry := "<deviceName>" + goaheadEscaper.Replace(name) + "</deviceName>"
	return goaheadWriteBody("DeviceBasicInfo", "set", entry)
}

// Duplex-admin/autoneg-admin wire codes, mirroring Python goahead.py's
// module constants DUPLEX_ADMIN_FULL/DUPLEX_ADMIN_HALF/AUTONEG_ON/
// AUTONEG_OFF. duplexAdminFull/duplexAdminHalf are DELIBERATELY NOT the
// same codes as the READ side's duplexOperMode decode (goaheadDuplexOper,
// parse_goahead.go), where 2 means full -- these are what the page's own
// SUBMIT path writes, a different enum entirely.
const (
	duplexAdminFull = "3"
	duplexAdminHalf = "2"
	autonegOn       = "1"
	autonegOff      = "2"
)

// goAheadForcedSpeed is one (speedMbps, fullDuplex) pair this UI's own
// slctPortSpeed dropdown offers as a FORCED choice.
type goAheadForcedSpeed struct {
	speedMbps  int
	fullDuplex bool
}

// goAheadForcedSpeeds is the forced-rate set this UI's dropdown offers,
// READ OFF the page's own <option> list (webui/testdata/http/
// gs728tpp_ports.xml), mirroring Python goahead.GOAHEAD_FORCED_SPEEDS
// EXACTLY: 10/100 half-or-full, 1000 FULL ONLY (no 1000H -- gigabit
// half-duplex is not offered), and Auto (handled separately, not part of
// this forced-rate set). This UI DOES offer a forced 1000 where the
// FASTPATH CLI does not -- which is exactly why that refusal lives in
// fastpath.Writer.SetPortSpeed and not here.
var goAheadForcedSpeeds = map[goAheadForcedSpeed]bool{
	{10, false}:  true,
	{10, true}:   true,
	{100, false}: true,
	{100, true}:  true,
	{1000, true}: true,
}

// isGoAheadForcedSpeed reports whether (speedMbps, fullDuplex) is one of
// this UI's offered forced choices, mirroring the Python membership test
// `(speed.speed_mbps, speed.full_duplex) not in goahead.GOAHEAD_FORCED_SPEEDS`.
func isGoAheadForcedSpeed(speedMbps int, fullDuplex bool) bool {
	return goAheadForcedSpeeds[goAheadForcedSpeed{speedMbps, fullDuplex}]
}

// portSpeedBody builds the Standard802_3List body that applies speed,
// mirroring Python goahead.port_speed_body EXACTLY -- transcribed from the
// page's own submit JS, which turns one dropdown value into three elements:
// AUTO sends autoNegotiationAdminEnabled=1, speedAdmin=0 (a rate of 0, not
// an omitted field), duplexAdminMode=3; a forced choice sends
// autoNegotiationAdminEnabled=2 with the parsed rate and the duplex code.
func portSpeedBody(portName string, portID int, speed model.PortSpeed) string {
	rate, autoneg, duplex := "0", autonegOn, duplexAdminFull
	if !speed.Autonegotiate {
		rate = strconv.Itoa(*speed.SpeedMbps)
		autoneg = autonegOff
		duplex = duplexAdminHalf
		if speed.FullDuplex != nil && *speed.FullDuplex {
			duplex = duplexAdminFull
		}
	}
	entry := goaheadEntry([]keyValue{
		{"interfaceName", portName},
		{"interfaceType", interfacePhysical},
		{"interfaceID", strconv.Itoa(portID)},
		{"autoNegotiationAdminEnabled", autoneg},
		{"speedAdmin", rate},
		{"duplexAdminMode", duplex},
	})
	return goaheadWriteBody("Standard802_3List", "set", entry)
}

// poeAdminBody builds the PoEPSEInterfaceList body that sets a port's PoE
// admin state, mirroring Python goahead.poe_admin_body EXACTLY: adminEnable
// 1 = enabled, 2 = disabled -- the same codes the READ side already decodes
// from this object (webui/parse_goahead.go's `gtext(iface, "adminEnable")
// == "1"`).
//
// Note what is NOT here: this UI has no PoE reset/power-cycle control at
// all -- Behaviour/UnitsPoe.js has no reset/cycle/reboot action and the
// page's only buttons are Refresh/Cancel/Apply -- so CyclePoE/ClearPoEFault
// (writer.go's goaheadPoERearm) drive this SAME builder twice (off then on)
// rather than a dedicated reset field, exactly the mechanism snmp.Writer
// already uses on agents with no reset column.
func poeAdminBody(portName string, enabled bool) string {
	entry := goaheadWrapped("Interface", []keyValue{
		{"interfaceName", portName},
		{"interfaceType", interfacePhysical},
		{"adminEnable", goaheadAdminCode(enabled)},
	})
	return goaheadWriteBody("PoEPSEInterfaceList", "set", entry)
}

// vlanCreateBody builds the VLANList body that creates (or renames) one
// VLAN, mirroring Python goahead.vlan_create_body EXACTLY.
//
// There is no "add" verb on this UI: the framework (js/home.js) defines
// exactly ACTION_SET="set", ACTION_DELETE="delete" and ACTION_RESTORE=
// "restore", and createPostXml stamps a NEW row with ACTION_SET like any
// other edit -- so creating and editing a VLAN are the same request shape.
//
// The switch's own page rejects ids outside 2-4093 (VlanConfig.
// checkValidVLANId), narrower than the 1-4094 the protocol allows -- VLAN 1
// is the default VLAN and cannot be created. Not enforced here (a
// capability/range check, not a wire-shape concern); the switch's own
// statusCode is what a caller sees.
func vlanCreateBody(vlan int, name string) string {
	entry := goaheadWrapped("VLAN", []keyValue{
		{"VLANID", strconv.Itoa(vlan)},
		{"VLANName", name},
	})
	return goaheadWriteBody("VLANList", "set", entry)
}

// vlanDeleteBody builds the VLANList body that deletes one VLAN, mirroring
// Python goahead.vlan_delete_body EXACTLY -- taken from VlanConfig.Reset,
// which posts a literal delete envelope carrying only the VLANID (no
// VLANName). Deliberately deletes ONLY the one VLAN it was asked to (the
// live page's own delete additionally sends a page-level
// "<VLANInterfaceList action=\"restoreAll\"/>" reset, which this builder
// does not reproduce).
func vlanDeleteBody(vlan int) string {
	entry := goaheadWrapped("VLAN", []keyValue{
		{"VLANID", strconv.Itoa(vlan)},
	})
	return goaheadWriteBody("VLANList", "delete", entry)
}

// pvidBody builds the VLANInterfaceList body that sets one port's PVID,
// mirroring Python goahead.pvid_body EXACTLY -- the same object the read
// side already parses PVIDs and per-port membership out of (see
// ParseGoAheadPVIDs/ParseGoAheadPortVlanMembership, parse_goahead.go). The
// page's own validation allows 1-4093 or 4095, and rejects 4094 explicitly
// (PortPVID.Apply) -- not enforced here; the switch's own statusCode is
// what a caller sees.
func pvidBody(portName string, vlan int) string {
	entry := goaheadWrapped("Interface", []keyValue{
		{"interfaceName", portName},
		{"interfaceType", interfacePhysical},
		{"PVID", strconv.Itoa(vlan)},
	})
	return goaheadWriteBody("VLANInterfaceList", "set", entry)
}

// GoAhead taggingMode wire codes, from the membership page's own "Group
// Operation" select, mirroring Python goahead.TAGGING_TAGGED/
// TAGGING_UNTAGGED/TAGGING_REMOVED.
const (
	goaheadTaggingTagged   = "2"
	goaheadTaggingUntagged = "1"
	goaheadTaggingRemoved  = "0"
)

// goaheadTaggingMode is the page's taggingMode code for a library
// model.VlanMode, mirroring Python goahead.tagging_mode.
func goaheadTaggingMode(mode model.VlanMode) string {
	switch mode {
	case model.VlanTagged:
		return goaheadTaggingTagged
	case model.VlanUntagged:
		return goaheadTaggingUntagged
	default:
		return goaheadTaggingRemoved
	}
}

// vlanMembershipBody builds the VLANMembershipList body that sets (or
// removes) one port's membership in vlan, mirroring Python
// goahead.vlan_membership_body EXACTLY -- captured verbatim off the live
// switch's VlanMembership_jq.htm (see this file's package doc comment):
//
//	post.VLANMembershipList['set'] = [{VLAN: {VLANID: "5",
//	    MembershipList: [{VLANMember: {interfaceName: "g17",
//	        interfaceType: "1", membershipType: "2", taggingMode: "2"}}]}}]
//	post.VLANMembershipList['delete'] = [{VLAN: {VLANID: "5",
//	    MembershipList: [{VLANMember: {interfaceName: "g17",
//	        interfaceType: "1"}}]}}]
//
// EXCLUDED is not a "set" with taggingMode 0 -- the page routes it to a
// SEPARATE "delete" action carrying only the interface identity, with no
// membershipType/taggingMode. That asymmetry is the page's, and reproducing
// it is the difference between removing a port and setting it to a mode the
// firmware does not have. membershipType is hardcoded "2" for BOTH tagged
// and untagged (only taggingMode differs) -- exactly what the captured JS
// above sends, not a guess.
func vlanMembershipBody(vlan int, portName string, mode model.VlanMode) string {
	member := []keyValue{
		{"interfaceName", portName},
		{"interfaceType", interfacePhysical},
	}
	action := "set"
	if mode == model.VlanExcluded {
		action = "delete"
	} else {
		member = append(member,
			keyValue{"membershipType", "2"},
			keyValue{"taggingMode", goaheadTaggingMode(mode)},
		)
	}
	vlanElem := "<VLAN><VLANID>" + strconv.Itoa(vlan) + "</VLANID>" +
		"<MembershipList>" + goaheadWrapped("VLANMember", member) + "</MembershipList></VLAN>"
	return goaheadWriteBody("VLANMembershipList", action, vlanElem)
}

// checkGoAheadStatus returns an error wrapping model.ErrHTTP unless a "wcd"
// write reported success, mirroring Python's _check_goahead_status
// EXACTLY: success is "<statusCode>0</statusCode>" -- the same convention
// cert.go's checkGoAheadUploadResponse already checks (reusing its
// uploadStatusRE/uploadStatusStringRE regexes rather than duplicating them,
// per this file's own doc comment). A missing statusCode means the POST did
// not reach a write handler at all (not logged in, or wrong endpoint),
// which must never read as success.
func checkGoAheadStatus(text, what string) error {
	match := uploadStatusRE.FindStringSubmatch(text)
	if match == nil {
		return fmt.Errorf("%s: response carried no <statusCode> (unexpected page -- not logged in, or wrong endpoint?): %w", what, model.ErrHTTP)
	}
	if match[1] != "0" {
		reason := "unknown error"
		if detail := uploadStatusStringRE.FindStringSubmatch(text); detail != nil {
			reason = detail[1]
		}
		return fmt.Errorf("%s failed (statusCode=%s): %s: %w", what, match[1], reason, model.ErrHTTP)
	}
	return nil
}
