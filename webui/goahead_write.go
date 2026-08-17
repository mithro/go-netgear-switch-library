package webui

// goahead_write.go: pure (I/O-free) builders for the GoAhead "wcd" XML write
// bodies SetPortDescription/SetPortSpeed need, ported field-for-field from
// src/netgear_switch/protocols/http/goahead.py at pin b26eb1f in
// python-netgear-switch-library (frozen snapshot worktree
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
// This file only needs the FLAT single-Entry shape (an Entry element with a
// handful of scalar child elements, no nesting, no repeated list) -- neither
// port_config_body nor port_speed_body needs Python goahead.py's fully
// general recursive Node renderer (that generality exists for
// vlan_membership_body's nested VLAN/MembershipList/VLANMember shape, which
// this file's two builders never touch), so goaheadEntry below renders just
// that flat case rather than porting the general recursion.
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

// keyValue is one ordered element-name/text-value pair for goaheadEntry.
type keyValue struct{ key, value string }

// goaheadEntry renders one "<Entry><k1>v1</k1><k2>v2</k2>...</Entry>"
// element, fields in the caller-given order, mirroring the flat-mapping
// case of Python goahead._render (see this file's doc comment for why the
// general recursive case is not needed here).
func goaheadEntry(fields []keyValue) string {
	var b strings.Builder
	b.WriteString("<Entry>")
	for _, f := range fields {
		b.WriteByte('<')
		b.WriteString(f.key)
		b.WriteByte('>')
		b.WriteString(goaheadEscaper.Replace(f.value))
		b.WriteString("</")
		b.WriteString(f.key)
		b.WriteByte('>')
	}
	b.WriteString("</Entry>")
	return b.String()
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

// portConfigBody builds the Standard802_3List body that sets a port's
// description, mirroring Python goahead.port_config_body's description-only
// use: SetPortDescription never sets admin_enabled through this path, so
// this Go port takes description directly rather than carrying Python's
// `admin_enabled: bool | None = None` parameter this file's one caller
// never needs. description is ALWAYS sent (an empty string is a real value
// here -- it clears the label), unlike Python's `description: str | None =
// None` "leave alone" sentinel -- again unneeded by this file's single
// call site, which always has a description to set.
func portConfigBody(portName string, portID int, description string) string {
	entry := goaheadEntry([]keyValue{
		{"interfaceName", portName},
		{"interfaceType", interfacePhysical},
		{"interfaceID", strconv.Itoa(portID)},
		{"interfaceDescription", description},
	})
	return goaheadWriteBody("Standard802_3List", "set", entry)
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
