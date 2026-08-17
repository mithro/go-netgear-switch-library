package capabilities

// support_http.go: the HTTP-backend derivation, ported field-for-field from
// src/netgear_switch/capabilities.py's _http_support and _http_path_for
// (pin go-port-pin-b26eb1f, lines 516-659). Any discrepancy between this
// file and that pin is a bug in this file.
//
// httpSupport/httpPathFor take an already-resolved *webui.HTTPModelSpec
// rather than calling webui.HTTPSpec(m) themselves -- see this task's
// Interfaces note (Go has no monkeypatching, so the ReadsVerified gate is
// tested with a synthetic spec instead; For, in support.go, is the one place
// that calls the real webui.HTTPSpec).

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// csrfHTTPWrites are the HTTP writes implemented by scraping the Plus
// dialect's CSRF token, mirroring Python's _CSRF_HTTP_WRITES
// (capabilities.py:104-112). A dialect without that token cannot serve any
// of them -- see webui.DialectHasCSRFHash for the measurement.
//
// The XML-API dialect is exempt, and not as a special case: its writer
// posts an XML body and never scrapes a token, so "does this UI carry an
// <input name='hash'>" is not a question about it (see isXMLAPIDialect's
// use in httpSupport below).
var csrfHTTPWrites = map[string]bool{"create_vlan": true, "delete_vlan": true}

// isXMLAPIDialect reports whether spec's dialect writes by POSTing an XML
// body to one endpoint, mirroring Python's http_write._is_xml_api_dialect.
// Only the GS728TPP's GoAhead wcd API today.
func isXMLAPIDialect(spec *webui.HTTPModelSpec) bool {
	return spec.HTMLDialect == webui.HTMLDialectGoAheadXML
}

// xmlAPIWrites are the writes the XML-API (GoAhead wcd) writer actually
// implements, each with a body builder GROUNDED in the page's own
// JavaScript, mirroring Python's _XML_API_WRITES (capabilities.py:495-513).
// An op absent here is honestly unsupported on this dialect -- not
// "probably works": the endpoint is shared, so a missing entry means nobody
// has established what body that operation sends, and guessing one would
// write something unintended.
var xmlAPIWrites = map[string]bool{
	"set_vlan_membership": true,
	"set_port_enabled":    true,
	"set_poe":             true,
	"set_pvid":            true,
	"create_vlan":         true,
	"delete_vlan":         true,
	// No reset control exists on this UI (its PoE page has only Refresh/
	// Cancel/Apply, and Behaviour/UnitsPoe.js has no reset action), so these
	// are an admin off/on re-arm of the same field -- the mechanism
	// snmp.Writer already uses on agents with no reset column.
	"cycle_poe":            true,
	"clear_poe_fault":      true,
	"set_port_description": true,
	"set_hostname":         true,
	// Standard802_3List's autoNegotiationAdminEnabled/speedAdmin/
	// duplexAdminMode, encoded exactly as the ports page's own submit JS
	// does.
	"set_port_speed": true,
}

// httpSupport derives the HTTP-backend verdict for (m, op) given spec.
func httpSupport(m *model.SwitchModel, spec *webui.HTTPModelSpec, op Operation) (Support, string) {
	if !spec.ReadsVerified {
		// The facade gates BOTH reads and writes on ReadsVerified (see
		// backend_http.go's httpReadsSupported, reused for both directions):
		// output nobody has cross-verified against hardware is not
		// dispatched at all.
		return SupportUnverified, fmt.Sprintf("model %q HTTP reads are UNVERIFIED-pending-capture", m.Key)
	}
	if op.Name == "upload_certificate" {
		// These models CAN take a certificate -- just not over HTTP. The
		// real facade raises model.ErrKnownUnimplemented naming the real
		// mechanism (webui/cert.go's rejectKnownUnimplementedCertUpload)
		// rather than model.ErrUnsupportedCapability -- but the ORACLE folds
		// both into this single Support.UNSUPPORTED verdict, exactly
		// mirroring Python's collapse of UnsupportedCapabilityError and
		// NotImplementedError. Do not add a distinct Support value here.
		if mechanism, ok := webui.CertUploadKnownUnimplemented[m.Key]; ok {
			return SupportUnsupported, fmt.Sprintf(
				"this model takes a certificate by %s, not over the web UI -- use upload_certificate_scp",
				mechanism)
		}
	}
	if csrfHTTPWrites[op.Name] && !isXMLAPIDialect(spec) && !webui.DialectHasCSRFHash(spec.HTMLDialect) {
		// These writers scrape an <input name="hash"> before posting, and
		// this dialect's pages do not carry one -- MEASURED on gsm7252ps and
		// gs110emx, see webui.DialectHasCSRFHash. Driving them raises an
		// unexpected-page error on real hardware, so claiming support here
		// would publish a support table that contradicts the device.
		return SupportUnsupported, fmt.Sprintf(
			"model %q web UI carries no CSRF 'hash' token, which the HTTP %s writer requires",
			m.Key, op.Name)
	}
	path := httpPathFor(spec, op)
	if path == "" {
		return SupportUnsupported, fmt.Sprintf("model %q web UI has no page for %s (%s)", m.Key, op.Name, op.Summary)
	}
	return SupportSupported, ""
}

// httpPathFor is the endpoint op needs, or "" if this model's UI has no such
// page (Go's None sentinel, matching every other webui *ModelSpec string
// field). Mirrors http_read.py/http_write.py one line at a time; the ops
// with composite conditions defer to webui's own exported helpers so there
// is exactly one definition of "this UI can answer that".
func httpPathFor(spec *webui.HTTPModelSpec, op Operation) string {
	if isXMLAPIDialect(spec) && op.Kind == OperationKindWrite {
		// On an XML-API UI every write POSTs to one endpoint and the BODY
		// selects the operation, so "is there a page for this op" is the
		// wrong question -- there is no per-op page, and answering it with
		// the op's READ path would claim support for any write whose data
		// can be read. That is not hypothetical: set_pvid was reported
		// SUPPORTED on the GS728TPP purely because pvid_path exists, while
		// the writer would have posted a Plus-class CGI form at a wcd query
		// string.
		//
		// Certificate upload keeps its own path: it is a distinct XML flow
		// with its own grounding and its own response check.
		if op.Name == "upload_certificate" {
			return spec.CertUploadPath
		}
		if xmlAPIWrites[op.Name] {
			return spec.XMLWritePath
		}
		return ""
	}

	switch op.Name {
	case "get_sensors":
		if webui.SupportsSensors(spec) {
			return spec.SysinfoPath
		}
		return ""
	case "get_services":
		// All four pages or none -- webui.HasServicePaths decides, so there
		// is one definition of "this UI can be asked" rather than two.
		if webui.HasServicePaths(spec) {
			return spec.HTTPServicePath
		}
		return ""
	case "get_hostname":
		// Only two identity pages carry the field (gs110emx's sysInfo.html
		// and gs105pe's switch_info.cgi) plus the GoAhead DeviceBasicInfo
		// section; webui.HasSysinfoHostname decides, so there is one
		// definition rather than two that can drift.
		if webui.HasSysinfoHostname(spec) {
			return spec.SysinfoPath
		}
		return ""
	case "get_mgmt_ip":
		return webui.MgmtIPPath(spec)
	case "set_mgmt_ip":
		// The XUI write needs the field map as well as the page.
		if spec.MgmtIPFields != nil {
			return spec.MgmtIPPath
		}
		return ""
	case "set_hostname":
		// The GS110EMX sysInfo form carries switch_name, so that dialect has
		// a grounded (and live-verified) host-name write; every other
		// non-XML-API dialect is "". gs105pe's switch_info.cgi has the same
		// field but its own CSRF-hash envelope, which has not been driven.
		if spec.HTMLDialect == webui.HTMLDialectGS110EMX {
			return spec.SysinfoPath
		}
		return ""
	case "remove_syslog_collector":
		// Only the M4300 XUI pages render the v_g_* template row AND inline
		// the cell metadata the write depends on; the other dialects'
		// syslog pages do neither, so they are refused rather than posted
		// at on an assumption. webui.Writer's syslogPage enforces the same
		// rule, so there is one definition of "this UI can be written".
		if spec.HTMLDialect == webui.HTMLDialectM4300 {
			return spec.SyslogPath
		}
		return ""
	}

	simple := map[string]string{
		"get_ports":           spec.DashboardPath,
		"get_stats":           spec.StatsPath,
		"get_poe":             spec.PoEStatusPath,
		"get_pvids":           spec.PvidPath,
		"get_vlans":           spec.VlanConfigPath,
		"get_macs":            spec.MacTablePath,
		"get_lldp":            spec.LLDPPath,
		"get_syslog":          spec.SyslogPath,
		"get_users":           spec.UsersPath,
		"set_poe":             spec.PoEConfigPath,
		"cycle_poe":           spec.PoEConfigPath,
		"clear_poe_fault":     spec.PoEConfigPath,
		"set_pvid":            spec.PvidPath,
		"set_vlan_membership": spec.VlanMembershipPath,
		"create_vlan":         spec.VlanConfigPath,
		"delete_vlan":         spec.VlanConfigPath,
		"set_port_enabled":    spec.PortConfigPath,
		// Only the XML-API dialect has a grounded description write; every
		// other dialect is handled by the branch above returning "" for it.
		"set_port_description": "",
		// Same shape: the FASTPATH XUI Speed control's cell id was never
		// captured, so only the XML-API branch above answers for this op.
		"set_port_speed": "",
		// No dialect has a captured flow-control write form -- including the
		// XML-API one, whose ports page reports the field but offers no
		// control for it (the xmlAPIWrites entry is absent for the same
		// reason). Unreachable in practice: set_flow_control's Operation.
		// Backends restricts it to the CLI backends before httpSupport is
		// ever asked, but kept for symmetry with the pinned Python source.
		"set_flow_control": "",
		// The add is refused on every dialect -- the M4300 firmware rejects
		// the body (see webui.Writer.AddSyslogCollector) and the others
		// render no usable template row at all. Unreachable in practice for
		// the same reason as set_flow_control above (Operation.Backends is
		// CLI-only), kept for symmetry.
		"add_syslog_collector": "",
		"upload_certificate":   spec.CertUploadPath,
	}
	return simple[op.Name]
}
