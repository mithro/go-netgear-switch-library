package webui

// Ported field-for-field from
// src/netgear_switch/protocols/http/{session,types}.py at pin b26eb1f in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-b26eb1f). Any discrepancy between this file and that pin is a
// bug in this file, not a deliberate deviation, unless called out in a
// comment.
//
// This file carries:
//   - MultipartFile + the Session interface (source: session.py's
//     MultipartFile dataclass and HttpSession/AsyncHttpSession Protocols,
//     59 lines total). Go has no separate sync/async client split -- one
//     interface with context.Context-first methods covers what Python
//     needed two Protocols for (dossier D-HTTP-P §7.4/§5.1).
//   - HTTPSysInfo (source: types.py's HttpSysInfo dataclass, dossier §5.2).
//   - XuiRow/XuiListPage/XuiFormPage (source: types.py, dossier §5.3). Note
//     that types.py's fourth dataclass, FastpathMembership, is deliberately
//     NOT here: Task 2/3 already defined it in parse_xe.go (it is the
//     return type of ParseFastpathMembership, which they implemented), and
//     the brief for this task says not to redefine it -- see that file's
//     "FastpathMembership" doc comment for its field-for-field mapping.
//
// The forms.py write-form encoders that consume these types live in
// forms.go; the parse.py functions that PRODUCE XuiListPage/XuiFormPage/
// HTTPSysInfo values (parse_xui_list_page/parse_xui_form_page in
// parse_xe.go, parse_sysinfo/parse_gs105pe_sysinfo in parse_gs110emx.go/
// parse_gs105pe.go) were deferred by Tasks 2/3 to this task, since they
// depend on the types defined here.

import (
	"context"
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
)

// MultipartFile is one file part of a multipart/form-data POST, mirroring
// Python session.MultipartFile (source lines 15-26). Used by the
// SSL-certificate upload flow: Field is the form field name the switch
// expects the file under (e.g. gsm7228ps's ".v_1_3_1_handle"), Content is
// served as Filename with MIME ContentType (e.g. "application/octet-stream").
type MultipartFile struct {
	Field       string
	Filename    string
	Content     []byte
	ContentType string
}

// Session is the transport-agnostic authenticated web-UI session interface
// for one switch, mirroring Python session.HttpSession/AsyncHttpSession
// (source lines 29-58) collapsed into a single Go interface: Go has no
// separate sync/async client split, so a context.Context-first parameter on
// every method covers what Python needed two Protocols for (dossier
// D-HTTP-P §7.4). Both the eventual net/http-backed transport client and the
// virtual HTTP face's own client (Part 2) implement this; http_read.go/
// http_write.go's Go equivalents depend ONLY on this five-method surface --
// exactly the role snmp.Client/nsdp.Client already play for their backends.
type Session interface {
	// Login performs this model's login handshake (dossier §1.1) and
	// establishes the cookie/token session every other method relies on.
	Login(ctx context.Context) error
	// GetPage fetches path and returns the response body, mirroring
	// Python's get_page. Implementations retry a dropped connection (never
	// an HTTP error status) exactly twice -- see dossier §6.4 -- but that
	// policy is a transport-implementation detail, not part of this
	// interface's contract.
	GetPage(ctx context.Context, path string) (string, error)
	// PostForm submits data as a application/x-www-form-urlencoded POST to
	// path and returns the response body. NEVER retried on a dropped
	// connection (dossier §6.4): a write's connection dropping mid-flight
	// does not prove the switch ignored it.
	PostForm(ctx context.Context, path string, data map[string]string) (string, error)
	// PostMultipart submits data plus file as a multipart/form-data POST to
	// path (the SSL-certificate upload flow). NEVER retried, same rationale
	// as PostForm.
	PostMultipart(ctx context.Context, path string, data map[string]string, file MultipartFile) (string, error)
	// PostXML submits body as a raw "application/xml; charset=utf-8" POST to
	// path (the gs728tpp GOAHEAD_XML dialect's only write mechanism). NEVER
	// retried, same rationale as PostForm.
	PostXML(ctx context.Context, path string, body string) (string, error)
}

// HTTPSysInfo is GS110EMX sysInfo.html / GS105PE switch_info.cgi's device
// identity + management-IP config, mirroring Python types.HttpSysInfo
// (source lines 190-201, dossier §5.2). GROUNDED in
// testdata/http/gs110emx_sysinfo.html (a real capture) -- see
// ParseSysInfo/ParseGS105PESysInfo.
//
// IPMode is inferred from the page's own DHCP-vs-static indicator (a
// `<tr data-select-value="N">` on GS110EMX, a `<select id="dhcpMode">` on
// GS105PE); see each parser's own doc comment. CAVEAT (GS110EMX only): only
// the STATIC-IP branch was directly observed in the one real capture that
// exists -- the DHCP branch is inferred from the same <select>'s option
// ordering, not itself captured from a real DHCP-configured device. Treat it
// as plausible-but-unverified even though this model's
// HTTPModelSpec.ReadsVerified is true for its grounded surface overall.
type HTTPSysInfo struct {
	ProductName     string
	SwitchName      string
	SerialNumber    string
	MacAddress      string
	FirmwareVersion string
	IPMode          model.IPMode
	IPAddress       string
	SubnetMask      string
	GatewayAddress  string
}

// XuiRow is one repeating row of a FASTPATH "XE"/Cheetah XUI list page,
// mirroring Python types.XuiRow (source lines 118-144, dossier §5.3). These
// pages (portsConfiguration.html, poeInterfaceConfiguration.html,
// basicAddressTable.html ...) render every cell as a hidden input whose NAME
// is "<unit>.<row0>.<count>.v_1_2_<column>" -- e.g. "1.35.52.v_1_2_6" is
// column 6 of the 36th row of a 52-row table on unit 1. Prefix is that
// "<unit>.<row0>.<count>." string, taken verbatim from the device (never
// computed from the port number: the row order is the device's, and the
// count is the rendered row count, not the model's port count -- the PoE
// page of a 52-port switch has 48 rows).
//
// Checkbox is the row's own "gecb*" selector, whose name differs per
// firmware ("1.0.52.gecb5" on gsm7252ps, "1.0.52.gecb10" on gsm7228ps,
// "1.0.24.gecb_1_2" on the M4300s) -- so it is scraped, not constructed. nil
// means the parser found no checkbox with this row's prefix.
type XuiRow struct {
	Prefix   string
	Checkbox *string
	Fields   map[string]string
}

// Field returns this row's value for column (e.g. "v_1_2_6"), mirroring
// Python XuiRow.field: ok=false when the row does not render that column at
// all (Python returns None), distinct from a rendered-but-empty value.
func (r XuiRow) Field(column string) (string, bool) {
	v, ok := r.Fields[r.Prefix+column]
	return v, ok
}

// XuiListPage is one render of a FASTPATH XUI *list* page (a table of
// XuiRow), mirroring Python types.XuiListPage (source lines 147-183, dossier
// §5.3). Action is the <FORM ACTION=...> of the page's SECOND form -- the
// write form ("<page>.html/a1"); the first ("/a0") is the applet/redirect
// form and carries no data. Hidden is that form's trailing "redirection
// elements" block (submit_flag/submit_target/err_flag/err_msg/
// clazz_information), echoed back on every POST. Buttons maps the page's
// button fields to their rendered labels ("v_2_1_2" -> "APPLY"); the
// firmware's own xuiProcessButtonActions ENABLES the clicked button's hidden
// input before submitting, so the POST carries it.
//
// Tokens is the form's page-level NON-DATA fields -- in practice the
// per-page CSRFToken the AV-era M4300-16X firmware issues, carried into
// every apply because that firmware answers 403 Forbidden to a POST that
// drops it.
//
// Nav is the page's list-NAVIGATION block: the v_* fields the firmware
// renders in its class=deftestme navigation rows above and below the table
// (the "Go To Port" bar), which scope the list -- e.g. v_1_1_1="1"/
// v_1_3_1="1" plus the interface-type filter v_1_1_2="^Physical$". They are
// ENABLED hidden inputs, so a browser submits them on every apply -- and on
// the GSM7252PS PoE page the firmware REQUIRES one of these to resolve the
// row at all (see forms.go's XuiRowApplyForm).
// Template is the page's blank "v_g_<table>_<tr>_<col>" TEMPLATE row, keyed
// by its FULL field name, mirroring Python XuiListPage.template. This is
// the row an ADD fills in: the firmware renders it with every value empty
// inside display:none cells, and the page's Apply button writes the
// row-status into it. Empty for a page that renders no template row --
// which is most of them, and is why this is a separate field rather than
// being folded into Rows: a one-row apply must never mention it (see
// XuiRowApplyForm, which deliberately never reads this field).
type XuiListPage struct {
	Action   string
	Hidden   map[string]string
	Buttons  map[string]string
	Rows     []XuiRow
	Tokens   map[string]string
	Nav      map[string]string
	Template map[string]string
}

// RowFor returns the row whose column renders value (e.g. the ifName cell),
// mirroring Python XuiListPage.row_for. ok=false if no row matches.
func (p XuiListPage) RowFor(column, value string) (XuiRow, bool) {
	for _, r := range p.Rows {
		if v, ok := r.Field(column); ok && v == value {
			return r, true
		}
	}
	return XuiRow{}, false
}

// XuiFormPage is one render of a FASTPATH XUI *detail* page (flat
// v_<a>_<b>_<c> fields, non-repeating), mirroring Python types.XuiFormPage
// (source lines 186-201, dossier §5.3). Same second-form/Hidden/Buttons
// shape as XuiListPage, but Fields is not row-repeating -- ipConfiguration.html
// and the M4300's mgmtVlanIpv4Configuration.html are of this kind. Fields is
// every named input the form rendered, verbatim, so a re-POST can echo the
// device's own body (the M4300-16X refuses a POST that drops its per-page
// CSRFToken, which lives in exactly this map).
type XuiFormPage struct {
	Action  string
	Hidden  map[string]string
	Buttons map[string]string
	Fields  map[string]string
}

// errHTTP wraps model.ErrHTTP with a formatted message -- the general
// HTTP-protocol-error shape used by forms.go's echo-back builders for a
// caller-usage mistake (e.g. a column/button the page never rendered),
// mirroring Python's uncaught KeyError there. Contrast errUnexpectedPage
// (parse_standard.go), which wraps the more specific
// model.ErrHTTPUnexpectedPage for "the wrong page came back".
func errHTTP(format string, a ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, a...), model.ErrHTTP)
}
