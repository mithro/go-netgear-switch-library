package webui

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
)

// Ported field-for-field from src/netgear_switch/protocols/http/endpoints.py
// (pure data: LoginScheme, HTMLDialect, HTTPModelSpec, HTTP_SPECS, http_spec)
// at pin 1841111. Field mapping notes (Python -> Go):
//
//   - Every `str | None` field on the Python HTTPModelSpec dataclass becomes
//     a plain Go string, with "" standing in for Python's None -- exactly
//     the same convention model.SwitchModel.SNMPVendorBase already uses.
//     None of these fields (URL/query paths, form field names) can
//     legitimately be the empty string, so "" is an unambiguous sentinel.
//     CookieName is the one field where "" is a *meaningful* spec value
//     (not "unset" but "this model uses a token session instead") -- see
//     its doc comment.
//   - `XuiMgmtIPFields | None` becomes *XuiMgmtIPFields (nil = Python None):
//     unlike the string fields, a zero-value XuiMgmtIPFields (all "") would
//     be indistinguishable from "not configured" if this were a plain
//     struct field, so it stays a pointer.
//   - `int | None` (WebPort) becomes *int for the same reason (0 is not
//     "unset", 49152 is; nil is the only unambiguous "not set" value).
//   - `Mapping[str, str]` (CertUploadFormFields), defaulted via
//     `default_factory=lambda: MappingProxyType({})` to dodge a Python
//     3.11 dataclass-mutable-default error irrelevant to Go, becomes a
//     plain map[string]string. Every HTTPModelSpec value in this file is a
//     package-level var populated once and never mutated after init --
//     treat every map/pointer field as read-only, exactly as the Python
//     frozen dataclass + MappingProxyType enforce at runtime there.
//
// SOURCE DISCREPANCIES vs the D-HTTP-P §1 dossier (source wins; see
// task-1-report.md for detail):
//   - HTMLDialect has 7 members, not 6: the dossier's own enum listing
//     (and prose) includes S3300 ("s3300", used by gsm7228ps) alongside the
//     6 the section header claims.
//   - HTTPModelSpec has 36 fields, not 34: a literal field-by-field count
//     of the dataclass (dossier's own §1.4 code block) totals 36.
//   - gsm7228ps's cert_upload_form_fields has 22 entries, not the "19-key"
//     the dossier's §1.5 prose claims; the transcribed table below has all
//     22, copied verbatim from source lines 567-590.

// LoginScheme is which of the five known Netgear web-UI login handshakes a
// model uses, mirroring Python protocols.http.endpoints.LoginScheme. See
// each constant's doc comment for the exact wire flow (dossier §1.1).
type LoginScheme string

const (
	// LoginSchemeMergeHashCGI is the Plus SID scheme (gs305ep, gs105pe) --
	// GROUNDED. GET login_path to scrape a `rand` nonce, POST
	// {password_field: MergeHashMD5(password, rand)} back to login_path,
	// success sets the CookieName cookie.
	LoginSchemeMergeHashCGI LoginScheme = "merge_hash_cgi"
	// LoginSchemeGambit is the EMx merge-hash + token scheme (gs110emx) --
	// GROUNDED. GET login_path (NOT the POST target) for `rand`, POST
	// {password_field: MergeHashMD5(password, rand)} to login_post_path;
	// success returns a Gambit TOKEN (SessionTokenField), never a cookie --
	// CookieName is "" (unused) for every LoginSchemeGambit model.
	LoginSchemeGambit LoginScheme = "gambit"
	// LoginSchemeCheetahForm is the Pro/S3300/gsm7252ps plaintext form
	// scheme: POST {password_field: password[, username_field: username]}
	// directly to login_path (NeedsRand is always false), success sets the
	// CookieName cookie. No GET-for-nonce step.
	LoginSchemeCheetahForm LoginScheme = "cheetah_form"
	// LoginSchemeCheetahV1 is the M4300 /v1 scheme: GET login_path (scrapes
	// an optional CSRFToken), POST {username_field: username,
	// password_field: password[, CSRFToken: token]} to login_post_path --
	// plaintext, NeedsRand is always false. Every model using this scheme
	// sets NeedsReferer true.
	LoginSchemeCheetahV1 LoginScheme = "cheetah_v1"
	// LoginSchemeXMLAPI is the GS728TPP GoAhead XML API: a three-step
	// handshake (GET / for a 302 session-path redirect, GET a login query
	// under that session path, then a sessionID response header + a body
	// containing "<statusCode>0</statusCode>" -- never a Set-Cookie). Not a
	// form POST at all; see dossier §1.1 for the full flow.
	LoginSchemeXMLAPI LoginScheme = "xml_api"
)

// HTMLDialect is which family of HTML (or, for HTMLDialectGoAheadXML, XML)
// a model's read pages are written in, selecting the whole parser set the
// reader uses for ports/stats/PVIDs/VLAN-list, mirroring Python
// protocols.http.endpoints.HTMLDialect. Defaults to HTMLDialectStandard.
type HTMLDialect string

const (
	// HTMLDialectStandard is the gs305ep CGI shape: closed
	// `<tr class="portID">...</tr>` rows, `vlanckN` VLAN checkboxes.
	HTMLDialectStandard HTMLDialect = "standard"
	// HTMLDialectGS110EMX is the real GS110EMX firmware shape: portID rows
	// that never close (cut at the next `<tr` or `</table>` instead), VLANs
	// listed as `<tr class="vlanID tableTr">` rows (Advanced 802.1Q).
	HTMLDialectGS110EMX HTMLDialect = "gs110emx"
	// HTMLDialectGS105PE is the real GS105PE status.cgi layout: its own
	// open-row shape (subtly different from GS110EMX's) and counters
	// carried in HIDDEN 32-bit half-pair inputs, not visible <td> text.
	HTMLDialectGS105PE HTMLDialect = "gs105pe"
	// HTMLDialectM4300 is the real M4300 Cheetah /v1 shape: FASTPATH hidden
	// inputs named `<unit>.<row>.<count>.v_<a>_<b>_<c>`, each followed by a
	// `<!-- field_name -->` comment naming the cell semantically -- cells
	// address BY NAME, immune to column reorder.
	HTMLDialectM4300 HTMLDialect = "m4300"
	// HTMLDialectXEFastpath is the "auto-generated by XE" FASTPATH shape
	// (gsm7252ps): the same hidden-input cells as HTMLDialectM4300 but with
	// NO field-name comment, so cells address ONLY by numeric column
	// coordinate, scraped/hardcoded per page.
	HTMLDialectXEFastpath HTMLDialect = "xe_fastpath"
	// HTMLDialectS3300 (gsm7228ps) reuses every XE-FASTPATH parser except
	// three model-specific pages: shifted MAC-table columns with escaped
	// "1/gN"/"1/xgN" ifNames, a sysInfo page carrying only the base MAC
	// (IPv4 config lives on a separate mgmt-IP page instead), and no live
	// fan/temp sensor table (get_sensors unsupported over HTTP).
	HTMLDialectS3300 HTMLDialect = "s3300"
	// HTMLDialectGoAheadXML (gs728tpp) is the only dialect that is not
	// HTML-scraping at all: a real (if hand-sliced) XML parse of the wcd
	// DeviceConfiguration data block.
	HTMLDialectGoAheadXML HTMLDialect = "goahead_xml"
)

// XuiMgmtIPFields names which fields of a FASTPATH XUI management-IP page
// carry address/mask/gateway/method/apply, mirroring Python
// protocols.http.endpoints.XuiMgmtIPFields. Deliberately PER MODEL, never
// shared by dialect: the two Cheetah families (GSM72xx vs M4300) put this
// information on different pages under different field names, and one
// field NAME that looks shared can mean something different on two boxes
// of the same family (see mgmtIPFieldsGSM72xx's Mode comment).
type XuiMgmtIPFields struct {
	Address string
	Netmask string
	Gateway string
	// Mode is the field carrying the addressing METHOD; StaticValue and
	// DHCPValue are the two values it takes.
	Mode        string
	StaticValue string
	DHCPValue   string
	// ApplyButton is the page's APPLY button field name. Its VALUE is read
	// off the page at write time, since the button label text differs
	// between families ("APPLY" vs "Apply").
	ApplyButton string
}

// mgmtIPFieldsGSM72xx is shared by gsm7252ps and gsm7228ps's
// /ipConfiguration.html page (dossier §1.3 / source lines 179-187).
var mgmtIPFieldsGSM72xx = XuiMgmtIPFields{
	Address: "v_1_1_1",
	Netmask: "v_1_2_1",
	Gateway: "v_1_3_1",
	// Mode is the HIDDEN twin of the visible radio (v_1_8_1 on gsm7252ps,
	// v_1_4_1 on gsm7228ps -- same name, different meaning per box, so only
	// the hidden one is used).
	Mode:        "v_1_18_1", // allWebEnums e_v_1_18_1 = ["None","Bootp","DHCP"]
	StaticValue: "None",
	DHCPValue:   "DHCP",
	ApplyButton: "v_3_1_1",
}

// mgmtIPFieldsM4300 is shared by both M4300 SKUs'
// /v1/mgmtVlanIpv4Configuration.html page (dossier §1.3 / source lines
// 188-196).
var mgmtIPFieldsM4300 = XuiMgmtIPFields{
	Address:     "v_1_6_1",
	Netmask:     "v_1_7_1",
	Gateway:     "v_1_71_1",
	Mode:        "v_1_5_3", // xeData["xew_1_5_3_Enable"] = "DHCP" (page's own JS)
	StaticValue: "Disable", // xew_1_5_3_Disable = "Manual"
	DHCPValue:   "Enable",  // xew_1_5_3_Enable = "DHCP"
	ApplyButton: "v_3_1_1",
}

// HTTPModelSpec records how one model logs in and which page each read/
// write op uses, mirroring Python protocols.http.endpoints.HTTPModelSpec
// (all 36 fields -- see the SOURCE DISCREPANCIES note above; the dossier's
// "34" is wrong). SchemeVerified/ReadsVerified mark whether that model's
// flows are grounded in captured prior art or still
// UNVERIFIED-pending-capture; see HTTPSpecs's per-model vars for the
// grounding citation each one carries.
type HTTPModelSpec struct {
	ModelKey       string
	Scheme         LoginScheme
	SchemeVerified bool
	LoginPath      string
	PasswordField  string
	// CookieName is the auth cookie name the client must see after login
	// for a cookie-session model. "" means this model uses a TOKEN session
	// instead (see SessionTokenField) -- the two are mutually exclusive.
	// Only LoginSchemeGambit (gs110emx) uses a token session; every other
	// model uses a cookie.
	CookieName string
	NeedsRand  bool

	DashboardPath      string
	StatsPath          string
	PoEConfigPath      string
	PoEStatusPath      string
	VlanConfigPath     string
	VlanMembershipPath string
	PvidPath           string
	RebootPath         string
	LogoutPath         string

	// IsEPXPoE is true only for gs305ep -- feeds the PoE apply form's
	// POW_LIMT_TYP field ("2" when true, "0" otherwise).
	IsEPXPoE bool
	// ReadsVerified gates whether the reader may be constructed at all for
	// this model (the "honesty gate": a model whose read parsers have not
	// been live cross-verified stays refused rather than silently
	// returning unverified data).
	ReadsVerified bool

	// SessionTokenField is the form/query-param NAME the session token is
	// carried under on every request once the login POST response has
	// yielded one (e.g. "Gambit" for LoginSchemeGambit). "" means this
	// model uses the cookie session instead -- see CookieName.
	SessionTokenField string
	// LoginPostPath is the login POST target, when it differs from
	// LoginPath (the GET page the rand nonce/login form is scraped from).
	// "" means POST goes to LoginPath itself (gs305ep, gs105pe, gsm7228ps,
	// gsm7252ps); gs110emx GETs "/" for the nonce but POSTs to
	// "/redirect.html", and the M4300s GET "/" but POST to
	// "/v1/base/cheetah_login.html".
	LoginPostPath string
	// SysinfoPath is the device identity + management-IP config page. ""
	// means this model has no such HTTP page (gs305ep/gs110emx read
	// mgmt-IP, if at all, via a different path -- see MgmtIPPath).
	SysinfoPath string
	// MgmtIPPath is a dedicated management-IP query, for a model whose
	// mgmt-IP lives on a DIFFERENT page than SysinfoPath (set for
	// gsm7228ps, gsm7252ps, both M4300 SKUs, and gs728tpp). "" means
	// mgmt-IP is read from SysinfoPath (every other model), or is
	// unsupported when that is "" too (gs305ep).
	MgmtIPPath string
	// HTMLDialect selects the ports/stats/PVID/VLAN-list parser set --
	// see HTMLDialect. Every HTTPModelSpec value in this file sets this
	// explicitly (Go has no dataclass-style default; the Python default is
	// HTMLDialectStandard).
	HTMLDialect HTMLDialect
	// MacTablePath is the MAC/FDB table page. "" = this model exposes no
	// FDB over HTTP (every Plus switch except the M4300s; only the managed
	// FASTPATH/Cheetah UIs have one).
	MacTablePath string
	// UsernameField is the username field name for schemes that need one
	// (M4300 /v1 and the Cheetah-form models post both uname and pwd; the
	// GoAhead XML API posts "user"). "" = password-only login.
	UsernameField string
	// Username is the default username sent alongside UsernameField.
	// Mirrors Python's `username: str = "admin"` default -- every spec
	// below sets it explicitly to "admin" where UsernameField is set.
	Username string
	// NeedsReferer reports whether every request must carry a
	// `Referer: <scheme>://<host>/` header. The M4300 /v1 UI answers 403 to
	// any request without it (a CSRF guard).
	NeedsReferer bool
	// LLDPPath is the LLDP neighbour table page. "" = this model's web UI
	// exposes no LLDP neighbour data.
	LLDPPath string

	// CertUploadPath is the HTTPS SSL-certificate upload target (multipart
	// POST for the FASTPATH/S3300 form, or a raw XML POST endpoint for
	// LoginSchemeXMLAPI -- see CertUploadFileField). "" = this model
	// exposes no cert-upload flow through this library.
	CertUploadPath string
	// CertUploadFileField is the multipart file field name (e.g.
	// ".v_1_3_1_handle" for gsm7228ps). "" for a model with no multipart
	// file part (gs728tpp's XML upload) or no upload flow at all.
	CertUploadFileField string
	// CertUploadFormFields are the fixed hidden form fields the upload page
	// submits alongside the file part. Never nil; empty for a model with
	// no multipart cert-upload flow. Treat as read-only -- see the package
	// doc comment.
	CertUploadFormFields map[string]string

	// Secure is true when this model's web UI is HTTPS (self-signed cert --
	// the facade leaves TLS verification off). false (the default) = plain
	// http://. Only m4300-16x sets this.
	Secure bool
	// VlanMembershipPostPath is the POST target of the VLAN-membership
	// form, when it differs from the GET page in VlanMembershipPath
	// (mirrors LoginPostPath). "" means the page POSTs back to itself
	// (every Plus-class model: 8021qMembe.cgi, vlanMembership.html).
	VlanMembershipPostPath string
	// WebPort is a non-standard web-UI TCP port. nil (the default) = the
	// URL's implicit 80/443. Only m4300-16x sets this (49152).
	WebPort *int
	// PortConfigPath is the per-port ADMIN-MODE write page (set_port_
	// enabled). On every FASTPATH model this is the same page the reader
	// scrapes for port status (DashboardPath), but it is a SEPARATE field
	// on purpose: "the page I read status from" and "the page I write
	// admin mode to" are different questions. "" = not discovered for this
	// model.
	PortConfigPath string
	// MgmtIPFields names which fields of MgmtIPPath carry
	// address/mask/gateway/method, for a model whose mgmt-IP page is a
	// FASTPATH XUI form. nil for the Plus/GoAhead models, whose mgmt-IP
	// pages are a different shape entirely.
	MgmtIPFields *XuiMgmtIPFields
}

// Shared FASTPATH/XUI path fragments, mirroring the Python module-level
// string constants they are transcribed from (source lines 341-356).
// Deliberately NOT per-model literals where the source isn't: the same
// relative path was confirmed live on every SKU that uses it, so a
// divergence would be a real finding, not a typo.
const (
	fastpathVlanMembership   = "/switching/dot1q/vlan_port_cfg.html"
	fastpathVlanMembershipRW = "/switching/dot1q/vlan_port_cfg_rw.html"
	m4300VlanMembership      = "/v1" + fastpathVlanMembership
	m4300VlanMembershipRW    = "/v1" + fastpathVlanMembershipRW
	fastpathPortConfig       = "/portsConfiguration.html"
	fastpathPoEConfig        = "/poeInterfaceConfiguration.html"
	gsm72xxMgmtIPPath        = "/ipConfiguration.html"
	m4300MgmtIPPath          = "/v1/mgmtVlanIpv4Configuration.html"
	m4300PortConfigPath      = "/v1" + fastpathPortConfig
	m4300PoEConfigPath       = "/v1" + fastpathPoEConfig
)

func intPtr(v int) *int { return &v }

// gs305epSpec: GROUNDED in py_netgear_plus/models.py (GS30xSeries /
// GS30xEPxSeries: CRYPT_FUNCTION="merge_hash", LOGIN_TEMPLATE, PoE/VLAN CGI
// paths) and rcfiles/bin/netgear-smp-vlan (identical merge-hash login
// observed on GS105PE; 8021qCf.cgi/8021qMembe.cgi/portPVID.cgi field shapes
// and 1=Untagged/2=Tagged/3=Excluded membership wire codes). Both
// SchemeVerified and ReadsVerified are true.
//
// SysinfoPath is deliberately still "" -- copying gs105pe's
// /switch_info.cgi here was tried and rejected: the fleet units were all
// powered off during the capture session, so it was never confirmed live
// (source lines 359-395).
var gs305epSpec = HTTPModelSpec{
	ModelKey:       "gs305ep",
	Scheme:         LoginSchemeMergeHashCGI,
	SchemeVerified: true,
	LoginPath:      "/login.cgi",
	PasswordField:  "password",
	CookieName:     "SID",
	NeedsRand:      true,

	DashboardPath:      "/dashboard.cgi",
	StatsPath:          "/portStatistics.cgi",
	PoEConfigPath:      "/PoEPortConfig.cgi",
	PoEStatusPath:      "/getPoePortStatus.cgi",
	VlanConfigPath:     "/8021qCf.cgi",
	VlanMembershipPath: "/8021qMembe.cgi",
	PvidPath:           "/portPVID.cgi",
	RebootPath:         "/device_reboot.cgi",
	LogoutPath:         "/logout.cgi",

	IsEPXPoE:      true,
	ReadsVerified: true,
	HTMLDialect:   HTMLDialectStandard,
	Username:      "admin",
}

// gs110emxSpec: GROUNDED in real captures from a physical GS110EMX
// (tests/fixtures/http/gs110emx_*.html) plus live 2026-07-21/07-30/07-31
// discovery on 10.1.5.25 (fw 1.0.2.8). HTTP covers the FULL NSDP read
// surface here: an earlier probe guessed /iss/specific/{vlan,port,pvid}.html,
// got 404s and WRONGLY concluded "NSDP-only" -- the real URLs live only as
// JS string literals in /frame.js and were harvested live (source lines
// 397-497).
//
// ReadsVerified=true caveat: only VLAN 1's membership page was captured;
// the DHCP branch of sysInfo parsing is inferred, not captured.
// mac_table_path/lldp_path/poe_*_path stay "" -- ENUMERATED absent (39
// harvested page literals contain none of them; plausible-name probes
// 404'd; the NSDP tag sweep found no such tag either).
var gs110emxSpec = HTTPModelSpec{
	ModelKey:       "gs110emx",
	Scheme:         LoginSchemeGambit,
	SchemeVerified: true,
	LoginPath:      "/",
	LoginPostPath:  "/redirect.html",
	PasswordField:  "LoginPassword",
	CookieName:     "", // unused: token session (see SessionTokenField)
	NeedsRand:      true,

	DashboardPath: "/iss/specific/port_settings.html",
	// Same page, but a genuinely different write mechanism from the
	// FASTPATH grid: gs110emx has no admin column, so an admin change is
	// its "Physical Mode" select (PORT_CTRL_MODE). LIVE-VERIFIED
	// 2026-07-31 on 10.1.5.25.
	PortConfigPath: "/iss/specific/port_settings.html",
	StatsPath:      "/iss/specific/interface_stats.html",
	SysinfoPath:    "/iss/specific/sysInfo.html",
	// poe_config_path / poe_status_path: confirmed 404 -- no PoE on this
	// model.
	VlanConfigPath:     "/iss/specific/Cf8021q.html",
	VlanMembershipPath: "/iss/specific/vlanMembership.html",
	PvidPath:           "/iss/specific/vlan_pvidsetting.html",
	// LIVE-DISCOVERED 2026-07-31, by harvesting the firmware's own page
	// literals rather than guessing (see source comment lines 471-480).
	RebootPath: "/iss/specific/sys_reload.html",
	LogoutPath: "/iss/specific/logout.html",

	IsEPXPoE:          false,
	ReadsVerified:     true,
	SessionTokenField: "Gambit",
	HTMLDialect:       HTMLDialectGS110EMX,
}

// gsm7228psSpec (S3300-52X-PoE+): login GROUNDED in
// certbot-hook-netgear-switches/netgear-updater.py (S3300Updater). Read
// pages LIVE-VERIFIED on the real S3300-52X (10.1.5.11, 2026-07-30):
// ports/stats/PVIDs/VLANs/PoE/LLDP EQUAL SNMP exactly (52/5/52/48/52/2).
// MgmtIPPath is a 1841111 CORRECTION -- this spec used to claim the IPv4
// address was on an "unreachable JS-menu-only page"; that was wrong (source
// lines 499-592).
var gsm7228psSpec = HTTPModelSpec{
	ModelKey:       "gsm7228ps",
	Scheme:         LoginSchemeCheetahForm,
	SchemeVerified: true,
	LoginPath:      "/base/cheetah_login.html",
	PasswordField:  "pwd",
	UsernameField:  "uname",
	Username:       "admin",
	CookieName:     "SID",
	NeedsRand:      false,

	DashboardPath:  "/portsConfiguration.html",
	PortConfigPath: fastpathPortConfig,
	StatsPath:      "/portStatistics.html",
	SysinfoPath:    "/base/system/management/sysInfo.html",
	MgmtIPPath:     gsm72xxMgmtIPPath, // CORRECTED 2026-07-30
	MgmtIPFields:   &mgmtIPFieldsGSM72xx,
	MacTablePath:   "/basicAddressTable.html",
	LLDPPath:       "/lldpRemoteInventory.html",
	PoEConfigPath:  "/poeInterfaceConfiguration.html",
	PoEStatusPath:  "/poeInterfaceConfiguration.html",
	VlanConfigPath: "/vlanStatus.html",
	// LIVE-DISCOVERED 2026-07-30: a leaf of the firmware's own JS nav tree
	// (GET /base/js/ng_sideNav.js), not one of the fifteen plausible
	// FASTPATH names that all 404'd.
	VlanMembershipPath:     fastpathVlanMembership,
	VlanMembershipPostPath: fastpathVlanMembershipRW,
	PvidPath:               "/portPvidConfiguration.html",
	// reboot_path / logout_path: never captured, not guessed -- stay "".

	IsEPXPoE:      false,
	ReadsVerified: true,
	HTMLDialect:   HTMLDialectS3300,

	// HTTPS SSL-cert upload IS grounded even though reads are not: copied
	// field-for-field from S3300Updater.upload_certificate (source lines
	// 559-591). All 22 keys transcribed verbatim (the dossier's "19-key"
	// claim undercounts them).
	CertUploadPath:      "/http_file_download.html/a1",
	CertUploadFileField: ".v_1_3_1_handle",
	CertUploadFormFields: map[string]string{
		"v_1_1_3":           "HTTP",
		"v_1_1_2":           "SSL Server Certificate PEM File",
		"v_1_2_1":           "",
		"v_1_3_2":           " not in progress",
		"v_1_3_3":           "",
		"v_1_3_4":           "",
		"v_1_9_1":           "image1",
		"v_1_9_5":           "",
		"v_1_9_2":           "1",
		"v_1_9_3":           "Enable",
		"v_1_19_1":          "32",
		"v_1_20_1":          "",
		"v_1_200_1":         "",
		"v_2_3_1":           " not in progress",
		"v_2_4_3":           "None",
		"v_2_4_2":           " not in progress",
		"v_4_1_1":           "",
		"submit_flag":       "8",
		"submit_target":     "http_file_download.html",
		"err_flag":          "0",
		"err_msg":           "",
		"clazz_information": "http_file_download.html",
	},
}

// gs105peSpec: LIVE-VERIFIED 2026-07-21 on real units (10.1.5.29/.30). The
// login scheme is BYTE-IDENTICAL to gs305ep's, but the READ paths are NOT
// gs305ep's -- those copies were PARTLY WRONG on real hardware
// (dashboard.cgi and getPoePortStatus.cgi both 404) (source lines 594-630).
var gs105peSpec = HTTPModelSpec{
	ModelKey:       "gs105pe",
	Scheme:         LoginSchemeMergeHashCGI,
	SchemeVerified: true,
	LoginPath:      "/login.cgi",
	PasswordField:  "password",
	CookieName:     "SID",
	NeedsRand:      true,

	DashboardPath: "/status.cgi", // NOT dashboard.cgi
	StatsPath:     "/portStatistics.cgi",
	SysinfoPath:   "/switch_info.cgi",
	// poe_config_path / poe_status_path: CONFIRMED 404 -- PoE
	// pass-through, not a PSE (matches poe_port_count=0 in the registry).
	VlanConfigPath:     "/8021qCf.cgi",
	VlanMembershipPath: "/8021qMembe.cgi",
	PvidPath:           "/portPVID.cgi",
	RebootPath:         "/device_reboot.cgi",
	LogoutPath:         "/logout.cgi",

	IsEPXPoE:      false,
	ReadsVerified: true,
	HTMLDialect:   HTMLDialectGS105PE,
	Username:      "admin",
}

// m430024xSpec: LIVE-VERIFIED 2026-07-21/07-30/07-31 against a real
// M4300-24X (10.1.5.13). URLs recovered by harvesting SetLinkPage('<page>')
// handlers from a real browser session (the Cheetah /v1 menu is built at
// runtime in JS). LLDPPath is a 1841111 CORRECTION -- was "" with a claim of
// "no chassis/port-id table available"; wrong, see below (source lines
// 632-720).
var m430024xSpec = HTTPModelSpec{
	ModelKey:       "m4300-24x",
	Scheme:         LoginSchemeCheetahV1,
	SchemeVerified: true,
	LoginPath:      "/",
	LoginPostPath:  "/v1/base/cheetah_login.html",
	PasswordField:  "pwd",
	UsernameField:  "uname",
	Username:       "admin",
	CookieName:     "SID",
	NeedsRand:      false,
	NeedsReferer:   true,

	DashboardPath:  "/v1/portsConfiguration.html",
	PortConfigPath: m4300PortConfigPath,
	StatsPath:      "/v1/portStatistics.html",
	SysinfoPath:    "/v1/base/system/management/sysInfo.html",
	// LIVE-MEASURED 2026-07-30 on BOTH M4300 SKUs: the management address
	// is on the MANAGEMENT-VLAN page, not the (unused, 0.0.0.0/0.0.0.0)
	// network-interface page -- see mgmtIPFieldsM4300's doc comment.
	MgmtIPPath:   m4300MgmtIPPath,
	MgmtIPFields: &mgmtIPFieldsM4300,
	MacTablePath: "/v1/basicAddressTable.html",
	// CORRECTION, live 2026-07-31 on BOTH SKUs: the real neighbour page is
	// the SAME lldpRemoteInventory.html the XE models use, found by reading
	// the firmware's own nav tree (GET /v1/base/js/ng_sideNav.js) instead
	// of guessing. parse_xe_lldp reads it EXACTLY equal to SNMP (11/11
	// neighbours).
	LLDPPath: "/v1/lldpRemoteInventory.html",
	// poe_config_path / poe_status_path: LIVE-MEASURED 2026-07-30 -- the
	// 24X genuinely has no PoE (a 200 with the full button set and ZERO
	// <TR p=...> rows, not a 404).
	VlanConfigPath: "/v1/vlanStatus.html",
	// LIVE-DISCOVERED 2026-07-30 -- see fastpathVlanMembership.
	VlanMembershipPath:     m4300VlanMembership,
	VlanMembershipPostPath: m4300VlanMembershipRW,
	PvidPath:               "/v1/portPvidConfiguration.html",
	// reboot_path / logout_path: never captured -- stay "".

	IsEPXPoE:      false,
	ReadsVerified: true,
	HTMLDialect:   HTMLDialectM4300,
}

// m430016xSpec is INHERITED, NOT INDEPENDENTLY CAPTURED, mirroring Python's
// dataclasses.replace(_M4300, ...) (source lines 722-762): the M4300-16X
// runs the same FASTPATH firmware image and Cheetah /v1 web UI as the 24X,
// so the login scheme and page URLs carry over verbatim. Only the fields
// listed in the initializer below are overridden; every other field is a
// straight copy of m430024xSpec. Its PoE fields and ReadsVerified ARE
// independently live-verified on the real unit (10.1.5.20:49152): the real
// 16X Cheetah "Main UI" is HTTPS on :49152 (the AV-era two-UI firmware moves
// it off port 80), so Secure/WebPort/CookieName all diverge from the 24X.
var m430016xSpec = func() HTTPModelSpec {
	s := m430024xSpec
	s.ModelKey = "m4300-16x"
	// LIVE cross-verified 2026-07-30 on the real M4300-16X-PoE
	// (10.1.5.20:49152): every HTTP read (ports/stats/PVIDs/VLANs/MACs/
	// mgmt-IP + PoE) matches SNMP.
	s.ReadsVerified = true
	// The HTTPS variant names its session cookie SIDSSL, not SID --
	// confirmed live.
	s.CookieName = "SIDSSL"
	// Per-port PoE: the 16X (unlike the non-PoE 24X) serves the FASTPATH
	// poeInterfaceConfiguration.html under /v1/, and it WRITES -- live-proven
	// 2026-07-30 by toggling Port Priority Low->High->Low and reading it
	// back.
	s.PoEStatusPath = m4300PoEConfigPath
	s.PoEConfigPath = m4300PoEConfigPath
	s.Secure = true
	s.WebPort = intPtr(49152)
	return s
}()

// gsm7252psSpec: LOGIN LIVE-VALIDATED against 10.1.5.22 (2026-07-22). Read
// pages at the ROOT prefix (not /base/ or /v1/), GROUNDED in real captures
// (tests/fixtures/http/gsm7252ps_*.html). PoEConfigPath is a 1841111
// CORRECTION -- was "" with a wrongly-blamed "the form refuses every write"
// note (source lines 776-856).
var gsm7252psSpec = HTTPModelSpec{
	ModelKey:       "gsm7252ps",
	Scheme:         LoginSchemeCheetahForm,
	SchemeVerified: true,
	LoginPath:      "/base/cheetah_login.html",
	PasswordField:  "pwd",
	UsernameField:  "uname",
	Username:       "admin",
	CookieName:     "SID",
	NeedsRand:      false,

	DashboardPath:  "/portsConfiguration.html",
	PortConfigPath: fastpathPortConfig,
	StatsPath:      "/portStatistics.html",
	SysinfoPath:    "/base/system/management/sysInfo.html",
	// moved off sysInfo (which lacks gateway/DHCP indicator)
	MgmtIPPath:   gsm72xxMgmtIPPath,
	MgmtIPFields: &mgmtIPFieldsGSM72xx,
	MacTablePath: "/basicAddressTable.html",
	LLDPPath:     "/lldpRemoteInventory.html",
	// NOW WRITABLE, LIVE-VERIFIED 2026-07-31 (Enable->Disable->Enable on
	// port 1/0/35, err_flag=0 each time) -- the earlier refusal was the
	// caller's bug: every write attempt omitted the page's own
	// urlListUnit scope field (v_1_1_1/v_1_3_1), which this firmware --
	// uniquely among the four managed models -- requires to resolve which
	// row is being addressed.
	PoEConfigPath:  fastpathPoEConfig,
	PoEStatusPath:  fastpathPoEConfig,
	VlanConfigPath: "/vlanStatus.html",
	// LIVE-DISCOVERED 2026-07-30 -- see fastpathVlanMembership.
	VlanMembershipPath:     fastpathVlanMembership,
	VlanMembershipPostPath: fastpathVlanMembershipRW,
	PvidPath:               "/portPvidConfiguration.html",
	// reboot_path / logout_path: never captured -- stay "".

	IsEPXPoE:      false,
	ReadsVerified: true, // live HTTP<->SNMP cross-verified 2026-07-23
	HTMLDialect:   HTMLDialectXEFastpath,
}

// gs728tppSpec: login GROUNDED in
// certbot-hook-netgear-switches/netgear-updater.py (GS728TPPUpdater) AND
// real captures (tmp/gs728tpp_ground_truth.json, 10.2.5.10). ReadsVerified
// REQUIRED a separate live cross-check against the switch's own config (not
// SNMP -- this model's SNMP OID family is itself unverified-pending-capture,
// so cross-checking HTTP against SNMP here would have proven nothing)
// (source lines 858-941).
//
// The wcd?{...} path strings themselves ARE the endpoint paths on this
// model -- they are not placeholders; the transport just prepends the
// session-path prefix in front of the literal string.
var gs728tppSpec = HTTPModelSpec{
	ModelKey:       "gs728tpp",
	Scheme:         LoginSchemeXMLAPI,
	SchemeVerified: true,
	LoginPath:      "/",
	PasswordField:  "password",
	UsernameField:  "user",
	Username:       "admin",
	CookieName:     "sessionID",
	NeedsRand:      false,

	DashboardPath: "wcd?{file=/Switching/Ports/portConfiguration_master_jq.htm}{Standard802_3List}",
	// per-port stats unreachable (behind unresolvable JS nav on this UI);
	// get_stats raises UnsupportedCapabilityError, SNMP is the source.
	StatsPath: "",
	SysinfoPath: "wcd?{file=/System/Management/SystemInfo_master_745.xml}" +
		"{DeviceBasicInfo}{TimeSetting}{DiagnosticsUnitList}",
	MgmtIPPath: "wcd?{file=/System/Management/IPConf_master.xml}" +
		"{IPv4InterfaceList}{IPv4GatewayList}",
	// poe_config_path: "" (no HTTP write flow for PoE on this model).
	PoEStatusPath:  "wcd?{file=/System/PoE/PoeInterfaceConf_master.xml}{PoEPSEInterfaceList}",
	VlanConfigPath: "wcd?{file=/Switching/VLAN/VlanConfBasic_master.xml}{VLANList}",
	// VLAN membership is derived from the per-port JoinVLANList carried
	// inline in the PVID page -- no separate membership request needed.
	VlanMembershipPath: "",
	PvidPath:           "wcd?{file=/Switching/VLAN/PortPvidConf_master_745.xml}{VLANInterfaceList}",
	MacTablePath: "wcd?{file=/Switching/Address Table/DynamicAddresses_master.xml}" +
		"{ForwardingTable}",
	LLDPPath: "wcd?{file=/System/LLDP/NeighborsInformation_master.xml}{LLDPMEDNeighborList}",
	// reboot_path / logout_path: "".

	IsEPXPoE: false,
	// A raw XML POST (SSLCryptoCertificateImportList body to the
	// session-path-prefixed wcd endpoint), NOT the gsm7228ps multipart
	// form -- CertUploadFileField stays "" (no multipart file part).
	CertUploadPath: "wcd",

	// LIVE-VERIFIED 2026-07-29 against 28 g1..g28 ports, 24 PoE ports, real
	// VLAN names, PVIDs, membership, 135 MAC entries, 4 LLDP neighbours,
	// Fan1/Fan2/PSU sensors, mgmt-IP -- all cross-checked vs the switch's
	// own known config.
	ReadsVerified: true,
	HTMLDialect:   HTMLDialectGoAheadXML,
}

// httpSpecs is the private, canonical model_key -> *HTTPModelSpec registry,
// mirroring Python's `_SPECS`. HTTPSpecs is the exported read-only view.
var httpSpecs = map[string]*HTTPModelSpec{
	gs305epSpec.ModelKey:   &gs305epSpec,
	gs110emxSpec.ModelKey:  &gs110emxSpec,
	gsm7228psSpec.ModelKey: &gsm7228psSpec,
	gs105peSpec.ModelKey:   &gs105peSpec,
	m430024xSpec.ModelKey:  &m430024xSpec,
	m430016xSpec.ModelKey:  &m430016xSpec,
	gsm7252psSpec.ModelKey: &gsm7252psSpec,
	gs728tppSpec.ModelKey:  &gs728tppSpec,
}

// HTTPSpecs is the web-UI spec registry, mirroring Python's module-level
// HTTP_SPECS mapping: model_key -> the model's HTTPModelSpec, for every one
// of the 8 models with a webui.HTTPModelSpec ("s3300", the gsm7228ps alias,
// deliberately does NOT appear as its own key here -- resolve it via
// model.GetModel first, exactly as Python's get_model() does). Every entry
// is a pointer into this package's own frozen data; treat it as read-only.
var HTTPSpecs = httpSpecs

// HTTPSpec returns the web-UI spec for m, mirroring Python
// protocols.http.endpoints.http_spec: it raises (here, returns an error
// wrapping model.ErrUnsupportedCapability) if m has no HTTP backend at all,
// or (a defensive belt-and-braces case) has the backend flag but no
// registered spec.
func HTTPSpec(m *model.SwitchModel) (*HTTPModelSpec, error) {
	if !m.HasBackend(model.BackendHTTP) {
		return nil, fmt.Errorf("model %q has no HTTP backend: %w", m.Key, model.ErrUnsupportedCapability)
	}
	spec, ok := httpSpecs[m.Key]
	if !ok {
		return nil, fmt.Errorf("model %q has an HTTP backend but no endpoint spec: %w", m.Key, model.ErrUnsupportedCapability)
	}
	return spec, nil
}
