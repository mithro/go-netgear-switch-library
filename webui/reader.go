package webui

// reader.go: model-driven web-UI read facade, ported field-for-field from
// src/netgear_switch/http_read.py at pin b26eb1f in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-b26eb1f). Any discrepancy between this file and that pin is a
// bug in this file, not a deliberate deviation, unless called out in a
// comment.
//
// Parallel to nsdp/reader.go and snmp/reader.go: maps each dialect's parsed
// HTML/XML onto the SAME shared model types (model.PortStatus/PoEStatus/
// VLANInfo/Pvid/LLDPNeighbor/MacEntry/Sensor/PortStats/MgmtIPConfig) so a
// caller sees one uniform shape regardless of backend. Reader's eleven
// Get* methods (GetPorts/GetStats/GetVLANs/GetPVIDs/GetLLDP/GetMACs/GetPoE/
// GetSensors/GetMgmtIP/GetUsers/GetServices) satisfy the root package's
// BackendReader interface verbatim -- see dispatch.go there.
//
// Python has NO separate "http_reads_supported" table distinct from
// HTTPModelSpec.ReadsVerified (dossier D-HTTP-F §1.5): NewReader gates
// construction on it, once, before any session use -- there is no per-op
// re-check after that. Ops a model's HTTP surface genuinely does not expose
// (e.g. gs110emx has no PoE) raise an error wrapping
// model.ErrUnsupportedCapability honestly rather than silently returning an
// empty slice, via requirePath's per-op ""-path check below.
//
// Message-wording note (dossier §1.6): Python's read-side "_unsupported"
// message ("model %r web UI does not expose %s") and write-side
// "_require_path" message ("model %r has no %s page in its HTTP endpoint
// spec (see protocols/http/endpoints.py for whether that is a measured
// absence or an undiscovered page)") are two DIFFERENT strings for the same
// condition. This Go port standardizes on the more informative write-side
// wording for every "no page for this op" error reached via requirePath
// (below) -- covering both the write side and the majority of reads, since
// in http_read.py those same ops ALSO route through _require_path, which
// (in that file) happens to just call _unsupported; picking the more
// informative wording for the Go equivalent avoids a bare "does not expose
// X" reading as a measured fact when the underlying gap may simply be
// undiscovered (CLAUDE.md principle 4, "no fabricated device
// limitations").
//
// Three reads -- GetSensors/GetHostname/GetMgmtIP -- are different: their
// Python counterparts (http_read.py get_sensors/get_hostname/get_mgmt_ip)
// bypass _require_path entirely and raise _unsupported(model_key, op)
// directly, with op phrases ("box sensors", "a host name field",
// "management-IP config") chosen to read naturally after "does not
// expose". Routing those same op strings through the write-style "has no
// %s page..." template (as this file used to) produced ungrammatical
// prose for the hostname case specifically ("has no a host name field
// page..."). unsupportedRead below mirrors _unsupported verbatim and is
// used ONLY at those three call sites, matching Python's own structural
// split rather than papering over it with one template.

import (
	"context"
	"fmt"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// unsupportedOp wraps model.ErrUnsupportedCapability naming modelKey and
// op, mirroring http_write.py's _require_path message shape (see the
// package-level "Message-wording note" above) rather than http_read.py's
// own (older, vaguer) _unsupported string.
func unsupportedOp(modelKey, op string) error {
	return fmt.Errorf(
		"model %q has no %s page in its HTTP endpoint spec (see webui/endpoints.go for whether that is a measured absence or an undiscovered page): %w",
		modelKey, op, model.ErrUnsupportedCapability,
	)
}

// requirePath returns path or raises unsupportedOp honestly, mirroring
// Python's _require_path (http_read.py:68-72): "" is this Go port's
// convention for Python's None (see endpoints.go's package doc comment).
func requirePath(modelKey, path, op string) (string, error) {
	if path == "" {
		return "", unsupportedOp(modelKey, op)
	}
	return path, nil
}

// unsupportedRead wraps model.ErrUnsupportedCapability naming modelKey and
// op, mirroring http_read.py's own "_unsupported" message VERBATIM
// (http_read.py:65-68, pin b26eb1f: `f"model {model_key!r} web UI does not
// expose {op}"`). Used only by GetSensors/GetHostname/GetMgmtIP, whose
// Python counterparts raise _unsupported directly rather than routing
// through _require_path -- see the package-level "Message-wording note"
// above for why those three keep Python's own read-side prose instead of
// unsupportedOp's write-style template.
func unsupportedRead(modelKey, op string) error {
	return fmt.Errorf("model %q web UI does not expose %s: %w", modelKey, op, model.ErrUnsupportedCapability)
}

// requireUnverifiedReads mirrors Python's _require_verified_reads
// (http_read.py:55-59) verbatim, including the exact message text.
func requireVerifiedReads(spec *HTTPModelSpec) error {
	if !spec.ReadsVerified {
		return fmt.Errorf("model %q HTTP reads are UNVERIFIED-pending-capture: %w", spec.ModelKey, model.ErrUnsupportedCapability)
	}
	return nil
}

// --- dialect predicates, mirroring http_read.py's _is_*_dialect/_uses_xe_grid/_is_fastpath_dialect (lines 75-124) ---

func isGS110EMXDialect(spec *HTTPModelSpec) bool { return spec.HTMLDialect == HTMLDialectGS110EMX }
func isGS105PEDialect(spec *HTTPModelSpec) bool  { return spec.HTMLDialect == HTMLDialectGS105PE }
func isM4300Dialect(spec *HTTPModelSpec) bool    { return spec.HTMLDialect == HTMLDialectM4300 }
func isXEFastpathDialect(spec *HTTPModelSpec) bool {
	return spec.HTMLDialect == HTMLDialectXEFastpath
}
func isS3300Dialect(spec *HTTPModelSpec) bool   { return spec.HTMLDialect == HTMLDialectS3300 }
func isGoAheadDialect(spec *HTTPModelSpec) bool { return spec.HTMLDialect == HTMLDialectGoAheadXML }

// usesXEGrid is true for the models that share the XE_FASTPATH cell grid for
// ports/stats/PVIDs/VLANs/PoE/LLDP: gsm7252ps (XE_FASTPATH) and the
// S3300-52X (gsm7228ps), whose MAC/mgmt/sensor pages diverge but whose six
// other reads are byte-identical.
func usesXEGrid(spec *HTTPModelSpec) bool {
	return isXEFastpathDialect(spec) || isS3300Dialect(spec)
}

// isFastpathDialect is true for the managed FASTPATH/Cheetah models
// (gsm7252ps, gsm7228ps and both M4300 SKUs), which share the
// switching/dot1q/vlan_port_cfg.html VLAN-membership page.
func isFastpathDialect(spec *HTTPModelSpec) bool {
	return isM4300Dialect(spec) || usesXEGrid(spec)
}

// --- per-op dialect dispatch, mirroring http_read.py's _parse_* helpers (lines 126-246) ---

func parsePorts(spec *HTTPModelSpec, html string) ([]model.PortStatus, error) {
	switch {
	case isGS110EMXDialect(spec):
		return ParseGS110EMXPortStatus(html)
	case isGS105PEDialect(spec):
		return ParseGS105PEPortStatus(html)
	case isM4300Dialect(spec):
		return ParseM4300PortStatus(html)
	case usesXEGrid(spec):
		return ParseXEPortStatus(html)
	case isGoAheadDialect(spec):
		return ParseGoAheadPorts(html)
	default:
		return ParsePortStatus(html)
	}
}

func parseStats(spec *HTTPModelSpec, html string) ([]model.PortStats, error) {
	switch {
	case isGS110EMXDialect(spec):
		return ParseInterfaceStats(html)
	case isGS105PEDialect(spec):
		return ParseGS105PEStats(html)
	case isM4300Dialect(spec):
		return ParseM4300Stats(html)
	case usesXEGrid(spec):
		return ParseXEStats(html)
	default:
		return ParsePortStats(html)
	}
}

func parsePoE(spec *HTTPModelSpec, html string) ([]model.PoEStatus, error) {
	switch {
	case isGoAheadDialect(spec):
		return ParseGoAheadPoE(html)
	case usesXEGrid(spec) || isM4300Dialect(spec):
		return ParseXEPoE(html)
	default:
		return ParsePoEStatus(html)
	}
}

func parseLLDP(spec *HTTPModelSpec, html string) ([]model.LLDPNeighbor, error) {
	if isGoAheadDialect(spec) {
		return ParseGoAheadLLDP(html)
	}
	return ParseXELLDP(html)
}

// SupportsSensors reports whether spec's dialect has a sysInfo page carrying
// box sensors, mirroring Python's _supports_sensors (http_read.py:178-190).
// Exported so the capabilities oracle's HTTP derivation can reuse this exact
// logic instead of re-deriving "does this model's web UI expose sensors".
func SupportsSensors(spec *HTTPModelSpec) bool {
	return (isM4300Dialect(spec) || isXEFastpathDialect(spec) || isGoAheadDialect(spec)) &&
		spec.SysinfoPath != ""
}

func parseSensors(spec *HTTPModelSpec, html string) ([]model.Sensor, error) {
	if isGoAheadDialect(spec) {
		return ParseGoAheadSensors(html)
	}
	if isXEFastpathDialect(spec) {
		return ParseXESensors(html), nil
	}
	return ParseM4300Sensors(html), nil
}

func parseMACs(spec *HTTPModelSpec, html string) ([]model.MacEntry, error) {
	switch {
	case isGoAheadDialect(spec):
		return ParseGoAheadMacs(html)
	case isS3300Dialect(spec):
		return ParseS3300Macs(html)
	case isXEFastpathDialect(spec):
		return ParseXEMacs(html)
	default:
		return ParseM4300Macs(html)
	}
}

func parsePVIDs(spec *HTTPModelSpec, html string) ([]model.Pvid, error) {
	switch {
	case isGS110EMXDialect(spec):
		return ParseGS110EMXPVIDs(html)
	case isGS105PEDialect(spec):
		return ParseGS105PEPVIDs(html)
	case isM4300Dialect(spec):
		return ParseM4300PVIDs(html)
	case usesXEGrid(spec):
		return ParseXEPVIDs(html)
	case isGoAheadDialect(spec):
		return ParseGoAheadPVIDs(html)
	default:
		return ParsePVIDs(html)
	}
}

// parseVlans dispatches an inline-egress VLAN page (VlanConfigPath) to its
// dialect's parser -- only reached from the isFastpathDialect branch of
// GetVLANs (M4300 or usesXEGrid), mirroring Python's module-level
// _parse_vlans.
func parseVlans(spec *HTTPModelSpec, html string) ([]model.VLANInfo, error) {
	if isS3300Dialect(spec) {
		return ParseS3300Vlans(html)
	}
	if usesXEGrid(spec) {
		return ParseXEVlans(html)
	}
	return ParseM4300Vlans(html)
}

// parseVlanIDs dispatches the Plus-class VLAN-list page -- only reached
// from the non-goahead/non-fastpath branch of GetVLANs (STANDARD/
// GS110EMX/GS105PE).
func parseVlanIDs(spec *HTTPModelSpec, html string) ([]int, error) {
	if isGS110EMXDialect(spec) {
		return ParseGS110EMXVlanIDs(html)
	}
	return ParseVLANIDs(html)
}

// --- Plus-class (STANDARD/GS105PE/GS110EMX) per-VLAN membership loop, mirroring http_read.py lines 249-300 ---

// membershipForm builds the POST body that selects VLAN vid's membership
// page, mirroring Python's _membership_form.
func membershipForm(spec *HTTPModelSpec, vid int, csrfHash string) map[string]string {
	data := map[string]string{"VLAN_ID": itoa(vid)}
	if isGS110EMXDialect(spec) {
		data["vlanIdSel"] = itoa(vid)
	}
	if isGS105PEDialect(spec) && csrfHash != "" {
		data["hash"] = csrfHash
	}
	return data
}

// requireCSRFHash mirrors Python's _require_csrf_hash, raising honestly
// when gs105pe's 8021qMembe.cgi page carries no CSRF hash field.
func requireCSRFHash(memberHTML string) (string, error) {
	csrf, ok := ParseCSRFHash(memberHTML)
	if !ok {
		return "", errUnexpectedPage(
			"8021qMembe.cgi: no CSRF 'hash' field -- without it the switch ignores VLAN_ID and every VLAN would report the selected VLAN's membership")
	}
	return csrf, nil
}

// checkMembershipIsFor mirrors Python's _check_membership_is_for: only
// gs105pe's page ever reports a "wrong VLAN" fallback, so every other
// dialect is a no-op.
func checkMembershipIsFor(spec *HTTPModelSpec, html string, vid int) error {
	if !isGS105PEDialect(spec) {
		return nil
	}
	shown, ok := ParseSelectedVlan(html)
	if ok && shown != vid {
		return errUnexpectedPage(
			"8021qMembe.cgi: asked for VLAN %d but the page shows VLAN %d -- refusing to report the wrong VLAN's membership", vid, shown)
	}
	return nil
}

// vlanInfoFromMembership is the pure conversion of one 8021qMembe.cgi
// response into a model.VLANInfo, mirroring Python's _vlan_info. Iterating
// 1..portCount in order keeps the resulting port slices canonically sorted
// with no separate sort step.
func vlanInfoFromMembership(vid int, membershipHTML string, portCount int) (model.VLANInfo, error) {
	states, err := ParseMembership(membershipHTML, portCount)
	if err != nil {
		return model.VLANInfo{}, err
	}
	tagged := make([]int, 0, portCount)
	untagged := make([]int, 0, portCount)
	member := make([]int, 0, portCount)
	for p := 1; p <= portCount; p++ {
		switch states[p] {
		case model.VlanTagged:
			tagged = append(tagged, p)
			member = append(member, p)
		case model.VlanUntagged:
			untagged = append(untagged, p)
			member = append(member, p)
		}
	}
	return model.VLANInfo{
		VlanID:        vid,
		Name:          nil,
		MemberPorts:   member,
		TaggedPorts:   tagged,
		UntaggedPorts: untagged,
	}, nil
}

// --- FASTPATH VLAN-Membership page (the managed models), mirroring http_read.py lines 302-380/586-608 ---

// fastpathMembershipPaths returns (GET page, POST target) for the managed
// FASTPATH VLAN-membership page, mirroring Python's
// fastpath_membership_paths. Both must be populated for a managed model; a
// "" here is a spec defect, not a device limitation.
func fastpathMembershipPaths(spec *HTTPModelSpec, modelKey string) (string, string, error) {
	getPath, err := requirePath(modelKey, spec.VlanMembershipPath, "VLAN membership")
	if err != nil {
		return "", "", err
	}
	postPath, err := requirePath(modelKey, spec.VlanMembershipPostPath, "the VLAN-membership form target")
	if err != nil {
		return "", "", err
	}
	return getPath, postPath, nil
}

// checkFastpathMembershipIsFor mirrors Python's
// _check_fastpath_membership_is_for: refuse a membership page that is
// showing a DIFFERENT VLAN than requested (the firmware re-renders whichever
// VLAN was last selected on a rejected POST).
func checkFastpathMembershipIsFor(page FastpathMembership, vid int) (FastpathMembership, error) {
	if page.VlanID != nil && *page.VlanID != vid {
		return FastpathMembership{}, errUnexpectedPage(
			"vlan_port_cfg_rw.html: asked for VLAN %d but the page shows VLAN %d -- refusing to report the wrong VLAN's membership", vid, *page.VlanID)
	}
	return page, nil
}

// withFastpathEgress rebuilds each VLAN's egress sets from its
// VLAN-Membership page, mirroring Python's _with_fastpath_egress
// (http_read.py:335-380) -- THE 1841111 headline fix. All three sets come
// from the membership page (tagged/untagged from its hiddenTagged/
// hiddenUnTagged ifName lists, member as their union), NEVER from
// VlanConfigPath's ("vlanStatus.html") own Member Ports cell: the two pages
// legitimately disagree on real hardware (dossier D-HTTP-F §1.3 -- that
// cell reports the CONFIGURED set on some firmware despite its field name),
// and the membership page's two lists are the one source that agreed with
// `show vlan <id>` on every VLAN of every managed switch measured. A VLAN
// with no membership page (pages[v.VlanID] absent -- it disappeared between
// the two reads) is left exactly as VlanConfigPath reported it.
func withFastpathEgress(vlans []model.VLANInfo, pages map[int]FastpathMembership) []model.VLANInfo {
	out := make([]model.VLANInfo, 0, len(vlans))
	for _, v := range vlans {
		page, ok := pages[v.VlanID]
		if !ok {
			out = append(out, v)
			continue
		}
		memberSet := make(map[int]bool, len(page.TaggedPorts)+len(page.UntaggedPorts))
		for _, p := range page.TaggedPorts {
			memberSet[p] = true
		}
		for _, p := range page.UntaggedPorts {
			memberSet[p] = true
		}
		v.MemberPorts = sortedPortSet(memberSet)
		v.TaggedPorts = page.TaggedPorts
		v.UntaggedPorts = page.UntaggedPorts
		out = append(out, v)
	}
	return out
}

// --- mgmt-IP dispatch, mirroring http_read.py lines 383-484 ---

// MgmtIPPath is the page GetMgmtIP reads for this model, mirroring Python's
// _mgmt_ip_path: spec.MgmtIPPath if named, else spec.SysinfoPath, else "" (no
// mgmt-IP page at all -- gs305ep). Exported for the same reason as
// SupportsSensors.
func MgmtIPPath(spec *HTTPModelSpec) string {
	if spec.MgmtIPPath != "" {
		return spec.MgmtIPPath
	}
	return spec.SysinfoPath
}

// parseSysInfoForModel dispatches the device-identity/mgmt-IP page,
// mirroring Python's _parse_sysinfo: gs105pe's switch_info.cgi (its own
// parser) vs gs110emx's sysInfo.html (the default, shared by every other
// dialect this function is ever called for -- see mgmtIPFor).
func parseSysInfoForModel(spec *HTTPModelSpec, html string) (HTTPSysInfo, error) {
	if isGS105PEDialect(spec) {
		return ParseGS105PESysInfo(html)
	}
	return ParseSysInfo(html)
}

// mgmtIPFromSysInfo maps GS110EMX/GS105PE/gs305ep's HTTPSysInfo onto the
// shared model.MgmtIPConfig, mirroring Python's _mgmt_ip_from_sysinfo
// verbatim: Address/Netmask/Gateway are always populated (never nil) --
// only BaseMac follows the "uppercase or absent" rule (the real capture's
// page text is lowercase).
func mgmtIPFromSysInfo(info HTTPSysInfo) model.MgmtIPConfig {
	var baseMac *string
	if mac := strings.ToUpper(info.MacAddress); mac != "" {
		baseMac = model.Ptr(mac)
	}
	return model.MgmtIPConfig{
		Mode:    info.IPMode,
		Address: model.Ptr(info.IPAddress),
		Netmask: model.Ptr(info.SubnetMask),
		Gateway: model.Ptr(info.GatewayAddress),
		BaseMac: baseMac,
	}
}

// mgmtIPFor dispatches the mgmt-IP page's HTML to the dialect's reader,
// mirroring Python's _mgmt_ip. The managed FASTPATH models' two older
// sysInfo-based mgmt-IP readers (ParseXEMgmtIP/ParseS3300Mgmt/
// ParseM4300Sysinfo) are used ONLY for the base MAC these dedicated XUI
// pages do not carry -- see fastpathBaseMac/needsFastpathBaseMac below.
func mgmtIPFor(spec *HTTPModelSpec, page string) (model.MgmtIPConfig, error) {
	if isGoAheadDialect(spec) {
		return ParseGoAheadMgmtIP(page)
	}
	if spec.MgmtIPFields != nil {
		f := spec.MgmtIPFields
		return ParseXUIMgmtIP(page, f.Address, f.Netmask, f.Gateway, f.Mode, spec.MgmtIPPath)
	}
	if isS3300Dialect(spec) {
		return ParseS3300Mgmt(page)
	}
	if isXEFastpathDialect(spec) {
		return ParseXEMgmtIP(page)
	}
	if isM4300Dialect(spec) {
		return ParseM4300Sysinfo(page)
	}
	info, err := parseSysInfoForModel(spec, page)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	return mgmtIPFromSysInfo(info), nil
}

// fastpathBaseMac reads the switch's BASE MAC from a managed model's
// sysInfo page, mirroring Python's _fastpath_base_mac: read separately from
// the management address because no FASTPATH mgmt-IP page carries it, and
// it must be the BASE MAC (dot1dBaseBridgeAddress parity) -- NOT the
// M4300's mgmt page's own v_4_4_1, which is the management INTERFACE's MAC,
// one off from the base MAC.
func fastpathBaseMac(spec *HTTPModelSpec, sysinfoHTML string) (*string, error) {
	if isS3300Dialect(spec) {
		cfg, err := ParseS3300Mgmt(sysinfoHTML)
		if err != nil {
			return nil, err
		}
		return cfg.BaseMac, nil
	}
	if isXEFastpathDialect(spec) {
		cfg, err := ParseXEMgmtIP(sysinfoHTML)
		if err != nil {
			return nil, err
		}
		return cfg.BaseMac, nil
	}
	cfg, err := ParseM4300Sysinfo(sysinfoHTML)
	if err != nil {
		return nil, err
	}
	return cfg.BaseMac, nil
}

// needsFastpathBaseMac mirrors Python's _needs_fastpath_base_mac: whether a
// second GET of SysinfoPath is needed to fill BaseMac.
func needsFastpathBaseMac(spec *HTTPModelSpec, cfg model.MgmtIPConfig) bool {
	return spec.MgmtIPFields != nil && cfg.BaseMac == nil && spec.SysinfoPath != ""
}

// --- Reader ---

// Reader is a model-driven web-UI read facade over one switch, mirroring
// Python's HttpReader/AsyncHttpReader (which are byte-for-byte mirrors of
// each other apart from await -- Go's context.Context-first methods cover
// both without a separate async type, exactly as webui.Session already
// collapses HttpSession/AsyncHttpSession, dossier D-HTTP-P §7.4).
type Reader struct {
	session Session
	spec    *HTTPModelSpec
	model   *model.SwitchModel
}

// NewReader constructs a Reader bound to session and m, mirroring Python
// HttpReader.__init__ (http_read.py:504-508): construction fails BEFORE
// any session use if m has no HTTP backend/spec (HTTPSpec) or if the
// model's HTTPModelSpec.ReadsVerified is false (requireVerifiedReads) --
// the "honesty gate": a model whose HTTP reads have not been live
// cross-verified refuses to construct rather than silently serve an
// unverified scrape. There is no per-op re-check after that.
func NewReader(session Session, m *model.SwitchModel) (*Reader, error) {
	spec, err := HTTPSpec(m)
	if err != nil {
		return nil, err
	}
	if err := requireVerifiedReads(spec); err != nil {
		return nil, err
	}
	return &Reader{session: session, spec: spec, model: m}, nil
}

// GetPorts reads per-port link/admin/speed status, mirroring Python
// HttpReader.get_ports (http_read.py:510-512).
func (r *Reader) GetPorts(ctx context.Context) ([]model.PortStatus, error) {
	path, err := requirePath(r.model.Key, r.spec.DashboardPath, "port status")
	if err != nil {
		return nil, err
	}
	html, err := r.session.GetPage(ctx, path)
	if err != nil {
		return nil, err
	}
	return parsePorts(r.spec, html)
}

// GetStats reads the per-port traffic-counter snapshot, mirroring Python
// HttpReader.get_stats (http_read.py:514-516).
func (r *Reader) GetStats(ctx context.Context) ([]model.PortStats, error) {
	path, err := requirePath(r.model.Key, r.spec.StatsPath, "port statistics")
	if err != nil {
		return nil, err
	}
	html, err := r.session.GetPage(ctx, path)
	if err != nil {
		return nil, err
	}
	return parseStats(r.spec, html)
}

// GetPoE reads per-port PoE status, mirroring Python HttpReader.get_poe
// (http_read.py:518-520).
func (r *Reader) GetPoE(ctx context.Context) ([]model.PoEStatus, error) {
	path, err := requirePath(r.model.Key, r.spec.PoEStatusPath, "PoE status")
	if err != nil {
		return nil, err
	}
	html, err := r.session.GetPage(ctx, path)
	if err != nil {
		return nil, err
	}
	return parsePoE(r.spec, html)
}

// GetPVIDs reads each port's default/untagged VLAN, mirroring Python
// HttpReader.get_pvids (http_read.py:522-524).
func (r *Reader) GetPVIDs(ctx context.Context) ([]model.Pvid, error) {
	path, err := requirePath(r.model.Key, r.spec.PvidPath, "port PVIDs")
	if err != nil {
		return nil, err
	}
	html, err := r.session.GetPage(ctx, path)
	if err != nil {
		return nil, err
	}
	return parsePVIDs(r.spec, html)
}

// GetVLANs reads the VLAN table, mirroring Python HttpReader.get_vlans
// (http_read.py:526-565) -- a three-way branch, NOT a simple dispatch call
// (dossier D-HTTP-F §1.2):
//
//  1. GOAHEAD_XML: VLAN names from VlanConfigPath + per-port membership
//     from PvidPath's inline JoinVLANList, combined by ParseGoAheadVlans.
//  2. FASTPATH (isFastpathDialect -- all four managed models): the VLAN
//     id/name/CURRENT-member list from VlanConfigPath, then
//     withFastpathEgress OVERWRITES tagged_ports/untagged_ports/
//     member_ports from the separate VLAN-Membership page -- the pin's
//     headline fix (dossier D-HTTP-F §1.3): before it existed,
//     tagged_ports/untagged_ports were always empty on these four models.
//  3. Else (STANDARD/GS110EMX/GS105PE): the classic 8021qMembe.cgi-style
//     per-VLAN POST loop.
func (r *Reader) GetVLANs(ctx context.Context) ([]model.VLANInfo, error) {
	spec := r.spec
	cfgPath, err := requirePath(r.model.Key, spec.VlanConfigPath, "VLAN configuration")
	if err != nil {
		return nil, err
	}

	if isGoAheadDialect(spec) {
		// The GoAhead VLANList carries names only; membership comes from the
		// per-port JoinVLANList on the PVID page. Fetch both and combine.
		pvidPath, err := requirePath(r.model.Key, spec.PvidPath, "VLAN membership")
		if err != nil {
			return nil, err
		}
		cfgHTML, err := r.session.GetPage(ctx, cfgPath)
		if err != nil {
			return nil, err
		}
		pvidHTML, err := r.session.GetPage(ctx, pvidPath)
		if err != nil {
			return nil, err
		}
		return ParseGoAheadVlans(cfgHTML, pvidHTML)
	}

	if isFastpathDialect(spec) {
		// vlanStatus.html gives the VLAN list, names and CURRENT member
		// ports; the separate VLAN-Membership page is what splits those
		// members into tagged vs untagged. Both are read here -- returning
		// empty tagged/untagged sets from vlanStatus alone was the defect
		// this replaces.
		cfgHTML, err := r.session.GetPage(ctx, cfgPath)
		if err != nil {
			return nil, err
		}
		vlans, err := parseVlans(spec, cfgHTML)
		if err != nil {
			return nil, err
		}
		pages, err := r.fastpathMembership(ctx, vlans)
		if err != nil {
			return nil, err
		}
		return withFastpathEgress(vlans, pages), nil
	}

	memberPath, err := requirePath(r.model.Key, spec.VlanMembershipPath, "VLAN membership")
	if err != nil {
		return nil, err
	}
	cfgHTML, err := r.session.GetPage(ctx, cfgPath)
	if err != nil {
		return nil, err
	}

	var memberPage, csrf string
	haveMemberPage := false
	var selected int
	haveSelected := false
	if isGS105PEDialect(spec) {
		memberPage, err = r.session.GetPage(ctx, memberPath)
		if err != nil {
			return nil, err
		}
		haveMemberPage = true
		csrf, err = requireCSRFHash(memberPage)
		if err != nil {
			return nil, err
		}
		selected, haveSelected = ParseSelectedVlan(memberPage)
	}

	vlanIDs, err := parseVlanIDs(spec, cfgHTML)
	if err != nil {
		return nil, err
	}
	result := make([]model.VLANInfo, 0, len(vlanIDs))
	for _, vid := range vlanIDs {
		var html string
		if haveMemberPage && haveSelected && vid == selected {
			html = memberPage // already shown; re-POSTing it drops the link
		} else {
			form := membershipForm(spec, vid, csrf)
			html, err = r.session.PostForm(ctx, memberPath, form)
			if err != nil {
				return nil, err
			}
		}
		if err := checkMembershipIsFor(spec, html, vid); err != nil {
			return nil, err
		}
		info, err := vlanInfoFromMembership(vid, html, r.model.PortCount)
		if err != nil {
			return nil, err
		}
		result = append(result, info)
	}
	return result, nil
}

// ReadFastpathMembership reads one VLAN's membership page from the managed
// FASTPATH web UI, mirroring Python HttpReader.read_fastpath_membership
// (http_read.py:567-584). The GET shows whichever VLAN the firmware last
// selected, so any other VLAN needs the form POST the browser's own
// screen_refresh() makes: the full field set with submt=0, which re-renders
// WITHOUT applying. Shared by GetVLANs and (eventually) the Writer's
// set_vlan_membership.
func (r *Reader) ReadFastpathMembership(ctx context.Context, vlan int) (FastpathMembership, error) {
	getPath, postPath, err := fastpathMembershipPaths(r.spec, r.model.Key)
	if err != nil {
		return FastpathMembership{}, err
	}
	html, err := r.session.GetPage(ctx, getPath)
	if err != nil {
		return FastpathMembership{}, err
	}
	page, err := ParseFastpathMembership(html)
	if err != nil {
		return FastpathMembership{}, err
	}
	if page.VlanID != nil && *page.VlanID == vlan {
		return page, nil
	}
	body := FastpathMembershipForm(page, vlan, nil, false)
	respHTML, err := r.session.PostForm(ctx, postPath, body)
	if err != nil {
		return FastpathMembership{}, err
	}
	page2, err := ParseFastpathMembership(respHTML)
	if err != nil {
		return FastpathMembership{}, err
	}
	return checkFastpathMembershipIsFor(page2, vlan)
}

// fastpathMembership reads every VLAN's membership page, reusing ONE base
// GET, mirroring Python HttpReader._fastpath_membership (http_read.py:
// 586-608). Deliberately not ReadFastpathMembership per VLAN: that would
// re-GET the base page for each of the (up to) 14 VLANs these switches
// carry.
func (r *Reader) fastpathMembership(ctx context.Context, vlans []model.VLANInfo) (map[int]FastpathMembership, error) {
	getPath, postPath, err := fastpathMembershipPaths(r.spec, r.model.Key)
	if err != nil {
		return nil, err
	}
	baseHTML, err := r.session.GetPage(ctx, getPath)
	if err != nil {
		return nil, err
	}
	base, err := ParseFastpathMembership(baseHTML)
	if err != nil {
		return nil, err
	}
	pages := make(map[int]FastpathMembership, len(vlans))
	for _, v := range vlans {
		if base.VlanID != nil && *base.VlanID == v.VlanID {
			pages[v.VlanID] = base
			continue
		}
		body := FastpathMembershipForm(base, v.VlanID, nil, false)
		respHTML, err := r.session.PostForm(ctx, postPath, body)
		if err != nil {
			return nil, err
		}
		page, err := ParseFastpathMembership(respHTML)
		if err != nil {
			return nil, err
		}
		checked, err := checkFastpathMembershipIsFor(page, v.VlanID)
		if err != nil {
			return nil, err
		}
		pages[v.VlanID] = checked
	}
	return pages, nil
}

// GetMACs reads the switch's MAC/FDB table, mirroring Python
// HttpReader.get_macs (http_read.py:610-614). Only a model whose spec
// names a MacTablePath has one at all (every Plus switch except the
// managed FASTPATH/Cheetah UIs does not).
func (r *Reader) GetMACs(ctx context.Context) ([]model.MacEntry, error) {
	path, err := requirePath(r.model.Key, r.spec.MacTablePath, "a MAC/FDB table")
	if err != nil {
		return nil, err
	}
	html, err := r.session.GetPage(ctx, path)
	if err != nil {
		return nil, err
	}
	return parseMACs(r.spec, html)
}

// GetLLDP reads the LLDP neighbour table, mirroring Python
// HttpReader.get_lldp (http_read.py:616-622). Only a model whose spec
// names an LLDPPath has a neighbour table.
func (r *Reader) GetLLDP(ctx context.Context) ([]model.LLDPNeighbor, error) {
	path, err := requirePath(r.model.Key, r.spec.LLDPPath, "LLDP neighbours")
	if err != nil {
		return nil, err
	}
	html, err := r.session.GetPage(ctx, path)
	if err != nil {
		return nil, err
	}
	return parseLLDP(r.spec, html)
}

// GetSensors reads box environmental sensors (temperature/fan/power),
// mirroring Python HttpReader.get_sensors (http_read.py:624-630). Raises
// (rather than returning an empty slice) when SupportsSensors is false --
// see its doc comment for the S3300 (gsm7228ps) exclusion.
func (r *Reader) GetSensors(ctx context.Context) ([]model.Sensor, error) {
	if !SupportsSensors(r.spec) {
		return nil, unsupportedRead(r.model.Key, "box sensors")
	}
	html, err := r.session.GetPage(ctx, r.spec.SysinfoPath)
	if err != nil {
		return nil, err
	}
	return parseSensors(r.spec, html)
}

// HasSysinfoHostname reports whether spec's dialect's identity page carries
// the switch's host name: true for gs110emx's sysInfo.html (switch_name
// input), gs105pe's switch_info.cgi, and the GoAhead DeviceBasicInfo section.
//
// The GoAhead entry corrects a claim an earlier version of this project's
// docstring used to make -- that page carries no host-name field; it does --
// DeviceBasicInfo/deviceName, MEASURED on the live GS728TPP (10.2.5.10,
// firmware 6.0.1.30, 2026-08-03) reading "sw-netgear-gs728tpp", byte-for-byte
// what SNMP reports through sysName. The FASTPATH/XE and M4300 identity
// pages really do lack one, so those models still read the name over SNMP or
// the CLI. Mirrors Python http_read._has_sysinfo_hostname. Exported (like
// SupportsSensors above) so the capabilities oracle's HTTP derivation can
// reuse this exact logic instead of re-deriving it.
func HasSysinfoHostname(spec *HTTPModelSpec) bool {
	return spec.SysinfoPath != "" && (isGS110EMXDialect(spec) || isGS105PEDialect(spec) || isGoAheadDialect(spec))
}

// GetHostname reads the switch's host name from its device-identity page,
// mirroring Python HttpReader.get_hostname (http_read.py:684-703).
//
// Only the dialects whose identity page actually carries the field can serve
// this: gs110emx's sysInfo.html and gs105pe's switch_info.cgi (both already
// expose it as HTTPSysInfo.SwitchName), plus the GoAhead XML API's
// DeviceBasicInfo/deviceName section (a different section of a different
// page shape -- the GoAhead identity data is XML, not the HTTPSysInfo form
// scrape). Every other dialect's identity page has no such field, and is
// refused by name rather than returning "" -- an empty string is a real
// host name on a switch that has never been named, so it must not double as
// "this backend cannot tell you".
func (r *Reader) GetHostname(ctx context.Context) (string, error) {
	if !HasSysinfoHostname(r.spec) {
		return "", unsupportedRead(r.model.Key, "a host name field")
	}
	page, err := r.session.GetPage(ctx, r.spec.SysinfoPath)
	if err != nil {
		return "", err
	}
	if isGoAheadDialect(r.spec) {
		return ParseGoAheadHostname(page)
	}
	info, err := parseSysInfoForModel(r.spec, page)
	if err != nil {
		return "", err
	}
	return info.SwitchName, nil
}

// GetMgmtIP reads the switch's own management-IP configuration, mirroring
// Python HttpReader.get_mgmt_ip (http_read.py:632-649). GoAhead/managed-
// FASTPATH models need a SECOND page fetch (SysinfoPath) to fill BaseMac,
// which their dedicated mgmt-IP page does not carry -- see mgmtIPFor's doc
// comment.
func (r *Reader) GetMgmtIP(ctx context.Context) (model.MgmtIPConfig, error) {
	path := MgmtIPPath(r.spec)
	if path == "" {
		return model.MgmtIPConfig{}, unsupportedRead(r.model.Key, "management-IP config")
	}
	page, err := r.session.GetPage(ctx, path)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}
	cfg, err := mgmtIPFor(r.spec, page)
	if err != nil {
		return model.MgmtIPConfig{}, err
	}

	switch {
	case isGoAheadDialect(r.spec) && r.spec.SysinfoPath != "":
		// GoAhead: the IPConf page has no MAC row, so read the base MAC from
		// the SystemInfo page to reach SNMP parity on BaseMac.
		sysHTML, err := r.session.GetPage(ctx, r.spec.SysinfoPath)
		if err != nil {
			return model.MgmtIPConfig{}, err
		}
		mac, ok, err := ParseGoAheadBaseMAC(sysHTML)
		if err != nil {
			return model.MgmtIPConfig{}, err
		}
		if ok {
			cfg.BaseMac = model.Ptr(mac)
		} else {
			cfg.BaseMac = nil
		}
	case needsFastpathBaseMac(r.spec, cfg):
		sysHTML, err := r.session.GetPage(ctx, r.spec.SysinfoPath)
		if err != nil {
			return model.MgmtIPConfig{}, err
		}
		mac, err := fastpathBaseMac(r.spec, sysHTML)
		if err != nil {
			return model.MgmtIPConfig{}, err
		}
		cfg.BaseMac = mac
	}
	return cfg, nil
}

// GetUsers reads local login accounts, mirroring Python HttpReader.get_users
// (http_read.py:724-734). Refuses by name on a model whose UI has no such
// page located, rather than returning empty: an empty answer would be
// indistinguishable from a switch that genuinely has no accounts.
func (r *Reader) GetUsers(ctx context.Context) ([]model.SwitchUser, error) {
	path, err := requirePath(r.model.Key, r.spec.UsersPath, "local user accounts")
	if err != nil {
		return nil, err
	}
	html, err := r.session.GetPage(ctx, path)
	if err != nil {
		return nil, err
	}
	return ParseXUIUsers(html)
}

// HasServicePaths reports whether spec names all four management-service
// pages (http/https/ssh/telnet), mirroring Python http_read._service_paths's
// all-or-nothing membership test. The S3300 is the case that motivates it --
// its https and telnet pages parse fine, but its httpConfiguration.html
// carries no admin control and its sshConfiguration.html 404s. Reporting the
// two that work would read as "this switch has no SSH" -- a confident wrong
// answer -- where refusing says only what is true: this UI cannot be asked.
// Exported (like SupportsSensors/HasSysinfoHostname above) so the
// capabilities oracle's HTTP derivation can reuse this exact logic instead
// of re-deriving it.
func HasServicePaths(spec *HTTPModelSpec) bool {
	return spec.HTTPServicePath != "" && spec.HTTPSServicePath != "" && spec.SSHServicePath != "" && spec.TelnetServicePath != ""
}

// requireServicePaths returns the (service, path) pairs for spec, in
// ServiceNames order, or refuses honestly unless ALL FOUR are populated
// (HasServicePaths), mirroring Python _require_service_paths (http_read.py:
// 96-104).
func requireServicePaths(modelKey string, spec *HTTPModelSpec) ([]struct{ Service, Path string }, error) {
	if !HasServicePaths(spec) {
		return nil, unsupportedOp(modelKey, "management-service state (http/https/telnet/ssh)")
	}
	pathFor := map[string]string{
		"http":   spec.HTTPServicePath,
		"https":  spec.HTTPSServicePath,
		"ssh":    spec.SSHServicePath,
		"telnet": spec.TelnetServicePath,
	}
	out := make([]struct{ Service, Path string }, 0, len(ServiceNames))
	for _, service := range ServiceNames {
		out = append(out, struct{ Service, Path string }{service, pathFor[service]})
	}
	return out, nil
}

// GetServices reads management-service state, one page per service,
// mirroring Python HttpReader.get_services (http_read.py:736-746).
func (r *Reader) GetServices(ctx context.Context) ([]model.ServiceStatus, error) {
	paths, err := requireServicePaths(r.model.Key, r.spec)
	if err != nil {
		return nil, err
	}
	out := make([]model.ServiceStatus, 0, len(paths))
	for _, p := range paths {
		html, err := r.session.GetPage(ctx, p.Path)
		if err != nil {
			return nil, err
		}
		status, err := ParseServicePage(html, p.Service)
		if err != nil {
			return nil, err
		}
		out = append(out, status)
	}
	return out, nil
}

// GetSyslog reads remote-logging configuration from this model's syslog
// page, mirroring Python HttpReader.get_syslog (http_read.py:748-758).
//
// Refuses by name on a model whose UI has no such page located, rather than
// returning empty: an empty answer would be indistinguishable from a switch
// that genuinely logs nowhere.
func (r *Reader) GetSyslog(ctx context.Context) (model.SyslogConfig, error) {
	path, err := requirePath(r.model.Key, r.spec.SyslogPath, "remote-logging configuration")
	if err != nil {
		return model.SyslogConfig{}, err
	}
	html, err := r.session.GetPage(ctx, path)
	if err != nil {
		return model.SyslogConfig{}, err
	}
	return ParseXUISyslog(html)
}

// itoa is a tiny local alias so membershipForm doesn't need a second
// stdlib import purely for one-line int->string conversions.
func itoa(v int) string { return fmt.Sprintf("%d", v) }
