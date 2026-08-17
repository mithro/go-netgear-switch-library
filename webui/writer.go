package webui

// writer.go: model-driven web-UI write facade, ported field-for-field from
// src/netgear_switch/http_write.py at pin 1841111 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1841111). Any discrepancy between this file and that pin is a
// bug in this file, not a deliberate deviation, unless called out in a
// comment. Cert upload (upload_certificate + its helpers) lives in cert.go,
// a deliberate split from the Python source's single http_write.py.
//
// Every mutating op here: (1) enforces protected ports on a disruptive
// per-port op unless force=true; (2) GETs the target page to scrape a fresh
// CSRF token where the dialect needs one; (3) POSTs the encoded form; (4)
// re-GETs and re-parses to confirm the change actually took, returning
// *model.WriteVerificationError on divergence -- NEVER silently succeeding.
// FASTPATH applies additionally check the page's own err_flag/err_msg
// (raiseOnFastpathErrFlag): these pages answer HTTP 200 even when they
// refuse a write.
//
// Unlike snmp.Writer's CyclePoE/ClearPoEFault (which poll with injectable
// deadlines, snmp.PoeCycleTimeouts), CyclePoE/ClearPoEFault below take no
// timeouts parameter: HTTP's mechanism is fire-and-forget (a hidden
// write-only "Port Reset" column, or the Plus CGI's reset form) with no
// polling loop, mirroring Python's cycle_poe/clear_poe_fault accepting a
// timeouts parameter purely so the SnmpWriter|NsdpWriter|HttpWriter union
// typechecks -- it is unused there too. This package deliberately does not
// import the snmp package to avoid a needless cross-backend dependency; the
// eventual backend_http.go adapter (root package, which already imports
// snmp) is expected to drop the timeouts argument when satisfying
// BackendWriter.CyclePoE/ClearPoEFault, exactly as backend_nsdp.go's
// adapter does for nsdp.Writer (which has no CyclePoE/ClearPoEFault of its
// own at all -- see nsdp/writer.go's package doc comment).
//
// NOTE on set_pvid/create_vlan/delete_vlan verify parsers (source fidelity,
// not a Go-side simplification): Python's set_pvid/create_vlan/delete_vlan
// verify against parse.parse_pvids/parse.parse_vlan_ids -- the PLAIN
// STANDARD-dialect parsers -- even when called against a FASTPATH/GS110EMX
// model, NOT the dialect-aware _parse_pvids/_parse_vlan_ids dispatcher
// http_read.py itself uses for reads. This Go port mirrors that exactly
// (ParsePVIDs/ParseVLANIDs below, not the parsePVIDs/parseVlanIDs
// dispatchers in reader.go) even though it means these three write ops are
// only reliable on the models whose pvid_path/vlan_config_path already
// render the STANDARD shape -- porting the Python behaviour honestly,
// per this task's fidelity requirement, rather than silently "fixing" it.
//
// NOTE on set_vlan_membership's Plus-CGI "before" value (source fidelity):
// Python's set_vlan_membership mutates `states[port] = mode` BEFORE using
// `states.get(port)` as the WriteVerificationError's `before=` value, so
// `before` is always literally `mode` itself on that path -- not the port's
// prior membership. That looks like a bug, but it is what the pinned source
// does, so this port preserves it verbatim (see the comment at the call
// site below) rather than silently "fixing" it into a more useful value.

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/mithro/go-netgear-switch-library/model"
)

// --- FASTPATH XUI column coordinates, mirroring http_write.py's module
// constants verbatim (lines 358-397) ---

const (
	xuiPortAdmin  = "v_1_2_6"
	xuiPortIfname = "v_1_2_1"

	xuiPoEIfname     = "v_1_2_1"
	xuiPoEAdmin      = "v_1_2_2"
	xuiPoEReset      = "v_1_2_20"
	xuiPoEResetValue = "Reset"

	xuiEnableValue  = "Enable"
	xuiDisableValue = "Disable"
)

// xuiPoEApplyOmits/xuiPoEResetOmits mirror Python's
// _XUI_POE_APPLY_OMITS/_XUI_POE_RESET_OMITS: the two PoE buttons' own "shed
// lists" (see writer.go's package doc + dossier D-HTTP-F §2.6) -- APPLY must
// omit the write-only Port Reset column, RESET must omit every config
// column, or the write-only action doubles as an unwanted rewrite.
var (
	xuiPoEApplyOmits = []string{xuiPoEReset}
	xuiPoEResetOmits = func() []string {
		out := make([]string, 0, 18)
		for n := 2; n < 20; n++ {
			out = append(out, fmt.Sprintf("v_1_2_%d", n))
		}
		return out
	}()
)

// xuiEnabled mirrors Python forms/_xui_enabled: the wire value of both
// admin-mode columns.
func xuiEnabled(v bool) string {
	if v {
		return xuiEnableValue
	}
	return xuiDisableValue
}

// fastpathIfnames returns the ifName spellings a FASTPATH page may use for
// physical port, mirroring Python's _fastpath_ifnames: the Fully-Managed/
// M4300 firmwares write "1/0/N", the Smart-Managed-Pro S3300 writes "1/gN"
// (and "1/xgN" for its 10G ports). Both are tried and the row is confirmed
// by MATCHING the device's own cell, never by computing a row index from
// the port number.
func fastpathIfnames(port int) []string {
	return []string{
		fmt.Sprintf("1/0/%d", port),
		fmt.Sprintf("1/g%d", port),
		fmt.Sprintf("1/xg%d", port),
	}
}

// findXUIRow returns the row of page whose column names physical port, or
// an error wrapping model.ErrUnsupportedCapability naming what was
// rendered, mirroring Python's _find_xui_row.
func findXUIRow(page XuiListPage, port int, column, what string) (XuiRow, error) {
	for _, ifname := range fastpathIfnames(port) {
		if row, ok := page.RowFor(column, ifname); ok {
			return row, nil
		}
	}
	rendered := make([]string, 0, len(page.Rows))
	for _, r := range page.Rows {
		v, _ := r.Field(column)
		rendered = append(rendered, v)
	}
	sort.Strings(rendered)
	return XuiRow{}, fmt.Errorf("%s: port %d is not on this page (it renders %v): %w", what, port, rendered, model.ErrUnsupportedCapability)
}

// raiseOnFastpathErrFlag surfaces the switch's own rejection of a FASTPATH
// apply, mirroring Python's _raise_on_fastpath_err_flag: these pages answer
// HTTP 200 even when they refuse a write, reporting it via hidden
// err_flag/err_msg fields.
func raiseOnFastpathErrFlag(html, what string) error {
	if msg, ok := ParseFastpathErr(html); ok {
		return fmt.Errorf("switch refused %s: %s: %w", what, msg, model.ErrHTTP)
	}
	return nil
}

// requireFastpathMembershipFor mirrors Python's
// _require_fastpath_membership_for: refuse a membership page showing a
// DIFFERENT VLAN than requested (see reader.go's checkFastpathMembershipIsFor,
// which this duplicates for the write path's own error wording -- Python
// keeps two near-identical checks too, _check_fastpath_membership_is_for on
// the read side and _require_fastpath_membership_for on the write side).
func requireFastpathMembershipFor(page FastpathMembership, vlan int, path string) error {
	if page.VlanID != nil && *page.VlanID != vlan {
		return errUnexpectedPage(
			"%s: asked for VLAN %d but the page shows VLAN %d -- refusing to write to the wrong VLAN", path, vlan, *page.VlanID)
	}
	return nil
}

// poeResetButton returns the PoE page's reset/power-cycle button field,
// mirroring Python's _poe_reset_button: "v_2_1_3" on every managed model,
// but only present when the page actually renders a button there (an
// honest capability check, not an invented one).
func poeResetButton(page XuiListPage, modelKey string) (string, error) {
	if _, ok := page.Buttons["v_2_1_3"]; ok {
		return "v_2_1_3", nil
	}
	names := make([]string, 0, len(page.Buttons))
	for k := range page.Buttons {
		names = append(names, k)
	}
	sort.Strings(names)
	return "", fmt.Errorf("model %q PoE page has no reset button (it renders %v): %w", modelKey, names, model.ErrUnsupportedCapability)
}

// vlanCheckboxRE/vlanCheckboxIndex mirror Python's _vlan_checkbox_index:
// scans STANDARD-dialect 8021qCf.cgi checkbox inputs named "vlanckN" whose
// value is the VLAN ID, returning the N whose value matches vlan.
var vlanCheckboxRE = regexp.MustCompile(`name="vlanck(\d+)"[^>]*value="(\d+)"`)

func vlanCheckboxIndex(html string, vlan int) (int, bool) {
	for _, m := range vlanCheckboxRE.FindAllStringSubmatch(html, -1) {
		v, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		if v == vlan {
			idx, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			return idx, true
		}
	}
	return 0, false
}

// requireXUIMgmtFields returns (page path, field map) for a model's mgmt-IP
// write, or an error wrapping model.ErrUnsupportedCapability, mirroring
// Python's _require_xui_mgmt_fields.
func requireXUIMgmtFields(spec *HTTPModelSpec) (string, *XuiMgmtIPFields, error) {
	if spec.MgmtIPPath == "" || spec.MgmtIPFields == nil {
		return "", nil, fmt.Errorf("model %q has no known web management-IP form (no MgmtIPPath/MgmtIPFields in its endpoint spec): %w", spec.ModelKey, model.ErrUnsupportedCapability)
	}
	return spec.MgmtIPPath, spec.MgmtIPFields, nil
}

// mgmtIPChanges returns the field overrides for a STATIC mgmt-IP apply,
// mirroring Python's _mgmt_ip_changes: the method field is set FIRST (map
// iteration order is irrelevant on the wire since these are POST form
// fields, but the comment matters) -- see forms.go's XuiFormApplyForm doc
// comment for why the method must accompany the address for the firmware to
// treat the address boxes as meaningful at all.
func mgmtIPChanges(fields *XuiMgmtIPFields, address, netmask, gateway string) map[string]string {
	return map[string]string{
		fields.Mode:    fields.StaticValue,
		fields.Address: address,
		fields.Netmask: netmask,
		fields.Gateway: gateway,
	}
}

// requireCSRF returns html's CSRF hash or raises honestly, mirroring
// Python's _csrf.
func requireCSRF(html string) (string, error) {
	token, ok := ParseCSRFHash(html)
	if !ok {
		return "", errUnexpectedPage("no CSRF 'hash' token on page before write")
	}
	return token, nil
}

// pvidLookupMap builds a port->vlan lookup from pairs, for set_pvid's
// verify step.
func pvidLookupMap(pairs []model.Pvid) map[int]int {
	m := make(map[int]int, len(pairs))
	for _, p := range pairs {
		m[p.Port] = p.Vlan
	}
	return m
}

// sortedRowPorts returns rows' keys in ascending order, for an honest
// "it renders %v" capability-check message.
func sortedRowPorts(rows map[int]map[string]string) []int {
	out := make([]int, 0, len(rows))
	for p := range rows {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// --- Writer ---

// Writer is a model-driven web-UI write facade over one switch, mirroring
// Python's HttpWriter/AsyncHttpWriter (byte-for-byte mirrors of each other
// apart from await -- see reader.go's Reader doc comment for why Go's
// context.Context-first methods need only one type here too).
type Writer struct {
	session        Session
	spec           *HTTPModelSpec
	model          *model.SwitchModel
	protectedPorts map[int]bool
}

// WriterOption configures optional Writer construction parameters (only
// protected ports today), mirroring snmp.Writer/nsdp.Writer's functional-
// options pattern.
type WriterOption func(*Writer)

// WithProtectedPorts marks ports as protected: every disruptive write to a
// protected port is refused unless force is passed as true, mirroring
// Python's HttpWriter(..., protected_ports=frozenset({...})).
func WithProtectedPorts(ports ...int) WriterOption {
	return func(w *Writer) {
		for _, p := range ports {
			w.protectedPorts[p] = true
		}
	}
}

// NewWriter constructs a Writer bound to session and m, mirroring Python
// HttpWriter.__init__ (http_write.py:497-507). Unlike NewReader, this does
// NOT gate on HTTPModelSpec.ReadsVerified -- dossier D-HTTP-F §1.5 is
// explicit that HttpWriter/AsyncHttpWriter never perform that check;
// individual write ops raise per missing path via requirePath instead.
// Construction fails only if m has no HTTP backend/spec at all.
func NewWriter(session Session, m *model.SwitchModel, opts ...WriterOption) (*Writer, error) {
	spec, err := HTTPSpec(m)
	if err != nil {
		return nil, err
	}
	w := &Writer{session: session, spec: spec, model: m, protectedPorts: make(map[int]bool)}
	for _, opt := range opts {
		opt(w)
	}
	return w, nil
}

// guard refuses port when it is protected and force is false, mirroring
// Python's HttpWriter._guard verbatim (including the exact message text).
func (w *Writer) guard(port int, force bool) error {
	if w.protectedPorts[port] && !force {
		return fmt.Errorf("port %d is protected on %q; pass force=true: %w", port, w.model.Key, model.ErrProtectedPort)
	}
	return nil
}

// poeAdmin reads port's current PoE admin-enabled state via the dialect-
// aware reader dispatcher (parsePoE, reader.go), mirroring Python's
// HttpWriter._poe_admin: dialect-aware on purpose, since the FASTPATH PoE
// page is an XE grid, not a Plus portID-row CGI.
func (w *Writer) poeAdmin(ctx context.Context, port int) (bool, error) {
	path, err := requirePath(w.model.Key, w.spec.PoEStatusPath, "PoE status")
	if err != nil {
		return false, err
	}
	html, err := w.session.GetPage(ctx, path)
	if err != nil {
		return false, err
	}
	rows, err := parsePoE(w.spec, html)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.Port == port {
			return r.AdminEnabled, nil
		}
	}
	return false, nil
}

// SetPoE sets port's PoE admin state, mirroring Python HttpWriter.set_poe
// (http_write.py:515-535). FASTPATH models drive the XUI grid
// (xuiPoEAdmin, the gsm7252ps fix's landing site); every other model drives
// the Plus-CGI PoEPortConfig.cgi form.
func (w *Writer) SetPoE(ctx context.Context, port int, on, force bool) error {
	path, err := requirePath(w.model.Key, w.spec.PoEConfigPath, "web PoE config")
	if err != nil {
		return err
	}
	if err := w.guard(port, force); err != nil {
		return err
	}
	if isFastpathDialect(w.spec) {
		return w.xuiPoEAdmin(ctx, path, port, on)
	}
	before, err := w.poeAdmin(ctx, port)
	if err != nil {
		return err
	}
	page, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	csrf, err := requireCSRF(page)
	if err != nil {
		return err
	}
	if _, err := w.session.PostForm(ctx, path, PoeApplyForm(port, on, w.spec.IsEPXPoE, csrf)); err != nil {
		return err
	}
	after, err := w.poeAdmin(ctx, port)
	if err != nil {
		return err
	}
	if after != on {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("PoE port %d did not read back as on=%v", port, on),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// xuiPoEAdmin drives poeInterfaceConfiguration.html's admin-mode column,
// mirroring Python HttpWriter._xui_poe_admin (http_write.py:537-570) -- the
// gsm7252ps PoE-over-HTTP fix (dossier D-HTTP-F §2.6): the page's own nav
// block MUST ride along (XuiRowApplyForm always sends page.Nav) and the
// write-only Port Reset column must NOT (xuiPoEApplyOmits).
func (w *Writer) xuiPoEAdmin(ctx context.Context, path string, port int, on bool) error {
	html, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	page, err := ParseXUIListPage(html, path)
	if err != nil {
		return err
	}
	row, err := findXUIRow(page, port, xuiPoEIfname, fmt.Sprintf("%q PoE", w.model.Key))
	if err != nil {
		return err
	}
	before, _ := row.Field(xuiPoEAdmin)
	body, err := XuiRowApplyForm(page, row, map[string]string{xuiPoEAdmin: xuiEnabled(on)}, "v_2_1_2", xuiPoEApplyOmits)
	if err != nil {
		return err
	}
	applied, err := w.session.PostForm(ctx, page.Action, body)
	if err != nil {
		return err
	}
	if err := raiseOnFastpathErrFlag(applied, fmt.Sprintf("PoE port %d admin -> %v", port, on)); err != nil {
		return err
	}
	after, err := w.poeAdmin(ctx, port)
	if err != nil {
		return err
	}
	if after != on {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("PoE port %d did not read back as on=%v on %s", port, on, path),
			Before: before, // the row's own pre-write text ("Enable"/"Disable"), mismatched in TYPE from After (bool) -- a Python source quirk (before is a string, after is a bool) preserved verbatim.
			After:  after,
		}
	}
	return nil
}

// CyclePoE power-cycles port's PD, mirroring Python HttpWriter.cycle_poe
// (http_write.py:572-592). No timeouts parameter -- see this file's
// package doc comment.
func (w *Writer) CyclePoE(ctx context.Context, port int, force bool) error {
	path, err := requirePath(w.model.Key, w.spec.PoEConfigPath, "web PoE config")
	if err != nil {
		return err
	}
	if err := w.guard(port, force); err != nil {
		return err
	}
	if isFastpathDialect(w.spec) {
		return w.xuiPoEReset(ctx, path, port)
	}
	page, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	csrf, err := requireCSRF(page)
	if err != nil {
		return err
	}
	_, err = w.session.PostForm(ctx, path, PoeResetForm(port, csrf))
	return err
}

// ClearPoEFault clears a PoE fault on port by re-running the port's PoE
// detection, mirroring Python HttpWriter.clear_poe_fault (http_write.py:
// 594-622): on the managed FASTPATH models this is the SAME hidden
// write-only "Port Reset" mechanism CyclePoE uses; on the Plus-class CGI UI
// it is the identical PoEPortConfig.cgi reset form -- a Plus switch has no
// separate "clear fault" action, the fault clears when detection re-runs.
// No timeouts parameter -- see this file's package doc comment.
func (w *Writer) ClearPoEFault(ctx context.Context, port int, force bool) error {
	path, err := requirePath(w.model.Key, w.spec.PoEConfigPath, "web PoE config")
	if err != nil {
		return err
	}
	if err := w.guard(port, force); err != nil {
		return err
	}
	if isFastpathDialect(w.spec) {
		return w.xuiPoEReset(ctx, path, port)
	}
	page, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	csrf, err := requireCSRF(page)
	if err != nil {
		return err
	}
	_, err = w.session.PostForm(ctx, path, PoeResetForm(port, csrf))
	return err
}

// xuiPoEReset presses the FASTPATH PoE page's per-port RESET for port,
// mirroring Python HttpWriter._xui_poe_reset (http_write.py:624-649). No
// verify-after-write: v_1_2_20 is a WRITE-ONLY field with no persistent
// state to read back (exactly like cycle_poe on every other backend) --
// what IS checked is the page's own err_flag/err_msg.
func (w *Writer) xuiPoEReset(ctx context.Context, path string, port int) error {
	html, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	page, err := ParseXUIListPage(html, path)
	if err != nil {
		return err
	}
	row, err := findXUIRow(page, port, xuiPoEIfname, fmt.Sprintf("%q PoE", w.model.Key))
	if err != nil {
		return err
	}
	button, err := poeResetButton(page, w.model.Key)
	if err != nil {
		return err
	}
	body, err := XuiRowApplyForm(page, row, map[string]string{xuiPoEReset: xuiPoEResetValue}, button, xuiPoEResetOmits)
	if err != nil {
		return err
	}
	applied, err := w.session.PostForm(ctx, page.Action, body)
	if err != nil {
		return err
	}
	return raiseOnFastpathErrFlag(applied, fmt.Sprintf("PoE reset of port %d", port))
}

// requireVlanExists refuses a PVID pointing at a VLAN this switch does not
// have, mirroring Python HttpWriter._require_vlan_exists (http_write.py:
// 622-644, added by commit 98fb935). A precondition, so nothing is sent
// when it fails.
//
// MEASURED on a GS728TPP (10.2.5.10, firmware 6.0.1.30, 2026-08-03):
// dot1qPvid.17 := a VLAN that does not exist is ACCEPTED, reads back as
// that value, and creates no VLAN -- so verify-after-write cannot catch
// it. Only a precondition can.
//
// Skipped where this UI cannot enumerate VLANs at all (VlanConfigPath ==
// ""): refusing against a list this backend cannot read would be worse
// than the risk it prevents.
//
// Deliberately reads the SAME single VlanConfigPath page Python's
// _require_vlan_exists reads (one GET, none of GetVLANs' extra per-VLAN
// membership fetches on FASTPATH/GS105PE), but dispatches it with the SAME
// per-dialect parsers GetVLANs itself uses (isGoAheadDialect/
// isFastpathDialect/parseVlanIDs) rather than Python's plain two-way branch
// (XML-API vs. parse_vlan_ids for everything else). Python's version
// hands a FASTPATH model's vlanStatus.html, or GS110EMX's Cf8021q.html, to
// parse_vlan_ids -- which expects 8021qCf.cgi's "vlanckN" checkboxes and
// finds none there, so EVERY set_pvid call on those dialects would fail
// with a confusing page-format error instead of the intended "VLAN does
// not exist" refusal (or the intended success). That is a latent bug in
// the pinned Python this port should not reproduce: the dispatch below
// reads each dialect's page with the SAME parser GetVLANs already uses for
// it, so a real target VLAN is still recognised as existing everywhere
// GetVLANs itself can see it.
func (w *Writer) requireVlanExists(ctx context.Context, vlan int) error {
	if w.spec.VlanConfigPath == "" {
		return nil
	}
	page, err := w.session.GetPage(ctx, w.spec.VlanConfigPath)
	if err != nil {
		return err
	}
	var known []int
	switch {
	case isGoAheadDialect(w.spec):
		names, err := ParseGoAheadVlanNames(page)
		if err != nil {
			return err
		}
		for id := range names {
			known = append(known, id)
		}
	case isFastpathDialect(w.spec):
		vlans, err := parseVlans(w.spec, page)
		if err != nil {
			return err
		}
		for _, v := range vlans {
			known = append(known, v.VlanID)
		}
	default:
		known, err = parseVlanIDs(w.spec, page)
		if err != nil {
			return err
		}
	}
	for _, id := range known {
		if id == vlan {
			return nil
		}
	}
	sort.Ints(known)
	return errUnexpectedPage("VLAN %d does not exist (known: %v)", vlan, known)
}

// SetPVID sets port's PVID, mirroring Python HttpWriter.set_pvid
// (http_write.py:651-664, updated by commit 98fb935). See this file's
// package doc comment for why this always uses the STANDARD-dialect
// ParsePVIDs verify, even on a FASTPATH/GS110EMX model -- a faithful port
// of a Python source quirk, not a Go-side choice. requireVlanExists above
// is NOT that quirk: it is the new GAP-1 precondition, dispatched
// correctly for every dialect (see its own doc comment for why it differs
// from Python's literal two-way branch).
func (w *Writer) SetPVID(ctx context.Context, port, vlan int, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	path, err := requirePath(w.model.Key, w.spec.PvidPath, "port PVIDs")
	if err != nil {
		return err
	}
	if err := w.requireVlanExists(ctx, vlan); err != nil {
		return err
	}
	page, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	csrf, err := requireCSRF(page)
	if err != nil {
		return err
	}
	if _, err := w.session.PostForm(ctx, path, PvidForm(port, vlan, csrf)); err != nil {
		return err
	}
	afterHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	afterPairs, err := ParsePVIDs(afterHTML)
	if err != nil {
		return err
	}
	after := pvidLookupMap(afterPairs)
	if got, ok := after[port]; !ok || got != vlan {
		var gotAny any
		if ok {
			gotAny = got
		}
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("PVID for port %d did not read back as %d", port, vlan),
			Before: nil,
			After:  gotAny,
		}
	}
	return nil
}

// SetVlanMembership sets port's membership mode within vlanID, mirroring
// Python HttpWriter.set_vlan_membership (http_write.py:666-691). FASTPATH
// models route through setFastpathMembership (the vlan_port_cfg_rw.html
// configured-view write); every other model uses the classic Plus-CGI
// 8021qMembe.cgi 3-step read/apply/verify.
func (w *Writer) SetVlanMembership(ctx context.Context, vlanID, port int, mode model.VlanMode, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	if isFastpathDialect(w.spec) {
		return w.setFastpathMembership(ctx, vlanID, port, mode)
	}
	path, err := requirePath(w.model.Key, w.spec.VlanMembershipPath, "VLAN membership")
	if err != nil {
		return err
	}
	html, err := w.session.PostForm(ctx, path, map[string]string{"VLAN_ID": strconv.Itoa(vlanID)})
	if err != nil {
		return err
	}
	states, err := ParseMembership(html, w.model.PortCount)
	if err != nil {
		return err
	}
	states[port] = mode
	hidden := MembershipHiddenMem(states, w.model.PortCount)
	// "before" below is states[port], which now equals mode because of the
	// mutation two lines up -- see this file's package doc comment: Python
	// does the identical thing, so `before` on this path is always just the
	// target mode, never the port's true prior state. Preserved verbatim.
	before := states[port]
	csrf, err := requireCSRF(html)
	if err != nil {
		return err
	}
	if _, err := w.session.PostForm(ctx, path, MembershipForm(vlanID, hidden, csrf)); err != nil {
		return err
	}
	verifyHTML, err := w.session.PostForm(ctx, path, map[string]string{"VLAN_ID": strconv.Itoa(vlanID)})
	if err != nil {
		return err
	}
	after, err := ParseMembership(verifyHTML, w.model.PortCount)
	if err != nil {
		return err
	}
	if after[port] != mode {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("VLAN %d port %d did not read back as %s", vlanID, port, mode),
			Before: before,
			After:  after[port],
		}
	}
	return nil
}

// setFastpathMembership sets one port's participation in vlan on the
// managed FASTPATH web UI, mirroring Python
// HttpWriter._set_fastpath_membership (http_write.py:693-736). Verification
// reads the page's CONFIGURED view (hiddenMem), never its CURRENT
// (hiddenTagged/hiddenUnTagged) egress lists -- see dossier D-HTTP-F §1.3/
// §2.1: those legitimately disagree for a port that is configured into a
// VLAN but currently link-down.
func (w *Writer) setFastpathMembership(ctx context.Context, vlan, port int, mode model.VlanMode) error {
	getPath, postPath, err := fastpathMembershipPaths(w.spec, w.model.Key)
	if err != nil {
		return err
	}
	before, err := w.readFastpathMembership(ctx, vlan, getPath, postPath)
	if err != nil {
		return err
	}
	hidden, err := FastpathHiddenMemWith(before, port, mode)
	if err != nil {
		return err
	}
	applied, err := w.session.PostForm(ctx, postPath, FastpathMembershipForm(before, vlan, &hidden, true))
	if err != nil {
		return err
	}
	if err := raiseOnFastpathErrFlag(applied, fmt.Sprintf("VLAN %d port %d -> %s", vlan, port, mode)); err != nil {
		return err
	}
	after, err := w.readFastpathMembership(ctx, vlan, getPath, postPath)
	if err != nil {
		return err
	}
	if got, ok := after.Configured[port]; !ok || got != mode {
		var gotAny, beforeAny any
		if ok {
			gotAny = got
		}
		if v, ok2 := before.Configured[port]; ok2 {
			beforeAny = v
		}
		return &model.WriteVerificationError{
			Msg: fmt.Sprintf("VLAN %d port %d did not read back as %s on %s (hiddenMem slot %d)",
				vlan, port, mode, postPath, before.PortSlots[port]),
			Before: beforeAny,
			After:  gotAny,
		}
	}
	return nil
}

// readFastpathMembership mirrors Python
// HttpWriter._read_fastpath_membership (http_write.py:738-749) -- the same
// GET-then-conditional-select-POST flow as Reader.ReadFastpathMembership,
// duplicated here (as the Python source duplicates it) so the Writer needs
// no Reader dependency and can reuse the getPath/postPath it already
// resolved.
func (w *Writer) readFastpathMembership(ctx context.Context, vlan int, getPath, postPath string) (FastpathMembership, error) {
	html, err := w.session.GetPage(ctx, getPath)
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
	respHTML, err := w.session.PostForm(ctx, postPath, body)
	if err != nil {
		return FastpathMembership{}, err
	}
	page2, err := ParseFastpathMembership(respHTML)
	if err != nil {
		return FastpathMembership{}, err
	}
	if err := requireFastpathMembershipFor(page2, vlan, postPath); err != nil {
		return FastpathMembership{}, err
	}
	return page2, nil
}

// CreateVlan creates vlanID, mirroring Python HttpWriter.create_vlan
// (http_write.py:751-762). name is accepted-but-unused: the web UI's
// 8021qCf.cgi form has no VLAN-name field (GROUNDED).
func (w *Writer) CreateVlan(ctx context.Context, vlanID int, name string) error {
	_ = name
	path, err := requirePath(w.model.Key, w.spec.VlanConfigPath, "VLAN config")
	if err != nil {
		return err
	}
	page, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	csrf, err := requireCSRF(page)
	if err != nil {
		return err
	}
	if _, err := w.session.PostForm(ctx, path, VlanAddForm(vlanID, csrf)); err != nil {
		return err
	}
	afterHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	after, err := ParseVLANIDs(afterHTML)
	if err != nil {
		return err
	}
	if !intSliceContains(after, vlanID) {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("VLAN %d was not created", vlanID),
			Before: nil,
			After:  after,
		}
	}
	return nil
}

// DeleteVlan deletes vlanID, mirroring Python HttpWriter.delete_vlan
// (http_write.py:764-781). force is accepted-but-unused: VLAN delete
// disruptiveness is guarded per-member elsewhere, matching the BackendWriter
// signature (see write_dispatch.go).
func (w *Writer) DeleteVlan(ctx context.Context, vlanID int, force bool) error {
	_ = force
	path, err := requirePath(w.model.Key, w.spec.VlanConfigPath, "VLAN config")
	if err != nil {
		return err
	}
	page, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	idx, ok := vlanCheckboxIndex(page, vlanID)
	if !ok {
		return errUnexpectedPage("VLAN %d not present to delete", vlanID)
	}
	csrf, err := requireCSRF(page)
	if err != nil {
		return err
	}
	if _, err := w.session.PostForm(ctx, path, VlanDeleteForm(vlanID, idx, csrf)); err != nil {
		return err
	}
	afterHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	after, err := ParseVLANIDs(afterHTML)
	if err != nil {
		return err
	}
	if intSliceContains(after, vlanID) {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("VLAN %d was not deleted", vlanID),
			Before: nil,
			After:  after,
		}
	}
	return nil
}

func intSliceContains(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// Reboot reboots the switch, mirroring Python HttpWriter.reboot
// (http_write.py:783-795). Capability is resolved BEFORE the force gate, so
// a model with no reboot endpoint raises the accurate
// UnsupportedCapabilityError rather than ProtectedPortError. Not part of
// the root package's BackendWriter interface (which has no Reboot op yet);
// exported here for source-fidelity completeness and for a future facade
// task to wire up.
func (w *Writer) Reboot(ctx context.Context, force bool) error {
	rebootPath, err := requirePath(w.model.Key, w.spec.RebootPath, "web reboot")
	if err != nil {
		return err
	}
	if !force {
		return fmt.Errorf("reboot is disruptive; pass force=true: %w", model.ErrProtectedPort)
	}
	landing := w.spec.VlanConfigPath
	if landing == "" {
		landing = w.spec.DashboardPath
	}
	landingPath, err := requirePath(w.model.Key, landing, "web reboot")
	if err != nil {
		return err
	}
	page, err := w.session.GetPage(ctx, landingPath)
	if err != nil {
		return err
	}
	csrf, err := requireCSRF(page)
	if err != nil {
		return err
	}
	_, err = w.session.PostForm(ctx, rebootPath, RebootForm(csrf))
	return err
}

// SetPortEnabled sets port's admin mode, mirroring Python
// HttpWriter.set_port_enabled (http_write.py:797-844). GS110EMX routes to
// setGS110EMXPortEnabled (a genuinely different mechanism, its own
// port_settings.html Physical Mode POST); every other managed model drives
// the shared FASTPATH XUI grid (portsConfiguration.html). Plus-class models
// (gs305ep/gs105pe) have port_config_path == "" at this pin and so raise
// via requirePath -- no Plus-class implementation exists yet, honestly.
func (w *Writer) SetPortEnabled(ctx context.Context, port int, enabled, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	path, err := requirePath(w.model.Key, w.spec.PortConfigPath, "the port-configuration page")
	if err != nil {
		return err
	}
	if w.spec.HTMLDialect == HTMLDialectGS110EMX {
		return w.setGS110EMXPortEnabled(ctx, path, port, enabled)
	}
	html, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	page, err := ParseXUIListPage(html, path)
	if err != nil {
		return err
	}
	row, err := findXUIRow(page, port, xuiPortIfname, fmt.Sprintf("%q port configuration", w.model.Key))
	if err != nil {
		return err
	}
	before, _ := row.Field(xuiPortAdmin)
	body, err := XuiRowApplyForm(page, row, map[string]string{xuiPortAdmin: xuiEnabled(enabled)}, "v_2_1_2", nil)
	if err != nil {
		return err
	}
	applied, err := w.session.PostForm(ctx, page.Action, body)
	if err != nil {
		return err
	}
	if err := raiseOnFastpathErrFlag(applied, fmt.Sprintf("port %d admin mode -> %v", port, enabled)); err != nil {
		return err
	}
	afterHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	afterPage, err := ParseXUIListPage(afterHTML, path)
	if err != nil {
		return err
	}
	afterRow, err := findXUIRow(afterPage, port, xuiPortIfname, fmt.Sprintf("%q port configuration", w.model.Key))
	if err != nil {
		return err
	}
	after, _ := afterRow.Field(xuiPortAdmin)
	if after != xuiEnabled(enabled) {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("port %d admin mode did not read back as %q on %s", port, xuiEnabled(enabled), path),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// setGS110EMXPortEnabled sets port admin mode on the GS110EMX's
// port_settings.html, mirroring Python
// HttpWriter._set_gs110emx_port_enabled (http_write.py:846-882). A
// genuinely different mechanism from the FASTPATH grid: this page has no
// admin column at all -- disabling means POSTing Physical Mode as Disable.
// flowControlMode is ECHOED from the port's own current row, never
// defaulted (see forms.go's GS110EMXPortAdminForm doc comment).
func (w *Writer) setGS110EMXPortEnabled(ctx context.Context, path string, port int, enabled bool) error {
	html, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	rows, err := ParseGS110EMXPortFormFields(html)
	if err != nil {
		return err
	}
	fields, ok := rows[port]
	if !ok {
		return fmt.Errorf("%q port configuration: port %d is not on this page (it renders %v): %w",
			w.model.Key, port, sortedRowPorts(rows), model.ErrUnsupportedCapability)
	}
	beforeStatus, err := ParseGS110EMXPortStatus(html)
	if err != nil {
		return err
	}
	was := adminEnabledFor(beforeStatus, port)
	flow := fields["FLOW_CONTROL_MODE"]
	if flow == "" {
		flow = "0"
	}
	if _, err := w.session.PostForm(ctx, path, GS110EMXPortAdminForm(port, enabled, flow)); err != nil {
		return err
	}
	afterHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	afterStatus, err := ParseGS110EMXPortStatus(afterHTML)
	if err != nil {
		return err
	}
	got := adminEnabledFor(afterStatus, port)
	if got == nil || *got != enabled {
		var gotAny any
		if got != nil {
			gotAny = *got
		}
		var wasAny any
		if was != nil {
			wasAny = *was
		}
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("port %d admin mode did not read back as %v on %s", port, enabled, path),
			Before: wasAny,
			After:  gotAny,
		}
	}
	return nil
}

// adminEnabledFor returns statuses[i].AdminEnabled for the row whose Port
// equals port, or nil if absent -- mirrors Python's
// `next((p.admin_enabled for p in status if p.port == port), None)`.
func adminEnabledFor(statuses []model.PortStatus, port int) *bool {
	for _, s := range statuses {
		if s.Port == port {
			v := s.AdminEnabled
			return &v
		}
	}
	return nil
}

// strPtrEqual reports whether a and b are both nil, or both non-nil with
// the same referenced value -- used by SetPortDescription's verify step.
func strPtrEqual(a, b *string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

// quoteOrNone renders s quoted, or "None" if s is nil -- mirrors Python's
// `{want!r}` repr for an Optional[str] in SetPortDescription's verification
// message.
func quoteOrNone(s *string) string {
	if s == nil {
		return "None"
	}
	return strconv.Quote(*s)
}

// goaheadWrite POSTs body to this model's single shared "wcd" XML-API write
// endpoint and raises unless the switch's own status reports success,
// mirroring Python HttpWriter._goahead_write.
func (w *Writer) goaheadWrite(ctx context.Context, body, what string) error {
	path, err := requirePath(w.model.Key, w.spec.XMLWritePath, "XML-API write endpoint")
	if err != nil {
		return err
	}
	resp, err := w.session.PostXML(ctx, path, body)
	if err != nil {
		return err
	}
	return checkGoAheadStatus(resp, what)
}

// goaheadPortRow returns port's current model.PortStatus off the GoAhead
// ports page at path, or nil if that port is absent from the parsed rows.
func (w *Writer) goaheadPortRow(ctx context.Context, path string, port int) (*model.PortStatus, error) {
	html, err := w.session.GetPage(ctx, path)
	if err != nil {
		return nil, err
	}
	rows, err := ParseGoAheadPorts(html)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Port == port {
			return &rows[i], nil
		}
	}
	return nil, nil
}

// SetPortDescription labels port through the GS728TPP ports page's
// interfaceDescription, mirroring Python HttpWriter.set_port_description.
//
// XML-API (GOAHEAD_XML) only for now: that page carries the field and the
// read side already parses it. The FASTPATH XUI port pages have a
// description column too, but its cell id has not been captured, and
// guessing one would post into an unknown cell.
func (w *Writer) SetPortDescription(ctx context.Context, port int, description string, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	if !isGoAheadDialect(w.spec) {
		return fmt.Errorf("model %q: no HTTP port-description write is built for this web UI dialect: %w", w.model.Key, model.ErrUnsupportedCapability)
	}
	path, err := requirePath(w.model.Key, w.spec.DashboardPath, "the ports page")
	if err != nil {
		return err
	}
	beforeRow, err := w.goaheadPortRow(ctx, path, port)
	if err != nil {
		return err
	}
	var before *string
	if beforeRow != nil {
		before = beforeRow.Description
	}
	body := portConfigBody(portInterfaceName(port), port, description)
	if err := w.goaheadWrite(ctx, body, fmt.Sprintf("port %d description", port)); err != nil {
		return err
	}
	afterRow, err := w.goaheadPortRow(ctx, path, port)
	if err != nil {
		return err
	}
	var after *string
	if afterRow != nil {
		after = afterRow.Description
	}
	var want *string
	if description != "" {
		want = &description
	}
	if !strPtrEqual(after, want) {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("description for port %d did not read back as %s", port, quoteOrNone(want)),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// SetPortSpeed sets port's speed/duplex through the ports page's admin
// fields, mirroring Python HttpWriter.set_port_speed.
//
// XML-API only. That page's Standard802_3List carries
// autoNegotiationAdminEnabled/speedAdmin/duplexAdminMode, the read side
// already parses them, and the exact encoding is transcribed from the
// page's own submit JS (see portSpeedBody, goahead_write.go). The FASTPATH
// XUI port pages have a Speed control too, but its cell id has not been
// captured, and guessing one would post into an unknown cell.
//
// A rate the page's own dropdown does not offer is refused by name: the
// slctPortSpeed <option> set is 10/100 half-or-full, 1000 FULL ONLY, and
// Auto. Note this UI DOES offer a forced 1000 where the FASTPATH CLI does
// not -- which is exactly why that refusal lives in fastpath.Writer.
// SetPortSpeed and not in model.PortSpeed itself.
//
// Disruptive -- applying a speed bounces the link -- so it honours
// protected_ports.
func (w *Writer) SetPortSpeed(ctx context.Context, port int, speed model.PortSpeed, force bool) error {
	if err := w.guard(port, force); err != nil {
		return err
	}
	if !isGoAheadDialect(w.spec) {
		return fmt.Errorf("model %q: no HTTP speed/duplex write form has been captured for this web UI dialect: %w", w.model.Key, model.ErrUnsupportedCapability)
	}
	if !speed.Autonegotiate {
		mbps := 0
		if speed.SpeedMbps != nil {
			mbps = *speed.SpeedMbps
		}
		full := speed.FullDuplex != nil && *speed.FullDuplex
		if !isGoAheadForcedSpeed(mbps, full) {
			return fmt.Errorf("model %q: this web UI offers no %s choice (its Speed control lists 10/100 half or full, 1000 full, and Auto): %w", w.model.Key, speed, model.ErrUnsupportedCapability)
		}
	}
	path, err := requirePath(w.model.Key, w.spec.DashboardPath, "the ports page")
	if err != nil {
		return err
	}
	beforeRow, err := w.goaheadPortRow(ctx, path, port)
	if err != nil {
		return err
	}
	var before *model.PortSpeed
	if beforeRow != nil {
		before = beforeRow.SpeedConfig
	}
	body := portSpeedBody(portInterfaceName(port), port, speed)
	if err := w.goaheadWrite(ctx, body, fmt.Sprintf("port %d speed -> %s", port, speed)); err != nil {
		return err
	}
	afterRow, err := w.goaheadPortRow(ctx, path, port)
	if err != nil {
		return err
	}
	var after *model.PortSpeed
	if afterRow != nil {
		after = afterRow.SpeedConfig
	}
	if after == nil || !after.Equal(speed) {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("speed for port %d did not read back as %s", port, speed),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// SetFlowControl always returns an error wrapping
// model.ErrUnsupportedCapability: this backend cannot configure flow
// control on this UI. Mirrors Python HttpWriter.set_flow_control.
//
// Refused by name, and this one is a MEASURED absence rather than an
// unsearched one. The GoAhead ports page publishes flowControlAdminType/
// flowControlOperType but has no control for either: its slct* selects are
// Admin Mode and Port Speed only, and its submit builder emits no
// flow-control field at all (see webui/testdata/http/gs728tpp_ports.xml).
// Flow control lives on a different page of that UI which has not been
// captured, and the FASTPATH XUI equivalent has not either. No guard call
// (unlike SetPortDescription/SetPortSpeed) -- mirroring Python exactly:
// there is nothing here to protect, since nothing is ever sent. Every
// parameter is accepted-but-unused, purely so this method's signature
// matches the shared BackendWriter surface (see the root package's
// write_dispatch.go).
func (w *Writer) SetFlowControl(_ context.Context, _ int, _ bool, _ bool) error {
	return fmt.Errorf("model %q: this web UI's ports page reports flow control but carries no control to change it: %w", w.model.Key, model.ErrUnsupportedCapability)
}

// SetSyslogEnabled always returns an error wrapping
// model.ErrUnsupportedCapability: this backend does not serve a
// remote-logging toggle. Mirrors Python HttpWriter.set_syslog_enabled.
//
// Refused by name rather than returned empty: an empty answer here would be
// indistinguishable from a switch that genuinely has none. Every parameter
// is accepted-but-unused, purely so this method's signature matches the
// shared BackendWriter surface (see the root package's write_dispatch.go).
func (w *Writer) SetSyslogEnabled(_ context.Context, _ bool, _ bool) error {
	return fmt.Errorf("model %q: this backend does not expose a remote-logging toggle: %w", w.model.Key, model.ErrUnsupportedCapability)
}

// syslogPath returns w.spec.SyslogPath or refuses honestly, mirroring
// Python HttpWriter._syslog_path.
func (w *Writer) syslogPath() (string, error) {
	return requirePath(w.model.Key, w.spec.SyslogPath, "remote-logging configuration")
}

// syslogPage fetches and parses the syslog page as an XUI list, mirroring
// Python HttpWriter._syslog_page.
//
// Only the two M4300 pages inline the cell metadata this write depends on
// and render the template row; gsm7252ps/gsm7228ps declare nine xeData
// entries and load the rest from a resource no capture has followed, so
// their coordinates are NOT established and they are refused here rather
// than posted at on the assumption they match.
func (w *Writer) syslogPage(ctx context.Context) (XuiListPage, error) {
	if w.spec.HTMLDialect != HTMLDialectM4300 {
		return XuiListPage{}, fmt.Errorf(
			"model %q: no syslog-collector row write is grounded for this web UI dialect (only the M4300 pages render the template row and declare their cell metadata): %w",
			w.model.Key, model.ErrUnsupportedCapability)
	}
	path, err := w.syslogPath()
	if err != nil {
		return XuiListPage{}, err
	}
	html, err := w.session.GetPage(ctx, path)
	if err != nil {
		return XuiListPage{}, err
	}
	page, err := ParseXUIListPage(html, "syslog configuration")
	if err != nil {
		return XuiListPage{}, err
	}
	if len(page.Template) == 0 {
		return XuiListPage{}, errUnexpectedPage(
			"the syslog page renders no v_g_* template row, so a collector cannot be added through it")
	}
	return page, nil
}

// AddSyslogCollector always returns an error wrapping
// model.ErrUnsupportedCapability: this UI will not accept a collector ADD
// -- established, not assumed.
//
// The template row is real and reachable: the page renders
// v_g_2_1_1..v_g_2_1_7 in the served HTML, and this library can build the
// body. What the FIRMWARE does with it, driven live against m4300-24x
// 10.1.5.13 on 2026-08-05, is refuse -- HTTP 200 with "Error! Failed to
// Set 'Host Address' with '<value>'" and the collector table unchanged
// (checked through the switch's own CLI, an independent witness). Three of
// the four fields can be made to stick and the address cannot; the
// remaining step is one capture of a real browser Add submission to diff
// against.
//
// The DELETE path on the same page DOES work and is live-verified; see
// RemoveSyslogCollector. Add over a CLI backend. Every parameter is
// accepted-but-unused, purely so this method's signature matches every
// other writer.
func (w *Writer) AddSyslogCollector(_ context.Context, _ string, _, _ int, _ bool) error {
	return fmt.Errorf(
		"model %q: this web UI refuses a collector add (measured: HTTP 200 + \"Failed to Set 'Host Address'\"); the page's delete works, and the CLI backend adds: %w",
		w.model.Key, model.ErrUnsupportedCapability)
}

// RemoveSyslogCollector removes a collector by marking its row-status
// "Delete", mirroring Python HttpWriter.remove_syslog_collector
// (http_write.py:1620-1650).
//
// The page's Delete action array writes "Delete" into the same write-only
// cell an Add sets to "Active". The row is addressed by its OWN rendered
// fields and checkbox, so no index arithmetic is involved -- unlike the CLI
// and SNMP routes, whose sparse table index bit once already. force is
// accepted-but-unused: redirecting logs cannot strand a switch.
func (w *Writer) RemoveSyslogCollector(ctx context.Context, host string, _ bool) error {
	page, err := w.syslogPage(ctx)
	if err != nil {
		return err
	}
	path, err := w.syslogPath()
	if err != nil {
		return err
	}
	beforeHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	before, err := ParseXUISyslog(beforeHTML)
	if err != nil {
		return err
	}
	beforeHas := false
	for _, s := range before.Servers {
		if s.Host == host {
			beforeHas = true
			break
		}
	}
	if !beforeHas {
		return errUnexpectedPage("no syslog collector for %q to remove", host)
	}
	row, ok := page.RowFor(xuiSyslogHostAddressCol, host)
	if !ok {
		return errUnexpectedPage("the syslog page renders no row for %q", host)
	}
	body, err := XuiRowApplyForm(page, row, map[string]string{xuiSyslogHostRowStatus: xuiSyslogRowStatusDelete}, xuiSyslogDeleteButton, nil)
	if err != nil {
		return err
	}
	if _, err := w.session.PostForm(ctx, page.Action, body); err != nil {
		return err
	}
	afterHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	after, err := ParseXUISyslog(afterHTML)
	if err != nil {
		return err
	}
	for _, s := range after.Servers {
		if s.Host == host {
			return &model.WriteVerificationError{
				Msg:    fmt.Sprintf("syslog collector %q is still configured after delete", host),
				Before: before.Servers,
				After:  after.Servers,
			}
		}
	}
	return nil
}

// emxNameMax is the GS110EMX sysInfo name box's maxlength="20"; its own
// checkValidName() additionally rejects anything outside printable ASCII.
// Both read off the live page (10.1.5.27, 2026-08-05), mirroring Python
// http_write._EMX_NAME_MAX.
const emxNameMax = 20

// isASCIIPrintable reports whether every byte of s is printable ASCII
// (0x20-0x7E inclusive), mirroring Python's `name.isascii() and
// name.isprintable()` combination for an ASCII-only string: for ASCII text,
// Python's isprintable() is false for exactly the control characters
// (0x00-0x1F, 0x7F), so the combined check is equivalent to "every
// character is in 0x20-0x7E" -- precisely the range the GS110EMX page's own
// checkValidName() builds from `for (var i = 32; i < 127; i++)`. Checking
// BYTES (not runes) is deliberate and still correct: any multi-byte UTF-8
// sequence for a non-ASCII rune is made of bytes >= 0x80, so it fails this
// same byte-range test without needing a separate isascii() pass -- an em
// dash is rejected exactly as Python's isascii()-then-isprintable() combo
// rejects it (isprintable() alone is Unicode-aware and would have let it
// through).
func isASCIIPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// SetHostname sets the host name, where this dialect's identity page
// carries one, mirroring Python HttpWriter.set_hostname (http_write.py:
// 1346-1387).
//
// Two dialects, and they are nothing alike:
//
//   - GoAhead XML API -- DeviceBasicInfo/deviceName IS the host name
//     (MEASURED: it reads byte-for-byte what SNMP reports through sysName).
//   - GS110EMX -- an ordinary form POST, but the host name shares that form
//     with the MANAGEMENT ADDRESS, so it is a read-modify-write. See
//     setGS110EMXHostname.
//
// Every other dialect is refused by name rather than returned empty: an
// empty answer here would be indistinguishable from a switch that genuinely
// has none.
//
// Not force-gated: renaming cannot strand a switch and is reversible by
// writing the old name back. force is accepted-but-unused, purely so this
// method's signature matches every other writer.
func (w *Writer) SetHostname(ctx context.Context, name string, _ bool) error {
	if w.spec.HTMLDialect == HTMLDialectGS110EMX {
		return w.setGS110EMXHostname(ctx, name)
	}
	if !isGoAheadDialect(w.spec) {
		return fmt.Errorf("model %q: this backend does not expose a host-name write: %w", w.model.Key, model.ErrUnsupportedCapability)
	}
	path, err := requirePath(w.model.Key, w.spec.SysinfoPath, "the system-information page")
	if err != nil {
		return err
	}
	beforeHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	before, err := ParseGoAheadHostname(beforeHTML)
	if err != nil {
		return err
	}
	// DeviceBasicInfo is a SCALAR section, so the body carries the field
	// directly rather than a repeated <Entry>. The page's own JS rejects
	// '&' in this field client-side; the value is XML-escaped here, and the
	// switch's own verdict is what checkGoAheadStatus reports.
	if err := w.goaheadWrite(ctx, deviceBasicInfoBody(name), fmt.Sprintf("hostname -> %q", name)); err != nil {
		return err
	}
	afterHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	after, err := ParseGoAheadHostname(afterHTML)
	if err != nil {
		return err
	}
	if after != name {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("hostname did not read back as %q", name),
			Before: before,
			After:  after,
		}
	}
	return nil
}

// setGS110EMXHostname renames a GS110EMX through its sysInfo form, without
// moving its address, mirroring Python HttpWriter._set_gs110emx_hostname
// (http_write.py:1388-1472).
//
// THE DANGEROUS ONE. That page posts the host name in the SAME form as
// dhcp_mode/IP_ADDRESS/SUBNET_MASK/GATEWAY_ADDRESS, so a rename is
// unavoidably a read-modify-write: the current addressing is read from the
// page and echoed back verbatim, and the write is only considered done once
// a re-read shows the new name AND every addressing field unchanged.
// Getting that wrong does not fail the rename, it reconfigures the address
// the caller is talking to.
//
// The envelope is the page's own submitSwitchInfoForm() (read from the live
// switch's /function.js, 2026-08-05) -- see GS110EMXSwitchInfoForm.
//
// LIVE-VERIFIED 2026-08-05 on gs110emx3 (10.1.5.27, firmware 1.0.2.8):
// renamed to a throwaway, confirmed the addressing was byte-identical,
// restored the original name and confirmed again.
func (w *Writer) setGS110EMXHostname(ctx context.Context, name string) error {
	// The page's own checkValidName() builds its allowed set from
	// `for (var i = 32; i < 127; i++)` -- so ASCII 32..126, and nothing
	// else. The input carries maxlength="20". Enforced here so the caller
	// gets a reason rather than a silently blanked field (that validator
	// sets the box to "" and pops an alert on failure).
	if name == "" || len(name) > emxNameMax || !isASCIIPrintable(name) {
		return fmt.Errorf(
			"GS110EMX host name %q is not acceptable to this page: it takes 1-%d printable ASCII characters: %w",
			name, emxNameMax, model.ErrUnsupportedCapability,
		)
	}
	path, err := requirePath(w.model.Key, w.spec.SysinfoPath, "the system-information page")
	if err != nil {
		return err
	}
	beforeHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	before, err := ParseSysInfo(beforeHTML)
	if err != nil {
		return err
	}
	dhcpMode := emxDHCPOff
	if before.IPMode == model.IPModeDHCP {
		dhcpMode = emxDHCPOn
	}
	if _, err := w.session.PostForm(ctx, path, GS110EMXSwitchInfoForm(name, dhcpMode, before.IPAddress, before.SubnetMask, before.GatewayAddress)); err != nil {
		return err
	}
	afterHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	after, err := ParseSysInfo(afterHTML)
	if err != nil {
		return err
	}
	// The addressing check comes FIRST and is the one that matters: a
	// rename that moved the management address is a far worse outcome than
	// a rename that did not happen, and the caller must hear about it even
	// if the name did change.
	if after.IPMode != before.IPMode || after.IPAddress != before.IPAddress ||
		after.SubnetMask != before.SubnetMask || after.GatewayAddress != before.GatewayAddress {
		return &model.WriteVerificationError{
			Msg:    "the host-name write CHANGED this switch's management addressing -- it may be unreachable at the old address",
			Before: [4]string{string(before.IPMode), before.IPAddress, before.SubnetMask, before.GatewayAddress},
			After:  [4]string{string(after.IPMode), after.IPAddress, after.SubnetMask, after.GatewayAddress},
		}
	}
	if after.SwitchName != name {
		return &model.WriteVerificationError{
			Msg:    fmt.Sprintf("hostname did not read back as %q", name),
			Before: before.SwitchName,
			After:  after.SwitchName,
		}
	}
	return nil
}

// SetMgmtIP sets the switch's static management address through its web
// UI, mirroring Python HttpWriter.set_mgmt_ip (http_write.py:884-940).
//
// The APPLY on this path is UNVERIFIED against live hardware, and
// deliberately so -- applying it to a real reachable switch would move the
// address the session is using and risk stranding the device. What IS
// exercised here: the page/field resolution, the shared XUI apply machinery
// (submit_flag, err_flag refusal check) SetPortEnabled/SetVlanMembership
// already prove live, and this method's own verify-after-write readback
// against the mock. See dossier D-HTTP-F §2.7 for the full caveat -- do not
// treat this op as "live-verified" in the same sense as those two.
func (w *Writer) SetMgmtIP(ctx context.Context, address, netmask, gateway string, force bool) error {
	path, fields, err := requireXUIMgmtFields(w.spec)
	if err != nil {
		return err
	}
	if !force {
		return fmt.Errorf("set_mgmt_ip moves the address this session is using and can leave the switch unreachable; pass force=true: %w", model.ErrProtectedPort)
	}
	html, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	page, err := ParseXUIFormPage(html, path)
	if err != nil {
		return err
	}
	body, err := XuiFormApplyForm(page, mgmtIPChanges(fields, address, netmask, gateway), fields.ApplyButton)
	if err != nil {
		return err
	}
	applied, err := w.session.PostForm(ctx, page.Action, body)
	if err != nil {
		return err
	}
	if err := raiseOnFastpathErrFlag(applied, fmt.Sprintf("management IP -> %s/%s", address, netmask)); err != nil {
		return err
	}
	afterHTML, err := w.session.GetPage(ctx, path)
	if err != nil {
		return err
	}
	afterPage, err := ParseXUIFormPage(afterHTML, path)
	if err != nil {
		return err
	}
	gotAddr, gotMask, gotGw := afterPage.Fields[fields.Address], afterPage.Fields[fields.Netmask], afterPage.Fields[fields.Gateway]
	if gotAddr != address || gotMask != netmask || gotGw != gateway {
		return &model.WriteVerificationError{
			Msg: fmt.Sprintf("management IP did not read back as %s/%s via %s on %s", address, netmask, gateway, path),
			Before: [3]string{
				page.Fields[fields.Address], page.Fields[fields.Netmask], page.Fields[fields.Gateway],
			},
			After: [3]string{gotAddr, gotMask, gotGw},
		}
	}
	return nil
}
