package webui_test

// writer_xui_test.go: TDD coverage for webui.Writer's FASTPATH "XUI" write
// paths (SetPortEnabled/SetPoE/ClearPoEFault/SetMgmtIP/SetVlanMembership on
// the managed models) and the GS110EMX's own differently-shaped port-admin
// mechanism, ported scenario-for-scenario from tests/test_http_xui_writes.py
// and tests/test_http_vlan_membership.py at pin 1841111 in
// python-netgear-switch-library. Those Python tests drive against a live
// virtual HTTP face (VirtualHttpFace); this Go port has no such face yet
// (a later slice-06 task), so xuiFakeSession below reproduces the same
// verify-after-write property directly against real captured fixtures: GET
// returns the CURRENT stored html for a path, POST records the call and (if
// honourWrites) mutates the underlying page's own NAME=.../VALUE="..."
// fields in place -- so a subsequent GET reflects exactly what was written,
// exactly what a real firmware round trip would show.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// setNamedFieldValue rewrites the VALUE="..." attribute of the FIRST hidden
// input/field named name in html (quoted or unquoted NAME=), mirroring how
// a stateful firmware would re-render a page after an apply. ok=false means
// html has no such field -- a no-op, not an error, since not every posted
// key corresponds to a literal page field (checkboxes carry no value
// attribute at all).
func setNamedFieldValue(html, name, value string) (string, bool) {
	re := regexp.MustCompile(`(?i)NAME="?` + regexp.QuoteMeta(name) + `"?([^>]*?)VALUE="([^"]*)"`)
	loc := re.FindStringSubmatchIndex(html)
	if loc == nil {
		return html, false
	}
	return html[:loc[4]] + value + html[loc[5]:], true
}

// xuiFakeSession is an in-memory webui.Session over real captured FASTPATH
// XUI fixtures. routes maps a POST target that is NOT its own read path
// (the FASTPATH VLAN-membership page's _rw.html apply target) to the read
// path whose stored html should be mutated; a POST target ending in "/a1"
// (every other XUI page in this fixture set) is mapped by stripping that
// suffix without needing an entry in routes.
type xuiFakeSession struct {
	pages        map[string]string
	routes       map[string]string
	honourWrites bool
	errFlag      bool // when true, every apply response reports err_flag=1
	posts        []postRecord
}

func newXUIFakeSession(pages map[string]string) *xuiFakeSession {
	return &xuiFakeSession{pages: pages, routes: map[string]string{}, honourWrites: true}
}

func (s *xuiFakeSession) Login(context.Context) error { return nil }

func (s *xuiFakeSession) GetPage(_ context.Context, path string) (string, error) {
	html, ok := s.pages[path]
	if !ok {
		return "", fmt.Errorf("xuiFakeSession: no page registered for %q", path)
	}
	return html, nil
}

func (s *xuiFakeSession) readPathFor(postPath string) string {
	if rp, ok := s.routes[postPath]; ok {
		return rp
	}
	if rp := strings.TrimSuffix(postPath, "/a1"); rp != postPath {
		return rp
	}
	return postPath
}

func (s *xuiFakeSession) PostForm(_ context.Context, path string, data map[string]string) (string, error) {
	s.posts = append(s.posts, postRecord{path: path, data: cloneMap(data)})
	readPath := s.readPathFor(path)
	html, ok := s.pages[readPath]
	if !ok {
		return "", fmt.Errorf("xuiFakeSession: PostForm to %q has no backing page %q", path, readPath)
	}
	if s.honourWrites {
		for name, value := range data {
			if mutated, changed := setNamedFieldValue(html, name, value); changed {
				html = mutated
			}
		}
		s.pages[readPath] = html
	}
	response := html
	if s.errFlag {
		if mutated, ok := setNamedFieldValue(response, "err_flag", "1"); ok {
			response = mutated
		}
		if mutated, ok := setNamedFieldValue(response, "err_msg", "switch refused the write"); ok {
			response = mutated
		}
	}
	return response, nil
}

func (s *xuiFakeSession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	return "", fmt.Errorf("xuiFakeSession: PostMultipart(%q) not supported by this fake", path)
}

func (s *xuiFakeSession) PostXML(_ context.Context, path string, _ string) (string, error) {
	return "", fmt.Errorf("xuiFakeSession: PostXML(%q) not supported by this fake", path)
}

var _ webui.Session = (*xuiFakeSession)(nil)

// hasSuffixedKey/valueForSuffixedKey look up a row-prefixed field
// ("1.0.48.v_1_2_2") by its bare column name ("v_1_2_2") -- XuiRowApplyForm
// always sends fields under row.Prefix+column, never the bare name.
func hasSuffixedKey(data map[string]string, column string) bool {
	_, ok := valueForSuffixedKey(data, column)
	return ok
}

func valueForSuffixedKey(data map[string]string, column string) (string, bool) {
	for k, v := range data {
		if strings.HasSuffix(k, column) {
			return v, true
		}
	}
	return "", false
}

func fastpathErrContains(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want one containing %q", substr)
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want model.ErrHTTP", err)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Errorf("error = %q, want it to contain %q", err.Error(), substr)
	}
}

// --- gsm7252ps SetPortEnabled (portsConfiguration.html) ---------------------

func TestFastpathSetPortEnabledRoundTrip(t *testing.T) {
	sess := newXUIFakeSession(map[string]string{
		"/portsConfiguration.html": readFixture(t, "gsm7252ps_portsConfiguration.html"),
	})
	w := mustNewWriter(t, sess, "gsm7252ps")

	if err := w.SetPortEnabled(context.Background(), 7, false, false); err != nil {
		t.Fatalf("SetPortEnabled(7, false) error = %v", err)
	}
	page, err := webui.ParseXUIListPage(sess.pages["/portsConfiguration.html"], "")
	if err != nil {
		t.Fatalf("ParseXUIListPage() error = %v", err)
	}
	row, ok := page.RowFor("v_1_2_1", "1/0/7")
	if !ok {
		t.Fatalf("port 7's row not found after write")
	}
	if got, _ := row.Field("v_1_2_6"); got != "Disable" {
		t.Errorf("v_1_2_6 after disable = %q, want \"Disable\"", got)
	}

	if err := w.SetPortEnabled(context.Background(), 7, true, false); err != nil {
		t.Fatalf("SetPortEnabled(7, true) error = %v", err)
	}
	page, err = webui.ParseXUIListPage(sess.pages["/portsConfiguration.html"], "")
	if err != nil {
		t.Fatalf("ParseXUIListPage() error = %v", err)
	}
	row, _ = page.RowFor("v_1_2_1", "1/0/7")
	if got, _ := row.Field("v_1_2_6"); got != "Enable" {
		t.Errorf("v_1_2_6 after re-enable = %q, want \"Enable\"", got)
	}
}

func TestFastpathSetPortEnabledSurfacesSwitchRefusal(t *testing.T) {
	sess := newXUIFakeSession(map[string]string{
		"/portsConfiguration.html": readFixture(t, "gsm7252ps_portsConfiguration.html"),
	})
	sess.honourWrites = false
	sess.errFlag = true
	w := mustNewWriter(t, sess, "gsm7252ps")
	err := w.SetPortEnabled(context.Background(), 7, false, false)
	fastpathErrContains(t, err, "switch refused")
}

func TestFastpathSetPortEnabledRejectsAPortThePageDoesNotRender(t *testing.T) {
	sess := newXUIFakeSession(map[string]string{
		"/portsConfiguration.html": readFixture(t, "gsm7252ps_portsConfiguration.html"),
	})
	w := mustNewWriter(t, sess, "gsm7252ps")
	err := w.SetPortEnabled(context.Background(), 99, false, false)
	wantUnsupported(t, err, "SetPortEnabled(99)")
	if !strings.Contains(err.Error(), "not on this page") {
		t.Errorf("error = %q, want it to contain \"not on this page\"", err.Error())
	}
}

// --- gsm7252ps SetPoE / ClearPoEFault (poeInterfaceConfiguration.html) -----

func TestFastpathSetPoERoundTripCarriesListUnit(t *testing.T) {
	sess := newXUIFakeSession(map[string]string{
		"/poeInterfaceConfiguration.html": readFixture(t, "gsm7252ps_poeInterfaceConfiguration.html"),
	})
	w := mustNewWriter(t, sess, "gsm7252ps")

	if err := w.SetPoE(context.Background(), 1, false, false); err != nil {
		t.Fatalf("SetPoE(1, false) error = %v", err)
	}
	page, err := webui.ParseXUIListPage(sess.pages["/poeInterfaceConfiguration.html"], "")
	if err != nil {
		t.Fatalf("ParseXUIListPage() error = %v", err)
	}
	row, ok := page.RowFor("v_1_2_1", "1/0/1")
	if !ok {
		t.Fatalf("port 1's PoE row not found after write")
	}
	if got, _ := row.Field("v_1_2_2"); got != "Disable" {
		t.Errorf("v_1_2_2 after disable = %q, want \"Disable\"", got)
	}

	// THE gsm7252ps fix (dossier D-HTTP-F §2.6): the apply body must carry
	// the page's own list-unit nav fields, or real hardware answers
	// err_flag=1 for every column even on a no-op body.
	var applyPost *postRecord
	for i := range sess.posts {
		if hasSuffixedKey(sess.posts[i].data, "v_1_2_2") {
			applyPost = &sess.posts[i]
		}
	}
	if applyPost == nil {
		t.Fatalf("no POST carried v_1_2_2")
	}
	if applyPost.data["v_1_1_1"] != "1" || applyPost.data["v_1_3_1"] != "1" {
		t.Errorf("apply body nav fields v_1_1_1/v_1_3_1 = %q/%q, want \"1\"/\"1\"",
			applyPost.data["v_1_1_1"], applyPost.data["v_1_3_1"])
	}
	// APPLY must never carry the write-only Port Reset column (its own shed
	// list omits it) -- see xuiPoEApplyOmits.
	if hasSuffixedKey(applyPost.data, "v_1_2_20") {
		t.Errorf("apply body carries the write-only v_1_2_20 Port Reset column, want omitted")
	}

	if err := w.SetPoE(context.Background(), 1, true, false); err != nil {
		t.Fatalf("SetPoE(1, true) error = %v", err)
	}
	page, err = webui.ParseXUIListPage(sess.pages["/poeInterfaceConfiguration.html"], "")
	if err != nil {
		t.Fatalf("ParseXUIListPage() error = %v", err)
	}
	row, _ = page.RowFor("v_1_2_1", "1/0/1")
	if got, _ := row.Field("v_1_2_2"); got != "Enable" {
		t.Errorf("v_1_2_2 after re-enable = %q, want \"Enable\"", got)
	}
}

func TestFastpathPoEResetDoesNotCarryConfigColumns(t *testing.T) {
	sess := newXUIFakeSession(map[string]string{
		"/poeInterfaceConfiguration.html": readFixture(t, "gsm7252ps_poeInterfaceConfiguration.html"),
	})
	w := mustNewWriter(t, sess, "gsm7252ps")
	if err := w.ClearPoEFault(context.Background(), 1, false); err != nil {
		t.Fatalf("ClearPoEFault(1) error = %v", err)
	}
	last := sess.posts[len(sess.posts)-1]
	if v, ok := valueForSuffixedKey(last.data, "v_1_2_20"); !ok || v != "Reset" {
		t.Errorf("v_1_2_20 = %q (ok=%v), want \"Reset\"", v, ok)
	}
	// The RESET shed list disables the config columns -- a power cycle must
	// not rewrite Admin Mode as a side effect.
	if hasSuffixedKey(last.data, "v_1_2_2") {
		t.Errorf("reset body carries the config column v_1_2_2, want omitted")
	}
}

func TestClearPoEFaultUnsupportedWhenNoPSE(t *testing.T) {
	// The M4300-24X genuinely has no PoE hardware (dossier D-HTTP-F §2.1):
	// poe_config_path is "" for this model, a MEASURED absence.
	w := mustNewWriter(t, newXUIFakeSession(map[string]string{}), "m4300-24x")
	err := w.ClearPoEFault(context.Background(), 1, false)
	wantUnsupported(t, err, "ClearPoEFault on m4300-24x")
}

// --- gsm7252ps SetMgmtIP (ipConfiguration.html) -----------------------------

func TestFastpathSetMgmtIPNeedsForce(t *testing.T) {
	sess := newXUIFakeSession(map[string]string{
		"/ipConfiguration.html": readFixture(t, "gsm7252ps_ipConfiguration.html"),
	})
	w := mustNewWriter(t, sess, "gsm7252ps")
	err := w.SetMgmtIP(context.Background(), "10.9.9.9", "255.255.255.0", "10.9.9.1", false)
	wantProtectedPort(t, err, "SetMgmtIP without force")
	if len(sess.posts) != 0 {
		t.Errorf("posts = %v, want none sent when force is withheld", sess.posts)
	}
}

func TestFastpathSetMgmtIPAppliesAndVerifies(t *testing.T) {
	sess := newXUIFakeSession(map[string]string{
		"/ipConfiguration.html": readFixture(t, "gsm7252ps_ipConfiguration.html"),
	})
	w := mustNewWriter(t, sess, "gsm7252ps")
	if err := w.SetMgmtIP(context.Background(), "10.9.9.9", "255.255.0.0", "10.9.0.1", true); err != nil {
		t.Fatalf("SetMgmtIP(force=true) error = %v", err)
	}
	page, err := webui.ParseXUIFormPage(sess.pages["/ipConfiguration.html"], "")
	if err != nil {
		t.Fatalf("ParseXUIFormPage() error = %v", err)
	}
	if page.Fields["v_1_1_1"] != "10.9.9.9" || page.Fields["v_1_2_1"] != "255.255.0.0" || page.Fields["v_1_3_1"] != "10.9.0.1" {
		t.Errorf("address/netmask/gateway = %q/%q/%q, want 10.9.9.9/255.255.0.0/10.9.0.1",
			page.Fields["v_1_1_1"], page.Fields["v_1_2_1"], page.Fields["v_1_3_1"])
	}
	if page.Fields["v_1_18_1"] != "None" {
		t.Errorf("v_1_18_1 (mode) = %q, want \"None\" (static)", page.Fields["v_1_18_1"])
	}
}

func TestFastpathSetMgmtIPSurfacesRefusal(t *testing.T) {
	sess := newXUIFakeSession(map[string]string{
		"/ipConfiguration.html": readFixture(t, "gsm7252ps_ipConfiguration.html"),
	})
	sess.honourWrites = false
	sess.errFlag = true
	w := mustNewWriter(t, sess, "gsm7252ps")
	err := w.SetMgmtIP(context.Background(), "10.9.9.999", "255.255.0.0", "10.9.0.1", true)
	fastpathErrContains(t, err, "switch refused")
}

func TestFastpathSetMgmtIPWriteNotReflectedRaisesVerification(t *testing.T) {
	sess := newXUIFakeSession(map[string]string{
		"/ipConfiguration.html": readFixture(t, "gsm7252ps_ipConfiguration.html"),
	})
	sess.honourWrites = false
	w := mustNewWriter(t, sess, "gsm7252ps")
	err := w.SetMgmtIP(context.Background(), "10.9.9.9", "255.255.0.0", "10.9.0.1", true)
	wantVerificationError(t, err, "SetMgmtIP not reflected")
}

// --- gsm7252ps SetVlanMembership (vlan_port_cfg.html / _rw.html) ----------

// fastpathWireToModeLocal duplicates parse_xe.go's unexported
// fastpathMemToMode (webui_test cannot reach package-private symbols): the
// FASTPATH hiddenMem wire codes 1=Tagged/2=Untagged/3=Excluded -- the
// INVERSE of the Plus-class 8021qMembe.cgi codes (dossier D-HTTP-F §1.3's
// "wire-code inversion trap").
var fastpathWireToModeLocal = map[string]model.VlanMode{
	"1": model.VlanTagged,
	"2": model.VlanUntagged,
	"3": model.VlanExcluded,
}

// fastpathGridACellRE duplicates parse_xe.go's unexported fastpathGridARE:
// gsm7252ps's "Grid style A" per-cell image whose *_[btu].gif suffix
// encodes the rendered VLAN mode. Needed so the fake session below can keep
// that presentation-layer grid consistent with the hiddenMem field it just
// mutated -- ParseFastpathMembership cross-checks the two and raises a
// "grid/hiddenMem mismatch" error if a test's fake left them disagreeing.
var fastpathGridACellRE = regexp.MustCompile(`(?s)toggleImageFirst\(this,(\d+),\d+,'img_unit\d+',(\d+)\).*?<img src="/base/images/(?:grey|blue)_([btu])\.gif" name="imx"`)

var fastpathModeToGridLetter = map[model.VlanMode]string{
	model.VlanTagged:   "t",
	model.VlanUntagged: "u",
	model.VlanExcluded: "b",
}

// setFastpathGridAState rewrites the Grid-A image-state letter for port's
// cell to mode, mirroring what a real firmware re-render would show.
// ok=false means the grid has no cell for port.
func setFastpathGridAState(html string, port int, mode model.VlanMode) (string, bool) {
	letter, known := fastpathModeToGridLetter[mode]
	if !known {
		return html, false
	}
	for _, m := range fastpathGridACellRE.FindAllStringSubmatchIndex(html, -1) {
		if html[m[4]:m[5]] == strconv.Itoa(port) {
			return html[:m[6]] + letter + html[m[7]:], true
		}
	}
	return html, false
}

// fastpathMembershipFakeSession is a webui.Session for exactly ONE FASTPATH
// VLAN-membership GET/POST pair. It keeps hiddenMem (the CONFIGURED wire
// codes) and the Grid-A presentation cells consistent on every apply -- the
// property ParseFastpathMembership's own grid/hiddenMem cross-check
// requires (see dossier D-HTTP-F §1.3) -- which is why this needs a
// dedicated session rather than xuiFakeSession's generic NAME=/VALUE=
// mutation: the grid state lives in <img> tags, not a form field.
type fastpathMembershipFakeSession struct {
	getPath, postPath string
	html              string
	honourWrites      bool
	errFlag           bool
	posts             []postRecord
}

func newFastpathMembershipFakeSession(t *testing.T, getPath, postPath, fixture string) *fastpathMembershipFakeSession {
	t.Helper()
	return &fastpathMembershipFakeSession{
		getPath: getPath, postPath: postPath,
		html:         readFixture(t, fixture),
		honourWrites: true,
	}
}

func (s *fastpathMembershipFakeSession) Login(context.Context) error { return nil }

func (s *fastpathMembershipFakeSession) GetPage(_ context.Context, path string) (string, error) {
	if path != s.getPath {
		return "", fmt.Errorf("fastpathMembershipFakeSession: no page registered for %q", path)
	}
	return s.html, nil
}

func (s *fastpathMembershipFakeSession) PostForm(_ context.Context, path string, data map[string]string) (string, error) {
	s.posts = append(s.posts, postRecord{path: path, data: cloneMap(data)})
	if path != s.postPath {
		return "", fmt.Errorf("fastpathMembershipFakeSession: PostForm to unexpected path %q", path)
	}
	if newHidden, ok := data["hiddenMem"]; ok && s.honourWrites {
		if page, err := webui.ParseFastpathMembership(s.html); err == nil {
			oldCodes := strings.Split(page.HiddenMem, ",")
			newCodes := strings.Split(newHidden, ",")
			for i, oldCode := range oldCodes {
				if i >= len(newCodes) || oldCode == newCodes[i] {
					continue
				}
				for p, slot := range page.PortSlots {
					if slot != i {
						continue
					}
					if mode, known := fastpathWireToModeLocal[newCodes[i]]; known {
						if mutated, ok := setFastpathGridAState(s.html, p, mode); ok {
							s.html = mutated
						}
					}
				}
			}
		}
		if mutated, ok := setNamedFieldValue(s.html, "hiddenMem", newHidden); ok {
			s.html = mutated
		}
	}
	response := s.html
	if s.errFlag {
		if mutated, ok := setNamedFieldValue(response, "err_flag", "1"); ok {
			response = mutated
		}
		if mutated, ok := setNamedFieldValue(response, "err_msg", "switch refused the write"); ok {
			response = mutated
		}
	}
	return response, nil
}

func (s *fastpathMembershipFakeSession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	return "", fmt.Errorf("fastpathMembershipFakeSession: PostMultipart(%q) not supported by this fake", path)
}

func (s *fastpathMembershipFakeSession) PostXML(_ context.Context, path string, _ string) (string, error) {
	return "", fmt.Errorf("fastpathMembershipFakeSession: PostXML(%q) not supported by this fake", path)
}

var _ webui.Session = (*fastpathMembershipFakeSession)(nil)

func TestFastpathSetVlanMembershipVerifies(t *testing.T) {
	getPath := "/switching/dot1q/vlan_port_cfg.html"
	postPath := "/switching/dot1q/vlan_port_cfg_rw.html"
	sess := newFastpathMembershipFakeSession(t, getPath, postPath, "gsm7252ps_vlanPortCfg_vlan1.html")

	before, err := webui.ParseFastpathMembership(sess.html)
	if err != nil {
		t.Fatalf("ParseFastpathMembership() error = %v", err)
	}
	const port = 1
	beforeMode, ok := before.Configured[port]
	if !ok {
		t.Fatalf("port %d not present in the fixture's Configured map", port)
	}
	target := model.VlanExcluded
	if beforeMode == model.VlanExcluded {
		target = model.VlanUntagged
	}

	w := mustNewWriter(t, sess, "gsm7252ps")
	if err := w.SetVlanMembership(context.Background(), 1, port, target, false); err != nil {
		t.Fatalf("SetVlanMembership() error = %v", err)
	}

	after, err := webui.ParseFastpathMembership(sess.html)
	if err != nil {
		t.Fatalf("ParseFastpathMembership() after write error = %v", err)
	}
	if after.Configured[port] != target {
		t.Errorf("Configured[%d] = %v, want %v", port, after.Configured[port], target)
	}
	// Every other port's slot must be untouched -- FastpathHiddenMemWith
	// preserves every other slot verbatim.
	for p, mode := range before.Configured {
		if p == port {
			continue
		}
		if after.Configured[p] != mode {
			t.Errorf("Configured[%d] changed from %v to %v, want untouched", p, mode, after.Configured[p])
		}
	}
}

func TestFastpathSetVlanMembershipWriteNotReflectedRaisesVerification(t *testing.T) {
	getPath := "/switching/dot1q/vlan_port_cfg.html"
	postPath := "/switching/dot1q/vlan_port_cfg_rw.html"
	sess := newFastpathMembershipFakeSession(t, getPath, postPath, "gsm7252ps_vlanPortCfg_vlan1.html")
	sess.honourWrites = false

	before, err := webui.ParseFastpathMembership(sess.html)
	if err != nil {
		t.Fatalf("ParseFastpathMembership() error = %v", err)
	}
	const port = 1
	target := model.VlanExcluded
	if before.Configured[port] == model.VlanExcluded {
		target = model.VlanUntagged
	}

	w := mustNewWriter(t, sess, "gsm7252ps")
	err = w.SetVlanMembership(context.Background(), 1, port, target, false)
	wantVerificationError(t, err, "SetVlanMembership not reflected")
}

func TestFastpathSetVlanMembershipSurfacesSwitchRefusal(t *testing.T) {
	getPath := "/switching/dot1q/vlan_port_cfg.html"
	postPath := "/switching/dot1q/vlan_port_cfg_rw.html"
	sess := newFastpathMembershipFakeSession(t, getPath, postPath, "gsm7252ps_vlanPortCfg_vlan1.html")
	sess.honourWrites = false
	sess.errFlag = true

	before, err := webui.ParseFastpathMembership(sess.html)
	if err != nil {
		t.Fatalf("ParseFastpathMembership() error = %v", err)
	}
	const port = 1
	target := model.VlanExcluded
	if before.Configured[port] == model.VlanExcluded {
		target = model.VlanUntagged
	}

	w := mustNewWriter(t, sess, "gsm7252ps")
	err = w.SetVlanMembership(context.Background(), 1, port, target, false)
	fastpathErrContains(t, err, "switch refused")
}

// multiVlanFastpathFakeSession serves TWO VLANs' membership pages, keyed by
// their own parsed VlanID, and simulates the firmware's re-render-whichever-
// VLAN-was-last-selected behaviour on a submt=0 (read-only) POST: a
// reselect to a VLAN this fake HAS switches "current" to it; a reselect to
// a VLAN it does NOT have leaves "current" unchanged (mirroring a firmware
// that silently refuses/ignores the select), which is what makes
// readFastpathMembership's requireFastpathMembershipFor error path
// reachable in a test. Exercises webui.Writer's OWN
// readFastpathMembership/requireFastpathMembershipFor (writer.go) rather
// than the Reader's near-identical pair (already covered by
// TestReadFastpathMembershipPostsWhenBaseGETShowsAnotherVLAN in
// reader_test.go) -- Go coverage is per compiled function, not per Python
// source line, so the writer's own copy needs its own test.
type multiVlanFastpathFakeSession struct {
	getPath, postPath string
	pages             map[int]string // VlanID -> html
	current           int
	posts             []postRecord
}

func newMultiVlanFastpathFakeSession(t *testing.T, getPath, postPath string, fixtures map[int]string) *multiVlanFastpathFakeSession {
	t.Helper()
	pages := make(map[int]string, len(fixtures))
	var first int
	for vid, name := range fixtures {
		pages[vid] = readFixture(t, name)
		if first == 0 {
			first = vid
		}
	}
	return &multiVlanFastpathFakeSession{getPath: getPath, postPath: postPath, pages: pages, current: first}
}

func (s *multiVlanFastpathFakeSession) Login(context.Context) error { return nil }

func (s *multiVlanFastpathFakeSession) GetPage(_ context.Context, path string) (string, error) {
	if path != s.getPath {
		return "", fmt.Errorf("multiVlanFastpathFakeSession: no page registered for %q", path)
	}
	return s.pages[s.current], nil
}

func (s *multiVlanFastpathFakeSession) PostForm(_ context.Context, path string, data map[string]string) (string, error) {
	s.posts = append(s.posts, postRecord{path: path, data: cloneMap(data)})
	if path != s.postPath {
		return "", fmt.Errorf("multiVlanFastpathFakeSession: PostForm to unexpected path %q", path)
	}
	if data["submt"] == "0" {
		if requested, err := strconv.Atoi(data["vlanId"]); err == nil {
			if _, ok := s.pages[requested]; ok {
				s.current = requested
			}
			// else: this fake has no page for the requested VLAN -- mirrors a
			// firmware that ignores the select and keeps rendering whichever
			// VLAN it was already showing.
		}
	}
	return s.pages[s.current], nil
}

func (s *multiVlanFastpathFakeSession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	return "", fmt.Errorf("multiVlanFastpathFakeSession: PostMultipart(%q) not supported by this fake", path)
}

func (s *multiVlanFastpathFakeSession) PostXML(_ context.Context, path string, _ string) (string, error) {
	return "", fmt.Errorf("multiVlanFastpathFakeSession: PostXML(%q) not supported by this fake", path)
}

var _ webui.Session = (*multiVlanFastpathFakeSession)(nil)

func TestFastpathSetVlanMembershipReselectsWhenAnotherVLANShown(t *testing.T) {
	getPath := "/switching/dot1q/vlan_port_cfg.html"
	postPath := "/switching/dot1q/vlan_port_cfg_rw.html"
	sess := newMultiVlanFastpathFakeSession(t, getPath, postPath, map[int]string{
		141: "gsm7252ps_vlanPortCfg_vlan141.html",
		1:   "gsm7252ps_vlanPortCfg_vlan1.html",
	})
	sess.current = 141 // the page last showed VLAN 141, not the VLAN 1 this write targets

	vlan1Before, err := webui.ParseFastpathMembership(sess.pages[1])
	if err != nil {
		t.Fatalf("ParseFastpathMembership() error = %v", err)
	}
	target := model.VlanExcluded
	if vlan1Before.Configured[1] == model.VlanExcluded {
		target = model.VlanUntagged
	}

	w := mustNewWriter(t, sess, "gsm7252ps")
	// This fake never persists an apply, so the write itself cannot verify --
	// the point of this test is the RESELECT that must happen first (GET
	// shows 141, so a submt=0 reselect to vlanId=1 is required before the
	// "before" state can even be read), not a successful round trip.
	err = w.SetVlanMembership(context.Background(), 1, 1, target, false)
	wantVerificationError(t, err, "SetVlanMembership after reselect")

	var sawReselect bool
	for _, p := range sess.posts {
		if p.data["submt"] == "0" && p.data["vlanId"] == "1" {
			sawReselect = true
		}
	}
	if !sawReselect {
		t.Errorf("posts = %v, want a submt=0 reselect to vlanId=1", sess.posts)
	}
}

func TestFastpathSetVlanMembershipRefusesWrongVLANAfterReselect(t *testing.T) {
	getPath := "/switching/dot1q/vlan_port_cfg.html"
	postPath := "/switching/dot1q/vlan_port_cfg_rw.html"
	// Only VLAN 141 is servable: a reselect to VLAN 1 (which this write
	// targets) is silently ignored by the fake, exactly as a real firmware
	// that refuses the select keeps rendering whichever VLAN it already
	// showed -- the writer must refuse to trust that mismatched page rather
	// than silently reporting/writing VLAN 141's state under VLAN 1's name.
	sess := newMultiVlanFastpathFakeSession(t, getPath, postPath, map[int]string{
		141: "gsm7252ps_vlanPortCfg_vlan141.html",
	})

	w := mustNewWriter(t, sess, "gsm7252ps")
	err := w.SetVlanMembership(context.Background(), 1, 1, model.VlanExcluded, false)
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
	if err == nil || !strings.Contains(err.Error(), "refusing to write to the wrong VLAN") {
		t.Errorf("error = %v, want it to contain \"refusing to write to the wrong VLAN\"", err)
	}
}

// --- GS110EMX: a genuinely different port-admin mechanism -------------------

// gs110emxFakeSession is a hand-built webui.Session for the GS110EMX's
// port_settings.html, whose "never closes a <tr>" open-row shape and
// visible-text (not hidden-input) admin-mode cell (dossier D-HTTP-F §2.5)
// make xuiFakeSession's generic NAME=/VALUE= mutation unsuitable -- this
// renders the minimal shape ParseGS110EMXPortStatus/
// ParseGS110EMXPortFormFields require from mutable per-port state, grounded
// in the same field names/positions gs110emx_port_settings.html itself
// uses (see parse_gs110emx.go's ParseGS110EMXPortStatus doc comment for the
// column layout this reproduces).
type gs110emxFakeSession struct {
	path         string
	ports        []int
	adminEnable  map[int]bool
	flowControl  map[int]string
	honourWrites bool
	posts        []postRecord
}

func newGS110EMXFakeSession() *gs110emxFakeSession {
	ports := []int{1, 2, 3, 4, 5, 6, 7, 8}
	admin := make(map[int]bool, len(ports))
	flow := make(map[int]string, len(ports))
	for _, p := range ports {
		admin[p] = true
		flow[p] = "4"
	}
	return &gs110emxFakeSession{
		path:         "/iss/specific/port_settings.html",
		ports:        ports,
		adminEnable:  admin,
		flowControl:  flow,
		honourWrites: true,
	}
}

func (s *gs110emxFakeSession) render() string {
	var b strings.Builder
	b.WriteString("<table>")
	for _, p := range s.ports {
		physical := "Auto"
		if !s.adminEnable[p] {
			physical = "Disable"
		}
		fmt.Fprintf(&b, `<tr class="portID">`+
			`<td class="def firstCol def_center"><input class="checkbox" type="checkbox" name="checkbox"></td>`+
			`<td class="def firstCol" sel="text">%d<input type="hidden" name="PORT_NO" value="%d"></td>`+
			`<td class="def" sel="input"></td>`+
			`<td class="def" sel="plain">Down</td>`+
			`<td class="def" id="an" sel="select">%s<input type="hidden" name="PHYSICAL_MODE" value="1"></td>`+
			`<td class="def" sel="plain">No Speed</td>`+
			`<td class="def" id="fc" sel="select">Enable<input type="hidden" name="FLOW_CONTROL_MODE" value="%s"></td>`,
			p, p, physical, s.flowControl[p])
		// Deliberately NOT closed with </tr> -- real GS110EMX firmware never
		// closes a portID row (see splitOpenRows's doc comment in
		// parse_gs110emx.go); the next <tr or the table's own </table> ends it.
	}
	b.WriteString("</table>")
	return b.String()
}

func (s *gs110emxFakeSession) Login(context.Context) error { return nil }

func (s *gs110emxFakeSession) GetPage(_ context.Context, path string) (string, error) {
	if path != s.path {
		return "", fmt.Errorf("gs110emxFakeSession: no page registered for %q", path)
	}
	return s.render(), nil
}

func (s *gs110emxFakeSession) PostForm(_ context.Context, path string, data map[string]string) (string, error) {
	s.posts = append(s.posts, postRecord{path: path, data: cloneMap(data)})
	if path != s.path {
		return "", fmt.Errorf("gs110emxFakeSession: PostForm to unexpected path %q", path)
	}
	portNo := data["PORT_NO"]
	// A bare number is accepted with HTTP 200 and applies NOTHING -- the
	// real firmware footgun dossier D-HTTP-F §2.5 documents (saveSelectedPorts()
	// builds "PORT_NO" as "<n>;"). Reproduced exactly: only a
	// semicolon-terminated PORT_NO selects a row to apply.
	if !strings.HasSuffix(portNo, ";") {
		return "SUCCESS", nil
	}
	port, err := strconv.Atoi(strings.TrimSuffix(portNo, ";"))
	if err != nil {
		return "SUCCESS", nil
	}
	if _, ok := s.adminEnable[port]; !ok {
		return "SUCCESS", nil
	}
	if s.honourWrites {
		s.adminEnable[port] = data["PORT_CTRL_MODE"] != "3"
	}
	return "SUCCESS", nil
}

func (s *gs110emxFakeSession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	return "", fmt.Errorf("gs110emxFakeSession: PostMultipart(%q) not supported by this fake", path)
}

func (s *gs110emxFakeSession) PostXML(_ context.Context, path string, _ string) (string, error) {
	return "", fmt.Errorf("gs110emxFakeSession: PostXML(%q) not supported by this fake", path)
}

var _ webui.Session = (*gs110emxFakeSession)(nil)

func TestGS110EMXSetPortEnabledRoundTrip(t *testing.T) {
	sess := newGS110EMXFakeSession()
	w := mustNewWriter(t, sess, "gs110emx")

	if err := w.SetPortEnabled(context.Background(), 3, false, false); err != nil {
		t.Fatalf("SetPortEnabled(3, false) error = %v", err)
	}
	if sess.adminEnable[3] {
		t.Errorf("adminEnable[3] = true, want false")
	}
	if err := w.SetPortEnabled(context.Background(), 3, true, false); err != nil {
		t.Fatalf("SetPortEnabled(3, true) error = %v", err)
	}
	if !sess.adminEnable[3] {
		t.Errorf("adminEnable[3] = false, want true")
	}
}

func TestGS110EMXSetPortEnabledWriteNotReflectedRaisesVerification(t *testing.T) {
	sess := newGS110EMXFakeSession()
	sess.honourWrites = false
	w := mustNewWriter(t, sess, "gs110emx")
	err := w.SetPortEnabled(context.Background(), 3, false, false)
	wantVerificationError(t, err, "GS110EMX SetPortEnabled not reflected")
}

func TestGS110EMXPortNoMustBeSemicolonTerminatedAtTheWriterLevel(t *testing.T) {
	// GS110EMXPortAdminForm itself is already pinned (forms_test.go); this
	// proves the WRITER's verify-after-write step is what catches the
	// footgun on a session that (mis-)applies a bare, non-semicolon PORT_NO.
	sess := newGS110EMXFakeSession()
	if _, err := sess.PostForm(context.Background(), sess.path, map[string]string{
		"PORT_NO": "3", "PORT_CTRL_MODE": "3", "PORT_CTRL_DUPLEX": "0", "PORT_CTRL_SPEED": "0",
		"FLOW_CONTROL_MODE": "4", "ACTION": "apply",
	}); err != nil {
		t.Fatalf("PostForm() error = %v", err)
	}
	if !sess.adminEnable[3] {
		t.Fatalf("adminEnable[3] = false after a bare PORT_NO, want unchanged (true) -- nothing should have applied")
	}
}

func TestGS110EMXRejectsAPortItDoesNotRender(t *testing.T) {
	w := mustNewWriter(t, newGS110EMXFakeSession(), "gs110emx")
	err := w.SetPortEnabled(context.Background(), 99, false, false)
	wantUnsupported(t, err, "SetPortEnabled(99) on gs110emx")
	if !strings.Contains(err.Error(), "not on this page") {
		t.Errorf("error = %q, want it to contain \"not on this page\"", err.Error())
	}
}

func TestGS110EMXPoEAndMgmtIPWriteStayHonest(t *testing.T) {
	// This model genuinely has no PoE (its own JS lists 39 pages, none a PoE
	// page) and its mgmt-IP page is a Plus-class sysInfo form, not a
	// FASTPATH XUI one, so set_mgmt_ip is not yet implemented for it.
	w := mustNewWriter(t, newGS110EMXFakeSession(), "gs110emx")
	err := w.ClearPoEFault(context.Background(), 1, false)
	wantUnsupported(t, err, "ClearPoEFault on gs110emx")

	err = w.SetMgmtIP(context.Background(), "10.9.9.9", "255.255.255.0", "10.9.9.1", true)
	wantUnsupported(t, err, "SetMgmtIP on gs110emx")
	if !strings.Contains(err.Error(), "management-IP form") {
		t.Errorf("error = %q, want it to contain \"management-IP form\"", err.Error())
	}
}
