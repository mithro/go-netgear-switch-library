package webui

// reader_internal_test.go: white-box coverage for reader.go's unexported
// FASTPATH VLAN-membership helpers (fastpathMembership/withFastpathEgress/
// parseVlans/checkFastpathMembershipIsFor/requireCSRFHash). These compose
// exactly what GetVLANs's isFastpathDialect branch does (dossier D-HTTP-F
// §1.2/§1.3, THE pin's headline fix), but tests/test_http_read.py never
// calls get_vlans() end to end on a managed model either -- every managed
// switch's capture set has ONLY 1-2 of its ~14 VLANs' membership pages
// (the rest were never fetched live), so a full GetVLANs round trip would
// have to either fabricate the missing pages (exactly the mislabelling the
// wrong-VLAN guard exists to catch) or fail. Python's own test suite
// defers that full round trip to tests/test_http_vlan_membership.py's
// VirtualHttpFace mock (a later task's territory here). This file instead
// exercises the real composition directly, restricted to the VLANs real
// captures exist for -- same fixtures, no fabrication, in-package so it
// can reach Reader's unexported fields/methods.

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func mustReadTestFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/http/" + name)
	if err != nil {
		t.Fatalf("mustReadTestFixture(%q): %v", name, err)
	}
	return string(data)
}

// internalFakeSession is a minimal Session for these white-box tests only
// (webui_test's readerFakeSession lives in the external test package and
// so cannot be reused here).
type internalFakeSession struct {
	pages map[string]any // string or func(map[string]string) string
}

func (s *internalFakeSession) resolve(path string, data map[string]string) (string, error) {
	page, ok := s.pages[path]
	if !ok {
		return "", errHTTP("internalFakeSession: no page registered for %q", path)
	}
	switch p := page.(type) {
	case string:
		return p, nil
	case func(map[string]string) string:
		return p(data), nil
	default:
		return "", errHTTP("internalFakeSession: page %q has unexpected value type %T", path, page)
	}
}

func (s *internalFakeSession) Login(context.Context) error { return nil }

func (s *internalFakeSession) GetPage(_ context.Context, path string) (string, error) {
	return s.resolve(path, nil)
}

func (s *internalFakeSession) PostForm(_ context.Context, path string, data map[string]string) (string, error) {
	return s.resolve(path, data)
}

func (s *internalFakeSession) PostMultipart(_ context.Context, path string, _ map[string]string, _ MultipartFile) (string, error) {
	return "", errHTTP("internalFakeSession: PostMultipart(%q) not supported", path)
}

func (s *internalFakeSession) PostXML(_ context.Context, path string, _ string) (string, error) {
	return s.resolve(path, nil)
}

var _ Session = (*internalFakeSession)(nil)

// internalMembershipResponder mirrors webui_test's membershipResponder (see
// reader_test.go's doc comment) for use from this in-package test file.
func internalMembershipResponder(t *testing.T, names ...string) func(map[string]string) string {
	t.Helper()
	bodies := make([]string, len(names))
	byVID := make(map[int]string, len(names))
	for i, n := range names {
		body := mustReadTestFixture(t, n)
		bodies[i] = body
		page, err := ParseFastpathMembership(body)
		if err != nil {
			t.Fatalf("internalMembershipResponder(%q): ParseFastpathMembership: %v", n, err)
		}
		if page.VlanID == nil {
			t.Fatalf("internalMembershipResponder(%q): capture has no vlan id", n)
		}
		byVID[*page.VlanID] = body
	}
	return func(data map[string]string) string {
		requested, ok := data["vlanId"]
		if !ok || requested == "" {
			return bodies[0]
		}
		vid, err := strconv.Atoi(requested)
		if err != nil {
			t.Fatalf("internalMembershipResponder: unparseable vlanId %q", requested)
		}
		body, ok := byVID[vid]
		if !ok {
			t.Fatalf("internalMembershipResponder: no capture for vlanId=%d", vid)
		}
		return body
	}
}

func equalIntSlices(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestFastpathMembershipBatchAndWithFastpathEgress exercises
// Reader.fastpathMembership + withFastpathEgress together -- the exact
// composition GetVLANs's isFastpathDialect branch uses -- against
// gsm7252ps's two real VLAN-Membership captures (VLAN 1 and VLAN 141). It
// also proves a VLAN with NO membership page is passed through unchanged
// by withFastpathEgress, using a third VLAN straight from vlanStatus.html.
func TestFastpathMembershipBatchAndWithFastpathEgress(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel(gsm7252ps): %v", err)
	}
	spec := HTTPSpecs["gsm7252ps"]

	session := &internalFakeSession{pages: map[string]any{
		spec.VlanMembershipPath: mustReadTestFixture(t, "gsm7252ps_vlanPortCfg_vlan1.html"),
		spec.VlanMembershipPostPath: internalMembershipResponder(t,
			"gsm7252ps_vlanPortCfg_vlan1.html", "gsm7252ps_vlanPortCfg_vlan141.html"),
	}}
	r := &Reader{session: session, spec: spec, model: m}

	allVlans, err := ParseXEVlans(mustReadTestFixture(t, "gsm7252ps_vlanStatus.html"))
	if err != nil {
		t.Fatalf("ParseXEVlans() error = %v", err)
	}

	var captured []model.VLANInfo
	var uncaptured model.VLANInfo
	haveUncaptured := false
	for _, v := range allVlans {
		switch v.VlanID {
		case 1, 141:
			captured = append(captured, v)
		default:
			if !haveUncaptured {
				uncaptured = v
				haveUncaptured = true
			}
		}
	}
	if len(captured) != 2 {
		t.Fatalf("expected exactly 2 pre-captured VLANs (1 and 141) in the fixture, got %d", len(captured))
	}
	if !haveUncaptured {
		t.Fatal("expected at least one VLAN with no membership capture")
	}

	pages, err := r.fastpathMembership(context.Background(), captured)
	if err != nil {
		t.Fatalf("fastpathMembership() error = %v", err)
	}
	if len(pages) != 2 {
		t.Fatalf("len(pages) = %d, want 2", len(pages))
	}

	out := withFastpathEgress(captured, pages)
	byID := make(map[int]model.VLANInfo, len(out))
	for _, v := range out {
		byID[v.VlanID] = v
	}
	v1 := byID[1]
	if !equalIntSlices(v1.TaggedPorts, []int{6}) {
		t.Errorf("vlan1.TaggedPorts = %v, want [6]", v1.TaggedPorts)
	}
	// member_ports must equal the union tagged|untagged (the invariant
	// vlanStatus.html's own cell breaks, per dossier D-HTTP-F §1.3).
	union := make(map[int]bool, len(v1.TaggedPorts)+len(v1.UntaggedPorts))
	for _, p := range v1.TaggedPorts {
		union[p] = true
	}
	for _, p := range v1.UntaggedPorts {
		union[p] = true
	}
	for _, p := range v1.MemberPorts {
		if !union[p] {
			t.Errorf("vlan1.MemberPorts contains %d, not in tagged|untagged", p)
		}
	}
	for p := range union {
		found := false
		for _, mp := range v1.MemberPorts {
			if mp == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("vlan1.MemberPorts missing %d (present in tagged|untagged)", p)
		}
	}

	v141 := byID[141]
	if !equalIntSlices(v141.TaggedPorts, []int{46, 47, 49}) {
		t.Errorf("vlan141.TaggedPorts = %v, want [46 47 49]", v141.TaggedPorts)
	}

	// A VLAN with no membership page is left exactly as vlanStatus reported
	// it -- withFastpathEgress must not drop or alter it.
	passthrough := withFastpathEgress([]model.VLANInfo{uncaptured}, pages)
	if len(passthrough) != 1 || !reflect.DeepEqual(passthrough[0], uncaptured) {
		t.Errorf("withFastpathEgress(no-page VLAN) = %+v, want unchanged %+v", passthrough, uncaptured)
	}
}

// TestParseVlansDispatchesPerDialect exercises parseVlans's three branches
// (S3300/usesXEGrid-XE/M4300-default) against each dialect's own real
// vlanStatus.html capture.
func TestParseVlansDispatchesPerDialect(t *testing.T) {
	cases := []struct {
		name    string
		spec    *HTTPModelSpec
		fixture string
	}{
		{"s3300", HTTPSpecs["gsm7228ps"], "gsm7228ps_vlanStatus.html"},
		{"xe_fastpath", HTTPSpecs["gsm7252ps"], "gsm7252ps_vlanStatus.html"},
		{"m4300", HTTPSpecs["m4300-24x"], "m4300_vlanstatus.html"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vlans, err := parseVlans(c.spec, mustReadTestFixture(t, c.fixture))
			if err != nil {
				t.Fatalf("parseVlans() error = %v", err)
			}
			if len(vlans) == 0 {
				t.Error("parseVlans() returned no VLANs")
			}
		})
	}
}

// TestCheckFastpathMembershipIsForRefusesWrongVLAN mirrors Python's
// _check_fastpath_membership_is_for guard.
func TestCheckFastpathMembershipIsForRefusesWrongVLAN(t *testing.T) {
	page := FastpathMembership{VlanID: model.Ptr(5)}
	if _, err := checkFastpathMembershipIsFor(page, 7); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("wrong VLAN: error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
	got, err := checkFastpathMembershipIsFor(page, 5)
	if err != nil {
		t.Fatalf("matching VLAN: unexpected error = %v", err)
	}
	if got.VlanID == nil || *got.VlanID != 5 {
		t.Errorf("matching VLAN: got = %+v, want VlanID=5", got)
	}
	// A page with no vlan_id at all (nil) is never refused -- there is
	// nothing to compare against.
	if _, err := checkFastpathMembershipIsFor(FastpathMembership{}, 5); err != nil {
		t.Errorf("nil VlanID: unexpected error = %v", err)
	}
}

// TestRequireCSRFHashMissing mirrors Python's _require_csrf_hash guard.
func TestRequireCSRFHashMissing(t *testing.T) {
	if _, err := requireCSRFHash("<html>no hash here</html>"); !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
	got, err := requireCSRFHash(`<input name="hash" value="abc123">`)
	if err != nil || got != "abc123" {
		t.Errorf("got = (%q, %v), want (\"abc123\", nil)", got, err)
	}
}

// TestGS105PEGetVLANsReusesSelectedPageWithoutRePOST exercises GetVLANs's
// GS105PE-specific branch (haveMemberPage/requireCSRFHash/ParseSelectedVlan
// and the "already shown, don't re-POST" shortcut) end to end, using the
// REAL gs105pe_membership.html capture (which shows VLAN 1 selected,
// per parse_gs105pe_test.go). The VLAN-list page is trimmed to just that
// one VLAN rather than fabricating membership state for the other two IDs
// the real vlancfg.html lists (41, 90) -- no real capture of THEIR
// membership pages exists, and inventing one is exactly what this reader's
// wrong-VLAN guard exists to catch (same rationale as the FASTPATH
// membership tests above).
func TestGS105PEGetVLANsReusesSelectedPageWithoutRePOST(t *testing.T) {
	m, err := model.GetModel("gs105pe")
	if err != nil {
		t.Fatalf("model.GetModel(gs105pe): %v", err)
	}
	spec := HTTPSpecs["gs105pe"]
	session := &internalFakeSession{pages: map[string]any{
		spec.VlanConfigPath:     `<html><input name="vlanck0" value="1"></html>`,
		spec.VlanMembershipPath: mustReadTestFixture(t, "gs105pe_membership.html"),
	}}
	r := &Reader{session: session, spec: spec, model: m}

	vlans, err := r.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	if len(vlans) != 1 || vlans[0].VlanID != 1 {
		t.Fatalf("GetVLANs() = %+v, want exactly [VLAN 1]", vlans)
	}
	// hiddenMem "33331" for port_count=5: ports 1-4 excluded, port 5 untagged
	// (parse_gs105pe_test.go::TestParseVLANIDsAndMembershipSharedWithGS105PE).
	if !equalIntSlices(vlans[0].UntaggedPorts, []int{5}) {
		t.Errorf("vlans[0].UntaggedPorts = %v, want [5]", vlans[0].UntaggedPorts)
	}
	if len(vlans[0].TaggedPorts) != 0 {
		t.Errorf("vlans[0].TaggedPorts = %v, want empty", vlans[0].TaggedPorts)
	}
}

// TestGS105PEGetVLANsRefusesWrongVLANPage exercises the OTHER half of that
// branch: a VLAN the fake session cannot show (its POST unconditionally
// returns the same VLAN-1 capture) must be refused via
// checkMembershipIsFor, not silently mislabelled.
func TestGS105PEGetVLANsRefusesWrongVLANPage(t *testing.T) {
	m, err := model.GetModel("gs105pe")
	if err != nil {
		t.Fatalf("model.GetModel(gs105pe): %v", err)
	}
	spec := HTTPSpecs["gs105pe"]
	membershipPage := mustReadTestFixture(t, "gs105pe_membership.html") // always shows VLAN 1
	session := &internalFakeSession{pages: map[string]any{
		spec.VlanConfigPath:     `<html><input name="vlanck0" value="41"></html>`,
		spec.VlanMembershipPath: membershipPage,
	}}
	r := &Reader{session: session, spec: spec, model: m}

	_, err = r.GetVLANs(context.Background())
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Fatalf("GetVLANs() error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
}
