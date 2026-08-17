package webui_test

// writer_test.go: TDD coverage for webui.Writer's Plus-CGI (gs305ep,
// HTMLDialectStandard) write paths, ported scenario-for-scenario from
// tests/test_http_write.py at pin 1841111 in python-netgear-switch-library
// (the sync HttpWriter half only -- this Go port has no separate async
// type, see writer.go's Writer doc comment).
//
// gs305epState mirrors Python's _FakeGs305epState: an in-memory stateful
// fake Session that records every POSTed field set and mutates its own
// returned pages so a verify-after-write GET reflects the write -- or, when
// honourWrites is false, deliberately does NOT, so the writer's verify step
// must raise *model.WriteVerificationError.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

const gs305epPortCount = 5 // gs305ep's registry port_count

var wireToMode = map[string]model.VlanMode{
	"1": model.VlanUntagged,
	"2": model.VlanTagged,
	"3": model.VlanExcluded,
}

var modeToWire = map[model.VlanMode]string{
	model.VlanUntagged: "1",
	model.VlanTagged:   "2",
	model.VlanExcluded: "3",
}

type postRecord struct {
	path string
	data map[string]string
}

// gs305epState is the shared PoE/PVID/VLAN state behind writerFakeSession,
// mirroring Python's _FakeGs305epState.
type gs305epState struct {
	poeOn        map[int]bool
	pvids        map[int]int
	vlanMembers  map[int]map[int]model.VlanMode
	vlanIDs      map[int]bool
	honourWrites bool
	posts        []postRecord
}

func newGS305epState(honourWrites bool) *gs305epState {
	pvids := make(map[int]int, gs305epPortCount)
	members := make(map[int]model.VlanMode, gs305epPortCount)
	for p := 1; p <= gs305epPortCount; p++ {
		pvids[p] = 1
		members[p] = model.VlanUntagged
	}
	return &gs305epState{
		poeOn:       map[int]bool{1: true, 2: false, 3: false, 4: false},
		pvids:       pvids,
		vlanMembers: map[int]map[int]model.VlanMode{1: members},
		// VLAN 20 exists because the PVID tests target it: SetPVID refuses a
		// PVID pointing at a VLAN the switch does not have (GAP-1 fix, parity
		// with Python commit 98fb935's _FakeGs305epState update), so a fake
		// that listed only VLAN 1 would be modelling a switch on which those
		// writes genuinely cannot succeed.
		vlanIDs:      map[int]bool{1: true, 20: true},
		honourWrites: honourWrites,
	}
}

func (s *gs305epState) renderGet(path string) string {
	switch path {
	case "/getPoePortStatus.cgi":
		var b strings.Builder
		b.WriteString("<table>")
		for p := 1; p <= gs305epPortCount; p++ {
			status := "Disabled"
			if s.poeOn[p] {
				status = "Delivering"
			}
			fmt.Fprintf(&b, `<tr class="portID"><td>%d</td><td>%s</td><td>0</td></tr>`, p, status)
		}
		b.WriteString("</table>")
		return b.String()
	case "/portPVID.cgi":
		var b strings.Builder
		b.WriteString(`<input name="hash" value="h"><table>`)
		for p := 1; p <= gs305epPortCount; p++ {
			fmt.Fprintf(&b, `<tr class="portID"><td>%d</td><td sel="text">%d</td><td sel="input">%d</td></tr>`, p, p, s.pvids[p])
		}
		b.WriteString("</table>")
		return b.String()
	case "/8021qCf.cgi":
		var b strings.Builder
		b.WriteString(`<input name="hash" value="h">`)
		i := 1
		for _, vid := range sortedVlanIDs(s.vlanIDs) {
			fmt.Fprintf(&b, `<input name="vlanck%d" value="%d">`, i, vid)
			i++
		}
		return b.String()
	default:
		return `<input name="hash" value="h">`
	}
}

func sortedVlanIDs(ids map[int]bool) []int {
	out := make([]int, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func (s *gs305epState) renderPost(path string, data map[string]string) string {
	s.posts = append(s.posts, postRecord{path: path, data: cloneMap(data)})
	switch path {
	case "/PoEPortConfig.cgi":
		if data["ACTION"] == "Apply" && s.honourWrites {
			portID, _ := strconv.Atoi(data["portID"])
			s.poeOn[portID+1] = data["ADMIN_MODE"] == "1"
		}
		return "OK"
	case "/portPVID.cgi":
		if s.honourWrites {
			for k, v := range data {
				if strings.HasPrefix(k, "port") && v == "checked" {
					n, err := strconv.Atoi(strings.TrimPrefix(k, "port"))
					if err == nil {
						pvid, _ := strconv.Atoi(data["pvid"])
						s.pvids[n+1] = pvid
					}
				}
			}
		}
		return "OK"
	case "/8021qMembe.cgi":
		vlan, _ := strconv.Atoi(data["VLAN_ID"])
		if hiddenMem, ok := data["hiddenMem"]; ok {
			if s.honourWrites {
				members := make(map[int]model.VlanMode, gs305epPortCount)
				for i := 0; i < gs305epPortCount && i < len(hiddenMem); i++ {
					members[i+1] = wireToMode[string(hiddenMem[i])]
				}
				s.vlanMembers[vlan] = members
			}
			return "OK"
		}
		current := s.vlanMembers[vlan]
		var hidden strings.Builder
		for p := 1; p <= gs305epPortCount; p++ {
			mode, ok := current[p]
			if !ok {
				mode = model.VlanExcluded
			}
			hidden.WriteString(modeToWire[mode])
		}
		return fmt.Sprintf(`<input name="hash" value="h"><input id="hiddenMem" value="%s">`, hidden.String())
	case "/8021qCf.cgi":
		if s.honourWrites {
			switch data["ACTION"] {
			case "Add":
				vid, _ := strconv.Atoi(data["ADD_VLANID"])
				s.vlanIDs[vid] = true
			case "Delete":
				for k, v := range data {
					if strings.HasPrefix(k, "vlanck") {
						vid, _ := strconv.Atoi(v)
						delete(s.vlanIDs, vid)
					}
				}
			}
		}
		return "OK"
	default:
		return "OK"
	}
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// writerFakeSession is the webui.Session over gs305epState, mirroring
// Python's _StatefulSession.
type writerFakeSession struct {
	*gs305epState
}

func newWriterFakeSession(honourWrites bool) *writerFakeSession {
	return &writerFakeSession{gs305epState: newGS305epState(honourWrites)}
}

func (s *writerFakeSession) Login(context.Context) error { return nil }

func (s *writerFakeSession) GetPage(_ context.Context, path string) (string, error) {
	return s.renderGet(path), nil
}

func (s *writerFakeSession) PostForm(_ context.Context, path string, data map[string]string) (string, error) {
	return s.renderPost(path, data), nil
}

func (s *writerFakeSession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	return "", fmt.Errorf("writerFakeSession: PostMultipart(%q) not supported by this fake", path)
}

func (s *writerFakeSession) PostXML(_ context.Context, path string, _ string) (string, error) {
	return "", fmt.Errorf("writerFakeSession: PostXML(%q) not supported by this fake", path)
}

var _ webui.Session = (*writerFakeSession)(nil)

func mustNewWriter(t *testing.T, sess webui.Session, modelKey string, opts ...webui.WriterOption) *webui.Writer {
	t.Helper()
	w, err := webui.NewWriter(sess, mustGetModel(t, modelKey), opts...)
	if err != nil {
		t.Fatalf("webui.NewWriter(%q): %v", modelKey, err)
	}
	return w
}

func wantVerificationError(t *testing.T, err error, what string) {
	t.Helper()
	var target *model.WriteVerificationError
	if !errors.As(err, &target) {
		t.Errorf("%s: error = %v, want *model.WriteVerificationError", what, err)
	}
}

func wantProtectedPort(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Errorf("%s: error = %v, want model.ErrProtectedPort", what, err)
	}
}

// --- SetPoE / protected ports / mgmt-IP unsupported -------------------------

func TestSetPoEVerifies(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep")
	if err := w.SetPoE(context.Background(), 2, true, false); err != nil {
		t.Fatalf("SetPoE() error = %v", err)
	}
	if !sess.poeOn[2] {
		t.Errorf("poeOn[2] = false, want true")
	}
}

func TestSetPoEWriteNotReflectedRaisesVerification(t *testing.T) {
	sess := newWriterFakeSession(false)
	w := mustNewWriter(t, sess, "gs305ep")
	err := w.SetPoE(context.Background(), 2, true, false)
	wantVerificationError(t, err, "SetPoE")
}

func TestProtectedPortBlocksWithoutForce(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep", webui.WithProtectedPorts(2))
	err := w.SetPoE(context.Background(), 2, false, false)
	wantProtectedPort(t, err, "SetPoE without force")
	if err := w.SetPoE(context.Background(), 2, false, true); err != nil {
		t.Fatalf("SetPoE(force=true) error = %v", err)
	}
	if sess.poeOn[2] {
		t.Errorf("poeOn[2] = true, want false")
	}
}

func TestMgmtIPWriteUnsupportedOnGs305ep(t *testing.T) {
	w := mustNewWriter(t, newWriterFakeSession(true), "gs305ep")
	err := w.SetMgmtIP(context.Background(), "10.0.0.2", "255.255.255.0", "10.0.0.1", true)
	wantUnsupported(t, err, "SetMgmtIP")
}

// --- PVID / VLAN membership / VLAN create-delete / PoE cycle & fault / -----
// --- reboot / port-enable ---------------------------------------------------

func TestSetPVIDVerifies(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep")
	if err := w.SetPVID(context.Background(), 3, 20, false); err != nil {
		t.Fatalf("SetPVID() error = %v", err)
	}
	if sess.pvids[3] != 20 {
		t.Errorf("pvids[3] = %d, want 20", sess.pvids[3])
	}
	last := sess.posts[len(sess.posts)-1]
	if last.path != "/portPVID.cgi" {
		t.Errorf("last post path = %q, want /portPVID.cgi", last.path)
	}
	want := map[string]string{"port2": "checked", "pvid": "20", "hash": "h"}
	if !mapsEqual(last.data, want) {
		t.Errorf("last post data = %v, want %v", last.data, want)
	}
}

func TestSetPVIDWriteNotReflectedRaisesVerification(t *testing.T) {
	sess := newWriterFakeSession(false)
	w := mustNewWriter(t, sess, "gs305ep")
	err := w.SetPVID(context.Background(), 3, 20, false)
	wantVerificationError(t, err, "SetPVID")
}

// TestSetPVIDRefusesAVlanThatDoesNotExist pins the GAP-1 fix (parity with
// Python commit 98fb935 / test_set_pvid_refuses_a_vlan_that_does_not_exist
// in test_http_write.py): a PVID may only point at a VLAN the switch
// actually has. MEASURED on a GS728TPP (10.2.5.10, firmware 6.0.1.30): the
// equivalent write to a nonexistent VLAN is ACCEPTED and reads back,
// creating no VLAN -- so verify-after-write cannot catch it. Only a
// precondition can, and nothing may be sent when it fails.
func TestSetPVIDRefusesAVlanThatDoesNotExist(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep")
	err := w.SetPVID(context.Background(), 3, 4007, false)
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Fatalf("SetPVID() error = %v, want errors.Is(..., model.ErrHTTPUnexpectedPage)", err)
	}
	if !strings.Contains(err.Error(), "VLAN 4007 does not exist") {
		t.Errorf("SetPVID() error = %q, want it to mention %q", err.Error(), "VLAN 4007 does not exist")
	}
	for _, p := range sess.posts {
		if p.path == "/portPVID.cgi" {
			t.Errorf("posts = %v, want no /portPVID.cgi POST -- precondition must fail before any write", sess.posts)
		}
	}
	if sess.pvids[3] != 1 {
		t.Errorf("pvids[3] = %d, want unchanged 1", sess.pvids[3])
	}
}

// TestSetPVIDRefusesNonexistentVlanOnGoAheadDialect exercises
// requireVlanExists' isGoAheadDialect branch (writer.go) directly against
// REAL captured gs728tpp fixture data (webui/testdata/http/
// gs728tpp_vlans.xml, the same page reader_goahead_test.go's gs728tppPages
// serves) -- GAP-1 fix parity with Python commit 98fb935. No other
// webui-package test drove this branch: TestSetPVIDRefusesAVlanThatDoesNotExist
// above only exercises the default (Plus-CGI) branch. SetPVID must refuse
// before reaching the CSRF/PostForm write this model's SetPVID otherwise
// shares with every other dialect (see this file's package doc comment on
// that shared-but-imperfect verify path).
func TestSetPVIDRefusesNonexistentVlanOnGoAheadDialect(t *testing.T) {
	w := mustNewWriter(t, newFakeSession(gs728tppPages(t)), "gs728tpp")
	const nonexistentVlan = 999999
	err := w.SetPVID(context.Background(), 2, nonexistentVlan, false)
	if err == nil {
		t.Fatal("SetPVID() with a nonexistent VLAN error = nil, want a refusal")
	}
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("SetPVID() error = %v, want errors.Is(..., model.ErrHTTPUnexpectedPage)", err)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(nonexistentVlan)) {
		t.Errorf("SetPVID() error = %q, want it to mention the nonexistent VLAN %d", err.Error(), nonexistentVlan)
	}
}

// TestSetPVIDRefusesNonexistentVlanOnFastpathDialect exercises
// requireVlanExists' isFastpathDialect branch (writer.go) directly against
// REAL captured gsm7252ps fixture data (webui/testdata/http/
// gsm7252ps_vlanStatus.html) -- GAP-1 fix parity with Python commit
// 98fb935. No other webui-package test drove this branch.
func TestSetPVIDRefusesNonexistentVlanOnFastpathDialect(t *testing.T) {
	w := mustNewWriter(t, newFakeSession(gsm7252psPages(t)), "gsm7252ps")
	const nonexistentVlan = 999999
	err := w.SetPVID(context.Background(), 1, nonexistentVlan, false)
	if err == nil {
		t.Fatal("SetPVID() with a nonexistent VLAN error = nil, want a refusal")
	}
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("SetPVID() error = %v, want errors.Is(..., model.ErrHTTPUnexpectedPage)", err)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(nonexistentVlan)) {
		t.Errorf("SetPVID() error = %q, want it to mention the nonexistent VLAN %d", err.Error(), nonexistentVlan)
	}
}

// erroringVlanConfigSession wraps writerFakeSession to fail GetPage for one
// specific path (the target's VlanConfigPath), for
// TestSetPVIDPropagatesVlanConfigPageTransportError below: requireVlanExists'
// own GetPage error-propagation branch (writer.go), which no other test
// drove -- every other requireVlanExists test either succeeds fetching the
// page or fails on VLAN-existence, never on the fetch itself.
type erroringVlanConfigSession struct {
	*writerFakeSession
	errPath string
	err     error
}

func (s *erroringVlanConfigSession) GetPage(ctx context.Context, path string) (string, error) {
	if path == s.errPath {
		return "", s.err
	}
	return s.writerFakeSession.GetPage(ctx, path)
}

func TestSetPVIDPropagatesVlanConfigPageTransportError(t *testing.T) {
	boom := errors.New("boom: transport down")
	sess := &erroringVlanConfigSession{writerFakeSession: newWriterFakeSession(true), errPath: "/8021qCf.cgi", err: boom}
	w := mustNewWriter(t, sess, "gs305ep")
	err := w.SetPVID(context.Background(), 3, 20, false)
	if !errors.Is(err, boom) {
		t.Fatalf("SetPVID() error = %v, want it to wrap the raw transport error fetching VlanConfigPath", err)
	}
}

// overriddenPageSession wraps writerFakeSession to serve a fixed body for
// one specific path regardless of state, for
// TestSetPVIDPropagatesVlanConfigPageParseError below: requireVlanExists'
// own default-dialect parse-error branch (ParseVLANIDs via parseVlanIDs,
// writer.go), which no other test drove -- TestSetPVIDRefusesAVlanThatDoesNotExist
// only exercises a WELL-FORMED page whose parse succeeds and simply lacks
// the target VLAN, a different branch from a page that fails to parse at all.
type overriddenPageSession struct {
	*writerFakeSession
	overridePath string
	overrideBody string
}

func (s *overriddenPageSession) GetPage(ctx context.Context, path string) (string, error) {
	if path == s.overridePath {
		return s.overrideBody, nil
	}
	return s.writerFakeSession.GetPage(ctx, path)
}

func TestSetPVIDPropagatesVlanConfigPageParseError(t *testing.T) {
	sess := &overriddenPageSession{
		writerFakeSession: newWriterFakeSession(true),
		overridePath:      "/8021qCf.cgi",
		overrideBody:      "<html>not a VLAN config page at all</html>",
	}
	w := mustNewWriter(t, sess, "gs305ep")
	err := w.SetPVID(context.Background(), 3, 20, false)
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Fatalf("SetPVID() error = %v, want errors.Is(..., model.ErrHTTPUnexpectedPage) (malformed VlanConfigPath page)", err)
	}
	if !strings.Contains(err.Error(), "vlanck") {
		t.Errorf("SetPVID() error = %q, want it to mention the malformed-page reason (vlanckN checkbox)", err.Error())
	}
}

func TestSetVlanMembershipVerifies(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep")
	if err := w.SetVlanMembership(context.Background(), 1, 3, model.VlanExcluded, false); err != nil {
		t.Fatalf("SetVlanMembership() error = %v", err)
	}
	if sess.vlanMembers[1][3] != model.VlanExcluded {
		t.Errorf("vlanMembers[1][3] = %v, want VlanExcluded", sess.vlanMembers[1][3])
	}
	var lastApply *postRecord
	for i := range sess.posts {
		if _, ok := sess.posts[i].data["hiddenMem"]; ok {
			lastApply = &sess.posts[i]
		}
	}
	if lastApply == nil {
		t.Fatalf("no POST carried hiddenMem")
	}
	want := map[string]string{"VLAN_ID": "1", "hiddenMem": "11311", "hash": "h"}
	if !mapsEqual(lastApply.data, want) {
		t.Errorf("apply post data = %v, want %v", lastApply.data, want)
	}
}

func TestSetVlanMembershipWriteNotReflectedRaisesVerification(t *testing.T) {
	sess := newWriterFakeSession(false)
	w := mustNewWriter(t, sess, "gs305ep")
	err := w.SetVlanMembership(context.Background(), 1, 3, model.VlanExcluded, false)
	wantVerificationError(t, err, "SetVlanMembership")
}

func TestCreateVlanVerifies(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep")
	if err := w.CreateVlan(context.Background(), 10, "irrelevant"); err != nil {
		t.Fatalf("CreateVlan() error = %v", err)
	}
	if !sess.vlanIDs[10] {
		t.Errorf("vlanIDs[10] absent, want present")
	}
	last := sess.posts[len(sess.posts)-1]
	want := map[string]string{"ACTION": "Add", "ADD_VLANID": "10", "status": "Enable", "hash": "h"}
	if last.path != "/8021qCf.cgi" || !mapsEqual(last.data, want) {
		t.Errorf("last post = (%q, %v), want (/8021qCf.cgi, %v)", last.path, last.data, want)
	}
}

func TestCreateVlanNotCreatedRaisesVerification(t *testing.T) {
	sess := newWriterFakeSession(false)
	w := mustNewWriter(t, sess, "gs305ep")
	err := w.CreateVlan(context.Background(), 10, "irrelevant")
	wantVerificationError(t, err, "CreateVlan")
}

func TestDeleteVlanVerifies(t *testing.T) {
	sess := newWriterFakeSession(true)
	sess.vlanIDs[10] = true
	w := mustNewWriter(t, sess, "gs305ep")
	if err := w.DeleteVlan(context.Background(), 10, false); err != nil {
		t.Fatalf("DeleteVlan() error = %v", err)
	}
	if sess.vlanIDs[10] {
		t.Errorf("vlanIDs[10] present, want absent")
	}
	last := sess.posts[len(sess.posts)-1]
	want := map[string]string{"ACTION": "Delete", "vlanck2": "10", "status": "Enable", "hash": "h"}
	if last.path != "/8021qCf.cgi" || !mapsEqual(last.data, want) {
		t.Errorf("last post = (%q, %v), want (/8021qCf.cgi, %v)", last.path, last.data, want)
	}
}

func TestDeleteVlanNotRemovedRaisesVerification(t *testing.T) {
	sess := newWriterFakeSession(false)
	sess.vlanIDs[10] = true
	w := mustNewWriter(t, sess, "gs305ep")
	err := w.DeleteVlan(context.Background(), 10, false)
	wantVerificationError(t, err, "DeleteVlan")
}

func TestDeleteVlanNotPresentRaisesUnexpectedPage(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep")
	err := w.DeleteVlan(context.Background(), 999, false)
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want model.ErrHTTPUnexpectedPage", err)
	}
	if len(sess.posts) != 0 {
		t.Errorf("posts = %v, want none sent -- the checkbox lookup must fail before any POST", sess.posts)
	}
}

func TestClearPoEFaultPostsThePlusResetForm(t *testing.T) {
	// A Plus switch has no separate clear-fault action: re-running detection
	// IS the clear, which on this UI is PoEPortConfig.cgi's Reset -- exactly
	// what CyclePoE posts. (This used to raise UnsupportedCapabilityError
	// even though the mechanism was already implemented next door.)
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep")
	if err := w.ClearPoEFault(context.Background(), 2, false); err != nil {
		t.Fatalf("ClearPoEFault() error = %v", err)
	}
	last := sess.posts[len(sess.posts)-1]
	want := map[string]string{"ACTION": "Reset", "port1": "checked", "hash": "h"}
	if last.path != "/PoEPortConfig.cgi" || !mapsEqual(last.data, want) {
		t.Errorf("last post = (%q, %v), want (/PoEPortConfig.cgi, %v)", last.path, last.data, want)
	}
}

func TestCyclePoEPostsResetForm(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep")
	if err := w.CyclePoE(context.Background(), 2, false); err != nil {
		t.Fatalf("CyclePoE() error = %v", err)
	}
	last := sess.posts[len(sess.posts)-1]
	want := map[string]string{"ACTION": "Reset", "port1": "checked", "hash": "h"}
	if last.path != "/PoEPortConfig.cgi" || !mapsEqual(last.data, want) {
		t.Errorf("last post = (%q, %v), want (/PoEPortConfig.cgi, %v)", last.path, last.data, want)
	}
	// CyclePoE is POST-only/no verify BY DESIGN: admin state must be untouched.
	if sess.poeOn[2] {
		t.Errorf("poeOn[2] = true, want false (unchanged)")
	}
}

func TestCyclePoERespectsProtectedPort(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep", webui.WithProtectedPorts(2))
	err := w.CyclePoE(context.Background(), 2, false)
	wantProtectedPort(t, err, "CyclePoE")
}

func TestRebootRequiresForce(t *testing.T) {
	w := mustNewWriter(t, newWriterFakeSession(true), "gs305ep")
	err := w.Reboot(context.Background(), false)
	wantProtectedPort(t, err, "Reboot")
}

func TestRebootPostsFormWithForce(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep")
	if err := w.Reboot(context.Background(), true); err != nil {
		t.Fatalf("Reboot(force=true) error = %v", err)
	}
	last := sess.posts[len(sess.posts)-1]
	want := map[string]string{"hash": "h"}
	if last.path != "/device_reboot.cgi" || !mapsEqual(last.data, want) {
		t.Errorf("last post = (%q, %v), want (/device_reboot.cgi, %v)", last.path, last.data, want)
	}
}

func TestSetPortEnabledIsUnsupportedOnGs305ep(t *testing.T) {
	w := mustNewWriter(t, newWriterFakeSession(true), "gs305ep")
	err := w.SetPortEnabled(context.Background(), 2, true, false)
	wantUnsupported(t, err, "SetPortEnabled")
}

// --- SetPortDescription / SetPortSpeed / SetFlowControl -- XML-API-only,
// refused by name on every non-GoAhead dialect (gs305ep exercises that
// refusal here; the GoAhead success/verify/forced-speed-refusal paths are
// exercised end to end against the REAL gs728tpp virtual HTTP fake in
// virtual/httpface_test.go, since a GoAhead XML round trip needs a stateful
// wcd-serving fake this package's gs305epState does not model). ------------

func TestSetPortDescriptionIsUnsupportedOnGs305ep(t *testing.T) {
	w := mustNewWriter(t, newWriterFakeSession(true), "gs305ep")
	err := w.SetPortDescription(context.Background(), 2, "uplink", false)
	wantUnsupported(t, err, "SetPortDescription")
}

func TestSetPortDescriptionProtectedPortBlocksWithoutForce(t *testing.T) {
	w := mustNewWriter(t, newWriterFakeSession(true), "gs305ep", webui.WithProtectedPorts(2))
	err := w.SetPortDescription(context.Background(), 2, "uplink", false)
	wantProtectedPort(t, err, "SetPortDescription(protected, no force)")
}

func TestSetPortSpeedIsUnsupportedOnGs305ep(t *testing.T) {
	w := mustNewWriter(t, newWriterFakeSession(true), "gs305ep")
	err := w.SetPortSpeed(context.Background(), 2, model.AutoPortSpeed(), false)
	wantUnsupported(t, err, "SetPortSpeed")
}

func TestSetPortSpeedProtectedPortBlocksWithoutForce(t *testing.T) {
	w := mustNewWriter(t, newWriterFakeSession(true), "gs305ep", webui.WithProtectedPorts(2))
	err := w.SetPortSpeed(context.Background(), 2, model.AutoPortSpeed(), false)
	wantProtectedPort(t, err, "SetPortSpeed(protected, no force)")
}

func TestSetFlowControlIsUnsupportedOnGs305ep(t *testing.T) {
	w := mustNewWriter(t, newWriterFakeSession(true), "gs305ep")
	err := w.SetFlowControl(context.Background(), 2, true, false)
	wantUnsupported(t, err, "SetFlowControl")
}

// TestSetHostnameIsUnsupportedOnGs305ep proves the STANDARD dialect refuses
// SetHostname by name -- its identity page carries no host-name field to
// write, and this is neither the GS110EMX form nor the GoAhead XML API.
func TestSetHostnameIsUnsupportedOnGs305ep(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs305ep")
	err := w.SetHostname(context.Background(), "renamed", false)
	wantUnsupported(t, err, "SetHostname")
	if len(sess.posts) != 0 {
		t.Errorf("posts = %d, want 0 -- refused before any session I/O", len(sess.posts))
	}
}

// TestSetHostnameIsUnsupportedOnGs105pe proves GS105PE -- which CAN read
// its host name over HTTP (switch_info.cgi's own switch_name field) -- is
// still refused for the WRITE side: Python's set_hostname wires only
// GS110EMX (the read-modify-write form) and the GoAhead XML API; GS105PE's
// own write mechanism for this field is unbuilt, so it is refused by name
// exactly like gs305ep rather than silently no-oping.
func TestSetHostnameIsUnsupportedOnGs105pe(t *testing.T) {
	sess := newWriterFakeSession(true)
	w := mustNewWriter(t, sess, "gs105pe")
	err := w.SetHostname(context.Background(), "renamed", false)
	wantUnsupported(t, err, "SetHostname")
	if len(sess.posts) != 0 {
		t.Errorf("posts = %d, want 0 -- refused before any session I/O", len(sess.posts))
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
