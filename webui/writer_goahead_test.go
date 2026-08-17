package webui_test

// writer_goahead_test.go: TDD coverage for webui.Writer's GoAhead-dialect
// (gs728tpp, HTMLDialectGoAheadXML) SetPortDescription/SetPortSpeed write
// paths (C3 slice) -- the success/verify/forced-speed-refusal branches this
// package's own writer_test.go leaves to the gs305ep Plus-CGI dialect
// refusal only.
//
// The REAL end-to-end wire round trip (a live wcd POST actually mutating
// State, driven through the real virtual HTTP fake) is already proven in
// virtual/httpface_test.go's TestHTTPFaceGS728TPPWriter* tests; this file's
// goAheadPortState is a package-LOCAL stateful double so webui's own test
// suite exercises the success path directly too, without depending on
// package virtual.

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// goAheadPortState is one GS728TPP port's admin/description/speed-config
// state, mirroring virtual/web_gs728tpp.go's RenderGS728TPPPorts shape
// closely enough for ParseGoAheadPorts to read it back, but package-local
// (not the real virtual fake) and single-port only. admin defaults to true
// (matching the field's Go zero-value-unfriendly default -- see
// newGoAheadPortState), the same default the hardcoded "<adminState>1"
// this type rendered before SetPortEnabled's GoAhead branch existed.
type goAheadPortState struct {
	port         int
	admin        bool
	description  string
	speed        model.PortSpeed
	honourWrites bool
	posts        []string
}

func newGoAheadPortState(port int, honourWrites bool) *goAheadPortState {
	return &goAheadPortState{port: port, admin: true, speed: model.AutoPortSpeed(), honourWrites: honourWrites}
}

func (s *goAheadPortState) page() string {
	autoneg, rate, duplex := "1", "1000", "3"
	if !s.speed.Autonegotiate {
		autoneg = "2"
		rate = strconv.Itoa(*s.speed.SpeedMbps)
		duplex = "2"
		if s.speed.FullDuplex != nil && *s.speed.FullDuplex {
			duplex = "3"
		}
	}
	adminState := "2"
	if s.admin {
		adminState = "1"
	}
	return fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8" ?><ResponseData><DeviceConfiguration><Standard802_3List type="section">`+
			`<Entry><interfaceName>g%d</interfaceName><interfaceType>1</interfaceType><interfaceID>%d</interfaceID>`+
			`<interfaceDescription>%s</interfaceDescription><adminState>%s</adminState><linkState>1</linkState>`+
			`<speedOper>1000</speedOper><duplexOperMode>2</duplexOperMode>`+
			`<speedAdmin>%s</speedAdmin><duplexAdminMode>%s</duplexAdminMode><autoNegotiationAdminEnabled>%s</autoNegotiationAdminEnabled>`+
			`</Entry></Standard802_3List></DeviceConfiguration></ResponseData>`,
		s.port, s.port, s.description, adminState, rate, duplex, autoneg,
	)
}

// postedStandard802_3Entry decodes just the fields a SetPortDescription/
// SetPortSpeed/SetPortEnabled POST body carries, independent of webui's own
// internal builders (this file has no access to them -- package webui_test
// is a black-box test package).
type postedStandard802_3Entry struct {
	AdminState                  string  `xml:"adminState"`
	InterfaceDescription        *string `xml:"interfaceDescription"`
	AutoNegotiationAdminEnabled string  `xml:"autoNegotiationAdminEnabled"`
	SpeedAdmin                  string  `xml:"speedAdmin"`
	DuplexAdminMode             string  `xml:"duplexAdminMode"`
}

type postedBody struct {
	Standard802_3List *struct {
		Entry postedStandard802_3Entry `xml:"Entry"`
	} `xml:"Standard802_3List"`
}

// goAheadPortSession is the webui.Session double over goAheadPortState.
type goAheadPortSession struct{ *goAheadPortState }

func (s *goAheadPortSession) Login(context.Context) error { return nil }

func (s *goAheadPortSession) GetPage(_ context.Context, _ string) (string, error) {
	return s.page(), nil
}

func (s *goAheadPortSession) PostForm(_ context.Context, path string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("goAheadPortSession: PostForm(%q) not supported by this GoAhead-only fake", path)
}

func (s *goAheadPortSession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	return "", fmt.Errorf("goAheadPortSession: PostMultipart(%q) not supported by this GoAhead-only fake", path)
}

func (s *goAheadPortSession) PostXML(_ context.Context, _ string, body string) (string, error) {
	s.posts = append(s.posts, body)
	if s.honourWrites {
		var doc postedBody
		if err := xml.Unmarshal([]byte(body), &doc); err != nil {
			return "", fmt.Errorf("goAheadPortSession: malformed POST body: %w", err)
		}
		if doc.Standard802_3List != nil {
			e := doc.Standard802_3List.Entry
			if e.AdminState == "1" || e.AdminState == "2" {
				s.admin = e.AdminState == "1"
			}
			if e.InterfaceDescription != nil {
				s.description = *e.InterfaceDescription
			}
			if e.AutoNegotiationAdminEnabled == "2" && e.SpeedAdmin != "" && (e.DuplexAdminMode == "2" || e.DuplexAdminMode == "3") {
				mbps, _ := strconv.Atoi(e.SpeedAdmin)
				s.speed = model.ForcedPortSpeed(mbps, e.DuplexAdminMode == "3")
			} else if e.AutoNegotiationAdminEnabled == "1" {
				s.speed = model.AutoPortSpeed()
			}
		}
	}
	return `<?xml version="1.0" encoding="UTF-8" ?><ResponseData><statusCode>0</statusCode></ResponseData>`, nil
}

var _ webui.Session = (*goAheadPortSession)(nil)

func newGoAheadWriter(t *testing.T, sess webui.Session) *webui.Writer {
	t.Helper()
	w, err := webui.NewWriter(sess, mustGetModel(t, "gs728tpp"))
	if err != nil {
		t.Fatalf("webui.NewWriter(gs728tpp): %v", err)
	}
	return w
}

// --- SetPortDescription (GoAhead dialect) -------------------------------

func TestSetPortDescriptionGoAheadSetsAndVerifies(t *testing.T) {
	state := newGoAheadPortState(5, true)
	w := newGoAheadWriter(t, &goAheadPortSession{state})
	if err := w.SetPortDescription(context.Background(), 5, "uplink", false); err != nil {
		t.Fatalf("SetPortDescription: %v", err)
	}
	if state.description != "uplink" {
		t.Errorf("state.description = %q, want \"uplink\"", state.description)
	}
	if len(state.posts) != 1 {
		t.Fatalf("posts = %d, want 1", len(state.posts))
	}
}

func TestSetPortDescriptionGoAheadClears(t *testing.T) {
	state := newGoAheadPortState(5, true)
	state.description = "old-label"
	w := newGoAheadWriter(t, &goAheadPortSession{state})
	if err := w.SetPortDescription(context.Background(), 5, "", false); err != nil {
		t.Fatalf("SetPortDescription(\"\"): %v", err)
	}
	if state.description != "" {
		t.Errorf("state.description = %q, want \"\" (cleared)", state.description)
	}
}

func TestSetPortDescriptionGoAheadVerificationFailureRaises(t *testing.T) {
	state := newGoAheadPortState(5, false) // device ignores the write
	w := newGoAheadWriter(t, &goAheadPortSession{state})
	err := w.SetPortDescription(context.Background(), 5, "uplink", false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPortDescription error = %v, want *model.WriteVerificationError", err)
	}
}

// --- SetPortSpeed (GoAhead dialect) --------------------------------------

func TestSetPortSpeedGoAheadForcesAndVerifies(t *testing.T) {
	state := newGoAheadPortState(5, true)
	w := newGoAheadWriter(t, &goAheadPortSession{state})
	speed := model.ForcedPortSpeed(100, false)
	if err := w.SetPortSpeed(context.Background(), 5, speed, false); err != nil {
		t.Fatalf("SetPortSpeed(100 half): %v", err)
	}
	if !state.speed.Equal(speed) {
		t.Errorf("state.speed = %v, want %v", state.speed, speed)
	}
}

func TestSetPortSpeedGoAheadReturnsToAutoAndVerifies(t *testing.T) {
	state := newGoAheadPortState(5, true)
	state.speed = model.ForcedPortSpeed(1000, true)
	w := newGoAheadWriter(t, &goAheadPortSession{state})
	if err := w.SetPortSpeed(context.Background(), 5, model.AutoPortSpeed(), false); err != nil {
		t.Fatalf("SetPortSpeed(auto): %v", err)
	}
	if !state.speed.Equal(model.AutoPortSpeed()) {
		t.Errorf("state.speed = %v, want auto", state.speed)
	}
}

func TestSetPortSpeedGoAheadVerificationFailureRaises(t *testing.T) {
	state := newGoAheadPortState(5, false) // device ignores the write
	w := newGoAheadWriter(t, &goAheadPortSession{state})
	err := w.SetPortSpeed(context.Background(), 5, model.ForcedPortSpeed(100, true), false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetPortSpeed error = %v, want *model.WriteVerificationError", err)
	}
}

// TestSetPortSpeedGoAheadRefusesUnofferedRate proves a rate this UI's own
// dropdown does not offer (10G forced) is refused BEFORE any POST, wrapping
// model.ErrUnsupportedCapability.
func TestSetPortSpeedGoAheadRefusesUnofferedRate(t *testing.T) {
	state := newGoAheadPortState(5, true)
	w := newGoAheadWriter(t, &goAheadPortSession{state})
	err := w.SetPortSpeed(context.Background(), 5, model.ForcedPortSpeed(10000, true), false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("SetPortSpeed(10G) error = %v, want model.ErrUnsupportedCapability", err)
	}
	if len(state.posts) != 0 {
		t.Errorf("posts = %d, want 0 (refused before any POST)", len(state.posts))
	}
}

// rejectingGoAheadSession wraps a goAheadPortState but answers every
// PostXML with a canned response (never applying the write), exercising
// checkGoAheadStatus's own two failure branches (goahead_write.go): a
// response with no <statusCode> at all (device serial confusion / wrong
// endpoint), and a non-zero <statusCode> (the switch's own explicit
// refusal, carrying a <statusString> reason).
type rejectingGoAheadSession struct {
	*goAheadPortSession
	response string
}

func (s *rejectingGoAheadSession) PostXML(_ context.Context, _ string, body string) (string, error) {
	s.posts = append(s.posts, body)
	return s.response, nil
}

func TestSetPortDescriptionGoAheadNoStatusCodeIsHTTPError(t *testing.T) {
	state := newGoAheadPortState(5, true)
	w := newGoAheadWriter(t, &rejectingGoAheadSession{goAheadPortSession: &goAheadPortSession{state}, response: "<html>not logged in</html>"})
	err := w.SetPortDescription(context.Background(), 5, "uplink", false)
	if !errors.Is(err, model.ErrHTTP) {
		t.Fatalf("SetPortDescription error = %v, want model.ErrHTTP (no <statusCode> in response)", err)
	}
}

func TestSetPortSpeedGoAheadNonZeroStatusCodeIsHTTPError(t *testing.T) {
	state := newGoAheadPortState(5, true)
	response := `<?xml version="1.0" encoding="UTF-8" ?><ResponseData><statusCode>2</statusCode><statusString>refused</statusString></ResponseData>`
	w := newGoAheadWriter(t, &rejectingGoAheadSession{goAheadPortSession: &goAheadPortSession{state}, response: response})
	err := w.SetPortSpeed(context.Background(), 5, model.ForcedPortSpeed(100, true), false)
	if !errors.Is(err, model.ErrHTTP) {
		t.Fatalf("SetPortSpeed error = %v, want model.ErrHTTP (non-zero statusCode)", err)
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("SetPortSpeed error = %q, want it to carry the device's own statusString", err.Error())
	}
}

func TestSetPortSpeedGoAheadProtectedPortBlocksWithoutForce(t *testing.T) {
	state := newGoAheadPortState(5, true)
	w, err := webui.NewWriter(&goAheadPortSession{state}, mustGetModel(t, "gs728tpp"), webui.WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	err = w.SetPortSpeed(context.Background(), 5, model.ForcedPortSpeed(100, true), false)
	wantProtectedPort(t, err, "SetPortSpeed(protected, no force)")
	if len(state.posts) != 0 {
		t.Errorf("posts = %d, want 0 (blocked before any I/O)", len(state.posts))
	}
}

// --- SetPortEnabled (GoAhead dialect: Standard802_3List/adminState) ------
//
// The real wire round trip (a live wcd POST actually mutating admin state,
// driven through the real virtual HTTP fake) is proven in
// virtual/httpface_test.go's TestHTTPFaceGS728TPPWriterSetPortEnabledRound
// Trips; this file's goAheadPortState success path is exercised there too
// (SetPortDescription/SetPortSpeed already prove the shared page/write
// primitive) -- the tests below cover what that round trip cannot: the
// verify-after-write failure and protected-port gating.

func TestSetPortEnabledGoAheadSetsAndVerifies(t *testing.T) {
	state := newGoAheadPortState(5, true)
	w := newGoAheadWriter(t, &goAheadPortSession{state})
	if err := w.SetPortEnabled(context.Background(), 5, false, false); err != nil {
		t.Fatalf("SetPortEnabled(false): %v", err)
	}
	if state.admin {
		t.Errorf("state.admin = true, want false")
	}
	if err := w.SetPortEnabled(context.Background(), 5, true, false); err != nil {
		t.Fatalf("SetPortEnabled(true): %v", err)
	}
	if !state.admin {
		t.Errorf("state.admin = false, want true")
	}
}

func TestSetPortEnabledGoAheadVerificationFailureRaises(t *testing.T) {
	state := newGoAheadPortState(5, false) // device ignores the write
	w := newGoAheadWriter(t, &goAheadPortSession{state})
	err := w.SetPortEnabled(context.Background(), 5, false, false)
	wantVerificationError(t, err, "SetPortEnabled")
}

func TestSetPortEnabledGoAheadProtectedPortBlocksWithoutForce(t *testing.T) {
	state := newGoAheadPortState(5, true)
	w, err := webui.NewWriter(&goAheadPortSession{state}, mustGetModel(t, "gs728tpp"), webui.WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	err = w.SetPortEnabled(context.Background(), 5, false, false)
	wantProtectedPort(t, err, "SetPortEnabled(protected, no force)")
	if len(state.posts) != 0 {
		t.Errorf("posts = %d, want 0 (blocked before any I/O)", len(state.posts))
	}
}

// --- SetHostname (GoAhead dialect: DeviceBasicInfo/deviceName) -----------

// goAheadDeviceInfoState models the GS728TPP's SystemInfo (DeviceBasicInfo)
// section -- just the switch's host name -- mirroring
// virtual/web_gs728tpp.go's RenderGS728TPPDeviceInfoAndSensors shape
// closely enough for ParseGoAheadHostname to read it back.
type goAheadDeviceInfoState struct {
	hostname     string
	honourWrites bool
	posts        []string
}

func (s *goAheadDeviceInfoState) page() string {
	return fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8" ?><ResponseData><DeviceConfiguration><DeviceBasicInfo type="section">`+
			`<deviceName>%s</deviceName></DeviceBasicInfo></DeviceConfiguration></ResponseData>`,
		s.hostname,
	)
}

// postedDeviceBasicInfo decodes just the field a SetHostname POST body
// carries: deviceName is a DIRECT child of DeviceBasicInfo (a SCALAR
// section, unlike Standard802_3List's repeated <Entry> children above --
// see deviceBasicInfoBody's own doc comment in goahead_write.go).
type postedDeviceBasicInfo struct {
	DeviceName *string `xml:"deviceName"`
}

type postedDeviceInfoBody struct {
	DeviceBasicInfo *postedDeviceBasicInfo `xml:"DeviceBasicInfo"`
}

// goAheadDeviceInfoSession is the webui.Session double over
// goAheadDeviceInfoState.
type goAheadDeviceInfoSession struct{ *goAheadDeviceInfoState }

func (s *goAheadDeviceInfoSession) Login(context.Context) error { return nil }

func (s *goAheadDeviceInfoSession) GetPage(_ context.Context, _ string) (string, error) {
	return s.page(), nil
}

func (s *goAheadDeviceInfoSession) PostForm(_ context.Context, path string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("goAheadDeviceInfoSession: PostForm(%q) not supported by this GoAhead-only fake", path)
}

func (s *goAheadDeviceInfoSession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	return "", fmt.Errorf("goAheadDeviceInfoSession: PostMultipart(%q) not supported by this GoAhead-only fake", path)
}

func (s *goAheadDeviceInfoSession) PostXML(_ context.Context, _ string, body string) (string, error) {
	s.posts = append(s.posts, body)
	if s.honourWrites {
		var doc postedDeviceInfoBody
		if err := xml.Unmarshal([]byte(body), &doc); err != nil {
			return "", fmt.Errorf("goAheadDeviceInfoSession: malformed POST body: %w", err)
		}
		if doc.DeviceBasicInfo != nil && doc.DeviceBasicInfo.DeviceName != nil {
			s.hostname = *doc.DeviceBasicInfo.DeviceName
		}
	}
	return `<?xml version="1.0" encoding="UTF-8" ?><ResponseData><statusCode>0</statusCode></ResponseData>`, nil
}

var _ webui.Session = (*goAheadDeviceInfoSession)(nil)

func TestSetHostnameGoAheadSetsAndVerifies(t *testing.T) {
	state := &goAheadDeviceInfoState{hostname: "sw-netgear-gs728tpp", honourWrites: true}
	w := newGoAheadWriter(t, &goAheadDeviceInfoSession{state})
	if err := w.SetHostname(context.Background(), "renamed-gs728tpp", false); err != nil {
		t.Fatalf("SetHostname: %v", err)
	}
	if state.hostname != "renamed-gs728tpp" {
		t.Errorf("state.hostname = %q, want %q", state.hostname, "renamed-gs728tpp")
	}
	if len(state.posts) != 1 {
		t.Fatalf("posts = %d, want 1", len(state.posts))
	}
	// The wire shape is a DIRECT <deviceName> child -- NOT wrapped in
	// <Entry> the way Standard802_3List's fields are -- see
	// deviceBasicInfoBody's own doc comment.
	if strings.Contains(state.posts[0], "<Entry>") {
		t.Errorf("POST body = %q, want NO <Entry> wrapper (DeviceBasicInfo is a scalar section)", state.posts[0])
	}
	if !strings.Contains(state.posts[0], "<deviceName>renamed-gs728tpp</deviceName>") {
		t.Errorf("POST body = %q, want it to carry <deviceName>renamed-gs728tpp</deviceName> directly", state.posts[0])
	}
}

// TestSetHostnameGoAheadNotForceGated proves force=false succeeds --
// renaming cannot strand a switch.
func TestSetHostnameGoAheadNotForceGated(t *testing.T) {
	state := &goAheadDeviceInfoState{hostname: "sw-netgear-gs728tpp", honourWrites: true}
	w := newGoAheadWriter(t, &goAheadDeviceInfoSession{state})
	if err := w.SetHostname(context.Background(), "renamed", false); err != nil {
		t.Fatalf("SetHostname(force=false) = %v, want success (not force-gated)", err)
	}
}

func TestSetHostnameGoAheadVerificationFailureRaises(t *testing.T) {
	state := &goAheadDeviceInfoState{hostname: "stuck-name", honourWrites: false} // device ignores the write
	w := newGoAheadWriter(t, &goAheadDeviceInfoSession{state})
	err := w.SetHostname(context.Background(), "new-name", false)
	var verr *model.WriteVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("SetHostname error = %v, want *model.WriteVerificationError", err)
	}
	if verr.Before != "stuck-name" || verr.After != "stuck-name" {
		t.Errorf("verification error before/after = %v/%v, want stuck-name/stuck-name", verr.Before, verr.After)
	}
}

// --- SetPoE / CyclePoE / ClearPoEFault (GoAhead dialect:
// PoEPSEInterfaceList) ------------------------------------------------
//
// The real wire round trip (a live wcd POST actually mutating PoE admin/
// detect state, driven through the real virtual HTTP fake) is proven in
// virtual/httpface_test.go's TestHTTPFaceGS728TPPWriterSetPoERoundTrips/
// CyclePoERoundTrips/ClearPoEFaultRoundTrips. Those cover the mechanism
// against port 17's SEEDED state (nothing attached, Detect=SEARCHING
// throughout) -- goaheadPoECycleComplete's OTHER branches (a port that WAS
// delivering before the cycle, and a port that never recovers at all) are
// scenarios the real fake's admin-off/on coherence rule can never itself
// produce (it only ever settles Detect to disabled/searching), so this
// file's package-local goAheadPoEState fake drives them directly.

// goAheadPoEState is one GS728TPP PoE port's admin/detect state, mirroring
// virtual/web_gs728tpp.go's RenderGS728TPPPoE shape closely enough for
// ParseGoAheadPoE to read it back, but package-local (not the real virtual
// fake) and single-port only. detect is the RAW GoAhead detectionStatus
// wire code (see webui/parse_goahead.go's goaheadPoeDetect: "1" disabled,
// "2" searching, "3" delivering, "4"/"6" fault).
//
// beforeDetect/afterDetect let a test separate goaheadPoERearm's "before"
// snapshot (the FIRST GetPage call) from every later read (both
// goaheadPoEAdmin's own before/after verification reads for its two writes,
// and the outer poll loop's reads) -- the two scenarios this file's tests
// need (a port that was delivering, a port that never recovers) both hinge
// on "before" and "now" disagreeing in a way the real device's own
// coherence rule cannot produce.
type goAheadPoEState struct {
	port         int
	admin        bool
	beforeDetect string
	afterDetect  string
	honourWrites bool
	calls        int
	posts        []string
	// getPageErr/postXMLErr, when non-nil, make every GetPage/PostXML call
	// fail instead of serving state -- proving the GoAhead read/write
	// primitives (goaheadPoEStatus, poeAdmin, goaheadWrite) propagate a
	// transport error honestly rather than swallowing it.
	getPageErr error
	postXMLErr error
}

// newGoAheadPoEState builds a state whose before/after detect codes start
// equal (detect); tests exercising the "before disagrees with after"
// branches set state.afterDetect directly afterward.
func newGoAheadPoEState(port int, admin bool, detect string, honourWrites bool) *goAheadPoEState {
	return &goAheadPoEState{port: port, admin: admin, beforeDetect: detect, afterDetect: detect, honourWrites: honourWrites}
}

func (s *goAheadPoEState) page() string {
	s.calls++
	detect := s.afterDetect
	if s.calls == 1 {
		detect = s.beforeDetect
	}
	adminEnable := "2"
	if s.admin {
		adminEnable = "1"
	}
	return fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8" ?><ResponseData><DeviceConfiguration><PoEPSEInterfaceList type="section">`+
			`<Interface><interfaceName>g%d</interfaceName><interfaceType>1</interfaceType><interfaceID>%d</interfaceID>`+
			`<adminEnable>%s</adminEnable><detectionStatus>%s</detectionStatus><outputPower>0</outputPower></Interface>`+
			`</PoEPSEInterfaceList></DeviceConfiguration></ResponseData>`,
		s.port, s.port, adminEnable, detect,
	)
}

// postedPoEInterface decodes just the field a SetPoE/CyclePoE/ClearPoEFault
// POST body carries, independent of webui's own internal builders.
type postedPoEInterface struct {
	AdminEnable string `xml:"adminEnable"`
}

type postedPoEBody struct {
	PoEPSEInterfaceList *struct {
		Interface postedPoEInterface `xml:"Interface"`
	} `xml:"PoEPSEInterfaceList"`
}

// goAheadPoESession is the webui.Session double over goAheadPoEState.
type goAheadPoESession struct{ *goAheadPoEState }

func (s *goAheadPoESession) Login(context.Context) error { return nil }

func (s *goAheadPoESession) GetPage(_ context.Context, _ string) (string, error) {
	if s.getPageErr != nil {
		return "", s.getPageErr
	}
	return s.page(), nil
}

func (s *goAheadPoESession) PostForm(_ context.Context, path string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("goAheadPoESession: PostForm(%q) not supported by this GoAhead-only fake", path)
}

func (s *goAheadPoESession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	return "", fmt.Errorf("goAheadPoESession: PostMultipart(%q) not supported by this GoAhead-only fake", path)
}

func (s *goAheadPoESession) PostXML(_ context.Context, _ string, body string) (string, error) {
	s.posts = append(s.posts, body)
	if s.postXMLErr != nil {
		return "", s.postXMLErr
	}
	if s.honourWrites {
		var doc postedPoEBody
		if err := xml.Unmarshal([]byte(body), &doc); err != nil {
			return "", fmt.Errorf("goAheadPoESession: malformed POST body: %w", err)
		}
		if doc.PoEPSEInterfaceList != nil {
			if a := doc.PoEPSEInterfaceList.Interface.AdminEnable; a == "1" || a == "2" {
				s.admin = a == "1"
			}
		}
	}
	return `<?xml version="1.0" encoding="UTF-8" ?><ResponseData><statusCode>0</statusCode></ResponseData>`, nil
}

var _ webui.Session = (*goAheadPoESession)(nil)

// incrementingGoAheadClock/noGoAheadSleep mirror snmp package's
// incrementingClock/noSleep (snmp/writer_cycle_test.go): a fake `now` func
// that jumps forward by step on every call, paired with a Sleep seam that
// never actually waits, guaranteeing a bounded, deterministic timeout-test
// runtime with zero real wall-clock delay.
func incrementingGoAheadClock(step time.Duration) func() time.Time {
	now := time.Now()
	return func() time.Time {
		now = now.Add(step)
		return now
	}
}

func noGoAheadSleep(context.Context, time.Duration) error { return nil }

func TestSetPoEGoAheadSetsAndVerifies(t *testing.T) {
	state := newGoAheadPoEState(17, true, "2", true)
	w := newGoAheadWriter(t, &goAheadPoESession{state})
	if err := w.SetPoE(context.Background(), 17, false, false); err != nil {
		t.Fatalf("SetPoE(false): %v", err)
	}
	if state.admin {
		t.Errorf("state.admin = true, want false")
	}
	if err := w.SetPoE(context.Background(), 17, true, false); err != nil {
		t.Fatalf("SetPoE(true): %v", err)
	}
	if !state.admin {
		t.Errorf("state.admin = false, want true")
	}
}

func TestSetPoEGoAheadVerificationFailureRaises(t *testing.T) {
	state := newGoAheadPoEState(17, true, "2", false) // device ignores the write
	w := newGoAheadWriter(t, &goAheadPoESession{state})
	err := w.SetPoE(context.Background(), 17, false, false)
	wantVerificationError(t, err, "SetPoE")
}

func TestSetPoEGoAheadProtectedPortBlocksWithoutForce(t *testing.T) {
	state := newGoAheadPoEState(17, true, "2", true)
	w, err := webui.NewWriter(&goAheadPoESession{state}, mustGetModel(t, "gs728tpp"), webui.WithProtectedPorts(17))
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	err = w.SetPoE(context.Background(), 17, false, false)
	wantProtectedPort(t, err, "SetPoE(protected, no force)")
	if len(state.posts) != 0 {
		t.Errorf("posts = %d, want 0 (blocked before any I/O)", len(state.posts))
	}
}

func TestCyclePoEGoAheadOffOnRoundTrips(t *testing.T) {
	state := newGoAheadPoEState(17, true, "2", true) // nothing attached: searching throughout
	w := newGoAheadWriter(t, &goAheadPoESession{state})
	if err := w.CyclePoE(context.Background(), 17, false); err != nil {
		t.Fatalf("CyclePoE: %v", err)
	}
	if !state.admin {
		t.Errorf("state.admin = false after CyclePoE, want true (re-armed)")
	}
	if len(state.posts) != 2 {
		t.Fatalf("posts = %d, want 2 (off then on, two SEPARATE writes)", len(state.posts))
	}
	if !strings.Contains(state.posts[0], "<adminEnable>2</adminEnable>") {
		t.Errorf("first post = %q, want adminEnable=2 (off)", state.posts[0])
	}
	if !strings.Contains(state.posts[1], "<adminEnable>1</adminEnable>") {
		t.Errorf("second post = %q, want adminEnable=1 (on)", state.posts[1])
	}
}

// TestCyclePoEGoAheadWasDeliveringRequiresDeliveringAgain exercises
// goaheadPoECycleComplete's `before.Delivering()` branch: a port that WAS
// delivering before the cycle must be DELIVERING again, not merely
// searching -- the real fake's seeded port 17 (PowerMw=0) can never
// reach this state, so this is package-local-only coverage.
func TestCyclePoEGoAheadWasDeliveringRequiresDeliveringAgain(t *testing.T) {
	state := newGoAheadPoEState(17, true, "3", true) // was delivering, still delivering after
	w := newGoAheadWriter(t, &goAheadPoESession{state})
	if err := w.CyclePoE(context.Background(), 17, false); err != nil {
		t.Fatalf("CyclePoE: %v", err)
	}
}

// TestCyclePoEGoAheadWasDeliveringButOnlySearchingTimesOut is the STRICT
// half of the same branch: a port that was delivering but only reaches
// SEARCHING after the cycle has NOT satisfied goaheadPoECycleComplete, so
// the poll loop must exhaust its deadline and raise
// *model.WriteVerificationError -- never silently accept "close enough".
func TestCyclePoEGoAheadWasDeliveringButOnlySearchingTimesOut(t *testing.T) {
	state := newGoAheadPoEState(17, true, "3", true)
	state.afterDetect = "2" // only searching after -- not enough once it was delivering
	w, err := webui.NewWriter(&goAheadPoESession{state}, mustGetModel(t, "gs728tpp"),
		webui.WithClock(incrementingGoAheadClock(100*time.Second), noGoAheadSleep))
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	err = w.CyclePoE(context.Background(), 17, false)
	wantVerificationError(t, err, "CyclePoE(was delivering, only searching after)")
}

// TestCyclePoEGoAheadNeverRecoversTimesOut proves the deadline actually
// terminates the poll loop (rather than looping forever) when the port
// never satisfies goaheadPoECycleComplete at all -- WithClock's injected
// incrementing clock + no-op sleep bound this test's real runtime near
// zero.
func TestCyclePoEGoAheadNeverRecoversTimesOut(t *testing.T) {
	state := newGoAheadPoEState(17, true, "2", true)
	state.afterDetect = "4" // faulted after -- never recovers
	w, err := webui.NewWriter(&goAheadPoESession{state}, mustGetModel(t, "gs728tpp"),
		webui.WithClock(incrementingGoAheadClock(100*time.Second), noGoAheadSleep))
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	err = w.CyclePoE(context.Background(), 17, false)
	wantVerificationError(t, err, "CyclePoE(never recovers)")
}

func TestCyclePoEGoAheadProtectedPortBlocksWithoutForce(t *testing.T) {
	state := newGoAheadPoEState(17, true, "2", true)
	w, err := webui.NewWriter(&goAheadPoESession{state}, mustGetModel(t, "gs728tpp"), webui.WithProtectedPorts(17))
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	err = w.CyclePoE(context.Background(), 17, false)
	wantProtectedPort(t, err, "CyclePoE(protected, no force)")
	if len(state.posts) != 0 {
		t.Errorf("posts = %d, want 0 (blocked before any I/O)", len(state.posts))
	}
}

// TestClearPoEFaultGoAheadSharesCyclePoEMechanism proves ClearPoEFault
// drives the IDENTICAL goaheadPoERearm mechanism CyclePoE does (Python's
// _goahead_poe_rearm is literally the same function for both callers) --
// a port that was FAULTED (not delivering) merely has to resume detecting
// (SEARCHING is enough), the loose half of goaheadPoECycleComplete.
func TestClearPoEFaultGoAheadSharesCyclePoEMechanism(t *testing.T) {
	state := newGoAheadPoEState(17, true, "4", true) // faulted before
	state.afterDetect = "2"                          // re-detecting after -- recovers
	w := newGoAheadWriter(t, &goAheadPoESession{state})
	if err := w.ClearPoEFault(context.Background(), 17, false); err != nil {
		t.Fatalf("ClearPoEFault: %v", err)
	}
	if len(state.posts) != 2 {
		t.Fatalf("posts = %d, want 2 (off then on, same mechanism as CyclePoE)", len(state.posts))
	}
}

func TestClearPoEFaultGoAheadProtectedPortBlocksWithoutForce(t *testing.T) {
	state := newGoAheadPoEState(17, true, "2", true)
	w, err := webui.NewWriter(&goAheadPoESession{state}, mustGetModel(t, "gs728tpp"), webui.WithProtectedPorts(17))
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	err = w.ClearPoEFault(context.Background(), 17, false)
	wantProtectedPort(t, err, "ClearPoEFault(protected, no force)")
	if len(state.posts) != 0 {
		t.Errorf("posts = %d, want 0 (blocked before any I/O)", len(state.posts))
	}
}

// --- GoAhead PoE transport-error propagation ------------------------------
//
// goaheadPoEAdmin/goaheadPoEStatus/goaheadPoERearm must surface a session
// error honestly (never swallow it as "verification failed" or silently
// succeed) -- proven directly since neither the real virtual fake nor any
// happy-path test above ever makes GetPage/PostXML fail.

func TestSetPoEGoAheadPropagatesReadError(t *testing.T) {
	state := newGoAheadPoEState(17, true, "2", true)
	state.getPageErr = errors.New("boom: read")
	w := newGoAheadWriter(t, &goAheadPoESession{state})
	err := w.SetPoE(context.Background(), 17, false, false)
	if err == nil || !strings.Contains(err.Error(), "boom: read") {
		t.Fatalf("SetPoE error = %v, want it to wrap the session's read error", err)
	}
}

func TestSetPoEGoAheadPropagatesWriteError(t *testing.T) {
	state := newGoAheadPoEState(17, true, "2", true)
	state.postXMLErr = errors.New("boom: write")
	w := newGoAheadWriter(t, &goAheadPoESession{state})
	err := w.SetPoE(context.Background(), 17, false, false)
	if err == nil || !strings.Contains(err.Error(), "boom: write") {
		t.Fatalf("SetPoE error = %v, want it to wrap the session's write error", err)
	}
}

func TestCyclePoEGoAheadPropagatesReadErrorOnBeforeSnapshot(t *testing.T) {
	state := newGoAheadPoEState(17, true, "2", true)
	state.getPageErr = errors.New("boom: before snapshot")
	w := newGoAheadWriter(t, &goAheadPoESession{state})
	err := w.CyclePoE(context.Background(), 17, false)
	if err == nil || !strings.Contains(err.Error(), "boom: before snapshot") {
		t.Fatalf("CyclePoE error = %v, want it to wrap the session's read error", err)
	}
	if len(state.posts) != 0 {
		t.Errorf("posts = %d, want 0 -- the before-snapshot read fails before any write", len(state.posts))
	}
}
