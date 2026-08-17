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

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// goAheadPortState is one GS728TPP port's description/speed-config state,
// mirroring virtual/web_gs728tpp.go's RenderGS728TPPPorts shape closely
// enough for ParseGoAheadPorts to read it back, but package-local (not the
// real virtual fake) and single-port only.
type goAheadPortState struct {
	port         int
	description  string
	speed        model.PortSpeed
	honourWrites bool
	posts        []string
}

func newGoAheadPortState(port int, honourWrites bool) *goAheadPortState {
	return &goAheadPortState{port: port, speed: model.AutoPortSpeed(), honourWrites: honourWrites}
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
	return fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8" ?><ResponseData><DeviceConfiguration><Standard802_3List type="section">`+
			`<Entry><interfaceName>g%d</interfaceName><interfaceType>1</interfaceType><interfaceID>%d</interfaceID>`+
			`<interfaceDescription>%s</interfaceDescription><adminState>1</adminState><linkState>1</linkState>`+
			`<speedOper>1000</speedOper><duplexOperMode>2</duplexOperMode>`+
			`<speedAdmin>%s</speedAdmin><duplexAdminMode>%s</duplexAdminMode><autoNegotiationAdminEnabled>%s</autoNegotiationAdminEnabled>`+
			`</Entry></Standard802_3List></DeviceConfiguration></ResponseData>`,
		s.port, s.port, s.description, rate, duplex, autoneg,
	)
}

// postedStandard802_3Entry decodes just the fields a SetPortDescription/
// SetPortSpeed POST body carries, independent of webui's own internal
// builders (this file has no access to them -- package webui_test is a
// black-box test package).
type postedStandard802_3Entry struct {
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
