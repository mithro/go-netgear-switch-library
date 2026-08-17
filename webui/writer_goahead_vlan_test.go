package webui_test

// writer_goahead_vlan_test.go: TDD coverage for webui.Writer's GoAhead-
// dialect (gs728tpp) CreateVlan/DeleteVlan/SetVlanMembership/SetPVID write
// paths -- the verify-after-write failure and protected-port branches
// virtual/httpface_test.go's real end-to-end round-trip tests
// (TestHTTPFaceGS728TPPWriterCreateDeleteVlanRoundTrips/
// SetVlanMembershipRoundTrips/SetPVIDRoundTrips) cannot themselves exercise
// (the real fake always honours a well-formed write), package-local to this
// test package the same way writer_goahead_test.go's goAheadPortState/
// goAheadPoEState already are.

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

// goAheadVlanSim is one VLAN's name plus tagged/untagged port sets, the
// package-local analogue of virtual/state.go's VlanSim.
type goAheadVlanSim struct {
	name     string
	tagged   map[int]bool
	untagged map[int]bool
}

// goAheadVlanState models a GS728TPP's VLANList (CreateVlan/DeleteVlan) and
// VLANInterfaceList (SetPVID/SetVlanMembership -- the PVID + per-port
// JoinVLANList page both share, matching the real device's own page
// layout) state, mirroring virtual/web_gs728tpp.go's RenderGS728TPPVlans/
// RenderGS728TPPPvidsMembership shapes closely enough for
// ParseGoAheadVlanNames/ParseGoAheadPVIDs/ParseGoAheadPortVlanMembership to
// read it back, but package-local (not the real virtual fake).
type goAheadVlanState struct {
	ports        []int // which physical ports render on the VLANInterfaceList page
	vlans        map[int]*goAheadVlanSim
	pvids        map[int]int
	honourWrites bool
	posts        []string
	// getPageErr/postXMLErr, when non-nil, make every GetPage/PostXML call
	// fail instead of serving state -- proving the GoAhead read/write
	// primitives (goaheadVlanIDs, goaheadMembership, goaheadPVIDs,
	// goaheadWrite) propagate a transport error honestly.
	getPageErr error
	postXMLErr error
}

// newGoAheadVlanState seeds VLAN 1 (every real GS728TPP's default VLAN,
// present unconditionally): ParseGoAheadVlanNames/ParseGoAheadPortVlan
// Membership both refuse an EMPTY VLANList/VLANInterfaceList page as
// unexpected (no row parsed at all is honestly indistinguishable from a
// wrong page) -- exactly like the real device, whose VLANList is never
// actually empty, this fake must not start from a state no real switch
// has.
func newGoAheadVlanState(ports []int, honourWrites bool) *goAheadVlanState {
	return &goAheadVlanState{
		ports:        ports,
		vlans:        map[int]*goAheadVlanSim{1: {name: "", tagged: map[int]bool{}, untagged: map[int]bool{}}},
		pvids:        map[int]int{},
		honourWrites: honourWrites,
	}
}

func (s *goAheadVlanState) vlanIDs() []int {
	out := make([]int, 0, len(s.vlans))
	for id := range s.vlans {
		out = append(out, id)
	}
	return out
}

func (s *goAheadVlanState) vlansPage() string {
	var rows strings.Builder
	for _, vid := range s.vlanIDs() {
		fmt.Fprintf(&rows, "<VLAN><VLANID>%d</VLANID><VLANName>%s</VLANName></VLAN>", vid, s.vlans[vid].name)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" ?><ResponseData><DeviceConfiguration>`+
		`<VLANList type="section">%s</VLANList></DeviceConfiguration></ResponseData>`, rows.String())
}

func (s *goAheadVlanState) interfacesPage() string {
	var rows strings.Builder
	for _, p := range s.ports {
		var entries strings.Builder
		for _, vid := range s.vlanIDs() {
			v := s.vlans[vid]
			switch {
			case v.tagged[p]:
				fmt.Fprintf(&entries, "<VLANEntry><VLANID>%d</VLANID><taggingMode>2</taggingMode></VLANEntry>", vid)
			case v.untagged[p]:
				fmt.Fprintf(&entries, "<VLANEntry><VLANID>%d</VLANID><taggingMode>1</taggingMode></VLANEntry>", vid)
			}
		}
		pvid := s.pvids[p]
		if pvid == 0 {
			pvid = 1
		}
		fmt.Fprintf(&rows,
			"<Interface><interfaceName>g%d</interfaceName><interfaceType>1</interfaceType><interfaceID>%d</interfaceID>"+
				"<PVID>%d</PVID><JoinVLANList>%s</JoinVLANList></Interface>",
			p, p, pvid, entries.String())
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" ?><ResponseData><DeviceConfiguration>`+
		`<VLANInterfaceList type="section">%s</VLANInterfaceList></DeviceConfiguration></ResponseData>`, rows.String())
}

// --- decode shapes for the write bodies this fake applies, independent of
// webui's own internal builders (this file has no access to them --
// package webui_test is a black-box test package) ---

type postedVLANListEntry struct {
	VLANID   string `xml:"VLANID"`
	VLANName string `xml:"VLANName"`
}

type postedVLANListXML struct {
	Action string                `xml:"action,attr"`
	VLANs  []postedVLANListEntry `xml:"VLAN"`
}

type postedVLANMember struct {
	InterfaceName string `xml:"interfaceName"`
	TaggingMode   string `xml:"taggingMode"`
}

type postedMembershipVLAN struct {
	VLANID  string             `xml:"VLANID"`
	Members []postedVLANMember `xml:"MembershipList>VLANMember"`
}

type postedVLANMembershipListXML struct {
	Action string                 `xml:"action,attr"`
	VLANs  []postedMembershipVLAN `xml:"VLAN"`
}

type postedPVIDInterface struct {
	InterfaceName string `xml:"interfaceName"`
	PVID          string `xml:"PVID"`
}

type postedVLANInterfaceListXML struct {
	Interfaces []postedPVIDInterface `xml:"Interface"`
}

type postedVlanBody struct {
	VLANList           *postedVLANListXML           `xml:"VLANList"`
	VLANMembershipList *postedVLANMembershipListXML `xml:"VLANMembershipList"`
	VLANInterfaceList  *postedVLANInterfaceListXML  `xml:"VLANInterfaceList"`
}

// vlanIfacePort converts a posted interfaceName ("g17") to a port number,
// mirroring webui/goahead_write.go's portInterfaceName inverse.
func vlanIfacePort(name string) (int, bool) {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, "g") {
		return 0, false
	}
	n, err := strconv.Atoi(name[1:])
	if err != nil {
		return 0, false
	}
	return n, true
}

// apply mutates s from one decoded POST body, mirroring (a small, single-
// port-set slice of) virtual/httpface.go's applyGoAheadWrite dispatch.
func (s *goAheadVlanState) apply(body string) error {
	var doc postedVlanBody
	if err := xml.Unmarshal([]byte(body), &doc); err != nil {
		return err
	}
	if doc.VLANList != nil {
		for _, v := range doc.VLANList.VLANs {
			vid, err := strconv.Atoi(strings.TrimSpace(v.VLANID))
			if err != nil {
				continue
			}
			if doc.VLANList.Action == "delete" {
				delete(s.vlans, vid)
				continue
			}
			if sim, ok := s.vlans[vid]; ok {
				sim.name = v.VLANName
			} else {
				s.vlans[vid] = &goAheadVlanSim{name: v.VLANName, tagged: map[int]bool{}, untagged: map[int]bool{}}
			}
		}
	}
	if doc.VLANMembershipList != nil {
		for _, v := range doc.VLANMembershipList.VLANs {
			vid, err := strconv.Atoi(strings.TrimSpace(v.VLANID))
			if err != nil {
				continue
			}
			sim, ok := s.vlans[vid]
			if !ok {
				continue
			}
			for _, m := range v.Members {
				port, ok := vlanIfacePort(m.InterfaceName)
				if !ok {
					continue
				}
				if doc.VLANMembershipList.Action == "delete" {
					delete(sim.tagged, port)
					delete(sim.untagged, port)
					continue
				}
				if strings.TrimSpace(m.TaggingMode) == "1" {
					sim.untagged[port] = true
					delete(sim.tagged, port)
				} else {
					sim.tagged[port] = true
					delete(sim.untagged, port)
				}
			}
		}
	}
	if doc.VLANInterfaceList != nil {
		for _, iface := range doc.VLANInterfaceList.Interfaces {
			port, ok := vlanIfacePort(iface.InterfaceName)
			if !ok {
				continue
			}
			pvid, err := strconv.Atoi(strings.TrimSpace(iface.PVID))
			if err != nil {
				continue
			}
			s.pvids[port] = pvid
		}
	}
	return nil
}

// goAheadVlanSession is the webui.Session double over goAheadVlanState.
type goAheadVlanSession struct{ *goAheadVlanState }

func (s *goAheadVlanSession) Login(context.Context) error { return nil }

func (s *goAheadVlanSession) GetPage(_ context.Context, path string) (string, error) {
	if s.getPageErr != nil {
		return "", s.getPageErr
	}
	if strings.Contains(path, "VLANInterfaceList") {
		return s.interfacesPage(), nil
	}
	return s.vlansPage(), nil
}

func (s *goAheadVlanSession) PostForm(_ context.Context, path string, _ map[string]string) (string, error) {
	return "", fmt.Errorf("goAheadVlanSession: PostForm(%q) not supported by this GoAhead-only fake", path)
}

func (s *goAheadVlanSession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	return "", fmt.Errorf("goAheadVlanSession: PostMultipart(%q) not supported by this GoAhead-only fake", path)
}

func (s *goAheadVlanSession) PostXML(_ context.Context, _ string, body string) (string, error) {
	s.posts = append(s.posts, body)
	if s.postXMLErr != nil {
		return "", s.postXMLErr
	}
	if s.honourWrites {
		if err := s.apply(body); err != nil {
			return "", fmt.Errorf("goAheadVlanSession: malformed POST body: %w", err)
		}
	}
	return `<?xml version="1.0" encoding="UTF-8" ?><ResponseData><statusCode>0</statusCode></ResponseData>`, nil
}

var _ webui.Session = (*goAheadVlanSession)(nil)

// --- CreateVlan / DeleteVlan (GoAhead dialect: VLANList) ------------------

func TestCreateVlanGoAheadSetsAndVerifies(t *testing.T) {
	state := newGoAheadVlanState([]int{2}, true)
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	if err := w.CreateVlan(context.Background(), 10, "guests"); err != nil {
		t.Fatalf("CreateVlan: %v", err)
	}
	sim, ok := state.vlans[10]
	if !ok {
		t.Fatalf("vlan 10 not created")
	}
	if sim.name != "guests" {
		t.Errorf("vlan 10 name = %q, want \"guests\"", sim.name)
	}
}

func TestCreateVlanGoAheadNotCreatedRaisesVerification(t *testing.T) {
	state := newGoAheadVlanState([]int{2}, false) // device ignores the write
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	err := w.CreateVlan(context.Background(), 10, "guests")
	wantVerificationError(t, err, "CreateVlan")
}

func TestDeleteVlanGoAheadDeletesAndVerifies(t *testing.T) {
	state := newGoAheadVlanState([]int{2}, true)
	state.vlans[10] = &goAheadVlanSim{name: "guests", tagged: map[int]bool{}, untagged: map[int]bool{}}
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	if err := w.DeleteVlan(context.Background(), 10, false); err != nil {
		t.Fatalf("DeleteVlan: %v", err)
	}
	if _, ok := state.vlans[10]; ok {
		t.Errorf("vlan 10 still present after DeleteVlan")
	}
}

func TestDeleteVlanGoAheadNotRemovedRaisesVerification(t *testing.T) {
	state := newGoAheadVlanState([]int{2}, false) // device ignores the write
	state.vlans[10] = &goAheadVlanSim{name: "guests", tagged: map[int]bool{}, untagged: map[int]bool{}}
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	err := w.DeleteVlan(context.Background(), 10, false)
	wantVerificationError(t, err, "DeleteVlan")
}

// --- SetVlanMembership (GoAhead dialect: VLANMembershipList) --------------

// TestSetVlanMembershipGoAheadSetsAndVerifies drives all three
// model.VlanMode values through vlanMembershipBody/goaheadTaggingMode:
// TAGGED and UNTAGGED are a "set" carrying membershipType/taggingMode,
// EXCLUDED is a "delete" carrying neither (see vlanMembershipBody's own
// doc comment for why that asymmetry is the page's, not a guess).
func TestSetVlanMembershipGoAheadSetsAndVerifies(t *testing.T) {
	state := newGoAheadVlanState([]int{17}, true)
	state.vlans[90] = &goAheadVlanSim{name: "iot", tagged: map[int]bool{}, untagged: map[int]bool{}}
	w := newGoAheadWriter(t, &goAheadVlanSession{state})

	if err := w.SetVlanMembership(context.Background(), 90, 17, model.VlanTagged, false); err != nil {
		t.Fatalf("SetVlanMembership(tagged): %v", err)
	}
	if !state.vlans[90].tagged[17] || state.vlans[90].untagged[17] {
		t.Errorf("VLAN 90 port 17 tagged/untagged = %v/%v, want tagged only",
			state.vlans[90].tagged[17], state.vlans[90].untagged[17])
	}

	if err := w.SetVlanMembership(context.Background(), 90, 17, model.VlanUntagged, false); err != nil {
		t.Fatalf("SetVlanMembership(untagged): %v", err)
	}
	if state.vlans[90].tagged[17] || !state.vlans[90].untagged[17] {
		t.Errorf("VLAN 90 port 17 tagged/untagged = %v/%v, want untagged only",
			state.vlans[90].tagged[17], state.vlans[90].untagged[17])
	}

	if err := w.SetVlanMembership(context.Background(), 90, 17, model.VlanExcluded, false); err != nil {
		t.Fatalf("SetVlanMembership(excluded): %v", err)
	}
	if state.vlans[90].tagged[17] || state.vlans[90].untagged[17] {
		t.Errorf("VLAN 90 port 17 still a member after excluding")
	}
}

func TestSetVlanMembershipGoAheadWriteNotReflectedRaisesVerification(t *testing.T) {
	state := newGoAheadVlanState([]int{17}, false) // device ignores the write
	state.vlans[90] = &goAheadVlanSim{name: "iot", tagged: map[int]bool{17: true}, untagged: map[int]bool{}}
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	err := w.SetVlanMembership(context.Background(), 90, 17, model.VlanExcluded, false)
	wantVerificationError(t, err, "SetVlanMembership")
}

func TestSetVlanMembershipGoAheadProtectedPortBlocksWithoutForce(t *testing.T) {
	state := newGoAheadVlanState([]int{17}, true)
	state.vlans[90] = &goAheadVlanSim{name: "iot", tagged: map[int]bool{17: true}, untagged: map[int]bool{}}
	w, err := webui.NewWriter(&goAheadVlanSession{state}, mustGetModel(t, "gs728tpp"), webui.WithProtectedPorts(17))
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	err = w.SetVlanMembership(context.Background(), 90, 17, model.VlanExcluded, false)
	wantProtectedPort(t, err, "SetVlanMembership(protected, no force)")
	if len(state.posts) != 0 {
		t.Errorf("posts = %d, want 0 (blocked before any I/O)", len(state.posts))
	}
}

// --- SetPVID (GoAhead dialect: VLANInterfaceList) -------------------------

func TestSetPVIDGoAheadSetsAndVerifies(t *testing.T) {
	state := newGoAheadVlanState([]int{2}, true)
	state.vlans[5] = &goAheadVlanSim{name: "net", tagged: map[int]bool{}, untagged: map[int]bool{}}
	state.pvids[2] = 1
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	if err := w.SetPVID(context.Background(), 2, 5, false); err != nil {
		t.Fatalf("SetPVID: %v", err)
	}
	if state.pvids[2] != 5 {
		t.Errorf("pvids[2] = %d, want 5", state.pvids[2])
	}
}

func TestSetPVIDGoAheadWriteNotReflectedRaisesVerification(t *testing.T) {
	state := newGoAheadVlanState([]int{2}, false) // device ignores the write
	state.vlans[5] = &goAheadVlanSim{name: "net", tagged: map[int]bool{}, untagged: map[int]bool{}}
	state.pvids[2] = 1
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	err := w.SetPVID(context.Background(), 2, 5, false)
	wantVerificationError(t, err, "SetPVID")
}

func TestSetPVIDGoAheadProtectedPortBlocksWithoutForce(t *testing.T) {
	state := newGoAheadVlanState([]int{2}, true)
	state.vlans[5] = &goAheadVlanSim{name: "net", tagged: map[int]bool{}, untagged: map[int]bool{}}
	w, err := webui.NewWriter(&goAheadVlanSession{state}, mustGetModel(t, "gs728tpp"), webui.WithProtectedPorts(2))
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	err = w.SetPVID(context.Background(), 2, 5, false)
	wantProtectedPort(t, err, "SetPVID(protected, no force)")
	if len(state.posts) != 0 {
		t.Errorf("posts = %d, want 0 (blocked before any I/O)", len(state.posts))
	}
}

// --- GoAhead VLAN/PVID/membership transport-error propagation -------------
//
// goaheadVlanIDs/goaheadMembership/goaheadPVIDs/goaheadWrite must surface a
// session error honestly (never swallow it as "verification failed" or
// silently succeed) -- proven directly since neither the real virtual fake
// nor any happy-path test above ever makes GetPage/PostXML fail.

func TestCreateVlanGoAheadPropagatesReadError(t *testing.T) {
	state := newGoAheadVlanState([]int{2}, true)
	state.getPageErr = errors.New("boom: read")
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	err := w.CreateVlan(context.Background(), 10, "guests")
	if err == nil || !strings.Contains(err.Error(), "boom: read") {
		t.Fatalf("CreateVlan error = %v, want it to wrap the session's read error", err)
	}
}

func TestCreateVlanGoAheadPropagatesWriteError(t *testing.T) {
	state := newGoAheadVlanState([]int{2}, true)
	state.postXMLErr = errors.New("boom: write")
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	err := w.CreateVlan(context.Background(), 10, "guests")
	if err == nil || !strings.Contains(err.Error(), "boom: write") {
		t.Fatalf("CreateVlan error = %v, want it to wrap the session's write error", err)
	}
}

func TestDeleteVlanGoAheadPropagatesReadError(t *testing.T) {
	state := newGoAheadVlanState([]int{2}, true)
	state.vlans[10] = &goAheadVlanSim{name: "guests", tagged: map[int]bool{}, untagged: map[int]bool{}}
	state.getPageErr = errors.New("boom: read")
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	err := w.DeleteVlan(context.Background(), 10, false)
	if err == nil || !strings.Contains(err.Error(), "boom: read") {
		t.Fatalf("DeleteVlan error = %v, want it to wrap the session's read error", err)
	}
}

func TestSetVlanMembershipGoAheadPropagatesReadError(t *testing.T) {
	state := newGoAheadVlanState([]int{17}, true)
	state.vlans[90] = &goAheadVlanSim{name: "iot", tagged: map[int]bool{17: true}, untagged: map[int]bool{}}
	state.getPageErr = errors.New("boom: read")
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	err := w.SetVlanMembership(context.Background(), 90, 17, model.VlanExcluded, false)
	if err == nil || !strings.Contains(err.Error(), "boom: read") {
		t.Fatalf("SetVlanMembership error = %v, want it to wrap the session's read error", err)
	}
}

func TestSetVlanMembershipGoAheadPropagatesWriteError(t *testing.T) {
	state := newGoAheadVlanState([]int{17}, true)
	state.vlans[90] = &goAheadVlanSim{name: "iot", tagged: map[int]bool{17: true}, untagged: map[int]bool{}}
	state.postXMLErr = errors.New("boom: write")
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	err := w.SetVlanMembership(context.Background(), 90, 17, model.VlanExcluded, false)
	if err == nil || !strings.Contains(err.Error(), "boom: write") {
		t.Fatalf("SetVlanMembership error = %v, want it to wrap the session's write error", err)
	}
}

func TestSetPVIDGoAheadPropagatesWriteError(t *testing.T) {
	state := newGoAheadVlanState([]int{2}, true)
	state.vlans[5] = &goAheadVlanSim{name: "net", tagged: map[int]bool{}, untagged: map[int]bool{}}
	state.postXMLErr = errors.New("boom: write")
	w := newGoAheadWriter(t, &goAheadVlanSession{state})
	err := w.SetPVID(context.Background(), 2, 5, false)
	if err == nil || !strings.Contains(err.Error(), "boom: write") {
		t.Fatalf("SetPVID error = %v, want it to wrap the session's write error", err)
	}
}
