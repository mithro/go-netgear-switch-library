package virtual

// Tests for HTTPFace, driven over real TCP loopback against webui's own
// Session implementation (webui.HTTPClient) and webui.Reader -- the same
// "drive the mock through the real client, not by peeking at internals"
// convention snmpface_test.go/nsdpface_test.go already use.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// clientSpec returns a shallow copy of spec with Secure forced false, for
// driving webui.HTTPClient/Reader/Writer against this mock over plain HTTP.
// spec.Secure only selects http:// vs https:// inside webui.NewHTTPClient
// (dossier §3.4/§6.6) -- this face never implements TLS (see
// TestHTTPFaceSecurePOSTRequiresOriginHeader's own doc comment) -- so a
// library-level (not raw net/http) test against a "secure" model (only
// m4300-16x) must hand the CLIENT this desecured copy or every request
// bounces off Go's http.Client with "server gave HTTP response to HTTPS
// client". webui.NewReader/NewWriter re-derive their OWN spec from m
// internally (they take a Session + *model.SwitchModel, not a spec), so
// passing this copy only to NewHTTPClient is enough -- every PATH value
// (unaffected by Secure) still matches.
func clientSpec(spec *webui.HTTPModelSpec) *webui.HTTPModelSpec {
	cp := *spec
	cp.Secure = false
	return &cp
}

// startHTTPFace starts an HTTPFace over st per spec with the given password
// on 127.0.0.1, registering t.Cleanup to stop it, and returns its
// "host:port" address.
func startHTTPFace(t *testing.T, st *State, spec *webui.HTTPModelSpec, password string) (addr string, face *HTTPFace) {
	t.Helper()
	face = NewHTTPFace(st, spec, password, "127.0.0.1")
	port, err := face.Start()
	if err != nil {
		t.Fatalf("HTTPFace.Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := face.Stop(); err != nil {
			t.Errorf("HTTPFace.Stop() error = %v", err)
		}
	})
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), face
}

// -- Login handshakes (all 5 LoginScheme values) -----------------------

func TestHTTPFaceLoginAllSchemes(t *testing.T) {
	tests := []struct {
		name     string
		modelKey string
		scheme   webui.LoginScheme
	}{
		{"MergeHashCGI/gs305ep", "gs305ep", webui.LoginSchemeMergeHashCGI},
		{"Gambit/gs110emx", "gs110emx", webui.LoginSchemeGambit},
		{"CheetahForm/gsm7252ps", "gsm7252ps", webui.LoginSchemeCheetahForm},
		{"CheetahV1/m4300-24x", "m4300-24x", webui.LoginSchemeCheetahV1},
		{"XMLAPI/gs728tpp", "gs728tpp", webui.LoginSchemeXMLAPI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := model.GetModel(tt.modelKey)
			if err != nil {
				t.Fatalf("model.GetModel(%q): %v", tt.modelKey, err)
			}
			spec, err := webui.HTTPSpec(m)
			if err != nil {
				t.Fatalf("webui.HTTPSpec(%q): %v", tt.modelKey, err)
			}
			if spec.Scheme != tt.scheme {
				t.Fatalf("spec.Scheme = %v, want %v (test table/registry drifted)", spec.Scheme, tt.scheme)
			}
			addr, _ := startHTTPFace(t, NewState(tt.modelKey), spec, "password")

			t.Run("correct password", func(t *testing.T) {
				client := webui.NewHTTPClient(addr, "password", spec)
				if err := client.Login(context.Background()); err != nil {
					t.Errorf("Login() with correct password error = %v, want nil", err)
				}
			})
			t.Run("wrong password", func(t *testing.T) {
				client := webui.NewHTTPClient(addr, "wrong-password", spec)
				err := client.Login(context.Background())
				if err == nil {
					t.Fatalf("Login() with wrong password error = nil, want an auth error")
				}
				if !errors.Is(err, model.ErrHTTPAuth) {
					t.Errorf("Login() with wrong password error = %v, want errors.Is(..., model.ErrHTTPAuth)", err)
				}
			})
		})
	}
}

// -- Referer/Origin 403 enforcement (CHEETAH_V1, dossier §3.4) ----------

func TestHTTPFaceRefererMissingIs403(t *testing.T) {
	m, err := model.GetModel("m4300-24x")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, NewState("m4300-24x"), spec, "password")

	// A bare net/http request, deliberately NOT going through
	// webui.HTTPClient (which always attaches Referer for a NeedsReferer
	// spec) -- proving the face itself enforces the guard, not just that the
	// client happens to always send the header.
	resp, err := http.Get("http://" + addr + spec.LoginPath) //nolint:noctx,gosec // test-only bare GET; addr is our own loopback face.
	if err != nil {
		t.Fatalf("GET %s: %v", spec.LoginPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET %s without Referer status = %d, want 403", spec.LoginPath, resp.StatusCode)
	}
}

// TestHTTPFaceSecurePOSTRequiresOriginHeader covers the m4300-16x-specific
// extra rule (dossier §3.4): a "secure" (HTTPS/:49152) NeedsReferer model
// answers 403 to a POST that carries Referer WITHOUT Origin, even though a
// GET (or a POST on a NON-secure NeedsReferer model, e.g. m4300-24x, already
// covered by TestHTTPFaceRefererMissingIs403) only ever requires Referer.
// Deliberately raw net/http (not webui.HTTPClient, which always attaches
// both headers together for a NeedsReferer+Secure spec) and deliberately
// plain http:// against the mock (this face never implements TLS -- spec.
// Secure only changes what scheme webui.HTTPClient itself would pick), so
// this test exercises refererOK's `isPost && spec.Secure` branch directly
// rather than asserting on a client that would never omit Origin in the
// first place.
func TestHTTPFaceSecurePOSTRequiresOriginHeader(t *testing.T) {
	m, err := model.GetModel("m4300-16x")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	if !spec.Secure || !spec.NeedsReferer {
		t.Fatalf("m4300-16x spec.Secure=%v/NeedsReferer=%v, want both true (test fixture assumption broken)", spec.Secure, spec.NeedsReferer)
	}
	addr, _ := startHTTPFace(t, NewState("m4300-16x"), spec, "password")

	postPath := spec.LoginPostPath
	if postPath == "" {
		postPath = spec.LoginPath
	}
	referer := "http://" + addr + "/"

	newPOST := func(t *testing.T, withOrigin bool) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+postPath, strings.NewReader("")) //nolint:noctx // test-only.
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Referer", referer)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if withOrigin {
			req.Header.Set("Origin", "http://"+addr)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", postPath, err)
		}
		return resp
	}

	t.Run("Referer without Origin is 403", func(t *testing.T) {
		resp := newPOST(t, false)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s with Referer but no Origin status = %d, want 403", postPath, resp.StatusCode)
		}
	})
	t.Run("Referer with Origin passes the referer gate", func(t *testing.T) {
		resp := newPOST(t, true)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusForbidden {
			t.Errorf("POST %s with both Referer and Origin status = 403, want NOT 403 (blocked only by the referer/origin gate, not this check)", postPath)
		}
	})
}

// -- 404 for any path not in the model's HttpModelSpec (dossier §3.7) ---

func TestHTTPFace404ForUnspeccedPath(t *testing.T) {
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, SeedGS305EP(), spec, "password")

	resp, err := http.Get("http://" + addr + "/this-path-does-not-exist.cgi") //nolint:noctx,gosec // test-only.
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET unspecced path status = %d, want 404", resp.StatusCode)
	}
}

// TestHTTPFaceNonStandardDialectReadPagesAreHonestly404 used to be a
// deliberate tripwire (dispatchRender's doc comment / principles 1 & 5):
// every dialect OTHER than HTMLDialectStandard/HTMLDialectGS110EMX/
// HTMLDialectGS105PE had no renderer wired yet, so a known, spec-advertised
// read page had to 404 honestly rather than silently fall through to the
// STANDARD-dialect fallback.
//
// Task 9 flipped the GS110EMX/GS105PE cases; Task 10 flips the remaining
// four (M4300 x2, XE_FASTPATH, S3300) plus GoAhead's wcd routing (see
// TestHTTPFaceGoAheadFaceServesEveryReadOpFromState, which replaced
// TestHTTPFaceGoAheadAuthenticatedReadOfUnimplementedWcdPage404s below) --
// EVERY HTMLDialect this package defines now has a real renderer wired in
// dispatchRender/dispatchApplyAndRender, so this tripwire has nothing left
// to cover and is removed rather than left as an empty shell. Coverage for
// "a model's spec advertises a path this dialect's renderer does not
// implement" now lives in each dialect's own *ServesEveryReadOpFromState /
// *404sAPathTheSpecDoesNotServe tests below.

// -- Wired dialect (STANDARD/gs305ep) end-to-end -------------------------

func TestHTTPFaceGS305EPReadPortsMatchesSeed(t *testing.T) {
	st := SeedGS305EP()
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	ports, err := reader.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != len(st.Ports) {
		t.Fatalf("GetPorts() returned %d ports, want %d (seeded)", len(ports), len(st.Ports))
	}
	for _, p := range ports {
		want, ok := st.Ports[p.Port]
		if !ok {
			t.Fatalf("GetPorts() returned unknown port %d", p.Port)
		}
		if p.LinkUp != want.Link {
			t.Errorf("port %d LinkUp = %v, want %v", p.Port, p.LinkUp, want.Link)
		}
		if p.AdminEnabled != want.Admin {
			t.Errorf("port %d AdminEnabled = %v, want %v", p.Port, p.AdminEnabled, want.Admin)
		}
		if want.Link {
			if p.SpeedMbps == nil || *p.SpeedMbps != want.Speed {
				t.Errorf("port %d SpeedMbps = %v, want %d", p.Port, p.SpeedMbps, want.Speed)
			}
		}
	}
}

// TestHTTPFaceGS305EPPoEWriteRoundTrip proves the write POST path
// (dispatchApplyAndRender: apply_form then re-render) actually mutates the
// shared State, by POSTing a PoE apply form directly (mirroring
// webui.PoeApplyForm's shape) and reading it back through the wired
// PoEStatusPath renderer.
func TestHTTPFaceGS305EPPoEWriteRoundTrip(t *testing.T) {
	st := SeedGS305EP()
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	if !st.Poe[2].Admin {
		t.Fatalf("test fixture assumption broken: port 2 PoE admin must start ON")
	}
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()

	// Turn port 2's PoE OFF (portID is 0-based -> "1").
	body := webui.PoeApplyForm(2, false, spec.IsEPXPoE, "virtualhash")
	if _, err := client.PostForm(ctx, spec.PoEConfigPath, body); err != nil {
		t.Fatalf("PostForm(%s) error = %v", spec.PoEConfigPath, err)
	}

	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	poe, err := reader.GetPoE(ctx)
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	var port2 *model.PoEStatus
	for i := range poe {
		if poe[i].Port == 2 {
			port2 = &poe[i]
		}
	}
	if port2 == nil {
		t.Fatalf("GetPoE() has no port 2 row")
	}
	if port2.AdminEnabled {
		t.Errorf("port 2 AdminEnabled after PoE-off write = true, want false")
	}
	// web.py's _detect_text (renderPoEStatus) renders "Disabled" whenever
	// psim.admin is false, REGARDLESS of the underlying Detect wire code --
	// so the readback must report PoEDetectDisabled, not whatever numeric
	// Detect applyPoE happened to leave behind.
	if port2.Detect != model.PoEDetectDisabled {
		t.Errorf("port 2 Detect after PoE-off write = %v, want PoEDetectDisabled", port2.Detect)
	}
}

// TestHTTPFaceGS305EPGetStats reads back the seeded per-port traffic
// counters, exercising renderStats (and u64OrZero's zero-default for the
// ports the seed left unset).
func TestHTTPFaceGS305EPGetStats(t *testing.T) {
	st := SeedGS305EP()
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	stats, err := reader.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	if len(stats) != len(st.Ports) {
		t.Fatalf("GetStats() returned %d rows, want %d (seeded)", len(stats), len(st.Ports))
	}
	for _, s := range stats {
		want := st.Ports[s.Port]
		if s.RxBytes == nil || *s.RxBytes != u64OrZero(want.RxOctets) {
			t.Errorf("port %d RxBytes = %v, want %d", s.Port, s.RxBytes, u64OrZero(want.RxOctets))
		}
		if s.TxBytes == nil || *s.TxBytes != u64OrZero(want.TxOctets) {
			t.Errorf("port %d TxBytes = %v, want %d", s.Port, s.TxBytes, u64OrZero(want.TxOctets))
		}
		if s.RxErrors == nil || *s.RxErrors != u64OrZero(want.RxErrors) {
			t.Errorf("port %d RxErrors = %v, want %d", s.Port, s.RxErrors, u64OrZero(want.RxErrors))
		}
	}
}

// TestHTTPFaceGS305EPGetPVIDs reads back the seeded per-port PVIDs,
// exercising renderPvid.
func TestHTTPFaceGS305EPGetPVIDs(t *testing.T) {
	st := SeedGS305EP()
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	pvids, err := reader.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	got := make(map[int]int, len(pvids))
	for _, p := range pvids {
		got[p.Port] = p.Vlan
	}
	for port, want := range st.Pvids {
		if got[port] != want {
			t.Errorf("port %d PVID = %d, want %d (seeded)", port, got[port], want)
		}
	}
}

// TestHTTPFaceGS305EPGetVLANs reads back the seeded VLAN table via the
// STANDARD-dialect per-VLAN 8021qMembe.cgi POST loop (dossier §1.2 branch
// 3), exercising renderVlanConfig + renderMembership together.
func TestHTTPFaceGS305EPGetVLANs(t *testing.T) {
	st := SeedGS305EP()
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	vlans, err := reader.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	if len(vlans) != len(st.Vlans) {
		t.Fatalf("GetVLANs() returned %d VLANs, want %d (seeded)", len(vlans), len(st.Vlans))
	}
	for _, v := range vlans {
		wantSim, ok := st.Vlans[v.VlanID]
		if !ok {
			t.Fatalf("GetVLANs() returned unknown VLAN %d", v.VlanID)
		}
		wantMember := len(wantSim.Member)
		if len(v.MemberPorts) != wantMember {
			t.Errorf("VLAN %d MemberPorts = %v, want %d ports (seeded member set)", v.VlanID, v.MemberPorts, wantMember)
		}
		for _, p := range v.UntaggedPorts {
			if !wantSim.Untagged[p] {
				t.Errorf("VLAN %d reports port %d untagged, seed does not", v.VlanID, p)
			}
		}
	}
}

// TestHTTPFaceGS305EPWriterSetPVID drives webui.Writer.SetPVID end-to-end
// (GET-for-CSRF, POST, re-GET-to-verify), exercising applyPvid + renderPvid
// together via the library's own public write API.
func TestHTTPFaceGS305EPWriterSetPVID(t *testing.T) {
	st := SeedGS305EP()
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	if err := writer.SetPVID(context.Background(), 3, 90, false); err != nil {
		t.Fatalf("SetPVID(port=3, vlan=90) error = %v", err)
	}

	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	pvids, err := reader.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	for _, p := range pvids {
		if p.Port == 3 && p.Vlan != 90 {
			t.Errorf("port 3 PVID after SetPVID(90) = %d, want 90", p.Vlan)
		}
	}
}

// TestHTTPFaceGS305EPWriterSetVlanMembership drives
// webui.Writer.SetVlanMembership end-to-end (the 8021qMembe.cgi 3-step
// read/apply/verify), exercising applyMembership.
func TestHTTPFaceGS305EPWriterSetVlanMembership(t *testing.T) {
	st := SeedGS305EP()
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	// VLAN 1 port 5 starts Untagged (member of the seed's {1,2,3,4,5} set,
	// untagged {3,4,5}); flip it to Tagged.
	if err := writer.SetVlanMembership(context.Background(), 1, 5, model.VlanTagged, false); err != nil {
		t.Fatalf("SetVlanMembership(vlan=1, port=5, Tagged) error = %v", err)
	}

	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	vlans, err := reader.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	for _, v := range vlans {
		if v.VlanID != 1 {
			continue
		}
		for _, p := range v.UntaggedPorts {
			if p == 5 {
				t.Errorf("VLAN 1 port 5 is still Untagged after SetVlanMembership(Tagged)")
			}
		}
		found := false
		for _, p := range v.TaggedPorts {
			if p == 5 {
				found = true
			}
		}
		if !found {
			t.Errorf("VLAN 1 TaggedPorts = %v, want it to contain port 5", v.TaggedPorts)
		}
	}
}

// TestHTTPFaceGS305EPWriterCreateDeleteVlan drives
// webui.Writer.CreateVlan/DeleteVlan end-to-end, exercising
// applyVlanConfig's Add and Delete branches.
func TestHTTPFaceGS305EPWriterCreateDeleteVlan(t *testing.T) {
	st := SeedGS305EP()
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	ctx := context.Background()

	const newVlan = 50
	if err := writer.CreateVlan(ctx, newVlan, "unused"); err != nil {
		t.Fatalf("CreateVlan(%d) error = %v", newVlan, err)
	}
	vlans, err := reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() after CreateVlan error = %v", err)
	}
	if !vlanIDPresent(vlans, newVlan) {
		t.Fatalf("GetVLANs() after CreateVlan(%d) does not contain it: %+v", newVlan, vlans)
	}

	if err := writer.DeleteVlan(ctx, newVlan, false); err != nil {
		t.Fatalf("DeleteVlan(%d) error = %v", newVlan, err)
	}
	vlans, err = reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() after DeleteVlan error = %v", err)
	}
	if vlanIDPresent(vlans, newVlan) {
		t.Errorf("GetVLANs() after DeleteVlan(%d) still contains it: %+v", newVlan, vlans)
	}
}

func vlanIDPresent(vlans []model.VLANInfo, vid int) bool {
	for _, v := range vlans {
		if v.VlanID == vid {
			return true
		}
	}
	return false
}

// -- Wired dialect (GS110EMX) end-to-end (Task 9) ------------------------
//
// Mirrors the Python pinned reference's test_gs110emx_http_reader_end_to_end
// (tests/virtual/test_virtual_http_face.py) and
// test_http_and_nsdp_reads_agree[gs110emx]
// (tests/test_cross_backend_equivalence.py): a real webui.HTTPClient/Reader
// against this GAMBIT-scheme mock must read back exactly the seeded State,
// proving the byte-faithful renderGS110EMXPage dispatch round-trips through
// the Task-2 parsers (ParseGS110EMXPortStatus/ParseInterfaceStats/
// ParseGS110EMXPVIDs/ParseGS110EMXVlanIDs/ParseSysInfo).

func gs110emxTestReader(t *testing.T, st *State) (*webui.Reader, string) {
	t.Helper()
	m, err := model.GetModel("gs110emx")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, st, spec, "password")
	client := webui.NewHTTPClient(addr, "password", spec)
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	return reader, addr
}

func TestHTTPFaceGS110EMXReadPortsMatchesSeed(t *testing.T) {
	st := SeedGS110EMX()
	reader, _ := gs110emxTestReader(t, st)
	ports, err := reader.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != len(st.Ports) {
		t.Fatalf("GetPorts() returned %d ports, want %d (seeded)", len(ports), len(st.Ports))
	}
	for _, p := range ports {
		want, ok := st.Ports[p.Port]
		if !ok {
			t.Fatalf("GetPorts() returned unknown port %d", p.Port)
		}
		if p.LinkUp != want.Link {
			t.Errorf("port %d LinkUp = %v, want %v", p.Port, p.LinkUp, want.Link)
		}
		if p.AdminEnabled != want.Admin {
			t.Errorf("port %d AdminEnabled = %v, want %v", p.Port, p.AdminEnabled, want.Admin)
		}
		if want.Link {
			if p.SpeedMbps == nil || *p.SpeedMbps != want.Speed {
				t.Errorf("port %d SpeedMbps = %v, want %d", p.Port, p.SpeedMbps, want.Speed)
			}
		}
		wantName := want.Name
		if want.Description != nil {
			wantName = *want.Description
		}
		if p.Name == nil || *p.Name != wantName {
			t.Errorf("port %d Name = %v, want %q", p.Port, p.Name, wantName)
		}
	}
}

// TestHTTPFaceGS110EMXGetStats exercises RenderGS110EMXInterfaceStats's
// deliberately malformed never-closed <tr class="portID"> rows read back
// through webui.ParseInterfaceStats.
func TestHTTPFaceGS110EMXGetStats(t *testing.T) {
	st := SeedGS110EMX()
	reader, _ := gs110emxTestReader(t, st)
	stats, err := reader.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	if len(stats) != len(st.Ports) {
		t.Fatalf("GetStats() returned %d rows, want %d (seeded)", len(stats), len(st.Ports))
	}
	for _, s := range stats {
		want := st.Ports[s.Port]
		if s.RxBytes == nil || *s.RxBytes != u64OrZero(want.RxOctets) {
			t.Errorf("port %d RxBytes = %v, want %d", s.Port, s.RxBytes, u64OrZero(want.RxOctets))
		}
		if s.TxBytes == nil || *s.TxBytes != u64OrZero(want.TxOctets) {
			t.Errorf("port %d TxBytes = %v, want %d", s.Port, s.TxBytes, u64OrZero(want.TxOctets))
		}
		if s.RxErrors == nil || *s.RxErrors != u64OrZero(want.RxErrors) {
			t.Errorf("port %d RxErrors = %v, want %d", s.Port, s.RxErrors, u64OrZero(want.RxErrors))
		}
	}
}

func TestHTTPFaceGS110EMXGetPVIDs(t *testing.T) {
	st := SeedGS110EMX()
	reader, _ := gs110emxTestReader(t, st)
	pvids, err := reader.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	got := make(map[int]int, len(pvids))
	for _, p := range pvids {
		got[p.Port] = p.Vlan
	}
	for port, want := range st.Pvids {
		if got[port] != want {
			t.Errorf("port %d PVID = %d, want %d (seeded)", port, got[port], want)
		}
	}
}

// TestHTTPFaceGS110EMXGetVLANs reads back the seeded VLAN table via the
// GAMBIT-scheme per-VLAN vlanMembership.html POST loop, exercising
// RenderGS110EMXCf8021q + RenderGS110EMXVlanMembership together.
func TestHTTPFaceGS110EMXGetVLANs(t *testing.T) {
	st := SeedGS110EMX()
	reader, _ := gs110emxTestReader(t, st)
	vlans, err := reader.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	if len(vlans) != len(st.Vlans) {
		t.Fatalf("GetVLANs() returned %d VLANs, want %d (seeded)", len(vlans), len(st.Vlans))
	}
	for _, v := range vlans {
		wantSim, ok := st.Vlans[v.VlanID]
		if !ok {
			t.Fatalf("GetVLANs() returned unknown VLAN %d", v.VlanID)
		}
		if len(v.MemberPorts) != len(wantSim.Member) {
			t.Errorf("VLAN %d MemberPorts = %v, want %d ports (seeded member set)", v.VlanID, v.MemberPorts, len(wantSim.Member))
		}
		for _, p := range v.UntaggedPorts {
			if !wantSim.Untagged[p] {
				t.Errorf("VLAN %d reports port %d untagged, seed does not", v.VlanID, p)
			}
		}
		for _, p := range v.TaggedPorts {
			if !wantSim.Member[p] || wantSim.Untagged[p] {
				t.Errorf("VLAN %d reports port %d tagged, seed disagrees", v.VlanID, p)
			}
		}
	}
}

// TestHTTPFaceGS110EMXGetMgmtIP exercises RenderGS110EMXSysinfo's
// mgmt-IP/DHCP-mode fields (webui.ParseSysInfo's data-select-value
// convention), mirroring the Python cross-backend equivalence test's
// mgmt-IP assertion for gs110emx.
func TestHTTPFaceGS110EMXGetMgmtIP(t *testing.T) {
	st := SeedGS110EMX()
	reader, _ := gs110emxTestReader(t, st)
	mgmt, err := reader.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != st.Mgmt.Address {
		t.Errorf("GetMgmtIP().Address = %v, want %q", mgmt.Address, st.Mgmt.Address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != st.Mgmt.Netmask {
		t.Errorf("GetMgmtIP().Netmask = %v, want %q", mgmt.Netmask, st.Mgmt.Netmask)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != st.Mgmt.Gateway {
		t.Errorf("GetMgmtIP().Gateway = %v, want %q", mgmt.Gateway, st.Mgmt.Gateway)
	}
	if mgmt.Mode != model.IPModeStatic {
		t.Errorf("GetMgmtIP().Mode = %v, want IPModeStatic (seed is static)", mgmt.Mode)
	}
	wantMac := strings.ToUpper(formatGS110EMXMac(st.NsdpMac))
	if mgmt.BaseMac == nil || *mgmt.BaseMac != wantMac {
		t.Errorf("GetMgmtIP().BaseMac = %v, want %q", mgmt.BaseMac, wantMac)
	}
}

// TestHTTPFaceGS110EMXWriterSetPortEnabled drives webui.Writer.SetPortEnabled
// end-to-end against the GS110EMX's OWN port-admin mechanism (Physical Mode
// on port_settings.html, not the FASTPATH XUI grid) -- the one write op
// web_gs110emx.py actually implements (ApplyGS110EMXPortSettings), mirroring
// Python's http_write.py._set_gs110emx_port_enabled live-verified behavior.
func TestHTTPFaceGS110EMXWriterSetPortEnabled(t *testing.T) {
	st := SeedGS110EMX()
	m, err := model.GetModel("gs110emx")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	if !st.Ports[3].Admin {
		t.Fatalf("test fixture assumption broken: port 3 admin must start enabled")
	}
	addr, _ := startHTTPFace(t, st, spec, "password")
	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	if err := writer.SetPortEnabled(context.Background(), 3, false, false); err != nil {
		t.Fatalf("SetPortEnabled(port=3, false) error = %v", err)
	}

	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	ports, err := reader.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	for _, p := range ports {
		if p.Port == 3 && p.AdminEnabled {
			t.Errorf("port 3 AdminEnabled after SetPortEnabled(false) = true, want false")
		}
	}
}

// TestHTTPFaceGS110EMXWriterSetPVIDHasNoCSRFHash pins a documented,
// preserved-from-Python behavior (not a Go-side bug): webui.Writer.SetPVID
// (mirroring Python HttpWriter.set_pvid verbatim, see writer.go's package
// doc comment) always scrapes a `name="hash"` CSRF token off the PVID page
// before POSTing, via the SAME requireCSRF helper every Plus-CGI write op
// uses -- but GS110EMX's vlan_pvidsetting.html carries no such field at all
// (its session identity is the Gambit query token, not a per-page hash), so
// this write genuinely cannot succeed against gs110emx over HTTP. No Python
// test exercises HttpWriter.set_pvid against gs110emx either (dossier §8's
// test inventory has no such case) -- this is a genuine capability gap of
// the pinned reference, not something this port should paper over. (Compare
// TestHTTPFaceGS110EMXWriterSetPortEnabled, the ONE write op gs110emx's own
// web_gs110emx.py genuinely implements.)
//
// Target vlan is 90 (seeded on gs110emx, see SeedGS110EMX), NOT an
// arbitrary unused id: SetPVID now refuses up front if the target VLAN
// does not exist (GAP-1 fix, parity with Python commit 98fb935), via
// requireVlanExists's GS110EMX-dialect-aware dispatch (writer.go), so this
// test's target must be real or it would fail at that earlier check
// instead of reaching the CSRF-hash bug this test exists to pin.
func TestHTTPFaceGS110EMXWriterSetPVIDHasNoCSRFHash(t *testing.T) {
	st := SeedGS110EMX()
	m, err := model.GetModel("gs110emx")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	wantUnchanged := st.Pvids[3]
	const targetVlan = 90
	addr, _ := startHTTPFace(t, st, spec, "password")
	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	err = writer.SetPVID(context.Background(), 3, targetVlan, false)
	if err == nil {
		t.Fatalf("SetPVID() against gs110emx error = nil, want an error (no CSRF hash field on this model's PVID page, see doc comment)")
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("SetPVID() against gs110emx error = %v, want errors.Is(..., model.ErrHTTP)", err)
	}
	if st.Pvids[3] != wantUnchanged {
		t.Errorf("state.Pvids[3] after a refused SetPVID = %d, want unchanged %d", st.Pvids[3], wantUnchanged)
	}
}

// TestHTTPFaceGS728TPPWriterSetPVIDRefusesNonexistentVlan exercises
// webui.Writer.requireVlanExists' isGoAheadDialect branch (writer.go) end-
// to-end -- GAP-1 fix parity with Python commit 98fb935 -- which no other
// test drove: SetPVID against a GS728TPP must refuse a PVID pointing at a
// VLAN the switch does not have, BEFORE reaching the CSRF/PostForm write
// this model's SetPVID otherwise shares with every other dialect (see
// writer.go's package doc comment on that shared-but-imperfect verify
// path), so this exercises the precondition without depending on that
// separate, already-documented gap.
func TestHTTPFaceGS728TPPWriterSetPVIDRefusesNonexistentVlan(t *testing.T) {
	st := SeedGS728TPP()
	m, err := model.GetModel("gs728tpp")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	wantUnchanged := st.Pvids[2]
	const nonexistentVlan = 4007 // not among gs728tpp's seeded VLANs (1,2,3,5,6,7,10,20,31,41,90,99)
	addr, _ := startHTTPFace(t, st, spec, "password")
	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}

	err = writer.SetPVID(context.Background(), 2, nonexistentVlan, false)
	if err == nil {
		t.Fatal("SetPVID() against gs728tpp with a nonexistent VLAN error = nil, want a refusal")
	}
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("SetPVID() error = %v, want errors.Is(..., model.ErrHTTPUnexpectedPage)", err)
	}
	if !strings.Contains(err.Error(), "4007") {
		t.Errorf("SetPVID() error = %q, want it to mention the nonexistent VLAN 4007", err.Error())
	}
	if st.Pvids[2] != wantUnchanged {
		t.Errorf("state.Pvids[2] after a refused SetPVID = %d, want unchanged %d", st.Pvids[2], wantUnchanged)
	}
}

// TestHTTPFaceGSM7252PSWriterSetPVIDRefusesNonexistentVlan exercises
// webui.Writer.requireVlanExists' isFastpathDialect branch (writer.go)
// end-to-end -- GAP-1 fix parity with Python commit 98fb935 -- which no
// other test drove: SetPVID against a managed FASTPATH model must refuse a
// PVID pointing at a VLAN the switch does not have, before any write.
func TestHTTPFaceGSM7252PSWriterSetPVIDRefusesNonexistentVlan(t *testing.T) {
	st := SeedGSM7252PS()
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	wantUnchanged := st.Pvids[1]
	const nonexistentVlan = 4007 // not among gsm7252ps's seeded VLANs
	addr, _ := startHTTPFace(t, st, spec, "password")
	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}

	err = writer.SetPVID(context.Background(), 1, nonexistentVlan, false)
	if err == nil {
		t.Fatal("SetPVID() against gsm7252ps with a nonexistent VLAN error = nil, want a refusal")
	}
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("SetPVID() error = %v, want errors.Is(..., model.ErrHTTPUnexpectedPage)", err)
	}
	if !strings.Contains(err.Error(), "4007") {
		t.Errorf("SetPVID() error = %q, want it to mention the nonexistent VLAN 4007", err.Error())
	}
	if st.Pvids[1] != wantUnchanged {
		t.Errorf("state.Pvids[1] after a refused SetPVID = %d, want unchanged %d", st.Pvids[1], wantUnchanged)
	}
}

// -- Wired dialect (GS105PE) end-to-end (Task 9) --------------------------
//
// Mirrors the Python pinned reference's test_http_and_nsdp_reads_agree
// parametrization over gs105pe (tests/test_cross_backend_equivalence.py) --
// its docstring notes gs105pe is included "because its HTTP face once
// silently reported every port down while the seed had two ports up",
// exactly the renderGS105PEPage dispatch this task wires (dossier §3.3 step
// 4 / faces/http.py._render_gs105pe_page).

func gs105peTestReader(t *testing.T, st *State) *webui.Reader {
	t.Helper()
	m, err := model.GetModel("gs105pe")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, st, spec, "password")
	client := webui.NewHTTPClient(addr, "password", spec)
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	return reader
}

func TestHTTPFaceGS105PEReadPortsMatchesSeed(t *testing.T) {
	st := SeedGS105PE()
	if st.Ports[3].Link == st.Ports[1].Link {
		t.Fatalf("test fixture assumption broken: seed must have a mix of up/down ports")
	}
	reader := gs105peTestReader(t, st)
	ports, err := reader.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != len(st.Ports) {
		t.Fatalf("GetPorts() returned %d ports, want %d (seeded)", len(ports), len(st.Ports))
	}
	for _, p := range ports {
		want, ok := st.Ports[p.Port]
		if !ok {
			t.Fatalf("GetPorts() returned unknown port %d", p.Port)
		}
		if p.LinkUp != want.Link {
			t.Errorf("port %d LinkUp = %v, want %v (this is the exact regression web_gs105pe.go's renderGS105PEPage dispatch fixes)", p.Port, p.LinkUp, want.Link)
		}
		if want.Link {
			if p.SpeedMbps == nil || *p.SpeedMbps != want.Speed {
				t.Errorf("port %d SpeedMbps = %v, want %d", p.Port, p.SpeedMbps, want.Speed)
			}
		}
	}
}

// TestHTTPFaceGS105PEGetStats exercises RenderGS105PEPortStatistics's hidden
// (hi, lo) 32-bit counter-half quirk read back through
// webui.ParseGS105PEStats.
func TestHTTPFaceGS105PEGetStats(t *testing.T) {
	st := SeedGS105PE()
	reader := gs105peTestReader(t, st)
	stats, err := reader.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	if len(stats) != len(st.Ports) {
		t.Fatalf("GetStats() returned %d rows, want %d (seeded)", len(stats), len(st.Ports))
	}
	for _, s := range stats {
		want := st.Ports[s.Port]
		if s.RxBytes == nil || *s.RxBytes != u64OrZero(want.RxOctets) {
			t.Errorf("port %d RxBytes = %v, want %d", s.Port, s.RxBytes, u64OrZero(want.RxOctets))
		}
		if s.TxBytes == nil || *s.TxBytes != u64OrZero(want.TxOctets) {
			t.Errorf("port %d TxBytes = %v, want %d", s.Port, s.TxBytes, u64OrZero(want.TxOctets))
		}
		if s.RxErrors == nil || *s.RxErrors != u64OrZero(want.RxErrors) {
			t.Errorf("port %d RxErrors = %v, want %d", s.Port, s.RxErrors, u64OrZero(want.RxErrors))
		}
	}
}

func TestHTTPFaceGS105PEGetPVIDs(t *testing.T) {
	st := SeedGS105PE()
	reader := gs105peTestReader(t, st)
	pvids, err := reader.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	got := make(map[int]int, len(pvids))
	for _, p := range pvids {
		got[p.Port] = p.Vlan
	}
	for port, want := range st.Pvids {
		if got[port] != want {
			t.Errorf("port %d PVID = %d, want %d (seeded)", port, got[port], want)
		}
	}
}

// TestHTTPFaceGS105PEGetVLANs reads back the seeded VLAN table via the
// Plus-CGI 8021qMembe.cgi per-VLAN POST loop (the gs105pe-specific
// CSRF-hash/selected-VLAN quirks, dossier §1.4), exercising
// RenderGS105PEVlanConfig + RenderGS105PEVlanMembership together.
func TestHTTPFaceGS105PEGetVLANs(t *testing.T) {
	st := SeedGS105PE()
	reader := gs105peTestReader(t, st)
	vlans, err := reader.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	if len(vlans) != len(st.Vlans) {
		t.Fatalf("GetVLANs() returned %d VLANs, want %d (seeded)", len(vlans), len(st.Vlans))
	}
	for _, v := range vlans {
		wantSim, ok := st.Vlans[v.VlanID]
		if !ok {
			t.Fatalf("GetVLANs() returned unknown VLAN %d", v.VlanID)
		}
		if len(v.MemberPorts) != len(wantSim.Member) {
			t.Errorf("VLAN %d MemberPorts = %v, want %d ports (seeded member set)", v.VlanID, v.MemberPorts, len(wantSim.Member))
		}
		for _, p := range v.UntaggedPorts {
			if !wantSim.Untagged[p] {
				t.Errorf("VLAN %d reports port %d untagged, seed does not", v.VlanID, p)
			}
		}
	}
}

// TestHTTPFaceGS105PEGetMgmtIP exercises RenderGS105PESwitchInfo read back
// through webui.ParseGS105PESysInfo (the lowercase ip_address/subnet_mask/
// gateway_address field-name convention, distinct from GS110EMX's uppercase
// IP_ADDRESS/etc).
func TestHTTPFaceGS105PEGetMgmtIP(t *testing.T) {
	st := SeedGS105PE()
	reader := gs105peTestReader(t, st)
	mgmt, err := reader.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != st.Mgmt.Address {
		t.Errorf("GetMgmtIP().Address = %v, want %q", mgmt.Address, st.Mgmt.Address)
	}
	if mgmt.Netmask == nil || *mgmt.Netmask != st.Mgmt.Netmask {
		t.Errorf("GetMgmtIP().Netmask = %v, want %q", mgmt.Netmask, st.Mgmt.Netmask)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != st.Mgmt.Gateway {
		t.Errorf("GetMgmtIP().Gateway = %v, want %q", mgmt.Gateway, st.Mgmt.Gateway)
	}
	if mgmt.Mode != model.IPModeDHCP {
		t.Errorf("GetMgmtIP().Mode = %v, want IPModeDHCP (seed is dhcp)", mgmt.Mode)
	}
	wantMac := strings.ToUpper(formatGS105PEMac(st.NsdpMac))
	if mgmt.BaseMac == nil || *mgmt.BaseMac != wantMac {
		t.Errorf("GetMgmtIP().BaseMac = %v, want %q", mgmt.BaseMac, wantMac)
	}
}

// TestHTTPFaceGS105PEWriterSetPVIDNeverAppliesOnThisMock pins a documented,
// preserved-from-Python behavior (not a Go-side bug): web_gs105pe.py has NO
// apply_* functions, and Python's own do_POST elif-chain priority means a
// POST to gs105pe's pvid_path is intercepted by _render_gs105pe_page (a
// read-only re-render of unmutated state) BEFORE it could ever reach
// web.py's generic apply_form fallback -- so on this mock, gs105pe HTTP
// writes never take effect. No Python test exercises HttpWriter.set_pvid
// against gs105pe either (dossier §8's test inventory has no such case),
// consistent with this being a genuine, if surprising, capability gap of
// the pinned reference rather than something this port should paper over.
//
// Target vlan is 41 (seeded on gs105pe, see SeedGS105PE), NOT an arbitrary
// unused id: SetPVID now refuses up front if the target VLAN does not
// exist (GAP-1 fix, parity with Python commit 98fb935), so this test's
// target must be real or it would fail at that earlier precondition
// instead of reaching the write-is-a-no-op behavior this test exists to
// pin.
func TestHTTPFaceGS105PEWriterSetPVIDNeverAppliesOnThisMock(t *testing.T) {
	st := SeedGS105PE()
	m, err := model.GetModel("gs105pe")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	wantUnchanged := st.Pvids[3]
	const targetVlan = 41
	addr, _ := startHTTPFace(t, st, spec, "password")
	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	err = writer.SetPVID(context.Background(), 3, targetVlan, false)
	if err == nil {
		t.Fatalf("SetPVID() against gs105pe error = nil, want a WriteVerificationError (this mock's known write-is-a-no-op gap, see doc comment)")
	}
	if st.Pvids[3] != wantUnchanged {
		t.Errorf("state.Pvids[3] after a refused SetPVID = %d, want unchanged %d", st.Pvids[3], wantUnchanged)
	}
}

// -- Lifecycle edge cases -------------------------------------------------

// TestHTTPFaceStartTwiceErrors covers Start's "already started" guard.
func TestHTTPFaceStartTwiceErrors(t *testing.T) {
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	face := NewHTTPFace(NewState("gs305ep"), spec, "password", "127.0.0.1")
	if _, err := face.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	t.Cleanup(func() { _ = face.Stop() })
	if _, err := face.Start(); err == nil {
		t.Errorf("second Start() (without an intervening Stop) error = nil, want an error")
	}
}

// TestHTTPFaceUnsupportedMethodIsNotImplemented covers serveHTTP's default
// branch: a verb neither webui.HTTPClient nor real hardware ever sends.
func TestHTTPFaceUnsupportedMethodIsNotImplemented(t *testing.T) {
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, NewState("gs305ep"), spec, "password")

	req, err := http.NewRequest(http.MethodPut, "http://"+addr+spec.LoginPath, nil) //nolint:noctx // test-only.
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("PUT status = %d, want 501", resp.StatusCode)
	}
}

// -- GoAhead session-check / unauthenticated-redirect (dossier §3.2 step 5) -

func TestHTTPFaceGoAheadUnauthenticatedReadRedirects(t *testing.T) {
	m, err := model.GetModel("gs728tpp")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, NewState("gs728tpp"), spec, "password")

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get("http://" + addr + "/cs0000face/wcd?{file=x}") //nolint:noctx,bodyclose // test-only; body closed below.
	if err != nil {
		t.Fatalf("GET wcd without a session cookie: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("GET wcd without a session cookie status = %d, want 302", resp.StatusCode)
	}
}

func TestHTTPFaceGoAheadUnauthenticatedWriteRedirects(t *testing.T) {
	m, err := model.GetModel("gs728tpp")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, NewState("gs728tpp"), spec, "password")

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Post("http://"+addr+"/cs0000face/wcd", "application/xml", strings.NewReader("<x/>")) //nolint:noctx,bodyclose // test-only; body closed below.
	if err != nil {
		t.Fatalf("POST wcd without a session cookie: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("POST wcd without a session cookie status = %d, want 302", resp.StatusCode)
	}
}

// TestHTTPFaceGoAheadFaceServesEveryReadOpFromState replaces the former
// TestHTTPFaceGoAheadAuthenticatedReadOfUnimplementedWcdPage404s tripwire:
// web_gs728tpp.go's RenderGS728TPPWcd is now wired into goaheadGet, so the
// mock renders the real wcd XML and the SAME webui.ParseGoAhead* parsers
// that read the hardware captures read it back -- ports/pvids/vlans/poe/
// macs/lldp/sensors/mgmt-IP, all from one seeded State. Mirrors Python
// test_goahead_face_serves_every_read_op_from_state.
func TestHTTPFaceGoAheadFaceServesEveryReadOpFromState(t *testing.T) {
	m, err := model.GetModel("gs728tpp")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := SeedGS728TPP()
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}

	// physicalCount counts only the set's members at or below the model's
	// physical port count: the seed also carries ifIndex-keyed entries for
	// the eight LAG pseudo-interfaces (1000-1007, GAP-2 fix parity with
	// Python commit 3f25b0b), which the real wcd pages never list -- see
	// physicalGS728TPPPorts's own doc comment.
	physicalCount := func(set map[int]bool) int {
		n := 0
		for p := range set {
			if p <= m.PortCount {
				n++
			}
		}
		return n
	}

	ports, err := reader.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != m.PortCount {
		t.Fatalf("GetPorts() returned %d ports, want %d (physical only -- the seed's 8 LAG pseudo-interfaces are never listed by the real wcd pages)", len(ports), m.PortCount)
	}
	for _, p := range ports {
		sim, ok := st.Ports[p.Port]
		if !ok {
			t.Fatalf("GetPorts() returned unknown port %d", p.Port)
		}
		if p.AdminEnabled != sim.Admin || p.LinkUp != sim.Link {
			t.Errorf("port %d = %+v, want admin=%v link=%v", p.Port, p, sim.Admin, sim.Link)
		}
	}

	pvids, err := reader.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	if len(pvids) != m.PortCount {
		t.Errorf("GetPVIDs() returned %d rows, want %d (physical only)", len(pvids), m.PortCount)
	}

	vlans, err := reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	if len(vlans) != len(st.Vlans) {
		t.Fatalf("GetVLANs() returned %d VLANs, want %d (seeded)", len(vlans), len(st.Vlans))
	}
	for _, v := range vlans {
		vsim := st.Vlans[v.VlanID]
		wantMembers := physicalCount(vsim.Member)
		if len(v.MemberPorts) != wantMembers {
			t.Errorf("VLAN %d MemberPorts = %v, want len %d (seeded, physical members only)", v.VlanID, v.MemberPorts, wantMembers)
		}
	}

	poe, err := reader.GetPoE(ctx)
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	if len(poe) != len(st.Poe) {
		t.Errorf("GetPoE() returned %d ports, want %d (seeded)", len(poe), len(st.Poe))
	}

	macs, err := reader.GetMACs(ctx)
	if err != nil {
		t.Fatalf("GetMACs() error = %v", err)
	}
	if len(macs) != len(st.Macs) {
		t.Errorf("GetMACs() returned %d entries, want %d (seeded)", len(macs), len(st.Macs))
	}

	lldp, err := reader.GetLLDP(ctx)
	if err != nil {
		t.Fatalf("GetLLDP() error = %v", err)
	}
	if len(lldp) != len(st.Lldp) {
		t.Errorf("GetLLDP() returned %d neighbours, want %d (seeded)", len(lldp), len(st.Lldp))
	}

	sensors, err := reader.GetSensors(ctx)
	if err != nil {
		t.Fatalf("GetSensors() error = %v", err)
	}
	byNameKind := map[[2]string]float64{}
	for _, s := range sensors {
		byNameKind[[2]string{s.Kind, s.Name}] = s.Value
	}
	if v, ok := byNameKind[[2]string{"fan", "Fan1"}]; !ok || v != 1.0 {
		t.Errorf("sensors[fan/Fan1] = %v (ok=%v), want 1.0", v, ok)
	}
	if _, ok := byNameKind[[2]string{"fan", "Fan3"}]; ok {
		t.Errorf("sensors carries fan/Fan3, want absent (unpopulated slot skipped)")
	}
	if v, ok := byNameKind[[2]string{"power", "Main PS"}]; !ok || v != 1.0 {
		t.Errorf("sensors[power/Main PS] = %v (ok=%v), want 1.0", v, ok)
	}

	mgmt, err := reader.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != st.Mgmt.Address {
		t.Errorf("mgmt.Address = %v, want %s", mgmt.Address, st.Mgmt.Address)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != st.Mgmt.Gateway {
		t.Errorf("mgmt.Gateway = %v, want %s", mgmt.Gateway, st.Mgmt.Gateway)
	}
	if mgmt.Mode != model.IPModeUnknown {
		t.Errorf("mgmt.Mode = %v, want Unknown (this page carries no DHCP/static indicator)", mgmt.Mode)
	}
}

// TestHTTPFaceGoAheadGetStatsUnsupported: per-port statistics are behind an
// unresolvable JS nav indirection on this UI (spec.StatsPath == ""), so
// GetStats must raise an UnsupportedCapabilityError, never fabricate
// counters. Mirrors Python test_goahead_get_stats_unsupported.
func TestHTTPFaceGoAheadGetStatsUnsupported(t *testing.T) {
	m, err := model.GetModel("gs728tpp")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, SeedGS728TPP(), spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	if _, err := reader.GetStats(ctx); !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("GetStats() error = %v, want errors.Is(..., model.ErrUnsupportedCapability)", err)
	}
}

// -- gsm7252ps: the XE FASTPATH face ------------------------------------

// TestHTTPFaceXEFaceServesEveryReadOpFromState mirrors Python
// test_xe_face_serves_every_read_op_from_state: the mock renders the real
// XE cell format, so the SAME parsers that read the hardware captures read
// it back -- ports/stats/PVIDs/VLANs/MACs/PoE/LLDP/sensors/mgmt-IP, all
// from one seeded State.
func TestHTTPFaceXEFaceServesEveryReadOpFromState(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := SeedGSM7252PS()
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}

	ports, err := reader.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	// The web UI lists ONLY physical ports: the state's CPU/lag interfaces
	// (ifIndex 417/418) must not appear.
	if len(ports) != 52 {
		t.Errorf("GetPorts() returned %d ports, want 52 (physical only)", len(ports))
	}
	for _, p := range ports {
		if p.Port > 52 {
			t.Errorf("GetPorts() returned non-physical port %d", p.Port)
		}
	}

	pvids, err := reader.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	wantPvids := 0
	for p := range st.Pvids {
		if p <= 52 {
			wantPvids++
		}
	}
	if len(pvids) != wantPvids {
		t.Errorf("GetPVIDs() returned %d rows, want %d (physical only)", len(pvids), wantPvids)
	}

	vlans, err := reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	if len(vlans) != len(st.Vlans) {
		t.Fatalf("GetVLANs() returned %d VLANs, want %d (seeded)", len(vlans), len(st.Vlans))
	}
	stats, err := reader.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	if len(stats) != 52 {
		t.Errorf("GetStats() returned %d rows, want 52 (physical only)", len(stats))
	}

	poe, err := reader.GetPoE(ctx)
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	if len(poe) != len(st.Poe) {
		t.Errorf("GetPoE() returned %d ports, want %d (seeded)", len(poe), len(st.Poe))
	}

	macs, err := reader.GetMACs(ctx)
	if err != nil {
		t.Fatalf("GetMACs() error = %v", err)
	}
	if len(macs) != len(st.Macs) {
		t.Errorf("GetMACs() returned %d entries, want %d (seeded)", len(macs), len(st.Macs))
	}

	lldp, err := reader.GetLLDP(ctx)
	if err != nil {
		t.Fatalf("GetLLDP() error = %v", err)
	}
	if len(lldp) != len(st.Lldp) {
		t.Errorf("GetLLDP() returned %d neighbours, want %d (seeded)", len(lldp), len(st.Lldp))
	}

	mgmt, err := reader.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != st.Mgmt.Address {
		t.Errorf("mgmt.Address = %v, want %s", mgmt.Address, st.Mgmt.Address)
	}
	if mgmt.Gateway == nil || *mgmt.Gateway != st.Mgmt.Gateway {
		t.Errorf("mgmt.Gateway = %v, want %s", mgmt.Gateway, st.Mgmt.Gateway)
	}

	// The HTTP sysInfo sensor set is the real web-UI one (temperatures +
	// fan/PSU health), DIFFERENT from this device's SNMP set.
	sensors, err := reader.GetSensors(ctx)
	if err != nil {
		t.Fatalf("GetSensors() error = %v", err)
	}
	byKindName := map[[2]string]float64{}
	for _, s := range sensors {
		byKindName[[2]string{s.Kind, s.Name}] = s.Value
	}
	if v, ok := byKindName[[2]string{"temperature", "System"}]; !ok || v != 29.0 {
		t.Errorf("sensors[temperature/System] = %v (ok=%v), want 29.0", v, ok)
	}
	if _, ok := byKindName[[2]string{"temperature", "MAC"}]; ok {
		t.Errorf("sensors carries temperature/MAC, want absent (N/A reading skipped)")
	}
	if v, ok := byKindName[[2]string{"fan", "Fan1/PWR"}]; !ok || v != 1.0 {
		t.Errorf("sensors[fan/Fan1/PWR] = %v (ok=%v), want 1.0", v, ok)
	}
}

// TestHTTPFaceXEFace404sAPathTheSpecDoesNotServe: this model's spec has no
// reboot/logout/PoE-config page, and the face must 404 rather than
// fabricate a 200 for one. Mirrors Python
// test_xe_face_404s_a_path_the_spec_does_not_serve.
func TestHTTPFaceXEFace404sAPathTheSpecDoesNotServe(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, SeedGSM7252PS(), spec, "password")
	resp, err := http.Get("http://" + addr + "/device_reboot.cgi") //nolint:noctx,gosec // test-only.
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /device_reboot.cgi status = %d, want 404", resp.StatusCode)
	}
}

// TestHTTPFaceXEWriterSetPortEnabledRoundTrip drives
// webui.Writer.SetPortEnabled end-to-end against the XE FASTPATH grid
// (GET-scrape-row, POST, re-GET-to-verify).
func TestHTTPFaceXEWriterSetPortEnabledRoundTrip(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := SeedGSM7252PS()
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	ctx := context.Background()
	target := !st.Ports[1].Admin
	if err := writer.SetPortEnabled(ctx, 1, target, false); err != nil {
		t.Fatalf("SetPortEnabled(port=1, %v) error = %v", target, err)
	}
	if st.Ports[1].Admin != target {
		t.Errorf("state.Ports[1].Admin = %v after SetPortEnabled(%v), want %v", st.Ports[1].Admin, target, target)
	}
}

// TestHTTPFaceXEWriterSetPoERoundTrip drives webui.Writer.SetPoE end-to-end
// against the XE FASTPATH PoE grid.
func TestHTTPFaceXEWriterSetPoERoundTrip(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := SeedGSM7252PS()
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	ctx := context.Background()
	target := !st.Poe[1].Admin
	if err := writer.SetPoE(ctx, 1, target, false); err != nil {
		t.Fatalf("SetPoE(port=1, %v) error = %v", target, err)
	}
	if st.Poe[1].Admin != target {
		t.Errorf("state.Poe[1].Admin = %v after SetPoE(%v), want %v", st.Poe[1].Admin, target, target)
	}
}

// TestHTTPFaceXEWriterSetMgmtIPRoundTrip drives webui.Writer.SetMgmtIP
// end-to-end against the gsm7252ps ipConfiguration.html XUI form page
// (GET-scrape, POST, re-GET-to-verify), exercising
// RenderFastpathMgmtIP/ApplyFastpathMgmtIP.
func TestHTTPFaceXEWriterSetMgmtIPRoundTrip(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := SeedGSM7252PS()
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	ctx := context.Background()
	// force=true required: SetMgmtIP moves the address the session itself
	// is using -- see the writer's own doc comment.
	if err := writer.SetMgmtIP(ctx, "10.1.5.99", "255.255.255.0", "10.1.5.1", true); err != nil {
		t.Fatalf("SetMgmtIP() error = %v", err)
	}
	if st.Mgmt.Address != "10.1.5.99" || st.Mgmt.Netmask != "255.255.255.0" || st.Mgmt.Gateway != "10.1.5.1" {
		t.Errorf("state.Mgmt = %+v after SetMgmtIP, want 10.1.5.99/255.255.255.0 gw 10.1.5.1", st.Mgmt)
	}

	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	mgmt, err := reader.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.99" {
		t.Errorf("GetMgmtIP().Address = %v, want 10.1.5.99", mgmt.Address)
	}
}

// TestHTTPFaceXEWriterSetPoENoListUnitFieldIsRefused exercises the
// GSM7252PS's real, measured refusal: unlike its gsm7228ps/M4300 siblings,
// this firmware's PoE rows carry no per-row "Unit" key, so an apply POST
// that omits the page's own urlListUnit fields (v_1_1_1/v_1_3_1) is
// refused with one "Error! Failed to Set '<label>' with '<value>'" line
// per read-write column -- even though the row/checkbox were present.
// Drives the raw form directly (not webui.Writer, which always echoes the
// page's own Nav fields back) to reach ApplyXEPoEWith's unitRequired
// refusal path deliberately.
func TestHTTPFaceXEWriterSetPoENoListUnitFieldIsRefused(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := SeedGSM7252PS()
	addr, _ := startHTTPFace(t, st, spec, "password")

	form := url.Values{
		"submit_flag":    {"8"},
		"1.0.48.gecb234": {"on"},
		"1.0.48.v_1_2_2": {"Enable"},
	}
	resp, err := http.PostForm("http://"+addr+spec.PoEConfigPath, form) //nolint:noctx,gosec // test-only.
	if err != nil {
		t.Fatalf("POST %s: %v", spec.PoEConfigPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	errMsg, hasErr := webui.ParseFastpathErr(string(body))
	if !hasErr {
		t.Fatal("response has no err_flag=1, want the missing-list-unit refusal")
	}
	if !strings.Contains(errMsg, "Admin <br/> Mode") {
		t.Errorf("err_msg = %q, want it to name the Admin Mode column", errMsg)
	}
}

// -- gsm7228ps: the S3300-52X XE FASTPATH face --------------------------

// TestHTTPFaceS3300FaceServesGroundedReadsMatchingSNMPCapture mirrors
// Python test_s3300_face_serves_grounded_reads_matching_snmp_capture: full
// stack, no hardware -- cheetah login -> HttpReader reproduces the grounded
// reads, cross-checked against the real SNMP capture. GetSensors raises
// Unsupported (the S3300 sysInfo has no live fan/temp table -- SNMP only).
func TestHTTPFaceS3300FaceServesGroundedReadsMatchingSNMPCapture(t *testing.T) {
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := SeedGSM7228PS()
	capture := loadCaptureSnapshot(t, captureGSM7228PS)
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}

	ports, err := reader.GetPorts(ctx)
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	realPorts := make(map[int]model.PortStatus, len(capture.Ports))
	for _, p := range capture.Ports {
		realPorts[p.Port] = p
	}
	if len(ports) != 52 {
		t.Errorf("GetPorts() returned %d ports, want 52", len(ports))
	}
	for _, p := range ports {
		wantPort, ok := realPorts[p.Port]
		if !ok {
			continue
		}
		if p.LinkUp != wantPort.LinkUp {
			t.Errorf("port %d LinkUp = %v, want %v (capture)", p.Port, p.LinkUp, wantPort.LinkUp)
		}
	}

	stats, err := reader.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	if len(stats) != 52 {
		t.Errorf("GetStats() returned %d rows, want 52", len(stats))
	}

	pvids, err := reader.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	realPvids := make(map[int]int, len(capture.Pvids))
	for _, p := range capture.Pvids {
		realPvids[p.Port] = p.Vlan
	}
	for _, p := range pvids {
		if wantVlan, ok := realPvids[p.Port]; ok && wantVlan != p.Vlan {
			t.Errorf("port %d pvid = %d, want %d (capture)", p.Port, p.Vlan, wantVlan)
		}
	}

	vlans, err := reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	wantVids := map[int]bool{1: true, 5: true, 21: true, 121: true, 4089: true}
	gotVids := map[int]bool{}
	for _, v := range vlans {
		gotVids[v.VlanID] = true
	}
	for vid := range wantVids {
		if !gotVids[vid] {
			t.Errorf("GetVLANs() missing VLAN %d (capture)", vid)
		}
	}

	poe, err := reader.GetPoE(ctx)
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	if len(poe) != len(st.Poe) {
		t.Errorf("GetPoE() returned %d ports, want %d (seeded)", len(poe), len(st.Poe))
	}

	// basicAddressTable.html's shifted S3300 columns (RenderS3300MacTable)
	// and sysInfo.html's base-MAC-only page (RenderS3300Sysinfo). The
	// switch's own base MAC is learned on the CPU interface (ifName "c1"),
	// which webui.ParseS3300Macs deliberately skips as non-physical -- so
	// the expected count is the seed's MACs minus that one entry, not
	// len(st.Macs) itself.
	macs, err := reader.GetMACs(ctx)
	if err != nil {
		t.Fatalf("GetMACs() error = %v", err)
	}
	wantMacs := 0
	for _, entry := range st.Macs {
		port := entry.BridgePort
		if p, ok := st.BridgePorts[entry.BridgePort]; ok {
			port = p
		}
		if port >= 1 && port <= 52 {
			wantMacs++
		}
	}
	if len(macs) != wantMacs {
		t.Errorf("GetMACs() returned %d entries, want %d (seeded, excluding the CPU-interface entry)", len(macs), wantMacs)
	}
	mgmt, err := reader.GetMgmtIP(ctx)
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != st.Mgmt.Address {
		t.Errorf("mgmt.Address = %v, want %s", mgmt.Address, st.Mgmt.Address)
	}
	if mgmt.BaseMac == nil {
		t.Error("GetMgmtIP() BaseMac is nil, want the base MAC scraped from sysInfo.html")
	}

	if _, err := reader.GetSensors(ctx); !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("GetSensors() error = %v, want errors.Is(..., model.ErrUnsupportedCapability) (S3300 sysInfo has no live sensor table)", err)
	}
}

// TestHTTPFaceS3300Face404sAPathTheSpecDoesNotServe mirrors Python
// test_s3300_face_404s_a_path_the_spec_does_not_serve.
func TestHTTPFaceS3300Face404sAPathTheSpecDoesNotServe(t *testing.T) {
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, SeedGSM7228PS(), spec, "password")
	resp, err := http.Get("http://" + addr + "/device_reboot.cgi") //nolint:noctx,gosec // test-only.
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /device_reboot.cgi status = %d, want 404", resp.StatusCode)
	}
}

// -- m4300-24x / m4300-16x: the Cheetah /v1 face -------------------------

// TestHTTPFaceM4300ServesEveryReadOpFromState covers both M4300 SKUs'
// shared ports/stats/pvids/vlans/mac-table/sysinfo/lldp reads, plus the
// 16X-only PoE page (the 24X genuinely has none).
func TestHTTPFaceM4300ServesEveryReadOpFromState(t *testing.T) {
	tests := []struct {
		modelKey string
		seed     func() *State
		hasPoE   bool
	}{
		{"m4300-24x", SeedM4300_24X, false},
		{"m4300-16x", SeedM4300_16X, true},
	}
	for _, tt := range tests {
		t.Run(tt.modelKey, func(t *testing.T) {
			m, err := model.GetModel(tt.modelKey)
			if err != nil {
				t.Fatalf("model.GetModel: %v", err)
			}
			spec, err := webui.HTTPSpec(m)
			if err != nil {
				t.Fatalf("webui.HTTPSpec: %v", err)
			}
			st := tt.seed()
			addr, _ := startHTTPFace(t, st, spec, "password")

			// wantPhysical mirrors xePhysicalPorts/m4300PhysicalPorts: the
			// seeded ports at or below model.PortCount -- deliberately NOT
			// model.PortCount itself, which the registry sets to 28 on the
			// M4300-24X while the real switch (and this seed) has only 24.
			wantPhysical := 0
			for p := range st.Ports {
				if p <= m.PortCount {
					wantPhysical++
				}
			}

			client := webui.NewHTTPClient(addr, "password", clientSpec(spec))
			ctx := context.Background()
			if err := client.Login(ctx); err != nil {
				t.Fatalf("Login() error = %v", err)
			}
			reader, err := webui.NewReader(client, m)
			if err != nil {
				t.Fatalf("webui.NewReader: %v", err)
			}

			ports, err := reader.GetPorts(ctx)
			if err != nil {
				t.Fatalf("GetPorts() error = %v", err)
			}
			if len(ports) != wantPhysical {
				t.Errorf("GetPorts() returned %d ports, want %d (seeded physical ports)", len(ports), wantPhysical)
			}

			stats, err := reader.GetStats(ctx)
			if err != nil {
				t.Fatalf("GetStats() error = %v", err)
			}
			if len(stats) != wantPhysical {
				t.Errorf("GetStats() returned %d rows, want %d", len(stats), wantPhysical)
			}

			pvids, err := reader.GetPVIDs(ctx)
			if err != nil {
				t.Fatalf("GetPVIDs() error = %v", err)
			}
			if len(pvids) == 0 {
				t.Error("GetPVIDs() returned no rows")
			}

			vlans, err := reader.GetVLANs(ctx)
			if err != nil {
				t.Fatalf("GetVLANs() error = %v", err)
			}
			if len(vlans) != len(st.Vlans) {
				t.Errorf("GetVLANs() returned %d VLANs, want %d (seeded)", len(vlans), len(st.Vlans))
			}

			macs, err := reader.GetMACs(ctx)
			if err != nil {
				t.Fatalf("GetMACs() error = %v", err)
			}
			if len(macs) != len(st.Macs) {
				t.Errorf("GetMACs() returned %d entries, want %d (seeded)", len(macs), len(st.Macs))
			}

			lldp, err := reader.GetLLDP(ctx)
			if err != nil {
				t.Fatalf("GetLLDP() error = %v", err)
			}
			if len(lldp) != len(st.Lldp) {
				t.Errorf("GetLLDP() returned %d neighbours, want %d (seeded)", len(lldp), len(st.Lldp))
			}

			mgmt, err := reader.GetMgmtIP(ctx)
			if err != nil {
				t.Fatalf("GetMgmtIP() error = %v", err)
			}
			if mgmt.BaseMac == nil {
				t.Error("GetMgmtIP() BaseMac is nil")
			}

			if tt.hasPoE {
				poe, err := reader.GetPoE(ctx)
				if err != nil {
					t.Fatalf("GetPoE() error = %v", err)
				}
				if len(poe) != len(st.Poe) {
					t.Errorf("GetPoE() returned %d ports, want %d (seeded)", len(poe), len(st.Poe))
				}
			}
		})
	}
}

// TestHTTPFaceM4300WriterSetPortEnabledRoundTrip drives
// webui.Writer.SetPortEnabled against the M4300 Cheetah /v1 grid.
func TestHTTPFaceM4300WriterSetPortEnabledRoundTrip(t *testing.T) {
	m, err := model.GetModel("m4300-24x")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := SeedM4300_24X()
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	ctx := context.Background()
	target := !st.Ports[1].Admin
	if err := writer.SetPortEnabled(ctx, 1, target, false); err != nil {
		t.Fatalf("SetPortEnabled(port=1, %v) error = %v", target, err)
	}
	if st.Ports[1].Admin != target {
		t.Errorf("state.Ports[1].Admin = %v after SetPortEnabled(%v), want %v", st.Ports[1].Admin, target, target)
	}
}

// TestHTTPFaceM4300WriterSetPoERoundTrip drives webui.Writer.SetPoE against
// the M4300-16X's own PoE page (watts-formatted power column, gecb_1_2
// checkbox, no page-level Unit field).
func TestHTTPFaceM4300WriterSetPoERoundTrip(t *testing.T) {
	m, err := model.GetModel("m4300-16x")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := SeedM4300_16X()
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", clientSpec(spec))
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	ctx := context.Background()
	port := sortedIntKeys(st.Poe)[0]
	target := !st.Poe[port].Admin
	if err := writer.SetPoE(ctx, port, target, false); err != nil {
		t.Fatalf("SetPoE(port=%d, %v) error = %v", port, target, err)
	}
	if st.Poe[port].Admin != target {
		t.Errorf("state.Poe[%d].Admin = %v after SetPoE(%v), want %v", port, st.Poe[port].Admin, target, target)
	}
}

// -- the shared FASTPATH VLAN Membership page ----------------------------

// TestHTTPFaceFastpathVlanMembershipRoundTrip drives
// webui.Writer.SetVlanMembership end-to-end for every managed model that
// accepts an explicit membership apply (m4300-24x is excluded -- see
// TestHTTPFaceFastpathVlanMembershipM4300_24XRefusalIsSurfacedVerbatim
// below for its own, deliberately different, per-port refusal).
func TestHTTPFaceFastpathVlanMembershipRoundTrip(t *testing.T) {
	tests := []struct {
		modelKey string
		seed     func() *State
	}{
		{"gsm7252ps", SeedGSM7252PS},
		{"gsm7228ps", SeedGSM7228PS},
		{"m4300-16x", SeedM4300_16X},
	}
	for _, tt := range tests {
		t.Run(tt.modelKey, func(t *testing.T) {
			m, err := model.GetModel(tt.modelKey)
			if err != nil {
				t.Fatalf("model.GetModel: %v", err)
			}
			spec, err := webui.HTTPSpec(m)
			if err != nil {
				t.Fatalf("webui.HTTPSpec: %v", err)
			}
			st := tt.seed()
			addr, _ := startHTTPFace(t, st, spec, "password")

			client := webui.NewHTTPClient(addr, "password", clientSpec(spec))
			ctx := context.Background()
			writer, err := webui.NewWriter(client, m)
			if err != nil {
				t.Fatalf("webui.NewWriter: %v", err)
			}
			reader, err := webui.NewReader(client, m)
			if err != nil {
				t.Fatalf("webui.NewReader: %v", err)
			}

			vid := 0
			for v := range st.Vlans {
				if vid == 0 || v > vid {
					vid = v
				}
			}
			// The highest PHYSICAL port the switch actually has -- not
			// model.PortCount, which the registry sets to 28 on the
			// M4300-24X-style models while the device renders fewer cells.
			port := 0
			for p := range st.Ports {
				if p <= m.PortCount && p > port {
					port = p
				}
			}
			if st.VlanMembershipLockedPorts[port] {
				t.Fatalf("test port %d is locked on %s; pick a different port for this model", port, tt.modelKey)
			}

			for _, mode := range []model.VlanMode{model.VlanTagged, model.VlanUntagged, model.VlanExcluded} {
				if err := writer.SetVlanMembership(ctx, vid, port, mode, false); err != nil {
					t.Fatalf("SetVlanMembership(vlan=%d, port=%d, %v) error = %v", vid, port, mode, err)
				}
				page, err := reader.ReadFastpathMembership(ctx, vid)
				if err != nil {
					t.Fatalf("ReadFastpathMembership(%d) error = %v", vid, err)
				}
				if got := page.Configured[port]; got != mode {
					t.Errorf("after SetVlanMembership(%v): Configured[%d] = %v, want %v", mode, port, got, mode)
				}
				vsim := st.Vlans[vid]
				switch mode {
				case model.VlanExcluded:
					if vsim.Member[port] {
						t.Errorf("port %d still a Member after Excluded apply", port)
					}
				default:
					if !vsim.Member[port] {
						t.Errorf("port %d not a Member after %v apply", port, mode)
					}
					if (vsim.Untagged[port]) != (mode == model.VlanUntagged) {
						t.Errorf("port %d Untagged = %v after %v apply", port, vsim.Untagged[port], mode)
					}
				}
			}
		})
	}
}

// TestHTTPFaceFastpathVlanMembershipM4300_24XRefusalIsSurfacedVerbatim
// mirrors Python test_mock_m4300_24x_refusal_is_surfaced_verbatim: on the
// real 10.1.5.13 every port is switchport mode access/trunk, and the M4300
// image only accepts explicit VLAN membership on a general-mode port. The
// web UI answers HTTP 200 with err_flag=1 and a human err_msg; the library
// surfaces that verbatim as an HTTP error, and a refused apply must leave
// the device untouched.
func TestHTTPFaceFastpathVlanMembershipM4300_24XRefusalIsSurfacedVerbatim(t *testing.T) {
	m, err := model.GetModel("m4300-24x")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := SeedM4300_24X()
	if !st.VlanMembershipLockedPorts[8] {
		t.Fatal("precondition: port 8 should be locked on the seeded m4300-24x")
	}
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()
	writer, err := webui.NewWriter(client, m)
	if err != nil {
		t.Fatalf("webui.NewWriter: %v", err)
	}
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	vid := 0
	for v := range st.Vlans {
		if vid == 0 || v > vid {
			vid = v
		}
	}
	before, err := reader.ReadFastpathMembership(ctx, vid)
	if err != nil {
		t.Fatalf("ReadFastpathMembership(%d) error = %v", vid, err)
	}
	err = writer.SetVlanMembership(ctx, vid, 8, model.VlanUntagged, false)
	if err == nil {
		t.Fatal("SetVlanMembership on a locked port returned nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "Unable to set VLAN membership") {
		t.Errorf("SetVlanMembership error = %v, want it to contain the firmware's verbatim refusal text", err)
	}
	after, err := reader.ReadFastpathMembership(ctx, vid)
	if err != nil {
		t.Fatalf("ReadFastpathMembership(%d) error = %v", vid, err)
	}
	for p, mode := range before.Configured {
		if after.Configured[p] != mode {
			t.Errorf("a refused apply mutated port %d's configured mode: %v -> %v", p, mode, after.Configured[p])
		}
	}
}

// TestHTTPFaceFastpathVlanMembershipConfiguredOnlyDivergence mirrors Python
// test_mock_configured_only_ports_are_absent_from_the_current_lists: the
// seeded GSM7252PS divergence, end to end through the mock's HTTP face --
// ports 50/51 are Configured: Include / Current: Exclude on the real
// switch, so the HTTP reader (which reports the CURRENT view) must not
// list them as members, while the membership page's Configured grid must.
func TestHTTPFaceFastpathVlanMembershipConfiguredOnlyDivergence(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := SeedGSM7252PS()
	if len(st.Vlans[1].ConfiguredOnly) == 0 {
		t.Fatal("precondition: seeded gsm7252ps VLAN 1 should carry ConfiguredOnly ports")
	}
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	reader, err := webui.NewReader(client, m)
	if err != nil {
		t.Fatalf("webui.NewReader: %v", err)
	}
	vlans, err := reader.GetVLANs(ctx)
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	var vlan1 *model.VLANInfo
	for i := range vlans {
		if vlans[i].VlanID == 1 {
			vlan1 = &vlans[i]
		}
	}
	if vlan1 == nil {
		t.Fatal("GetVLANs() has no VLAN 1")
	}
	for port := range st.Vlans[1].ConfiguredOnly {
		for _, p := range vlan1.MemberPorts {
			if p == port {
				t.Errorf("VLAN 1 MemberPorts (CURRENT view) lists ConfiguredOnly port %d, want absent", port)
			}
		}
	}
	page, err := reader.ReadFastpathMembership(ctx, 1)
	if err != nil {
		t.Fatalf("ReadFastpathMembership(1) error = %v", err)
	}
	for port := range st.Vlans[1].ConfiguredOnly {
		if page.Configured[port] != model.VlanUntagged {
			t.Errorf("membership page Configured[%d] = %v, want Untagged (the CONFIGURED view)", port, page.Configured[port])
		}
	}
}

// -- SSL-cert upload validation (dossier §3.5/§3.6) ----------------------

func TestHTTPFaceCertUploadMultipart(t *testing.T) {
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	if spec.CertUploadPath == "" || spec.CertUploadFileField == "" {
		t.Fatalf("gsm7228ps spec unexpectedly has no cert-upload flow (test fixture assumption broken)")
	}
	addr, _ := startHTTPFace(t, NewState("gsm7228ps"), spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()
	const certBytes = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
	resp, err := client.PostMultipart(ctx, spec.CertUploadPath, spec.CertUploadFormFields, webui.MultipartFile{
		Field:       spec.CertUploadFileField,
		Filename:    "certificate.pem",
		Content:     []byte(certBytes),
		ContentType: "application/octet-stream",
	})
	if err != nil {
		t.Fatalf("PostMultipart() error = %v", err)
	}
	if !strings.Contains(strings.ToLower(resp), "completed successfully") {
		t.Errorf("PostMultipart() response = %q, want it to contain \"completed successfully\"", resp)
	}
}

func TestHTTPFaceCertUploadMultipartMissingFieldIs400(t *testing.T) {
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, NewState("gsm7228ps"), spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()
	// Deliberately empty data map: every one of spec.CertUploadFormFields's
	// ~22 required keys is missing.
	_, err = client.PostMultipart(ctx, spec.CertUploadPath, map[string]string{}, webui.MultipartFile{
		Field:       spec.CertUploadFileField,
		Filename:    "certificate.pem",
		Content:     []byte("x"),
		ContentType: "application/octet-stream",
	})
	if err == nil {
		t.Fatalf("PostMultipart() with missing required fields error = nil, want an HTTP 400 error")
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("PostMultipart() error = %v, want errors.Is(..., model.ErrHTTP)", err)
	}
}

func TestHTTPFaceCertUploadGoAhead(t *testing.T) {
	m, err := model.GetModel("gs728tpp")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := NewState("gs728tpp")
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	const xmlBody = `<?xml version='1.0' encoding='utf-8'?>` +
		`<DeviceConfiguration><SSLCryptoCertificateImportList action="set">` +
		`<Entry><instance>1</instance>` +
		`<certificate>FAKECERTDATA</certificate>` +
		`<publicKey>FAKEPUBDATA</publicKey>` +
		`<privateKey>FAKEPRIVDATA</privateKey>` +
		`</Entry></SSLCryptoCertificateImportList></DeviceConfiguration>`
	resp, err := client.PostXML(ctx, spec.CertUploadPath, xmlBody)
	if err != nil {
		t.Fatalf("PostXML() error = %v", err)
	}
	if !strings.Contains(resp, "<statusCode>0</statusCode>") {
		t.Errorf("PostXML() response = %q, want <statusCode>0</statusCode>", resp)
	}
	if st.UploadedCert == nil || *st.UploadedCert != "FAKECERTDATA" {
		t.Errorf("state.UploadedCert = %v, want \"FAKECERTDATA\"", st.UploadedCert)
	}
}

func TestHTTPFaceCertUploadGoAheadXXERejected(t *testing.T) {
	m, err := model.GetModel("gs728tpp")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	st := NewState("gs728tpp")
	addr, _ := startHTTPFace(t, st, spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	const xxeBody = `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
		`<DeviceConfiguration><SSLCryptoCertificateImportList action="set">` +
		`<Entry><certificate>&xxe;</certificate><privateKey>x</privateKey></Entry>` +
		`</SSLCryptoCertificateImportList></DeviceConfiguration>`
	resp, err := client.PostXML(ctx, spec.CertUploadPath, xxeBody)
	if err != nil {
		t.Fatalf("PostXML() error = %v", err)
	}
	if strings.Contains(resp, "<statusCode>0</statusCode>") {
		t.Errorf("PostXML() with a DOCTYPE/ENTITY body response = %q, want a REJECTED (non-zero) statusCode", resp)
	}
	if st.UploadedCert != nil {
		t.Errorf("state.UploadedCert after a rejected XXE upload = %v, want nil (unchanged)", st.UploadedCert)
	}
}

// -- Lifecycle (mirrors TestSnmpFaceStartStopCyclesLeakNoGoroutinesOrFDs) --

func countOpenHTTPFDs(t *testing.T) (count int, ok bool) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	return len(entries), true
}

func TestHTTPFaceStartStopCyclesLeakNoGoroutinesOrFDs(t *testing.T) {
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	beforeGoroutines := runtime.NumGoroutine()
	beforeFDs, haveFDs := countOpenHTTPFDs(t)

	for i := 0; i < 10; i++ {
		face := NewHTTPFace(NewState("gs305ep"), spec, "password", "127.0.0.1")
		port, err := face.Start()
		if err != nil {
			t.Fatalf("cycle %d: Start() error = %v", i, err)
		}
		if port == 0 {
			t.Fatalf("cycle %d: Start() returned port 0", i)
		}
		if err := face.Stop(); err != nil {
			t.Fatalf("cycle %d: Stop() error = %v", i, err)
		}
		// A second Stop must be a harmless no-op (idempotent).
		if err := face.Stop(); err != nil {
			t.Fatalf("cycle %d: second Stop() error = %v", i, err)
		}
	}

	for i := 0; i < 50; i++ {
		if runtime.NumGoroutine() <= beforeGoroutines {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > beforeGoroutines {
		t.Errorf("goroutine count after 10 start/stop cycles = %d, want <= %d (baseline)", after, beforeGoroutines)
	}

	if haveFDs {
		if afterFDs, ok := countOpenHTTPFDs(t); ok && afterFDs > beforeFDs {
			t.Errorf("open FD count after 10 start/stop cycles = %d, want <= %d (baseline; every TCP socket must be released)", afterFDs, beforeFDs)
		}
	}
}

func TestHTTPFaceStopBeforeStartIsNoOp(t *testing.T) {
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	face := NewHTTPFace(NewState("gs305ep"), spec, "password", "127.0.0.1")
	if err := face.Stop(); err != nil {
		t.Errorf("Stop() before Start() error = %v, want nil (no-op)", err)
	}
}
