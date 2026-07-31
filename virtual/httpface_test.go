package virtual

// Tests for HTTPFace, driven over real TCP loopback against webui's own
// Session implementation (webui.HTTPClient) and webui.Reader -- the same
// "drive the mock through the real client, not by peeking at internals"
// convention snmpface_test.go/nsdpface_test.go already use.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

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

// TestHTTPFaceNonStandardDialectReadPagesAreHonestly404 is a deliberate
// tripwire (dispatchRender's doc comment / principles 1 & 5): every dialect
// OTHER than HTMLDialectStandard has no renderer wired in this task, so a
// known, spec-advertised read page must 404 honestly rather than silently
// falling through to the STANDARD-dialect fallback (which would render a
// plausible-looking page in the WRONG shape, built from real seeded data --
// worse than a 404, since it would false-green a caller's integration
// against a page this mock cannot actually produce yet).
//
// Tasks 9/10 MUST update this test (per model, as its real renderer lands)
// to assert a genuine render instead -- a green run of this test after
// Tasks 9/10 land a dialect's renderer means that dialect's own tripwire
// case was never removed, not that the renderer is still missing.
func TestHTTPFaceNonStandardDialectReadPagesAreHonestly404(t *testing.T) {
	tests := []struct {
		name     string
		modelKey string
		dialect  webui.HTMLDialect
	}{
		{"GS110EMX/gs110emx", "gs110emx", webui.HTMLDialectGS110EMX},
		{"GS105PE/gs105pe", "gs105pe", webui.HTMLDialectGS105PE},
		{"M4300/m4300-24x", "m4300-24x", webui.HTMLDialectM4300},
		{"M4300/m4300-16x", "m4300-16x", webui.HTMLDialectM4300},
		{"XEFastpath/gsm7252ps", "gsm7252ps", webui.HTMLDialectXEFastpath},
		{"S3300/gsm7228ps", "gsm7228ps", webui.HTMLDialectS3300},
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
			if spec.HTMLDialect != tt.dialect {
				t.Fatalf("spec.HTMLDialect = %v, want %v (test table/registry drifted)", spec.HTMLDialect, tt.dialect)
			}
			addr, _ := startHTTPFace(t, NewState(tt.modelKey), spec, "password")

			// Raw net/http, with a Referer/Origin header whenever this
			// model's spec demands one, so the request reaches the dialect
			// gate at all (not rejected earlier by the unrelated referer
			// check -- see TestHTTPFaceRefererMissingIs403/
			// TestHTTPFaceSecurePOSTRequiresOriginHeader for THAT gate).
			req, err := http.NewRequest(http.MethodGet, "http://"+addr+spec.DashboardPath, nil) //nolint:noctx // test-only.
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if spec.NeedsReferer {
				req.Header.Set("Referer", "http://"+addr+"/")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", spec.DashboardPath, err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s (dialect %v, no renderer wired yet) status = %d, want 404", spec.DashboardPath, spec.HTMLDialect, resp.StatusCode)
			}
		})
	}
}

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

func TestHTTPFaceGoAheadAuthenticatedReadOfUnimplementedWcdPage404s(t *testing.T) {
	m, err := model.GetModel("gs728tpp")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}
	addr, _ := startHTTPFace(t, NewState("gs728tpp"), spec, "password")

	client := webui.NewHTTPClient(addr, "password", spec)
	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	// TASK 9/10 SEAM: web_gs728tpp's render_wcd isn't ported yet, so every
	// authenticated wcd read 404s honestly (never a fabricated page) --
	// pinned here so Task 9/10 landing render_wcd is a deliberate, visible
	// change to this test's expectation, not a silent regression either way.
	_, err = client.GetPage(ctx, spec.PoEStatusPath)
	if err == nil {
		t.Fatalf("GetPage(%s) after login error = nil, want an HTTP error (Task 9/10 hasn't wired render_wcd yet)", spec.PoEStatusPath)
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("GetPage(%s) error = %v, want errors.Is(..., model.ErrHTTP)", spec.PoEStatusPath, err)
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
