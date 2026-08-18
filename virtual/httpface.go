package virtual

// httpface.go ports src/netgear_switch/virtual/faces/http.py's
// VirtualHttpFace (the normative source; that repo is read-only from here --
// pin 1841111, branch go-port-pin-1841111). Any discrepancy between this
// file and the Python source is a bug here, unless called out in a comment.
// See docs/superpowers/plans/2026-07-31-slice-06-dossier-http-readwrite-face.md
// §3 for the full porting dossier this mirrors.
//
// HTTPFace is a real net/http.Server web-UI face serving a *State, bound to
// an ephemeral TCP port on 127.0.0.1 -- the HTTP analogue of SnmpFace/
// NsdpFace (same Start()-returns-port / deterministic-idempotent-Stop()
// shape). Unlike Python's ThreadingHTTPServer (one OS thread per accepted
// connection, no built-in synchronization of its own), Go's http.Server is
// already concurrent by design; render/apply access to the shared *State is
// serialized on renderMu, mirroring Python's single self._lock (dossier
// §3.8) at the SAME granularity: held only for the dispatch-and-render/apply
// critical section, never for header parsing or the login/referer checks.
//
// Go's http.Server.Shutdown(ctx) WAITS for in-flight handlers to finish --
// strictly stronger than Python's ThreadingHTTPServer.shutdown() (which only
// stops NEW-connection acceptance, leaving already-dispatched per-request
// threads to finish on their own, unwaited). This Go port embraces that
// extra determinism rather than fighting it (dossier §3.1) -- Stop() is
// genuinely leak-free, not just "no new leaks after this returns".
//
// TASK 8 SCOPE (this file, as first landed): the face skeleton
// (bind/serve/stop), all 5 login handshakes (dossier §3.2), Referer/Origin
// 403 enforcement (§3.4), the 404-for-unspecced-path gate (§3.7),
// SSL-cert-upload validation (both the multipart/S3300 shape and the
// GoAhead XML shape, §3.5/§3.6), and ONE dialect (HTMLDialectStandard --
// gs305ep, and gs105pe's shared pages) wired end-to-end to prove the
// read/write/re-render shape. Tasks 9/10 have since landed every other
// dialect's own byte-faithful renderer (GS110EMX, GS105PE's own port/PVID/
// stats pages, M4300, XE_FASTPATH/gsm7252ps, S3300/gsm7228ps, the FASTPATH
// shared VLAN-membership/XUI pages, GoAhead's wcd read routing) -- see
// dispatchRender/dispatchApplyAndRender's own doc comments for the exact
// per-dialect priority order, mirroring Python's elif chain. Both dispatch
// functions are DIALECT-GATED, not a blanket fallback: every HTMLDialect
// this package serves reaches its own byte-faithful renderer -- the six
// non-GoAhead dialects through the cases in these two functions, and
// GoAheadXML diverted upstream in handleGet/handlePost before either is ever
// called. Any dialect/path that isn't wired returns implemented=false, so
// the caller (handleGet/handlePost) answers an honest 404 -- never a
// wrong-shaped STANDARD page. renderStandardPage (this file, below) is
// reachable ONLY under HTMLDialectStandard; see its own doc comment.

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

const (
	// virtualHTTPToken is the fixed mock session token issued on a successful
	// LoginSchemeGambit login, mirroring Python's module-level _VIRTUAL_TOKEN
	// (faces/http.py:51). Any non-empty string works: real hardware mints one
	// per login, but the mock's job is proving the *shape* of the exchange
	// (ParseGambitToken), not producing a cryptographically-real value.
	virtualHTTPToken = "virtual-gambit-session-token-0123456789abcdef"
	// virtualHTTPSessionPath is the fixed per-face GoAhead XML_API session
	// path segment, mirroring Python's self._session_path (faces/http.py:158).
	virtualHTTPSessionPath = "cs0000face"
	// virtualHTTPCSRFHash is web.py's _HASH literal ("virtualhash"): emitted
	// on every STANDARD-dialect login/writable page, never validated
	// anywhere (write-only decoration proving the round-trip shape).
	virtualHTTPCSRFHash = "virtualhash"
	// virtualHTTPRand is the fixed login nonce this mock issues on every GET
	// of the login page, mirroring Python's constructor default rand="1234".
	virtualHTTPRand = "1234"
	// notFoundBody is the uniform 404 body for any path not in a model's
	// HttpModelSpec, mirroring Python's literal (dossier §3.7).
	notFoundBody = "<html><body>Not Found</body></html>"
)

// HTTPFace is a net/http.Server web-UI face serving a *State, mirroring
// Python VirtualHttpFace. Construct with NewHTTPFace; call Start to bind and
// begin serving, Stop to tear down (idempotent; safe to call before Start or
// more than once).
type HTTPFace struct {
	state    *State
	spec     *webui.HTTPModelSpec
	host     string
	port     int // 0 (the default) asks the OS for an ephemeral port; see SetPort.
	password string
	rand     string

	cookie      string // "<CookieName>=virtualsid"
	token       string
	sessionPath string
	known       map[string]bool // built once at construction; read-only thereafter

	mu       sync.Mutex // guards srv/listener (Start/Stop lifecycle only)
	srv      *http.Server
	listener net.Listener
	wg       sync.WaitGroup

	// renderMu serializes the render/apply critical section against the
	// shared *State, mirroring Python's self._lock (dossier §3.8) -- NOT
	// held across header parsing, the login/referer checks, or cert-upload
	// validation's response building (only its one state.UploadedCert
	// assignment).
	renderMu sync.Mutex

	// expireGoAheadSessionRemaining, guarded by renderMu, counts the number
	// of upcoming authenticated GoAhead wcd requests (read or write) that
	// should still answer as an expired session -- see
	// SimulateGoAheadSessionExpiry.
	expireGoAheadSessionRemaining int
}

// NewHTTPFace builds an HTTPFace serving state per spec, accepting only a
// login whose credential matches password, bound to host (typically
// "127.0.0.1") once Start is called.
func NewHTTPFace(state *State, spec *webui.HTTPModelSpec, password, host string) *HTTPFace {
	return &HTTPFace{
		state:       state,
		spec:        spec,
		host:        host,
		password:    password,
		rand:        virtualHTTPRand,
		cookie:      spec.CookieName + "=virtualsid",
		token:       virtualHTTPToken,
		sessionPath: virtualHTTPSessionPath,
		known:       knownHTTPPaths(spec),
	}
}

// SetPort pins the TCP port Start binds to, mirroring the Python
// reference's VirtualSwitch(http_port=...) constructor argument (server.py's
// own "self.http_port"). The default, 0, asks the OS for an ephemeral port,
// same as before this method existed. Call before Start; a call after Start
// has no effect until the next Start following a Stop.
func (f *HTTPFace) SetPort(port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.port = port
}

// Start binds f.host:f.port (an ephemeral port when f.port is 0, the
// default) and begins serving on a background goroutine, returning the
// bound port. Calling Start twice without an intervening Stop is an error.
func (f *HTTPFace) Start() (port int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listener != nil {
		return 0, fmt.Errorf("virtual: HTTPFace.Start: already started")
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(f.host, strconv.Itoa(f.port)))
	if err != nil {
		return 0, fmt.Errorf("virtual: HTTPFace.Start: listen tcp on %s: %w", f.host, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(f.serveHTTP)}
	f.listener = ln
	f.srv = srv

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		_ = srv.Serve(ln) // returns http.ErrServerClosed on a clean Shutdown
	}()

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		// Unreachable: net.Listen("tcp", ...) always returns a *net.TCPAddr
		// from Addr().
		return 0, fmt.Errorf("virtual: HTTPFace.Start: unexpected local addr type %T", ln.Addr())
	}
	return tcpAddr.Port, nil
}

// Stop shuts the server down (waiting for in-flight handlers, per Go's
// stronger http.Server.Shutdown contract -- see the package doc comment
// above) and waits for the serve goroutine to exit. Idempotent: a Stop
// before Start, or a second Stop, is a no-op.
func (f *HTTPFace) Stop() error {
	f.mu.Lock()
	srv := f.srv
	f.srv = nil
	f.listener = nil
	f.mu.Unlock()

	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := srv.Shutdown(ctx)
	f.wg.Wait()
	if err != nil {
		return fmt.Errorf("virtual: HTTPFace.Stop: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// known-paths gate (dossier §3.3's _known_paths/_PATH_FIELDS/_xui_write_paths)
// ---------------------------------------------------------------------

// httpSpecPathFields returns every *_path field on spec EXCEPT LoginPath/
// LoginPostPath (handled as the login handshake, never as a generically-
// servable page), mirroring Python's _PATH_FIELDS -- built there via
// dataclasses.fields() introspection over every field ending "_path"; this
// Go port has no equivalent struct-tag convention for that, so the field
// list is transcribed by hand. A future webui.HTTPModelSpec field ending in
// "Path" must be added here too, or it silently 404s forever exactly as an
// un-added Python dataclass field would raise no error but also never route.
func httpSpecPathFields(spec *webui.HTTPModelSpec) []string {
	return []string{
		spec.DashboardPath, spec.StatsPath, spec.PoEConfigPath, spec.PoEStatusPath,
		spec.VlanConfigPath, spec.VlanMembershipPath, spec.PvidPath, spec.RebootPath,
		spec.LogoutPath, spec.SysinfoPath, spec.MgmtIPPath, spec.MacTablePath,
		spec.LLDPPath, spec.CertUploadPath, spec.VlanMembershipPostPath, spec.PortConfigPath,
		spec.UsersPath, spec.HTTPServicePath, spec.HTTPSServicePath, spec.SSHServicePath,
		spec.TelnetServicePath, spec.SyslogPath,
	}
}

// xuiWriteHTTPPaths returns {"<page>.html/a1": "<page>.html"} for every XUI
// write page (PortConfigPath/PoEConfigPath/MgmtIPPath/SyslogPath -- the
// syslog page posts collector row add/delete to its own /a1), mirroring
// Python's _xui_write_paths: on real managed-model firmware every one of
// these pages GETs at "<page>.html" and POSTs to "<page>.html/a1" (its
// second form's ACTION), so the mock must serve both paths or a faithful
// writer's apply would 404 against it while working on hardware. Included
// unconditionally, regardless of dialect, mirroring
// _XUI_WRITE_PATH_FIELDS: a non-M4300 model with a SyslogPath (gsm7252ps,
// gsm7228ps) still gets the alias registered as "known", even though
// renderFastpathXUIPage refuses to apply through it for any dialect but
// M4300 -- the outcome (404) is unchanged either way, since webui.Writer's
// own dialect gate never lets a POST reach here for those models.
func xuiWriteHTTPPaths(spec *webui.HTTPModelSpec) map[string]string {
	out := map[string]string{}
	for _, p := range []string{spec.PortConfigPath, spec.PoEConfigPath, spec.MgmtIPPath, spec.SyslogPath} {
		if p != "" {
			out[p+"/a1"] = p
		}
	}
	return out
}

// knownHTTPPaths is the set of paths spec actually serves (populated fields
// only), mirroring Python's _known_paths.
func knownHTTPPaths(spec *webui.HTTPModelSpec) map[string]bool {
	out := map[string]bool{}
	for _, p := range httpSpecPathFields(spec) {
		if p != "" {
			out[p] = true
		}
	}
	for alias := range xuiWriteHTTPPaths(spec) {
		out[alias] = true
	}
	return out
}

// ---------------------------------------------------------------------
// Top-level dispatch (dossier §3.9's "full routing precedence")
// ---------------------------------------------------------------------

func (f *HTTPFace) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		f.handleGet(w, r)
	case http.MethodPost:
		f.handlePost(w, r)
	default:
		// Python's BaseHTTPRequestHandler only ever defines do_GET/do_POST;
		// this mock (like the Python one) never receives any other verb from
		// webui.HTTPClient/the eventual Reader/Writer.
		w.WriteHeader(http.StatusNotImplemented)
	}
}

// refererOK mirrors Python Handler._referer_ok (dossier §3.4): checked at
// the very top of BOTH GET and POST, before EVERYTHING else (dialect
// dispatch, login-path handling, known-paths gating).
func (f *HTTPFace) refererOK(r *http.Request, isPost bool) bool {
	if !f.spec.NeedsReferer {
		return true
	}
	if r.Header.Get("Referer") == "" {
		return false
	}
	if isPost && f.spec.Secure {
		return r.Header.Get("Origin") != ""
	}
	return true
}

// send mirrors Python Handler._send: always Content-Type text/html, an
// explicit Content-Length, and Set-Cookie only when withCookie.
func (f *HTTPFace) send(w http.ResponseWriter, text string, status int, withCookie bool) {
	data := []byte(text)
	if withCookie {
		w.Header().Set("Set-Cookie", f.cookie+"; path=/")
	}
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func (f *HTTPFace) handleGet(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !f.refererOK(r, false) {
		f.send(w, "403 Forbidden", http.StatusForbidden, false)
		return
	}
	if f.spec.HTMLDialect == webui.HTMLDialectGoAheadXML {
		f.goaheadGet(w, r)
		return
	}
	if path == f.spec.LoginPath {
		f.send(w, f.renderLogin(), http.StatusOK, false)
		return
	}
	if !f.known[path] {
		f.send(w, notFoundBody, http.StatusNotFound, false)
		return
	}
	f.renderMu.Lock()
	page, implemented := f.dispatchRender(path, map[string]string{})
	f.renderMu.Unlock()
	if !implemented {
		// TASK 9/10 SEAM: this model's HTMLDialect has no renderer wired yet
		// (see dispatchRender's doc comment) -- an honest 404, never the
		// STANDARD-dialect fallback rendering the wrong shape.
		f.send(w, notFoundBody, http.StatusNotFound, false)
		return
	}
	f.send(w, page, http.StatusOK, false)
}

func (f *HTTPFace) handlePost(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !f.refererOK(r, true) {
		f.send(w, "403 Forbidden", http.StatusForbidden, false)
		return
	}
	if f.spec.HTMLDialect == webui.HTMLDialectGoAheadXML {
		// Every GoAhead write is a raw XML POST to <session>/wcd, dispatched
		// by applyGoAheadWrite on the object name inside the body (SSL-cert
		// import, port/PoE/VLAN/PVID writes); goaheadPost 404s any other
		// path.
		f.goaheadPost(w, r)
		return
	}

	raw, _ := io.ReadAll(r.Body)
	contentType := r.Header.Get("Content-Type")
	// SSL-cert upload: handled BEFORE the urlencoded-body parse (a multipart
	// body is not urlencoded), mirroring Python's ordering exactly -- this
	// runs even BEFORE the login-post-path check below (dossier §3.9's
	// routing precedence note: the CODE, not the dossier prose summary, is
	// authoritative for this ordering).
	if path == f.spec.CertUploadPath && strings.HasPrefix(contentType, "multipart/form-data") {
		status, page := f.handleCertUpload(contentType, raw)
		f.send(w, page, status, false)
		return
	}

	form := parseHTTPFormBody(raw)
	loginPostPath := f.spec.LoginPostPath
	if loginPostPath == "" {
		loginPostPath = f.spec.LoginPath
	}
	if path == loginPostPath {
		ok := f.loginResponse(form) == "OK"
		if f.spec.SessionTokenField != "" {
			token := ""
			if ok {
				token = f.token
			}
			f.send(w, f.renderRedirect(token), http.StatusOK, false)
			return
		}
		body := "Login failed"
		if ok {
			body = "OK"
		}
		f.send(w, body, http.StatusOK, ok)
		return
	}

	if !f.known[path] {
		f.send(w, notFoundBody, http.StatusNotFound, false)
		return
	}
	f.renderMu.Lock()
	page, implemented := f.dispatchApplyAndRender(path, form)
	f.renderMu.Unlock()
	if !implemented {
		// TASK 9/10 SEAM: see handleGet's matching branch / dispatchRender's
		// doc comment.
		f.send(w, notFoundBody, http.StatusNotFound, false)
		return
	}
	f.send(w, page, http.StatusOK, false)
}

// parseHTTPFormBody url-decodes raw and collapses each key to its FIRST
// value only, mirroring Python's `{k: v[0] for k, v in parse_qs(raw.decode
// ("latin-1")).items()}` (dossier §3.9): a duplicate key silently keeps only
// the first value, never an error. Go's url.Values.Get already does this
// per-key, but the whole raw body must still be collapsed into a
// map[string]string up front since every dispatch helper below (mirroring
// Python's plain dict-shaped `form`) indexes it that way.
func parseHTTPFormBody(raw []byte) map[string]string {
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

// ---------------------------------------------------------------------
// Login handshakes (dossier §3.2 -- all 5 LoginScheme values)
// ---------------------------------------------------------------------

// renderLogin renders the login GET page for every non-GoAhead scheme,
// mirroring Python's `web_gs110emx.render_login(rand) if
// spec.session_token_field is not None else web.render_login(rand)`
// dispatch (faces/http.py:309-313): MERGE_HASH_CGI/CHEETAH_FORM/CHEETAH_V1
// all render the SAME generic rand+hash form (web.py's render_login is
// reused verbatim across those three schemes -- CHEETAH_FORM/CHEETAH_V1
// scrape rand off this page but never use it for hashing, see
// webui.HTTPClient.loginBody's CHEETAH_FORM/CHEETAH_V1 branches); GAMBIT
// gets its own template.
func (f *HTTPFace) renderLogin() string {
	if f.spec.SessionTokenField != "" {
		return RenderGS110EMXLogin(f.rand)
	}
	return renderGenericLoginPage(f.rand)
}

// renderGenericLoginPage mirrors web.py's render_login exactly (the
// STANDARD/gs305ep/gs105pe login page, and Task 8's stand-in for GS110EMX's
// byte-faithful one -- see renderLogin's doc comment).
func renderGenericLoginPage(rand string) string {
	return fmt.Sprintf(
		`<html><body><form>`+
			`<input type="hidden" id="rand" name="rand" value="%s">`+
			`<input type="hidden" name="hash" value="%s">`+
			`</form></body></html>`,
		rand, virtualHTTPCSRFHash)
}

// renderRedirect renders the GAMBIT scheme's login-POST response, mirroring
// Python web_gs110emx.render_redirect(token): a page carrying the Gambit
// token webui.ParseGambitToken reads. token=="" for a failed login (mirrors
// Python's `token = face._token if ok else ""`).
func (f *HTTPFace) renderRedirect(token string) string {
	return RenderGS110EMXRedirect(token)
}

// loginResponse validates one login POST's credential against f.password,
// mirroring Python VirtualHttpFace._login_response (faces/http.py:675-691)
// EXACTLY, including which two schemes compare plaintext vs which three
// compare the merge-hash.
func (f *HTTPFace) loginResponse(form map[string]string) string {
	supplied := form[f.spec.PasswordField]
	var ok bool
	switch f.spec.Scheme {
	case webui.LoginSchemeCheetahForm, webui.LoginSchemeCheetahV1:
		// Both post the password in plaintext. A spec that names a username
		// field (M4300 /v1, and the gsm7252ps/gsm7228ps XE login form) also
		// sends a username, validated alongside the password -- so a
		// transport regression that dropped it would be caught here rather
		// than passing silently.
		ok = supplied == f.password
		if f.spec.UsernameField != "" {
			ok = ok && form[f.spec.UsernameField] == f.spec.Username
		}
	default: // LoginSchemeMergeHashCGI, LoginSchemeGambit
		ok = supplied == webui.MergeHashMD5(f.password, f.rand)
	}
	if ok {
		return "OK"
	}
	return "Login failed"
}

// ---------------------------------------------------------------------
// GoAhead XML_API (LoginSchemeXMLAPI, gs728tpp) -- dossier §3.2 step 5, §3.6
// ---------------------------------------------------------------------

// goaheadGet serves the three-step GoAhead GET flow: GET / -> 302 to the
// session path; "<session>/System.xml?action=login" -> statusCode +
// sessionID header; "<session>/wcd?{..}" -> the rendered data block. Any
// other path 404s (the mock never fabricates a page), mirroring Python
// Handler._goahead_get (faces/http.py:217-274).
//
// The wcd READ branch below renders the GoAhead XML data block via
// RenderGS728TPPWcd (web_gs728tpp's render_wcd, routed by the query's
// file= target -- see that function's own doc comment for the route
// table); an unrecognized file= target still 404s, since the mock never
// fabricates a page for a route it doesn't know. The
// redirect-when-unauthenticated and login-statusCode/sessionID steps were
// Task 8 scope (all 5 login handshakes); the wcd renderer itself landed in
// Task 9/10.
func (f *HTTPFace) goaheadGet(w http.ResponseWriter, r *http.Request) {
	pathOnly := r.URL.Path
	rawQuery := r.URL.RawQuery

	if pathOnly == "/" {
		f.redirectToSession(w)
		return
	}
	if strings.HasSuffix(pathOnly, "/System.xml") && strings.Contains(rawQuery, "action=login") {
		query, _ := url.ParseQuery(rawQuery)
		ok := query.Get("user") == f.spec.Username && query.Get("password") == f.password
		code := "1"
		if ok {
			code = "0"
		}
		body := `<?xml version="1.0" encoding="UTF-8" ?>` +
			`<ResponseData><statusCode>` + code + `</statusCode></ResponseData>`
		data := []byte(body)
		w.Header().Set("Content-Type", "text/xml")
		if ok {
			w.Header().Set("sessionID", "virtualsid")
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}

	decoded := pathOnly
	if rawQuery != "" {
		decoded += "?" + rawQuery
	}
	if strings.Contains(decoded, "wcd?") {
		// Real hardware answers an unauthenticated wcd read with HTTP 200 and
		// statusCode 4 -- NOT a redirect (captured; see
		// UnauthenticatedResponse). A session that expires MID-RUN (armed via
		// SimulateGoAheadSessionExpiry) answers the same way even with an
		// otherwise-valid cookie.
		if !strings.Contains(r.Header.Get("Cookie"), "sessionID=virtualsid") || f.consumeGoAheadSessionExpiry() {
			f.send(w, UnauthenticatedResponse(), http.StatusOK, false)
			return
		}
		f.renderMu.Lock()
		page, ok := RenderGS728TPPWcd(f.state, decoded[strings.Index(decoded, "wcd?"):])
		f.renderMu.Unlock()
		if !ok {
			f.send(w, notFoundBody, http.StatusNotFound, false)
			return
		}
		f.send(w, page, http.StatusOK, false)
		return
	}
	f.send(w, notFoundBody, http.StatusNotFound, false)
}

// goaheadPost serves the GoAhead XML_API write flow: a POST of an XML body
// to "<session>/wcd" -- the object name (and its action attribute) inside
// the body selects the operation, applied by applyGoAheadWrite. Any other
// path 404s, mirroring Python Handler._goahead_post (faces/http.py:276-299).
func (f *HTTPFace) goaheadPost(w http.ResponseWriter, r *http.Request) {
	pathOnly := r.URL.Path
	// Real hardware answers an unauthenticated write the same way it answers
	// an unauthenticated read: HTTP 200, statusCode 4 (UnauthenticatedResponse) --
	// NEVER a redirect. A session that expires MID-RUN (armed via
	// SimulateGoAheadSessionExpiry) answers the same way even with an
	// otherwise-valid cookie; the write is never applied in that case.
	if !strings.Contains(r.Header.Get("Cookie"), "sessionID=virtualsid") || f.consumeGoAheadSessionExpiry() {
		f.send(w, UnauthenticatedResponse(), http.StatusOK, false)
		return
	}
	if !strings.HasSuffix(pathOnly, "/wcd") {
		f.send(w, notFoundBody, http.StatusNotFound, false)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	f.renderMu.Lock()
	response := applyGoAheadWrite(f.state, string(raw))
	f.renderMu.Unlock()
	w.Header().Set("Content-Type", "text/xml")
	data := []byte(response)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// redirectToSession sends the 302-to-session-path GoAhead uses for the
// initial "GET /" step -- the one place real hardware genuinely redirects
// (an unauthenticated wcd read/write instead gets UnauthenticatedResponse,
// see goaheadGet/goaheadPost).
func (f *HTTPFace) redirectToSession(w http.ResponseWriter) {
	w.Header().Set("Location", "/"+f.sessionPath+"/")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusFound)
}

// SimulateGoAheadSessionExpiry arms this face to answer the next `times`
// authenticated GoAhead wcd requests (read or write) with
// UnauthenticatedResponse -- HTTP 200 + statusCode 4 -- exactly as if the
// switch's own session had died server-side mid-run, then resumes normal
// service once the count is exhausted. times=1 models a session that comes
// back the moment the caller re-authenticates; times=2 models one that
// still refuses the caller even after re-authenticating (covering
// webui.HTTPClient.GetPage's one retry attempt, which makes exactly two wcd
// requests when the first is expired).
//
// Test-only: real hardware's session dies on its own; a same-process
// net/http test has no equivalent of Python's test reaching into the
// client's private cookie jar (`client._client.cookies.set("sessionID",
// "stale")`, tests/virtual/test_virtual_http_face.py's
// test_expired_session_recovers_on_a_read_but_never_resends_a_write), so
// this simulates the same OBSERVABLE effect from the server side instead.
func (f *HTTPFace) SimulateGoAheadSessionExpiry(times int) {
	f.renderMu.Lock()
	f.expireGoAheadSessionRemaining = times
	f.renderMu.Unlock()
}

// consumeGoAheadSessionExpiry reports whether the current wcd request should
// be answered as an expired session, decrementing the remaining count if so
// (see SimulateGoAheadSessionExpiry).
func (f *HTTPFace) consumeGoAheadSessionExpiry() bool {
	f.renderMu.Lock()
	defer f.renderMu.Unlock()
	if f.expireGoAheadSessionRemaining <= 0 {
		return false
	}
	f.expireGoAheadSessionRemaining--
	return true
}

// goaheadCertImportXML is the minimal shape apply_cert_import needs out of
// the posted SSLCryptoCertificateImportList XML -- deliberately not the
// FULL document shape (no XMLName/instance/publicKey fields), mirroring
// Python's ElementTree.find/findtext, which likewise reads only these two
// leaves and ignores everything else in the document.
type goaheadCertImportXML struct {
	List struct {
		Entry struct {
			Certificate string `xml:"certificate"`
			PrivateKey  string `xml:"privateKey"`
		} `xml:"Entry"`
	} `xml:"SSLCryptoCertificateImportList"`
}

// goaheadApplyCertImport accepts an SSLCryptoCertificateImportList XML
// upload, validates it, and records the received certificate on
// state.UploadedCert, mirroring Python web_gs728tpp.apply_cert_import
// exactly: XXE hardening (a literal "<!DOCTYPE"/"<!ENTITY" substring is
// rejected BEFORE any XML parsing is attempted, per Go's own encoding/xml
// not resolving external entities but this project's belt-and-suspenders
// convention -- see webui's parser dossier §2.10's identical recommendation),
// malformed XML, a missing Entry, or an empty certificate/privateKey each
// yield their own distinct non-zero statusCode; success yields statusCode 0
// and stores ONLY the certificate text (never the private key).
//
// Deliberately collapses Python's TWO distinct "no Entry"/"empty field"
// messages into one ("missing certificate or privateKey") for the missing-
// Entry case too: encoding/xml zero-values an absent element exactly like an
// empty one, so there is no cheap way to tell "Entry absent" from "Entry
// present with empty children" apart without a heavier XML walk -- both are
// equally a caller error a real face would refuse, so the coarser message is
// an acceptable, documented divergence for this skeleton rather than
// over-engineering a presence-tracking XML decoder.
func goaheadApplyCertImport(state *State, xmlBody string) string {
	if strings.Contains(xmlBody, "<!DOCTYPE") || strings.Contains(xmlBody, "<!ENTITY") {
		return goaheadStatusResponse(3, "DTD/entity declaration rejected")
	}
	var doc goaheadCertImportXML
	if err := xml.Unmarshal([]byte(xmlBody), &doc); err != nil {
		return goaheadStatusResponse(1, fmt.Sprintf("malformed XML: %v", err))
	}
	cert := strings.TrimSpace(doc.List.Entry.Certificate)
	key := strings.TrimSpace(doc.List.Entry.PrivateKey)
	if cert == "" || key == "" {
		return goaheadStatusResponse(2, "missing certificate or privateKey")
	}
	state.UploadedCert = model.Ptr(cert)
	return goaheadStatusResponse(0, "")
}

// goaheadStandard802_3Entry is one Standard802_3List/Entry the GoAhead ports
// page posts, mirroring the subset of fields Python web_gs728tpp.apply_write
// reads off each entry: interfaceName (identifies the port), adminState
// (SetPortEnabled's write, pin b26eb1f / commit f8a890f), and the
// description/speed-duplex triad SetPortDescription/SetPortSpeed post.
// InterfaceDescription is a pointer so an ABSENT element (an admin- or
// speed-only write) is distinguishable from a PRESENT-but-empty one (a
// description write clearing the label) -- mirroring Python's `desc is not
// None` check against ElementTree's findtext.
type goaheadStandard802_3Entry struct {
	InterfaceName               string  `xml:"interfaceName"`
	AdminState                  string  `xml:"adminState"`
	InterfaceDescription        *string `xml:"interfaceDescription"`
	AutoNegotiationAdminEnabled string  `xml:"autoNegotiationAdminEnabled"`
	SpeedAdmin                  string  `xml:"speedAdmin"`
	DuplexAdminMode             string  `xml:"duplexAdminMode"`
}

// goaheadIfacePort converts a Standard802_3List entry's interfaceName
// ("g17") to a port number, mirroring Python web_gs728tpp._iface_port: a
// LAG or any other non-"g<digits>" name yields ok=false.
func goaheadIfacePort(name string) (int, bool) {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, "g") {
		return 0, false
	}
	rest := name[1:]
	if !isAllDigits(rest) {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	return n, true
}

// applyGoAheadStandard802_3List mutates state from a Standard802_3List
// write's entries, mirroring Python web_gs728tpp.apply_write's
// "Standard802_3List" branch EXACTLY: admin state and description apply
// independently of each other and of the speed/duplex triad, which itself
// applies as a UNIT (the page's JS marks each of autoNegotiationAdminEnabled/
// speedAdmin/duplexAdminMode "undefined" -- omitted -- when the operator did
// not touch the Speed control, so a well-formed write always carries all
// three together or none). Forcing a rate does NOT re-negotiate the link, so
// Speed/Link are left untouched -- the same separation the FASTPATH CLI face
// keeps between Physical Mode and Physical Status. Returning to auto sends
// speedAdmin="0", but the live switch reports a REAL rate there while
// negotiating, so the previous SpeedAdmin is kept rather than storing the 0.
// An unknown port, or a port this switch does not have, is a silent skip,
// mirroring Python's `port not in state.ports: continue`.
func applyGoAheadStandard802_3List(state *State, entries []goaheadStandard802_3Entry) {
	for _, entry := range entries {
		port, ok := goaheadIfacePort(entry.InterfaceName)
		if !ok {
			continue
		}
		sim, exists := state.Ports[port]
		if !exists {
			continue
		}
		if admin := strings.TrimSpace(entry.AdminState); admin == "1" || admin == "2" {
			sim.Admin = admin == "1"
			if admin == "2" {
				sim.Link = false
			}
		}
		if entry.InterfaceDescription != nil {
			if desc := strings.TrimSpace(*entry.InterfaceDescription); desc != "" {
				sim.Description = &desc
			} else {
				sim.Description = nil
			}
		}
		autoneg := strings.TrimSpace(entry.AutoNegotiationAdminEnabled)
		rate := strings.TrimSpace(entry.SpeedAdmin)
		duplex := strings.TrimSpace(entry.DuplexAdminMode)
		if (autoneg == "1" || autoneg == "2") && rate != "" && (duplex == "2" || duplex == "3") {
			sim.AutonegAdmin = autoneg
			sim.DuplexAdminMode = duplex
			if autoneg == "2" {
				sim.SpeedAdmin = rate
			}
		}
	}
}

// goaheadVLANEntry is one VLANList/VLAN element a create/rename or delete
// write posts, mirroring Python web_gs728tpp.apply_write's "VLANList"
// branch. VLANName is only meaningful on a "set" (create/rename) write.
type goaheadVLANEntry struct {
	VLANID   string `xml:"VLANID"`
	VLANName string `xml:"VLANName"`
}

// goaheadVLANListXML is the VLANList write body's decode shape --
// vlanCreateBody/vlanDeleteBody (webui/goahead_write.go) each post exactly
// one <VLAN>, but the shape allows more, mirroring Python's `for vlan_el in
// section.findall("VLAN")`.
type goaheadVLANListXML struct {
	Action string             `xml:"action,attr"`
	VLANs  []goaheadVLANEntry `xml:"VLAN"`
}

// goaheadVLANMember is one VLANMember element a VLANMembershipList write
// posts, mirroring Python web_gs728tpp.apply_write's "VLANMembershipList"
// branch. TaggingMode is only present on a "set" write (EXCLUDED is a
// "delete" carrying no taggingMode at all -- see vlanMembershipBody's own
// doc comment, webui/goahead_write.go).
type goaheadVLANMember struct {
	InterfaceName string `xml:"interfaceName"`
	TaggingMode   string `xml:"taggingMode"`
}

// goaheadMembershipVLAN is one VLANMembershipList/VLAN element, carrying
// the VLAN identity plus its (usually single) posted member.
type goaheadMembershipVLAN struct {
	VLANID  string              `xml:"VLANID"`
	Members []goaheadVLANMember `xml:"MembershipList>VLANMember"`
}

// goaheadVLANMembershipListXML is the VLANMembershipList write body's
// decode shape.
type goaheadVLANMembershipListXML struct {
	Action string                  `xml:"action,attr"`
	VLANs  []goaheadMembershipVLAN `xml:"VLAN"`
}

// goaheadPVIDInterface is one VLANInterfaceList/Interface element a PVID
// write posts, mirroring Python web_gs728tpp.apply_write's
// "VLANInterfaceList" branch.
type goaheadPVIDInterface struct {
	InterfaceName string `xml:"interfaceName"`
	PVID          string `xml:"PVID"`
}

// goaheadVLANInterfaceListXML is the VLANInterfaceList write body's decode
// shape (SetPVID's pvidBody, webui/goahead_write.go).
type goaheadVLANInterfaceListXML struct {
	Interfaces []goaheadPVIDInterface `xml:"Interface"`
}

// goaheadPoEInterface is one PoEPSEInterfaceList/Interface element a PoE
// admin write posts, mirroring Python web_gs728tpp.apply_write's
// "PoEPSEInterfaceList" branch.
type goaheadPoEInterface struct {
	InterfaceName string `xml:"interfaceName"`
	AdminEnable   string `xml:"adminEnable"`
}

// goaheadPoEPSEInterfaceListXML is the PoEPSEInterfaceList write body's
// decode shape (SetPoE/CyclePoE/ClearPoEFault's poeAdminBody,
// webui/goahead_write.go).
type goaheadPoEPSEInterfaceListXML struct {
	Interfaces []goaheadPoEInterface `xml:"Interface"`
}

// goaheadWriteXML captures every "POST wcd" DeviceConfiguration object this
// Go codebase's writers can post, mirroring the shape Python
// web_gs728tpp.apply_write's per-tag dispatch loop reads:
// Standard802_3List (SetPortDescription/SetPortSpeed/SetPortEnabled),
// DeviceBasicInfo (SetHostname), VLANList (CreateVlan/DeleteVlan),
// VLANMembershipList (SetVlanMembership), VLANInterfaceList (SetPVID) and
// PoEPSEInterfaceList (SetPoE/CyclePoE/ClearPoEFault).
// SSLCryptoCertificateImportList is detected and handled separately
// (applyGoAheadWrite, below): its own decode shape (goaheadCertImportXML)
// predates this struct and is unrelated to Standard802_3List's fields.
// DeviceBasicInfo is a SCALAR section (see deviceBasicInfoBody's own doc
// comment in webui/goahead_write.go): its one field, deviceName, is a
// DIRECT child of <DeviceBasicInfo>, with NO <Entry> wrapper, unlike
// Standard802_3List's repeated <Entry> children -- decoded with its own
// struct shape rather than goaheadStandard802_3Entry's. Other captures
// every OTHER top-level child's tag name, purely for an honest "no handler
// for X" refusal message -- mirroring Python's `[s.tag for s in root]`
// diagnostic -- when none of the objects above is present: an unrecognized
// object fails loudly here rather than silently succeeding.
type goaheadWriteXML struct {
	Standard802_3List *struct {
		Entries []goaheadStandard802_3Entry `xml:"Entry"`
	} `xml:"Standard802_3List"`
	DeviceBasicInfo *struct {
		DeviceName *string `xml:"deviceName"`
	} `xml:"DeviceBasicInfo"`
	VLANList            *goaheadVLANListXML            `xml:"VLANList"`
	VLANMembershipList  *goaheadVLANMembershipListXML  `xml:"VLANMembershipList"`
	VLANInterfaceList   *goaheadVLANInterfaceListXML   `xml:"VLANInterfaceList"`
	PoEPSEInterfaceList *goaheadPoEPSEInterfaceListXML `xml:"PoEPSEInterfaceList"`
	Other               []struct {
		XMLName xml.Name
	} `xml:",any"`
}

// applyGoAheadVLANList mutates state from a VLANList write's <VLAN>
// entries -- create/rename ("set") or delete -- mirroring Python
// web_gs728tpp.apply_write's "VLANList" branch. Returns ok=false on a bad
// (non-digit) VLANID so the caller can surface the SAME non-zero statusCode
// Python's fake does, rather than silently skipping it.
func applyGoAheadVLANList(state *State, action string, vlans []goaheadVLANEntry) (badVLANID string, ok bool) {
	for _, v := range vlans {
		vidText := strings.TrimSpace(v.VLANID)
		if vidText == "" || !isAllDigits(vidText) {
			return vidText, false
		}
		vid, err := strconv.Atoi(vidText)
		if err != nil {
			return vidText, false
		}
		if action == "delete" {
			delete(state.Vlans, vid)
			continue
		}
		name := strings.TrimSpace(v.VLANName)
		if sim, exists := state.Vlans[vid]; exists {
			sim.Name = name
		} else {
			state.Vlans[vid] = &VlanSim{Name: name}
		}
	}
	return "", true
}

// applyGoAheadVLANMembership mutates one VLAN's per-port membership from a
// VLANMembershipList write's <VLAN><MembershipList><VLANMember> entries,
// mirroring Python web_gs728tpp.apply_write's "VLANMembershipList" branch.
// A referenced VLAN that does not exist is refused (ok=false, matching
// Python's early "no such VLAN" statusCode), never silently skipped. A
// member whose interfaceName is not a physical port ("g<digits>") is a
// silent skip, mirroring Python's `if port is None: continue`.
func applyGoAheadVLANMembership(state *State, action string, vlans []goaheadMembershipVLAN) (missingVLAN int, ok bool) {
	for _, v := range vlans {
		vid, _ := strconv.Atoi(strings.TrimSpace(v.VLANID))
		vsim, exists := state.Vlans[vid]
		if !exists {
			return vid, false
		}
		for _, m := range v.Members {
			port, portOK := goaheadIfacePort(m.InterfaceName)
			if !portOK {
				continue
			}
			if action == "delete" {
				delete(vsim.Member, port)
				delete(vsim.Untagged, port)
				continue
			}
			if vsim.Member == nil {
				vsim.Member = map[int]bool{}
			}
			vsim.Member[port] = true
			if strings.TrimSpace(m.TaggingMode) == "1" {
				if vsim.Untagged == nil {
					vsim.Untagged = map[int]bool{}
				}
				vsim.Untagged[port] = true
			} else {
				delete(vsim.Untagged, port)
			}
		}
	}
	return 0, true
}

// applyGoAheadPVIDs mutates each Interface's PVID from a VLANInterfaceList
// write, mirroring Python web_gs728tpp.apply_write's "VLANInterfaceList"
// branch. An interface name that isn't a physical port, or a non-numeric
// PVID, is a silent skip, mirroring Python's `if port is not None and
// pvid.isdigit()`.
func applyGoAheadPVIDs(state *State, interfaces []goaheadPVIDInterface) {
	for _, iface := range interfaces {
		port, ok := goaheadIfacePort(iface.InterfaceName)
		if !ok {
			continue
		}
		pvidText := strings.TrimSpace(iface.PVID)
		if pvidText == "" || !isAllDigits(pvidText) {
			continue
		}
		pvid, err := strconv.Atoi(pvidText)
		if err != nil {
			continue
		}
		state.Pvids[port] = pvid
	}
}

// applyGoAheadPoE mutates each Interface's PoE admin state (and its
// coherent detect status) from a PoEPSEInterfaceList write, mirroring
// Python web_gs728tpp.apply_write's "PoEPSEInterfaceList" branch: admin off
// settles to detect DISABLED(1); admin on with nothing attached resumes
// SEARCHING(2) -- the same coherence rule this file's applyPoE uses for the
// Plus-CGI dialect, just with different wire admin codes (1/2 here vs
// ADMIN_MODE's "1"/"0" there). An interface name that isn't a physical PoE
// port, or an adminEnable outside {1,2}, is a silent skip, mirroring
// Python's `if port is None or port not in state.poe or admin not in
// ("1", "2"): continue`.
func applyGoAheadPoE(state *State, interfaces []goaheadPoEInterface) {
	for _, iface := range interfaces {
		port, ok := goaheadIfacePort(iface.InterfaceName)
		if !ok {
			continue
		}
		sim, exists := state.Poe[port]
		if !exists {
			continue
		}
		admin := strings.TrimSpace(iface.AdminEnable)
		if admin != "1" && admin != "2" {
			continue
		}
		sim.Admin = admin == "1"
		if admin == "1" {
			sim.Detect = 2
		} else {
			sim.Detect = 1
		}
	}
}

// applyGoAheadWrite applies one "POST wcd" write body and returns the wcd
// status response, mirroring Python web_gs728tpp.apply_write: the real UI
// writes EVERYTHING through this one endpoint, with the object name (and
// its action attribute) selecting the operation, so the mock must dispatch
// the same way rather than recognizing one special upload. An unrecognized
// object returns a NON-zero statusCode, never a silent success -- see
// goaheadWriteXML's own doc comment for exactly which objects this Go port
// wires versus the pinned Python fake.
func applyGoAheadWrite(state *State, xmlBody string) string {
	if strings.Contains(xmlBody, "<!DOCTYPE") || strings.Contains(xmlBody, "<!ENTITY") {
		return goaheadStatusResponse(3, "DTD/entity declaration rejected")
	}
	if strings.Contains(xmlBody, "SSLCryptoCertificateImportList") {
		return goaheadApplyCertImport(state, xmlBody)
	}
	var doc goaheadWriteXML
	if err := xml.Unmarshal([]byte(xmlBody), &doc); err != nil {
		return goaheadStatusResponse(1, fmt.Sprintf("malformed XML: %v", err))
	}
	if doc.VLANList != nil {
		if bad, ok := applyGoAheadVLANList(state, doc.VLANList.Action, doc.VLANList.VLANs); !ok {
			return goaheadStatusResponse(2, fmt.Sprintf("bad VLANID %q", bad))
		}
		return goaheadStatusResponse(0, "")
	}
	if doc.VLANMembershipList != nil {
		if missing, ok := applyGoAheadVLANMembership(state, doc.VLANMembershipList.Action, doc.VLANMembershipList.VLANs); !ok {
			return goaheadStatusResponse(2, fmt.Sprintf("no such VLAN %d", missing))
		}
		return goaheadStatusResponse(0, "")
	}
	if doc.VLANInterfaceList != nil {
		applyGoAheadPVIDs(state, doc.VLANInterfaceList.Interfaces)
		return goaheadStatusResponse(0, "")
	}
	if doc.PoEPSEInterfaceList != nil {
		applyGoAheadPoE(state, doc.PoEPSEInterfaceList.Interfaces)
		return goaheadStatusResponse(0, "")
	}
	if doc.Standard802_3List != nil {
		applyGoAheadStandard802_3List(state, doc.Standard802_3List.Entries)
		return goaheadStatusResponse(0, "")
	}
	if doc.DeviceBasicInfo != nil {
		if doc.DeviceBasicInfo.DeviceName != nil {
			state.Hostname = *doc.DeviceBasicInfo.DeviceName
		}
		return goaheadStatusResponse(0, "")
	}
	tags := make([]string, len(doc.Other))
	for i, o := range doc.Other {
		tags[i] = o.XMLName.Local
	}
	return goaheadStatusResponse(2, fmt.Sprintf("no handler for %v", tags))
}

// goaheadStatusResponse mirrors Python web_gs728tpp._status_response: a
// minimal wcd <ResponseData> status envelope, message XML-escaped.
func goaheadStatusResponse(code int, message string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(message))
	return fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8" ?><ResponseData><statusCode>%d</statusCode><statusString>%s</statusString></ResponseData>`,
		code, buf.String())
}

// ---------------------------------------------------------------------
// SSL-cert upload -- multipart/S3300 shape (dossier §3.5)
// ---------------------------------------------------------------------

// handleCertUpload accepts a multipart SSL-cert upload, validates the field
// names the model's spec advertises, and records the received certificate
// on state, mirroring Python Handler._handle_cert_upload (faces/http.py:
// 644-673). Returns (status, page); a missing boundary, missing file field,
// or any missing required form field yields 400 -- so a transport regression
// that dropped a field is caught here rather than passing silently, exactly
// like the login-field validation in loginResponse.
func (f *HTTPFace) handleCertUpload(contentType string, raw []byte) (int, string) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return http.StatusBadRequest, "<html><body>missing multipart boundary</body></html>"
	}
	form, err := multipart.NewReader(bytes.NewReader(raw), params["boundary"]).ReadForm(int64(len(raw)) + 1024)
	if err != nil {
		return http.StatusBadRequest, "<html><body>missing multipart boundary</body></html>"
	}

	fileField := f.spec.CertUploadFileField
	var fileContent []byte
	haveFile := false
	if fileField != "" {
		if files := form.File[fileField]; len(files) > 0 {
			if fh, ferr := files[0].Open(); ferr == nil {
				fileContent, _ = io.ReadAll(fh)
				_ = fh.Close()
				haveFile = true
			}
		}
	}
	if fileField == "" || !haveFile {
		return http.StatusBadRequest, "<html><body>missing cert file field</body></html>"
	}

	var missing []string
	for k := range f.spec.CertUploadFormFields {
		if _, ok := form.Value[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing) // deterministic message; Go map iteration is not
		return http.StatusBadRequest, fmt.Sprintf("<html><body>missing fields: %v</body></html>", missing)
	}

	f.renderMu.Lock()
	f.state.UploadedCert = model.Ptr(string(fileContent))
	f.renderMu.Unlock()
	// Real S3300 firmware renders this exact success marker (live-captured);
	// webui's cert-upload response check keys off it, so the mock must emit
	// it too or a faithful upload would look rejected.
	return http.StatusOK, "<html><body>SSL PEM Server Certificate file download through HTTP " +
		"is completed successfully.</body></html>"
}

// ---------------------------------------------------------------------
// Per-dialect render/apply dispatch (dossier §3.3) -- Task 8's ONE wired
// dialect (STANDARD/gs305ep) plus the Task 9/10 seam.
// ---------------------------------------------------------------------

// dispatchRender renders path for a GET (form is always {}), mirroring
// Python do_GET's "with face._lock: ... elif chain" (faces/http.py:318-338).
// Must be called with f.renderMu held.
//
// Priority order, mirroring Python's elif chain exactly (dossier §3.3):
//  1. the shared FASTPATH "VLAN Membership" page (renderFastpathVlanPage)
//     -- checked first because it is served byte-shape-identically across
//     three dialects (M4300/S3300/XE_FASTPATH), independent of html_dialect;
//  2. the shared FASTPATH XUI write pages (renderFastpathXUIPage: the
//     per-dialect module's port_config_path/poe_config_path/mgmt_ip_path
//     apply-then-render, including their "<page>.html/a1" alias);
//  3. the GAMBIT token-session page set (spec.SessionTokenField != "");
//  4. web_gs105pe's own dashboard/stats/pvid/vlan-config/sysinfo/membership
//     renderers (HTMLDialectGS105PE);
//  5. web_m4300's renderers (HTMLDialectM4300, cross-reusing web_gsm7252ps
//     for lldp_path/poe_status_path);
//  6. web_gsm7228ps's renderers (HTMLDialectS3300);
//  7. web_gsm7252ps's renderers (HTMLDialectXEFastpath).
//
// Getting this ordering wrong breaks any model whose written page is not
// itself present in f.known -- see dossier §3.9's routing-precedence note.
//
// This function is DIALECT-GATED, not a blanket fallback: a dialect with no
// case below (there are none left; every HTMLDialect this package defines
// now has one) would answer ok=false, telling the caller to 404 honestly
// rather than fall through to the STANDARD renderer and render a
// plausible-looking page in the WRONG dialect shape -- principles 1/5: the
// fake must match hardware, never paper over a gap.
func (f *HTTPFace) dispatchRender(path string, form map[string]string) (page string, implemented bool) {
	if page, ok := f.renderFastpathVlanPage(path, form); ok {
		return page, true
	}
	if page, ok := f.renderFastpathXUIPage(path, form); ok {
		return page, true
	}
	if f.spec.SessionTokenField != "" {
		return f.renderGS110EMXPage(path, form), true
	}
	if f.spec.HTMLDialect == webui.HTMLDialectGS105PE {
		if page, ok := f.renderGS105PEPage(path, form); ok {
			return page, true
		}
	}
	if f.spec.HTMLDialect == webui.HTMLDialectM4300 {
		if page, ok := f.renderM4300Page(path); ok {
			return page, true
		}
	}
	if f.spec.HTMLDialect == webui.HTMLDialectS3300 {
		if page, ok := f.renderS3300Page(path); ok {
			return page, true
		}
	}
	if f.spec.HTMLDialect == webui.HTMLDialectXEFastpath {
		if page, ok := f.renderXEPage(path); ok {
			return page, true
		}
	}
	if f.spec.HTMLDialect == webui.HTMLDialectStandard {
		return f.renderStandardPage(path, form), true
	}
	return "", false
}

// dispatchApplyAndRender applies path/form then re-renders (or, for the
// GAMBIT token-session model's dashboard path, returns the apply's own bare
// reply body instead of a re-rendered page -- see renderGS110EMXPage's doc
// comment), mirroring Python do_POST's matching elif chain (faces/http.py:
// 376-397). Must be called with f.renderMu held. See dispatchRender's doc
// comment for the exact priority order and for why this is dialect-gated
// (ok=false -> caller 404s) rather than a blanket STANDARD-dialect fallback
// for every model.
func (f *HTTPFace) dispatchApplyAndRender(path string, form map[string]string) (page string, implemented bool) {
	if page, ok := f.renderFastpathVlanPage(path, form); ok {
		return page, true
	}
	if page, ok := f.renderFastpathXUIPage(path, form); ok {
		return page, true
	}
	if f.spec.SessionTokenField != "" {
		return f.renderGS110EMXPage(path, form), true
	}
	if f.spec.HTMLDialect == webui.HTMLDialectGS105PE {
		// web_gs105pe.py has NO apply_* functions of its own: every one of its
		// known paths (dashboard/stats/pvid/vlan-config/sysinfo/membership) is
		// intercepted here, read-only, exactly mirroring Python's do_POST
		// elif-chain priority (_render_gs105pe_page runs BEFORE the generic
		// web.apply_form fallback ever could) -- so a POST to gs105pe's
		// pvid_path/vlan_config_path/vlan_membership_path never mutates state
		// on this mock. This is the pinned source's own (surprising but
		// faithfully-preserved) behavior, not a Go-side gap: no Python test
		// exercises HttpWriter.set_pvid/set_vlan_membership against gs105pe
		// either (dossier §8/test inventory).
		if page, ok := f.renderGS105PEPage(path, form); ok {
			return page, true
		}
	}
	if f.spec.HTMLDialect == webui.HTMLDialectM4300 {
		if page, ok := f.renderM4300Page(path); ok {
			return page, true
		}
	}
	if f.spec.HTMLDialect == webui.HTMLDialectS3300 {
		if page, ok := f.renderS3300Page(path); ok {
			return page, true
		}
	}
	if f.spec.HTMLDialect == webui.HTMLDialectXEFastpath {
		if page, ok := f.renderXEPage(path); ok {
			return page, true
		}
	}
	if f.spec.HTMLDialect == webui.HTMLDialectStandard {
		f.applyStandardForm(path, form)
		return f.renderStandardPage(path, form), true
	}
	return "", false
}

// renderFastpathVlanPage serves the managed FASTPATH VLAN Membership page
// (GET page or its "_rw.html" form target), applying the form first when it
// carries the apply flag. ok=false = not that page, so the caller falls
// through. Checked BEFORE the per-dialect renderers because all three
// managed dialects (XE_FASTPATH/S3300/M4300) serve the SAME page from the
// same state -- see web_fastpath_vlan.go. Mirrors Python
// VirtualHttpFace._render_fastpath_vlan_page (faces/http.py:488-516).
func (f *HTTPFace) renderFastpathVlanPage(path string, form map[string]string) (string, bool) {
	if path != f.spec.VlanMembershipPath && path != f.spec.VlanMembershipPostPath {
		return "", false
	}
	if f.state.VlanMembershipPage == nil {
		// A model with no MEASURED page geometry must not get a fabricated
		// page (principle 5); 404 is what the face does for any endpoint
		// the device does not serve.
		return "", false
	}
	// Resolve the refusal BEFORE applying: a refused apply must change
	// nothing and come back as err_flag=1 + err_msg on a 200 page, exactly
	// as the M4300 firmware answers a port that is not in general mode.
	errMsg := FastpathVlanRefusal(f.state, form)
	ApplyFastpathVlanMembership(f.state, form)
	return RenderFastpathVlanMembership(f.state, f.spec, form, errMsg), true
}

// renderFastpathXUIPage serves a managed model's XUI write page, applying
// the form first. Covers portsConfiguration.html (set_port_enabled),
// poeInterfaceConfiguration.html (set_poe/cycle_poe/clear_poe_fault) and the
// model's management-IP page -- both the GET page and its "/a1" POST
// target. ok=false = not one of these, so the caller falls through. Mirrors
// Python VirtualHttpFace._render_fastpath_xui_page (faces/http.py:438-486).
//
// The apply happens BEFORE the re-render and its refusal (err_msg) is
// rendered onto the page as err_flag=1 on a 200, which is how these pages
// report a rejection -- never an HTTP error status. On a GET, form is
// always {}, so every apply_* below is a no-op (their own is_apply guard
// requires submit_flag=8) and this reduces to a plain render -- exactly
// mirroring Python calling this same function from both do_GET and do_POST.
func (f *HTTPFace) renderFastpathXUIPage(path string, form map[string]string) (string, bool) {
	pagePath := path
	if orig, aliased := xuiWriteHTTPPaths(f.spec)[path]; aliased {
		pagePath = orig
	}
	if pagePath == f.spec.SyslogPath && f.spec.SyslogPath != "" {
		// Collector row add/delete. Only the M4300 pages carry the metadata
		// the writer depends on, and webui.Writer refuses the other
		// dialects, so the fake must not accept them either -- fall
		// through (ok=false) to the per-dialect GET-only renderer
		// (renderS3300Page/renderXEPage), or 404 on a POST no writer ever
		// issues.
		if f.spec.HTMLDialect != webui.HTMLDialectM4300 {
			return "", false
		}
		errMsg := ApplyXUISyslogRows(f.state, form)
		return RenderXUISyslog(f.state, pagePath, errMsg), true
	}
	if pagePath != f.spec.PortConfigPath && pagePath != f.spec.PoEConfigPath && pagePath != f.spec.MgmtIPPath {
		return "", false
	}
	dialect := f.spec.HTMLDialect
	if dialect != webui.HTMLDialectM4300 && dialect != webui.HTMLDialectS3300 && dialect != webui.HTMLDialectXEFastpath {
		return "", false
	}
	if pagePath == f.spec.MgmtIPPath {
		if f.spec.MgmtIPFields == nil {
			return "", false
		}
		errMsg := ApplyFastpathMgmtIP(f.state, f.spec, form)
		return RenderFastpathMgmtIP(f.state, f.spec, errMsg), true
	}
	if pagePath == f.spec.PortConfigPath {
		switch dialect {
		case webui.HTMLDialectM4300:
			errMsg := ApplyM4300Ports(f.state, form)
			return RenderM4300Ports(f.state, errMsg), true
		case webui.HTMLDialectS3300:
			errMsg := ApplyS3300Ports(f.state, form)
			return RenderS3300Ports(f.state, errMsg), true
		default: // HTMLDialectXEFastpath
			errMsg := ApplyXEPorts(f.state, form)
			return RenderXEPorts(f.state, errMsg), true
		}
	}
	// pagePath == f.spec.PoEConfigPath
	switch dialect {
	case webui.HTMLDialectM4300:
		errMsg := ApplyM4300PoE(f.state, form)
		return RenderM4300PoE(f.state, errMsg), true
	case webui.HTMLDialectS3300:
		errMsg := ApplyS3300PoE(f.state, form)
		return RenderS3300PoE(f.state, errMsg), true
	default: // HTMLDialectXEFastpath
		errMsg := ApplyXEPoE(f.state, form)
		return RenderXEPoE(f.state, errMsg), true
	}
}

// serviceFor returns which management service path is the config page for,
// mirroring Python VirtualHttpFace._service_for (faces/http.py:513-521): a
// path only resolves to a service the STATE has seeded (state.Services),
// even when the spec itself names the page -- exactly reproducing Python's
// behavior for m4300-16x, whose webui.HTTPModelSpec inherits m4300-24x's
// service paths unchanged (Go struct-copy mirrors Python's
// dataclasses.replace not touching them) but whose own seed has never
// measured (and so never populates) Services, leaving those pages served
// nowhere (an honest 404) rather than this mock fabricating page content
// that model's state was never given.
func (f *HTTPFace) serviceFor(path string) (string, bool) {
	spec := f.spec
	configuredPaths := map[string]string{
		"http":   spec.HTTPServicePath,
		"https":  spec.HTTPSServicePath,
		"ssh":    spec.SSHServicePath,
		"telnet": spec.TelnetServicePath,
	}
	for _, service := range webui.ServiceNames {
		configured := configuredPaths[service]
		if configured != "" && path == configured {
			if _, ok := f.state.Services[service]; ok {
				return service, true
			}
			return "", false
		}
	}
	return "", false
}

// renderM4300Page renders an M4300 Cheetah /v1 read page from state,
// ok=false if this model is not an M4300 (so the caller falls through).
// Mirrors Python VirtualHttpFace._render_m4300_page (faces/http.py:518-551).
func (f *HTTPFace) renderM4300Page(path string) (string, bool) {
	spec := f.spec
	switch {
	case path == spec.DashboardPath:
		return RenderM4300Ports(f.state, ""), true
	case path == spec.StatsPath:
		return RenderM4300PortStatistics(f.state), true
	case path == spec.PvidPath:
		return RenderM4300Pvids(f.state), true
	case path == spec.VlanConfigPath:
		return RenderM4300Vlans(f.state), true
	case path == spec.MacTablePath:
		return RenderM4300MacTable(f.state), true
	case path == spec.SysinfoPath:
		return RenderM4300Sysinfo(f.state), true
	case spec.UsersPath != "" && path == spec.UsersPath:
		return RenderXUIUsers(f.state, path), true
		// SyslogPath is deliberately NOT a case here: renderFastpathXUIPage
		// (checked before this function in dispatchRender/dispatchApplyAndRender)
		// already intercepts it for the M4300 dialect, both GET and POST -- see
		// that function's own doc comment.
	}
	// The M4300 serves http/https as PLAIN named forms and ssh/telnet as
	// XUI -- measured, see xeServiceFormFields.
	if service, ok := f.serviceFor(path); ok {
		if service == "http" || service == "https" {
			return RenderFormServicePage(f.state, path, service), true
		}
		return RenderXUIServicePage(f.state, path, service), true
	}
	switch {
	case spec.LLDPPath != "" && path == spec.LLDPPath:
		// lldpRemoteInventory.html is the SAME page (and the same XE cell
		// grid, with 1/0/N ifNames) on the M4300s as on gsm7252ps.
		return RenderXELLDP(f.state), true
	case spec.PoEStatusPath != "" && path == spec.PoEStatusPath:
		// The M4300-16X PoE page shares the gsm7252ps XE cell layout, but
		// watts=true: the M4300 firmware renders the power column in
		// decimal WATTS ("4.60"), not the gsm7252ps's integer mW. The 24X
		// has PoEStatusPath=="" and never reaches here. Mirrors Python's
		// exact call (web_gsm7252ps.render_poe(state, watts=True) with
		// every OTHER argument left at its XE default -- NOT M4300's own
		// iface/checkbox/path) -- in practice unreachable on the shipped
		// m4300-16x spec, where PoEStatusPath==PoEConfigPath, so
		// renderFastpathXUIPage's M4300 branch (which DOES use the
		// M4300-specific iface/checkbox/path) always intercepts this path
		// first; kept for exact structural fidelity with the Python source.
		return RenderXEPoEWith(f.state, true, "", xeIface, xePoECheckbox, "RESET", "/poeInterfaceConfiguration.html"), true
	default:
		return "", false
	}
}

// renderS3300Page renders an S3300-52X (gsm7228ps) read page from state,
// ok=false if this model is not the S3300 dialect (so the caller falls
// through). Ports/stats/PVIDs/VLANs/PoE/LLDP reuse the gsm7252ps XE
// renderers (same cell grid); only the MAC table (shifted columns, escaped
// 1/gN ports) and sysInfo (base MAC only) are S3300-specific. Mirrors
// Python VirtualHttpFace._render_s3300_page (faces/http.py:553-584).
func (f *HTTPFace) renderS3300Page(path string) (string, bool) {
	spec := f.spec
	switch path {
	case spec.DashboardPath:
		return RenderS3300Ports(f.state, ""), true
	case spec.StatsPath:
		return RenderXEPortStatistics(f.state), true
	case spec.PvidPath:
		return RenderXEPvids(f.state), true
	case spec.VlanConfigPath:
		return RenderS3300Vlans(f.state), true
	case spec.MacTablePath:
		return RenderS3300MacTable(f.state), true
	case spec.PoEStatusPath:
		return RenderS3300PoE(f.state, ""), true
	case spec.LLDPPath:
		return RenderXELLDP(f.state), true
	case spec.SysinfoPath:
		return RenderS3300Sysinfo(f.state), true
	case spec.SyslogPath:
		return RenderXUISyslog(f.state, path, ""), true
	default:
		return "", false
	}
}

// renderXEPage renders a GSM7252PS XE FASTPATH read page from state,
// ok=false if this model is not XE (so the caller falls through). Mirrors
// Python VirtualHttpFace._render_xe_page (faces/http.py:586-614).
func (f *HTTPFace) renderXEPage(path string) (string, bool) {
	spec := f.spec
	switch path {
	case spec.DashboardPath:
		return RenderXEPorts(f.state, ""), true
	case spec.StatsPath:
		return RenderXEPortStatistics(f.state), true
	case spec.PvidPath:
		return RenderXEPvids(f.state), true
	case spec.VlanConfigPath:
		return RenderXEVlans(f.state), true
	case spec.MacTablePath:
		return RenderXEMacTable(f.state), true
	case spec.PoEStatusPath:
		return RenderXEPoE(f.state, ""), true
	case spec.LLDPPath:
		return RenderXELLDP(f.state), true
	case spec.SysinfoPath:
		return RenderXESysinfo(f.state), true
	case spec.UsersPath:
		return RenderXUIUsers(f.state, path), true
	case spec.SyslogPath:
		return RenderXUISyslog(f.state, path, ""), true
	}
	// gsm7252ps renders ALL FOUR service pages as XUI (unlike the M4300).
	if service, ok := f.serviceFor(path); ok {
		return RenderXUIServicePage(f.state, path, service), true
	}
	return "", false
}

// renderGS110EMXPage renders one of the GAMBIT token-session model's known
// GET/POST paths from state, mirroring Python VirtualHttpFace._render_token_page
// (faces/http.py:616-642) -- gs110emx's ENTIRE known-path set is covered
// here (never falls through to renderStandardPage), so the HTTP face serves
// the FULL NSDP read surface (ports/stats/VLANs/PVIDs/mgmt-IP) real hardware
// does. form carries the VLAN_ID for a vlanMembership POST. Any path not
// populated in the spec 404s honestly before this is ever called (f.known
// already gates on the spec's populated fields).
func (f *HTTPFace) renderGS110EMXPage(path string, form map[string]string) string {
	spec := f.spec
	switch path {
	case spec.SysinfoPath:
		// The sysInfo POST carries capital-"Apply" (its own
		// submitSwitchInfoForm() sets form1.elements["ACTION"].value =
		// "Apply") -- deliberately NOT the lowercase "apply" the
		// port_settings.html AJAX apply sends (see ApplyGS110EMXPortSettings
		// below); both spellings are real, per page.
		if form["ACTION"] == "Apply" {
			return ApplyGS110EMXSysinfo(f.state, f.token, form)
		}
		return RenderGS110EMXSysinfo(f.state, f.token)
	case spec.StatsPath:
		return RenderGS110EMXInterfaceStats(f.state, f.token)
	case spec.DashboardPath:
		// Same URL for read and write on this model. An apply POST (ACTION=
		// apply) is answered with the firmware's bare SUCCESS body, NOT a
		// re-rendered page -- reproducing that is what lets the library's
		// GS110EMX apply-verification be exercised without hardware.
		if form["ACTION"] == "apply" {
			return ApplyGS110EMXPortSettings(f.state, form)
		}
		return RenderGS110EMXPortSettings(f.state, f.token)
	case spec.PvidPath:
		return RenderGS110EMXPvid(f.state, f.token)
	case spec.VlanConfigPath:
		return RenderGS110EMXCf8021q(f.state, f.token)
	case spec.VlanMembershipPath:
		vid, err := strconv.Atoi(form["VLAN_ID"])
		if err != nil {
			vid = 1
		}
		return RenderGS110EMXVlanMembership(f.state, f.token, vid)
	default:
		return notFoundBody
	}
}

// renderGS105PEPage renders a GS105PE read page from state, mirroring Python
// VirtualHttpFace._render_gs105pe_page (faces/http.py:408-436): ok=false
// means this path is not one of gs105pe's own pages, so the caller falls
// through to the STANDARD-dialect renderer -- unreachable in practice since
// this model's own known-path set (dossier §3.3 step 4) is a strict subset
// of the branches below, but mirrored for exact structural fidelity with the
// Python source (a future path added to gs105peSpec without a matching case
// here would silently fall through rather than panic, exactly as Python's
// `return None` does).
//
// A GET (no VLAN_ID) shows the lowest VLAN, matching real firmware; a POST
// selects the requested one. Without this dispatch, a gs105pe VirtualSwitch
// fell through to the STANDARD renderer whose permissive catch-all returns a
// fabricated 200 -- the mock silently reported every port DOWN while the
// seed had ports 3 and 5 UP, exactly the "mock must never fabricate" rule
// this face's package doc comment states.
func (f *HTTPFace) renderGS105PEPage(path string, form map[string]string) (string, bool) {
	spec := f.spec
	switch path {
	case spec.DashboardPath:
		return RenderGS105PEStatus(f.state), true
	case spec.StatsPath:
		return RenderGS105PEPortStatistics(f.state), true
	case spec.PvidPath:
		return RenderGS105PEPvid(f.state), true
	case spec.VlanConfigPath:
		return RenderGS105PEVlanConfig(f.state), true
	case spec.SysinfoPath:
		return RenderGS105PESwitchInfo(f.state), true
	case spec.VlanMembershipPath:
		vid, err := strconv.Atoi(form["VLAN_ID"])
		if err != nil || vid == 0 {
			vid = lowestVlanID(f.state, 1)
		}
		return RenderGS105PEVlanMembership(f.state, vid), true
	default:
		return "", false
	}
}

// lowestVlanID returns the lowest VLAN ID in state.Vlans, or fallback if
// state.Vlans is empty, mirroring Python's `min(self.state.vlans,
// default=1)`.
func lowestVlanID(state *State, fallback int) int {
	keys := sortedIntKeys(state.Vlans)
	if len(keys) == 0 {
		return fallback
	}
	return keys[0]
}

// hashInput is web.py's _hash_input(): the constant CSRF `hash` field
// spliced into every STANDARD-dialect writable/dashboard page. Never
// validated anywhere -- write-only decoration proving the round-trip shape.
func hashInput() string {
	return fmt.Sprintf(`<input type="hidden" name="hash" value="%s">`, virtualHTTPCSRFHash)
}

// renderStandardPage is the STANDARD dialect's (gs305ep only) generic page
// renderer, ported field-for-field from Python web.py's render_page
// (lines 42-60). dispatchRender/dispatchApplyAndRender only ever call this
// under HTMLDialectStandard -- every other dialect is routed to its own
// per-dialect renderer instead (gs105pe, though it shared these pages when
// Task 8 first landed, has had its own renderGS105PEPage since Task 9), so
// this function is reachable ONLY for STANDARD-dialect paths. The final `return` is still
// DELIBERATELY PERMISSIVE within that STANDARD scope (an "OK" catch-all for
// any known-but-unhandled STANDARD path, e.g. a POE apply target that has
// no distinct status view) -- exactly as web.py's own module docstring
// warns.
func (f *HTTPFace) renderStandardPage(path string, form map[string]string) string {
	spec := f.spec
	switch path {
	case spec.DashboardPath:
		return f.renderDashboard()
	case spec.StatsPath:
		return f.renderStats()
	case spec.PoEStatusPath:
		return f.renderPoEStatus()
	case spec.PvidPath:
		return f.renderPvid()
	case spec.VlanConfigPath:
		return f.renderVlanConfig()
	case spec.VlanMembershipPath:
		vid, err := strconv.Atoi(form["VLAN_ID"])
		if err != nil || vid == 0 {
			vid = 1
		}
		return f.renderMembership(vid)
	case spec.PoEConfigPath:
		return "<html><body>" + hashInput() + "</body></html>"
	default:
		return "<html><body>OK" + hashInput() + "</body></html>"
	}
}

func (f *HTTPFace) renderDashboard() string {
	var b strings.Builder
	b.WriteString("<html><body>")
	b.WriteString(hashInput())
	b.WriteString("<table>")
	for _, p := range sortedIntKeys(f.state.Ports) {
		sim := f.state.Ports[p]
		linkText := "Down"
		if sim.Link {
			linkText = fmt.Sprintf("Up %dM", sim.Speed)
		}
		adminText := "Disabled"
		if sim.Admin {
			adminText = "Enabled"
		}
		fmt.Fprintf(&b, `<tr class="portID"><td><input type="checkbox"></td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			p, linkText, adminText, sim.Name)
	}
	b.WriteString("</table></body></html>")
	return b.String()
}

func (f *HTTPFace) renderStats() string {
	var b strings.Builder
	b.WriteString("<html><body><table>")
	for _, p := range sortedIntKeys(f.state.Ports) {
		sim := f.state.Ports[p]
		fmt.Fprintf(&b, `<tr class="portID"><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>`,
			p, u64OrZero(sim.RxOctets), u64OrZero(sim.TxOctets), u64OrZero(sim.RxErrors))
	}
	b.WriteString("</table></body></html>")
	return b.String()
}

// standardPoEDetectText mirrors web.py's module-level _DETECT_TEXT.
var standardPoEDetectText = map[int]string{3: "Delivering", 1: "Searching", 2: "Disabled", 4: "Fault"}

func (f *HTTPFace) renderPoEStatus() string {
	var b strings.Builder
	b.WriteString("<html><body>")
	b.WriteString(hashInput())
	b.WriteString("<table>")
	for _, p := range sortedIntKeys(f.state.Poe) {
		sim := f.state.Poe[p]
		detect := "Disabled"
		if sim.Admin {
			if t, ok := standardPoEDetectText[sim.Detect]; ok {
				detect = t
			}
		}
		fmt.Fprintf(&b, `<tr class="portID"><td>%d</td><td>%s</td><td>%d</td></tr>`, p, detect, sim.PowerMw)
	}
	b.WriteString("</table></body></html>")
	return b.String()
}

func (f *HTTPFace) renderPvid() string {
	var b strings.Builder
	b.WriteString("<html><body>")
	b.WriteString(hashInput())
	b.WriteString("<table>")
	for _, p := range sortedIntKeys(f.state.Ports) {
		pvid, ok := f.state.Pvids[p]
		if !ok {
			pvid = 1
		}
		fmt.Fprintf(&b, `<tr class="portID"><td><input type="checkbox" name="port%d"></td>`+
			`<td sel="text">%d<input type="hidden" value="1"></td><td sel="input">%d</td></tr>`,
			p-1, p, pvid)
	}
	b.WriteString("</table></body></html>")
	return b.String()
}

func (f *HTTPFace) renderVlanConfig() string {
	var b strings.Builder
	b.WriteString("<html><body>")
	b.WriteString(hashInput())
	for i, vid := range sortedIntKeys(f.state.Vlans) {
		fmt.Fprintf(&b, `<input type="checkbox" name="vlanck%d" value="%d">`, i, vid)
	}
	b.WriteString("</body></html>")
	return b.String()
}

func (f *HTTPFace) renderMembership(vid int) string {
	vsim := f.state.Vlans[vid]
	portCount := f.state.mustModel().PortCount
	chars := make([]byte, portCount)
	for i := range portCount {
		p := i + 1
		switch {
		case vsim == nil || !vsim.Member[p]:
			chars[i] = '3'
		case vsim.Untagged[p]:
			chars[i] = '1'
		default:
			chars[i] = '2'
		}
	}
	var opts strings.Builder
	for _, v := range sortedIntKeys(f.state.Vlans) {
		selected := ""
		if v == vid {
			selected = "selected "
		}
		fmt.Fprintf(&opts, `<option %svalue="%d">VLAN %d</option>`, selected, v, v)
	}
	return fmt.Sprintf(
		`<html><body><form>%s%s<input name="hiddenMem" id="hiddenMem" value="%s" type="hidden"></form></body></html>`,
		hashInput(), opts.String(), string(chars))
}

// standardPortFormKeyRE mirrors web.py's `re.fullmatch(r"port(\d+)", key)`
// scan, used by _apply_poe's Reset branch and _apply_pvid.
var standardPortFormKeyRE = regexp.MustCompile(`^port(\d+)$`)

// standardVlanckKeyRE mirrors web.py's `re.fullmatch(r"vlanck\d+", key)`.
var standardVlanckKeyRE = regexp.MustCompile(`^vlanck\d+$`)

// applyStandardForm is the STANDARD dialect's write dispatcher, ported
// field-for-field from Python web.py's apply_form (lines 143-153).
func (f *HTTPFace) applyStandardForm(path string, form map[string]string) {
	spec := f.spec
	if _, hasHiddenMem := form["hiddenMem"]; path == spec.PoEConfigPath {
		f.applyPoE(form)
	} else if path == spec.PvidPath {
		f.applyPvid(form)
	} else if path == spec.VlanMembershipPath && hasHiddenMem {
		f.applyMembership(form)
	} else if path == spec.VlanConfigPath {
		f.applyVlanConfig(form)
	}
}

func (f *HTTPFace) applyPoE(form map[string]string) {
	switch form["ACTION"] {
	case "Apply":
		portIDStr, ok := form["portID"]
		if !ok {
			return
		}
		portID, err := strconv.Atoi(portIDStr)
		if err != nil {
			return
		}
		sim, exists := f.state.Poe[portID+1]
		if !exists {
			return
		}
		on := form["ADMIN_MODE"] == "1"
		sim.Admin = on
		if on {
			sim.Detect = 3
		} else {
			sim.Detect = 1
		}
	case "Reset":
		for key := range form {
			m := standardPortFormKeyRE.FindStringSubmatch(key)
			if m == nil {
				continue
			}
			n, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			if sim, exists := f.state.Poe[n+1]; exists {
				if sim.Admin {
					sim.Detect = 3
				} else {
					sim.Detect = 1
				}
			}
		}
	}
}

func (f *HTTPFace) applyPvid(form map[string]string) {
	vlan, err := strconv.Atoi(form["pvid"])
	if err != nil || vlan <= 0 {
		return
	}
	for key := range form {
		m := standardPortFormKeyRE.FindStringSubmatch(key)
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		f.state.Pvids[n+1] = vlan
	}
}

func (f *HTTPFace) applyMembership(form map[string]string) {
	vid, err := strconv.Atoi(form["VLAN_ID"])
	if err != nil {
		return
	}
	vsim, exists := f.state.Vlans[vid]
	if !exists {
		return
	}
	hidden := form["hiddenMem"]
	member := map[int]bool{}
	untagged := map[int]bool{}
	for i := 0; i < len(hidden); i++ {
		port := i + 1
		switch hidden[i] {
		case '1':
			member[port] = true
			untagged[port] = true
		case '2':
			member[port] = true
		}
	}
	vsim.Member = member
	vsim.Untagged = untagged
}

func (f *HTTPFace) applyVlanConfig(form map[string]string) {
	switch form["ACTION"] {
	case "Add":
		vidStr, ok := form["ADD_VLANID"]
		if !ok {
			return
		}
		vid, err := strconv.Atoi(vidStr)
		if err != nil {
			return
		}
		if _, exists := f.state.Vlans[vid]; !exists {
			f.state.Vlans[vid] = &VlanSim{Name: ""}
		}
	case "Delete":
		for key, val := range form {
			if !standardVlanckKeyRE.MatchString(key) {
				continue
			}
			if vid, err := strconv.Atoi(val); err == nil {
				delete(f.state.Vlans, vid)
			}
		}
	}
}
