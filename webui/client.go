package webui

// Ported field-for-field from
// src/netgear_switch/transport/http/client.py at pin 1841111 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1841111): HttpClient/AsyncHttpClient collapse into one Go
// type, HTTPClient, implementing the Session interface (types.go) --
// context.Context-first parameters cover what Python needed two classes
// (sync httpx.Client / async httpx.AsyncClient) for (dossier D-HTTP-P
// §6/§7.4). Any discrepancy between this file and that pin is a bug in this
// file, not a deliberate deviation, unless called out in a comment.
//
// net/http equivalents of the httpx knobs (dossier §6.1/§7.1):
//   - 15s timeout (http.Client.Timeout).
//   - No keep-alive (http.Transport.DisableKeepAlives=true -- NOT
//     MaxIdleConnsPerHost=0, which has looser semantics): real Plus
//     hardware aggressively closes idle keep-alive connections, so a
//     pooled connection is often already dead by the next request.
//   - TLS verification off by default (self-signed switch certs).
//   - A fresh cookiejar.Jar PER CLIENT INSTANCE (never shared across
//     switches -- that would leak SID cookies between hosts).
//   - follow_redirects=True by default, except the XML_API login's first
//     GET, which uses CheckRedirect: http.ErrUseLastResponse to read the
//     302's Location header itself (doGoAheadRedirectGET).
//
// Login dispatch (Login): every scheme except LoginSchemeXMLAPI shares one
// GET-then-POST flow (loginStandard) -- even LoginSchemeCheetahForm, whose
// dossier §1.1 prose says "no GET-for-nonce step": that describes the
// SCHEME's wire semantics (no nonce is scraped), not the literal request
// sequence -- client.py's login() unconditionally GETs login_path first for
// every non-XML_API scheme, and loginBody's CHEETAH_FORM branch simply
// never reads the fetched page text. Preserved here on purpose, verified
// against the actual pin source (not just the dossier's prose summary).
//
// Error wrapping mirrors client.py's two shapes exactly (source lines
// 344-345, 374-375 etc.): a GENUINE transport failure (net/http returning
// an error instead of a response, or a body read failing) is wrapped as
// "<context> transport error: <err>" (login's GET+POST share ONE generic
// "web-UI login transport error: <err>" instead, since Python wraps both
// under a single try/except); an HTTP status >=400 or a stale-session
// "redirect to login" body is validateResponse's job and is NEVER
// re-wrapped as a transport error (it is a different Python exception type
// that the surrounding try/except does not catch).

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
)

// httpClientTimeout is Go's equivalent of client.py's module-level
// _TIMEOUT = 15.0 (dossier §6.1).
const httpClientTimeout = 15 * time.Second

// droppedConnectionRetries is client.py's _DROPPED_CONNECTION_RETRIES: up to
// 2 retries (3 attempts total) of a GET whose connection was dropped mid-
// request -- see isDroppedConnection and getWithRetry (dossier §6.4).
const droppedConnectionRetries = 2

// ClientOption configures NewHTTPClient beyond its required host/password/
// spec triple, mirroring Python HttpClient.__init__'s keyword-only
// secure/verify_tls/transport parameters (dossier §6.1). secure is
// deliberately NOT an option here: it comes from spec.Secure exactly like
// Python's _referer_headers(spec, host, secure=secure) call derives scheme
// from the spec, not a separately-threaded flag -- the two always agree in
// every real caller, so a second knob here would let them drift.
type ClientOption func(*clientConfig)

type clientConfig struct {
	verifyTLS bool
	transport http.RoundTripper
}

// WithVerifyTLS enables TLS certificate verification (default off, matching
// Python's verify_tls=False default -- every switch web UI this library
// talks to uses a self-signed certificate).
func WithVerifyTLS(verify bool) ClientOption {
	return func(c *clientConfig) { c.verifyTLS = verify }
}

// WithTransport replaces the underlying http.RoundTripper entirely -- the
// Go equivalent of Python's transport=httpx.MockTransport(...) constructor
// parameter (dossier §6.1): a unit-test seam for controlling the wire
// (e.g. simulating a dropped connection deterministically) without a real
// server. When set, NewHTTPClient does NOT layer DisableKeepAlives/TLS
// config on top -- the caller owns the whole RoundTripper, exactly as
// passing transport= bypasses httpx's own Limits/verify handling.
func WithTransport(rt http.RoundTripper) ClientOption {
	return func(c *clientConfig) { c.transport = rt }
}

// HTTPClient is the net/http-backed Session (types.go) for one switch's web
// UI, mirroring Python HttpClient/AsyncHttpClient (dossier §6). One
// instance owns one login session (one cookie jar, one Gambit token slot,
// one GoAhead session path) for one host -- never share an HTTPClient, or
// its jar, across switches.
type HTTPClient struct {
	spec     *HTTPModelSpec
	password string
	baseURL  string // "<scheme>://<host>", no trailing slash

	// refererHeader/originHeader are "" unless spec.NeedsReferer -- computed
	// once at construction and sent on EVERY request (dossier §6.6): Go's
	// http.Client has no per-client default-header hook the way httpx does,
	// so newRequest sets them explicitly on every request it builds instead
	// of via a shared RoundTripper wrapper.
	refererHeader string
	originHeader  string

	client *http.Client

	mu          sync.Mutex
	loggedIn    bool
	token       string // Gambit session token (LoginSchemeGambit only)
	sessionPath string // GoAhead per-session URL path (LoginSchemeXMLAPI only)
}

var _ Session = (*HTTPClient)(nil)

// NewHTTPClient constructs a Session for one switch's web UI, mirroring
// Python HttpClient.__init__ (dossier §6.1). host is a scheme-less
// "ip[:port]" (the eventual http_backend.go builder forms "ip:49152" for
// m4300-16x per spec.WebPort before calling this -- this constructor takes
// host as-is, exactly like Python's constructor takes its host argument).
// password is the plaintext switch password; spec selects the login
// scheme/dialect/paths (see HTTPSpec).
func NewHTTPClient(host, password string, spec *HTTPModelSpec, opts ...ClientOption) *HTTPClient {
	cfg := clientConfig{verifyTLS: false}
	for _, opt := range opts {
		opt(&cfg)
	}

	scheme := "http"
	if spec.Secure {
		scheme = "https"
	}

	transport := cfg.transport
	if transport == nil {
		transport = &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !cfg.verifyTLS, //nolint:gosec // switch web UIs use self-signed certs; matches Python's verify=False default.
			},
		}
	}

	// nil PublicSuffixList: this jar is scoped to exactly one host for
	// exactly one HTTPClient's lifetime (dossier §7.1's "per session, never
	// per process" -- never share this jar across switches).
	jar, _ := cookiejar.New(nil)

	var referer, origin string
	if spec.NeedsReferer {
		referer = fmt.Sprintf("%s://%s/", scheme, host)
		origin = fmt.Sprintf("%s://%s", scheme, host)
	}

	return &HTTPClient{
		spec:          spec,
		password:      password,
		baseURL:       scheme + "://" + host,
		refererHeader: referer,
		originHeader:  origin,
		client: &http.Client{
			Timeout:   httpClientTimeout,
			Transport: transport,
			Jar:       jar,
		},
	}
}

// Close releases idle connections. Not part of the Session interface (Go's
// http.Client needs no explicit close the way httpx.Client does), but
// provided for callers that want to be tidy -- mirrors client.py's
// close()/__exit__, which is "just self._client.close(); no other
// teardown".
func (c *HTTPClient) Close() {
	c.client.CloseIdleConnections()
}

// ---------------------------------------------------------------------
// Session state (loggedIn/token/sessionPath), guarded by mu.
// ---------------------------------------------------------------------

func (c *HTTPClient) isLoggedIn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loggedIn
}

func (c *HTTPClient) setLoggedIn(token, sessionPath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loggedIn = true
	c.token = token
	c.sessionPath = sessionPath
}

func (c *HTTPClient) getToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

func (c *HTTPClient) getSessionPath() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionPath
}

// ---------------------------------------------------------------------
// Login (dossier §1.1/§6.2/§6.3/§6.8)
// ---------------------------------------------------------------------

// Login performs this model's login handshake, mirroring Python
// HttpClient.login (source lines 333-350) dispatching to _xml_api_login
// for LoginSchemeXMLAPI and the shared GET-then-POST flow for the other
// four schemes.
func (c *HTTPClient) Login(ctx context.Context) error {
	if c.spec.Scheme == LoginSchemeXMLAPI {
		return c.loginXMLAPI(ctx)
	}
	return c.loginStandard(ctx)
}

// ensureLoggedIn mirrors every Session method's own "if not self._logged_in:
// self.login()" guard (source lines 366-367 etc.).
func (c *HTTPClient) ensureLoggedIn(ctx context.Context) error {
	if c.isLoggedIn() {
		return nil
	}
	return c.Login(ctx)
}

// loginStandard is the shared MERGE_HASH_CGI/GAMBIT/CHEETAH_FORM/CHEETAH_V1
// flow, mirroring Python HttpClient.login's non-XML_API branch (source
// lines 337-350) exactly: GET spec.LoginPath, build the scheme-specific
// body from that page's HTML, POST it to (LoginPostPath or LoginPath), then
// check for a session cookie or a Gambit token depending on the scheme.
func (c *HTTPClient) loginStandard(ctx context.Context) error {
	resp, err := c.doRequest(ctx, http.MethodGet, c.spec.LoginPath, nil, "")
	if err != nil {
		return errHTTPCause(err, "web-UI login transport error")
	}
	pageText, rerr := readBody(resp)
	_ = resp.Body.Close()
	if rerr != nil {
		return errHTTPCause(rerr, "web-UI login transport error")
	}
	if err := validateResponse(resp.StatusCode, pageText, fmt.Sprintf("GET %s", c.spec.LoginPath), ""); err != nil {
		return err
	}

	body, err := c.loginBody(pageText)
	if err != nil {
		return err
	}

	postPath := c.spec.LoginPostPath
	if postPath == "" {
		postPath = c.spec.LoginPath
	}

	resp2, err := c.doRequest(ctx, http.MethodPost, postPath, strings.NewReader(encodeForm(body)), "application/x-www-form-urlencoded")
	if err != nil {
		return errHTTPCause(err, "web-UI login transport error")
	}
	respText, rerr := readBody(resp2)
	_ = resp2.Body.Close()
	if rerr != nil {
		return errHTTPCause(rerr, "web-UI login transport error")
	}
	if err := validateResponse(resp2.StatusCode, respText, fmt.Sprintf("POST %s", postPath), ""); err != nil {
		return err
	}

	if c.spec.SessionTokenField != "" {
		token, ok := ParseGambitToken(respText)
		if !ok || token == "" {
			return errHTTPAuth("web-UI login failed for %s -- no %s token returned (check password, or switch may be locked out)",
				c.spec.ModelKey, c.spec.SessionTokenField)
		}
		c.setLoggedIn(token, "")
		return nil
	}

	if !c.hasCookie(c.spec.CookieName) {
		return errHTTPAuth("web-UI login failed for %s -- no %s cookie (check password, or switch may be locked out)",
			c.spec.ModelKey, c.spec.CookieName)
	}
	c.setLoggedIn("", "")
	return nil
}

// loginBody builds the login POST body for c.spec given the login page's
// HTML, mirroring Python _login_body (source lines 60-100) exactly.
func (c *HTTPClient) loginBody(loginPageHTML string) (map[string]string, error) {
	spec := c.spec
	switch spec.Scheme {
	case LoginSchemeCheetahV1:
		// M4300 /v1: plaintext username + password, no nonce. The AV-era
		// 16X firmware issues a per-page CSRFToken and binds the session
		// cookie to it (older 24X firmware has no such field), so include
		// it only when present.
		unameField := spec.UsernameField
		if unameField == "" {
			unameField = "uname"
		}
		body := map[string]string{
			unameField:         spec.Username,
			spec.PasswordField: c.password,
		}
		if token, ok := cheetahCSRFToken(loginPageHTML); ok {
			body["CSRFToken"] = token
		}
		return body, nil
	case LoginSchemeCheetahForm:
		body := map[string]string{spec.PasswordField: c.password}
		if spec.UsernameField != "" {
			body[spec.UsernameField] = spec.Username
		}
		return body, nil
	default: // LoginSchemeMergeHashCGI, LoginSchemeGambit
		var rand string
		if spec.NeedsRand {
			if r, ok := ParseLoginRand(loginPageHTML); ok {
				rand = r
			}
			if rand == "" {
				return nil, errUnexpectedPage("no login 'rand' nonce on %s -- not a %s?", spec.LoginPath, spec.ModelKey)
			}
		}
		hashed := MergeHashMD5(c.password, rand)
		return map[string]string{spec.PasswordField: hashed}, nil
	}
}

// cheetahCSRFTokenNameFirstRE/cheetahCSRFTokenValueFirstRE together mirror
// Python client.py's _CHEETAH_CSRF_RE (source lines 44-48): the M4300
// Cheetah login form's CSRFToken hidden input, whose attribute order
// (name= before value=, or the reverse) varies by firmware. Two separate
// regexes tried in order -- the same "alternated regex" idiom
// parse_standard.go's ParseSelectedVlan already uses -- rather than one
// combined-alternation regex, which would make it ambiguous (via Go's
// FindStringSubmatch) whether an unmatched vs. an empty-string capture
// group fired.
var (
	cheetahCSRFTokenNameFirstRE  = regexp.MustCompile(`(?i)name=["']?CSRFToken["']?[^>]*?value=["']([^"']*)["']`)
	cheetahCSRFTokenValueFirstRE = regexp.MustCompile(`(?i)value=["']([^"']*)["'][^>]*?name=["']?CSRFToken["']?`)
)

// cheetahCSRFToken scrapes the M4300 login form's CSRFToken value, or
// ok=false if the form has no such field (older 24X firmware).
func cheetahCSRFToken(html string) (string, bool) {
	if m := cheetahCSRFTokenNameFirstRE.FindStringSubmatch(html); m != nil {
		return m[1], true
	}
	if m := cheetahCSRFTokenValueFirstRE.FindStringSubmatch(html); m != nil {
		return m[1], true
	}
	return "", false
}

// xmlAPISessionPathRE mirrors Python's _XML_API_SESSION_PATH_RE (source
// line 106): pulls the opaque per-session path segment out of the GoAhead
// login redirect's Location header, e.g. "/cs5f72b8e1/..." -> "cs5f72b8e1".
var xmlAPISessionPathRE = regexp.MustCompile(`/([A-Za-z0-9]+)/`)

// xmlAPISessionPath mirrors Python _xml_api_session_path (source lines
// 109-119).
func xmlAPISessionPath(spec *HTTPModelSpec, resp *http.Response) (string, error) {
	location := resp.Header.Get("Location")
	m := xmlAPISessionPathRE.FindStringSubmatch(location)
	if m == nil {
		return "", errHTTPAuth("%s login: GET %s gave no session-path redirect (Location=%q)", spec.ModelKey, spec.LoginPath, location)
	}
	return m[1], nil
}

// loginXMLAPI is the GS728TPP GoAhead three-step handshake, mirroring
// Python HttpClient._xml_api_login (source lines 352-363) exactly: GET
// login_path WITHOUT following the redirect to capture its session-path
// Location header, GET the session-scoped System.xml login query, then
// validate the body's <statusCode>0</statusCode> + sessionID response
// header and set the three cookies the firmware itself never does.
func (c *HTTPClient) loginXMLAPI(ctx context.Context) error {
	resp, err := c.doRequestNoRedirect(ctx, c.spec.LoginPath)
	if err != nil {
		return errHTTPCause(err, "web-UI login transport error")
	}
	sessionPath, perr := xmlAPISessionPath(c.spec, resp)
	_ = resp.Body.Close()
	if perr != nil {
		return perr
	}

	loginURL := fmt.Sprintf("/%s/System.xml?action=login&user=%s&password=%s",
		sessionPath, url.QueryEscape(c.spec.Username), url.QueryEscape(c.password))

	resp2, err := c.doRequest(ctx, http.MethodGet, loginURL, nil, "")
	if err != nil {
		return errHTTPCause(err, "web-UI login transport error")
	}
	text, rerr := readBody(resp2)
	_ = resp2.Body.Close()
	if rerr != nil {
		return errHTTPCause(rerr, "web-UI login transport error")
	}
	if err := validateResponse(resp2.StatusCode, text, "GET System.xml?action=login", ""); err != nil {
		return err
	}

	if !strings.Contains(text, "<statusCode>0</statusCode>") {
		return errHTTPAuth("web-UI login failed for %s -- no <statusCode>0</statusCode> (check password, or switch may be locked out)", c.spec.ModelKey)
	}
	sessionID := resp2.Header.Get("sessionID")
	if sessionID == "" {
		return errHTTPAuth("web-UI login failed for %s -- no sessionID response header", c.spec.ModelKey)
	}

	c.setCookie("userStatus", "ok")
	c.setCookie("usernme", c.spec.Username) // sic -- the firmware's own real (misspelled) cookie name, preserved verbatim
	c.setCookie(c.spec.CookieName, sessionID)
	c.setLoggedIn("", sessionPath)
	return nil
}

// ---------------------------------------------------------------------
// The five Session methods (dossier §6.8)
// ---------------------------------------------------------------------

// readURL prefixes path with the captured GoAhead session path for
// LoginSchemeXMLAPI, mirroring Python HttpClient._read_url (source lines
// 315-320); every other scheme passes path through unchanged.
func (c *HTTPClient) readURL(path string) string {
	if c.spec.Scheme == LoginSchemeXMLAPI {
		return "/" + c.getSessionPath() + "/" + path
	}
	return path
}

// GetPage fetches path (mirroring Python get_page, source lines 365-377):
// applies the session-path prefix / Gambit token query param, then GETs
// with up to droppedConnectionRetries retries on a genuinely dropped
// connection (never on an HTTP error status -- see getWithRetry).
func (c *HTTPClient) GetPage(ctx context.Context, path string) (string, error) {
	if err := c.ensureLoggedIn(ctx); err != nil {
		return "", err
	}
	reqPath := c.readURL(path)
	if c.spec.SessionTokenField != "" {
		reqPath = appendQueryParam(reqPath, c.spec.SessionTokenField, c.getToken())
	}
	status, text, err := c.getWithRetry(ctx, reqPath, path)
	if err != nil {
		return "", err
	}
	if err := validateResponse(status, text, fmt.Sprintf("GET %s", path), path); err != nil {
		return "", err
	}
	return text, nil
}

// PostForm submits data as an application/x-www-form-urlencoded POST to
// path, mirroring Python post_form (source lines 379-393). NEVER retried
// (dossier §6.4): a dropped connection during a write does not prove the
// switch ignored it.
func (c *HTTPClient) PostForm(ctx context.Context, path string, data map[string]string) (string, error) {
	if err := c.ensureLoggedIn(ctx); err != nil {
		return "", err
	}
	body := mergeTokenField(c.spec, c.getToken(), data)
	status, text, err := c.postOnce(ctx, path, strings.NewReader(encodeForm(body)), "application/x-www-form-urlencoded")
	if err != nil {
		return "", err
	}
	if err := validateResponse(status, text, fmt.Sprintf("POST %s", path), ""); err != nil {
		return "", err
	}
	return text, nil
}

// PostMultipart submits data plus file as a multipart/form-data POST to
// path, mirroring Python post_multipart (source lines 395-409). NEVER
// retried, same rationale as PostForm.
func (c *HTTPClient) PostMultipart(ctx context.Context, path string, data map[string]string, file MultipartFile) (string, error) {
	if err := c.ensureLoggedIn(ctx); err != nil {
		return "", err
	}
	body := mergeTokenField(c.spec, c.getToken(), data)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range body {
		if err := mw.WriteField(k, v); err != nil {
			return "", errHTTPCause(err, "POST %s: encoding multipart field %q", path, k)
		}
	}
	// mime/multipart.Writer.CreateFormFile hardcodes
	// Content-Type: application/octet-stream, ignoring file.ContentType --
	// build the part header manually to preserve the caller's MIME type
	// (Python's httpx files={field: (filename, content, content_type)}
	// sends exactly the given content_type).
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, file.Field, file.Filename))
	h.Set("Content-Type", file.ContentType)
	part, err := mw.CreatePart(h)
	if err != nil {
		return "", errHTTPCause(err, "POST %s: creating multipart file part", path)
	}
	if _, err := part.Write(file.Content); err != nil {
		return "", errHTTPCause(err, "POST %s: writing multipart file content", path)
	}
	if err := mw.Close(); err != nil {
		return "", errHTTPCause(err, "POST %s: closing multipart writer", path)
	}

	status, text, err := c.postOnce(ctx, path, &buf, mw.FormDataContentType())
	if err != nil {
		return "", err
	}
	if err := validateResponse(status, text, fmt.Sprintf("POST %s", path), ""); err != nil {
		return "", err
	}
	return text, nil
}

// PostXML submits body as a raw "application/xml; charset=utf-8" POST to
// path (the GS728TPP GoAhead cert-upload flow), mirroring Python post_xml
// (source lines 411-429): the SAME session-path prefixing GetPage applies.
// NEVER retried, same rationale as PostForm.
func (c *HTTPClient) PostXML(ctx context.Context, path string, body string) (string, error) {
	if err := c.ensureLoggedIn(ctx); err != nil {
		return "", err
	}
	reqPath := c.readURL(path)
	status, text, err := c.postOnce(ctx, reqPath, strings.NewReader(body), "application/xml; charset=utf-8")
	if err != nil {
		return "", err
	}
	if err := validateResponse(status, text, fmt.Sprintf("POST %s", path), ""); err != nil {
		return "", err
	}
	return text, nil
}

// mergeTokenField mirrors Python _token_form_field (source lines 186-192):
// {} (here, a plain copy of data) for a cookie-session model, or data plus
// {SessionTokenField: token} for a token-session model (only
// LoginSchemeGambit today).
func mergeTokenField(spec *HTTPModelSpec, token string, data map[string]string) map[string]string {
	merged := make(map[string]string, len(data)+1)
	for k, v := range data {
		merged[k] = v
	}
	if spec.SessionTokenField != "" {
		merged[spec.SessionTokenField] = token
	}
	return merged
}

// appendQueryParam adds key=value to path's query string, mirroring Python
// _token_params (source lines 178-183) folded into the URL httpx's
// params=... kwarg would build. path may already contain a "?" (the
// GS728TPP GoAhead read paths carry a literal query already), so this
// appends with "&" in that case rather than assuming a bare path.
func appendQueryParam(path, key, value string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + key + "=" + url.QueryEscape(value)
}

// ---------------------------------------------------------------------
// Low-level request plumbing
// ---------------------------------------------------------------------

// newRequest builds a request for path (which must start with "/"),
// attaching the Referer/Origin headers baked in at construction when
// spec.NeedsReferer (dossier §6.6) -- Go's http.Client has no per-client
// default-header hook the way httpx.Client(headers=...) does, so every
// call site funnels through here instead.
func (c *HTTPClient) newRequest(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.spec.NeedsReferer {
		req.Header.Set("Referer", c.refererHeader)
		req.Header.Set("Origin", c.originHeader)
	}
	return req, nil
}

// doRequest sends one request via c.client (following redirects, per the
// default -- see doRequestNoRedirect for the one exception).
func (c *HTTPClient) doRequest(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := c.newRequest(ctx, method, path, body, contentType)
	if err != nil {
		return nil, err
	}
	return c.client.Do(req) //nolint:bodyclose // callers close resp.Body themselves (they need it before closing, to read the body).
}

// doRequestNoRedirect sends a GET that does NOT follow redirects, mirroring
// Python's follow_redirects=False on the XML_API login's first GET (dossier
// §6.1/§7.1): CheckRedirect: http.ErrUseLastResponse is Go's idiom for
// "give me the 3xx response itself". Reuses c.client's Transport/Jar/
// Timeout so this one-off client shares connection/cookie state.
func (c *HTTPClient) doRequestNoRedirect(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.newRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}
	noRedirect := &http.Client{
		Transport: c.client.Transport,
		Jar:       c.client.Jar,
		Timeout:   c.client.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return noRedirect.Do(req) //nolint:bodyclose // caller closes resp.Body.
}

// readBody fully reads and returns resp.Body as a string (httpx downloads
// the whole body eagerly by default; net/http requires an explicit read --
// this is that read, shared by every call site).
func readBody(resp *http.Response) (string, error) {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// encodeForm form-urlencodes data, mirroring httpx's data=... kwarg.
func encodeForm(data map[string]string) string {
	values := url.Values{}
	for k, v := range data {
		values.Set(k, v)
	}
	return values.Encode()
}

// ---------------------------------------------------------------------
// GET retry-on-dropped-connection (dossier §6.4/§7.1)
// ---------------------------------------------------------------------

// isDroppedConnection reports whether err looks like httpx.RemoteProtocolError
// -- a connection that was dropped mid-request (the server closed it before
// sending a full response) -- as opposed to any OTHER transport failure
// (DNS/dial failure, TLS handshake failure, timeout: httpx's
// ConnectError/TimeoutException family, which Python's retry helper does
// NOT catch and so does NOT retry). Only this narrower class is retried;
// see getWithRetry.
func isDroppedConnection(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "server closed idle connection")
}

// wrapTransportErr mirrors client.py's f"{method} {path} transport error:
// {exc}" message shape (e.g. source lines 374-375, 390-391).
func wrapTransportErr(method, path string, err error) error {
	return errHTTPCause(err, "%s %s transport error", method, path)
}

// attemptGet performs exactly one GET+body-read attempt against reqPath,
// returning the RAW (unwrapped) error so getWithRetry can classify it via
// isDroppedConnection before deciding whether to retry or wrap-and-return.
func (c *HTTPClient) attemptGet(ctx context.Context, reqPath string) (int, string, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, reqPath, nil, "")
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	text, err := readBody(resp)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, text, nil
}

// getWithRetry mirrors Python _retry_on_dropped_connection wired into
// get_page (source lines 213-223, 370-375): reqPath is the actual request
// URL (session-prefixed / token-suffixed); displayPath is the caller's
// original path, used in error messages exactly like Python's retry
// context uses the ORIGINAL path, not the rewritten url. A non-dropped-
// connection error is wrapped and returned immediately, with NO retry
// (matching Python: only httpx.RemoteProtocolError is caught by the retry
// loop at all -- any other httpx.HTTPError propagates straight out of the
// single attempt). Exhausting all droppedConnectionRetries+1 attempts on a
// genuinely dropped connection wraps the last error as "connection dropped
// by switch".
func (c *HTTPClient) getWithRetry(ctx context.Context, reqPath, displayPath string) (int, string, error) {
	var lastErr error
	for attempt := 0; attempt <= droppedConnectionRetries; attempt++ {
		status, text, err := c.attemptGet(ctx, reqPath)
		if err == nil {
			return status, text, nil
		}
		if !isDroppedConnection(err) {
			return 0, "", wrapTransportErr("GET", displayPath, err)
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return 0, "", errHTTPCause(lastErr, "GET %s: connection dropped by switch", displayPath)
}

// postOnce performs exactly one POST+body-read attempt, wrapping any
// transport failure immediately -- POST is NEVER retried (dossier §6.4).
func (c *HTTPClient) postOnce(ctx context.Context, path string, body io.Reader, contentType string) (int, string, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, path, body, contentType)
	if err != nil {
		return 0, "", wrapTransportErr("POST", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	text, err := readBody(resp)
	if err != nil {
		return 0, "", wrapTransportErr("POST", path, err)
	}
	return resp.StatusCode, text, nil
}

// ---------------------------------------------------------------------
// Shared response validation + cookie helpers
// ---------------------------------------------------------------------

// validateResponse mirrors Python _validate_response (source lines
// 268-283): status>=400 is always an error wrapping model.ErrHTTP; a
// non-empty path ALSO checks bodyText for a case-insensitive "redirect to
// login" substring (a mid-session soft-bounce back to the login page some
// firmware use instead of a hard 401/403), wrapping model.ErrHTTPAuth.
// path=="" (every login call site, and every post_*) skips that second
// check -- mirrors Python's path=None default.
func validateResponse(status int, bodyText, context, path string) error {
	if status >= 400 {
		return errHTTP("%s returned HTTP %d", context, status)
	}
	if path != "" && strings.Contains(strings.ToLower(bodyText), "redirect to login") {
		return errHTTPAuth("session lost fetching %s", path)
	}
	return nil
}

// errHTTPAuth wraps model.ErrHTTPAuth with a formatted message, the
// login/session-loss counterpart to types.go's errHTTP (which wraps the
// more general model.ErrHTTP).
func errHTTPAuth(format string, a ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, a...), model.ErrHTTPAuth)
}

// errHTTPCause wraps model.ErrHTTP AND cause (a Go 1.20+ multi-%w Errorf),
// so errors.Is matches either the general HTTP sentinel or the underlying
// transport/encoding error -- mirrors nsdp/client.go's errNSDPCause. Used
// for every genuine net/http (or stdlib encoding) failure client.go wraps;
// contrast types.go's errHTTP, used for logical/structural failures (a bad
// status code, a missing cookie) with no underlying Go error to preserve.
func errHTTPCause(cause error, format string, a ...any) error {
	return fmt.Errorf("%s: %w: %w", fmt.Sprintf(format, a...), model.ErrHTTP, cause)
}

// cookieURL is the URL every cookie-jar lookup/set uses: the client's own
// base origin's root path, which is where every login response sets its
// session cookie (default Path, per RFC 6265, is the directory of the
// request that set it -- every login_path used by this package is directly
// under "/").
func (c *HTTPClient) cookieURL() *url.URL {
	u, _ := url.Parse(c.baseURL + "/")
	return u
}

// hasCookie mirrors Python _check_authed's `spec.cookie_name not in
// cookies` check (source lines 155-160).
func (c *HTTPClient) hasCookie(name string) bool {
	for _, ck := range c.client.Jar.Cookies(c.cookieURL()) {
		if ck.Name == name {
			return true
		}
	}
	return false
}

// setCookie mirrors Python _apply_xml_api_login's cookies.set(...) calls
// (source lines 150-152): the GS728TPP GoAhead firmware never sends
// Set-Cookie itself, so the client sets these three into its own jar.
func (c *HTTPClient) setCookie(name, value string) {
	c.client.Jar.SetCookies(c.cookieURL(), []*http.Cookie{{Name: name, Value: value}})
}
