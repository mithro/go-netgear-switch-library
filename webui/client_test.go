package webui_test

// Real-loopback tests for webui.HTTPClient (client.go), mirroring the
// Python reference's tests/transport/test_http*.py: httptest.Server fakes
// emulate each of the 5 login schemes' actual wire handshake -- real TCP
// over the loopback interface, not an injected fake -- so Login/GetPage/
// PostForm/PostMultipart/PostXML are exercised end to end without a real
// switch. The GET-retry/POST-never-retry tests use webui.WithTransport as
// a lower-level unit-test seam (dossier D-HTTP-P §6.1's "transport=" test
// seam, mirroring httpx.MockTransport) since a dropped-mid-request
// connection is otherwise hard to trigger deterministically over a real
// socket.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// trimScheme strips "http://"/"https://" off a httptest.Server URL, giving
// the scheme-less "ip:port" host string webui.NewHTTPClient expects.
func trimScheme(rawURL string) string {
	return strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
}

// gs305epLoginHandler fakes the MERGE_HASH_CGI login.cgi handshake shared
// by gs305ep/gs105pe: GET returns the rand nonce, POST checks
// MergeHashMD5(password, rand) and sets cookieName=cookieValue on success
// (silently on failure -- callers construct a dedicated failure handler
// when they need to assert the no-cookie path).
func gs305epLoginHandler(password, rand, cookieName, cookieValue string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = fmt.Fprintf(w, `<input id="rand" value="%s">`, rand)
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if r.FormValue("password") != webui.MergeHashMD5(password, rand) {
				_, _ = fmt.Fprint(w, "bad login")
				return
			}
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: cookieValue, Path: "/"})
			_, _ = fmt.Fprint(w, "OK")
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// ---------------------------------------------------------------------
// MERGE_HASH_CGI (gs305ep/gs105pe): GET login.cgi -> scrape rand -> POST
// MergeHashMD5(password, rand) -> SID cookie -> every later request rides
// the cookie jar.
// ---------------------------------------------------------------------

func TestMergeHashCGILoginAndGetPage(t *testing.T) {
	const password, rand = "secret", "abc123def"
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", gs305epLoginHandler(password, rand, "SID", "sesh1"))
	mux.HandleFunc("/dashboard.cgi", func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie("SID"); err != nil || ck.Value != "sesh1" {
			http.Error(w, "no session", http.StatusForbidden)
			return
		}
		_, _ = fmt.Fprint(w, "DASHBOARD-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs305ep"])
	text, err := client.GetPage(context.Background(), "/dashboard.cgi")
	if err != nil {
		t.Fatalf("GetPage() = %v, want nil", err)
	}
	if text != "DASHBOARD-OK" {
		t.Errorf("GetPage() = %q, want %q", text, "DASHBOARD-OK")
	}
}

func TestMergeHashCGILoginNoCookieIsAuthError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprint(w, `<input id="rand" value="abc">`)
			return
		}
		_, _ = fmt.Fprint(w, "wrong password") // 200 OK, no Set-Cookie
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), "wrong", webui.HTTPSpecs["gs305ep"])
	err := client.Login(context.Background())
	if err == nil {
		t.Fatal("Login() = nil, want an error (no SID cookie set)")
	}
	if !errors.Is(err, model.ErrHTTPAuth) {
		t.Errorf("error = %v, want wrapping model.ErrHTTPAuth", err)
	}
}

func TestMergeHashCGILoginMissingRandIsUnexpectedPage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "<html>no rand field on this page</html>")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), "secret", webui.HTTPSpecs["gs305ep"])
	err := client.Login(context.Background())
	if err == nil {
		t.Fatal("Login() = nil, want an error (no rand nonce)")
	}
	if !errors.Is(err, model.ErrHTTPUnexpectedPage) {
		t.Errorf("error = %v, want wrapping model.ErrHTTPUnexpectedPage", err)
	}
}

// ---------------------------------------------------------------------
// GAMBIT (gs110emx): GET / for rand -> POST /redirect.html
// MergeHashMD5(password, rand) -> a Gambit TOKEN in the body (no cookie) ->
// every later GET carries ?Gambit=tok, every POST carries a Gambit field.
// ---------------------------------------------------------------------

func TestGambitLoginTokenThreadedOnGetAndPost(t *testing.T) {
	const password, rand, token = "secret", "xyz789", "tok-42"
	var gotGetQuery, gotPostForm url.Values
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `<input id="rand" value="%s">`, rand)
	})
	mux.HandleFunc("/redirect.html", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.FormValue("LoginPassword") != webui.MergeHashMD5(password, rand) {
			_, _ = fmt.Fprint(w, `<input type="hidden" name="Gambit" value="">`)
			return
		}
		_, _ = fmt.Fprintf(w, `<input type="hidden" name="Gambit" value="%s">`, token)
	})
	mux.HandleFunc("/iss/specific/port_settings.html", func(w http.ResponseWriter, r *http.Request) {
		gotGetQuery = r.URL.Query()
		_, _ = fmt.Fprint(w, "PORTS-OK")
	})
	mux.HandleFunc("/iss/specific/vlan_pvidsetting.html", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gotPostForm = r.Form
		_, _ = fmt.Fprint(w, "WRITE-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs110emx"])
	ctx := context.Background()

	text, err := client.GetPage(ctx, "/iss/specific/port_settings.html")
	if err != nil {
		t.Fatalf("GetPage() = %v, want nil", err)
	}
	if text != "PORTS-OK" {
		t.Errorf("GetPage() = %q, want %q", text, "PORTS-OK")
	}
	if got := gotGetQuery.Get("Gambit"); got != token {
		t.Errorf("GET ?Gambit= %q, want %q", got, token)
	}

	if _, err := client.PostForm(ctx, "/iss/specific/vlan_pvidsetting.html", map[string]string{"PVID": "5"}); err != nil {
		t.Fatalf("PostForm() = %v, want nil", err)
	}
	if got := gotPostForm.Get("Gambit"); got != token {
		t.Errorf("POST Gambit field = %q, want %q", got, token)
	}
	if got := gotPostForm.Get("PVID"); got != "5" {
		t.Errorf("POST PVID field = %q, want %q", got, "5")
	}
}

func TestGambitLoginRejectedIsAuthError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<input id="rand" value="xyz">`)
	})
	mux.HandleFunc("/redirect.html", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<input type="hidden" name="Gambit" value="">`) // rejected: empty token
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), "wrong", webui.HTTPSpecs["gs110emx"])
	err := client.Login(context.Background())
	if err == nil {
		t.Fatal("Login() = nil, want an error (empty Gambit token)")
	}
	if !errors.Is(err, model.ErrHTTPAuth) {
		t.Errorf("error = %v, want wrapping model.ErrHTTPAuth", err)
	}
}

// ---------------------------------------------------------------------
// CHEETAH_FORM (gsm7228ps/gsm7252ps): POST cheetah_login.html directly
// (password-only, or +username when the spec names a username_field) ->
// SID cookie. Both real specs in the registry set UsernameField="uname"
// (pinned by TestGSM7228PSSpec/TestGSM7252PSSpec in endpoints_test.go --
// this is the actual grounded HTTPModelSpec data this client.go must
// consume, not the dossier's own summary prose, which says gsm7228ps is
// password-only; the registry wins), so both are exercised here with a
// username. The password-only branch of loginBody (UsernameField=="") has
// no real spec today, so TestCheetahFormLoginPasswordOnlyBranch exercises
// it directly against a synthetic copy of a real spec.
// ---------------------------------------------------------------------

func TestCheetahFormLoginGsm7228ps(t *testing.T) {
	const password = "secret"
	mux := http.NewServeMux()
	mux.HandleFunc("/base/cheetah_login.html", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			_, _ = fmt.Fprint(w, "<html></html>")
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.FormValue("uname") != "admin" || r.FormValue("pwd") != password {
			http.Error(w, "bad", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "SID", Value: "sesh", Path: "/"})
	})
	mux.HandleFunc("/portsConfiguration.html", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "PORTS-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gsm7228ps"])
	text, err := client.GetPage(context.Background(), "/portsConfiguration.html")
	if err != nil {
		t.Fatalf("GetPage() = %v, want nil", err)
	}
	if text != "PORTS-OK" {
		t.Errorf("GetPage() = %q, want %q", text, "PORTS-OK")
	}
}

func TestCheetahFormLoginGsm7252ps(t *testing.T) {
	const password = "secret"
	mux := http.NewServeMux()
	mux.HandleFunc("/base/cheetah_login.html", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			_, _ = fmt.Fprint(w, "<html></html>")
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.FormValue("uname") != "admin" || r.FormValue("pwd") != password {
			http.Error(w, "bad", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "SID", Value: "sesh", Path: "/"})
	})
	mux.HandleFunc("/portsConfiguration.html", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "PORTS-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gsm7252ps"])
	text, err := client.GetPage(context.Background(), "/portsConfiguration.html")
	if err != nil {
		t.Fatalf("GetPage() = %v, want nil", err)
	}
	if text != "PORTS-OK" {
		t.Errorf("GetPage() = %q, want %q", text, "PORTS-OK")
	}
}

// TestCheetahFormLoginPasswordOnlyBranch exercises loginBody's
// UsernameField=="" branch directly: no CHEETAH_FORM model in the registry
// exercises it today (both gsm7228ps and gsm7252ps validate a username),
// but the branch is real code (mirrors Python _login_body's `if
// spec.username_field is not None`) and deserves direct coverage. Uses a
// local copy of gsm7228ps's spec with UsernameField cleared.
func TestCheetahFormLoginPasswordOnlyBranch(t *testing.T) {
	const password = "secret"
	spec := *webui.HTTPSpecs["gsm7228ps"]
	spec.UsernameField = ""

	mux := http.NewServeMux()
	mux.HandleFunc("/base/cheetah_login.html", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			_, _ = fmt.Fprint(w, "<html></html>")
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, hasUname := r.Form["uname"]; hasUname {
			t.Errorf("UsernameField==\"\" POST unexpectedly carried a uname field: %v", r.Form)
		}
		if r.FormValue("pwd") != password {
			http.Error(w, "bad", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "SID", Value: "sesh", Path: "/"})
	})
	mux.HandleFunc("/portsConfiguration.html", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "PORTS-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, &spec)
	text, err := client.GetPage(context.Background(), "/portsConfiguration.html")
	if err != nil {
		t.Fatalf("GetPage() = %v, want nil", err)
	}
	if text != "PORTS-OK" {
		t.Errorf("GetPage() = %q, want %q", text, "PORTS-OK")
	}
}

func TestCheetahFormLoginNoCookieIsAuthError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/base/cheetah_login.html", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "bad password page") // 200 OK, never sets SID
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), "wrong", webui.HTTPSpecs["gsm7228ps"])
	err := client.Login(context.Background())
	if err == nil {
		t.Fatal("Login() = nil, want an error (no SID cookie set)")
	}
	if !errors.Is(err, model.ErrHTTPAuth) {
		t.Errorf("error = %v, want wrapping model.ErrHTTPAuth", err)
	}
}

// ---------------------------------------------------------------------
// CHEETAH_V1 (m4300-24x/-16x): GET / (scrape optional CSRFToken) -> POST
// /v1/base/cheetah_login.html uname+pwd(+CSRFToken) -> SID/SIDSSL cookie;
// EVERY request carries Referer (+Origin) or 403.
// ---------------------------------------------------------------------

func TestCheetahV1LoginRefererOriginAndCSRFToken(t *testing.T) {
	const password = "secret"
	var mu sync.Mutex
	var gotReferers, gotOrigins []string
	record := func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotReferers = append(gotReferers, r.Header.Get("Referer"))
		gotOrigins = append(gotOrigins, r.Header.Get("Origin"))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		_, _ = fmt.Fprint(w, `<input name="CSRFToken" value="csrf-xyz">`)
	})
	mux.HandleFunc("/v1/base/cheetah_login.html", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.FormValue("uname") != "admin" || r.FormValue("pwd") != password || r.FormValue("CSRFToken") != "csrf-xyz" {
			http.Error(w, "bad login", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "SID", Value: "sesh", Path: "/"})
	})
	mux.HandleFunc("/v1/portsConfiguration.html", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Referer") == "" {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		_, _ = fmt.Fprint(w, "PORTS-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	host := trimScheme(server.URL)

	client := webui.NewHTTPClient(host, password, webui.HTTPSpecs["m4300-24x"])
	text, err := client.GetPage(context.Background(), "/v1/portsConfiguration.html")
	if err != nil {
		t.Fatalf("GetPage() = %v, want nil", err)
	}
	if text != "PORTS-OK" {
		t.Errorf("GetPage() = %q, want %q", text, "PORTS-OK")
	}

	wantReferer := "http://" + host + "/"
	wantOrigin := "http://" + host
	mu.Lock()
	defer mu.Unlock()
	if len(gotReferers) != 2 {
		t.Fatalf("recorded %d requests during login, want 2 (GET / + POST cheetah_login.html)", len(gotReferers))
	}
	for i, got := range gotReferers {
		if got != wantReferer {
			t.Errorf("request %d Referer = %q, want %q", i, got, wantReferer)
		}
	}
	for i, got := range gotOrigins {
		if got != wantOrigin {
			t.Errorf("request %d Origin = %q, want %q", i, got, wantOrigin)
		}
	}
}

func TestCheetahV1SecureSIDSSLCookieAndOptionalCSRFToken(t *testing.T) {
	const password = "secret"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "<html>older firmware, no CSRFToken field</html>")
	})
	mux.HandleFunc("/v1/base/cheetah_login.html", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.FormValue("uname") != "admin" || r.FormValue("pwd") != password {
			http.Error(w, "bad login", http.StatusForbidden)
			return
		}
		if _, ok := r.Form["CSRFToken"]; ok {
			t.Errorf("POST carried a CSRFToken field even though the login page had none: %v", r.Form)
		}
		http.SetCookie(w, &http.Cookie{Name: "SIDSSL", Value: "sesh16x", Path: "/"})
	})
	mux.HandleFunc("/v1/poeInterfaceConfiguration.html", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "POE-OK")
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	// spec.Secure=true (https) + TLS verify off by default (self-signed
	// cert) + CookieName="SIDSSL" (not "SID") -- all from the real
	// m4300-16x spec, unmodified.
	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["m4300-16x"])
	text, err := client.GetPage(context.Background(), "/v1/poeInterfaceConfiguration.html")
	if err != nil {
		t.Fatalf("GetPage() = %v, want nil", err)
	}
	if text != "POE-OK" {
		t.Errorf("GetPage() = %q, want %q", text, "POE-OK")
	}
}

// ---------------------------------------------------------------------
// XML_API (gs728tpp): GET / (no redirects followed) -> session-path from
// Location -> GET <sess>/System.xml?action=login -> statusCode 0 body +
// sessionID response header -> client sets userStatus/usernme/sessionID
// cookies itself; every later read/write is under /<sess>/.
// ---------------------------------------------------------------------

func TestXMLAPILoginGetPageAndPostXML(t *testing.T) {
	const password, sessionPath = "secret", "cs5f72b8e1"
	var gotContentType, gotBody string

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/"+sessionPath+"/")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/"+sessionPath+"/System.xml", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") != "login" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("user") != "admin" || r.URL.Query().Get("password") != password {
			_, _ = fmt.Fprint(w, "<statusCode>1</statusCode>")
			return
		}
		w.Header().Set("sessionID", "sid-999")
		_, _ = fmt.Fprint(w, "<statusCode>0</statusCode>")
	})
	mux.HandleFunc("/"+sessionPath+"/wcd", func(w http.ResponseWriter, r *http.Request) {
		userStatus, _ := r.Cookie("userStatus")
		usernme, _ := r.Cookie("usernme")
		sessionID, _ := r.Cookie("sessionID")
		if userStatus == nil || userStatus.Value != "ok" ||
			usernme == nil || usernme.Value != "admin" ||
			sessionID == nil || sessionID.Value != "sid-999" {
			http.Error(w, "missing session cookies", http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_, _ = fmt.Fprint(w, "WCD-OK")
		case http.MethodPost:
			gotContentType = r.Header.Get("Content-Type")
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			gotBody = string(body)
			_, _ = fmt.Fprint(w, "WCD-POST-OK")
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs728tpp"])
	ctx := context.Background()

	text, err := client.GetPage(ctx, "wcd")
	if err != nil {
		t.Fatalf("GetPage() = %v, want nil", err)
	}
	if text != "WCD-OK" {
		t.Errorf("GetPage() = %q, want %q", text, "WCD-OK")
	}

	text2, err := client.PostXML(ctx, "wcd", "<SSLCryptoCertificateImportList/>")
	if err != nil {
		t.Fatalf("PostXML() = %v, want nil", err)
	}
	if text2 != "WCD-POST-OK" {
		t.Errorf("PostXML() = %q, want %q", text2, "WCD-POST-OK")
	}
	if gotContentType != "application/xml; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", gotContentType, "application/xml; charset=utf-8")
	}
	if gotBody != "<SSLCryptoCertificateImportList/>" {
		t.Errorf("POST body = %q, want the literal XML", gotBody)
	}
}

func TestXMLAPILoginMissingLocationIsAuthError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "no redirect here")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), "secret", webui.HTTPSpecs["gs728tpp"])
	err := client.Login(context.Background())
	if err == nil {
		t.Fatal("Login() = nil, want an error (no session-path redirect)")
	}
	if !errors.Is(err, model.ErrHTTPAuth) {
		t.Errorf("error = %v, want wrapping model.ErrHTTPAuth", err)
	}
}

func TestXMLAPILoginWrongPasswordIsAuthError(t *testing.T) {
	const sessionPath = "cs1"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/"+sessionPath+"/")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/"+sessionPath+"/System.xml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "<statusCode>1</statusCode>")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), "wrong", webui.HTTPSpecs["gs728tpp"])
	err := client.Login(context.Background())
	if err == nil {
		t.Fatal("Login() = nil, want an error (statusCode != 0)")
	}
	if !errors.Is(err, model.ErrHTTPAuth) {
		t.Errorf("error = %v, want wrapping model.ErrHTTPAuth", err)
	}
}

func TestXMLAPILoginMissingSessionIDHeaderIsAuthError(t *testing.T) {
	const sessionPath = "cs2"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/"+sessionPath+"/")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/"+sessionPath+"/System.xml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "<statusCode>0</statusCode>") // success body, but no sessionID header
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), "secret", webui.HTTPSpecs["gs728tpp"])
	err := client.Login(context.Background())
	if err == nil {
		t.Fatal("Login() = nil, want an error (no sessionID header)")
	}
	if !errors.Is(err, model.ErrHTTPAuth) {
		t.Errorf("error = %v, want wrapping model.ErrHTTPAuth", err)
	}
}

// ---------------------------------------------------------------------
// Shared validateResponse behaviour (dossier §6.7): >=400 -> HttpError;
// mid-session "redirect to login" body -> HttpAuthError, GET only.
// ---------------------------------------------------------------------

func TestGetPageHTTPErrorOnStatus(t *testing.T) {
	const password, rand = "secret", "abc"
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", gs305epLoginHandler(password, rand, "SID", "sesh"))
	mux.HandleFunc("/broken.cgi", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs305ep"])
	_, err := client.GetPage(context.Background(), "/broken.cgi")
	if err == nil {
		t.Fatal("GetPage() = nil, want an error (HTTP 500)")
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want wrapping model.ErrHTTP", err)
	}
	if errors.Is(err, model.ErrHTTPAuth) {
		t.Errorf("error = %v, a 500 must NOT be classified as an auth error", err)
	}
}

func TestGetPageRedirectToLoginIsAuthError(t *testing.T) {
	const password, rand = "secret", "abc"
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", gs305epLoginHandler(password, rand, "SID", "sesh"))
	mux.HandleFunc("/stale.cgi", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "<html>Please Redirect To Login page</html>")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs305ep"])
	_, err := client.GetPage(context.Background(), "/stale.cgi")
	if err == nil {
		t.Fatal("GetPage() = nil, want an error (stale session)")
	}
	if !errors.Is(err, model.ErrHTTPAuth) {
		t.Errorf("error = %v, want wrapping model.ErrHTTPAuth", err)
	}
}

func TestPostFormHTTPErrorOnStatus(t *testing.T) {
	const password, rand = "secret", "abc"
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", gs305epLoginHandler(password, rand, "SID", "sesh"))
	mux.HandleFunc("/write.cgi", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs305ep"])
	_, err := client.PostForm(context.Background(), "/write.cgi", map[string]string{"a": "b"})
	if err == nil {
		t.Fatal("PostForm() = nil, want an error (HTTP 500)")
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want wrapping model.ErrHTTP", err)
	}
}

// TestPostFormDoesNotCheckRedirectToLogin pins the GET-only asymmetry in
// dossier §6.7's _validate_response: post_form's call site never passes
// path=, so a "redirect to login" body (which WOULD fail a GET) is not an
// error on a POST.
func TestPostFormDoesNotCheckRedirectToLogin(t *testing.T) {
	const password, rand = "secret", "abc"
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", gs305epLoginHandler(password, rand, "SID", "sesh"))
	mux.HandleFunc("/write.cgi", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "please redirect to login")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs305ep"])
	text, err := client.PostForm(context.Background(), "/write.cgi", map[string]string{"a": "b"})
	if err != nil {
		t.Fatalf("PostForm() = %v, want nil (POST never checks redirect-to-login)", err)
	}
	if text != "please redirect to login" {
		t.Errorf("PostForm() = %q, want the literal body echoed back", text)
	}
}

// ---------------------------------------------------------------------
// PostMultipart: file + data fields + token field threading.
// ---------------------------------------------------------------------

func TestPostMultipartSendsFileFieldsAndToken(t *testing.T) {
	const password, rand, token = "secret", "xyz789", "tok-9"
	var gotFieldA, gotToken, gotFileContent, gotFileName, gotFileContentType string

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `<input id="rand" value="%s">`, rand)
	})
	mux.HandleFunc("/redirect.html", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `<input type="hidden" name="Gambit" value="%s">`, token)
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gotFieldA = r.FormValue("a")
		gotToken = r.FormValue("Gambit")
		file, hdr, err := r.FormFile("cert")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer func() { _ = file.Close() }()
		data, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gotFileContent = string(data)
		gotFileName = hdr.Filename
		gotFileContentType = hdr.Header.Get("Content-Type")
		_, _ = fmt.Fprint(w, "UPLOAD-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs110emx"])
	text, err := client.PostMultipart(context.Background(), "/upload", map[string]string{"a": "1"}, webui.MultipartFile{
		Field:       "cert",
		Filename:    "cert.pem",
		Content:     []byte("PEMDATA"),
		ContentType: "application/octet-stream",
	})
	if err != nil {
		t.Fatalf("PostMultipart() = %v, want nil", err)
	}
	if text != "UPLOAD-OK" {
		t.Errorf("PostMultipart() = %q, want %q", text, "UPLOAD-OK")
	}
	if gotFieldA != "1" {
		t.Errorf("data field a = %q, want \"1\"", gotFieldA)
	}
	if gotToken != token {
		t.Errorf("Gambit field = %q, want %q", gotToken, token)
	}
	if gotFileContent != "PEMDATA" {
		t.Errorf("file content = %q, want %q", gotFileContent, "PEMDATA")
	}
	if gotFileName != "cert.pem" {
		t.Errorf("file name = %q, want %q", gotFileName, "cert.pem")
	}
	if gotFileContentType != "application/octet-stream" {
		t.Errorf("file Content-Type = %q, want %q", gotFileContentType, "application/octet-stream")
	}
}

// ---------------------------------------------------------------------
// GET retry-on-dropped-connection (2x), POST never retried (dossier §6.4).
// countingTransport is a webui.WithTransport unit-test seam: it can be
// told to fail the next N RoundTrips with an EOF-shaped error (simulating
// a switch that drops the connection mid-request) before delegating to a
// real transport -- deterministic in a way a real dropped socket is not.
// ---------------------------------------------------------------------

type countingTransport struct {
	real http.RoundTripper

	mu    sync.Mutex
	fail  int
	calls int
}

func (t *countingTransport) setFail(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fail = n
}

func (t *countingTransport) resetCalls() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.calls = 0
}

func (t *countingTransport) callCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.calls++
	shouldFail := t.fail > 0
	if shouldFail {
		t.fail--
	}
	t.mu.Unlock()
	if shouldFail {
		return nil, io.ErrUnexpectedEOF
	}
	return t.real.RoundTrip(req) //nolint:wrapcheck // test double: the raw transport error IS the thing under test.
}

func TestGetRetriesOnDroppedConnectionThenSucceeds(t *testing.T) {
	const password, rand = "secret", "abc123"
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", gs305epLoginHandler(password, rand, "SID", "sesh"))
	mux.HandleFunc("/dashboard.cgi", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "DASHBOARD-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	ct := &countingTransport{real: http.DefaultTransport}
	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs305ep"], webui.WithTransport(ct))
	ctx := context.Background()

	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() = %v, want nil", err)
	}

	ct.resetCalls()
	ct.setFail(2) // droppedConnectionRetries=2 -> 3 attempts total: fail, fail, succeed.

	text, err := client.GetPage(ctx, "/dashboard.cgi")
	if err != nil {
		t.Fatalf("GetPage() = %v, want nil (should succeed on the 3rd attempt)", err)
	}
	if text != "DASHBOARD-OK" {
		t.Errorf("GetPage() = %q, want %q", text, "DASHBOARD-OK")
	}
	if got := ct.callCount(); got != 3 {
		t.Errorf("transport RoundTrip calls = %d, want 3 (2 dropped + 1 success)", got)
	}
}

func TestGetFailsAfterExhaustingRetries(t *testing.T) {
	const password, rand = "secret", "abc123"
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", gs305epLoginHandler(password, rand, "SID", "sesh"))
	mux.HandleFunc("/dashboard.cgi", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "DASHBOARD-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	ct := &countingTransport{real: http.DefaultTransport}
	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs305ep"], webui.WithTransport(ct))
	ctx := context.Background()

	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() = %v, want nil", err)
	}

	ct.resetCalls()
	ct.setFail(3) // every attempt fails.

	_, err := client.GetPage(ctx, "/dashboard.cgi")
	if err == nil {
		t.Fatal("GetPage() = nil, want an error (every attempt dropped)")
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want wrapping model.ErrHTTP", err)
	}
	if !strings.Contains(err.Error(), "connection dropped by switch") {
		t.Errorf("error = %v, want it to mention %q", err, "connection dropped by switch")
	}
	if got := ct.callCount(); got != 3 {
		t.Errorf("transport RoundTrip calls = %d, want 3 (droppedConnectionRetries+1)", got)
	}
}

func TestPostNeverRetriedOnDroppedConnection(t *testing.T) {
	const password, rand = "secret", "abc123"
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", gs305epLoginHandler(password, rand, "SID", "sesh"))
	mux.HandleFunc("/write.cgi", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "WRITE-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	ct := &countingTransport{real: http.DefaultTransport}
	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs305ep"], webui.WithTransport(ct))
	ctx := context.Background()

	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login() = %v, want nil", err)
	}

	ct.resetCalls()
	ct.setFail(1) // a single dropped connection must NOT be retried on POST.

	_, err := client.PostForm(ctx, "/write.cgi", map[string]string{"x": "1"})
	if err == nil {
		t.Fatal("PostForm() = nil, want an error (dropped connection)")
	}
	if strings.Contains(err.Error(), "connection dropped by switch") {
		t.Errorf("error = %v, POST must NOT get the GET-only retry-exhaustion wrapping", err)
	}
	if !strings.Contains(err.Error(), "transport error") {
		t.Errorf("error = %v, want it to mention %q", err, "transport error")
	}
	if got := ct.callCount(); got != 1 {
		t.Errorf("transport RoundTrip calls = %d, want 1 (POST must never retry)", got)
	}
}

// ---------------------------------------------------------------------
// Transport shape: no keep-alive, ctx-aware.
// ---------------------------------------------------------------------

func TestNoKeepAliveNeverReusesAConnection(t *testing.T) {
	const password, rand = "secret", "abc123"
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", gs305epLoginHandler(password, rand, "SID", "sesh"))
	mux.HandleFunc("/dashboard.cgi", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "DASHBOARD-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs305ep"])

	var mu sync.Mutex
	var reused []bool
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			mu.Lock()
			defer mu.Unlock()
			reused = append(reused, info.Reused)
		},
	}
	ctx := httptrace.WithClientTrace(context.Background(), trace)

	if _, err := client.GetPage(ctx, "/dashboard.cgi"); err != nil {
		t.Fatalf("GetPage() #1 = %v, want nil", err)
	}
	if _, err := client.GetPage(ctx, "/dashboard.cgi"); err != nil {
		t.Fatalf("GetPage() #2 = %v, want nil", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reused) < 2 {
		t.Fatalf("got %d GotConn events, want at least 2 (one per GetPage call)", len(reused))
	}
	for i, r := range reused {
		if r {
			t.Errorf("connection %d was reused; DisableKeepAlives should force a fresh connection every request", i)
		}
	}
}

func TestContextCancellationPropagates(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), "secret", webui.HTTPSpecs["gs305ep"])

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.GetPage(ctx, "/dashboard.cgi")
	if err == nil {
		t.Fatal("GetPage() with a canceled context = nil, want an error")
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want wrapping model.ErrHTTP", err)
	}
}

// TestGetPageTokenQueryParamAppendsWithAmpersandWhenPathHasQuery pins
// appendQueryParam's "&" branch: a token-session GET whose path already
// carries a query string (as GS728TPP's own wcd? paths do, though that
// model uses cookies not a token -- this exercises the general case)
// appends with "&", not a second "?".
func TestGetPageTokenQueryParamAppendsWithAmpersandWhenPathHasQuery(t *testing.T) {
	const password, rand, token = "secret", "xyz789", "tok-7"
	var gotRawQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `<input id="rand" value="%s">`, rand)
	})
	mux.HandleFunc("/redirect.html", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `<input type="hidden" name="Gambit" value="%s">`, token)
	})
	mux.HandleFunc("/iss/specific/port_settings.html", func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		_, _ = fmt.Fprint(w, "PORTS-OK")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs110emx"])
	if _, err := client.GetPage(context.Background(), "/iss/specific/port_settings.html?unit=1"); err != nil {
		t.Fatalf("GetPage() = %v, want nil", err)
	}
	want := "unit=1&Gambit=" + token
	if gotRawQuery != want {
		t.Errorf("raw query = %q, want %q", gotRawQuery, want)
	}
}

// ---------------------------------------------------------------------
// ensureLoggedIn propagation: PostForm/PostMultipart/PostXML must fail the
// same way GetPage does when the implicit login fails.
// ---------------------------------------------------------------------

func failingLoginServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	return httptest.NewServer(mux)
}

func TestPostFormFailsWhenLoginFails(t *testing.T) {
	server := failingLoginServer()
	defer server.Close()
	client := webui.NewHTTPClient(trimScheme(server.URL), "secret", webui.HTTPSpecs["gs305ep"])
	_, err := client.PostForm(context.Background(), "/write.cgi", map[string]string{"a": "b"})
	if err == nil {
		t.Fatal("PostForm() = nil, want an error (login itself fails)")
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want wrapping model.ErrHTTP", err)
	}
}

func TestPostMultipartFailsWhenLoginFails(t *testing.T) {
	server := failingLoginServer()
	defer server.Close()
	client := webui.NewHTTPClient(trimScheme(server.URL), "secret", webui.HTTPSpecs["gs305ep"])
	_, err := client.PostMultipart(context.Background(), "/upload", nil, webui.MultipartFile{
		Field: "f", Filename: "f.bin", Content: []byte("x"), ContentType: "application/octet-stream",
	})
	if err == nil {
		t.Fatal("PostMultipart() = nil, want an error (login itself fails)")
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want wrapping model.ErrHTTP", err)
	}
}

func TestPostXMLFailsWhenLoginFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := webui.NewHTTPClient(trimScheme(server.URL), "secret", webui.HTTPSpecs["gs728tpp"])
	_, err := client.PostXML(context.Background(), "wcd", "<x/>")
	if err == nil {
		t.Fatal("PostXML() = nil, want an error (login itself fails)")
	}
	if !errors.Is(err, model.ErrHTTPAuth) {
		t.Errorf("error = %v, want wrapping model.ErrHTTPAuth (no session-path redirect)", err)
	}
}

// ---------------------------------------------------------------------
// PostMultipart/PostXML share PostForm's >=400 -> HttpError validation.
// ---------------------------------------------------------------------

func TestPostMultipartHTTPErrorOnStatus(t *testing.T) {
	const password, rand = "secret", "abc"
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", gs305epLoginHandler(password, rand, "SID", "sesh"))
	mux.HandleFunc("/upload", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs305ep"])
	_, err := client.PostMultipart(context.Background(), "/upload", nil, webui.MultipartFile{
		Field: "f", Filename: "f.bin", Content: []byte("x"), ContentType: "application/octet-stream",
	})
	if err == nil {
		t.Fatal("PostMultipart() = nil, want an error (HTTP 500)")
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want wrapping model.ErrHTTP", err)
	}
}

func TestPostXMLHTTPErrorOnStatus(t *testing.T) {
	const sessionPath = "cs3"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/"+sessionPath+"/")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/"+sessionPath+"/System.xml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("sessionID", "sid-1")
		_, _ = fmt.Fprint(w, "<statusCode>0</statusCode>")
	})
	mux.HandleFunc("/"+sessionPath+"/wcd", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), "secret", webui.HTTPSpecs["gs728tpp"])
	_, err := client.PostXML(context.Background(), "wcd", "<x/>")
	if err == nil {
		t.Fatal("PostXML() = nil, want an error (HTTP 500)")
	}
	if !errors.Is(err, model.ErrHTTP) {
		t.Errorf("error = %v, want wrapping model.ErrHTTP", err)
	}
}

// ---------------------------------------------------------------------
// WithVerifyTLS / Close.
// ---------------------------------------------------------------------

// TestWithVerifyTLSRejectsUntrustedCert confirms WithVerifyTLS(true)
// actually re-enables certificate verification (the default is off, since
// every switch web UI this library talks to uses a self-signed cert) --
// against server.Client()'s own untrusted-by-default cert, a verifying
// client must fail the TLS handshake instead of silently accepting it.
func TestWithVerifyTLSRejectsUntrustedCert(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/poeInterfaceConfiguration.html", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "POE-OK")
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), "secret", webui.HTTPSpecs["m4300-16x"], webui.WithVerifyTLS(true))
	_, err := client.GetPage(context.Background(), "/v1/poeInterfaceConfiguration.html")
	if err == nil {
		t.Fatal("GetPage() with WithVerifyTLS(true) against a self-signed cert = nil, want a TLS verification error")
	}
}

// TestCloseIsSafeToCall confirms HTTPClient.Close() (idle-connection
// cleanup, mirroring Python's close()/__exit__) doesn't panic and can be
// called after normal use.
func TestCloseIsSafeToCall(t *testing.T) {
	const password, rand = "secret", "abc"
	mux := http.NewServeMux()
	mux.HandleFunc("/login.cgi", gs305epLoginHandler(password, rand, "SID", "sesh"))
	server := httptest.NewServer(mux)
	defer server.Close()

	client := webui.NewHTTPClient(trimScheme(server.URL), password, webui.HTTPSpecs["gs305ep"])
	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login() = %v, want nil", err)
	}
	client.Close()
}
