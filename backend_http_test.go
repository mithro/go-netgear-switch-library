package netgearswitch

// backend_http_test.go: unit tests for backend_http.go's builder wiring,
// mirroring backend_nsdp_test.go's shape exactly (fakes exercising the
// build* functions directly, never through readerFor/writerFor's registry).
// See D-HTTP-F §6-§7 for the semantics pinned below;
// facade_http_integration_test.go covers the real-loopback end-to-end
// capstone this file's fakes stand in for.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// fakeHTTPSession is a minimal webui.Session test double: every method
// records that it was called (via calls) and returns a canned response or
// callErr. Used to prove lazyHTTPSession truly defers session use, and to
// count builds via a wrapping build func.
type fakeHTTPSession struct {
	calls   []string
	pageErr error
	page    string
}

func (f *fakeHTTPSession) Login(context.Context) error {
	f.calls = append(f.calls, "Login")
	return f.pageErr
}

func (f *fakeHTTPSession) GetPage(_ context.Context, path string) (string, error) {
	f.calls = append(f.calls, "GetPage:"+path)
	if f.pageErr != nil {
		return "", f.pageErr
	}
	return f.page, nil
}

func (f *fakeHTTPSession) PostForm(_ context.Context, path string, _ map[string]string) (string, error) {
	f.calls = append(f.calls, "PostForm:"+path)
	if f.pageErr != nil {
		return "", f.pageErr
	}
	return f.page, nil
}

func (f *fakeHTTPSession) PostMultipart(_ context.Context, path string, _ map[string]string, _ webui.MultipartFile) (string, error) {
	f.calls = append(f.calls, "PostMultipart:"+path)
	if f.pageErr != nil {
		return "", f.pageErr
	}
	return f.page, nil
}

func (f *fakeHTTPSession) PostXML(_ context.Context, path, _ string) (string, error) {
	f.calls = append(f.calls, "PostXML:"+path)
	if f.pageErr != nil {
		return "", f.pageErr
	}
	return f.page, nil
}

var _ webui.Session = (*fakeHTTPSession)(nil)

// httpModel returns a model.SwitchModel keyed exactly as a real registered
// model (e.g. "gs305ep") but built directly (not via model.GetModel) so
// tests control Backends independently -- webui.HTTPSpec looks up its spec
// table BY KEY STRING, so this still resolves the REAL HTTPModelSpec for
// that key, letting these tests exercise real spec data without a network
// round trip. Mirrors backend_nsdp_test.go's nsdpModel helper.
func httpModel(key string, backends ...model.Backend) *model.SwitchModel {
	return &model.SwitchModel{Key: key, Backends: backends, PortCount: 5}
}

// --- requireHTTPPassword ----------------------------------------------------

func TestRequireHTTPPassword_RejectsNil(t *testing.T) {
	_, err := requireHTTPPassword("10.0.0.1", nil)
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("requireHTTPPassword(nil) error = %v, want wrapping ErrCredential", err)
	}
}

func TestRequireHTTPPassword_RejectsEmptyString(t *testing.T) {
	// Unlike NSDP's password gate (nil-only), this mirrors Python's
	// _require_http_password falsy check: "" is ALSO rejected, matching the
	// stricter SNMP write-community gate's shape (D-HTTP-F §7.5).
	empty := ""
	_, err := requireHTTPPassword("10.0.0.1", &empty)
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("requireHTTPPassword(\"\") error = %v, want wrapping ErrCredential", err)
	}
}

func TestRequireHTTPPassword_AcceptsNonEmptyString(t *testing.T) {
	password := "admin"
	got, err := requireHTTPPassword("10.0.0.1", &password)
	if err != nil {
		t.Fatalf("requireHTTPPassword() error = %v, want nil", err)
	}
	if got != password {
		t.Fatalf("requireHTTPPassword() = %q, want %q", got, password)
	}
}

// --- httpHost ----------------------------------------------------------

func TestHTTPHost_NoWebPortPassesHostThrough(t *testing.T) {
	spec, err := webui.HTTPSpec(httpModel("gs305ep", model.BackendHTTP))
	if err != nil {
		t.Fatalf("webui.HTTPSpec() error = %v", err)
	}
	if got := httpHost("10.0.0.1", spec); got != "10.0.0.1" {
		t.Errorf("httpHost() = %q, want %q (gs305ep has no WebPort)", got, "10.0.0.1")
	}
}

func TestHTTPHost_WebPortAppended(t *testing.T) {
	spec, err := webui.HTTPSpec(httpModel("m4300-16x", model.BackendHTTP))
	if err != nil {
		t.Fatalf("webui.HTTPSpec() error = %v", err)
	}
	if got, want := httpHost("10.0.0.1", spec), "10.0.0.1:49152"; got != want {
		t.Errorf("httpHost() = %q, want %q (m4300-16x has WebPort 49152)", got, want)
	}
}

// --- httpReadsSupported ------------------------------------------------

func TestHTTPReadsSupported_TrueForVerifiedModel(t *testing.T) {
	if !httpReadsSupported(httpModel("gs305ep", model.BackendHTTP)) {
		t.Error("httpReadsSupported(gs305ep) = false, want true (ReadsVerified=true at this pin)")
	}
}

func TestHTTPReadsSupported_FalseWithoutHTTPBackend(t *testing.T) {
	if httpReadsSupported(httpModel("gs305ep")) {
		t.Error("httpReadsSupported(no HTTP backend) = true, want false")
	}
}

func TestHTTPReadsSupported_FalseWhenNoSpecRegistered(t *testing.T) {
	if httpReadsSupported(httpModel("not-a-real-model-key", model.BackendHTTP)) {
		t.Error("httpReadsSupported(unregistered key) = true, want false")
	}
}

func TestHTTPReadsSupported_FalseWhenSpecUnverified(t *testing.T) {
	// Every shipped spec is ReadsVerified=true at this pin (D-HTTP-F §7.2's
	// dossier note); temporarily flip one, mirroring webui's own
	// reader_test.go::TestNewReaderRefusesUnverifiedModel convention.
	spec := webui.HTTPSpecs["gsm7228ps"]
	original := spec.ReadsVerified
	spec.ReadsVerified = false
	defer func() { spec.ReadsVerified = original }()

	if httpReadsSupported(httpModel("gsm7228ps", model.BackendHTTP)) {
		t.Error("httpReadsSupported(unverified gsm7228ps) = true, want false")
	}
}

// --- buildHTTPReader: gate ordering (no CredentialError leak) -----------

func TestBuildHTTPReader_UnverifiedModelRefusesBeforePasswordResolution(t *testing.T) {
	spec := webui.HTTPSpecs["gsm7228ps"]
	original := spec.ReadsVerified
	spec.ReadsVerified = false
	defer func() { spec.ReadsVerified = original }()

	// Deliberately NO password configured: if the gate check ran AFTER
	// password resolution, this would surface ErrCredential instead.
	sw, err := New(httpModel("gsm7228ps", model.BackendHTTP), "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = buildHTTPReader(sw)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("buildHTTPReader() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if errors.Is(err, model.ErrCredential) {
		t.Error("buildHTTPReader() on an unverified model must NOT leak ErrCredential -- the gate must precede password resolution")
	}
}

func TestBuildHTTPWriter_UnverifiedModelRefusesBeforePasswordResolution(t *testing.T) {
	spec := webui.HTTPSpecs["gsm7228ps"]
	original := spec.ReadsVerified
	spec.ReadsVerified = false
	defer func() { spec.ReadsVerified = original }()

	sw, err := New(httpModel("gsm7228ps", model.BackendHTTP), "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = buildHTTPWriter(sw)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("buildHTTPWriter() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if errors.Is(err, model.ErrCredential) {
		t.Error("buildHTTPWriter() on an unverified model must NOT leak ErrCredential -- the gate must precede password resolution")
	}
}

func TestBuildHTTPReader_NoHTTPBackendErrors(t *testing.T) {
	sw, err := New(httpModel("fake", model.BackendSNMP), "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = buildHTTPReader(sw)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("buildHTTPReader() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
}

func TestBuildHTTPReader_VerifiedModelWithoutPasswordConstructsButPasswordUnresolvedUntilUse(t *testing.T) {
	// gs305ep is ReadsVerified=true, so construction must succeed WITHOUT a
	// configured password (no session touched at construction) -- proving
	// the lazy-session deferral (D-HTTP-F §7.2).
	sw, err := New(httpModel("gs305ep", model.BackendHTTP), "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	reader, err := buildHTTPReader(sw)
	if err != nil {
		t.Fatalf("buildHTTPReader() error = %v, want nil (construction never touches the session)", err)
	}
	if reader == nil {
		t.Fatal("buildHTTPReader() returned nil reader")
	}
	// An op this model's spec genuinely can't serve (no MAC table page)
	// must raise UnsupportedCapability, honestly, WITHOUT ever needing the
	// (unconfigured) password.
	if _, err := reader.GetMACs(context.Background()); !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("GetMACs() error = %v, want wrapping ErrUnsupportedCapability (gs305ep has no MAC table page)", err)
	}
}

// --- WithHTTPClient injection --------------------------------------------

func TestBuildHTTPReader_InjectedClientUsedAsIs(t *testing.T) {
	fake := &fakeHTTPSession{page: "<html></html>"}
	sw, err := New(httpModel("gs305ep", model.BackendHTTP), "10.0.0.1", WithHTTPClient(fake))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	reader, err := buildHTTPReader(sw)
	if err != nil {
		t.Fatalf("buildHTTPReader() error = %v", err)
	}
	// The fake's canned page is not real port-status HTML, so parsing it
	// fails -- the point here is only that the INJECTED session was
	// actually reached (proving buildHTTPReader used it as-is, not a
	// freshly default-built one), not that the parse succeeds.
	_, _ = reader.GetPorts(context.Background())
	if len(fake.calls) == 0 {
		t.Error("injected session was never used by the reader")
	}
}

func TestBuildHTTPWriter_InjectedClientSharedWithReader(t *testing.T) {
	// The reader and the writer must share the SAME injected session
	// instance (WithHTTPClient sidesteps sw.httpSessionCache entirely) --
	// prove it by checking both dispatch through the one fake and
	// accumulate calls on the same object.
	fake := &fakeHTTPSession{page: "<html></html>"}
	sw, err := New(httpModel("gs305ep", model.BackendHTTP), "10.0.0.1", WithHTTPClient(fake))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	reader, err := buildHTTPReader(sw)
	if err != nil {
		t.Fatalf("buildHTTPReader() error = %v", err)
	}
	writer, err := buildHTTPWriter(sw)
	if err != nil {
		t.Fatalf("buildHTTPWriter() error = %v", err)
	}
	_, _ = reader.GetPorts(context.Background())
	before := len(fake.calls)
	if before == 0 {
		t.Fatal("reader never reached the injected session")
	}
	// gs305ep has a PoEConfigPath, so SetPoE dispatches all the way to the
	// session (the fake's canned non-HTML page fails PoE's verify-after-
	// write step, which is fine -- the point is that MORE calls land on the
	// SAME fake, proving the writer shares the reader's injected session).
	_ = writer.SetPoE(context.Background(), 1, true, false)
	if len(fake.calls) <= before {
		t.Error("writer never reached the injected session shared with the reader")
	}
}

// --- httpSession sharing (one login session across reader/writer/cert) ---

func TestHTTPSession_SharedAcrossReaderAndWriterWhenDefaultBuilt(t *testing.T) {
	sw, err := New(httpModel("gs305ep", model.BackendHTTP), "10.0.0.1", WithHTTPPassword("secret"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	spec, err := webui.HTTPSpec(sw.model)
	if err != nil {
		t.Fatalf("webui.HTTPSpec() error = %v", err)
	}
	s1 := sw.httpSession(spec)
	s2 := sw.httpSession(spec)
	if s1 != s2 {
		t.Error("sw.httpSession() returned two different sessions across calls, want the SAME cached lazyHTTPSession")
	}
}

// --- lazyHTTPSession ------------------------------------------------------

func TestLazyHTTPSession_DefersBuildUntilFirstUse(t *testing.T) {
	built := 0
	fake := &fakeHTTPSession{page: "ok"}
	l := newLazyHTTPSession(func() (webui.Session, error) {
		built++
		return fake, nil
	})
	if built != 0 {
		t.Fatalf("build ran %d times before any use, want 0", built)
	}
	if _, err := l.GetPage(context.Background(), "/x"); err != nil {
		t.Fatalf("GetPage() error = %v", err)
	}
	if built != 1 {
		t.Fatalf("build ran %d times after first use, want 1", built)
	}
	if _, err := l.PostForm(context.Background(), "/y", nil); err != nil {
		t.Fatalf("PostForm() error = %v", err)
	}
	if built != 1 {
		t.Fatalf("build ran %d times after second use, want 1 (cached)", built)
	}
}

func TestLazyHTTPSession_BuildErrorNotCached(t *testing.T) {
	attempts := 0
	buildErr := errors.New("boom")
	l := newLazyHTTPSession(func() (webui.Session, error) {
		attempts++
		if attempts == 1 {
			return nil, buildErr
		}
		return &fakeHTTPSession{page: "ok"}, nil
	})
	if _, err := l.GetPage(context.Background(), "/x"); !errors.Is(err, buildErr) {
		t.Fatalf("first GetPage() error = %v, want wrapping the build error", err)
	}
	if _, err := l.GetPage(context.Background(), "/x"); err != nil {
		t.Fatalf("second GetPage() error = %v, want nil (retries build after a failure)", err)
	}
	if attempts != 2 {
		t.Fatalf("build attempts = %d, want 2 (a failed build must not be cached)", attempts)
	}
}

// --- UploadCertificate -----------------------------------------------------

func TestUploadCertificate_NoHTTPBackendErrors(t *testing.T) {
	sw, err := New(httpModel("fake", model.BackendSNMP), "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = sw.UploadCertificate(context.Background(), "cert", "key", true)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("UploadCertificate() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
}

func TestUploadCertificate_KnownUnimplementedMechanismRefusesBeforeCredentialResolution(t *testing.T) {
	// m4300-24x's cert upload is SCP, not HTTP (webui.CertUploadKnownUnimplemented)
	// -- deliberately NO password configured, to prove this refuses with
	// ErrKnownUnimplemented rather than leaking ErrCredential from an eager
	// session build (D-HTTP-F §7.2's ordering requirement, applied to cert
	// upload too).
	sw, err := New(httpModel("m4300-24x", model.BackendHTTP), "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = sw.UploadCertificate(context.Background(), "cert", "key", true)
	if !errors.Is(err, model.ErrKnownUnimplemented) {
		t.Fatalf("UploadCertificate() error = %v, want wrapping ErrKnownUnimplemented", err)
	}
	if errors.Is(err, model.ErrCredential) {
		t.Error("UploadCertificate() on a known-unimplemented model must NOT leak ErrCredential")
	}
}

func TestUploadCertificate_BypassesReadsVerifiedGate(t *testing.T) {
	// gsm7228ps is grounded for cert upload even when (hypothetically)
	// ReadsVerified is false -- UploadCertificate must bypass that gate
	// entirely (Python's _cert_writer comment: "INDEPENDENT of read
	// verification"). Use the injected-session seam so this never touches
	// the network; the fake session's canned response won't satisfy the
	// multipart-success check, but the point is that we get PAST the gate
	// and INTO the writer's own multipart flow, not an UnsupportedCapability
	// from a reads_verified check.
	spec := webui.HTTPSpecs["gsm7228ps"]
	original := spec.ReadsVerified
	spec.ReadsVerified = false
	defer func() { spec.ReadsVerified = original }()

	fake := &fakeHTTPSession{page: "not a real cert response"}
	sw, err := New(httpModel("gsm7228ps", model.BackendHTTP), "10.0.0.1", WithHTTPClient(fake))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = sw.UploadCertificate(context.Background(), "cert-pem", "key-pem", true)
	// We expect a genuine ErrHTTP (the fake's canned page fails the
	// "completed successfully" check) -- NOT ErrUnsupportedCapability from
	// a reads_verified gate.
	if errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("UploadCertificate() error = %v, must not be gated by ReadsVerified", err)
	}
	if err == nil {
		t.Fatal("UploadCertificate() error = nil, want an error from the fake's non-success page")
	}
}

// --- PRINCIPLE-1: explicit backend=HTTP never invokes the SNMP builder ---

// TestPrincipleOne_ExplicitHTTPRequestNeverInvokesSNMPBuilder is the
// builder-invocation SPY proof that an explicit backend=HTTP request never
// falls back to (or even TOUCHES) SNMP -- mirroring switch_test.go's own
// TestReadVia_NoFallbackWhenChosenBackendCannotServe (the nil-requested/
// default-backend case) but for the EXPLICIT-requested case instead: the
// model declares BOTH SNMP and HTTP, HTTP genuinely refuses the op, and
// SNMP -- despite being registered, declared by the model, and configured
// to happily succeed if ever reached -- must NEVER be invoked at all. This
// is a STRONGER guarantee than an error-text check (facade_http_integration_
// test.go's own M430024X companion test): a regression that reintroduced
// ANY silent-fallback code path would flip snmpBuilt to true here even if
// it happened to produce an error message that still mentioned "http" by
// coincidence.
func TestPrincipleOne_ExplicitHTTPRequestNeverInvokesSNMPBuilder(t *testing.T) {
	clearBackendRegistry(t)

	snmpBuilt := false
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		snmpBuilt = true
		return &fakeReader{}, nil // would happily serve the op if ever reached
	})
	httpErr := fmt.Errorf("model %q HTTP reads are UNVERIFIED-pending-capture: %w", "fake", model.ErrUnsupportedCapability)
	withRegisteredBackend(t, model.BackendHTTP, func(_ *Switch) (BackendReader, error) {
		return nil, httpErr
	})

	m := fakeModel("fake", model.BackendSNMP, model.BackendHTTP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	requestedHTTP := model.BackendHTTP
	err = sw.readVia(context.Background(), &requestedHTTP, func(r BackendReader) error {
		_, err := r.GetPorts(context.Background())
		return err
	})
	if err == nil {
		t.Fatal("readVia(requested=HTTP) error = nil, want HTTP's UnsupportedCapability error")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("readVia(requested=HTTP) error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if !strings.Contains(err.Error(), "the requested backend http cannot serve") {
		t.Fatalf("readVia(requested=HTTP) error = %q, want the cannotServe requested-branch shape naming http", err.Error())
	}
	if snmpBuilt {
		t.Fatal("readVia(requested=HTTP) invoked the SNMP builder -- an explicit backend=HTTP request must NEVER fall back to (or even touch) another backend, even one the model declares and that would have happily served the op")
	}
}
