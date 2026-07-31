// backend_http.go: the HTTP BackendBuilder/WriteBackendBuilder, registered
// into dispatch.go's/write_dispatch.go's registries from THIS file's own
// init() -- follows backend_nsdp.go's exact shape (see that file's own doc
// comment, and backend_snmp.go's, for the pattern rationale: a root-package
// shim per backend, since only code in THIS package can reach Switch's
// unexported fields). Ported from src/netgear_switch/_dispatch.py's
// build_sync_http_client/_require_http_password/http_reads_supported and
// sync_api.py's HTTP branches of _reader_for/_writer_for/upload_certificate/
// _cert_writer (the normative source; that repo is read-only from here).
// Any discrepancy between this file and the pinned Python source is a bug
// in this file. See D-HTTP-F (docs/superpowers/plans/
// 2026-07-31-slice-06-dossier-http-readwrite-face.md) §6-§7 for the full
// porting dossier this implements.
//
// The reads_verified gate (httpReadsSupported below) is checked as the
// LITERAL FIRST statement in both buildHTTPReader and buildHTTPWriter --
// BEFORE any password resolution or session construction -- mirroring
// Python's exact ordering (dossier §7.2): a model whose HTTP reads/writes
// are UNVERIFIED-pending-capture must refuse with a plain
// UnsupportedCapabilityError, never a CredentialError from resolving a web
// password this backend will never use. Session construction itself is
// ALSO deferred past that point via lazyHTTPSession (mirroring Python's
// _LazyHttpSession): an op that refuses honestly without ever touching the
// wire (e.g. GetPoE on a model with no PoE page) must never trigger HTTP
// password resolution or a live connection either -- only an op HTTP
// actually ends up serving pays that cost.

package netgearswitch

import (
	"context"
	"fmt"
	"sync"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
	"github.com/mithro/go-netgear-switch-library/webui"
)

func init() {
	RegisterBackend(model.BackendHTTP, buildHTTPReader)
	RegisterWriteBackend(model.BackendHTTP, buildHTTPWriter)
}

// requireHTTPPassword mirrors Python's _require_http_password: a nil OR
// EMPTY-STRING password is rejected with an error wrapping
// model.ErrCredential naming host -- a falsy check, matching the write-side
// SNMP-community gate's stricter semantics (requireSNMPWriteCommunity), NOT
// the NSDP password gate's nil-only check (requireNSDPPassword) -- this
// codebase's three password/community gates are deliberately non-uniform;
// see each one's own doc comment.
func requireHTTPPassword(host string, password *string) (string, error) {
	if password == nil || *password == "" {
		return "", fmt.Errorf("no HTTP password configured for %q: %w", host, model.ErrCredential)
	}
	return *password, nil
}

// httpHost mirrors Python's _http_host: the bare switch host for a
// standard-port model, or "host:web_port" for one on a non-standard web-UI
// port (m4300-16x's :49152).
func httpHost(host string, spec *webui.HTTPModelSpec) string {
	if spec.WebPort != nil {
		return fmt.Sprintf("%s:%d", host, *spec.WebPort)
	}
	return host
}

// httpReadsSupported mirrors Python's http_reads_supported(model): false if
// m has no HTTP backend at all, or its HTTPModelSpec is missing/its
// ReadsVerified flag is false. The facade uses this to gate BOTH HTTP reads
// and HTTP writes (Python reuses the same function for its "_writer_for"
// HTTP branch too -- there is no separate http_writes_supported).
func httpReadsSupported(m *model.SwitchModel) bool {
	if !m.HasBackend(model.BackendHTTP) {
		return false
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		return false
	}
	return spec.ReadsVerified
}

// buildDefaultHTTPSession resolves sw's OWN httpPassword resolveOnce cell
// and builds a not-yet-connected webui.HTTPClient targeting
// httpHost(sw.host, spec) -- mirroring build_sync_http_client. No I/O:
// webui.NewHTTPClient only constructs an http.Client/cookie jar; the first
// real network request happens on first Login/GetPage/PostForm/etc, which
// is why this is safe to call from lazyHTTPSession's deferred build
// closure (never eagerly, from a BackendBuilder itself, per this file's own
// package doc comment).
func buildDefaultHTTPSession(sw *Switch, spec *webui.HTTPModelSpec) (webui.Session, error) {
	password, err := sw.httpPassword.resolve()
	if err != nil {
		return nil, err
	}
	required, err := requireHTTPPassword(sw.host, password)
	if err != nil {
		return nil, err
	}
	return webui.NewHTTPClient(httpHost(sw.host, spec), required, spec), nil
}

// httpSession returns s's injected webui.Session as-is (WithHTTPClient), or
// the SAME lazily-built default lazyHTTPSession every call returns --
// cached on s.httpSessionCache so the reader, the writer AND
// UploadCertificate all share ONE login session (one password resolution,
// one cookie jar/Gambit token), mirroring Python's single memoized
// self._built_http_client reused by _reader_for/_writer_for/_cert_writer
// alike. The returned session defers its own first build (and therefore
// password resolution) until its first actual Login/GetPage/PostForm/etc
// call -- see lazyHTTPSession's own doc comment. Receiver named `s`,
// matching switch.go's/switch_write.go's own convention for every other
// *Switch method (backend_http.go's remaining functions all take `sw
// *Switch` as a plain PARAMETER, mirroring backend_nsdp.go/backend_snmp.go's
// BackendBuilder-function convention instead -- only an actual METHOD
// receiver follows switch.go's naming).
func (s *Switch) httpSession(spec *webui.HTTPModelSpec) webui.Session {
	if s.httpClient != nil {
		return s.httpClient
	}
	s.httpSessionMu.Lock()
	defer s.httpSessionMu.Unlock()
	if s.httpSessionCache == nil {
		s.httpSessionCache = newLazyHTTPSession(func() (webui.Session, error) { return buildDefaultHTTPSession(s, spec) })
	}
	return s.httpSessionCache
}

// buildHTTPReader is the BackendBuilder registered for model.BackendHTTP:
// the reads_verified gate (httpReadsSupported) runs FIRST -- before
// webui.HTTPSpec is even resolved a second time or any session is touched
// -- then wraps sw's shared HTTP session in a *webui.Reader via
// webui.NewReader, which itself re-checks the SAME gate (belt-and-braces;
// see webui/reader.go's NewReader doc comment) but never touches the
// session either. *webui.Reader already satisfies the BackendReader
// interface verbatim, so no adapter shim is needed.
func buildHTTPReader(sw *Switch) (BackendReader, error) {
	if !httpReadsSupported(sw.model) {
		return nil, fmt.Errorf("model %q HTTP reads are UNVERIFIED-pending-capture: %w", sw.model.Key, model.ErrUnsupportedCapability)
	}
	spec, err := webui.HTTPSpec(sw.model)
	if err != nil {
		return nil, err
	}
	return webui.NewReader(sw.httpSession(spec), sw.model)
}

// buildHTTPWriter is the WriteBackendBuilder registered for
// model.BackendHTTP: gated on the SAME httpReadsSupported check as
// buildHTTPReader (mirroring Python's _writer_for HTTP branch, which reuses
// http_reads_supported verbatim for writes too -- there is no separate
// "http_writes_supported"), checked BEFORE any session use. Wraps sw's
// shared HTTP session in a *webui.Writer via webui.NewWriter (passing
// sw.protectedPorts through), then wraps THAT in httpWriterAdapter to fill
// the two BackendWriter methods package webui's Writer doesn't define under
// the shared signature (CyclePoE/ClearPoEFault).
func buildHTTPWriter(sw *Switch) (BackendWriter, error) {
	if !httpReadsSupported(sw.model) {
		return nil, fmt.Errorf("model %q HTTP writes are UNVERIFIED-pending-capture: %w", sw.model.Key, model.ErrUnsupportedCapability)
	}
	spec, err := webui.HTTPSpec(sw.model)
	if err != nil {
		return nil, err
	}
	writer, err := webui.NewWriter(sw.httpSession(spec), sw.model, webui.WithProtectedPorts(sw.protectedPorts...))
	if err != nil {
		return nil, err
	}
	return &httpWriterAdapter{Writer: writer}, nil
}

// httpWriterAdapter wraps *webui.Writer to satisfy the full 9-method
// BackendWriter interface: package webui's Writer implements 7 of those
// verbatim, plus CyclePoE/ClearPoEFault under a DIFFERENT signature (no
// timeouts parameter -- HTTP's PoE-cycle mechanism is fire-and-forget,
// never polled; see webui/writer.go's own package doc comment). This
// adapter DROPS the timeouts argument and delegates -- unlike
// nsdpWriterAdapter's CyclePoE/ClearPoEFault (constant
// ErrUnsupportedCapability stubs, since NSDP has no PoE-cycle mechanism at
// all), HTTP genuinely has one on every managed/FASTPATH model, so this
// adapter forwards rather than refuses.
type httpWriterAdapter struct {
	*webui.Writer
}

// CyclePoE power-cycles port's PD over HTTP, dropping the timeouts argument
// (accepted-but-unused, purely so this method's signature matches the
// shared BackendWriter surface) before delegating to *webui.Writer.CyclePoE.
func (a *httpWriterAdapter) CyclePoE(ctx context.Context, port int, _ snmp.PoeCycleTimeouts, force bool) error {
	return a.Writer.CyclePoE(ctx, port, force)
}

// ClearPoEFault clears a PoE fault on port over HTTP, dropping the timeouts
// argument the same way CyclePoE does.
func (a *httpWriterAdapter) ClearPoEFault(ctx context.Context, port int, _ snmp.PoeCycleTimeouts, force bool) error {
	return a.Writer.ClearPoEFault(ctx, port, force)
}

// lazyHTTPSession defers webui.Session construction -- and therefore this
// Switch's own httpPassword resolution and the (not-yet-connected, but
// still worth deferring) webui.HTTPClient construction -- until the FIRST
// actual session method call, mirroring Python's _LazyHttpSession (dossier
// D-HTTP-F §7.2). A successful build is cached (never re-built); a FAILED
// build is NOT cached, so the next call retries the resolver from scratch
// (mirroring resolveOnce's own "an error is never marked resolved"
// contract, switch.go) -- e.g. a `!command` HTTP-password secret spec that
// failed once must still get a fresh chance on the next call.
type lazyHTTPSession struct {
	mu      sync.Mutex
	build   func() (webui.Session, error)
	session webui.Session
}

// newLazyHTTPSession wraps build in a lazyHTTPSession cell.
func newLazyHTTPSession(build func() (webui.Session, error)) *lazyHTTPSession {
	return &lazyHTTPSession{build: build}
}

// resolve returns the cached session if this cell has already built one
// successfully; otherwise it runs build now, caching a successful result.
func (l *lazyHTTPSession) resolve() (webui.Session, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session != nil {
		return l.session, nil
	}
	s, err := l.build()
	if err != nil {
		return nil, err
	}
	l.session = s
	return s, nil
}

// builtSession returns the already-built session, if any, WITHOUT
// triggering a build -- used only by Switch.Close() to release a session
// that was actually built, never to force one into existence just to close
// it.
func (l *lazyHTTPSession) builtSession() webui.Session {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.session
}

var _ webui.Session = (*lazyHTTPSession)(nil)

// Login implements webui.Session by resolving (building on first use) then
// delegating.
func (l *lazyHTTPSession) Login(ctx context.Context) error {
	s, err := l.resolve()
	if err != nil {
		return err
	}
	return s.Login(ctx)
}

// GetPage implements webui.Session by resolving then delegating.
func (l *lazyHTTPSession) GetPage(ctx context.Context, path string) (string, error) {
	s, err := l.resolve()
	if err != nil {
		return "", err
	}
	return s.GetPage(ctx, path)
}

// PostForm implements webui.Session by resolving then delegating.
func (l *lazyHTTPSession) PostForm(ctx context.Context, path string, data map[string]string) (string, error) {
	s, err := l.resolve()
	if err != nil {
		return "", err
	}
	return s.PostForm(ctx, path, data)
}

// PostMultipart implements webui.Session by resolving then delegating.
func (l *lazyHTTPSession) PostMultipart(ctx context.Context, path string, data map[string]string, file webui.MultipartFile) (string, error) {
	s, err := l.resolve()
	if err != nil {
		return "", err
	}
	return s.PostMultipart(ctx, path, data, file)
}

// PostXML implements webui.Session by resolving then delegating.
func (l *lazyHTTPSession) PostXML(ctx context.Context, path, body string) (string, error) {
	s, err := l.resolve()
	if err != nil {
		return "", err
	}
	return s.PostXML(ctx, path, body)
}

// UploadCertificate uploads an HTTPS SSL server certificate + private key
// (combined PEM) to this switch, mirroring Python's
// SyncSwitch.upload_certificate/_cert_writer exactly: a GROUNDED web-UI
// write flow that is DELIBERATELY INDEPENDENT of the httpReadsSupported
// gate (webui.NewWriter itself never checks ReadsVerified either -- see
// webui/writer.go's own doc comment) and BYPASSES the SNMP-first single-
// backend dispatch entirely (writeVia/resolveBackend are never consulted)
// -- HTTP is the ONLY backend that can ever serve this op, the same
// dispatch-bypass shape Identify/NSDPDevice use for SNMP/NSDP (switch.go).
//
// require_http_backend is checked BEFORE building any session -- a model
// with no HTTP backend at all raises naming it, never a password/session
// error. Building the session itself is still lazy (sw.httpSession):
// webui.Writer.UploadCertificate checks the known-unimplemented-mechanism
// case (a model whose real cert-upload is SCP, not HTTP) and the
// no-known-mechanism case BEFORE ever touching the session -- so a caller
// with no HTTP password configured still gets the honest
// ErrKnownUnimplemented/ErrUnsupportedCapability for those models, never a
// CredentialError from resolving a password this op was never going to use.
func (s *Switch) UploadCertificate(ctx context.Context, certPEM, keyPEM string, force bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.model.HasBackend(model.BackendHTTP) {
		return fmt.Errorf("model %q has no HTTP backend: %w", s.model.Key, model.ErrUnsupportedCapability)
	}
	spec, err := webui.HTTPSpec(s.model)
	if err != nil {
		return err
	}
	writer, err := webui.NewWriter(s.httpSession(spec), s.model, webui.WithProtectedPorts(s.protectedPorts...))
	if err != nil {
		return err
	}
	return writer.UploadCertificate(ctx, certPEM, keyPEM, force)
}
