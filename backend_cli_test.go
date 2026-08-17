package netgearswitch

// backend_cli_test.go: unit tests for backend_cli.go's builder + lazy-session
// wiring, mirroring backend_http_test.go's shape (hand fakes exercising the
// build* functions / cliSession / lazyCLISession directly, never through the
// dispatch registry). facade_cli_integration_test.go covers the real-loopback
// SSH+telnet end-to-end capstone this file's fakes stand in for.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/mithro/go-netgear-switch-library/fastpath"
	"github.com/mithro/go-netgear-switch-library/model"
)

// recordingCLISession is a fake fastpath.Session: it returns a single canned
// output for every Run, records the commands issued and Close calls, and can
// be told to fail. Enough to exercise the read wiring (GetPorts issues one
// command) and the session-lifecycle plumbing without a real socket.
type recordingCLISession struct {
	mu     sync.Mutex
	output string
	runErr error
	calls  []string
	closed int
}

func (r *recordingCLISession) Run(_ context.Context, command string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, command)
	if r.runErr != nil {
		return "", r.runErr
	}
	return r.output, nil
}

func (r *recordingCLISession) RunSCPCopy(_ context.Context, command, _ string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, command)
	return "", r.runErr
}

func (r *recordingCLISession) RunWriteMemory(_ context.Context, command string, _ bool) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, command)
	return "", r.runErr
}

func (r *recordingCLISession) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed++
	return nil
}

func (r *recordingCLISession) commandCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *recordingCLISession) closeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func newCLISwitch(t *testing.T, modelKey string, opts ...SwitchOption) *Switch {
	t.Helper()
	m, err := model.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q): %v", modelKey, err)
	}
	sw, err := New(m, "10.0.0.1", opts...)
	if err != nil {
		t.Fatalf("New(%q): %v", modelKey, err)
	}
	return sw
}

func TestRequireCLIPassword_RejectsNilAcceptsEmptyAndNonEmpty(t *testing.T) {
	if _, err := requireCLIPassword("h", nil); !errors.Is(err, model.ErrCredential) {
		t.Fatalf("nil password: want ErrCredential, got %v", err)
	}
	empty := ""
	if got, err := requireCLIPassword("h", &empty); err != nil || got != "" {
		t.Fatalf("empty password: want (\"\", nil), got (%q, %v)", got, err)
	}
	pw := "s3cret"
	if got, err := requireCLIPassword("h", &pw); err != nil || got != "s3cret" {
		t.Fatalf("non-empty: want (\"s3cret\", nil), got (%q, %v)", got, err)
	}
}

func TestCLISession_InjectedClientUsedAsIs(t *testing.T) {
	fake := &recordingCLISession{}
	sw := newCLISwitch(t, "gsm7252ps", WithCLIClient(fake))
	for _, kind := range []cliTransportKind{cliTransportSSH, cliTransportTelnet} {
		got, err := sw.cliSession(kind)
		if err != nil {
			t.Fatalf("cliSession(%v): %v", kind, err)
		}
		if got != fastpath.Session(fake) {
			t.Fatalf("cliSession(%v): want the injected fake, got %T", kind, got)
		}
	}
}

func TestCLISession_DefaultBuiltAndCachedPerKind(t *testing.T) {
	sw := newCLISwitch(t, "gsm7252ps", WithCLIPassword("x"))
	ssh1, err := sw.cliSession(cliTransportSSH)
	if err != nil {
		t.Fatal(err)
	}
	ssh2, err := sw.cliSession(cliTransportSSH)
	if err != nil {
		t.Fatal(err)
	}
	if ssh1 != ssh2 {
		t.Fatalf("same kind returned different lazy sessions (not cached)")
	}
	telnet1, err := sw.cliSession(cliTransportTelnet)
	if err != nil {
		t.Fatal(err)
	}
	if ssh1 == telnet1 {
		t.Fatalf("different transport kinds shared one session (must be per-kind)")
	}
}

func TestLazyCLISession_DefersBuildUntilFirstUseAndCaches(t *testing.T) {
	var builds int
	fake := &recordingCLISession{output: "ok"}
	lazy := newLazyCLISession(func(context.Context) (fastpath.Session, error) {
		builds++
		return fake, nil
	})
	if builds != 0 {
		t.Fatalf("build ran before first use")
	}
	if _, err := lazy.Run(context.Background(), "show version"); err != nil {
		t.Fatal(err)
	}
	if _, err := lazy.Run(context.Background(), "show version"); err != nil {
		t.Fatal(err)
	}
	if builds != 1 {
		t.Fatalf("build ran %d times, want exactly 1 (cached after first use)", builds)
	}
}

func TestLazyCLISession_BuildErrorNotCached(t *testing.T) {
	var attempts int
	sentinel := errors.New("dial failed")
	lazy := newLazyCLISession(func(context.Context) (fastpath.Session, error) {
		attempts++
		if attempts == 1 {
			return nil, sentinel
		}
		return &recordingCLISession{output: "ok"}, nil
	})
	if _, err := lazy.Run(context.Background(), "x"); !errors.Is(err, sentinel) {
		t.Fatalf("first Run: want sentinel, got %v", err)
	}
	if _, err := lazy.Run(context.Background(), "x"); err != nil {
		t.Fatalf("second Run after failed build should retry: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("failed build was cached (attempts=%d, want 2)", attempts)
	}
}

func TestLazyCLISession_CloseClosesBuiltSessionOnlyOnce(t *testing.T) {
	fake := &recordingCLISession{output: "ok"}
	lazy := newLazyCLISession(func(context.Context) (fastpath.Session, error) { return fake, nil })
	// Close before any build is a no-op (nothing to close).
	if err := lazy.Close(); err != nil {
		t.Fatalf("Close before build: %v", err)
	}
	if fake.closeCount() != 0 {
		t.Fatalf("Close before build closed the (unbuilt) session")
	}
	if _, err := lazy.Run(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if err := lazy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lazy.Close(); err != nil {
		t.Fatal(err)
	}
	if fake.closeCount() != 1 {
		t.Fatalf("built session closed %d times, want exactly 1", fake.closeCount())
	}
}

func TestSwitchClose_ClosesBuiltCLISessionsButNotInjected(t *testing.T) {
	// Injected client: Switch.Close must NOT close it (this Switch does not
	// own it).
	injected := &recordingCLISession{}
	sw := newCLISwitch(t, "gsm7252ps", WithCLIClient(injected))
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	if injected.closeCount() != 0 {
		t.Fatalf("Switch.Close closed an INJECTED cli client")
	}

	// Default-built session: Switch.Close must close it. Seed the cache with a
	// lazy session over a recording fake and drive one Run so it is built.
	sw2 := newCLISwitch(t, "gsm7252ps", WithCLIPassword("x"))
	built := &recordingCLISession{output: "ok"}
	lazy := newLazyCLISession(func(context.Context) (fastpath.Session, error) { return built, nil })
	if _, err := lazy.Run(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	sw2.cliSessionMu.Lock()
	sw2.cliSessionCache[cliTransportSSH] = lazy
	sw2.cliSessionMu.Unlock()
	if err := sw2.Close(); err != nil {
		t.Fatal(err)
	}
	if built.closeCount() != 1 {
		t.Fatalf("Switch.Close closed built session %d times, want 1", built.closeCount())
	}
}

func TestBuildCLIReader_RoutesGetPortsToSessionAndParses(t *testing.T) {
	// A model whose CLISpec exists; GetPorts issues exactly its PortStatusCmd
	// and parses the canned real-hardware fixture the fake returns.
	fixture, err := os.ReadFile(filepath.Join("fastpath", "testdata", "cli", "gsm7252ps_show_port_all.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	fake := &recordingCLISession{output: string(fixture)}
	sw := newCLISwitch(t, "gsm7252ps", WithCLIClient(fake))
	reader, err := buildCLIReader(sw, cliTransportSSH)
	if err != nil {
		t.Fatalf("buildCLIReader: %v", err)
	}
	ports, err := reader.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts: %v", err)
	}
	if len(ports) == 0 {
		t.Fatalf("GetPorts parsed no ports from the fixture")
	}
	if fake.commandCount() == 0 {
		t.Fatalf("GetPorts issued no command to the session")
	}
}

func TestBuildCLIWriter_AdapterDelegatesVLANCasing(t *testing.T) {
	// CreateVlan (BackendWriter casing) must reach the embedded fastpath
	// Writer's CreateVLAN, which drives config-mode commands on the session.
	// An accepted (empty-output) session lets the config commands "succeed";
	// we assert the writer actually issued commands (delegation happened),
	// not that the full verify round-trip passed (that is the capstone's job).
	fake := &recordingCLISession{output: ""}
	sw := newCLISwitch(t, "gsm7252ps", WithCLIClient(fake))
	writer, err := buildCLIWriter(sw, cliTransportSSH)
	if err != nil {
		t.Fatalf("buildCLIWriter: %v", err)
	}
	// CreateVlan has no verify-after-write mismatch path that would need a
	// scripted read-back here beyond the empty-accept convention; if the
	// adapter did NOT delegate, zero commands would be issued.
	_ = writer.CreateVlan(context.Background(), 4001, "throwaway")
	if fake.commandCount() == 0 {
		t.Fatalf("cliWriterAdapter.CreateVlan did not delegate to Writer.CreateVLAN (no commands issued)")
	}
}

func TestBuildCLIReader_ModelWithoutCLIRefusesUnsupported(t *testing.T) {
	// gs305ep declares no CLI backend / no CLISpec: the reader build must
	// refuse with ErrUnsupportedCapability, never a credential error.
	fake := &recordingCLISession{}
	sw := newCLISwitch(t, "gs305ep", WithCLIClient(fake))
	_, err := buildCLIReader(sw, cliTransportSSH)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("build for non-CLI model: want ErrUnsupportedCapability, got %v", err)
	}
	if errors.Is(err, model.ErrCredential) {
		t.Fatalf("non-CLI model refused with a credential error, not a capability error")
	}
}

// --- cliReadsSupported / cliWritesSupported gate -------------------------
//
// The gap these tests close: before this change, buildCLIReader/
// buildCLIWriter never checked CliModelSpec.ReadsVerified/WritesVerified at
// all, so a hypothetical unverified CLI model would have gotten a working
// reader/writer that dials the real SSH/telnet session on its first actual
// command -- disagreeing with the capabilities oracle (capabilities/
// support_cli.go's cliSupport, which already reports Support.UNVERIFIED for
// exactly this case) and with Python's cli_reads_supported/
// cli_writes_supported gate in SyncSwitch._reader_for/_writer_for. All 4
// real registered CLI models are verified at this pin, so there is no
// registered model that can exercise the refusal directly -- these tests
// use fastpath.CLISpecs' exported map (the same seam backend_http_test.go
// uses via webui.HTTPSpecs) to temporarily flip a REAL model's spec
// unverified, restoring it via defer, mirroring
// TestHTTPReadsSupported_FalseWhenSpecUnverified/
// TestBuildHTTPReader_UnverifiedModelRefusesBeforePasswordResolution.

func TestCLIReadsSupported_TrueForVerifiedModel(t *testing.T) {
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("GetModel: %v", err)
	}
	if !cliReadsSupported(m) {
		t.Error("cliReadsSupported(gsm7252ps) = false, want true (ReadsVerified=true at this pin)")
	}
}

func TestCLIReadsSupported_FalseWithoutCLIBackend(t *testing.T) {
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("GetModel: %v", err)
	}
	if cliReadsSupported(m) {
		t.Error("cliReadsSupported(gs305ep) = true, want false (no CLI backend at all)")
	}
}

func TestCLIReadsSupported_FalseWhenSpecUnverified(t *testing.T) {
	// Every shipped CliModelSpec is ReadsVerified=true at this pin; flip
	// gsm7252ps's temporarily via the exported fastpath.CLISpecs map (the
	// package's own documented mutation seam), then restore it.
	spec := fastpath.CLISpecs["gsm7252ps"]
	original := spec.ReadsVerified
	spec.ReadsVerified = false
	defer func() { spec.ReadsVerified = original }()

	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("GetModel: %v", err)
	}
	if cliReadsSupported(m) {
		t.Error("cliReadsSupported(unverified gsm7252ps) = true, want false")
	}
}

func TestCLIWritesSupported_RequiresBothReadsAndWritesVerified(t *testing.T) {
	spec := fastpath.CLISpecs["gsm7252ps"]
	origReads, origWrites := spec.ReadsVerified, spec.WritesVerified
	defer func() {
		spec.ReadsVerified = origReads
		spec.WritesVerified = origWrites
	}()

	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("GetModel: %v", err)
	}
	if !cliWritesSupported(m) {
		t.Fatal("cliWritesSupported(gsm7252ps) = false at baseline, want true (both verified at this pin)")
	}

	spec.WritesVerified = false
	if cliWritesSupported(m) {
		t.Error("cliWritesSupported() = true with WritesVerified=false, want false")
	}
	spec.WritesVerified = origWrites

	// ReadsVerified=false alone (WritesVerified still true) must ALSO gate
	// writes off: a write cannot be honestly verified by reading back
	// through an unverified reader (mirrors Python's cli_writes_supported
	// layering, _dispatch.py:220-234).
	spec.ReadsVerified = false
	if cliWritesSupported(m) {
		t.Error("cliWritesSupported() = true with ReadsVerified=false, want false (writes require reads too)")
	}
}

// --- buildCLIReader/buildCLIWriter: the dispatch refusal itself ----------

func TestBuildCLIReader_UnverifiedModelRefusesBeforeSessionLookup(t *testing.T) {
	spec := fastpath.CLISpecs["gsm7252ps"]
	original := spec.ReadsVerified
	spec.ReadsVerified = false
	defer func() { spec.ReadsVerified = original }()

	// A real (non-injected) password so that, absent the gate, cliSession()
	// would happily hand back a lazy session ready to dial 10.0.0.1 on its
	// first command.
	sw := newCLISwitch(t, "gsm7252ps", WithCLIPassword("x"))

	reader, err := buildCLIReader(sw, cliTransportSSH)
	if reader != nil {
		t.Fatalf("buildCLIReader() returned a non-nil reader for an unverified model")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("buildCLIReader() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if want := `model "gsm7252ps" CLI reads are UNVERIFIED-pending cross-verify`; !strings.Contains(err.Error(), want) {
		t.Errorf("buildCLIReader() error = %q, want containing %q (Python cli_reads_supported message parity)", err.Error(), want)
	}
	// The decisive proof this refuses BEFORE ever reaching for a session:
	// sw.cliSession(kind) is the ONLY thing that populates cliSessionCache
	// (switch.go's New leaves it empty), so an untouched, still-empty cache
	// means the gate short-circuited before any session/dial plumbing ran.
	sw.cliSessionMu.Lock()
	cacheLen := len(sw.cliSessionCache)
	sw.cliSessionMu.Unlock()
	if cacheLen != 0 {
		t.Errorf("buildCLIReader() on an unverified model populated cliSessionCache (len=%d) -- the gate must run before sw.cliSession()", cacheLen)
	}
}

func TestBuildCLIWriter_UnverifiedModelRefusesBeforeSessionLookup(t *testing.T) {
	spec := fastpath.CLISpecs["gsm7252ps"]
	original := spec.WritesVerified
	spec.WritesVerified = false
	defer func() { spec.WritesVerified = original }()

	sw := newCLISwitch(t, "gsm7252ps", WithCLIPassword("x"))

	writer, err := buildCLIWriter(sw, cliTransportSSH)
	if writer != nil {
		t.Fatalf("buildCLIWriter() returned a non-nil writer for an unverified model")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("buildCLIWriter() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if want := `model "gsm7252ps" CLI writes are UNVERIFIED-pending a live write run`; !strings.Contains(err.Error(), want) {
		t.Errorf("buildCLIWriter() error = %q, want containing %q (Python cli_writes_supported message parity)", err.Error(), want)
	}
	sw.cliSessionMu.Lock()
	cacheLen := len(sw.cliSessionCache)
	sw.cliSessionMu.Unlock()
	if cacheLen != 0 {
		t.Errorf("buildCLIWriter() on an unverified model populated cliSessionCache (len=%d) -- the gate must run before sw.cliSession()", cacheLen)
	}
}

// TestBuildCLIReader_VerifiedModelStillConstructsNormally guards against a
// too-eager gate: gsm7252ps IS ReadsVerified at this pin (no spec mutation
// here), so construction must still succeed and route to the injected
// session exactly as TestBuildCLIReader_RoutesGetPortsToSessionAndParses
// already proves end-to-end -- this one just pins the gate functions
// themselves returning true so a future accidental sign-flip (e.g. `!` typo)
// in cliReadsSupported/cliWritesSupported would fail loudly here even before
// the heavier fixture-based test noticed.
func TestBuildCLIReader_VerifiedModelStillConstructsNormally(t *testing.T) {
	fake := &recordingCLISession{output: ""}
	sw := newCLISwitch(t, "gsm7252ps", WithCLIClient(fake))
	if _, err := buildCLIReader(sw, cliTransportSSH); err != nil {
		t.Fatalf("buildCLIReader() on a verified model: error = %v, want nil", err)
	}
	if _, err := buildCLIWriter(sw, cliTransportSSH); err != nil {
		t.Fatalf("buildCLIWriter() on a verified model: error = %v, want nil", err)
	}
}

// --- UploadCertificateSCP --------------------------------------------------

func TestDefaultCLITransportKind_SSHUnlessTelnetOnly(t *testing.T) {
	// Every model with a real copy-scp SSL-certificate profile declares BOTH
	// transports and must resolve to SSH.
	for _, key := range []string{"m4300-24x", "m4300-16x", "gsm7252ps"} {
		m, err := model.GetModel(key)
		if err != nil {
			t.Fatalf("GetModel(%q): %v", key, err)
		}
		if got := defaultCLITransportKind(m); got != cliTransportSSH {
			t.Errorf("defaultCLITransportKind(%q) = %v, want ssh", key, got)
		}
	}
	// gsm7228ps is the one TELNET-but-not-SSH model (FASTPATH-Lite, no SSH
	// listener) -- mirrors Python's build_sync_cli_client transport branch.
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("GetModel: %v", err)
	}
	if got := defaultCLITransportKind(m); got != cliTransportTelnet {
		t.Errorf("defaultCLITransportKind(gsm7228ps) = %v, want telnet", got)
	}
}

func TestUploadCertificateSCP_NoCLIBackendErrors(t *testing.T) {
	// gs305ep has no CLI backend at all (NSDP+HTTP only) -- fastpath.ScpProfile's
	// hasCLIBackend gate must refuse before ever touching the (injected) fake
	// session.
	fake := &recordingCLISession{}
	sw := newCLISwitch(t, "gs305ep", WithCLIClient(fake))
	err := sw.UploadCertificateSCP(context.Background(), "user@host", "pw", "/staging", false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("UploadCertificateSCP() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if fake.commandCount() != 0 {
		t.Fatalf("UploadCertificateSCP() on a non-CLI model issued %d commands, want 0 (the gate must fire before any session I/O)", fake.commandCount())
	}
}

func TestUploadCertificateSCP_CancelledContextErrorsBeforeAnySessionWork(t *testing.T) {
	// UploadCertificateSCP's own ctx.Err() check (backend_cli.go) must fire
	// before it ever resolves a CLI session -- no other existing test drives
	// a cancelled context through this path.
	fake := &recordingCLISession{}
	sw := newCLISwitch(t, "m4300-24x", WithCLIClient(fake))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := sw.UploadCertificateSCP(ctx, "user@host", "pw", "/staging", false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("UploadCertificateSCP() with a cancelled context: error = %v, want wrapping context.Canceled", err)
	}
	if fake.commandCount() != 0 {
		t.Fatalf("UploadCertificateSCP() with a cancelled context issued %d commands, want 0 (must fail before any session I/O)", fake.commandCount())
	}
}

func TestUploadCertificateSCP_KnownMechanismDifferenceGSM7228PS(t *testing.T) {
	// gsm7228ps has a CLI backend (telnet) but no known copy-scp cert
	// profile -- its cert upload is the separate HTTP-multipart mechanism
	// (Switch.UploadCertificate). The refusal must name that difference, and
	// must still never touch the session.
	fake := &recordingCLISession{}
	sw := newCLISwitch(t, "gsm7228ps", WithCLIClient(fake))
	err := sw.UploadCertificateSCP(context.Background(), "user@host", "pw", "/staging", false)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("UploadCertificateSCP() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if !strings.Contains(err.Error(), "HTTP multipart upload") {
		t.Errorf("UploadCertificateSCP() error = %q, want it to quote the mechanism-difference justification", err.Error())
	}
	if fake.commandCount() != 0 {
		t.Fatalf("UploadCertificateSCP() on gsm7228ps issued %d commands, want 0", fake.commandCount())
	}
}

func TestUploadCertificateSCP_Success(t *testing.T) {
	// m4300-24x has a real copy-scp cert profile (modern crypto,
	// WritememStuff=false): prove the facade wires ctx/session/model/params
	// through to fastpath.DeployCertificateSCP correctly end-to-end,
	// including the dot-to-dash host sanitization Python's
	// `base = self.host.replace(".", "-")` performs.
	fake := &recordingCLISession{}
	m, err := model.GetModel("m4300-24x")
	if err != nil {
		t.Fatalf("GetModel: %v", err)
	}
	sw, err := New(m, "10.1.5.13", WithCLIClient(fake))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sw.UploadCertificateSCP(context.Background(), "user@host", "pw", "/staging", true); err != nil {
		t.Fatalf("UploadCertificateSCP() error = %v, want nil", err)
	}
	wantCalls := []string{
		"no ip http secure-server",
		"copy scp://user@host/staging/10-1-5-13-server.pem nvram:sslpem-server",
		"copy scp://user@host/staging/10-1-5-13-root.pem nvram:sslpem-root",
		"ip http secure-server",
		"write memory",
	}
	if !reflect.DeepEqual(fake.calls, wantCalls) {
		t.Fatalf("UploadCertificateSCP() calls = %v, want %v", fake.calls, wantCalls)
	}
}
