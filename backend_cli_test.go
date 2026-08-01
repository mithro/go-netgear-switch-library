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
