package fastpath

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// fakeTransport is an in-memory, non-blocking Transport for tests: each
// Write is matched against script (in order encountered) to decide what
// bytes to enqueue for subsequent Reads. Read returns whatever is pending,
// split into chunkSize pieces if chunkSize > 0 (to exercise multi-chunk
// framing); once pending is drained, Read returns (0, io.EOF) -- exactly
// the "channel closed, no more data right now" signal ShellDriver's read
// loops treat as non-fatal.
type fakeTransport struct {
	mu        sync.Mutex
	responder func(written string) string
	pending   []byte
	chunkSize int
	writes    []string
	closed    bool
	closeErr  error
}

func (t *fakeTransport) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writes = append(t.writes, string(p))
	if t.responder != nil {
		t.pending = append(t.pending, []byte(t.responder(string(p)))...)
	}
	return len(p), nil
}

func (t *fakeTransport) Read(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.pending) == 0 {
		return 0, io.EOF
	}
	n := len(t.pending)
	if t.chunkSize > 0 && n > t.chunkSize {
		n = t.chunkSize
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, t.pending[:n])
	t.pending = t.pending[n:]
	return n, nil
}

func (t *fakeTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return t.closeErr
}

func (t *fakeTransport) writeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.writes)
}

func (t *fakeTransport) writesSnapshot() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, len(t.writes))
	copy(out, t.writes)
	return out
}

// responseQueue is a tiny helper for scripting a sequence of responses, one
// per Write() call, used by the Setup/RunSCPCopy/RunWriteMemory tests below
// that need a multi-round-trip exchange.
type responseQueue struct {
	mu        sync.Mutex
	responses []string
	i         int
}

func (q *responseQueue) respond(written string) string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.i >= len(q.responses) {
		return ""
	}
	resp := q.responses[q.i]
	q.i++
	return resp
}

// --- §1.1 sentinel / prompt-matching tests ---------------------------------

func TestPromptRE(t *testing.T) {
	matches := []string{
		"(GSM7252PS) #",
		"(GSM7252PS) >",
		"(GSM7252PS) (Config)#",
		"(GSM7252PS) (Config-if-1/0/7)#",
		"junk\r\n(M4300-24X) #",
	}
	for _, s := range matches {
		if !promptRE.MatchString(s) {
			t.Errorf("promptRE did not match %q, want match", s)
		}
	}
	nonMatches := []string{
		"",
		"(GSM7252PS) # extra",
		"just some text",
		"Password:",
	}
	for _, s := range nonMatches {
		if promptRE.MatchString(s) {
			t.Errorf("promptRE matched %q, want no match", s)
		}
	}
}

func TestPasswordRE(t *testing.T) {
	if !passwordRE.MatchString("Password:") {
		t.Error("passwordRE did not match \"Password:\"")
	}
	if !passwordRE.MatchString("Enable password:   ") {
		t.Error("passwordRE did not match trailing-space variant")
	}
	if passwordRE.MatchString("password: junk") {
		t.Error("passwordRE matched non-end-anchored text, want no match")
	}
}

func TestSCPSentinels(t *testing.T) {
	if !scpTOFURE.MatchString("The authenticity of host '1.2.3.4' can't be established.\nRSA key fingerprint...\nAre you sure you want to continue connecting (yes/no)?") {
		t.Error("scpTOFURE did not match TOFU prompt")
	}
	if !scpConfirmRE.MatchString("Overwrite file cert.pem? (y/n)") {
		t.Error("scpConfirmRE did not match (y/n) confirm")
	}
	if !scpSuccessRE.MatchString("1234 bytes transferred in 0.1 seconds") {
		t.Error("scpSuccessRE did not match success phrase")
	}
	if !scpFailureRE.MatchString("scp: Connection closed: Transfer failed") {
		t.Error("scpFailureRE did not match failure phrase (case-insensitive)")
	}
}

// --- ShellDriver.readUntil / Run framing tests ------------------------------

func TestShellDriverRunFraming(t *testing.T) {
	transport := &fakeTransport{
		pending: []byte("show version\r\nsome output line 1\r\nsome output line 2\r\n(GSM7252PS) #"),
	}
	d := NewShellDriver(transport, ShellDriverConfig{})
	out, err := d.Run(context.Background(), "show version")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	want := "some output line 1\nsome output line 2"
	if out != want {
		t.Errorf("Run() output = %q, want %q", out, want)
	}
}

func TestShellDriverRunMultiChunkFraming(t *testing.T) {
	// Split the response across several small Read() calls to prove
	// readUntil accumulates correctly rather than assuming one full read.
	transport := &fakeTransport{
		pending:   []byte("cmd\r\nline one\r\nline two\r\n(SW) #"),
		chunkSize: 5,
	}
	d := NewShellDriver(transport, ShellDriverConfig{})
	out, err := d.Run(context.Background(), "cmd")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	want := "line one\nline two"
	if out != want {
		t.Errorf("Run() output = %q, want %q", out, want)
	}
}

func TestShellDriverRunStripsMultipleTrailingPromptLines(t *testing.T) {
	// _clean's prompt-strip is a while loop: it can strip MULTIPLE
	// trailing prompt-matching lines, not just one.
	transport := &fakeTransport{
		pending: []byte("cmd\r\noutput\r\n(SW) #\r\n(SW) #"),
	}
	d := NewShellDriver(transport, ShellDriverConfig{})
	out, err := d.Run(context.Background(), "cmd")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if out != "output" {
		t.Errorf("Run() output = %q, want %q", out, "output")
	}
}

func TestShellDriverRunEchoSubstringContainment(t *testing.T) {
	// The echoed first line need not equal the command exactly -- substring
	// containment, tolerating leading control bytes/whitespace.
	transport := &fakeTransport{
		pending: []byte("\x00show version\r\nAtheros SoC\r\n(SW) #"),
	}
	d := NewShellDriver(transport, ShellDriverConfig{})
	out, err := d.Run(context.Background(), "show version")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if out != "Atheros SoC" {
		t.Errorf("Run() output = %q, want %q", out, "Atheros SoC")
	}
}

func TestShellDriverReadUntilNoPromptChannelClosed(t *testing.T) {
	transport := &fakeTransport{pending: []byte("just some banner, no prompt")}
	d := NewShellDriver(transport, ShellDriverConfig{})
	_, err := d.Run(context.Background(), "cmd")
	if err == nil {
		t.Fatal("Run() error = nil, want error (no prompt seen)")
	}
	if !errors.Is(err, ErrCliTransport) {
		t.Errorf("Run() error = %v, want wrapping ErrCliTransport", err)
	}
}

// alwaysJunkTransport never emits a prompt and never closes -- every Read
// returns 1 fresh byte, forever, forcing readUntil to exhaust maxReads.
type alwaysJunkTransport struct{ writes int }

func (t *alwaysJunkTransport) Write(p []byte) (int, error) { t.writes++; return len(p), nil }
func (t *alwaysJunkTransport) Read(p []byte) (int, error) {
	p[0] = 'x'
	return 1, nil
}
func (t *alwaysJunkTransport) Close() error { return nil }

func TestShellDriverReadUntilExhaustsMaxReads(t *testing.T) {
	d := NewShellDriver(&alwaysJunkTransport{}, ShellDriverConfig{})
	_, err := d.Run(context.Background(), "cmd")
	if err == nil {
		t.Fatal("Run() error = nil, want error (maxReads exhausted)")
	}
	if !errors.Is(err, ErrCliTransport) {
		t.Errorf("Run() error = %v, want wrapping ErrCliTransport", err)
	}
}

// --- Setup tests -------------------------------------------------------------

func TestShellDriverSetupNoEnablePassword(t *testing.T) {
	q := &responseQueue{responses: []string{"(SW) #", "(SW) #"}}
	transport := &fakeTransport{
		pending:   []byte("Welcome\r\n(SW) >"), // initial banner/prompt
		responder: q.respond,
	}
	d := NewShellDriver(transport, ShellDriverConfig{EnablePassword: "secret"})
	if err := d.Setup(context.Background()); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	writes := transport.writesSnapshot()
	if len(writes) != 2 || writes[0] != "enable\r\n" || writes[1] != "terminal length 0\r\n" {
		t.Errorf("Setup() writes = %#v, want [enable, terminal length 0]", writes)
	}
}

func TestShellDriverSetupWithEnablePassword(t *testing.T) {
	// reply to "enable" (a password prompt), then the password answer,
	// then "terminal length 0".
	q := &responseQueue{responses: []string{"Password: ", "(SW) #", "(SW) #"}}
	transport := &fakeTransport{
		pending:   []byte("Welcome\r\n(SW) >"),
		responder: q.respond,
	}
	d := NewShellDriver(transport, ShellDriverConfig{EnablePassword: "secret"})
	if err := d.Setup(context.Background()); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	writes := transport.writesSnapshot()
	want := []string{"enable\r\n", "secret\r\n", "terminal length 0\r\n"}
	if len(writes) != len(want) {
		t.Fatalf("Setup() writes = %#v, want %#v", writes, want)
	}
	for i := range want {
		if writes[i] != want[i] {
			t.Errorf("Setup() writes[%d] = %q, want %q", i, writes[i], want[i])
		}
	}
}

func TestShellDriverSetupCustomCommands(t *testing.T) {
	q := &responseQueue{responses: []string{"(SW) #", "(SW) #"}}
	transport := &fakeTransport{
		pending:   []byte("(SW) >"),
		responder: q.respond,
	}
	d := NewShellDriver(transport, ShellDriverConfig{
		EnableCmd:    "enable",
		PagingOffCmd: "terminal datadump", // model override, not the default
	})
	if err := d.Setup(context.Background()); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	writes := transport.writesSnapshot()
	if writes[1] != "terminal datadump\r\n" {
		t.Errorf("Setup() paging-off write = %q, want %q", writes[1], "terminal datadump\r\n")
	}
}

// --- run() reject-convention tests ------------------------------------------

// scriptedSession is a Session implementation entirely driven by a
// caller-supplied function per method, used for testing run/inMode without
// needing a real ShellDriver+Transport underneath.
type scriptedSession struct {
	runFn func(ctx context.Context, command string) (string, error)
	calls []string
}

func (s *scriptedSession) Run(ctx context.Context, command string) (string, error) {
	s.calls = append(s.calls, command)
	if s.runFn != nil {
		return s.runFn(ctx, command)
	}
	return "", nil
}
func (s *scriptedSession) RunSCPCopy(ctx context.Context, command, scpPassword string) (string, error) {
	return "", nil
}
func (s *scriptedSession) RunWriteMemory(ctx context.Context, command string, prestuff bool) (string, error) {
	return "", nil
}
func (s *scriptedSession) Close() error { return nil }

func TestRunAcceptsEmptyOutput(t *testing.T) {
	sess := &scriptedSession{runFn: func(ctx context.Context, command string) (string, error) {
		return "", nil
	}}
	if err := run(context.Background(), sess, "vlan 10"); err != nil {
		t.Errorf("run() error = %v, want nil for empty output", err)
	}
}

func TestRunAcceptsWhitespaceOnlyOutput(t *testing.T) {
	sess := &scriptedSession{runFn: func(ctx context.Context, command string) (string, error) {
		return "  \r\n", nil
	}}
	if err := run(context.Background(), sess, "vlan 10"); err != nil {
		t.Errorf("run() error = %v, want nil for whitespace-only output", err)
	}
}

func TestRunRejectsNonEmptyOutput(t *testing.T) {
	sess := &scriptedSession{runFn: func(ctx context.Context, command string) (string, error) {
		return "% Invalid input detected at '^' marker.", nil
	}}
	err := run(context.Background(), sess, "poe")
	if err == nil {
		t.Fatal("run() error = nil, want error for non-empty output")
	}
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Errorf("run() error = %v, want wrapping ErrCliCommandRejected", err)
	}
}

func TestRunPropagatesTransportError(t *testing.T) {
	wantErr := fmt.Errorf("%w: boom", ErrCliTransport)
	sess := &scriptedSession{runFn: func(ctx context.Context, command string) (string, error) {
		return "", wantErr
	}}
	err := run(context.Background(), sess, "poe")
	if !errors.Is(err, wantErr) {
		t.Errorf("run() error = %v, want %v", err, wantErr)
	}
}

// --- inMode: the counted-unwind hazard --------------------------------------

func TestInModeAllSucceedUnwindsEveryEnteredLevel(t *testing.T) {
	sess := &scriptedSession{runFn: func(ctx context.Context, command string) (string, error) {
		return "", nil // every command accepted
	}}
	enter := []string{"configure terminal", "interface 1/0/7"}
	body := []string{"switchport mode general", "vlan participation include 10"}
	if err := inMode(context.Background(), sess, enter, body, "exit"); err != nil {
		t.Fatalf("inMode() error = %v", err)
	}
	want := append(append(append([]string{}, enter...), body...), "exit", "exit")
	if len(sess.calls) != len(want) {
		t.Fatalf("inMode() calls = %#v, want %#v", sess.calls, want)
	}
	for i := range want {
		if sess.calls[i] != want[i] {
			t.Errorf("inMode() calls[%d] = %q, want %q", i, sess.calls[i], want[i])
		}
	}
}

func TestInModePartialEnterFailureUnwindsOnlyEnteredLevels(t *testing.T) {
	// THE hazard test: enter has 3 levels, the 2nd is rejected. inMode
	// must unwind exactly 1 level (the one that actually succeeded), never
	// 0 and never len(enter)==3.
	enter := []string{"level1", "level2-rejected", "level3-never-reached"}
	sess := &scriptedSession{runFn: func(ctx context.Context, command string) (string, error) {
		if command == "level2-rejected" {
			return "% Invalid input detected at '^' marker.", nil
		}
		return "", nil
	}}
	err := inMode(context.Background(), sess, enter, nil, "exit")
	if err == nil {
		t.Fatal("inMode() error = nil, want error from the rejected enter command")
	}
	if !errors.Is(err, ErrCliCommandRejected) {
		t.Errorf("inMode() error = %v, want wrapping ErrCliCommandRejected", err)
	}
	// Expect: level1 (succeeds), level2-rejected (fails, level3 never
	// sent), then exactly ONE "exit" during unwind.
	want := []string{"level1", "level2-rejected", "exit"}
	if len(sess.calls) != len(want) {
		t.Fatalf("inMode() calls = %#v, want %#v (exactly one unwind exit)", sess.calls, want)
	}
	for i := range want {
		if sess.calls[i] != want[i] {
			t.Errorf("inMode() calls[%d] = %q, want %q", i, sess.calls[i], want[i])
		}
	}
}

func TestInModeBodyFailureUnwindsAllEnteredLevels(t *testing.T) {
	// All enter[] commands succeed (2 levels), but a body command is
	// rejected: unwind must still issue exactly len(enter)==2 exits, since
	// every enter level really was entered.
	enter := []string{"vlan database"}
	body := []string{"vlan name 10 bad name with spaces"}
	sess := &scriptedSession{runFn: func(ctx context.Context, command string) (string, error) {
		if command == body[0] {
			return "ERROR: VLAN 10 does not exist", nil
		}
		return "", nil
	}}
	err := inMode(context.Background(), sess, enter, body, "exit")
	if err == nil {
		t.Fatal("inMode() error = nil, want error from the rejected body command")
	}
	want := []string{"vlan database", "vlan name 10 bad name with spaces", "exit"}
	if len(sess.calls) != len(want) {
		t.Fatalf("inMode() calls = %#v, want %#v", sess.calls, want)
	}
	for i := range want {
		if sess.calls[i] != want[i] {
			t.Errorf("inMode() calls[%d] = %q, want %q", i, sess.calls[i], want[i])
		}
	}
}

func TestInModeUnwindUsesRawRunNotWrappedRun(t *testing.T) {
	// The unwind's own "exit" call must go through sess.Run directly, not
	// through the wrapped run() reject-convention -- so even if "exit"
	// itself returns non-empty (rejected/erroring) text, that must NOT
	// surface as inMode's returned error (which must remain the ORIGINAL
	// failure, not be masked by an unwind failure).
	enter := []string{"level1", "level2-rejected"}
	sess := &scriptedSession{runFn: func(ctx context.Context, command string) (string, error) {
		switch command {
		case "level2-rejected":
			return "% Invalid input detected at '^' marker.", nil
		case "exit":
			// Simulate exit itself being rejected/erroring -- must be
			// silently discarded by the unwind, not raised.
			return "% Invalid input detected at '^' marker.", nil
		}
		return "", nil
	}}
	err := inMode(context.Background(), sess, enter, nil, "exit")
	if err == nil {
		t.Fatal("inMode() error = nil, want the original level2-rejected error")
	}
	if !strings.Contains(err.Error(), "level2-rejected") {
		t.Errorf("inMode() error = %v, want it to reference the original rejected command, not the exit failure", err)
	}
	want := []string{"level1", "level2-rejected", "exit"}
	if len(sess.calls) != len(want) {
		t.Fatalf("inMode() calls = %#v, want %#v", sess.calls, want)
	}
}

func TestInModeNoLevelsEnteredNoUnwind(t *testing.T) {
	// The very first enter command is rejected: entered stays 0, so the
	// unwind must issue ZERO exits, not len(enter).
	enter := []string{"configure terminal", "interface 1/0/7", "switchport mode general"}
	sess := &scriptedSession{runFn: func(ctx context.Context, command string) (string, error) {
		return "% Invalid input detected at '^' marker.", nil
	}}
	err := inMode(context.Background(), sess, enter, nil, "exit")
	if err == nil {
		t.Fatal("inMode() error = nil, want error")
	}
	want := []string{"configure terminal"}
	if len(sess.calls) != len(want) {
		t.Fatalf("inMode() calls = %#v, want %#v (no exit issued, nothing was entered)", sess.calls, want)
	}
}

func TestInModeEmptyEnterRunsBodyDirectly(t *testing.T) {
	sess := &scriptedSession{runFn: func(ctx context.Context, command string) (string, error) {
		return "", nil
	}}
	if err := inMode(context.Background(), sess, nil, []string{"no ip http secure-server"}, "exit"); err != nil {
		t.Fatalf("inMode() error = %v", err)
	}
	want := []string{"no ip http secure-server"}
	if len(sess.calls) != len(want) || sess.calls[0] != want[0] {
		t.Errorf("inMode() calls = %#v, want %#v (no exit -- nothing was entered)", sess.calls, want)
	}
}

// --- RunSCPCopy tests --------------------------------------------------------

func TestShellDriverRunSCPCopyHappyPath(t *testing.T) {
	transport := &fakeTransport{
		pending: []byte("copy scp://x y\r\n1234 bytes transferred in 0.1 seconds\r\n(SW) #"),
	}
	d := NewShellDriver(transport, ShellDriverConfig{})
	out, err := d.RunSCPCopy(context.Background(), "copy scp://x y", "scppass")
	if err != nil {
		t.Fatalf("RunSCPCopy() error = %v", err)
	}
	if !strings.Contains(out, "bytes transferred") {
		t.Errorf("RunSCPCopy() transcript = %q, want it to contain the success phrase", out)
	}
}

func TestShellDriverRunSCPCopyDrivesTOFUAndPassword(t *testing.T) {
	transport := &fakeTransport{
		chunkSize: 4096,
	}
	// Script the multi-step interactive exchange: TOFU prompt -> "yes",
	// then Password prompt -> scp password, then success + shell prompt.
	step := 0
	transport.responder = func(written string) string {
		step++
		switch step {
		case 1: // reply to the initial "copy ..." command
			return "Are you sure you want to continue connecting (yes/no)?"
		case 2: // reply to "yes"
			return "Password: "
		case 3: // reply to the scp password
			return "Sending file...\r\ncompleted successfully\r\n(SW) #"
		}
		return ""
	}
	// Prime the very first read with the TOFU prompt (no write has
	// happened yet at the point Run's initial write triggers step 1).
	d := NewShellDriver(transport, ShellDriverConfig{})
	out, err := d.RunSCPCopy(context.Background(), "copy scp://x y", "scppass")
	if err != nil {
		t.Fatalf("RunSCPCopy() error = %v", err)
	}
	writes := transport.writesSnapshot()
	if len(writes) != 3 {
		t.Fatalf("RunSCPCopy() writes = %#v, want 3 (command, yes, password)", writes)
	}
	if writes[1] != "yes\r\n" {
		t.Errorf("RunSCPCopy() TOFU answer = %q, want %q", writes[1], "yes\r\n")
	}
	if writes[2] != "scppass\r\n" {
		t.Errorf("RunSCPCopy() password answer = %q, want %q", writes[2], "scppass\r\n")
	}
	if !strings.Contains(out, "completed successfully") {
		t.Errorf("RunSCPCopy() transcript = %q, want it to contain the success phrase", out)
	}
}

func TestShellDriverRunSCPCopyOverwriteConfirmIsBareY(t *testing.T) {
	transport := &fakeTransport{}
	step := 0
	transport.responder = func(written string) string {
		step++
		switch step {
		case 1:
			return "Overwrite cert.pem? (y/n)"
		case 2:
			return "1024 bytes transferred\r\n(SW) #"
		}
		return ""
	}
	d := NewShellDriver(transport, ShellDriverConfig{})
	if _, err := d.RunSCPCopy(context.Background(), "copy scp://x y", "pw"); err != nil {
		t.Fatalf("RunSCPCopy() error = %v", err)
	}
	writes := transport.writesSnapshot()
	if len(writes) != 2 || writes[1] != "y" {
		t.Errorf("RunSCPCopy() overwrite-confirm write = %#v, want bare \"y\" with NO trailing newline", writes)
	}
}

func TestShellDriverRunSCPCopyFailureRaises(t *testing.T) {
	transport := &fakeTransport{
		pending: []byte("copy scp://x y\r\nscp: Transfer failed\r\n"),
	}
	d := NewShellDriver(transport, ShellDriverConfig{})
	_, err := d.RunSCPCopy(context.Background(), "copy scp://x y", "pw")
	if err == nil {
		t.Fatal("RunSCPCopy() error = nil, want error on failure phrase")
	}
	if !errors.Is(err, ErrCliTransport) {
		t.Errorf("RunSCPCopy() error = %v, want wrapping ErrCliTransport", err)
	}
}

func TestShellDriverRunSCPCopySucceededButStreamEndsReturnsTranscript(t *testing.T) {
	// Success phrase seen, but the channel closes before a shell prompt
	// reappears: Python still returns the transcript (succeeded
	// short-circuit), rather than erroring.
	transport := &fakeTransport{
		pending: []byte("copy scp://x y\r\noperation completed\r\n"),
	}
	d := NewShellDriver(transport, ShellDriverConfig{})
	out, err := d.RunSCPCopy(context.Background(), "copy scp://x y", "pw")
	if err != nil {
		t.Fatalf("RunSCPCopy() error = %v, want nil (succeeded short-circuit)", err)
	}
	if !strings.Contains(out, "operation completed") {
		t.Errorf("RunSCPCopy() transcript = %q, want it to contain the success phrase", out)
	}
}

func TestShellDriverRunSCPCopyIncompleteNoSuccessNoPromptErrors(t *testing.T) {
	transport := &fakeTransport{
		pending: []byte("copy scp://x y\r\nstill working...\r\n"),
	}
	d := NewShellDriver(transport, ShellDriverConfig{})
	_, err := d.RunSCPCopy(context.Background(), "copy scp://x y", "pw")
	if err == nil {
		t.Fatal("RunSCPCopy() error = nil, want error (no success, no prompt, stream ended)")
	}
	if !errors.Is(err, ErrCliTransport) {
		t.Errorf("RunSCPCopy() error = %v, want wrapping ErrCliTransport", err)
	}
}

// --- RunWriteMemory tests ----------------------------------------------------

func TestShellDriverRunWriteMemoryPrestuffSingleWrite(t *testing.T) {
	transport := &fakeTransport{
		pending: []byte("(SW) #"),
	}
	d := NewShellDriver(transport, ShellDriverConfig{})
	if _, err := d.RunWriteMemory(context.Background(), "write memory", true); err != nil {
		t.Fatalf("RunWriteMemory() error = %v", err)
	}
	writes := transport.writesSnapshot()
	if len(writes) != 1 || writes[0] != "write memory\ry\r" {
		t.Errorf("RunWriteMemory(prestuff=true) writes = %#v, want a single %q write", writes, "write memory\ry\r")
	}
}

func TestShellDriverRunWriteMemoryNonPrestuffWaitsForConfirm(t *testing.T) {
	transport := &fakeTransport{}
	step := 0
	transport.responder = func(written string) string {
		step++
		switch step {
		case 1:
			return "Are you sure you want to save? (y/n)"
		case 2:
			return "(SW) #"
		}
		return ""
	}
	d := NewShellDriver(transport, ShellDriverConfig{})
	if _, err := d.RunWriteMemory(context.Background(), "write memory", false); err != nil {
		t.Fatalf("RunWriteMemory() error = %v", err)
	}
	writes := transport.writesSnapshot()
	if len(writes) != 2 || writes[0] != "write memory\r\n" || writes[1] != "y" {
		t.Errorf("RunWriteMemory(prestuff=false) writes = %#v, want [%q, %q]", writes, "write memory\r\n", "y")
	}
}

func TestShellDriverRunWriteMemoryIncompleteErrors(t *testing.T) {
	transport := &fakeTransport{pending: []byte("still saving...")}
	d := NewShellDriver(transport, ShellDriverConfig{})
	_, err := d.RunWriteMemory(context.Background(), "write memory", false)
	if err == nil {
		t.Fatal("RunWriteMemory() error = nil, want error (stream ended without prompt)")
	}
	if !errors.Is(err, ErrCliTransport) {
		t.Errorf("RunWriteMemory() error = %v, want wrapping ErrCliTransport", err)
	}
}

// --- Close --------------------------------------------------------------

func TestShellDriverClose(t *testing.T) {
	transport := &fakeTransport{}
	d := NewShellDriver(transport, ShellDriverConfig{})
	if err := d.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !transport.closed {
		t.Error("Close() did not close the underlying transport")
	}
}

func TestShellDriverCloseSurfacesTransportError(t *testing.T) {
	wantErr := errors.New("boom")
	transport := &fakeTransport{closeErr: wantErr}
	d := NewShellDriver(transport, ShellDriverConfig{})
	if err := d.Close(); !errors.Is(err, wantErr) {
		t.Errorf("Close() error = %v, want %v", err, wantErr)
	}
}

// --- context cancellation ----------------------------------------------------

func TestShellDriverRunFailsFastOnCanceledContext(t *testing.T) {
	transport := &fakeTransport{}
	d := NewShellDriver(transport, ShellDriverConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Run(ctx, "cmd"); err == nil {
		t.Error("Run() error = nil, want error for already-canceled context")
	}
	if transport.writeCount() != 0 {
		t.Errorf("Run() wrote %d times on a canceled context, want 0", transport.writeCount())
	}
}

// interfaceCompileChecks statically asserts *ShellDriver satisfies Session.
var _ Session = (*ShellDriver)(nil)
