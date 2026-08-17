package safety

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

func newStreams(in string) (Streams, *bytes.Buffer, *bytes.Buffer) {
	var out, errBuf bytes.Buffer
	return Streams{Out: &out, Err: &errBuf, In: bufio.NewReader(strings.NewReader(in))}, &out, &errBuf
}

// failAfterWriter succeeds its first n Write calls, then fails every call
// after that -- used to exercise a SECOND write's failure without also
// failing the FIRST write in the same code path (e.g. DoWrite's own
// "aborted: ..." message, printed to the same stream Confirm just used
// for its prompt).
type failAfterWriter struct{ n int }

func (f *failAfterWriter) Write(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("write failed")
	}
	f.n--
	return len(p), nil
}

// erroringReader always returns a non-EOF read error, exercising
// Confirm's "propagate a real read failure" branch (distinct from the
// io.EOF-is-a-decline branch TestConfirmEOFIsDeclineNotError covers).
type erroringReader struct{}

func (erroringReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// --- ExitCodeFor -----------------------------------------------------

func TestExitCodeForNil(t *testing.T) {
	if got := ExitCodeFor(nil); got != ExitOK {
		t.Errorf("ExitCodeFor(nil) = %d, want %d", got, ExitOK)
	}
}

func TestExitCodeForPlainError(t *testing.T) {
	if got := ExitCodeFor(errors.New("boom")); got != ExitError {
		t.Errorf("ExitCodeFor(plain) = %d, want %d", got, ExitError)
	}
}

func TestExitCodeForProtectedPort(t *testing.T) {
	err := fmt.Errorf("port 5 is protected: %w", model.ErrProtectedPort)
	if got := ExitCodeFor(err); got != ExitProtected {
		t.Errorf("ExitCodeFor(protected) = %d, want %d", got, ExitProtected)
	}
}

func TestExitCodeForWriteVerification(t *testing.T) {
	err := &model.WriteVerificationError{Msg: "port speed mismatch", Before: "auto", After: "auto"}
	if got := ExitCodeFor(err); got != ExitVerify {
		t.Errorf("ExitCodeFor(verify) = %d, want %d", got, ExitVerify)
	}
}

func TestExitCodeForWrappedWriteVerification(t *testing.T) {
	inner := &model.WriteVerificationError{Msg: "mismatch"}
	err := fmt.Errorf("write failed: %w", inner)
	if got := ExitCodeFor(err); got != ExitVerify {
		t.Errorf("ExitCodeFor(wrapped verify) = %d, want %d", got, ExitVerify)
	}
}

func TestExitCodeForWrappedProtectedPort(t *testing.T) {
	err := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", model.ErrProtectedPort))
	if got := ExitCodeFor(err); got != ExitProtected {
		t.Errorf("ExitCodeFor(doubly wrapped protected) = %d, want %d", got, ExitProtected)
	}
}

// --- Confirm -----------------------------------------------------------

func TestConfirmAssumeYesSkipsPromptAndRead(t *testing.T) {
	streams, out, errBuf := newStreams("")
	ok, err := Confirm(streams, "About to do a thing.", true)
	if err != nil {
		t.Fatalf("Confirm() error = %v, want nil", err)
	}
	if !ok {
		t.Error("Confirm(assumeYes=true) = false, want true")
	}
	if out.Len() != 0 || errBuf.Len() != 0 {
		t.Errorf("Confirm(assumeYes=true) wrote out=%q err=%q, want nothing written", out.String(), errBuf.String())
	}
}

func TestConfirmPromptText(t *testing.T) {
	streams, _, errBuf := newStreams("y\n")
	if _, err := Confirm(streams, "About to reboot switch on 10.0.0.5.", false); err != nil {
		t.Fatalf("Confirm() error = %v, want nil", err)
	}
	want := "About to reboot switch on 10.0.0.5. [y/N]: "
	if errBuf.String() != want {
		t.Errorf("Confirm() wrote %q to Err, want %q", errBuf.String(), want)
	}
}

func TestConfirmAcceptedReplies(t *testing.T) {
	for _, reply := range []string{"y\n", "Y\n", "yes\n", "YES\n", "Yes\n", "  y  \n", "y"} {
		streams, _, _ := newStreams(reply)
		ok, err := Confirm(streams, "prompt", false)
		if err != nil {
			t.Fatalf("Confirm(%q) error = %v, want nil", reply, err)
		}
		if !ok {
			t.Errorf("Confirm(%q) = false, want true", reply)
		}
	}
}

func TestConfirmDeclinedReplies(t *testing.T) {
	for _, reply := range []string{"n\n", "no\n", "\n", "maybe\n", "", "yesplease\n"} {
		streams, _, _ := newStreams(reply)
		ok, err := Confirm(streams, "prompt", false)
		if err != nil {
			t.Fatalf("Confirm(%q) error = %v, want nil", reply, err)
		}
		if ok {
			t.Errorf("Confirm(%q) = true, want false", reply)
		}
	}
}

func TestConfirmEOFIsDeclineNotError(t *testing.T) {
	streams, _, _ := newStreams("") // immediate EOF, nothing typed
	ok, err := Confirm(streams, "prompt", false)
	if err != nil {
		t.Fatalf("Confirm() error = %v, want nil (Python's readline() never raises at EOF)", err)
	}
	if ok {
		t.Error("Confirm(EOF) = true, want false")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestConfirmPromptWriteErrorPropagates(t *testing.T) {
	streams := Streams{Out: &bytes.Buffer{}, Err: failingWriter{}, In: bufio.NewReader(strings.NewReader("y\n"))}
	_, err := Confirm(streams, "prompt", false)
	if err == nil {
		t.Fatal("Confirm() error = nil, want the write error to propagate")
	}
}

// --- DoWrite: dry-run --------------------------------------------------

func TestDoWriteDryRun(t *testing.T) {
	streams, out, errBuf := newStreams("")
	actionCalled := false
	code, err := DoWrite(streams, WriteRequest{
		DryRun:      true,
		Host:        "10.0.0.5",
		Description: "set port 1 speed to 1000M full-duplex",
		Action:      func() error { actionCalled = true; return nil },
	})
	if err != nil {
		t.Fatalf("DoWrite() error = %v, want nil", err)
	}
	if code != ExitOK {
		t.Errorf("DoWrite() code = %d, want %d", code, ExitOK)
	}
	want := "DRY-RUN: would set port 1 speed to 1000M full-duplex on 10.0.0.5 (nothing sent)\n"
	if out.String() != want {
		t.Errorf("DoWrite(dry-run) wrote %q, want %q", out.String(), want)
	}
	if errBuf.Len() != 0 {
		t.Errorf("DoWrite(dry-run) wrote to Err: %q, want nothing", errBuf.String())
	}
	if actionCalled {
		t.Error("DoWrite(dry-run) called Action, want it to send nothing")
	}
}

// --- DoWrite: confirm accepted / declined -------------------------

func TestDoWriteConfirmedRunsActionAndPrintsOK(t *testing.T) {
	streams, out, errBuf := newStreams("y\n")
	actionCalled := false
	code, err := DoWrite(streams, WriteRequest{
		Host:        "10.0.0.5",
		Description: "enable port 1",
		Action:      func() error { actionCalled = true; return nil },
	})
	if err != nil {
		t.Fatalf("DoWrite() error = %v, want nil", err)
	}
	if code != ExitOK {
		t.Errorf("DoWrite() code = %d, want %d", code, ExitOK)
	}
	if !actionCalled {
		t.Error("DoWrite() did not call Action")
	}
	wantPrompt := "About to enable port 1 on 10.0.0.5. [y/N]: "
	if errBuf.String() != wantPrompt {
		t.Errorf("DoWrite() wrote %q to Err, want %q", errBuf.String(), wantPrompt)
	}
	wantOut := "ok: enable port 1\n"
	if out.String() != wantOut {
		t.Errorf("DoWrite() wrote %q to Out, want %q", out.String(), wantOut)
	}
}

func TestDoWriteDeclinedAbortsWithoutRunningAction(t *testing.T) {
	streams, out, errBuf := newStreams("n\n")
	actionCalled := false
	code, err := DoWrite(streams, WriteRequest{
		Host:        "10.0.0.5",
		Description: "enable port 1",
		Action:      func() error { actionCalled = true; return nil },
	})
	if err != nil {
		t.Fatalf("DoWrite() error = %v, want nil", err)
	}
	if code != ExitError {
		t.Errorf("DoWrite() code = %d, want %d", code, ExitError)
	}
	if actionCalled {
		t.Error("DoWrite() called Action despite a decline")
	}
	if out.Len() != 0 {
		t.Errorf("DoWrite(declined) wrote to Out: %q, want nothing", out.String())
	}
	if !strings.Contains(errBuf.String(), "aborted: no changes made") {
		t.Errorf("DoWrite(declined) wrote %q to Err, want it to contain %q", errBuf.String(), "aborted: no changes made")
	}
}

func TestDoWriteAssumeYesSkipsPrompt(t *testing.T) {
	streams, _, errBuf := newStreams("")
	actionCalled := false
	code, err := DoWrite(streams, WriteRequest{
		AssumeYes:   true,
		Host:        "10.0.0.5",
		Description: "enable port 1",
		Action:      func() error { actionCalled = true; return nil },
	})
	if err != nil {
		t.Fatalf("DoWrite() error = %v, want nil", err)
	}
	if code != ExitOK {
		t.Errorf("DoWrite() code = %d, want %d", code, ExitOK)
	}
	if !actionCalled {
		t.Error("DoWrite(assumeYes) did not call Action")
	}
	if errBuf.Len() != 0 {
		t.Errorf("DoWrite(assumeYes) wrote to Err: %q, want nothing (no prompt)", errBuf.String())
	}
}

func TestDoWriteWarningPrependedToPrompt(t *testing.T) {
	streams, _, errBuf := newStreams("y\n")
	if _, err := DoWrite(streams, WriteRequest{
		Host:        "10.0.0.5",
		Description: "reboot switch",
		Warning:     "WARNING: this will drop all links.",
		Action:      func() error { return nil },
	}); err != nil {
		t.Fatalf("DoWrite() error = %v, want nil", err)
	}
	want := "WARNING: this will drop all links.\nAbout to reboot switch on 10.0.0.5. [y/N]: "
	if errBuf.String() != want {
		t.Errorf("DoWrite() wrote %q to Err, want %q", errBuf.String(), want)
	}
}

// --- DoWrite: action error propagation + exit-code classification ---

func TestDoWriteActionErrorPropagatesAndSkipsOKMessage(t *testing.T) {
	streams, out, _ := newStreams("y\n")
	wantErr := fmt.Errorf("verify failed: %w", &model.WriteVerificationError{Msg: "mismatch"})
	code, err := DoWrite(streams, WriteRequest{
		Host:        "10.0.0.5",
		Description: "set port 1 speed",
		Action:      func() error { return wantErr },
	})
	if !errors.Is(err, wantErr) && err.Error() != wantErr.Error() {
		t.Fatalf("DoWrite() error = %v, want %v", err, wantErr)
	}
	if code != ExitVerify {
		t.Errorf("DoWrite() code = %d, want %d (classified via ExitCodeFor)", code, ExitVerify)
	}
	if strings.Contains(out.String(), "ok:") {
		t.Errorf("DoWrite() wrote %q to Out, want no \"ok:\" message on Action failure", out.String())
	}
}

func TestDoWriteActionProtectedPortError(t *testing.T) {
	streams, _, _ := newStreams("y\n")
	code, err := DoWrite(streams, WriteRequest{
		Host:        "10.0.0.5",
		Description: "disable port 1",
		Action:      func() error { return fmt.Errorf("port 1 is protected: %w", model.ErrProtectedPort) },
	})
	if err == nil {
		t.Fatal("DoWrite() error = nil, want the protected-port error")
	}
	if code != ExitProtected {
		t.Errorf("DoWrite() code = %d, want %d", code, ExitProtected)
	}
}

func TestDoWriteActionGenericError(t *testing.T) {
	streams, _, _ := newStreams("y\n")
	code, err := DoWrite(streams, WriteRequest{
		Host:        "10.0.0.5",
		Description: "enable port 1",
		Action:      func() error { return errors.New("network unreachable") },
	})
	if err == nil {
		t.Fatal("DoWrite() error = nil, want the action's error")
	}
	if code != ExitError {
		t.Errorf("DoWrite() code = %d, want %d", code, ExitError)
	}
}

// --- Secret redaction --------------------------------------------------

// TestDoWriteNeverEchoesSecrets confirms DoWrite's prompts/messages only
// ever interpolate Description/Host/Warning -- never a credential value
// -- by constructing a request whose Action closure closes over a
// "secret" that must never appear in ANY stream DoWrite writes to,
// across every code path (dry-run, prompt, ok, abort).
func TestDoWriteNeverEchoesSecrets(t *testing.T) {
	const secret = "s3cr3t-write-community-DO-NOT-LEAK"
	req := func(dryRun bool, assumeYes bool) WriteRequest {
		return WriteRequest{
			DryRun:      dryRun,
			AssumeYes:   assumeYes,
			Host:        "10.0.0.5",
			Description: "set snmp write community", // deliberately generic, no secret value
			Action:      func() error { _ = secret; return nil },
		}
	}

	for _, tc := range []struct {
		name string
		in   string
		req  WriteRequest
	}{
		{"dry-run", "", req(true, false)},
		{"confirmed", "y\n", req(false, false)},
		{"declined", "n\n", req(false, false)},
		{"assume-yes", "", req(false, true)},
	} {
		streams, out, errBuf := newStreams(tc.in)
		if _, err := DoWrite(streams, tc.req); err != nil {
			t.Fatalf("%s: DoWrite() error = %v, want nil", tc.name, err)
		}
		if strings.Contains(out.String(), secret) || strings.Contains(errBuf.String(), secret) {
			t.Errorf("%s: DoWrite() leaked the secret value into output: out=%q err=%q", tc.name, out.String(), errBuf.String())
		}
	}
}

// --- Confirm: real (non-EOF) read error ---------------------------

func TestConfirmReadErrorPropagates(t *testing.T) {
	streams := Streams{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, In: bufio.NewReader(erroringReader{})}
	_, err := Confirm(streams, "prompt", false)
	if err == nil {
		t.Fatal("Confirm() error = nil, want the underlying read error to propagate")
	}
}

// --- DoWrite: write-failure branches on every stream it touches ----

func TestDoWriteDryRunWriteErrorPropagates(t *testing.T) {
	streams := Streams{Out: failingWriter{}, Err: &bytes.Buffer{}, In: bufio.NewReader(strings.NewReader(""))}
	code, err := DoWrite(streams, WriteRequest{
		DryRun:      true,
		Host:        "10.0.0.5",
		Description: "enable port 1",
		Action:      func() error { return nil },
	})
	if err == nil {
		t.Fatal("DoWrite(dry-run) error = nil, want the Out write failure to propagate")
	}
	if code != ExitError {
		t.Errorf("DoWrite(dry-run) code = %d, want %d", code, ExitError)
	}
}

func TestDoWriteOKMessageWriteErrorPropagates(t *testing.T) {
	streams := Streams{Out: failingWriter{}, Err: &bytes.Buffer{}, In: bufio.NewReader(strings.NewReader("y\n"))}
	code, err := DoWrite(streams, WriteRequest{
		Host:        "10.0.0.5",
		Description: "enable port 1",
		Action:      func() error { return nil },
	})
	if err == nil {
		t.Fatal("DoWrite() error = nil, want the Out write failure (the final \"ok: ...\" print) to propagate")
	}
	if code != ExitError {
		t.Errorf("DoWrite() code = %d, want %d", code, ExitError)
	}
}

func TestDoWriteAbortMessageWriteErrorPropagates(t *testing.T) {
	// The FIRST write to Err (Confirm's own prompt) must succeed so the
	// SECOND write (DoWrite's own "aborted: ..." message, after a
	// decline) is the one that fails -- isolating DoWrite's own Fprintln
	// error-return branch from Confirm's.
	streams := Streams{Out: &bytes.Buffer{}, Err: &failAfterWriter{n: 1}, In: bufio.NewReader(strings.NewReader("n\n"))}
	code, err := DoWrite(streams, WriteRequest{
		Host:        "10.0.0.5",
		Description: "enable port 1",
		Action:      func() error { return nil },
	})
	if err == nil {
		t.Fatal("DoWrite() error = nil, want the Err write failure (the \"aborted: ...\" print) to propagate")
	}
	if code != ExitError {
		t.Errorf("DoWrite() code = %d, want %d", code, ExitError)
	}
}
