// session.go ports src/netgear_switch/transport/cli/session.py (241 lines)
// at pin 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362 -- the shared,
// transport-free FASTPATH shell-session state machine every real CLI
// transport (SSH/telnet/serial, Tasks 6-7) reuses unchanged, and the
// package's write path (Task 9-10) drives through the `run`/`inMode`
// accept-reject convention (protocol dossier §4.1). Any discrepancy
// between this file and the pin is a bug in this file, not a deliberate
// deviation, unless called out in a comment.
//
// Field mapping notes (Python -> Go), mirroring the conventions already
// established by webui.Session / nsdp.Client:
//
//   - Python's `send`/`recv` callables (session.py:82-84, "deliberately
//     transport-free so SSH, telnet and console reuse it unchanged")
//     become one Go interface, Transport (io.ReadWriteCloser): a
//     Read/Write/Close-able byte channel. Any concrete type that already
//     satisfies io.ReadWriteCloser satisfies Transport with no adapter
//     code, and a scripted in-memory fake is trivial to write for tests.
//   - Go has no default arguments and no separate sync/async client split
//     (Python needs neither a `command: str = "write memory"` default nor
//     two Protocol classes); every Session method takes context.Context
//     first, matching the webui.Session / nsdp.Client idiom already
//     established elsewhere in this repo.
//   - ShellDriver directly implements Session (unlike Python, where each
//     of the three real transport CLASSES implements CliSession and each
//     independently *contains* a ShellDriver): since Go's ShellDriver is
//     already transport-agnostic via the Transport interface, there is no
//     need for a second wrapping type per transport -- ssh.go/telnet.go/
//     serial.go (Tasks 6-7) each only need to construct a Transport value
//     (dial + authenticate at the byte level) and hand it to
//     NewShellDriver, then call Setup once before returning the
//     *ShellDriver as a Session. This also means ShellDriver owns Close
//     (Python's ShellDriver has no close method at all -- closing is each
//     transport CLASS's own job, session.py has none) since there is no
//     separate wrapper type left to own it in the Go shape.
//   - `run`/`inMode` (protocol dossier §4.1, CliWriter._run/_in_mode,
//     python-netgear-switch-library dossier
//     2026-08-01-slice-07-dossier-cli-protocol.md lines 1169-1212) are
//     ported here, ahead of the Task 9/10 Writer, as free functions over
//     the Session interface rather than CliWriter methods: Go has no
//     access-modifier reason to duplicate them per writer, and hoisting
//     them here lets this file's own tests exercise the counted-unwind
//     hazard (protocol dossier risk #5) against a scripted Session
//     directly, without needing a CliModelSpec or Writer.
package fastpath

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// --- Sentinels (transport dossier §1.1, quoted/ported verbatim) -----------

// promptRE mirrors Python `_PROMPT_RE` (session.py:28): FASTPATH prompts
// look like "(GSM7252PS) #" (privileged) or "(GSM7252PS) >" (unprivileged);
// some pages also show "(GSM7252PS) (Config)#". Match a ")" followed by an
// optional parenthesised word and a #/> at end of the buffered output.
// Anchored to end-of-buffer (unlike the SCP sentinels below) -- note the
// trailing `\s*` before `$` means this is faithful under Go regexp's
// stricter (non-multiline) `$` semantics (true end-of-text, not "before a
// trailing newline" like Python's default `$`): any trailing whitespace/
// newline after the prompt character is consumed by `\s*` first, so `$`
// always lands on the true end of the buffer either way.
var promptRE = regexp.MustCompile(`\)\s*(?:\([^)]*\)\s*)?[#>]\s*$`)

// passwordRE mirrors Python `_PASSWORD_RE` (session.py:29). Also
// end-anchored.
var passwordRE = regexp.MustCompile(`[Pp]assword:\s*$`)

// maxReads mirrors Python `_MAX_READS = 10_000` (session.py:32): "a hard
// cap so a transport that never sees a prompt (wrong device, hung link)
// fails instead of looping forever." This is a loop-iteration bound, NOT a
// wall-clock timeout -- the per-Read-call timeout is each transport's own
// responsibility (Tasks 6-7).
const maxReads = 10_000

// recvChunkSize mirrors Python's `self._recv(4096)` -- the fixed read size
// every ShellDriver read loop uses.
const recvChunkSize = 4096

// The five SCP sentinels (transport dossier §1.1, session.py:39-47) are
// NOT anchored to end-of-buffer (unlike promptRE/passwordRE): they appear
// inline as the switch's SCP client runs, so they are matched anywhere in
// the buffer accumulated since the last answered prompt. GROUNDED in the
// working certbot-hook FastpathScpUpdater._send_copy regexes per the pin's
// own comment.
var (
	scpTOFURE     = regexp.MustCompile(`(?i)host key|continue connecting|\(yes\s*/\s*no`)
	scpPasswordRE = regexp.MustCompile(`[Pp]assword:`)
	scpConfirmRE  = regexp.MustCompile(`\(y\s*/\s*n\)`)
	scpSuccessRE  = regexp.MustCompile(`(?i)bytes transferred|completed successfully|operation completed`)
	scpFailureRE  = regexp.MustCompile(`(?i)transfer failed|failed!|%\s*error|error during`)
)

// ErrCliTransport mirrors Python `CliTransportError` (session.py:75-76):
// "A CLI transport failed to connect, authenticate, or read a prompt." --
// the one error every transport/ShellDriver failure wraps, matchable with
// errors.Is.
var ErrCliTransport = errors.New("fastpath: cli transport error")

// ErrCliCommandRejected mirrors the CliWriter._run "any non-empty output =
// reject" convention (protocol dossier §4.1): FASTPATH answers an accepted
// configuration command with EMPTY output, so any text back ("% Invalid
// input ...", "ERROR: ...") is treated as a rejection and returned as an
// error, never swallowed. Nothing parses the rejection text itself, only
// its emptiness (dossier: "the rejection-string WORDING is NOT ground
// truth... only the empty/non-empty CONTRACT matters").
var ErrCliCommandRejected = errors.New("fastpath: cli command rejected")

// --- Session ---------------------------------------------------------------

// Session is a ready-to-use, already-authenticated FASTPATH CLI session for
// one switch: the Go equivalent of Python's CliSession Protocol (transport
// dossier §1.2, session.py:50-72). Setup (enable + disable paging) is the
// responsibility of whichever transport constructs the session (ssh.go/
// telnet.go/serial.go, Tasks 6-7) -- by the time a Session is handed to a
// caller, ShellDriver.Setup has already run once; nothing in this
// interface's contract requires calling it again.
type Session interface {
	// Run issues one command and returns its output text with the echoed
	// command line and the trailing prompt removed.
	Run(ctx context.Context, command string) (string, error)

	// RunSCPCopy issues an interactive `copy scp://...` and drives its
	// mid-command prompts (host-key TOFU, remote password, (y/n) overwrite
	// confirm), returning the transcript on success and an error wrapping
	// ErrCliTransport on failure. Only the FASTPATH cert-deploy write path
	// (a later task) uses this; a session used purely for reads never
	// calls it.
	RunSCPCopy(ctx context.Context, command, scpPassword string) (string, error)

	// RunWriteMemory issues command (normally "write memory") and answers
	// its (y/n) save-config confirm. prestuff selects which of the two
	// FASTPATH confirm dialects to drive: true pre-stuffs the "y" answer
	// in the same write as the command (GSM7252PS, whose confirm times out
	// too fast for a read-then-answer round trip); false waits for the
	// (y/n) prompt then answers it (M4300).
	RunWriteMemory(ctx context.Context, command string, prestuff bool) (string, error)

	// Close releases the underlying transport.
	Close() error
}

// Transport is the abstract byte-level interactive-shell channel
// ShellDriver drives -- deliberately transport-free (mirrors Python
// ShellDriver's send/recv callables, session.py:82-84: "This is
// deliberately transport-free so SSH, telnet and console reuse it
// unchanged") so SSH, telnet, and console (Tasks 6-7) share this exact
// framing logic; only how a channel's bytes are wired differs per
// transport. Read returning 0 bytes with a non-nil error signals the
// channel closed with no more data available right now (mirrors Python's
// blocking recv() returning b"" on a closed channel) and is NOT itself
// treated as a hard failure by ShellDriver's read loops -- they stop
// reading and decide based on whatever was accumulated. Any Read call that
// returns 0 bytes with an error OTHER than io.EOF propagates immediately
// as a genuine failure (mirrors a Python recv() raising, e.g. a socket
// timeout or a reset connection).
type Transport interface {
	io.ReadWriteCloser
}

// ShellDriverConfig configures ShellDriver's session-setup handshake,
// mirroring ShellDriver.__init__'s keyword-only parameters
// (session.py:89-104). Zero-value fields for EnableCmd/PagingOffCmd/
// Newline fall back to the same defaults Python's signature declares;
// EnablePassword's zero value ("") matches Python's `enable_password: str
// | None = None` -- "if the enable prompt asks for a password, reuse the
// login password by default" becomes "write whatever EnablePassword holds,
// even if empty" here, exactly as Python's `self._enable_password or ""`
// does.
type ShellDriverConfig struct {
	EnableCmd      string
	PagingOffCmd   string
	EnablePassword string
	Newline        string
}

// ShellDriver frames an interactive shell (a Transport's bytes) into
// per-command text: send a command, read back until the FASTPATH prompt
// reappears, strip the command echo and the trailing prompt. Mirrors
// Python's ShellDriver class (session.py:79-241) field-for-field, with
// Close folded in (see the file-level doc comment for why). Construct with
// NewShellDriver, call Setup once, then use it as a Session.
type ShellDriver struct {
	transport Transport
	cfg       ShellDriverConfig
}

// NewShellDriver constructs a ShellDriver over transport, applying
// ShellDriverConfig's Python-equivalent defaults for any zero-valued
// field. Callers (ssh.go/telnet.go/serial.go, Tasks 6-7) must call Setup
// once, after transport-level connect/auth has already succeeded, before
// treating the result as a ready Session -- mirrors the docstring on
// CliSession.run: "Setup (enable + disable paging) is the transport's
// responsibility, done before the first `run`."
func NewShellDriver(transport Transport, cfg ShellDriverConfig) *ShellDriver {
	if cfg.EnableCmd == "" {
		cfg.EnableCmd = "enable"
	}
	if cfg.PagingOffCmd == "" {
		cfg.PagingOffCmd = "terminal length 0"
	}
	if cfg.Newline == "" {
		cfg.Newline = "\r\n"
	}
	return &ShellDriver{transport: transport, cfg: cfg}
}

// writeLine mirrors Python `_write_line` (session.py:120-122): writes
// text+Newline as raw bytes.
func (d *ShellDriver) writeLine(text string) error {
	_, err := d.transport.Write([]byte(text + d.cfg.Newline))
	return err
}

// readUntil mirrors Python `_read_until` (session.py:106-119): accumulates
// Read chunks (up to recvChunkSize bytes at a time, up to maxReads
// iterations) until promptRE matches the whole buffer, or -- if
// allowPassword -- passwordRE matches. Returns an error wrapping
// ErrCliTransport if the channel closes (a 0-byte, io.EOF read) or maxReads
// is exhausted without ever seeing a prompt.
func (d *ShellDriver) readUntil(allowPassword bool) (string, error) {
	var buf strings.Builder
	chunk := make([]byte, recvChunkSize)
	for i := 0; i < maxReads; i++ {
		n, err := d.transport.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
		}
		text := buf.String()
		if promptRE.MatchString(text) {
			return text, nil
		}
		if allowPassword && passwordRE.MatchString(text) {
			return text, nil
		}
		if n == 0 {
			if err != nil && err != io.EOF {
				return "", fmt.Errorf("%w: read failed: %w", ErrCliTransport, err)
			}
			// Channel closed with no prompt seen (mirrors Python's
			// `if not chunk: break`).
			break
		}
	}
	return "", fmt.Errorf("%w: no CLI prompt seen before end of stream", ErrCliTransport)
}

// Setup mirrors Python `ShellDriver.setup` (session.py:124-134): consume
// the initial banner/prompt, send the enable command, answer an enable
// password prompt if one appears (reusing EnablePassword), then disable
// paging. ctx is checked once up front for fail-fast cancellation; the
// underlying blocking Read/Write calls are each Transport implementation's
// own responsibility to bound (e.g. via a socket/serial deadline) --
// ShellDriver itself has no way to interrupt a call already in flight.
func (d *ShellDriver) Setup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := d.readUntil(false); err != nil { // initial banner/prompt
		return err
	}
	if err := d.writeLine(d.cfg.EnableCmd); err != nil {
		return err
	}
	out, err := d.readUntil(true)
	if err != nil {
		return err
	}
	if passwordRE.MatchString(out) {
		// enable asked for a password; reuse the login password by default.
		if err := d.writeLine(d.cfg.EnablePassword); err != nil {
			return err
		}
		if _, err := d.readUntil(false); err != nil {
			return err
		}
	}
	if err := d.writeLine(d.cfg.PagingOffCmd); err != nil {
		return err
	}
	_, err = d.readUntil(false)
	return err
}

// Run implements Session, mirroring Python `ShellDriver.run`
// (session.py:136-139).
func (d *ShellDriver) Run(ctx context.Context, command string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := d.writeLine(command); err != nil {
		return "", err
	}
	raw, err := d.readUntil(false)
	if err != nil {
		return "", err
	}
	return cleanOutput(raw, command), nil
}

// RunSCPCopy implements Session, mirroring Python
// `ShellDriver.run_scp_copy` (session.py:141-198) exactly, including its
// control-flow order (failure check first every iteration, then TOFU, then
// password, then the (y/n) confirm, then the success marker, then the
// prompt, then end-of-stream) and its per-answered-prompt buffer reset
// (buf, not transcript, is cleared after each answered mid-flight prompt).
func (d *ShellDriver) RunSCPCopy(ctx context.Context, command, scpPassword string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := d.writeLine(command); err != nil {
		return "", err
	}
	var transcript strings.Builder
	var buf strings.Builder
	succeeded := false
	chunk := make([]byte, recvChunkSize)
	for i := 0; i < maxReads; i++ {
		n, err := d.transport.Read(chunk)
		if n > 0 {
			transcript.Write(chunk[:n])
			buf.Write(chunk[:n])
		}
		text := buf.String()
		if scpFailureRE.MatchString(text) {
			return "", fmt.Errorf("%w: SCP copy reported a failed transfer: %q", ErrCliTransport, command)
		}
		if scpTOFURE.MatchString(text) {
			if err := d.writeLine("yes"); err != nil {
				return "", err
			}
			buf.Reset()
			continue
		}
		if scpPasswordRE.MatchString(text) {
			if err := d.writeLine(scpPassword); err != nil {
				return "", err
			}
			buf.Reset()
			continue
		}
		if scpConfirmRE.MatchString(text) {
			// FASTPATH's (y/n) overwrite confirm takes a single keystroke.
			if _, err := d.transport.Write([]byte("y")); err != nil {
				return "", err
			}
			buf.Reset()
			continue
		}
		if scpSuccessRE.MatchString(text) {
			succeeded = true
		}
		if promptRE.MatchString(text) {
			return transcript.String(), nil
		}
		if n == 0 {
			if err != nil && err != io.EOF {
				return "", fmt.Errorf("%w: read failed: %w", ErrCliTransport, err)
			}
			break
		}
	}
	if succeeded {
		return transcript.String(), nil
	}
	return "", fmt.Errorf("%w: SCP copy did not complete: %q", ErrCliTransport, command)
}

// RunWriteMemory implements Session, mirroring Python
// `ShellDriver.run_write_memory` (session.py:200-229). Unlike RunSCPCopy,
// there is no "succeeded but no prompt" short-circuit here -- write-memory
// never treats a mid-transcript success phrase as itself sufficient;
// running out of stream without a prompt is always an error.
func (d *ShellDriver) RunWriteMemory(ctx context.Context, command string, prestuff bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if prestuff {
		// GSM7252PS pre-stuffs the "y" answer in the SAME write as the
		// command, because that image's confirm has a tiny timeout that a
		// read-then-answer round trip races.
		if _, err := d.transport.Write([]byte(command + "\ry\r")); err != nil {
			return "", err
		}
	} else {
		if err := d.writeLine(command); err != nil {
			return "", err
		}
	}
	var transcript strings.Builder
	var buf strings.Builder
	chunk := make([]byte, recvChunkSize)
	for i := 0; i < maxReads; i++ {
		n, err := d.transport.Read(chunk)
		if n > 0 {
			transcript.Write(chunk[:n])
			buf.Write(chunk[:n])
		}
		text := buf.String()
		if !prestuff && scpConfirmRE.MatchString(text) {
			if _, err := d.transport.Write([]byte("y")); err != nil {
				return "", err
			}
			buf.Reset()
			continue
		}
		if promptRE.MatchString(text) {
			return transcript.String(), nil
		}
		if n == 0 {
			if err != nil && err != io.EOF {
				return "", fmt.Errorf("%w: read failed: %w", ErrCliTransport, err)
			}
			break
		}
	}
	return "", fmt.Errorf("%w: write memory did not complete", ErrCliTransport)
}

// Close implements Session by closing the underlying Transport. Python's
// ShellDriver has no close method at all (each transport CLASS owns
// teardown, suppressing exceptions -- "teardown must not raise"); Go's
// ShellDriver folds that role in since there is no separate wrapper type
// left to own it (see the file-level doc comment). Deliberately does NOT
// suppress the Transport's Close error the way Python's per-transport
// close() does -- callers that want Python's "never raise on teardown"
// behavior can discard the error themselves, exactly as inMode's own
// unwind does below.
func (d *ShellDriver) Close() error {
	return d.transport.Close()
}

// cleanOutput mirrors Python `ShellDriver._clean` (session.py:231-241,
// @staticmethod): drop the echoed command line (substring containment, not
// exact equality -- tolerates a device echoing the command with extra
// leading/trailing whitespace or control bytes on that line) and the
// trailing prompt line(s) (a while-loop: MULTIPLE trailing prompt-matching
// lines are all stripped).
func cleanOutput(raw, command string) string {
	normalized := strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(normalized, "\n")
	trimmedCmd := strings.TrimSpace(command)
	if len(lines) > 0 && trimmedCmd != "" && strings.Contains(lines[0], trimmedCmd) {
		lines = lines[1:]
	}
	for len(lines) > 0 && promptRE.MatchString(lines[len(lines)-1]) {
		lines = lines[:len(lines)-1]
	}
	return strings.Trim(strings.Join(lines, "\n"), "\n")
}

// --- run / inMode: the FASTPATH config-mode accept/reject convention ------

// run issues command on sess and returns an error if the switch answered
// with ANY non-empty (trimmed) output -- the blanket FASTPATH config-mode
// accept/reject convention every write op relies on (protocol dossier
// §4.1, CliWriter._run: "FASTPATH answers an ACCEPTED configuration
// command with EMPTY output, so any text back... is treated as a failure
// and raised... never swallowed"). Nothing here parses the rejection text
// itself, only its emptiness.
func run(ctx context.Context, sess Session, command string) error {
	out, err := sess.Run(ctx, command)
	if err != nil {
		return err
	}
	if trimmed := strings.TrimSpace(out); trimmed != "" {
		return fmt.Errorf("%w: %q: %s", ErrCliCommandRejected, command, trimmed)
	}
	return nil
}

// inMode runs enter (a nested config-mode entry sequence, e.g.
// []string{"vlan database"} or []string{"configure terminal", "interface
// 1/0/7"}) then body, each command through run's accept/reject convention,
// and ALWAYS unwinds with one exitCmd per level ACTUALLY entered -- even
// when a body command (or a later enter command) is rejected -- mirroring
// Python `CliWriter._in_mode` (protocol dossier §4.1, lines 1186-1212).
//
// This is the counted-unwind hazard call out by protocol dossier risk #5:
// entered only increments strictly AFTER each enter[] command succeeds, so
// if e.g. the 2nd of 3 enter commands is rejected, entered == 1 and only
// ONE exitCmd is issued during unwind -- NOT len(enter), and NOT zero. The
// unwind issues exitCmd via sess.Run directly, never through run: "an
// error while backing out must not mask the real failure" -- exit's own
// output/error (if any) is silently discarded, never returned. Getting
// this wrong strands the shared session in a nested config prompt,
// corrupting every subsequent read on that session -- including this same
// write's own verify-after-write read-back.
func inMode(ctx context.Context, sess Session, enter, body []string, exitCmd string) error {
	entered := 0
	defer func() {
		for i := 0; i < entered; i++ {
			_, _ = sess.Run(ctx, exitCmd) // errors intentionally discarded
		}
	}()
	for _, cmd := range enter {
		if err := run(ctx, sess, cmd); err != nil {
			return err
		}
		entered++
	}
	for _, cmd := range body {
		if err := run(ctx, sess, cmd); err != nil {
			return err
		}
	}
	return nil
}
