// Package safety is the write-safety gate ngsw's disruptive commands
// funnel every mutating operation through, plus the shared exit-code
// policy those commands report through. Ported from
// src/netgear_switch/cli/safety.py and cli/context.py (the normative
// source; that repo is read-only from here). Any discrepancy between this
// file and the pinned Python source is a bug in this file.
//
// DoWrite/Confirm read from and write to an injected Streams bundle
// (never os.Stdin/os.Stdout/os.Stderr directly), so the whole package is
// unit-testable without a real TTY.
//
// SECRET REDACTION: DoWrite/Confirm interpolate ONLY the caller-supplied
// Description/Host/Warning strings into their prompts and messages --
// never a credential. Every ngsw command must build its Description from
// facade-granularity values (port/vlan/name/rate), exactly as safety.py's
// own do_write doc comment requires; this package has nothing to redact
// because it never touches a secret value itself.
package safety

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
)

// Exit codes, mirroring cli/context.py's EXIT_* constants exactly.
const (
	// ExitOK is the successful-completion exit code.
	ExitOK = 0
	// ExitError is the generic-failure exit code -- anything not more
	// specifically classified below.
	ExitError = 1
	// ExitUsage is the argument-parsing/usage-error exit code (e.g. a bad
	// flag combination). Never returned by ExitCodeFor -- reserved for a
	// CLI's own flag-parsing layer, which mirrors context.py's EXIT_USAGE
	// existing only as a constant argparse-adjacent callers use directly.
	ExitUsage = 2
	// ExitVerify is returned when a write's verify-after-write step
	// mismatched (model.WriteVerificationError).
	ExitVerify = 3
	// ExitProtected is returned when a write was refused because it
	// targeted a protected port (model.ErrProtectedPort).
	ExitProtected = 4
)

// ExitCodeFor maps err to the process exit code an ngsw command should
// report, mirroring cli/context.py's exit_code_for: a
// *model.WriteVerificationError (matched via errors.As, so it still
// classifies correctly when wrapped with fmt.Errorf("...: %w", ...))
// maps to ExitVerify; an error wrapping model.ErrProtectedPort (matched
// via errors.Is) maps to ExitProtected; any other non-nil error maps to
// ExitError. A nil err maps to ExitOK -- an extension beyond
// exit_code_for's own Python signature (which is only ever called on an
// actually-raised exception), added because a Go caller naturally has
// this function available for the success case too.
func ExitCodeFor(err error) int {
	if err == nil {
		return ExitOK
	}
	var verifyErr *model.WriteVerificationError
	if errors.As(err, &verifyErr) {
		return ExitVerify
	}
	if errors.Is(err, model.ErrProtectedPort) {
		return ExitProtected
	}
	return ExitError
}

// Streams bundles the input/output handles DoWrite/Confirm read from and
// write to, mirroring the out/err/inp fields of cli/context.py's
// CliContext (as_json/verbose are CLI-specific concerns that stay out of
// this shared package -- see fmtx.Emit's separate asJSON parameter for
// where that lives instead). In is a *bufio.Reader (not a bare io.Reader)
// so Confirm can call ReadString directly, matching Python's
// `ctx.inp.readline()`.
type Streams struct {
	Out io.Writer
	Err io.Writer
	In  *bufio.Reader
}

// Confirm asks for confirmation by printing "{prompt} [y/N]: " to
// streams.Err and reading one line from streams.In, mirroring
// safety.py's confirm exactly. assumeYes (-y/--yes) short-circuits to
// true without printing or reading anything. The reply is accepted
// case-insensitively as "y" or "yes" (leading/trailing whitespace
// trimmed first); anything else -- including an empty reply or an
// immediate EOF (streams.In already exhausted) -- is a decline, NOT an
// error: Python's ctx.inp.readline() returns "" at EOF without raising,
// and this mirrors that exactly (io.EOF from ReadString is swallowed
// here, not propagated).
func Confirm(streams Streams, prompt string, assumeYes bool) (bool, error) {
	if assumeYes {
		return true, nil
	}
	if _, err := fmt.Fprintf(streams.Err, "%s [y/N]: ", prompt); err != nil {
		return false, err
	}
	line, err := streams.In.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	reply := strings.ToLower(strings.TrimSpace(line))
	return reply == "y" || reply == "yes", nil
}

// WriteRequest bundles DoWrite's parameters, mirroring safety.py's
// do_write keyword arguments as one struct -- Go has no keyword
// arguments, and do_write's Python signature already reads as a small
// named-parameter bundle.
type WriteRequest struct {
	// DryRun (--dry-run): describe the operation and send nothing.
	DryRun bool
	// AssumeYes (-y/--yes): skip the confirmation prompt.
	AssumeYes bool
	// Host is the target switch, interpolated into both the dry-run and
	// confirmation messages.
	Host string
	// Description is the operation description at FACADE granularity
	// (method + args), e.g. "set port 12 speed to 1000M full-duplex" --
	// NEVER a re-encoded wire payload (SNMP SET/NSDP packet/HTTP form)
	// and NEVER a credential; see this package's doc comment.
	Description string
	// Warning, if non-empty, is prepended (its own line) to the
	// confirmation prompt -- e.g. a note that the op will bounce a link.
	// Mirrors safety.py's `warning: str | None = None`.
	Warning string
	// Action is the verify-after-write facade call. Any error it returns
	// propagates back through DoWrite's own return value UNCHANGED (for
	// ExitCodeFor to classify) -- mirrors safety.py's doc comment: "any
	// NetgearSwitchError it raises propagates to main() for clean
	// reporting", ported here as an ordinary Go return rather than a
	// Python exception unwinding through the call.
	Action func() error
}

// DoWrite is the single disruptive-write gate every ngsw mutating command
// funnels through: dry-run short-circuits (describe, send nothing); else
// print a confirmation prompt to streams.Err and read one line from
// streams.In (via Confirm); on decline, print "aborted: no changes made"
// to streams.Err and return ExitError with a nil error (an abort is not
// itself a failure worth logging further -- mirrors safety.py returning
// EXIT_ERROR with no exception); on confirm, run req.Action -- if it
// returns an error, DoWrite returns (ExitCodeFor(err), err) WITHOUT
// printing "ok: ..." (mirroring do_write's error path never reaching its
// own success print, since in Python action() raising skips the rest of
// the function entirely); on success, print "ok: {description}" to
// streams.Out and return (ExitOK, nil). Mirrors safety.py's do_write
// exactly.
func DoWrite(streams Streams, req WriteRequest) (int, error) {
	if req.DryRun {
		if _, err := fmt.Fprintf(streams.Out, "DRY-RUN: would %s on %s (nothing sent)\n", req.Description, req.Host); err != nil {
			return ExitError, err
		}
		return ExitOK, nil
	}

	prompt := fmt.Sprintf("About to %s on %s.", req.Description, req.Host)
	if req.Warning != "" {
		prompt = req.Warning + "\n" + prompt
	}
	ok, err := Confirm(streams, prompt, req.AssumeYes)
	if err != nil {
		return ExitError, err
	}
	if !ok {
		if _, err := fmt.Fprintln(streams.Err, "aborted: no changes made"); err != nil {
			return ExitError, err
		}
		return ExitError, nil
	}

	if err := req.Action(); err != nil {
		return ExitCodeFor(err), err
	}

	if _, err := fmt.Fprintf(streams.Out, "ok: %s\n", req.Description); err != nil {
		return ExitError, err
	}
	return ExitOK, nil
}
