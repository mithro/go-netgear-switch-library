// Command gngsw is the Go port of Python's "ngsw" CLI: query and control
// Netgear switches over the netgearswitch facade. Ported from
// src/netgear_switch/cli/main.py (the normative source; that repo is
// read-only from here). Any discrepancy between this package and the
// pinned Python source is a bug in this package.
//
// This file defines the injectable-dependency seam (App/cmdContext) every
// subcommand's RunE closes over, mirroring Python main()'s own
// switch_factory/stdin/stdout/stderr/env/prompt parameters -- see
// tests/cli/test_cli_integration.py's own doc comment: "the resolve seam is
// bypassed via switch_factory (exactly how main is designed to be driven in
// tests)". Every ngsw subcommand ultimately returns a distinct process exit
// code (safety.ExitOK/ExitError/ExitUsage/ExitVerify/ExitProtected), which
// cobra's own RunE-returns-error convention cannot carry on the SUCCESS
// path (a dry-run or a declined confirmation both return nil error but a
// non-zero code) -- so the resolved code is tracked out-of-band on
// cmdContext rather than through cobra's Execute() return value; see
// Run's own doc comment.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/resolve"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/safety"
)

// App bundles gngsw's injectable dependencies: the streams every command
// reads from/writes to (never os.Stdin/os.Stdout/os.Stderr referenced
// directly anywhere below this file), the environment lookup and
// interactive prompt resolve.Resolve consults, and an optional
// SwitchFactory that -- when non-nil -- REPLACES resolve.Resolve entirely,
// mirroring Python main()'s own switch_factory parameter (the sanctioned
// test seam the Python reference's own CLI integration tests use, per
// tests/cli/test_cli_integration.py's doc comment). A nil SwitchFactory
// (the production default) drives the real resolve.Resolve path.
type App struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader

	// Env overrides the environment lookup resolve.Resolve uses for
	// NGSW_COMMUNITY/NGSW_WRITE_COMMUNITY (and the inventory path's own
	// secret-spec resolvers). nil uses resolve.Resolve's own default
	// (os.LookupEnv, the process's real environment).
	Env func(string) (string, bool)
	// Prompt supplies the interactive prompt resolve.Resolve falls back to
	// for an unresolved SNMP read community. nil disables interactive
	// prompting entirely (resolve.Resolve's own default) -- the right
	// default for anything non-interactive; production wiring (main.go)
	// injects resolve.NewStdinPrompt.
	Prompt resolve.PromptFunc

	// SwitchFactory, when non-nil, builds the target *netgearswitch.Switch
	// directly from the resolved resolve.Params, bypassing resolve.Resolve
	// (and therefore Env/Prompt above) entirely. Primarily for tests that
	// want to point a command at an in-process or real-loopback
	// virtual.VirtualSwitch without going through resolve.Resolve's
	// network-facing client construction.
	SwitchFactory func(p resolve.Params) (*netgearswitch.Switch, error)
}

// defaultApp returns the production App: the process's real stdio streams,
// the real environment, and an interactive stdin prompt for an unresolved
// SNMP community -- mirroring Python main()'s own defaults (stdin=sys.stdin,
// stdout=sys.stdout, stderr=sys.stderr, env=os.environ, prompt=getpass.getpass).
// Go has no direct getpass.getpass() equivalent in the standard library;
// resolve.NewStdinPrompt (echoing the typed community to stderr) is the
// closest -- an intentional, documented deviation, not an oversight.
func defaultApp() *App {
	return &App{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Stdin:  os.Stdin,
		Prompt: resolve.NewStdinPrompt(os.Stderr, bufio.NewReader(os.Stdin)),
	}
}

// globalFlags holds the 10 persistent (global) flag values every gngsw
// subcommand reads, mirroring main.py's _global_parser fields. Registered
// ONCE on the root cobra.Command (root.go): cobra's persistent flags are
// inherited by every descendant command regardless of whether the flag
// appears before or after the subcommand name on the command line, so --
// unlike main.py's own suppress_defaults/child_gp dance, which exists
// purely to work around argparse's subparser default-clobbering quirk --
// no per-subcommand re-registration is needed here at all.
type globalFlags struct {
	config, switchName, host, modelKey string
	community, writeCommunity          string
	nsdpInterface, httpPassword        string
	backend                            string
	asJSON, verbose                    bool
}

// params builds a resolve.Params from f, mirroring resolve.py's own
// argparse.Namespace field reads.
func (f *globalFlags) params() resolve.Params {
	return resolve.Params{
		Switch:         f.switchName,
		Config:         f.config,
		Host:           f.host,
		Model:          f.modelKey,
		Community:      f.community,
		WriteCommunity: f.writeCommunity,
		Backend:        f.backend,
		NSDPInterface:  f.nsdpInterface,
		HTTPPassword:   f.httpPassword,
	}
}

// cmdContext is threaded through every RunE closure (root.go builds one
// per Run call): flags is the shared globalFlags every subcommand reads,
// code is the resolved process exit code (see this file's doc comment for
// why cobra's Execute() error return alone cannot carry it), and app is
// the injected I/O/factory bundle.
type cmdContext struct {
	app   *App
	flags *globalFlags
	code  int
}

// getSwitch builds the target *netgearswitch.Switch for this invocation:
// cc.app.SwitchFactory if set (test seam), else resolve.Resolve wired with
// cc.app's Env/Prompt -- mirroring main.py's get_switch() closure exactly
// (switch_factory when given, else resolve_switch(args, env=env,
// prompt=prompt)). The caller MUST defer Close() on a successful result,
// mirroring resolve.Resolve's own doc comment.
func (cc *cmdContext) getSwitch() (*netgearswitch.Switch, error) {
	p := cc.flags.params()
	if cc.app.SwitchFactory != nil {
		return cc.app.SwitchFactory(p)
	}
	var opts []resolve.Option
	if cc.app.Env != nil {
		opts = append(opts, resolve.WithEnv(cc.app.Env))
	}
	if cc.app.Prompt != nil {
		opts = append(opts, resolve.WithPrompt(cc.app.Prompt))
	}
	return resolve.Resolve(p, opts...)
}

// streams builds the safety.Streams DoWrite/Confirm read from and write
// to, mirroring cli.CliContext's out/err/inp fields.
func (cc *cmdContext) streams() safety.Streams {
	return safety.Streams{Out: cc.app.Stdout, Err: cc.app.Stderr, In: bufio.NewReader(cc.app.Stdin)}
}

// fail records a plain "error: <message>" outcome at the given exit code
// -- used for CLI-shape problems this package detects itself (a bad
// positional argument, a missing file) rather than an error the library
// raised. Always returns nil so the caller's RunE can `return cc.fail(...)`
// without cobra treating this as a hard parse failure (which would ALSO
// dump cobra's own usage text -- this package handles all its own error
// reporting, see root.go's SilenceErrors/SilenceUsage).
func (cc *cmdContext) fail(code int, format string, args ...any) error {
	// A write failure here (a broken stderr pipe) has nowhere left to be
	// reported -- this function's whole job IS the error report -- so its
	// own write error is deliberately discarded, not propagated.
	_, _ = fmt.Fprintf(cc.app.Stderr, "error: "+format+"\n", args...)
	cc.code = code
	return nil
}

// usageError is fail(safety.ExitUsage, ...), mirroring main.py's several
// `print(...); return EXIT_USAGE` sites (a bad --backend value, a poe
// port given with no action, an unparsable speed rate, ...).
func (cc *cmdContext) usageError(format string, args ...any) error {
	return cc.fail(safety.ExitUsage, format, args...)
}

// libraryError records the outcome of an error returned by the facade
// (get_switch() or a Switch method), mirroring main.py's top-level
// try/except NetgearSwitchError block exactly: the exit code comes from
// safety.ExitCodeFor(err) (WriteVerificationError -> 3, a wrapped
// ErrProtectedPort -> 4, else 1), --verbose prints a best-effort diagnostic
// first (Go has no exception traceback to replay; see printVerboseChain's
// own doc comment), then "error: <err>" is printed to stderr -- exactly
// once, here, never inside a lower-level helper (mirrors do_write/DoWrite
// never printing the error themselves, leaving that to this single site).
func (cc *cmdContext) libraryError(err error) error {
	if cc.flags.verbose {
		printVerboseChain(cc.app.Stderr, err)
	}
	_, _ = fmt.Fprintf(cc.app.Stderr, "error: %s\n", err) // see fail's own doc comment on discarding this write's error.
	cc.code = safety.ExitCodeFor(err)
	return nil
}

// printVerboseChain is gngsw's best-effort analogue of Python -v/--verbose's
// `traceback.print_exc(file=err)`: Go errors carry no call-stack traceback
// (there is nothing equivalent to replay), so this instead prints every
// layer of err's Unwrap chain, innermost cause last-printed-first-in becomes
// last -- actually printed OUTERMOST first (the same order err.Error()'s own
// ": "-joined text already reads in), one per line, as strictly-more-
// diagnostic-than-nothing context for a caller debugging a failure. This is
// a deliberate, documented deviation from Python's own output, not a
// literal port -- there is no Go stdlib feature to port faithfully here.
func printVerboseChain(w io.Writer, err error) {
	for e := err; e != nil; e = errors.Unwrap(e) {
		_, _ = fmt.Fprintf(w, "  %v\n", e) // see cmdContext.fail's own doc comment on discarding this write's error.
	}
}

// Run builds gngsw's full command tree, executes it against argv, and
// returns the process exit code -- the package's equivalent of main.py's
// own main() function. Every RunE below always returns nil (see
// cmdContext.fail's doc comment) and instead records the resolved code on
// cc.code, so the ONLY way root.Execute() itself returns a non-nil error is
// a genuine cobra-level flag-parsing failure (an unregistered flag, a
// custom pflag.Value.Set failure such as an invalid --backend choice, a
// cobra.Args arity mismatch) -- argparse's own "usage" exit-2 behavior,
// which happens BEFORE any subcommand handler runs, mirrored here as an
// unconditional ExitUsage.
func Run(argv []string, app *App) int {
	cc := &cmdContext{app: app, flags: &globalFlags{}, code: safety.ExitOK}
	root := newRootCmd(cc)
	root.SetArgs(argv)
	root.SetOut(app.Stdout)
	root.SetErr(app.Stderr)

	if err := root.Execute(); err != nil {
		_, _ = fmt.Fprintf(app.Stderr, "error: %s\n", err) // see cmdContext.fail's own doc comment on discarding this write's error.
		return safety.ExitUsage
	}
	return cc.code
}
