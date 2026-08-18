package main

// serve.go is this binary's whole implementation, split out of main.go so
// it is unit-testable without a real process/signal/stdin -- run is the
// package's equivalent of Python main.py's _cmd_serve (flag surface and
// validation) plus virtual/server.py's serve_forever (start-report-block-
// stop), ported not as a literal line-for-line translation but as the same
// three phases in the same order: (1) parse+validate flags exactly like
// _cmd_serve, (2) build+start every requested VirtualSwitch exactly like
// serve_forever (one bad model is reported and skipped, never sinks the
// fleet -- see startAll's own doc comment for the one place this diverges
// from _cmd_serve, by design), (3) block until stopped, then Stop every
// started switch in reverse order, even on early return.
//
// THE ANNOUNCEMENT CONTRACT (design doc §8.3, deliberately NOT Python's own
// human-readable _print_switch block): for every switch that starts, this
// package writes exactly one JSON line to stdout -- and stdout ONLY ever
// carries these JSON lines, nothing else, so a cross-test harness can
// read+json.Unmarshal each line without ever needing to distinguish
// "announcement" from "chatter". Every other message (usage errors, a
// skipped bad model, the final human-readable "serving N switch(es)" note)
// goes to stderr instead. The JSON shape, field order, and omitted-when-
// unbound convention are exactly the spec's:
//
//	{"model": "...", "host": "127.0.0.1", "snmp_port": N, "nsdp_port": N,
//	 "http_port": N, "ssh_port": N, "telnet_port": N, "community": "public",
//	 "password": "password"}
//
// PASSWORD FIELD: unlike Python (which has no CLI/SSH/Telnet concept in
// serve at all, so its own block only ever prints http_password), this
// binary's virtual.VirtualSwitch binds real loopback SSH/Telnet CLI faces
// too (model.BackendSSH/BackendTelnet) with their OWN password
// (virtual.WithCLIPassword, independent of virtual.WithHTTPPassword by
// default). The spec's JSON schema has a single "password" field, not two
// -- so buildSwitches applies --http-password to BOTH the HTTP face and
// the CLI (SSH/Telnet) faces (see its own doc comment). The alternative --
// reporting only the HTTP password while leaving the CLI faces silently on
// their own separate, unreported default -- would make the announcement
// actively WRONG for any --http-password override on an SSH/Telnet-capable
// model (m4300-24x/m4300-16x/gsm7252ps): a harness trusting the single
// "password" field would fail to authenticate against the real SSH/Telnet
// listener. Unifying the two avoids ever printing a credential that does
// not work.
//
// FLAGS mirror _cmd_serve's own `serve` subparser (main.py) field-for-
// field, including defaults and the two validation errors:
//   - --model KEY (repeatable, append; order and duplicates preserved,
//     exactly like argparse's action="append")
//   - --all (every registered model; when given, silently IGNORES --model,
//     exactly like _cmd_serve's own `list(MODELS) if args.all else
//     list(args.models or [])` -- not a merge)
//   - --host (default "127.0.0.1")
//   - --community (default "public")
//   - --http-password (default "password")
//   - --port (default 0 = ephemeral; pins the SNMP-or-NSDP UDP port,
//     virtual.WithPort)
//   - --http-port (default 0 = ephemeral; pins the HTTP TCP port,
//     virtual.WithHTTPPort)
//
// Refuses (exit 2, mirroring _cmd_serve's own EXIT_USAGE) with neither
// --model nor --all given, or --port/--http-port given alongside more than
// one resolved model (a fixed port cannot be shared across a fleet). Also
// refuses (exit 2) immediately, without starting ANYTHING, the moment any
// requested --model key fails to resolve against the registry -- mirroring
// _cmd_serve's own eager `VirtualSwitch(key, ...)` construction loop
// (UnknownModelError there is model.ErrUnknownModel here), which is a
// DIFFERENT failure mode than a model that resolves but fails to bind any
// face at Start (that one is reported-and-skipped, not fatal -- see
// startAll).
//
// Exits 0 on a clean stop with at least one switch served, 1 if every
// requested model resolved but zero switches actually started (mirroring
// _cmd_serve's `EXIT_OK if served else EXIT_ERROR`).
//
// BLOCKING (design doc §8.3, a Go-only addition Python's serve_forever has
// no equivalent of): waits for EITHER a signal on stop OR EOF on stdin,
// whichever comes first, then returns. A caller that wants only the
// SIGINT/SIGTERM behaviour can pass a nil stdin to skip the stdin watch
// entirely (used by this package's own signal-path tests, so they never
// block on an unclosed reader).

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// Exit codes, mirroring cli/context.py's EXIT_OK/EXIT_ERROR/EXIT_USAGE
// (0/1/2) exactly -- this binary has no dry-run/verify/protected-port
// concepts, so it never needs EXIT_VERIFY/EXIT_PROTECTED's Go analogues.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// modelKeysFlag collects repeated --model KEY flags, appending in the
// order given (duplicates preserved) -- the Go stdlib flag package's
// idiomatic way to get argparse's action="append" behaviour, since flag has
// no built-in repeatable-string flag type.
type modelKeysFlag []string

func (m *modelKeysFlag) String() string { return strings.Join(*m, ",") }

func (m *modelKeysFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// servedSwitch pairs a constructed VirtualSwitch with the model key it was
// built from -- VirtualSwitch itself has no exported accessor for its own
// model key (server.go's modelKey field is intentionally unexported, an
// implementation detail the package's own tests don't need either), so
// this package tracks the pairing on its own side instead of asking the
// library to expose one just for this.
type servedSwitch struct {
	key string
	sw  *virtual.VirtualSwitch
}

// run parses args, builds and starts every requested VirtualSwitch,
// announces each on stdout, then blocks until stop fires or stdin reaches
// EOF (skipped entirely when stdin is nil), stopping every started switch
// in reverse order before returning. See this file's doc comment for the
// full contract. All non-JSON output (usage errors, skipped-model reports,
// the final "serving N switch(es)" note) goes to stderr, never stdout --
// stdout carries only the announcement JSON lines.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, stop <-chan os.Signal) int {
	cfg, code, ok := parseFlags(args, stderr)
	if !ok {
		return code
	}

	switches, code, ok := buildSwitches(cfg, stderr)
	if !ok {
		return code
	}

	started := startAll(switches, cfg, stdout, stderr)
	defer stopAll(started, stderr)

	if len(started) == 0 {
		_, _ = fmt.Fprintln(stderr, "error: no switches could be served")
		return exitError
	}
	_, _ = fmt.Fprintf(stderr, "serving %d mock switch(es); press Ctrl-C to stop\n", len(started))

	waitForStop(stdin, stop)
	return exitOK
}

// serveConfig holds every flag value run needs past parseFlags, so the
// three phases (parse, build, start) each take a small, explicit argument
// instead of threading the raw *flag.FlagSet around.
type serveConfig struct {
	modelKeys    []string
	host         string
	community    string
	httpPassword string
	port         int
	httpPort     int
}

// parseFlags registers and parses this binary's flag surface (this file's
// own doc comment lists every flag), then resolves and validates the
// requested model-key set. ok is false the moment any usage problem is
// found (a flag-parse error, --help, neither --model/--all, or
// --port/--http-port with more than one model); code is the exit code the
// caller should return immediately in that case.
func parseFlags(args []string, stderr io.Writer) (cfg serveConfig, code int, ok bool) {
	fs := flag.NewFlagSet("gngsw-virtual", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var models modelKeysFlag
	fs.Var(&models, "model", "model key to serve (repeatable); e.g. --model gsm7228ps")
	all := fs.Bool("all", false, "serve every registered model")
	host := fs.String("host", "127.0.0.1", "bind address (use 0.0.0.0 to expose off-host)")
	community := fs.String("community", "public", "SNMP community the mock accepts")
	httpPassword := fs.String("http-password", "password", "HTTP/SSH/Telnet admin password the mock accepts")
	port := fs.Int("port", 0, "pin the SNMP/NSDP UDP port (0 = ephemeral; single model only)")
	httpPort := fs.Int("http-port", 0, "pin the HTTP TCP port (0 = ephemeral; single model only)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cfg, exitOK, false
		}
		// flag.ContinueOnError already printed the error + usage to stderr.
		return cfg, exitUsage, false
	}
	if extra := fs.Args(); len(extra) > 0 {
		_, _ = fmt.Fprintf(stderr, "error: unrecognized arguments: %s\n", strings.Join(extra, " "))
		return cfg, exitUsage, false
	}

	modelKeys := []string(models)
	if *all {
		modelKeys = allModelKeys()
	}
	if len(modelKeys) == 0 {
		_, _ = fmt.Fprintln(stderr, "error: give one or more --model KEY, or --all")
		return cfg, exitUsage, false
	}
	if (*port != 0 || *httpPort != 0) && len(modelKeys) > 1 {
		_, _ = fmt.Fprintln(stderr, "error: --port/--http-port pin a single listener; they cannot be "+
			"shared across multiple served models")
		return cfg, exitUsage, false
	}

	return serveConfig{
		modelKeys:    modelKeys,
		host:         *host,
		community:    *community,
		httpPassword: *httpPassword,
		port:         *port,
		httpPort:     *httpPort,
	}, exitOK, true
}

// allModelKeys returns every registered model's key in canonical registry
// order, mirroring _cmd_serve's own `list(MODELS)` (Python's MODELS is an
// insertion-ordered dict over the same canonical entries model.Models()
// returns here).
func allModelKeys() []string {
	infos := model.Models()
	keys := make([]string, len(infos))
	for i, m := range infos {
		keys[i] = m.Key
	}
	return keys
}

// buildSwitches constructs one VirtualSwitch per cfg.modelKeys entry,
// applying every flag consistently across the fleet (mirroring
// _cmd_serve's single VirtualSwitch(key, community=..., http_password=...,
// host=..., port=..., http_port=...) call per key). The FIRST unresolvable
// model key aborts immediately with exitUsage, nothing started yet --
// mirroring _cmd_serve's own eager construction loop, which is a
// deliberately different failure mode than a model that resolves but
// cannot bind any face at Start (see startAll, which reports-and-skips
// instead). virtual.WithCLIPassword uses cfg.httpPassword too -- see this
// file's top doc comment ("PASSWORD FIELD") for why.
func buildSwitches(cfg serveConfig, stderr io.Writer) (switches []*servedSwitch, code int, ok bool) {
	switches = make([]*servedSwitch, 0, len(cfg.modelKeys))
	for _, key := range cfg.modelKeys {
		sw, err := virtual.NewVirtualSwitch(key,
			virtual.WithHost(cfg.host),
			virtual.WithCommunity(cfg.community),
			virtual.WithHTTPPassword(cfg.httpPassword),
			virtual.WithCLIPassword(cfg.httpPassword),
			virtual.WithPort(cfg.port),
			virtual.WithHTTPPort(cfg.httpPort),
		)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %s\n", err)
			return nil, exitUsage, false
		}
		switches = append(switches, &servedSwitch{key: key, sw: sw})
	}
	return switches, exitOK, true
}

// startAll starts every switch in switches independently: a switch whose
// Start fails (e.g. no bindable face for its model, or a requested --port
// already in use) is reported on stderr and skipped, exactly like
// virtual/server.py's serve_forever -- "one bad model must not sink the
// fleet". Every switch that DOES start is announced on stdout (one JSON
// line, printAnnouncement) before moving to the next. Returns exactly the
// switches that started, in start order, for the caller to Stop later.
func startAll(switches []*servedSwitch, cfg serveConfig, stdout, stderr io.Writer) []*servedSwitch {
	started := make([]*servedSwitch, 0, len(switches))
	for _, s := range switches {
		if err := s.sw.Start(); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: cannot serve %q: %s\n", s.key, err)
			continue
		}
		started = append(started, s)
		printAnnouncement(stdout, s, cfg.community, cfg.httpPassword)
	}
	return started
}

// stopAll stops every started switch in REVERSE order, matching
// serve_forever's own `for sw in reversed(started): sw.stop()`. UNLIKE
// serve_forever's finally block, though, this loop deliberately continues
// past an individual Stop error (reported on stderr) instead of letting
// one switch's teardown trouble abort the loop -- Python's own version has
// no try/except around sw.stop(), so a single raising Stop there aborts
// the whole finally block and leaves every switch after it un-stopped.
// This is a deliberate improvement over that behaviour, not a port of it:
// one switch's teardown trouble here never leaves a LATER switch's sockets
// leaked.
func stopAll(started []*servedSwitch, stderr io.Writer) {
	for i := len(started) - 1; i >= 0; i-- {
		if err := started[i].sw.Stop(); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: stopping %q: %s\n", started[i].key, err)
		}
	}
}

// announcement is the exact JSON shape design doc §8.3 specifies -- field
// order matches the spec's example verbatim (encoding/json preserves
// struct field declaration order), and every port field is omitempty so an
// unbound face (port 0) is OMITTED entirely rather than printed as a
// misleading 0, exactly as the spec says: "absent faces omitted".
type announcement struct {
	Model      string `json:"model"`
	Host       string `json:"host"`
	SNMPPort   int    `json:"snmp_port,omitempty"`
	NSDPPort   int    `json:"nsdp_port,omitempty"`
	HTTPPort   int    `json:"http_port,omitempty"`
	SSHPort    int    `json:"ssh_port,omitempty"`
	TelnetPort int    `json:"telnet_port,omitempty"`
	Community  string `json:"community"`
	Password   string `json:"password"`
}

// printAnnouncement writes s's single announcement JSON line to stdout.
// community/password are the flag values applied fleet-wide (not read back
// off s.sw, which keeps them unexported -- see servedSwitch's own doc
// comment on why this package tracks its own state instead). A
// marshal/write failure here (unreachable for this fixed, always-valid
// struct shape, or a broken stdout pipe) is deliberately swallowed: this
// function's job IS the report, so there is nowhere further to escalate a
// failure reporting the report -- the same convention cmd/gngsw's
// cmdContext.fail documents for its own stderr writes.
func printAnnouncement(stdout io.Writer, s *servedSwitch, community, httpPassword string) {
	line, err := json.Marshal(announcement{
		Model:      s.key,
		Host:       s.sw.Host,
		SNMPPort:   s.sw.SnmpPort,
		NSDPPort:   s.sw.NsdpPort,
		HTTPPort:   s.sw.HTTPPort,
		SSHPort:    s.sw.SSHPort,
		TelnetPort: s.sw.TelnetPort,
		Community:  community,
		Password:   httpPassword,
	})
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(stdout, string(line))
}

// waitForStop blocks until EITHER a signal arrives on stop OR stdin
// reaches EOF, whichever comes first (design doc §8.3: "blocks until
// SIGINT/SIGTERM/stdin-EOF"). A nil stdin skips the stdin watch entirely --
// used by this package's signal-path tests so they never start a goroutine
// blocked on a reader nobody closes; production (main.go) always passes
// os.Stdin. A non-nil stdin whose Read never returns (e.g. an interactive
// terminal the user never types Ctrl-D into) leaves its background
// goroutine blocked until the whole process exits, exactly like Python's
// own bare `stop.wait()` leaves nothing OTHER than a signal to unblock it
// when no one closes stdin either -- not a leak in the sense this
// function's own caller needs to care about, since the process is exiting
// via os.Exit right after waitForStop returns either way.
func waitForStop(stdin io.Reader, stop <-chan os.Signal) {
	if stdin == nil {
		<-stop
		return
	}
	eof := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, stdin)
		close(eof)
	}()
	select {
	case <-stop:
	case <-eof:
	}
}
