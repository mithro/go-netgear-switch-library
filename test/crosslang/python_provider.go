//go:build crosslang

package crosslang

// python_provider.go: CC2's own deliverable -- a virtual.EndpointProvider
// (see provider.go's doc comment on that seam) that starts modelKey's fake
// by shelling the PINNED Python reference implementation's `ngsw serve`
// subcommand, rather than an in-process Go listener. This is the harness's
// FIRST true cross-language check: the same suite.go/opmap.go/triples.go
// machinery Suite 1 (go_fake_test.go) already exercised against a Go fake
// now runs, completely unchanged, against a REAL Python process talking
// real SNMP/NSDP/HTTP wire protocol.
//
// Python's fake serves SNMP/NSDP/HTTP only: its FASTPATH/CLI face
// (virtual/faces/cli.py in the pinned worktree) is in-process with no
// socket at all -- VirtualSwitch.start() (virtual/server.py) binds an SNMP,
// NSDP and/or HTTP face per the model's registry entry but never a CLI
// listener -- so PythonFakeProvider's Endpoints always report SSHPort==0
// and TelnetPort==0. servedBackends (provider.go) already treats a 0 port
// as "this provider does not serve that backend" and skips those triples
// silently; python_fake_test.go additionally asserts SSHPort==0/
// TelnetPort==0 EXPLICITLY (a positive check of this structural exclusion,
// not just the mechanical silent skip).
//
// pythonNgswPath is an ABSOLUTE path into a READ-ONLY pinned snapshot of the
// Python repo (a sibling worktree, never this repo) -- this package never
// cds into it and never imports anything from it; the only contact surface
// is this one subprocess invocation and its stdout announcement.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/mithro/go-netgear-switch-library/virtual"
)

// pythonNgswPath is the pinned Python reference implementation's `ngsw` CLI
// entry point -- see the package doc comment above (D-VIRT §5/slice
// CC2's brief): a Python 3.12 venv with pysnmp+httpx already installed,
// NO paramiko needed (this slice never touches SSH/Telnet).
const pythonNgswPath = "/home/tim/github/mithro/python-netgear-switch-library/.claude/worktrees/go-port-pin-b26eb1f/.venv/bin/ngsw"

// pythonServeCommunity/pythonServeHTTPPassword are the SNMP community and
// HTTP admin password every `ngsw serve` subprocess this provider starts is
// asked (via --community/--http-password) to accept, deliberately spelled
// differently from either fake's own built-in default ("public"/
// "password", cli/main.py's own `serve` subparser defaults) so that a
// provider parsing bug which silently fell back to some hardcoded default
// would make the SNMP/HTTP round trip fail loudly instead of accidentally
// still working.
const (
	pythonServeCommunity    = "cc2-crosslang"
	pythonServeHTTPPassword = "cc2-crosslang-pw"
)

// pythonStartupTimeout bounds how long StartModel waits for `ngsw serve` to
// print its full announcement (model+host line, one line per bound
// backend, then the community/http-password line -- see
// _print_switch/serve_forever in the pinned virtual/server.py) before
// giving up. Generous for a Python interpreter + pysnmp/httpx import under
// scripts/jail.sh's CPU/memory limits, short enough that a genuinely wedged
// subprocess still fails the calling test rather than hanging `make
// crosslang` forever.
const pythonStartupTimeout = 15 * time.Second

// pythonShutdownGrace bounds how long stop waits for a SIGTERM'd `ngsw
// serve` subprocess to exit cleanly before escalating to SIGKILL.
const pythonShutdownGrace = 5 * time.Second

// pythonAnnounceModelRE/pythonAnnouncePortRE/pythonAnnounceCredRE parse
// _print_switch's three exact line shapes (virtual/server.py, pinned
// snapshot, live-verified against a real one-shot `ngsw serve` run while
// building this provider):
//
//	[gsm7252ps] host=127.0.0.1
//	    SNMP udp/47537
//	    HTTP tcp/37861
//	    community='public' http_password='password'
//
// -- never guessed from the source's f-strings alone.
var (
	pythonAnnounceModelRE = regexp.MustCompile(`^\[([^\]]+)\] host=(\S+)$`)
	pythonAnnouncePortRE  = regexp.MustCompile(`^\s+(SNMP|NSDP|HTTP)\s+(?:udp|tcp)/(\d+)$`)
	pythonAnnounceCredRE  = regexp.MustCompile(`^\s+community='([^']*)' http_password='([^']*)'$`)
)

// syncBuffer is a mutex-guarded bytes.Buffer: cmd.Stderr is written from a
// goroutine os/exec owns internally (started at cmd.Start, joined at
// cmd.Wait), while this provider's error paths read the accumulated text
// from a different goroutine before Wait has necessarily returned -- a
// plain bytes.Buffer would race under `go test -race` for exactly that
// reason.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// pythonAnnounce is the one-shot outcome the stdout-scanning goroutine
// (see startPythonServe) sends on its result channel: either the fully
// parsed Endpoints, or the reason the announcement never completed.
type pythonAnnounce struct {
	ep  virtual.Endpoints
	err error
}

// pythonProc tracks one `ngsw serve` subprocess this provider started, for
// PythonFakeProvider.stop/CloseAll's lifecycle management -- the direct
// analogue of server.go's own trackedSwitch for GoFakeProvider.
type pythonProc struct {
	cmd    *exec.Cmd
	stderr *syncBuffer

	// done is closed by the stdout-scanning goroutine (startPythonServe)
	// once it has both drained stdout to EOF AND called cmd.Wait() itself
	// -- Wait is deliberately owned by that single goroutine, called only
	// once its own reads have completed, rather than raced from a second
	// goroutine (exec.Cmd.StdoutPipe's own doc comment: "it is incorrect to
	// call Wait before all reads from the pipe have completed").
	done    chan struct{}
	waitErr error

	// stopSignal is closed by stop() so a StartModel caller's ctx-watcher
	// goroutine (which selects on ctx.Done() OR this channel) never leaks
	// waiting on an uncancelled ctx (e.g. context.Background()) once
	// CloseAll has already stopped this process by another path -- mirrors
	// trackedSwitch.stopCh in server.go exactly.
	stopSignal chan struct{}
	stopOnce   sync.Once
}

// startPythonServe starts `ngsw serve --model modelKey ...` with a fresh
// process group (so stop can signal the whole group, not just the direct
// child) and returns the tracked process plus a channel that will receive
// exactly one pythonAnnounce once its stdout has been scanned far enough to
// know the outcome either way.
func startPythonServe(modelKey string) (*pythonProc, <-chan pythonAnnounce, error) {
	cmd := exec.Command(pythonNgswPath, "serve",
		"--model", modelKey,
		"--host", "127.0.0.1",
		"--port", "0",
		"--http-port", "0",
		"--community", pythonServeCommunity,
		"--http-password", pythonServeHTTPPassword,
	)
	// New process group: stop() signals -pgid so a Python interpreter that
	// ever forked a helper child (it doesn't today, but this is the
	// standard defensive shape for "kill everything this subprocess tree
	// started") is reaped too, never just the direct child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("ngsw serve --model %s: StdoutPipe: %w", modelKey, err)
	}
	stderr := &syncBuffer{}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("starting %s serve --model %s: %w", pythonNgswPath, modelKey, err)
	}

	proc := &pythonProc{
		cmd:        cmd,
		stderr:     stderr,
		done:       make(chan struct{}),
		stopSignal: make(chan struct{}),
	}
	resultCh := make(chan pythonAnnounce, 1)

	go func() {
		sc := bufio.NewScanner(stdout)
		var ep virtual.Endpoints
		haveModel, sent := false, false
		send := func(a pythonAnnounce) {
			if !sent {
				sent = true
				resultCh <- a
			}
		}
		for sc.Scan() {
			if sent {
				continue // drain -- nothing after the announcement matters to this provider.
			}
			line := sc.Text()
			switch {
			case pythonAnnounceModelRE.MatchString(line):
				m := pythonAnnounceModelRE.FindStringSubmatch(line)
				ep = virtual.Endpoints{Host: m[2]}
				haveModel = true
			case !haveModel:
				// Stray output before the "[model] host=..." line (there
				// shouldn't be any) -- ignored rather than misparsed.
			case pythonAnnouncePortRE.MatchString(line):
				m := pythonAnnouncePortRE.FindStringSubmatch(line)
				port, convErr := strconv.Atoi(m[2])
				if convErr != nil {
					continue
				}
				switch m[1] {
				case "SNMP":
					ep.SnmpPort = port
				case "NSDP":
					ep.NsdpPort = port
				case "HTTP":
					ep.HTTPPort = port
				}
			case pythonAnnounceCredRE.MatchString(line):
				m := pythonAnnounceCredRE.FindStringSubmatch(line)
				ep.Community, ep.HTTPPassword = m[1], m[2]
				send(pythonAnnounce{ep: ep}) // the announcement for our one model is now complete.
			}
		}
		if !sent {
			send(pythonAnnounce{err: fmt.Errorf(
				"ngsw serve --model %s exited before printing its endpoint announcement (scan err: %v); stderr:\n%s",
				modelKey, sc.Err(), stderr.String())})
		}
		proc.waitErr = cmd.Wait()
		close(proc.done)
	}()

	return proc, resultCh, nil
}

// PythonFakeProvider is the virtual.EndpointProvider implementation this
// slice adds: each StartModel call shells a brand-new `ngsw serve --model
// modelKey` subprocess (Python's serve subcommand refuses to share a single
// pinned --port/--http-port across more than one --model, so one process
// per model is the only shape that works anyway) and tracks it so CloseAll
// can stop every process this provider has ever started. The zero value is
// ready to use, mirroring GoFakeProvider's own contract exactly.
type PythonFakeProvider struct {
	mu    sync.Mutex
	procs []*pythonProc
}

// StartModel implements virtual.EndpointProvider: starts modelKey's fake as
// a real OS subprocess, waits for its announcement (or a startup failure,
// or ctx/timeout), and -- on success -- spawns a goroutine that stops the
// subprocess once EITHER ctx is done OR CloseAll runs, exactly mirroring
// GoFakeProvider.StartModel's own cancellation contract (server.go) so this
// provider is a drop-in replacement for the same suite.go call sites.
func (p *PythonFakeProvider) StartModel(ctx context.Context, modelKey string) (virtual.Endpoints, error) {
	proc, resultCh, err := startPythonServe(modelKey)
	if err != nil {
		return virtual.Endpoints{}, err
	}
	p.track(proc)

	select {
	case res := <-resultCh:
		if res.err != nil {
			_ = p.stop(proc)
			return virtual.Endpoints{}, res.err
		}
		go func() {
			select {
			case <-ctx.Done():
			case <-proc.stopSignal:
			}
			_ = p.stop(proc)
		}()
		return res.ep, nil
	case <-time.After(pythonStartupTimeout):
		_ = p.stop(proc)
		return virtual.Endpoints{}, fmt.Errorf(
			"ngsw serve --model %s: timed out after %s waiting for its endpoint announcement; stderr so far:\n%s",
			modelKey, pythonStartupTimeout, proc.stderr.String())
	case <-ctx.Done():
		_ = p.stop(proc)
		return virtual.Endpoints{}, ctx.Err()
	}
}

// track registers proc so CloseAll can find it later, even if StartModel's
// own caller never learns about it (e.g. the announcement parse below
// fails) -- a started subprocess is tracked the instant it exists, never
// only after a successful StartModel return, so no startup failure can ever
// leak a process.
func (p *PythonFakeProvider) track(proc *pythonProc) {
	p.mu.Lock()
	p.procs = append(p.procs, proc)
	p.mu.Unlock()
}

// stop signals proc's whole process group to terminate (SIGTERM, escalating
// to SIGKILL after pythonShutdownGrace) and waits for the stdout-scanning
// goroutine's own cmd.Wait() to finish. Idempotent (sync.Once): safe to call
// once from a ctx-watcher goroutine and again from CloseAll, or vice versa,
// whichever comes first.
func (p *PythonFakeProvider) stop(proc *pythonProc) error {
	proc.stopOnce.Do(func() {
		close(proc.stopSignal)
		if proc.cmd.Process != nil {
			pid := proc.cmd.Process.Pid
			_ = syscall.Kill(-pid, syscall.SIGTERM) // -pid: the whole process group (Setpgid above).
			select {
			case <-proc.done:
			case <-time.After(pythonShutdownGrace):
				_ = syscall.Kill(-pid, syscall.SIGKILL)
				<-proc.done
			}
		}
	})
	return proc.waitErr
}

// CloseAll stops every `ngsw serve` subprocess this provider has ever
// started via StartModel, regardless of whether its ctx was ever cancelled,
// and forgets them (a later CloseAll call is a no-op). Safe to call more
// than once. Mirrors GoFakeProvider.CloseAll exactly -- see its own doc
// comment for the ctx-vs-CloseAll race this same shape avoids.
func (p *PythonFakeProvider) CloseAll() error {
	p.mu.Lock()
	procs := p.procs
	p.procs = nil
	p.mu.Unlock()

	var firstErr error
	for _, proc := range procs {
		if err := p.stop(proc); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
