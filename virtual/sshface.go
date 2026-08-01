package virtual

// sshface.go is [NEW DESIGN] (transport dossier §7.7): a REAL loopback SSH
// listener serving the FASTPATH shell (Task 11's CliFace, wrapped in
// cli_socket.go's byte-framing loop) over an actual TCP socket + SSH
// handshake, so a real CLI client -- this repo's own fastpath.NewSSHTransport
// (Task 6), or a future cross-language client (slice 10) -- can dial it
// exactly as it would dial real hardware. There is no Python source to port:
// the Python virtual CLI face (cli.py) is in-process only and never served
// FASTPATH over a real socket at all (dossier §7.5's own note, "cli_session()
// ... needing no socket").
//
// Built on github.com/gliderlabs/ssh (already a dependency, Task 6's own
// fastpath/ssh_test.go already uses it to fake a legacy-FASTPATH SSH server
// for the CLIENT side's tests -- this file is that same server shape,
// promoted from a test helper to a real, start/stop-able production face).
// Legacy-friendly by construction: the server is restricted to EXACTLY the
// key exchange old FASTPATH firmware offers (dossier: "old FASTPATH firmware
// only offers the legacy key exchange diffie-hellman-group14-sha1 and the
// ssh-rsa host-key algorithm", fastpath/ssh.go's own doc comment) -- an RSA
// host key (so "ssh-rsa" is negotiable) plus a ServerConfigCallback pinning
// KeyExchanges to legacySSHKeyExchange alone, mirroring
// fastpath/ssh_test.go's newLegacySSHTestServer exactly (proven there:
// TestSSHTransportRunRoundTripThroughShellDriver asserts the negotiated KEX
// and host-key algorithm are actually the legacy ones, not just offered).
// This is also the FAITHFUL choice, not merely the convenient one: real
// FASTPATH firmware genuinely has no other KEX to offer, so restricting the
// fake the same way is what proves NewSSHTransport's legacy-algorithm
// preference is load-bearing rather than merely offered-but-unused.
import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"sync"

	gliderssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/mithro/go-netgear-switch-library/fastpath"
)

// sshLegacyKeyExchange duplicates fastpath's own unexported
// legacySSHKeyExchange constant (fastpath/ssh.go): old FASTPATH firmware's
// ONLY key exchange algorithm. Cannot import it directly (unexported,
// different package) -- see the file-level doc comment for why this fake
// restricts itself to exactly this value rather than a modern default set.
const sshLegacyKeyExchange = "diffie-hellman-group14-sha1"

// SSHFace is a real loopback SSH server serving the FASTPATH shell over a
// *State, mirroring HTTPFace's shape (bind-on-Start/deterministic-
// idempotent-Stop) but with gliderlabs/ssh's *Server standing in for
// net/http.Server. Construct with NewSSHFace; call Start to bind and begin
// serving, Stop to tear down (idempotent; safe to call before Start or more
// than once).
type SSHFace struct {
	state    *State
	spec     *fastpath.CliModelSpec
	host     string
	username string
	password string

	mu       sync.Mutex // guards srv/listener (Start/Stop lifecycle only)
	srv      *gliderssh.Server
	listener net.Listener
	// wg tracks BOTH the background Serve goroutine Start spawns AND every
	// per-connection handleSession invocation gliderlabs itself spawns (see
	// handleSession's own doc comment for why this is the ONLY way to make
	// Stop's wait deterministic: gliderlabs' own connWg does not wait for
	// per-session handler goroutines, only for the outer per-TCP-connection
	// dispatch loop).
	wg sync.WaitGroup
}

// NewSSHFace builds an SSHFace serving state per spec (the model's FASTPATH
// CLI command spec, fastpath.CLISpec), accepting only a login whose
// username/password match username/password, bound to host (typically
// "127.0.0.1") once Start is called. Each accepted connection dispatches
// through its OWN fresh *CliFace (independent mode stack) over the SAME
// state (task brief: "each connection gets its own session/mode-stack but
// shares the ONE VirtualSwitchState") -- mirroring
// VirtualSwitch.CliSession's own in-process equivalent exactly.
func NewSSHFace(state *State, spec *fastpath.CliModelSpec, username, password, host string) *SSHFace {
	return &SSHFace{state: state, spec: spec, username: username, password: password, host: host}
}

// Start binds an ephemeral TCP port on f.host and begins serving on a
// background goroutine, returning the bound port. Calling Start twice
// without an intervening Stop is an error. Generates a fresh, ephemeral RSA
// host key on every Start call (dossier §7.7: "ephemeral host key generation
// per fake instance ... any key satisfies parity" since the real Python
// client, mirroring paramiko.Transport directly, never validates the host
// key at all).
func (f *SSHFace) Start() (port int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listener != nil {
		return 0, fmt.Errorf("virtual: SSHFace.Start: already started")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return 0, fmt.Errorf("virtual: SSHFace.Start: generate host key: %w", err)
	}
	signer, err := gossh.NewSignerFromKey(rsaKey)
	if err != nil {
		return 0, fmt.Errorf("virtual: SSHFace.Start: %w", err)
	}

	srv := &gliderssh.Server{
		Handler: f.handleSession,
		PasswordHandler: func(ctx gliderssh.Context, password string) bool {
			return ctx.User() == f.username && password == f.password
		},
		// See the file-level doc comment: restrict to the ONE key exchange
		// real old FASTPATH firmware offers, exactly like
		// fastpath/ssh_test.go's newLegacySSHTestServer.
		ServerConfigCallback: func(gliderssh.Context) *gossh.ServerConfig {
			return &gossh.ServerConfig{Config: gossh.Config{KeyExchanges: []string{sshLegacyKeyExchange}}}
		},
	}
	srv.AddHostKey(signer)

	ln, err := net.Listen("tcp", net.JoinHostPort(f.host, "0"))
	if err != nil {
		return 0, fmt.Errorf("virtual: SSHFace.Start: listen tcp on %s: %w", f.host, err)
	}
	f.listener = ln
	f.srv = srv

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		_ = srv.Serve(ln) // returns ssh.ErrServerClosed on a clean Close
	}()

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		// Unreachable: net.Listen("tcp", ...) always returns a *net.TCPAddr
		// from Addr().
		return 0, fmt.Errorf("virtual: SSHFace.Start: unexpected local addr type %T", ln.Addr())
	}
	return tcpAddr.Port, nil
}

// Stop tears the server down deterministically (transport dossier §5's
// leak-free contract): srv.Close() force-closes the listener AND every
// currently-active SSH connection at once (unlike srv.Shutdown, which only
// waits for existing connections to disconnect on their own -- an
// indefinite hang if a caller forgot to close its client first), which
// unblocks any in-flight per-connection Read; f.wg.Wait() then blocks until
// the Serve goroutine AND every handleSession invocation (see its own doc
// comment) have actually returned, not merely been asked to. Idempotent: a
// Stop before Start, or a second Stop, is a no-op.
func (f *SSHFace) Stop() error {
	f.mu.Lock()
	srv := f.srv
	f.srv = nil
	f.listener = nil
	f.mu.Unlock()

	if srv == nil {
		return nil
	}
	err := srv.Close()
	f.wg.Wait()
	if err != nil {
		return fmt.Errorf("virtual: SSHFace.Stop: %w", err)
	}
	return nil
}

// handleSession is the gliderlabs/ssh Handler for every accepted, shell-
// requesting connection: builds a fresh *CliFace over f.state (independent
// mode stack, shared state) and drives it through cli_socket.go's shared
// framing loop until the channel closes.
//
// f.wg.Add(1) here (rather than relying on gliderlabs' own internal connWg)
// is load-bearing: gliderlabs spawns this Handler on its OWN goroutine
// (session.go's `go func() { sess.handler(sess); sess.Exit(0) }()`) that is
// NOT awaited by the per-TCP-connection dispatch loop whose completion
// connWg tracks (server.go's `for ch := range chans` loop moves on to the
// next channel, or exits when the connection itself closes, without waiting
// for spawned session handlers) -- so srv.Shutdown's own connWg.Wait() could
// return while a handleSession invocation is still running. Tracking it on
// f.wg instead (waited on by Stop, above) is what makes this fake's Stop
// contract as strong as HTTPFace's Go-native one, not merely as strong as
// gliderlabs' own (weaker) default.
func (f *SSHFace) handleSession(sess gliderssh.Session) {
	f.wg.Add(1)
	defer f.wg.Done()
	face := NewCliFace(f.state, f.spec)
	// CliFace.Close is a documented no-op (cliface.go); nothing to report.
	defer func() { _ = face.Close() }()
	cliListenerLoop(sess.Context(), sess, bufio.NewReader(sess), face, f.state.ModelKey)
}
