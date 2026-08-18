// ssh.go ports src/netgear_switch/transport/cli/ssh.py (147 lines) at pin
// b26eb1f -- the SSH byte transport old FASTPATH firmware (the
// GSM7252PS/M4300 generation) needs, built on
// golang.org/x/crypto/ssh. Scope is deliberately narrower than the Python
// class: SshCliTransport (ssh.py:47-147) bundles connect + ShellDriver
// construction + Setup + the CliSession methods into one object; this file
// only produces the byte-level Transport (io.ReadWriteCloser) that Task 5's
// ShellDriver/NewShellDriver already consumes -- wiring a Transport into a
// ready Session (NewShellDriver + Setup) is left to whatever constructs a
// session per model (a later task), matching session.go's own file-level
// doc comment ("ssh.go/telnet.go/serial.go ... each only need to construct
// a Transport value").
//
// Fidelity notes (Python -> Go), mirroring the pin as closely as the
// library difference allows:
//
//   - paramiko.Transport is used directly (ssh.py:98), never
//     paramiko.SSHClient, so there is NO host-key verification at all --
//     "any host key is accepted implicitly because it is never checked."
//     The Go equivalent is ssh.ClientConfig.HostKeyCallback:
//     ssh.InsecureIgnoreHostKey().
//   - Legacy algorithms (module docstring, ssh.py:7-27, and
//     _LEGACY_KEX/_LEGACY_HOSTKEYS, ssh.py:41-42): old FASTPATH firmware
//     "only offers the legacy key exchange diffie-hellman-group14-sha1 and
//     the ssh-rsa (SHA-1) host-key algorithm." x/crypto/ssh still ships
//     both (unlike paramiko>=3, which dropped them from its default lists)
//     but at LOW preference; _prefer_legacy_algorithms (ssh.py:70-88,
//     "moves the legacy KEX/host-key algorithm to the FRONT of the
//     preferred list, doesn't remove others") is mirrored by the
//     ClientConfig built in NewSSHTransport, which puts them first in
//     Config.KeyExchanges / HostKeyAlgorithms ahead of everything
//     ssh.SupportedAlgorithms() reports -- belt-and-suspenders exactly like
//     the Python comment: still correct even if a future x/crypto/ssh
//     release merely de-prioritises (rather than removes) these
//     primitives.
//   - Auth is password-only (ssh.py:101, `transport.auth_password`): no
//     pubkey, no keyboard-interactive, no agent.
//   - Default port 22, default timeout 20s (ssh.py:44,57-58) bound the TCP
//     dial via net.DialTimeout AND every subsequent blocking Read, mirroring
//     paramiko's channel.settimeout(self._timeout) (ssh.py:105). x/crypto/ssh's
//     Channel has no per-Read deadline of its own (it is an in-memory buffer
//     fed by the Client's background packet-dispatch loop, not a direct
//     socket proxy), so Read arms a deadline on the underlying net.Conn
//     instead -- see sshTransport.Read's doc comment for the resulting
//     failure mode and why it is still the desired recovery behavior.
//   - PTY requested with paramiko's own get_pty() defaults (ssh.py:103,
//     called with zero arguments: term "vt100", width 80, height 24) --
//     mirrored by RequestPty("vt100", 24, 80, ssh.TerminalModes{}).
//   - Shell mode, not exec (ssh.py:104, `channel.invoke_shell()`):
//     Session.Shell(), matching FASTPATH needing one live interactive PTY
//     channel for multiple commands.
//   - Close (ssh.py:138-147) closes the channel before the transport and
//     suppresses ALL teardown exceptions ("teardown must not raise").
//     session.go's ShellDriver.Close deliberately does NOT suppress the
//     Transport's Close error (see its doc comment); this file follows
//     that same Go-idiom deviation and returns real errors from Close
//     instead of swallowing them -- callers wanting Python's
//     never-raise-on-teardown behavior can discard the error themselves.

package fastpath

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// Legacy algorithm identifiers old FASTPATH firmware requires, mirroring
// ssh.py:41-42's _LEGACY_KEX/_LEGACY_HOSTKEYS.
const (
	legacySSHKeyExchange = "diffie-hellman-group14-sha1"
	legacySSHHostKeyAlgo = "ssh-rsa"
)

// defaultSSHPort/defaultSSHTimeout mirror ssh.py:57-58's
// `port: int = 22, timeout: float = _DEFAULT_TIMEOUT` and ssh.py:44's
// `_DEFAULT_TIMEOUT = 20.0`.
const (
	defaultSSHPort    = 22
	defaultSSHTimeout = 20 * time.Second
)

// SSHConfig configures NewSSHTransport, mirroring SshCliTransport.__init__'s
// connection parameters (ssh.py:50-65): host/port/username/password for a
// FASTPATH switch's SSH CLI. Auth is password-only, matching the Python
// transport (ssh.py:101) -- there is no separate key-based auth field.
type SSHConfig struct {
	Host string
	// Port defaults to 22 (ssh.py:57) when zero.
	Port     int
	Username string
	Password string
	// Timeout bounds BOTH the TCP dial and every subsequent blocking
	// Transport.Read call (one field for both, exactly like ssh.py's
	// single self._timeout: ssh.py:100's `start_client(timeout=...)` and
	// ssh.py:105's `channel.settimeout(...)`), defaulting to 20s
	// (ssh.py:44,58) when zero or negative.
	Timeout time.Duration
}

// sshTransport adapts an x/crypto/ssh interactive PTY shell channel to the
// Transport interface (io.ReadWriteCloser) ShellDriver consumes: Read/Write
// go straight to the channel's stdout/stdin pipes (ssh.py's
// channel.recv/channel.sendall), and Close tears down the channel then the
// client connection (ssh.py:138-147's close() order).
type sshTransport struct {
	conn        net.Conn
	client      *ssh.Client
	session     *ssh.Session
	stdin       io.WriteCloser
	stdout      io.Reader
	readTimeout time.Duration
}

// NewSSHTransport dials cfg.Host:cfg.Port, authenticates with
// cfg.Username/cfg.Password, and opens one interactive PTY shell channel --
// the Go equivalent of SshCliTransport.connect() (ssh.py:90-110) up to (but
// not including) ShellDriver construction/Setup, which is the caller's job
// (see the file-level doc comment). Any failure at any step is wrapped in
// ErrCliTransport, mirroring ssh.py:106-108's single
// `except Exception as exc: raise CliTransportError(...)`.
func NewSSHTransport(cfg SSHConfig) (Transport, error) {
	port := cfg.Port
	if port == 0 {
		port = defaultSSHPort
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultSSHTimeout
	}

	clientCfg := &ssh.ClientConfig{
		User: cfg.Username,
		Auth: []ssh.AuthMethod{ssh.Password(cfg.Password)},
		// paramiko.Transport (ssh.py:98) does no host-key check at all
		// (never paramiko.SSHClient) -- match that exactly, not a TOFU
		// or known_hosts check.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		// Belt-and-suspenders legacy host-key algorithm, moved to the
		// front (ssh.py:70-88's _prefer_legacy_algorithms).
		HostKeyAlgorithms: preferAlgorithm(legacySSHHostKeyAlgo, ssh.SupportedAlgorithms().HostKeys),
		Timeout:           timeout,
		Config: ssh.Config{
			// Same belt-and-suspenders treatment for the legacy KEX.
			KeyExchanges: preferAlgorithm(legacySSHKeyExchange, ssh.SupportedAlgorithms().KeyExchanges),
		},
	}

	// Dial and handshake by hand (rather than ssh.Dial, which does the
	// same two steps internally) so the raw net.Conn can be retained on
	// sshTransport -- Read needs it to arm a per-call deadline (see
	// sshTransport.Read's doc comment); ssh.Client/ssh.Session never
	// expose the conn themselves.
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: SSH connect/auth failed: %w", ErrCliTransport, err)
	}
	sconn, chans, reqs, err := ssh.NewClientConn(conn, addr, clientCfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: SSH connect/auth failed: %w", ErrCliTransport, err)
	}
	client := ssh.NewClient(sconn, chans, reqs)

	t, err := newSSHShellTransport(client, conn, timeout)
	if err != nil {
		_ = client.Close() // also closes conn (Client.Close tears down the whole chain down to it).
		return nil, fmt.Errorf("%w: SSH connect/auth failed: %w", ErrCliTransport, err)
	}
	return t, nil
}

// preferAlgorithm returns algos with prefer moved to the front, removing
// any pre-existing occurrence elsewhere in the list first so the result
// never lists an identifier twice -- mirrors ssh.py:70-88's
// _prefer_legacy_algorithms ("moves the legacy KEX/host-key algorithm to
// the FRONT of the preferred list, doesn't remove others"; its Python form
// is naturally dedup-safe via a set membership check, `if _LEGACY_KEX in
// available_kex`).
func preferAlgorithm(prefer string, algos []string) []string {
	out := make([]string, 0, len(algos)+1)
	out = append(out, prefer)
	for _, a := range algos {
		if a != prefer {
			out = append(out, a)
		}
	}
	return out
}

// newSSHShellTransport opens one session channel on client, requests a PTY,
// and starts an interactive shell on it -- ssh.py:102-104's
// `channel = transport.open_session(...); channel.get_pty(); channel.invoke_shell()`.
// conn is the raw net.Conn client was built on (retained for Read's
// deadline) and readTimeout is the per-Read deadline duration (see
// sshTransport.Read).
func newSSHShellTransport(client *ssh.Client, conn net.Conn, readTimeout time.Duration) (*sshTransport, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	// paramiko's channel.get_pty() (ssh.py:103) is called with zero
	// arguments, so paramiko's own defaults apply: term "vt100", width
	// 80, height 24.
	if err := session.RequestPty("vt100", 24, 80, ssh.TerminalModes{}); err != nil {
		_ = session.Close()
		return nil, err
	}
	// StdinPipe/StdoutPipe expose the raw channel directly (must be
	// obtained before Shell() starts the session) -- this is what makes
	// Read return the channel's own bare io.EOF on close (session.go's
	// Transport contract) with no translation needed: x/crypto/ssh's
	// internal buffer.Read (ssh/buffer.go) returns exactly io.EOF, never
	// a wrapped error, once the channel is drained and closed.
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	// Shell mode, not exec (ssh.py:104) -- FASTPATH needs one live
	// interactive PTY channel for multiple commands.
	if err := session.Shell(); err != nil {
		_ = session.Close()
		return nil, err
	}
	return &sshTransport{
		conn:        conn,
		client:      client,
		session:     session,
		stdin:       stdin,
		stdout:      stdout,
		readTimeout: readTimeout,
	}, nil
}

// Read implements Transport by reading from the shell channel's stdout,
// first arming a deadline on the underlying net.Conn -- ssh.py:105's
// `channel.settimeout(self._timeout)` -- so a switch that stops responding
// mid-session cannot block a Read forever (session.go's ctx.Err() check in
// ShellDriver only runs once up front, never during an in-flight Read, so
// this is the only thing that can still unblock it).
//
// Mechanism and consequence, since x/crypto/ssh's Channel is an in-memory
// buffer fed by the Client's background packet-dispatch loop rather than a
// direct socket proxy: arming the deadline does NOT cancel this specific
// Read in isolation. If it fires while that dispatch loop is itself
// blocked reading the next SSH packet off conn, the loop errors out and
// tears down every channel on this connection at once (x/crypto/ssh's
// mux.loop() calls dropAll() on any read error, deadline-caused or not) --
// so a fired deadline surfaces here as this channel's ordinary clean-close
// signal, bare io.EOF, not a distinguishable timeout error, and the whole
// ssh.Client becomes unusable afterward. That is still the desired
// recovery: ShellDriver's readUntil (session.go) breaks out of its retry
// loop on ANY io.EOF with no prompt yet seen and returns a hard
// ErrCliTransport-wrapped failure instead of hanging forever, and the
// caller closes the session on any Run/Setup failure regardless, so the
// now-unusable connection is torn down anyway.
//
// A Read that completes before the deadline is completely unaffected --
// SetReadDeadline is re-armed fresh (relative to "now") at the start of
// every call, so steady traffic never trips it, and this Read's own return
// value (data, bare io.EOF on a clean close, or otherwise) is passed
// through unchanged, never wrapped or reinterpreted here.
func (t *sshTransport) Read(p []byte) (int, error) {
	if t.readTimeout > 0 {
		_ = t.conn.SetReadDeadline(time.Now().Add(t.readTimeout))
	}
	return t.stdout.Read(p)
}

// Write implements Transport by writing to the shell channel's stdin --
// ssh.py's `channel.sendall`.
func (t *sshTransport) Write(p []byte) (int, error) {
	return t.stdin.Write(p)
}

// Close implements Transport, mirroring ssh.py:138-147's close() ORDER
// (channel before transport connection) but NOT its exception suppression
// -- see the file-level doc comment for why this file returns real errors
// instead of swallowing them.
func (t *sshTransport) Close() error {
	sessErr := t.session.Close()
	clientErr := t.client.Close()
	return errors.Join(sessErr, clientErr)
}
