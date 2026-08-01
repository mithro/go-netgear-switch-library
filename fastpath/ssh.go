// ssh.go ports src/netgear_switch/transport/cli/ssh.py (147 lines) at pin
// 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362 -- the SSH byte transport old
// FASTPATH firmware (the GSM7252PS/M4300 generation) needs, built on
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
//     dial + handshake via ssh.ClientConfig.Timeout. x/crypto/ssh has no
//     per-Read timeout knob equivalent to paramiko's channel.settimeout
//     (ssh.py:105); ShellDriver's maxReads loop bound (session.go) is what
//     still bounds a hung read in this port.
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
	// Timeout bounds the TCP dial + handshake, defaulting to 20s
	// (ssh.py:44,58) when zero or negative.
	Timeout time.Duration
}

// sshTransport adapts an x/crypto/ssh interactive PTY shell channel to the
// Transport interface (io.ReadWriteCloser) ShellDriver consumes: Read/Write
// go straight to the channel's stdout/stdin pipes (ssh.py's
// channel.recv/channel.sendall), and Close tears down the channel then the
// client connection (ssh.py:138-147's close() order).
type sshTransport struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
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
		HostKeyAlgorithms: append([]string{legacySSHHostKeyAlgo}, ssh.SupportedAlgorithms().HostKeys...),
		Timeout:           timeout,
		Config: ssh.Config{
			// Same belt-and-suspenders treatment for the legacy KEX.
			KeyExchanges: append([]string{legacySSHKeyExchange}, ssh.SupportedAlgorithms().KeyExchanges...),
		},
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", addr, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("%w: SSH connect/auth failed: %w", ErrCliTransport, err)
	}

	t, err := newSSHShellTransport(client)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("%w: SSH connect/auth failed: %w", ErrCliTransport, err)
	}
	return t, nil
}

// newSSHShellTransport opens one session channel on client, requests a PTY,
// and starts an interactive shell on it -- ssh.py:102-104's
// `channel = transport.open_session(...); channel.get_pty(); channel.invoke_shell()`.
func newSSHShellTransport(client *ssh.Client) (*sshTransport, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	// paramiko's channel.get_pty() (ssh.py:103) is called with zero
	// arguments, so paramiko's own defaults apply: term "vt100", width
	// 80, height 24.
	if err := session.RequestPty("vt100", 24, 80, ssh.TerminalModes{}); err != nil {
		session.Close()
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
		session.Close()
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, err
	}
	// Shell mode, not exec (ssh.py:104) -- FASTPATH needs one live
	// interactive PTY channel for multiple commands.
	if err := session.Shell(); err != nil {
		session.Close()
		return nil, err
	}
	return &sshTransport{client: client, session: session, stdin: stdin, stdout: stdout}, nil
}

// Read implements Transport by reading from the shell channel's stdout.
// The underlying channel returns bare io.EOF (not a wrapped error) once
// closed and drained -- see newSSHShellTransport's doc comment --
// ShellDriver's read loops (session.go) depend on that exact sentinel.
func (t *sshTransport) Read(p []byte) (int, error) {
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
