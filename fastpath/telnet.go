// telnet.go ports src/netgear_switch/transport/cli/telnet.py (104 lines) at
// pin 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362 -- the telnet byte transport
// for FASTPATH's plaintext CLI, built directly on net.Conn (no third-party
// telnet client). Scope mirrors ssh.go: this file only produces the
// byte-level Transport (io.ReadWriteCloser) Task 5's ShellDriver/
// NewShellDriver consumes; wiring a Transport into a ready Session
// (NewShellDriver + Setup) is a later task's job.
//
// Library choice (spec line ~235 offered ziutek/telnet with a hand-rolled
// fallback "if the lib misbehaves"; task brief's Hazard paragraph asks for
// the decision to be documented here):
//
//   - ziutek/telnet@v0.1.0 was fetched and its Conn.cmd option handler read
//     in full (conn.go). It does NOT replicate telnetlib's default
//     "refuse-everything" posture required by the transport dossier §2.2
//     ("Go port parity implication: whatever raw-socket/hand-rolled IAC
//     handling the Go telnet client uses must replicate telnetlib's default
//     behavior of transparently stripping/refusing IAC sequences ... i.e.
//     ShellDriver NEVER sees raw IAC bytes"): ziutek's Conn AUTO-ACCEPTS the
//     ECHO and SUPPRESS-GO-AHEAD options (replying WILL/DO, enabling them)
//     and answers NAWS with a window-size subnegotiation of its own --
//     three options telnetlib's default (no custom
//     set_option_negotiation_callback) posture would instead refuse (WONT/
//     DONT), never enabling anything. That is a materially different wire
//     posture than what the pin's `telnetlib.Telnet(host, port,
//     timeout=...)` produces, so this file HAND-ROLLS the ~100 lines of IAC
//     handling instead (telnetConn below), refusing every DO/WILL it is
//     sent and never emitting an unsolicited negotiation of its own --
//     exactly telnetlib's default.
//
// Fidelity notes (Python -> Go):
//
//   - Login (`_login`, telnet.py:50-55): waits for the LITERAL byte
//     sequence "User:" (not a regex -- telnetlib.read_until does a literal
//     substring search), writes username+"\r\n"; waits for the literal
//     "Password:", writes password+"\r\n". No confirmation read after the
//     password write -- ShellDriver.Setup's own first readUntil consumes
//     whatever comes back next (initial post-login banner/prompt).
//   - Two-tier eager/blocking read (telnet.py:72-78's `lambda n:
//     conn.read_eager() or conn.read_some()`): non-blocking read_eager()
//     first (whatever's already buffered, possibly none), falling back to
//     a single blocking read_some() only when nothing was already
//     buffered. telnetConn.Read (below) replicates the net *effect* of
//     this pair for ShellDriver's synchronous, single-goroutine recv loop:
//     it blocks (bounded by whatever deadline the caller has armed on the
//     underlying net.Conn) only until AT LEAST one data byte is available,
//     then drains whatever is already buffered beyond that without
//     blocking again -- there is no other consumer racing the same
//     buffered bytes, so "check non-blocking, else block once" and "block
//     until >=1 byte, then drain eagerly" are indistinguishable outcomes
//     here.
//   - Default port 23, default timeout 20s (telnet.py:38,25).
//   - Any connect/login failure is normalized to one error type wrapping
//     ErrCliTransport (telnet.py:68-70's `except Exception as exc:
//     self.close(); raise CliTransportError(f"telnet connect/login
//     failed: {exc}")`).
//   - Read arms a per-call deadline on the underlying net.Conn before every
//     Transport.Read, exactly like ssh.go's sshTransport.Read (see that
//     file's doc comment for the failure-mode rationale) -- session.go's
//     10,000-iteration readUntil loop has no wall-clock bound of its own,
//     so a wedged/never-responding switch must be caught here.

package fastpath

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// defaultTelnetPort/defaultTelnetTimeout mirror telnet.py:38's
// `port: int = 23` and telnet.py:25's `_DEFAULT_TIMEOUT = 20.0`.
const (
	defaultTelnetPort    = 23
	defaultTelnetTimeout = 20 * time.Second
)

// TelnetConfig configures NewTelnetTransport, mirroring
// TelnetCliTransport.__init__'s connection parameters (telnet.py, module
// docstring + constructor): host/port/username/password for a FASTPATH
// switch's telnet CLI.
type TelnetConfig struct {
	Host string
	// Port defaults to 23 (telnet.py:38) when zero. Some models (gsm7228ps,
	// dossier §2.2) listen on a non-standard port (60000) -- callers pass
	// that explicitly, this file has no per-model knowledge.
	Port     int
	Username string
	Password string
	// Timeout bounds the TCP dial, the User:/Password: login reads, and
	// every subsequent Transport.Read call, defaulting to 20s
	// (telnet.py:25) when zero or negative.
	Timeout time.Duration
}

// --- RFC 854 IAC command bytes -- the minimal set telnetConn needs to
// refuse every negotiated option and skip subnegotiation blocks. This file
// never itself proposes an option (no unsolicited WILL/DO of its own),
// exactly like telnetlib's default posture.
const (
	tnIAC  = 255
	tnDONT = 254
	tnDO   = 253
	tnWONT = 252
	tnWILL = 251
	tnSB   = 250
	tnSE   = 240
)

// telnetConn wraps a net.Conn, stripping IAC (RFC 854) command/negotiation/
// subnegotiation sequences from Read and refusing every negotiated option --
// WONT in reply to a DO, DONT in reply to a WILL -- exactly telnetlib's
// default option-negotiation posture (see the file-level doc comment for
// why ziutek/telnet's Conn was rejected in favor of this hand-rolled
// version). A literal 0xFF byte in the data stream is escaped by both ends
// as IAC IAC per RFC 854; Write escapes outgoing 0xFF bytes the same way
// telnetlib's own `write` doubles IAC ("Write a string to the socket,
// doubling any IAC characters").
type telnetConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func newTelnetConn(conn net.Conn) *telnetConn {
	return &telnetConn{conn: conn, r: bufio.NewReader(conn)}
}

// Read implements io.Reader, returning only already-negotiated data bytes
// (see the file-level doc comment for how this replicates telnetlib's
// read_eager()-or-read_some() pair for ShellDriver's synchronous recv
// loop): it blocks (via the underlying net.Conn, bounded by whatever
// deadline the caller armed) until at least one data byte is decoded, then
// keeps draining already-buffered bytes without blocking again, stopping
// as soon as the bufio.Reader's internal buffer would require another
// blocking read to satisfy.
func (t *telnetConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := 0
	for n < len(p) {
		b, err := t.r.ReadByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		if b == tnIAC {
			literal, handleErr := t.handleIAC()
			if handleErr != nil {
				if n > 0 {
					return n, nil
				}
				return 0, handleErr
			}
			if !literal {
				// Consumed a command/negotiation/subnegotiation sequence,
				// no data byte produced -- keep looking for a real data
				// byte, unless returning what's accumulated so far avoids
				// a further blocking read.
				if n > 0 && t.r.Buffered() == 0 {
					return n, nil
				}
				continue
			}
			// Escaped IAC (IAC IAC): a literal 0xFF data byte.
			b = tnIAC
		}
		p[n] = b
		n++
		if t.r.Buffered() == 0 {
			// Don't block for more once nothing is immediately available --
			// mirrors read_eager()'s non-blocking-drain half: return what
			// has accumulated rather than forcing another blocking read to
			// fill p completely.
			return n, nil
		}
	}
	return n, nil
}

// handleIAC consumes one IAC-introduced sequence (the IAC byte itself has
// already been read by the caller) and returns literal=true only when the
// sequence was an escaped IAC IAC (a literal 0xFF data byte the caller
// should emit); every other case is fully handled here (a negotiation
// reply sent, or a subnegotiation block skipped) and produces no data byte.
func (t *telnetConn) handleIAC() (literal bool, err error) {
	cmd, err := t.r.ReadByte()
	if err != nil {
		return false, err
	}
	switch cmd {
	case tnIAC:
		return true, nil
	case tnDO, tnDONT, tnWILL, tnWONT:
		opt, err := t.r.ReadByte()
		if err != nil {
			return false, err
		}
		return false, t.refuse(cmd, opt)
	case tnSB:
		return false, t.skipSubnegotiation()
	default:
		// Other IAC commands (NOP, GA, ...) carry no option byte and need
		// no reply -- telnetlib's default handling likewise ignores them.
		return false, nil
	}
}

// refuse mirrors telnetlib's default (no custom option_negotiation_callback
// installed) option-negotiation reply: a DO is answered WONT, a WILL is
// answered DONT -- it never enables ANY option (unlike ziutek/telnet's
// Conn, which auto-accepts ECHO and SUPPRESS-GO-AHEAD -- see the
// file-level doc comment). DONT/WONT need no reply (the peer has already
// agreed not to use the option).
func (t *telnetConn) refuse(cmd, opt byte) error {
	var reply byte
	switch cmd {
	case tnDO:
		reply = tnWONT
	case tnWILL:
		reply = tnDONT
	default:
		return nil
	}
	_, err := t.conn.Write([]byte{tnIAC, reply, opt})
	return err
}

// skipSubnegotiation reads and discards an entire IAC SB ... IAC SE block
// (the leading IAC SB has already been consumed by the caller), never
// surfacing any of it as data.
func (t *telnetConn) skipSubnegotiation() error {
	for {
		b, err := t.r.ReadByte()
		if err != nil {
			return err
		}
		if b != tnIAC {
			continue
		}
		b2, err := t.r.ReadByte()
		if err != nil {
			return err
		}
		if b2 == tnSE {
			return nil
		}
		// IAC escaped inside the subnegotiation payload, or an unexpected
		// command byte: keep skipping until IAC SE is actually seen.
	}
}

// Write implements io.Writer, escaping any literal 0xFF byte as IAC IAC
// (telnetlib's own write() behavior: "doubling any IAC characters").
func (t *telnetConn) Write(p []byte) (int, error) {
	if bytes.IndexByte(p, tnIAC) == -1 {
		return t.conn.Write(p)
	}
	escaped := make([]byte, 0, len(p)+4)
	for _, b := range p {
		escaped = append(escaped, b)
		if b == tnIAC {
			escaped = append(escaped, tnIAC)
		}
	}
	// net.Conn.Write either writes the whole buffer or returns a non-nil
	// error (TCP streams have no short-write-without-error case), so it is
	// safe to report the caller's own byte count on success rather than
	// the escaped count.
	if _, err := t.conn.Write(escaped); err != nil {
		return 0, err
	}
	return len(p), nil
}

// telnetTransport adapts telnetConn to the Transport interface, arming a
// per-Read deadline on the underlying net.Conn before every call -- see the
// file-level doc comment and ssh.go's sshTransport.Read for the rationale
// (a wedged switch must not hang ShellDriver's readUntil loop forever).
type telnetTransport struct {
	tc          *telnetConn
	conn        net.Conn
	readTimeout time.Duration
	closed      atomic.Bool
}

// Read implements Transport. Unlike ssh.go's sshTransport (which reads from
// an x/crypto/ssh channel pipe that already surfaces bare io.EOF on close),
// this Read goes straight to the underlying net.Conn: reading from a
// connection the PEER closed does return bare io.EOF, but reading from a
// connection THIS PROCESS closed (via Close, below) instead returns a
// wrapped *net.OpError ("use of closed network connection") -- so, exactly
// like serial.go's serialTransport, this file tracks its own closed flag
// and translates any post-Close Read error to bare io.EOF, satisfying
// session.go's Transport contract (session.go:242/362/416's `err !=
// io.EOF` comparisons) for the self-initiated-close case regardless of
// which of the two underlying error shapes applies.
func (t *telnetTransport) Read(p []byte) (int, error) {
	if t.readTimeout > 0 {
		_ = t.conn.SetReadDeadline(time.Now().Add(t.readTimeout))
	}
	n, err := t.tc.Read(p)
	if err != nil && !errors.Is(err, io.EOF) && t.closed.Load() {
		return n, io.EOF
	}
	return n, err
}

// Write implements Transport.
func (t *telnetTransport) Write(p []byte) (int, error) {
	return t.tc.Write(p)
}

// Close implements Transport, mirroring telnet.py:99-104's close() (single
// connection object, no channel/transport split) but -- like ssh.go --
// NOT suppressing the error (see ssh.go's file-level doc comment for why).
func (t *telnetTransport) Close() error {
	t.closed.Store(true)
	return t.conn.Close()
}

// telnetReadUntil reads from t (arming a fresh per-call deadline each
// Transport.Read, via t.Read) until the literal byte sequence needle has
// been seen in the accumulated buffer, mirroring telnetlib.read_until's
// literal substring search (telnet.py:50-53) -- NOT promptRE/passwordRE,
// which are ShellDriver's own concern and never applied during login. A
// wedged/never-responding server surfaces here as t.Read's own deadline
// error, bounding this loop exactly like readUntil in session.go bounds
// ShellDriver's post-login reads.
func telnetReadUntil(t *telnetTransport, needle string) (string, error) {
	var buf strings.Builder
	chunk := make([]byte, 256)
	for {
		n, err := t.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			if strings.Contains(buf.String(), needle) {
				return buf.String(), nil
			}
		}
		if err != nil {
			return "", err
		}
	}
}

// telnetLogin mirrors Python `_login` (telnet.py:50-55) exactly: wait for
// the literal "User:", write username+"\r\n"; wait for the literal
// "Password:", write password+"\r\n". No confirmation read after the
// password write -- the caller's ShellDriver.Setup performs the first real
// readUntil against whatever comes back next.
func telnetLogin(t *telnetTransport, username, password string) error {
	if _, err := telnetReadUntil(t, "User:"); err != nil {
		return err
	}
	if _, err := t.Write([]byte(username + "\r\n")); err != nil {
		return err
	}
	if _, err := telnetReadUntil(t, "Password:"); err != nil {
		return err
	}
	if _, err := t.Write([]byte(password + "\r\n")); err != nil {
		return err
	}
	return nil
}

// NewTelnetTransport dials cfg.Host:cfg.Port and drives the User:/Password:
// login handshake -- the Go equivalent of TelnetCliTransport.connect()
// (telnet.py:57-79) up to (but not including) ShellDriver construction/
// Setup, which is the caller's job (see the file-level doc comment). Any
// failure at any step is wrapped in ErrCliTransport, mirroring
// telnet.py:68-70's single `except Exception as exc: self.close(); raise
// CliTransportError(f"telnet connect/login failed: {exc}")`.
func NewTelnetTransport(cfg TelnetConfig) (Transport, error) {
	port := cfg.Port
	if port == 0 {
		port = defaultTelnetPort
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTelnetTimeout
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: telnet connect/login failed: %w", ErrCliTransport, err)
	}

	t := &telnetTransport{tc: newTelnetConn(conn), conn: conn, readTimeout: timeout}
	if err := telnetLogin(t, cfg.Username, cfg.Password); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: telnet connect/login failed: %w", ErrCliTransport, err)
	}
	return t, nil
}
