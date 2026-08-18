package virtual

// telnetface.go is [NEW DESIGN] (transport dossier §7.7), the Telnet
// analogue of sshface.go: a REAL loopback Telnet listener serving the
// FASTPATH shell (Task 11's CliFace, over cli_socket.go's shared
// byte-framing loop) so a real CLI client -- fastpath.NewTelnetTransport
// (Task 7), or a future cross-language client (slice 10) -- can dial it
// exactly as it would dial real hardware. No net/telnet server library is
// used, mirroring fastpath/telnet.go's own choice (see that file's doc
// comment on why ziutek/telnet was rejected): the login handshake and IAC
// handling are hand-rolled directly on net.Conn, exactly as the CLIENT side
// already is.
//
// Login: the literal byte sequence "User:" then "Password:"
// (dossier §7.7/telnet.py:52,54 -- these are the exact bytes
// fastpath.telnetLogin (telnet.go) waits for and never anything else), each
// followed by reading one CRLF-terminated line and comparing it to the
// configured username/password. No retry loop, no lockout: a mismatch on
// either simply closes the connection (the client's own Setup then fails
// with ErrCliTransport on the immediate EOF, an honest and unambiguous
// failure mode -- real hardware's own retry/lockout behavior is not
// ground-truthed anywhere in this pin, so this fake does not fabricate one).
//
// IAC posture: "refuse-all", mirroring telnetlib's default (dossier §7.7,
// "whatever raw-socket/hand-rolled IAC handling ... must replicate
// telnetlib's default behavior of transparently stripping/refusing IAC
// sequences") -- this fake SERVER never proposes an option of its own and
// answers any DO/WILL it is sent with WONT/DONT, structurally identical to
// fastpath's own unexported telnetConn (telnet.go) on the CLIENT side.
// Duplicated rather than exported solely for this: telnetConn is unexported
// in a different package, and the refuse-everything logic is role-agnostic
// (~60 lines) -- see telnetServerConn below.
import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/mithro/go-netgear-switch-library/fastpath"
)

// --- server-side IAC handling (mirrors fastpath's unexported telnetConn) --

// Duplicated RFC 854 IAC command bytes -- see fastpath/telnet.go's own
// identical block for the authoritative commentary; this file needs its own
// copy since fastpath.tnIAC etc. are unexported in a different package.
const (
	telnetIAC  = 255
	telnetDONT = 254
	telnetDO   = 253
	telnetWONT = 252
	telnetWILL = 251
	telnetSB   = 250
	telnetSE   = 240
)

// telnetServerConn wraps a net.Conn, stripping IAC command/negotiation/
// subnegotiation sequences from Read and refusing every negotiated option --
// WONT in reply to a DO, DONT in reply to a WILL -- exactly telnetlib's
// default option-negotiation posture, mirroring fastpath.telnetConn
// (fastpath/telnet.go) structurally (same behavior, server role instead of
// client: refuse() is symmetric regardless of which end sent the DO/WILL).
type telnetServerConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func newTelnetServerConn(conn net.Conn) *telnetServerConn {
	return &telnetServerConn{conn: conn, r: bufio.NewReader(conn)}
}

// Read implements io.Reader, returning only already-negotiated data bytes.
// See fastpath.telnetConn.Read's doc comment (telnet.go) for the exact
// blocking/draining shape this mirrors.
func (t *telnetServerConn) Read(p []byte) (int, error) {
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
		if b == telnetIAC {
			literal, handleErr := t.handleIAC()
			if handleErr != nil {
				if n > 0 {
					return n, nil
				}
				return 0, handleErr
			}
			if !literal {
				if n > 0 && t.r.Buffered() == 0 {
					return n, nil
				}
				continue
			}
			b = telnetIAC
		}
		p[n] = b
		n++
		if t.r.Buffered() == 0 {
			return n, nil
		}
	}
	return n, nil
}

// handleIAC consumes one IAC-introduced sequence (the IAC byte itself
// already read by the caller), mirroring fastpath.telnetConn.handleIAC
// exactly.
func (t *telnetServerConn) handleIAC() (literal bool, err error) {
	cmd, err := t.r.ReadByte()
	if err != nil {
		return false, err
	}
	switch cmd {
	case telnetIAC:
		return true, nil
	case telnetDO, telnetDONT, telnetWILL, telnetWONT:
		opt, err := t.r.ReadByte()
		if err != nil {
			return false, err
		}
		return false, t.refuse(cmd, opt)
	case telnetSB:
		return false, t.skipSubnegotiation()
	default:
		return false, nil
	}
}

// refuse answers a DO with WONT and a WILL with DONT -- never enabling any
// option, mirroring fastpath.telnetConn.refuse.
func (t *telnetServerConn) refuse(cmd, opt byte) error {
	var reply byte
	switch cmd {
	case telnetDO:
		reply = telnetWONT
	case telnetWILL:
		reply = telnetDONT
	default:
		return nil
	}
	_, err := t.conn.Write([]byte{telnetIAC, reply, opt})
	return err
}

// skipSubnegotiation reads and discards an entire IAC SB ... IAC SE block,
// mirroring fastpath.telnetConn.skipSubnegotiation.
func (t *telnetServerConn) skipSubnegotiation() error {
	for {
		b, err := t.r.ReadByte()
		if err != nil {
			return err
		}
		if b != telnetIAC {
			continue
		}
		b2, err := t.r.ReadByte()
		if err != nil {
			return err
		}
		if b2 == telnetSE {
			return nil
		}
	}
}

// Write implements io.Writer, escaping any literal 0xFF byte as IAC IAC,
// mirroring fastpath.telnetConn.Write.
func (t *telnetServerConn) Write(p []byte) (int, error) {
	if bytes.IndexByte(p, telnetIAC) == -1 {
		return t.conn.Write(p)
	}
	escaped := make([]byte, 0, len(p)+4)
	for _, b := range p {
		escaped = append(escaped, b)
		if b == telnetIAC {
			escaped = append(escaped, telnetIAC)
		}
	}
	if _, err := t.conn.Write(escaped); err != nil {
		return 0, err
	}
	return len(p), nil
}

// --- TelnetFace -------------------------------------------------------

// TelnetFace is a real loopback Telnet server serving the FASTPATH shell
// over a *State, mirroring SSHFace's shape (bind-on-Start/deterministic-
// idempotent-Stop) with a hand-rolled accept loop standing in for
// gliderlabs/ssh's *Server (there is no telnet-server framework dependency
// in this repo, matching fastpath/telnet.go's own hand-rolled client
// choice). Construct with NewTelnetFace; call Start to bind and begin
// serving, Stop to tear down (idempotent; safe to call before Start or more
// than once).
type TelnetFace struct {
	state    *State
	spec     *fastpath.CliModelSpec
	host     string
	username string
	password string

	mu       sync.Mutex // guards listener/conns (Start/Stop lifecycle only)
	listener net.Listener
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

// NewTelnetFace builds a TelnetFace serving state per spec, accepting only a
// login whose username/password match username/password, bound to host
// (typically "127.0.0.1") once Start is called. Each accepted connection
// dispatches through its OWN fresh *CliFace (independent mode stack) over
// the SAME state -- see SSHFace's matching doc comment; the two listeners
// share this exact per-connection-isolation/shared-state contract.
func NewTelnetFace(state *State, spec *fastpath.CliModelSpec, username, password, host string) *TelnetFace {
	return &TelnetFace{state: state, spec: spec, username: username, password: password, host: host}
}

// Start binds an ephemeral TCP port on f.host and begins accepting on a
// background goroutine, returning the bound port. Calling Start twice
// without an intervening Stop is an error.
func (f *TelnetFace) Start() (port int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listener != nil {
		return 0, fmt.Errorf("virtual: TelnetFace.Start: already started")
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(f.host, "0"))
	if err != nil {
		return 0, fmt.Errorf("virtual: TelnetFace.Start: listen tcp on %s: %w", f.host, err)
	}
	f.listener = ln
	f.conns = map[net.Conn]struct{}{}

	f.wg.Add(1)
	go f.acceptLoop(ln)

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		// Unreachable: net.Listen("tcp", ...) always returns a *net.TCPAddr
		// from Addr().
		return 0, fmt.Errorf("virtual: TelnetFace.Start: unexpected local addr type %T", ln.Addr())
	}
	return tcpAddr.Port, nil
}

// acceptLoop accepts connections on ln until Accept errors (always the
// outcome of Stop closing ln, since a fresh loopback listener has no other
// realistic failure mode here) -- each accepted connection is tracked (so
// Stop can force-close it) and served on its own goroutine, both counted on
// f.wg so Stop's Wait is deterministic.
func (f *TelnetFace) acceptLoop(ln net.Listener) {
	defer f.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		f.trackConn(conn, true)
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer f.trackConn(conn, false)
			defer func() { _ = conn.Close() }()
			f.serveConn(conn)
		}()
	}
}

func (f *TelnetFace) trackConn(c net.Conn, add bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conns == nil {
		return // Stop already ran and cleared the map; nothing to track.
	}
	if add {
		f.conns[c] = struct{}{}
	} else {
		delete(f.conns, c)
	}
}

// serveConn drives the User:/Password: login handshake, then -- only on a
// successful match -- hands off to cli_socket.go's shared framing loop over
// a fresh *CliFace. A failed login simply returns (closing the connection
// via acceptLoop's own defer); see the file-level doc comment for why no
// retry/lockout is modeled.
func (f *TelnetFace) serveConn(conn net.Conn) {
	tc := newTelnetServerConn(conn)
	r := bufio.NewReader(tc)
	if !f.login(tc, r) {
		return
	}
	face := NewCliFace(f.state, f.spec)
	// CliFace.Close is a documented no-op (cliface.go); nothing to report.
	defer func() { _ = face.Close() }()
	// ModelKey is set once at construction and never changed afterward in
	// practice, but SnmpFace's SET rollback path (RestoreState) does write
	// it back (to the same value) under State's lock -- so this read needs
	// the SAME lock too, even though the value can never actually differ
	// (Go-only; see State.mu's own doc comment). A one-off read here, but
	// NOT the only direct State access cliListenerLoop's loop reaches:
	// cliPrompt -> CliFace.InterfaceName also reads f.state.Ports on every
	// iteration (locked independently there, cliface.go) -- this call does
	// not hold a lock across the whole loop, only around this one field.
	f.state.LockState()
	modelKey := f.state.ModelKey
	f.state.UnlockState()
	cliListenerLoop(context.Background(), tc, r, face, modelKey)
}

// login mirrors fastpath.telnetLogin's WIRE SHAPE from the other end: send
// the literal "User:", read one line, send "Password:", read one line,
// compare both against f.username/f.password. Uses the SAME *bufio.Reader r
// that cliListenerLoop will go on to use, so no byte the client sent after
// the password line (e.g. the start of its first real command, if a client
// ever pipelines) is silently dropped by wrapping a second, independent
// bufio.Reader over the same connection.
func (f *TelnetFace) login(w *telnetServerConn, r *bufio.Reader) bool {
	if _, err := w.Write([]byte("User:")); err != nil {
		return false
	}
	userLine, err := r.ReadString('\n')
	if err != nil {
		return false
	}
	if _, err := w.Write([]byte("Password:")); err != nil {
		return false
	}
	passLine, err := r.ReadString('\n')
	if err != nil {
		return false
	}
	user := trimCRLF(userLine)
	pass := trimCRLF(passLine)
	return user == f.username && pass == f.password
}

// trimCRLF strips a trailing "\r\n", "\n", or "\r" -- whichever terminator
// the client actually sent -- mirroring cli_socket.go's own
// strings.TrimRight(raw, "\r\n") convention.
func trimCRLF(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// Stop tears the server down deterministically (transport dossier §5's
// leak-free contract): closes the listener (unblocking acceptLoop's Accept)
// and force-closes every currently-tracked connection (unblocking any
// in-flight per-connection Read in serveConn/cliListenerLoop) BEFORE
// waiting, then f.wg.Wait() blocks until acceptLoop and every serveConn
// goroutine have actually returned. Idempotent: a Stop before Start, or a
// second Stop, is a no-op.
func (f *TelnetFace) Stop() error {
	f.mu.Lock()
	ln := f.listener
	f.listener = nil
	conns := f.conns
	f.conns = nil
	f.mu.Unlock()

	if ln == nil {
		return nil
	}
	var firstErr error
	if err := ln.Close(); err != nil {
		firstErr = err
	}
	for c := range conns {
		_ = c.Close() // best-effort: unblocks the owning goroutine's Read; that goroutine's own defer already double-closes harmlessly.
	}
	f.wg.Wait()
	if firstErr != nil {
		return fmt.Errorf("virtual: TelnetFace.Stop: %w", firstErr)
	}
	return nil
}
