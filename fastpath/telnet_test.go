package fastpath

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeTelnetServer scripts a tiny FASTPATH-like telnet listener over a real
// loopback TCP connection: it first sends an IAC DO ECHO negotiation
// request the client MUST refuse (proving the refuse-everything posture
// runs below ShellDriver, dossier §2.2), then the literal "User:"/
// "Password:" login prompts (telnet.py:50-55), then answers "enable"/
// "terminal length 0" with a bare prompt and any command in responses with
// an echo + canned output + prompt -- the same framing shape as ssh_test.go's
// fakeFastpathHandler, but over raw TCP bytes instead of an SSH channel.
type fakeTelnetServer struct {
	ln              net.Listener
	negotiationRepl chan []byte
	usernameLine    chan string
	passwordLine    chan string
	stop            chan struct{}
}

func newFakeTelnetServer(t *testing.T, responses map[string]string, hangOnCmd string) *fakeTelnetServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	srv := &fakeTelnetServer{
		ln:              ln,
		negotiationRepl: make(chan []byte, 1),
		usernameLine:    make(chan string, 1),
		passwordLine:    make(chan string, 1),
		stop:            make(chan struct{}),
	}
	t.Cleanup(func() {
		close(srv.stop)
		ln.Close()
	})
	go srv.serve(responses, hangOnCmd)
	return srv
}

func (s *fakeTelnetServer) serve(responses map[string]string, hangOnCmd string) {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// IAC DO ECHO -- the client must reply IAC WONT ECHO (refuse), never
	// enabling it.
	if _, err := conn.Write([]byte{tnIAC, tnDO, 1}); err != nil {
		return
	}
	reply := make([]byte, 3)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return
	}
	s.negotiationRepl <- append([]byte(nil), reply...)

	r := bufio.NewReader(conn)
	if _, err := conn.Write([]byte("User:")); err != nil {
		return
	}
	userLine, err := r.ReadString('\n')
	if err != nil {
		return
	}
	s.usernameLine <- strings.TrimRight(userLine, "\r\n")

	if _, err := conn.Write([]byte("Password:")); err != nil {
		return
	}
	passLine, err := r.ReadString('\n')
	if err != nil {
		return
	}
	s.passwordLine <- strings.TrimRight(passLine, "\r\n")

	if _, err := conn.Write([]byte("\r\n(FAKESW) #")); err != nil {
		return
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		switch {
		case cmd == hangOnCmd && hangOnCmd != "":
			<-s.stop
			return
		case cmd == "enable" || cmd == "terminal length 0":
			if _, err := conn.Write([]byte("\r\n(FAKESW) #")); err != nil {
				return
			}
		default:
			out, ok := responses[cmd]
			if !ok {
				out = "% Unknown command"
			}
			if _, err := conn.Write([]byte(cmd + "\r\n" + out + "\r\n(FAKESW) #")); err != nil {
				return
			}
		}
	}
}

func (s *fakeTelnetServer) hostPort(t *testing.T) (string, int) {
	t.Helper()
	hostStr, portStr, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) error = %v", s.ln.Addr().String(), err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi(%q) error = %v", portStr, err)
	}
	return hostStr, portNum
}

// TestTelnetTransportLoginAndRunRoundTripThroughShellDriver drives a real
// loopback telnet connection through NewTelnetTransport -> NewShellDriver ->
// Setup -> Run, asserting: the IAC DO ECHO negotiation was refused (IAC
// WONT ECHO, never enabled), the literal User:/Password: login sequence
// carried the configured credentials, the command's output round-trips
// correctly framed, and Close() leaves the Transport's Read returning bare
// io.EOF (session.go's Transport contract, mirroring ssh_test.go's
// equivalent assertion).
func TestTelnetTransportLoginAndRunRoundTripThroughShellDriver(t *testing.T) {
	const username, password = "admin", "s3cret"
	const wantOutput = "FAKESW Software, Version 1.2.3"
	srv := newFakeTelnetServer(t, map[string]string{"show version": wantOutput}, "")
	host, port := srv.hostPort(t)

	transport, err := NewTelnetTransport(TelnetConfig{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewTelnetTransport() error = %v", err)
	}

	select {
	case reply := <-srv.negotiationRepl:
		want := []byte{tnIAC, tnWONT, 1}
		if string(reply) != string(want) {
			t.Errorf("negotiation reply = % x, want %x (IAC WONT ECHO -- refuse, never enable)", reply, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never received a negotiation reply")
	}
	select {
	case got := <-srv.usernameLine:
		if got != username {
			t.Errorf("username line = %q, want %q", got, username)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never received a username line")
	}
	select {
	case got := <-srv.passwordLine:
		if got != password {
			t.Errorf("password line = %q, want %q", got, password)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never received a password line")
	}

	driver := NewShellDriver(transport, ShellDriverConfig{})
	ctx := context.Background()
	if err := driver.Setup(ctx); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	out, err := driver.Run(ctx, "show version")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if out != wantOutput {
		t.Errorf("Run() output = %q, want %q", out, wantOutput)
	}

	if err := driver.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	buf := make([]byte, 16)
	n, err := transport.Read(buf)
	if err != io.EOF {
		t.Errorf("Read() after Close() = (%d, %v), want (_, io.EOF) [bare, via errors.Is-independent ==]", n, err)
	}
}

// TestTelnetTransportConnectFailureWrapsErrCliTransport proves a dial
// failure (nothing listening on the port) is normalized to ErrCliTransport,
// matchable with errors.Is, exactly like every other transport failure in
// this package.
func TestTelnetTransportConnectFailureWrapsErrCliTransport(t *testing.T) {
	// A closed listener's address: nothing will ever accept there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	host, port := func() (string, int) {
		hostStr, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatalf("net.SplitHostPort() error = %v", err)
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatalf("strconv.Atoi() error = %v", err)
		}
		return hostStr, p
	}()
	ln.Close()

	_, err = NewTelnetTransport(TelnetConfig{
		Host:     host,
		Port:     port,
		Username: "admin",
		Password: "s3cret",
		Timeout:  2 * time.Second,
	})
	if err == nil {
		t.Fatal("NewTelnetTransport() against a closed port succeeded, want error")
	}
	if !errors.Is(err, ErrCliTransport) {
		t.Errorf("NewTelnetTransport() error = %v, want it to wrap ErrCliTransport", err)
	}
}

// TestTelnetTransportReadTimesOutInsteadOfHanging is the telnet analogue of
// ssh_test.go's TestSSHTransportReadTimesOutInsteadOfHanging: against a
// server that completes login normally but then never responds to "show
// version", Run must still return -- bounded by TelnetConfig.Timeout, which
// arms a net.Conn read deadline before every Transport.Read (telnetTransport.Read)
// -- instead of blocking forever.
func TestTelnetTransportReadTimesOutInsteadOfHanging(t *testing.T) {
	const username, password = "admin", "s3cret"
	const readTimeout = 500 * time.Millisecond
	srv := newFakeTelnetServer(t, nil, "show version")
	host, port := srv.hostPort(t)

	transport, err := NewTelnetTransport(TelnetConfig{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		Timeout:  readTimeout,
	})
	if err != nil {
		t.Fatalf("NewTelnetTransport() error = %v", err)
	}
	defer transport.Close()

	driver := NewShellDriver(transport, ShellDriverConfig{})
	ctx := context.Background()
	if err := driver.Setup(ctx); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	type runResult struct {
		out string
		err error
	}
	done := make(chan runResult, 1)
	start := time.Now()
	go func() {
		out, err := driver.Run(ctx, "show version")
		done <- runResult{out, err}
	}()

	select {
	case r := <-done:
		elapsed := time.Since(start)
		if r.err == nil {
			t.Fatalf("Run() = (%q, nil) against a server that never responds, want a non-nil error", r.out)
		}
		if elapsed > 10*readTimeout {
			t.Errorf("Run() took %s to fail, want roughly bounded by Timeout=%s", elapsed, readTimeout)
		}
		t.Logf("Run() failed after %s (Timeout=%s): %v", elapsed, readTimeout, r.err)
	case <-time.After(10 * time.Second):
		t.Fatal("Run() did not return within 10s -- read deadline was not applied, hang not bounded")
	}
}

// TestTelnetConnStripsSubnegotiationAndUnescapesIAC exercises telnetConn
// directly (without a full TCP round trip) against a scripted net.Pipe,
// proving Read never surfaces IAC bytes to its caller: a WILL negotiation
// is refused (DONT), a subnegotiation block is skipped whole, and an
// escaped IAC IAC decodes to a single literal 0xFF data byte -- all
// interleaved with ordinary data bytes.
func TestTelnetConnStripsSubnegotiationAndUnescapesIAC(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	done := make(chan struct{})
	var negotiationReply []byte
	go func() {
		defer close(done)
		// Send FIRST: "ab" + IAC WILL SUPPRESS-GO-AHEAD + IAC SB <junk> IAC
		// SE + "c" + IAC IAC (literal 0xFF) + "d". The client's refuse()
		// reply to the WILL is only produced once it has decoded these
		// bytes, so the reply can only be read back AFTER this write --
		// reading it first would deadlock (nothing would ever prompt the
		// client to write anything).
		payload := []byte{'a', 'b', tnIAC, tnWILL, 3, tnIAC, tnSB, 3, 1, 2, 3, tnIAC, tnSE, 'c', tnIAC, tnIAC, 'd'}
		if _, err := serverConn.Write(payload); err != nil {
			return
		}
		reply := make([]byte, 3)
		if _, err := io.ReadFull(serverConn, reply); err == nil {
			negotiationReply = reply
		}
	}()

	tc := newTelnetConn(clientConn)
	// Want: "ab" + "c" + literal 0xFF + "d" = 5 decoded data bytes, once
	// every IAC negotiation/subnegotiation sequence is stripped. Read may
	// split this across multiple calls (each Read only drains what's
	// already buffered without a further blocking wait), so keep reading
	// until all 5 bytes are collected or an error ends the exchange.
	const wantLen = 5
	got := make([]byte, 0, wantLen)
	buf := make([]byte, 16)
	for len(got) < wantLen {
		n, err := tc.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	<-done

	want := []byte{'a', 'b', 'c', 0xff, 'd'}
	if string(got) != string(want) {
		t.Errorf("telnetConn.Read() decoded = % x, want %x (IAC negotiation/subnegotiation stripped, escaped IAC unescaped)", got, want)
	}
	wantReply := []byte{tnIAC, tnDONT, 3}
	if string(negotiationReply) != string(wantReply) {
		t.Errorf("negotiation reply = % x, want %x (IAC DONT in reply to IAC WILL -- refuse)", negotiationReply, wantReply)
	}
}
