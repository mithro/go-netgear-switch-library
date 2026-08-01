package fastpath

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// fakeFastpathHandler returns a gliderlabs/ssh Handler that plays a tiny
// scripted FASTPATH CLI over a real interactive shell channel: it writes an
// initial prompt as soon as the shell starts (matching Setup's first
// readUntil, which reads a banner/prompt BEFORE writing anything --
// session.go), then answers "enable"/"terminal length 0" with a bare
// prompt and any command in responses with an echo + canned output +
// prompt, exactly the framing ShellDriver's readUntil/cleanOutput expect
// (session_test.go's fakeTransport tests establish the same shape over an
// in-memory channel; this is the same script over a real network+crypto
// channel).
func fakeFastpathHandler(responses map[string]string) gliderssh.Handler {
	return func(sess gliderssh.Session) {
		if _, err := sess.Write([]byte("\r\n(FAKESW) #")); err != nil {
			return
		}
		reader := bufio.NewReader(sess)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.TrimRight(line, "\r\n")
			switch cmd {
			case "enable", "terminal length 0":
				if _, err := sess.Write([]byte("\r\n(FAKESW) #")); err != nil {
					return
				}
			default:
				out, ok := responses[cmd]
				if !ok {
					out = "% Unknown command"
				}
				if _, err := sess.Write([]byte(cmd + "\r\n" + out + "\r\n(FAKESW) #")); err != nil {
					return
				}
			}
		}
	}
}

// hangingFastpathHandler behaves exactly like fakeFastpathHandler for
// "enable"/"terminal length 0" (so Setup completes normally) but, on
// hangOnCmd, deliberately never writes a response -- simulating a
// wedged/flaky old-FASTPATH switch that accepted the connection and the
// command but never answers. It blocks until the session's context is
// done (client disconnect) instead of returning immediately, so it
// doesn't race the client's own read timeout by closing the channel
// itself first.
func hangingFastpathHandler(hangOnCmd string) gliderssh.Handler {
	return func(sess gliderssh.Session) {
		if _, err := sess.Write([]byte("\r\n(FAKESW) #")); err != nil {
			return
		}
		reader := bufio.NewReader(sess)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.TrimRight(line, "\r\n")
			switch cmd {
			case hangOnCmd:
				<-sess.Context().Done()
				return
			case "enable", "terminal length 0":
				if _, err := sess.Write([]byte("\r\n(FAKESW) #")); err != nil {
					return
				}
			default:
				if _, err := sess.Write([]byte(cmd + "\r\n% Unknown command\r\n(FAKESW) #")); err != nil {
					return
				}
			}
		}
	}
}

// newLegacySSHTestServer starts a loopback-only gliderlabs/ssh server that
// accepts ONLY the legacy key exchange diffie-hellman-group14-sha1 (dossier
// §2.1) and an RSA host key (so the "ssh-rsa" host-key algorithm is what
// gets negotiated), authenticating exactly one username/password pair.
// Returns the listener's host and port. The server is closed via
// t.Cleanup.
func newLegacySSHTestServer(t *testing.T, username, password string, responses map[string]string) (host string, port int) {
	t.Helper()
	return newLegacySSHTestServerWithHandler(t, username, password, fakeFastpathHandler(responses))
}

// newLegacySSHTestServerWithHandler is newLegacySSHTestServer's underlying
// builder, parameterized on the Handler so tests that need a
// non-standard script (e.g. hangingFastpathHandler) can reuse the same
// legacy-KEX-only, RSA-host-key server setup.
func newLegacySSHTestServerWithHandler(t *testing.T, username, password string, handler gliderssh.Handler) (host string, port int) {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	signer, err := gossh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey() error = %v", err)
	}

	srv := &gliderssh.Server{
		Handler: handler,
		PasswordHandler: func(ctx gliderssh.Context, pass string) bool {
			return ctx.User() == username && pass == password
		},
		// Restrict the server to ONLY the legacy KEX old FASTPATH
		// firmware offers, so a successful round trip proves the
		// client actually negotiated it rather than falling back to
		// a modern default.
		ServerConfigCallback: func(_ gliderssh.Context) *gossh.ServerConfig {
			return &gossh.ServerConfig{
				Config: gossh.Config{KeyExchanges: []string{legacySSHKeyExchange}},
			}
		},
	}
	srv.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	hostStr, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) error = %v", ln.Addr().String(), err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi(%q) error = %v", portStr, err)
	}
	return hostStr, portNum
}

// TestSSHTransportRunRoundTripThroughShellDriver drives a real loopback SSH
// connection (real TCP + real crypto handshake against a gliderlabs/ssh
// server restricted to the legacy KEX) through NewSSHTransport ->
// NewShellDriver -> Setup -> Run, asserting: the legacy KEX and ssh-rsa
// host-key algorithm were actually negotiated (not just offered), the
// command's output round-trips correctly framed, and Close() leaves the
// Transport's Read returning bare io.EOF (session.go's Transport contract
// -- see ssh.go's Read doc comment).
func TestSSHTransportRunRoundTripThroughShellDriver(t *testing.T) {
	const username, password = "admin", "s3cret"
	const wantOutput = "FAKESW Software, Version 1.2.3"
	host, port := newLegacySSHTestServer(t, username, password, map[string]string{
		"show version": wantOutput,
	})

	transport, err := NewSSHTransport(SSHConfig{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSSHTransport() error = %v", err)
	}

	st, ok := transport.(*sshTransport)
	if !ok {
		t.Fatalf("NewSSHTransport() returned %T, want *sshTransport", transport)
	}
	algoConn, ok := st.client.Conn.(gossh.AlgorithmsConnMetadata)
	if !ok {
		t.Fatalf("client.Conn (%T) does not implement AlgorithmsConnMetadata", st.client.Conn)
	}
	algos := algoConn.Algorithms()
	if algos.KeyExchange != legacySSHKeyExchange {
		t.Errorf("negotiated key exchange = %q, want %q", algos.KeyExchange, legacySSHKeyExchange)
	}
	if algos.HostKey != legacySSHHostKeyAlgo {
		t.Errorf("negotiated host-key algorithm = %q, want %q", algos.HostKey, legacySSHHostKeyAlgo)
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
	if !errors.Is(err, io.EOF) {
		t.Errorf("Read() after Close() = (%d, %v), want (_, io.EOF) [bare, via errors.Is-independent ==]", n, err)
	}
}

// TestSSHTransportAuthFailureWrapsErrCliTransport proves connect/auth
// failures (ssh.py:106-108's `except Exception as exc: raise
// CliTransportError(...)`) are normalized to ErrCliTransport, matchable
// with errors.Is, exactly like every other transport failure in this
// package.
func TestSSHTransportAuthFailureWrapsErrCliTransport(t *testing.T) {
	const username, password = "admin", "s3cret"
	host, port := newLegacySSHTestServer(t, username, password, nil)

	_, err := NewSSHTransport(SSHConfig{
		Host:     host,
		Port:     port,
		Username: username,
		Password: "wrong-password",
		Timeout:  5 * time.Second,
	})
	if err == nil {
		t.Fatal("NewSSHTransport() with wrong password succeeded, want error")
	}
	if !errors.Is(err, ErrCliTransport) {
		t.Errorf("NewSSHTransport() error = %v, want it to wrap ErrCliTransport", err)
	}
}

// TestSSHTransportReadTimesOutInsteadOfHanging is the fix-round-1 regression
// test: against a server that accepts the connection, completes Setup
// normally, but then never responds to "show version" (hangingFastpathHandler),
// Run must still return -- bounded by SSHConfig.Timeout, which now also
// arms a net.Conn read deadline before every Transport.Read (see ssh.go's
// Read doc comment) -- instead of blocking forever. Before this fix,
// session.go's ctx check (only up front, never mid-Read) could not unblock
// this: nothing bounded the read at all.
func TestSSHTransportReadTimesOutInsteadOfHanging(t *testing.T) {
	const username, password = "admin", "s3cret"
	const readTimeout = 500 * time.Millisecond
	host, port := newLegacySSHTestServerWithHandler(t, username, password, hangingFastpathHandler("show version"))

	transport, err := NewSSHTransport(SSHConfig{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		Timeout:  readTimeout,
	})
	if err != nil {
		t.Fatalf("NewSSHTransport() error = %v", err)
	}
	defer func() { _ = transport.Close() }()

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
		// Generously loose upper bound: prove it's bounded by
		// roughly the configured timeout, not that it hangs --
		// readUntil only needs to observe ONE timed-out Read before
		// giving up (the deadline firing tears down the whole
		// connection, so every channel on it closes at once), so in
		// practice this lands close to 1x readTimeout.
		if elapsed > 10*readTimeout {
			t.Errorf("Run() took %s to fail, want roughly bounded by Timeout=%s", elapsed, readTimeout)
		}
		t.Logf("Run() failed after %s (Timeout=%s): %v", elapsed, readTimeout, r.err)
	case <-time.After(10 * time.Second):
		t.Fatal("Run() did not return within 10s -- read deadline was not applied, hang not bounded")
	}
}
