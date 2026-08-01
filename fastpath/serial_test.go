package fastpath

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"go.bug.st/serial"
)

// TestSerialModeDefaults asserts serialMode reproduces console.py:21,63-65's
// "NETGEAR console ports default to 115200 8N1" -- baud defaults to 115200
// when SerialConfig.Baud is zero, and data bits/parity/stop bits are always
// 8/None/One regardless of Baud, matching pyserial's own library defaults
// for the fields console.py never passes explicitly.
func TestSerialModeDefaults(t *testing.T) {
	mode := serialMode(SerialConfig{})
	if mode.BaudRate != defaultSerialBaud {
		t.Errorf("BaudRate = %d, want %d (default 115200)", mode.BaudRate, defaultSerialBaud)
	}
	if mode.DataBits != 8 {
		t.Errorf("DataBits = %d, want 8", mode.DataBits)
	}
	if mode.Parity != serial.NoParity {
		t.Errorf("Parity = %v, want NoParity", mode.Parity)
	}
	if mode.StopBits != serial.OneStopBit {
		t.Errorf("StopBits = %v, want OneStopBit", mode.StopBits)
	}
}

// TestSerialModeExplicitBaud asserts a non-zero SerialConfig.Baud overrides
// the 115200 default while framing (8N1) stays fixed.
func TestSerialModeExplicitBaud(t *testing.T) {
	mode := serialMode(SerialConfig{Baud: 9600})
	if mode.BaudRate != 9600 {
		t.Errorf("BaudRate = %d, want 9600 (explicit override)", mode.BaudRate)
	}
	if mode.DataBits != 8 || mode.Parity != serial.NoParity || mode.StopBits != serial.OneStopBit {
		t.Errorf("framing changed with explicit baud: DataBits=%d Parity=%v StopBits=%v, want 8/NoParity/OneStopBit",
			mode.DataBits, mode.Parity, mode.StopBits)
	}
}

// TestSerialTimeoutDefault asserts serialTimeout mirrors console.py:22's
// `_DEFAULT_TIMEOUT = 20.0` for zero/negative SerialConfig.Timeout, and
// passes a positive value through unchanged.
func TestSerialTimeoutDefault(t *testing.T) {
	tests := []struct {
		name string
		cfg  SerialConfig
		want time.Duration
	}{
		{"zero", SerialConfig{}, defaultSerialTimeout},
		{"negative", SerialConfig{Timeout: -1 * time.Second}, defaultSerialTimeout},
		{"explicit", SerialConfig{Timeout: 5 * time.Second}, 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := serialTimeout(tt.cfg); got != tt.want {
				t.Errorf("serialTimeout(%+v) = %s, want %s", tt.cfg, got, tt.want)
			}
		})
	}
}

// TestSerialLoginBlindWriteSequence asserts serialLogin reproduces
// console.py:48-53's `_login` exactly: a bare "\r\n" prod, then
// username+"\r\n" and password+"\r\n" written in immediate succession, with
// NO reads at all -- the least robust of the three transports' login
// sequences by design (ShellDriver.Setup's own first readUntil is what
// resyncs). Exercised against an in-memory bytes.Buffer since the design
// keeps serialLogin transport-agnostic (any io.Writer).
func TestSerialLoginBlindWriteSequence(t *testing.T) {
	var buf bytes.Buffer
	if err := serialLogin(&buf, "admin", "s3cret"); err != nil {
		t.Fatalf("serialLogin() error = %v", err)
	}
	want := "\r\nadmin\r\ns3cret\r\n"
	if buf.String() != want {
		t.Errorf("serialLogin() wrote %q, want %q", buf.String(), want)
	}
}

// TestSerialLoginPropagatesWriteError asserts serialLogin stops and returns
// the first Write error it sees, rather than continuing to write further
// login bytes on a broken channel.
func TestSerialLoginPropagatesWriteError(t *testing.T) {
	wantErr := errors.New("boom")
	w := &erroringWriter{failAfter: 0, err: wantErr}
	if err := serialLogin(w, "admin", "s3cret"); !errors.Is(err, wantErr) {
		t.Errorf("serialLogin() error = %v, want it to wrap %v", err, wantErr)
	}
	if w.calls != 1 {
		t.Errorf("Write called %d times, want exactly 1 (stop at first error)", w.calls)
	}
}

type erroringWriter struct {
	failAfter int
	calls     int
	err       error
}

func (w *erroringWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls > w.failAfter {
		return 0, w.err
	}
	return len(p), nil
}

// fakeSerialPort is a minimal in-memory serialPort fake for testing
// serialTransport's Read/Write/Close plumbing (in particular the post-Close
// io.EOF translation) without a real or PTY-backed serial device.
type fakeSerialPort struct {
	writes      []string
	readErr     error
	readTimeout time.Duration
	closeErr    error
	closed      bool
}

func (p *fakeSerialPort) Read(_ []byte) (int, error) {
	if p.readErr != nil {
		return 0, p.readErr
	}
	return 0, nil // mirrors a timed-out serial read: (0, nil), no data.
}

func (p *fakeSerialPort) Write(buf []byte) (int, error) {
	p.writes = append(p.writes, string(buf))
	return len(buf), nil
}

func (p *fakeSerialPort) Close() error {
	p.closed = true
	return p.closeErr
}

func (p *fakeSerialPort) SetReadTimeout(t time.Duration) error {
	p.readTimeout = t
	return nil
}

// TestSerialTransportReadAfterCloseIsBareIOEOF is the serial analogue of
// ssh_test.go/telnet_test.go's post-Close bare-io.EOF assertion
// (session.go's Transport contract, session.go:242/362/416's `err !=
// io.EOF` comparisons): go.bug.st/serial's real Read on an already-closed
// port returns *serial.PortError{code: PortClosed}, not io.EOF, so
// serialTransport must translate. Modeled here with a fake port whose Read
// returns an arbitrary non-nil error post-close (the exact library error
// type can only be produced by a real/PTY-backed port, a documented gap --
// see serial.go's file-level doc comment) to prove the translation itself,
// independent of the specific error go.bug.st/serial happens to return.
func TestSerialTransportReadAfterCloseIsBareIOEOF(t *testing.T) {
	fp := &fakeSerialPort{readErr: errors.New("port closed (library-specific error)")}
	tr := newSerialTransport(fp)

	if err := tr.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !fp.closed {
		t.Fatal("Close() did not close the underlying port")
	}

	buf := make([]byte, 16)
	n, err := tr.Read(buf)
	if !errors.Is(err, io.EOF) {
		t.Errorf("Read() after Close() = (%d, %v), want (_, io.EOF) [bare, via == not just errors.Is]", n, err)
	}
}

// TestSerialTransportReadBeforeCloseDoesNotTranslate asserts the io.EOF
// translation only applies AFTER this transport's own Close has run -- an
// error surfacing on a still-open port (e.g. a genuine unplug) is passed
// through unmodified, not silently turned into a clean-close signal.
func TestSerialTransportReadBeforeCloseDoesNotTranslate(t *testing.T) {
	wantErr := errors.New("read failed, port still open")
	fp := &fakeSerialPort{readErr: wantErr}
	tr := newSerialTransport(fp)

	buf := make([]byte, 16)
	_, err := tr.Read(buf)
	if !errors.Is(err, wantErr) {
		t.Errorf("Read() before Close() = %v, want it to pass through %v unmodified", err, wantErr)
	}
}

// TestSerialTransportSetReadTimeoutIsSticky asserts NewSerialTransport's
// timeout wiring calls SetReadTimeout exactly once with the resolved
// duration (default or explicit) -- unlike ssh.go/telnet.go, which re-arm a
// net.Conn deadline before every single Read, go.bug.st/serial's timeout is
// set once and applies to every subsequent Read automatically (see
// serial.go's file-level doc comment). This test exercises the plumbing
// serialTransport itself is built on (a fake port), not NewSerialTransport
// (which needs a real device to open).
func TestSerialTransportSetReadTimeoutIsSticky(t *testing.T) {
	fp := &fakeSerialPort{}
	if err := fp.SetReadTimeout(7 * time.Second); err != nil {
		t.Fatalf("SetReadTimeout() error = %v", err)
	}
	tr := newSerialTransport(fp)
	// Two Reads, no re-arming call between them (unlike telnetTransport.Read/
	// sshTransport.Read) -- the sticky timeout set once above still applies.
	buf := make([]byte, 4)
	if _, err := tr.Read(buf); err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if _, err := tr.Read(buf); err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if fp.readTimeout != 7*time.Second {
		t.Errorf("readTimeout = %s, want 7s (unchanged across Reads)", fp.readTimeout)
	}
}
