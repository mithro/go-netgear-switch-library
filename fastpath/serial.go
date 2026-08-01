// serial.go ports src/netgear_switch/transport/cli/console.py (103 lines)
// at pin 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362 -- the serial/console
// byte transport for FASTPATH's CLI over a physical RS-232 line, built on
// go.bug.st/serial (spec line 236). Scope mirrors ssh.go/telnet.go: this
// file only produces the byte-level Transport (io.ReadWriteCloser) Task 5's
// ShellDriver/NewShellDriver consumes.
//
// Fidelity notes (Python -> Go):
//
//   - Framing/baud (console.py:21-23,63-65): "NETGEAR console ports default
//     to 115200 8N1." pyserial's `serial.Serial(device, baudrate=...,
//     timeout=...)` passes ONLY baudrate/timeout explicitly, so 8 data
//     bits / no parity / 1 stop bit / no flow control come from pyserial's
//     OWN library defaults, not an explicit choice in the pin. This file
//     sets them explicitly on go.bug.st/serial's Mode (which has no
//     implicit-default equivalent -- its zero value already happens to be
//     8N1 via Go's zero-value DataBits==0 being invalid, so BOTH
//     DataBits=8 and Parity/StopBits are set explicitly here) to match the
//     RESULT of pyserial's defaults byte-for-byte, documented as an
//     explicit choice rather than left to chance.
//   - Login (`_login`, console.py:48-53): a BLIND write sequence with NO
//     reads at all (unlike telnet's `_login`, which waits for each literal
//     prompt) -- "prod the console (it may already be at a prompt)" with a
//     bare "\r\n", then unconditionally write username+"\r\n" and
//     password+"\r\n" in immediate succession, trusting the device's own
//     line-buffering and ShellDriver.Setup's first readUntil (session.go)
//     to resync. serialLogin below is a pure function over any io.Writer so
//     this exact byte sequence is unit-testable without a real port (see
//     serial_test.go).
//   - Per-read timeout (console.py:63-65's `timeout=self._timeout`,
//     default 20s per `_DEFAULT_TIMEOUT = 20.0`, console.py:22): unlike
//     ssh.go/telnet.go (which re-arm a net.Conn deadline before every
//     single Read), go.bug.st/serial's SetReadTimeout is STICKY -- set once
//     after Open, it applies to every subsequent Port.Read call
//     automatically, exactly matching pyserial's `timeout=` constructor
//     argument (also a persistent per-read bound, not re-armed per call).
//     On timeout with no bytes received, go.bug.st/serial's Read returns
//     (0, nil) -- NOT an error -- which is the EXACT SAME shape as
//     pyserial's ser.read(n) returning b"" on timeout; session.go's
//     readUntil (mirroring session.py's `if not chunk: break`) already
//     treats a (0, nil) Read as "channel closed, no prompt seen yet" and
//     fails the op with ErrCliTransport rather than retrying -- so a single
//     unanswered read already bounds the op exactly like the Python
//     transport, with no extra translation needed for the timeout case
//     itself.
//   - Bare io.EOF on OUR OWN Close (the one case session.go's Transport
//     contract cares about, mirroring ssh.go/telnet.go): go.bug.st/serial's
//     Read on an already-closed port returns *serial.PortError{code:
//     PortClosed}, NOT io.EOF (unlike net.Conn). serialTransport tracks its
//     own closed flag and translates any post-Close Read error to bare
//     io.EOF (see serialTransport.Read) rather than pattern-matching on the
//     library's specific error type, which keeps the translation
//     unit-testable against a fake port (serial_test.go) without a real or
//     PTY-backed serial.Port. A spontaneous mid-session disconnect NOT
//     caused by our own Close() is passed through unmodified -- exercising
//     that path needs real (or PTY) hardware, a documented gap for Task
//     14/slice 11 (see this file's package doc note and the task report).
package fastpath

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"go.bug.st/serial"
)

// defaultSerialBaud/defaultSerialTimeout mirror console.py:21-22's
// `_DEFAULT_BAUD = 115200` and `_DEFAULT_TIMEOUT = 20.0`.
const (
	defaultSerialBaud    = 115200
	defaultSerialTimeout = 20 * time.Second
)

// SerialConfig configures NewSerialTransport, mirroring
// ConsoleCliTransport.__init__'s connection parameters (console.py):
// device path/baud/username/password/timeout for a FASTPATH switch's
// serial console CLI.
type SerialConfig struct {
	// Device is the serial port path (e.g. "/dev/ttyUSB0"). There is no
	// default -- unlike Host in SSHConfig/TelnetConfig, a console transport
	// is never network-reachable (transport dossier §4.1: CONSOLE "is a
	// transport option... not something auto-dispatch ever selects").
	Device string
	// Baud defaults to 115200 (console.py:21) when zero.
	Baud     int
	Username string
	Password string
	// Timeout bounds every Port.Read call (go.bug.st/serial's sticky
	// SetReadTimeout, set once after Open -- see the file-level doc
	// comment), defaulting to 20s (console.py:22) when zero or negative.
	Timeout time.Duration
}

// serialMode mirrors console.py:63-65's `serial.Serial(device,
// baudrate=self._baudrate, timeout=self._timeout)`: pyserial's own library
// defaults for the fields it doesn't pass explicitly are 8 data bits, no
// parity, 1 stop bit, no flow control ("NETGEAR console ports default to
// 115200 8N1", console.py:21) -- set explicitly here since
// go.bug.st/serial's Mode has no such implicit-default behavior of its own.
func serialMode(cfg SerialConfig) *serial.Mode {
	baud := cfg.Baud
	if baud == 0 {
		baud = defaultSerialBaud
	}
	return &serial.Mode{
		BaudRate: baud,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}
}

// serialTimeout applies SerialConfig.Timeout's zero/negative -> default
// fallback (console.py:22's `_DEFAULT_TIMEOUT = 20.0`), factored out as a
// pure function so it is unit-testable without opening a real port.
func serialTimeout(cfg SerialConfig) time.Duration {
	if cfg.Timeout <= 0 {
		return defaultSerialTimeout
	}
	return cfg.Timeout
}

// serialLogin mirrors Python `_login` (console.py:48-53) exactly: a BLIND
// write sequence with NO reads at all. w is any io.Writer so this exact
// byte sequence is unit-testable against an in-memory buffer without a real
// serial port (serial_test.go).
func serialLogin(w io.Writer, username, password string) error {
	// "Prod the console (it may already be at a prompt)".
	if _, err := w.Write([]byte("\r\n")); err != nil {
		return err
	}
	if _, err := w.Write([]byte(username + "\r\n")); err != nil {
		return err
	}
	if _, err := w.Write([]byte(password + "\r\n")); err != nil {
		return err
	}
	return nil
}

// serialPort is the minimal subset of go.bug.st/serial's Port interface
// serialTransport needs -- narrowed from the library's full Port interface
// (which also has SetMode/Drain/ResetInputBuffer/ResetOutputBuffer/SetDTR/
// SetRTS/GetModemStatusBits/Break) so tests can substitute a fake
// implementing just this subset, without a real or PTY-backed serial
// device.
type serialPort interface {
	io.ReadWriteCloser
	SetReadTimeout(t time.Duration) error
}

// serialTransport adapts a serialPort to the Transport interface
// (io.ReadWriteCloser), mirroring console.py:71-77's `send=ser.write,
// recv=ser.read` wiring (pyserial's `.read(n)` blocks up to `timeout`
// seconds returning fewer bytes or none, matching the Callable[[int],
// bytes] recv contract directly -- unlike telnet's lambda wrapper, no
// framing translation is needed here).
type serialTransport struct {
	port   serialPort
	closed atomic.Bool
}

func newSerialTransport(port serialPort) *serialTransport {
	return &serialTransport{port: port}
}

// Read implements Transport, delegating straight to the serialPort's Read
// -- go.bug.st/serial's sticky per-read timeout (set once in
// NewSerialTransport) already bounds every call the same way pyserial's
// timeout= does, so no per-call deadline arming is needed here (contrast
// with ssh.go/telnet.go's net.Conn.SetReadDeadline, which must be re-armed
// before every Read). If this transport's own Close has already run,
// translate whatever error the underlying port now reports to bare io.EOF
// -- see the file-level doc comment for why this is done via our own
// closed flag rather than pattern-matching go.bug.st/serial's specific
// *serial.PortError type.
func (t *serialTransport) Read(p []byte) (int, error) {
	n, err := t.port.Read(p)
	if err != nil && t.closed.Load() {
		return n, io.EOF
	}
	return n, err
}

// Write implements Transport.
func (t *serialTransport) Write(p []byte) (int, error) {
	return t.port.Write(p)
}

// Close implements Transport, mirroring console.py:98-103's close() (a
// single ser.close() call) -- like ssh.go/telnet.go, NOT suppressing the
// error (see ssh.go's file-level doc comment for why).
func (t *serialTransport) Close() error {
	t.closed.Store(true)
	return t.port.Close()
}

// NewSerialTransport opens cfg.Device at 115200 8N1 (or SerialConfig.Baud),
// arms the per-read timeout, and drives the blind prod+User:+Password:
// login write sequence -- the Go equivalent of ConsoleCliTransport.connect()
// (console.py:55-78) up to (but not including) ShellDriver construction/
// Setup, which is the caller's job (see the file-level doc comment). Any
// failure at any step is wrapped in ErrCliTransport, mirroring
// console.py:67-69's single `except Exception as exc: self.close(); raise
// CliTransportError(f"console open/login failed: {exc}")`.
//
// This function itself -- opening a real device and completing a login
// round trip against real FASTPATH console firmware -- has no CI coverage
// (no serial hardware/PTY harness in this task's scope); serial_test.go
// covers everything below it (mode/timeout defaults, the login byte
// sequence, and the post-Close io.EOF translation) against fakes. See the
// file-level doc comment's "documented gap" note.
func NewSerialTransport(cfg SerialConfig) (Transport, error) {
	mode := serialMode(cfg)
	timeout := serialTimeout(cfg)

	port, err := serial.Open(cfg.Device, mode)
	if err != nil {
		return nil, fmt.Errorf("%w: console open/login failed: %w", ErrCliTransport, err)
	}
	if err := port.SetReadTimeout(timeout); err != nil {
		port.Close()
		return nil, fmt.Errorf("%w: console open/login failed: %w", ErrCliTransport, err)
	}

	t := newSerialTransport(port)
	if err := serialLogin(t, cfg.Username, cfg.Password); err != nil {
		port.Close()
		return nil, fmt.Errorf("%w: console open/login failed: %w", ErrCliTransport, err)
	}
	return t, nil
}
