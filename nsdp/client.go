package nsdp

// Ported field-for-field from
// src/netgear_switch/transport/sync/nsdp_udp.py (+ transport/aio/nsdp_udp.py
// deltas) and src/netgear_switch/protocols/nsdp/client.py at pin 1aa1274 in
// python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274, branch fix/s3300-52x-live-verify). Any discrepancy
// between this file and that pin is a bug in this file, not a deliberate
// deviation, unless called out in a comment.
//
// Go has no separate sync/async split, so only one transport client exists
// here (UDPClient), combining the Python sync client's socket lifecycle with
// the aio client's injectable-transceive seam for testability
// (`transceive` plays the role of both `sock_factory` and `_udp_transceive`).

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
)

// Defaults for UDPClient, mirroring Python UdpNsdpClient's constructor
// kwargs (dossier §5.1/§5.5): these are per-instance overridable defaults,
// not module constants/env vars, matching Python exactly.
const (
	DefaultClientPort = 63321
	DefaultServerPort = 63322
	DefaultTimeout    = 2 * time.Second

	// recvBufferSize bounds a single received datagram (dossier §5.5); a
	// larger real response is silently truncated by the OS/kernel exactly as
	// Python's sock.recvfrom(4096) would truncate it.
	recvBufferSize = 4096
)

// dummyClientMAC is used as ClientMAC when neither an explicit MAC nor an
// interface was configured (dossier §5.7's _DUMMY_MAC).
var dummyClientMAC = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

// zeroMAC is the destination-MAC header field placeholder
// (dossier §5.7's _BROADCAST_MAC) sent as ServerMAC on every outgoing
// request -- read AND write -- regardless of query type.
var zeroMAC = make([]byte, 6)

// errNSDPCause returns an error wrapping both model.ErrNSDP and cause (via a
// Go 1.20+ multi-%w Errorf), so errors.Is matches either the library-wide
// NSDP sentinel or the original underlying cause. Sibling to errNSDP
// (protocol.go), for the handful of call sites in this file that must keep
// a wrapped cause reachable in the error chain (a decode error behind a
// malformed response, or the real net.Error behind a receive timeout) --
// see TestErrNSDPCause_PreservesCauseAndSentinel for the direct proof this
// mechanism actually works.
func errNSDPCause(cause error, format string, a ...any) error {
	return fmt.Errorf("%s: %w: %w", fmt.Sprintf(format, a...), model.ErrNSDP, cause)
}

// CheckResult returns an error (wrapping model.ErrNSDP, via errNSDP) unless
// packet reports success (Result == ResultSuccess). Mirrors Python
// protocols.nsdp.client.check_result exactly: only ResultSuccess is silent;
// ResultBadPassword gets the bad-password message with AuthV2Unsupported
// appended verbatim; any other non-zero result gets a generic "failed with
// result 0x%04x" message (4 lowercase hex digits, zero-padded).
func CheckResult(packet Packet) error {
	switch packet.Result {
	case ResultSuccess:
		return nil
	case ResultBadPassword:
		return errNSDP("NSDP write rejected: bad password (result 0x0700). %s", AuthV2Unsupported)
	default:
		return errNSDP("NSDP request failed with result 0x%04x", packet.Result)
	}
}

// ReadInterfaceMAC reads iface's 6-byte MAC address from Linux sysfs
// (/sys/class/net/<iface>/address), mirroring Python
// protocols.nsdp.client.read_interface_mac exactly: Linux-sysfs-only, no
// portability fallback attempted here (the fallback to the dummy MAC lives
// in NewUDPClient, only when neither an explicit MAC nor an interface is
// given at all -- see dossier §5.7).
//
// A missing/unreadable sysfs file, or non-hex content, propagates the raw
// os/hex error UNWRAPPED (mirroring Python's Path.read_text()/bytes.fromhex
// raising their own exception types, not NsdpError). Only the length check
// -- present but not 6 bytes -- returns an error wrapping model.ErrNSDP (via
// errNSDP), matching Python's single explicit `raise NsdpError(...)` call
// site.
func ReadInterfaceMAC(iface string) ([]byte, error) {
	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/address", iface))
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(data))
	raw, err := hex.DecodeString(strings.ReplaceAll(text, ":", ""))
	if err != nil {
		return nil, err
	}
	if len(raw) != 6 {
		return nil, errNSDP("interface %q MAC is not 6 bytes: %q", iface, text)
	}
	return raw, nil
}

// Client is the NSDP read client interface for a single switch, mirroring
// Python's protocols.nsdp.client.NsdpClient Protocol (Go has no separate
// sync/async split, so only one pair of interfaces is needed here).
type Client interface {
	Read(ctx context.Context, tags []Tag) (*Packet, error)
}

// WriteClient extends Client with an authenticated write, mirroring
// Python's NsdpWriteClient Protocol.
type WriteClient interface {
	Client
	Write(ctx context.Context, tlvs []TLVEntry, password string) (*Packet, error)
}

// transceiveFunc sends payload to host:serverPort over UDP (binding the
// local socket to clientPort, best-effort SO_BINDTODEVICE-ing to iface if
// non-empty) and returns the raw response datagram. realTransceive is the
// production implementation (a real socket per call, mirroring Python's
// per-call socket lifecycle); tests inject a fake here instead, mirroring
// Python's dual seams: the sync client's injectable `sock_factory` and the
// aio client's standalone `_udp_transceive` coroutine.
type transceiveFunc func(ctx context.Context, payload []byte, host string, serverPort, clientPort int, iface string) ([]byte, error)

// UDPClient is the NSDP UDP transport client for a single switch: the
// "query_ip" pattern (dossier §5.8) -- unicast to a known host, no broadcast
// discovery. Construct with NewUDPClient, never a bare struct literal (the
// zero value has no ClientMAC resolved and no default transceive func).
type UDPClient struct {
	// Host is the switch's IP/hostname; every request is sent here,
	// unicast, on ServerPort. Mandatory (set by NewUDPClient's host arg).
	Host string
	// ClientPort is the local UDP port to bind ("" all-interfaces, per
	// dossier §5.2); 0 requests an ephemeral unprivileged port (used by
	// tests). Defaults to DefaultClientPort.
	ClientPort int
	// ServerPort is the switch's NSDP UDP port. Defaults to DefaultServerPort.
	ServerPort int
	// Interface, if non-empty, is best-effort SO_BINDTODEVICE'd on the
	// socket (dossier §5.3) and, absent an explicit ClientMAC, is read via
	// ReadInterfaceMAC to populate ClientMAC.
	Interface string
	// ClientMAC is the 6-byte MAC placed in every outgoing request's
	// ClientMAC header field. Resolved by NewUDPClient per dossier §5.7.
	ClientMAC []byte
	// Timeout bounds each request/response exchange. Defaults to
	// DefaultTimeout (2s).
	Timeout time.Duration

	mu       sync.Mutex
	sequence uint32

	transceive transceiveFunc
}

// Option configures a UDPClient at construction time (NewUDPClient).
type Option func(*UDPClient)

// WithClientPort overrides the local UDP client port (default
// DefaultClientPort; pass 0 for an ephemeral unprivileged bind, e.g. in tests).
func WithClientPort(port int) Option { return func(c *UDPClient) { c.ClientPort = port } }

// WithServerPort overrides the switch's NSDP UDP port (default DefaultServerPort).
func WithServerPort(port int) Option { return func(c *UDPClient) { c.ServerPort = port } }

// WithTimeout overrides the per-exchange timeout (default DefaultTimeout).
func WithTimeout(d time.Duration) Option { return func(c *UDPClient) { c.Timeout = d } }

// WithInterface sets the network interface to best-effort SO_BINDTODEVICE
// and, absent WithClientMAC, to read the ClientMAC from via ReadInterfaceMAC.
func WithInterface(iface string) Option { return func(c *UDPClient) { c.Interface = iface } }

// WithClientMAC sets an explicit 6-byte ClientMAC, taking precedence over
// any WithInterface-derived MAC (dossier §5.7).
func WithClientMAC(mac []byte) Option { return func(c *UDPClient) { c.ClientMAC = mac } }

// withTransceiver overrides the real UDP transceiver with fn. Unexported:
// only this package's own tests use it, to exercise Read/Write's
// request-building, op-check, and CheckResult logic without a real socket.
func withTransceiver(fn transceiveFunc) Option { return func(c *UDPClient) { c.transceive = fn } }

// NewUDPClient constructs a UDPClient for host, applying opts over the
// documented defaults, then resolving ClientMAC per dossier §5.7's exact
// precedence:
//
//  1. an explicit WithClientMAC wins outright;
//  2. else, if WithInterface was given, the real MAC is read via
//     ReadInterfaceMAC -- and any error from that read (missing interface,
//     wrong-length MAC) is returned here, NOT silently swallowed into the
//     dummy MAC (this is deliberately not a try/except fallback, matching
//     Python's __init__ exactly);
//  3. else the dummy MAC 00:00:00:00:00:01 is used.
func NewUDPClient(host string, opts ...Option) (*UDPClient, error) {
	c := &UDPClient{
		Host:       host,
		ClientPort: DefaultClientPort,
		ServerPort: DefaultServerPort,
		Timeout:    DefaultTimeout,
		transceive: realTransceive,
	}
	for _, opt := range opts {
		opt(c)
	}

	switch {
	case c.ClientMAC != nil:
		// explicit WithClientMAC wins; nothing to do.
	case c.Interface != "":
		mac, err := ReadInterfaceMAC(c.Interface)
		if err != nil {
			return nil, err
		}
		c.ClientMAC = mac
	default:
		c.ClientMAC = dummyClientMAC
	}
	return c, nil
}

// nextSeq increments and returns the client's 16-bit sequence counter,
// mirroring Python's _next_seq: starts at 0, PRE-increments (the first
// sequence sent is 1, not 0), wraps at 0xFFFF (dossier §5.6) even though the
// wire header field itself is a full 32 bits (dossier §1.2).
func (c *UDPClient) nextSeq() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sequence = (c.sequence + 1) & 0xFFFF
	return c.sequence
}

// exchange encodes req, sends it via c.transceive, and decodes the response.
// Mirrors Python UdpNsdpClient._exchange's error ordering exactly: any
// transceive error (bind/send/recv failure -- including a receive timeout)
// propagates from c.transceive UNCHANGED; the recv-side timeout-to-"timed
// out" translation happens inside the transceiveFunc itself (realTransceive
// does this only for its actual recv step, matching Python's _exchange only
// special-casing the recvfrom TimeoutError and letting any other OSError
// from bind/sendto propagate raw). A decode failure becomes an error
// wrapping model.ErrNSDP and the decode cause ("malformed NSDP response
// from %s: %v").
func (c *UDPClient) exchange(ctx context.Context, req Packet) (Packet, error) {
	payload, err := req.Encode()
	if err != nil {
		return Packet{}, err
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	cctx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	fn := c.transceive
	if fn == nil {
		fn = realTransceive
	}
	data, err := fn(cctx, payload, c.Host, c.ServerPort, c.ClientPort, c.Interface)
	if err != nil {
		return Packet{}, err
	}

	resp, err := DecodePacket(data)
	if err != nil {
		return Packet{}, errNSDPCause(err, "malformed NSDP response from %s: %v", c.Host, err)
	}
	return resp, nil
}

// Read sends a READ_REQUEST for tags and returns the decoded response.
// Mirrors Python UdpNsdpClient.read: checks the response op-code against
// OpReadResponse before returning it (no CheckResult call at all for reads
// -- only the write path inspects Result).
func (c *UDPClient) Read(ctx context.Context, tags []Tag) (*Packet, error) {
	req := BuildReadRequest(c.ClientMAC, zeroMAC, c.nextSeq(), tags)
	resp, err := c.exchange(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Op != OpReadResponse {
		return nil, errNSDP("expected READ_RESPONSE from %s, got %s", c.Host, resp.Op)
	}
	return &resp, nil
}

// Write sends a password-authenticated WRITE_REQUEST for tlvs and returns
// the decoded response, after confirming success via CheckResult. Mirrors
// Python UdpNsdpClient.write: the op-code check runs BEFORE CheckResult
// (dossier §5.9) -- a stray/misrouted datagram (e.g. an old READ_RESPONSE
// with Result==ResultSuccess) must not silently pass as a successful write,
// so anything that isn't actually a WRITE_RESPONSE is rejected before its
// Result field is ever consulted.
func (c *UDPClient) Write(ctx context.Context, tlvs []TLVEntry, password string) (*Packet, error) {
	req, err := BuildWriteRequest(c.ClientMAC, zeroMAC, c.nextSeq(), password, tlvs)
	if err != nil {
		return nil, err
	}
	resp, err := c.exchange(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Op != OpWriteResponse {
		return nil, errNSDP("expected WRITE_RESPONSE from %s, got %s", c.Host, resp.Op)
	}
	if err := CheckResult(resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Compile-time interface satisfaction checks.
var (
	_ Client      = (*UDPClient)(nil)
	_ WriteClient = (*UDPClient)(nil)
)

// realTransceive is the production transceiveFunc: one real UDP socket per
// call (mirroring Python's per-call socket lifecycle), ctx-aware via
// net.Dialer (dial itself derives its deadline from ctx, set up by exchange
// -- either the caller's own ctx deadline, or one derived from the client's
// configured Timeout).
//
// Socket options (dossier §5.3/§5.4) are applied via the platform-specific
// controlFunc: SO_REUSEADDR unconditionally, and -- on linux only, via a
// build-tagged file -- best-effort SO_BINDTODEVICE to iface, suppressing
// any error (needs CAP_NET_RAW/root; an unprivileged caller must still
// attempt the query rather than crash).
//
// The ctx deadline is applied ONLY as a read deadline (conn.SetReadDeadline,
// not conn.SetDeadline), so it bounds the recv step alone -- matching
// Python's _exchange, which only special-cases the recvfrom TimeoutError and
// lets any dial/sendto failure propagate raw (dossier §5.10). Dial and write
// failures here likewise return the raw error unchanged; only a recv-side
// net.Error with Timeout()==true is translated into an error wrapping
// model.ErrNSDP (via errNSDPCause, preserving the original net.Error as the
// cause) with the "NSDP request to %s timed out" message.
func realTransceive(ctx context.Context, payload []byte, host string, serverPort, clientPort int, iface string) ([]byte, error) {
	dialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{Port: clientPort},
		Control:   controlFunc(iface),
	}

	conn, err := dialer.DialContext(ctx, "udp4", net.JoinHostPort(host, strconv.Itoa(serverPort)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetReadDeadline(dl); err != nil {
			return nil, err
		}
	}

	buf := make([]byte, recvBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, errNSDPCause(err, "NSDP request to %s timed out", host)
		}
		return nil, err
	}
	return buf[:n], nil
}
