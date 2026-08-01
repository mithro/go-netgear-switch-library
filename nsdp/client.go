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

// errorNames maps an NSDP error code (Result>>8) to its human name, mirroring
// Python protocol.py's ERROR_NAMES verbatim.
var errorNames = map[int]string{
	0:                 "none",
	ErrorReadOnly:     "attribute not readable",
	ErrorWriteOnly:    "attribute not writable",
	0x05:              "invalid value",
	ErrorDenied:       "denied",
	ErrorAuthRejected: "write authentication rejected",
	ErrorLocked:       "write locked out after repeated auth failures",
}

// errorName names an NSDP error code, falling back to "unknown error code N".
func errorName(code int) string {
	if n, ok := errorNames[code]; ok {
		return n
	}
	return fmt.Sprintf("unknown error code %d", code)
}

// attrName names the TLV tag the switch blamed for a rejection, mirroring
// Python client.py's _attr_name ("<NAME> (0x%04x)"), or "no attribute" when
// the switch named none. Go has no enum-name reflection like Python's
// Tag(tag).name, so the tag is rendered as its 4-digit hex value (the
// slice-10 cross-language error-text comparison already folds Python's richer
// wording; the numeric tag is what actually identifies the blamed attribute).
func attrName(attr uint16) string {
	if attr == 0 {
		return "no attribute"
	}
	return fmt.Sprintf("0x%04x", attr)
}

// CheckResult returns an error (wrapping model.ErrNSDP, via errNSDP) unless
// packet reports success (Result == ResultSuccess). Mirrors Python
// protocols.nsdp.client.check_result: it NAMES the blamed attribute (ErrorAttr)
// so a caller can debug the rejection (principle 1). The load-bearing case is
// error 13 (ErrorAuthRejected) blamed on TagPassword -- a v1 XOR password
// offered to firmware that only accepts the v2 salted challenge-response,
// which is a WIRING problem (AuthV2Unsupported), not a wrong credential. Error
// 13 on any other attribute, or error 7, really is a bad password. Error 14 is
// the write lockout.
func CheckResult(packet Packet) error {
	if packet.Result == ResultSuccess {
		return nil
	}
	code := packet.ErrorCode()
	blamed := attrName(packet.ErrorAttr)
	detail := errorName(code)
	if code == ErrorAuthRejected && packet.ErrorAttr == uint16(TagPassword) {
		return errNSDP("NSDP write rejected at %s: error %d (%s) -- %s", blamed, code, detail, AuthV2Unsupported)
	}
	if code == ErrorDenied || code == ErrorAuthRejected {
		return errNSDP("NSDP write rejected: bad password (error 0x%02x) at %s", code, blamed)
	}
	if code == ErrorLocked {
		return errNSDP("NSDP write locked out after repeated auth failures (error 0x%02x) at %s; "+
			"the switch goes silent for a cooldown -- pace writes and retry", code, blamed)
	}
	return errNSDP("NSDP request failed with result 0x%04x (error %d: %s) on %s", packet.Result, code, detail, blamed)
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
	// authScheme is the configured write-auth scheme: "auto" (detect via
	// AUTH_V2_ENCPASS on the first write), "v1", or "v2". Default "auto".
	// resolvedScheme caches the outcome ("v1"/"v2") after the first resolve
	// so the ENCPASS read happens at most once. Both guarded by mu.
	authScheme     string
	resolvedScheme string

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

// WithAuthScheme forces the write-auth scheme: "v1" (XOR password), "v2"
// (salted token), or "auto" (the default: detect via AUTH_V2_ENCPASS on the
// first write). Mirrors Python nsdp_udp.py's auth_scheme constructor keyword.
// An unrecognized value is treated as "auto".
func WithAuthScheme(scheme string) Option {
	return func(c *UDPClient) {
		if scheme == "v1" || scheme == "v2" {
			c.authScheme = scheme
		} else {
			c.authScheme = "auto"
		}
	}
}

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
		authScheme: "auto",
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
//
// Deliberate improvement over the pinned Python reference's deadline
// handling: Python's sock.settimeout(2s) (dossier §5.5) bounds EVERY
// recvfrom call unconditionally, regardless of how the caller got there --
// there is no concept of a caller-supplied deadline overriding it. The
// original Go port instead applied c.Timeout ONLY when ctx had no deadline
// of its own, which meant a caller-supplied ctx with a large request-scoped
// deadline (e.g. a 30s HTTP-request-lifetime ctx passed down through several
// layers) could make a single NSDP exchange block up to THAT deadline
// instead of c.Timeout -- diverging from Python, which always caps it at
// ~2s. This is resolved with min-deadline semantics: the effective read
// deadline for this exchange is min(now+c.Timeout, ctx's own deadline, if
// any) -- so the client's own Timeout always bounds a single exchange no
// matter how generous the caller's ctx is, while a SHORTER caller deadline
// (or outright cancellation) still takes effect exactly as before, since
// context.WithDeadline derives cctx from ctx and therefore still closes
// cctx.Done() the moment ctx itself is cancelled. See
// docs/cross-language-divergences.md, "Slice 05", for the divergence this
// resolves (now CLOSER to Python than before, not further from it) --
// TestUDPClient_ExchangeUsesMinOfClientTimeoutAndCtxDeadline proves a long
// caller ctx deadline no longer defeats c.Timeout.
func (c *UDPClient) exchange(ctx context.Context, req Packet) (Packet, error) {
	payload, err := req.Encode()
	if err != nil {
		return Packet{}, err
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	deadlineFromTimeout := time.Now().Add(timeout)
	effectiveDeadline := deadlineFromTimeout
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(effectiveDeadline) {
		effectiveDeadline = ctxDeadline
	}
	cctx, cancel := context.WithDeadline(ctx, effectiveDeadline)
	defer cancel()

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
	req, err := c.buildAuthWrite(ctx, tlvs, password)
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

// firstTLVValue returns the value of the first TLV in packet with tag, or nil
// if absent. Mirrors Python client.first_tlv_value.
func firstTLVValue(packet Packet, tag Tag) []byte {
	for _, t := range packet.TLVs {
		if t.Tag == tag {
			return t.Value
		}
	}
	return nil
}

// resolveScheme returns the write-auth scheme ("v1" or "v2"), detecting it via
// an AUTH_V2_ENCPASS read the FIRST time when configured "auto" and caching the
// result so at most one ENCPASS read ever happens. A forced "v1"/"v2" skips the
// read. Mirrors Python nsdp_udp.py's _resolve_scheme. The read runs without the
// lock held (it does I/O); the cache write is serialized under mu.
func (c *UDPClient) resolveScheme(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.resolvedScheme != "" {
		s := c.resolvedScheme
		c.mu.Unlock()
		return s, nil
	}
	forced := c.authScheme
	c.mu.Unlock()

	if forced == "v1" || forced == "v2" {
		c.mu.Lock()
		c.resolvedScheme = forced
		c.mu.Unlock()
		return forced, nil
	}

	resp, err := c.Read(ctx, []Tag{TagAuthV2Encpass})
	if err != nil {
		return "", err
	}
	scheme := "v1"
	if EncpassIsV2(firstTLVValue(*resp, TagAuthV2Encpass)) {
		scheme = "v2"
	}
	c.mu.Lock()
	c.resolvedScheme = scheme
	c.mu.Unlock()
	return scheme, nil
}

// buildAuthWrite builds the authenticated WRITE_REQUEST for the resolved
// scheme, mirroring Python nsdp_udp.py's _build_auth_write. For v2 it reads a
// FRESH AUTH_V2_SALT (the switch rotates it every read), folds the token
// against the salt and the switch's own MAC (the salt response's ServerMAC),
// and builds the token-FIRST v2 write; for v1 it prepends the XOR password TLV.
func (c *UDPClient) buildAuthWrite(ctx context.Context, tlvs []TLVEntry, password string) (Packet, error) {
	scheme, err := c.resolveScheme(ctx)
	if err != nil {
		return Packet{}, err
	}
	if scheme == "v2" {
		saltResp, err := c.Read(ctx, []Tag{TagAuthV2Salt})
		if err != nil {
			return Packet{}, err
		}
		salt := firstTLVValue(*saltResp, TagAuthV2Salt)
		if len(salt) == 0 {
			return Packet{}, errNSDP("switch selected NSDP v2 write auth but returned no AUTH_V2_SALT (0x0017)")
		}
		token, err := AuthV2Password(password, saltResp.ServerMAC, salt)
		if err != nil {
			return Packet{}, err
		}
		return BuildWriteRequestV2(c.ClientMAC, zeroMAC, c.nextSeq(), token, tlvs), nil
	}
	return BuildWriteRequest(c.ClientMAC, zeroMAC, c.nextSeq(), password, tlvs)
}

// Compile-time interface satisfaction checks.
var (
	_ Client      = (*UDPClient)(nil)
	_ WriteClient = (*UDPClient)(nil)
)

// realTransceive is the production transceiveFunc: one real UDP socket per
// call (mirroring Python's per-call socket lifecycle), ctx-aware via
// net.Dialer (dial itself derives its deadline from ctx, set up by exchange
// as min(now+c.Timeout, the caller's own ctx deadline, if any) -- see
// exchange's doc comment).
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
