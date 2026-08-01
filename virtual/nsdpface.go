package virtual

// nsdpface.go ports src/netgear_switch/virtual/faces/nsdp.py's
// VirtualNsdpFace (the normative source; that repo is read-only from here --
// pin 1aa1274, branch fix/s3300-52x-live-verify). Any discrepancy between
// this file and the Python source is a bug here. See D-NSDP §7.2/§10.3 for
// the full porting dossier this mirrors, and virtual/snmpface.go for the
// exact goroutine-loop shape this file is a direct sibling of.
//
// NsdpFace is a real UDP NSDP command-responder agent serving a State,
// bound to an ephemeral UDP port on 127.0.0.1 -- no root, no privileged
// 63321/63322 bind, no SO_BINDTODEVICE (unlike the real client transport in
// package nsdp). It answers READ_REQUEST from State.NsdpTlvs and applies
// WRITE_REQUEST after validating the v1 PASSWORD TLV (a mismatch responds
// with Result ResultBadPassword, exactly as real hardware does -- package
// nsdp's own client surfaces that as an error). Stop closes the socket
// deterministically so no bound port or serve goroutine survives past it.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/mithro/go-netgear-switch-library/nsdp"
)

// NsdpFace is a UDP NSDP command-responder agent serving a State. Runs its
// receive loop on a dedicated goroutine, bound to an ephemeral UDP port on
// host. Construct with NewNsdpFace; call Start to bind and begin serving,
// Stop to tear down (idempotent; safe to call before Start or more than
// once).
type NsdpFace struct {
	state *State
	host  string

	mu   sync.Mutex
	conn *net.UDPConn
	wg   sync.WaitGroup

	// saltMu guards the v2 auth challenge: saltCounter drives a deterministic
	// rotation (reproducible, no wall-clock/RNG, yet "rotates on every read"
	// like real hardware) and salt holds the last one issued on an
	// AUTH_V2_SALT read, against which the next v2 write token is validated.
	saltMu      sync.Mutex
	salt        [4]byte
	saltCounter uint32
}

// nextSalt issues a fresh 4-byte AUTH_V2_SALT and stores it for the next v2
// write's token validation. Deterministic (Knuth multiplicative hash of a
// counter), so the mock is reproducible.
func (f *NsdpFace) nextSalt() [4]byte {
	f.saltMu.Lock()
	defer f.saltMu.Unlock()
	f.saltCounter++
	binary.BigEndian.PutUint32(f.salt[:], f.saltCounter*2654435761)
	return f.salt
}

// currentSalt returns the last salt nextSalt issued -- the challenge the next
// v2 write token must fold against.
func (f *NsdpFace) currentSalt() [4]byte {
	f.saltMu.Lock()
	defer f.saltMu.Unlock()
	return f.salt
}

// NewNsdpFace builds an NsdpFace serving state, bound to host (typically
// "127.0.0.1") once Start is called. The write-auth password is read live
// from state.NsdpPassword at each WRITE_REQUEST (not captured here at
// construction), mirroring Python's _write_response reading
// self._state.nsdp_password fresh on every call -- a test that mutates
// state mid-test sees the new password take effect immediately.
func NewNsdpFace(state *State, host string) *NsdpFace {
	return &NsdpFace{state: state, host: host}
}

// Start binds an ephemeral UDP port on f.host and begins serving on a
// background goroutine, returning the bound port. Calling Start twice
// without an intervening Stop is an error.
func (f *NsdpFace) Start() (port int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		return 0, fmt.Errorf("virtual: NsdpFace.Start: already started")
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(f.host)})
	if err != nil {
		return 0, fmt.Errorf("virtual: NsdpFace.Start: listen udp on %s: %w", f.host, err)
	}
	f.conn = conn

	f.wg.Add(1)
	go f.serve(conn)

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		// Unreachable: net.ListenUDP("udp", ...) always returns a *net.UDPAddr
		// from LocalAddr().
		return 0, fmt.Errorf("virtual: NsdpFace.Start: unexpected local addr type %T", conn.LocalAddr())
	}
	return udpAddr.Port, nil
}

// Stop closes the listening socket and waits for the serve goroutine to
// exit. Idempotent: a Stop before Start, or a second Stop, is a no-op.
func (f *NsdpFace) Stop() error {
	f.mu.Lock()
	conn := f.conn
	f.conn = nil
	f.mu.Unlock()

	if conn == nil {
		return nil
	}
	err := conn.Close()
	f.wg.Wait()
	if err != nil {
		return fmt.Errorf("virtual: NsdpFace.Stop: %w", err)
	}
	return nil
}

// serve is the receive loop: decode each incoming datagram with package
// nsdp's own wire codec, dispatch, and reply in kind. A malformed packet is
// silently dropped -- no response at all, matching real hardware's
// silent-drop behavior for anything it can't parse (D-NSDP §7.2). Exits
// when conn is closed (Stop, or any other read error).
func (f *NsdpFace) serve(conn *net.UDPConn) {
	defer f.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed (Stop): stop serving
		}

		req, err := nsdp.DecodePacket(buf[:n])
		if err != nil {
			continue // malformed request datagram: ignore, as hardware does
		}

		resp, err := f.handle(req)
		if err != nil {
			continue // e.g. a non-ASCII NsdpPassword: drop, don't ever crash the loop
		}
		if resp == nil {
			continue // unrecognized op: no response, matching real hardware
		}

		out, err := resp.Encode()
		if err != nil {
			continue
		}
		_, _ = conn.WriteToUDP(out, raddr)
	}
}

// handle dispatches one decoded request packet to the matching op handler.
// Returns a nil packet (no error) for any op this mock doesn't serve
// (READ_RESPONSE/WRITE_RESPONSE echoed back by a misbehaving client) so the
// caller drops it, exactly like real hardware's silent-drop-of-unexpected-op
// behavior.
func (f *NsdpFace) handle(req nsdp.Packet) (*nsdp.Packet, error) {
	switch req.Op {
	case nsdp.OpReadRequest:
		resp := f.readResponse(req)
		return &resp, nil
	case nsdp.OpWriteRequest:
		return f.writeResponse(req)
	default:
		return nil, nil
	}
}

// readResponse answers a READ_REQUEST: the response TLVs are exactly
// State.NsdpTlvs's strict per-tag projection of whichever tags req.TLVs
// asked for -- no identity tag is added unconditionally (see NsdpTlvs's own
// doc comment).
func (f *NsdpFace) readResponse(req nsdp.Packet) nsdp.Packet {
	tags := make(map[nsdp.Tag]bool, len(req.TLVs))
	for _, t := range req.TLVs {
		tags[t.Tag] = true
	}
	resp := nsdp.Packet{
		Op:        nsdp.OpReadResponse,
		ClientMAC: req.ClientMAC,
		ServerMAC: append([]byte(nil), f.state.NsdpMac[:]...),
		Sequence:  req.Sequence,
	}
	// AUTH_V2_PASSWORD (0x001A) is write-only: a READ naming it returns error
	// 3 (read-only), live-observed on a GS110EMX (auth.py:38).
	if tags[nsdp.TagAuthV2Password] {
		resp.Result = nsdp.ResultReadOnly
		resp.ErrorAttr = uint16(nsdp.TagAuthV2Password)
		return resp
	}
	resp.TLVs = f.state.NsdpTlvs(tags)
	// AUTH_V2_ENCPASS (0x0014) advertises the write-auth scheme; AUTH_V2_SALT
	// (0x0017) is a fresh rotating challenge -- neither is a NsdpTlvs state
	// projection, so answer them here.
	if tags[nsdp.TagAuthV2Encpass] {
		scheme := byte(nsdp.EncpassV1)
		if f.state.NsdpAuthV2 {
			scheme = byte(nsdp.EncpassV2)
		}
		resp.TLVs = append(resp.TLVs, nsdp.TLVEntry{Tag: nsdp.TagAuthV2Encpass, Value: []byte{0x00, 0x00, 0x00, scheme}})
	}
	if tags[nsdp.TagAuthV2Salt] {
		salt := f.nextSalt()
		resp.TLVs = append(resp.TLVs, nsdp.TLVEntry{Tag: nsdp.TagAuthV2Salt, Value: append([]byte(nil), salt[:]...)})
	}
	return resp
}

// writeResponse answers a WRITE_REQUEST: validates the v1-XOR-encoded
// PASSWORD TLV against f.state.NsdpPassword (a plain byte-slice compare --
// deliberately NOT constant-time, since this is a loopback-only test mock,
// not a security boundary), and on success applies every non-PASSWORD TLV
// via State.ApplyNsdpWrite in order. A mismatch responds with
// nsdp.ResultBadPassword and applies nothing at all.
//
// Returns an error (dropping the whole response, per serve's doc comment)
// only if f.state.NsdpPassword itself can't be v1-XOR-encoded (a non-ASCII
// byte in it) -- mirroring Python's _write_response, where the equivalent
// encode_password_v1(self._state.nsdp_password) call is UNCAUGHT and
// propagates out through _handle into _serve's own `except ValueError:
// continue`, silently dropping the response. Every seeded NsdpPassword in
// this repo is plain ASCII, so this path is not expected to trigger in
// practice.
func (f *NsdpFace) writeResponse(req nsdp.Packet) (*nsdp.Packet, error) {
	resp := nsdp.Packet{
		Op:        nsdp.OpWriteResponse,
		ClientMAC: req.ClientMAC,
		ServerMAC: append([]byte(nil), f.state.NsdpMac[:]...),
		Sequence:  req.Sequence,
	}

	// v2 SKUs: the write MUST lead with a valid AUTH_V2_PASSWORD token folded
	// against the salt this fake last issued (CurrentNsdpSalt) and its own MAC.
	// A v1 PASSWORD offered here is error 13 blamed on PASSWORD (the
	// "v1 to v2-only firmware" wiring case); a wrong token is error 13 blamed
	// on AUTH_V2_PASSWORD; ordering it non-first is not accepted.
	if f.state.NsdpAuthV2 {
		if len(req.TLVs) == 0 || req.TLVs[0].Tag != nsdp.TagAuthV2Password {
			resp.Result = nsdp.ResultBadPasswordV2
			resp.ErrorAttr = uint16(nsdp.TagPassword)
			return &resp, nil
		}
		salt := f.currentSalt()
		expected, err := nsdp.AuthV2Password(f.state.NsdpPassword, f.state.NsdpMac[:], salt[:])
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(req.TLVs[0].Value, expected) {
			resp.Result = nsdp.ResultBadPasswordV2
			resp.ErrorAttr = uint16(nsdp.TagAuthV2Password)
			return &resp, nil
		}
		for _, t := range req.TLVs[1:] {
			f.state.ApplyNsdpWrite(t.Tag, t.Value)
		}
		resp.Result = nsdp.ResultSuccess
		return &resp, nil
	}

	// v1 SKUs: validate the XOR PASSWORD TLV.
	expected, err := nsdp.EncodePasswordV1(f.state.NsdpPassword)
	if err != nil {
		return nil, err
	}
	passwordOK := false
	for _, t := range req.TLVs {
		if t.Tag == nsdp.TagPassword && bytes.Equal(t.Value, expected) {
			passwordOK = true
			break
		}
	}
	if !passwordOK {
		resp.Result = nsdp.ResultBadPassword
		return &resp, nil
	}
	for _, t := range req.TLVs {
		if t.Tag != nsdp.TagPassword {
			f.state.ApplyNsdpWrite(t.Tag, t.Value)
		}
	}
	resp.Result = nsdp.ResultSuccess
	return &resp, nil
}
