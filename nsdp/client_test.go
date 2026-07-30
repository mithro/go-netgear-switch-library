package nsdp

// Ported field-for-field (in spirit; the fake seam differs by language --
// see transceiveFunc's doc comment) from tests/transport/test_nsdp_udp_sync.py
// at pin 1aa1274 in python-netgear-switch-library (frozen snapshot worktree
// go-port-pin-1aa1274). Internal (package nsdp, not nsdp_test) so tests can
// inject the unexported transceiveFunc seam via withTransceiver, mirroring
// write_internal_test.go's precedent for whitebox-only members.

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
)

var clientTestMAC = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

// responsePacket builds a canned response datagram, mirroring the Python
// test helper _response_packet.
func responsePacket(t *testing.T, op Op, result uint16) []byte {
	t.Helper()
	pkt := Packet{Op: op, ClientMAC: clientTestMAC, ServerMAC: bytesRepeat(0xaa, 6), Result: result}
	pkt.AddTLV(TagModel, []byte("GS110EMX"))
	data, err := pkt.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return data
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// fakeExchange records the payload sent to it and returns a scripted
// response (or error), standing in for a real UDP socket. Mirrors the
// Python test suite's _FakeSocket / _fake_transceive.
type fakeExchange struct {
	response []byte
	err      error
	sent     [][]byte
	hosts    []string
}

func (f *fakeExchange) transceive(_ context.Context, payload []byte, host string, _, _ int, _ string) ([]byte, error) {
	f.sent = append(f.sent, payload)
	f.hosts = append(f.hosts, host)
	if f.err != nil {
		return nil, f.err
	}
	return f.response, nil
}

func newTestClient(t *testing.T, fx *fakeExchange) *UDPClient {
	t.Helper()
	c, err := NewUDPClient("127.0.0.1", WithClientMAC(clientTestMAC), withTransceiver(fx.transceive))
	if err != nil {
		t.Fatalf("NewUDPClient: %v", err)
	}
	return c
}

func TestUDPClient_ReadSendsReadRequestAndDecodesResponse(t *testing.T) {
	fx := &fakeExchange{response: responsePacket(t, OpReadResponse, ResultSuccess)}
	c := newTestClient(t, fx)

	pkt, err := c.Read(context.Background(), []Tag{TagModel, TagPortStatus})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if pkt.Op != OpReadResponse {
		t.Errorf("Op = %v, want OpReadResponse", pkt.Op)
	}
	if string(pkt.TLVs[0].Value) != "GS110EMX" {
		t.Errorf("TLVs[0].Value = %q, want %q", pkt.TLVs[0].Value, "GS110EMX")
	}

	if len(fx.sent) != 1 {
		t.Fatalf("sent %d requests, want 1", len(fx.sent))
	}
	if fx.hosts[0] != "127.0.0.1" {
		t.Errorf("host = %q, want unicast to 127.0.0.1", fx.hosts[0])
	}
	req, err := DecodePacket(fx.sent[0])
	if err != nil {
		t.Fatalf("DecodePacket(sent): %v", err)
	}
	if req.Op != OpReadRequest {
		t.Errorf("sent Op = %v, want OpReadRequest", req.Op)
	}
	if len(req.TLVs) != 2 || req.TLVs[0].Tag != TagModel || req.TLVs[1].Tag != TagPortStatus {
		t.Errorf("sent TLVs = %+v, want [TagModel, TagPortStatus]", req.TLVs)
	}
	if req.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1 (pre-increment from 0)", req.Sequence)
	}
}

func TestUDPClient_ReadMalformedResponseRaisesNsdpError(t *testing.T) {
	fx := &fakeExchange{response: []byte("not-nsdp-bytes")}
	c := newTestClient(t, fx)

	_, err := c.Read(context.Background(), []Tag{TagModel})
	wantSubstr(t, err, "malformed")
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("errors.Is(err, model.ErrNSDP) = false, want true")
	}
}

func TestUDPClient_ReadWrongOpRaisesNsdpError(t *testing.T) {
	// A stray WRITE_RESPONSE must not be accepted as a valid read reply.
	fx := &fakeExchange{response: responsePacket(t, OpWriteResponse, ResultSuccess)}
	c := newTestClient(t, fx)

	_, err := c.Read(context.Background(), []Tag{TagModel})
	wantSubstr(t, err, "expected READ_RESPONSE")
}

func TestUDPClient_ReadPropagatesTransportErrorsUnwrapped(t *testing.T) {
	// ANY transceive failure -- bind/send/recv, timeout or not -- must
	// propagate exactly as the transceiveFunc returned it: exchange() no
	// longer inspects/wraps transceive errors at all (that translation, for
	// the one case Python special-cases -- a real recv timeout -- lives
	// inside realTransceive itself; see TestRealTransceive_*). A fake
	// transceiver returning a plain sentinel error must therefore come back
	// out of Read completely unwrapped: not matching model.ErrNSDP.
	sentinel := errors.New("bind: address already in use")
	fx := &fakeExchange{err: sentinel}
	c := newTestClient(t, fx)

	_, err := c.Read(context.Background(), []Tag{TagModel})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want to wrap %v unwrapped", err, sentinel)
	}
	if errors.Is(err, model.ErrNSDP) {
		t.Errorf("err = %v, want it NOT to wrap model.ErrNSDP (dial/send/recv errors from the transceiver propagate raw)", err)
	}
}

func TestUDPClient_WriteSendsWriteRequestWithPasswordAndChecksResult(t *testing.T) {
	fx := &fakeExchange{response: responsePacket(t, OpWriteResponse, ResultSuccess)}
	c := newTestClient(t, fx)

	pvid, err := PvidTLV(1, 90)
	if err != nil {
		t.Fatalf("PvidTLV: %v", err)
	}
	pkt, err := c.Write(context.Background(), []TLVEntry{pvid}, "admin")
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if pkt.Op != OpWriteResponse {
		t.Errorf("Op = %v, want OpWriteResponse", pkt.Op)
	}

	req, err := DecodePacket(fx.sent[0])
	if err != nil {
		t.Fatalf("DecodePacket(sent): %v", err)
	}
	if req.Op != OpWriteRequest {
		t.Errorf("sent Op = %v, want OpWriteRequest", req.Op)
	}
	if len(req.TLVs) == 0 || req.TLVs[0].Tag != TagPassword {
		t.Errorf("sent TLVs[0].Tag = %+v, want TagPassword first", req.TLVs)
	}
}

func TestUDPClient_WriteBadPasswordRaisesNsdpError(t *testing.T) {
	fx := &fakeExchange{response: responsePacket(t, OpWriteResponse, ResultBadPassword)}
	c := newTestClient(t, fx)

	pvid, _ := PvidTLV(1, 90)
	_, err := c.Write(context.Background(), []TLVEntry{pvid}, "wrong")
	wantSubstr(t, err, "bad password")
	wantSubstr(t, err, AuthV2Unsupported)
}

func TestUDPClient_WriteWrongOpResponseRaisesNsdpError(t *testing.T) {
	// A stray READ_RESPONSE with result=0 must NOT pass as a successful
	// write -- proves the op-check runs BEFORE CheckResult (dossier §5.9).
	fx := &fakeExchange{response: responsePacket(t, OpReadResponse, ResultSuccess)}
	c := newTestClient(t, fx)

	pvid, _ := PvidTLV(1, 90)
	_, err := c.Write(context.Background(), []TLVEntry{pvid}, "admin")
	wantSubstr(t, err, "expected WRITE_RESPONSE")
}

func TestUDPClient_SequenceIncrementsAndWrapsAt0xFFFF(t *testing.T) {
	fx := &fakeExchange{response: responsePacket(t, OpReadResponse, ResultSuccess)}
	c := newTestClient(t, fx)
	c.sequence = 0xFFFF // force the wraparound edge

	if _, err := c.Read(context.Background(), []Tag{TagModel}); err != nil {
		t.Fatalf("Read: %v", err)
	}
	req, err := DecodePacket(fx.sent[0])
	if err != nil {
		t.Fatalf("DecodePacket(sent): %v", err)
	}
	if req.Sequence != 0 {
		t.Errorf("Sequence = %d, want 0 (wrapped from 0xFFFF)", req.Sequence)
	}
}

func TestCheckResult(t *testing.T) {
	tests := []struct {
		name       string
		result     uint16
		wantErr    bool
		wantSubstr string
	}{
		{name: "success is silent", result: ResultSuccess, wantErr: false},
		{name: "bad password", result: ResultBadPassword, wantErr: true, wantSubstr: "bad password"},
		{name: "generic failure formats hex", result: 0x1234, wantErr: true, wantSubstr: "0x1234"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckResult(Packet{Op: OpWriteResponse, Result: tt.result})
			if tt.wantErr {
				wantSubstr(t, err, tt.wantSubstr)
				if !errors.Is(err, model.ErrNSDP) {
					t.Errorf("errors.Is(err, model.ErrNSDP) = false, want true")
				}
			} else if err != nil {
				t.Errorf("CheckResult = %v, want nil", err)
			}
		})
	}
}

func TestNewUDPClient_DefaultsAndDummyMAC(t *testing.T) {
	c, err := NewUDPClient("10.1.5.25")
	if err != nil {
		t.Fatalf("NewUDPClient: %v", err)
	}
	if c.ClientPort != DefaultClientPort {
		t.Errorf("ClientPort = %d, want %d", c.ClientPort, DefaultClientPort)
	}
	if c.ServerPort != DefaultServerPort {
		t.Errorf("ServerPort = %d, want %d", c.ServerPort, DefaultServerPort)
	}
	if c.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", c.Timeout, DefaultTimeout)
	}
	if string(c.ClientMAC) != string(dummyClientMAC) {
		t.Errorf("ClientMAC = %x, want dummy %x", c.ClientMAC, dummyClientMAC)
	}
}

func TestNewUDPClient_ExplicitClientMACWinsOverInterface(t *testing.T) {
	explicit := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	// "lo" exists on essentially every Linux host; if the explicit MAC did
	// NOT win, NewUDPClient would instead try to read lo's real MAC
	// (00:00:00:00:00:00) and this assertion would fail.
	c, err := NewUDPClient("127.0.0.1", WithClientMAC(explicit), WithInterface("lo"))
	if err != nil {
		t.Fatalf("NewUDPClient: %v", err)
	}
	if string(c.ClientMAC) != string(explicit) {
		t.Errorf("ClientMAC = %x, want explicit %x (must win over interface)", c.ClientMAC, explicit)
	}
}

func TestNewUDPClient_InterfaceReadFailurePropagates(t *testing.T) {
	_, err := NewUDPClient("127.0.0.1", WithInterface("nsdp-test-nonexistent-iface"))
	if err == nil {
		t.Fatal("NewUDPClient with a nonexistent interface: want error, got nil")
	}
	// Not silently falling back to the dummy MAC (dossier §5.7): the error
	// from the failed sysfs read must actually surface.
}

func TestReadInterfaceMAC_Loopback(t *testing.T) {
	mac, err := ReadInterfaceMAC("lo")
	if err != nil {
		t.Skipf("ReadInterfaceMAC(lo): %v (no /sys/class/net/lo on this host)", err)
	}
	if len(mac) != 6 {
		t.Errorf("len(mac) = %d, want 6", len(mac))
	}
}

func TestReadInterfaceMAC_MissingInterfacePropagatesRaw(t *testing.T) {
	_, err := ReadInterfaceMAC("nsdp-test-nonexistent-iface")
	if err == nil {
		t.Fatal("want error for a nonexistent interface")
	}
	if errors.Is(err, model.ErrNSDP) {
		t.Errorf("err = %v, want it NOT to wrap model.ErrNSDP (mirrors Python's Path.read_text() propagating its own raw exception type unwrapped)", err)
	}
}

// TestErrNSDPCause_PreservesCauseAndSentinel directly proves errNSDPCause's
// Go 1.20+ multi-%w mechanism actually does what its doc comment claims:
// both the library-wide model.ErrNSDP sentinel AND the original cause must
// be independently reachable via errors.Is. This is the deterministic,
// identity-based proof that a review nit flagged as missing when the wrap
// path only had indirect (message-substring) coverage.
func TestErrNSDPCause_PreservesCauseAndSentinel(t *testing.T) {
	cause := errors.New("boom")
	err := errNSDPCause(cause, "context %s", "info")

	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("errors.Is(err, model.ErrNSDP) = false, want true")
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(err, cause) = false, want true -- the cause must survive in the error chain")
	}
	wantSubstr(t, err, "context info")
}

// TestRealTransceive_RecvTimeoutWrapsErrNSDPWithCause exercises the ACTUAL
// production recv-timeout path (realTransceive itself, called directly, no
// fake): a real UDP server binds and drains every datagram it receives but
// never replies, so the client's conn.Read genuinely times out (as opposed
// to an immediate ECONNREFUSED, which loopback UDP can otherwise deliver
// near-instantly for a CLOSED port -- this is why the test needs a real,
// listening-but-silent server rather than just an unused port number).
//
// This is the direct, non-fake proof that dossier §5.10's exact message
// ("NSDP request to %s timed out") is produced, model.ErrNSDP is reachable,
// AND the real net.Error (satisfying Timeout()==true) survives as the cause
// -- closing the review's "untested cause" gap for the one call site a fake
// can't exercise (the fake seam bypasses realTransceive entirely).
func TestRealTransceive_RecvTimeoutWrapsErrNSDPWithCause(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer func() { _ = serverConn.Close() }()
	serverPort := serverConn.LocalAddr().(*net.UDPAddr).Port

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, recvBufferSize)
		_, _, _ = serverConn.ReadFromUDP(buf) // read it, but never reply
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = realTransceive(ctx, []byte("probe"), "127.0.0.1", serverPort, 0, "")
	if err == nil {
		t.Fatal("realTransceive: want a recv-timeout error, got nil")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("errors.Is(err, model.ErrNSDP) = false, want true: %v", err)
	}
	wantSubstr(t, err, "timed out")

	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("errors.As(err, &netErr) found a Timeout()==true net.Error = false, want true (the original cause must be reachable): %v", err)
	}

	<-drained
}

// wantSubstr fails t if err is nil or its message doesn't contain substr.
func wantSubstr(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("err = nil, want an error containing %q", substr)
	}
	if !contains(err.Error(), substr) {
		t.Errorf("err = %q, want it to contain %q", err.Error(), substr)
	}
}

func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// --- Real loopback round-trip: no fake, a genuine UDP socket on each side. ---

func TestUDPClient_RealLoopbackRoundTrip(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer func() { _ = serverConn.Close() }()
	serverPort := serverConn.LocalAddr().(*net.UDPAddr).Port

	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, recvBufferSize)
		_ = serverConn.SetDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			serverDone <- err
			return
		}
		req, err := DecodePacket(buf[:n])
		if err != nil {
			serverDone <- err
			return
		}
		if req.Op != OpReadRequest {
			serverDone <- errUnexpectedOp(req.Op)
			return
		}
		resp := Packet{
			Op:        OpReadResponse,
			ClientMAC: req.ClientMAC,
			ServerMAC: make([]byte, 6),
			Sequence:  req.Sequence,
		}
		resp.AddTLV(TagModel, []byte("GS110EMX"))
		data, err := resp.Encode()
		if err != nil {
			serverDone <- err
			return
		}
		if _, err := serverConn.WriteToUDP(data, addr); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	// interface="lo" exercises the real best-effort SO_BINDTODEVICE path
	// (dossier §5.3) end-to-end: whether or not this sandbox has
	// CAP_NET_RAW, the read below must still succeed either way.
	client, err := NewUDPClient("127.0.0.1",
		WithClientPort(0),
		WithServerPort(serverPort),
		WithClientMAC(clientTestMAC),
		WithInterface("lo"),
		WithTimeout(3*time.Second),
	)
	if err != nil {
		t.Fatalf("NewUDPClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pkt, err := client.Read(ctx, []Tag{TagModel})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if pkt.Op != OpReadResponse {
		t.Errorf("Op = %v, want OpReadResponse", pkt.Op)
	}
	if len(pkt.TLVs) != 1 || string(pkt.TLVs[0].Value) != "GS110EMX" {
		t.Errorf("TLVs = %+v, want [MODEL=GS110EMX]", pkt.TLVs)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

type errUnexpectedOp Op

func (e errUnexpectedOp) Error() string { return "unexpected op: " + Op(e).String() }
