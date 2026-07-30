package virtual

// Tests for NsdpFace, driven over real UDP against package nsdp's own
// UDPClient. Mirrors tests/virtual/test_virtual_nsdp_face.py's intents
// (D-NSDP §9.4: read returns seeded ports, an authenticated write is
// durably read back, a wrong password is rejected) plus this repo's own
// malformed-drop/leak-cycle conventions already pinned for SnmpFace
// (snmpface_test.go) -- NsdpFace is a direct sibling of SnmpFace; see
// nsdpface.go's own doc comment for the shared shape.

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
)

// startNsdpFace starts an NsdpFace over st on 127.0.0.1, registering
// t.Cleanup to stop it, and returns its bound port.
func startNsdpFace(t *testing.T, st *State) (port int, face *NsdpFace) {
	t.Helper()
	face = NewNsdpFace(st, "127.0.0.1")
	port, err := face.Start()
	if err != nil {
		t.Fatalf("NsdpFace.Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := face.Stop(); err != nil {
			t.Errorf("NsdpFace.Stop() error = %v", err)
		}
	})
	return port, face
}

// nsdpTestClient builds a UDPClient talking to a face bound on port, with a
// fixed dummy ClientMAC and an ephemeral local port (test-friendly: no root,
// no fixed port collision across parallel test runs).
func nsdpTestClient(t *testing.T, port int) *nsdp.UDPClient {
	t.Helper()
	c, err := nsdp.NewUDPClient("127.0.0.1",
		nsdp.WithServerPort(port),
		nsdp.WithClientPort(0),
		nsdp.WithClientMAC([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
		nsdp.WithTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("nsdp.NewUDPClient: %v", err)
	}
	return c
}

// -- Read/write intent (test_virtual_nsdp_face.py) --------------------------

func TestNsdpFaceReadReturnsSeedPorts(t *testing.T) {
	port, _ := startNsdpFace(t, SeedGS110EMX())
	client := nsdpTestClient(t, port)

	pkt, err := client.Read(context.Background(), []nsdp.Tag{nsdp.TagModel, nsdp.TagPortCount, nsdp.TagPortStatus})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	dev, err := nsdp.ParseDevice(*pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.Model != "GS110EMX" {
		t.Errorf("Model = %q, want GS110EMX", dev.Model)
	}

	gotPorts := map[int]bool{}
	for _, p := range dev.PortStatus {
		gotPorts[p.PortID] = true
	}
	if len(gotPorts) != 10 {
		t.Errorf("len(PortStatus) = %d, want 10", len(gotPorts))
	}
	for want := 1; want <= 10; want++ {
		if !gotPorts[want] {
			t.Errorf("PortStatus missing port %d", want)
		}
	}
}

func TestNsdpFaceAuthenticatedWriteIsReadBack(t *testing.T) {
	port, _ := startNsdpFace(t, SeedGS110EMX())
	client := nsdpTestClient(t, port)

	pvidTLV, err := nsdp.PvidTLV(5, 90)
	if err != nil {
		t.Fatalf("PvidTLV: %v", err)
	}
	if _, err := client.Write(context.Background(), []nsdp.TLVEntry{pvidTLV}, "password"); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// MODEL must be requested explicitly: the face (like real hardware)
	// answers with only the requested tags, and ParseDevice requires a
	// MODEL tag to be present at all.
	pkt, err := client.Read(context.Background(), []nsdp.Tag{nsdp.TagModel, nsdp.TagPortPVID})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	dev, err := nsdp.ParseDevice(*pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	found := false
	for _, p := range dev.PortPvids {
		if p.PortID == 5 && p.VlanID == 90 {
			found = true
		}
	}
	if !found {
		t.Errorf("PortPvids = %+v, want (port=5, vlan=90) among them", dev.PortPvids)
	}
}

func TestNsdpFaceWrongPasswordReturnsBadPassword(t *testing.T) {
	port, _ := startNsdpFace(t, SeedGS110EMX())
	client := nsdpTestClient(t, port)

	pvidTLV, err := nsdp.PvidTLV(5, 90)
	if err != nil {
		t.Fatalf("PvidTLV: %v", err)
	}
	_, err = client.Write(context.Background(), []nsdp.TLVEntry{pvidTLV}, "wrong-password")
	if err == nil {
		t.Fatal("Write with wrong password error = nil, want an error mentioning bad password")
	}
	if !errors.Is(err, model.ErrNSDP) {
		t.Errorf("Write error = %v, want wrapping model.ErrNSDP", err)
	}
	if !strings.Contains(err.Error(), "bad password") {
		t.Errorf("Write error = %q, want it to mention bad password", err.Error())
	}
}

// TestNsdpFaceWriteAppliesNothingOnAuthFailure proves the auth-failure path
// applies zero write TLVs (D-NSDP §7.2: "no state mutation, no TLVs
// applied" on a bad password), not just that it responds with an error --
// a face that validated auth but still silently applied the TLVs anyway
// would still fail Write's own CheckResult check, so a dedicated read-back
// assertion is needed to catch that class of bug.
func TestNsdpFaceWriteAppliesNothingOnAuthFailure(t *testing.T) {
	st := SeedGS110EMX()
	port, _ := startNsdpFace(t, st)
	client := nsdpTestClient(t, port)

	pvidTLV, err := nsdp.PvidTLV(1, 42)
	if err != nil {
		t.Fatalf("PvidTLV: %v", err)
	}
	if _, err := client.Write(context.Background(), []nsdp.TLVEntry{pvidTLV}, "wrong-password"); err == nil {
		t.Fatal("Write with wrong password succeeded, want an error")
	}

	pkt, err := client.Read(context.Background(), []nsdp.Tag{nsdp.TagModel, nsdp.TagPortPVID})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	dev, err := nsdp.ParseDevice(*pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	for _, p := range dev.PortPvids {
		if p.PortID == 1 && p.VlanID == 42 {
			t.Error("PVID 42 was applied despite the wrong password -- auth failure must apply nothing")
		}
	}
}

// -- Malformed input / lifecycle (mirrors snmpface_test.go's conventions) --

// TestNsdpFaceDropsMalformedPacket mirrors
// TestSnmpFaceDropsMalformedPacket: a garbage datagram gets no response at
// all (silently dropped, not an error reply), and the serve loop survives
// to answer a subsequent well-formed request.
func TestNsdpFaceDropsMalformedPacket(t *testing.T) {
	port, _ := startNsdpFace(t, SeedGS110EMX())

	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer func() { _ = conn.Close() }()

	garbage := []byte{0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03}
	if _, err := conn.Write(garbage); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1024)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("got a response to malformed input (%d bytes), want no response (silently dropped)", n)
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("Read after malformed packet error = %v, want a read-deadline timeout (no response was sent)", err)
		}
	}

	// The serve loop must still be alive and answering correctly afterward
	// -- one malformed datagram must not derail it.
	client := nsdpTestClient(t, port)
	if _, err := client.Read(context.Background(), []nsdp.Tag{nsdp.TagModel}); err != nil {
		t.Fatalf("Read after malformed packet error = %v, want the face to still be serving", err)
	}
}

// TestNsdpFaceStartStopCyclesLeakNoGoroutinesOrFDs mirrors
// TestSnmpFaceStartStopCyclesLeakNoGoroutinesOrFDs exactly (same 10-cycle,
// extra-idempotent-Stop, goroutine+FD baseline pattern), reusing that
// test's own countOpenFDs helper (same package).
func TestNsdpFaceStartStopCyclesLeakNoGoroutinesOrFDs(t *testing.T) {
	st := SeedGS110EMX()
	beforeGoroutines := runtime.NumGoroutine()
	beforeFDs, haveFDs := countOpenFDs(t)

	for i := 0; i < 10; i++ {
		face := NewNsdpFace(st, "127.0.0.1")
		port, err := face.Start()
		if err != nil {
			t.Fatalf("cycle %d: Start() error = %v", i, err)
		}
		if port == 0 {
			t.Fatalf("cycle %d: Start() returned port 0", i)
		}
		if err := face.Stop(); err != nil {
			t.Fatalf("cycle %d: Stop() error = %v", i, err)
		}
		// A second Stop must be a harmless no-op (idempotent).
		if err := face.Stop(); err != nil {
			t.Fatalf("cycle %d: second Stop() error = %v", i, err)
		}
	}

	// Let any just-exited goroutines actually finish unwinding.
	for i := 0; i < 50; i++ {
		if runtime.NumGoroutine() <= beforeGoroutines {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > beforeGoroutines {
		t.Errorf("goroutine count after 10 start/stop cycles = %d, want <= %d (baseline)", after, beforeGoroutines)
	}

	if haveFDs {
		if afterFDs, ok := countOpenFDs(t); ok && afterFDs > beforeFDs {
			t.Errorf("open FD count after 10 start/stop cycles = %d, want <= %d (baseline; every UDP socket must be released)", afterFDs, beforeFDs)
		}
	}
}

func TestNsdpFaceStopBeforeStartIsNoOp(t *testing.T) {
	face := NewNsdpFace(SeedGS110EMX(), "127.0.0.1")
	if err := face.Stop(); err != nil {
		t.Errorf("Stop() before Start() error = %v, want nil (no-op)", err)
	}
}
