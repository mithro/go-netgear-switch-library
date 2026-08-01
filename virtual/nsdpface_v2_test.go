package virtual

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/nsdp"
)

// TestNsdpFaceV2WriteRoundTrip is the Go-client <-> Go-fake cross-check for
// NSDP v2 salted write auth: a real UDPClient (auth_scheme "auto") auto-
// negotiates v2 against the v2 GS110EMX fake over real UDP loopback -- reading
// AUTH_V2_ENCPASS (0x10), a fresh AUTH_V2_SALT, folding the token against the
// switch MAC + salt, and sending it token-first -- and the fake applies it.
func TestNsdpFaceV2WriteRoundTrip(t *testing.T) {
	st := SeedGS110EMX() // NsdpAuthV2 == true
	port, face := startNsdpFace(t, st)
	client := nsdpTestClient(t, port) // auth_scheme "auto"
	ctx := context.Background()

	pvid, _ := nsdp.PvidTLV(1, 5)
	if _, err := client.Write(ctx, []nsdp.TLVEntry{pvid}, "password"); err != nil {
		t.Fatalf("v2 write round-trip failed: %v", err)
	}

	// A wrong password folds a wrong token -> the fake rejects error 13.
	if _, err := client.Write(ctx, []nsdp.TLVEntry{pvid}, "wrongpw"); err == nil {
		t.Fatal("wrong v2 password was accepted")
	}

	// A client FORCED to v1 against a v2-only fake gets the v2-required wiring
	// hint (not a plain bad-password), proving the CheckResult attr-blame path.
	v1c, err := nsdp.NewUDPClient("127.0.0.1",
		nsdp.WithServerPort(port), nsdp.WithClientPort(0),
		nsdp.WithClientMAC([]byte{0, 0, 0, 0, 0, 1}),
		nsdp.WithAuthScheme("v1"))
	if err != nil {
		t.Fatal(err)
	}
	_, v1err := v1c.Write(ctx, []nsdp.TLVEntry{pvid}, "password")
	if v1err == nil || !strings.Contains(v1err.Error(), "v2") {
		t.Fatalf("v1-on-v2 write: want a v2-required hint, got %v", v1err)
	}

	// Stop the face (its wg.Wait establishes a happens-before with the serve
	// goroutine that applied the write) before reading shared state directly,
	// so the successful v2 write is confirmed applied, race-free.
	if err := face.Stop(); err != nil {
		t.Fatalf("face.Stop: %v", err)
	}
	if st.Pvids[1] != 5 {
		t.Fatalf("v2 write not applied to shared state: Pvids[1] = %d, want 5", st.Pvids[1])
	}
}

// TestNsdpFaceV1WriteRoundTrip covers the fake's v1 write path (a Plus SKU,
// NsdpAuthV2 false): the client auto-detects v1 via AUTH_V2_ENCPASS=0x01 and
// sends the XOR PASSWORD write.
func TestNsdpFaceV1WriteRoundTrip(t *testing.T) {
	st := SeedGS105PE() // v1 (NsdpAuthV2 == false)
	port, face := startNsdpFace(t, st)
	client := nsdpTestClient(t, port)
	ctx := context.Background()

	pvid, _ := nsdp.PvidTLV(1, 5)
	if _, err := client.Write(ctx, []nsdp.TLVEntry{pvid}, st.NsdpPassword); err != nil {
		t.Fatalf("v1 write round-trip failed: %v", err)
	}
	if _, err := client.Write(ctx, []nsdp.TLVEntry{pvid}, "wrong-v1-pw"); err == nil {
		t.Fatal("wrong v1 password was accepted")
	}
	if err := face.Stop(); err != nil {
		t.Fatalf("face.Stop: %v", err)
	}
	if st.Pvids[1] != 5 {
		t.Fatalf("v1 write not applied: Pvids[1] = %d, want 5", st.Pvids[1])
	}
}

// TestNsdpFaceV2PasswordReadIsWriteOnly covers the readResponse write-only
// branch: a READ naming AUTH_V2_PASSWORD (0x001A) comes back with error 3
// (read-only) blamed on that tag. The client itself does not raise on a read
// result code (reads work even when writes are locked, matching the pin), so
// the caller inspects the response's Result.
func TestNsdpFaceV2PasswordReadIsWriteOnly(t *testing.T) {
	port, _ := startNsdpFace(t, SeedGS110EMX())
	client := nsdpTestClient(t, port)
	resp, err := client.Read(context.Background(), []nsdp.Tag{nsdp.TagAuthV2Password})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Result != nsdp.ResultReadOnly {
		t.Fatalf("Result = %#04x, want ResultReadOnly (%#04x)", resp.Result, nsdp.ResultReadOnly)
	}
	if resp.ErrorAttr != uint16(nsdp.TagAuthV2Password) {
		t.Fatalf("ErrorAttr = %#x, want AUTH_V2_PASSWORD (%#x)", resp.ErrorAttr, uint16(nsdp.TagAuthV2Password))
	}
}

// TestNsdpFaceV2LockoutEscalatesThenSilences mirrors the pin's
// test_face_v2_repeated_failures_escalate_then_lock: consecutive wrong v2
// tokens come back "bad password" (error 13), then escalate to "locked out"
// (error 14), then the switch goes SILENT (no reply -> the client's write-
// response read times out). A short client timeout keeps the silent phase fast.
func TestNsdpFaceV2LockoutEscalatesThenSilences(t *testing.T) {
	port, _ := startNsdpFace(t, SeedGS110EMX())
	client, err := nsdp.NewUDPClient("127.0.0.1",
		nsdp.WithServerPort(port), nsdp.WithClientPort(0),
		nsdp.WithClientMAC([]byte{0, 0, 0, 0, 0, 1}),
		nsdp.WithTimeout(400*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pvid, _ := nsdp.PvidTLV(1, 5)

	var sawBad, sawLocked, sawSilent bool
	for i := 0; i < 10; i++ {
		_, werr := client.Write(ctx, []nsdp.TLVEntry{pvid}, "wrong")
		if werr == nil {
			t.Fatalf("write %d with wrong password unexpectedly succeeded", i)
		}
		switch msg := werr.Error(); {
		case strings.Contains(msg, "bad password"):
			sawBad = true
		case strings.Contains(msg, "locked"):
			sawLocked = true
		default: // no reply -> read-deadline timeout: the silent lockout phase
			sawSilent = true
		}
		if sawSilent {
			break
		}
	}
	if !sawBad || !sawLocked || !sawSilent {
		t.Fatalf("v2 lockout escalation: sawBad=%v sawLocked=%v sawSilent=%v (want all true)",
			sawBad, sawLocked, sawSilent)
	}
}

// TestNsdpFaceV2LockoutCounterResetsAfterSuccess mirrors the pin's
// test_face_lockout_counter_resets_after_success: three wrong tokens (below
// the escalate threshold, so still "bad password") followed by one correct
// write, which succeeds and clears the failure counter back to zero.
func TestNsdpFaceV2LockoutCounterResetsAfterSuccess(t *testing.T) {
	st := SeedGS110EMX()
	port, face := startNsdpFace(t, st)
	client := nsdpTestClient(t, port)
	ctx := context.Background()
	pvid, _ := nsdp.PvidTLV(1, 5)

	for i := 0; i < 3; i++ {
		if _, err := client.Write(ctx, []nsdp.TLVEntry{pvid}, "wrong"); err == nil {
			t.Fatalf("wrong-password write %d unexpectedly succeeded", i)
		}
	}
	if _, err := client.Write(ctx, []nsdp.TLVEntry{pvid}, st.NsdpPassword); err != nil {
		t.Fatalf("correct write after 3 failures: %v", err)
	}

	// Stop the face (wg.Wait establishes happens-before with the serve
	// goroutine that owns authFailures) before reading the counter race-free.
	if err := face.Stop(); err != nil {
		t.Fatalf("face.Stop: %v", err)
	}
	if face.authFailures != 0 {
		t.Fatalf("authFailures = %d after a successful write, want 0 (counter did not reset)", face.authFailures)
	}
}
