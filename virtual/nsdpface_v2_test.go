package virtual

import (
	"context"
	"strings"
	"testing"

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
