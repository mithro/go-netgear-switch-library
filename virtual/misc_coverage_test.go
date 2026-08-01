package virtual

// misc_coverage_test.go: direct unit tests for small package functions and
// options exercised only through full protocol round-trips elsewhere -- real
// assertions on real behavior, not coverage theater.

import (
	"strconv"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestFromWireValue_AllTypes(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want any
	}{
		{"int", 7, 7},
		{"int8", int8(8), 8},
		{"int16", int16(16), 16},
		{"int32", int32(32), 32},
		{"int64", int64(64), 64},
		{"uint", uint(1), 1},
		{"uint8", uint8(2), 2},
		{"uint16", uint16(3), 3},
		{"uint32", uint32(4), 4},
		{"uint64", uint64(5), 5},
		{"string", "hi", "hi"},
	}
	for _, c := range cases {
		if got := fromWireValue(gosnmp.SnmpPDU{Value: c.in}); got != c.want {
			t.Errorf("fromWireValue(%s=%v) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
	// []byte returns the slice as-is.
	b := []byte{0xde, 0xad}
	if got, ok := fromWireValue(gosnmp.SnmpPDU{Value: b}).([]byte); !ok || len(got) != 2 {
		t.Errorf("fromWireValue([]byte) = %v, want the byte slice", got)
	}
	// An unhandled type falls through to fmt.Sprint.
	if got := fromWireValue(gosnmp.SnmpPDU{Value: 3.5}); got != "3.5" {
		t.Errorf("fromWireValue(float) = %v, want \"3.5\"", got)
	}
}

func TestHTTPFaceApplyPoE(t *testing.T) {
	st := SeedGSM7252PS()
	// applyPoE addresses state.Poe[portID+1]; find a seeded PoE port.
	var portZeroBased int = -1
	for p := range st.Poe {
		portZeroBased = p - 1
		break
	}
	if portZeroBased < 0 {
		t.Skip("no PoE ports seeded")
	}
	f := &HTTPFace{state: st}
	f.applyPoE(map[string]string{"ACTION": "Apply", "portID": strconv.Itoa(portZeroBased), "ADMIN_MODE": "0"})
	if st.Poe[portZeroBased+1].Admin {
		t.Fatalf("applyPoE Apply/ADMIN_MODE=0 did not disable PoE admin")
	}
	f.applyPoE(map[string]string{"ACTION": "Apply", "portID": strconv.Itoa(portZeroBased), "ADMIN_MODE": "1"})
	if !st.Poe[portZeroBased+1].Admin {
		t.Fatalf("applyPoE Apply/ADMIN_MODE=1 did not enable PoE admin")
	}
	// Malformed forms: no panic, no change.
	f.applyPoE(map[string]string{"ACTION": "Apply"})                // missing portID
	f.applyPoE(map[string]string{"ACTION": "Apply", "portID": "x"}) // non-numeric
	f.applyPoE(map[string]string{"ACTION": "Nonsense"})             // unknown action
}

func TestVirtualSwitchWithHTTPPasswordOption(t *testing.T) {
	vsw, err := NewVirtualSwitch("gs305ep", WithHTTPPassword("secret"), WithHost("127.0.0.1"))
	if err != nil {
		t.Fatalf("NewVirtualSwitch: %v", err)
	}
	if vsw.Host != "127.0.0.1" {
		t.Fatalf("WithHost not applied: %q", vsw.Host)
	}
}
