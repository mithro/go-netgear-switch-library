package snmp

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mithro/go-netgear-switch-library/model"
)

// Mirrors tests/protocols/snmp/test_write_encode.py's intents (Python
// reference pinned at b26eb1f).

func TestEncodePortBitmapIsInverseOfDecode(t *testing.T) {
	ports := []int{1, 8, 9, 52}
	got := DecodePortBitmap(EncodePortBitmap(ports, 8))
	if diff := cmp.Diff(ports, got); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestEncodeDecodeLargePortSetGrowsPastWidth(t *testing.T) {
	// >64-port switches require buffer growth past the default width.
	ports := []int{1, 65, 100}
	encoded := EncodePortBitmap(ports, 8)
	if diff := cmp.Diff(ports, DecodePortBitmap(encoded)); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
	if len(encoded) <= 8 {
		t.Errorf("len(encoded) = %d, want > 8 (buffer must grow for port 100)", len(encoded))
	}
}

func TestSetPortBitOnlyChangesTargetBit(t *testing.T) {
	base := EncodePortBitmap([]int{1, 2, 10, 48}, 8) // a "trunk" set
	added := SetPortBit(base, 25, true)
	if diff := cmp.Diff([]int{1, 2, 10, 25, 48}, DecodePortBitmap(added)); diff != "" {
		t.Errorf("added mismatch (-want +got):\n%s", diff)
	}
	removed := SetPortBit(base, 10, false)
	if diff := cmp.Diff([]int{1, 2, 48}, DecodePortBitmap(removed)); diff != "" {
		t.Errorf("removed mismatch (-want +got):\n%s", diff)
	}
	// base itself must be untouched (no aliasing).
	if diff := cmp.Diff([]int{1, 2, 10, 48}, DecodePortBitmap(base)); diff != "" {
		t.Errorf("base mutated by SetPortBit (-want +got):\n%s", diff)
	}
}

func TestSetPortBitPreservesWidth(t *testing.T) {
	// A 16-byte input stays 16 bytes.
	bitmap16 := EncodePortBitmap([]int{1}, 16)
	if len(bitmap16) != 16 {
		t.Fatalf("len(bitmap16) = %d, want 16", len(bitmap16))
	}
	result := SetPortBit(bitmap16, 2, true)
	if len(result) != 16 {
		t.Errorf("len(result) = %d, want 16", len(result))
	}
	if diff := cmp.Diff([]int{1, 2}, DecodePortBitmap(result)); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}

	// An 8-byte input stays at least 8 bytes.
	bitmap8 := EncodePortBitmap([]int{1}, 8)
	result = SetPortBit(bitmap8, 2, true)
	if len(result) < 8 {
		t.Errorf("len(result) = %d, want >= 8", len(result))
	}
	if diff := cmp.Diff([]int{1, 2}, DecodePortBitmap(result)); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestSetPortBitWidensToRequestedWidthBytes(t *testing.T) {
	base := EncodePortBitmap([]int{1}, 8)
	result := SetPortBit(base, 2, true, 12)
	if len(result) != 12 {
		t.Errorf("len(result) = %d, want 12", len(result))
	}
	if diff := cmp.Diff([]int{1, 2}, DecodePortBitmap(result)); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestSetPortBitWidthNeverNarrowsBelowInputOr8(t *testing.T) {
	// The result is max(8, input width, requested width) -- never narrower
	// than what was read, and never narrower than the requested width.
	wide := EncodePortBitmap([]int{1}, 16)
	result := SetPortBit(wide, 2, true, 12)
	if len(result) != 16 {
		t.Errorf("len(result) = %d, want 16 (wider input wins over the smaller requested width)", len(result))
	}

	narrow := EncodePortBitmap([]int{1}, 8)
	result = SetPortBit(narrow, 2, true)
	if len(result) != 8 {
		t.Errorf("len(result) = %d, want 8 (no requested width stays at the 8-byte default)", len(result))
	}
}

func TestMembershipBitmapsUntaggedTaggedExcluded(t *testing.T) {
	egress := EncodePortBitmap([]int{1, 2}, 8)
	untagged := EncodePortBitmap([]int{1}, 8)

	// UNTAGGED: port in egress AND untagged.
	e, u := MembershipBitmaps(egress, untagged, 5, model.VlanUntagged, 0)
	if diff := cmp.Diff([]int{1, 2, 5}, DecodePortBitmap(e)); diff != "" {
		t.Errorf("untagged egress mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]int{1, 5}, DecodePortBitmap(u)); diff != "" {
		t.Errorf("untagged untagged-col mismatch (-want +got):\n%s", diff)
	}

	// TAGGED: port in egress, NOT untagged.
	e, u = MembershipBitmaps(egress, untagged, 1, model.VlanTagged, 0)
	if diff := cmp.Diff([]int{1, 2}, DecodePortBitmap(e)); diff != "" {
		t.Errorf("tagged egress mismatch (-want +got):\n%s", diff)
	}
	if len(DecodePortBitmap(u)) != 0 {
		t.Errorf("tagged untagged-col = %v, want empty", DecodePortBitmap(u))
	}

	// EXCLUDED: port in neither; other ports preserved.
	e, u = MembershipBitmaps(egress, untagged, 1, model.VlanExcluded, 0)
	if diff := cmp.Diff([]int{2}, DecodePortBitmap(e)); diff != "" {
		t.Errorf("excluded egress mismatch (-want +got):\n%s", diff)
	}
	if len(DecodePortBitmap(u)) != 0 {
		t.Errorf("excluded untagged-col = %v, want empty", DecodePortBitmap(u))
	}
}

func TestMembershipBitmapsForwardsWidth(t *testing.T) {
	egress := EncodePortBitmap([]int{1}, 8)
	untagged := EncodePortBitmap([]int{1}, 8)

	e, u := MembershipBitmaps(egress, untagged, 5, model.VlanUntagged, 12)
	if len(e) != 12 {
		t.Errorf("len(e) = %d, want 12", len(e))
	}
	if len(u) != 12 {
		t.Errorf("len(u) = %d, want 12", len(u))
	}
	if diff := cmp.Diff([]int{1, 5}, DecodePortBitmap(e)); diff != "" {
		t.Errorf("egress mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]int{1, 5}, DecodePortBitmap(u)); diff != "" {
		t.Errorf("untagged mismatch (-want +got):\n%s", diff)
	}
}

func TestVlanBitmapWidth52PortModelIs8(t *testing.T) {
	if got := VlanBitmapWidth(52); got != 8 {
		t.Errorf("VlanBitmapWidth(52) = %d, want 8", got)
	}
}

func TestVlanBitmapWidthSynthetic96PortModelIs12(t *testing.T) {
	if got := VlanBitmapWidth(96); got != 12 {
		t.Errorf("VlanBitmapWidth(96) = %d, want 12", got)
	}
}
