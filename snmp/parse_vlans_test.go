package snmp

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mithro/go-netgear-switch-library/model"
)

// TestDecodePortBitmapBit7IsPort1 pins the bit convention: bit 7 (the high
// bit) of byte 0 is port 1, and the same MSB-first convention continues
// into later bytes.
func TestDecodePortBitmapBit7IsPort1(t *testing.T) {
	if diff := cmp.Diff([]int{1, 3}, DecodePortBitmap([]byte{0b10100000})); diff != "" {
		t.Errorf("bitmap [0b10100000] mismatch (-want +got):\n%s", diff)
	}
	// second byte, bit7 -> port 9
	if diff := cmp.Diff([]int{9}, DecodePortBitmap([]byte{0, 0b10000000})); diff != "" {
		t.Errorf("bitmap [0, 0b10000000] mismatch (-want +got):\n%s", diff)
	}
}

// TestDecodePortBitmapEmptyIsEmptyNonNilSlice verifies both an empty and a
// nil bitmap decode to an empty, non-nil slice -- never a nil result that
// would marshal as JSON null instead of "[]".
func TestDecodePortBitmapEmptyIsEmptyNonNilSlice(t *testing.T) {
	if got := DecodePortBitmap([]byte{}); got == nil || len(got) != 0 {
		t.Errorf("DecodePortBitmap([]byte{}) = %v, want empty non-nil slice", got)
	}
	if got := DecodePortBitmap(nil); got == nil || len(got) != 0 {
		t.Errorf("DecodePortBitmap(nil) = %v, want empty non-nil slice", got)
	}
}

func TestParseVlansJoinsNamesEgressUntagged(t *testing.T) {
	names := []Row{NewStrRow(Dot1qVlanStaticName+".5", "net")}
	// egress ports 1,2 ; untagged port 2 -> tagged {1}, untagged {2}
	egress := []Row{NewBytesRow(Dot1qVlanStaticEgress+".5", []byte{0b11000000})}
	untag := []Row{NewBytesRow(Dot1qVlanStaticUntagged+".5", []byte{0b01000000})}

	vlans, err := ParseVlans(names, egress, untag)
	if err != nil {
		t.Fatalf("ParseVlans: %v", err)
	}
	if len(vlans) != 1 {
		t.Fatalf("len(vlans) = %d, want 1", len(vlans))
	}
	v := vlans[0]
	if v.VlanID != 5 {
		t.Errorf("VlanID = %d, want 5", v.VlanID)
	}
	if v.Name == nil || *v.Name != "net" {
		t.Errorf("Name = %v, want \"net\"", v.Name)
	}
	if diff := cmp.Diff([]int{1, 2}, v.MemberPorts); diff != "" {
		t.Errorf("MemberPorts mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]int{2}, v.UntaggedPorts); diff != "" {
		t.Errorf("UntaggedPorts mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]int{1}, v.TaggedPorts); diff != "" {
		t.Errorf("TaggedPorts mismatch (-want +got):\n%s", diff)
	}
}

// TestParseVlansAbsentBitmapYieldsEmptyPortSets verifies a VLAN with a name
// but NO egress/untagged rows at all (absent, not malformed) gets empty,
// non-nil port sets rather than an error.
func TestParseVlansAbsentBitmapYieldsEmptyPortSets(t *testing.T) {
	names := []Row{NewStrRow(Dot1qVlanStaticName+".10", "empty")}
	vlans, err := ParseVlans(names, nil, nil)
	if err != nil {
		t.Fatalf("ParseVlans: %v", err)
	}
	if len(vlans) != 1 {
		t.Fatalf("len(vlans) = %d, want 1", len(vlans))
	}
	v := vlans[0]
	for label, got := range map[string][]int{
		"MemberPorts": v.MemberPorts, "UntaggedPorts": v.UntaggedPorts, "TaggedPorts": v.TaggedPorts,
	} {
		if got == nil || len(got) != 0 {
			t.Errorf("%s = %v, want empty non-nil slice", label, got)
		}
	}
}

// TestParseVlansEnumeratesOnlyNamesWalk verifies enumeration is
// names-walk-only: a VLAN with an egress bitmap but no name row is dropped
// entirely, never fabricated from bitmap data alone.
func TestParseVlansEnumeratesOnlyNamesWalk(t *testing.T) {
	egress := []Row{NewBytesRow(Dot1qVlanStaticEgress+".9", []byte{0b10000000})}
	vlans, err := ParseVlans(nil, egress, nil)
	if err != nil {
		t.Fatalf("ParseVlans: %v", err)
	}
	if len(vlans) != 0 {
		t.Fatalf("len(vlans) = %d, want 0 (bitmap-only VLAN must be dropped)", len(vlans))
	}
}

// TestParseVlansNameNilForEmptyString verifies an empty-string
// dot1qVlanStaticName value maps to a nil Name, not a fabricated "".
func TestParseVlansNameNilForEmptyString(t *testing.T) {
	names := []Row{NewStrRow(Dot1qVlanStaticName+".7", "")}
	vlans, err := ParseVlans(names, nil, nil)
	if err != nil {
		t.Fatalf("ParseVlans: %v", err)
	}
	if vlans[0].Name != nil {
		t.Errorf("Name = %q, want nil for an empty-string value", *vlans[0].Name)
	}
}

// TestParseVlansBitmapAcceptsStringValueDirectly verifies a string-typed
// bitmap row (as CLI-style transports may surface) decodes identically to
// the same bytes as a []byte row: Go strings are already byte-transparent,
// so this requires no latin-1 dance and can never fail to "encode".
func TestParseVlansBitmapAcceptsStringValueDirectly(t *testing.T) {
	names := []Row{NewStrRow(Dot1qVlanStaticName+".5", "net")}
	egress := []Row{NewStrRow(Dot1qVlanStaticEgress+".5", string([]byte{0b11000000}))}

	vlans, err := ParseVlans(names, egress, nil)
	if err != nil {
		t.Fatalf("ParseVlans: %v", err)
	}
	if diff := cmp.Diff([]int{1, 2}, vlans[0].MemberPorts); diff != "" {
		t.Errorf("MemberPorts mismatch (-want +got):\n%s", diff)
	}
}

// TestParseVlansRaisesOnPresentButMalformedIndex verifies an egress row
// present under the base OID but with a non-numeric VLAN index suffix is
// drift (not absence) and raises, wrapping model.ErrSNMP.
func TestParseVlansRaisesOnPresentButMalformedIndex(t *testing.T) {
	names := []Row{NewStrRow(Dot1qVlanStaticName+".5", "net")}
	egress := []Row{NewBytesRow(Dot1qVlanStaticEgress+".x", []byte{0b11000000})}

	_, err := ParseVlans(names, egress, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseVlans error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), "malformed VLAN index") {
		t.Errorf("error = %q, want substring %q", err.Error(), "malformed VLAN index")
	}
}

// TestParseVlansRejectsNegativeIndex verifies the VLAN index check is
// isdigit-style (all ASCII digits), not a bare integer parse: a leading '-'
// (e.g. "-5") must be rejected even though strconv.Atoi would accept it.
func TestParseVlansRejectsNegativeIndex(t *testing.T) {
	names := []Row{NewStrRow(Dot1qVlanStaticName+".5", "net")}
	egress := []Row{NewBytesRow(Dot1qVlanStaticEgress+".-5", []byte{0b11000000})}

	_, err := ParseVlans(names, egress, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseVlans error = %v, want wrap of model.ErrSNMP", err)
	}
}

// TestParseVlansRaisesOnMalformedBitmapType verifies an egress row present
// under the base OID but whose value is neither []byte nor string (a wrong
// SNMP type on the wire, e.g. an int64) raises, naming the offending OID.
func TestParseVlansRaisesOnMalformedBitmapType(t *testing.T) {
	names := []Row{NewStrRow(Dot1qVlanStaticName+".5", "net")}
	egress := []Row{NewIntRow(Dot1qVlanStaticEgress+".5", 42)}

	_, err := ParseVlans(names, egress, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseVlans error = %v, want wrap of model.ErrSNMP", err)
	}
	wantOID := Dot1qVlanStaticEgress + ".5"
	if !strings.Contains(err.Error(), wantOID) {
		t.Errorf("error = %q, want it to contain the offending OID %q", err.Error(), wantOID)
	}
	if !strings.Contains(err.Error(), "malformed VLAN port bitmap type") {
		t.Errorf("error = %q, want substring %q", err.Error(), "malformed VLAN port bitmap type")
	}
}

// TestParseVlansPropagatesColumnErrors verifies a malformed names-column
// row (a distinct failure mode from the VLAN-bitmap-specific checks above)
// still propagates as a wrap of model.ErrSNMP.
func TestParseVlansPropagatesColumnErrors(t *testing.T) {
	names := []Row{NewIntRow(Dot1qVlanStaticName+".5", 1)}
	_, err := ParseVlans(names, nil, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseVlans error = %v, want wrap of model.ErrSNMP", err)
	}
}

func TestParsePvidsSortedPortVlanPairs(t *testing.T) {
	rows := []Row{
		NewIntRow(Dot1qPvid+".2", 90),
		NewIntRow(Dot1qPvid+".1", 90),
	}
	pvids, err := ParsePvids(rows, nil)
	if err != nil {
		t.Fatalf("ParsePvids: %v", err)
	}
	want := []model.Pvid{{Port: 1, Vlan: 90}, {Port: 2, Vlan: 90}}
	if diff := cmp.Diff(want, pvids); diff != "" {
		t.Errorf("pvids mismatch (-want +got):\n%s", diff)
	}
}

// TestParsePvidsFiltersToPhysicalPorts is the deferred 14th intent from the
// Python reference's test_parse_ports.py: PVIDs are reported for LAG
// interfaces too, so ParsePvids must filter them out via ifType --
// DIRECTLY against ifIndex, with no dot1dBasePortIfIndex translation (see
// ParsePvids's docstring / D-SNMP §3.9) -- so the SNMP PVID map matches the
// HTTP page's physical-only view.
func TestParsePvidsFiltersToPhysicalPorts(t *testing.T) {
	rows := []Row{
		NewIntRow(Dot1qPvid+".1", 10),
		NewIntRow(Dot1qPvid+".2", 20),
		NewIntRow(Dot1qPvid+".770", 1),
	}
	ifTypes := []Row{
		NewIntRow(IfType+".1", 6),
		NewIntRow(IfType+".2", 6),
		NewIntRow(IfType+".770", 161),
	}

	got, err := ParsePvids(rows, ifTypes)
	if err != nil {
		t.Fatalf("ParsePvids: %v", err)
	}
	want := []model.Pvid{{Port: 1, Vlan: 10}, {Port: 2, Vlan: 20}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("pvids mismatch (-want +got):\n%s", diff)
	}

	// No ifType walk -> keep all (backward-compatible), including the LAG.
	gotAll, err := ParsePvids(rows, nil)
	if err != nil {
		t.Fatalf("ParsePvids: %v", err)
	}
	wantAll := []model.Pvid{{Port: 1, Vlan: 10}, {Port: 2, Vlan: 20}, {Port: 770, Vlan: 1}}
	if diff := cmp.Diff(wantAll, gotAll); diff != "" {
		t.Errorf("pvids mismatch (-want +got):\n%s", diff)
	}
}

// TestParsePvidsPropagatesColumnErrors verifies ParsePvids propagates the
// underlying IndexIntColumn error rather than swallowing it.
func TestParsePvidsPropagatesColumnErrors(t *testing.T) {
	rows := []Row{NewStrRow(Dot1qPvid+".1", "not-a-number")}
	_, err := ParsePvids(rows, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParsePvids error = %v, want wrap of model.ErrSNMP", err)
	}
}
