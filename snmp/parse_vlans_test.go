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

	vlans, err := ParseVlans(names, egress, untag, nil, nil, nil)
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
	vlans, err := ParseVlans(names, nil, nil, nil, nil, nil)
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

// TestParseVlansEnumeratesOnlyNamesWalk verifies a VLAN with a STATIC
// egress bitmap but no name row AND no current-table row is dropped
// entirely, never fabricated from bitmap data alone. (Enumeration is no
// longer names-walk-ONLY since the GAP-2 fix -- a current-table-only VLAN
// IS enumerated, see TestParseVlansIncludesCurrentTableOnlyVlan below --
// but a static-bitmap-only VLAN with neither signal still is not.)
func TestParseVlansEnumeratesOnlyNamesWalk(t *testing.T) {
	egress := []Row{NewBytesRow(Dot1qVlanStaticEgress+".9", []byte{0b10000000})}
	vlans, err := ParseVlans(nil, egress, nil, nil, nil, nil)
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
	vlans, err := ParseVlans(names, nil, nil, nil, nil, nil)
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

	vlans, err := ParseVlans(names, egress, nil, nil, nil, nil)
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

	_, err := ParseVlans(names, egress, nil, nil, nil, nil)
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

	_, err := ParseVlans(names, egress, nil, nil, nil, nil)
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

	_, err := ParseVlans(names, egress, nil, nil, nil, nil)
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
	_, err := ParseVlans(names, nil, nil, nil, nil, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseVlans error = %v, want wrap of model.ErrSNMP", err)
	}
}

// --- GAP-2 regression tests: parity with Python commit 3f25b0b
// ("fix(snmp): get_vlans lost VLAN 1 and invented a member port 1000") ---

// TestParseVlansFiltersPhantomLAGMemberPort pins the GAP-2 fix: a LAG
// bridge-port set in a VLAN's egress/untagged bitmap must not surface as a
// member port. MEASURED live on a GS728TPP (10.2.5.10, firmware 6.0.1.30):
// its 126-byte Q-BRIDGE PortList sets bit 1000 -- ifName "po 1", ifType 161
// (ieee8023adLag), one of eight LAGs at ifIndex 1000-1007, confirmed
// identity-mapped via dot1dBasePortIfIndex -- in 11 of its 13 VLANs, on a
// switch with only 28 physical ports. Without the ifType filter, ParseVlans
// would report "member port 1000": not something a caller can act on, and
// never reported by the HTTP backend either.
func TestParseVlansFiltersPhantomLAGMemberPort(t *testing.T) {
	names := []Row{NewStrRow(Dot1qVlanStaticName+".5", "net")}
	egress := []Row{NewBytesRow(Dot1qVlanStaticEgress+".5", EncodePortBitmap([]int{1, 2, 1000}, 125))}
	untag := []Row{NewBytesRow(Dot1qVlanStaticUntagged+".5", EncodePortBitmap([]int{2, 1000}, 125))}
	ifTypes := []Row{
		NewIntRow(IfType+".1", EthernetCsmacd),
		NewIntRow(IfType+".2", EthernetCsmacd),
		NewIntRow(IfType+".1000", 161), // ieee8023adLag ("po 1")
	}

	vlans, err := ParseVlans(names, egress, untag, ifTypes, nil, nil)
	if err != nil {
		t.Fatalf("ParseVlans: %v", err)
	}
	if len(vlans) != 1 {
		t.Fatalf("len(vlans) = %d, want 1", len(vlans))
	}
	v := vlans[0]
	if diff := cmp.Diff([]int{1, 2}, v.MemberPorts); diff != "" {
		t.Errorf("MemberPorts mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]int{2}, v.UntaggedPorts); diff != "" {
		t.Errorf("UntaggedPorts mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]int{1}, v.TaggedPorts); diff != "" {
		t.Errorf("TaggedPorts mismatch (-want +got):\n%s", diff)
	}

	// No ifType walk -> keep all (backward-compatible, matching
	// physicalPorts' other callers), so the phantom port DOES surface --
	// filtering only happens when ifType data is actually available.
	vlansAll, err := ParseVlans(names, egress, untag, nil, nil, nil)
	if err != nil {
		t.Fatalf("ParseVlans (no ifTypes): %v", err)
	}
	if diff := cmp.Diff([]int{1, 2, 1000}, vlansAll[0].MemberPorts); diff != "" {
		t.Errorf("MemberPorts (no ifTypes) mismatch (-want +got):\n%s", diff)
	}
}

// TestParseVlansIncludesCurrentTableOnlyVlan pins the GAP-2 fix: a VLAN
// with NO dot1qVlanStaticTable row at all -- only a dot1qVlanCurrentTable
// row -- must still be enumerated, with a nil Name (the static table is
// the only source of a name). MEASURED live on a GS728TPP (10.2.5.10,
// firmware 6.0.1.30): its default VLAN 1 has no static row at all
// (dot1qVlanStatus = 1 "other" there, versus 2 "permanent" for every other
// VLAN there), so reading only the static table silently lost the VLAN
// carrying the switch's own uplinks. The static bitmap wins where both
// tables have the VLAN (VLAN 5 here), matching the live GS728TPP measurement
// that the two agreed byte-for-byte for every VLAN present in both.
func TestParseVlansIncludesCurrentTableOnlyVlan(t *testing.T) {
	// VLAN 1 exists ONLY in the current table (time mark 0, matching the
	// live GS728TPP capture). VLAN 5 has a normal static row too, with a
	// DELIBERATELY different current-table row, to prove the static
	// bitmap wins when both are present.
	names := []Row{NewStrRow(Dot1qVlanStaticName+".5", "net")}
	egress := []Row{NewBytesRow(Dot1qVlanStaticEgress+".5", []byte{0b11000000})}  // ports 1,2
	untag := []Row{NewBytesRow(Dot1qVlanStaticUntagged+".5", []byte{0b01000000})} // port 2
	curEgress := []Row{
		NewBytesRow(Dot1qVlanCurrentEgress+".0.1", []byte{0b11100000}), // ports 1,2,3
		NewBytesRow(Dot1qVlanCurrentEgress+".0.5", []byte{0b11111111}), // would be ports 1-8 if it won
	}
	curUntag := []Row{
		NewBytesRow(Dot1qVlanCurrentUntagged+".0.1", []byte{0b11100000}),
	}

	vlans, err := ParseVlans(names, egress, untag, nil, curEgress, curUntag)
	if err != nil {
		t.Fatalf("ParseVlans: %v", err)
	}
	if len(vlans) != 2 {
		t.Fatalf("len(vlans) = %d, want 2 (VLAN 1 from the current table + VLAN 5 from the static table)", len(vlans))
	}

	vlan1 := vlans[0]
	if vlan1.VlanID != 1 {
		t.Fatalf("vlans[0].VlanID = %d, want 1", vlan1.VlanID)
	}
	if vlan1.Name != nil {
		t.Errorf("VLAN 1 Name = %q, want nil (no static row, and the current table has no name column)", *vlan1.Name)
	}
	if diff := cmp.Diff([]int{1, 2, 3}, vlan1.MemberPorts); diff != "" {
		t.Errorf("VLAN 1 MemberPorts mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]int{1, 2, 3}, vlan1.UntaggedPorts); diff != "" {
		t.Errorf("VLAN 1 UntaggedPorts mismatch (-want +got):\n%s", diff)
	}

	vlan5 := vlans[1]
	if vlan5.VlanID != 5 {
		t.Fatalf("vlans[1].VlanID = %d, want 5", vlan5.VlanID)
	}
	if vlan5.Name == nil || *vlan5.Name != "net" {
		t.Errorf("VLAN 5 Name = %v, want \"net\"", vlan5.Name)
	}
	if diff := cmp.Diff([]int{1, 2}, vlan5.MemberPorts); diff != "" {
		t.Errorf("VLAN 5 MemberPorts mismatch (-want +got):\n%s", diff)
	}
}

// TestParseVlansRaisesOnMalformedCurrentTableIndex verifies a
// dot1qVlanCurrentTable row whose suffix is not exactly
// <timemark>.<vlanid> (two all-digit components) is drift, not absence,
// and raises wrapping model.ErrSNMP -- mirroring vlanBitmapMap's own
// malformed-index check for the static table.
func TestParseVlansRaisesOnMalformedCurrentTableIndex(t *testing.T) {
	curEgress := []Row{NewBytesRow(Dot1qVlanCurrentEgress+".5", []byte{0b10000000})} // missing the timemark component
	_, err := ParseVlans(nil, nil, nil, nil, curEgress, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseVlans error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), "malformed dot1qVlanCurrentTable index") {
		t.Errorf("error = %q, want substring %q", err.Error(), "malformed dot1qVlanCurrentTable index")
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
