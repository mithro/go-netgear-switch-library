package snmp

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// --- ParseLldp ---------------------------------------------------------

// lldpBase is the lldpRemTable column-table prefix used to build test row
// OIDs: LldpRemTable + ".1" (the ".1" is the lldpRemEntry table index),
// with ".<col>.<timeMark>.<localPort>.<remIndex>" appended per row.
const lldpBase = LldpRemTable + ".1"

// TestParseLldpGroupsColumnsByLocalPort mirrors
// test_parse_lldp_groups_columns_by_local_port: sysName (col 9), portDesc
// (col 8), and portId (col 7) rows for the same (timeMark, localPort,
// remIndex) group into one LLDPNeighbor. remote_port_id is a distinct
// field from remote_port_desc, not discarded/aliased.
func TestParseLldpGroupsColumnsByLocalPort(t *testing.T) {
	rows := []Row{
		NewStrRow(lldpBase+".9.75.49.7", "sw-cisco-shed"),
		NewStrRow(lldpBase+".8.75.49.7", "eth0"),
		NewStrRow(lldpBase+".7.75.49.7", "1/xg51"),
	}
	n, err := ParseLldp(rows)
	if err != nil {
		t.Fatalf("ParseLldp: %v", err)
	}
	if len(n) != 1 {
		t.Fatalf("len(n) = %d, want 1", len(n))
	}
	if n[0].LocalPort != 49 {
		t.Errorf("LocalPort = %d, want 49", n[0].LocalPort)
	}
	if got := deref(n[0].RemoteSysName); got != "sw-cisco-shed" {
		t.Errorf("RemoteSysName = %q, want %q", got, "sw-cisco-shed")
	}
	if got := deref(n[0].RemotePortDesc); got != "eth0" {
		t.Errorf("RemotePortDesc = %q, want %q", got, "eth0")
	}
	if got := deref(n[0].RemotePortID); got != "1/xg51" {
		t.Errorf("RemotePortID = %q, want %q", got, "1/xg51")
	}
	if deref(n[0].RemotePortID) == deref(n[0].RemotePortDesc) {
		t.Errorf("RemotePortID must differ from RemotePortDesc")
	}
}

// TestParseLldpRemotePortIDAbsentIsNone mirrors
// test_parse_lldp_remote_port_id_absent_is_none: a neighbour row group with
// no col-7 value yields RemotePortID == nil, not a fabricated "".
func TestParseLldpRemotePortIDAbsentIsNone(t *testing.T) {
	rows := []Row{NewStrRow(lldpBase+".9.75.49.7", "sw-cisco-shed")}
	n, err := ParseLldp(rows)
	if err != nil {
		t.Fatalf("ParseLldp: %v", err)
	}
	if len(n) != 1 {
		t.Fatalf("len(n) = %d, want 1", len(n))
	}
	if n[0].RemotePortID != nil {
		t.Errorf("RemotePortID = %v, want nil", n[0].RemotePortID)
	}
}

// TestParseLldpRemotePortIDBinaryMacFormatsAsHex mirrors
// test_parse_lldp_remote_port_id_binary_mac_formats_as_hex: a
// MAC-address-subtype (lldpPortIdSubtype 3) portId arrives as a raw 6-byte
// OCTET STRING and must format as "XX:XX:XX:XX:XX:XX", not get
// UTF-8-mangled into U+FFFD replacement characters.
func TestParseLldpRemotePortIDBinaryMacFormatsAsHex(t *testing.T) {
	rows := []Row{
		NewBytesRow(lldpBase+".7.75.49.7", []byte{0x0c, 0xc4, 0x7a, 0x16, 0x3b, 0x4a}),
	}
	n, err := ParseLldp(rows)
	if err != nil {
		t.Fatalf("ParseLldp: %v", err)
	}
	if len(n) != 1 {
		t.Fatalf("len(n) = %d, want 1", len(n))
	}
	if got := deref(n[0].RemotePortID); got != "0C:C4:7A:16:3B:4A" {
		t.Errorf("RemotePortID = %q, want %q", got, "0C:C4:7A:16:3B:4A")
	}
}

// TestParseLldpRemotePortIDAsciiStaysText mirrors
// test_parse_lldp_remote_port_id_ascii_stays_text: an ASCII
// interface-name-subtype portId (e.g. "gi24") is plain text and must NOT
// be reinterpreted as MAC bytes.
func TestParseLldpRemotePortIDAsciiStaysText(t *testing.T) {
	rows := []Row{NewStrRow(lldpBase+".7.75.49.7", "gi24")}
	n, err := ParseLldp(rows)
	if err != nil {
		t.Fatalf("ParseLldp: %v", err)
	}
	if len(n) != 1 {
		t.Fatalf("len(n) = %d, want 1", len(n))
	}
	if got := deref(n[0].RemotePortID); got != "gi24" {
		t.Errorf("RemotePortID = %q, want %q", got, "gi24")
	}
}

// TestParseLldpRemotePortIDPrintableSixCharStaysText is the critical
// asymmetry pinned by D-SNMP §3.11: a printable 6-character string portId
// (e.g. "1/xg51", already covered above at length 6) must stay text, while
// a non-printable 6-character string (simulating a latin-1-normalized
// transport handing back raw MAC bytes as a string) must format as hex.
func TestParseLldpRemotePortIDNonPrintableSixCharIsMac(t *testing.T) {
	// Raw MAC bytes 0x00,0xC4,0x7A,0x16,0x3B,0x4A packed directly as a Go
	// string's bytes (mirrors a latin-1-normalizing transport); byte 0x00
	// is non-printable, so this must be treated as MAC-shaped, unlike the
	// printable "1/xg51" case above.
	rows := []Row{NewStrRow(lldpBase+".7.75.49.7", string([]byte{0x00, 0xc4, 0x7a, 0x16, 0x3b, 0x4a}))}
	n, err := ParseLldp(rows)
	if err != nil {
		t.Fatalf("ParseLldp: %v", err)
	}
	if len(n) != 1 {
		t.Fatalf("len(n) = %d, want 1", len(n))
	}
	if got := deref(n[0].RemotePortID); got != "00:C4:7A:16:3B:4A" {
		t.Errorf("RemotePortID = %q, want %q", got, "00:C4:7A:16:3B:4A")
	}
}

// TestParseLldpRaisesOnPresentButMalformedLocalPort mirrors
// test_parse_lldp_raises_on_present_but_malformed_local_port: a row IS
// present with a non-empty sysName column but a non-integer local port.
func TestParseLldpRaisesOnPresentButMalformedLocalPort(t *testing.T) {
	rows := []Row{NewStrRow(lldpBase+".9.75.xx.7", "sw-cisco-shed")}
	_, err := ParseLldp(rows)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseLldp error = %v, want wrap of model.ErrSNMP", err)
	}
}

// TestParseLldpRaisesOnWrongIndexArity mirrors
// test_parse_lldp_raises_on_wrong_index_arity: index has 5 parts instead
// of exactly 4.
func TestParseLldpRaisesOnWrongIndexArity(t *testing.T) {
	oid := lldpBase + ".9.75.49.7.extra"
	rows := []Row{NewStrRow(oid, "sw-cisco-shed")}
	_, err := ParseLldp(rows)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseLldp error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), oid) {
		t.Errorf("error = %q, want it to contain the offending OID %q", err.Error(), oid)
	}
}

// TestParseLldpRaisesOnNonIntegerColumn mirrors
// test_parse_lldp_raises_on_non_integer_column: column component is 'xx'
// (non-integer).
func TestParseLldpRaisesOnNonIntegerColumn(t *testing.T) {
	oid := lldpBase + ".xx.75.49.7"
	rows := []Row{NewStrRow(oid, "sw-cisco-shed")}
	_, err := ParseLldp(rows)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseLldp error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), oid) {
		t.Errorf("error = %q, want it to contain the offending OID %q", err.Error(), oid)
	}
}

// --- ParseMacs -----------------------------------------------------------

// TestParseMacsMapsBridgePortToIfindex mirrors
// test_parse_macs_maps_bridge_port_to_ifindex.
func TestParseMacsMapsBridgePortToIfindex(t *testing.T) {
	fdb := []Row{NewIntRow(Dot1qTpFdbPort+".90.200.0.132.137.113.112", 10)}
	// bridge port 10 -> ifIndex 24
	bridge := []Row{NewIntRow(fmt.Sprintf("%s.10", Dot1dBasePortIfIndex), 24)}
	macs, err := ParseMacs(fdb, bridge)
	if err != nil {
		t.Fatalf("ParseMacs: %v", err)
	}
	if len(macs) != 1 {
		t.Fatalf("len(macs) = %d, want 1", len(macs))
	}
	if macs[0].Mac != "C8:00:84:89:71:70" {
		t.Errorf("Mac = %q, want %q", macs[0].Mac, "C8:00:84:89:71:70")
	}
	if macs[0].VlanID == nil || *macs[0].VlanID != 90 {
		t.Errorf("VlanID = %v, want 90", macs[0].VlanID)
	}
	if macs[0].Port != 24 {
		t.Errorf("Port = %d, want 24", macs[0].Port)
	}
}

// TestParseMacsFallsBackToBridgePortWhenUnmapped verifies the D-SNMP
// §3.14 fallback: an unmapped bridge port falls back to the bridge port
// number itself, rather than being dropped or erroring.
func TestParseMacsFallsBackToBridgePortWhenUnmapped(t *testing.T) {
	fdb := []Row{NewIntRow(Dot1qTpFdbPort+".5.1.2.3.4.5.6", 7)}
	macs, err := ParseMacs(fdb, nil)
	if err != nil {
		t.Fatalf("ParseMacs: %v", err)
	}
	if len(macs) != 1 {
		t.Fatalf("len(macs) = %d, want 1", len(macs))
	}
	if macs[0].Port != 7 {
		t.Errorf("Port = %d, want 7 (bridge port fallback)", macs[0].Port)
	}
}

// TestParseMacsSortedByPortThenMac verifies the D-SNMP §3.14 output
// ordering: sorted by (port, mac).
func TestParseMacsSortedByPortThenMac(t *testing.T) {
	fdb := []Row{
		NewIntRow(Dot1qTpFdbPort+".1.2.2.2.2.2.2", 2), // port 2, mac 02:02:02:02:02:02
		NewIntRow(Dot1qTpFdbPort+".1.1.1.1.1.1.1", 1), // port 1, mac 01:01:01:01:01:01
		NewIntRow(Dot1qTpFdbPort+".1.3.3.3.3.3.3", 1), // port 1, mac 03:03:03:03:03:03
	}
	macs, err := ParseMacs(fdb, nil)
	if err != nil {
		t.Fatalf("ParseMacs: %v", err)
	}
	if len(macs) != 3 {
		t.Fatalf("len(macs) = %d, want 3", len(macs))
	}
	if macs[0].Port != 1 || macs[0].Mac != "01:01:01:01:01:01" {
		t.Errorf("macs[0] = %+v, want port 1 mac 01:01:01:01:01:01", macs[0])
	}
	if macs[1].Port != 1 || macs[1].Mac != "03:03:03:03:03:03" {
		t.Errorf("macs[1] = %+v, want port 1 mac 03:03:03:03:03:03", macs[1])
	}
	if macs[2].Port != 2 {
		t.Errorf("macs[2].Port = %d, want 2", macs[2].Port)
	}
}

// TestParseMacsRaisesOnNonIntegerPort mirrors
// test_parse_macs_raises_on_non_integer_port.
func TestParseMacsRaisesOnNonIntegerPort(t *testing.T) {
	bad := []Row{NewStrRow(Dot1qTpFdbPort+".1.1.2.3.4.5.6", "learned")}
	_, err := ParseMacs(bad, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseMacs error = %v, want wrap of model.ErrSNMP", err)
	}
}

// TestParseMacsRaisesOnWrongIndexArity mirrors
// test_parse_macs_raises_on_wrong_index_arity: index has 6 parts instead
// of exactly 7 (vlan + 6 MAC bytes).
func TestParseMacsRaisesOnWrongIndexArity(t *testing.T) {
	oid := Dot1qTpFdbPort + ".90.200.0.132.137.113"
	rows := []Row{NewIntRow(oid, 10)}
	_, err := ParseMacs(rows, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseMacs error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), oid) {
		t.Errorf("error = %q, want it to contain the offending OID %q", err.Error(), oid)
	}
}

// TestParseMacsRaisesOnNonIntegerVlan mirrors
// test_parse_macs_raises_on_non_integer_vlan.
func TestParseMacsRaisesOnNonIntegerVlan(t *testing.T) {
	oid := Dot1qTpFdbPort + ".xx.200.0.132.137.113.112"
	rows := []Row{NewIntRow(oid, 10)}
	_, err := ParseMacs(rows, nil)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseMacs error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), oid) {
		t.Errorf("error = %q, want it to contain the offending OID %q", err.Error(), oid)
	}
}

// --- ParseBaseMac --------------------------------------------------------

// TestParseBaseMacAbsentIsNone mirrors test_parse_base_mac_absent_is_none.
func TestParseBaseMacAbsentIsNone(t *testing.T) {
	mac, err := ParseBaseMac(nil)
	if err != nil {
		t.Fatalf("ParseBaseMac: %v", err)
	}
	if mac != nil {
		t.Errorf("ParseBaseMac(nil) = %v, want nil", mac)
	}
}

// TestParseBaseMacDecodesBytesOctetstring mirrors
// test_parse_base_mac_decodes_bytes_octetstring.
func TestParseBaseMacDecodesBytesOctetstring(t *testing.T) {
	rows := []Row{
		NewBytesRow(Dot1dBaseBridgeAddress+".0", []byte{0xc8, 0x00, 0x84, 0x89, 0x71, 0x70}),
	}
	mac, err := ParseBaseMac(rows)
	if err != nil {
		t.Fatalf("ParseBaseMac: %v", err)
	}
	if deref(mac) != "C8:00:84:89:71:70" {
		t.Errorf("ParseBaseMac = %q, want %q", deref(mac), "C8:00:84:89:71:70")
	}
}

// TestParseBaseMacDecodesLatin1StrOctetstring mirrors
// test_parse_base_mac_decodes_latin1_str_octetstring: a transport that
// normalizes an OCTET STRING to latin-1 text (raw bytes packed directly
// into a Go string).
func TestParseBaseMacDecodesLatin1StrOctetstring(t *testing.T) {
	raw := []byte{0xc8, 0x00, 0x84, 0x89, 0x71, 0x70}
	rows := []Row{NewStrRow(Dot1dBaseBridgeAddress+".0", string(raw))}
	mac, err := ParseBaseMac(rows)
	if err != nil {
		t.Fatalf("ParseBaseMac: %v", err)
	}
	if deref(mac) != "C8:00:84:89:71:70" {
		t.Errorf("ParseBaseMac = %q, want %q", deref(mac), "C8:00:84:89:71:70")
	}
}

// TestParseBaseMacM4300AsciiColonHexQuirk mirrors
// test_parse_mgmt_ip_base_mac_from_ascii_colon_hex_string: the M4300-24X's
// verified-live quirk of returning dot1dBaseBridgeAddress as a 17-char
// ASCII colon-hex string. Case-insensitive in, uppercase out.
func TestParseBaseMacM4300AsciiColonHexQuirk(t *testing.T) {
	rows := []Row{NewStrRow(Dot1dBaseBridgeAddress+".0", "8c:3b:ad:6b:bb:e0")}
	mac, err := ParseBaseMac(rows)
	if err != nil {
		t.Fatalf("ParseBaseMac: %v", err)
	}
	if deref(mac) != "8C:3B:AD:6B:BB:E0" {
		t.Errorf("ParseBaseMac = %q, want %q", deref(mac), "8C:3B:AD:6B:BB:E0")
	}
}

// TestParseBaseMacMalformedRaises mirrors
// test_parse_mgmt_ip_malformed_base_mac_raises_snmp_error: a value that is
// neither a 6-byte/6-char octet string nor the M4300 ASCII quirk is drift,
// not absence, and errors naming the offending OID.
func TestParseBaseMacMalformedRaises(t *testing.T) {
	oid := Dot1dBaseBridgeAddress + ".0"
	rows := []Row{NewStrRow(oid, "not-six-bytes")}
	_, err := ParseBaseMac(rows)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("ParseBaseMac error = %v, want wrap of model.ErrSNMP", err)
	}
	if !strings.Contains(err.Error(), oid) {
		t.Errorf("error = %q, want it to contain the offending OID %q", err.Error(), oid)
	}
}

// deref returns *s or "" when s is nil, for terser assertions above.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
