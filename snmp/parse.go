package snmp

// This file holds pure SNMP-row -> model parsers. No I/O. Ported
// field-for-field from src/netgear_switch/protocols/snmp/parse.py (the
// normative source; that repo is read-only from here). Any discrepancy
// between this file and the Python source is a bug in this file.

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mithro/go-netgear-switch-library/model"
)

// suffix returns the portion of row.OID after "base+.", and whether row.OID
// actually has that prefix. This is a literal string-prefix match on
// base+"." -- no OID normalization (leading-dot stripping, numeric
// comparison, etc.) happens anywhere here, mirroring Python's _suffix.
func suffix(row Row, base string) (string, bool) {
	prefix := base + "."
	if !strings.HasPrefix(row.OID, prefix) {
		return "", false
	}
	return row.OID[len(prefix):], true
}

// formatValue renders a Row.Value for an error message: quoted for
// string/[]byte (so the message reads like a Python repr, e.g. "up"),
// %v otherwise.
func formatValue(v any) string {
	switch t := v.(type) {
	case string:
		return fmt.Sprintf("%q", t)
	case []byte:
		return fmt.Sprintf("%q", t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

// IndexIntColumn maps a single-int-index column walk to {index: int64
// value}. Rows whose OID doesn't start with baseOID+"." are ignored; rows
// with a dotted (deeper) suffix belong to a different, deeper column and
// are also skipped. An absent column (no matching rows at all) yields an
// empty, non-nil map -- not an error.
//
// Returns an error wrapping model.ErrSNMP, naming the offending OID, when:
//   - the single-component suffix isn't a valid integer index ("malformed
//     index"): the walk is pinned to one column, so this means the table
//     drifted;
//   - the row's Value isn't int64 ("non-integer value"): per the Row
//     contract, an int-valued column must arrive as int64.
func IndexIntColumn(rows []Row, baseOID string) (map[int]int64, error) {
	out := make(map[int]int64)
	for _, row := range rows {
		s, ok := suffix(row, baseOID)
		if !ok || strings.Contains(s, ".") {
			continue
		}
		idx, err := strconv.Atoi(s)
		if err != nil {
			return nil, errOID(row.OID, "malformed index %q", s)
		}
		v, ok := row.Value.(int64)
		if !ok {
			return nil, errOID(row.OID, "non-integer value %s", formatValue(row.Value))
		}
		out[idx] = v
	}
	return out, nil
}

// IndexStrColumn maps a single-index text column walk to {index: string
// value}. Rows whose OID doesn't start with baseOID+"." are ignored; a
// dotted (deeper) suffix belongs to a different column and is skipped. An
// absent column yields an empty, non-nil map.
//
// A text-name OCTET STRING (ifName/ifAlias/dot1qVlanStaticName) can
// legitimately arrive as string (the CLI transport) or []byte (a transport
// whose non-printable heuristic picks Hex-STRING for a value with any byte
// outside the printable-ASCII range, e.g. a name with a trailing NUL); both
// are valid text here, so []byte is decoded to string (UTF-8, replacing any
// undecodable byte) so the two transports yield the same model value. Any
// other type (e.g. int64) is a genuine wrong-type reply.
//
// Returns an error wrapping model.ErrSNMP, naming the offending OID, when:
//   - the single-component suffix isn't a valid integer index
//     ("non-integer index") -- present-but-malformed, not absence;
//   - the row's Value is neither string nor []byte ("non-string value").
func IndexStrColumn(rows []Row, baseOID string) (map[int]string, error) {
	out := make(map[int]string)
	for _, row := range rows {
		s, ok := suffix(row, baseOID)
		if !ok || strings.Contains(s, ".") {
			continue
		}
		idx, err := strconv.Atoi(s)
		if err != nil {
			return nil, errOID(row.OID, "non-integer index %q", s)
		}
		switch v := row.Value.(type) {
		case string:
			out[idx] = v
		case []byte:
			out[idx] = decodeUTF8Replace(v)
		default:
			return nil, errOID(row.OID, "non-string value %s", formatValue(row.Value))
		}
	}
	return out, nil
}

// decodeUTF8Replace decodes b as UTF-8, replacing each invalid byte with
// U+FFFD (the Unicode replacement character), mirroring Python's
// bytes.decode("utf-8", "replace").
//
// Go's string(b) conversion does NOT validate UTF-8 -- it copies the bytes
// verbatim, so an invalid byte silently survives inside a technically
// "invalid" Go string instead of being replaced. strings.ToValidUTF8 does
// replace invalid runs, but collapses each maximal invalid run to a single
// replacement character, whereas Python's decoder replaces byte-by-byte in
// some multi-byte-invalid-sequence cases; walking the bytes with
// utf8.DecodeRune (which reports a single invalid byte, size 1, on a bad
// lead/continuation byte) and appending one U+FFFD per invalid byte matches
// Python's replace semantics precisely.
func decodeUTF8Replace(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			sb.WriteRune(utf8.RuneError)
			b = b[1:]
			continue
		}
		sb.WriteRune(r)
		b = b[size:]
	}
	return sb.String()
}

// physicalPorts returns the set of physical (ethernetCsmacd) ifIndexes from
// an ifType walk, or nil when the walk yields NO rows under IfType at all
// -- the caller then keeps every interface, so a transport/mock that does
// not surface ifType is unchanged.
//
// When ifType IS present (every real switch), non-physical interfaces are
// excluded: the M4300 ifTable carries 128 ieee8023adLag(161) + a CPU(1) + a
// VLAN(135) interface alongside its 16 ethernetCsmacd(6) ports, none of
// which the web UI's port pages list -- so filtering here makes SNMP
// get_ports/get_stats agree field-for-field with the HTTP backend.
func physicalPorts(ifTypes []Row) (map[int]bool, error) {
	typeMap, err := IndexIntColumn(ifTypes, IfType)
	if err != nil {
		return nil, err
	}
	if len(typeMap) == 0 {
		return nil, nil
	}
	physical := make(map[int]bool, len(typeMap))
	for idx, t := range typeMap {
		if t == EthernetCsmacd {
			physical[idx] = true
		}
	}
	return physical, nil
}

// sortedUnion returns the sorted union of keys across all the given
// int64-valued maps.
func sortedUnion(maps ...map[int]int64) []int {
	set := make(map[int]struct{})
	for _, m := range maps {
		for k := range m {
			set[k] = struct{}{}
		}
	}
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// filterPhysical returns the subset of ports present in physical, or ports
// unchanged when physical is nil (meaning "no ifType walk -> keep all").
func filterPhysical(ports []int, physical map[int]bool) []int {
	if physical == nil {
		return ports
	}
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if physical[p] {
			out = append(out, p)
		}
	}
	return out
}

// ParsePortStatus builds the per-port operational status from six column
// walks (admin/oper/speed/name/alias, plus an optional ifType walk for
// physical-port filtering).
//
// Ports = sorted(admin keys ∪ oper keys), physical-filtered when ifTypes is
// non-empty. Per port: LinkUp = (oper == 1); AdminEnabled = (admin == 1)
// exactly (any other value, including absent, is false); SpeedMbps is nil
// unless the reported speed is > 0 AND the link is up -- a DOWN port's
// ifHighSpeed keeps reporting its configured rate (verified on the
// gsm7252ps: 10000 on down 1/0/52), which is NOT an operational speed, so
// it is suppressed to nil to agree with the web UI's "Unknown"/None.
// Name/Description are nil when the column has no row for the port OR the
// value is the empty string -- an absent ifAlias and an empty-string
// ifAlias both mean "no description set", never a fabricated "".
func ParsePortStatus(admin, oper, speed, names, aliases, ifTypes []Row) ([]model.PortStatus, error) {
	adminMap, err := IndexIntColumn(admin, IfAdminStatus)
	if err != nil {
		return nil, err
	}
	operMap, err := IndexIntColumn(oper, IfOperStatus)
	if err != nil {
		return nil, err
	}
	speedMap, err := IndexIntColumn(speed, IfHighSpeed)
	if err != nil {
		return nil, err
	}
	nameMap, err := IndexStrColumn(names, IfName)
	if err != nil {
		return nil, err
	}
	// ifAlias (operator-set description): distinct column from ifName
	// above. An absent row for a port (or an empty-string alias) both mean
	// "no description set" -> honest nil, never a fabricated "".
	aliasMap, err := IndexStrColumn(aliases, IfAlias)
	if err != nil {
		return nil, err
	}
	physical, err := physicalPorts(ifTypes)
	if err != nil {
		return nil, err
	}

	ports := filterPhysical(sortedUnion(adminMap, operMap), physical)
	result := make([]model.PortStatus, 0, len(ports))
	for _, p := range ports {
		linkUp := operMap[p] == 1
		mbps, hasSpeed := speedMap[p]
		var speedMbps *int
		if hasSpeed && mbps > 0 && linkUp {
			speedMbps = model.Ptr(int(mbps))
		}
		var name *string
		if n, ok := nameMap[p]; ok && n != "" {
			name = model.Ptr(n)
		}
		var description *string
		if d, ok := aliasMap[p]; ok && d != "" {
			description = model.Ptr(d)
		}
		result = append(result, model.PortStatus{
			Port:         p,
			Name:         name,
			AdminEnabled: adminMap[p] == 1,
			LinkUp:       linkUp,
			SpeedMbps:    speedMbps,
			Description:  description,
		})
	}
	return result, nil
}

// PortStatsCols is the argument struct for ParsePortStats: one Row walk per
// traffic counter column, plus an optional ifType walk for physical-port
// filtering. A named struct (rather than 7 positional/keyword-only
// parameters, as in the Python source) avoids the multi-bool/slice-arg
// footgun in Go.
type PortStatsCols struct {
	InOctets, OutOctets, InUcast, OutUcast, InErrors, OutErrors, IfTypes []Row
}

// ParsePortStats builds the per-port traffic-counter snapshot from the six
// ifHC*/ifIn/OutErrors column walks in cols (plus the optional ifType walk
// for physical-port filtering).
//
// Ports = sorted union of all six counters' key sets, physical-filtered
// when cols.IfTypes is non-empty (ifHC* counters are ifIndex-keyed, same
// space as ifType, so get_stats must drop the same LAG/CPU/VLAN pseudo-
// interfaces get_ports does, or SNMP stats disagree with the HTTP
// backend's physical-only view). A counter absent for a port is nil, never
// fabricated as 0.
func ParsePortStats(cols PortStatsCols) ([]model.PortStats, error) {
	rxBytes, err := IndexIntColumn(cols.InOctets, IfHCInOctets)
	if err != nil {
		return nil, err
	}
	txBytes, err := IndexIntColumn(cols.OutOctets, IfHCOutOctets)
	if err != nil {
		return nil, err
	}
	rxPackets, err := IndexIntColumn(cols.InUcast, IfHCInUcast)
	if err != nil {
		return nil, err
	}
	txPackets, err := IndexIntColumn(cols.OutUcast, IfHCOutUcast)
	if err != nil {
		return nil, err
	}
	rxErrors, err := IndexIntColumn(cols.InErrors, IfInErrors)
	if err != nil {
		return nil, err
	}
	txErrors, err := IndexIntColumn(cols.OutErrors, IfOutErrors)
	if err != nil {
		return nil, err
	}
	physical, err := physicalPorts(cols.IfTypes)
	if err != nil {
		return nil, err
	}

	ports := filterPhysical(
		sortedUnion(rxBytes, txBytes, rxPackets, txPackets, rxErrors, txErrors),
		physical,
	)
	result := make([]model.PortStats, 0, len(ports))
	for _, p := range ports {
		result = append(result, model.PortStats{
			Port:      p,
			RxBytes:   uint64PtrIfPresent(rxBytes, p),
			TxBytes:   uint64PtrIfPresent(txBytes, p),
			RxPackets: uint64PtrIfPresent(rxPackets, p),
			TxPackets: uint64PtrIfPresent(txPackets, p),
			RxErrors:  uint64PtrIfPresent(rxErrors, p),
			TxErrors:  uint64PtrIfPresent(txErrors, p),
		})
	}
	return result, nil
}

// uint64PtrIfPresent returns a pointer to m[p] as uint64, or nil when p has
// no entry in m -- an absent counter stays nil, never a fabricated 0.
func uint64PtrIfPresent(m map[int]int64, p int) *uint64 {
	v, ok := m[p]
	if !ok {
		return nil
	}
	return model.Ptr(uint64(v))
}

// DecodePortBitmap decodes a VLAN port bitmap (dot1qVlanStaticEgressPorts/
// dot1qVlanStaticUntaggedPorts OCTET STRING): bit 7 (the high bit) of byte 0
// is port 1, bit 6 of byte 0 is port 2, and so on -- port = byteIdx*8+bit+1
// for bit counted 0 (MSB) through 7 (LSB). An empty (including nil) bitmap
// is a legitimately absent value, not an error, and yields an empty, non-nil
// slice.
//
// The result is sorted ascending by construction: iterating bytes
// low-to-high and, within a byte, MSB-to-LSB visits ports in strictly
// increasing order, so no separate sort is needed.
//
// Unlike the Python reference's decode_port_bitmap (bytes | str, with a
// latin-1 str encode step that can fail on a non-latin-1 codepoint and
// raise SnmpError), this Go port only accepts []byte: a Go string is
// already a byte sequence (unlike Python's Unicode str), so a string-typed
// bitmap row converts to []byte directly with no encoding step and no
// possibility of a decode error -- see vlanBitmapMap, which does that
// conversion before calling here.
func DecodePortBitmap(bitmap []byte) []int {
	ports := make([]int, 0)
	for byteIdx, byteVal := range bitmap {
		for bit := 0; bit < 8; bit++ {
			if byteVal&(0x80>>uint(bit)) != 0 {
				ports = append(ports, byteIdx*8+bit+1)
			}
		}
	}
	return ports
}

// isAllDigits reports whether s is non-empty and consists entirely of ASCII
// digits, mirroring Python's str.isdigit() as used to validate a VLAN index
// suffix. This deliberately rejects a leading '-' (e.g. "-5"): a bare
// strconv.Atoi check would accept that as a valid negative integer, but a
// VLAN index suffix is never signed.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// vlanBitmapMap maps a VLAN bitmap column walk (dot1qVlanStaticEgressPorts/
// dot1qVlanStaticUntaggedPorts) to {vlan_id: bitmap bytes}.
//
// A row absent from the column (OID doesn't start with baseOID+".") is
// skipped. A row present under baseOID whose VLAN index suffix is not all
// ASCII digits, or whose value is neither []byte nor string (wrong SNMP
// type on the wire), is drift -- present but malformed, not absent -- and
// returns an error wrapping model.ErrSNMP naming the offending OID rather
// than silently dropping present-but-malformed data. A string value is
// converted to []byte directly (see DecodePortBitmap's docstring).
func vlanBitmapMap(rows []Row, baseOID string) (map[int][]byte, error) {
	out := make(map[int][]byte)
	for _, row := range rows {
		s, ok := suffix(row, baseOID)
		if !ok {
			continue
		}
		if !isAllDigits(s) {
			return nil, errOID(row.OID, "malformed VLAN index %q", s)
		}
		var data []byte
		switch v := row.Value.(type) {
		case []byte:
			data = v
		case string:
			data = []byte(v)
		default:
			return nil, errOID(row.OID, "malformed VLAN port bitmap type")
		}
		idx, err := strconv.Atoi(s)
		if err != nil {
			// Unreachable: isAllDigits already guarantees s parses cleanly.
			return nil, errOID(row.OID, "malformed VLAN index %q", s)
		}
		out[idx] = data
	}
	return out, nil
}

// intSliceDiff returns the elements of a not present in b, preserving a's
// order. Since ParseVlans always calls this with a sorted-ascending a (the
// output of DecodePortBitmap), the result stays sorted ascending too. The
// result is a non-nil slice even when empty.
func intSliceDiff(a, b []int) []int {
	exclude := make(map[int]struct{}, len(b))
	for _, v := range b {
		exclude[v] = struct{}{}
	}
	out := make([]int, 0, len(a))
	for _, v := range a {
		if _, skip := exclude[v]; !skip {
			out = append(out, v)
		}
	}
	return out
}

// ParseVlans builds the switch's VLAN table from the dot1qVlanStaticName/
// dot1qVlanStaticEgressPorts/dot1qVlanStaticUntaggedPorts column walks.
//
// VLANs are enumerated names-walk-only: only a VLAN ID present in the names
// walk becomes a VLANInfo, even if it also has an egress/untagged bitmap --
// a bitmap-only VLAN (no name row) is silently dropped. MemberPorts is the
// decoded egress bitmap; UntaggedPorts is the decoded untagged bitmap;
// TaggedPorts is always derived as MemberPorts minus UntaggedPorts, never
// read from a separate source. A VLAN with a name but no egress/untagged
// row at all (absent, not malformed) gets empty, non-nil port sets. Name is
// nil for an empty-string dot1qVlanStaticName value, consistent with the
// nil-for-absent-or-empty convention used throughout this package.
func ParseVlans(names, egress, untagged []Row) ([]model.VLANInfo, error) {
	nameMap, err := IndexStrColumn(names, Dot1qVlanStaticName)
	if err != nil {
		return nil, err
	}
	egressMap, err := vlanBitmapMap(egress, Dot1qVlanStaticEgress)
	if err != nil {
		return nil, err
	}
	untagMap, err := vlanBitmapMap(untagged, Dot1qVlanStaticUntagged)
	if err != nil {
		return nil, err
	}

	ids := make([]int, 0, len(nameMap))
	for id := range nameMap {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	result := make([]model.VLANInfo, 0, len(ids))
	for _, vid := range ids {
		member := DecodePortBitmap(egressMap[vid])
		untag := DecodePortBitmap(untagMap[vid])
		var name *string
		if n := nameMap[vid]; n != "" {
			name = model.Ptr(n)
		}
		result = append(result, model.VLANInfo{
			VlanID:        vid,
			Name:          name,
			MemberPorts:   member,
			TaggedPorts:   intSliceDiff(member, untag),
			UntaggedPorts: untag,
		})
	}
	return result, nil
}

// ParsePvids builds the (port, VLAN) PVID table from a dot1qPvid column
// walk, optionally physical-filtered by an ifType walk.
//
// dot1qPvid is keyed by dot1dBasePort. On every real Netgear switch the
// bridge-port and ifIndex spaces COINCIDE for physical ports (SNMP-verified
// on the M4300: PVIDs matched the ifIndex physical set with no
// translation), so filtering the PVID keys directly against the physical
// ifIndex set (via ifTypes) drops LAG/CPU/VLAN PVIDs correctly. A
// dot1dBasePortIfIndex translation was tried in the Python reference but is
// WRONG here: it couples PVIDs to the independently-populated FDB
// base-port map (which can point a physical port's base-port at an
// unrelated ifIndex), silently dropping real physical PVIDs. Do not "fix"
// this by adding a translation when touching this function.
//
// Results are sorted by (port, vlan). An empty ifTypes walk keeps every
// port (no filtering), matching every other physical-filtered parser in
// this package.
func ParsePvids(rows, ifTypes []Row) ([]model.Pvid, error) {
	pvidMap, err := IndexIntColumn(rows, Dot1qPvid)
	if err != nil {
		return nil, err
	}
	physical, err := physicalPorts(ifTypes)
	if err != nil {
		return nil, err
	}

	ports := filterPhysical(sortedUnion(pvidMap), physical)
	result := make([]model.Pvid, 0, len(ports))
	for _, p := range ports {
		result = append(result, model.Pvid{Port: p, Vlan: int(pvidMap[p])})
	}
	return result, nil
}

// formatMacBytesRaw renders b as an uppercase colon-hex MAC string, e.g.
// []byte{0xC8, 0, 0x84, 0x89, 0x71, 0x70} -> "C8:00:84:89:71:70".
func formatMacBytesRaw(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

// formatMacBytesFromOIDParts renders a slice of decimal-ASCII OID index
// components (the six trailing sub-identifiers of a dot1qTpFdbPort
// instance, one decimal byte value per component) as an uppercase
// colon-hex MAC string. Mirrors Python's _format_mac_bytes.
//
// A non-numeric component returns a plain (non-model.ErrSNMP-wrapped)
// error: the Python source's _format_mac_bytes has no try/except around
// its int(b) conversion, so a malformed byte there is an uncaught bare
// ValueError there, not an SnmpError -- a deliberate, untested corner of
// the source (no test exercises a non-numeric MAC-byte OID component) that
// is preserved here rather than "fixed" into a wrapped error.
//
// An out-of-range component (e.g. "256") is a second, separate,
// also-untested divergence: Python's f"{int(b):02X}" formats it as extra
// hex digits ("100") with no truncation, whereas byte(v) below silently
// truncates it modulo 256 ("00"). Real MAC-OID index components are
// always 0-255, so neither behavior is reachable in practice.
func formatMacBytesFromOIDParts(parts []string) (string, error) {
	b := make([]byte, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return "", fmt.Errorf("non-numeric MAC OID byte %q: %w", p, err)
		}
		b[i] = byte(v)
	}
	return formatMacBytesRaw(b), nil
}

// formatMacOctetString formats a raw 6-byte/6-char MAC-shaped OCTET
// STRING value as "XX:XX:XX:XX:XX:XX", returning ok=false when value
// isn't MAC-shaped (neither a 6-byte []byte nor a 6-char string).
//
// A string value is treated as raw bytes directly: Go's string is already
// a byte sequence, unlike Python's str (a sequence of Unicode code
// points), so no latin-1 decode/encode step is needed here, unlike the
// Python source's _format_mac_octetstring -- the same reasoning
// DecodePortBitmap's docstring applies to VLAN bitmaps.
func formatMacOctetString(value any) (string, bool) {
	var b []byte
	switch v := value.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return "", false
	}
	if len(b) != 6 {
		return "", false
	}
	return formatMacBytesRaw(b), true
}

// macFromASCIIText recognizes a MAC already rendered as 17-character ASCII
// text "XX:XX:XX:XX:XX:XX" -- the M4300-24X quirk, where
// dot1dBaseBridgeAddress arrives as human-readable colon-hex text instead
// of 6 raw octets. Each of the 6 colon-separated parts must be exactly 2
// hex characters (case-insensitive in; strconv.ParseUint accepts upper or
// lower case); output is always uppercase. Returns ok=false (not an
// error) for anything else, so callers fall through to the
// malformed-drift path.
func macFromASCIIText(value any) (string, bool) {
	s, ok := value.(string)
	if !ok {
		return "", false
	}
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return "", false
	}
	octets := make([]byte, 6)
	for i, p := range parts {
		if len(p) != 2 {
			return "", false
		}
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return "", false
		}
		octets[i] = byte(v)
	}
	return formatMacBytesRaw(octets), true
}

// isPrintableLatin1 reports whether every byte of s is "printable",
// mirroring Python's str.isprintable() as applied to a
// latin-1-normalized OCTET STRING (or plain ASCII text): each byte is
// treated as its own Unicode code point (0-255), matching how the Python
// reference's string values arise -- either genuine ASCII text, or a
// transport that maps raw octets 1:1 onto Latin-1 chr() values.
// Crucially this is NOT a UTF-8 decode of s (which could combine bytes
// into different code points and diverge from Python's per-character
// check). Go's unicode.IsPrint uses the same definition of "printable" as
// Python's str.isprintable() for this purpose: both admit the L/M/N/P/S
// categories plus the ASCII space (0x20), and both reject other Unicode
// separators/control characters (e.g. U+00A0 NBSP, U+007F DEL, or a NUL
// byte) -- so space IS printable here, but \x00 is not.
func isPrintableLatin1(s string) bool {
	for i := 0; i < len(s); i++ {
		if !unicode.IsPrint(rune(s[i])) {
			return false
		}
	}
	return true
}

// columnText renders a non-chassis, non-port-id LLDP column
// (portDesc/sysName) as text: []byte is UTF-8-decoded (replacing invalid
// bytes), string is returned as-is, anything else falls back to fmt's
// default formatting.
func columnText(value any) string {
	switch v := value.(type) {
	case []byte:
		return decodeUTF8Replace(v)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

// formatChassisID formats an lldpRemChassisId value: the MAC-address
// chassis subtype (a 6-byte/6-char MAC-shaped OCTET STRING) formats as
// colon-hex; any other chassis-id subtype (e.g. a chassis component name)
// falls back to formatValue rather than columnText's UTF-8 decode -- a
// literal port of a "latent oddity" in the Python source
// (_format_chassis_id's non-MAC fallback calls Python's str() on a bytes
// value, producing its b'...' repr, rather than decoding it as UTF-8 text
// like _column_text does). No test in the ported suite exercises a
// non-MAC-shaped bytes chassis-id, so this divergence from columnText is
// preserved exactly as documented rather than "fixed".
func formatChassisID(value any) string {
	if mac, ok := formatMacOctetString(value); ok {
		return mac
	}
	if s, ok := value.(string); ok {
		return s
	}
	return formatValue(value)
}

// formatPortID formats an lldpRemPortId value. Consistent with
// formatChassisID, a MAC-address port-id subtype (lldpPortIdSubtype 3) is
// raw binary and formats as colon-hex, instead of being UTF-8-decoded
// (with replacement) into garbled U+FFFD text.
//
// THE trickiest asymmetry in this file (D-SNMP §3.11): a 6-byte []byte
// value is ALWAYS MAC-hex -- a genuinely binary portId only ever arrives
// as []byte (the transport's own printable-ASCII heuristic only emits
// string for values that decode cleanly as text). A 6-char string,
// however, is treated as raw MAC bytes ONLY when it is NOT printable text
// (isPrintableLatin1): this guards a real, everyday ASCII interface-name
// portId that happens to be exactly 6 characters (e.g. "1/xg51") from
// being mistaken for a MAC and corrupted into hex -- unlike chassis-id,
// port-id routinely carries short human-readable interface names, so a
// bare length-6 check on string is unsafe here. Get this check backwards
// and interface-name portIds corrupt silently. Any other value (a
// printable 6-char string, or any non-MAC-shaped value) is plain text,
// per columnText.
func formatPortID(value any) string {
	switch v := value.(type) {
	case []byte:
		if len(v) == 6 {
			if mac, ok := formatMacOctetString(v); ok {
				return mac
			}
		}
	case string:
		if len(v) == 6 && !isPrintableLatin1(v) {
			if mac, ok := formatMacOctetString(v); ok {
				return mac
			}
		}
	}
	return columnText(value)
}

// ParseBaseMac parses dot1dBaseBridgeAddress (BRIDGE-MIB scalar, standard
// MIB-II) into a colon-separated MAC string.
//
// An absent scalar (no row under the OID at all) is honestly nil -- not
// every device necessarily answers this instance. A row that IS present
// but isn't a 6-byte/6-char OCTET STRING (raw bytes) NOR the M4300-24X's
// 17-char ASCII colon-hex quirk is drift, not absence, and returns an
// error wrapping model.ErrSNMP naming the offending OID.
func ParseBaseMac(rows []Row) (*string, error) {
	prefix := Dot1dBaseBridgeAddress + "."
	for _, row := range rows {
		if !strings.HasPrefix(row.OID, prefix) {
			continue
		}
		if mac, ok := formatMacOctetString(row.Value); ok {
			return model.Ptr(mac), nil
		}
		if mac, ok := macFromASCIIText(row.Value); ok {
			return model.Ptr(mac), nil
		}
		return nil, errOID(row.OID, "malformed base MAC %s", formatValue(row.Value))
	}
	return nil, nil
}

// lldpKey groups lldpRemTable rows into one neighbor entry by their
// (timeMark, localPort, remIndex) instance-suffix components, compared as
// raw strings (never parsed to int) -- only localPort is parsed to int,
// and only once, at emit time.
type lldpKey struct {
	timeMark, localPort, remIndex string
}

// lldpValueEmpty reports whether an LLDP column value counts as "no data"
// for the purposes of skipping an all-empty neighbor group, mirroring
// Python truthiness: an empty string or []byte, or an int64 zero, are all
// falsy; anything else (including a non-empty string of any content, e.g.
// a single NUL byte) is not.
func lldpValueEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []byte:
		return len(t) == 0
	case int64:
		return t == 0
	default:
		return false
	}
}

// colOrEmpty returns cols[col], or "" (a string, never Go's untyped nil)
// when col isn't in cols -- mirroring Python's dict.get(col, "").
func colOrEmpty(cols map[int]any, col int) any {
	if v, ok := cols[col]; ok {
		return v
	}
	return ""
}

// ParseLldp groups lldpRemTable rows by local port into LLDPNeighbor
// entries.
//
// The instance suffix is "<column>.<timeMark>.<localPortNum>.<remIndex>";
// the middle component is the local port. A row present under the table
// prefix but with other than exactly 4 suffix components, or a
// non-integer column component, is drift (not absence) and returns an
// error wrapping model.ErrSNMP naming the offending OID. Columns 5/7/8/9
// are chassis-id/port-id/port-desc/sys-name; other columns are ignored. A
// fully-empty neighbor group (every tracked column absent) carries no
// data and is skipped. A non-integer local-port component (present but
// malformed) also errors -- following the Python source literally, this
// error names "<prefix>...<localPort>", a synthetic string rather than a
// real row OID, since the offending row's own OID is discarded once rows
// are grouped by key.
//
// Results are sorted by local port using a STABLE sort: two neighbours
// that tie on local port keep their first-appearance (row) order, exactly
// mirroring Python's semantics (an insertion-ordered dict grouped by key,
// followed by a stable sorted()). A plain map has no defined iteration
// order in Go, so groups are additionally tracked in an explicit `order`
// slice, appended to only the first time a given key is seen -- iterating
// that slice (not the map) is what makes first-appearance order
// reproducible instead of randomized per run.
func ParseLldp(rows []Row) ([]model.LLDPNeighbor, error) {
	prefix := LldpRemTable + ".1."
	grouped := make(map[lldpKey]map[int]any)
	order := make([]lldpKey, 0)
	for _, row := range rows {
		if !strings.HasPrefix(row.OID, prefix) {
			continue
		}
		parts := strings.Split(row.OID[len(prefix):], ".")
		if len(parts) != 4 {
			return nil, errOID(row.OID, "malformed LLDP index")
		}
		column, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, errOID(row.OID, "non-integer LLDP column %q", parts[0])
		}
		key := lldpKey{parts[1], parts[2], parts[3]}
		if grouped[key] == nil {
			grouped[key] = make(map[int]any)
			order = append(order, key)
		}
		grouped[key][column] = row.Value
	}

	result := make([]model.LLDPNeighbor, 0, len(order))
	for _, key := range order {
		cols := grouped[key]
		// An absent column defaults to "" (mirroring Python's
		// cols.get(col, "")), not Go's nil zero value: nil would render as
		// the literal text "<nil>" through columnText's fmt fallback
		// instead of being recognized as empty by lldpValueEmpty/the
		// formatters' "" checks below.
		chassis := colOrEmpty(cols, 5)
		portID := colOrEmpty(cols, 7)
		portDesc := colOrEmpty(cols, 8)
		sysName := colOrEmpty(cols, 9)
		if lldpValueEmpty(chassis) && lldpValueEmpty(portID) && lldpValueEmpty(portDesc) && lldpValueEmpty(sysName) {
			continue
		}
		lp, err := strconv.Atoi(key.localPort)
		if err != nil {
			return nil, errOID(fmt.Sprintf("%s...%s", prefix, key.localPort), "non-integer LLDP local port %q", key.localPort)
		}
		neighbor := model.LLDPNeighbor{LocalPort: lp}
		if t := columnText(sysName); t != "" {
			neighbor.RemoteSysName = model.Ptr(t)
		}
		if t := columnText(portDesc); t != "" {
			neighbor.RemotePortDesc = model.Ptr(t)
		}
		if t := formatChassisID(chassis); t != "" {
			neighbor.RemoteChassisID = model.Ptr(t)
		}
		if t := formatPortID(portID); t != "" {
			neighbor.RemotePortID = model.Ptr(t)
		}
		result = append(result, neighbor)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].LocalPort < result[j].LocalPort })
	return result, nil
}

// ParseMacs builds the MAC/FDB table from dot1qTpFdbPort +
// dot1dBasePortIfIndex.
//
// dot1qTpFdbPort gives the bridge PORT number keyed by
// "<vlan>.<mac-as-6-oid-octets>"; dot1dBasePortIfIndex maps that bridge
// port to an ifIndex, falling back to the bridge port number itself when
// unmapped. An FDB OID suffix that isn't exactly 7 parts (vlan + 6 MAC
// bytes), a non-integer VLAN component, or a bridge-port Value that isn't
// int64, is drift and returns an error wrapping model.ErrSNMP naming the
// offending OID. Results are sorted by (port, mac).
func ParseMacs(fdb, bridgePorts []Row) ([]model.MacEntry, error) {
	bridgeToIf, err := IndexIntColumn(bridgePorts, Dot1dBasePortIfIndex)
	if err != nil {
		return nil, err
	}
	prefix := Dot1qTpFdbPort + "."
	result := make([]model.MacEntry, 0)
	for _, row := range fdb {
		if !strings.HasPrefix(row.OID, prefix) {
			continue
		}
		parts := strings.Split(row.OID[len(prefix):], ".")
		if len(parts) != 7 { // <vlan>.<6 MAC bytes>
			return nil, errOID(row.OID, "malformed FDB index")
		}
		vlanID, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, errOID(row.OID, "non-integer VLAN index %q", parts[0])
		}
		bridgePortVal, ok := row.Value.(int64)
		if !ok {
			return nil, errOID(row.OID, "non-integer bridge port %s", formatValue(row.Value))
		}
		mac, err := formatMacBytesFromOIDParts(parts[1:7])
		if err != nil {
			return nil, err
		}
		port, mapped := bridgeToIf[int(bridgePortVal)]
		if !mapped {
			port = bridgePortVal
		}
		result = append(result, model.MacEntry{
			Mac:    mac,
			Port:   int(port),
			VlanID: model.Ptr(vlanID),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}
		return result[i].Mac < result[j].Mac
	})
	return result, nil
}

// errSNMP wraps model.ErrSNMP with a plain message and no OID, for cases
// where there is no single offending row to name -- e.g. an entire
// tracked column missing for a given (group, port) key, as opposed to one
// malformed row (which uses errOID instead).
func errSNMP(format string, a ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, a...), model.ErrSNMP)
}

// DetectMap maps the pethPsePortDetectionStatus INTEGER value (RFC 3621) to
// model.PoEDetect. A value outside this map (including any never-seen
// future enum member) is model.PoEDetectUnknown at the ParsePoe call site,
// never a zero-value PoEDetect("").
var DetectMap = map[int64]model.PoEDetect{
	1: model.PoEDetectDisabled,
	2: model.PoEDetectSearching,
	3: model.PoEDetectDelivering,
	4: model.PoEDetectFault,
}

// poeKey groups pethPsePortTable rows by their (group, port)
// instance-suffix components -- the last two of the three
// "<column>.<group>.<port>" suffix components.
type poeKey struct{ group, port int }

// ParsePoe builds PoE port status from RFC3621 pethPsePortTable + a vendor
// per-port mW column.
//
// status is a walk of pethPsePortTable; only columns 3 (admin) and 6
// (detect) are honoured -- never column 1. A row present under the table
// prefix whose instance suffix isn't exactly 3 parts ("<column>.<group>.
// <port>") is SILENTLY SKIPPED, unlike every other parser in this file
// (which treats wrong arity as drift and errors): D-SNMP §3.15 pins this
// asymmetry deliberately. A port present in the walk but missing either
// tracked column IS drift and returns an error wrapping model.ErrSNMP
// naming the port (no single offending row to name an OID from, since the
// error is about an absent column, not a malformed one).
//
// powerMw is the vendor per-port power walk (e.g. VendorOids.PoEPowerMw),
// matched to a port by the FINAL OID suffix component only (no base-OID
// prefix check); a row whose final suffix component or Value isn't a
// plain int64 is SILENTLY SKIPPED (never an error) -- mirroring Python's
// bare try/except ValueError: continue. A port without a vendor mW row
// gets PowerMw == nil, never a fabricated 0 (this is how a no-vendor-OID
// model such as the gs728tpp, which always passes an empty powerMw walk,
// is represented).
func ParsePoe(status, powerMw []Row) ([]model.PoEStatus, error) {
	prefix := PethPsePortTable + "."
	cols := make(map[poeKey]map[int]int64)
	for _, row := range status {
		if !strings.HasPrefix(row.OID, prefix) {
			continue
		}
		parts := strings.Split(row.OID[len(prefix):], ".")
		if len(parts) != 3 {
			continue // wrong arity: silently skipped, per D-SNMP §3.15.
		}
		column, err := strconv.Atoi(parts[0])
		if err != nil {
			// Mirrors a deliberate, untested corner of the Python source:
			// int(parts[0]) sits OUTSIDE the try/except that wraps the
			// group/port/value conversion below, so a non-integer column
			// component there is an uncaught ValueError, not an
			// SnmpError. Preserved here as a plain (non-model.ErrSNMP)
			// error, following the same precedent as
			// formatMacBytesFromOIDParts.
			return nil, fmt.Errorf("non-integer PoE column %q at %s: %w", parts[0], row.OID, err)
		}
		if column != 3 && column != 6 {
			continue
		}
		group, gerr := strconv.Atoi(parts[1])
		port, perr := strconv.Atoi(parts[2])
		value, ok := row.Value.(int64)
		if gerr != nil || perr != nil || !ok {
			return nil, errOID(row.OID, "non-integer PoE value %s", formatValue(row.Value))
		}
		key := poeKey{group, port}
		if cols[key] == nil {
			cols[key] = make(map[int]int64)
		}
		cols[key][column] = value
	}

	// Vendor mW keyed by the FINAL suffix component only; non-int
	// component or value is silently skipped, never an error.
	mw := make(map[int]int64)
	for _, row := range powerMw {
		parts := strings.Split(row.OID, ".")
		idx, err := strconv.Atoi(parts[len(parts)-1])
		if err != nil {
			continue
		}
		v, ok := row.Value.(int64)
		if !ok {
			continue
		}
		mw[idx] = v
	}

	keys := make([]poeKey, 0, len(cols))
	for k := range cols {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].group != keys[j].group {
			return keys[i].group < keys[j].group
		}
		return keys[i].port < keys[j].port
	})

	result := make([]model.PoEStatus, 0, len(keys))
	for _, k := range keys {
		c := cols[k]
		admin, ok := c[3]
		if !ok {
			return nil, errSNMP("PoE port %d missing admin (col 3)", k.port)
		}
		detectVal, ok := c[6]
		if !ok {
			return nil, errSNMP("PoE port %d missing detect (col 6)", k.port)
		}
		detect, ok := DetectMap[detectVal]
		if !ok {
			detect = model.PoEDetectUnknown
		}
		var powerMwPtr *int
		if v, ok := mw[k.port]; ok {
			powerMwPtr = model.Ptr(int(v))
		}
		result = append(result, model.PoEStatus{
			Port:         k.port,
			AdminEnabled: admin == 1,
			Detect:       detect,
			PowerMw:      powerMwPtr,
		})
	}
	return result, nil
}

// SensorColumn is one vendor box-sensor column walk (e.g. fan RPM, PSU
// power, temperature): Kind/Unit label the whole column (e.g. "fan",
// "RPM"), and Rows is that column's walk-discovered rows. Sensor indices
// come from each row's OID, never hardcoded, since they differ per model.
type SensorColumn struct {
	Kind, Unit string
	Rows       []Row
}

// parseSensorReading extracts an integer box-sensor reading from a row's
// Value, accepting either a plain int64 (the usual value-normalization
// representation for a Gauge32/Integer wire value) OR a numeric string.
// Some vendor sensor readings have been observed on the wire as a
// STRING-typed OCTET STRING containing plain decimal digits (e.g. "3500")
// rather than an INTEGER/Gauge32 -- Python's int(value) accepts both
// transparently (a str or an int alike); this mirrors that dual
// acceptance explicitly, since Go's type switch can't coerce silently the
// way Python's int() does. Returns ok=false for anything else (including
// a non-numeric string, e.g. "warm" or the "Not Supported" placeholder
// handled separately by the caller).
func parseSensorReading(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// ParseBoxSensors builds box sensors from walk-discovered Netgear vendor
// columns.
//
// Each SensorColumn is one vendor column walk (fan RPM, PSU power,
// temperature, ...). The instance is the LAST OID component, used
// verbatim (as a string) in the sensor's Name. The literal string
// "Not Supported" is Netgear's placeholder for an unpopulated slot and is
// skipped, not an error; any other value that isn't a plain int64 or
// numeric string (see parseSensorReading) is present-but-malformed and
// returns an error wrapping model.ErrSNMP naming the kind, the offending
// value, and the OID.
func ParseBoxSensors(cols []SensorColumn) ([]model.Sensor, error) {
	result := make([]model.Sensor, 0)
	for _, col := range cols {
		for _, row := range col.Rows {
			parts := strings.Split(row.OID, ".")
			instance := parts[len(parts)-1]
			if s, ok := row.Value.(string); ok && s == "Not Supported" {
				continue
			}
			value, ok := parseSensorReading(row.Value)
			if !ok {
				return nil, errOID(row.OID, "non-integer %s reading %s", col.Kind, formatValue(row.Value))
			}
			result = append(result, model.Sensor{
				Name:  col.Kind + instance,
				Kind:  col.Kind,
				Value: float64(value),
				Unit:  col.Unit,
			})
		}
	}
	return result, nil
}

// entitySensorKindOf maps the entPhysicalClass INTEGER value to the Sensor
// Kind label; any other class (chassis, module/slot, port, ...) is
// ignored by ParseEntitySensors.
var entitySensorKindOf = map[int64]string{
	int64(EntClassPowerSupply): "power",
	int64(EntClassFan):         "fan",
}

// canonSensorName canonicalizes an ENTITY-MIB component name to the
// box-sensor label the HTTP DiagnosticsUnitList backend uses, so the two
// backends' sensor NAMES are identical (only the value/unit differ -- SNMP
// has no live reading here). entPhysicalName renders a PSU as
// "Main PowerSupply"/"Redundant PowerSupply"; the web UI labels the same
// component "Main PS"/"Redundant PS". Abbreviating "PowerSupply" -> "PS"
// (with or without an internal space) unifies them; a fan name ("Fan1")
// already matches and is returned unchanged.
func canonSensorName(name string) string {
	name = strings.ReplaceAll(name, "Power Supply", "PS")
	name = strings.ReplaceAll(name, "PowerSupply", "PS")
	return name
}

// ParseEntitySensors builds box sensors from the standard ENTITY-MIB
// physical inventory -- the fallback path for a model whose SNMP agent
// implements NO Netgear vendor OIDs (verified: the GS728TPP).
// entPhysicalClass (6=powerSupply, 7=fan) identifies each row;
// entPhysicalName, falling back to entPhysicalDescr, names it. This is
// INVENTORY ONLY: the switch exposes NO live sensor value/status anywhere
// in SNMP (ENTITY-SENSOR-MIB and the vendor tree both answer
// noSuchObject on real hardware), so each Sensor carries Value ==
// math.NaN() and Unit == "inventory" -- the component is honestly
// reported as present without a fabricated reading. Callers must compare
// with math.IsNaN, never ==. (HTTP DOES expose a health status for these
// same components -- a real per-backend difference, not a parser bug.)
//
// Rows are matched by their shared entPhysicalIndex (the trailing OID
// component, sorted ascending for deterministic output). Only
// powerSupply/fan classes become sensors; chassis/module/port rows are
// ignored. A non-integer class value present under the class column is
// drift and returns an error wrapping model.ErrSNMP naming the offending
// OID (via IndexIntColumn).
func ParseEntitySensors(classRows, nameRows, descrRows []Row) ([]model.Sensor, error) {
	names, err := IndexStrColumn(nameRows, EntPhysicalName)
	if err != nil {
		return nil, err
	}
	descrs, err := IndexStrColumn(descrRows, EntPhysicalDescr)
	if err != nil {
		return nil, err
	}
	classes, err := IndexIntColumn(classRows, EntPhysicalClass)
	if err != nil {
		return nil, err
	}

	idxs := make([]int, 0, len(classes))
	for idx := range classes {
		idxs = append(idxs, idx)
	}
	sort.Ints(idxs)

	result := make([]model.Sensor, 0, len(idxs))
	for _, idx := range idxs {
		kind, ok := entitySensorKindOf[classes[idx]]
		if !ok {
			continue
		}
		// name/descr/index fallback chain: names.get(idx) or
		// descrs.get(idx) or f"{kind}{idx}" -- a Go map's zero value for
		// a missing key is "" here, matching Python's falsy-empty-string
		// behavior for both an ABSENT and a present-but-empty entry, so
		// no separate presence check is needed.
		name := names[idx]
		if name == "" {
			name = descrs[idx]
		}
		if name == "" {
			name = fmt.Sprintf("%s%d", kind, idx)
		}
		result = append(result, model.Sensor{
			Name:  canonSensorName(name),
			Kind:  kind,
			Value: math.NaN(),
			Unit:  "inventory",
		})
	}
	return result, nil
}
