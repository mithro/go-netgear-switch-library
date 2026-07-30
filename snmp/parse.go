package snmp

// This file holds pure SNMP-row -> model parsers. No I/O. Ported
// field-for-field from src/netgear_switch/protocols/snmp/parse.py (the
// normative source; that repo is read-only from here). Any discrepancy
// between this file and the Python source is a bug in this file.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
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
