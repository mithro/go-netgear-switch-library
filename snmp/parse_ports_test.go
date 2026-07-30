package snmp

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mithro/go-netgear-switch-library/model"
)

// intRows builds a []Row of int64-valued rows at base+"."+index, for the
// given index->value pairs.
func intRows(base string, pairs map[int]int64) []Row {
	out := make([]Row, 0, len(pairs))
	for i, v := range pairs {
		out = append(out, NewIntRow(fmt.Sprintf("%s.%d", base, i), v))
	}
	return out
}

// strRows builds a []Row of string-valued rows at base+"."+index, for the
// given index->value pairs.
func strRows(base string, pairs map[int]string) []Row {
	out := make([]Row, 0, len(pairs))
	for i, v := range pairs {
		out = append(out, NewStrRow(fmt.Sprintf("%s.%d", base, i), v))
	}
	return out
}

func portsOf(statuses []model.PortStatus) []int {
	out := make([]int, len(statuses))
	for i, s := range statuses {
		out[i] = s.Port
	}
	return out
}

func statsPortsOf(stats []model.PortStats) []int {
	out := make([]int, len(stats))
	for i, s := range stats {
		out[i] = s.Port
	}
	return out
}

func TestParsePortStatusJoinsAdminOperSpeedName(t *testing.T) {
	admin := intRows(IfAdminStatus, map[int]int64{1: 1, 2: 2})
	oper := intRows(IfOperStatus, map[int]int64{1: 1, 2: 2})
	speed := intRows(IfHighSpeed, map[int]int64{1: 1000, 2: 0})
	names := strRows(IfName, map[int]string{1: "1/0/1", 2: "1/0/2"})
	aliases := strRows(IfAlias, map[int]string{1: "uplink"})

	ports, err := ParsePortStatus(admin, oper, speed, names, aliases, nil)
	if err != nil {
		t.Fatalf("ParsePortStatus: %v", err)
	}
	if diff := cmp.Diff([]int{1, 2}, portsOf(ports)); diff != "" {
		t.Fatalf("ports mismatch (-want +got):\n%s", diff)
	}

	p1, p2 := ports[0], ports[1]
	if !p1.AdminEnabled {
		t.Error("port 1 AdminEnabled = false, want true")
	}
	if !p1.LinkUp {
		t.Error("port 1 LinkUp = false, want true")
	}
	if p1.SpeedMbps == nil || *p1.SpeedMbps != 1000 {
		t.Errorf("port 1 SpeedMbps = %v, want 1000", p1.SpeedMbps)
	}
	if p1.Name == nil || *p1.Name != "1/0/1" {
		t.Errorf("port 1 Name = %v, want 1/0/1", p1.Name)
	}
	if p1.Description == nil || *p1.Description != "uplink" {
		t.Errorf("port 1 Description = %v, want uplink", p1.Description)
	}

	if p2.AdminEnabled {
		t.Error("port 2 AdminEnabled = true, want false")
	}
	if p2.LinkUp {
		t.Error("port 2 LinkUp = true, want false")
	}
	if p2.SpeedMbps != nil {
		t.Errorf("port 2 SpeedMbps = %v, want nil (0 Mbps -> nil)", *p2.SpeedMbps)
	}
	// No ifAlias row for port 2 -> honest nil, not "".
	if p2.Description != nil {
		t.Errorf("port 2 Description = %v, want nil", *p2.Description)
	}
}

// TestParsePortStatusFiltersToPhysicalEthernetPorts mirrors the Python
// pin: the M4300 ifTable carries 16 ethernetCsmacd(6) physical ports
// alongside ieee8023adLag(161) LAGs, a CPU(1) interface and an l2vlan(135)
// routing interface -- none of which the web UI's port page lists. Given
// an ifType walk, ParsePortStatus must keep ONLY the physical ports so
// SNMP get_ports agrees field-for-field with the HTTP backend.
func TestParsePortStatusFiltersToPhysicalEthernetPorts(t *testing.T) {
	idx := map[int]int64{1: 1, 2: 1, 769: 1, 770: 1, 898: 1}
	admin := intRows(IfAdminStatus, idx)
	oper := intRows(IfOperStatus, idx)
	names := strRows(IfName, map[int]string{
		1: "1/0/1", 2: "1/0/2", 769: "CPU", 770: "lag 1", 898: "vlan 1",
	})
	ifTypes := intRows(IfType, map[int]int64{1: 6, 2: 6, 769: 1, 770: 161, 898: 135})

	ports, err := ParsePortStatus(admin, oper, nil, names, nil, ifTypes)
	if err != nil {
		t.Fatalf("ParsePortStatus: %v", err)
	}
	if diff := cmp.Diff([]int{1, 2}, portsOf(ports)); diff != "" {
		t.Fatalf("ports mismatch (-want +got):\n%s", diff) // LAG/CPU/VLAN dropped
	}
}

// TestParsePortStatusKeepsAllWhenNoIfTypeWalk verifies that with NO ifType
// walk (a transport/mock that does not surface ifType), every interface is
// kept -- backward-compatible, no silent drop.
func TestParsePortStatusKeepsAllWhenNoIfTypeWalk(t *testing.T) {
	admin := intRows(IfAdminStatus, map[int]int64{1: 1, 770: 1})
	oper := intRows(IfOperStatus, map[int]int64{1: 1, 770: 1})

	ports, err := ParsePortStatus(admin, oper, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("ParsePortStatus: %v", err)
	}
	if diff := cmp.Diff([]int{1, 770}, portsOf(ports)); diff != "" {
		t.Fatalf("ports mismatch (-want +got):\n%s", diff)
	}
}

// TestParsePortStatsFiltersToPhysicalPorts verifies ifHC counters are
// ifIndex-keyed; ParsePortStats must drop the same non-physical interfaces
// ParsePortStatus does, or SNMP stats disagree with HTTP stats.
func TestParsePortStatsFiltersToPhysicalPorts(t *testing.T) {
	inOctets := intRows(IfHCInOctets, map[int]int64{1: 100, 770: 999})
	outOctets := intRows(IfHCOutOctets, map[int]int64{1: 200, 770: 999})
	ifTypes := intRows(IfType, map[int]int64{1: 6, 770: 161})

	stats, err := ParsePortStats(PortStatsCols{
		InOctets:  inOctets,
		OutOctets: outOctets,
		IfTypes:   ifTypes,
	})
	if err != nil {
		t.Fatalf("ParsePortStats: %v", err)
	}
	if diff := cmp.Diff([]int{1}, statsPortsOf(stats)); diff != "" {
		t.Fatalf("ports mismatch (-want +got):\n%s", diff) // LAG 770 dropped
	}

	// No ifType walk -> keep all (backward-compatible).
	statsAll, err := ParsePortStats(PortStatsCols{
		InOctets:  inOctets,
		OutOctets: outOctets,
	})
	if err != nil {
		t.Fatalf("ParsePortStats: %v", err)
	}
	if diff := cmp.Diff([]int{1, 770}, statsPortsOf(statsAll)); diff != "" {
		t.Fatalf("ports mismatch (-want +got):\n%s", diff)
	}
}

// TestParsePortStatusDownPortReportsNoSpeed verifies a DOWN port whose
// ifHighSpeed still advertises the configured rate (verified real
// behavior: gsm7252ps down 1/0/52 reports 10000) has NO operational speed
// -> nil, so the SNMP reader agrees field-for-field with the web UI's
// "Unknown"/None for the same port.
func TestParsePortStatusDownPortReportsNoSpeed(t *testing.T) {
	admin := intRows(IfAdminStatus, map[int]int64{1: 1})
	oper := intRows(IfOperStatus, map[int]int64{1: 2}) // link down
	speed := intRows(IfHighSpeed, map[int]int64{1: 10000})
	names := strRows(IfName, map[int]string{1: "1/0/52"})

	ports, err := ParsePortStatus(admin, oper, speed, names, nil, nil)
	if err != nil {
		t.Fatalf("ParsePortStatus: %v", err)
	}
	if ports[0].LinkUp {
		t.Error("LinkUp = true, want false")
	}
	if ports[0].SpeedMbps != nil {
		t.Errorf("SpeedMbps = %v, want nil (down -> no operational speed)", *ports[0].SpeedMbps)
	}
}

func TestParsePortStatusEmptyAliasIsNoneNotEmptyString(t *testing.T) {
	admin := intRows(IfAdminStatus, map[int]int64{1: 1})
	oper := intRows(IfOperStatus, map[int]int64{1: 1})
	speed := intRows(IfHighSpeed, map[int]int64{1: 1000})
	names := strRows(IfName, map[int]string{1: "1/0/1"})
	// ifAlias column IS present for port 1 but with an empty value -- a
	// switch that has an ifAlias instance but no operator-set text.
	aliases := strRows(IfAlias, map[int]string{1: ""})

	ports, err := ParsePortStatus(admin, oper, speed, names, aliases, nil)
	if err != nil {
		t.Fatalf("ParsePortStatus: %v", err)
	}
	if ports[0].Description != nil {
		t.Errorf("Description = %v, want nil", *ports[0].Description)
	}
}

func TestParsePortStatsAbsentCounterIsNone(t *testing.T) {
	stats, err := ParsePortStats(PortStatsCols{
		InOctets:  intRows(IfHCInOctets, map[int]int64{1: 100}),
		OutOctets: intRows(IfHCOutOctets, map[int]int64{1: 200}),
		InUcast:   intRows(IfHCInUcast, map[int]int64{1: 5}),
		OutUcast:  intRows(IfHCOutUcast, map[int]int64{1: 6}),
		InErrors:  intRows(IfInErrors, map[int]int64{1: 0}),
		OutErrors: nil, // switch didn't expose ifOutErrors for port 1
	})
	if err != nil {
		t.Fatalf("ParsePortStats: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("len(stats) = %d, want 1", len(stats))
	}
	s := stats[0]
	if s.RxBytes == nil || *s.RxBytes != 100 {
		t.Errorf("RxBytes = %v, want 100", s.RxBytes)
	}
	if s.TxBytes == nil || *s.TxBytes != 200 {
		t.Errorf("TxBytes = %v, want 200", s.TxBytes)
	}
	if s.RxPackets == nil || *s.RxPackets != 5 {
		t.Errorf("RxPackets = %v, want 5", s.RxPackets)
	}
	if s.TxPackets == nil || *s.TxPackets != 6 {
		t.Errorf("TxPackets = %v, want 6", s.TxPackets)
	}
	if s.RxErrors == nil || *s.RxErrors != 0 {
		t.Errorf("RxErrors = %v, want 0 (present, not absent)", s.RxErrors)
	}
	if s.TxErrors != nil {
		t.Errorf("TxErrors = %v, want nil", *s.TxErrors)
	}
}

func TestIndexIntColumnRaisesOnNonInteger(t *testing.T) {
	rows := []Row{NewStrRow(IfOperStatus+".1", "up")}
	_, err := IndexIntColumn(rows, IfOperStatus)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("IndexIntColumn error = %v, want wrap of model.ErrSNMP", err)
	}
}

// TestIndexStrColumnRaisesOnPresentButMalformedIndex verifies: column IS
// present under base but its index component is non-integer: drift, not
// absence -> error (an absent column would just be an empty map).
func TestIndexStrColumnRaisesOnPresentButMalformedIndex(t *testing.T) {
	rows := []Row{NewStrRow(IfName+".x", "eth")}
	_, err := IndexStrColumn(rows, IfName)
	if !errors.Is(err, model.ErrSNMP) {
		t.Fatalf("IndexStrColumn error = %v, want wrap of model.ErrSNMP", err)
	}
}

// TestIndexStrColumnRaisesOnNonStringValue verifies IndexStrColumn errors
// when a present row has a non-string/[]byte value (e.g. an int64) -- a
// genuine wrong-type reply.
func TestIndexStrColumnRaisesOnNonStringValue(t *testing.T) {
	rows := []Row{NewIntRow(IfName+".1", 42)}
	_, err := IndexStrColumn(rows, IfName)
	if err == nil {
		t.Fatal("IndexStrColumn error = nil, want error")
	}
	if !strings.Contains(err.Error(), "non-string value") {
		t.Errorf("error = %q, want substring %q", err.Error(), "non-string value")
	}
	if !strings.Contains(err.Error(), IfName+".1") {
		t.Errorf("error = %q, want it to contain the offending OID %q", err.Error(), IfName+".1")
	}
}

// TestIndexStrColumnDecodesBytesValue verifies a []byte OCTET STRING (a
// transport's non-printable heuristic, e.g. a name with a trailing NUL)
// decodes to the same string the CLI transport would yield for the same
// underlying value -- transport parity.
func TestIndexStrColumnDecodesBytesValue(t *testing.T) {
	rows := []Row{
		NewBytesRow(IfName+".9", []byte("1/0/9")),
		NewBytesRow(IfName+".10", []byte("eth1\x00")),
	}
	result, err := IndexStrColumn(rows, IfName)
	if err != nil {
		t.Fatalf("IndexStrColumn: %v", err)
	}
	if result[9] != "1/0/9" {
		t.Errorf("result[9] = %q, want %q", result[9], "1/0/9")
	}
	if result[10] != "eth1\x00" {
		t.Errorf("result[10] = %q, want %q", result[10], "eth1\x00")
	}
}

// TestIndexIntColumnRaisesOnMalformedIndex verifies IndexIntColumn errors
// (message containing "malformed index") for a non-numeric OID suffix.
func TestIndexIntColumnRaisesOnMalformedIndex(t *testing.T) {
	rows := []Row{NewIntRow(IfOperStatus+".abc", 42)}
	_, err := IndexIntColumn(rows, IfOperStatus)
	if err == nil {
		t.Fatal("IndexIntColumn error = nil, want error")
	}
	if !strings.Contains(err.Error(), "malformed index") {
		t.Errorf("error = %q, want substring %q", err.Error(), "malformed index")
	}
	if !strings.Contains(err.Error(), IfOperStatus+".abc") {
		t.Errorf("error = %q, want it to contain the offending OID %q", err.Error(), IfOperStatus+".abc")
	}
}

// TestIndexIntColumnRaisesOnNonIntegerValue verifies IndexIntColumn errors
// (message containing "non-integer value") for a non-numeric value.
func TestIndexIntColumnRaisesOnNonIntegerValue(t *testing.T) {
	rows := []Row{NewStrRow(IfOperStatus+".1", "not_a_number")}
	_, err := IndexIntColumn(rows, IfOperStatus)
	if err == nil {
		t.Fatal("IndexIntColumn error = nil, want error")
	}
	if !strings.Contains(err.Error(), "non-integer value") {
		t.Errorf("error = %q, want substring %q", err.Error(), "non-integer value")
	}
	if !strings.Contains(err.Error(), IfOperStatus+".1") {
		t.Errorf("error = %q, want it to contain the offending OID %q", err.Error(), IfOperStatus+".1")
	}
}

// TestIndexIntColumnRaisesOnNonInt64Bytes verifies IndexIntColumn rejects
// a []byte value in an int column too (not just string) -- exercises the
// []byte arm of formatValue in the resulting error message.
func TestIndexIntColumnRaisesOnNonInt64Bytes(t *testing.T) {
	rows := []Row{NewBytesRow(IfOperStatus+".1", []byte("weird"))}
	_, err := IndexIntColumn(rows, IfOperStatus)
	if err == nil {
		t.Fatal("IndexIntColumn error = nil, want error")
	}
	if !strings.Contains(err.Error(), "non-integer value") {
		t.Errorf("error = %q, want substring %q", err.Error(), "non-integer value")
	}
}

// TestDecodeUTF8ReplaceInvalidByte verifies decodeUTF8Replace substitutes
// U+FFFD for a byte that is not valid UTF-8 (e.g. a bare continuation
// byte), mirroring Python's bytes.decode("utf-8", "replace"), while
// leaving valid bytes (including ASCII control bytes like NUL) untouched.
func TestDecodeUTF8ReplaceInvalidByte(t *testing.T) {
	got := decodeUTF8Replace([]byte{'a', 0xff, 'b'})
	want := "a�b"
	if got != want {
		t.Errorf("decodeUTF8Replace = %q, want %q", got, want)
	}
}

// TestParsePortStatusPropagatesColumnErrors verifies each of ParsePortStatus's
// six input walks propagates its own IndexIntColumn/IndexStrColumn/
// physicalPorts error rather than being swallowed.
func TestParsePortStatusPropagatesColumnErrors(t *testing.T) {
	// Bad rows must match the respective column's own base OID prefix, or
	// IndexIntColumn/IndexStrColumn simply skips them as belonging to a
	// different column -- see suffix()'s literal-prefix match.
	badInt := func(base string) []Row { return []Row{NewStrRow(base+".1", "bad")} }
	badStr := func(base string) []Row { return []Row{NewIntRow(base+".1", 1)} }

	cases := []struct {
		name                                      string
		admin, oper, speed, names, aliases, types []Row
	}{
		{"admin", badInt(IfAdminStatus), nil, nil, nil, nil, nil},
		{"oper", nil, badInt(IfOperStatus), nil, nil, nil, nil},
		{"speed", nil, nil, badInt(IfHighSpeed), nil, nil, nil},
		{"names", nil, nil, nil, badStr(IfName), nil, nil},
		{"aliases", nil, nil, nil, nil, badStr(IfAlias), nil},
		{"ifTypes", nil, nil, nil, nil, nil, badInt(IfType)},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePortStatus(tt.admin, tt.oper, tt.speed, tt.names, tt.aliases, tt.types)
			if !errors.Is(err, model.ErrSNMP) {
				t.Fatalf("ParsePortStatus(%s bad) error = %v, want wrap of model.ErrSNMP", tt.name, err)
			}
		})
	}
}

// TestParsePortStatsPropagatesColumnErrors mirrors
// TestParsePortStatusPropagatesColumnErrors for ParsePortStats's seven
// input walks.
func TestParsePortStatsPropagatesColumnErrors(t *testing.T) {
	badInt := func(base string) []Row { return []Row{NewStrRow(base+".1", "bad")} }

	cases := []struct {
		name string
		cols PortStatsCols
	}{
		{"InOctets", PortStatsCols{InOctets: badInt(IfHCInOctets)}},
		{"OutOctets", PortStatsCols{OutOctets: badInt(IfHCOutOctets)}},
		{"InUcast", PortStatsCols{InUcast: badInt(IfHCInUcast)}},
		{"OutUcast", PortStatsCols{OutUcast: badInt(IfHCOutUcast)}},
		{"InErrors", PortStatsCols{InErrors: badInt(IfInErrors)}},
		{"OutErrors", PortStatsCols{OutErrors: badInt(IfOutErrors)}},
		{"IfTypes", PortStatsCols{IfTypes: badInt(IfType)}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePortStats(tt.cols)
			if !errors.Is(err, model.ErrSNMP) {
				t.Fatalf("ParsePortStats(%s bad) error = %v, want wrap of model.ErrSNMP", tt.name, err)
			}
		})
	}
}
