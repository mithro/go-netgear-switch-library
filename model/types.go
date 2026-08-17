// Package model holds the shared device-data types, typed errors and the
// switch-model registry for the Netgear switch library. It is the leaf
// package every protocol package imports; it imports nothing internal.
package model

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// PoEDetect is the IEEE 802.3af/at PoE detection state of a port, as
// reported by the switch. It mirrors the Python reference's PoEDetect enum
// field-for-field (values are the lower-case Python enum values).
type PoEDetect string

// PoEDetect values, mirroring Python models.PoEDetect.
const (
	PoEDetectDisabled   PoEDetect = "disabled"
	PoEDetectSearching  PoEDetect = "searching"
	PoEDetectDelivering PoEDetect = "delivering"
	PoEDetectFault      PoEDetect = "fault"
	PoEDetectUnknown    PoEDetect = "unknown"
)

// VlanMode is a port's membership mode within a single VLAN.
type VlanMode string

// VlanMode values, mirroring Python models.VlanMode.
const (
	VlanUntagged VlanMode = "untagged"
	VlanTagged   VlanMode = "tagged"
	VlanExcluded VlanMode = "excluded"
)

// IPMode is how a switch's management IP address was configured.
type IPMode string

// IPMode values, mirroring Python models.IPMode.
const (
	IPModeDHCP    IPMode = "dhcp"
	IPModeStatic  IPMode = "static"
	IPModeUnknown IPMode = "unknown"
)

// Ptr returns a pointer to v; convenience for constructing optional
// (nullable) fields inline, e.g. model.Ptr("value").
func Ptr[T any](v T) *T { return &v }

// PortSpeed is a port's CONFIGURED speed/duplex -- what it is SET to, not
// what it got. Deliberately NOT folded into PortStatus.SpeedMbps, which is
// the OPERATIONAL rate the link actually came up at. The two answer
// different questions and neither substitutes for the other: a port
// configured auto can be running at 100 Mbit/s, and a port forced to
// 100 Mbit/s full-duplex still reports no operational rate at all while its
// link is down. Overloading one field would have made "what did I
// configure?" unanswerable exactly when it matters most -- on a down port,
// which is the only kind this library is allowed to reconfigure.
//
// Invariant (mirroring the Python reference's __post_init__, NOT enforced
// by this type -- construct via AutoPortSpeed/ForcedPortSpeed instead of
// the struct literal to keep it): when Autonegotiate is true, SpeedMbps and
// FullDuplex are both nil, because an auto port has no configured rate --
// it has whatever it negotiates. A FORCED configuration carries both,
// because every firmware measured here requires the duplex to be named
// alongside the rate ("speed 100 full-duplex").
//
// NOT representable, deliberately: auto-negotiation with a restricted
// ADVERTISED rate list (FASTPATH's "speed auto [10] [100] [1000] [10G]").
// The grammar accepts it, but "show port"'s Physical Mode column reports a
// bare "Auto" for it -- measured on gsm7252ps 10.1.5.22 port 1/0/8,
// 2026-08-03, where "speed auto 1000" read back identically to "speed
// auto". Offering it would mean offering a write this library cannot
// verify it made, so it is left out until a read that can distinguish the
// two (the running-config line) is built.
type PortSpeed struct {
	Autonegotiate bool  `json:"autonegotiate"`
	SpeedMbps     *int  `json:"speed_mbps"`
	FullDuplex    *bool `json:"full_duplex"`
}

// AutoPortSpeed returns the auto-negotiate PortSpeed (the factory default
// on every switch measured here).
func AutoPortSpeed() PortSpeed {
	return PortSpeed{Autonegotiate: true}
}

// ForcedPortSpeed returns a forced fixed-rate/duplex PortSpeed, disabling
// auto-negotiation.
func ForcedPortSpeed(speedMbps int, fullDuplex bool) PortSpeed {
	return PortSpeed{
		Autonegotiate: false,
		SpeedMbps:     Ptr(speedMbps),
		FullDuplex:    Ptr(fullDuplex),
	}
}

// String renders p the way the Python reference's __str__ does: "auto", or
// "<N>M full-duplex"/"<N>M half-duplex" for a forced configuration.
func (p PortSpeed) String() string {
	if p.Autonegotiate {
		return "auto"
	}
	speed := 0
	if p.SpeedMbps != nil {
		speed = *p.SpeedMbps
	}
	duplex := "half"
	if p.FullDuplex != nil && *p.FullDuplex {
		duplex = "full"
	}
	return fmt.Sprintf("%dM %s-duplex", speed, duplex)
}

// PortStatus mirrors Python models.PortStatus. Name is ifName; Description
// is ifAlias — a backend that cannot read a field leaves it nil rather than
// fabricating a value.
type PortStatus struct {
	Port         int     `json:"port"`
	Name         *string `json:"name"`
	AdminEnabled bool    `json:"admin_enabled"`
	LinkUp       bool    `json:"link_up"`
	SpeedMbps    *int    `json:"speed_mbps"`
	Description  *string `json:"description"`
	// FullDuplex is whether the link negotiated FULL duplex. nil when the
	// backend cannot tell -- a down port has no negotiated duplex, and not
	// every backend reports it at all. Measured 2026-08-02: the M4300's
	// EtherLike-MIB dot3 table exposes only error counters, NOT
	// dot3StatsDuplexStatus (column 19 is absent), so SNMP cannot answer
	// this and leaves it nil. The FASTPATH CLI does: `show port all`
	// reports "1000 Full" in its Physical Status column, carrying speed
	// and duplex together.
	FullDuplex *bool `json:"full_duplex"`
	// FlowControl is whether IEEE 802.3x flow control is enabled on the
	// port ("Flow Mode" in `show port all`). nil where the backend does
	// not report it.
	FlowControl *bool `json:"flow_control"`
	// SpeedConfig is the port's CONFIGURED speed/duplex -- `show port`'s
	// "Physical Mode" column, as opposed to the "Physical Status" column
	// the two fields above come from. nil where the backend cannot tell,
	// which is every backend but the CLI so far: SNMP's ifSpeed and the
	// Plus models' NSDP port record both report the NEGOTIATED rate only,
	// and no vendor column carrying the admin setting has been located on
	// any of them.
	SpeedConfig *PortSpeed `json:"speed_config"`
}

// PoEStatus is the Power-over-Ethernet state of a single port, mirroring
// Python models.PoEStatus.
type PoEStatus struct {
	Port         int       `json:"port"`
	AdminEnabled bool      `json:"admin_enabled"`
	Detect       PoEDetect `json:"detect"`
	PowerMw      *int      `json:"power_mw"`
}

// Delivering reports whether the port is currently delivering PoE power.
func (p PoEStatus) Delivering() bool { return p.Detect == PoEDetectDelivering }

// VLANInfo describes a single VLAN's configuration. Port sets are
// canonical: sorted ascending, never nil.
type VLANInfo struct {
	VlanID        int     `json:"vlan_id"`
	Name          *string `json:"name"`
	MemberPorts   []int   `json:"member_ports"`
	TaggedPorts   []int   `json:"tagged_ports"`
	UntaggedPorts []int   `json:"untagged_ports"`
}

// LLDPNeighbor is a single LLDP neighbor entry learned on a local port,
// mirroring Python models.LLDPNeighbor.
type LLDPNeighbor struct {
	LocalPort       int     `json:"local_port"`
	RemoteSysName   *string `json:"remote_sys_name"`
	RemotePortDesc  *string `json:"remote_port_desc"`
	RemoteChassisID *string `json:"remote_chassis_id"`
	RemotePortID    *string `json:"remote_port_id"`
}

// MacEntry is a single row of the switch's MAC address / forwarding table.
type MacEntry struct {
	Mac    string `json:"mac"`
	Port   int    `json:"port"`
	VlanID *int   `json:"vlan_id"`
}

// Sensor is a single environmental sensor reading. Kind is one of
// "temperature", "fan", "power".
type Sensor struct {
	Name  string  `json:"name"`
	Kind  string  `json:"kind"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}

// PortStats is the traffic-counter snapshot for a single port.
type PortStats struct {
	Port      int     `json:"port"`
	RxBytes   *uint64 `json:"rx_bytes"`
	TxBytes   *uint64 `json:"tx_bytes"`
	RxPackets *uint64 `json:"rx_packets"`
	TxPackets *uint64 `json:"tx_packets"`
	RxErrors  *uint64 `json:"rx_errors"`
	TxErrors  *uint64 `json:"tx_errors"`
}

// MgmtIPConfig is the switch's own management IP configuration. BaseMac is
// uppercase "XX:XX:XX:XX:XX:XX" when present.
type MgmtIPConfig struct {
	Mode    IPMode  `json:"mode"`
	Address *string `json:"address"`
	Netmask *string `json:"netmask"`
	Gateway *string `json:"gateway"`
	BaseMac *string `json:"base_mac"`
}

// ServiceStatus is one management service the switch offers, and whether
// it is on, mirroring Python models.ServiceStatus. Covers the four
// protocols an operator turns on or off to control how the switch itself
// can be reached: "http", "https", "telnet" and "ssh".
type ServiceStatus struct {
	// Name is one of "http", "https", "telnet", "ssh".
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Port is the TCP port the service listens on, or nil where the
	// firmware does not report one. Measured: gsm7252ps omits the "SSH
	// Port" line that m4300-24x prints, so this is genuinely absent
	// rather than defaulted to 22.
	Port *int `json:"port"`
}

// PrivilegedAccessModes is access-mode text meaning FULL privilege, in
// every vocabulary measured so far. There are three, and they do not
// agree -- the same two accounts on the same two switches read differently
// depending on which face you ask (2026-08-02 / 2026-08-03):
//
//	backend          m4300-24x admin   gsm7252ps admin   guest (both)
//	CLI `show users` Privilege-15      Read/Write        Privilege-1 / Read Only
//	web userManagement.html            Super User        Read Only
//
// Note the web UI is the CONSISTENT one: it says "Super User"/"Read Only"
// on both switches, where the CLI's wording splits by firmware family. A
// parser taught only one vocabulary would silently mis-report the others,
// so this table is shared by every backend rather than living in one
// parser. Copied VERBATIM from Python's PRIVILEGED_ACCESS_MODES.
var PrivilegedAccessModes = map[string]struct{}{
	"privilege-15": {},
	"read/write":   {},
	"super user":   {},
}

// UnprivilegedAccessModes is access-mode text meaning NO/read-only
// privilege, in every vocabulary measured so far. Copied VERBATIM from
// Python's UNPRIVILEGED_ACCESS_MODES; see PrivilegedAccessModes.
var UnprivilegedAccessModes = map[string]struct{}{
	"privilege-1": {},
	"read only":   {},
	"no access":   {},
}

// PrivilegedAccess reports whether accessMode is a full-privilege level, or
// nil if the word is one this library has not measured on a device.
func PrivilegedAccess(accessMode string) *bool {
	text := strings.ToLower(strings.TrimSpace(accessMode))
	if _, ok := PrivilegedAccessModes[text]; ok {
		return Ptr(true)
	}
	if _, ok := UnprivilegedAccessModes[text]; ok {
		return Ptr(false)
	}
	return nil
}

// SwitchUser is one local login account on the switch, mirroring Python
// models.SwitchUser.
type SwitchUser struct {
	Name string `json:"name"`
	// AccessMode is the access mode exactly as this firmware words it, on
	// the FACE that was asked. Kept verbatim because the vocabulary is not
	// shared -- see PrivilegedAccessModes for the three spellings measured
	// so far.
	AccessMode string `json:"access_mode"`
	// Privileged is whether AccessMode is the full-privilege level,
	// normalised across every measured vocabulary so callers do not have
	// to know which image or which backend they are on. nil when the text
	// is none of them -- an unrecognised level is reported honestly rather
	// than guessed.
	Privileged *bool `json:"privileged"`
	// SNMPv3Access/SNMPv3Auth/SNMPv3Encryption are the three SNMPv3
	// columns the same table carries. nil where the firmware prints
	// nothing.
	SNMPv3Access     *string `json:"snmpv3_access"`
	SNMPv3Auth       *string `json:"snmpv3_auth"`
	SNMPv3Encryption *string `json:"snmpv3_encryption"`
}

// SyslogServer is one remote syslog collector the switch is configured to
// send to, mirroring Python models.SyslogServer.
type SyslogServer struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// Severity is the standard syslog severity, 0 (emergency) to 7
	// (debug). The switch sends messages AT OR ABOVE this level.
	// Cross-checked on m4300-24x: the SNMP column reads 6 where `show
	// logging hosts` prints "info".
	Severity int `json:"severity"`
	// Active is the switch's own word for the row's state, "Active" in
	// the CLI table.
	Active bool `json:"active"`
	// Index is the row's index in the switch's own host table, where the
	// backend reports one -- the handle a removal addresses. nil from
	// backends that do not expose it (SNMP walks it as the OID instance,
	// HTTP's page does not print it).
	//
	// It is SPARSE, and that is not a detail: measured on m4300-24x
	// (10.1.5.13, 2026-08-05) the table held Index 1 and Index 3 with
	// nothing at 2. Deriving it from a row's POSITION -- which is the
	// obvious thing to do -- addresses the wrong row as soon as anything
	// has ever been removed. NEVER derive Index from row position.
	Index *int `json:"index"`
}

// SyslogSeverityNames maps syslog severity names, as the switches PRINT
// them, to the standard numbers the SNMP columns carry. Netgear spells the
// same value differently depending on which face you ask, so this is
// shared rather than per-backend: the FASTPATH CLI's `show logging hosts`
// prints "info" (lowercase) while the web UI's Severity Filter column
// prints "Info" -- MEASURED on the same collector row of the same switch
// (m4300-24x 10.1.5.13, 2026-08-03), where the SNMP severity column reads
// 6.
//
// "informational" is listed beside "info" because it is the word
// FASTPATH's own `logging host` command accepts; both are severity 6.
// Copied VERBATIM from Python's SYSLOG_SEVERITY_NAMES.
var SyslogSeverityNames = map[string]int{
	"emergency":     0,
	"alert":         1,
	"critical":      2,
	"error":         3,
	"warning":       4,
	"notice":        5,
	"info":          6,
	"informational": 6,
	"debug":         7,
}

// SyslogSeverityWords is the canonical WORD each severity number is
// written back as. The inverse of SyslogSeverityNames is not a function --
// 6 has two spellings there -- so the one a command may carry is pinned
// rather than derived. "info" is the spelling every switch's own
// running-config uses (`logging host "10.1.5.1" ipv4 514 info`, read off
// all four FASTPATH models 2026-08-05). Copied VERBATIM from Python's
// SYSLOG_SEVERITY_WORDS.
var SyslogSeverityWords = map[int]string{
	0: "emergency",
	1: "alert",
	2: "critical",
	3: "error",
	4: "warning",
	5: "notice",
	6: "info",
	7: "debug",
}

// SyslogSeverityLabels is the same severities as the WEB UI spells them.
// Title-case, not the CLI's lowercase -- both read off real output on the
// same switch (m4300-24x 10.1.5.13): `show logging hosts` prints "info"
// while syslogConfiguration.html's Severity Filter enum offers "Info".
// Pinned rather than derived by title-casing, because a formula that
// happens to agree today is exactly what stops being checked. Copied
// VERBATIM from Python's SYSLOG_SEVERITY_LABELS.
var SyslogSeverityLabels = map[int]string{
	0: "Emergency",
	1: "Alert",
	2: "Critical",
	3: "Error",
	4: "Warning",
	5: "Notice",
	6: "Info",
	7: "Debug",
}

// SyslogSeverityLabel maps a severity NUMBER to the word the WEB UI's enum
// carries. Returns an error for anything outside the standard range 0-7;
// see SyslogSeverityWord for the CLI's spelling of the same value.
func SyslogSeverityLabel(level int) (string, error) {
	word, ok := SyslogSeverityLabels[level]
	if !ok {
		return "", fmt.Errorf("syslog severity %d is outside the standard range 0-7", level)
	}
	return word, nil
}

// SyslogSeverityWord maps a severity NUMBER to the word a switch command
// carries. Returns an error on anything outside 0-7 rather than emitting
// the integer: syslog severities are a closed set, and a command built
// from an out-of-range value would be rejected by the device with a
// message that names the command rather than the caller's mistake.
func SyslogSeverityWord(level int) (string, error) {
	word, ok := SyslogSeverityWords[level]
	if !ok {
		return "", fmt.Errorf("syslog severity %d is outside the standard range 0-7", level)
	}
	return word, nil
}

// SyslogSeverity maps a switch's severity WORD to its standard number,
// case-insensitively. Returns an error on a word this library has not
// measured. That is deliberate: the obvious alternative -- defaulting to
// 0 -- reports the switch as forwarding EMERGENCIES ONLY, which is both
// wrong and invisible, and 0 is indistinguishable from a genuine
// "emergency" row. An unrecognised word means a firmware spells a level
// differently than any device measured here, and the caller should see
// that rather than a plausible number.
func SyslogSeverity(name string) (int, error) {
	text := strings.ToLower(strings.TrimSpace(name))
	if level, ok := SyslogSeverityNames[text]; ok {
		return level, nil
	}
	names := make([]string, 0, len(SyslogSeverityNames))
	for k := range SyslogSeverityNames {
		names = append(names, k)
	}
	sort.Strings(names)
	return 0, fmt.Errorf("unknown syslog severity %q; measured names are %v", name, names)
}

// SyslogConfig is remote-logging configuration: whether it is on, and
// where it sends, mirroring Python models.SyslogConfig.
//
// Deliberately narrower than everything `show logging` prints. The
// console and buffered-logging columns are in the same vendor subtree,
// but only the console pair could be decoded against captured CLI output;
// the buffered severity did not match any column read, so it is left out
// rather than guessed at. See snmp.VendorOids's Syslog* fields.
type SyslogConfig struct {
	Enabled bool `json:"enabled"`
	// LocalPort is the source port the switch sends FROM ("Logging Client
	// Local Port"), not the collector's port -- that is per-server in
	// Servers.
	LocalPort int            `json:"local_port"`
	Servers   []SyslogServer `json:"servers"`
}

// DetectedModel is the result of identifying a switch's model over SNMP
// (sysObjectID + sysDescr matching). Key is a registry key when the switch
// was confidently identified: either SysObjectID matches an entry in the
// known-OID map (the preferred, authoritative signal -- an unambiguous
// manufacturer product identifier, tried first) or, failing that, SysDescr
// confidently matches exactly one registered model's name (the fallback
// text heuristic); nil is never a fabricated guess. The Go port's
// DetectModel arrives in a later slice and MUST port the Python reference's
// SYSOBJECTID_MODELS map (protocols/snmp/parse.py) to preserve this
// preference order.
type DetectedModel struct {
	Key         *string `json:"key"`
	SysDescr    *string `json:"sys_descr"`
	SysObjectID *string `json:"sys_object_id"`
}

// Matched reports whether sysDescr matching identified a known model.
func (d DetectedModel) Matched() bool { return d.Key != nil }

// Pvid is a (port, vlan) pair recording a port's default/untagged VLAN
// assignment. Python uses tuple[int, int]; Pvid marshals to/from that same
// 2-element JSON array shape via its custom MarshalJSON/UnmarshalJSON.
type Pvid struct {
	Port int
	Vlan int
}

// MarshalJSON encodes p as the 2-element JSON array [port, vlan], matching
// the Python reference's tuple[int, int] serialization.
func (p Pvid) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]int{p.Port, p.Vlan})
}

// UnmarshalJSON decodes p from a 2-element JSON array [port, vlan].
func (p *Pvid) UnmarshalJSON(b []byte) error {
	var pair [2]int
	if err := json.Unmarshal(b, &pair); err != nil {
		return err
	}
	p.Port, p.Vlan = pair[0], pair[1]
	return nil
}

// SwitchData is the complete snapshot of a single switch's state, mirroring
// Python models.SwitchData. Zero-value slice fields marshal as JSON null;
// call Canonical() first to get Python-parity "[]" output for empty
// collections.
type SwitchData struct {
	Model   string         `json:"model"`
	Host    string         `json:"host"`
	Ports   []PortStatus   `json:"ports"`
	PoE     []PoEStatus    `json:"poe"`
	Vlans   []VLANInfo     `json:"vlans"`
	Pvids   []Pvid         `json:"pvids"`
	Lldp    []LLDPNeighbor `json:"lldp"`
	Macs    []MacEntry     `json:"macs"`
	Sensors []Sensor       `json:"sensors"`
	Stats   []PortStats    `json:"stats"`
	MgmtIP  *MgmtIPConfig  `json:"mgmt_ip"`
}

// Canonical returns a copy of sd with every nil slice field replaced by a
// non-nil empty slice, so that json.Marshal emits "[]" rather than "null"
// for absent collections -- matching the Python reference's default-empty-
// tuple fields. The original sd is never mutated.
func (sd SwitchData) Canonical() SwitchData {
	out := sd
	if out.Ports == nil {
		out.Ports = []PortStatus{}
	}
	if out.PoE == nil {
		out.PoE = []PoEStatus{}
	}
	if out.Vlans == nil {
		out.Vlans = []VLANInfo{}
	}
	if out.Pvids == nil {
		out.Pvids = []Pvid{}
	}
	if out.Lldp == nil {
		out.Lldp = []LLDPNeighbor{}
	}
	if out.Macs == nil {
		out.Macs = []MacEntry{}
	}
	if out.Sensors == nil {
		out.Sensors = []Sensor{}
	}
	if out.Stats == nil {
		out.Stats = []PortStats{}
	}
	return out
}
