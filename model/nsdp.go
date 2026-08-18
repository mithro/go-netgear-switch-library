package model

import "sort"

// LinkSpeed is the raw NSDP wire byte for a port's link speed (TLV tag
// 0x0C00), mirroring Python protocols.nsdp.types.LinkSpeed. Unlike this
// package's other enums (string-based, see PoEDetect/VlanMode/IPMode),
// LinkSpeed is int-based so it round-trips the exact wire byte, including
// 0xFF, and marshals to JSON as that raw int (matching Python's IntEnum
// jsonify behaviour, which emits enum.value not the member name).
type LinkSpeed int

// LinkSpeed values, mirroring Python protocols.nsdp.types.LinkSpeed.
const (
	LinkSpeedDown     LinkSpeed = 0x00
	LinkSpeedHalf10M  LinkSpeed = 0x01
	LinkSpeedFull10M  LinkSpeed = 0x02
	LinkSpeedHalf100M LinkSpeed = 0x03
	LinkSpeedFull100M LinkSpeed = 0x04
	LinkSpeedGigabit  LinkSpeed = 0x05
	// LinkSpeedTenGigabit is MEASURED off real hardware -- a GS110EMX
	// (10.1.5.25/.26, firmware 1.0.2.8, 2026-07-30) answers PORT_STATUS
	// "09 06 01" / "0a 06 01" for the two uplinks its own web UI shows as
	// "10G Full". This Go repo had DRIFTED BEHIND the pinned Python
	// reference on this exact point -- go-port-pin-b26eb1f's
	// src/netgear_switch/protocols/nsdp/types.py:40 already carries
	// `TEN_GIGABIT = 0x06` (with the same GS110EMX capture cited in its own
	// comment, lines 32-39) and its _MBPS decode table
	// (protocols/nsdp/types.py:13-22) already maps `0x06: 10000`; this
	// package's linkSpeedMbps below had no entry for 0x06 at all until this
	// fix, so LinkSpeedFromByte(0x06) fell through to LinkSpeedDown --
	// meaning this library would have misread a REAL GS110EMX's 10G uplink
	// as link-down, independent of any fake. This is the value this repo's
	// own virtual-switch fake now EMITS for a 10G port (virtual/state.go's
	// mbpsToSpeedByte, mirroring go-port-pin-b26eb1f's src/netgear_switch/
	// virtual/state.py:112's `_mbps_to_speed_byte`); it used to emit
	// LinkSpeedTenGigabitPriorArt below instead, an undetected Go-behind-
	// pin parity gap CC3 (test/crosslang) caught by diffing this fake's raw
	// NsdpDevice reading against Python's own fake's, which the pin had
	// already corrected (that same virtual/state.py:104-110 docstring:
	// "This mock previously emitted 0xFF here, the same unverified
	// prior-art guess the DECODER carried ... 0xFF is still decoded ...
	// but is never emitted").
	LinkSpeedTenGigabit LinkSpeed = 0x06
	// LinkSpeedTenGigabitPriorArt is UNVERIFIED prior art carried over from
	// the reference spec as "the 10G code" without independent confirmation,
	// mirroring go-port-pin-b26eb1f's protocols/nsdp/types.py:46
	// `LinkSpeed.TEN_GIGABIT_PRIOR_ART`: still DECODED as 10 Gbps (a real
	// device this library has not yet talked to might still emit it, and
	// the pin's own _MBPS table keeps `0xFF: 10000` for exactly that
	// reason), but never EMITTED by this repo's own fake -- see
	// LinkSpeedTenGigabit's own doc comment for the measurement that
	// replaced it there.
	LinkSpeedTenGigabitPriorArt LinkSpeed = 0xFF
)

// linkSpeedMbps mirrors Python's module-level _MBPS lookup table.
var linkSpeedMbps = map[LinkSpeed]int{
	LinkSpeedDown:               0,
	LinkSpeedHalf10M:            10,
	LinkSpeedFull10M:            10,
	LinkSpeedHalf100M:           100,
	LinkSpeedFull100M:           100,
	LinkSpeedGigabit:            1000,
	LinkSpeedTenGigabit:         10000,
	LinkSpeedTenGigabitPriorArt: 10000,
}

// LinkSpeedFromByte decodes a raw NSDP wire byte into a LinkSpeed, mirroring
// Python's LinkSpeed.from_byte classmethod. Unknown/undocumented byte values
// (e.g. unassigned 2.5G/5G codes) report LinkSpeedDown; this never errors,
// matching the Python reference exactly.
func LinkSpeedFromByte(b byte) LinkSpeed {
	v := LinkSpeed(b)
	if _, ok := linkSpeedMbps[v]; ok {
		return v
	}
	return LinkSpeedDown
}

// SpeedMbps returns the link speed in megabits per second, mirroring
// Python's LinkSpeed.speed_mbps property. Unrecognized values report 0.
func (s LinkSpeed) SpeedMbps() int {
	return linkSpeedMbps[s]
}

// VLANEngine is a switch's configured VLAN engine mode (NSDP TLV tag
// 0x2000), mirroring Python protocols.nsdp.types.VLANEngine.
type VLANEngine int

// VLANEngine values, mirroring Python protocols.nsdp.types.VLANEngine.
const (
	VLANEngineDisabled      VLANEngine = 0
	VLANEngineBasicPort     VLANEngine = 1
	VLANEngineAdvancedPort  VLANEngine = 2
	VLANEngineBasic8021Q    VLANEngine = 3
	VLANEngineAdvanced8021Q VLANEngine = 4
)

// NsdpPortStatus is a single port's link-speed reading (NSDP TLV tag
// 0x0C00), mirroring Python protocols.nsdp.types.NsdpPortStatus.
type NsdpPortStatus struct {
	PortID int       `json:"port_id"`
	Speed  LinkSpeed `json:"speed"`
	// FlowControl is PORT_STATUS byte 2 (pin protocols/nsdp/types.py:78
	// `flow_control: bool | None = None`), MEASURED as the port's
	// flow-control state across all three real GS110EMX units (2026-07-30,
	// pin types.py:72-77): 10.1.5.25 and .26, whose web UI shows "Flow
	// Control: Enable" on every port, answer 0x01 on every port; 10.1.5.27,
	// whose page shows "Disable" on every port, answers 0x00 -- 30 ports, no
	// exceptions. nil when the TLV was shorter than 3 bytes (per the pin's
	// own comment; nsdp.ParsePortStatus currently requires exactly 3 bytes
	// or errors, so in practice this is always non-nil once parsing
	// succeeds -- the pin's parser has the identical invariant).
	//
	// This field lives on the RAW NsdpPortStatus only. Python's `_ports()`
	// (state translation into the public PortStatus shape) deliberately
	// DROPS flow_control -- it is not one of the fields NsdpPortStatus
	// contributes to the public model -- so Go's mapPorts must not surface
	// it on model.PortStatus either.
	FlowControl *bool `json:"flow_control"`
}

// NsdpPortStatistics is a single port's traffic-counter reading (NSDP TLV
// tag 0x1000), mirroring Python protocols.nsdp.types.NsdpPortStatistics.
// (Not "NsdpStatistics" — that name does not appear in the Python source.)
type NsdpPortStatistics struct {
	PortID        int    `json:"port_id"`
	BytesReceived uint64 `json:"bytes_received"`
	BytesSent     uint64 `json:"bytes_sent"`
	CrcErrors     uint64 `json:"crc_errors"`
}

// NsdpVlanMembership is a single VLAN's port membership (NSDP TLV tag
// 0x2800), mirroring Python protocols.nsdp.types.NsdpVlanMembership.
// MemberPorts/TaggedPorts are canonical: sorted ascending, never nil, never
// containing duplicates. UntaggedPorts is deliberately not a struct field —
// see its method below.
type NsdpVlanMembership struct {
	VlanID      int   `json:"vlan_id"`
	MemberPorts []int `json:"member_ports"`
	TaggedPorts []int `json:"tagged_ports"`
}

// UntaggedPorts returns the sorted set of member ports absent from
// TaggedPorts (member_ports - tagged_ports), mirroring Python's
// NsdpVlanMembership.untagged_ports computed property. It is deliberately
// not a stored field: Python's version is a @property recomputed on every
// access from the two frozenset fields, and dataclasses.fields() (the
// source jsonify walks) never sees properties, so this also never appears
// as a JSON key when marshalling NsdpVlanMembership — only when a caller
// calls this method explicitly.
func (m NsdpVlanMembership) UntaggedPorts() []int {
	tagged := make(map[int]bool, len(m.TaggedPorts))
	for _, p := range m.TaggedPorts {
		tagged[p] = true
	}
	out := make([]int, 0, len(m.MemberPorts))
	for _, p := range m.MemberPorts {
		if !tagged[p] {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// NsdpPortPvid is a port's default/untagged VLAN assignment (NSDP TLV tag
// 0x3000), mirroring Python protocols.nsdp.types.NsdpPortPvid.
type NsdpPortPvid struct {
	PortID int `json:"port_id"`
	VlanID int `json:"vlan_id"`
}

// NsdpPortMirroring is a port mirroring configuration (NSDP TLV tag
// 0x5C00), mirroring Python protocols.nsdp.types.NsdpPortMirroring.
type NsdpPortMirroring struct {
	// DestinationPort is the port receiving mirrored traffic (0 = disabled).
	DestinationPort int `json:"destination_port"`
	// SourcePorts are the ports being mirrored.
	SourcePorts []int `json:"source_ports"`
}

// NsdpIgmpSnooping is an IGMP snooping configuration (NSDP TLV tag 0x6800),
// mirroring Python protocols.nsdp.types.NsdpIgmpSnooping.
type NsdpIgmpSnooping struct {
	Enabled bool `json:"enabled"`
	// VlanID is the VLAN for IGMP snooping, nil when the wire value is 0
	// (no VLAN association).
	VlanID *int `json:"vlan_id"`
}

// NsdpPortName is one port's operator description (NSDP TLV tag 0xB000),
// mirroring Python protocols.nsdp.types.NsdpPortName. Name is nil when the TLV
// carries only the port byte, which is how a real GS110EMX reports a port with
// no description set (deliberately distinct from an empty-string description).
type NsdpPortName struct {
	PortID int     `json:"port_id"`
	Name   *string `json:"name"`
}

// NsdpDevice is the NSDP-native aggregate device snapshot produced by
// parse_device, mirroring Python protocols.nsdp.types.NsdpDevice. Model and
// Mac are the only required fields (every parsed reply carries them); every
// other field is optional and nil/empty when the switch's reply didn't
// include that TLV — never a fabricated zero value, per this package's
// established nullable-field convention (see types.go).
type NsdpDevice struct {
	Model string `json:"model"`
	Mac   string `json:"mac"`

	Hostname        *string `json:"hostname"`
	IP              *string `json:"ip"`
	Netmask         *string `json:"netmask"`
	Gateway         *string `json:"gateway"`
	FirmwareVersion *string `json:"firmware_version"`
	DhcpEnabled     *bool   `json:"dhcp_enabled"`
	PortCount       *int    `json:"port_count"`
	SerialNumber    *string `json:"serial_number"`

	VlanEngine *VLANEngine `json:"vlan_engine"`

	PortStatus []NsdpPortStatus `json:"port_status"`
	// PortNames are per-port operator descriptions (tag 0xB000), when that tag
	// was requested. Ordered between PortStatus and PortStatistics to match
	// Python's NsdpDevice field order.
	PortNames      []NsdpPortName       `json:"port_names"`
	PortStatistics []NsdpPortStatistics `json:"port_statistics"`
	VlanMembers    []NsdpVlanMembership `json:"vlan_members"`
	PortPvids      []NsdpPortPvid       `json:"port_pvids"`

	// QosEngine is the QoS engine mode (TLV tag 0x3400): 0=disabled,
	// 1=port-based, 2=802.1p.
	QosEngine *int `json:"qos_engine"`

	// PortMirroring is the port mirroring configuration (TLV tag 0x5C00).
	PortMirroring *NsdpPortMirroring `json:"port_mirroring"`

	// IgmpSnooping is the IGMP snooping configuration (TLV tag 0x6800).
	IgmpSnooping *NsdpIgmpSnooping `json:"igmp_snooping"`

	// BroadcastFiltering reports whether broadcast storm filtering is
	// enabled (TLV tag 0x5400).
	BroadcastFiltering *bool `json:"broadcast_filtering"`

	// LoopDetection reports whether loop detection is enabled (TLV tag
	// 0x9000).
	LoopDetection *bool `json:"loop_detection"`
}

// Canonical returns a copy of d with every nil slice field (PortStatus,
// PortStatistics, VlanMembers, PortPvids — and, recursively, each
// VlanMembers entry's MemberPorts/TaggedPorts and a non-nil PortMirroring's
// SourcePorts) replaced by a non-nil empty slice, so that json.Marshal
// emits "[]" rather than "null" for absent collections — matching Python's
// jsonify, which always renders these (default-()/frozenset) fields as
// empty lists, never null. Follows the same precedent as
// SwitchData.Canonical(). The original d is never mutated.
func (d NsdpDevice) Canonical() NsdpDevice {
	out := d

	if out.PortStatus == nil {
		out.PortStatus = []NsdpPortStatus{}
	}
	if out.PortStatistics == nil {
		out.PortStatistics = []NsdpPortStatistics{}
	}
	if out.PortPvids == nil {
		out.PortPvids = []NsdpPortPvid{}
	}

	if out.VlanMembers == nil {
		out.VlanMembers = []NsdpVlanMembership{}
	} else {
		members := make([]NsdpVlanMembership, len(out.VlanMembers))
		for i, m := range out.VlanMembers {
			members[i] = m.canonical()
		}
		out.VlanMembers = members
	}

	if out.PortMirroring != nil {
		pm := out.PortMirroring.canonical()
		out.PortMirroring = &pm
	}

	return out
}

// canonical returns a copy of m with nil MemberPorts/TaggedPorts replaced by
// non-nil empty slices; see NsdpDevice.Canonical.
func (m NsdpVlanMembership) canonical() NsdpVlanMembership {
	out := m
	if out.MemberPorts == nil {
		out.MemberPorts = []int{}
	}
	if out.TaggedPorts == nil {
		out.TaggedPorts = []int{}
	}
	return out
}

// canonical returns a copy of p with a nil SourcePorts replaced by a
// non-nil empty slice; see NsdpDevice.Canonical.
func (p NsdpPortMirroring) canonical() NsdpPortMirroring {
	out := p
	if out.SourcePorts == nil {
		out.SourcePorts = []int{}
	}
	return out
}
