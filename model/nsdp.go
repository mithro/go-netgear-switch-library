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
	// LinkSpeedTenGigabit is ASSUMED/UNVERIFIED — the reference spec states
	// 2.5G/5G/10G speed byte values are undocumented and require a hardware
	// capture; 0xFF is carried over from prior art without independent
	// confirmation.
	LinkSpeedTenGigabit LinkSpeed = 0xFF
)

// linkSpeedMbps mirrors Python's module-level _MBPS lookup table.
var linkSpeedMbps = map[LinkSpeed]int{
	LinkSpeedDown:       0,
	LinkSpeedHalf10M:    10,
	LinkSpeedFull10M:    10,
	LinkSpeedHalf100M:   100,
	LinkSpeedFull100M:   100,
	LinkSpeedGigabit:    1000,
	LinkSpeedTenGigabit: 10000,
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
// MemberPorts/TaggedPorts are canonical: sorted ascending, never containing
// duplicates. UntaggedPorts is deliberately not a struct field — see its
// method below.
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

	PortStatus     []NsdpPortStatus     `json:"port_status"`
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
