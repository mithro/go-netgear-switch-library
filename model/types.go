// Package model holds the shared device-data types, typed errors and the
// switch-model registry for the Netgear switch library. It is the leaf
// package every protocol package imports; it imports nothing internal.
package model

import "encoding/json"

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

// IpMode is how a switch's management IP address was configured.
type IpMode string

// IpMode values, mirroring Python models.IpMode.
const (
	IpModeDHCP    IpMode = "dhcp"
	IpModeStatic  IpMode = "static"
	IpModeUnknown IpMode = "unknown"
)

// Ptr returns a pointer to v; convenience for constructing optional
// (nullable) fields inline, e.g. model.Ptr("value").
func Ptr[T any](v T) *T { return &v }

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

// MgmtIpConfig is the switch's own management IP configuration. BaseMac is
// uppercase "XX:XX:XX:XX:XX:XX" when present.
type MgmtIpConfig struct {
	Mode    IpMode  `json:"mode"`
	Address *string `json:"address"`
	Netmask *string `json:"netmask"`
	Gateway *string `json:"gateway"`
	BaseMac *string `json:"base_mac"`
}

// DetectedModel is the result of identifying a switch's model over SNMP
// (sysDescr matching). Key is a registry key iff sysDescr confidently
// matched exactly one model; nil is never a fabricated guess. SysObjectID
// is carried but never used for matching (no OID→model table exists).
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
	MgmtIP  *MgmtIpConfig  `json:"mgmt_ip"`
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
