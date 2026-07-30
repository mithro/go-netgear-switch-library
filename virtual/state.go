// Package virtual holds the in-memory virtual-switch device state used by
// the mock SNMP/NSDP/HTTP faces (later slices), ported field-for-field from
// src/netgear_switch/virtual/state.py (the normative source; that repo is
// read-only from here). Any discrepancy between this package and the Python
// source is a bug here.
//
// State holds everything a simulated switch "knows" about itself -- port
// link/admin/speed, counters, VLANs, PoE, sensors, the MAC/FDB table, LLDP
// neighbours and the management IP -- as small mutable *Sim structs.
// OIDMap projects that state onto the flat numeric OID -> (type, value)
// view a protocol face serves. This package is pure data + projection: no
// network.
package virtual

// PortSim is one switch port's link/admin/speed/name plus optional HC
// counters. Counters are *uint64: nil means "this port does not expose this
// counter" and must round-trip to an absent row in OIDMap (never a
// fabricated zero).
type PortSim struct {
	Name  string
	Admin bool
	Link  bool
	Speed int
	// IfType (IF-MIB): 6=ethernetCsmacd (a physical port -- the default via
	// NewPortSim). Real hardware also exposes non-physical rows in the same
	// ifTable -- LAGs (161=ieee8023adLag), the CPU interface (1=other),
	// VLAN routing interfaces (135=l2vlan) -- which the read path filters
	// OUT. A seed that adds those interfaces sets IfType directly so the
	// mock's SNMP reads drop them exactly as real hardware does.
	IfType   int
	RxOctets *uint64
	TxOctets *uint64
	RxUcast  *uint64
	TxUcast  *uint64
	RxErrors *uint64
	TxErrors *uint64
	// Description is ifAlias. nil means this port's ifAlias column instance
	// is entirely absent (never configured) -- never a fabricated "".
	Description *string
}

// NewPortSim builds a PortSim with the physical-port default IfType (6 =
// ethernetCsmacd). Non-physical rows (LAGs, CPU, VLAN interfaces) must set
// IfType explicitly after construction.
func NewPortSim(name string, admin, link bool, speed int) *PortSim {
	return &PortSim{Name: name, Admin: admin, Link: link, Speed: speed, IfType: 6}
}

// VlanSim is one dot1q VLAN: display name plus egress-member and untagged
// port sets. Member/Untagged represent sets: a port is a member iff its map
// value is true (see EncodePortBitmap).
type VlanSim struct {
	Name     string
	Member   map[int]bool
	Untagged map[int]bool
}

// PoeSim is one PoE port: RFC 3621 admin/detect state plus vendor delivered
// power. Detect is the raw RFC3621 pethPsePortDetectionStatus wire int
// (1=disabled/unused, 2=searching, 3=deliveringPower, ...), not the
// higher-level model.PoEDetect enum.
type PoeSim struct {
	Admin   bool
	Detect  int
	PowerMw int
}

// SensorSim is one box sensor reading (fan RPM / PSU watts / temperature).
// Raw is the literal wire text: either a decimal integer string or
// Netgear's "Not Supported" placeholder for an unpopulated slot.
type SensorSim struct {
	Kind     string // "fan" | "power" | "temperature"
	Instance string
	Raw      string
}

// EntitySim is one ENTITY-MIB entPhysicalTable component (index plus
// class/name/descr). Used only by models whose SNMP agent exposes fan/PSU
// inventory via the standard ENTITY-MIB instead of a Netgear vendor column
// (verified: GS728TPP). PhysClass is the entPhysicalClass int enum
// (6=powerSupply, 7=fan). No live value/status on the wire -- inventory
// only.
type EntitySim struct {
	Index     int
	PhysClass int
	Name      string
	Descr     string
}

// MacSim is one learned MAC/FDB entry.
type MacSim struct {
	Vlan       int
	MacBytes   [6]byte
	BridgePort int
}

// LldpSim is one lldpRemTable neighbour row group.
type LldpSim struct {
	TimeMark  int
	LocalPort int
	RemIdx    int
	Chassis   string
	PortID    string
	PortDesc  string
	SysName   string
}

// MgmtSim is the switch's own management-IP configuration. Mode is
// "static" | "dhcp".
type MgmtSim struct {
	Address string
	Netmask string
	Gateway string
	Mode    string
}

// ScpCopy is one (source_url, dest) pair of an SCP cert-deploy copy
// command, part of ScpCertDeploySim.
type ScpCopy struct {
	Source string
	Dest   string
}

// ScpCertDeploySim records a FASTPATH "copy scp://" SSL-cert deploy the mock
// CLI face received. Purely a record of the EXEC sequence the library
// issued -- not part of any SNMP/NSDP/HTTP projection; CLI/HTTP-face
// concern only, carried on State for completeness (see State.ScpCertDeploy).
type ScpCertDeploySim struct {
	Commands      []string
	Copies        []ScpCopy
	HTTPSDisabled bool
	HTTPSEnabled  bool
	Saved         bool
}

// State is the one authoritative in-memory virtual-switch device state. A
// mutable holder (ApplyWrite mutates it to simulate an SNMP SET); pure data
// plus the OIDMap SNMP projection, no network here.
type State struct {
	ModelKey         string
	Ports            map[int]*PortSim
	Vlans            map[int]*VlanSim
	Pvids            map[int]int
	Poe              map[int]*PoeSim
	Sensors          []SensorSim
	HTTPSensors      []SensorSim
	EntityComponents []EntitySim
	Macs             []MacSim
	BridgePorts      map[int]int
	Lldp             []LldpSim
	Mgmt             MgmtSim

	ModelName    string
	Serial       string
	Firmware     string
	Hostname     string
	NsdpPassword string
	NsdpMac      [6]byte

	SysDescr          string
	SysObjectID       string
	Dot1dBaseMacASCII bool

	// NSDP-extra fields (D-VIRT §1.3), nil-able/unseeded semantics
	// mirroring the Python dataclass exactly. NOT consumed by anything in
	// this slice: the NsdpTlvs()/ApplyNsdpWrite() methods that project and
	// mutate these fields are slice-05 scope (protocols/nsdp face work) --
	// these fields exist here now purely so State's shape is complete and
	// later slices don't need to touch this struct's field list again.
	NsdpQosEngine            *int
	NsdpPortMirroringDest    *int
	NsdpPortMirroringSources map[int]bool
	NsdpIgmpSnoopingEnabled  *bool
	NsdpIgmpSnoopingVlan     *int
	NsdpBroadcastFiltering   *bool
	NsdpLoopDetection        *bool

	// HTTP/CLI-only fields -- not part of any SNMP/NSDP projection, carried
	// here for completeness only (see ScpCertDeploySim doc comment above).
	UploadedCert  *string
	ScpCertDeploy *ScpCertDeploySim
}

// NewState builds a blank-but-valid State for modelKey, with the same
// defaults as the Python dataclass: NsdpPassword "password", NsdpMac
// 28:c6:8e:00:00:01, and Mgmt 0.0.0.0/dhcp (an unconfigured static-IP-less
// device). Every map/slice field starts non-nil and empty.
func NewState(modelKey string) *State {
	return &State{
		ModelKey:         modelKey,
		Ports:            map[int]*PortSim{},
		Vlans:            map[int]*VlanSim{},
		Pvids:            map[int]int{},
		Poe:              map[int]*PoeSim{},
		Sensors:          []SensorSim{},
		EntityComponents: []EntitySim{},
		Macs:             []MacSim{},
		BridgePorts:      map[int]int{},
		Lldp:             []LldpSim{},
		Mgmt: MgmtSim{
			Address: "0.0.0.0",
			Netmask: "0.0.0.0",
			Gateway: "0.0.0.0",
			Mode:    "dhcp",
		},
		NsdpPassword:             "password",
		NsdpMac:                  [6]byte{0x28, 0xc6, 0x8e, 0x00, 0x00, 0x01},
		NsdpPortMirroringSources: map[int]bool{},
	}
}

// SysinfoSensors returns the sensor set the HTTP sysInfo page renders:
// HTTPSensors when a model's web UI exposes a different sensor set than
// SNMP (e.g. gsm7252ps), else Sensors, so a model whose two faces agree
// (M4300) is unchanged. Mirrors the Python sysinfo_sensors property.
func (s *State) SysinfoSensors() []SensorSim {
	if s.HTTPSensors == nil {
		return s.Sensors
	}
	return s.HTTPSensors
}

// Snapshot deep-copies this state, for atomic multi-varbind SET rollback.
//
// A single SNMP SET PDU can carry several varbinds (e.g. a VLAN-membership
// write touching both the egress AND untagged bitmaps in one call) and a
// real agent guarantees they apply all-or-nothing: the (later-slice) face
// snapshots the state before applying a PDU's varbinds and calls Restore on
// this snapshot if any of them fails, so a partial mutation is never
// observable. Every map/slice/pointer field is deep-copied by hand here (no
// gob/reflection) -- see Restore.
func (s *State) Snapshot() *State {
	cp := &State{
		ModelKey:                 s.ModelKey,
		Ports:                    clonePortsMap(s.Ports),
		Vlans:                    cloneVlansMap(s.Vlans),
		Pvids:                    cloneIntIntMap(s.Pvids),
		Poe:                      clonePoeMap(s.Poe),
		Sensors:                  cloneSensorSlice(s.Sensors),
		HTTPSensors:              cloneSensorSliceNilable(s.HTTPSensors),
		EntityComponents:         cloneEntitySlice(s.EntityComponents),
		Macs:                     cloneMacSlice(s.Macs),
		BridgePorts:              cloneIntIntMap(s.BridgePorts),
		Lldp:                     cloneLldpSlice(s.Lldp),
		Mgmt:                     s.Mgmt,
		ModelName:                s.ModelName,
		Serial:                   s.Serial,
		Firmware:                 s.Firmware,
		Hostname:                 s.Hostname,
		NsdpPassword:             s.NsdpPassword,
		NsdpMac:                  s.NsdpMac,
		SysDescr:                 s.SysDescr,
		SysObjectID:              s.SysObjectID,
		Dot1dBaseMacASCII:        s.Dot1dBaseMacASCII,
		NsdpQosEngine:            cloneIntPtr(s.NsdpQosEngine),
		NsdpPortMirroringDest:    cloneIntPtr(s.NsdpPortMirroringDest),
		NsdpPortMirroringSources: cloneIntBoolMap(s.NsdpPortMirroringSources),
		NsdpIgmpSnoopingEnabled:  cloneBoolPtr(s.NsdpIgmpSnoopingEnabled),
		NsdpIgmpSnoopingVlan:     cloneIntPtr(s.NsdpIgmpSnoopingVlan),
		NsdpBroadcastFiltering:   cloneBoolPtr(s.NsdpBroadcastFiltering),
		NsdpLoopDetection:        cloneBoolPtr(s.NsdpLoopDetection),
		UploadedCert:             cloneStringPtr(s.UploadedCert),
		ScpCertDeploy:            cloneScpCertDeploy(s.ScpCertDeploy),
	}
	return cp
}

// Restore restores this state in place from a prior Snapshot result.
//
// This copies every field from snap onto *s (a single struct assignment)
// rather than replacing s itself, so existing holders of this exact *State
// pointer keep seeing the restored data -- the critical porting detail from
// the Python reference's restore(), which sets attributes on self rather
// than reassigning the variable holding it. Safe because Snapshot deep-
// copied every map/slice/pointer field: after this assignment s's fields
// alias snap's already-independent data, never anything still shared with
// whatever was mutated between Snapshot and Restore.
func (s *State) Restore(snap *State) {
	*s = *snap
}

func clonePortsMap(in map[int]*PortSim) map[int]*PortSim {
	if in == nil {
		return nil
	}
	out := make(map[int]*PortSim, len(in))
	for k, v := range in {
		cp := *v
		cp.RxOctets = cloneUint64Ptr(v.RxOctets)
		cp.TxOctets = cloneUint64Ptr(v.TxOctets)
		cp.RxUcast = cloneUint64Ptr(v.RxUcast)
		cp.TxUcast = cloneUint64Ptr(v.TxUcast)
		cp.RxErrors = cloneUint64Ptr(v.RxErrors)
		cp.TxErrors = cloneUint64Ptr(v.TxErrors)
		cp.Description = cloneStringPtr(v.Description)
		out[k] = &cp
	}
	return out
}

func cloneVlansMap(in map[int]*VlanSim) map[int]*VlanSim {
	if in == nil {
		return nil
	}
	out := make(map[int]*VlanSim, len(in))
	for k, v := range in {
		out[k] = &VlanSim{
			Name:     v.Name,
			Member:   cloneIntBoolMap(v.Member),
			Untagged: cloneIntBoolMap(v.Untagged),
		}
	}
	return out
}

func clonePoeMap(in map[int]*PoeSim) map[int]*PoeSim {
	if in == nil {
		return nil
	}
	out := make(map[int]*PoeSim, len(in))
	for k, v := range in {
		cp := *v
		out[k] = &cp
	}
	return out
}

func cloneSensorSlice(in []SensorSim) []SensorSim {
	if in == nil {
		return nil
	}
	out := make([]SensorSim, len(in))
	copy(out, in)
	return out
}

// cloneSensorSliceNilable is identical to cloneSensorSlice; named
// separately for HTTPSensors to make the None-vs-empty-list significance
// (see State.HTTPSensors doc) explicit at each call site.
func cloneSensorSliceNilable(in []SensorSim) []SensorSim {
	return cloneSensorSlice(in)
}

func cloneEntitySlice(in []EntitySim) []EntitySim {
	if in == nil {
		return nil
	}
	out := make([]EntitySim, len(in))
	copy(out, in)
	return out
}

func cloneMacSlice(in []MacSim) []MacSim {
	if in == nil {
		return nil
	}
	out := make([]MacSim, len(in))
	copy(out, in)
	return out
}

func cloneLldpSlice(in []LldpSim) []LldpSim {
	if in == nil {
		return nil
	}
	out := make([]LldpSim, len(in))
	copy(out, in)
	return out
}

func cloneIntIntMap(in map[int]int) map[int]int {
	if in == nil {
		return nil
	}
	out := make(map[int]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneIntBoolMap(in map[int]bool) map[int]bool {
	if in == nil {
		return nil
	}
	out := make(map[int]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneUint64Ptr(p *uint64) *uint64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneStringPtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneScpCertDeploy(in *ScpCertDeploySim) *ScpCertDeploySim {
	if in == nil {
		return nil
	}
	return &ScpCertDeploySim{
		Commands:      append([]string(nil), in.Commands...),
		Copies:        append([]ScpCopy(nil), in.Copies...),
		HTTPSDisabled: in.HTTPSDisabled,
		HTTPSEnabled:  in.HTTPSEnabled,
		Saved:         in.Saved,
	}
}
