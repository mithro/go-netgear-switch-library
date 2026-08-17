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

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/mithro/go-netgear-switch-library/nsdp"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

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
	// SwitchportMode is the FASTPATH CLI-only "switchport mode
	// access|general|trunk" running-config value (slice-07, ported from
	// Python PortSim.switchport_mode: str = "general", state.py:143), which
	// gates whether a per-port `vlan participation`/`vlan tagging`/`vlan
	// pvid` CLI write actually takes effect (see virtual/cliface.go's
	// general() gate) -- live-proven on an M4300-24X: those commands are
	// ACCEPTED but INERT while the port is in "switchport mode access".
	// NOT part of any SNMP/NSDP/HTTP projection: no captured MIB/TLV/web
	// page exposes it.
	//
	// Go has no per-field struct-literal defaults, unlike Python's
	// dataclass default, and every seed in this package builds its (very
	// large) port tables via bare struct literals rather than NewPortSim
	// (see seed.go's own doc comment), so this field's Go zero value ""
	// deliberately stands in for "not yet explicitly configured over CLI"
	// on every existing seed, rather than requiring every port literal in
	// every seed to spell out `SwitchportMode: "general"`. cliface.go's
	// general() gate treats "" the same as an explicit "general" UNLESS
	// the model/port has a measured VlanMembershipLockedPorts entry
	// documenting it as access/trunk instead (e.g. every M4300-24X port,
	// live-proven -- see that field's own seed.go doc comment): the SAME
	// underlying live finding, observed over the HTTP VLAN-membership page
	// there and over the CLI here. Once this face executes an explicit
	// "switchport mode <mode>" command, this field holds that literal
	// mode string ("access"/"general"/"trunk") and takes precedence over
	// both defaults.
	SwitchportMode string
	// Description is ifAlias. nil means this port's ifAlias column instance
	// is entirely absent (never configured) -- never a fabricated "".
	Description *string
	// FlowControl is IEEE 802.3x flow control, as reported in the FASTPATH
	// CLI's "Flow Mode" column and the GoAhead web UI's flowControlOperType/
	// flowControlAdminType. Zero value (false) matches every model this
	// field currently drives: MEASURED False on all 28 GS728TPP ports
	// (2026-08-03, both the SNMP dot3PauseOperMode walk and the GoAhead wcd
	// page agreed) and False in every captured `show port all` Flow Mode
	// column (gsm7252ps/gsm7228ps/m4300-16x/m4300-24x) -- so no seed needs
	// to set this explicitly today; a future seed with a measured True port
	// sets it directly.
	FlowControl bool
	// ServesEtherlike reports whether this model's SNMP agent publishes the
	// EtherLike-MIB dot3StatsDuplexStatus/dot3Pause{Admin,Oper}Mode columns
	// for this interface. Per-model, MEASURED 2026-08-03: the GS728TPP
	// serves them for all 28 physical ports; the GSM7252PS's dot3StatsTable
	// stops at column 16 (no 19) and its dot3PauseTable serves only the
	// counters, not AdminMode/OperMode. Default false so no model's mock
	// gains an OID its hardware was never observed to answer -- a seed
	// opts in. Where false, SNMP GetPorts reports FullDuplex/FlowControl as
	// nil, the honest reading of an absent column.
	ServesEtherlike bool
	// PhysicalMode is the FASTPATH CLI's "Physical Mode" column raw text --
	// the port's CONFIGURED speed/duplex, as opposed to Speed/Link above
	// (the NEGOTIATED rate the "Physical Status" column reports). Kept as
	// raw device text, like SwitchportMode, so the mock does not re-derive
	// the cell with the same helper the parser uses. Empty string (the Go
	// zero value) is treated as "Auto" by the CLI renderer -- "Auto" is
	// what every real port on every switch captured here reports, so no
	// seed needs to set this explicitly today.
	PhysicalMode string
	// AutonegAdmin/SpeedAdmin/DuplexAdminMode are the GoAhead web UI's own
	// three-field encoding of the SAME configured speed/duplex PhysicalMode
	// carries for the CLI -- kept as separate raw fields, for the same
	// "don't re-derive what the parser decodes" reason. Wire codes: 1 =
	// negotiating, 2 = forced (autoneg); 2 = half, 3 = full (duplex). Empty
	// string defaults to "1"/"1000"/"3" respectively -- what the live
	// GS728TPP (10.2.5.10, firmware 6.0.1.30) returned for EVERY port
	// (2026-08-03): autoneg 1 with speedAdmin 1000 sitting beside it
	// (meaningful only while autoneg is 2). No FASTPATH model serves these
	// fields and no GoAhead model serves PhysicalMode, so the two never
	// disagree on one device.
	AutonegAdmin    string
	SpeedAdmin      string
	DuplexAdminMode string
}

// physicalMode returns sim.PhysicalMode, defaulting to "Auto" when unset
// (the Go zero value), mirroring PortSim.physical_mode's Python dataclass
// default.
func (sim *PortSim) physicalMode() string {
	if sim.PhysicalMode == "" {
		return "Auto"
	}
	return sim.PhysicalMode
}

// autonegAdmin/speedAdmin/duplexAdminMode return the GoAhead raw wire
// fields, defaulting to the live GS728TPP's own per-port defaults
// ("1"/"1000"/"3") when unset -- mirroring PortSim's Python dataclass
// defaults (autoneg_admin/speed_admin/duplex_admin_mode).
func (sim *PortSim) autonegAdmin() string {
	if sim.AutonegAdmin == "" {
		return "1"
	}
	return sim.AutonegAdmin
}

func (sim *PortSim) speedAdmin() string {
	if sim.SpeedAdmin == "" {
		return "1000"
	}
	return sim.SpeedAdmin
}

func (sim *PortSim) duplexAdminMode() string {
	if sim.DuplexAdminMode == "" {
		return "3"
	}
	return sim.DuplexAdminMode
}

// NewPortSim builds a PortSim with the physical-port default IfType (6 =
// ethernetCsmacd). Non-physical rows (LAGs, CPU, VLAN interfaces) must set
// IfType explicitly after construction.
func NewPortSim(name string, admin, link bool, speed int) *PortSim {
	return &PortSim{Name: name, Admin: admin, Link: link, Speed: speed, IfType: 6, SwitchportMode: "general"}
}

// VlanSim is one dot1q VLAN: display name plus egress-member and untagged
// port sets. Member/Untagged represent sets: a port is a member iff its map
// value is true (see sliceFromPortSet, snmp.EncodePortBitmap).
type VlanSim struct {
	Name     string
	Member   map[int]bool
	Untagged map[int]bool
	// ConfiguredOnly is the set of ports CONFIGURED into this VLAN but NOT
	// currently participating -- ``show vlan`` prints them as "Current:
	// Exclude / Configured: Include". A REAL, MEASURED divergence, not a
	// theoretical one: on GSM7252PS @10.1.5.22, VLAN 1 lists ports 1/0/50
	// and 1/0/51 exactly that way, so the switch reports them in
	// dot1qVlanStaticEgressPorts (the STATIC/configured table) and in the
	// web UI's hiddenMem grid, while omitting them from the CLI's current
	// list, from vlanStatus.html and from hiddenTagged/hiddenUnTagged.
	// Keeping the two views separate is what lets the mock reproduce that
	// split -- collapsing them would make the mock's SNMP and HTTP faces
	// agree with each other while both disagree with hardware. Empty (the
	// default) = configured and current coincide, the normal case. Mirrors
	// Python VlanSim.configured_only.
	ConfiguredOnly map[int]bool
	// NoStaticRow is true when this VLAN has NO dot1qVlanStaticTable row at
	// all -- present only in dot1qVlanCurrentTable. Mirrors Python
	// VlanSim.static_row, INVERTED (Python defaults True; Go's bool zero
	// value is false) so the Go zero value is the normal case and every
	// existing seed is unaffected without touching it.
	//
	// MEASURED on the GS728TPP (sw-netgear-gs728tpp.monarto.mithis.com /
	// 10.2.5.10, firmware 6.0.1.30, 2026-08-02): its default VLAN 1 does
	// NOT have one. A walk of dot1qVlanStaticName/Egress/Untagged/
	// RowStatus returns exactly 12 rows -- ids 2,3,4,5,6,7,10,20,31,41,90,99
	// -- while dot1qVlanCurrentTable returns 13, the extra one being VLAN 1
	// with dot1qVlanStatus = 1 (other) where every other VLAN reads 2
	// (permanent). The web UI lists VLAN 1, so a reader that consults only
	// the static table loses it; see snmp.ParseVlans, which reads both
	// tables because of this.
	//
	// False (the default) is itself measured as the normal case: the
	// GSM7252PS, both M4300s and the S3300-52X all publish a static VLAN 1
	// row.
	NoStaticRow bool
}

// Configured returns the CONFIGURED egress set: current members plus
// ConfiguredOnly, mirroring Python VlanSim.configured (a computed
// property there; a method here since Go has no property syntax).
func (v *VlanSim) Configured() map[int]bool {
	out := make(map[int]bool, len(v.Member)+len(v.ConfiguredOnly))
	for p := range v.Member {
		out[p] = true
	}
	for p := range v.ConfiguredOnly {
		out[p] = true
	}
	return out
}

// PoeSim is one PoE port: RFC 3621 admin/detect state plus vendor delivered
// power. Detect is the raw RFC3621 pethPsePortDetectionStatus wire int
// (1=disabled/unused, 2=searching, 3=deliveringPower, ...), not the
// higher-level model.PoEDetect enum.
type PoeSim struct {
	Admin   bool
	Detect  int
	PowerMw int
	// CliStatusLagReads is how many more CLI `show poe port info all` reads
	// still report the pre-enable "Disabled" status after PoE was
	// administratively re-enabled, ported from Python PoeSim's
	// cli_status_lag_reads: int = 0 (state.py:253).
	//
	// MEASURED ON HARDWARE (M4300-16X, 10.1.5.20, FASTPATH 12.0.19.15,
	// 2026-07-30): right after `poe` re-enabled port 1/0/1 the table still
	// said "Disabled"; the same port read "Searching" moments later. That
	// column is a DETECTION state, and it lags the admin write -- which
	// made a single immediate read-back report a perfectly good SetPoE as
	// a verification failure. The mock reproduces the lag (one stale read)
	// so fastpath.Writer.SetPoE's polling is actually exercised instead of
	// passing by accident; SNMP's pethPsePortAdminEnable has no such lag
	// and is deliberately unaffected. Consumed (and decremented) by
	// cliPoeStatusText in cliface_render.go; set by CliFace.applyPoeAdmin
	// on an off->on transition.
	CliStatusLagReads int
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

// UserSim is one local login account, as the switch's own pages/CLI word
// it, mirroring Python's UserSim dataclass (state.py:212-230) plus one
// field Python's fake does not yet have.
//
// HTTPAccessMode is stored VERBATIM rather than derived from a privilege
// flag, because the same account is worded DIFFERENTLY depending on which
// face is asked -- measured on 10.1.5.22 and 10.1.5.13, where admin reads
// "Super User" on userManagement.html but "Read/Write" and "Privilege-15"
// respectively through each switch's own `show users`. A mock that stored
// one level and rendered it per face would be inventing the wording;
// storing what each page really emits means the reader's own word-to-
// privilege mapping is what gets exercised.
//
// CLIAccessMode extends beyond the pinned Python source (pin b26eb1f):
// Python's own state.py docstring for this type says "The CLI face has no
// `show users` yet. When it gains one it needs its own field here, NOT this
// one: the two faces genuinely disagree" -- i.e. Python has never built the
// CLI `show users` virtual-fake renderer this slice's task explicitly
// requires, so there is no existing Go-side Python field to port for it.
// The VALUES below are still measured, not invented: Python commit 4619e3c
// ("feat(cli): read the switch's local user accounts") records the
// live-verified table this field's seed values are transcribed from --
//
//	m4300-24x  admin=Privilege-15  guest=Privilege-1
//	gsm7252ps  admin=Read/Write    guest=Read Only
//
// -- but that commit message is prose, not a checked-in fixture file or a
// Python fake seed, so per this project's principle 5 this is flagged
// explicitly here rather than silently claimed as "ported from Python's
// fake" the way HTTPAccessMode is.
type UserSim struct {
	Name           string
	HTTPAccessMode string
	CLIAccessMode  string
	// SNMPv3Access/SNMPv3Auth/SNMPv3Encryption are the three SNMPv3 columns
	// `show users` also carries. "" (the default, for every row but one --
	// see SeedM4300_24X) means unmeasured, rendered as a blank cell rather
	// than a guess: only ONE row anywhere in the pinned Python source has a
	// measured value here (parse_users' own docstring transcript, which is
	// m4300-24x's admin row).
	SNMPv3Access     string
	SNMPv3Auth       string
	SNMPv3Encryption string
}

// ServiceSim is one management service's admin state, as its own config
// page / CLI show command reports it, mirroring Python's ServiceSim
// dataclass (state.py:233-245) plus one field Python's fake does not yet
// have.
//
// Port is nil where the HTTP config page carries NO port field -- which is
// a real per-page difference, not a gap in the mock: the m4300 SSH page
// publishes v_1_10_1="22" while the gsm7252ps SSH page has no such
// coordinate at all (measured 2026-08-03). Seeding 22 there would make the
// fake claim a field the device does not print.
//
// CLIPort extends beyond the pinned Python source, for the same reason
// UserSim.CLIAccessMode does: Python's virtual CLI face has no `show ip
// http`/`show telnetcon`/`show ip ssh` renderer at this pin, only
// HTTP-page ServiceSim values. The port VALUES here are still measured,
// via Python commit 2c7ddff ("feat(cli): read which management services
// are enabled")'s live-verified table --
//
//	m4300-24x  http=on:80    https=on:443  telnet=on:23   ssh=on:22
//	gsm7252ps  http=on:None  https=on:443  telnet=off     ssh=on:None
//
// -- prose in a commit message, not a fixture file; flagged per principle 5
// the same way CLIAccessMode is. Enabled state is NOT duplicated per face:
// every measured case has the CLI and HTTP page agreeing on admin state
// ("HTTP<->CLI agree exactly" / "agreeing on every state"), so ServiceSim
// carries one Enabled field for both.
type ServiceSim struct {
	Enabled bool
	Port    *int
	CLIPort *int
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

// VlanMembershipPageSim records the MEASURED byte-shape of one managed
// FASTPATH model's "VLAN Membership" page (dossier D-HTTP-F §5.2), mirroring
// Python's VlanMembershipPageSim dataclass. Populated only by the four
// managed models' Seed*() functions (gsm7252ps, gsm7228ps, m4300-24x,
// m4300-16x) -- State.VlanMembershipPage stays nil for every other model
// (every Plus-class/GoAhead model has no such page at all). Consumed by the
// (slice-06 Task 9/10) FASTPATH VLAN-membership renderer, not by anything in
// this slice's Task 8 HTTP-face skeleton.
type VlanMembershipPageSim struct {
	// Slots is the page's hiddenMem/hiddenTagged/hiddenUnTagged grid width in
	// slots (physical ports plus trailing LAG pseudo-interfaces) -- a
	// hardware-fixed constant PER MODEL, wider than the port count.
	Slots int
	// LagSlot is the 1-based slot number the first LAG pseudo-interface
	// occupies (LAG slots run from here through Slots).
	LagSlot int
	// Grid is which firmware-generation rendering variant this model's page
	// uses: "gif" (older XE, gsm7252ps -- toggleImageFirst()/grey_[btu].gif,
	// 0-based hiddenMem index) or "png" (newer jQuery, gsm7228ps/both
	// M4300s -- togImg()/switch_*.png, 1-based index).
	Grid string
	// TrailingComma is whether this model's hiddenMem/hiddenTagged/
	// hiddenUnTagged strings carry a trailing comma.
	TrailingComma bool
	// CSRF is whether this model's page requires its own per-page CSRF token
	// (the "virtualcsrf" literal, D-HTTP-F §4.1 -- a THIRD distinct CSRF-shaped
	// constant from web.py's "virtualhash" and gs105pe's "18007") riding
	// along on every apply.
	CSRF bool
	// Escape is whether this model's page HTML-escapes ifNames in the
	// rendered grid (e.g. "1/0/1" -> "1&#x2F;0&#x2F;1").
	Escape bool
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

	// Users/Services back GetUsers/GetServices, mirroring Python's
	// VirtualSwitchState.users: list[UserSim] = field(default_factory=list)
	// / .services: dict[str, ServiceSim] = field(default_factory=dict)
	// (state.py:525/529). Populated only by SeedGSM7252PS/SeedM4300_24X --
	// see those functions' own doc comments for exactly why not the other
	// managed-model seeds. Services is keyed "http"/"https"/"ssh"/"telnet".
	Users    []UserSim
	Services map[string]ServiceSim

	ModelName    string
	Serial       string
	Firmware     string
	Hostname     string
	NsdpPassword string
	NsdpMac      [6]byte
	// NsdpAuthV2, when true, makes a fake serving this state require NSDP v2
	// salted write auth (AUTH_V2_ENCPASS reads 0x10; AUTH_V2_SALT is a rotating
	// readable challenge; AUTH_V2_PASSWORD is a write-only token) instead of v1
	// XOR -- LIVE-MEASURED on a GS110EMX (fw 1.0.2.8). The rotating salt itself
	// is transient per-connection challenge state, so it lives on NsdpFace, not
	// here (Snapshot copies logical switch state, not a serving session).
	NsdpAuthV2 bool

	SysDescr          string
	SysObjectID       string
	Dot1dBaseMacASCII bool

	// VLANPortListWidth is the model's REAL, live-measured wire byte-width
	// of dot1qVlanStaticEgressPorts/UntaggedPorts (D-REC Topic B), nil when
	// unmeasured. A Netgear switch's Q-BRIDGE PortList covers LAG and CPU
	// pseudo-ports too, so its width is a hardware-fixed constant wider
	// than max(8, ceil(port_count/8)) -- e.g. GSM7252PS = 79 bytes,
	// GSM7228PS = 45, both M4300s = 131 (see the four managed seeds).
	// OIDMap prefers this field over snmp.VlanBitmapWidth(port_count) so
	// the mock is an INDEPENDENT source of truth for the wire width, not a
	// re-derivation of the writer's own formula -- the whole point being
	// that a mock sharing the writer's formula can never catch the writer
	// re-encoding a bitmap at the wrong width (the historical bug this
	// field exists to trap). nil (Plus-class models, gs728tpp) falls back
	// to the formula. Ported from Python's State.vlan_portlist_width.
	VLANPortListWidth *int

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

	// VlanMembershipPage/VlanMembershipLockedPorts are the FASTPATH "VLAN
	// Membership" page's state (D-HTTP-F §5.2) -- see VlanMembershipPageSim's
	// doc comment. VlanMembershipLockedPorts is the PER-PORT set of ports
	// whose switchport mode (access/trunk) makes this model's firmware
	// refuse an explicit VLAN-membership apply over HTTP, returning HTTP 200
	// with err_flag=1 rather than applying -- empty (the default) means
	// every port on this model accepts the apply. Only m4300-24x's seed
	// populates this (every port on that live-captured unit is
	// access/trunk); m4300-16x's ports 1-8 have no switchport mode line at
	// all, so its seed leaves this empty, letting the apply succeed there --
	// a deliberate live counter-example pair, not an oversight.
	VlanMembershipPage        *VlanMembershipPageSim
	VlanMembershipLockedPorts map[int]bool

	// Reboots is the number of reboots requested through a protocol face
	// (slice-07: the FASTPATH CLI's "reload", virtual/cliface.go's
	// RunWriteMemory), ported from Python's VirtualSwitchState.reboots: int
	// = 0 (state.py:448). A reload cannot actually restart this mock, so
	// this counter is the only observable record that the request was
	// issued -- not part of any SNMP/NSDP/HTTP projection.
	Reboots int
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
		Users:                     []UserSim{},
		Services:                  map[string]ServiceSim{},
		NsdpPassword:              "password",
		NsdpMac:                   [6]byte{0x28, 0xc6, 0x8e, 0x00, 0x00, 0x01},
		NsdpPortMirroringSources:  map[int]bool{},
		VlanMembershipLockedPorts: map[int]bool{},
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
		ModelKey:                  s.ModelKey,
		Ports:                     clonePortsMap(s.Ports),
		Vlans:                     cloneVlansMap(s.Vlans),
		Pvids:                     cloneIntIntMap(s.Pvids),
		Poe:                       clonePoeMap(s.Poe),
		Sensors:                   cloneSensorSlice(s.Sensors),
		HTTPSensors:               cloneSensorSliceNilable(s.HTTPSensors),
		EntityComponents:          cloneEntitySlice(s.EntityComponents),
		Macs:                      cloneMacSlice(s.Macs),
		BridgePorts:               cloneIntIntMap(s.BridgePorts),
		Lldp:                      cloneLldpSlice(s.Lldp),
		Mgmt:                      s.Mgmt,
		Users:                     cloneUsersSlice(s.Users),
		Services:                  cloneServicesMap(s.Services),
		ModelName:                 s.ModelName,
		Serial:                    s.Serial,
		Firmware:                  s.Firmware,
		Hostname:                  s.Hostname,
		NsdpPassword:              s.NsdpPassword,
		NsdpMac:                   s.NsdpMac,
		NsdpAuthV2:                s.NsdpAuthV2,
		SysDescr:                  s.SysDescr,
		SysObjectID:               s.SysObjectID,
		Dot1dBaseMacASCII:         s.Dot1dBaseMacASCII,
		VLANPortListWidth:         cloneIntPtr(s.VLANPortListWidth),
		NsdpQosEngine:             cloneIntPtr(s.NsdpQosEngine),
		NsdpPortMirroringDest:     cloneIntPtr(s.NsdpPortMirroringDest),
		NsdpPortMirroringSources:  cloneIntBoolMap(s.NsdpPortMirroringSources),
		NsdpIgmpSnoopingEnabled:   cloneBoolPtr(s.NsdpIgmpSnoopingEnabled),
		NsdpIgmpSnoopingVlan:      cloneIntPtr(s.NsdpIgmpSnoopingVlan),
		NsdpBroadcastFiltering:    cloneBoolPtr(s.NsdpBroadcastFiltering),
		NsdpLoopDetection:         cloneBoolPtr(s.NsdpLoopDetection),
		UploadedCert:              cloneStringPtr(s.UploadedCert),
		ScpCertDeploy:             cloneScpCertDeploy(s.ScpCertDeploy),
		VlanMembershipPage:        cloneVlanMembershipPage(s.VlanMembershipPage),
		VlanMembershipLockedPorts: cloneIntBoolMap(s.VlanMembershipLockedPorts),
		Reboots:                   s.Reboots,
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
			Name:           v.Name,
			Member:         cloneIntBoolMap(v.Member),
			Untagged:       cloneIntBoolMap(v.Untagged),
			ConfiguredOnly: cloneIntBoolMap(v.ConfiguredOnly),
			NoStaticRow:    v.NoStaticRow,
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

// cloneUsersSlice copies in element-by-element: UserSim carries only plain
// strings, so a shallow slice copy is already a deep copy.
func cloneUsersSlice(in []UserSim) []UserSim {
	if in == nil {
		return nil
	}
	out := make([]UserSim, len(in))
	copy(out, in)
	return out
}

// cloneServicesMap deep-copies in, including each ServiceSim's Port/CLIPort
// pointers -- a shallow map copy would leave the clone's *int fields
// aliasing the original's, which Restore's whole-struct assignment (see its
// own doc comment) requires NOT to happen.
func cloneServicesMap(in map[string]ServiceSim) map[string]ServiceSim {
	if in == nil {
		return nil
	}
	out := make(map[string]ServiceSim, len(in))
	for k, v := range in {
		v.Port = cloneIntPtr(v.Port)
		v.CLIPort = cloneIntPtr(v.CLIPort)
		out[k] = v
	}
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

func cloneVlanMembershipPage(in *VlanMembershipPageSim) *VlanMembershipPageSim {
	if in == nil {
		return nil
	}
	cp := *in
	return &cp
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

// --- ApplyWrite / IsWritableOID: device-coherence write rules ----------
//
// D-VIRT §1.7/§1.8. ApplyWrite dispatches on the OID's column prefix (first
// match wins, each branch returns); an unhandled writable OID is a
// deliberate silent no-op -- the write "succeeds" but reads back unchanged,
// which is exactly what a verify-after-write must catch. IsWritableOID
// mirrors the same dispatch prefixes on purpose (single set of column
// constants from package snmp) but is a separate, stricter gate: a
// (later-slice) SNMP face uses it to reject a SET on a genuinely unknown/
// read-only OID with a proper SNMP notWritable error, before the
// always-succeeding ApplyWrite would silently allow it.

// columnTail returns the int suffix of oid if oid starts with base+"." and
// the remainder is all ASCII digits, mirroring the Python reference's
// `_tail` closure.
func columnTail(base, oid string) (int, bool) {
	prefix := base + "."
	if !strings.HasPrefix(oid, prefix) {
		return 0, false
	}
	rest := oid[len(prefix):]
	if !isAllDigits(rest) {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	return n, true
}

// isAllDigits reports whether s is non-empty and consists entirely of ASCII
// digits, mirroring Python's str.isdigit() as used to validate a column
// index suffix. Deliberately rejects a leading '-' (a column index is
// never signed).
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

// isPoeAdminColumn reports whether oid is a
// pethPsePortAdminEnable = PethPsePortTable.3.1.<port> instance, returning
// the port number when it is.
func isPoeAdminColumn(oid string) (int, bool) {
	prefix := snmp.PethPsePortTable + ".3.1."
	if !strings.HasPrefix(oid, prefix) {
		return 0, false
	}
	rest := oid[len(prefix):]
	if !isAllDigits(rest) {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	return n, true
}

// mustInt converts an ApplyWrite value to int, mirroring Python's
// permissive int(value) on the int/str union this method accepts for every
// integer-valued column.
//
// Deliberately does NOT accept []byte, even a single-byte slice that looks
// superficially int-convertible: Python's int(value) raises TypeError for a
// bytes argument (int() coerces a numeric str, never a bytes object), so an
// OctetString-typed SET value against an INTEGER-typed column (e.g.
// ifAdminStatus) must fail there too. Panics on this and on any other value
// type no real call site ever passes (a caller bug, not a device
// condition); for the (later-slice) SNMP face this is exactly right, since
// applyUncommitted's recover (snmpface.go) converts the panic into a clean
// wrongValue error status with a full-PDU rollback -- mirroring the Python
// face's behaviour on the same wrong-type SET exactly.
func mustInt(oid string, value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case uint:
		return int(v)
	case uint32:
		return int(v)
	case uint64:
		return int(v)
	case byte: // == uint8
		return int(v)
	case string:
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	panic(fmt.Sprintf("virtual: ApplyWrite(%q): value %v (%T) is not int-convertible", oid, value, value))
}

// asBytes converts an ApplyWrite value to bytes: []byte passes through; a
// Go string is already a raw byte sequence (no latin-1 encode step needed,
// unlike the Python reference); an int becomes a single byte. Mirrors the
// Python reference's `_as_bytes` helper.
func asBytes(oid string, value any) []byte {
	switch v := value.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	case int:
		return []byte{byte(v)}
	default:
		panic(fmt.Sprintf("virtual: ApplyWrite(%q): value %v (%T) is not bytes-convertible", oid, value, value))
	}
}

// asString converts an ApplyWrite value to string for the mgmt-IP/VLAN-name
// write branches: []byte decodes byte-for-byte (Go string IS a byte
// sequence, so this is exact, unlike Python's latin-1 decode step); any
// other value is its default string form (mirrors Python's plain str(value)
// for a non-bytes value).
func asString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprint(v)
	}
}

// portSetFromSlice converts a snmp.DecodePortBitmap-style sorted port slice
// into the map[int]bool set representation VlanSim.Member/Untagged use.
func portSetFromSlice(ports []int) map[int]bool {
	out := make(map[int]bool, len(ports))
	for _, p := range ports {
		out[p] = true
	}
	return out
}

// sliceFromPortSet is portSetFromSlice's inverse: it converts the
// map[int]bool set representation VlanSim.Member/Untagged use into a
// snmp.EncodePortBitmap-style sorted []int, keeping only ports whose map
// value is true (a false-valued or absent key is never a member).
func sliceFromPortSet(ports map[int]bool) []int {
	out := make([]int, 0, len(ports))
	for p, present := range ports {
		if present {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// ApplyWrite mutates this state from one SNMP SET varbind, with device
// coherence. Applies the same coherence a real PoE switch shows so a
// cycle_poe operation (later slice) terminates against the mock: admin off
// -> detect=1 (unused) + data-port link down; admin on -> detect=3
// (delivering). See the section doc comment above for the full dispatch
// contract.
func (s *State) ApplyWrite(oid string, value any) {
	v := resolveVendorOids(s.mustModel())

	// 1. ifAdminStatus.<port>
	if port, ok := columnTail(snmp.IfAdminStatus, oid); ok {
		if p, exists := s.Ports[port]; exists {
			iv := mustInt(oid, value)
			p.Admin = iv == 1
			if iv != 1 {
				p.Link = false
			}
		}
		return
	}

	// 2. ifAlias.<port> -- the per-port description. An EMPTY value clears
	// it, and OIDMap omits the row entirely when Description is nil --
	// which is what makes the reader report nil rather than "". That round
	// trip is the one the live transport could not do until an empty
	// OCTET STRING learned to travel as an empty hex string (see
	// snmp.gosnmp's toOctetBytes, which this mock's own SET path already
	// exercises since it goes through the real gosnmp wire encoding).
	if port, ok := columnTail(snmp.IfAlias, oid); ok {
		if p, exists := s.Ports[port]; exists {
			text := asString(value)
			if text != "" {
				p.Description = &text
			} else {
				p.Description = nil
			}
		}
		return
	}

	// 3. pethPsePortAdminEnable = PethPsePortTable.3.1.<port>
	if port, ok := isPoeAdminColumn(oid); ok {
		if poe, exists := s.Poe[port]; exists {
			on := mustInt(oid, value) == 1
			poe.Admin = on
			if on {
				poe.Detect = 3 // delivering
			} else {
				poe.Detect = 1 // unused/disabled
			}
			if !on {
				if p, exists2 := s.Ports[port]; exists2 {
					p.Link = false
				}
			}
		}
		return
	}

	// 4. dot1qPvid.<port>: no existence check -- creates the entry
	// unconditionally.
	if port, ok := columnTail(snmp.Dot1qPvid, oid); ok {
		s.Pvids[port] = mustInt(oid, value)
		return
	}

	// 5. dot1qVlanStaticEgressPorts.<vid>
	if vid, ok := columnTail(snmp.Dot1qVlanStaticEgress, oid); ok {
		if vl, exists := s.Vlans[vid]; exists {
			vl.Member = portSetFromSlice(snmp.DecodePortBitmap(asBytes(oid, value)))
		}
		return
	}

	// 6. dot1qVlanStaticUntaggedPorts.<vid>
	if vid, ok := columnTail(snmp.Dot1qVlanStaticUntagged, oid); ok {
		if vl, exists := s.Vlans[vid]; exists {
			vl.Untagged = portSetFromSlice(snmp.DecodePortBitmap(asBytes(oid, value)))
		}
		return
	}

	// 7. dot1qVlanStaticRowStatus.<vid> (createAndGo=4 / destroy=6).
	if vid, ok := columnTail(snmp.Dot1qVlanStaticRowStatus, oid); ok {
		iv := mustInt(oid, value)
		switch iv {
		case snmp.RowStatusDestroy:
			delete(s.Vlans, vid)
		case snmp.RowStatusCreateAndGo:
			if _, exists := s.Vlans[vid]; !exists {
				s.Vlans[vid] = &VlanSim{Name: ""}
			}
		}
		return
	}

	// 8. dot1qVlanStaticName.<vid>: a name write alone can create a row
	// too, independent of RowStatus.
	if vid, ok := columnTail(snmp.Dot1qVlanStaticName, oid); ok {
		name := asString(value)
		if vl, exists := s.Vlans[vid]; exists {
			vl.Name = name
		} else {
			s.Vlans[vid] = &VlanSim{Name: name}
		}
		return
	}

	// 9. Vendor mgmt-IP/dhcp-mode writes -- only for a model with a vendor
	// subtree; a no-vendor model (gs728tpp) never advertises or accepts
	// these.
	if v != nil {
		switch oid {
		case v.MgmtWriteAddrUnverified:
			s.Mgmt.Address = asString(value)
			return
		case v.MgmtWriteNetmaskUnverified:
			s.Mgmt.Netmask = asString(value)
			return
		case v.MgmtWriteGatewayUnverified:
			s.Mgmt.Gateway = asString(value)
			return
		}
		if oid == v.DHCPModeUnverified+".0" {
			// 2=static, anything else=dhcp, matching OIDMap's encoding.
			if mustInt(oid, value) == 2 {
				s.Mgmt.Mode = "static"
			} else {
				s.Mgmt.Mode = "dhcp"
			}
			return
		}
	}

	// 10. Unhandled writable OID: deliberate no-op (verify-after-write
	// catches it).
}

// IsWritableOID reports whether oid is one this mock recognizes as
// SNMP-writable. See the section doc comment above for why this is a
// separate, stricter gate than ApplyWrite's own always-succeeding
// dispatch.
func (s *State) IsWritableOID(oid string) bool {
	v := resolveVendorOids(s.mustModel())

	if _, ok := columnTail(snmp.IfAdminStatus, oid); ok {
		return true
	}
	// ifAlias, the standard per-port description column. WRITABLE on real
	// hardware: confirmed on a GS728TPP (10.2.5.10, firmware 6.0.1.30,
	// 2026-08-03) -- a SET was accepted and read straight back through
	// GetPorts, and an empty value cleared it again.
	if _, ok := columnTail(snmp.IfAlias, oid); ok {
		return true
	}
	if _, ok := isPoeAdminColumn(oid); ok {
		return true
	}
	if _, ok := columnTail(snmp.Dot1qPvid, oid); ok {
		return true
	}
	if _, ok := columnTail(snmp.Dot1qVlanStaticEgress, oid); ok {
		return true
	}
	if _, ok := columnTail(snmp.Dot1qVlanStaticUntagged, oid); ok {
		return true
	}
	if _, ok := columnTail(snmp.Dot1qVlanStaticRowStatus, oid); ok {
		// Even for a not-yet-existing VLAN row: RowStatus createAndGo must
		// be allowed through.
		return true
	}
	if _, ok := columnTail(snmp.Dot1qVlanStaticName, oid); ok {
		return true
	}
	// The vendor-subtree mgmt-IP/dhcp-mode write OIDs exist only for a
	// model with a vendor subtree; a no-vendor model has none of them.
	if v == nil {
		return false
	}
	if oid == v.MgmtWriteAddrUnverified || oid == v.MgmtWriteNetmaskUnverified || oid == v.MgmtWriteGatewayUnverified {
		return true
	}
	return oid == v.DHCPModeUnverified+".0"
}

// --- NsdpTlvs / ApplyNsdpWrite: the NSDP-face projection/write pair -------
//
// Ported field-for-field from src/netgear_switch/virtual/state.py's
// nsdp_tlvs/apply_nsdp_write (lines 573-735 at pin 1aa1274), reproduced
// verbatim in D-NSDP §7.1 (2026-07-30-slice-05-dossier-nsdp.md). Any
// discrepancy between this section and that pin is a bug here.

// sortedIntKeys returns m's keys in ascending order, for every NsdpTlvs
// emission loop below that must iterate a map deterministically (mirroring
// Python's `sorted(self.ports.items())`/`sorted(self.vlans.items())`/
// `sorted(self.pvids.items())`, since a plain dict-iteration order is not
// itself meaningful there either -- `sorted` is what makes it deterministic
// in both languages).
func sortedIntKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// setDifference returns the set of keys present (true) in a but absent (or
// false) in b, mirroring Python's `frozenset.__sub__` as used by
// nsdp_tlvs's `tagged = vsim.member - vsim.untagged`.
func setDifference(a, b map[int]bool) map[int]bool {
	out := make(map[int]bool, len(a))
	for k, in := range a {
		if in && !b[k] {
			out[k] = true
		}
	}
	return out
}

// mbpsToSpeedByte maps a negotiated Mbps rate to its NSDP LinkSpeed wire
// byte, mirroring Python's `_mbps_to_speed_byte` helper exactly: only
// 10/100/1000/10000 Mbps have a mapping; anything else (including 0, the
// value PortSim.Speed holds while down) is byte 0x00 (down/unrecognized).
func mbpsToSpeedByte(mbps int) byte {
	switch mbps {
	case 10:
		return 0x02
	case 100:
		return 0x04
	case 1000:
		return 0x05
	case 10000:
		return 0xFF
	default:
		return 0x00
	}
}

// u64OrZero dereferences p, or returns 0 for a nil counter -- the NSDP
// PORT_STATISTICS projection reports a zeroed row for an idle port rather
// than omitting the row (unlike OIDMap's SNMP counters, which omit an
// absent instance entirely; see PORT_STATISTICS's own doc note below for
// why the two protocols disagree here).
func u64OrZero(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

// appendIPv4TLV appends an IPv4-shaped TLV (IP_ADDRESS/NETMASK/GATEWAY) for
// dotted onto out, silently omitting it if dotted isn't a valid dotted-quad
// address. Every Mgmt.Address/Netmask/Gateway value this package itself
// ever sets (NewState's "0.0.0.0" default, every seed, and
// ApplyNsdpWrite's own IP_ADDRESS/NETMASK/GATEWAY branches, which parse via
// nsdp.ParseIPv4 first) is already valid, so this omission path is a
// pure defensive backstop, never expected to trigger in practice -- see the
// package-level divergence note on ApplyNsdpWrite for why this package
// prefers "skip" over "panic"/crash for state that should be unreachable
// but is cheap to guard against.
func appendIPv4TLV(out []nsdp.TLVEntry, tag nsdp.Tag, dotted string) []nsdp.TLVEntry {
	tlv, err := nsdp.IPv4TLV(tag, dotted)
	if err != nil {
		return out
	}
	return append(out, tlv)
}

// NsdpTlvs projects this State onto NSDP READ_RESPONSE TLVs for exactly the
// requested tags, mirroring Python's nsdp_tlvs (D-NSDP §7.1).
//
// STRICT (the load-bearing behavior D-NSDP §7.1/§10.6#6 calls out): answers
// with ONLY the tags actually present in tags -- real Plus hardware does
// exactly this (a read omitting MODEL gets a MODEL-less response). This
// deliberately does NOT special-case MODEL/MAC/PORT_COUNT as "always
// included" despite the pinned Python source's own docstring first line
// claiming that: the pinned CODE gates all three on `if Tag.X in tags`
// exactly like every other tag (confirmed by an inline "STRICT" comment in
// that source and pinned by its own
// test_nsdp_tlvs_projects_ports_and_identity, which requires a
// PORT_STATUS-only request to NOT also return MODEL) -- the docstring's
// first line is stale prose, not the contract. Port the code, not that one
// sentence.
func (s *State) NsdpTlvs(tags map[nsdp.Tag]bool) []nsdp.TLVEntry {
	sm := s.mustModel()
	width := (sm.PortCount + 7) / 8

	modelName := s.ModelName
	if modelName == "" {
		modelName = sm.DisplayName
	}

	out := make([]nsdp.TLVEntry, 0)

	if tags[nsdp.TagModel] {
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagModel, Value: []byte(modelName)})
	}
	if tags[nsdp.TagMAC] {
		mac := s.NsdpMac // array value copy: safe to slice, never aliases s.NsdpMac's storage
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagMAC, Value: mac[:]})
	}
	if tags[nsdp.TagPortCount] {
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagPortCount, Value: []byte{byte(sm.PortCount)}}) //nolint:gosec // PortCount is a registry constant, always well under 256
	}
	if tags[nsdp.TagSerialNumber] && s.Serial != "" {
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagSerialNumber, Value: append([]byte{0x01}, s.Serial...)})
	}
	if tags[nsdp.TagHostname] && s.Hostname != "" {
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagHostname, Value: []byte(s.Hostname)})
	}
	if tags[nsdp.TagFirmwareVer1] && s.Firmware != "" {
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagFirmwareVer1, Value: []byte(s.Firmware)})
	}
	if tags[nsdp.TagPortStatus] {
		for _, port := range sortedIntKeys(s.Ports) {
			sim := s.Ports[port]
			speedByte := byte(0x00)
			if sim.Link {
				speedByte = mbpsToSpeedByte(sim.Speed)
			}
			out = append(out, nsdp.TLVEntry{Tag: nsdp.TagPortStatus, Value: []byte{byte(port), speedByte, 0x01}}) //nolint:gosec // port is a 1-based port number, always well under 256
		}
	}
	if tags[nsdp.TagPortName] {
		// One PORT_NAME TLV per port ALWAYS -- a real GS110EMX answers every
		// port, emitting a bare 1-byte TLV (the port byte only) for an
		// undescribed port; skipping those would make the mock's row count
		// disagree with hardware. Description is the SAME per-port field the
		// SNMP ifAlias / HTTP backends project (single source of truth, exactly
		// as Python's sim.description feeds both IF_ALIAS and PORT_NAME).
		for _, port := range sortedIntKeys(s.Ports) {
			sim := s.Ports[port]
			value := []byte{byte(port)} //nolint:gosec // port is a 1-based port number, always well under 256
			if sim.Description != nil {
				value = append(value, []byte(*sim.Description)...)
			}
			out = append(out, nsdp.TLVEntry{Tag: nsdp.TagPortName, Value: value})
		}
	}
	if tags[nsdp.TagPortStatistics] {
		// Real hardware returns a PORT_STATISTICS TLV for EVERY port, with
		// zeroed counters on an idle port (verified on a real GS105PE, whose
		// capture has all 5 rows) -- unlike OIDMap's SNMP counters, which
		// omit an absent instance rather than fabricate a zero. Both are
		// faithful to their own protocol's real behavior; they are not the
		// same rule and must not be unified.
		for _, port := range sortedIntKeys(s.Ports) {
			sim := s.Ports[port]
			value := make([]byte, 0, 49)
			value = append(value, byte(port)) //nolint:gosec // port is a 1-based port number, always well under 256
			value = binary.BigEndian.AppendUint64(value, u64OrZero(sim.RxOctets))
			value = binary.BigEndian.AppendUint64(value, u64OrZero(sim.TxOctets))
			value = binary.BigEndian.AppendUint64(value, u64OrZero(sim.RxErrors))
			value = append(value, make([]byte, 24)...)
			out = append(out, nsdp.TLVEntry{Tag: nsdp.TagPortStatistics, Value: value})
		}
	}
	if tags[nsdp.TagVLANMembers] {
		for _, vid := range sortedIntKeys(s.Vlans) {
			vsim := s.Vlans[vid]
			tagged := setDifference(vsim.Member, vsim.Untagged)
			tlv, err := nsdp.VlanMembersTLV(vid, sliceFromPortSet(vsim.Member), sliceFromPortSet(tagged), sm.PortCount)
			if err == nil { // vid always fits a uint16 in practice; see VlanMembersTLV's own doc comment
				out = append(out, tlv)
			}
		}
	}
	if tags[nsdp.TagPortPVID] {
		for _, port := range sortedIntKeys(s.Pvids) {
			value := make([]byte, 3)
			value[0] = byte(port)                                         //nolint:gosec // port is a 1-based port number, always well under 256
			binary.BigEndian.PutUint16(value[1:3], uint16(s.Pvids[port])) //nolint:gosec // VLAN IDs are always well under 65536
			out = append(out, nsdp.TLVEntry{Tag: nsdp.TagPortPVID, Value: value})
		}
	}
	if tags[nsdp.TagIPAddress] {
		out = appendIPv4TLV(out, nsdp.TagIPAddress, s.Mgmt.Address)
	}
	if tags[nsdp.TagNetmask] {
		out = appendIPv4TLV(out, nsdp.TagNetmask, s.Mgmt.Netmask)
	}
	if tags[nsdp.TagGateway] {
		out = appendIPv4TLV(out, nsdp.TagGateway, s.Mgmt.Gateway)
	}
	if tags[nsdp.TagDHCPMode] {
		dhcpByte := byte(0x00)
		if s.Mgmt.Mode != "static" {
			dhcpByte = 0x01
		}
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagDHCPMode, Value: []byte{dhcpByte}})
	}
	if tags[nsdp.TagQOSEngine] && s.NsdpQosEngine != nil {
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagQOSEngine, Value: []byte{byte(*s.NsdpQosEngine)}}) //nolint:gosec // seeded QoS-engine mode enum, always well under 256
	}
	if tags[nsdp.TagPortMirroring] && s.NsdpPortMirroringDest != nil {
		// The source-port bitmap width is MODEL-dependent on real hardware
		// (a 5-port GS105PE returns a 2-byte bitmap, a 10-port GS110EMX 3
		// bytes) -- derived from port_count via `width` above, never
		// hardcoded; see ParsePortMirroring's own doc comment for the read
		// side of this same lesson.
		value := append([]byte{byte(*s.NsdpPortMirroringDest)}, //nolint:gosec // dest is a 1-based port number, always well under 256
			snmp.EncodePortBitmap(sliceFromPortSet(s.NsdpPortMirroringSources), width)...)
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagPortMirroring, Value: value})
	}
	if tags[nsdp.TagIGMPSnooping] && s.NsdpIgmpSnoopingEnabled != nil {
		enabledByte := byte(0)
		if *s.NsdpIgmpSnoopingEnabled {
			enabledByte = 1
		}
		vlanByte := byte(0)
		if s.NsdpIgmpSnoopingVlan != nil {
			vlanByte = byte(*s.NsdpIgmpSnoopingVlan) //nolint:gosec // seeded VLAN ID test fixture, always well under 256
		}
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagIGMPSnooping, Value: []byte{0x00, enabledByte, 0x00, vlanByte}})
	}
	if tags[nsdp.TagBroadcastFiltering] && s.NsdpBroadcastFiltering != nil {
		b := byte(0)
		if *s.NsdpBroadcastFiltering {
			b = 1
		}
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagBroadcastFiltering, Value: []byte{b}})
	}
	if tags[nsdp.TagLoopDetection] && s.NsdpLoopDetection != nil {
		b := byte(0)
		if *s.NsdpLoopDetection {
			b = 1
		}
		out = append(out, nsdp.TLVEntry{Tag: nsdp.TagLoopDetection, Value: []byte{b}})
	}
	return out
}

// ApplyNsdpWrite mutates this State from one authenticated NSDP WRITE_REQUEST
// TLV (a subsequent read, i.e. verify-after-write, observes the mutation),
// mirroring Python's apply_nsdp_write (D-NSDP §7.1). Unknown, read-only
// (REBOOT/FACTORY_RESET), and unrecognized tags are a deliberate no-op.
//
// Deliberate Go-safety divergence from the pinned Python reference: a
// malformed VALUE for a known tag (too short to hold its fixed fields) is
// ALSO treated as a no-op here, guarded by an explicit length check before
// any indexing/parsing. Python's equivalent branches have no such guard and
// are themselves inconsistent about what happens: PORT_PVID's `value[0]`/
// `struct.unpack_from` raises IndexError/struct.error, and IP_ADDRESS/
// NETMASK/GATEWAY's `socket.inet_ntoa` raises OSError on a wrong-length
// value -- none of those three are a ValueError, so faces/nsdp.py's
// `_serve` (which only catches ValueError around `_handle`) does NOT catch
// them, silently killing that one Python mock's serve thread permanently.
// VLAN_MEMBERS is the one exception that's already safe in Python:
// parse_vlan_members explicitly raises a plain ValueError for a too-short
// buffer, which `_serve` DOES catch (response silently dropped, thread
// survives). A Go panic from an unrecovered out-of-range access in this
// package's background serve goroutine would be strictly worse than even
// the thread-killing cases above: it crashes the entire process, not just
// one mock's request loop. Go therefore guards every branch uniformly
// rather than mirroring Python's per-tag mix.
//
// DHCP_MODE is a related but distinct case: neither language ever panics on
// an empty value here (indexing `value[:1]`/`value[0]==0x01` guarded by
// `len(value) > 0` doesn't raise/index-fault on empty in either language).
// But Python's `value[:1] == b"\x01"` is simply False for an empty value,
// so Python's else branch sets Mode="static" -- a spurious mutation of a
// known tag from a too-short (here, zero-length) value, violating the same
// "too-short value = no-op" contract this comment documents for the other
// tags above. Go deliberately does NOT mirror that inconsistency: an empty
// DHCP_MODE value is guarded to a no-op up front, same as every other known
// tag's too-short value.
//
// See docs/cross-language-divergences.md, "Slice 05", entry 4, for the full
// call-out; nothing here changes the wire encoding of any well-formed
// write, only how a malformed one degrades.
func (s *State) ApplyNsdpWrite(tag nsdp.Tag, value []byte) {
	switch tag {
	case nsdp.TagPortPVID:
		if len(value) < 3 {
			return
		}
		s.Pvids[int(value[0])] = int(binary.BigEndian.Uint16(value[1:3]))
	case nsdp.TagVLANMembers:
		sm := s.mustModel()
		m, err := nsdp.ParseVlanMembers(value, sm.PortCount)
		if err != nil {
			return
		}
		name := ""
		if existing, ok := s.Vlans[m.VlanID]; ok {
			name = existing.Name
		}
		// Untagged is the COMPUTED `member - tagged` set (m.UntaggedPorts()),
		// NOT the wire's raw second bitmap (m.TaggedPorts) -- mirroring
		// Python's `untagged=set(m.untagged_ports)` exactly; using
		// TaggedPorts here directly would invert every subsequent read of
		// this VLAN's tagged/untagged split.
		s.Vlans[m.VlanID] = &VlanSim{
			Name:     name,
			Member:   portSetFromSlice(m.MemberPorts),
			Untagged: portSetFromSlice(m.UntaggedPorts()),
		}
	case nsdp.TagIPAddress:
		if addr, err := nsdp.ParseIPv4(value); err == nil {
			s.Mgmt.Address = addr
		}
	case nsdp.TagNetmask:
		if addr, err := nsdp.ParseIPv4(value); err == nil {
			s.Mgmt.Netmask = addr
		}
	case nsdp.TagGateway:
		if addr, err := nsdp.ParseIPv4(value); err == nil {
			s.Mgmt.Gateway = addr
		}
	case nsdp.TagDHCPMode:
		if len(value) == 0 {
			return
		}
		if value[0] == 0x01 {
			s.Mgmt.Mode = "dhcp"
		} else {
			s.Mgmt.Mode = "static"
		}
	case nsdp.TagVLANDestroy:
		// Write-only action carrying the 2-byte VLAN id (ngadmin
		// ATTR_VLAN_DESTROY 0x2C00). Destroying a VLAN also drops every port's
		// PVID that pointed at it back to the default VLAN 1 -- a PVID may not
		// name a VLAN that no longer exists. Mirrors Python's apply_nsdp_write.
		if len(value) < 2 {
			return
		}
		vid := int(binary.BigEndian.Uint16(value[0:2]))
		if _, ok := s.Vlans[vid]; ok {
			delete(s.Vlans, vid)
			for port, pv := range s.Pvids {
				if pv == vid {
					s.Pvids[port] = 1
				}
			}
		}
	case nsdp.TagPortName:
		// Per-port operator description (0xB000). value is the port byte + the
		// UTF-8 name; a bare 1-byte value clears the description (nil, not "").
		// nsdp.Writer.SetPortDescription emits this (0xB000); the fake applies
		// it, mirroring Python's apply_nsdp_write, so the write's
		// verify-after-write read-back round-trips.
		if len(value) == 0 {
			return
		}
		if sim := s.Ports[int(value[0])]; sim != nil {
			if text := strings.TrimRight(string(value[1:]), "\x00"); text != "" {
				sim.Description = &text
			} else {
				sim.Description = nil
			}
		}
	}
	// REBOOT / FACTORY_RESET / unrecognized tag: deliberate no-op.
}
