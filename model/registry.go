package model

import "fmt"

// Declarative registry of known Netgear switch models, ported field-for-
// field and entry-for-entry from src/netgear_switch/registry.py (the
// normative source; that repo is read-only from here). Any discrepancy
// between this file and the Python source is a bug in this file.
//
// Field mapping notes (Python -> Go):
//   - SwitchModel.snmp_vendor_base is `str | None` in Python; the Go struct
//     field SNMPVendorBase is a plain string per this package's interface,
//     so Python's None is represented as "" here. HasBackend(BackendSNMP)
//     is the correct way to check "does this model do SNMP at all" --
//     SNMPVendorBase == "" does not mean "no SNMP" (e.g. gs728tpp is SNMP
//     with no vendor OID family, standard MIBs only).
//   - The vendor-base string form is copied verbatim from Python's _FM /
//     _SMP constants, which hold the FULL OID ("1.3.6.1.4.1.4526.10" /
//     ".11"), not a bare suffix -- so the Go constants below do the same.
//   - Python's SwitchModel dataclass (as of pin b26eb1f) has the 8 fields
//     reproduced on SwitchModel below (key, display_name, switch_class,
//     port_count, poe_port_count, backends, snmp_vendor_base, verified),
//     the computed has_mac_table property (ported as the HasMACTable
//     method), and three capability/mechanism fields: snmp_can_create_vlan
//     (ported as SNMPCanCreateVLAN -- see its own doc comment, read by the
//     capabilities oracle), plus snmp_vlan_write and
//     snmp_vlan_split_membership_writes (ported as SnmpVlanWrite and
//     SnmpVlanSplitMembershipWrites -- see their own doc comments), which
//     govern the SNMP VLAN-membership write ENCODING that
//     snmp.Writer.SetVlanMembership and the virtual fake's switchport
//     control plane dispatch on. The capabilities oracle does not read
//     either of these two: registry.py's _model(...) default
//     ("qbridge"/False) never changes a support verdict, only which wire
//     encoding a supported write uses.
//   - Python's backends field is a frozenset[Backend] (membership only, no
//     order). The Go Backends field is a slice for a concrete, orderable
//     Go type; the per-model order chosen below is arbitrary (matches the
//     order Backend variants are listed in each Python _model(...) call)
//     and carries no meaning -- use HasBackend, never index into Backends,
//     to test membership.
//   - Python additionally defines MODEL_ALIASES (currently just
//     "s3300" -> "gsm7228ps") and get_model() resolves it before the
//     canonical lookup: `MODEL_ALIASES.get(key, key)` is an exact
//     (case-sensitive) dict lookup with no key normalisation anywhere in
//     the resolution path, and aliases are deliberately NOT added to
//     MODELS/_MODELS -- they resolve only inside get_model(), never appear
//     as their own entry when iterating the registry. modelAliases below
//     ports that table verbatim, and GetModel resolves it the same way
//     (case-sensitively, before the canonical-key lookup) without adding
//     alias keys to the models slice/Models() output.

// Backend is a protocol/transport this library can use to talk to a
// switch, mirroring Python registry.Backend.
type Backend string

// Backend values, mirroring Python registry.Backend. BackendConsole exists
// as a named value (the FASTPATH CLI reachable over a physical serial
// line) but -- as in Python -- is not registered as a Backends member on
// any model in this registry: it is a transport option on an already-
// registered CLI backend (SSH/Telnet), not an independently network-
// reachable backend.
const (
	BackendSNMP    Backend = "snmp"
	BackendNSDP    Backend = "nsdp"
	BackendHTTP    Backend = "http"
	BackendSSH     Backend = "ssh"
	BackendTelnet  Backend = "telnet"
	BackendConsole Backend = "console"
)

// SwitchClass is the product line a switch model belongs to, mirroring
// Python registry.SwitchClass.
type SwitchClass string

// SwitchClass values, mirroring Python registry.SwitchClass.
const (
	ClassFullyManaged    SwitchClass = "fully_managed"
	ClassSmartManagedPro SwitchClass = "smart_managed_pro"
	ClassPlus            SwitchClass = "plus"
)

// Vendor SNMP OID subtrees, mirroring Python registry._FM / _SMP. These
// are the FULL OID prefix (not a bare numeric suffix) -- see the package
// comment above.
const (
	vendorBaseFullyManaged    = "1.3.6.1.4.1.4526.10" // Fully Managed (M4300, GSM7252PS)
	vendorBaseSmartManagedPro = "1.3.6.1.4.1.4526.11" // Smart Managed Pro (S3300/GSM7228PS)
)

// SnmpVlanWrite values, mirroring the two strings Python's
// SwitchModel.snmp_vlan_write ever holds (registry.py's own field docstring,
// reproduced on SwitchModel.SnmpVlanWrite below).
const (
	// SNMPVlanWriteQBridge is the default: a membership change is a
	// read-modify-write of the standard Q-BRIDGE
	// dot1qVlanStaticEgress/UntaggedPorts PortLists.
	SNMPVlanWriteQBridge = "qbridge"
	// SNMPVlanWriteFastpathSwitchport is FASTPATH 12.x's dialect (both
	// M4300 SKUs): the Q-BRIDGE PortLists are read-only mirrors, so
	// membership writes go through the vendor switchport table instead
	// (see package snmp's FASTPATH_SWITCHPORT_* OIDs and
	// snmp.PlanSwitchportMembership).
	SNMPVlanWriteFastpathSwitchport = "fastpath_switchport"
)

// SwitchModel describes one known Netgear switch model, mirroring Python
// registry.SwitchModel. Values obtained from Models() or GetModel are
// canonical registry data; treat them as read-only (see each function's
// doc comment for the exact aliasing/copying contract).
type SwitchModel struct {
	Key            string
	DisplayName    string
	Class          SwitchClass
	PortCount      int
	PoEPortCount   int
	Backends       []Backend
	SNMPVendorBase string // "" means Python's None (no vendor OID family)
	// Verified is true (the default) for every model with a real device
	// capture or other hardware-validated prior art backing its fields.
	// False marks a model registered from spec sheets/product briefs
	// alone, with NO capture -- its port/PoE counts and (for SNMP models)
	// vendor OID family are a best-effort guess, and vendor-specific reads
	// are unverified-pending-capture even though model-agnostic
	// standard-MIB/CGI reads should still work. Mirrors Python
	// SwitchModel.verified; do not flip to true without a real capture.
	Verified bool
	// SNMPCanCreateVLAN reports whether this model's SNMP agent can CREATE a
	// VLAN (a dot1qVlanStaticTable row), mirroring Python
	// SwitchModel.snmp_can_create_vlan. True (the default -- set explicitly
	// on every model below, so a future addition cannot silently inherit
	// Go's zero-value false) for every model except gs728tpp: every
	// documented RowStatus creation mechanism against its real agent
	// (createAndGo alone; createAndGo+name in one PDU; createAndWait->
	// name->active; the name column alone; createAndGo+an empty egress
	// PortList) is answered inconsistentValue -- measured 2026-08-03 on
	// sw-netgear-gs728tpp.monarto.mithis.com/10.2.5.10, firmware 6.0.1.30.
	// Membership, PVID and delete all DO work over SNMP on that same
	// switch; only row CREATION is refused, which is exactly why the
	// capabilities oracle routes create_vlan to the HTTP backend there
	// instead (support_snmp.go) rather than treating this as "no SNMP VLAN
	// support" wholesale.
	SNMPCanCreateVLAN bool
	// SnmpVlanWrite says how this model's SNMP agent accepts a VLAN
	// port-membership WRITE, mirroring Python SwitchModel.snmp_vlan_write
	// (registry.py:59-82, pin b26eb1f). One of the SNMPVlanWrite* constants
	// above.
	//
	// SNMPVlanWriteQBridge (the default): the standard Q-BRIDGE
	// dot1qVlanStaticEgressPorts/UntaggedPorts PortLists are read-WRITE, so a
	// membership change is a read-modify-write of those bitmaps. VERIFIED
	// live on the GSM7252PS (10.1.5.22) and the S3300-52X (10.1.5.11) -- and
	// it is the ONLY membership mechanism either publishes: a walk of the
	// vendor switchport table 1.3.6.1.4.1.4526.10.1.2.8.37 returned ZERO
	// rows on both (2026-07-30, community "public"), versus 1520 rows on
	// the m4300-24x and 1440 on the m4300-16x.
	//
	// SNMPVlanWriteFastpathSwitchport: on FASTPATH 12.x (VERIFIED live on
	// BOTH M4300 SKUs) membership is owned by the per-port SWITCHPORT MODE,
	// so writes go to the vendor switchport table (see package snmp's
	// FASTPATH_SWITCHPORT_* OIDs and PlanSwitchportMembership, which
	// documents the full derivation and the live evidence).
	// dot1qVlanStaticEgressPorts is writable ONLY while no interface on the
	// switch is in access mode -- and since an UNTAGGED write is expressed
	// as access mode, the qbridge dialect cannot be used here at all.
	// dot1qVlanStaticUntaggedPorts is worse than read-only: a SET returns
	// noError and is then silently discarded (proved on the -24X).
	SnmpVlanWrite string
	// SnmpVlanSplitMembershipWrites, when true, means the writer must send
	// the egress and untagged PortLists in SEPARATE PDUs, egress first,
	// instead of one atomic multi-varbind SET, mirroring Python
	// SwitchModel.snmp_vlan_split_membership_writes (registry.py:83-93).
	//
	// VERIFIED live on the S3300-52X-PoE+ (10.1.5.11, Smart firmware):
	// setting a port's egress bit has a side effect -- the firmware makes
	// that port an UNTAGGED member -- and when both columns travel in ONE
	// PDU that side effect wins, so a TAGGED request silently comes back
	// untagged:
	//
	//	one PDU  : egress=[1] untagged=[1]  <- untagged intent lost
	//	two PDUs : egress=[1] untagged=[]   <- correct, CLI confirms "Tagged"
	//
	// The GSM7252PS applies a single combined PDU correctly, so this stays
	// opt-in per model rather than changing that verified path.
	SnmpVlanSplitMembershipWrites bool
}

// HasBackend reports whether m supports the given backend.
func (m *SwitchModel) HasBackend(b Backend) bool {
	for _, have := range m.Backends {
		if have == b {
			return true
		}
	}
	return false
}

// HasMACTable reports whether m exposes a MAC/FDB table. Mirrors Python
// SwitchModel.has_mac_table: the MAC table is only reachable via SNMP
// (managed switches); Plus-class NSDP-only models never expose one.
func (m *SwitchModel) HasMACTable() bool {
	return m.HasBackend(BackendSNMP)
}

// models is the canonical, package-private, ordered registry, ported
// entry-for-entry and in the same order as Python's _MODELS table
// (registry.py lines 89-297: m4300-24x, m4300-16x, gsm7252ps, gsm7228ps,
// gs110emx, gs305ep, m7300, xs748t, gs728tpp, gs105pe). Never mutate this
// slice or its elements after init(); Models() and GetModel() both depend
// on it staying fixed.
var models = []SwitchModel{
	{
		// VERIFIED live @10.1.5.13 (FASTPATH 12.0.13.8): the Q-BRIDGE static
		// PortLists are read-only mirrors here; membership writes must go
		// through the vendor switchport table. See SwitchModel.SnmpVlanWrite.
		Key:               "m4300-24x",
		DisplayName:       "M4300-24X (XSM4324CS)",
		Class:             ClassFullyManaged,
		PortCount:         28,
		PoEPortCount:      0,
		Backends:          []Backend{BackendSNMP, BackendHTTP, BackendSSH, BackendTelnet},
		SNMPVendorBase:    vendorBaseFullyManaged,
		Verified:          true,
		SNMPCanCreateVLAN: true,
		SnmpVlanWrite:     SNMPVlanWriteFastpathSwitchport,
	},
	{
		// VERIFIED live @10.1.5.20 (FASTPATH 12.0.19.15) on 2026-07-30 --
		// previously only INFERRED from the -24X. A deterministic A/B/A on
		// port 1/0/1 (byte-identical writes to a throwaway VLAN, flipping
		// only that port's mode) settled it: general->noError,
		// access->commitFailed, general->noError, trunk->noError,
		// access->commitFailed, general->noError -- i.e.
		// dot1qVlanStaticEgressPorts is writable only while NO interface on
		// the switch is in access mode (switch-wide, not per-VLAN). Since an
		// UNTAGGED membership write is expressed AS access mode, the qbridge
		// dialect would disable itself on first use, so this SKU belongs on
		// the switchport dialect too. The same rule explains why the -24X
		// (21 of 24 ports access-mode) rejects the write in every port mode.
		Key:               "m4300-16x",
		DisplayName:       "M4300-16X (XSM4316)",
		Class:             ClassFullyManaged,
		PortCount:         16,
		PoEPortCount:      16,
		Backends:          []Backend{BackendSNMP, BackendHTTP, BackendSSH, BackendTelnet},
		SNMPVendorBase:    vendorBaseFullyManaged,
		Verified:          true,
		SNMPCanCreateVLAN: true,
		SnmpVlanWrite:     SNMPVlanWriteFastpathSwitchport,
	},
	{
		Key:               "gsm7252ps",
		DisplayName:       "GSM7252PS",
		Class:             ClassFullyManaged,
		PortCount:         52,
		PoEPortCount:      48,
		Backends:          []Backend{BackendSNMP, BackendHTTP, BackendSSH, BackendTelnet},
		SNMPVendorBase:    vendorBaseFullyManaged,
		Verified:          true,
		SNMPCanCreateVLAN: true,
		SnmpVlanWrite:     SNMPVlanWriteQBridge,
	},
	{
		// VERIFIED 2026-07-30 against real hardware: the S3300-52X-PoE+
		// (sw-netgear-s3300-1, sysObjectID 4526.100.10.19). The live
		// capture confirmed the smart-managed-pro (4526.11) vendor family
		// is correct here -- unlike gs728tpp (which had zero 4526 OIDs),
		// this switch's fan/temp/PoE vendor data really does live under
		// 4526.11.43, and all 9 read ops cross-verified SNMP<->mock. Its
		// sysDescr "S3300-52X-PoE+" is deliberately unmatchable text (same
		// shape as the unregistered S3300-28X), so it is auto-detected via
		// the sysObjectID map instead. Registered key is gsm7228ps;
		// "s3300" is an alias (see modelAliases). Note 4526.100.10.19 is
		// the product-ID OID, distinct from the 4526.11 vendor DATA
		// subtree.
		//
		// TELNET, NOT SSH: the S3300-52X's FASTPATH CLI is reachable over
		// telnet on the NON-STANDARD port 60000 (not 23) -- live-verified
		// 2026-07-30 on 10.1.5.11 (login admin+password, prompt
		// "(manage-sw-netgear-s3300-1) >"). SSH is genuinely ABSENT: the
		// switch runs no ssh listener on any port (its own SNMP
		// tcpConnTable shows only 80/443/60000). Mirrors Python
		// registry.py's gsm7228ps _model(...) call exactly -- do not
		// re-add BackendSSH here without a NEW live capture proving it.
		//
		// VERIFIED live 2026-07-30: this Smart firmware auto-untags a port
		// when its egress bit is set, and that side effect beats an
		// untagged varbind carried in the SAME PDU -- so the two columns
		// must be written in separate PDUs, egress first, or every TAGGED
		// request silently lands as UNTAGGED. See
		// SwitchModel.SnmpVlanSplitMembershipWrites.
		Key:                           "gsm7228ps",
		DisplayName:                   "GSM7228PS (S3300)",
		Class:                         ClassSmartManagedPro,
		PortCount:                     52,
		PoEPortCount:                  48,
		Backends:                      []Backend{BackendSNMP, BackendHTTP, BackendTelnet},
		SNMPVendorBase:                vendorBaseSmartManagedPro,
		Verified:                      true,
		SNMPCanCreateVLAN:             true,
		SnmpVlanWrite:                 SNMPVlanWriteQBridge,
		SnmpVlanSplitMembershipWrites: true,
	},
	{
		Key:               "gs110emx",
		DisplayName:       "GS110EMX",
		Class:             ClassPlus,
		PortCount:         10,
		PoEPortCount:      0,
		Backends:          []Backend{BackendNSDP, BackendHTTP},
		SNMPVendorBase:    "",
		Verified:          true,
		SNMPCanCreateVLAN: true,                 // irrelevant: this model has no SNMP backend
		SnmpVlanWrite:     SNMPVlanWriteQBridge, // irrelevant: this model has no SNMP backend
	},
	{
		Key:               "gs305ep",
		DisplayName:       "GS305EP",
		Class:             ClassPlus,
		PortCount:         5,
		PoEPortCount:      4,
		Backends:          []Backend{BackendNSDP, BackendHTTP},
		SNMPVendorBase:    "",
		Verified:          true,
		SNMPCanCreateVLAN: true,                 // irrelevant: this model has no SNMP backend
		SnmpVlanWrite:     SNMPVlanWriteQBridge, // irrelevant: this model has no SNMP backend
	},
	{
		// UNVERIFIED-pending-capture: no device capture exists (registered
		// from spec sheets/product briefs only). M7300-24XF (24x SFP+, 0
		// PoE) is the assumed/documented variant; which exact SKU is
		// actually deployed is unverified. Same FASTPATH fully-managed
		// lineage as M4300, so the fully-managed vendor subtree is the
		// best spec-guess, itself unverified. SnmpVlanWrite stays the
		// "qbridge" default (Python's registry.py never overrides it for
		// this model either) since there is no capture to justify claiming
		// the switchport dialect here.
		Key:               "m7300",
		DisplayName:       "M7300-24XF",
		Class:             ClassFullyManaged,
		PortCount:         24,
		PoEPortCount:      0,
		Backends:          []Backend{BackendSNMP},
		SNMPVendorBase:    vendorBaseFullyManaged,
		Verified:          false,
		SNMPCanCreateVLAN: true,
		SnmpVlanWrite:     SNMPVlanWriteQBridge,
	},
	{
		// UNVERIFIED-pending-capture: 48x 10G copper (+ SFP+ combo),
		// non-PoE per the documented base spec. HTTP is plausible for a
		// Smart Managed Pro switch but is deliberately OMITTED (not just
		// unverified) to avoid implying a web-UI integration that does
		// not exist in this codebase.
		Key:               "xs748t",
		DisplayName:       "XS748T",
		Class:             ClassSmartManagedPro,
		PortCount:         48,
		PoEPortCount:      0,
		Backends:          []Backend{BackendSNMP},
		SNMPVendorBase:    vendorBaseSmartManagedPro,
		Verified:          false,
		SNMPCanCreateVLAN: true,
		SnmpVlanWrite:     SNMPVlanWriteQBridge,
	},
	{
		// GS728TPP: 24x Gigabit PoE+ + 4x SFP combo = 28 total ports, 24
		// PoE+. SNMP vendor OID family resolved by a real live capture:
		// this model implements zero Netgear vendor OIDs -- it serves
		// everything (per-port PoE, mgmt-IP, sensor inventory) via
		// standard MIBs, hence SNMPVendorBase "". HTTP backend
		// live-verified against a real unit. verified=true: SNMP<->HTTP
		// parity cross-verified for ports/vlans/pvids/macs/lldp/poe/
		// mgmt-IP.
		Key:            "gs728tpp",
		DisplayName:    "GS728TPP",
		Class:          ClassSmartManagedPro,
		PortCount:      28,
		PoEPortCount:   24,
		Backends:       []Backend{BackendSNMP, BackendHTTP},
		SNMPVendorBase: "",
		Verified:       true,
		// Its SNMP agent cannot CREATE a VLAN -- measured, with the device's
		// own inconsistentValue for every documented RowStatus mechanism;
		// see SNMPCanCreateVLAN's doc comment. Everything else in the VLAN
		// surface (membership, PVID, destroy) works over SNMP, and creation
		// works over HTTP.
		SNMPCanCreateVLAN: false,
		SnmpVlanWrite:     SNMPVlanWriteQBridge,
	},
	{
		// GS105PE: a real, distinct SKU from gs305ep -- a 5-port Gigabit
		// "Smart Plus" switch. No SNMP (Plus switches never expose SNMP).
		// Live-verified against real units: NSDP reports MODEL="GS105PE",
		// port_count=5. PoE port count 0 is confirmed (not merely
		// unverified): the web UI's PoE-status page 404s on the real
		// unit -- the product's PoE-passthrough capability is not a PSE
		// claim.
		Key:               "gs105pe",
		DisplayName:       "GS105PE",
		Class:             ClassPlus,
		PortCount:         5,
		PoEPortCount:      0,
		Backends:          []Backend{BackendNSDP, BackendHTTP},
		SNMPVendorBase:    "",
		Verified:          true,
		SNMPCanCreateVLAN: true,                 // irrelevant: this model has no SNMP backend
		SnmpVlanWrite:     SNMPVlanWriteQBridge, // irrelevant: this model has no SNMP backend
	},
}

// modelAliases maps an alternate model-name key to the canonical registry
// key it resolves to, ported verbatim from Python's MODEL_ALIASES.
// "s3300" <-> "gsm7228ps": the model registered under the canonical key
// "gsm7228ps" is really the S3300-52X-PoE+ (its real firmware sysDescr and
// marketing name are "S3300-52X"; GSM7228PS is the ProSAFE part-number
// family), so both names must resolve to it. Aliases are deliberately not
// entries in models/modelIndex's canonical listing (what Models() and
// range-over-registry callers iterate) -- they are resolved only by
// GetModel, exactly mirroring Python's get_model().
var modelAliases = map[string]string{
	"s3300": "gsm7228ps",
}

// modelIndex maps canonical registry key -> pointer into models, built
// once in init(). Since models is never resized or reallocated after
// init(), these pointers stay valid and stable for the process lifetime.
var modelIndex map[string]*SwitchModel

func init() {
	modelIndex = make(map[string]*SwitchModel, len(models))
	for i := range models {
		modelIndex[models[i].Key] = &models[i]
	}
}

// Models returns the registry in canonical order (matching Python's
// _MODELS table order). The returned slice and its *SwitchModel elements
// are an independent, fully-detached copy -- including a copy of each
// entry's Backends slice -- so callers may freely mutate what they get
// back (append, reassign fields, etc.) without affecting the package's
// canonical registry state or any pointer returned by GetModel.
func Models() []*SwitchModel {
	out := make([]*SwitchModel, len(models))
	for i, m := range models {
		cp := m
		cp.Backends = append([]Backend(nil), m.Backends...)
		out[i] = &cp
	}
	return out
}

// GetModel looks up a switch model by its canonical registry key or by a
// known alias (see modelAliases; resolution is an exact, case-sensitive
// match, mirroring Python's MODEL_ALIASES.get(key, key)). On a miss it
// returns an error wrapping ErrUnknownModel (match with errors.Is). The
// returned pointer references the canonical registry entry directly (not a
// copy, unlike Models()) and must be treated as read-only -- mutating it
// corrupts shared package state.
func GetModel(key string) (*SwitchModel, error) {
	canonical := key
	if alias, ok := modelAliases[key]; ok {
		canonical = alias
	}
	m, ok := modelIndex[canonical]
	if !ok {
		return nil, fmt.Errorf("%s: %w", key, ErrUnknownModel)
	}
	return m, nil
}
