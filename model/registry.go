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
//   - Python's SwitchModel dataclass has exactly the 8 fields reproduced on
//     SwitchModel below (key, display_name, switch_class, port_count,
//     poe_port_count, backends, snmp_vendor_base, verified) plus the
//     computed has_mac_table property (ported as the HasMACTable method).
//     No other fields (no quirk/capability-flag fields) exist on the
//     Python dataclass.
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
		Key:            "m4300-24x",
		DisplayName:    "M4300-24X (XSM4324CS)",
		Class:          ClassFullyManaged,
		PortCount:      28,
		PoEPortCount:   0,
		Backends:       []Backend{BackendSNMP, BackendHTTP, BackendSSH, BackendTelnet},
		SNMPVendorBase: vendorBaseFullyManaged,
		Verified:       true,
	},
	{
		Key:            "m4300-16x",
		DisplayName:    "M4300-16X (XSM4316)",
		Class:          ClassFullyManaged,
		PortCount:      16,
		PoEPortCount:   16,
		Backends:       []Backend{BackendSNMP, BackendHTTP, BackendSSH, BackendTelnet},
		SNMPVendorBase: vendorBaseFullyManaged,
		Verified:       true,
	},
	{
		Key:            "gsm7252ps",
		DisplayName:    "GSM7252PS",
		Class:          ClassFullyManaged,
		PortCount:      52,
		PoEPortCount:   48,
		Backends:       []Backend{BackendSNMP, BackendHTTP, BackendSSH, BackendTelnet},
		SNMPVendorBase: vendorBaseFullyManaged,
		Verified:       true,
	},
	{
		// UNVERIFIED-pending-capture: no real-hardware capture exists for
		// this model (its seed is illustrative/structural only). The
		// smart-managed-pro (4526.11) vendor family is a spec-guess from
		// the same 4526 subtree that turned out WRONG on gs728tpp, so its
		// vendor sensor/PoE-power readings are unconfirmed.
		Key:            "gsm7228ps",
		DisplayName:    "GSM7228PS (S3300)",
		Class:          ClassSmartManagedPro,
		PortCount:      52,
		PoEPortCount:   48,
		Backends:       []Backend{BackendSNMP, BackendHTTP, BackendSSH, BackendTelnet},
		SNMPVendorBase: vendorBaseSmartManagedPro,
		Verified:       false,
	},
	{
		Key:            "gs110emx",
		DisplayName:    "GS110EMX",
		Class:          ClassPlus,
		PortCount:      10,
		PoEPortCount:   0,
		Backends:       []Backend{BackendNSDP, BackendHTTP},
		SNMPVendorBase: "",
		Verified:       true,
	},
	{
		Key:            "gs305ep",
		DisplayName:    "GS305EP",
		Class:          ClassPlus,
		PortCount:      5,
		PoEPortCount:   4,
		Backends:       []Backend{BackendNSDP, BackendHTTP},
		SNMPVendorBase: "",
		Verified:       true,
	},
	{
		// UNVERIFIED-pending-capture: no device capture exists (registered
		// from spec sheets/product briefs only). M7300-24XF (24x SFP+, 0
		// PoE) is the assumed/documented variant; which exact SKU is
		// actually deployed is unverified. Same FASTPATH fully-managed
		// lineage as M4300, so the fully-managed vendor subtree is the
		// best spec-guess, itself unverified.
		Key:            "m7300",
		DisplayName:    "M7300-24XF",
		Class:          ClassFullyManaged,
		PortCount:      24,
		PoEPortCount:   0,
		Backends:       []Backend{BackendSNMP},
		SNMPVendorBase: vendorBaseFullyManaged,
		Verified:       false,
	},
	{
		// UNVERIFIED-pending-capture: 48x 10G copper (+ SFP+ combo),
		// non-PoE per the documented base spec. HTTP is plausible for a
		// Smart Managed Pro switch but is deliberately OMITTED (not just
		// unverified) to avoid implying a web-UI integration that does
		// not exist in this codebase.
		Key:            "xs748t",
		DisplayName:    "XS748T",
		Class:          ClassSmartManagedPro,
		PortCount:      48,
		PoEPortCount:   0,
		Backends:       []Backend{BackendSNMP},
		SNMPVendorBase: vendorBaseSmartManagedPro,
		Verified:       false,
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
	},
	{
		// GS105PE: a real, distinct SKU from gs305ep -- a 5-port Gigabit
		// "Smart Plus" switch. No SNMP (Plus switches never expose SNMP).
		// Live-verified against real units: NSDP reports MODEL="GS105PE",
		// port_count=5. PoE port count 0 is confirmed (not merely
		// unverified): the web UI's PoE-status page 404s on the real
		// unit -- the product's PoE-passthrough capability is not a PSE
		// claim.
		Key:            "gs105pe",
		DisplayName:    "GS105PE",
		Class:          ClassPlus,
		PortCount:      5,
		PoEPortCount:   0,
		Backends:       []Backend{BackendNSDP, BackendHTTP},
		SNMPVendorBase: "",
		Verified:       true,
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
