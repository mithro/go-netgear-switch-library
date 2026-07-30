// switch.go: Switch construction -- model/host binding, option application,
// lazy once-only secret-resolution cells, and FromConfig's field mapping.
// Ported from src/netgear_switch/sync_api.py's SyncSwitch.__init__/
// from_config/close (the normative source; that repo is read-only from
// here). Any discrepancy between this file and the pinned Python source is
// a bug in this file. See D-FAC (docs/superpowers/plans/
// 2026-07-30-slice-03-dossier-facade.md) §2.2, §2.13, §2.16 for the exact
// semantics ported.

package netgearswitch

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// resolveOnce is a lazily-resolved optional secret cell: resolve() runs its
// resolver at most once, ever, and caches the result -- including a nil
// ("not configured") result -- so a later call never re-invokes it. This is
// the Go replacement for Python's `_Unset`/`_UNSET` sentinel pattern (D-FAC
// §2.2): Go has no ambient class-identity sentinel, so a resolved bool flag
// plus a cached *string plays the same role without overloading nil for
// both "unresolved" and "resolved-to-nil".
//
// Critically, a resolver that RETURNS AN ERROR is NOT marked resolved: the
// next resolve() call retries the resolver from scratch (D-FAC §2.13/trap
// #2 -- e.g. a `!command` secret spec that failed once must still get a
// fresh chance on the next write, while a spec that already resolved
// successfully must never re-exec its subprocess).
type resolveOnce struct {
	mu       sync.Mutex
	resolver func() (*string, error)
	resolved bool
	value    *string
}

// newResolveOnce wraps resolver in a resolveOnce cell. A nil resolver is
// valid and resolves to (nil, nil) -- "no resolver configured" -- exactly
// once (cheaply; it still only runs the "resolver is nil" check the first
// time, though that has no observable cost either way).
func newResolveOnce(resolver func() (*string, error)) *resolveOnce {
	return &resolveOnce{resolver: resolver}
}

// resolve returns the cached value if this cell has already resolved
// successfully; otherwise it runs the resolver now, caches a successful
// result (marking the cell resolved), and returns it as-is. A resolver
// error is returned to the caller WITHOUT marking the cell resolved.
func (c *resolveOnce) resolve() (*string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.resolved {
		return c.value, nil
	}
	if c.resolver == nil {
		c.resolved = true
		return nil, nil
	}
	v, err := c.resolver()
	if err != nil {
		return nil, err
	}
	c.resolved = true
	c.value = v
	return v, nil
}

// Switch is a model-driven read/write facade over one physical switch,
// mirroring Python's SyncSwitch. Construction (New/FromConfig) never does
// I/O and never resolves a secret: SNMP/NSDP clients an option injects are
// used as-is, un-injected ones are built lazily on first dispatch (see
// dispatch.go's readerFor), and write-community/HTTP-password resolvers
// are stashed as resolveOnce cells that run only on first actual use.
type Switch struct {
	model *model.SwitchModel
	host  string

	// snmpClient, if non-nil, is used as-is by the SNMP BackendBuilder
	// (slice 05's snmp registration) instead of building a default one.
	snmpClient snmp.Client
	// snmpCommunity is the SNMP read community; nil means "not configured"
	// (distinct from Python's plain `str | None`, matching the read-side
	// credential gate that rejects only a nil community, never "").
	snmpCommunity *string

	// snmpWriteCommunity resolves the write community lazily; consumed by
	// slice 04's write dispatch, stored here since construction already
	// accepts the resolver option.
	snmpWriteCommunity *resolveOnce
	// snmpWriteClient, if non-nil, is used as-is by the SNMP
	// WriteBackendBuilder (buildSNMPWriter, write_dispatch.go/backend_snmp.go)
	// instead of building a default one from host/write-community -- a
	// SEPARATE field from snmpClient, mirroring Python's distinct
	// _snmp_write_client constructor param (D-WR §3.4 point 1: Go does not
	// type-assert the read client into a WriteClient).
	snmpWriteClient snmp.WriteClient

	// nsdpInterface, if set, names the network interface NSDP UDP broadcast
	// discovery should bind to; stored for slice 05.
	nsdpInterface *string

	// httpPassword resolves the HTTP (and, per D-FAC §2.16, NSDP-shared)
	// admin password lazily; consumed by slice 06.
	httpPassword *resolveOnce

	// protectedPorts is stored sorted ascending with duplicates removed
	// (this codebase's canonical form for Python's frozenset[int]; see
	// config.go's protectedPorts helper for the same convention).
	protectedPorts []int

	// mu guards readerCache/writerCache: readerFor/writerFor both read and
	// populate them, and a Switch may be dispatched from multiple
	// goroutines concurrently.
	mu          sync.Mutex
	readerCache map[model.Backend]BackendReader
	writerCache map[model.Backend]BackendWriter
}

// SwitchOption configures a Switch at construction time (functional-options
// pattern); see New/FromConfig.
type SwitchOption func(*Switch)

// WithSNMPCommunity sets the SNMP read community explicitly (a plain
// string, not a secret spec: the read-side credential gate needs no
// resolution, mirroring Python's snmp_community constructor parameter).
func WithSNMPCommunity(s string) SwitchOption {
	return func(sw *Switch) { sw.snmpCommunity = &s }
}

// WithSNMPWriteCommunityResolver stashes r as the write-community resolver,
// invoked at most once, lazily, on first write (slice 04). Passing this
// option never causes r to run during New/FromConfig.
func WithSNMPWriteCommunityResolver(r func() (*string, error)) SwitchOption {
	return func(sw *Switch) { sw.snmpWriteCommunity = newResolveOnce(r) }
}

// WithSNMPClient injects an already-built snmp.Client, used as-is instead
// of a default one the SNMP backend builder would otherwise construct from
// the host/community. Primarily for tests (a fake/virtual client) or a
// caller reusing an already-open connection.
func WithSNMPClient(c snmp.Client) SwitchOption {
	return func(sw *Switch) { sw.snmpClient = c }
}

// WithSNMPWriteClient injects an already-built snmp.WriteClient, used as-is
// instead of a default one the SNMP WriteBackendBuilder would otherwise
// construct from the host/resolved write community -- the write-side twin
// of WithSNMPClient, kept as a SEPARATE field/option (not a type-assert of
// an injected read client) per D-WR §3.4 point 1.
func WithSNMPWriteClient(c snmp.WriteClient) SwitchOption {
	return func(sw *Switch) { sw.snmpWriteClient = c }
}

// WithProtectedPorts marks ports as protected (write guards -- slice 04 --
// refuse to disrupt them without an explicit force override). Stored
// sorted ascending with duplicates removed.
func WithProtectedPorts(ports ...int) SwitchOption {
	return func(sw *Switch) { sw.protectedPorts = sortedUniquePorts(ports) }
}

// WithNSDPInterface names the network interface NSDP UDP discovery should
// bind to. Stored for slice 05's NSDP backend; unused until then.
func WithNSDPInterface(s string) SwitchOption {
	return func(sw *Switch) { sw.nsdpInterface = &s }
}

// WithHTTPPasswordResolver stashes r as the HTTP admin-password resolver,
// invoked at most once, lazily, on first HTTP session use (slice 06).
// Passing this option never causes r to run during New/FromConfig.
func WithHTTPPasswordResolver(r func() (*string, error)) SwitchOption {
	return func(sw *Switch) { sw.httpPassword = newResolveOnce(r) }
}

// sortedUniquePorts returns ports sorted ascending with duplicates removed,
// mirroring config.go's protectedPorts helper (this codebase's canonical
// form for Python's frozenset[int]). The result is never nil.
func sortedUniquePorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// New constructs a Switch bound to m/host, applying opts in order. New does
// NO I/O and resolves NO secret -- an injected client is stashed as-is, and
// a write-community/HTTP-password resolver option only stores the closure;
// it is invoked (at most once) on first actual use, never here. m must be
// non-nil; every other field is optional and defaults to "not configured".
func New(m *model.SwitchModel, host string, opts ...SwitchOption) (*Switch, error) {
	if m == nil {
		return nil, fmt.Errorf("netgearswitch.New: model must not be nil: %w", model.ErrConfig)
	}

	sw := &Switch{
		model:              m,
		host:               host,
		snmpWriteCommunity: newResolveOnce(nil),
		httpPassword:       newResolveOnce(nil),
		protectedPorts:     []int{},
		readerCache:        make(map[model.Backend]BackendReader),
		writerCache:        make(map[model.Backend]BackendWriter),
	}
	for _, opt := range opts {
		opt(sw)
	}
	return sw, nil
}

// FromConfig builds a Switch from cfg, mapping its fields per D-FAC §2.16's
// table (the same shape as Python's SyncSwitch.from_config):
//
//   - cfg.Model/cfg.Host map straight to New's positional arguments.
//   - cfg.SNMPCommunity, if set, maps to WithSNMPCommunity (a literal value,
//     not a resolver: the read community needs no secret-spec resolution).
//   - cfg.SNMPWriteCommunitySpec becomes a resolver closure calling
//     cfg.SNMPWriteCommunity(os.LookupEnv, nil) -- LAZY, never invoked here.
//   - cfg.NSDPInterface, if set, maps to WithNSDPInterface (an interface
//     name, not a secret; not resolved).
//   - cfg.HTTPPasswordSpec becomes a resolver closure calling
//     cfg.HTTPPassword(os.LookupEnv, nil) -- LAZY, never invoked here. (Per
//     D-FAC §2.16, Python's from_config also reuses this same spec as the
//     NSDP admin-password resolver; slice 05 wires that reuse in once an
//     NSDP password option exists on Switch.)
//   - cfg.ProtectedPorts maps to WithProtectedPorts.
//
// opts, if given, are applied AFTER the config-derived options, so a caller
// can override any config-mapped field (e.g. inject a fake snmp.Client in
// tests) without FromConfig needing its own escape hatch per field.
func FromConfig(cfg SwitchConfig, opts ...SwitchOption) (*Switch, error) {
	configOpts := make([]SwitchOption, 0, 6+len(opts))

	if cfg.SNMPCommunity != nil {
		configOpts = append(configOpts, WithSNMPCommunity(*cfg.SNMPCommunity))
	}
	configOpts = append(configOpts, WithSNMPWriteCommunityResolver(func() (*string, error) {
		return cfg.SNMPWriteCommunity(os.LookupEnv, nil)
	}))
	if cfg.NSDPInterface != nil {
		configOpts = append(configOpts, WithNSDPInterface(*cfg.NSDPInterface))
	}
	configOpts = append(configOpts, WithHTTPPasswordResolver(func() (*string, error) {
		return cfg.HTTPPassword(os.LookupEnv, nil)
	}))
	configOpts = append(configOpts, WithProtectedPorts(cfg.ProtectedPorts...))
	configOpts = append(configOpts, opts...)

	return New(cfg.Model, cfg.Host, configOpts...)
}

// Close releases any resource THIS Switch built for itself. Slice 03 has
// none yet: SNMP/NSDP clients (injected or default-built) are never closed
// (mirroring Python: they are built fresh per call and need no teardown),
// and no HTTP client exists until slice 06 wires one up as the sole
// persistent connection worth closing (D-FAC §2.15). Safe to call at any
// time, including on a Switch that never dispatched a single read.
func (s *Switch) Close() error {
	return nil
}

// Model returns the model.SwitchModel this Switch was constructed with,
// mirroring Python's SyncSwitch.model attribute. This is the model as
// GIVEN at construction (New/FromConfig), never the actual detected model:
// callers wanting to confirm/discover a switch's real identity should use
// Identify instead. The returned pointer is s's own model reference (models
// are immutable registry singletons -- see model/registry.go -- so sharing
// it is safe); callers must not mutate it.
func (s *Switch) Model() *model.SwitchModel {
	return s.model
}

// Host returns the hostname or IP address this Switch was constructed with,
// mirroring Python's SyncSwitch.host attribute.
func (s *Switch) Host() string {
	return s.host
}

// --- Read methods --------------------------------------------------------
//
// Every method below is a thin readVia wrapper, mirroring Python's
// SyncSwitch read methods (D-FAC §2.8-§2.9): the ONLY per-method logic is
// which BackendReader method is invoked and how its result is captured, per-
// backend-preference dispatch/skip/reraise-last semantics live entirely in
// dispatch.go's readVia. GetMACs is the one exception with an extra guard
// (require_mac_table, run BEFORE dispatch); see getMACsNoGate below for the
// ungated variant snapshot.go's Snapshot uses instead of this method, per
// D-FAC §2.12/trap #5.

// GetPorts reads per-port administrative/operational status, speed, name and
// description via whichever backend model.BackendPreference-order serves it
// first.
func (s *Switch) GetPorts(ctx context.Context) ([]model.PortStatus, error) {
	var out []model.PortStatus
	err := s.readVia(ctx, "get_ports", func(r BackendReader) error {
		v, err := r.GetPorts(ctx)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// GetStats reads the per-port traffic-counter snapshot.
func (s *Switch) GetStats(ctx context.Context) ([]model.PortStats, error) {
	var out []model.PortStats
	err := s.readVia(ctx, "get_stats", func(r BackendReader) error {
		v, err := r.GetStats(ctx)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// GetVLANs reads the static VLAN table.
func (s *Switch) GetVLANs(ctx context.Context) ([]model.VLANInfo, error) {
	var out []model.VLANInfo
	err := s.readVia(ctx, "get_vlans", func(r BackendReader) error {
		v, err := r.GetVLANs(ctx)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// GetPVIDs reads each physical port's default/untagged VLAN (PVID).
func (s *Switch) GetPVIDs(ctx context.Context) ([]model.Pvid, error) {
	var out []model.Pvid
	err := s.readVia(ctx, "get_pvids", func(r BackendReader) error {
		v, err := r.GetPVIDs(ctx)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// GetLLDP reads the LLDP remote-neighbor table.
func (s *Switch) GetLLDP(ctx context.Context) ([]model.LLDPNeighbor, error) {
	var out []model.LLDPNeighbor
	err := s.readVia(ctx, "get_lldp", func(r BackendReader) error {
		v, err := r.GetLLDP(ctx)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// getMACsNoGate dispatches get_macs WITHOUT the require_mac_table guard
// GetMACs applies below -- the exact code path Snapshot's macs field uses
// (D-FAC §2.12: "snapshot()'s macs field does NOT call require_mac_table --
// it just lets _read exhaust naturally to the same outcome"). Exported only
// within this package; snapshot.go's Snapshot is its other caller.
func (s *Switch) getMACsNoGate(ctx context.Context) ([]model.MacEntry, error) {
	var out []model.MacEntry
	err := s.readVia(ctx, "get_macs", func(r BackendReader) error {
		v, err := r.GetMACs(ctx)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// GetMACs reads the MAC address / forwarding-database table. Unlike every
// other read method, require_mac_table(s.model) is checked FIRST,
// unconditionally, BEFORE any backend dispatch is attempted (D-FAC §2.9): a
// model with no MAC table (i.e. no SNMP backend -- see
// model.SwitchModel.HasMACTable) raises directly from this guard and never
// even enters readVia's loop, mirroring Python's exact error text
// (`f"model {model.key!r} has no MAC/FDB table"`).
func (s *Switch) GetMACs(ctx context.Context) ([]model.MacEntry, error) {
	if !s.model.HasMACTable() {
		return nil, fmt.Errorf("model %q has no MAC/FDB table: %w", s.model.Key, model.ErrUnsupportedCapability)
	}
	return s.getMACsNoGate(ctx)
}

// GetPoE reads the per-port Power-over-Ethernet status. No facade-level
// guard: each backend's own reader (e.g. snmp.Reader.GetPoE) applies its own
// 0-PSE-port capability gate internally.
func (s *Switch) GetPoE(ctx context.Context) ([]model.PoEStatus, error) {
	var out []model.PoEStatus
	err := s.readVia(ctx, "get_poe", func(r BackendReader) error {
		v, err := r.GetPoE(ctx)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// GetSensors reads the switch's environmental sensors (fans, PSUs,
// temperature).
func (s *Switch) GetSensors(ctx context.Context) ([]model.Sensor, error) {
	var out []model.Sensor
	err := s.readVia(ctx, "get_sensors", func(r BackendReader) error {
		v, err := r.GetSensors(ctx)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// GetMgmtIP reads the switch's own management IP configuration.
func (s *Switch) GetMgmtIP(ctx context.Context) (model.MgmtIPConfig, error) {
	var out model.MgmtIPConfig
	err := s.readVia(ctx, "get_mgmt_ip", func(r BackendReader) error {
		v, err := r.GetMgmtIP(ctx)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// Identify detects this switch's ACTUAL model via SNMP sysDescr/sysObjectID,
// independent of s.model. Unlike every other read method, this deliberately
// bypasses BOTH the per-op backend-preference dispatch (readVia/readerFor,
// and therefore s.readerCache) AND s.model's SNMP-backend gate entirely --
// mirroring Python's identify() (D-FAC §2.11) exactly: it exists precisely
// to confirm/discover a switch's real model when the caller does not yet
// trust s.model, so it reuses an injected client (or builds a default one
// via buildSNMPClient, the SAME path buildSNMPReader uses) without ever
// checking s.model.HasBackend(model.BackendSNMP) -- it works even when
// s.model has no SNMP backend at all (e.g. a Plus-class model). No reader is
// built or cached; this is a bare client plus one call to
// snmp.ReadSystemInfo.
func (s *Switch) Identify(ctx context.Context) (model.DetectedModel, error) {
	if err := ctx.Err(); err != nil {
		return model.DetectedModel{}, err
	}
	client, err := buildSNMPClient(s)
	if err != nil {
		return model.DetectedModel{}, err
	}
	return snmp.ReadSystemInfo(ctx, client)
}
