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

	// mu guards readerCache: readerFor both reads and populates it, and a
	// Switch may be dispatched from multiple goroutines concurrently.
	mu          sync.Mutex
	readerCache map[model.Backend]BackendReader
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
