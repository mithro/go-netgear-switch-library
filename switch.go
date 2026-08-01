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

	"github.com/mithro/go-netgear-switch-library/fastpath"
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
	"github.com/mithro/go-netgear-switch-library/snmp"
	"github.com/mithro/go-netgear-switch-library/webui"
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

	// nsdpClient, if non-nil, is used as-is by BOTH the NSDP BackendBuilder
	// and BackendWriter (backend_nsdp.go's buildNSDPClient) instead of
	// building a default one -- unlike SNMP's separate read/write client
	// fields, NSDP has only ONE injected-client field: package nsdp's
	// default-built client (nsdp.NewUDPClient) always satisfies both
	// nsdp.Client and nsdp.WriteClient (D-NSDP §10.2/§8.1), so there is
	// nothing to split.
	nsdpClient nsdp.Client

	// nsdpPassword resolves the NSDP v1 write-auth admin password lazily,
	// INDEPENDENT of httpPassword below -- mirroring Python's
	// SyncSwitch.__init__ exactly: nsdp_password/nsdp_password_resolver is a
	// SEPARATE constructor param and _resolved_nsdp_password a SEPARATE
	// resolve-once cell from http_password/http_password_resolver/
	// _resolved_http_password. Only SyncSwitch.from_config happens to feed
	// both from the same cfg.http_password(env) spec (via two independent
	// closures, each re-resolving that spec on its own first use) -- a
	// deliberate, source-commented choice ("the facade already accepts a
	// distinct nsdp_password/nsdp_password_resolver ... if a deployment
	// ever needs to split them; do NOT add a separate config key now") that
	// preserves the option for a New()+options caller to supply a genuinely
	// different NSDP password than the HTTP one, without an API break.
	// Consumed by backend_nsdp.go's buildNSDPWriter.
	nsdpPassword *resolveOnce

	// httpPassword resolves the HTTP admin password lazily; consumed by
	// slice 06's HTTP writer. See nsdpPassword's doc comment above for why
	// this is a SEPARATE cell, not a shared one, despite FromConfig feeding
	// both from the same underlying secret spec.
	httpPassword *resolveOnce

	// httpClient, if non-nil, is used AS-IS by every HTTP consumer
	// (backend_http.go's buildHTTPReader/buildHTTPWriter/
	// Switch.UploadCertificate) instead of a default one this Switch would
	// otherwise build+cache from host/the resolved HTTP password. Mirrors
	// WithSNMPClient/WithNSDPClient; unlike SNMP's split read/write client
	// fields, ONE field serves all three HTTP consumers here -- exactly
	// like NSDP's single nsdpClient field -- because webui.Session already
	// spans reads, writes AND cert-upload (webui/types.go).
	httpClient webui.Session

	// httpSessionMu guards httpSessionCache below.
	httpSessionMu sync.Mutex
	// httpSessionCache is the lazily-built DEFAULT webui.Session this Switch
	// built for itself (nil until first built, or forever nil when
	// httpClient was injected instead) -- shared across
	// buildHTTPReader/buildHTTPWriter/UploadCertificate so all three reuse
	// the SAME login session (one password resolution, one cookie jar/
	// Gambit token), mirroring Python's SyncSwitch._built_http_client.
	// Closed by Close().
	httpSessionCache *lazyHTTPSession

	// cliClient, if non-nil, is used AS-IS by every FASTPATH-CLI consumer
	// (backend_cli.go's buildCLIReader/buildCLIWriter) instead of a default
	// SSH/telnet session this Switch would otherwise build+cache. Mirrors
	// httpClient/nsdpClient; ONE injected fastpath.Session spans CLI reads
	// AND writes (a CLI session is a single interactive shell), so no split
	// read/write field is drawn -- exactly like NSDP/HTTP.
	cliClient fastpath.Session

	// cliPassword resolves the FASTPATH-CLI login password lazily, INDEPENDENT
	// of the other password cells (mirroring nsdpPassword/httpPassword's own
	// independence -- see nsdpPassword's doc comment). Consumed by
	// backend_cli.go's default-session builder.
	cliPassword *resolveOnce

	// cliUsername is the FASTPATH-CLI login username (default "admin"). The
	// per-model CliModelSpec carries no username (the device prompt is the
	// same regardless), so it lives here, set via WithCLIUsername.
	cliUsername string

	// sshPort / telnetPort override the CLI transport's TCP port when set
	// (nil = SSH's default 22 / the model's CliModelSpec.TelnetPort). Set via
	// WithSSHPort/WithTelnetPort -- needed to dial a fake's ephemeral loopback
	// listener (the virtual SSH/telnet faces, Task 12) in tests and the
	// cross-language suite.
	sshPort    *int
	telnetPort *int

	// cliSessionMu guards cliSessionCache below.
	cliSessionMu sync.Mutex
	// cliSessionCache holds the lazily-built DEFAULT fastpath.Session per
	// transport kind (ssh/telnet) this Switch built for itself -- keyed by
	// kind so an explicit per-op WithReadBackend(SSH)+Write-over-telnet never
	// reuses the wrong transport's shell. Each entry is shared by the reader
	// AND writer for that kind (one login, one interactive shell), mirroring
	// Python's SyncSwitch._built_cli_client. Closed by Close().
	cliSessionCache map[cliTransportKind]*lazyCLISession

	// protectedPorts is stored sorted ascending with duplicates removed
	// (this codebase's canonical form for Python's frozenset[int]; see
	// config.go's protectedPorts helper for the same convention).
	protectedPorts []int

	// backend, if set, pins EVERY op on this Switch to exactly one backend
	// by default (nil = the model's highest-preference one -- see
	// resolveBackend in dispatch.go). Set via WithBackend to restrict a
	// whole session to one protocol ("talk to this switch over HTTP only");
	// a per-call ReadOption/Write.Backend override still wins over this.
	// Mirrors Python's SyncSwitch.backend (D-REC A.3).
	backend *model.Backend

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

// WithNSDPInterface names the network interface a default-built NSDP client
// should bind to (best-effort SO_BINDTODEVICE, plus the sysfs-read
// ClientMAC source absent an explicit one), consumed by backend_nsdp.go's
// buildNSDPClient. No effect when a client is injected via WithNSDPClient.
func WithNSDPInterface(s string) SwitchOption {
	return func(sw *Switch) { sw.nsdpInterface = &s }
}

// WithNSDPClient injects an already-built nsdp.Client, used as-is instead of
// a default one the NSDP BackendBuilder/WriteBackendBuilder would otherwise
// construct from the host/interface -- primarily for tests (a fake/virtual
// client, or a real nsdp.UDPClient pointed at a VirtualSwitch's ephemeral
// NsdpPort) or a caller reusing an already-open client. Mirrors
// WithSNMPClient; unlike SNMP, one field/option serves BOTH reads and
// writes (see Switch.nsdpClient's doc comment).
func WithNSDPClient(c nsdp.Client) SwitchOption {
	return func(sw *Switch) { sw.nsdpClient = c }
}

// WithNSDPPassword sets the NSDP v1 write-auth admin password literally (a
// plain string, not a secret spec), mirroring Python's nsdp_password
// constructor parameter. INDEPENDENT of any HTTP password configured via
// WithHTTPPasswordResolver -- see Switch.nsdpPassword's doc comment.
func WithNSDPPassword(s string) SwitchOption {
	return func(sw *Switch) {
		sw.nsdpPassword = newResolveOnce(func() (*string, error) { return &s, nil })
	}
}

// WithNSDPPasswordResolver stashes r as the NSDP v1 write-auth admin-
// password resolver, invoked at most once, lazily, on first NSDP write --
// mirroring Python's nsdp_password_resolver constructor parameter. Passing
// this option never causes r to run during New/FromConfig. INDEPENDENT of
// any HTTP password resolver configured via WithHTTPPasswordResolver -- see
// Switch.nsdpPassword's doc comment.
func WithNSDPPasswordResolver(r func() (*string, error)) SwitchOption {
	return func(sw *Switch) { sw.nsdpPassword = newResolveOnce(r) }
}

// WithHTTPPasswordResolver stashes r as the HTTP admin-password resolver,
// invoked at most once, lazily, on first HTTP session use (slice 06).
// Passing this option never causes r to run during New/FromConfig.
func WithHTTPPasswordResolver(r func() (*string, error)) SwitchOption {
	return func(sw *Switch) { sw.httpPassword = newResolveOnce(r) }
}

// WithHTTPPassword sets the HTTP admin password literally (a plain string,
// not a secret spec), mirroring Python's http_password constructor
// parameter and WithNSDPPassword's shape on the NSDP side. INDEPENDENT of
// any NSDP password configured via WithNSDPPassword/WithNSDPPasswordResolver
// -- see Switch.nsdpPassword's doc comment.
func WithHTTPPassword(s string) SwitchOption {
	return func(sw *Switch) {
		sw.httpPassword = newResolveOnce(func() (*string, error) { return &s, nil })
	}
}

// WithHTTPClient injects an already-built webui.Session, used as-is by
// EVERY HTTP consumer (the reader, the writer, and UploadCertificate)
// instead of a default one this Switch would otherwise build+cache from
// host/the resolved HTTP password. Primarily for tests (a fake/virtual
// session, or a real webui.HTTPClient pointed at a VirtualSwitch's
// ephemeral HTTPPort) or a caller reusing an already-logged-in session.
// Mirrors WithSNMPClient/WithNSDPClient.
func WithHTTPClient(session webui.Session) SwitchOption {
	return func(sw *Switch) { sw.httpClient = session }
}

// WithCLIPassword sets the FASTPATH-CLI login password literally (a plain
// string), mirroring WithHTTPPassword/WithNSDPPassword. INDEPENDENT of the
// other password cells -- see Switch.cliPassword's doc comment.
func WithCLIPassword(s string) SwitchOption {
	return func(sw *Switch) {
		sw.cliPassword = newResolveOnce(func() (*string, error) { return &s, nil })
	}
}

// WithCLIPasswordResolver stashes r as the FASTPATH-CLI login-password
// resolver, invoked at most once, lazily, on first CLI session use. Passing
// this option never causes r to run during New/FromConfig.
func WithCLIPasswordResolver(r func() (*string, error)) SwitchOption {
	return func(sw *Switch) { sw.cliPassword = newResolveOnce(r) }
}

// WithCLIUsername overrides the FASTPATH-CLI login username (default
// "admin"). WithSSHPassword is an alias for WithCLIPassword kept for callers
// who think in transport terms; there is only ONE CLI credential pair.
func WithCLIUsername(username string) SwitchOption {
	return func(sw *Switch) { sw.cliUsername = username }
}

// WithSSHPassword is an alias for WithCLIPassword (SSH and telnet share the
// one FASTPATH-CLI credential pair), for callers who think in transport
// terms.
func WithSSHPassword(s string) SwitchOption { return WithCLIPassword(s) }

// WithSSHPort overrides the TCP port the SSH CLI transport dials (default
// 22) -- needed to reach a virtual SSH face's ephemeral loopback port.
func WithSSHPort(port int) SwitchOption {
	return func(sw *Switch) { p := port; sw.sshPort = &p }
}

// WithTelnetPort overrides the TCP port the telnet CLI transport dials
// (default the model's CliModelSpec.TelnetPort) -- needed to reach a virtual
// telnet face's ephemeral loopback port.
func WithTelnetPort(port int) SwitchOption {
	return func(sw *Switch) { p := port; sw.telnetPort = &p }
}

// WithCLIClient injects an already-built fastpath.Session, used as-is by the
// CLI reader AND writer instead of a default SSH/telnet session this Switch
// would otherwise build+cache. Primarily for tests. Mirrors WithHTTPClient.
// An injected client is never Closed by Switch.Close (this Switch does not
// own it).
func WithCLIClient(session fastpath.Session) SwitchOption {
	return func(sw *Switch) { sw.cliClient = session }
}

// WithBackend pins EVERY op on this Switch to backend by default, unless a
// per-call ReadOption/Write.Backend override says otherwise (which still
// wins). Absent this option, a Switch has no pinned default and each op
// resolves to the model's own highest-preference backend (see
// resolveBackend in dispatch.go). Mirrors Python's SyncSwitch backend=
// constructor keyword (D-REC A.3/A.10.2) -- setting it is the session-wide
// equivalent of passing backend= on every single call.
func WithBackend(b model.Backend) SwitchOption {
	return func(sw *Switch) { sw.backend = &b }
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
		nsdpPassword:       newResolveOnce(nil),
		httpPassword:       newResolveOnce(nil),
		cliPassword:        newResolveOnce(nil),
		cliUsername:        "admin",
		cliSessionCache:    make(map[cliTransportKind]*lazyCLISession),
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
//   - cfg.HTTPPasswordSpec becomes TWO INDEPENDENT resolver closures, each
//     calling cfg.HTTPPassword(os.LookupEnv, nil) -- LAZY, never invoked
//     here -- one wired via WithHTTPPasswordResolver into httpPassword, the
//     other via WithNSDPPasswordResolver into the SEPARATE nsdpPassword
//     cell. Per D-FAC §2.16/D-NSDP §8.2, this mirrors Python's from_config
//     exactly: it feeds the SAME underlying cfg.http_password(env) spec to
//     BOTH _resolve_http_password and _resolve_nsdp_password, but those
//     remain two distinct closures/cells (SyncSwitch.__init__ itself takes
//     genuinely separate nsdp_password/nsdp_password_resolver and
//     http_password/http_password_resolver params) -- a New()+options caller
//     (unlike a FromConfig caller) CAN supply a different NSDP password via
//     WithNSDPPassword/WithNSDPPasswordResolver, since nothing here forces
//     the two cells to share a value, only FromConfig's shared spec does.
//   - cfg.ProtectedPorts maps to WithProtectedPorts.
//
// opts, if given, are applied AFTER the config-derived options, so a caller
// can override any config-mapped field (e.g. inject a fake snmp.Client in
// tests) without FromConfig needing its own escape hatch per field.
func FromConfig(cfg SwitchConfig, opts ...SwitchOption) (*Switch, error) {
	configOpts := make([]SwitchOption, 0, 7+len(opts))

	if cfg.SNMPCommunity != nil {
		configOpts = append(configOpts, WithSNMPCommunity(*cfg.SNMPCommunity))
	}
	configOpts = append(configOpts, WithSNMPWriteCommunityResolver(func() (*string, error) {
		return cfg.SNMPWriteCommunity(os.LookupEnv, nil)
	}))
	if cfg.NSDPInterface != nil {
		configOpts = append(configOpts, WithNSDPInterface(*cfg.NSDPInterface))
	}
	// TWO independent closures over the SAME cfg.HTTPPassword spec, wired
	// into TWO independent resolveOnce cells -- mirroring Python's
	// from_config, which defines _resolve_nsdp_password and
	// _resolve_http_password as separate functions that both happen to call
	// cfg.http_password(env=_env) (see nsdpPassword's doc comment on Switch).
	configOpts = append(configOpts, WithNSDPPasswordResolver(func() (*string, error) {
		return cfg.HTTPPassword(os.LookupEnv, nil)
	}))
	configOpts = append(configOpts, WithHTTPPasswordResolver(func() (*string, error) {
		return cfg.HTTPPassword(os.LookupEnv, nil)
	}))
	configOpts = append(configOpts, WithProtectedPorts(cfg.ProtectedPorts...))
	configOpts = append(configOpts, opts...)

	return New(cfg.Model, cfg.Host, configOpts...)
}

// Close releases the HTTP client THIS Switch built for itself (never one
// injected via WithHTTPClient) -- the "sole persistent connection worth
// closing" D-FAC §2.15 anticipated. SNMP/NSDP clients (injected or default-
// built) are still never closed (mirroring Python: they are built fresh per
// call and need no teardown). Safe to call at any time, including on a
// Switch that never dispatched a single HTTP op (or any op at all).
func (s *Switch) Close() error {
	s.httpSessionMu.Lock()
	cache := s.httpSessionCache
	s.httpSessionCache = nil
	s.httpSessionMu.Unlock()
	if cache != nil {
		if closable, ok := cache.builtSession().(interface{ Close() }); ok {
			closable.Close()
		}
	}

	// Release every FASTPATH-CLI shell this Switch built for itself (one per
	// transport kind). Unlike an HTTP session (a cookie jar with nothing to
	// close on the wire), a CLI session is a live SSH/telnet connection whose
	// socket MUST be closed -- Python's own SyncSwitch.close() forgets to do
	// this (a real socket leak, transport dossier §0/§4.3); the Go port
	// deliberately does NOT reproduce that bug. An INJECTED cliClient
	// (WithCLIClient) is never closed here -- this Switch does not own it.
	s.cliSessionMu.Lock()
	cliCaches := s.cliSessionCache
	s.cliSessionCache = make(map[cliTransportKind]*lazyCLISession)
	s.cliSessionMu.Unlock()
	for _, c := range cliCaches {
		if built := c.builtSession(); built != nil {
			_ = built.Close()
		}
	}
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
// SyncSwitch read methods: the ONLY per-method logic is which BackendReader
// method is invoked and how its result is captured; single-backend
// resolution/dispatch semantics live entirely in dispatch.go's readVia.
// GetMACs is the one exception with an extra guard (require_mac_table, run
// BEFORE dispatch); see getMACsNoGate below for the ungated variant
// snapshot.go's Snapshot uses instead of this method.
//
// Every method takes a trailing ...ReadOption (D-REC A.10.3): pass
// WithReadBackend(b) to run THIS ONE call over exactly b, overriding both
// this Switch's pinned default (WithBackend) and the model's own
// highest-preference backend. A zero-arg call costs nothing extra (Go's
// variadic-with-no-args is free) and resolves exactly as before this
// option existed.

// readOptions carries the per-call knobs every read method's trailing
// ...ReadOption accepts -- currently just an optional backend override.
// Mirrors CycleOption's role for CyclePoE/ClearPoEFault (switch_write.go).
type readOptions struct {
	backend *model.Backend
}

// ReadOption configures one read call; see WithReadBackend.
type ReadOption func(*readOptions)

// WithReadBackend runs ONE read call over exactly backend, overriding both
// this Switch's pinned default (WithBackend) and the model's own
// highest-preference backend (D-REC A.10.3). The named backend must be one
// the model declares (model.SwitchModel.Backends) or the call raises naming
// it (resolveBackend's "no such backend" shape, dispatch.go); it need not be
// one that can actually serve the operation -- an op the named backend
// cannot serve still raises, just from cannotServe's "requested" branch
// (no "try another backend" hint), never falling back to a different one.
func WithReadBackend(b model.Backend) ReadOption {
	return func(o *readOptions) { o.backend = &b }
}

// resolveReadOptions applies opts, in order, to a fresh readOptions,
// mirroring cycleTimeoutsFromOptions's default-then-override shape
// (switch_write.go).
func resolveReadOptions(opts []ReadOption) readOptions {
	var o readOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// GetPorts reads per-port administrative/operational status, speed, name and
// description via the resolved backend (see readOptions above).
func (s *Switch) GetPorts(ctx context.Context, opts ...ReadOption) ([]model.PortStatus, error) {
	o := resolveReadOptions(opts)
	var out []model.PortStatus
	err := s.readVia(ctx, o.backend, func(r BackendReader) error {
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
func (s *Switch) GetStats(ctx context.Context, opts ...ReadOption) ([]model.PortStats, error) {
	o := resolveReadOptions(opts)
	var out []model.PortStats
	err := s.readVia(ctx, o.backend, func(r BackendReader) error {
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
func (s *Switch) GetVLANs(ctx context.Context, opts ...ReadOption) ([]model.VLANInfo, error) {
	o := resolveReadOptions(opts)
	var out []model.VLANInfo
	err := s.readVia(ctx, o.backend, func(r BackendReader) error {
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
func (s *Switch) GetPVIDs(ctx context.Context, opts ...ReadOption) ([]model.Pvid, error) {
	o := resolveReadOptions(opts)
	var out []model.Pvid
	err := s.readVia(ctx, o.backend, func(r BackendReader) error {
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
func (s *Switch) GetLLDP(ctx context.Context, opts ...ReadOption) ([]model.LLDPNeighbor, error) {
	o := resolveReadOptions(opts)
	var out []model.LLDPNeighbor
	err := s.readVia(ctx, o.backend, func(r BackendReader) error {
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
// ("snapshot()'s macs field does NOT call require_mac_table -- it just lets
// _read exhaust naturally to the same outcome"). Exported only within this
// package; snapshot.go's Snapshot is its other caller.
func (s *Switch) getMACsNoGate(ctx context.Context, opts ...ReadOption) ([]model.MacEntry, error) {
	o := resolveReadOptions(opts)
	var out []model.MacEntry
	err := s.readVia(ctx, o.backend, func(r BackendReader) error {
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
// unconditionally, BEFORE any backend dispatch is attempted: a model with no
// MAC table (i.e. no SNMP backend -- see model.SwitchModel.HasMACTable)
// raises directly from this guard and never even enters readVia, mirroring
// Python's exact error text (`f"model {model.key!r} has no MAC/FDB table"`).
func (s *Switch) GetMACs(ctx context.Context, opts ...ReadOption) ([]model.MacEntry, error) {
	if !s.model.HasMACTable() {
		return nil, fmt.Errorf("model %q has no MAC/FDB table: %w", s.model.Key, model.ErrUnsupportedCapability)
	}
	return s.getMACsNoGate(ctx, opts...)
}

// GetPoE reads the per-port Power-over-Ethernet status. No facade-level
// guard: each backend's own reader (e.g. snmp.Reader.GetPoE) applies its own
// 0-PSE-port capability gate internally.
func (s *Switch) GetPoE(ctx context.Context, opts ...ReadOption) ([]model.PoEStatus, error) {
	o := resolveReadOptions(opts)
	var out []model.PoEStatus
	err := s.readVia(ctx, o.backend, func(r BackendReader) error {
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
func (s *Switch) GetSensors(ctx context.Context, opts ...ReadOption) ([]model.Sensor, error) {
	o := resolveReadOptions(opts)
	var out []model.Sensor
	err := s.readVia(ctx, o.backend, func(r BackendReader) error {
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
func (s *Switch) GetMgmtIP(ctx context.Context, opts ...ReadOption) (model.MgmtIPConfig, error) {
	o := resolveReadOptions(opts)
	var out model.MgmtIPConfig
	err := s.readVia(ctx, o.backend, func(r BackendReader) error {
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

// NSDPDevice returns the COMPLETE raw NSDP-native device snapshot for this
// switch (every tag nsdp.ParseDevice knows how to decode, in one round
// trip). Unlike every other read method, this deliberately BYPASSES the
// SNMP/NSDP/HTTP backend-preference dispatch (readVia) entirely, mirroring
// Python's sync_api.nsdp_device() (D-NSDP §8.3): NSDP is the ONLY backend
// that can ever serve it, so a model without an NSDP backend raises an
// error wrapping model.ErrUnsupportedCapability directly rather than
// falling back to (or through) any other backend. Also unlike readVia's
// cached readerFor path, this builds a fresh nsdp.Reader on every call --
// the same bypass shape Identify uses for SNMP (buildSNMPClient, above),
// since GetDevice is not part of the 9-method BackendReader interface
// readerFor's cache holds.
func (s *Switch) NSDPDevice(ctx context.Context) (model.NsdpDevice, error) {
	if err := ctx.Err(); err != nil {
		return model.NsdpDevice{}, err
	}
	if !s.model.HasBackend(model.BackendNSDP) {
		return model.NsdpDevice{}, fmt.Errorf("model %q has no NSDP backend: %w", s.model.Key, model.ErrUnsupportedCapability)
	}
	client, err := buildNSDPClient(s)
	if err != nil {
		return model.NsdpDevice{}, err
	}
	reader, err := nsdp.NewReader(client, s.model)
	if err != nil {
		return model.NsdpDevice{}, err
	}
	return reader.GetDevice(ctx)
}
