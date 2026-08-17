// Package resolve builds a *netgearswitch.Switch from CLI-flag-shaped or
// MCP-tool-param-shaped input, ported from
// src/netgear_switch/cli/resolve.py (the normative source; that repo is
// read-only from here). Any discrepancy between this file and the pinned
// Python source is a bug in this file.
//
// Credential precedence (mirroring resolve.py's module doc comment, design
// spec Sec5.1): CLI flag -> environment variable -> inventory config value
// -> interactive prompt. The whole package is a pure "Params -> (*Switch,
// error)" function plus a handful of pure precedence helpers, so it is
// unit-testable without a real switch, a real TTY, or the process's real
// environment: env and the interactive prompt are both injectable via
// Option (WithEnv/WithPrompt).
package resolve

import (
	"fmt"
	"os"
	"strings"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/model"
)

// Params is the resolution-agnostic set of inputs Resolve consumes,
// mirroring the argparse.Namespace fields resolve.py's resolve_switch
// reads. Both the CLI (a struct populated by a flag parser) and the MCP
// server (a struct populated from per-tool JSON params) build one of
// these and hand it to Resolve; neither needs to know how the other
// gathers its fields. The zero value of every string field ("") means
// "not given" -- there is no separate "was this flag present" bit,
// matching argparse's own None-vs-falsy-default handling for these
// specific fields (an empty string is never a meaningful flag value here).
type Params struct {
	// Switch names an inventory entry ([switches.NAME] in Config's TOML
	// file). When set, it wins over Host/Model entirely (mirrors
	// resolve.py's `if args.switch:` check) -- Config must also be set.
	Switch string
	// Config is the path to an inventory TOML file (--config). Required
	// when Switch is set; unused on the Host/Model path.
	Config string

	// Host and Model build a Switch directly, with no inventory -- used
	// only when Switch is empty. Model is looked up via
	// netgearswitch.GetModel (canonical key or alias).
	Host  string
	Model string

	// Community is the SNMP read community (--community). Wins over the
	// NGSW_COMMUNITY env var, the inventory's snmp.community, and the
	// interactive prompt.
	Community string
	// WriteCommunity is the SNMP write community (--write-community).
	// Wins over the NGSW_WRITE_COMMUNITY env var and the inventory's
	// snmp.write_community secret spec.
	WriteCommunity string
	// Backend pins every op of the built Switch to one protocol
	// (--backend), one of "snmp", "nsdp", "http", "ssh", "telnet",
	// "console" (case-sensitive, lowercase only -- matching the wire
	// values model.Backend uses). Empty leaves the model's own
	// highest-preference backend in force.
	Backend string
	// NSDPInterface names the network interface a default-built NSDP
	// client should bind to (--nsdp-interface). Wins over the inventory's
	// nsdp.interface.
	NSDPInterface string
	// HTTPPassword is the web-admin password (--http-password). Wins over
	// the inventory's http.password secret spec, and -- mirroring
	// resolve.py's shared-secret comment -- feeds BOTH the HTTP and NSDP
	// v1 write-auth password cells: Plus-class models share one
	// web-admin secret across both protocols.
	HTTPPassword string
}

// PromptFunc requests one line of interactive input, given the label to
// show the user (e.g. "SNMP read community: "). A nil PromptFunc (the
// Resolve default) disables interactive prompting entirely: SNMP-community
// resolution simply stops at the config tier and leaves the community
// unresolved rather than blocking on stdin -- the right default for a
// non-interactive caller (the MCP server, a piped CLI invocation, or any
// test). See NewStdinPrompt for a real-TTY implementation the CLI can
// inject.
type PromptFunc func(label string) (string, error)

// options holds Resolve's injectable dependencies (env lookup + the
// interactive prompt), configured via Option. Unexported: callers only
// ever see the With* constructors.
type options struct {
	env    func(string) (string, bool)
	prompt PromptFunc
}

// Option configures Resolve's injectable dependencies; see WithEnv and
// WithPrompt.
type Option func(*options)

// WithEnv overrides the environment lookup Resolve uses for NGSW_COMMUNITY/
// NGSW_WRITE_COMMUNITY and (on the inventory path) the env passed to the
// inventory's own secret-spec resolvers (snmp.write_community,
// http.password). Absent this option, Resolve uses os.LookupEnv (the
// process's real environment) -- mirroring resolve.py's `env =
// os.environ if env is None else env`. Primarily for tests, which can
// inject a fake map-backed lookup instead of mutating the real process
// environment.
func WithEnv(env func(string) (string, bool)) Option {
	return func(o *options) { o.env = env }
}

// WithPrompt supplies the interactive prompt Resolve falls back to for an
// unresolved SNMP read community, ONLY on a model that actually has an
// SNMP backend (see readCommunity). Absent this option, Resolve never
// prompts -- matching resolve.py's `prompt: Callable[[str], str] | None =
// None` default.
func WithPrompt(p PromptFunc) Option {
	return func(o *options) { o.prompt = p }
}

// resolveOptions applies opts, in order, over Resolve's defaults (the
// process's real environment, no interactive prompt).
func resolveOptions(opts []Option) options {
	o := options{env: os.LookupEnv}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// Resolve builds a *netgearswitch.Switch from p, mirroring resolve.py's
// resolve_switch: an inventory lookup (p.Switch, requires p.Config) wins
// when given; otherwise p.Host/p.Model build a switch directly (no
// inventory, no protected-ports config, no --nsdp-interface/
// --http-password fallback value). Neither path performs I/O beyond a
// (possible) inventory-file read and a (possible) interactive prompt: no
// secret is resolved and no network connection is made here -- every
// resolver Resolve wires up is invoked lazily, at most once, by the
// *netgearswitch.Switch itself on first actual use (see switch.go's
// resolveOnce).
//
// The caller owns the returned Switch and MUST call its Close method when
// done (mirroring Python's context-manager SyncSwitch.close(), exposed
// here as an explicit method since Go has no `with` statement) --
// typically via `defer sw.Close()` immediately after a successful Resolve.
func Resolve(p Params, opts ...Option) (*netgearswitch.Switch, error) {
	o := resolveOptions(opts)

	if p.Switch != "" {
		return fromInventory(p, o)
	}
	if p.Host != "" && p.Model != "" {
		return fromHostModel(p, o)
	}
	return nil, fmt.Errorf("specify --switch <name> (with --config) or both --host and --model: %w", model.ErrConfig)
}

// fromInventory resolves p via an inventory lookup, mirroring resolve.py's
// _from_inventory exactly (see its module-level doc comment for the
// shared-HTTP-password-spec rationale repeated on Params.HTTPPassword).
func fromInventory(p Params, o options) (*netgearswitch.Switch, error) {
	if p.Config == "" {
		return nil, fmt.Errorf("--switch requires --config <inventory.toml>: %w", model.ErrConfig)
	}
	inventory, err := netgearswitch.LoadInventory(p.Config)
	if err != nil {
		return nil, err
	}
	cfg, ok := inventory[p.Switch]
	if !ok {
		return nil, fmt.Errorf("switch %q not found in %s: %w", p.Switch, p.Config, model.ErrConfig)
	}

	// --nsdp-interface wins over the inventory's nsdp.interface; feed the
	// (possibly overridden) value through FromConfig's own mapping rather
	// than re-deriving it, mirroring _nsdp_interface.
	cfg.NSDPInterface = nsdpInterfaceOverride(p.NSDPInterface, cfg.NSDPInterface)

	community, err := readCommunity(p.Community, o.env, cfg.SNMPCommunity, o.prompt, cfg.Model.HasBackend(model.BackendSNMP))
	if err != nil {
		return nil, err
	}

	var fcOpts []netgearswitch.SwitchOption
	if community != nil {
		fcOpts = append(fcOpts, netgearswitch.WithSNMPCommunity(*community))
	}

	// The write community ALWAYS gets its own resolver here (mirroring
	// _from_inventory always passing both snmp_write_community and
	// snmp_write_community_resolver to SyncSwitch): a literal --write-
	// community/NGSW_WRITE_COMMUNITY override wins immediately, else the
	// inventory's own snmp.write_community secret spec is resolved lazily
	// -- using o.env (the INJECTED environment), not FromConfig's own
	// hardcoded os.LookupEnv, so this whole path stays testable without
	// touching the process's real environment.
	writeOverride := writeCommunityOverride(p.WriteCommunity, o.env)
	fcOpts = append(fcOpts, netgearswitch.WithSNMPWriteCommunityResolver(
		writeCommunityResolver(writeOverride, func() (*string, error) { return cfg.SNMPWriteCommunity(o.env, nil) }),
	))

	// The ONE HTTPPassword resolver feeds BOTH the NSDP and HTTP password
	// cells (mirroring _from_inventory's single `password_resolver`
	// passed to both nsdp_password_resolver and http_password_resolver):
	// Plus-class models share one web-admin secret across both protocols.
	// --http-password wins immediately (config_resolver is never even
	// invoked -- a read-only op on an SNMP switch must never force
	// resolution of an absent web password); else the inventory's
	// http.password secret spec is resolved lazily via o.env.
	pwResolver := httpPasswordResolver(p.HTTPPassword, func() (*string, error) { return cfg.HTTPPassword(o.env, nil) })
	fcOpts = append(fcOpts, netgearswitch.WithNSDPPasswordResolver(pwResolver), netgearswitch.WithHTTPPasswordResolver(pwResolver))

	backend, err := parseBackend(p.Backend)
	if err != nil {
		return nil, err
	}
	if backend != nil {
		fcOpts = append(fcOpts, netgearswitch.WithBackend(*backend))
	}

	return netgearswitch.FromConfig(cfg, fcOpts...)
}

// fromHostModel resolves p via --host/--model directly, with no inventory,
// mirroring resolve.py's resolve_switch host/model branch exactly: a Plus
// switch (NSDP/HTTP) reached this way still needs --nsdp-interface/
// --http-password to be usable -- there is no config value to fall back
// to on this path, only the CLI flags themselves.
func fromHostModel(p Params, o options) (*netgearswitch.Switch, error) {
	m, err := netgearswitch.GetModel(p.Model)
	if err != nil {
		return nil, err
	}

	community, err := readCommunity(p.Community, o.env, nil, o.prompt, m.HasBackend(model.BackendSNMP))
	if err != nil {
		return nil, err
	}

	var swOpts []netgearswitch.SwitchOption
	if community != nil {
		swOpts = append(swOpts, netgearswitch.WithSNMPCommunity(*community))
	}
	if writeOverride := writeCommunityOverride(p.WriteCommunity, o.env); writeOverride != nil {
		swOpts = append(swOpts, netgearswitch.WithSNMPWriteCommunityResolver(writeCommunityResolver(writeOverride, nil)))
	}
	if iface := nsdpInterfaceOverride(p.NSDPInterface, nil); iface != nil {
		swOpts = append(swOpts, netgearswitch.WithNSDPInterface(*iface))
	}
	if p.HTTPPassword != "" {
		pwResolver := httpPasswordResolver(p.HTTPPassword, nil)
		swOpts = append(swOpts, netgearswitch.WithNSDPPasswordResolver(pwResolver), netgearswitch.WithHTTPPasswordResolver(pwResolver))
	}

	backend, err := parseBackend(p.Backend)
	if err != nil {
		return nil, err
	}
	if backend != nil {
		swOpts = append(swOpts, netgearswitch.WithBackend(*backend))
	}

	return netgearswitch.New(m, p.Host, swOpts...)
}

// readCommunity resolves the SNMP read community by precedence CLI flag ->
// NGSW_COMMUNITY env var -> config value -> interactive prompt, mirroring
// resolve.py's _read_community exactly (including its doc comment below).
//
// Only an SNMP-capable model needs a read community. A Plus (NSDP/
// HTTP-only) switch has no SNMP backend, so prompting for one is both
// pointless and, in a non-interactive context (piped stdin), a hard block
// on the NSDP/HTTP reads entirely -- snmpBackend=false (or prompt==nil)
// skips the prompt tier and returns (nil, nil) instead.
//
// A bare Enter at the prompt (or any all-whitespace reply) must NOT become
// a literal empty-string SNMP community; it is treated as unresolved so
// the library's existing lazy CredentialError fires at SNMP-build time
// instead (CLI/env/config tiers are out of scope here, same as Python).
func readCommunity(flag string, env func(string) (string, bool), configValue *string, prompt PromptFunc, snmpBackend bool) (*string, error) {
	if flag != "" {
		v := flag
		return &v, nil
	}
	if v, _ := env("NGSW_COMMUNITY"); v != "" {
		return &v, nil
	}
	if configValue != nil && *configValue != "" {
		return configValue, nil
	}
	if snmpBackend && prompt != nil {
		typed, err := prompt("SNMP read community: ")
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(typed) == "" {
			return nil, nil
		}
		return &typed, nil
	}
	return nil, nil
}

// writeCommunityOverride resolves a LITERAL write-community override by
// precedence CLI flag -> NGSW_WRITE_COMMUNITY env var, mirroring
// resolve.py's _write_community_override exactly. Returns nil when
// neither tier has a value -- the caller falls back to a lazy inventory
// resolver (or, on the --host/--model path, to no write community at
// all).
func writeCommunityOverride(flag string, env func(string) (string, bool)) *string {
	if flag != "" {
		v := flag
		return &v
	}
	if v, _ := env("NGSW_WRITE_COMMUNITY"); v != "" {
		return &v
	}
	return nil
}

// writeCommunityResolver combines a literal override (from
// writeCommunityOverride, possibly nil) with a lazy config resolver
// (possibly nil, e.g. on the --host/--model path) into the single
// resolver function netgearswitch.WithSNMPWriteCommunityResolver accepts:
// the literal wins immediately, WITHOUT ever invoking configResolver (a
// read-only op must never force resolution of an absent inventory
// secret); otherwise configResolver is called, or (nil, nil) if there is
// none. Mirrors the precedence SyncSwitch's own snmp_write_community
// (literal) vs snmp_write_community_resolver (lazy) constructor
// parameters apply.
func writeCommunityResolver(literal *string, configResolver func() (*string, error)) func() (*string, error) {
	return func() (*string, error) {
		if literal != nil {
			return literal, nil
		}
		if configResolver != nil {
			return configResolver()
		}
		return nil, nil
	}
}

// nsdpInterfaceOverride returns flag (wrapped) when given, else
// configValue unchanged -- mirroring resolve.py's _nsdp_interface exactly.
// configValue is nil on the --host/--model path (no inventory).
func nsdpInterfaceOverride(flag string, configValue *string) *string {
	if flag != "" {
		v := flag
		return &v
	}
	return configValue
}

// httpPasswordResolver returns the single resolver fed to BOTH the NSDP
// and HTTP password cells (see Params.HTTPPassword's doc comment),
// mirroring resolve.py's _http_password_resolver exactly: the CLI flag
// wins when given, returned directly WITHOUT ever invoking configResolver
// (lazy, like the inventory resolver it wraps -- a read-only op on an
// SNMP switch must never force resolution of an absent web password);
// otherwise falls back to configResolver (nil on the --host/--model path).
func httpPasswordResolver(flag string, configResolver func() (*string, error)) func() (*string, error) {
	return func() (*string, error) {
		if flag != "" {
			v := flag
			return &v, nil
		}
		if configResolver != nil {
			return configResolver()
		}
		return nil, nil
	}
}

// backendNames maps every --backend flag value this library accepts to
// its model.Backend, mirroring resolve.py's `Backend[name.upper()]` enum
// lookup -- except keyed directly by the lowercase wire value (this
// codebase's model.Backend constants ARE their lowercase string value, see
// model/registry.go), so no case-folding happens here: an upper-case or
// mixed-case flag value is rejected, not normalised.
var backendNames = map[string]model.Backend{
	string(model.BackendSNMP):    model.BackendSNMP,
	string(model.BackendNSDP):    model.BackendNSDP,
	string(model.BackendHTTP):    model.BackendHTTP,
	string(model.BackendSSH):     model.BackendSSH,
	string(model.BackendTelnet):  model.BackendTelnet,
	string(model.BackendConsole): model.BackendConsole,
}

// parseBackend validates name against the 6 lowercase backend names
// (--backend snmp|nsdp|http|ssh|telnet|console), mirroring resolve.py's
// _backend: an empty name (flag not given) returns (nil, nil), leaving
// the model's own default resolution in place; any other unrecognised
// name is an error wrapping model.ErrConfig.
func parseBackend(name string) (*model.Backend, error) {
	if name == "" {
		return nil, nil
	}
	b, ok := backendNames[name]
	if !ok {
		return nil, fmt.Errorf("unknown backend %q; must be one of snmp, nsdp, http, ssh, telnet, console: %w", name, model.ErrConfig)
	}
	return &b, nil
}
