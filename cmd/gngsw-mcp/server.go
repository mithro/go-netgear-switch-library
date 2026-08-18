// Command gngsw-mcp is the Go port of Python's "ngsw-mcp" MCP server: it
// exposes the netgearswitch facade's read/write API as 35 MCP tools over
// stdio, built on the official Go MCP SDK
// (github.com/modelcontextprotocol/go-sdk/mcp). Ported from
// src/netgear_switch/mcp/server.py (the normative source; that repo is
// read-only from here). Any discrepancy between this package and the
// pinned Python source is a bug in this package, UNLESS explicitly called
// out in a comment as a deliberate deviation (see get_device's own doc
// comment in read.go for the one case where this package knowingly
// improves on a genuine bug in the pinned reference).
//
// server.go holds the package's shared scaffolding: EnvFunc (the
// injectable environment lookup every other file threads through, mirroring
// server.py's own `env: dict[str, str]` parameter), the selector/backend
// input-schema fragments every tool embeds, resolveSwitch (server.py's
// `_resolve` closure), writesEnabled (server.py's `writes_enabled`), the
// backend-name parser (server.py's `_as_backend`), and BuildServer itself
// (server.py's `build_server`).
package main

import (
	"fmt"
	"os"
	"strings"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/resolve"
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// serverVersion is this binary's reported Implementation.Version. Not a
// semver contract with anything else in this repo -- MCP clients display it,
// nothing here parses it back.
const serverVersion = "0.1.0"

// writeEnvVar / inventoryEnvVar are the two environment variables this
// server reads directly (as opposed to the several more resolve.Resolve
// itself consults for NGSW_COMMUNITY/NGSW_WRITE_COMMUNITY), mirroring
// server.py's module-level `_WRITE_ENV`/`_INVENTORY_ENV` constants exactly.
const (
	writeEnvVar     = "NGSW_MCP_ALLOW_WRITES"
	inventoryEnvVar = "NGSW_INVENTORY"
)

// EnvFunc is this server's injectable environment lookup, the same shape
// resolve.WithEnv accepts -- threaded through BuildServer into every tool
// closure (for NGSW_INVENTORY/NGSW_MCP_ALLOW_WRITES) AND into
// resolve.Resolve itself (for NGSW_COMMUNITY/NGSW_WRITE_COMMUNITY and the
// inventory path's own secret-spec resolvers), exactly mirroring server.py
// passing one `env` dict everywhere. Production wiring (main.go) uses
// os.LookupEnv; tests inject a fake map-backed lookup instead of mutating
// the real process environment.
type EnvFunc func(string) (string, bool)

// selectorFields carries the 7 params every read AND write tool accepts to
// pick and authenticate a target switch, mirroring server.py's `resolver()`
// closure's own parameter list (switch/host/model/config/community/
// http_password/nsdp_interface) -- embedded anonymously by every tool's
// input struct so its fields flatten straight into that tool's JSON
// arguments object. All optional (omitempty): the zero value "" means "not
// given", exactly matching resolve.Params' own zero-value convention.
type selectorFields struct {
	Switch        string `json:"switch,omitempty"        jsonschema:"inventory switch name (with config or $NGSW_INVENTORY)"`
	Host          string `json:"host,omitempty"          jsonschema:"switch host or IP address (with model)"`
	Model         string `json:"model,omitempty"         jsonschema:"switch model key (with host)"`
	Config        string `json:"config,omitempty"        jsonschema:"path to a TOML inventory file"`
	Community     string `json:"community,omitempty"     jsonschema:"SNMP read community"`
	HTTPPassword  string `json:"http_password,omitempty" jsonschema:"web-admin / NSDP write password"`
	NSDPInterface string `json:"nsdp_interface,omitempty" jsonschema:"network interface a default-built NSDP client should bind to"`
}

// backendField is embedded (alongside selectorFields) by every tool whose
// op can be pinned to one protocol per call -- every read/write tool except
// upload_certificate/upload_certificate_scp, which deliberately omit it (see
// write.go's own doc comment on those two).
type backendField struct {
	Backend string `json:"backend,omitempty" jsonschema:"pin the protocol used: snmp|nsdp|http|ssh|telnet|console; omit to use the model's default backend"`
}

// backendDoc is appended to every one of the 15 generically-registered read
// tools' descriptions, mirroring server.py's module-level `_BACKEND_DOC`
// constant verbatim (down to the double-space before "Omit", which is an
// artifact of Python's own multi-line string literal this port keeps for
// text parity). Deliberately NOT appended to any write tool's description --
// server.py's write tools are declared individually with a plain docstring,
// never routed through the `_register_read`-equivalent helper that adds this
// suffix.
const backendDoc = " Optional 'backend' pins the protocol used: snmp|nsdp|http|ssh|telnet|console. Omit it to use the model's default backend. The chosen backend either serves the operation or the call fails -- it is NEVER quietly run over a different protocol."

// backendNames maps every backend name this server accepts (case-
// insensitively, see parseBackendName) to its model.Backend, mirroring
// server.py's `_as_backend` -- which looks up `Backend[name.upper()]`
// against the six-member Backend enum. Keyed by the lowercase wire value
// (matching this codebase's model.Backend constants).
var backendNames = map[string]model.Backend{
	"snmp":    netgearswitch.BackendSNMP,
	"nsdp":    netgearswitch.BackendNSDP,
	"http":    netgearswitch.BackendHTTP,
	"ssh":     netgearswitch.BackendSSH,
	"telnet":  netgearswitch.BackendTelnet,
	"console": netgearswitch.BackendConsole,
}

// parseBackendName converts a tool's `backend` string into a *model.Backend
// (nil for "", meaning "use the model's default"), mirroring server.py's
// `_as_backend` exactly: an unrecognised name is rejected LOUDLY (wrapping
// model.ErrConfig) rather than silently falling back to the default backend
// -- principle 1, "never let a caller believe they pinned a protocol when
// they did not". Case-insensitive (name is lower-cased before lookup),
// matching Python's `name.upper()` fold.
func parseBackendName(name string) (*model.Backend, error) {
	if name == "" {
		return nil, nil
	}
	b, ok := backendNames[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown backend %q; expected one of: snmp, nsdp, http, ssh, telnet, console: %w", name, model.ErrConfig)
	}
	return &b, nil
}

// readOptsForBackend converts a parsed *model.Backend (possibly nil) into
// the netgearswitch.ReadOption slice a read call needs: nil yields no
// options (falls through to the switch's/model's own default resolution).
func readOptsForBackend(b *model.Backend) []netgearswitch.ReadOption {
	if b == nil {
		return nil
	}
	return []netgearswitch.ReadOption{netgearswitch.WithReadBackend(*b)}
}

// resolveSwitch builds the target *netgearswitch.Switch for sel, mirroring
// server.py's `_resolve` exactly: `switch` (with `config`, falling back to
// $NGSW_INVENTORY) wins when given, else both `host` and `model` are
// required. Deliberately never installs a resolve.WithPrompt: the
// resolve.Resolve package's own default (no injected PromptFunc) already
// disables interactive prompting entirely -- see resolve.PromptFunc's own
// doc comment -- which is exactly server.py's own `_no_prompt` contract (an
// unresolved SNMP community is left unresolved rather than blocking on
// stdin, surfacing as a lazy CredentialError at first actual use instead).
// A non-interactive MCP server calling this can therefore never hang on
// stdin waiting for a credential, by construction: there is nowhere in this
// call graph a prompt could even be wired in.
//
// The caller owns the returned Switch and MUST call its Close method when
// done (typically via `defer sw.Close()` immediately after a successful
// call), mirroring resolve.Resolve's own contract.
func resolveSwitch(env EnvFunc, sel selectorFields) (*netgearswitch.Switch, error) {
	if sel.Switch == "" && (sel.Host == "" || sel.Model == "") {
		return nil, fmt.Errorf("specify either `switch` (an inventory name, with `config` or $NGSW_INVENTORY) or both `host` and `model`: %w", model.ErrConfig)
	}
	config := sel.Config
	if config == "" {
		if v, ok := env(inventoryEnvVar); ok {
			config = v
		}
	}
	p := resolve.Params{
		Switch:        sel.Switch,
		Config:        config,
		Host:          sel.Host,
		Model:         sel.Model,
		Community:     sel.Community,
		NSDPInterface: sel.NSDPInterface,
		HTTPPassword:  sel.HTTPPassword,
	}
	return resolve.Resolve(p, resolve.WithEnv(env))
}

// writesEnabled reports whether the write tools should be registered,
// mirroring server.py's `writes_enabled` exactly: $NGSW_MCP_ALLOW_WRITES,
// trimmed and lower-cased, must be one of "1", "true", "yes", "on".
func writesEnabled(env EnvFunc) bool {
	v, _ := env(writeEnvVar)
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// BuildServer constructs the full MCP server: the 2 meta tools and 15 read
// tools are always registered; the 18 write tools are registered ONLY when
// writesEnabled(env) -- mirroring server.py's `build_server` exactly. A nil
// env defaults to os.LookupEnv (the process's real environment), matching
// server.py's `env = env if env is not None else dict(os.environ)`.
func BuildServer(env EnvFunc) *mcp.Server {
	if env == nil {
		env = os.LookupEnv
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "netgear-switch", Version: serverVersion}, nil)

	registerMetaTools(s, env)
	registerReadTools(s, env)
	if writesEnabled(env) {
		registerWriteTools(s, env)
	}
	return s
}
