// meta.go: the 2 meta tools, mirroring server.py's `list_switches` and
// `identify` top-level tool functions exactly.
package main

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// listSwitchesIn is list_switches' input, mirroring server.py's
// `list_switches(config: str | None = None)`.
type listSwitchesIn struct {
	Config string `json:"config,omitempty" jsonschema:"path to a TOML inventory file; omits to $NGSW_INVENTORY"`
}

// inventoryEntry is one [switches.NAME] entry as list_switches reports it,
// mirroring server.py's `{"name": name, "model": spec.get("model"), "host":
// spec.get("host")}` dict exactly -- Model/Host are `any` (not `string`) so
// a switch entry missing either key serializes as JSON null (Python's
// Mapping.get default), the same as a present-but-non-string TOML value
// serializing as whatever type it actually is, rather than this package
// silently coercing either case into an empty string.
type inventoryEntry struct {
	Name  string `json:"name"`
	Model any    `json:"model"`
	Host  any    `json:"host"`
}

// registerMetaTools registers list_switches and identify -- the 2 tools
// registered regardless of the write gate, mirroring server.py's
// `build_server` registering both unconditionally before the
// writes_enabled(env) check.
func registerMetaTools(s *mcp.Server, env EnvFunc) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_switches",
		Description: "List the named switches in the TOML inventory.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in listSwitchesIn) (*mcp.CallToolResult, any, error) {
		entries, err := listInventorySwitches(in.Config, env)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(entries)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "identify",
		Description: "Detect a switch's model over SNMP (sysDescr matching).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in identifyIn) (*mcp.CallToolResult, any, error) {
		// Mirrors server.py's `identify`: switch/http_password/
		// nsdp_interface are ALWAYS empty on this path -- identify's whole
		// point is probing a switch whose real model isn't trusted yet, so
		// it only ever resolves via host+model, never an inventory entry.
		sel := selectorFields{Host: in.Host, Model: in.Model, Config: in.Config, Community: in.Community}
		sw, err := resolveSwitch(env, sel)
		if err != nil {
			return nil, nil, err
		}
		defer func() { _ = sw.Close() }()

		v, opErr := sw.Identify(ctx)
		return jsonResult(readResult("identify", v, opErr))
	})
}

// identifyIn is identify's input -- deliberately NARROWER than every other
// tool's: host and model are REQUIRED (no inventory `switch` lookup, no
// http_password/nsdp_interface/backend at all), mirroring server.py's
// `identify(host: str, model: str, config: str | None = None, community:
// str | None = None)` exactly.
type identifyIn struct {
	Host      string `json:"host"                jsonschema:"switch host or IP address"`
	Model     string `json:"model"                jsonschema:"switch model key"`
	Config    string `json:"config,omitempty"    jsonschema:"path to a TOML inventory file (unused on this host/model-only resolution path; accepted for signature parity)"`
	Community string `json:"community,omitempty" jsonschema:"SNMP read community"`
}

// listInventorySwitches reads path's [switches.*] table entries directly
// (name/model/host only, in that order), mirroring server.py's
// `list_inventory_switches` exactly: NO model-key validation (an entry
// naming an unregistered model key is still listed, its raw string value
// unchanged) and NO permission/secure-file check -- deliberately NOT the
// same code path as netgearswitch.LoadInventory (used by the read/write
// tools' own resolveSwitch), which performs both and would abort listing
// the ENTIRE inventory over one bad entry. path falls back to
// $NGSW_INVENTORY when empty, mirroring `config or env.get(_INVENTORY_ENV)`.
//
// Entries are returned SORTED BY NAME for determinism: Go's decoded
// map[string]any (unlike Python's insertion-ordered dict) carries no file
// order at all, so sorting is the closest deterministic substitute --
// a disclosed adaptation to Go's map semantics, not a fidelity bug (the
// CONTENT of each entry is unchanged; only the LIST order is Go's own,
// alphabetical convention rather than Python's file order).
func listInventorySwitches(configArg string, env EnvFunc) ([]inventoryEntry, error) {
	path := configArg
	if path == "" {
		if v, ok := env(inventoryEnvVar); ok {
			path = v
		}
	}
	if path == "" {
		return nil, fmt.Errorf("no inventory: pass `config` or set $NGSW_INVENTORY: %w", model.ErrConfig)
	}
	if fi, err := os.Stat(path); err != nil || fi.IsDir() {
		return nil, fmt.Errorf("inventory file not found: %s: %w", path, model.ErrConfig)
	}

	var data map[string]any
	if _, err := toml.DecodeFile(path, &data); err != nil {
		return nil, err
	}

	switchesRaw, _ := data["switches"].(map[string]any)
	names := make([]string, 0, len(switchesRaw))
	for name := range switchesRaw {
		names = append(names, name)
	}
	sort.Strings(names)

	entries := make([]inventoryEntry, 0, len(names))
	for _, name := range names {
		spec, _ := switchesRaw[name].(map[string]any)
		entries = append(entries, inventoryEntry{
			Name:  name,
			Model: spec["model"],
			Host:  spec["host"],
		})
	}
	return entries, nil
}
