package netgearswitch

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/mithro/go-netgear-switch-library/model"
)

// SwitchConfig is one [switches.NAME] entry from an inventory TOML file,
// mirroring Python config.SwitchConfig. Credential fields hold the raw spec
// string (env-var reference, `!command`, or literal) rather than a resolved
// value -- call SNMPWriteCommunity/HTTPPassword to resolve. ProtectedPorts
// is stored sorted ascending with duplicates removed (Go's canonical form
// for Python's frozenset[int]).
type SwitchConfig struct {
	Name                   string
	Model                  *model.SwitchModel
	Host                   string
	SNMPCommunity          *string
	SNMPWriteCommunitySpec *string
	HTTPPasswordSpec       *string
	NSDPInterface          *string
	ProtectedPorts         []int
}

// SNMPWriteCommunity resolves this switch's snmp.write_community spec (nil
// if the inventory entry didn't set one); see ResolveSecret for the env/
// runner contract (a nil runner selects the default os/exec-based one).
func (c SwitchConfig) SNMPWriteCommunity(env func(string) (string, bool), runner SecretRunner) (*string, error) {
	return ResolveSecret(c.SNMPWriteCommunitySpec, env, runner)
}

// HTTPPassword resolves this switch's http.password spec (nil if the
// inventory entry didn't set one); see ResolveSecret for the env/runner
// contract (a nil runner selects the default os/exec-based one).
func (c SwitchConfig) HTTPPassword(env func(string) (string, bool), runner SecretRunner) (*string, error) {
	return ResolveSecret(c.HTTPPasswordSpec, env, runner)
}

// isLiteralSecret reports whether spec is a "literal" secret value -- one
// that is neither an "${ENV_VAR}" reference nor a "!command" -- mirroring
// Python config._is_literal. A nil spec (field absent from the inventory)
// is never literal.
func isLiteralSecret(spec *string) bool {
	if spec == nil {
		return false
	}
	s := *spec
	if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		return false
	}
	return !strings.HasPrefix(s, "!")
}

// asStringPtr returns nil for a nil (absent) value, or a pointer to v's
// string form when v is already known (by the caller) to be a string.
func asStringPtr(v any) *string {
	if v == nil {
		return nil
	}
	s := v.(string) //nolint:forcetypeassert // caller has already type-checked v.
	return &s
}

// subtable fetches table[key] as a TOML table (map[string]any), defaulting
// to an empty table when the key is absent. ok is false when the key is
// present but not a table.
func subtable(table map[string]any, key string) (sub map[string]any, ok bool) {
	v, present := table[key]
	if !present {
		return map[string]any{}, true
	}
	sub, ok = v.(map[string]any)
	return sub, ok
}

// switchFromTable validates and builds one SwitchConfig from a decoded
// [switches.NAME] table, porting Python config._switch_from_table's
// validation order and error text exactly. hasLiteral reports whether
// either secret spec on this switch is a literal value (triggering the
// caller's secure-file check).
func switchFromTable(name string, table map[string]any) (cfg SwitchConfig, hasLiteral bool, err error) {
	modelRaw, hasModel := table["model"]
	if !hasModel {
		return SwitchConfig{}, false, fmt.Errorf("switch %q is missing required key %q: %w", name, "model", model.ErrConfig)
	}
	hostRaw, hasHost := table["host"]
	if !hasHost {
		return SwitchConfig{}, false, fmt.Errorf("switch %q is missing required key %q: %w", name, "host", model.ErrConfig)
	}
	modelKey, modelIsStr := modelRaw.(string)
	host, hostIsStr := hostRaw.(string)
	if !modelIsStr || !hostIsStr {
		return SwitchConfig{}, false, fmt.Errorf("switch %q: 'model' and 'host' must be strings: %w", name, model.ErrConfig)
	}

	snmp, snmpOK := subtable(table, "snmp")
	http, httpOK := subtable(table, "http")
	nsdp, nsdpOK := subtable(table, "nsdp")
	if !snmpOK || !httpOK || !nsdpOK {
		return SwitchConfig{}, false, fmt.Errorf("switch %q: snmp/http/nsdp must be tables: %w", name, model.ErrConfig)
	}

	ports, portsErr := protectedPorts(table)
	if portsErr != nil {
		return SwitchConfig{}, false, fmt.Errorf("switch %q: %w: %w", name, portsErr, model.ErrConfig)
	}

	for _, field := range []struct {
		label string
		value any
	}{
		{"snmp.community", snmp["community"]},
		{"snmp.write_community", snmp["write_community"]},
		{"http.password", http["password"]},
		{"nsdp.interface", nsdp["interface"]},
	} {
		if field.value != nil {
			if _, ok := field.value.(string); !ok {
				return SwitchConfig{}, false, fmt.Errorf("switch %q: %s must be a string: %w", name, field.label, model.ErrConfig)
			}
		}
	}

	sm, err := model.GetModel(modelKey)
	if err != nil {
		return SwitchConfig{}, false, err
	}

	writeSpec := asStringPtr(snmp["write_community"])
	passwordSpec := asStringPtr(http["password"])
	hasLiteral = isLiteralSecret(writeSpec) || isLiteralSecret(passwordSpec)

	cfg = SwitchConfig{
		Name:                   name,
		Model:                  sm,
		Host:                   host,
		SNMPCommunity:          asStringPtr(snmp["community"]),
		SNMPWriteCommunitySpec: writeSpec,
		HTTPPasswordSpec:       passwordSpec,
		NSDPInterface:          asStringPtr(nsdp["interface"]),
		ProtectedPorts:         ports,
	}
	return cfg, hasLiteral, nil
}

// protectedPorts extracts and validates the optional protected_ports list
// (default: empty), returning it sorted ascending with duplicates removed.
// The result is never nil, matching this codebase's convention for port
// collections (see model.VLANInfo's doc comment) and Python's
// frozenset(ports) default of an empty-but-present frozenset. A non-list
// value, or any element that isn't a TOML integer (including bools -- TOML
// 1.0 allows mixed-type arrays, and a bool never satisfies the int64 type
// assertion below), is rejected.
func protectedPorts(table map[string]any) ([]int, error) {
	raw, present := table["protected_ports"]
	if !present {
		return []int{}, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("protected_ports must be a list of ints")
	}

	seen := make(map[int]struct{}, len(list))
	ports := make([]int, 0, len(list))
	for _, elem := range list {
		iv, ok := elem.(int64)
		if !ok {
			return nil, fmt.Errorf("protected_ports must be a list of ints")
		}
		p := int(iv)
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

// LoadInventory loads a TOML inventory file into a {name: SwitchConfig}
// map using the process's real environment (os.LookupEnv); see
// LoadInventoryEnv to inject a fake environment (e.g. in tests).
func LoadInventory(path string) (map[string]SwitchConfig, error) {
	return LoadInventoryEnv(path, os.LookupEnv)
}

// LoadInventoryEnv loads a TOML inventory file into a {name: SwitchConfig}
// map, porting Python config.load_inventory's validation exactly: required
// model/host strings, snmp/http/nsdp tables, a protected_ports list of
// ints, the four optional string-typed credential/interface fields
// type-checked, and unknown extra keys silently ignored (mirroring
// Python's Mapping.get-based field access, which never errors on an unread
// key). If any switch carries a literal (non-"${...}", non-"!command")
// secret, EnsureSecureFile is run on path itself before returning.
//
// env is accepted for signature parity with Python's load_inventory(path,
// *, env=None) parameter -- which itself is assigned a default but never
// read again in the function body -- and is likewise unused here; loading
// never resolves secrets (SwitchConfig.SNMPWriteCommunity/HTTPPassword do
// that later, given their own env argument). It exists so callers have an
// explicit "inject an environment" entry point if that ever changes.
func LoadInventoryEnv(path string, env func(string) (string, bool)) (map[string]SwitchConfig, error) {
	_ = env

	var data map[string]any
	if _, err := toml.DecodeFile(path, &data); err != nil {
		return nil, err
	}

	switchesTable := map[string]any{}
	if raw, present := data["switches"]; present {
		table, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("top-level [switches] must be a table: %w", model.ErrConfig)
		}
		switchesTable = table
	}

	result := make(map[string]SwitchConfig, len(switchesTable))
	anyLiteral := false
	for name, raw := range switchesTable {
		table, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("[switches.%s] must be a table: %w", name, model.ErrConfig)
		}
		cfg, hasLiteral, err := switchFromTable(name, table)
		if err != nil {
			return nil, err
		}
		if hasLiteral {
			anyLiteral = true
		}
		result[name] = cfg
	}

	if anyLiteral {
		if err := EnsureSecureFile(path); err != nil {
			return nil, err
		}
	}
	return result, nil
}
