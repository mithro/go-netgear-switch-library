package main

import (
	"os"
	"slices"
	"sort"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// The 15 read tool names, in server.py's own registration order.
var readToolNames = []string{
	"get_ports", "get_stats", "get_vlans", "get_pvids", "get_macs", "get_lldp",
	"get_sensors", "get_poe", "get_mgmt_ip", "get_hostname", "get_users",
	"get_services", "get_syslog", "snapshot", "get_device",
}

// The 18 write tool names, in server.py's own registration order.
var writeToolNames = []string{
	"set_pvid", "set_port_description", "set_port_speed", "add_syslog_collector",
	"remove_syslog_collector", "set_flow_control", "set_hostname", "set_syslog_enabled",
	"set_port_enabled", "set_poe", "set_vlan_membership", "create_vlan", "delete_vlan",
	"cycle_poe", "clear_poe_fault", "set_mgmt_ip", "upload_certificate", "upload_certificate_scp",
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	sort.Strings(out)
	return out
}

func TestBuildServer_WritesDisabled_Registers17Tools(t *testing.T) {
	srv := BuildServer(mapEnv(nil))
	got := sortedCopy(toolNames(t, srv))

	want := sortedCopy(append([]string{"list_switches", "identify"}, readToolNames...))
	if len(got) != 17 {
		t.Fatalf("len(tools) = %d, want 17: %v", len(got), got)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("tool names = %v, want %v", got, want)
	}
	for _, name := range writeToolNames {
		if slices.Contains(got, name) {
			t.Errorf("write tool %q registered with writes disabled", name)
		}
	}
}

func TestBuildServer_WritesEnabled_Registers35Tools(t *testing.T) {
	for _, truthy := range []string{"1", "true", "yes", "on", "TRUE", "Yes", " on "} {
		t.Run(truthy, func(t *testing.T) {
			srv := BuildServer(mapEnv(map[string]string{writeEnvVar: truthy}))
			got := sortedCopy(toolNames(t, srv))

			want := sortedCopy(append(append([]string{"list_switches", "identify"}, readToolNames...), writeToolNames...))
			if len(got) != 35 {
				t.Fatalf("len(tools) = %d, want 35: %v", len(got), got)
			}
			if !slices.Equal(got, want) {
				t.Fatalf("tool names = %v, want %v", got, want)
			}
		})
	}
}

func TestWritesEnabled_FalsyValuesLeaveGateClosed(t *testing.T) {
	for _, falsy := range []string{"", "0", "false", "no", "off", "banana"} {
		t.Run("value="+falsy, func(t *testing.T) {
			if writesEnabled(mapEnv(map[string]string{writeEnvVar: falsy})) {
				t.Errorf("writesEnabled(%q) = true, want false", falsy)
			}
		})
	}
}

func TestBuildServer_NilEnvDefaultsToRealEnvironment(t *testing.T) {
	// A nil env must not panic and must default to the real process
	// environment (os.LookupEnv), mirroring server.py's `env = env if env
	// is not None else dict(os.environ)` -- exercised here only for "does
	// not panic and produces the write-disabled tool set", since the test
	// process itself is not expected to have NGSW_MCP_ALLOW_WRITES set.
	t.Setenv(writeEnvVar, "")
	srv := BuildServer(nil)
	got := toolNames(t, srv)
	if len(got) != 17 {
		t.Fatalf("len(tools) with nil env = %d, want 17 (write gate closed): %v", len(got), got)
	}
}

func TestParseBackendName(t *testing.T) {
	cases := []struct {
		name    string
		want    *model.Backend
		wantErr bool
	}{
		{"", nil, false},
		{"snmp", backendPtr(model.BackendSNMP), false},
		{"NSDP", backendPtr(model.BackendNSDP), false},
		{"Http", backendPtr(model.BackendHTTP), false},
		{"ssh", backendPtr(model.BackendSSH), false},
		{"telnet", backendPtr(model.BackendTelnet), false},
		{"console", backendPtr(model.BackendConsole), false},
		{"bogus", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseBackendName(c.name)
			if c.wantErr {
				if err == nil {
					t.Fatalf("parseBackendName(%q) error = nil, want an error", c.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseBackendName(%q) error = %v", c.name, err)
			}
			if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
				t.Errorf("parseBackendName(%q) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

func backendPtr(b model.Backend) *model.Backend { return &b }

func TestResolveSwitch_BadSelectorErrors(t *testing.T) {
	_, err := resolveSwitch(mapEnv(nil), selectorFields{})
	if err == nil {
		t.Fatal("resolveSwitch(empty selector) error = nil, want an error")
	}
}

func TestListInventorySwitches_NGSWInventoryEnvFallback(t *testing.T) {
	path := writeTempInventory(t)
	env := mapEnv(map[string]string{inventoryEnvVar: path})

	entries, err := listInventorySwitches("", env)
	if err != nil {
		t.Fatalf("listInventorySwitches() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2: %+v", len(entries), entries)
	}
	if entries[0].Name != "alpha" || entries[1].Name != "zeta" {
		t.Errorf("entries = %+v, want sorted [alpha, zeta]", entries)
	}
	if entries[0].Model != "not-a-real-model-key" || entries[0].Host != "10.0.0.2" {
		t.Errorf("entries[0] = %+v, want model=not-a-real-model-key host=10.0.0.2 (unregistered model key listed as-is)", entries[0])
	}
	if entries[1].Model != "gsm7228ps" || entries[1].Host != "10.0.0.1" {
		t.Errorf("entries[1] = %+v, want model=gsm7228ps host=10.0.0.1", entries[1])
	}
}

func TestListInventorySwitches_MissingFileIsConfigError(t *testing.T) {
	_, err := listInventorySwitches("/no/such/inventory.toml", mapEnv(nil))
	if err == nil {
		t.Fatal("listInventorySwitches(missing file) error = nil, want an error")
	}
}

func TestListInventorySwitches_NoConfigNoEnvIsConfigError(t *testing.T) {
	_, err := listInventorySwitches("", mapEnv(nil))
	if err == nil {
		t.Fatal("listInventorySwitches(no config, no env) error = nil, want an error")
	}
}

// writeTempInventory writes a small 2-switch TOML inventory (one entry with
// an UNREGISTERED model key, proving list_switches lists it anyway --
// unlike netgearswitch.LoadInventory, it never validates the model key) and
// returns its path.
func writeTempInventory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/inventory.toml"
	content := `
[switches.zeta]
model = "gsm7228ps"
host = "10.0.0.1"

[switches.alpha]
model = "not-a-real-model-key"
host = "10.0.0.2"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	return path
}
