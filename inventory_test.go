package netgearswitch_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
)

const exampleInventoryPath = "testdata/inventory_example.toml"

// writeInventory writes content to a fresh file under t.TempDir() with the
// given permission bits and returns its path.
func writeInventory(t *testing.T, content string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory.toml")
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// readExampleFixture returns the checked-in example fixture's contents so
// tests can derive mutated copies (bad model, bad protected_ports, ...)
// without hand-duplicating the whole TOML document.
func readExampleFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(exampleInventoryPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", exampleInventoryPath, err)
	}
	return string(data)
}

func TestLoadInventoryExample(t *testing.T) {
	cfgs, err := netgearswitch.LoadInventory(exampleInventoryPath)
	if err != nil {
		t.Fatalf("LoadInventory(%s) error = %v, want nil", exampleInventoryPath, err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("LoadInventory(%s) = %d entries, want 2", exampleInventoryPath, len(cfgs))
	}

	m4300, ok := cfgs["m4300"]
	if !ok {
		t.Fatal(`LoadInventory result missing "m4300" entry`)
	}
	if m4300.Model == nil || m4300.Model.Key != "m4300-24x" {
		t.Errorf("m4300.Model = %+v, want key m4300-24x", m4300.Model)
	}
	if m4300.Host != "10.1.5.13" {
		t.Errorf("m4300.Host = %q, want %q", m4300.Host, "10.1.5.13")
	}
	if m4300.SNMPCommunity == nil || *m4300.SNMPCommunity != "public" {
		t.Errorf("m4300.SNMPCommunity = %v, want %q", m4300.SNMPCommunity, "public")
	}
	if m4300.SNMPWriteCommunitySpec == nil || *m4300.SNMPWriteCommunitySpec != "${M4300_WRITE}" {
		t.Errorf("m4300.SNMPWriteCommunitySpec = %v, want %q", m4300.SNMPWriteCommunitySpec, "${M4300_WRITE}")
	}
	if !reflect.DeepEqual(m4300.ProtectedPorts, []int{25, 26}) {
		t.Errorf("m4300.ProtectedPorts = %v, want [25 26]", m4300.ProtectedPorts)
	}

	fakeEnv := func(k string) (string, bool) {
		if k == "M4300_WRITE" {
			return "w", true
		}
		return "", false
	}
	got, err := m4300.SNMPWriteCommunity(fakeEnv, nil)
	if err != nil {
		t.Fatalf("m4300.SNMPWriteCommunity() error = %v, want nil", err)
	}
	if got == nil || *got != "w" {
		t.Errorf("m4300.SNMPWriteCommunity() = %v, want %q", got, "w")
	}

	poeMicro1, ok := cfgs["poe-micro1"]
	if !ok {
		t.Fatal(`LoadInventory result missing "poe-micro1" entry`)
	}
	if poeMicro1.Model == nil || poeMicro1.Model.Key != "gs305ep" {
		t.Errorf("poe-micro1.Model = %+v, want key gs305ep", poeMicro1.Model)
	}
	if poeMicro1.Host != "10.1.5.28" {
		t.Errorf("poe-micro1.Host = %q, want %q", poeMicro1.Host, "10.1.5.28")
	}
	if poeMicro1.NSDPInterface == nil || *poeMicro1.NSDPInterface != "br-net" {
		t.Errorf("poe-micro1.NSDPInterface = %v, want %q", poeMicro1.NSDPInterface, "br-net")
	}
	if poeMicro1.HTTPPasswordSpec == nil || *poeMicro1.HTTPPasswordSpec != "!echo hunter2" {
		t.Errorf("poe-micro1.HTTPPasswordSpec = %v, want %q", poeMicro1.HTTPPasswordSpec, "!echo hunter2")
	}
	if len(poeMicro1.ProtectedPorts) != 0 {
		t.Errorf("poe-micro1.ProtectedPorts = %v, want empty (not declared in fixture)", poeMicro1.ProtectedPorts)
	}

	pw, err := poeMicro1.HTTPPassword(fakeEnv, nil)
	if err != nil {
		t.Fatalf("poe-micro1.HTTPPassword() error = %v, want nil", err)
	}
	if pw == nil || *pw != "hunter2" {
		t.Errorf("poe-micro1.HTTPPassword() = %v, want %q", pw, "hunter2")
	}
}

func TestLoadInventoryUnknownModel(t *testing.T) {
	content := strings.Replace(readExampleFixture(t), `model = "m4300-24x"`, `model = "bogus"`, 1)
	path := writeInventory(t, content, 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrUnknownModel) {
		t.Fatalf("LoadInventory(bogus model) error = %v, want wrapping ErrUnknownModel", err)
	}
}

func TestLoadInventoryProtectedPortsRejectsBool(t *testing.T) {
	content := strings.Replace(readExampleFixture(t), "protected_ports = [25, 26]", "protected_ports = [true]", 1)
	path := writeInventory(t, content, 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("LoadInventory(protected_ports = [true]) error = %v, want wrapping ErrConfig", err)
	}
}

func TestLoadInventoryProtectedPortsMixedTypesRejected(t *testing.T) {
	content := strings.Replace(readExampleFixture(t), "protected_ports = [25, 26]", `protected_ports = [25, "26"]`, 1)
	path := writeInventory(t, content, 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("LoadInventory(protected_ports with string) error = %v, want wrapping ErrConfig", err)
	}
}

func TestLoadInventoryLiteralSecretInsecureFile(t *testing.T) {
	content := "[switches.a]\nmodel = \"gs305ep\"\nhost = \"10.0.0.1\"\nhttp = { password = \"literal-secret\" }\n"
	path := writeInventory(t, content, 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("LoadInventory(literal secret, 0644) error = %v, want wrapping ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "600") {
		t.Errorf("LoadInventory(literal secret, 0644) error = %q, want it to mention chmod 600", err.Error())
	}
}

func TestLoadInventoryLiteralSecretSecureFileOK(t *testing.T) {
	content := "[switches.a]\nmodel = \"gs305ep\"\nhost = \"10.0.0.1\"\nhttp = { password = \"literal-secret\" }\n"
	path := writeInventory(t, content, 0o600)

	cfgs, err := netgearswitch.LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory(literal secret, 0600) error = %v, want nil", err)
	}
	a := cfgs["a"]
	if a.HTTPPasswordSpec == nil || *a.HTTPPasswordSpec != "literal-secret" {
		t.Errorf("a.HTTPPasswordSpec = %v, want %q", a.HTTPPasswordSpec, "literal-secret")
	}
}

func TestLoadInventoryNonLiteralSecretsSkipSecureFileCheck(t *testing.T) {
	// The checked-in example fixture only has env-var and command secret
	// specs (no literal), so it must load fine even though it's 0644 in
	// git (Python: only a literal secret triggers ensure_secure_file).
	info, err := os.Stat(exampleInventoryPath)
	if err != nil {
		t.Fatalf("Stat(%s): %v", exampleInventoryPath, err)
	}
	if info.Mode().Perm()&0o077 == 0 {
		t.Skip("fixture happens to be locked down; test wants it to prove non-literal specs bypass the secure-file check")
	}
	if _, err := netgearswitch.LoadInventory(exampleInventoryPath); err != nil {
		t.Fatalf("LoadInventory(%s) error = %v, want nil (no literal secrets present)", exampleInventoryPath, err)
	}
}

func TestLoadInventoryMissingModelKey(t *testing.T) {
	path := writeInventory(t, "[switches.a]\nhost = \"10.0.0.1\"\n", 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("LoadInventory(missing model) error = %v, want wrapping ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "model") || !strings.Contains(err.Error(), "a") {
		t.Errorf("LoadInventory(missing model) error = %q, want it to mention %q and switch name %q", err.Error(), "model", "a")
	}
}

func TestLoadInventoryMissingHostKey(t *testing.T) {
	path := writeInventory(t, "[switches.a]\nmodel = \"gs305ep\"\n", 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("LoadInventory(missing host) error = %v, want wrapping ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "host") || !strings.Contains(err.Error(), "a") {
		t.Errorf("LoadInventory(missing host) error = %q, want it to mention %q and switch name %q", err.Error(), "host", "a")
	}
}

func TestLoadInventoryModelHostWrongType(t *testing.T) {
	path := writeInventory(t, "[switches.a]\nmodel = 5\nhost = \"10.0.0.1\"\n", 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("LoadInventory(model=5) error = %v, want wrapping ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "string") {
		t.Errorf("LoadInventory(model=5) error = %q, want it to mention strings", err.Error())
	}
}

func TestLoadInventorySNMPNotTable(t *testing.T) {
	path := writeInventory(t, "[switches.a]\nmodel = \"gs305ep\"\nhost = \"10.0.0.1\"\nsnmp = \"oops\"\n", 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("LoadInventory(snmp=string) error = %v, want wrapping ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "table") {
		t.Errorf("LoadInventory(snmp=string) error = %q, want it to mention tables", err.Error())
	}
}

func TestLoadInventoryProtectedPortsNotList(t *testing.T) {
	path := writeInventory(t, "[switches.a]\nmodel = \"gs305ep\"\nhost = \"10.0.0.1\"\nprotected_ports = \"oops\"\n", 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("LoadInventory(protected_ports=string) error = %v, want wrapping ErrConfig", err)
	}
}

func TestLoadInventoryOptionalStringFieldWrongType(t *testing.T) {
	path := writeInventory(t, "[switches.a]\nmodel = \"gs305ep\"\nhost = \"10.0.0.1\"\nsnmp = { community = 5 }\n", 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("LoadInventory(snmp.community=5) error = %v, want wrapping ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "snmp.community") {
		t.Errorf("LoadInventory(snmp.community=5) error = %q, want it to mention snmp.community", err.Error())
	}
}

func TestLoadInventoryProtectedPortsDedupSort(t *testing.T) {
	path := writeInventory(t, "[switches.a]\nmodel = \"gs305ep\"\nhost = \"10.0.0.1\"\nprotected_ports = [26, 25, 25, 3]\n", 0o644)

	cfgs, err := netgearswitch.LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory error = %v, want nil", err)
	}
	if !reflect.DeepEqual(cfgs["a"].ProtectedPorts, []int{3, 25, 26}) {
		t.Errorf("ProtectedPorts = %v, want [3 25 26]", cfgs["a"].ProtectedPorts)
	}
}

func TestLoadInventoryTopLevelSwitchesNotTable(t *testing.T) {
	path := writeInventory(t, "switches = \"oops\"\n", 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("LoadInventory(switches=string) error = %v, want wrapping ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "switches") {
		t.Errorf("LoadInventory(switches=string) error = %q, want it to mention switches", err.Error())
	}
}

func TestLoadInventorySwitchTableNotTable(t *testing.T) {
	path := writeInventory(t, "[switches]\nfoo = \"oops\"\n", 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("LoadInventory([switches.foo]=string) error = %v, want wrapping ErrConfig", err)
	}
}

func TestLoadInventoryEmptySwitches(t *testing.T) {
	path := writeInventory(t, "# no switches here\n", 0o644)

	cfgs, err := netgearswitch.LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory(no [switches]) error = %v, want nil", err)
	}
	if len(cfgs) != 0 {
		t.Errorf("LoadInventory(no [switches]) = %v, want empty map", cfgs)
	}
}

func TestLoadInventoryUnknownExtraKeysIgnored(t *testing.T) {
	path := writeInventory(t, "[switches.a]\nmodel = \"gs305ep\"\nhost = \"10.0.0.1\"\nsome_future_key = \"whatever\"\n", 0o644)

	cfgs, err := netgearswitch.LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory(unknown extra key) error = %v, want nil", err)
	}
	if _, ok := cfgs["a"]; !ok {
		t.Error(`LoadInventory(unknown extra key) missing "a" entry`)
	}
}

func TestLoadInventoryMissingFile(t *testing.T) {
	_, err := netgearswitch.LoadInventory(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err == nil {
		t.Fatal("LoadInventory(missing file) = nil error, want non-nil")
	}
}

func TestLoadInventoryInvalidTOMLSyntax(t *testing.T) {
	path := writeInventory(t, "this is not [valid toml\n", 0o644)

	_, err := netgearswitch.LoadInventory(path)
	if err == nil {
		t.Fatal("LoadInventory(invalid TOML) = nil error, want non-nil")
	}
}

func TestLoadInventoryEnv(t *testing.T) {
	env := func(string) (string, bool) { return "", false }
	cfgs, err := netgearswitch.LoadInventoryEnv(exampleInventoryPath, env)
	if err != nil {
		t.Fatalf("LoadInventoryEnv(%s) error = %v, want nil", exampleInventoryPath, err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("LoadInventoryEnv(%s) = %d entries, want 2", exampleInventoryPath, len(cfgs))
	}
}
