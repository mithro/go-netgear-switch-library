package resolve

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// mapEnv returns an env lookup function backed by m, matching the
// func(string) (string, bool) shape Resolve/WithEnv expect. A nil map
// behaves like an entirely empty environment.
func mapEnv(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// --- readCommunity ---------------------------------------------------

func TestReadCommunityFlagWins(t *testing.T) {
	cfgVal := "config-community"
	promptCalled := false
	prompt := func(string) (string, error) {
		promptCalled = true
		return "prompted", nil
	}
	got, err := readCommunity("flag-community", mapEnv(map[string]string{"NGSW_COMMUNITY": "env-community"}), &cfgVal, prompt, true)
	if err != nil {
		t.Fatalf("readCommunity() error = %v, want nil", err)
	}
	if got == nil || *got != "flag-community" {
		t.Fatalf("readCommunity() = %v, want %q", got, "flag-community")
	}
	if promptCalled {
		t.Error("readCommunity() called prompt despite a flag value being present")
	}
}

func TestReadCommunityEnvWinsOverConfigAndPrompt(t *testing.T) {
	cfgVal := "config-community"
	got, err := readCommunity("", mapEnv(map[string]string{"NGSW_COMMUNITY": "env-community"}), &cfgVal, nil, true)
	if err != nil {
		t.Fatalf("readCommunity() error = %v, want nil", err)
	}
	if got == nil || *got != "env-community" {
		t.Fatalf("readCommunity() = %v, want %q", got, "env-community")
	}
}

func TestReadCommunityConfigWinsOverPrompt(t *testing.T) {
	cfgVal := "config-community"
	promptCalled := false
	prompt := func(string) (string, error) {
		promptCalled = true
		return "prompted", nil
	}
	got, err := readCommunity("", mapEnv(nil), &cfgVal, prompt, true)
	if err != nil {
		t.Fatalf("readCommunity() error = %v, want nil", err)
	}
	if got == nil || *got != "config-community" {
		t.Fatalf("readCommunity() = %v, want %q", got, "config-community")
	}
	if promptCalled {
		t.Error("readCommunity() called prompt despite a config value being present")
	}
}

func TestReadCommunityFallsBackToPrompt(t *testing.T) {
	got, err := readCommunity("", mapEnv(nil), nil, func(label string) (string, error) {
		if label != "SNMP read community: " {
			t.Errorf("prompt label = %q, want %q", label, "SNMP read community: ")
		}
		return "typed-community", nil
	}, true)
	if err != nil {
		t.Fatalf("readCommunity() error = %v, want nil", err)
	}
	if got == nil || *got != "typed-community" {
		t.Fatalf("readCommunity() = %v, want %q", got, "typed-community")
	}
}

func TestReadCommunityBlankPromptIsUnresolved(t *testing.T) {
	got, err := readCommunity("", mapEnv(nil), nil, func(string) (string, error) { return "   ", nil }, true)
	if err != nil {
		t.Fatalf("readCommunity() error = %v, want nil", err)
	}
	if got != nil {
		t.Fatalf("readCommunity() = %v, want nil (blank prompt reply must not become a literal empty community)", got)
	}
}

func TestReadCommunitySkipsPromptWithoutSNMPBackend(t *testing.T) {
	promptCalled := false
	got, err := readCommunity("", mapEnv(nil), nil, func(string) (string, error) {
		promptCalled = true
		return "typed", nil
	}, false)
	if err != nil {
		t.Fatalf("readCommunity() error = %v, want nil", err)
	}
	if got != nil {
		t.Fatalf("readCommunity() = %v, want nil", got)
	}
	if promptCalled {
		t.Error("readCommunity() called prompt on a model with no SNMP backend")
	}
}

func TestReadCommunityNoPromptFunc(t *testing.T) {
	got, err := readCommunity("", mapEnv(nil), nil, nil, true)
	if err != nil {
		t.Fatalf("readCommunity() error = %v, want nil", err)
	}
	if got != nil {
		t.Fatalf("readCommunity() = %v, want nil (no prompt func supplied)", got)
	}
}

func TestReadCommunityPromptError(t *testing.T) {
	wantErr := errors.New("EOF")
	_, err := readCommunity("", mapEnv(nil), nil, func(string) (string, error) { return "", wantErr }, true)
	if !errors.Is(err, wantErr) {
		t.Fatalf("readCommunity() error = %v, want %v", err, wantErr)
	}
}

func TestReadCommunityEmptyEnvValueSkipped(t *testing.T) {
	cfgVal := "config-community"
	got, err := readCommunity("", mapEnv(map[string]string{"NGSW_COMMUNITY": ""}), &cfgVal, nil, true)
	if err != nil {
		t.Fatalf("readCommunity() error = %v, want nil", err)
	}
	if got == nil || *got != "config-community" {
		t.Fatalf("readCommunity() = %v, want %q (empty env value treated as absent)", got, "config-community")
	}
}

func TestReadCommunityEmptyConfigValueSkipped(t *testing.T) {
	empty := ""
	got, err := readCommunity("", mapEnv(nil), &empty, func(string) (string, error) { return "typed", nil }, true)
	if err != nil {
		t.Fatalf("readCommunity() error = %v, want nil", err)
	}
	if got == nil || *got != "typed" {
		t.Fatalf("readCommunity() = %v, want %q (empty config value treated as absent)", got, "typed")
	}
}

// --- writeCommunityOverride / writeCommunityResolver ------------------

func TestWriteCommunityOverrideFlagWins(t *testing.T) {
	got := writeCommunityOverride("flag-write", mapEnv(map[string]string{"NGSW_WRITE_COMMUNITY": "env-write"}))
	if got == nil || *got != "flag-write" {
		t.Fatalf("writeCommunityOverride() = %v, want %q", got, "flag-write")
	}
}

func TestWriteCommunityOverrideEnvFallback(t *testing.T) {
	got := writeCommunityOverride("", mapEnv(map[string]string{"NGSW_WRITE_COMMUNITY": "env-write"}))
	if got == nil || *got != "env-write" {
		t.Fatalf("writeCommunityOverride() = %v, want %q", got, "env-write")
	}
}

func TestWriteCommunityOverrideNone(t *testing.T) {
	if got := writeCommunityOverride("", mapEnv(nil)); got != nil {
		t.Fatalf("writeCommunityOverride() = %v, want nil", got)
	}
}

func TestWriteCommunityResolverLiteralNeverInvokesConfigResolver(t *testing.T) {
	literal := "literal-write"
	called := false
	resolver := writeCommunityResolver(&literal, func() (*string, error) {
		called = true
		return nil, nil
	})
	got, err := resolver()
	if err != nil {
		t.Fatalf("resolver() error = %v, want nil", err)
	}
	if got == nil || *got != literal {
		t.Fatalf("resolver() = %v, want %q", got, literal)
	}
	if called {
		t.Error("resolver() invoked configResolver despite a literal override being present")
	}
}

func TestWriteCommunityResolverFallsBackToConfigResolver(t *testing.T) {
	resolver := writeCommunityResolver(nil, func() (*string, error) {
		v := "from-config"
		return &v, nil
	})
	got, err := resolver()
	if err != nil {
		t.Fatalf("resolver() error = %v, want nil", err)
	}
	if got == nil || *got != "from-config" {
		t.Fatalf("resolver() = %v, want %q", got, "from-config")
	}
}

func TestWriteCommunityResolverNilBoth(t *testing.T) {
	resolver := writeCommunityResolver(nil, nil)
	got, err := resolver()
	if err != nil || got != nil {
		t.Fatalf("resolver() = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestWriteCommunityResolverPropagatesConfigError(t *testing.T) {
	wantErr := errors.New("boom")
	resolver := writeCommunityResolver(nil, func() (*string, error) { return nil, wantErr })
	_, err := resolver()
	if !errors.Is(err, wantErr) {
		t.Fatalf("resolver() error = %v, want %v", err, wantErr)
	}
}

// --- nsdpInterfaceOverride ---------------------------------------------

func TestNSDPInterfaceOverrideFlagWins(t *testing.T) {
	cfgVal := "eth1"
	got := nsdpInterfaceOverride("eth0", &cfgVal)
	if got == nil || *got != "eth0" {
		t.Fatalf("nsdpInterfaceOverride() = %v, want %q", got, "eth0")
	}
}

func TestNSDPInterfaceOverrideFallsBackToConfig(t *testing.T) {
	cfgVal := "eth1"
	got := nsdpInterfaceOverride("", &cfgVal)
	if got != &cfgVal {
		t.Fatalf("nsdpInterfaceOverride() = %v, want the same pointer as configValue", got)
	}
}

func TestNSDPInterfaceOverrideNilConfig(t *testing.T) {
	if got := nsdpInterfaceOverride("", nil); got != nil {
		t.Fatalf("nsdpInterfaceOverride() = %v, want nil", got)
	}
}

// --- httpPasswordResolver ------------------------------------------------

func TestHTTPPasswordResolverFlagNeverInvokesConfigResolver(t *testing.T) {
	called := false
	resolver := httpPasswordResolver("flag-password", func() (*string, error) {
		called = true
		return nil, nil
	})
	got, err := resolver()
	if err != nil {
		t.Fatalf("resolver() error = %v, want nil", err)
	}
	if got == nil || *got != "flag-password" {
		t.Fatalf("resolver() = %v, want %q", got, "flag-password")
	}
	if called {
		t.Error("resolver() invoked configResolver despite --http-password being set (must stay lazy)")
	}
}

func TestHTTPPasswordResolverFallsBackToConfigResolver(t *testing.T) {
	resolver := httpPasswordResolver("", func() (*string, error) {
		v := "config-password"
		return &v, nil
	})
	got, err := resolver()
	if err != nil {
		t.Fatalf("resolver() error = %v, want nil", err)
	}
	if got == nil || *got != "config-password" {
		t.Fatalf("resolver() = %v, want %q", got, "config-password")
	}
}

func TestHTTPPasswordResolverNilBoth(t *testing.T) {
	resolver := httpPasswordResolver("", nil)
	got, err := resolver()
	if err != nil || got != nil {
		t.Fatalf("resolver() = (%v, %v), want (nil, nil)", got, err)
	}
}

// --- parseBackend --------------------------------------------------------

func TestParseBackendEmpty(t *testing.T) {
	b, err := parseBackend("")
	if err != nil {
		t.Fatalf("parseBackend(\"\") error = %v, want nil", err)
	}
	if b != nil {
		t.Fatalf("parseBackend(\"\") = %v, want nil", b)
	}
}

func TestParseBackendAllSixNames(t *testing.T) {
	want := map[string]model.Backend{
		"snmp":    model.BackendSNMP,
		"nsdp":    model.BackendNSDP,
		"http":    model.BackendHTTP,
		"ssh":     model.BackendSSH,
		"telnet":  model.BackendTelnet,
		"console": model.BackendConsole,
	}
	for name, wantBackend := range want {
		b, err := parseBackend(name)
		if err != nil {
			t.Errorf("parseBackend(%q) error = %v, want nil", name, err)
			continue
		}
		if b == nil || *b != wantBackend {
			t.Errorf("parseBackend(%q) = %v, want %v", name, b, wantBackend)
		}
	}
}

func TestParseBackendUnknown(t *testing.T) {
	_, err := parseBackend("carrier-pigeon")
	if !errors.Is(err, model.ErrConfig) {
		t.Fatalf("parseBackend(bad) error = %v, want wrapping model.ErrConfig", err)
	}
}

func TestParseBackendRejectsUppercase(t *testing.T) {
	// resolve.py's Backend[name.upper()] would accept "SNMP" by
	// upper-casing internally; this port keys directly by the lowercase
	// wire value and does NOT normalise case, matching the flag's
	// documented lowercase-only contract.
	_, err := parseBackend("SNMP")
	if !errors.Is(err, model.ErrConfig) {
		t.Fatalf("parseBackend(SNMP) error = %v, want wrapping model.ErrConfig", err)
	}
}

// --- Resolve: dispatch + error paths --------------------------------

func TestResolveNoSwitchNoHostModel(t *testing.T) {
	_, err := Resolve(Params{})
	if !errors.Is(err, model.ErrConfig) {
		t.Fatalf("Resolve({}) error = %v, want wrapping model.ErrConfig", err)
	}
}

func TestResolveSwitchWithoutConfig(t *testing.T) {
	_, err := Resolve(Params{Switch: "sw1"})
	if !errors.Is(err, model.ErrConfig) {
		t.Fatalf("Resolve(switch, no config) error = %v, want wrapping model.ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "--config") {
		t.Errorf("Resolve error = %q, want it to mention --config", err.Error())
	}
}

func TestResolveHostOnlyNoModel(t *testing.T) {
	_, err := Resolve(Params{Host: "10.0.0.5"})
	if !errors.Is(err, model.ErrConfig) {
		t.Fatalf("Resolve(host only) error = %v, want wrapping model.ErrConfig", err)
	}
}

func TestResolveUnknownModel(t *testing.T) {
	_, err := Resolve(Params{Host: "10.0.0.5", Model: "no-such-model"})
	if !errors.Is(err, model.ErrUnknownModel) {
		t.Fatalf("Resolve(unknown model) error = %v, want wrapping model.ErrUnknownModel", err)
	}
}

func TestResolveHostModelSuccess(t *testing.T) {
	sw, err := Resolve(Params{Host: "10.0.0.5", Model: "gsm7252ps"})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	defer func() { _ = sw.Close() }()
	if sw.Host() != "10.0.0.5" {
		t.Errorf("sw.Host() = %q, want %q", sw.Host(), "10.0.0.5")
	}
	if sw.Model().Key != "gsm7252ps" {
		t.Errorf("sw.Model().Key = %q, want %q", sw.Model().Key, "gsm7252ps")
	}
}

func TestResolveHostModelSNMPPromptsWhenUnresolved(t *testing.T) {
	promptCalled := false
	sw, err := Resolve(Params{Host: "10.0.0.5", Model: "gsm7252ps"}, WithEnv(mapEnv(nil)), WithPrompt(func(string) (string, error) {
		promptCalled = true
		return "typed-community", nil
	}))
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	defer func() { _ = sw.Close() }()
	if !promptCalled {
		t.Error("Resolve() did not prompt for an SNMP-capable model with no other community source")
	}
}

func TestResolveHostModelSkipsPromptForPlusModel(t *testing.T) {
	promptCalled := false
	// gs305ep is NSDP/HTTP only (no SNMP backend) -- resolve.py's whole
	// point of the snmp_backend guard is that a Plus switch must never
	// block a non-interactive caller on an SNMP-community prompt it can't
	// even use.
	sw, err := Resolve(Params{Host: "10.0.0.6", Model: "gs305ep"}, WithEnv(mapEnv(nil)), WithPrompt(func(string) (string, error) {
		promptCalled = true
		return "typed", nil
	}))
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	defer func() { _ = sw.Close() }()
	if promptCalled {
		t.Error("Resolve() prompted for a community on a model with no SNMP backend")
	}
}

func TestResolveHostModelBadBackend(t *testing.T) {
	_, err := Resolve(Params{Host: "10.0.0.5", Model: "gsm7252ps", Backend: "not-a-backend"})
	if !errors.Is(err, model.ErrConfig) {
		t.Fatalf("Resolve(bad backend) error = %v, want wrapping model.ErrConfig", err)
	}
}

func TestResolveHostModelBackendPinsSession(t *testing.T) {
	sw, err := Resolve(Params{Host: "10.0.0.5", Model: "gsm7252ps", Backend: "http"})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	defer func() { _ = sw.Close() }()
	// The Switch's Model()/Host() are the only externally observable
	// fields from this package; the pinned backend itself is exercised
	// end-to-end by switch_test.go in the root package. Just confirm
	// Resolve accepted the flag and built successfully.
}

// --- Resolve: inventory path ------------------------------------------

func writeInventory(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestResolveSwitchNotFound(t *testing.T) {
	path := writeInventory(t, `
[switches.sw1]
model = "gsm7252ps"
host = "10.0.0.5"
`)
	_, err := Resolve(Params{Switch: "no-such-switch", Config: path})
	if !errors.Is(err, model.ErrConfig) {
		t.Fatalf("Resolve(missing switch) error = %v, want wrapping model.ErrConfig", err)
	}
}

func TestResolveInventorySuccess(t *testing.T) {
	path := writeInventory(t, `
[switches.sw1]
model = "gsm7252ps"
host = "10.0.0.5"

[switches.sw1.snmp]
community = "public"
`)
	sw, err := Resolve(Params{Switch: "sw1", Config: path})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	defer func() { _ = sw.Close() }()
	if sw.Host() != "10.0.0.5" {
		t.Errorf("sw.Host() = %q, want %q", sw.Host(), "10.0.0.5")
	}
	if sw.Model().Key != "gsm7252ps" {
		t.Errorf("sw.Model().Key = %q, want %q", sw.Model().Key, "gsm7252ps")
	}
}

func TestResolveInventoryNSDPInterfaceFlagWinsOverConfig(t *testing.T) {
	path := writeInventory(t, `
[switches.sw1]
model = "gs305ep"
host = "10.0.0.6"

[switches.sw1.nsdp]
interface = "eth1"
`)
	// Only observable indirectly (no exported accessor on Switch for the
	// NSDP interface): confirm Resolve accepts the override without
	// error. The precedence itself is covered directly by
	// TestNSDPInterfaceOverrideFlagWins above.
	sw, err := Resolve(Params{Switch: "sw1", Config: path, NSDPInterface: "eth0"})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	defer func() { _ = sw.Close() }()
}

func TestResolveInventoryPromptSkippedForPlusModel(t *testing.T) {
	path := writeInventory(t, `
[switches.sw1]
model = "gs110emx"
host = "10.0.0.7"
`)
	promptCalled := false
	sw, err := Resolve(Params{Switch: "sw1", Config: path}, WithEnv(mapEnv(nil)), WithPrompt(func(string) (string, error) {
		promptCalled = true
		return "typed", nil
	}))
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	defer func() { _ = sw.Close() }()
	if promptCalled {
		t.Error("Resolve() prompted for a community on an inventory switch with no SNMP backend")
	}
}

func TestResolveInventoryHTTPPasswordFlagOverridesInventory(t *testing.T) {
	path := writeInventory(t, `
[switches.sw1]
model = "gs305ep"
host = "10.0.0.6"

[switches.sw1.http]
password = "${UNSET_INVENTORY_HTTP_PASSWORD_XYZ}"
`)
	// The inventory spec references an unset env var, which would error
	// if ever resolved -- since --http-password wins and must never even
	// invoke the config resolver, FromConfig must succeed here.
	sw, err := Resolve(Params{Switch: "sw1", Config: path, HTTPPassword: "flag-password"})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil (flag override must short-circuit the unresolvable inventory spec)", err)
	}
	defer func() { _ = sw.Close() }()
}

func TestResolveInventoryBadBackend(t *testing.T) {
	path := writeInventory(t, `
[switches.sw1]
model = "gsm7252ps"
host = "10.0.0.5"
`)
	_, err := Resolve(Params{Switch: "sw1", Config: path, Backend: "bogus"})
	if !errors.Is(err, model.ErrConfig) {
		t.Fatalf("Resolve(bad backend) error = %v, want wrapping model.ErrConfig", err)
	}
}

func TestResolveInventoryMissingFile(t *testing.T) {
	_, err := Resolve(Params{Switch: "sw1", Config: filepath.Join(t.TempDir(), "does-not-exist.toml")})
	if err == nil {
		t.Fatal("Resolve(missing inventory file) = nil error, want an error")
	}
}

// --- WithEnv / default env -----------------------------------------

func TestResolveDefaultEnvIsProcessEnvironment(t *testing.T) {
	const key = "NGSW_COMMUNITY_RESOLVE_TEST_XYZ"
	if err := os.Setenv(key, "from-process-env"); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv(key) })

	// readCommunity itself only ever looks at NGSW_COMMUNITY, so exercise
	// the default env plumbing (Resolve -> resolveOptions -> os.LookupEnv)
	// through writeCommunityOverride's NGSW_WRITE_COMMUNITY tier instead,
	// which takes the exact same code path.
	if err := os.Setenv("NGSW_WRITE_COMMUNITY", "from-process-env-write"); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("NGSW_WRITE_COMMUNITY") })

	sw, err := Resolve(Params{Host: "10.0.0.5", Model: "gsm7252ps"})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	defer func() { _ = sw.Close() }()
	// No exported accessor exists to read back the resolved write
	// community; this test's real value is exercising resolveOptions'
	// os.LookupEnv default without panicking or erroring -- the tier
	// selection logic itself is covered directly by
	// TestWriteCommunityOverrideEnvFallback.
}

// --- NewStdinPrompt ----------------------------------------------------

func TestNewStdinPromptReadsLine(t *testing.T) {
	var out strings.Builder
	in := bufio.NewReader(strings.NewReader("typed-value\n"))
	p := NewStdinPrompt(&out, in)

	got, err := p("Label: ")
	if err != nil {
		t.Fatalf("prompt() error = %v, want nil", err)
	}
	if got != "typed-value" {
		t.Fatalf("prompt() = %q, want %q", got, "typed-value")
	}
	if out.String() != "Label: " {
		t.Fatalf("prompt wrote %q, want %q", out.String(), "Label: ")
	}
}

func TestNewStdinPromptNoTrailingNewline(t *testing.T) {
	var out strings.Builder
	in := bufio.NewReader(strings.NewReader("typed-value"))
	p := NewStdinPrompt(&out, in)

	got, err := p("Label: ")
	if err != nil {
		t.Fatalf("prompt() error = %v, want nil", err)
	}
	if got != "typed-value" {
		t.Fatalf("prompt() = %q, want %q", got, "typed-value")
	}
}

func TestNewStdinPromptImmediateEOF(t *testing.T) {
	var out strings.Builder
	in := bufio.NewReader(strings.NewReader(""))
	p := NewStdinPrompt(&out, in)

	_, err := p("Label: ")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("prompt() error = %v, want wrapping io.EOF", err)
	}
}

func TestNewStdinPromptWriteError(t *testing.T) {
	p := NewStdinPrompt(failingWriter{}, bufio.NewReader(strings.NewReader("x\n")))
	_, err := p("Label: ")
	if err == nil {
		t.Fatal("prompt() error = nil, want an error from the failing writer")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("write failed") }

// --- Resolve: prompt-error propagation (both dispatch paths) -------

func TestResolveHostModelPromptErrorPropagates(t *testing.T) {
	wantErr := errors.New("EOF")
	_, err := Resolve(Params{Host: "10.0.0.5", Model: "gsm7252ps"}, WithEnv(mapEnv(nil)), WithPrompt(func(string) (string, error) {
		return "", wantErr
	}))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Resolve() error = %v, want wrapping %v", err, wantErr)
	}
}

func TestResolveInventoryPromptErrorPropagates(t *testing.T) {
	path := writeInventory(t, `
[switches.sw1]
model = "gsm7252ps"
host = "10.0.0.5"
`)
	wantErr := errors.New("EOF")
	_, err := Resolve(Params{Switch: "sw1", Config: path}, WithEnv(mapEnv(nil)), WithPrompt(func(string) (string, error) {
		return "", wantErr
	}))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Resolve() error = %v, want wrapping %v", err, wantErr)
	}
}

// --- Resolve: write-community / nsdp-interface / http-password on the
// --host/--model path (fromHostModel's own branches, not just the
// underlying helpers) -----------------------------------------------

func TestResolveHostModelWriteCommunityFlag(t *testing.T) {
	sw, err := Resolve(Params{Host: "10.0.0.5", Model: "gsm7252ps", WriteCommunity: "write-secret"})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	defer func() { _ = sw.Close() }()
}

func TestResolveHostModelNSDPInterfaceFlag(t *testing.T) {
	sw, err := Resolve(Params{Host: "10.0.0.6", Model: "gs305ep", NSDPInterface: "eth0"})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	defer func() { _ = sw.Close() }()
}

func TestResolveHostModelHTTPPasswordFlag(t *testing.T) {
	sw, err := Resolve(Params{Host: "10.0.0.6", Model: "gs305ep", HTTPPassword: "web-secret"})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	defer func() { _ = sw.Close() }()
}
