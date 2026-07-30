package netgearswitch_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
)

// mapEnv returns an env lookup function backed by m, matching the
// func(string) (string, bool) shape ResolveSecret expects.
func mapEnv(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestResolveSecretNilSpec(t *testing.T) {
	got, err := netgearswitch.ResolveSecret(nil, mapEnv(nil), nil)
	if err != nil {
		t.Fatalf("ResolveSecret(nil) error = %v, want nil", err)
	}
	if got != nil {
		t.Fatalf("ResolveSecret(nil) = %v, want nil", got)
	}
}

func TestResolveSecretLiteralPassthrough(t *testing.T) {
	spec := "plain-literal-value"
	got, err := netgearswitch.ResolveSecret(&spec, mapEnv(nil), nil)
	if err != nil {
		t.Fatalf("ResolveSecret(%q) error = %v, want nil", spec, err)
	}
	if got == nil || *got != spec {
		t.Fatalf("ResolveSecret(%q) = %v, want %q", spec, got, spec)
	}
}

func TestResolveSecretEnvSet(t *testing.T) {
	spec := "${HOME_TEST_VAR}"
	env := mapEnv(map[string]string{"HOME_TEST_VAR": "env-value"})
	got, err := netgearswitch.ResolveSecret(&spec, env, nil)
	if err != nil {
		t.Fatalf("ResolveSecret(%q) error = %v, want nil", spec, err)
	}
	if got == nil || *got != "env-value" {
		t.Fatalf("ResolveSecret(%q) = %v, want %q", spec, got, "env-value")
	}
}

func TestResolveSecretEnvUnset(t *testing.T) {
	spec := "${HOME_TEST_VAR}"
	got, err := netgearswitch.ResolveSecret(&spec, mapEnv(nil), nil)
	if got != nil {
		t.Fatalf("ResolveSecret(%q) = %v, want nil", spec, got)
	}
	if !errors.Is(err, netgearswitch.ErrCredential) {
		t.Fatalf("ResolveSecret(%q) error = %v, want wrapping ErrCredential", spec, err)
	}
	if !strings.Contains(err.Error(), "HOME_TEST_VAR") {
		t.Errorf("ResolveSecret(%q) error = %q, want it to mention the variable name", spec, err.Error())
	}
}

func TestResolveSecretCommandSuccess(t *testing.T) {
	spec := "!echo  secret "
	got, err := netgearswitch.ResolveSecret(&spec, mapEnv(nil), nil)
	if err != nil {
		t.Fatalf("ResolveSecret(%q) error = %v, want nil", spec, err)
	}
	if got == nil || *got != "secret" {
		t.Fatalf("ResolveSecret(%q) = %v, want %q", spec, got, "secret")
	}
}

func TestResolveSecretCommandEmpty(t *testing.T) {
	spec := "!"
	got, err := netgearswitch.ResolveSecret(&spec, mapEnv(nil), nil)
	if got != nil {
		t.Fatalf("ResolveSecret(%q) = %v, want nil", spec, got)
	}
	if !errors.Is(err, netgearswitch.ErrCredential) {
		t.Fatalf("ResolveSecret(%q) error = %v, want wrapping ErrCredential", spec, err)
	}
}

func TestResolveSecretCommandWhitespaceOnly(t *testing.T) {
	spec := "!   "
	got, err := netgearswitch.ResolveSecret(&spec, mapEnv(nil), nil)
	if got != nil {
		t.Fatalf("ResolveSecret(%q) = %v, want nil", spec, got)
	}
	if !errors.Is(err, netgearswitch.ErrCredential) {
		t.Fatalf("ResolveSecret(%q) error = %v, want wrapping ErrCredential", spec, err)
	}
}

func TestResolveSecretCommandFailingExit(t *testing.T) {
	spec := "!sh -c 'exit 3'"
	got, err := netgearswitch.ResolveSecret(&spec, mapEnv(nil), nil)
	if got != nil {
		t.Fatalf("ResolveSecret(%q) = %v, want nil", spec, got)
	}
	if !errors.Is(err, netgearswitch.ErrCredential) {
		t.Fatalf("ResolveSecret(%q) error = %v, want wrapping ErrCredential", spec, err)
	}
	if !strings.Contains(err.Error(), "exit 3") {
		t.Errorf("ResolveSecret(%q) error = %q, want it to contain %q", spec, err.Error(), "exit 3")
	}
}

func TestResolveSecretCommandStderrIncluded(t *testing.T) {
	spec := "!sh -c 'echo boom 1>&2; exit 1'"
	_, err := netgearswitch.ResolveSecret(&spec, mapEnv(nil), nil)
	if !errors.Is(err, netgearswitch.ErrCredential) {
		t.Fatalf("ResolveSecret(%q) error = %v, want wrapping ErrCredential", spec, err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("ResolveSecret(%q) error = %q, want it to contain stderr text %q", spec, err.Error(), "boom")
	}
}

func TestResolveSecretRunnerTimeout(t *testing.T) {
	spec := "!some-tool --flag"
	timeoutErr := fmt.Errorf("signal: killed (timed out)")
	fakeRunner := func(name string, args []string) (string, error) {
		if name != "some-tool" {
			t.Fatalf("runner called with name = %q, want %q", name, "some-tool")
		}
		if len(args) != 1 || args[0] != "--flag" {
			t.Fatalf("runner called with args = %v, want %v", args, []string{"--flag"})
		}
		return "", timeoutErr
	}

	got, err := netgearswitch.ResolveSecret(&spec, mapEnv(nil), fakeRunner)
	if got != nil {
		t.Fatalf("ResolveSecret(%q) = %v, want nil", spec, got)
	}
	if !errors.Is(err, netgearswitch.ErrCredential) {
		t.Fatalf("ResolveSecret(%q) error = %v, want wrapping ErrCredential", spec, err)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("ResolveSecret(%q) error = %q, want it to mention the runner's error", spec, err.Error())
	}
}

func TestEnsureSecureFileOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure.toml")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := netgearswitch.EnsureSecureFile(path); err != nil {
		t.Errorf("EnsureSecureFile(0600 file) = %v, want nil", err)
	}
}

func TestEnsureSecureFileInsecure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "insecure.toml")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := netgearswitch.EnsureSecureFile(path)
	if !errors.Is(err, netgearswitch.ErrConfig) {
		t.Fatalf("EnsureSecureFile(0644 file) = %v, want wrapping ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "600") {
		t.Errorf("EnsureSecureFile error = %q, want it to mention chmod 600", err.Error())
	}
}

func TestEnsureSecureFileGroupWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "group-writable.toml")
	if err := os.WriteFile(path, []byte("data"), 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := netgearswitch.EnsureSecureFile(path); !errors.Is(err, netgearswitch.ErrConfig) {
		t.Errorf("EnsureSecureFile(0660 file) = %v, want wrapping ErrConfig", err)
	}
}

func TestEnsureSecureFileMissing(t *testing.T) {
	err := netgearswitch.EnsureSecureFile(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err == nil {
		t.Fatal("EnsureSecureFile(missing file) = nil, want an error")
	}
}

func TestResolveSecretCommandNotFound(t *testing.T) {
	spec := "!netgearswitch-does-not-exist-anywhere-on-path --flag"
	got, err := netgearswitch.ResolveSecret(&spec, mapEnv(nil), nil)
	if got != nil {
		t.Fatalf("ResolveSecret(%q) = %v, want nil", spec, got)
	}
	if !errors.Is(err, netgearswitch.ErrCredential) {
		t.Fatalf("ResolveSecret(%q) error = %v, want wrapping ErrCredential", spec, err)
	}
}

// TestGetModelAndModels exercises the alias.go re-exports of the model
// registry, so callers importing only this top-level package can look up
// models without a direct import of the model subpackage.
func TestGetModelAndModels(t *testing.T) {
	sm, err := netgearswitch.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("GetModel(gs305ep) error = %v, want nil", err)
	}
	if sm.Key != "gs305ep" {
		t.Errorf("GetModel(gs305ep).Key = %q, want %q", sm.Key, "gs305ep")
	}

	if _, err := netgearswitch.GetModel("no-such-model"); !errors.Is(err, netgearswitch.ErrUnknownModel) {
		t.Errorf("GetModel(no-such-model) error = %v, want wrapping ErrUnknownModel", err)
	}

	all := netgearswitch.Models()
	if len(all) == 0 {
		t.Error("Models() returned no entries, want the full registry")
	}
}
