//go:build crosslang

package crosslang

// python_fake_test.go: Suite 2 -- the Go-library <-> Python-fake round trip
// (CC2's own deliverable, D-VIRT §5/slice 10). For every model in
// suite1Models (the same 8 hand-authored-seed models Suite 1 exercises --
// Python's own pinned virtual/server.py._SEEDS carries the identical set,
// modulo m7300/xs748t, which neither language's fake seeds at all), starts a
// REAL Python `ngsw serve` subprocess via PythonFakeProvider and runs the
// SAME shared suite (suite.go), opmap (opmap.go) and enumerator (triples.go)
// Suite 1 already used against virtual.GoFakeProvider -- completely
// unchanged. This is the harness's first genuine cross-LANGUAGE check: every
// assertion that passes here is Go's library reading real wire protocol
// bytes a Python process produced and getting back exactly the value Go's
// OWN fake would have given it, which is only possible if both languages'
// hand-authored seeds -- transcribed independently from the SAME real
// hardware captures (principle 5) -- genuinely agree.
//
// FASTPATH (SSH/Telnet) triples are structurally absent here, not skipped:
// TestPythonFakeProvider_NoCLIBackend asserts PythonFakeProvider's own
// Endpoints report SSHPort==0/TelnetPort==0 for every model, and
// servedBackends (provider.go) already treats those as "not served" so
// triples() never generates an SSH/Telnet triple against this provider in
// the first place -- see python_provider.go's own doc comment for why
// Python's fake can never bind either.

import (
	"context"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// TestPythonFakeProvider_NoCLIBackend is the POSITIVE, explicit assertion of
// PythonFakeProvider's structural FASTPATH exclusion (see this file's own
// doc comment): for every model this suite drives, Endpoints.SSHPort and
// Endpoints.TelnetPort are exactly 0. Deliberately separate from
// TestGoLibVsPythonFake_AllBackends below -- a provider that ever started
// reporting a nonzero SSH/TelnetPort by accident (e.g. a copy-paste from
// GoFakeProvider) would otherwise pass completely unnoticed: triples() would
// simply start generating SSH/Telnet triples against it, and any that
// happened to fail would look like an ordinary read-check bug, not what it
// actually is.
func TestPythonFakeProvider_NoCLIBackend(t *testing.T) {
	provider := &PythonFakeProvider{}
	t.Cleanup(func() { _ = provider.CloseAll() })

	for _, modelKey := range suite1Models {
		t.Run(modelKey, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
			defer cancel()
			ep, err := provider.StartModel(ctx, modelKey)
			if err != nil {
				t.Fatalf("StartModel(%q): %v", modelKey, err)
			}
			if ep.SSHPort != 0 {
				t.Errorf("SSHPort = %d, want 0 -- Python's fake's FASTPATH/CLI face is in-process with no socket (virtual/faces/cli.py)", ep.SSHPort)
			}
			if ep.TelnetPort != 0 {
				t.Errorf("TelnetPort = %d, want 0 -- Python's fake's FASTPATH/CLI face is in-process with no socket (virtual/faces/cli.py)", ep.TelnetPort)
			}
		})
	}
}

// TestGoLibVsPythonFake_AllBackends drives runReadSuite for every model in
// suite1Models against a live PythonFakeProvider -- across SNMP/NSDP/HTTP
// (whichever backends that model's Python fake actually binds; SSH/Telnet
// never run at all, per this file's own doc comment).
func TestGoLibVsPythonFake_AllBackends(t *testing.T) {
	provider := &PythonFakeProvider{}
	t.Cleanup(func() { _ = provider.CloseAll() })

	for _, modelKey := range suite1Models {
		t.Run(modelKey, func(t *testing.T) {
			runReadSuite(t, provider, modelKey)
		})
	}
}

// TestGoLibVsPythonFake_WriteRoundTripPerBackend proves a write op reaches
// Python's fake and verifies, for every backend this provider addresses:
// SNMP, NSDP and HTTP (mirrors TestGoLibVsGoFake_WriteRoundTripPerBackend in
// go_fake_test.go minus its SSH/Telnet cases, which have no Python-fake
// analogue at all). Same (model, backend) pairings Suite 1 uses where
// Python's fake serves them too, so this is a direct, symmetric proof that
// Go's WRITERS -- not just its readers -- work unchanged against real
// Python-fake wire protocol.
func TestGoLibVsPythonFake_WriteRoundTripPerBackend(t *testing.T) {
	provider := &PythonFakeProvider{}
	t.Cleanup(func() { _ = provider.CloseAll() })

	t.Run("nsdp", func(t *testing.T) {
		runSetPortDescriptionRoundTrip(t, provider, "gs110emx", model.BackendNSDP)
	})

	cases := []struct {
		modelKey string
		backend  model.Backend
	}{
		{"gsm7252ps", model.BackendSNMP},
		{"gs728tpp", model.BackendHTTP},
	}
	for _, tc := range cases {
		t.Run(string(tc.backend), func(t *testing.T) {
			runSetPortEnabledRoundTrip(t, provider, tc.modelKey, tc.backend)
		})
	}
}
