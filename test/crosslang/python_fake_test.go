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
// TestPythonFakeProvider_ExactBoundBackends asserts PythonFakeProvider's own
// Endpoints report SSHPort==0/TelnetPort==0 for every model (Python's fake
// can never bind either -- see python_provider.go's own doc comment), and
// servedBackends (provider.go) already treats those as "not served" so
// triples() never generates an SSH/Telnet triple against this provider in
// the first place. That same test also asserts the EXACT set of {SNMP,
// NSDP, HTTP} backends each model's Python fake binds, and a running total
// of read triples exercised across all models -- see its own doc comment
// for why a merely-nonempty-per-model check (runReadSuite's own
// len(trips)==0 guard) is not enough to catch a PARTIAL Python-fake startup
// (e.g. a regression that bound SNMP but silently not HTTP for a
// multi-backend model), which would otherwise shrink this suite's total
// coverage silently, with an all-green result.

import (
	"context"
	"testing"

	"github.com/mithro/go-netgear-switch-library/capabilities"
	"github.com/mithro/go-netgear-switch-library/model"
)

// pythonBoundBackends is the exact, fixed set of backend faces Python's
// fake can EVER bind (the pinned virtual/server.py's VirtualSwitch.start():
// SNMP, NSDP and HTTP each in their own independent `if Backend.X in
// self._model_info.backends` block). The FASTPATH/CLI face
// (virtual/faces/cli.py) is in-process with no socket at all -- never a
// member of this set, regardless of a model's own registry Backends, which
// is why SSHPort/TelnetPort are asserted 0 for every model unconditionally
// below rather than derived from expectedPythonBoundBackends.
var pythonBoundBackends = []model.Backend{model.BackendSNMP, model.BackendNSDP, model.BackendHTTP}

// expectedPythonBoundBackends returns the exact set of backends
// PythonFakeProvider's Endpoints must report a nonzero port for, given m:
// m's OWN registry Backends intersected with pythonBoundBackends, grounded
// directly in model.Registry (never a hardcoded per-model list) so this can
// never drift out of step with a registry change.
//
// Deliberately INDEPENDENT of provider.go's servedBackends m4300-16x/HTTP
// exclusion: that exclusion is about the Go FACADE being unable to dial
// this fake's ephemeral plain-HTTP port for that one model (its
// webui.HTTPModelSpec forces a fixed WebPort/HTTPS scheme -- see
// servedBackends' own doc comment), not about whether Python's fake itself
// bound the face -- it does (VirtualSwitch.start() binds HTTP for any model
// with Backend.HTTP in its registry entry, m4300-16x included), so this
// function's expected set for m4300-16x still includes HTTP even though
// servedBackends() will never route a triple to it.
func expectedPythonBoundBackends(m *model.SwitchModel) map[model.Backend]bool {
	want := make(map[model.Backend]bool, len(pythonBoundBackends))
	for _, b := range pythonBoundBackends {
		if m.HasBackend(b) {
			want[b] = true
		}
	}
	return want
}

// wantPythonReadTripleCount is the total number of (model, backend, op)
// READ triples this suite exercises across all suite1Models entries and
// every backend PythonFakeProvider actually serves for each -- measured
// directly (a live run while building this suite: 132) and asserted below
// as a second, coarser net alongside the per-model exact-bound-backend
// check: a regression that silently dropped an entire model's or backend's
// worth of triples would shrink this total even if every triple that DID
// still run kept passing -- exactly the quietly-shrinking-coverage-with-a-
// green-result failure mode this harness exists to catch (see this file's
// own doc comment).
const wantPythonReadTripleCount = 132

// TestPythonFakeProvider_ExactBoundBackends is the POSITIVE, explicit
// per-model assertion that PythonFakeProvider's announced Endpoints bind
// EXACTLY the backend set the model's own registry entry says Python's fake
// should bind (expectedPythonBoundBackends): a nonzero port for each
// backend in that set, a zero port for every other backend of {SNMP, NSDP,
// HTTP}, and SSHPort/TelnetPort always 0 (Python's fake has no CLI socket
// at all, unconditionally -- see this file's own doc comment).
//
// This is strictly stronger than checking "at least one triple ran"
// (runReadSuite's own len(trips)==0 guard): that guard only catches a model
// with ZERO triples, not a PARTIAL loss. Without this test, a regression
// that made `ngsw serve` bind SNMP for a multi-backend model but silently
// fail to bind its HTTP face would make that model's HTTP triples vanish
// via the ordinary port==0-means-unserved convention (servedBackends,
// provider.go) while its SNMP triples kept passing -- total exercised
// coverage would silently shrink below wantPythonReadTripleCount with an
// otherwise all-green result, exactly the vacuity this harness exists to
// prevent. Folding in what was formerly a separate SSH/Telnet-only test
// also halves the number of `ngsw serve` subprocesses this file starts
// just to prove the FASTPATH exclusion, since the same StartModel call now
// proves both facts at once.
//
// The running total of read triples across all models is checked against
// wantPythonReadTripleCount once every subtest has completed, as the
// second, coarser net described in this file's own doc comment.
func TestPythonFakeProvider_ExactBoundBackends(t *testing.T) {
	provider := &PythonFakeProvider{}
	t.Cleanup(func() { _ = provider.CloseAll() })

	total := 0
	for _, modelKey := range suite1Models {
		t.Run(modelKey, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
			defer cancel()
			ep, err := provider.StartModel(ctx, modelKey)
			if err != nil {
				t.Fatalf("StartModel(%q): %v", modelKey, err)
			}
			m, err := model.GetModel(modelKey)
			if err != nil {
				t.Fatalf("GetModel(%q): %v", modelKey, err)
			}

			want := expectedPythonBoundBackends(m)
			got := map[model.Backend]int{
				model.BackendSNMP: ep.SnmpPort,
				model.BackendNSDP: ep.NsdpPort,
				model.BackendHTTP: ep.HTTPPort,
			}
			for _, b := range pythonBoundBackends {
				bound := got[b] != 0
				switch {
				case want[b] && !bound:
					t.Errorf("%s port = 0, want nonzero -- %s's registry Backends includes %s, so Python's fake must bind it", b, modelKey, b)
				case !want[b] && bound:
					t.Errorf("%s port = %d, want 0 -- %s's registry Backends does not include %s", b, got[b], modelKey, b)
				}
			}
			if ep.SSHPort != 0 {
				t.Errorf("SSHPort = %d, want 0 -- Python's fake's FASTPATH/CLI face is in-process with no socket (virtual/faces/cli.py)", ep.SSHPort)
			}
			if ep.TelnetPort != 0 {
				t.Errorf("TelnetPort = %d, want 0 -- Python's fake's FASTPATH/CLI face is in-process with no socket (virtual/faces/cli.py)", ep.TelnetPort)
			}

			served := servedBackends(modelKey, ep)
			trips, err := triples(modelKey, capabilities.ReadOperations, served)
			if err != nil {
				t.Fatalf("triples(%q): %v", modelKey, err)
			}
			total += len(trips)
		})
	}

	if total != wantPythonReadTripleCount {
		t.Errorf("total read triples across all %d models = %d, want %d -- see wantPythonReadTripleCount's own doc comment", len(suite1Models), total, wantPythonReadTripleCount)
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
