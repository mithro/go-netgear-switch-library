//go:build crosslang

package crosslang

// go_fake_test.go: Suite 1 -- the Go-library <-> Go-fake round trip
// (CC1's own deliverable). For every model in suite1Models, starts a REAL
// Go fake via virtual.GoFakeProvider -- real loopback SNMP/NSDP/HTTP/SSH/
// Telnet listeners, never an in-process stub -- and runs the shared suite
// (suite.go) across every backend the model serves, INCLUDING the FASTPATH
// backends (SSH/Telnet): this is both the framework's own proof (the
// Provider seam, the capability-matrix-driven enumerator and the central
// op->method map all get exercised here for the first time) and a genuine,
// full-coverage Go<->Go conformance round trip in its own right.

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// TestGoLibVsGoFake_AllBackends drives runReadSuite for every model in
// suite1Models against a live virtual.GoFakeProvider.
func TestGoLibVsGoFake_AllBackends(t *testing.T) {
	provider := &virtual.GoFakeProvider{}
	t.Cleanup(func() { _ = provider.CloseAll() })

	for _, modelKey := range suite1Models {
		t.Run(modelKey, func(t *testing.T) {
			runReadSuite(t, provider, modelKey)
		})
	}
}

// TestGoLibVsGoFake_WriteRoundTripPerBackend proves a write op reaches the
// fake and verifies, for every backend this harness addresses: SNMP, NSDP,
// HTTP, SSH and Telnet. NSDP is demonstrated via set_port_description (the
// only one of the two demo ops NSDP supports at all); the other four are
// demonstrated via set_port_enabled -- see runSetPortEnabledRoundTrip's own
// doc comment for why the FASTPATH CLI backends specifically need that op
// rather than set_port_description. One (model, backend) pairing is picked
// per backend, each one a model that genuinely serves the chosen op over it
// per the capabilities oracle (capabilities.Matrix).
func TestGoLibVsGoFake_WriteRoundTripPerBackend(t *testing.T) {
	provider := &virtual.GoFakeProvider{}
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
		{"gsm7252ps", model.BackendSSH},
		{"gsm7228ps", model.BackendTelnet},
	}
	for _, tc := range cases {
		t.Run(string(tc.backend), func(t *testing.T) {
			runSetPortEnabledRoundTrip(t, provider, tc.modelKey, tc.backend)
		})
	}
}
