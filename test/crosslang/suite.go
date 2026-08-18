//go:build crosslang

// Package crosslang is the reusable cross-language conformance-test harness
// skeleton (CC1, D-VIRT §5/slice 10): a Provider seam (provider.go) that
// starts a running fake and hands back its live endpoints, a capability-
// matrix-driven (model, backend, operation) enumerator (triples.go) that
// reads its verdicts from the SAME oracle capabilities/matrix_parity_test.go
// cross-checks against the pinned Python reference, a central op-name ->
// facade-method map (opmap.go) with this suite's own non-degenerate
// assertions, and the shared suite body (this file) that ties all three
// together: build a *netgearswitch.Switch pointed at the fake's announced
// endpoint for one backend, run the op, assert on the result.
//
// This package is build-tag-gated (see the tag on every file in it) so it
// never runs under plain `go test ./...` or this repo's default CI gate --
// only `make crosslang` (-tags crosslang) builds and runs it -- because it
// starts REAL loopback network listeners per subtest, which is a different
// resource/latency profile than this repo's default, always-on unit-test
// suite.
//
// go_fake_test.go (this package) is Suite 1: the Go-library <-> Go-fake
// round trip, driven through virtual.GoFakeProvider. Later crosslang slices
// plug a Python-fake Provider (CC2) and a Python-driver-vs-Go-fake pairing
// (CC4) into this SAME suite.go/opmap.go/triples.go machinery -- that
// reusability is the entire point of splitting the harness out from Suite
// 1's own test file.
package crosslang

import (
	"context"
	"fmt"
	"testing"
	"time"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/capabilities"
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// suiteTimeout bounds every StartModel/read/write call this suite issues --
// generous for a loopback round trip under `make crosslang`'s
// jail.sh-wrapped, CPU/memory-limited environment, short enough that a
// genuine deadlock still fails the test rather than hanging make forever.
const suiteTimeout = 30 * time.Second

// cliUsername/cliPassword are virtual.NewVirtualSwitch's own SSH/telnet
// login defaults (server.go's WithCLIUsername/WithCLIPassword doc
// comments). virtual.Endpoints deliberately carries no CLI credential
// fields (only Community/HTTPPassword -- see its own doc comment), so a
// Provider that wants different CLI credentials must document that
// out-of-band; this harness hardcodes the ones every current Provider
// (GoFakeProvider) actually uses, mirroring facade_cli_integration_test.go's
// own cliCapstoneUser/cliCapstonePass constants one level up.
const (
	cliUsername = "admin"
	cliPassword = "password"
)

// suite1Models is every registered model EXCEPT m7300 and xs748t, which
// virtual.BuildState (virtual/seed.go) has no hand-authored seed for at
// all: NewVirtualSwitch for either falls through to NewState's blank-but-
// valid State -- zero ports, zero VLANs, zero everything -- so a live round
// trip against them would only ever prove "empty in, empty out", a vacuous,
// silently-misleading pass this suite refuses to fabricate (principle 2).
// Every OTHER registered model has a real, hand-authored seed (BuildState's
// own doc comment lists all eight) and is exercised in full below. If a
// hand-authored seed is ever added for m7300/xs748t, deleting the two names
// below is the only change needed to include them.
var suite1Models = func() []string {
	excluded := map[string]bool{"m7300": true, "xs748t": true}
	var out []string
	for _, m := range model.Models() {
		if !excluded[m.Key] {
			out = append(out, m.Key)
		}
	}
	return out
}()

// buildSwitch constructs a *netgearswitch.Switch pinned to backend,
// addressing ep's live endpoint for it -- one construction shape per
// backend, mirroring exactly how this repo's own facade_*_integration_
// test.go files build a Switch per backend (facadeFor/httpFacadeFor/
// nsdpFacadeFor/cliFacadeOverSSH/cliFacadeOverTelnet): SNMP and HTTP take a
// "host:port" address string, NSDP needs an already-built nsdp.Client
// (package nsdp separates host/port, so the facade's single "host" string
// can't carry an ephemeral port the way SNMP's convention does), and SSH/
// Telnet take a bare host plus WithSSHPort/WithTelnetPort.
func buildSwitch(t testing.TB, ep virtual.Endpoints, m *model.SwitchModel, backend model.Backend) *netgearswitch.Switch {
	t.Helper()
	switch backend {
	case model.BackendSNMP:
		host := fmt.Sprintf("%s:%d", ep.Host, ep.SnmpPort)
		// WithSNMPWriteCommunityResolver mirrors facade_write_integration_
		// test.go's writableFacadeFor: the virtual fake's single SNMP
		// community string serves both reads and writes (virtual/server.go's
		// WithCommunity option), and the write-side gate is a SEPARATE,
		// stricter check than the read-side one (D-WR §3.4) that this
		// package's own write round trip (suite.go's runWriteRoundTrip)
		// needs resolved.
		sw, err := netgearswitch.New(m, host,
			netgearswitch.WithSNMPCommunity(ep.Community),
			netgearswitch.WithSNMPWriteCommunityResolver(func() (*string, error) { c := ep.Community; return &c, nil }),
			netgearswitch.WithBackend(backend))
		if err != nil {
			t.Fatalf("New(%s, snmp): %v", m.Key, err)
		}
		return sw
	case model.BackendNSDP:
		client, err := nsdp.NewUDPClient(ep.Host, nsdp.WithServerPort(ep.NsdpPort), nsdp.WithClientPort(0), nsdp.WithTimeout(suiteTimeout))
		if err != nil {
			t.Fatalf("nsdp.NewUDPClient(%s): %v", m.Key, err)
		}
		// WithNSDPPassword("password") matches virtual.NewState's own
		// NsdpPassword default (state.go) -- GoFakeProvider never overrides
		// it -- mirroring facade_nsdp_integration_test.go's own comment on
		// the same literal.
		sw, err := netgearswitch.New(m, ep.Host,
			netgearswitch.WithNSDPClient(client),
			netgearswitch.WithNSDPPassword("password"),
			netgearswitch.WithBackend(backend))
		if err != nil {
			t.Fatalf("New(%s, nsdp): %v", m.Key, err)
		}
		return sw
	case model.BackendHTTP:
		host := fmt.Sprintf("%s:%d", ep.Host, ep.HTTPPort)
		sw, err := netgearswitch.New(m, host, netgearswitch.WithHTTPPassword(ep.HTTPPassword), netgearswitch.WithBackend(backend))
		if err != nil {
			t.Fatalf("New(%s, http): %v", m.Key, err)
		}
		return sw
	case model.BackendSSH:
		sw, err := netgearswitch.New(m, ep.Host, netgearswitch.WithBackend(backend), netgearswitch.WithSSHPort(ep.SSHPort),
			netgearswitch.WithCLIUsername(cliUsername), netgearswitch.WithCLIPassword(cliPassword))
		if err != nil {
			t.Fatalf("New(%s, ssh): %v", m.Key, err)
		}
		return sw
	case model.BackendTelnet:
		sw, err := netgearswitch.New(m, ep.Host, netgearswitch.WithBackend(backend), netgearswitch.WithTelnetPort(ep.TelnetPort),
			netgearswitch.WithCLIUsername(cliUsername), netgearswitch.WithCLIPassword(cliPassword))
		if err != nil {
			t.Fatalf("New(%s, telnet): %v", m.Key, err)
		}
		return sw
	}
	t.Fatalf("buildSwitch: no builder for backend %s", backend)
	return nil
}

// runReadSuite starts modelKey's fake via provider, then -- for every
// (backend, read-op) triple capabilities.Matrix marks Supported AND whose
// backend provider actually serves (servedBackends) -- builds a Switch
// pinned to that backend and runs the op's central readOps check
// (opmap.go). Shared by every read-side crosslang suite (this slice's
// Go-lib<->Go-fake suite; later slices' Python-fake/Python-driver suites),
// so the op->method wiring and non-degenerate assertions live in exactly
// one place.
func runReadSuite(t *testing.T, provider Provider, modelKey string) {
	t.Helper()
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

	served := servedBackends(modelKey, ep)
	trips, err := triples(modelKey, capabilities.ReadOperations, served)
	if err != nil {
		t.Fatalf("triples(%q): %v", modelKey, err)
	}
	if len(trips) == 0 {
		t.Fatalf("triples(%q) = 0 read triples -- provider serves backends %v, want at least one Supported triple", modelKey, served)
	}

	for _, tr := range trips {
		t.Run(string(tr.Backend)+"/"+tr.Op.Name, func(t *testing.T) {
			check, ok := readOps[tr.Op.Name]
			if !ok {
				t.Fatalf("no readOps entry for operation %q -- opmap.go is missing a case", tr.Op.Name)
				return
			}
			sw := buildSwitch(t, ep, m, tr.Backend)
			t.Cleanup(func() { _ = sw.Close() })
			check(ctx, t, sw, tr.Backend, m)
		})
	}
}

// writeDemoPort is the port every write-round-trip demonstration below
// targets -- port 1 exists on every model any crosslang suite exercises
// (the smallest, gs105pe/gs305ep, has 5 ports).
const writeDemoPort = 1

// runWriteRoundTrip is the shared write+verify scaffold every per-backend
// demonstration below drives: start modelKey's fake via provider, confirm
// the capabilities oracle marks (backend, opName) Supported (never assumed
// -- picking the wrong model/backend pairing fails loudly here, before any
// wire I/O), build a Switch pinned to backend, run write against it, then
// run verify against the SAME Switch to read back and assert the mutation
// stuck. Shared by every write-side demonstration (this slice's two op-
// specific wrappers below; later slices' Python-fake/Python-driver suites
// can reuse it unchanged for their own write+verify pairs).
func runWriteRoundTrip(
	t *testing.T, provider Provider, modelKey string, backend model.Backend, opName string,
	write func(ctx context.Context, sw *netgearswitch.Switch) error,
	verify func(ctx context.Context, t *testing.T, sw *netgearswitch.Switch),
) {
	t.Helper()
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

	op, err := capabilities.OperationByName(opName)
	if err != nil {
		t.Fatalf("OperationByName(%s): %v", opName, err)
	}
	if verdict := capabilities.For(m, backend, op); verdict.Support != capabilities.SupportSupported {
		t.Fatalf("%s/%s not Supported for %q per the capabilities oracle (%s) -- pick a different model/backend pairing", opName, backend, modelKey, verdict.Reason)
	}

	sw := buildSwitch(t, ep, m, backend)
	t.Cleanup(func() { _ = sw.Close() })

	if err := write(ctx, sw); err != nil {
		t.Fatalf("%s(backend=%s) error = %v", opName, backend, err)
		return
	}
	verify(ctx, t, sw)
}

// runSetPortDescriptionRoundTrip drives set_port_description over backend:
// write via the facade, then re-read (over the SAME backend) and assert the
// Description field stuck. Used for SNMP/NSDP/HTTP -- see
// runSetPortEnabledRoundTrip's own doc comment for why the FASTPATH CLI
// backends (SSH/Telnet) need a DIFFERENT op instead.
func runSetPortDescriptionRoundTrip(t *testing.T, provider Provider, modelKey string, backend model.Backend) {
	t.Helper()
	const want = "crosslang-demo"
	runWriteRoundTrip(t, provider, modelKey, backend, "set_port_description",
		func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.SetPortDescription(ctx, writeDemoPort, want, netgearswitch.Write{Backend: &backend})
		},
		func(ctx context.Context, t *testing.T, sw *netgearswitch.Switch) {
			ports, err := sw.GetPorts(ctx, netgearswitch.WithReadBackend(backend))
			if err != nil {
				t.Fatalf("GetPorts() after write, over %s: %v", backend, err)
				return
			}
			for _, p := range ports {
				if p.Port != writeDemoPort {
					continue
				}
				if p.Description == nil || *p.Description != want {
					t.Errorf("port %d Description after SetPortDescription(over %s) = %v, want %q", writeDemoPort, backend, p.Description, want)
				}
				return
			}
			t.Errorf("port %d not present in GetPorts() over %s after write", writeDemoPort, backend)
		},
	)
}

// runSetPortEnabledRoundTrip drives set_port_enabled over backend: read the
// port's current AdminEnabled first (so the write is a genuine, observable
// transition, never a same-state no-op), flip it via the facade, then
// re-read and assert it stuck. Used for SNMP/HTTP/SSH/Telnet -- NOT NSDP,
// which does not support this op at all (facade_nsdp_integration_test.go's
// own doc comment: NSDP's PORT_STATUS carries no interface identifier, so
// AdminEnabled is always reported true regardless of the real admin state --
// exactly why the capabilities oracle excludes NSDP from set_port_enabled).
// See runSetPortDescriptionRoundTrip for NSDP's own demonstration instead.
//
// This op -- not set_port_description -- is what demonstrates the FASTPATH
// CLI backends (SSH/Telnet) specifically: fastpath.Reader.parsePortStatus
// documents (fastpath/parse.go) that `show port all` "carries no ifAlias
// column", so PortStatus.Description is ALWAYS nil over CLI, by design --
// the CLI write side genuinely applies AND internally verifies the
// description (fastpath.Writer.SetPortDescription reads it back via a
// SEPARATE per-port `show port description` command), but the facade's own
// GetPorts() can never observe that field over this backend, so it would be
// the wrong verification read for a CLI round trip specifically.
// AdminEnabled carries no such gap: `show port all` reports it directly.
func runSetPortEnabledRoundTrip(t *testing.T, provider Provider, modelKey string, backend model.Backend) {
	t.Helper()
	var target bool
	runWriteRoundTrip(t, provider, modelKey, backend, "set_port_enabled",
		func(ctx context.Context, sw *netgearswitch.Switch) error {
			ports, err := sw.GetPorts(ctx, netgearswitch.WithReadBackend(backend))
			if err != nil {
				return fmt.Errorf("GetPorts() before write: %w", err)
			}
			found := false
			for _, p := range ports {
				if p.Port == writeDemoPort {
					target = !p.AdminEnabled
					found = true
				}
			}
			if !found {
				return fmt.Errorf("port %d not present in GetPorts() before write", writeDemoPort)
			}
			return sw.SetPortEnabled(ctx, writeDemoPort, target, netgearswitch.Write{Backend: &backend})
		},
		func(ctx context.Context, t *testing.T, sw *netgearswitch.Switch) {
			ports, err := sw.GetPorts(ctx, netgearswitch.WithReadBackend(backend))
			if err != nil {
				t.Fatalf("GetPorts() after write, over %s: %v", backend, err)
				return
			}
			for _, p := range ports {
				if p.Port != writeDemoPort {
					continue
				}
				if p.AdminEnabled != target {
					t.Errorf("port %d AdminEnabled after SetPortEnabled(over %s) = %v, want %v", writeDemoPort, backend, p.AdminEnabled, target)
				}
				return
			}
			t.Errorf("port %d not present in GetPorts() over %s after write", writeDemoPort, backend)
		},
	)
}
