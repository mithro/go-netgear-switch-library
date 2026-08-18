//go:build crosslang

package crosslang

// provider.go: the Provider seam this harness drives (CC1's own deliverable
// -- see the package doc comment on suite.go for the full picture). A
// Provider starts a running fake for a model key and hands back the
// endpoints (host, per-backend ports, community, HTTP password) a caller
// needs to point a *netgearswitch.Switch at it; it never hands back a
// concrete fake implementation, so the SAME harness (triples.go's
// enumerator, opmap.go's op->method map, suite.go's runReadSuite/
// runSetPortDescriptionRoundTrip) can be driven against a completely
// different Provider implementation -- this slice's virtual.GoFakeProvider
// (real Go loopback listeners), and, in a later slice, a PythonFakeProvider
// that shells out to `ngsw serve` -- without a single change to any of
// those three files.

import (
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// Provider is virtual.EndpointProvider itself, not a locally-redeclared
// lookalike: virtual.GoFakeProvider already satisfies it with zero adapter
// code, and its StartModel(ctx, modelKey) (virtual.Endpoints, error)
// signature is exactly the shape a future PythonFakeProvider needs to
// implement to plug into this same suite.
type Provider = virtual.EndpointProvider

// servedBackends returns the backends ep actually serves, mapped to the
// port each one is live on. virtual.Endpoints' own convention (see its doc
// comment in virtual/server.go) is that a 0 port means "this provider does
// not serve that backend" -- e.g. a model with no BackendNSDP, or, for a
// future provider, a backend it simply never implemented -- and triples()
// relies on this map to skip any (backend, op) pair the running provider
// cannot actually reach, rather than re-deriving backend membership from
// the model registry itself.
//
// modelKey carries ONE deliberate, documented exception on top of that
// mechanical port check: m4300-16x's HTTP backend is excluded here even
// though GoFakeProvider genuinely binds a live HTTPPort for it. Its
// webui.HTTPModelSpec (webui/endpoints.go) sets BOTH Secure=true (so
// backend_http.go's buildDefaultHTTPSession/httpHost pick an "https://"
// scheme) AND a fixed WebPort=49152 (httpHost unconditionally appends
// ":49152" to whatever host string it is given) -- so a *netgearswitch.
// Switch can only ever be told to dial https://host:49152 for this model,
// never this fake's own ephemeral, plain-HTTP HTTPPort. This is not
// something this test harness can route around: every existing HTTP
// integration test for m4300-16x in this repo (virtual/httpface_test.go's
// TestHTTPFaceSecurePOSTRequiresOriginHeader and friends) bypasses the
// public facade entirely for exactly this reason, constructing a
// desecured spec copy and handing it straight to webui.NewHTTPClient
// instead of going through netgearswitch.New. capabilities.Matrix still
// (correctly) marks m4300-16x/http Supported -- a REAL switch's HTTPS
// port 49152 works fine -- so this is a harness-reachability exclusion,
// not a capabilities-table correction; a future slice giving this harness
// a way to run a real TLS listener (or to override WebPort) could remove
// it.
func servedBackends(modelKey string, ep virtual.Endpoints) map[model.Backend]int {
	served := map[model.Backend]int{}
	if ep.SnmpPort != 0 {
		served[model.BackendSNMP] = ep.SnmpPort
	}
	if ep.NsdpPort != 0 {
		served[model.BackendNSDP] = ep.NsdpPort
	}
	if ep.HTTPPort != 0 && modelKey != "m4300-16x" {
		served[model.BackendHTTP] = ep.HTTPPort
	}
	if ep.SSHPort != 0 {
		served[model.BackendSSH] = ep.SSHPort
	}
	if ep.TelnetPort != 0 {
		served[model.BackendTelnet] = ep.TelnetPort
	}
	return served
}
