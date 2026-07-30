// dispatch.go: the backend-registry seam + read-side dispatch loop, ported
// from src/netgear_switch/_dispatch.py and sync_api.py's SyncSwitch._read
// (the normative source; that repo is read-only from here). Any discrepancy
// between this file and the pinned Python source is a bug in this file. See
// docs/superpowers/plans/2026-07-30-slice-03-dossier-facade.md (D-FAC) §2.7
// and §3.2 for the full semantics this file implements.

package netgearswitch

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/mithro/go-netgear-switch-library/model"
)

// BackendReader is the read-op surface the dispatch loop calls, mirroring
// the union Python's _AnyReader spans (SnmpReader | NsdpReader | HttpReader
// | CliReader): every registered backend's reader must implement all nine
// methods, and an op it cannot serve returns an error wrapping
// model.ErrUnsupportedCapability rather than a panic or a fabricated zero
// value. snmp.Reader (see snmp/reader.go) already satisfies this interface
// verbatim -- no adapter shim is needed for the SNMP backend.
type BackendReader interface {
	GetPorts(ctx context.Context) ([]model.PortStatus, error)
	GetStats(ctx context.Context) ([]model.PortStats, error)
	GetVlans(ctx context.Context) ([]model.VLANInfo, error)
	GetPvids(ctx context.Context) ([]model.Pvid, error)
	GetLldp(ctx context.Context) ([]model.LLDPNeighbor, error)
	GetMacs(ctx context.Context) ([]model.MacEntry, error)
	GetPoe(ctx context.Context) ([]model.PoEStatus, error)
	GetSensors(ctx context.Context) ([]model.Sensor, error)
	GetMgmtIP(ctx context.Context) (model.MgmtIPConfig, error)
}

// BackendBuilder constructs the BackendReader for one backend, given the
// Switch requesting it -- so the builder can read whatever per-backend
// credential/injection field the Switch already holds (an injected
// snmp.Client, the SNMP read community, etc.) without this package needing
// a separate options-bag type per backend. A builder that cannot serve the
// model at all (e.g. the model has no SNMP backend) returns an error
// wrapping model.ErrUnsupportedCapability; readVia treats that exactly like
// an unregistered backend (see readerFor below).
type BackendBuilder func(sw *Switch) (BackendReader, error)

// backendPreference is the fixed per-op backend fallback order, mirroring
// Python's _BACKEND_PREFERENCE exactly: try SNMP, then NSDP, then HTTP,
// then SSH -- the first backend whose reader serves an op wins. This order
// is NEVER derived from a model's own Backends slice (model/registry.go's
// own doc comment says that order carries no meaning) and must not change
// without a deliberate, separately-flagged decision (D-FAC §3.3).
var backendPreference = []model.Backend{model.BackendSNMP, model.BackendNSDP, model.BackendHTTP, model.BackendSSH}

// backendRegistryMu guards backendRegistry so RegisterBackend is safe to
// call from multiple packages' init() functions -- Go gives no ordering
// guarantee across independent packages' init()s beyond the one implied by
// their import graph -- and so a concurrently-dispatching Switch never
// races a RegisterBackend call landing at the same time (e.g. a program
// that registers backends from goroutines at startup, or a test suite that
// registers fakes per-test).
var (
	backendRegistryMu sync.RWMutex
	backendRegistry   = map[model.Backend]BackendBuilder{}
)

// RegisterBackend installs build as the reader constructor for backend b,
// overwriting any builder previously registered for the same backend. Meant
// to be called from an importing package's init() -- slices 05-07 register
// their NSDP/HTTP/SSH backends this way -- or explicitly from a caller's
// main() (a blank `_` import of the backend package is Go's standard
// plugin-registration idiom), never implicitly from inside this package, so
// "which backends are compiled in" stays an explicit, grep-able decision
// (mirroring Python's function-local lazy transport imports: "import
// netgear_switch never requires net-snmp binaries or pysnmp"). Safe for
// concurrent use with itself and with any in-flight Switch dispatch.
func RegisterBackend(b model.Backend, build BackendBuilder) {
	backendRegistryMu.Lock()
	defer backendRegistryMu.Unlock()
	backendRegistry[b] = build
}

// lookupBackendBuilder returns the builder registered for b, if any.
func lookupBackendBuilder(b model.Backend) (BackendBuilder, bool) {
	backendRegistryMu.RLock()
	defer backendRegistryMu.RUnlock()
	build, ok := backendRegistry[b]
	return build, ok
}

// readerFor returns the cached BackendReader for backend, building (and
// caching) it via the registered BackendBuilder on first use -- mirroring
// Python's _reader_for: populated lazily, exactly once per backend per
// Switch. An unregistered backend (no Go implementation yet -- NSDP/HTTP/
// SSH today) returns an error wrapping model.ErrUnsupportedCapability
// naming the backend, exactly like a registered builder's own capability
// gate would (D-FAC §3.2/§3.3, trap #10) -- readVia cannot tell the two
// cases apart, by design. A builder's error is NEVER cached (only a
// successfully built reader is), so a gated-off model re-evaluates the gate
// every call -- cheap (a map lookup), so this is a correctness point, not a
// performance one (D-FAC §2.5, trap #3).
func (s *Switch) readerFor(backend model.Backend) (BackendReader, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r, ok := s.readerCache[backend]; ok {
		return r, nil
	}

	build, ok := lookupBackendBuilder(backend)
	if !ok {
		return nil, fmt.Errorf("model %q has no %s backend implementation yet: %w", s.model.Key, backend, model.ErrUnsupportedCapability)
	}
	r, err := build(s)
	if err != nil {
		return nil, err
	}
	s.readerCache[backend] = r
	return r, nil
}

// readVia is the read-side dispatch loop, mirroring Python's
// SyncSwitch._read exactly (D-FAC §2.7's six ordering rules):
//
//  1. Walk backendPreference in its fixed order, never model.Backends' own
//     (unordered-by-contract) order.
//  2. A backend the model doesn't have (model.HasBackend false) is skipped
//     silently -- no `last` update.
//  3. readerFor's construction/gate failure, if it wraps
//     model.ErrUnsupportedCapability, is recorded as `last`; the loop moves
//     on to the next backend without retrying this one.
//  4. fn(reader) raising an error wrapping model.ErrUnsupportedCapability is
//     likewise recorded as `last` and the loop proceeds to the next
//     backend.
//  5. Any OTHER error -- notably one wrapping model.ErrCredential -- is
//     NEVER treated as a skip; it propagates immediately, aborting the
//     whole loop right there (a bare "catch any error" implementation would
//     silently swallow a credential failure; this must not happen).
//  6. If every applicable backend was tried and none returned successfully,
//     the LAST recorded error is returned (whichever backend was tried
//     last chronologically, which is the lowest-preference backend among
//     those attempted -- NOT necessarily the first one tried). If no
//     backend in backendPreference was even a member of model.Backends (so
//     `last` never got set), a fresh error wrapping
//     model.ErrUnsupportedCapability naming the model and op is returned.
//
// op is a short, snake_case-ish operation name (e.g. "get_ports") folded
// into that fresh fallback error's message for diagnosability; it plays no
// role in the dispatch semantics themselves.
func (s *Switch) readVia(ctx context.Context, op string, fn func(BackendReader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var last error
	for _, backend := range backendPreference {
		if !s.model.HasBackend(backend) {
			continue
		}

		reader, err := s.readerFor(backend)
		if err != nil {
			if errors.Is(err, model.ErrUnsupportedCapability) {
				last = err
				continue
			}
			return err
		}

		if err := fn(reader); err != nil {
			if errors.Is(err, model.ErrUnsupportedCapability) {
				last = err
				continue
			}
			return err
		}
		return nil
	}

	if last != nil {
		return last
	}
	return fmt.Errorf("model %q has no backend supporting %s: %w", s.model.Key, op, model.ErrUnsupportedCapability)
}
