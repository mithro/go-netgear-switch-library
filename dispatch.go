// dispatch.go: the backend-registry seam + read-side single-backend
// dispatch, ported from src/netgear_switch/_dispatch.py and sync_api.py's
// SyncSwitch._read/resolve_backend (the normative source; that repo is
// read-only from here). Any discrepancy between this file and the pinned
// Python source is a bug in this file. See docs/superpowers/plans/
// 2026-07-31-slice-05b-dossier-reconciliation.md (D-REC) Topic A for the
// full semantics this file implements -- in particular A.2 (resolveBackend),
// A.4 (the three-step single dispatch), A.6 (cannotServe's two message
// shapes), and A.10.1-A.10.6 (the Go rework itself).
//
// As of the 1841111 Python re-pin, there is NO loop here: an op runs on
// EXACTLY ONE backend, chosen once by resolveBackend, and an
// UnsupportedCapabilityError from either building that backend's reader or
// running the op itself raises directly (via cannotServe), naming the
// backend that failed -- it is never silently retried on a different one.
// The OLD Go shape (a for loop over backendPreference that skipped backends
// the model lacked and re-raised the LAST UnsupportedCapability seen) was a
// silent fallback and is deleted; see D-REC's "why this dossier exists" for
// the concrete bug that motivated removing it in Python.

package netgearswitch

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/mithro/go-netgear-switch-library/model"
)

// BackendReader is the read-op surface dispatch calls, mirroring the union
// Python's _AnyReader spans (SnmpReader | NsdpReader | HttpReader |
// CliReader): every registered backend's reader must implement all nine
// methods, and an op it cannot serve returns an error wrapping
// model.ErrUnsupportedCapability rather than a panic or a fabricated zero
// value. snmp.Reader (see snmp/reader.go) already satisfies this interface
// verbatim -- no adapter shim is needed for the SNMP backend.
type BackendReader interface {
	GetPorts(ctx context.Context) ([]model.PortStatus, error)
	GetStats(ctx context.Context) ([]model.PortStats, error)
	GetVLANs(ctx context.Context) ([]model.VLANInfo, error)
	GetPVIDs(ctx context.Context) ([]model.Pvid, error)
	GetLLDP(ctx context.Context) ([]model.LLDPNeighbor, error)
	GetMACs(ctx context.Context) ([]model.MacEntry, error)
	GetPoE(ctx context.Context) ([]model.PoEStatus, error)
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
//
// WARNING: readerFor holds s.mu for the entire duration of a builder call
// (see below). A BackendBuilder MUST NOT call back into any Switch method
// that itself acquires s.mu -- directly or transitively -- or it will
// deadlock (sync.Mutex is not reentrant). In practice this means a builder
// may freely READ a Switch's already-resolved fields (host, model, injected
// client, community, etc.) but must never call s.readerFor/readVia or any
// public read method on the same *Switch it was handed.
type BackendBuilder func(sw *Switch) (BackendReader, error)

// backendPreference is the fixed backend RESOLUTION order, mirroring
// Python's _BACKEND_PREFERENCE exactly: when a caller does not name a
// backend, the first member of this list the model declares is THE ONE
// chosen -- nothing else is ever tried. This order is NEVER derived from a
// model's own Backends slice (model/registry.go's own doc comment says that
// order carries no meaning) and must not change without a deliberate,
// separately-flagged decision (D-REC A.2's "preference" parameter mirrors
// this exactly).
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
// overwriting any builder previously registered for the same backend.
//
// The actual registration pattern (see backend_snmp.go): a new root-package
// (netgearswitch) shim file per backend, whose own init() calls
// RegisterBackend, with the BackendBuilder itself calling into that
// backend's protocol package (snmp/, and later nsdp/, http/, ssh/ in slices
// 05-07) to do the real work. This lives in the root package, NOT in the
// protocol package or some external package reached via a blank `_` import,
// because Switch's fields a builder needs (snmpClient, snmpCommunity,
// nsdpInterface, httpPassword, host, model, ...) are all unexported: an
// out-of-package BackendBuilder could not read them, so an
// out-of-package builder is not possible. (This also means there is no
// "which backends are compiled in" toggle via import graph -- every backend
// shim in this module's own source tree registers itself unconditionally.)
//
// A BackendBuilder MUST NOT perform blocking I/O: readerFor (below) calls it
// while holding s.mu for the entire call, so a builder that dials out
// (rather than merely constructing a lazy, not-yet-connected client/session,
// mirroring Python's transports) would serialize and stall every concurrent
// Switch dispatch on that same *Switch. Building a *snmp.Reader or an
// injected client wrapper is fine; opening a socket is not.
//
// Safe for concurrent use with itself and with any in-flight Switch
// dispatch.
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
// gate would -- readVia cannot tell the two cases apart, by design. A
// builder's error is NEVER cached (only a successfully built reader is), so
// a gated-off model re-evaluates the gate every call -- cheap (a map
// lookup), so this is a correctness point, not a performance one. Unchanged
// by the D-REC Topic A rework (A.5): readVia now calls this at most ONCE
// per op, for the single resolved backend, instead of in a preference loop.
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

// resolveBackend picks THE ONE backend an op will run on -- no silent
// substitution -- mirroring Python's _dispatch.resolve_backend verbatim
// (D-REC A.2):
//
//   - requested non-nil: that exact backend, or an error wrapping
//     model.ErrUnsupportedCapability if m does not declare it at all. The
//     caller named a protocol; getting a different one back would make any
//     claim about that protocol worthless (the concrete bug this replaced:
//     an HTTP reader's gap going unnoticed for months because the facade
//     quietly answered from SNMP instead). Note this does NOT check that
//     the resolved backend can actually serve the op -- only that the model
//     declares it -- an op it cannot serve still raises, just later (see
//     cannotServe below).
//   - requested nil: the FIRST backend in preference m declares. This is a
//     pure function of (m, preference) with no memory of any prior call, so
//     repeated calls with the SAME nil requested always resolve to the SAME
//     backend -- the property Snapshot leans on (snapshot.go) to have every
//     field in one call land on one backend, without any extra plumbing.
//     If m declares nothing preference lists at all, an error wrapping
//     model.ErrUnsupportedCapability is returned naming the model.
//
// Message text uses Go's own lowercase Backend spelling throughout (D-REC
// A.10.6): this codebase already renders Backend lowercase everywhere else
// (readerFor's "has no %s backend implementation yet" above, etc.), so these
// two new messages follow suit rather than chasing Python's uppercase
// Backend.name byte-for-byte.
func resolveBackend(m *model.SwitchModel, requested *model.Backend, preference []model.Backend) (model.Backend, error) {
	if requested != nil {
		if !m.HasBackend(*requested) {
			have := make([]string, 0, len(m.Backends))
			for _, b := range m.Backends {
				have = append(have, string(b))
			}
			sort.Strings(have)
			return "", fmt.Errorf("model %q has no %s backend (it has: %s): %w",
				m.Key, *requested, strings.Join(have, ", "), model.ErrUnsupportedCapability)
		}
		return *requested, nil
	}
	for _, b := range preference {
		if m.HasBackend(b) {
			return b, nil
		}
	}
	return "", fmt.Errorf("model %q declares no backend this library can dispatch to: %w", m.Key, model.ErrUnsupportedCapability)
}

// ResolveBackend returns the ONE backend an op with this optional requested
// backend would run on, WITHOUT performing it -- mirroring Python's
// SyncSwitch.resolve_backend (D-REC A.3/A.10.4): public so a caller can ask
// "what would this op talk to?" for diagnostics or tests. requested is
// 0-or-1 values, Go's stand-in for Python's `Backend | None`; callers pass
// at most one.
//
// Resolution order matches every dispatch call exactly: the given requested
// backend, else this Switch's pinned default (see WithBackend), else the
// first backend in backendPreference the model declares.
func (s *Switch) ResolveBackend(requested ...model.Backend) (model.Backend, error) {
	var effective *model.Backend
	if len(requested) > 0 {
		effective = &requested[0]
	} else {
		effective = s.backend
	}
	return resolveBackend(s.model, effective, backendPreference)
}

// cannotServe builds the error for "chosen cannot serve this operation",
// naming chosen and -- when requested is nil (the caller took this Switch's
// default rather than asking for chosen by name) -- hinting at the model's
// other backends. Mirrors Python's SyncSwitch._cannot_serve exactly
// (D-REC A.6): two message shapes, selected SOLELY by whether requested is
// nil, never by whether chosen happens to equal s.backend (A.3's trap: a
// session-level WithBackend pin, like a per-call override, makes every op
// read as "explicitly requested" -- no hint -- because requested is already
// the coalesced `override or s.backend` value BY THE TIME readVia/writeVia
// call this, never the raw per-call argument alone).
func (s *Switch) cannotServe(chosen model.Backend, requested *model.Backend, exc error) error {
	if requested == nil {
		var others []string
		for _, b := range s.model.Backends {
			if b != chosen {
				others = append(others, string(b))
			}
		}
		sort.Strings(others)
		hint := ""
		if len(others) > 0 {
			hint = fmt.Sprintf("; pass backend=Backend.<%s> to use another backend", strings.Join(others, "|"))
		}
		return fmt.Errorf("model %q: the default backend %s cannot serve this operation: %w%s",
			s.model.Key, chosen, exc, hint)
	}
	return fmt.Errorf("model %q: the requested backend %s cannot serve this operation: %w",
		s.model.Key, chosen, exc)
}

// readVia is the read-side single-backend dispatch, mirroring Python's
// SyncSwitch._read exactly (D-REC A.4's three-step shape):
//
//  1. requested (this call's override, e.g. from a ReadOption) is coalesced
//     with this Switch's pinned default (s.backend) if requested is nil --
//     this SAME coalesced value, not the raw per-call argument, is what
//     cannotServe sees below (A.3's trap).
//  2. chosen := resolveBackend(s.model, effective, backendPreference) --
//     raises directly (resolveBackend's two message shapes) if effective
//     names a backend the model lacks, or (only when effective is nil) if
//     the model declares nothing backendPreference lists at all. There is
//     NO fallback to a second backend under any circumstance.
//  3. Build/reuse (via the cache readerFor already maintains) chosen's
//     reader, run fn. If EITHER readerFor or fn returns an error wrapping
//     model.ErrUnsupportedCapability, it is re-raised via cannotServe,
//     naming chosen -- this is the ONE place the old code used to fall
//     through to the next backend; now it is a hard stop. Any OTHER error
//     (notably one wrapping model.ErrCredential) propagates completely
//     unchanged.
func (s *Switch) readVia(ctx context.Context, requested *model.Backend, fn func(BackendReader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	effective := requested
	if effective == nil {
		effective = s.backend
	}

	chosen, err := resolveBackend(s.model, effective, backendPreference)
	if err != nil {
		return err
	}

	reader, err := s.readerFor(chosen)
	if err != nil {
		if errors.Is(err, model.ErrUnsupportedCapability) {
			return s.cannotServe(chosen, effective, err)
		}
		return err
	}

	if err := fn(reader); err != nil {
		if errors.Is(err, model.ErrUnsupportedCapability) {
			return s.cannotServe(chosen, effective, err)
		}
		return err
	}
	return nil
}
