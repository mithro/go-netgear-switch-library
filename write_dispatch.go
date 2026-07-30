// write_dispatch.go: the write-side backend-registry seam + write dispatch
// loop, mirroring dispatch.go exactly (see that file's doc comment for the
// read-side rationale this file duplicates on the write side). Ported from
// src/netgear_switch/_dispatch.py and sync_api.py's SyncSwitch._write (the
// normative source; that repo is read-only from here). Any discrepancy
// between this file and the pinned Python source is a bug in this file. See
// docs/superpowers/plans/2026-07-30-slice-04-dossier-snmp-write.md (D-WR)
// §3.1-§3.2 for the full semantics this file implements.

package netgearswitch

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// BackendWriter is the write-op surface the dispatch loop calls, mirroring
// the union Python's writer-side _write spans (SnmpWriter | NsdpWriter |
// HttpWriter): every registered backend's writer must implement all nine
// methods, and an op it cannot serve returns an error wrapping
// model.ErrUnsupportedCapability rather than a panic or a silent no-op.
// snmp.Writer (see snmp/writer.go, snmp/writer_vlan.go, snmp/writer_cycle.go)
// already satisfies this interface verbatim -- no adapter shim is needed for
// the SNMP backend, exactly like BackendReader/snmp.Reader.
//
// Every method's signature is copied verbatim from the corresponding
// snmp.Writer method (D-WR §2.5-§2.13): CreateVlan deliberately has no force
// parameter (an empty VLAN is never disruptive, so nothing to refuse);
// CyclePoE/ClearPoEFault take a snmp.PoeCycleTimeouts (re-exported from this
// package as PoeCycleTimeouts, see alias.go) since the poll deadlines are a
// per-call, not per-Switch, concern.
type BackendWriter interface {
	SetPoE(ctx context.Context, port int, on bool, force bool) error
	SetPortEnabled(ctx context.Context, port int, enabled bool, force bool) error
	SetPVID(ctx context.Context, port, vlan int, force bool) error
	SetVlanMembership(ctx context.Context, vlanID, port int, mode model.VlanMode, force bool) error
	CreateVlan(ctx context.Context, vlanID int, name string) error
	DeleteVlan(ctx context.Context, vlanID int, force bool) error
	SetMgmtIP(ctx context.Context, address, netmask, gateway string, force bool) error
	CyclePoE(ctx context.Context, port int, timeouts snmp.PoeCycleTimeouts, force bool) error
	ClearPoEFault(ctx context.Context, port int, timeouts snmp.PoeCycleTimeouts, force bool) error
}

// WriteBackendBuilder constructs the BackendWriter for one backend, given
// the Switch requesting it -- the write-side twin of BackendBuilder. Same
// no-blocking-I/O contract applies (see BackendBuilder's doc comment in
// dispatch.go): writerFor calls this while holding s.mu.
type WriteBackendBuilder func(sw *Switch) (BackendWriter, error)

// writerRegistryMu guards writerRegistry, mirroring backendRegistryMu.
var (
	writerRegistryMu sync.RWMutex
	writerRegistry   = map[model.Backend]WriteBackendBuilder{}
)

// RegisterWriteBackend installs build as the writer constructor for backend
// b, overwriting any builder previously registered for the same backend --
// the write-side twin of RegisterBackend. See backend_snmp.go for the
// registration pattern (a root-package shim file per backend, whose init()
// calls this).
func RegisterWriteBackend(b model.Backend, build WriteBackendBuilder) {
	writerRegistryMu.Lock()
	defer writerRegistryMu.Unlock()
	writerRegistry[b] = build
}

// lookupWriteBackendBuilder returns the builder registered for b, if any.
func lookupWriteBackendBuilder(b model.Backend) (WriteBackendBuilder, bool) {
	writerRegistryMu.RLock()
	defer writerRegistryMu.RUnlock()
	build, ok := writerRegistry[b]
	return build, ok
}

// writerFor returns the cached BackendWriter for backend, building (and
// caching) it via the registered WriteBackendBuilder on first use -- the
// write-side twin of readerFor; same caching/gate-failure-never-cached
// semantics apply verbatim.
func (s *Switch) writerFor(backend model.Backend) (BackendWriter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if w, ok := s.writerCache[backend]; ok {
		return w, nil
	}

	build, ok := lookupWriteBackendBuilder(backend)
	if !ok {
		return nil, fmt.Errorf("model %q has no %s backend implementation yet: %w", s.model.Key, backend, model.ErrUnsupportedCapability)
	}
	w, err := build(s)
	if err != nil {
		return nil, err
	}
	s.writerCache[backend] = w
	return w, nil
}

// writeVia is the write-side dispatch loop, mirroring Python's
// SyncSwitch._write exactly (D-WR §3.1's six ordering rules, identical to
// readVia's -- see dispatch.go's readVia doc comment for the full
// enumeration): the ONLY difference from readVia is that a write op returns
// no captured value (fn(writer) either succeeds or returns an error; there
// is no result to stash), so a successful op returns nil immediately rather
// than a captured value.
func (s *Switch) writeVia(ctx context.Context, op string, fn func(BackendWriter) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var last error
	for _, backend := range backendPreference {
		if !s.model.HasBackend(backend) {
			continue
		}

		writer, err := s.writerFor(backend)
		if err != nil {
			if errors.Is(err, model.ErrUnsupportedCapability) {
				last = err
				continue
			}
			return err
		}

		if err := fn(writer); err != nil {
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
