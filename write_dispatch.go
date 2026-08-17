// write_dispatch.go: the write-side backend-registry seam + write dispatch,
// mirroring dispatch.go exactly (see that file's doc comment for the
// read-side rationale this file duplicates on the write side). Ported from
// src/netgear_switch/_dispatch.py and sync_api.py's SyncSwitch._write (the
// normative source; that repo is read-only from here). Any discrepancy
// between this file and the pinned Python source is a bug in this file. See
// docs/superpowers/plans/2026-07-31-slice-05b-dossier-reconciliation.md
// (D-REC) Topic A for the full semantics this file implements.

package netgearswitch

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// BackendWriter is the write-op surface dispatch calls, mirroring the union
// Python's writer-side _write spans (SnmpWriter | NsdpWriter | HttpWriter):
// every registered backend's writer must implement all twelve methods, and an
// op it cannot serve returns an error wrapping model.ErrUnsupportedCapability
// rather than a panic or a silent no-op. snmp.Writer (see snmp/writer.go,
// snmp/writer_vlan.go, snmp/writer_cycle.go) already satisfies this
// interface verbatim -- no adapter shim is needed for the SNMP backend,
// exactly like BackendReader/snmp.Reader.
//
// Every method's signature is copied verbatim from the corresponding
// snmp.Writer method: CreateVlan deliberately has no force parameter (an
// empty VLAN is never disruptive, so nothing to refuse); CyclePoE/
// ClearPoEFault take a snmp.PoeCycleTimeouts (re-exported from this package
// as PoeCycleTimeouts, see alias.go) since the poll deadlines are a per-call,
// not per-Switch, concern.
//
// SetHostname is NOT force-gated by any backend (force is accepted so every
// writer's signature stays uniform, but never checked): renaming a switch
// cannot strand it the way a mgmt-IP write can, and it is trivially
// reversible by writing the old name back, mirroring Python's
// SnmpWriter/NsdpWriter/CliWriter/HttpWriter.set_hostname exactly.
//
// SetSyslogEnabled is served over SNMP (the vendor admin-mode scalar) and
// the FASTPATH CLI (`logging syslog`/`no logging syslog`); the HTTP and NSDP
// backends refuse by name -- mirroring Python's
// SnmpWriter/CliWriter.set_syslog_enabled (served) and
// HttpWriter/NsdpWriter.set_syslog_enabled (refused) exactly. Not
// force-gated by any backend: toggling log delivery cannot strand a switch
// and is reversible by writing the old value back.
//
// AddSyslogCollector is served ONLY over the FASTPATH CLI
// (`logging host "<addr>" <ipv4|ipv6|dns> <port> <severity-word>`), mirroring
// Python CliWriter.add_syslog_collector. Every other backend refuses by
// name, wrapping model.ErrUnsupportedCapability, and every refusal is a
// MEASURED hardware finding, not an assumption: SNMP's agent answers
// inconsistentValue/commitFailed to every row-creation mechanism tried
// (SnmpWriter.add_syslog_collector); the HTTP web UI answers HTTP 200 with
// "Failed to Set 'Host Address'" and leaves the table unchanged
// (HttpWriter.add_syslog_collector); NSDP has no logging surface at all
// (NsdpWriter.add_syslog_collector). Not force-gated: refuses a duplicate
// host up front as a precondition failure rather than sending a command
// that would silently add a second row for the same address.
//
// RemoveSyslogCollector is served over the FASTPATH CLI (`logging host
// remove <index>`, a SUBCOMMAND, never a negation), SNMP (RowStatus
// destroy(6) written to the collector's OWN sparse table index -- NEVER a
// row position, re-read fresh from GetSyslog immediately before the write)
// and the HTTP web UI (M4300 dialect only: the syslog page's row-status
// cell set to "Delete"); NSDP refuses by name (no logging surface). Not
// force-gated by any backend: redirecting logs cannot strand a switch. Every
// backend refuses up front, as a precondition failure, if no collector for
// the requested host is configured, rather than sending a removal for a row
// that is not there.
type BackendWriter interface {
	SetPoE(ctx context.Context, port int, on bool, force bool) error
	SetPortEnabled(ctx context.Context, port int, enabled bool, force bool) error
	SetPortDescription(ctx context.Context, port int, description string, force bool) error
	SetPortSpeed(ctx context.Context, port int, speed model.PortSpeed, force bool) error
	SetFlowControl(ctx context.Context, port int, enabled bool, force bool) error
	SetPVID(ctx context.Context, port, vlan int, force bool) error
	SetVlanMembership(ctx context.Context, vlanID, port int, mode model.VlanMode, force bool) error
	CreateVlan(ctx context.Context, vlanID int, name string) error
	DeleteVlan(ctx context.Context, vlanID int, force bool) error
	SetMgmtIP(ctx context.Context, address, netmask, gateway string, force bool) error
	CyclePoE(ctx context.Context, port int, timeouts snmp.PoeCycleTimeouts, force bool) error
	ClearPoEFault(ctx context.Context, port int, timeouts snmp.PoeCycleTimeouts, force bool) error
	SetHostname(ctx context.Context, name string, force bool) error
	SetSyslogEnabled(ctx context.Context, enabled bool, force bool) error
	AddSyslogCollector(ctx context.Context, host string, port, severity int, force bool) error
	RemoveSyslogCollector(ctx context.Context, host string, force bool) error
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
// semantics apply verbatim. Unchanged by the D-REC Topic A rework: writeVia
// now calls this at most ONCE per op, for the single resolved backend.
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

// writeVia is the write-side single-backend dispatch, mirroring Python's
// SyncSwitch._write exactly (D-REC A.4, identical to readVia's three-step
// shape -- see dispatch.go's readVia doc comment for the full enumeration):
// the ONLY difference from readVia is that a write op returns no captured
// value (fn(writer) either succeeds or returns an error; there is no result
// to stash), so a successful op returns nil immediately rather than a
// captured value. There is NO fallback to a second backend under any
// circumstance: exactly one backend is resolved, built/reused, and run: an
// UnsupportedCapabilityError from either step raises via cannotServe naming
// that one backend.
func (s *Switch) writeVia(ctx context.Context, requested *model.Backend, fn func(BackendWriter) error) error {
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

	writer, err := s.writerFor(chosen)
	if err != nil {
		if errors.Is(err, model.ErrUnsupportedCapability) {
			return s.cannotServe(chosen, effective, err)
		}
		return err
	}

	if err := fn(writer); err != nil {
		if errors.Is(err, model.ErrUnsupportedCapability) {
			return s.cannotServe(chosen, effective, err)
		}
		return err
	}
	return nil
}
