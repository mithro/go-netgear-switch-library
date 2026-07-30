// backend_nsdp.go: the NSDP BackendBuilder/WriteBackendBuilder, registered
// into dispatch.go's/write_dispatch.go's registries from THIS file's own
// init() -- follows backend_snmp.go's exact shape (see that file's own doc
// comment for the pattern rationale: a root-package shim per backend, since
// only code in THIS package can reach Switch's unexported fields). Ported
// from src/netgear_switch/_dispatch.py's build_sync_nsdp_client and
// sync_api.py's NSDP branches of _reader_for/_writer_for (the normative
// source; that repo is read-only from here). Any discrepancy between this
// file and the pinned Python source is a bug in this file. See D-NSDP
// (docs/superpowers/plans/2026-07-30-slice-05-dossier-nsdp.md) §8 and
// §10.2 for the full semantics this file implements.

package netgearswitch

import (
	"context"
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

func init() {
	RegisterBackend(model.BackendNSDP, buildNSDPReader)
	RegisterWriteBackend(model.BackendNSDP, buildNSDPWriter)
}

// buildNSDPClient returns sw's injected nsdp.Client as-is, or builds a
// default one via nsdp.NewUDPClient(sw.host, nsdp.WithInterface(...)) --
// mirroring Python's build_sync_nsdp_client(host, interface). Used by the
// NSDP BackendBuilder/WriteBackendBuilder below AND Switch.NSDPDevice
// (switch.go), which deliberately bypasses the reader cache the same way
// Identify bypasses buildSNMPClient for SNMP.
//
// Unlike SNMP's separate read/write client fields, NSDP has only ONE
// injected-client field/option (sw.nsdpClient/WithNSDPClient): Python's own
// build_sync_nsdp_client always returns something implementing BOTH
// NsdpClient and NsdpWriteClient (there is no read-only NSDP transport), so
// splitting the Go field in two the way SNMP's snmpClient/snmpWriteClient
// are split would add a distinction the source never draws (D-NSDP
// §8.1/§10.2).
//
// No blocking I/O here (same contract as buildSNMPClient): nsdp.NewUDPClient
// only opens a socket lazily per Read/Write call, never at construction --
// except when WithInterface is configured, which reads the interface's MAC
// from sysfs synchronously (mirroring Python's NewUDPClient exactly; still
// not network I/O).
func buildNSDPClient(sw *Switch) (nsdp.Client, error) {
	if sw.nsdpClient != nil {
		return sw.nsdpClient, nil
	}
	var opts []nsdp.Option
	if sw.nsdpInterface != nil {
		opts = append(opts, nsdp.WithInterface(*sw.nsdpInterface))
	}
	return nsdp.NewUDPClient(sw.host, opts...)
}

// buildNSDPReader is the BackendBuilder registered for model.BackendNSDP: it
// builds (or reuses an injected) nsdp.Client via buildNSDPClient, then wraps
// it in a *nsdp.Reader via nsdp.NewReader, which itself returns an error
// wrapping model.ErrUnsupportedCapability if sw.model has no NSDP backend --
// needing no further gate here (D-NSDP §8.1). *nsdp.Reader already satisfies
// the BackendReader interface verbatim, so no adapter shim is needed.
func buildNSDPReader(sw *Switch) (BackendReader, error) {
	client, err := buildNSDPClient(sw)
	if err != nil {
		return nil, err
	}
	reader, err := nsdp.NewReader(client, sw.model)
	if err != nil {
		return nil, err
	}
	return reader, nil
}

// requireNSDPPassword mirrors Python's write-dispatch NSDP-branch gate
// (sync_api.py: `password = self._resolve_nsdp_password(); if password is
// None: raise CredentialError(...)`): a nil (unresolved/unconfigured)
// password is rejected with an error wrapping model.ErrCredential naming
// host, message byte-identical to Python's `f"no NSDP admin password
// configured for {host!r}"`.
//
// Deliberately does NOT reject an empty string the way SNMP's write-
// community gate does (requireSNMPWriteCommunity) -- Python's own guard is
// a plain `is None` check, not a falsy check, so "" is a configured (if
// useless) password here, not an unconfigured one. Unifying the two gates
// would silently diverge from the pinned source.
func requireNSDPPassword(host string, password *string) (string, error) {
	if password == nil {
		return "", fmt.Errorf("no NSDP admin password configured for %q: %w", host, model.ErrCredential)
	}
	return *password, nil
}

// buildNSDPWriteClient returns sw's injected nsdp.Client (used for both
// reads and writes, unlike SNMP -- see buildNSDPClient's doc comment) type-
// asserted to nsdp.WriteClient, or a freshly default-built one via
// buildNSDPClient, which -- when default-built -- is always a *nsdp.UDPClient
// and therefore always satisfies nsdp.WriteClient too. The type-assertion
// only matters for an injected test double that implements nsdp.Client but
// not nsdp.WriteClient, which is rejected with an error wrapping
// model.ErrUnsupportedCapability rather than a panic.
func buildNSDPWriteClient(sw *Switch) (nsdp.WriteClient, error) {
	client, err := buildNSDPClient(sw)
	if err != nil {
		return nil, err
	}
	wc, ok := client.(nsdp.WriteClient)
	if !ok {
		return nil, fmt.Errorf("nsdp client for %q does not support writes: %w", sw.host, model.ErrUnsupportedCapability)
	}
	return wc, nil
}

// buildNSDPWriter is the WriteBackendBuilder registered for
// model.BackendNSDP: it builds (or reuses an injected) nsdp.WriteClient via
// buildNSDPWriteClient, resolves sw's OWN nsdpPassword resolveOnce cell --
// INDEPENDENT of sw.httpPassword (D-NSDP §8.2 correction: Python's
// SyncSwitch keeps nsdp_password/nsdp_password_resolver as a separate
// constructor param + resolve-once cell from http_password/
// http_password_resolver; only from_config happens to feed both from the
// same cfg.http_password(env) spec via two independent closures -- see
// Switch.nsdpPassword's doc comment in switch.go) -- gates a nil resolved
// password via requireNSDPPassword, then wraps the client+password+
// protected-ports in a *nsdp.Writer (nsdp.NewWriter), itself wrapped in
// nsdpWriterAdapter to fill the two BackendWriter methods package nsdp's
// Writer doesn't define (CyclePoE/ClearPoEFault).
func buildNSDPWriter(sw *Switch) (BackendWriter, error) {
	client, err := buildNSDPWriteClient(sw)
	if err != nil {
		return nil, err
	}
	password, err := sw.nsdpPassword.resolve()
	if err != nil {
		return nil, err
	}
	requiredPassword, err := requireNSDPPassword(sw.host, password)
	if err != nil {
		return nil, err
	}
	writer, err := nsdp.NewWriter(client, sw.model, requiredPassword, nsdp.WithProtectedPorts(sw.protectedPorts...))
	if err != nil {
		return nil, err
	}
	return &nsdpWriterAdapter{Writer: writer}, nil
}

// nsdpWriterAdapter wraps *nsdp.Writer to satisfy the full 9-method
// BackendWriter interface: package nsdp's Writer implements 7 of those (all
// but CyclePoE/ClearPoEFault -- deliberately not ported, since NSDP has no
// PoE control tag at all and the timeouts parameter's package "home" is a
// slice-06 decision; see nsdp/writer.go's own doc comment). CyclePoE/
// ClearPoEFault below are constant model.ErrUnsupportedCapability stubs
// wrapping nsdp.NoPoEWriteMsg VERBATIM -- the same exported message
// constant SetPoE itself wraps (mirroring Python's NsdpWriter.cycle_poe/
// clear_poe_fault, which both raise the same _NO_POE
// UnsupportedCapabilityError set_poe does) -- rather than calling through
// to SetPoE: these are unsupported operations in their own right, not "turn
// PoE off", and a stub that never touches the embedded Writer at all makes
// that reading unambiguous at the call site.
type nsdpWriterAdapter struct {
	*nsdp.Writer
}

// CyclePoE always returns an error wrapping model.ErrUnsupportedCapability:
// NSDP has no PoE control tag. port/timeouts/force are accepted-but-unused,
// purely so this method's signature matches the shared BackendWriter
// surface (see write_dispatch.go); this is a constant stub, never a
// disguised "turn PoE off" call.
func (a *nsdpWriterAdapter) CyclePoE(_ context.Context, _ int, _ snmp.PoeCycleTimeouts, _ bool) error {
	return fmt.Errorf("%s: %w", nsdp.NoPoEWriteMsg, model.ErrUnsupportedCapability)
}

// ClearPoEFault always returns an error wrapping
// model.ErrUnsupportedCapability: NSDP has no PoE control tag. See
// CyclePoE's doc comment.
func (a *nsdpWriterAdapter) ClearPoEFault(_ context.Context, _ int, _ snmp.PoeCycleTimeouts, _ bool) error {
	return fmt.Errorf("%s: %w", nsdp.NoPoEWriteMsg, model.ErrUnsupportedCapability)
}
