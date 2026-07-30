// backend_snmp.go: the SNMP BackendBuilder, registered into dispatch.go's
// registry from THIS file's own init(). This is the pattern every backend
// follows (see dispatch.go's RegisterBackend doc): a root-package
// (netgearswitch) shim file per backend whose init() registers a
// BackendBuilder that calls into that backend's own protocol package (here,
// snmp/) to do the real work -- necessarily in THIS package, not snmp/ or
// some external package, because a builder needs Switch's unexported fields
// (snmpClient, snmpCommunity, host, ...), which only code inside this
// package can read. Slices 05-07 will add nsdp_backend.go/http_backend.go/
// ssh_backend.go alongside this file, each following the same shape. Per
// dispatch.go's BackendBuilder contract, buildSNMPReader below performs no
// blocking I/O -- it only constructs a lazy, not-yet-connected client/reader
// (mirroring Python's transports), since it runs while readerFor holds
// s.mu. Ported from src/netgear_switch/_dispatch.py's
// build_sync_snmp_client/_require_community (the normative source; that repo
// is read-only from here). Any discrepancy between this file and the pinned
// Python source is a bug in this file. See D-FAC §1.5, §2.5, §2.11.

package netgearswitch

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

func init() {
	RegisterBackend(model.BackendSNMP, buildSNMPReader)
	RegisterWriteBackend(model.BackendSNMP, buildSNMPWriter)
}

// requireSNMPCommunity mirrors Python's _require_community: a nil
// (unconfigured) read community is rejected with an error wrapping
// model.ErrCredential naming host, exactly like Python's
// `CredentialError(f"no SNMP read community configured for {host!r}")`.
//
// Unlike the write-community/HTTP-password gates (D-FAC §1.5's asymmetric
// _require_write_community/_require_http_password, which ALSO reject an
// empty string), this read-side gate accepts "" as a configured value --
// deliberately NOT unified with the write-side gate (D-FAC trap #1).
func requireSNMPCommunity(host string, community *string) (string, error) {
	if community == nil {
		return "", fmt.Errorf("no SNMP read community configured for %q: %w", host, model.ErrCredential)
	}
	return *community, nil
}

// buildSNMPClient returns sw's injected snmp.Client as-is, or builds a
// default one via snmp.NewGoSNMPClient(sw.host, community) -- mirroring
// Python's build_sync_snmp_client(host, community). Used by BOTH the SNMP
// BackendBuilder (buildSNMPReader, below) and Switch.Identify (D-FAC §2.11),
// which deliberately reuses this exact same client-build path instead of a
// separate one, just without a Reader wrapper or reader-cache entry.
//
// An injected client bypasses the community gate entirely (mirroring
// Python: `if client is None: client = build_sync_snmp_client(...)` never
// even evaluates _require_community when a client was already given).
func buildSNMPClient(sw *Switch) (snmp.Client, error) {
	if sw.snmpClient != nil {
		return sw.snmpClient, nil
	}
	community, err := requireSNMPCommunity(sw.host, sw.snmpCommunity)
	if err != nil {
		return nil, err
	}
	return snmp.NewGoSNMPClient(sw.host, community), nil
}

// buildSNMPReader is the BackendBuilder registered for model.BackendSNMP: it
// builds (or reuses an injected) snmp.Client via buildSNMPClient, then wraps
// it in a *snmp.Reader via snmp.NewReader, which itself returns an error
// wrapping model.ErrUnsupportedCapability if sw.model has no SNMP backend --
// needing no further gate here (D-FAC §5.1). *snmp.Reader already satisfies
// the BackendReader interface verbatim, so no adapter shim is needed.
func buildSNMPReader(sw *Switch) (BackendReader, error) {
	client, err := buildSNMPClient(sw)
	if err != nil {
		return nil, err
	}
	reader, err := snmp.NewReader(client, sw.model)
	if err != nil {
		return nil, err
	}
	return reader, nil
}

// requireSNMPWriteCommunity mirrors Python's _require_write_community: a
// nil (unconfigured) OR EMPTY-STRING write community is rejected with an
// error wrapping model.ErrCredential naming host, exactly like Python's
// `CredentialError(f"no SNMP write community configured for {host!r}")`
// (`if not community:` is Python's falsy check, which is true for both None
// and "").
//
// This is DELIBERATELY a separate function from requireSNMPCommunity (the
// read-side gate, which accepts "" as configured) -- D-WR §3.4/trap #9:
// unifying the two would silently break the `snmpset -c ""` regression the
// write side must still reject.
func requireSNMPWriteCommunity(host string, community *string) (string, error) {
	if community == nil || *community == "" {
		return "", fmt.Errorf("no SNMP write community configured for %q: %w", host, model.ErrCredential)
	}
	return *community, nil
}

// buildSNMPWriteClient returns sw's injected snmp.WriteClient as-is, or
// resolves the write community (via sw.snmpWriteCommunity's lazy,
// once-only cell) and builds a default one via
// snmp.NewGoSNMPClient(sw.host, community) -- mirroring Python's
// _writer_for's SNMP branch (D-WR §3.2/§3.4). An injected write client
// bypasses community resolution entirely, exactly like the read side's
// buildSNMPClient. A resolver error (e.g. an unresolvable secret spec) or a
// requireSNMPWriteCommunity gate failure propagates uncaught -- this is
// where a CredentialError-equivalent surfaces on first write, never cached
// as resolved (D-WR §3.2 point 2, D-FAC trap #2).
func buildSNMPWriteClient(sw *Switch) (snmp.WriteClient, error) {
	if sw.snmpWriteClient != nil {
		return sw.snmpWriteClient, nil
	}
	community, err := sw.snmpWriteCommunity.resolve()
	if err != nil {
		return nil, err
	}
	requiredCommunity, err := requireSNMPWriteCommunity(sw.host, community)
	if err != nil {
		return nil, err
	}
	return snmp.NewGoSNMPClient(sw.host, requiredCommunity), nil
}

// buildSNMPWriter is the WriteBackendBuilder registered for
// model.BackendSNMP: it builds (or reuses an injected) snmp.WriteClient via
// buildSNMPWriteClient, then wraps it in a *snmp.Writer via snmp.NewWriter
// (passing sw.protectedPorts through, D-WR §2.4), which itself returns an
// error wrapping model.ErrUnsupportedCapability if sw.model has no SNMP
// backend -- needing no further gate here. *snmp.Writer already satisfies
// the BackendWriter interface verbatim, so no adapter shim is needed.
func buildSNMPWriter(sw *Switch) (BackendWriter, error) {
	client, err := buildSNMPWriteClient(sw)
	if err != nil {
		return nil, err
	}
	writer, err := snmp.NewWriter(client, sw.model, snmp.WithProtectedPorts(sw.protectedPorts...))
	if err != nil {
		return nil, err
	}
	return writer, nil
}
