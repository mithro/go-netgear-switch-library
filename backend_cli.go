// backend_cli.go: the FASTPATH-CLI BackendBuilder/WriteBackendBuilder,
// registered into dispatch.go's/write_dispatch.go's registries from THIS
// file's own init() -- follows backend_http.go's/backend_nsdp.go's exact
// shape (a root-package shim per backend, since only code in THIS package can
// reach Switch's unexported fields). Ported from
// src/netgear_switch/_dispatch.py's build_sync_cli_client and sync_api.py's
// CLI branches of _reader_for/_writer_for (the normative source; that repo is
// read-only from here). Any discrepancy is a bug in this file. See the
// transport+fake dossier §4 for the facade semantics this implements.
//
// CLI is served over TWO transport backends -- model.BackendSSH and
// model.BackendTelnet -- so both are registered here, each pointing at a
// builder that knows its own cliTransportKind. Session construction (the
// actual SSH/telnet dial + login + enable/disable-paging Setup, all blocking
// I/O) is DEFERRED past the BackendBuilder via lazyCLISession (mirroring
// backend_http.go's lazyHTTPSession and Python's memoized _built_cli_client):
// an op that refuses honestly without ever touching the wire must never dial
// a socket -- only an op the CLI actually ends up serving pays that cost.

package netgearswitch

import (
	"context"
	"fmt"
	"sync"

	"github.com/mithro/go-netgear-switch-library/fastpath"
	"github.com/mithro/go-netgear-switch-library/model"
)

func init() {
	RegisterBackend(model.BackendSSH, buildCLIReaderSSH)
	RegisterBackend(model.BackendTelnet, buildCLIReaderTelnet)
	RegisterWriteBackend(model.BackendSSH, buildCLIWriterSSH)
	RegisterWriteBackend(model.BackendTelnet, buildCLIWriterTelnet)
}

// cliTransportKind selects which byte transport a CLI session dials. A Switch
// caches at most one built session per kind (see Switch.cliSessionCache) so
// an SSH read and a telnet write on the same Switch never share the wrong
// shell.
type cliTransportKind int

const (
	cliTransportSSH cliTransportKind = iota
	cliTransportTelnet
)

func (k cliTransportKind) String() string {
	if k == cliTransportTelnet {
		return "telnet"
	}
	return "ssh"
}

func buildCLIReaderSSH(sw *Switch) (BackendReader, error) {
	return buildCLIReader(sw, cliTransportSSH)
}

func buildCLIReaderTelnet(sw *Switch) (BackendReader, error) {
	return buildCLIReader(sw, cliTransportTelnet)
}

func buildCLIWriterSSH(sw *Switch) (BackendWriter, error) {
	return buildCLIWriter(sw, cliTransportSSH)
}

func buildCLIWriterTelnet(sw *Switch) (BackendWriter, error) {
	return buildCLIWriter(sw, cliTransportTelnet)
}

// buildCLIReader is the BackendBuilder body for both CLI transports: it takes
// sw's shared (lazily-built) CLI session for kind, then wraps it in a
// *fastpath.Reader via fastpath.NewReader -- which itself returns an error
// wrapping model.ErrUnsupportedCapability if sw.model has no CLI command spec
// (fastpath.CLISpec), needing no further gate here. *fastpath.Reader already
// satisfies BackendReader verbatim (its Get* method set/signatures match the
// merged SNMP/HTTP readers), so no adapter shim is needed on the read side.
func buildCLIReader(sw *Switch, kind cliTransportKind) (BackendReader, error) {
	session, err := sw.cliSession(kind)
	if err != nil {
		return nil, err
	}
	return fastpath.NewReader(session, sw.model)
}

// buildCLIWriter is the WriteBackendBuilder body for both CLI transports:
// wraps sw's shared CLI session in a *fastpath.Writer (passing
// sw.protectedPorts through), then wraps THAT in cliWriterAdapter to bridge
// the VLAN/Vlan method-name casing difference between package fastpath's
// Writer (CreateVLAN/DeleteVLAN/SetVLANMembership, matching its own
// Reader.GetVLANs) and the shared BackendWriter interface (CreateVlan/
// DeleteVlan/SetVlanMembership). Every other write method (SetPVID/SetPoE/
// SetPortEnabled/SetMgmtIP/CyclePoE/ClearPoEFault) already matches
// BackendWriter's name+signature and is promoted from the embedded Writer.
func buildCLIWriter(sw *Switch, kind cliTransportKind) (BackendWriter, error) {
	session, err := sw.cliSession(kind)
	if err != nil {
		return nil, err
	}
	writer, err := fastpath.NewWriter(session, sw.model, fastpath.WithProtectedPorts(sw.protectedPorts...))
	if err != nil {
		return nil, err
	}
	return &cliWriterAdapter{Writer: writer}, nil
}

// requireCLIPassword rejects a nil (unresolved/unconfigured) CLI login
// password with an error wrapping model.ErrCredential naming host -- a plain
// nil check like the NSDP gate (requireNSDPPassword), NOT the falsy check the
// HTTP/SNMP-community gates use: an empty string is a configured (if useless)
// CLI password here, not an unconfigured one.
func requireCLIPassword(host string, password *string) (string, error) {
	if password == nil {
		return "", fmt.Errorf("no CLI password configured for %q: %w", host, model.ErrCredential)
	}
	return *password, nil
}

// cliSession returns sw's injected fastpath.Session as-is (WithCLIClient), or
// the SAME lazily-built default lazyCLISession for kind that every later call
// with the same kind returns -- cached on sw.cliSessionCache[kind] so the
// reader and the writer for a given transport share ONE interactive shell
// (one password resolution, one login), mirroring Python's memoized
// _built_cli_client. The returned session defers its own first build (the
// SSH/telnet dial + login + Setup, all blocking I/O) until its first actual
// Run/RunSCPCopy/RunWriteMemory call -- see lazyCLISession's doc comment.
func (s *Switch) cliSession(kind cliTransportKind) (fastpath.Session, error) {
	if s.cliClient != nil {
		return s.cliClient, nil
	}
	s.cliSessionMu.Lock()
	defer s.cliSessionMu.Unlock()
	if s.cliSessionCache == nil {
		s.cliSessionCache = make(map[cliTransportKind]*lazyCLISession)
	}
	if cached, ok := s.cliSessionCache[kind]; ok {
		return cached, nil
	}
	lazy := newLazyCLISession(func(ctx context.Context) (fastpath.Session, error) {
		return buildDefaultCLISession(ctx, s, kind)
	})
	s.cliSessionCache[kind] = lazy
	return lazy, nil
}

// buildDefaultCLISession resolves sw's OWN cliPassword cell, dials the
// kind-appropriate byte transport (SSH on sw.sshPort or 22; telnet on
// sw.telnetPort or the model's CliModelSpec.TelnetPort), wraps it in a
// fastpath.ShellDriver, and runs Setup (enable + disable paging) -- returning
// a ready fastpath.Session. Mirrors Python's build_sync_cli_client up through
// the transport's connect()+ShellDriver Setup. Called ONLY from
// lazyCLISession's deferred build closure (never eagerly from a
// BackendBuilder), so its blocking dial/login/Setup I/O never fires for an op
// the CLI does not actually serve. On any post-dial failure the transport is
// closed so a half-open socket never leaks.
func buildDefaultCLISession(ctx context.Context, sw *Switch, kind cliTransportKind) (fastpath.Session, error) {
	spec, err := fastpath.CLISpec(sw.model)
	if err != nil {
		return nil, err
	}
	password, err := sw.cliPassword.resolve()
	if err != nil {
		return nil, err
	}
	required, err := requireCLIPassword(sw.host, password)
	if err != nil {
		return nil, err
	}

	var transport fastpath.Transport
	switch kind {
	case cliTransportSSH:
		port := 22
		if sw.sshPort != nil {
			port = *sw.sshPort
		}
		transport, err = fastpath.NewSSHTransport(fastpath.SSHConfig{
			Host:     sw.host,
			Port:     port,
			Username: sw.cliUsername,
			Password: required,
		})
	case cliTransportTelnet:
		port := spec.TelnetPort
		if sw.telnetPort != nil {
			port = *sw.telnetPort
		}
		transport, err = fastpath.NewTelnetTransport(fastpath.TelnetConfig{
			Host:     sw.host,
			Port:     port,
			Username: sw.cliUsername,
			Password: required,
		})
	default:
		return nil, fmt.Errorf("unknown CLI transport kind %d", int(kind))
	}
	if err != nil {
		return nil, err
	}

	driver := fastpath.NewShellDriver(transport, fastpath.ShellDriverConfig{
		EnableCmd:    spec.EnableCmd,
		PagingOffCmd: spec.PagingOffCmd,
	})
	if err := driver.Setup(ctx); err != nil {
		_ = transport.Close()
		return nil, err
	}
	return driver, nil
}

// cliWriterAdapter wraps *fastpath.Writer to satisfy BackendWriter: it adds
// the three VLAN-op methods whose BackendWriter spelling differs from
// fastpath's own (Create/Delete/SetVlanMembership vs Create/Delete/
// SetVLANMembership), delegating each to the embedded Writer. All six other
// BackendWriter methods (SetPVID/SetPoE/SetPortEnabled/SetMgmtIP/CyclePoE/
// ClearPoEFault) already match name+signature -- CyclePoE/ClearPoEFault
// because fastpath.PoeCycleTimeouts is a type alias for snmp.PoeCycleTimeouts
// (fastpath/writer.go) -- and are promoted verbatim from the embedded Writer.
type cliWriterAdapter struct {
	*fastpath.Writer
}

var _ BackendWriter = (*cliWriterAdapter)(nil)

// CreateVlan delegates to the embedded Writer's CreateVLAN (name-casing
// bridge only).
func (a *cliWriterAdapter) CreateVlan(ctx context.Context, vlanID int, name string) error {
	return a.CreateVLAN(ctx, vlanID, name)
}

// DeleteVlan delegates to the embedded Writer's DeleteVLAN.
func (a *cliWriterAdapter) DeleteVlan(ctx context.Context, vlanID int, force bool) error {
	return a.DeleteVLAN(ctx, vlanID, force)
}

// SetVlanMembership delegates to the embedded Writer's SetVLANMembership.
func (a *cliWriterAdapter) SetVlanMembership(ctx context.Context, vlanID, port int, mode model.VlanMode, force bool) error {
	return a.SetVLANMembership(ctx, vlanID, port, mode, force)
}

// lazyCLISession defers fastpath.Session construction -- the SSH/telnet dial,
// login, and enable/disable-paging Setup, plus this Switch's own cliPassword
// resolution -- until the FIRST actual Run/RunSCPCopy/RunWriteMemory call,
// mirroring backend_http.go's lazyHTTPSession. A successful build is cached;
// a FAILED build is NOT cached, so the next call retries the resolver+dial
// from scratch (mirroring resolveOnce's "an error is never marked resolved").
// The build closure receives the caller's ctx so the Setup handshake honors
// it. Unlike lazyHTTPSession, Close is load-bearing: a CLI session is a live
// socket, and Switch.Close closes every built one (Python's SyncSwitch.close
// forgets to -- a real leak this port refuses to reproduce).
type lazyCLISession struct {
	mu      sync.Mutex
	build   func(ctx context.Context) (fastpath.Session, error)
	session fastpath.Session
}

func newLazyCLISession(build func(ctx context.Context) (fastpath.Session, error)) *lazyCLISession {
	return &lazyCLISession{build: build}
}

// resolve returns the cached session, or builds one now (with ctx), caching a
// successful result only.
func (l *lazyCLISession) resolve(ctx context.Context) (fastpath.Session, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session != nil {
		return l.session, nil
	}
	s, err := l.build(ctx)
	if err != nil {
		return nil, err
	}
	l.session = s
	return s, nil
}

// builtSession returns the already-built session, if any, WITHOUT triggering
// a build -- used only by Switch.Close to release a live shell, never to
// force one into existence just to close it.
func (l *lazyCLISession) builtSession() fastpath.Session {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.session
}

var _ fastpath.Session = (*lazyCLISession)(nil)

// Run builds (on first use) then delegates.
func (l *lazyCLISession) Run(ctx context.Context, command string) (string, error) {
	s, err := l.resolve(ctx)
	if err != nil {
		return "", err
	}
	return s.Run(ctx, command)
}

// RunSCPCopy builds (on first use) then delegates.
func (l *lazyCLISession) RunSCPCopy(ctx context.Context, command, scpPassword string) (string, error) {
	s, err := l.resolve(ctx)
	if err != nil {
		return "", err
	}
	return s.RunSCPCopy(ctx, command, scpPassword)
}

// RunWriteMemory builds (on first use) then delegates.
func (l *lazyCLISession) RunWriteMemory(ctx context.Context, command string, prestuff bool) (string, error) {
	s, err := l.resolve(ctx)
	if err != nil {
		return "", err
	}
	return s.RunWriteMemory(ctx, command, prestuff)
}

// Close closes the built session if one exists (idempotent). Never builds.
func (l *lazyCLISession) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session == nil {
		return nil
	}
	err := l.session.Close()
	l.session = nil
	return err
}
