package virtual

// server.go ports src/netgear_switch/virtual/server.py's VirtualSwitch (the
// normative source; that repo is read-only from here -- pin 1aa1274, branch
// fix/s3300-52x-live-verify). Any discrepancy between this file and the
// Python source is a bug here. See D-VIRT §5 and D-NSDP §7.4 for the full
// porting dossier this mirrors.
//
// VirtualSwitch is a mock switch server: a seeded State plus whichever
// protocol faces the model's registry entry supports, bound on Start. This
// package implements the SNMP face (snmpface.go), the NSDP face
// (nsdpface.go, slice 05), the HTTP face (httpface.go, slice 06), and, as of
// slice 07 Task 12, real loopback SSH/Telnet CLI faces (sshface.go,
// telnetface.go) wrapping Task 11's in-process CliFace dispatcher.
//
// Matches the Python reference exactly (D-HTTP-F §6.1): VirtualSwitch.
// start() independently binds each backend the model supports, so a
// {NSDP, HTTP} model ends up with BOTH its NSDP face (NsdpPort) and its
// HTTP face (HTTPPort) live at once. This Go port keeps SnmpPort/NsdpPort/
// HTTPPort as separate fields (see NsdpPort's own doc comment), so Start's
// "at least one face bound" check is "does this model have BackendSNMP,
// BackendNSDP or BackendHTTP" as of this slice; the moment slice 07 lands,
// Start's body gains the same independent per-backend `if` blocks for SSH/
// Telnet, and the "no face bindable" branch becomes reachable only for a
// model with none of the five backends -- see the per-field TODOs below for
// exactly which slice wires which remaining field.

import (
	"context"
	"fmt"
	"sync"

	"github.com/mithro/go-netgear-switch-library/fastpath"
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// VirtualSwitch is a mock switch server: a seeded State plus its bound
// protocol faces. Construct with NewVirtualSwitch; call Start to bind
// whichever protocol faces this slice implements and the model supports,
// Stop to tear them down (idempotent; safe to call before Start or more than
// once).
type VirtualSwitch struct { //nolint:revive // name is mandated by D-VIRT §5/Task 13's brief, mirroring the Python reference's VirtualSwitch class exactly; renaming to "Switch" would break that intentional parity.
	// State is this switch's in-memory device state (D-VIRT §1), seeded (or
	// left blank-but-valid) for the model NewVirtualSwitch was constructed
	// with.
	State *State

	// Host is the loopback address every bound face listens on (default
	// "127.0.0.1"; override with WithHost).
	Host string

	// SnmpPort is the bound SNMP face's UDP port once Start has bound it (0
	// otherwise). Deliberately a field distinct from every other backend's
	// port below -- unlike the Python reference, which reuses self.port for
	// BOTH the SNMP and NSDP faces (they're never both live at once on any
	// real registered model, but sharing one field is still a latent trap
	// D-VIRT §5 calls out explicitly). See D-VIRT §8.2.
	SnmpPort int

	// NsdpPort is the bound NSDP face's UDP port once Start has bound it (0
	// otherwise; 0 before Start, or on a model with no BackendNSDP). See
	// SnmpPort's own doc comment for why this is a field distinct from
	// every other backend's port.
	NsdpPort int
	// HTTPPort is the bound HTTP face's TCP port once Start has bound it (0
	// otherwise; 0 before Start, or on a model with no BackendHTTP). See
	// SnmpPort's own doc comment for why this is a field distinct from
	// every other backend's port -- confirmed by D-HTTP-F §6.1 to match the
	// Python reference's independent self.http_port field exactly (a
	// {NSDP, HTTP} model such as gs305ep/gs110emx/gs105pe binds BOTH its
	// NSDP face (NsdpPort) and its HTTP face (HTTPPort) CONCURRENTLY).
	HTTPPort int
	// SSHPort is the bound SSH CLI face's TCP port once Start has bound it
	// (0 otherwise; 0 before Start, or on a model with no BackendSSH). See
	// SnmpPort's own doc comment for why this is a field distinct from
	// every other backend's port.
	SSHPort int
	// TelnetPort is the bound Telnet CLI face's TCP port once Start has
	// bound it (0 otherwise; 0 before Start, or on a model with no
	// BackendTelnet). See SnmpPort's own doc comment for why this is a
	// field distinct from every other backend's port.
	TelnetPort int

	modelKey     string
	modelInfo    *model.SwitchModel
	community    string
	httpPassword string
	cliUsername  string
	cliPassword  string
	// requestedPort/requestedHTTPPort are the caller-pinned ports Start
	// applies to whichever UDP face (SNMP or NSDP -- never both; no
	// registered model has both backends, see model/registry.go) and the
	// HTTP face bind, respectively. 0 (the default) asks the OS for an
	// ephemeral port, exactly like before WithPort/WithHTTPPort existed.
	// Mirrors the Python reference's VirtualSwitch(port=..., http_port=...)
	// constructor arguments (server.py), including its single shared "port"
	// field covering both SNMP and NSDP.
	requestedPort     int
	requestedHTTPPort int

	mu         sync.Mutex
	snmpFace   *SnmpFace
	nsdpFace   *NsdpFace
	httpFace   *HTTPFace
	sshFace    *SSHFace
	telnetFace *TelnetFace
}

// Option configures a VirtualSwitch at construction time.
type Option func(*VirtualSwitch)

// WithCommunity overrides the SNMP community string every bound face
// requires (default "public").
func WithCommunity(community string) Option {
	return func(v *VirtualSwitch) { v.community = community }
}

// WithHost overrides the loopback address every bound face listens on
// (default "127.0.0.1").
func WithHost(host string) Option {
	return func(v *VirtualSwitch) { v.Host = host }
}

// WithHTTPPassword overrides the HTTP admin password the bound HTTP face
// requires (default "password", mirroring Python VirtualSwitch's own
// http_password="password" constructor default).
func WithHTTPPassword(password string) Option {
	return func(v *VirtualSwitch) { v.httpPassword = password }
}

// WithCLIUsername overrides the username the bound SSH/Telnet CLI faces
// require (default "admin", mirroring the dossier's own note that "the
// default CLI username is hardcoded 'admin'" -- transport dossier §7.6).
func WithCLIUsername(username string) Option {
	return func(v *VirtualSwitch) { v.cliUsername = username }
}

// WithCLIPassword overrides the password the bound SSH/Telnet CLI faces
// require (default "password", matching WithHTTPPassword's own default).
func WithCLIPassword(password string) Option {
	return func(v *VirtualSwitch) { v.cliPassword = password }
}

// WithPort pins the UDP port Start binds its SNMP-or-NSDP face to (default
// 0, an ephemeral port). Mirrors the Python reference's
// VirtualSwitch(port=...) constructor argument. Applies to whichever of
// SnmpPort/NsdpPort the model actually binds -- no registered model has
// both backends, so, like the Python reference's single shared self.port,
// there is never an ambiguity about which one this pins.
func WithPort(port int) Option {
	return func(v *VirtualSwitch) { v.requestedPort = port }
}

// WithHTTPPort pins the TCP port Start binds its HTTP face to (default 0,
// an ephemeral port). Mirrors the Python reference's
// VirtualSwitch(http_port=...) constructor argument.
func WithHTTPPort(port int) Option {
	return func(v *VirtualSwitch) { v.requestedHTTPPort = port }
}

// NewVirtualSwitch builds a VirtualSwitch for modelKey: resolves modelKey
// against the model registry FIRST (an unknown key returns an error
// wrapping model.ErrUnknownModel immediately, before any state is built or
// option is applied), then seeds (or, for a model with no hand-authored
// seed, default-blanks) its State via BuildState. Call Start to bind
// protocol faces.
func NewVirtualSwitch(modelKey string, opts ...Option) (*VirtualSwitch, error) {
	m, err := model.GetModel(modelKey) // wraps model.ErrUnknownModel on a miss
	if err != nil {
		return nil, err
	}
	v := &VirtualSwitch{
		State:        BuildState(modelKey),
		Host:         "127.0.0.1",
		community:    "public",
		httpPassword: "password",
		cliUsername:  "admin",
		cliPassword:  "password",
		modelKey:     modelKey,
		modelInfo:    m,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// Start binds every protocol face this package implements that the model
// supports: SNMP (bound iff the model's registry entry has
// model.BackendSNMP), NSDP (bound iff it has model.BackendNSDP, slice 05),
// HTTP (bound iff it has model.BackendHTTP, slice 06), and, as of slice 07
// Task 12, SSH (bound iff it has model.BackendSSH) and Telnet (bound iff it
// has model.BackendTelnet) -- each an independent `if` block, exactly
// mirroring the Python reference's start(). A Plus-class model such as
// gs110emx/gs305ep/gs105pe (registry backends {NSDP, HTTP}) binds BOTH its
// NSDP face (NsdpPort) AND its HTTP face (HTTPPort) CONCURRENTLY
// (D-HTTP-F §6.1), exactly like a managed model (SNMP, HTTP, SSH, Telnet)
// binds all four of its own ports at once. A model with no face at all
// (none of BackendSNMP/BackendNSDP/BackendHTTP/BackendSSH/BackendTelnet)
// returns an error wrapping model.ErrUnsupportedCapability.
//
// SELF-CLEANING ON A PARTIAL FAILURE: a later face's bind can fail after an
// earlier one already succeeded (most reachably via cmd/gngsw-virtual's
// --port/--http-port pinning a face onto an address that's already taken).
// Every error path below therefore routes through fail, which calls this
// same switch's own Stop() -- idempotent, and already tears down exactly
// whichever faces are non-nil -- BEFORE returning the error, so a caller
// never has to distinguish "Start failed, nothing to clean up" from "Start
// failed after partially succeeding, something is still bound"; either way
// every socket and goroutine Start opened before the failure is already
// closed by the time it returns.
func (v *VirtualSwitch) Start() error {
	v.mu.Lock()

	// fail unlocks v.mu (Stop() below re-locks it itself -- sync.Mutex is
	// not re-entrant, so Start cannot call Stop while still holding the
	// lock it took at the top of this function) and stops whatever this
	// call has bound so far, then returns the wrapped error. Every error
	// return in this function goes through fail instead of a bare
	// `return fmt.Errorf(...)`, specifically so a spec-lookup failure
	// (webui.HTTPSpec/fastpath.CLISpec, which happens before that face's
	// own Start is even attempted) unwinds any EARLIER face that already
	// bound successfully, not just a later face's own bind failure.
	fail := func(err error) error {
		v.mu.Unlock()
		_ = v.Stop()
		return fmt.Errorf("virtual: VirtualSwitch.Start: %w", err)
	}

	if v.modelInfo.HasBackend(model.BackendSNMP) {
		view := NewMibView(v.State)
		face := NewSnmpFace(view, v.community, v.Host)
		face.SetPort(v.requestedPort)
		port, err := face.Start()
		if err != nil {
			return fail(err)
		}
		v.SnmpPort = port
		v.snmpFace = face
	}

	if v.modelInfo.HasBackend(model.BackendNSDP) {
		face := NewNsdpFace(v.State, v.Host)
		face.SetPort(v.requestedPort)
		port, err := face.Start()
		if err != nil {
			return fail(err)
		}
		v.NsdpPort = port
		v.nsdpFace = face
	}

	if v.modelInfo.HasBackend(model.BackendHTTP) {
		spec, err := webui.HTTPSpec(v.modelInfo)
		if err != nil {
			return fail(err)
		}
		face := NewHTTPFace(v.State, spec, v.httpPassword, v.Host)
		face.SetPort(v.requestedHTTPPort)
		port, err := face.Start()
		if err != nil {
			return fail(err)
		}
		v.HTTPPort = port
		v.httpFace = face
	}

	if v.modelInfo.HasBackend(model.BackendSSH) {
		spec, err := fastpath.CLISpec(v.modelInfo)
		if err != nil {
			return fail(err)
		}
		face := NewSSHFace(v.State, spec, v.cliUsername, v.cliPassword, v.Host)
		port, err := face.Start()
		if err != nil {
			return fail(err)
		}
		v.SSHPort = port
		v.sshFace = face
	}

	if v.modelInfo.HasBackend(model.BackendTelnet) {
		spec, err := fastpath.CLISpec(v.modelInfo)
		if err != nil {
			return fail(err)
		}
		face := NewTelnetFace(v.State, spec, v.cliUsername, v.cliPassword, v.Host)
		port, err := face.Start()
		if err != nil {
			return fail(err)
		}
		v.TelnetPort = port
		v.telnetFace = face
	}

	if v.snmpFace == nil && v.nsdpFace == nil && v.httpFace == nil && v.sshFace == nil && v.telnetFace == nil {
		v.mu.Unlock()
		return fmt.Errorf("model %q has no protocol face this package can bind (no SNMP/NSDP/HTTP/SSH/Telnet backend): %w",
			v.modelKey, model.ErrUnsupportedCapability)
	}
	v.mu.Unlock()
	return nil
}

// Stop stops every bound face. Idempotent: safe to call if Start failed,
// was never called, or Stop was already called. Stops the SNMP face first,
// then NSDP, then HTTP, then SSH, then Telnet, regardless of whether an
// earlier stop errored, so a failure stopping one face never leaks the
// others; only the first error (if any) is returned.
func (v *VirtualSwitch) Stop() error {
	v.mu.Lock()
	snmpFace := v.snmpFace
	v.snmpFace = nil
	v.SnmpPort = 0
	nsdpFace := v.nsdpFace
	v.nsdpFace = nil
	v.NsdpPort = 0
	httpFace := v.httpFace
	v.httpFace = nil
	v.HTTPPort = 0
	sshFace := v.sshFace
	v.sshFace = nil
	v.SSHPort = 0
	telnetFace := v.telnetFace
	v.telnetFace = nil
	v.TelnetPort = 0
	v.mu.Unlock()

	var firstErr error
	if snmpFace != nil {
		if err := snmpFace.Stop(); err != nil {
			firstErr = fmt.Errorf("virtual: VirtualSwitch.Stop: %w", err)
		}
	}
	if nsdpFace != nil {
		if err := nsdpFace.Stop(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("virtual: VirtualSwitch.Stop: %w", err)
		}
	}
	if httpFace != nil {
		if err := httpFace.Stop(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("virtual: VirtualSwitch.Stop: %w", err)
		}
	}
	if sshFace != nil {
		if err := sshFace.Stop(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("virtual: VirtualSwitch.Stop: %w", err)
		}
	}
	if telnetFace != nil {
		if err := telnetFace.Stop(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("virtual: VirtualSwitch.Stop: %w", err)
		}
	}
	return firstErr
}

// CliSession returns an in-process fastpath.Session (CliFace) bound to
// this switch's State, mirroring Python VirtualSwitch.cli_session():
// "Unlike the SNMP/NSDP/HTTP faces (real sockets bound in start()), the
// CLI face is an in-process CliSession needing no socket" (server.py:
// 130-140) -- so, unlike SnmpPort/NsdpPort/HTTPPort/SSHPort/TelnetPort,
// this needs no Start call at all; it is available immediately after
// NewVirtualSwitch. Errors exactly like fastpath.NewReader/NewWriter would
// for a model with no CLI backend or no registered fastpath.CliModelSpec
// (fastpath.CLISpec's own two-stage guard). The real SSH/Telnet listeners
// bound during Start (SSHPort/TelnetPort, sshface.go/telnetface.go, Task
// 12) each construct their OWN fresh *CliFace per connection the same way
// this accessor does -- this one remains the unit-test-path seam
// cliface_test.go drives the real fastpath.Reader/Writer against, with no
// socket in the way at all.
func (v *VirtualSwitch) CliSession() (fastpath.Session, error) {
	spec, err := fastpath.CLISpec(v.modelInfo)
	if err != nil {
		return nil, err
	}
	return NewCliFace(v.State, spec), nil
}

// --- EndpointProvider: conformance-harness seam (D-VIRT §5, slice 10) -----

// Endpoints is the set of listening endpoints a started VirtualSwitch
// exposes, for a caller (e.g. a cross-language conformance-harness client,
// slice 10) that wants only connection details, not this package's
// concrete VirtualSwitch type. NsdpPort mirrors VirtualSwitch.NsdpPort;
// HTTPPort/HTTPPassword mirror VirtualSwitch.HTTPPort/httpPassword now that
// the HTTP face has landed (this slice); later slices add SSHPort/
// TelnetPort the same way, mirroring VirtualSwitch's own reserved fields.
type Endpoints struct {
	Host         string
	SnmpPort     int
	NsdpPort     int
	Community    string
	HTTPPort     int
	HTTPPassword string
}

// EndpointProvider is the conformance-harness seam a cross-language test
// suite (slice 10) drives against: start a named model's virtual switch and
// get back the endpoints to connect a client to, without needing to import
// this package's concrete VirtualSwitch type at all.
type EndpointProvider interface {
	// StartModel starts a virtual switch for modelKey and returns its
	// endpoints. The switch this call started keeps running until ctx is
	// done (see GoFakeProvider's doc comment for this Go implementation's
	// exact cancellation contract) or the provider's CloseAll is called.
	StartModel(ctx context.Context, modelKey string) (Endpoints, error)
}

// GoFakeProvider is the Go EndpointProvider implementation backing this
// package's VirtualSwitch: each StartModel call starts one VirtualSwitch and
// tracks it so CloseAll can stop every switch this provider has ever
// started. Ownership is intentionally minimal for this slice: there is no
// per-endpoint stop handle in the EndpointProvider interface itself (a
// cross-language harness client has no Go object to hold one on), so a
// started switch's teardown path is exactly one of: its ctx being
// cancelled/timing out, or an explicit CloseAll -- watched on a dedicated
// per-switch goroutine that exits on whichever comes first (never leaked
// waiting on a ctx, e.g. context.Background(), that's never cancelled: see
// trackedSwitch.stopCh). The zero value is ready to use.
type GoFakeProvider struct {
	mu       sync.Mutex
	switches []*trackedSwitch
}

// trackedSwitch pairs a started VirtualSwitch with the channel CloseAll
// closes to wake its watcher goroutine even when ctx is never cancelled.
type trackedSwitch struct {
	sw     *VirtualSwitch
	stopCh chan struct{}
}

// StartModel implements EndpointProvider: builds and starts a VirtualSwitch
// for modelKey (propagating NewVirtualSwitch/Start's errors, e.g.
// model.ErrUnknownModel or model.ErrUnsupportedCapability, unwrapped), then
// spawns a goroutine that stops it once EITHER ctx is done OR CloseAll runs
// -- whichever happens first -- so a caller that only ever calls CloseAll
// (never cancelling ctx, e.g. context.Background()) doesn't leak that
// goroutine forever.
func (p *GoFakeProvider) StartModel(ctx context.Context, modelKey string) (Endpoints, error) {
	sw, err := NewVirtualSwitch(modelKey)
	if err != nil {
		return Endpoints{}, err
	}
	if err := sw.Start(); err != nil {
		return Endpoints{}, err
	}

	tracked := &trackedSwitch{sw: sw, stopCh: make(chan struct{})}
	p.mu.Lock()
	p.switches = append(p.switches, tracked)
	p.mu.Unlock()

	go func() {
		select {
		case <-ctx.Done():
		case <-tracked.stopCh:
		}
		_ = sw.Stop() // idempotent: a no-op if CloseAll's own Stop call already ran.
	}()

	return Endpoints{
		Host:         sw.Host,
		SnmpPort:     sw.SnmpPort,
		NsdpPort:     sw.NsdpPort,
		Community:    sw.community,
		HTTPPort:     sw.HTTPPort,
		HTTPPassword: sw.httpPassword,
	}, nil
}

// CloseAll stops every VirtualSwitch this provider has ever started via
// StartModel, regardless of whether its ctx was ever cancelled, and forgets
// them (a later CloseAll call is a no-op). Closes each tracked switch's
// stopCh first so its StartModel watcher goroutine exits promptly too,
// rather than leaking until (or forever, for an uncancelled
// context.Background()) its ctx is done. Safe to call more than once:
// VirtualSwitch.Stop is itself idempotent.
func (p *GoFakeProvider) CloseAll() error {
	p.mu.Lock()
	switches := p.switches
	p.switches = nil
	p.mu.Unlock()

	var firstErr error
	for _, tracked := range switches {
		close(tracked.stopCh)
		if err := tracked.sw.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
