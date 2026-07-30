package virtual

// server.go ports src/netgear_switch/virtual/server.py's VirtualSwitch (the
// normative source; that repo is read-only from here -- pin 1aa1274, branch
// fix/s3300-52x-live-verify). Any discrepancy between this file and the
// Python source is a bug here. See D-VIRT §5 and D-NSDP §7.4 for the full
// porting dossier this mirrors.
//
// VirtualSwitch is a mock switch server: a seeded State plus whichever
// protocol faces the model's registry entry supports, bound on Start. This
// slice implements the SNMP face (snmpface.go) and, as of slice 05, the
// NSDP face (nsdpface.go); HTTP (slice 06) and SSH/Telnet CLI (slice 07)
// faces land later -- see the reserved port fields below, which exist now
// so this struct's shape never needs to change again once those faces
// arrive.
//
// Deviates from the Python reference in one deliberate way: Python's
// VirtualSwitch.start() independently binds each backend the model
// supports, so a {NSDP, HTTP} model ends up with BOTH self.port (NSDP) and
// self.http_port (HTTP) live at once. This Go port keeps SnmpPort/NsdpPort
// as separate fields from the start (see NsdpPort's own doc comment), so
// Start's "at least one face bound" check is "does this model have
// BackendSNMP or BackendNSDP" as of this slice; the moment slice 06/07
// land, Start's body gains the same independent per-backend `if` blocks
// for HTTP/SSH/Telnet, and the "no face bindable" branch becomes reachable
// only for a model with none of the four backends -- see the per-field
// TODOs below for exactly which slice wires which remaining field.

import (
	"context"
	"fmt"
	"sync"

	"github.com/mithro/go-netgear-switch-library/model"
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
	// HTTPPort is reserved for slice 06's HTTP face; always 0 in this slice.
	HTTPPort int
	// SSHPort is reserved for slice 07's SSH CLI face; always 0 in this slice.
	SSHPort int
	// TelnetPort is reserved for slice 07's Telnet CLI face; always 0 in
	// this slice.
	TelnetPort int

	modelKey  string
	modelInfo *model.SwitchModel
	community string

	mu       sync.Mutex
	snmpFace *SnmpFace
	nsdpFace *NsdpFace
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
		State:     BuildState(modelKey),
		Host:      "127.0.0.1",
		community: "public",
		modelKey:  modelKey,
		modelInfo: m,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// Start binds every protocol face this slice implements that the model
// supports: SNMP (bound iff the model's registry entry has
// model.BackendSNMP) and, as of slice 05, NSDP (bound iff it has
// model.BackendNSDP) -- HTTP/SSH/Telnet aren't independent `if` blocks yet,
// see the package doc comment above. A Plus-class model such as
// gs110emx/gs305ep/gs105pe (registry backends {NSDP, HTTP}) now binds its
// NSDP face into NsdpPort; only HTTPPort stays 0 until slice 06 lands. A
// model with no face this slice can bind for it at all (none of
// BackendSNMP/BackendNSDP) returns an error wrapping
// model.ErrUnsupportedCapability.
//
// TODO(slice-06/slice-07): once the HTTP and SSH/Telnet faces exist, this
// gains their own independent `if` blocks too (mirroring the Python
// reference's start()), and this method's "no face bindable" error becomes
// reachable only for a hypothetical model with none of the four backends.
func (v *VirtualSwitch) Start() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.modelInfo.HasBackend(model.BackendSNMP) {
		view := NewMibView(v.State)
		face := NewSnmpFace(view, v.community, v.Host)
		port, err := face.Start()
		if err != nil {
			return fmt.Errorf("virtual: VirtualSwitch.Start: %w", err)
		}
		v.SnmpPort = port
		v.snmpFace = face
	}

	if v.modelInfo.HasBackend(model.BackendNSDP) {
		face := NewNsdpFace(v.State, v.Host)
		port, err := face.Start()
		if err != nil {
			return fmt.Errorf("virtual: VirtualSwitch.Start: %w", err)
		}
		v.NsdpPort = port
		v.nsdpFace = face
	}

	if v.snmpFace == nil && v.nsdpFace == nil {
		return fmt.Errorf("model %q has no protocol face this slice can bind (no SNMP/NSDP backend; see slices 06-07 for HTTP/SSH/Telnet): %w",
			v.modelKey, model.ErrUnsupportedCapability)
	}
	return nil
}

// Stop stops every bound face. Idempotent: safe to call if Start failed,
// was never called, or Stop was already called. Stops the SNMP face first,
// then NSDP, regardless of whether the first stop errored, so a failure
// stopping one face never leaks the other; only the first error (if any)
// is returned.
func (v *VirtualSwitch) Stop() error {
	v.mu.Lock()
	snmpFace := v.snmpFace
	v.snmpFace = nil
	v.SnmpPort = 0
	nsdpFace := v.nsdpFace
	v.nsdpFace = nil
	v.NsdpPort = 0
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
	return firstErr
}

// --- EndpointProvider: conformance-harness seam (D-VIRT §5, slice 10) -----

// Endpoints is the set of listening endpoints a started VirtualSwitch
// exposes, for a caller (e.g. a cross-language conformance-harness client,
// slice 10) that wants only connection details, not this package's
// concrete VirtualSwitch type. NsdpPort mirrors VirtualSwitch.NsdpPort now
// that the NSDP face has landed (this slice); later slices add HTTPPort,
// SSHPort, TelnetPort, Password fields the same way, as those faces land,
// mirroring VirtualSwitch's own reserved fields.
type Endpoints struct {
	Host      string
	SnmpPort  int
	NsdpPort  int
	Community string
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

	return Endpoints{Host: sw.Host, SnmpPort: sw.SnmpPort, NsdpPort: sw.NsdpPort, Community: sw.community}, nil
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
