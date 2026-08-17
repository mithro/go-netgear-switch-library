package netgearswitch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// --- test fixtures -------------------------------------------------------

// fakeWriter is a BackendWriter test double recording every call it
// receives and returning its configured errs, mirroring switch_test.go's
// fakeReader shape.
type fakeWriter struct {
	mu sync.Mutex

	setPoECalls []struct {
		port      int
		on, force bool
	}
	setPortEnabledCalls []struct {
		port           int
		enabled, force bool
	}
	setPortDescriptionCalls []struct {
		port        int
		description string
		force       bool
	}
	setPortSpeedCalls []struct {
		port  int
		speed model.PortSpeed
		force bool
	}
	setFlowControlCalls []struct {
		port           int
		enabled, force bool
	}
	setPVIDCalls []struct {
		port, vlan int
		force      bool
	}
	setVlanMembershipCall *struct {
		vlanID, port int
		mode         model.VlanMode
		force        bool
	}
	createVlanCall *struct {
		vlanID int
		name   string
	}
	deleteVlanCall *struct {
		vlanID int
		force  bool
	}
	setMgmtIPCall *struct {
		address, netmask, gateway string
		force                     bool
	}
	setHostnameCall *struct {
		name  string
		force bool
	}
	setSyslogEnabledCall *struct {
		enabled, force bool
	}
	addSyslogCollectorCall *struct {
		host           string
		port, severity int
		force          bool
	}
	removeSyslogCollectorCall *struct {
		host  string
		force bool
	}
	cyclePoECall *struct {
		port     int
		timeouts snmp.PoeCycleTimeouts
		force    bool
	}
	clearPoEFaultCall *struct {
		port     int
		timeouts snmp.PoeCycleTimeouts
		force    bool
	}

	err error // returned by whichever method is called, if non-nil
}

func (f *fakeWriter) SetPoE(_ context.Context, port int, on bool, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setPoECalls = append(f.setPoECalls, struct {
		port      int
		on, force bool
	}{port, on, force})
	return f.err
}

func (f *fakeWriter) SetPortEnabled(_ context.Context, port int, enabled bool, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setPortEnabledCalls = append(f.setPortEnabledCalls, struct {
		port           int
		enabled, force bool
	}{port, enabled, force})
	return f.err
}

func (f *fakeWriter) SetPortDescription(_ context.Context, port int, description string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setPortDescriptionCalls = append(f.setPortDescriptionCalls, struct {
		port        int
		description string
		force       bool
	}{port, description, force})
	return f.err
}

func (f *fakeWriter) SetPortSpeed(_ context.Context, port int, speed model.PortSpeed, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setPortSpeedCalls = append(f.setPortSpeedCalls, struct {
		port  int
		speed model.PortSpeed
		force bool
	}{port, speed, force})
	return f.err
}

func (f *fakeWriter) SetFlowControl(_ context.Context, port int, enabled bool, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setFlowControlCalls = append(f.setFlowControlCalls, struct {
		port           int
		enabled, force bool
	}{port, enabled, force})
	return f.err
}

func (f *fakeWriter) SetPVID(_ context.Context, port, vlan int, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setPVIDCalls = append(f.setPVIDCalls, struct {
		port, vlan int
		force      bool
	}{port, vlan, force})
	return f.err
}

func (f *fakeWriter) SetVlanMembership(_ context.Context, vlanID, port int, mode model.VlanMode, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setVlanMembershipCall = &struct {
		vlanID, port int
		mode         model.VlanMode
		force        bool
	}{vlanID, port, mode, force}
	return f.err
}

func (f *fakeWriter) CreateVlan(_ context.Context, vlanID int, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createVlanCall = &struct {
		vlanID int
		name   string
	}{vlanID, name}
	return f.err
}

func (f *fakeWriter) DeleteVlan(_ context.Context, vlanID int, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteVlanCall = &struct {
		vlanID int
		force  bool
	}{vlanID, force}
	return f.err
}

func (f *fakeWriter) SetMgmtIP(_ context.Context, address, netmask, gateway string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setMgmtIPCall = &struct {
		address, netmask, gateway string
		force                     bool
	}{address, netmask, gateway, force}
	return f.err
}

func (f *fakeWriter) SetHostname(_ context.Context, name string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setHostnameCall = &struct {
		name  string
		force bool
	}{name, force}
	return f.err
}

func (f *fakeWriter) SetSyslogEnabled(_ context.Context, enabled bool, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setSyslogEnabledCall = &struct {
		enabled, force bool
	}{enabled, force}
	return f.err
}

func (f *fakeWriter) AddSyslogCollector(_ context.Context, host string, port, severity int, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addSyslogCollectorCall = &struct {
		host           string
		port, severity int
		force          bool
	}{host, port, severity, force}
	return f.err
}

func (f *fakeWriter) RemoveSyslogCollector(_ context.Context, host string, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeSyslogCollectorCall = &struct {
		host  string
		force bool
	}{host, force}
	return f.err
}

func (f *fakeWriter) CyclePoE(_ context.Context, port int, timeouts snmp.PoeCycleTimeouts, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cyclePoECall = &struct {
		port     int
		timeouts snmp.PoeCycleTimeouts
		force    bool
	}{port, timeouts, force}
	return f.err
}

func (f *fakeWriter) ClearPoEFault(_ context.Context, port int, timeouts snmp.PoeCycleTimeouts, force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clearPoEFaultCall = &struct {
		port     int
		timeouts snmp.PoeCycleTimeouts
		force    bool
	}{port, timeouts, force}
	return f.err
}

// withRegisteredWriteBackend registers build for backend for the duration
// of the calling test, restoring whatever was previously registered via
// t.Cleanup -- the write-side twin of switch_test.go's
// withRegisteredBackend.
func withRegisteredWriteBackend(t *testing.T, backend model.Backend, build WriteBackendBuilder) {
	t.Helper()
	writerRegistryMu.Lock()
	previous, had := writerRegistry[backend]
	writerRegistryMu.Unlock()

	RegisterWriteBackend(backend, build)

	t.Cleanup(func() {
		writerRegistryMu.Lock()
		defer writerRegistryMu.Unlock()
		if had {
			writerRegistry[backend] = previous
		} else {
			delete(writerRegistry, backend)
		}
	})
}

// clearWriteBackendRegistry empties the write-side package registry for the
// duration of the calling test, restoring the prior contents via
// t.Cleanup.
func clearWriteBackendRegistry(t *testing.T) {
	t.Helper()
	writerRegistryMu.Lock()
	previous := writerRegistry
	writerRegistry = map[model.Backend]WriteBackendBuilder{}
	writerRegistryMu.Unlock()

	t.Cleanup(func() {
		writerRegistryMu.Lock()
		defer writerRegistryMu.Unlock()
		writerRegistry = previous
	})
}

func newTestSwitch(t *testing.T, m *model.SwitchModel) *Switch {
	t.Helper()
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return sw
}

// --- writeVia: single-backend dispatch (D-REC Topic A, write-side twin of
// --- switch_test.go's readVia section -- see that section's header comment
// --- for what changed and why) ----------------------------------------------

func TestWriteVia_ResolvesToFirstPreferenceBackendModelHas(t *testing.T) {
	clearWriteBackendRegistry(t)
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		t.Fatal("SNMP builder invoked for a model with no SNMP backend")
		return nil, nil
	})
	fw := &fakeWriter{}
	withRegisteredWriteBackend(t, model.BackendNSDP, func(_ *Switch) (BackendWriter, error) {
		return fw, nil
	})

	m := fakeModel("gs110emx-like", model.BackendNSDP, model.BackendHTTP)
	sw := newTestSwitch(t, m)

	err := sw.writeVia(context.Background(), nil, func(w BackendWriter) error {
		return w.SetPoE(context.Background(), 1, true, false)
	})
	if err != nil {
		t.Fatalf("writeVia() error = %v, want nil (NSDP is the first backendPreference member this model declares)", err)
	}
	if len(fw.setPoECalls) != 1 {
		t.Fatalf("NSDP writer received %d SetPoE calls, want 1", len(fw.setPoECalls))
	}
}

func TestWriteVia_NoFallbackWhenChosenBackendCannotServe(t *testing.T) {
	// Was TestWriteVia_SkipAndReraiseLast (builder-level) AND
	// TestWriteVia_OpUnsupportedCapabilitySkipsToNextBackend (op-level) --
	// BOTH tested the removed fallback directly (the op-level one even had
	// "SkipsToNextBackend" in its name). Under single-backend dispatch,
	// SNMP (chosen) failing at the OP level must raise naming SNMP; NSDP
	// must never be invoked even though it is registered and would have
	// succeeded.
	clearWriteBackendRegistry(t)
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		return &fakeWriter{err: fmt.Errorf("snmp op unsupported: %w", model.ErrUnsupportedCapability)}, nil
	})
	nsdpBuilt := false
	withRegisteredWriteBackend(t, model.BackendNSDP, func(_ *Switch) (BackendWriter, error) {
		nsdpBuilt = true
		return &fakeWriter{}, nil
	})

	m := fakeModel("fake", model.BackendSNMP, model.BackendNSDP)
	sw := newTestSwitch(t, m)

	err := sw.writeVia(context.Background(), nil, func(w BackendWriter) error {
		return w.SetPoE(context.Background(), 1, true, false)
	})
	if err == nil {
		t.Fatal("writeVia() error = nil, want SNMP's UnsupportedCapability error (cannotServe-wrapped)")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("writeVia() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if !strings.Contains(err.Error(), "the default backend snmp cannot serve") {
		t.Fatalf("writeVia() error = %q, want the cannotServe default-branch shape naming snmp", err.Error())
	}
	if nsdpBuilt {
		t.Fatal("writeVia() must NOT fall through to NSDP just because it could have served the op -- no fallback, ever")
	}
}

func TestWriteVia_CredentialErrorPropagatesImmediately(t *testing.T) {
	clearWriteBackendRegistry(t)
	credErr := fmt.Errorf("no SNMP write community configured: %w", model.ErrCredential)
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		return nil, credErr
	})
	nsdpCalled := false
	withRegisteredWriteBackend(t, model.BackendNSDP, func(_ *Switch) (BackendWriter, error) {
		nsdpCalled = true
		return &fakeWriter{}, nil
	})

	m := fakeModel("fake", model.BackendSNMP, model.BackendNSDP)
	sw := newTestSwitch(t, m)

	err := sw.writeVia(context.Background(), nil, func(w BackendWriter) error {
		return w.SetPoE(context.Background(), 1, true, false)
	})
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("writeVia() error = %v, want wrapping ErrCredential", err)
	}
	if nsdpCalled {
		t.Fatal("writeVia() must propagate a non-UnsupportedCapability error immediately, never try NSDP")
	}
}

func TestWriteVia_OpCredentialErrorPropagatesImmediately(t *testing.T) {
	clearWriteBackendRegistry(t)
	opCredErr := fmt.Errorf("op needs a credential: %w", model.ErrCredential)
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		return &fakeWriter{err: opCredErr}, nil
	})
	nsdpCalled := false
	withRegisteredWriteBackend(t, model.BackendNSDP, func(_ *Switch) (BackendWriter, error) {
		nsdpCalled = true
		return &fakeWriter{}, nil
	})

	m := fakeModel("fake", model.BackendSNMP, model.BackendNSDP)
	sw := newTestSwitch(t, m)

	err := sw.writeVia(context.Background(), nil, func(w BackendWriter) error {
		return w.SetPoE(context.Background(), 1, true, false)
	})
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("writeVia() error = %v, want wrapping ErrCredential", err)
	}
	if nsdpCalled {
		t.Fatal("writeVia() must propagate immediately when the op itself raises a non-UnsupportedCapability error")
	}
}

func TestWriteVia_UnregisteredBackendTreatedAsUnsupported(t *testing.T) {
	// Under single-backend dispatch, only NSDP (the model's first-preference
	// backend) is ever attempted -- the error must name NSDP as chosen, with
	// HTTP appearing only in the hint, never as a "last tried" backend.
	clearWriteBackendRegistry(t)

	m := fakeModel("gs110emx-like", model.BackendNSDP, model.BackendHTTP)
	sw := newTestSwitch(t, m)

	err := sw.writeVia(context.Background(), nil, func(w BackendWriter) error {
		return w.SetPoE(context.Background(), 1, true, false)
	})
	if err == nil {
		t.Fatal("writeVia() error = nil, want ErrUnsupportedCapability for an unregistered backend")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("writeVia() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if !strings.Contains(err.Error(), "the default backend nsdp cannot serve") {
		t.Fatalf("writeVia() error = %q, want it to name nsdp as the (only) chosen backend", err.Error())
	}
	if !strings.Contains(err.Error(), "backend=Backend.<http>") {
		t.Fatalf("writeVia() error = %q, want the hint to suggest http as an alternate", err.Error())
	}
}

func TestWriteVia_CancelledContextFailsFast(t *testing.T) {
	clearWriteBackendRegistry(t)
	called := false
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		called = true
		return &fakeWriter{}, nil
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw := newTestSwitch(t, m)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sw.writeVia(ctx, nil, func(w BackendWriter) error {
		return w.SetPoE(ctx, 1, true, false)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("writeVia() error = %v, want wrapping context.Canceled", err)
	}
	if called {
		t.Fatal("writeVia() must fail fast on an already-cancelled context, never build a backend")
	}
}

func TestWriteVia_NoApplicableBackendRaisesFreshError(t *testing.T) {
	clearWriteBackendRegistry(t)
	m := fakeModel("fake", model.BackendConsole) // not in backendPreference at all
	sw := newTestSwitch(t, m)

	err := sw.writeVia(context.Background(), nil, func(w BackendWriter) error {
		return w.SetPoE(context.Background(), 1, true, false)
	})
	if err == nil {
		t.Fatal("writeVia() error = nil, want ErrUnsupportedCapability")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("writeVia() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if !strings.Contains(err.Error(), "fake") {
		t.Fatalf("writeVia() error = %q, want it to name the model", err.Error())
	}
	if !strings.Contains(err.Error(), "declares no backend this library can dispatch to") {
		t.Fatalf("writeVia() error = %q, want resolveBackend's no-preference-match shape", err.Error())
	}
}

func TestWriteVia_WriterCacheBuilderCalledOnce(t *testing.T) {
	clearWriteBackendRegistry(t)
	var calls int
	var mu sync.Mutex
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return &fakeWriter{}, nil
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw := newTestSwitch(t, m)

	for i := 0; i < 3; i++ {
		if err := sw.writeVia(context.Background(), nil, func(w BackendWriter) error {
			return w.SetPoE(context.Background(), 1, true, false)
		}); err != nil {
			t.Fatalf("writeVia() call %d error = %v", i, err)
		}
	}

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("builder called %d times, want exactly 1 (writer cache reuse)", got)
	}
}

func TestWriteVia_GateFailureIsNeverCached(t *testing.T) {
	clearWriteBackendRegistry(t)
	var calls int
	var mu sync.Mutex
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil, fmt.Errorf("gated off: %w", model.ErrUnsupportedCapability)
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw := newTestSwitch(t, m)

	for i := 0; i < 3; i++ {
		err := sw.writeVia(context.Background(), nil, func(w BackendWriter) error {
			return w.SetPoE(context.Background(), 1, true, false)
		})
		if !errors.Is(err, model.ErrUnsupportedCapability) {
			t.Fatalf("call %d: writeVia() error = %v, want wrapping ErrUnsupportedCapability", i, err)
		}
	}

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 3 {
		t.Fatalf("builder called %d times, want exactly 3 (a gate failure must never be cached)", got)
	}
}

// --- RegisterWriteBackend concurrency --------------------------------------

func TestRegisterWriteBackend_ConcurrentRegisterAndDispatch(t *testing.T) {
	clearWriteBackendRegistry(t)
	m := fakeModel("fake", model.BackendSNMP)
	sw := newTestSwitch(t, m)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RegisterWriteBackend(model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
				return &fakeWriter{}, nil
			})
		}()
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sw.writeVia(context.Background(), nil, func(w BackendWriter) error {
				return w.SetPoE(context.Background(), 1, true, false)
			})
		}()
	}
	wg.Wait()
}

// --- facade write-method delegation ---------------------------------------

func testSwitchWithFakeWriter(t *testing.T) (*Switch, *fakeWriter) {
	t.Helper()
	clearWriteBackendRegistry(t)
	fw := &fakeWriter{}
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		return fw, nil
	})
	m := fakeModel("fake", model.BackendSNMP)
	sw := newTestSwitch(t, m)
	return sw, fw
}

func TestSetPoE_DelegatesToWriterAndForwardsForce(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	if err := sw.SetPoE(context.Background(), 7, false, Write{Force: true}); err != nil {
		t.Fatalf("SetPoE() error = %v", err)
	}
	if len(fw.setPoECalls) != 1 {
		t.Fatalf("SetPoE calls = %d, want 1", len(fw.setPoECalls))
	}
	got := fw.setPoECalls[0]
	if got.port != 7 || got.on != false || got.force != true {
		t.Fatalf("SetPoE call = %+v, want port=7 on=false force=true", got)
	}
}

func TestSetPortEnabled_DelegatesToWriterAndForwardsForce(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	if err := sw.SetPortEnabled(context.Background(), 3, false, Write{Force: true}); err != nil {
		t.Fatalf("SetPortEnabled() error = %v", err)
	}
	if len(fw.setPortEnabledCalls) != 1 {
		t.Fatalf("SetPortEnabled calls = %d, want 1", len(fw.setPortEnabledCalls))
	}
	got := fw.setPortEnabledCalls[0]
	if got.port != 3 || got.enabled != false || got.force != true {
		t.Fatalf("SetPortEnabled call = %+v, want port=3 enabled=false force=true", got)
	}
}

func TestSetPortDescription_DelegatesToWriterAndForwardsForce(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	if err := sw.SetPortDescription(context.Background(), 3, "uplink", Write{Force: true}); err != nil {
		t.Fatalf("SetPortDescription() error = %v", err)
	}
	if len(fw.setPortDescriptionCalls) != 1 {
		t.Fatalf("SetPortDescription calls = %d, want 1", len(fw.setPortDescriptionCalls))
	}
	got := fw.setPortDescriptionCalls[0]
	if got.port != 3 || got.description != "uplink" || got.force != true {
		t.Fatalf("SetPortDescription call = %+v, want port=3 description=uplink force=true", got)
	}
}

func TestSetPortSpeed_DelegatesToWriterAndForwardsForce(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	speed := ForcedPortSpeed(100, true)
	if err := sw.SetPortSpeed(context.Background(), 3, speed, Write{Force: true}); err != nil {
		t.Fatalf("SetPortSpeed() error = %v", err)
	}
	if len(fw.setPortSpeedCalls) != 1 {
		t.Fatalf("SetPortSpeed calls = %d, want 1", len(fw.setPortSpeedCalls))
	}
	got := fw.setPortSpeedCalls[0]
	if got.port != 3 || !got.speed.Equal(speed) || got.force != true {
		t.Fatalf("SetPortSpeed call = %+v, want port=3 speed=%v force=true", got, speed)
	}
}

func TestSetFlowControl_DelegatesToWriterAndForwardsForce(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	if err := sw.SetFlowControl(context.Background(), 3, true, Write{Force: true}); err != nil {
		t.Fatalf("SetFlowControl() error = %v", err)
	}
	if len(fw.setFlowControlCalls) != 1 {
		t.Fatalf("SetFlowControl calls = %d, want 1", len(fw.setFlowControlCalls))
	}
	got := fw.setFlowControlCalls[0]
	if got.port != 3 || got.enabled != true || got.force != true {
		t.Fatalf("SetFlowControl call = %+v, want port=3 enabled=true force=true", got)
	}
}

func TestSetPVID_DelegatesToWriterAndForwardsForce(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	if err := sw.SetPVID(context.Background(), 3, 20, Write{Force: true}); err != nil {
		t.Fatalf("SetPVID() error = %v", err)
	}
	if len(fw.setPVIDCalls) != 1 {
		t.Fatalf("SetPVID calls = %d, want 1", len(fw.setPVIDCalls))
	}
	got := fw.setPVIDCalls[0]
	if got.port != 3 || got.vlan != 20 || got.force != true {
		t.Fatalf("SetPVID call = %+v, want port=3 vlan=20 force=true", got)
	}
}

func TestSetVlanMembership_DelegatesToWriterAndForwardsForce(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	if err := sw.SetVlanMembership(context.Background(), 20, 3, VlanTagged, Write{Force: true}); err != nil {
		t.Fatalf("SetVlanMembership() error = %v", err)
	}
	if fw.setVlanMembershipCall == nil {
		t.Fatal("SetVlanMembership not delegated to writer")
	}
	got := fw.setVlanMembershipCall
	if got.vlanID != 20 || got.port != 3 || got.mode != model.VlanTagged || got.force != true {
		t.Fatalf("SetVlanMembership call = %+v, want vlanID=20 port=3 mode=tagged force=true", got)
	}
}

func TestCreateVlan_DelegatesToWriterWithoutForce(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	if err := sw.CreateVlan(context.Background(), 30, "eng", Write{Force: true}); err != nil {
		t.Fatalf("CreateVlan() error = %v", err)
	}
	if fw.createVlanCall == nil {
		t.Fatal("CreateVlan not delegated to writer")
	}
	if fw.createVlanCall.vlanID != 30 || fw.createVlanCall.name != "eng" {
		t.Fatalf("CreateVlan call = %+v, want vlanID=30 name=%q", fw.createVlanCall, "eng")
	}
}

func TestSetMgmtIP_DelegatesToWriterAndForwardsForce(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	if err := sw.SetMgmtIP(context.Background(), "10.0.0.9", "255.255.255.0", "10.0.0.1", Write{Force: true}); err != nil {
		t.Fatalf("SetMgmtIP() error = %v", err)
	}
	if fw.setMgmtIPCall == nil {
		t.Fatal("SetMgmtIP not delegated to writer")
	}
	got := fw.setMgmtIPCall
	if got.address != "10.0.0.9" || got.netmask != "255.255.255.0" || got.gateway != "10.0.0.1" || got.force != true {
		t.Fatalf("SetMgmtIP call = %+v, want address/netmask/gateway forwarded and force=true", got)
	}
}

func TestSetMgmtIP_ForceFalseStillForwardedNotGatedByFacade(t *testing.T) {
	// The facade must NOT re-implement set_mgmt_ip's unconditional force
	// gate itself -- that lives entirely in the BackendWriter (D-WR §2.13).
	// A force=false call must still reach the writer unchanged, letting the
	// writer's own gate decide.
	sw, fw := testSwitchWithFakeWriter(t)
	if err := sw.SetMgmtIP(context.Background(), "a", "b", "c", Write{Force: false}); err != nil {
		t.Fatalf("SetMgmtIP() error = %v", err)
	}
	if fw.setMgmtIPCall == nil || fw.setMgmtIPCall.force != false {
		t.Fatalf("SetMgmtIP call = %+v, want it reached the writer with force=false (facade does not gate)", fw.setMgmtIPCall)
	}
}

func TestCyclePoE_DelegatesToWriterWithDefaultTimeouts(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	if err := sw.CyclePoE(context.Background(), 5, Write{Force: true}); err != nil {
		t.Fatalf("CyclePoE() error = %v", err)
	}
	if fw.cyclePoECall == nil {
		t.Fatal("CyclePoE not delegated to writer")
	}
	got := fw.cyclePoECall
	want := snmp.DefaultPoeCycleTimeouts()
	if got.port != 5 || got.force != true || got.timeouts != want {
		t.Fatalf("CyclePoE call = %+v, want port=5 force=true timeouts=%+v", got, want)
	}
}

func TestCyclePoE_WithCycleTimeoutsOverridesDefault(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	custom := snmp.PoeCycleTimeouts{Off: time.Second, On: time.Second, Poll: 0}
	if err := sw.CyclePoE(context.Background(), 5, Write{}, WithCycleTimeouts(custom)); err != nil {
		t.Fatalf("CyclePoE() error = %v", err)
	}
	if fw.cyclePoECall == nil || fw.cyclePoECall.timeouts != custom {
		t.Fatalf("CyclePoE timeouts = %+v, want %+v", fw.cyclePoECall, custom)
	}
}

func TestClearPoEFault_DelegatesToWriterWithDefaultTimeouts(t *testing.T) {
	sw, fw := testSwitchWithFakeWriter(t)
	if err := sw.ClearPoEFault(context.Background(), 5, Write{Force: true}); err != nil {
		t.Fatalf("ClearPoEFault() error = %v", err)
	}
	if fw.clearPoEFaultCall == nil {
		t.Fatal("ClearPoEFault not delegated to writer")
	}
	got := fw.clearPoEFaultCall
	want := snmp.DefaultPoeCycleTimeouts()
	if got.port != 5 || got.force != true || got.timeouts != want {
		t.Fatalf("ClearPoEFault call = %+v, want port=5 force=true timeouts=%+v", got, want)
	}
}

// --- DeleteVlan facade-level member guard (guardVLANDeleteMembers) --------

// fakeVLANReader is a minimal BackendReader that only serves GetVLANs (with
// getVLANsErr, if set); every other method panics if called, since the
// DeleteVlan guard tests below must never dispatch anything but GetVLANs.
type fakeVLANReader struct {
	vlans       []model.VLANInfo
	getVLANsErr error
}

func (f *fakeVLANReader) GetPorts(context.Context) ([]model.PortStatus, error) { panic("not used") }
func (f *fakeVLANReader) GetStats(context.Context) ([]model.PortStats, error)  { panic("not used") }
func (f *fakeVLANReader) GetVLANs(context.Context) ([]model.VLANInfo, error) {
	return f.vlans, f.getVLANsErr
}
func (f *fakeVLANReader) GetPVIDs(context.Context) ([]model.Pvid, error)        { panic("not used") }
func (f *fakeVLANReader) GetLLDP(context.Context) ([]model.LLDPNeighbor, error) { panic("not used") }
func (f *fakeVLANReader) GetMACs(context.Context) ([]model.MacEntry, error)     { panic("not used") }
func (f *fakeVLANReader) GetPoE(context.Context) ([]model.PoEStatus, error)     { panic("not used") }
func (f *fakeVLANReader) GetSensors(context.Context) ([]model.Sensor, error)    { panic("not used") }
func (f *fakeVLANReader) GetMgmtIP(context.Context) (model.MgmtIPConfig, error) {
	panic("not used")
}
func (f *fakeVLANReader) GetUsers(context.Context) ([]model.SwitchUser, error) { panic("not used") }
func (f *fakeVLANReader) GetServices(context.Context) ([]model.ServiceStatus, error) {
	panic("not used")
}
func (f *fakeVLANReader) GetHostname(context.Context) (string, error) { panic("not used") }
func (f *fakeVLANReader) GetSyslog(context.Context) (model.SyslogConfig, error) {
	panic("not used")
}

func TestDeleteVlan_ProtectedMemberBlocksWithoutForce(t *testing.T) {
	clearBackendRegistry(t)
	clearWriteBackendRegistry(t)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &fakeVLANReader{vlans: []model.VLANInfo{{VlanID: 20, MemberPorts: []int{1, 5, 8}}}}, nil
	})
	fw := &fakeWriter{}
	writerBuilt := false
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		writerBuilt = true
		return fw, nil
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1", WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = sw.DeleteVlan(context.Background(), 20, Write{Force: false})
	if err == nil {
		t.Fatal("DeleteVlan() error = nil, want a protected-port refusal")
	}
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("DeleteVlan() error = %v, want wrapping ErrProtectedPort", err)
	}
	wantSubstr := "VLAN 20 includes protected port(s) [5]; pass force=True to delete it anyway"
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("DeleteVlan() error = %q, want it to contain %q", err.Error(), wantSubstr)
	}
	if writerBuilt || fw.deleteVlanCall != nil {
		t.Fatal("DeleteVlan() must guard BEFORE dispatch: the writer must never be built/called")
	}
}

func TestDeleteVlan_ForceBypassesFacadeGuardEntirely(t *testing.T) {
	clearBackendRegistry(t)
	clearWriteBackendRegistry(t)
	readerBuilt := false
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		readerBuilt = true
		return &fakeVLANReader{vlans: []model.VLANInfo{{VlanID: 20, MemberPorts: []int{5}}}}, nil
	})
	fw := &fakeWriter{}
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		return fw, nil
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1", WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := sw.DeleteVlan(context.Background(), 20, Write{Force: true}); err != nil {
		t.Fatalf("DeleteVlan() error = %v, want nil (force bypasses the guard)", err)
	}
	if readerBuilt {
		t.Fatal("DeleteVlan(force=true) must skip the guard's read entirely, never build a reader")
	}
	if fw.deleteVlanCall == nil || fw.deleteVlanCall.vlanID != 20 || fw.deleteVlanCall.force != true {
		t.Fatalf("DeleteVlan writer call = %+v, want vlanID=20 force=true", fw.deleteVlanCall)
	}
}

func TestDeleteVlan_UnprotectedMembersProceedToDispatch(t *testing.T) {
	clearBackendRegistry(t)
	clearWriteBackendRegistry(t)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &fakeVLANReader{vlans: []model.VLANInfo{{VlanID: 20, MemberPorts: []int{1, 2}}}}, nil
	})
	fw := &fakeWriter{}
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		return fw, nil
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1", WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := sw.DeleteVlan(context.Background(), 20, Write{}); err != nil {
		t.Fatalf("DeleteVlan() error = %v, want nil (no protected member)", err)
	}
	if fw.deleteVlanCall == nil {
		t.Fatal("DeleteVlan() should have dispatched to the writer")
	}
}

func TestDeleteVlan_GuardVLANNotFoundAmongOthersProceeds(t *testing.T) {
	clearBackendRegistry(t)
	clearWriteBackendRegistry(t)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &fakeVLANReader{vlans: []model.VLANInfo{
			{VlanID: 10, MemberPorts: []int{5}},
			{VlanID: 30, MemberPorts: []int{5}},
		}}, nil
	})
	fw := &fakeWriter{}
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		return fw, nil
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1", WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Target VLAN 20 is not in the list at all (only 10 and 30 are) -- the
	// guard must scan past every non-matching VLAN (exercising the loop's
	// continue branch) and, finding no match, proceed to dispatch rather
	// than block or error.
	if err := sw.DeleteVlan(context.Background(), 20, Write{}); err != nil {
		t.Fatalf("DeleteVlan() error = %v, want nil (target VLAN absent from the list is not a guard match)", err)
	}
	if fw.deleteVlanCall == nil {
		t.Fatal("DeleteVlan() should have dispatched to the writer once the guard found no matching VLAN")
	}
}

func TestDeleteVlan_GuardDegradesSilentlyWhenNoBackendCanReadVLANs(t *testing.T) {
	clearBackendRegistry(t) // no BackendReader registered for anything
	clearWriteBackendRegistry(t)
	fw := &fakeWriter{}
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		return fw, nil
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1", WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := sw.DeleteVlan(context.Background(), 20, Write{}); err != nil {
		t.Fatalf("DeleteVlan() error = %v, want nil (guard must degrade silently when VLANs are unreadable)", err)
	}
	if fw.deleteVlanCall == nil {
		t.Fatal("DeleteVlan() should still have dispatched to the writer after the guard degraded silently")
	}
}

func TestDeleteVlan_GuardPropagatesNonUnsupportedReadError(t *testing.T) {
	clearBackendRegistry(t)
	clearWriteBackendRegistry(t)
	readErr := fmt.Errorf("no SNMP read community configured: %w", model.ErrCredential)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return nil, readErr
	})
	fw := &fakeWriter{}
	writerBuilt := false
	withRegisteredWriteBackend(t, model.BackendSNMP, func(_ *Switch) (BackendWriter, error) {
		writerBuilt = true
		return fw, nil
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1", WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = sw.DeleteVlan(context.Background(), 20, Write{})
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("DeleteVlan() error = %v, want wrapping ErrCredential (must propagate, not degrade)", err)
	}
	if writerBuilt {
		t.Fatal("DeleteVlan() must not dispatch to the writer when the guard's read fails with a non-UnsupportedCapability error")
	}
}

func TestDeleteVlan_GuardReadRunsOverWriteBackendOverride(t *testing.T) {
	// D-REC A.7/A.10.7: readOptsForBackend threads Write.Backend into the
	// guard's own GetVLANs read, so the guard checks the SAME backend the
	// delete itself will use, not the facade's default (new plumbing versus
	// the pre-reconciliation Go source, which always read the default
	// backend regardless of o.Backend). Register SNMP -- the model's
	// default, first in backendPreference -- as a reader whose VLAN 20 DOES
	// clash with a protected port, and NSDP as a reader whose VLAN 20 does
	// NOT. If the guard read the default (SNMP) it would block; since
	// Write.Backend explicitly names NSDP, it must read NSDP instead and
	// proceed.
	clearBackendRegistry(t)
	clearWriteBackendRegistry(t)
	snmpReaderBuilt := false
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		snmpReaderBuilt = true
		return &fakeVLANReader{vlans: []model.VLANInfo{{VlanID: 20, MemberPorts: []int{5}}}}, nil
	})
	nsdpReaderBuilt := false
	withRegisteredBackend(t, model.BackendNSDP, func(_ *Switch) (BackendReader, error) {
		nsdpReaderBuilt = true
		return &fakeVLANReader{vlans: []model.VLANInfo{{VlanID: 20, MemberPorts: []int{1, 2}}}}, nil
	})
	fw := &fakeWriter{}
	withRegisteredWriteBackend(t, model.BackendNSDP, func(_ *Switch) (BackendWriter, error) {
		return fw, nil
	})

	m := fakeModel("fake", model.BackendSNMP, model.BackendNSDP)
	sw, err := New(m, "10.0.0.1", WithProtectedPorts(5))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	nsdp := model.BackendNSDP
	if err := sw.DeleteVlan(context.Background(), 20, Write{Backend: &nsdp}); err != nil {
		t.Fatalf("DeleteVlan() error = %v, want nil (guard must have read NSDP's VLAN 20, which has no protected member)", err)
	}
	if snmpReaderBuilt {
		t.Fatal("DeleteVlan() guard read the facade-default SNMP backend instead of the explicitly-requested NSDP backend")
	}
	if !nsdpReaderBuilt {
		t.Fatal("DeleteVlan() guard never read the explicitly-requested NSDP backend")
	}
	if fw.deleteVlanCall == nil || fw.deleteVlanCall.vlanID != 20 {
		t.Fatalf("DeleteVlan() writer call = %+v, want a dispatched call for vlanID=20 over NSDP", fw.deleteVlanCall)
	}
}

// --- write-community gate (requireSNMPWriteCommunity) ---------------------

func TestRequireSNMPWriteCommunity_RejectsNil(t *testing.T) {
	_, err := requireSNMPWriteCommunity("10.0.0.1", nil)
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("requireSNMPWriteCommunity(nil) error = %v, want wrapping ErrCredential", err)
	}
}

func TestRequireSNMPWriteCommunity_RejectsEmptyString(t *testing.T) {
	empty := ""
	_, err := requireSNMPWriteCommunity("10.0.0.1", &empty)
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("requireSNMPWriteCommunity(\"\") error = %v, want wrapping ErrCredential (write gate rejects empty, unlike read gate)", err)
	}
}

func TestRequireSNMPWriteCommunity_AcceptsNonEmptyString(t *testing.T) {
	community := "private"
	got, err := requireSNMPWriteCommunity("10.0.0.1", &community)
	if err != nil {
		t.Fatalf("requireSNMPWriteCommunity() error = %v, want nil", err)
	}
	if got != community {
		t.Fatalf("requireSNMPWriteCommunity() = %q, want %q", got, community)
	}
}

func TestBuildSNMPWriteClient_InjectedClientBypassesCommunityResolution(t *testing.T) {
	resolverCalled := false
	m := fakeModel("fake", model.BackendSNMP)
	injected := &recordingWriteClient{}
	sw, err := New(m, "10.0.0.1",
		WithSNMPWriteClient(injected),
		WithSNMPWriteCommunityResolver(func() (*string, error) {
			resolverCalled = true
			return nil, nil
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	client, err := buildSNMPWriteClient(sw)
	if err != nil {
		t.Fatalf("buildSNMPWriteClient() error = %v", err)
	}
	if client != injected {
		t.Fatalf("buildSNMPWriteClient() = %v, want the injected client", client)
	}
	if resolverCalled {
		t.Fatal("buildSNMPWriteClient() must not resolve a write community when a client is injected")
	}
}

func TestBuildSNMPWriteClient_ResolverErrorPropagates(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	resolveErr := errors.New("boom")
	sw, err := New(m, "10.0.0.1", WithSNMPWriteCommunityResolver(func() (*string, error) {
		return nil, resolveErr
	}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = buildSNMPWriteClient(sw)
	if !errors.Is(err, resolveErr) {
		t.Fatalf("buildSNMPWriteClient() error = %v, want wrapping the resolver's error", err)
	}
}

func TestBuildSNMPWriteClient_UnresolvedCommunityGatedByCredentialError(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1") // no write-community resolver configured at all
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = buildSNMPWriteClient(sw)
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("buildSNMPWriteClient() error = %v, want wrapping ErrCredential", err)
	}
}

func TestBuildSNMPWriteClient_EmptyResolvedCommunityRejected(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	empty := ""
	sw, err := New(m, "10.0.0.1", WithSNMPWriteCommunityResolver(func() (*string, error) {
		return &empty, nil
	}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = buildSNMPWriteClient(sw)
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("buildSNMPWriteClient() error = %v, want wrapping ErrCredential (empty resolved community is still rejected)", err)
	}
}

// recordingWriteClient is a minimal snmp.WriteClient stand-in for injection
// tests -- its methods are never expected to be called by these tests, so
// they simply return zero values.
type recordingWriteClient struct{}

func (recordingWriteClient) Get(context.Context, []string) ([]snmp.Row, error) { return nil, nil }
func (recordingWriteClient) Walk(context.Context, string) ([]snmp.Row, error)  { return nil, nil }
func (recordingWriteClient) Set(context.Context, snmp.SetVarbind) error        { return nil }
func (recordingWriteClient) SetMany(context.Context, []snmp.SetVarbind) error  { return nil }

func TestBuildSNMPWriteClient_ResolvesAndBuildsDefaultClient(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	community := "private"
	sw, err := New(m, "10.0.0.1", WithSNMPWriteCommunityResolver(func() (*string, error) {
		return &community, nil
	}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	client, err := buildSNMPWriteClient(sw)
	if err != nil {
		t.Fatalf("buildSNMPWriteClient() error = %v, want nil", err)
	}
	if client == nil {
		t.Fatal("buildSNMPWriteClient() = nil, want a default-built snmp.WriteClient")
	}
}

// --- buildSNMPWriter wiring ------------------------------------------------

func TestBuildSNMPWriter_PassesProtectedPortsThrough(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	injected := &recordingWriteClient{}
	sw, err := New(m, "10.0.0.1", WithSNMPWriteClient(injected), WithProtectedPorts(2, 4))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	writer, err := buildSNMPWriter(sw)
	if err != nil {
		t.Fatalf("buildSNMPWriter() error = %v, want nil", err)
	}
	if writer == nil {
		t.Fatal("buildSNMPWriter() returned nil writer")
	}
	// Verify protected ports were wired by observing the guard refuses
	// port 2 without force: SetPortEnabled(disable) is the disruptive
	// direction.
	err = writer.SetPortEnabled(context.Background(), 2, false, false)
	if !errors.Is(err, model.ErrProtectedPort) {
		t.Fatalf("SetPortEnabled on protected port 2 error = %v, want wrapping ErrProtectedPort (protectedPorts not wired through)", err)
	}
}

func TestBuildSNMPWriter_PropagatesWriteClientError(t *testing.T) {
	// No injected write client and no write-community resolver configured
	// at all: buildSNMPWriteClient's own CredentialError must propagate
	// straight out of buildSNMPWriter, uncaught.
	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = buildSNMPWriter(sw)
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("buildSNMPWriter() error = %v, want wrapping ErrCredential (propagated from buildSNMPWriteClient)", err)
	}
}

func TestBuildSNMPWriter_NoSNMPBackendModelErrors(t *testing.T) {
	m := fakeModel("fake") // no backends at all
	injected := &recordingWriteClient{}
	sw, err := New(m, "10.0.0.1", WithSNMPWriteClient(injected))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = buildSNMPWriter(sw)
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("buildSNMPWriter() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
}
