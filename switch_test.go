package netgearswitch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// --- test fixtures -----------------------------------------------------

// fakeReader is a BackendReader test double: every method returns its
// configured err (nil unless set), so a single fixture can stand in for
// "this backend serves every op" or "this backend raises for op X" as each
// test needs. Fields not exercised by a given test are left nil/zero.
type fakeReader struct {
	getPortsErr error
}

func (f *fakeReader) GetPorts(context.Context) ([]model.PortStatus, error) {
	return nil, f.getPortsErr
}
func (f *fakeReader) GetStats(context.Context) ([]model.PortStats, error)   { return nil, nil }
func (f *fakeReader) GetVLANs(context.Context) ([]model.VLANInfo, error)    { return nil, nil }
func (f *fakeReader) GetPVIDs(context.Context) ([]model.Pvid, error)        { return nil, nil }
func (f *fakeReader) GetLLDP(context.Context) ([]model.LLDPNeighbor, error) { return nil, nil }
func (f *fakeReader) GetMACs(context.Context) ([]model.MacEntry, error)     { return nil, nil }
func (f *fakeReader) GetPoE(context.Context) ([]model.PoEStatus, error)     { return nil, nil }
func (f *fakeReader) GetSensors(context.Context) ([]model.Sensor, error)    { return nil, nil }
func (f *fakeReader) GetMgmtIP(context.Context) (model.MgmtIPConfig, error) {
	return model.MgmtIPConfig{}, nil
}

// withRegisteredBackend registers build for backend for the duration of the
// calling test, restoring whatever (if anything) was registered before via
// t.Cleanup -- so tests that plug in a fake builder never leak state into
// sibling tests, including any real backend a later slice/task registers
// via its own init().
func withRegisteredBackend(t *testing.T, backend model.Backend, build BackendBuilder) {
	t.Helper()
	backendRegistryMu.Lock()
	previous, had := backendRegistry[backend]
	backendRegistryMu.Unlock()

	RegisterBackend(backend, build)

	t.Cleanup(func() {
		backendRegistryMu.Lock()
		defer backendRegistryMu.Unlock()
		if had {
			backendRegistry[backend] = previous
		} else {
			delete(backendRegistry, backend)
		}
	})
}

// clearBackendRegistry empties the package registry for the duration of the
// calling test (restoring the prior contents via t.Cleanup), so a test
// exercising "no backend registered" behavior isn't accidentally satisfied
// by a real backend some other test (or a future slice's init()) left
// registered.
func clearBackendRegistry(t *testing.T) {
	t.Helper()
	backendRegistryMu.Lock()
	previous := backendRegistry
	backendRegistry = map[model.Backend]BackendBuilder{}
	backendRegistryMu.Unlock()

	t.Cleanup(func() {
		backendRegistryMu.Lock()
		defer backendRegistryMu.Unlock()
		backendRegistry = previous
	})
}

func fakeModel(key string, backends ...model.Backend) *model.SwitchModel {
	return &model.SwitchModel{Key: key, Backends: backends}
}

// --- New()/construction: no I/O, no secret resolution -------------------

func TestNew_NilModelErrors(t *testing.T) {
	sw, err := New(nil, "10.0.0.1")
	if err == nil {
		t.Fatal("New(nil, ...) error = nil, want non-nil")
	}
	if sw != nil {
		t.Fatalf("New(nil, ...) switch = %v, want nil", sw)
	}
}

func TestNew_NeverResolvesSecrets(t *testing.T) {
	called := false
	resolver := func() (*string, error) {
		called = true
		return nil, nil
	}
	m := fakeModel("fake", model.BackendSNMP)
	_, err := New(m, "10.0.0.1",
		WithSNMPWriteCommunityResolver(resolver),
		WithHTTPPasswordResolver(resolver),
	)
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	if called {
		t.Fatal("New() invoked a secret resolver at construction time; must defer to first use")
	}
}

func TestNew_NeverDialsAnInjectedClient(t *testing.T) {
	// A snmp.Client whose methods panic if ever called stands in for "no
	// I/O happened": construction must never touch it.
	client := panicClient{t: t}
	m := fakeModel("fake", model.BackendSNMP)
	if _, err := New(m, "10.0.0.1", WithSNMPClient(client)); err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
}

type panicClient struct{ t *testing.T }

func (p panicClient) Get(context.Context, []string) ([]snmp.Row, error) {
	p.t.Fatal("Get called during construction")
	return nil, nil
}

func (p panicClient) Walk(context.Context, string) ([]snmp.Row, error) {
	p.t.Fatal("Walk called during construction")
	return nil, nil
}

func TestNew_ProtectedPortsStoredSortedAndDeduped(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1", WithProtectedPorts(5, 1, 3, 1, 5))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	want := []int{1, 3, 5}
	if got := sw.protectedPorts; !intSlicesEqual(got, want) {
		t.Fatalf("protectedPorts = %v, want %v", got, want)
	}
}

func TestNew_ProtectedPortsDefaultEmptyNotNil(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if sw.protectedPorts == nil {
		t.Fatal("protectedPorts = nil, want non-nil empty slice")
	}
	if len(sw.protectedPorts) != 0 {
		t.Fatalf("protectedPorts = %v, want empty", sw.protectedPorts)
	}
}

func intSlicesEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- readVia dispatch loop -----------------------------------------------

func TestReadVia_SkipsBackendsModelDoesNotHave(t *testing.T) {
	clearBackendRegistry(t)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		t.Fatal("SNMP builder invoked for a model with no SNMP backend")
		return nil, nil
	})
	withRegisteredBackend(t, model.BackendNSDP, func(_ *Switch) (BackendReader, error) {
		return &fakeReader{}, nil
	})

	m := fakeModel("gs110emx-like", model.BackendNSDP, model.BackendHTTP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = sw.readVia(context.Background(), "get_ports", func(r BackendReader) error {
		_, err := r.GetPorts(context.Background())
		return err
	})
	if err != nil {
		t.Fatalf("readVia() error = %v, want nil (NSDP should have served it)", err)
	}
}

func TestReadVia_SkipAndReraiseLast(t *testing.T) {
	clearBackendRegistry(t)
	snmpErr := fmt.Errorf("model %q has no SNMP backend: %w", "fake", model.ErrUnsupportedCapability)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return nil, snmpErr
	})
	withRegisteredBackend(t, model.BackendNSDP, func(_ *Switch) (BackendReader, error) {
		return &fakeReader{getPortsErr: fmt.Errorf("nsdp has no get_ports: %w", model.ErrUnsupportedCapability)}, nil
	})

	m := fakeModel("fake", model.BackendSNMP, model.BackendNSDP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = sw.readVia(context.Background(), "get_ports", func(r BackendReader) error {
		_, err := r.GetPorts(context.Background())
		return err
	})
	if err == nil {
		t.Fatal("readVia() error = nil, want the last (NSDP) UnsupportedCapability error")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("readVia() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if !strings.Contains(err.Error(), "nsdp") {
		t.Fatalf("readVia() error = %q, want it to be the LAST (NSDP) error, not the first (SNMP)", err.Error())
	}
}

func TestReadVia_CredentialErrorPropagatesImmediately(t *testing.T) {
	clearBackendRegistry(t)
	credErr := fmt.Errorf("no SNMP write community configured: %w", model.ErrCredential)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return nil, credErr
	})
	nsdpCalled := false
	withRegisteredBackend(t, model.BackendNSDP, func(_ *Switch) (BackendReader, error) {
		nsdpCalled = true
		return &fakeReader{}, nil
	})

	m := fakeModel("fake", model.BackendSNMP, model.BackendNSDP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = sw.readVia(context.Background(), "get_ports", func(r BackendReader) error {
		_, err := r.GetPorts(context.Background())
		return err
	})
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("readVia() error = %v, want wrapping ErrCredential", err)
	}
	if nsdpCalled {
		t.Fatal("readVia() must abort the loop immediately on a non-UnsupportedCapability error, never try NSDP")
	}
}

func TestReadVia_OpCredentialErrorPropagatesImmediately(t *testing.T) {
	clearBackendRegistry(t)
	opCredErr := fmt.Errorf("op needs a credential: %w", model.ErrCredential)
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		return &fakeReader{getPortsErr: opCredErr}, nil
	})
	nsdpCalled := false
	withRegisteredBackend(t, model.BackendNSDP, func(_ *Switch) (BackendReader, error) {
		nsdpCalled = true
		return &fakeReader{}, nil
	})

	m := fakeModel("fake", model.BackendSNMP, model.BackendNSDP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = sw.readVia(context.Background(), "get_ports", func(r BackendReader) error {
		_, err := r.GetPorts(context.Background())
		return err
	})
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("readVia() error = %v, want wrapping ErrCredential", err)
	}
	if nsdpCalled {
		t.Fatal("readVia() must abort immediately when the op itself raises a non-UnsupportedCapability error")
	}
}

func TestReadVia_UnregisteredBackendTreatedAsUnsupported(t *testing.T) {
	clearBackendRegistry(t) // NSDP/HTTP: nothing registered, mirroring slice 03's reality

	m := fakeModel("gs110emx-like", model.BackendNSDP, model.BackendHTTP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = sw.readVia(context.Background(), "get_ports", func(r BackendReader) error {
		_, err := r.GetPorts(context.Background())
		return err
	})
	if err == nil {
		t.Fatal("readVia() error = nil, want ErrUnsupportedCapability for an unregistered backend")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("readVia() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	// http is the LAST backend tried (NSDP, then HTTP per backendPreference).
	if !strings.Contains(err.Error(), "http") {
		t.Fatalf("readVia() error = %q, want it to mention the last-tried unregistered backend (http)", err.Error())
	}
}

func TestReadVia_CancelledContextFailsFast(t *testing.T) {
	clearBackendRegistry(t)
	called := false
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		called = true
		return &fakeReader{}, nil
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = sw.readVia(ctx, "get_ports", func(r BackendReader) error {
		_, err := r.GetPorts(ctx)
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("readVia() error = %v, want wrapping context.Canceled", err)
	}
	if called {
		t.Fatal("readVia() must fail fast on an already-cancelled context, never build a backend")
	}
}

func TestReadVia_NoApplicableBackendRaisesFreshError(t *testing.T) {
	clearBackendRegistry(t)
	m := fakeModel("fake", model.BackendConsole) // not in backendPreference at all
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = sw.readVia(context.Background(), "get_ports", func(r BackendReader) error {
		_, err := r.GetPorts(context.Background())
		return err
	})
	if err == nil {
		t.Fatal("readVia() error = nil, want ErrUnsupportedCapability")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("readVia() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if !strings.Contains(err.Error(), "fake") {
		t.Fatalf("readVia() error = %q, want it to name the model", err.Error())
	}
}

func TestReadVia_ReaderCacheBuilderCalledOnce(t *testing.T) {
	clearBackendRegistry(t)
	var calls int
	var mu sync.Mutex
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return &fakeReader{}, nil
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := sw.readVia(context.Background(), "get_ports", func(r BackendReader) error {
			_, err := r.GetPorts(context.Background())
			return err
		}); err != nil {
			t.Fatalf("readVia() call %d error = %v", i, err)
		}
	}

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("builder called %d times, want exactly 1 (reader cache reuse)", got)
	}
}

func TestReadVia_GateFailureIsNeverCached(t *testing.T) {
	clearBackendRegistry(t)
	var calls int
	var mu sync.Mutex
	withRegisteredBackend(t, model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil, fmt.Errorf("gated off: %w", model.ErrUnsupportedCapability)
	})

	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for i := 0; i < 3; i++ {
		err := sw.readVia(context.Background(), "get_ports", func(r BackendReader) error {
			_, err := r.GetPorts(context.Background())
			return err
		})
		if !errors.Is(err, model.ErrUnsupportedCapability) {
			t.Fatalf("call %d: readVia() error = %v, want wrapping ErrUnsupportedCapability", i, err)
		}
	}

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 3 {
		t.Fatalf("builder called %d times, want exactly 3 (a gate failure must never be cached)", got)
	}
}

func TestReadVia_BackendOrderIsFixedNotModelOrder(t *testing.T) {
	clearBackendRegistry(t)
	var order []string
	record := func(name string) BackendBuilder {
		return func(_ *Switch) (BackendReader, error) {
			order = append(order, name)
			return nil, fmt.Errorf("%s unsupported: %w", name, model.ErrUnsupportedCapability)
		}
	}
	withRegisteredBackend(t, model.BackendHTTP, record("http"))
	withRegisteredBackend(t, model.BackendNSDP, record("nsdp"))
	withRegisteredBackend(t, model.BackendSNMP, record("snmp"))

	// Backends is deliberately listed HTTP, NSDP, SNMP (reverse of
	// backendPreference) to prove the dispatch order is NEVER derived from
	// the model's own Backends slice order.
	m := fakeModel("fake", model.BackendHTTP, model.BackendNSDP, model.BackendSNMP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_ = sw.readVia(context.Background(), "get_ports", func(r BackendReader) error {
		_, err := r.GetPorts(context.Background())
		return err
	})

	want := []string{"snmp", "nsdp", "http"}
	if len(order) != len(want) {
		t.Fatalf("build order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("build order = %v, want %v", order, want)
		}
	}
}

// --- RegisterBackend concurrency -----------------------------------------

func TestRegisterBackend_ConcurrentRegisterAndDispatch(t *testing.T) {
	clearBackendRegistry(t)
	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RegisterBackend(model.BackendSNMP, func(_ *Switch) (BackendReader, error) {
				return &fakeReader{}, nil
			})
		}()
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sw.readVia(context.Background(), "get_ports", func(r BackendReader) error {
				_, err := r.GetPorts(context.Background())
				return err
			})
		}()
	}
	wg.Wait()
}

// --- FromConfig field mapping ---------------------------------------------

func TestFromConfig_NeverResolvesSecretsOrDialsNetwork(t *testing.T) {
	community := "public"
	writeSpec := "${UNSET_WRITE_COMMUNITY_XYZ}" // deliberately unresolvable
	httpSpec := "${UNSET_HTTP_PASSWORD_XYZ}"
	nsdpIface := "eth0"
	m := fakeModel("fake", model.BackendSNMP)

	cfg := SwitchConfig{
		Name:                   "sw1",
		Model:                  m,
		Host:                   "10.0.0.5",
		SNMPCommunity:          &community,
		SNMPWriteCommunitySpec: &writeSpec,
		HTTPPasswordSpec:       &httpSpec,
		NSDPInterface:          &nsdpIface,
		ProtectedPorts:         []int{3, 1, 2},
	}

	sw, err := FromConfig(cfg)
	if err != nil {
		t.Fatalf("FromConfig() error = %v, want nil (must not resolve unset env vars at construction)", err)
	}

	if sw.model != m {
		t.Fatalf("model = %v, want %v", sw.model, m)
	}
	if sw.host != cfg.Host {
		t.Fatalf("host = %q, want %q", sw.host, cfg.Host)
	}
	if sw.snmpCommunity == nil || *sw.snmpCommunity != community {
		t.Fatalf("snmpCommunity = %v, want %q", sw.snmpCommunity, community)
	}
	if sw.nsdpInterface == nil || *sw.nsdpInterface != nsdpIface {
		t.Fatalf("nsdpInterface = %v, want %q", sw.nsdpInterface, nsdpIface)
	}
	want := []int{1, 2, 3}
	if !intSlicesEqual(sw.protectedPorts, want) {
		t.Fatalf("protectedPorts = %v, want %v", sw.protectedPorts, want)
	}

	// Resolvers must exist but must be lazy: resolving now (first use) is
	// where an unresolvable ${...} spec is allowed to raise.
	if sw.snmpWriteCommunity == nil {
		t.Fatal("snmpWriteCommunity resolver cell not wired by FromConfig")
	}
	if _, err := sw.snmpWriteCommunity.resolve(); !errors.Is(err, model.ErrCredential) {
		t.Fatalf("resolving write-community spec = %v, want wrapping ErrCredential (only on first USE, not construction)", err)
	}
	if sw.httpPassword == nil {
		t.Fatal("httpPassword resolver cell not wired by FromConfig")
	}
	if _, err := sw.httpPassword.resolve(); !errors.Is(err, model.ErrCredential) {
		t.Fatalf("resolving http-password spec = %v, want wrapping ErrCredential (only on first USE, not construction)", err)
	}
	// nsdpPassword is a SEPARATE cell FromConfig also wires (from the same
	// HTTPPasswordSpec, via its own independent closure -- see
	// TestFromConfig_FeedsBothPasswordCellsFromSameHTTPPasswordSpec).
	if sw.nsdpPassword == nil {
		t.Fatal("nsdpPassword resolver cell not wired by FromConfig")
	}
	if _, err := sw.nsdpPassword.resolve(); !errors.Is(err, model.ErrCredential) {
		t.Fatalf("resolving nsdp-password spec = %v, want wrapping ErrCredential (only on first USE, not construction)", err)
	}
}

// TestFromConfig_FeedsBothPasswordCellsFromSameHTTPPasswordSpec proves the
// D-NSDP §8.2 (corrected) contract directly: FromConfig wires nsdpPassword
// and httpPassword as TWO INDEPENDENT resolveOnce cells (mirroring Python's
// SyncSwitch.__init__ keeping nsdp_password_resolver/http_password_resolver
// as separate constructor params/cells), but both happen to read the SAME
// underlying cfg.HTTPPasswordSpec -- so a config-file user gets one shared
// password out of FromConfig, exactly like Python's from_config, even
// though the two cells never reference each other internally.
func TestFromConfig_FeedsBothPasswordCellsFromSameHTTPPasswordSpec(t *testing.T) {
	m := fakeModel("fake", model.BackendNSDP)
	literal := "s3cr3t"
	cfg := SwitchConfig{Model: m, Host: "10.0.0.5", HTTPPasswordSpec: &literal}

	sw, err := FromConfig(cfg)
	if err != nil {
		t.Fatalf("FromConfig() error = %v", err)
	}

	gotHTTP, err := sw.httpPassword.resolve()
	if err != nil {
		t.Fatalf("httpPassword.resolve() error = %v, want nil", err)
	}
	if gotHTTP == nil || *gotHTTP != literal {
		t.Fatalf("httpPassword.resolve() = %v, want %q", gotHTTP, literal)
	}

	gotNSDP, err := sw.nsdpPassword.resolve()
	if err != nil {
		t.Fatalf("nsdpPassword.resolve() error = %v, want nil", err)
	}
	if gotNSDP == nil || *gotNSDP != literal {
		t.Fatalf("nsdpPassword.resolve() = %v, want %q (same spec as httpPassword)", gotNSDP, literal)
	}
}

func TestFromConfig_WriteCommunityResolvesToLiteralOnFirstUse(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	literal := "s3cr3t"
	cfg := SwitchConfig{
		Model:                  m,
		Host:                   "10.0.0.5",
		SNMPWriteCommunitySpec: &literal,
	}
	sw, err := FromConfig(cfg)
	if err != nil {
		t.Fatalf("FromConfig() error = %v", err)
	}
	got, err := sw.snmpWriteCommunity.resolve()
	if err != nil {
		t.Fatalf("resolve() error = %v, want nil", err)
	}
	if got == nil || *got != literal {
		t.Fatalf("resolve() = %v, want %q", got, literal)
	}
}

func TestFromConfig_UnsetOptionalFieldsStayNil(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	cfg := SwitchConfig{Model: m, Host: "10.0.0.5"}
	sw, err := FromConfig(cfg)
	if err != nil {
		t.Fatalf("FromConfig() error = %v", err)
	}
	if sw.snmpCommunity != nil {
		t.Fatalf("snmpCommunity = %v, want nil (not set in config)", sw.snmpCommunity)
	}
	if sw.nsdpInterface != nil {
		t.Fatalf("nsdpInterface = %v, want nil (not set in config)", sw.nsdpInterface)
	}
	if len(sw.protectedPorts) != 0 {
		t.Fatalf("protectedPorts = %v, want empty", sw.protectedPorts)
	}
}

func TestFromConfig_ExtraOptionsOverrideConfigMapping(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	cfgCommunity := "from-config"
	cfg := SwitchConfig{Model: m, Host: "10.0.0.5", SNMPCommunity: &cfgCommunity}

	sw, err := FromConfig(cfg, WithSNMPCommunity("from-option"))
	if err != nil {
		t.Fatalf("FromConfig() error = %v", err)
	}
	if sw.snmpCommunity == nil || *sw.snmpCommunity != "from-option" {
		t.Fatalf("snmpCommunity = %v, want %q (trailing opts override config mapping)", sw.snmpCommunity, "from-option")
	}
}

// --- Close() ----------------------------------------------------------

func TestClose_IsSafeWithNoHTTPClientEverBuilt(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
}

// --- Model()/Host() accessors --------------------------------------------

func TestModelAndHost_ReturnConstructionValues(t *testing.T) {
	m := fakeModel("fake", model.BackendSNMP)
	sw, err := New(m, "10.0.0.1")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := sw.Model(); got != m {
		t.Fatalf("Model() = %v, want %v (the exact model New was given)", got, m)
	}
	if got := sw.Host(); got != "10.0.0.1" {
		t.Fatalf("Host() = %q, want %q", got, "10.0.0.1")
	}
}

// --- resolveOnce: lazy once-only secret resolution ------------------------

func TestResolveOnce_ResolverCalledExactlyOnce(t *testing.T) {
	var calls int
	val := "x"
	cell := newResolveOnce(func() (*string, error) {
		calls++
		return &val, nil
	})
	for i := 0; i < 3; i++ {
		got, err := cell.resolve()
		if err != nil {
			t.Fatalf("resolve() error = %v", err)
		}
		if got == nil || *got != val {
			t.Fatalf("resolve() = %v, want %q", got, val)
		}
	}
	if calls != 1 {
		t.Fatalf("resolver called %d times, want exactly 1", calls)
	}
}

func TestResolveOnce_NilResultIsCached(t *testing.T) {
	var calls int
	cell := newResolveOnce(func() (*string, error) {
		calls++
		return nil, nil
	})
	for i := 0; i < 2; i++ {
		got, err := cell.resolve()
		if err != nil || got != nil {
			t.Fatalf("resolve() = (%v, %v), want (nil, nil)", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("resolver called %d times, want exactly 1 (nil is still a cached result)", calls)
	}
}

func TestResolveOnce_RaisingResolverIsNotCached(t *testing.T) {
	var calls int
	cell := newResolveOnce(func() (*string, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("boom")
		}
		v := "ok"
		return &v, nil
	})
	if _, err := cell.resolve(); err == nil {
		t.Fatal("first resolve() error = nil, want the resolver's error")
	}
	got, err := cell.resolve()
	if err != nil {
		t.Fatalf("second resolve() error = %v, want nil (a raising resolver must be retried)", err)
	}
	if got == nil || *got != "ok" {
		t.Fatalf("second resolve() = %v, want %q", got, "ok")
	}
	if calls != 2 {
		t.Fatalf("resolver called %d times, want exactly 2", calls)
	}
}

func TestResolveOnce_NilResolverResolvesToNil(t *testing.T) {
	cell := newResolveOnce(nil)
	got, err := cell.resolve()
	if err != nil || got != nil {
		t.Fatalf("resolve() = (%v, %v), want (nil, nil)", got, err)
	}
}
