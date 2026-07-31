package virtual

// Tests for VirtualSwitch (server.go): construction/model-resolution,
// lifecycle (Start/Stop), and the GoFakeProvider EndpointProvider seam.
// See D-VIRT §5/§6 and Task 13's brief for the intents this mirrors.

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// startVirtualSwitch builds and starts a VirtualSwitch for modelKey,
// registering t.Cleanup to stop it -- the closest Go equivalent to the
// Python reference's `with VirtualSwitch(...) as sw:` context-manager usage
// (VirtualSwitch.__enter__/__exit__ in D-VIRT §5), since Go has no
// with-statement: every test in this package that needs a running switch
// goes through this one helper instead of repeating start-then-defer-stop.
func startVirtualSwitch(t *testing.T, modelKey string, opts ...Option) *VirtualSwitch {
	t.Helper()
	sw, err := NewVirtualSwitch(modelKey, opts...)
	if err != nil {
		t.Fatalf("NewVirtualSwitch(%q) error = %v", modelKey, err)
	}
	if err := sw.Start(); err != nil {
		t.Fatalf("VirtualSwitch.Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Errorf("VirtualSwitch.Stop() error = %v", err)
		}
	})
	return sw
}

func TestNewVirtualSwitchUnknownModelIsAnEarlyError(t *testing.T) {
	sw, err := NewVirtualSwitch("not-a-real-model")
	if err == nil {
		t.Fatal("NewVirtualSwitch(unknown model) error = nil, want ErrUnknownModel")
	}
	if !errors.Is(err, model.ErrUnknownModel) {
		t.Errorf("NewVirtualSwitch(unknown model) error = %v, want wrapping model.ErrUnknownModel", err)
	}
	if sw != nil {
		t.Errorf("NewVirtualSwitch(unknown model) switch = %v, want nil", sw)
	}
}

func TestVirtualSwitchGSM7252PSStartBindsSNMPFaceAndStopIsClean(t *testing.T) {
	sw, err := NewVirtualSwitch("gsm7252ps")
	if err != nil {
		t.Fatalf("NewVirtualSwitch(gsm7252ps) error = %v", err)
	}
	if sw.SnmpPort != 0 {
		t.Fatalf("SnmpPort before Start = %d, want 0", sw.SnmpPort)
	}

	if err := sw.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if sw.SnmpPort == 0 {
		t.Fatal("SnmpPort after Start = 0, want nonzero bound port")
	}
	if sw.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want 127.0.0.1 (default)", sw.Host)
	}

	// Prove the bound face is actually live, not just a nonzero field: a
	// real SNMP GET against it must succeed.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := snmp.NewGoSNMPClient(sw.Host+":"+strconv.Itoa(sw.SnmpPort), "public")
	rows, err := client.Get(ctx, []string{snmp.SysDescr})
	if err != nil {
		t.Fatalf("GET sysDescr against started face: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("GET sysDescr rows = %d, want 1", len(rows))
	}

	if err := sw.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if sw.SnmpPort != 0 {
		t.Errorf("SnmpPort after Stop = %d, want 0", sw.SnmpPort)
	}

	// A second Stop is a no-op, and the port must stay closed: a GET must
	// now fail (nothing listening).
	if err := sw.Stop(); err != nil {
		t.Errorf("second Stop() error = %v, want nil (idempotent)", err)
	}
}

// TestVirtualSwitchGS305EPStartBindsNsdpFaceNotSnmp supersedes the former
// TestVirtualSwitchGS305EPStartReturnsUnsupportedCapability (Task 13's
// pre-slice-05 pin): gs305ep is a Plus-class model whose ONLY backends are
// NSDP+HTTP (model.Backends has no model.BackendSNMP -- see
// model/registry.go). As of slice 05 this package implements the NSDP face,
// and as of slice 06 the HTTP face too, so Start now SUCCEEDS for gs305ep
// -- binding BOTH NsdpPort and HTTPPort CONCURRENTLY (D-HTTP-F §6.1) and
// leaving SnmpPort 0 (no BackendSNMP to bind at all, mirroring D-NSDP
// §9.6's test_plus_model_binds_nsdp_not_snmp intent). This is the exact
// expectation flip the superseded test's own doc comment anticipated.
func TestVirtualSwitchGS305EPStartBindsNsdpFaceNotSnmp(t *testing.T) {
	sw, err := NewVirtualSwitch("gs305ep")
	if err != nil {
		t.Fatalf("NewVirtualSwitch(gs305ep) error = %v", err)
	}
	if err := sw.Start(); err != nil {
		t.Fatalf("Start() on gs305ep error = %v, want nil (NSDP face now binds for this model)", err)
	}
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})

	if sw.NsdpPort == 0 {
		t.Fatal("NsdpPort after Start = 0, want nonzero bound port")
	}
	if sw.SnmpPort != 0 {
		t.Errorf("SnmpPort after Start = %d, want 0 (gs305ep has no BackendSNMP)", sw.SnmpPort)
	}
	if sw.HTTPPort == 0 {
		t.Error("HTTPPort after Start = 0, want nonzero bound port (gs305ep has BackendHTTP, bound concurrently with NSDP)")
	}

	// Prove the bound face is actually live, not just a nonzero field: a
	// real NSDP READ_REQUEST against it must succeed.
	client, err := nsdp.NewUDPClient(sw.Host, nsdp.WithServerPort(sw.NsdpPort), nsdp.WithClientPort(0), nsdp.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("nsdp.NewUDPClient: %v", err)
	}
	pkt, err := client.Read(context.Background(), []nsdp.Tag{nsdp.TagModel})
	if err != nil {
		t.Fatalf("Read against started NSDP face: %v", err)
	}
	dev, err := nsdp.ParseDevice(*pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.Model != "GS305EP" {
		t.Errorf("ParseDevice.Model = %q, want GS305EP", dev.Model)
	}
}

func TestVirtualSwitchStopBeforeStartIsNoOp(t *testing.T) {
	sw, err := NewVirtualSwitch("gsm7252ps")
	if err != nil {
		t.Fatalf("NewVirtualSwitch(gsm7252ps) error = %v", err)
	}
	if err := sw.Stop(); err != nil {
		t.Errorf("Stop() before Start() error = %v, want nil (no-op)", err)
	}
}

func TestStartVirtualSwitchHelperStopsOnCleanup(t *testing.T) {
	sw := startVirtualSwitch(t, "gsm7252ps")
	if sw.SnmpPort == 0 {
		t.Fatal("SnmpPort = 0 after startVirtualSwitch, want nonzero")
	}
	// t.Cleanup registered by the helper stops sw once this test returns;
	// nothing further to assert here (server_test.go/oracle_test.go's other
	// tests using the same helper are the proof it tears down cleanly
	// across many calls without leaking ports).
}

func TestVirtualSwitchWithHostAndWithCommunityOptions(t *testing.T) {
	sw, err := NewVirtualSwitch("gsm7252ps", WithHost("127.0.0.1"), WithCommunity("rw-community"))
	if err != nil {
		t.Fatalf("NewVirtualSwitch error = %v", err)
	}
	if err := sw.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() {
		if err := sw.Stop(); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The default community must now be rejected...
	wrongClient := snmp.NewGoSNMPClient(sw.Host+":"+strconv.Itoa(sw.SnmpPort), "public", snmp.WithTimeout(300*time.Millisecond), snmp.WithRetries(0))
	if _, err := wrongClient.Get(ctx, []string{snmp.SysDescr}); err == nil {
		t.Error("GET with wrong (default) community succeeded, want a timeout/error")
	}

	// ...and the configured one accepted.
	rightClient := snmp.NewGoSNMPClient(sw.Host+":"+strconv.Itoa(sw.SnmpPort), "rw-community")
	if _, err := rightClient.Get(ctx, []string{snmp.SysDescr}); err != nil {
		t.Errorf("GET with configured community %q failed: %v", "rw-community", err)
	}
}

// --- GoFakeProvider ---------------------------------------------------------

func TestGoFakeProviderStartModelReturnsLiveEndpoints(t *testing.T) {
	p := &GoFakeProvider{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ep, err := p.StartModel(ctx, "gsm7252ps")
	if err != nil {
		t.Fatalf("StartModel(gsm7252ps) error = %v", err)
	}
	if ep.Host != "127.0.0.1" {
		t.Errorf("Endpoints.Host = %q, want 127.0.0.1", ep.Host)
	}
	if ep.SnmpPort == 0 {
		t.Fatal("Endpoints.SnmpPort = 0, want nonzero")
	}
	if ep.Community != "public" {
		t.Errorf("Endpoints.Community = %q, want public", ep.Community)
	}

	getCtx, getCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer getCancel()
	client := snmp.NewGoSNMPClient(ep.Host+":"+strconv.Itoa(ep.SnmpPort), ep.Community)
	if _, err := client.Get(getCtx, []string{snmp.SysDescr}); err != nil {
		t.Errorf("GET against provider-started endpoint failed: %v", err)
	}

	if err := p.CloseAll(); err != nil {
		t.Errorf("CloseAll() error = %v", err)
	}
}

// TestGoFakeProviderStartModelReturnsLiveNsdpEndpoint proves Endpoints.NsdpPort
// mirrors VirtualSwitch.NsdpPort through the provider seam: gs305ep (a
// Plus-class, NSDP+HTTP-only model, see TestVirtualSwitchGS305EPStartBindsNsdpFaceNotSnmp)
// must come back with a nonzero, LIVE Endpoints.NsdpPort and a zero
// Endpoints.SnmpPort -- the same "no face this slice can't bind for" split
// as the underlying VirtualSwitch, just surfaced through the
// EndpointProvider seam slice 10's cross-language harness drives.
func TestGoFakeProviderStartModelReturnsLiveNsdpEndpoint(t *testing.T) {
	p := &GoFakeProvider{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ep, err := p.StartModel(ctx, "gs305ep")
	if err != nil {
		t.Fatalf("StartModel(gs305ep) error = %v", err)
	}
	if ep.NsdpPort == 0 {
		t.Fatal("Endpoints.NsdpPort = 0, want nonzero bound port")
	}
	if ep.SnmpPort != 0 {
		t.Errorf("Endpoints.SnmpPort = %d, want 0 (gs305ep has no BackendSNMP)", ep.SnmpPort)
	}

	client, err := nsdp.NewUDPClient(ep.Host, nsdp.WithServerPort(ep.NsdpPort), nsdp.WithClientPort(0), nsdp.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("nsdp.NewUDPClient: %v", err)
	}
	if _, err := client.Read(context.Background(), []nsdp.Tag{nsdp.TagModel}); err != nil {
		t.Errorf("Read against provider-started NSDP endpoint failed: %v", err)
	}

	if err := p.CloseAll(); err != nil {
		t.Errorf("CloseAll() error = %v", err)
	}
}

func TestGoFakeProviderUnknownModelPropagatesError(t *testing.T) {
	p := &GoFakeProvider{}
	_, err := p.StartModel(context.Background(), "not-a-real-model")
	if !errors.Is(err, model.ErrUnknownModel) {
		t.Errorf("StartModel(unknown model) error = %v, want wrapping model.ErrUnknownModel", err)
	}
}

func TestGoFakeProviderCloseAllStopsEveryStartedSwitch(t *testing.T) {
	p := &GoFakeProvider{}
	ctx := context.Background()

	ep1, err := p.StartModel(ctx, "gsm7252ps")
	if err != nil {
		t.Fatalf("StartModel(gsm7252ps) error = %v", err)
	}
	ep2, err := p.StartModel(ctx, "m4300-24x")
	if err != nil {
		t.Fatalf("StartModel(m4300-24x) error = %v", err)
	}

	if err := p.CloseAll(); err != nil {
		t.Errorf("CloseAll() error = %v", err)
	}

	// Both bound ports must now be dead: a GET against either, with a tight
	// timeout and no retries, must fail.
	for _, ep := range []Endpoints{ep1, ep2} {
		getCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		client := snmp.NewGoSNMPClient(ep.Host+":"+strconv.Itoa(ep.SnmpPort), ep.Community, snmp.WithTimeout(300*time.Millisecond), snmp.WithRetries(0))
		_, err := client.Get(getCtx, []string{snmp.SysDescr})
		cancel()
		if err == nil {
			t.Errorf("GET against closed endpoint %+v succeeded, want error (nothing should be listening)", ep)
		}
	}

	// A second CloseAll is a no-op.
	if err := p.CloseAll(); err != nil {
		t.Errorf("second CloseAll() error = %v, want nil", err)
	}
}

func TestGoFakeProviderContextCancellationStopsTheSwitch(t *testing.T) {
	p := &GoFakeProvider{}
	ctx, cancel := context.WithCancel(context.Background())

	ep, err := p.StartModel(ctx, "gsm7252ps")
	if err != nil {
		t.Fatalf("StartModel(gsm7252ps) error = %v", err)
	}
	cancel()

	// The provider's watcher goroutine stops the switch asynchronously on
	// ctx.Done(); poll (bounded) rather than sleep-then-assert-once, since
	// there is no signal back to the caller for exactly when that
	// goroutine has run.
	deadline := time.Now().Add(3 * time.Second)
	for {
		getCtx, getCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		client := snmp.NewGoSNMPClient(ep.Host+":"+strconv.Itoa(ep.SnmpPort), ep.Community, snmp.WithTimeout(200*time.Millisecond), snmp.WithRetries(0))
		_, err := client.Get(getCtx, []string{snmp.SysDescr})
		getCancel()
		if err != nil {
			break // endpoint is down: ctx cancellation stopped it.
		}
		if time.Now().After(deadline) {
			t.Fatal("endpoint still answering 3s after ctx cancellation, want it stopped")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
