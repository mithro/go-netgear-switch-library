package virtual

// Tests for VirtualSwitch (server.go): construction/model-resolution,
// lifecycle (Start/Stop), and the GoFakeProvider EndpointProvider seam.
// See D-VIRT §5/§6 and Task 13's brief for the intents this mirrors.

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/nsdp"
	"github.com/mithro/go-netgear-switch-library/snmp"
	"github.com/mithro/go-netgear-switch-library/webui"
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

// TestVirtualSwitchWithPortPinsSNMPPort proves WithPort actually reaches
// the bound SNMP face (not just accepted-and-ignored, "cmd/gngsw-virtual"'s
// --port flag depends on this): start once with the default ephemeral port
// to discover a free one, stop, then start a second switch pinned to that
// exact port number and confirm it binds there -- and is actually live.
func TestVirtualSwitchWithPortPinsSNMPPort(t *testing.T) {
	probe, err := NewVirtualSwitch("gsm7252ps")
	if err != nil {
		t.Fatalf("NewVirtualSwitch error = %v", err)
	}
	if err := probe.Start(); err != nil {
		t.Fatalf("probe Start() error = %v", err)
	}
	free := probe.SnmpPort
	if err := probe.Stop(); err != nil {
		t.Fatalf("probe Stop() error = %v", err)
	}

	sw, err := NewVirtualSwitch("gsm7252ps", WithPort(free))
	if err != nil {
		t.Fatalf("NewVirtualSwitch error = %v", err)
	}
	if err := sw.Start(); err != nil {
		t.Fatalf("Start() with WithPort(%d) error = %v", free, err)
	}
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if sw.SnmpPort != free {
		t.Errorf("SnmpPort after Start() with WithPort(%d) = %d, want %d", free, sw.SnmpPort, free)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := snmp.NewGoSNMPClient(sw.Host+":"+strconv.Itoa(sw.SnmpPort), "public")
	if _, err := client.Get(ctx, []string{snmp.SysDescr}); err != nil {
		t.Errorf("GET against the pinned port failed: %v", err)
	}
}

// TestVirtualSwitchWithPortPinsNsdpPort is WithPort's NSDP-face analogue:
// gs305ep (Plus-class, NSDP+HTTP, no SNMP) binds its one UDP face --
// NsdpPort, not SnmpPort -- through the exact same requestedPort field
// (mirroring the Python reference's single shared self.port; see
// server.go's WithPort doc comment).
func TestVirtualSwitchWithPortPinsNsdpPort(t *testing.T) {
	probe, err := NewVirtualSwitch("gs305ep")
	if err != nil {
		t.Fatalf("NewVirtualSwitch error = %v", err)
	}
	if err := probe.Start(); err != nil {
		t.Fatalf("probe Start() error = %v", err)
	}
	free := probe.NsdpPort
	if err := probe.Stop(); err != nil {
		t.Fatalf("probe Stop() error = %v", err)
	}

	sw, err := NewVirtualSwitch("gs305ep", WithPort(free))
	if err != nil {
		t.Fatalf("NewVirtualSwitch error = %v", err)
	}
	if err := sw.Start(); err != nil {
		t.Fatalf("Start() with WithPort(%d) error = %v", free, err)
	}
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if sw.NsdpPort != free {
		t.Errorf("NsdpPort after Start() with WithPort(%d) = %d, want %d", free, sw.NsdpPort, free)
	}

	client, err := nsdp.NewUDPClient(sw.Host, nsdp.WithServerPort(sw.NsdpPort), nsdp.WithClientPort(0), nsdp.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("nsdp.NewUDPClient: %v", err)
	}
	pkt, err := client.Read(context.Background(), []nsdp.Tag{nsdp.TagModel})
	if err != nil {
		t.Fatalf("Read against the pinned NSDP port failed: %v", err)
	}
	dev, err := nsdp.ParseDevice(*pkt)
	if err != nil {
		t.Fatalf("ParseDevice: %v", err)
	}
	if dev.Model != "GS305EP" {
		t.Errorf("ParseDevice.Model = %q, want GS305EP", dev.Model)
	}
}

// TestVirtualSwitchWithHTTPPortPinsHTTPPort is WithPort's HTTP-face
// analogue for WithHTTPPort.
func TestVirtualSwitchWithHTTPPortPinsHTTPPort(t *testing.T) {
	probe, err := NewVirtualSwitch("gs305ep")
	if err != nil {
		t.Fatalf("NewVirtualSwitch error = %v", err)
	}
	if err := probe.Start(); err != nil {
		t.Fatalf("probe Start() error = %v", err)
	}
	free := probe.HTTPPort
	if err := probe.Stop(); err != nil {
		t.Fatalf("probe Stop() error = %v", err)
	}

	sw, err := NewVirtualSwitch("gs305ep", WithHTTPPort(free))
	if err != nil {
		t.Fatalf("NewVirtualSwitch error = %v", err)
	}
	if err := sw.Start(); err != nil {
		t.Fatalf("Start() with WithHTTPPort(%d) error = %v", free, err)
	}
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	if sw.HTTPPort != free {
		t.Errorf("HTTPPort after Start() with WithHTTPPort(%d) = %d, want %d", free, sw.HTTPPort, free)
	}
}

// TestVirtualSwitchStartRollsBackPartiallyBoundFacesOnFailure proves a
// later face's bind failure unwinds every EARLIER face this Start() call
// already bound, rather than leaking its socket and serve goroutine --
// reachable from cmd/gngsw-virtual whenever --port and --http-port
// (WithPort/WithHTTPPort here) pin two faces and one of the two addresses
// is already taken: Start binds SNMP first (pinned to a port this test
// knows is free), THEN fails binding HTTP (pinned to a port this test has
// deliberately pre-occupied) -- before this fix, Start returned the error
// with the SNMP face still bound, listening, and serving forever.
func TestVirtualSwitchStartRollsBackPartiallyBoundFacesOnFailure(t *testing.T) {
	// A UDP port this test knows is free right now (closed immediately, so
	// Start can bind it -- and, after the rollback this test is proving,
	// re-bind it again).
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("discovering a free UDP port: %v", err)
	}
	snmpPort := probe.LocalAddr().(*net.UDPAddr).Port //nolint:forcetypeassert // net.ListenUDP("udp", ...) always returns a *net.UDPAddr from LocalAddr().
	if err := probe.Close(); err != nil {
		t.Fatalf("closing the probe UDP socket: %v", err)
	}

	// A TCP port this test occupies for the whole test, so HTTP's own bind
	// genuinely fails (a real "address already in use", not a fabricated
	// error).
	occupied, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("occupying a TCP port: %v", err)
	}
	defer func() { _ = occupied.Close() }()
	occupiedPort := occupied.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // net.ListenTCP("tcp", ...) always returns a *net.TCPAddr from Addr().

	before := runtime.NumGoroutine()

	// gsm7252ps binds SNMP before HTTP (Start's own fixed SNMP->NSDP->HTTP->
	// SSH->Telnet order), so this reliably exercises "SNMP already bound,
	// HTTP's bind is what fails".
	sw, err := NewVirtualSwitch("gsm7252ps", WithPort(snmpPort), WithHTTPPort(occupiedPort))
	if err != nil {
		t.Fatalf("NewVirtualSwitch error = %v", err)
	}
	if err := sw.Start(); err == nil {
		t.Fatal("Start() with a colliding --http-port succeeded, want an error")
	}
	if sw.SnmpPort != 0 || sw.HTTPPort != 0 {
		t.Errorf("ports after a failed Start() = snmp:%d http:%d, want 0/0 (rolled back)", sw.SnmpPort, sw.HTTPPort)
	}

	// The SNMP port Start bound and then had to unwind must be genuinely
	// released -- proven by successfully re-binding it ourselves, not just
	// trusting the zeroed field.
	relisten, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: snmpPort})
	if err != nil {
		t.Errorf("SNMP port %d not released after a failed Start(): %v", snmpPort, err)
	} else {
		_ = relisten.Close()
	}

	// A second Stop() after Start's own self-cleaning rollback must remain
	// a harmless no-op.
	if err := sw.Stop(); err != nil {
		t.Errorf("Stop() after a failed Start() error = %v, want nil (already clean)", err)
	}

	for i := 0; i < 50; i++ {
		if runtime.NumGoroutine() <= before {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutine count after a failed partial Start() = %d, want <= %d (baseline; no leaked serve goroutine)", after, before)
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

// TestGoFakeProviderStartModelReturnsLiveSSHAndTelnetEndpoints proves
// Endpoints.SSHPort/Endpoints.TelnetPort mirror VirtualSwitch.SSHPort/
// TelnetPort through the provider seam (this slice's Endpoints extension):
// m4300-24x (registry backends {SNMP, HTTP, SSH, Telnet}) comes back with
// BOTH a nonzero, LIVE SSHPort and a nonzero, LIVE TelnetPort, while
// gsm7228ps (registry backends {SNMP, HTTP, Telnet} -- no SSH; the real
// S3300 genuinely runs no ssh listener on any port, see model/registry.go's
// own doc comment) comes back with SSHPort == 0 and only TelnetPort live --
// the same "0 means this provider doesn't serve that backend" contract
// SnmpPort/NsdpPort already establish, extended to the two fields this
// slice adds.
func TestGoFakeProviderStartModelReturnsLiveSSHAndTelnetEndpoints(t *testing.T) {
	p := &GoFakeProvider{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ep, err := p.StartModel(ctx, "m4300-24x")
	if err != nil {
		t.Fatalf("StartModel(m4300-24x) error = %v", err)
	}
	if ep.SSHPort == 0 {
		t.Fatal("Endpoints.SSHPort = 0, want nonzero bound port (m4300-24x has BackendSSH)")
	}
	if ep.TelnetPort == 0 {
		t.Fatal("Endpoints.TelnetPort = 0, want nonzero bound port (m4300-24x has BackendTelnet)")
	}
	assertTCPPortLive(t, ep.Host, ep.SSHPort)
	assertTCPPortLive(t, ep.Host, ep.TelnetPort)

	ep2, err := p.StartModel(ctx, "gsm7228ps")
	if err != nil {
		t.Fatalf("StartModel(gsm7228ps) error = %v", err)
	}
	if ep2.SSHPort != 0 {
		t.Errorf("Endpoints.SSHPort = %d, want 0 (gsm7228ps has no BackendSSH -- real S3300 hardware, measured absent)", ep2.SSHPort)
	}
	if ep2.TelnetPort == 0 {
		t.Fatal("Endpoints.TelnetPort = 0, want nonzero bound port (gsm7228ps has BackendTelnet)")
	}
	assertTCPPortLive(t, ep2.Host, ep2.TelnetPort)

	if err := p.CloseAll(); err != nil {
		t.Errorf("CloseAll() error = %v", err)
	}
}

// assertTCPPortLive dials host:port over TCP and immediately closes the
// connection, proving a real listener is bound there -- not merely that the
// Endpoints field holds a nonzero int.
func assertTCPPortLive(t *testing.T, host string, port int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Errorf("net.DialTimeout(%s:%d) error = %v, want a live listener", host, port, err)
		return
	}
	_ = conn.Close()
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

// TestVirtualSwitchConcurrentFacesRaceFree is the positive proof State.mu
// actually closes the gap [FIXA-RACE] found: gsm7252ps binds FOUR backends
// at once (SNMP, HTTP, SSH, Telnet -- registry.go), all sharing this ONE
// *State, each on its own real goroutine (SnmpFace.serve, HTTPFace's
// goroutine-per-request via net/http, SSHFace/TelnetFace's
// goroutine-per-session). This drives a REAL, sustained write storm over
// SNMP concurrently with a REAL, sustained read storm over HTTP -- genuine
// concurrent traffic on two DIFFERENT backends against the SAME State, not
// two sequential calls a test happens to interleave -- and must be clean
// under `go test -race`. It is not a proof of any particular final value
// (the writer and reader race each other by design; whichever admin state
// the reader observes at any given moment is a legitimate value), only that
// observing it is never a DATA race.
func TestVirtualSwitchConcurrentFacesRaceFree(t *testing.T) {
	sw := startVirtualSwitch(t, "gsm7252ps")
	m, err := model.GetModel("gsm7252ps")
	if err != nil {
		t.Fatalf("model.GetModel: %v", err)
	}
	spec, err := webui.HTTPSpec(m)
	if err != nil {
		t.Fatalf("webui.HTTPSpec: %v", err)
	}

	const iterations = 40
	var wg sync.WaitGroup
	errs := make(chan error, 2*iterations)

	// Writer goroutine: real SNMP SET traffic, toggling port 1's admin
	// state back and forth -- SnmpFace.serve's goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		snmpClient := snmp.NewGoSNMPClient(sw.Host+":"+strconv.Itoa(sw.SnmpPort), "public")
		writer, err := snmp.NewWriter(snmpClient, m)
		if err != nil {
			errs <- err
			return
		}
		ctx := context.Background()
		for i := 0; i < iterations; i++ {
			if err := writer.SetPortEnabled(ctx, 1, i%2 == 0, false); err != nil {
				errs <- err
				return
			}
		}
	}()

	// Reader goroutine: real HTTP GET traffic, concurrently -- HTTPFace's
	// own goroutine(s), a COMPLETELY DIFFERENT face/protocol from the
	// writer above, both touching the SAME *State (sw.State).
	wg.Add(1)
	go func() {
		defer wg.Done()
		httpClient := webui.NewHTTPClient(sw.Host+":"+strconv.Itoa(sw.HTTPPort), "password", spec)
		reader, err := webui.NewReader(httpClient, m)
		if err != nil {
			errs <- err
			return
		}
		ctx := context.Background()
		for i := 0; i < iterations; i++ {
			if _, err := reader.GetPorts(ctx); err != nil {
				errs <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent SNMP-write/HTTP-read traffic: %v", err)
	}
}
