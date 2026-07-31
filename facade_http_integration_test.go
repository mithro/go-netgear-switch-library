// facade_http_integration_test.go: the slice-06 capstone -- the root
// netgearswitch facade's HTTP backend (backend_http.go) driven end-to-end
// against REAL virtual.VirtualSwitch instances over real TCP loopback,
// proving the facade's HTTP dispatch seam (dispatch.go/write_dispatch.go ->
// backend_http.go's buildHTTPReader/buildHTTPWriter -> webui.Reader/
// webui.Writer) is wired correctly on top of the already-capstoned webui
// package (see webui/reader_test.go, webui/writer_test.go and
// virtual/httpface_test.go, whose pinned seed values this file reuses) --
// never a vacuous pass. Per Task 11's brief and D-HTTP-F (docs/superpowers/
// plans/2026-07-31-slice-06-dossier-http-readwrite-face.md) §6-§7.
//
// Every model exercised here defaults to SNMP or NSDP (backendPreference:
// SNMP, NSDP, HTTP, SSH), so EVERY test below reaches HTTP via an EXPLICIT
// backend selection (WithReadBackend(BackendHTTP) / Write{Backend:
// &httpBackend}) -- this is itself part of what this file proves (D-REC
// A.2/A.3): a caller must ask for HTTP by name to get it, on every one of
// these models.
//
// package netgearswitch_test (external), same package as
// facade_integration_test.go/facade_nsdp_integration_test.go -- this file
// reuses those files' startVirtualSwitch/derefStr/derefInt/facadeTestTimeout
// helpers directly.
package netgearswitch_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/virtual"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// httpBackend is a package-level var (not const) purely so Write{Backend:
// &httpBackend}/WithReadBackend can take its address -- mirrors how
// resolveBackend/cannotServe (dispatch.go) distinguish "explicitly
// requested" from "this Switch's default" solely by whether a *Backend is
// nil, never by its value.
var httpBackend = netgearswitch.BackendHTTP

// httpFacadeFor constructs a *netgearswitch.Switch bound to modelKey,
// talking to vsw's live HTTP face over "host:port" with the password every
// VirtualSwitch's HTTP face defaults to ("password") -- the HTTP analogue
// of facade_nsdp_integration_test.go's nsdpFacadeFor. opts, if given, are
// applied AFTER the password default so a caller can override it (e.g. the
// wrong-password auth-failure test).
func httpFacadeFor(t *testing.T, vsw *virtual.VirtualSwitch, modelKey string, opts ...netgearswitch.SwitchOption) *netgearswitch.Switch {
	t.Helper()
	m, err := netgearswitch.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q) error = %v", modelKey, err)
	}
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.HTTPPort)
	base := []netgearswitch.SwitchOption{netgearswitch.WithHTTPPassword("password")}
	sw, err := netgearswitch.New(m, host, append(base, opts...)...)
	if err != nil {
		t.Fatalf("New(%q) error = %v", modelKey, err)
	}
	return sw
}

// overHTTP is the ReadOption every read call below passes -- every model
// this file exercises defaults to SNMP or NSDP, so an explicit override is
// REQUIRED to reach HTTP at all (see this file's own package doc comment).
func overHTTP() netgearswitch.ReadOption {
	return netgearswitch.WithReadBackend(netgearswitch.BackendHTTP)
}

// httpWrite builds a Write{} pinned to BackendHTTP, the write-side twin of
// overHTTP.
func httpWrite(force bool) netgearswitch.Write {
	return netgearswitch.Write{Backend: &httpBackend, Force: force}
}

// --- gs305ep (STANDARD dialect, backends {NSDP, HTTP}) ---------------------

// TestFacadeHTTPIntegration_GS305EPReadsNonVacuousAndPoEWriteRoundTrip proves
// every HTTP-servable read is non-vacuous against SeedGS305EP(), INCLUDING
// GetPoE/GetStats -- fields facade_nsdp_integration_test.go's own
// TestFacadeNSDPIntegration_GS305EPUnsupportedReadsRaise proved NSDP (this
// model's default backend) genuinely cannot serve at all. It then proves the
// SetPoE write actually reaches the switch and verifies -- again ONLY
// reachable via explicit backend=HTTP, since gs305ep's default (NSDP) has no
// PoE tag at all.
func TestFacadeHTTPIntegration_GS305EPReadsNonVacuousAndPoEWriteRoundTrip(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs305ep")
	sw := httpFacadeFor(t, vsw, "gs305ep")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	ports, err := sw.GetPorts(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != 5 {
		t.Fatalf("len(GetPorts()) = %d, want 5", len(ports))
	}
	for _, p := range ports {
		wantLink := p.Port == 1
		if p.LinkUp != wantLink {
			t.Errorf("port %d LinkUp = %v, want %v", p.Port, p.LinkUp, wantLink)
		}
	}

	stats, err := sw.GetStats(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}
	var port1Stats *netgearswitch.PortStats
	for i := range stats {
		if stats[i].Port == 1 {
			port1Stats = &stats[i]
		}
	}
	if port1Stats == nil || port1Stats.RxBytes == nil || *port1Stats.RxBytes != 1_000_000 {
		t.Errorf("port 1 RxBytes = %v, want 1000000", port1Stats)
	}

	vlans, err := sw.GetVLANs(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	vlan1 := findVlan(t, vlans, 1)
	if !equalIntSet(vlan1.MemberPorts, []int{1, 2, 3, 4, 5}) {
		t.Errorf("vlan 1 MemberPorts = %v, want {1..5}", vlan1.MemberPorts)
	}

	pvids, err := sw.GetPVIDs(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPVIDs() error = %v", err)
	}
	if len(pvids) != 5 {
		t.Fatalf("len(GetPVIDs()) = %d, want 5", len(pvids))
	}

	// GetPoE: the field NSDP genuinely cannot serve for this model at all
	// (see facade_nsdp_integration_test.go's GS305EPUnsupportedReadsRaise).
	poe, err := sw.GetPoE(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPoE() error = %v, want nil (HTTP genuinely serves PoE on gs305ep)", err)
	}
	var port1PoE, port4PoE *netgearswitch.PoEStatus
	for i := range poe {
		switch poe[i].Port {
		case 1:
			port1PoE = &poe[i]
		case 4:
			port4PoE = &poe[i]
		}
	}
	if port1PoE == nil || !port1PoE.AdminEnabled {
		t.Errorf("port 1 PoE AdminEnabled = %v, want true", port1PoE)
	}
	if port4PoE == nil || port4PoE.AdminEnabled {
		t.Errorf("port 4 PoE AdminEnabled = %v, want false", port4PoE)
	}

	// SetPoE round trip: default backend (NSDP) has no PoE tag, so this
	// MUST use explicit backend=HTTP to succeed at all.
	if err := sw.SetPoE(ctx, 2, false, httpWrite(false)); err != nil {
		t.Fatalf("SetPoE(port=2, false, backend=HTTP) error = %v", err)
	}
	poeAfter, err := sw.GetPoE(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPoE() after SetPoE error = %v", err)
	}
	for _, p := range poeAfter {
		if p.Port == 2 && p.AdminEnabled {
			t.Error("port 2 PoE AdminEnabled after SetPoE(false) = true, want false")
		}
	}
}

// TestFacadeHTTPIntegration_GS305EPUnsupportedHTTPOpsRaise proves ops
// gs305ep's own HTTPModelSpec genuinely has no page for (no PortConfigPath,
// no MgmtIPPath/SysinfoPath) raise ErrUnsupportedCapability over HTTP,
// honestly, rather than a fabricated result.
func TestFacadeHTTPIntegration_GS305EPUnsupportedHTTPOpsRaise(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs305ep")
	sw := httpFacadeFor(t, vsw, "gs305ep")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	if _, err := sw.GetMgmtIP(ctx, overHTTP()); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetMgmtIP() error = %v, want wrapping ErrUnsupportedCapability (gs305ep has no mgmt-IP page)", err)
	}
	err := sw.SetPortEnabled(ctx, 1, false, httpWrite(false))
	if !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("SetPortEnabled() error = %v, want wrapping ErrUnsupportedCapability (gs305ep has no port-configuration page)", err)
	}
	// PRINCIPLE-1: the error must name the REQUESTED backend (http), never
	// silently fall back to (or even mention succeeding via) NSDP.
	if !strings.Contains(err.Error(), "http") {
		t.Errorf("SetPortEnabled() error = %q, want it to name the requested backend http", err.Error())
	}
}

// --- gs110emx (GAMBIT dialect, backends {NSDP, HTTP}) -----------------------

// TestFacadeHTTPIntegration_GS110EMXReadsNonVacuousAndSetPortEnabledRoundTrip
// proves GetPorts' port-8 row differs genuinely from what
// facade_nsdp_integration_test.go pinned for the SAME seed over NSDP (Name
// "g8", never populated with the seed's Description at all): gs110emx's
// port_settings.html renders its "description" into the SAME visual column
// webui.ParseGS110EMXPortStatus maps onto Name (this dialect's parser never
// populates PortStatus.Description at all), so over HTTP port 8's Name
// becomes "rumpus", overwriting NSDP's "g8" -- proving HTTP is genuinely
// being used, not merely a relabelled NSDP result. It also proves
// SetPortEnabled reaches gs110emx's own port_settings.html mechanism (a
// genuinely different write path from the FASTPATH grid) and verifies.
func TestFacadeHTTPIntegration_GS110EMXReadsNonVacuousAndSetPortEnabledRoundTrip(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs110emx")
	sw := httpFacadeFor(t, vsw, "gs110emx")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	ports, err := sw.GetPorts(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != 10 {
		t.Fatalf("len(GetPorts()) = %d, want 10", len(ports))
	}
	foundRumpus := false
	for _, p := range ports {
		if p.Port == 8 && p.Name != nil && *p.Name == "rumpus" {
			foundRumpus = true
		}
	}
	if !foundRumpus {
		t.Error("GetPorts() over HTTP: no port 8 with Name \"rumpus\" (NSDP always reports \"g8\" for this port; proves HTTP is genuinely being used)")
	}

	mgmt, err := sw.GetMgmtIP(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.25" {
		t.Errorf("GetMgmtIP().Address = %s, want 10.1.5.25", derefStr(mgmt.Address))
	}
	if mgmt.BaseMac == nil || *mgmt.BaseMac != "BC:A5:11:B8:EC:F1" {
		t.Errorf("GetMgmtIP().BaseMac = %s, want BC:A5:11:B8:EC:F1", derefStr(mgmt.BaseMac))
	}

	// SetPortEnabled: gs110emx's default backend is NSDP, which DOES
	// support port admin writes (facade_nsdp_integration_test.go doesn't
	// cover it, but nsdp.Writer does) -- the point of using explicit
	// backend=HTTP here is proving gs110emx's OWN write mechanism
	// (port_settings.html Physical Mode), not merely that some backend can
	// flip the bit.
	if err := sw.SetPortEnabled(ctx, 3, false, httpWrite(false)); err != nil {
		t.Fatalf("SetPortEnabled(port=3, false, backend=HTTP) error = %v", err)
	}
	after, err := sw.GetPorts(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPorts() after SetPortEnabled error = %v", err)
	}
	for _, p := range after {
		if p.Port == 3 && p.AdminEnabled {
			t.Error("port 3 AdminEnabled after SetPortEnabled(false) = true, want false")
		}
	}
}

// TestFacadeHTTPIntegration_GS110EMXUnsupportedHTTPOpsRaise proves the ops
// gs110emx's HTTPModelSpec genuinely has no page for (no PoE hardware at
// all, no MAC/FDB/LLDP page) raise ErrUnsupportedCapability over HTTP.
func TestFacadeHTTPIntegration_GS110EMXUnsupportedHTTPOpsRaise(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs110emx")
	sw := httpFacadeFor(t, vsw, "gs110emx")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	_, poeErr := sw.GetPoE(ctx, overHTTP())
	if !errors.Is(poeErr, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetPoE() error = %v, want wrapping ErrUnsupportedCapability (gs110emx has no PoE)", poeErr)
	}
	if !strings.Contains(poeErr.Error(), "http") {
		t.Errorf("GetPoE() error = %q, want it to name the requested backend http", poeErr.Error())
	}
	if _, err := sw.GetMACs(ctx); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		// GetMACs is gated at the facade level BEFORE dispatch (no SNMP
		// backend at all -- HasMACTable false) regardless of requested
		// backend; included here for completeness of "unsupported ops".
		t.Errorf("GetMACs() error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if _, err := sw.GetLLDP(ctx, overHTTP()); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetLLDP() error = %v, want wrapping ErrUnsupportedCapability (gs110emx has no LLDP page)", err)
	}
	if _, err := sw.GetSensors(ctx, overHTTP()); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetSensors() error = %v, want wrapping ErrUnsupportedCapability (GS110EMX dialect has no sensor table)", err)
	}
}

// --- m4300-24x (CHEETAH_V1 dialect, backends {SNMP, HTTP, SSH, Telnet}) -----

// TestFacadeHTTPIntegration_M430024XReadsNonVacuousAndSetPortEnabledRoundTrip
// proves box sensors/MAC-FDB/LLDP (all served by SNMP too, but pinned here
// via HTTP specifically) are non-vacuous vs SeedM4300_24X(), and that
// SetPortEnabled reaches the FASTPATH XUI grid and verifies.
func TestFacadeHTTPIntegration_M430024XReadsNonVacuousAndSetPortEnabledRoundTrip(t *testing.T) {
	vsw := startVirtualSwitch(t, "m4300-24x")
	sw := httpFacadeFor(t, vsw, "m4300-24x")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	// M4300's own sysInfo.html web page carries ONLY the temperature
	// reading (RenderM4300Sysinfo emits no fan/power rows at all -- those
	// are SNMP-only on this dialect); the seed's single ASCII-digit
	// temperature entry (49C) is the one non-vacuous value to pin here.
	sensors, err := sw.GetSensors(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetSensors() error = %v", err)
	}
	if len(sensors) != 1 || sensors[0].Kind != "temperature" || sensors[0].Value != 49 {
		t.Errorf("GetSensors() = %+v, want exactly one temperature reading of 49", sensors)
	}

	macs, err := sw.GetMACs(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetMACs() error = %v", err)
	}
	if len(macs) != 3 {
		t.Errorf("len(GetMACs()) = %d, want 3", len(macs))
	}

	lldp, err := sw.GetLLDP(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetLLDP() error = %v", err)
	}
	foundKraken := false
	for _, n := range lldp {
		if n.RemoteSysName != nil && *n.RemoteSysName == "rpi-sdr-kraken" {
			foundKraken = true
		}
	}
	if !foundKraken {
		t.Error("GetLLDP() over HTTP: no neighbor RemoteSysName \"rpi-sdr-kraken\"")
	}

	// SetPortEnabled round trip via the FASTPATH XUI grid, mirroring
	// virtual/httpface_test.go's TestHTTPFaceM4300WriterSetPortEnabledRoundTrip
	// at the facade layer instead. Port 1's link is up in the seed but its
	// admin state is what's flipped; toggle it back afterward so this test
	// leaves the VirtualSwitch's in-memory state as it found it (no shared
	// fixture across tests in this file, but tidy regardless).
	before, err := sw.GetPorts(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	var wasEnabled bool
	for _, p := range before {
		if p.Port == 1 {
			wasEnabled = p.AdminEnabled
		}
	}
	target := !wasEnabled
	if err := sw.SetPortEnabled(ctx, 1, target, httpWrite(false)); err != nil {
		t.Fatalf("SetPortEnabled(port=1, %v, backend=HTTP) error = %v", target, err)
	}
	after, err := sw.GetPorts(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPorts() after SetPortEnabled error = %v", err)
	}
	for _, p := range after {
		if p.Port == 1 && p.AdminEnabled != target {
			t.Errorf("port 1 AdminEnabled after SetPortEnabled(%v) = %v, want %v", target, p.AdminEnabled, target)
		}
	}
}

// TestFacadeHTTPIntegration_M430024XUnsupportedPoENamesOnlyItsOwnBackend is
// an end-to-end (real VirtualSwitch, real dispatch) companion to the
// PRINCIPLE-1 proofs elsewhere: m4300-24x genuinely has NO PoE hardware, so
// BOTH its default backend (SNMP) AND an explicit backend=HTTP request
// refuse GetPoE -- but for DIFFERENT reasons, and each error must name its
// OWN backend, never the other one's. This is an ERROR-TEXT check only (an
// op NEITHER backend can serve, so a hypothetical silent-fallback bug would
// still error here, just with the wrong wording) -- the two OUTCOME-based
// proofs that a fallback bug genuinely could not survive are
// TestPrincipleOne_ExplicitHTTPRequestNeverInvokesSNMPBuilder
// (backend_http_test.go: a builder-invocation SPY proves the SNMP builder
// is never even CALLED) and
// TestFacadeHTTPIntegration_ReadsVerifiedGateRefusesBeforeSessionUse (below:
// HTTP's gate fails on an op SNMP genuinely COULD serve, so a real fallback
// would silently SUCCEED via SNMP instead of erroring -- this test alone
// could not catch that class of bug, which is why the other two exist).
func TestFacadeHTTPIntegration_M430024XUnsupportedPoENamesOnlyItsOwnBackend(t *testing.T) {
	vsw := startVirtualSwitch(t, "m4300-24x")
	sw := httpFacadeFor(t, vsw, "m4300-24x")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	// Default backend: SNMP has no injected client/community configured on
	// this Switch at all, so resolve via explicit backend=SNMP is not what
	// we want here -- instead, confirm the model's OWN default resolves to
	// snmp (per backendPreference) via ResolveBackend, and separately prove
	// HTTP's explicit failure names http, not snmp.
	resolved, err := sw.ResolveBackend()
	if err != nil {
		t.Fatalf("ResolveBackend() error = %v", err)
	}
	if resolved != netgearswitch.BackendSNMP {
		t.Fatalf("ResolveBackend() = %v, want BackendSNMP (m4300-24x's default per backendPreference)", resolved)
	}

	_, httpErr := sw.GetPoE(ctx, overHTTP())
	if !errors.Is(httpErr, netgearswitch.ErrUnsupportedCapability) {
		t.Fatalf("GetPoE(backend=HTTP) error = %v, want wrapping ErrUnsupportedCapability (m4300-24x genuinely has no PoE page)", httpErr)
	}
	if !strings.Contains(httpErr.Error(), "http") {
		t.Errorf("GetPoE(backend=HTTP) error = %q, want it to name the requested backend http", httpErr.Error())
	}
	if strings.Contains(httpErr.Error(), "snmp") {
		t.Errorf("GetPoE(backend=HTTP) error = %q, must NOT mention snmp -- the explicit HTTP request must never be conflated with the default backend", httpErr.Error())
	}
}

// --- gsm7252ps (XE_FASTPATH dialect, backends {SNMP, HTTP, SSH, Telnet}) ---

// TestFacadeHTTPIntegration_GSM7252PSReadsNonVacuousAndPoEWriteRoundTrip
// proves box sensors + mgmt-IP are non-vacuous vs SeedGSM7252PS(), and that
// SetPoE reaches the gsm7252ps-specific XUI nav-field fix (the pin's
// namesake commit, D-HTTP-F §2.6) and verifies.
func TestFacadeHTTPIntegration_GSM7252PSReadsNonVacuousAndPoEWriteRoundTrip(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := httpFacadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	// gsm7252ps's HTTP sysInfo sensor set is its OWN (state.SysinfoSensors(),
	// distinct from the SNMP entity table), traced through
	// webui.ParseXESensors exactly: 5 temperature rows (System=29, CPU=49,
	// MAC="N/A" SKIPPED -- parseIntCell rejects non-numeric, MAC-A=32,
	// MAC-B=31 -> 4 kept) + 5 fan-health rows (Fan1/PWR/Fan2/CPU/Fan3/SYS=
	// "OK" kept, Fan4/Fan5="NA" SKIPPED by xeAbsentText -> 3 kept) + the
	// Device-Status table's RPS/Power Module rows ("Operational" kept,
	// filtered to exactly those two labels by xePowerRows -> 2 kept) = 9.
	sensors, err := sw.GetSensors(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetSensors() error = %v", err)
	}
	if len(sensors) != 9 {
		t.Fatalf("len(GetSensors()) = %d, want 9", len(sensors))
	}
	var foundCPUTemp, foundFan2, foundRPS bool
	for _, s := range sensors {
		switch {
		case s.Name == "CPU" && s.Kind == "temperature" && s.Value == 49:
			foundCPUTemp = true
		case s.Name == "Fan2/CPU" && s.Kind == "fan" && s.Value == 1:
			foundFan2 = true
		case s.Name == "RPS" && s.Kind == "power" && s.Value == 1:
			foundRPS = true
		}
	}
	if !foundCPUTemp {
		t.Error("GetSensors(): no CPU temperature reading of 49C")
	}
	if !foundFan2 {
		t.Error("GetSensors(): no healthy (1.0) Fan2/CPU fan-state reading")
	}
	if !foundRPS {
		t.Error("GetSensors(): no healthy (1.0) RPS power-state reading")
	}

	mgmt, err := sw.GetMgmtIP(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetMgmtIP() error = %v", err)
	}
	if mgmt.Address == nil || *mgmt.Address != "10.1.5.22" {
		t.Errorf("GetMgmtIP().Address = %s, want 10.1.5.22", derefStr(mgmt.Address))
	}

	poeBefore, err := sw.GetPoE(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPoE() error = %v", err)
	}
	var wasOn bool
	for _, p := range poeBefore {
		if p.Port == 1 {
			wasOn = p.AdminEnabled
		}
	}
	target := !wasOn
	// SetPoE: gsm7252ps's default backend is SNMP, which ALSO supports PoE
	// writes -- explicit backend=HTTP here specifically proves the
	// gsm7252ps XUI nav-field fix (urlListUnit), not merely "some backend
	// can toggle PoE".
	if err := sw.SetPoE(ctx, 1, target, httpWrite(false)); err != nil {
		t.Fatalf("SetPoE(port=1, %v, backend=HTTP) error = %v", target, err)
	}
	poeAfter, err := sw.GetPoE(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPoE() after SetPoE error = %v", err)
	}
	for _, p := range poeAfter {
		if p.Port == 1 && p.AdminEnabled != target {
			t.Errorf("port 1 PoE AdminEnabled after SetPoE(%v) = %v, want %v", target, p.AdminEnabled, target)
		}
	}
}

// TestFacadeHTTPIntegration_GSM7252PSVlanMembershipRoundTrip proves
// SetVlanMembership reaches the FASTPATH VLAN-Membership page (vlan_port_
// cfg_rw.html) -- the pin's headline read-side fix's write-side twin -- and
// verifies, mirroring virtual/httpface_test.go's
// TestHTTPFaceFastpathVlanMembershipRoundTrip at the facade layer.
func TestFacadeHTTPIntegration_GSM7252PSVlanMembershipRoundTrip(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := httpFacadeFor(t, vsw, "gsm7252ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	// Port 45's PVID is 20 ("roam") in the seed, a VLAN this port is NOT
	// already Configured-member of via any of the "locked" default ports --
	// pick VLAN 4 ("wifi"), which port 45 is not currently a member of.
	if err := sw.SetVlanMembership(ctx, 4, 45, netgearswitch.VlanTagged, httpWrite(false)); err != nil {
		t.Fatalf("SetVlanMembership(vlan=4, port=45, tagged, backend=HTTP) error = %v", err)
	}
	vlans, err := sw.GetVLANs(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetVLANs() error = %v", err)
	}
	vlan4 := findVlan(t, vlans, 4)
	if !containsInt(vlan4.TaggedPorts, 45) {
		t.Errorf("vlan 4 TaggedPorts = %v, want to contain 45 after SetVlanMembership", vlan4.TaggedPorts)
	}
}

// --- gs728tpp (GOAHEAD_XML dialect, backends {SNMP, HTTP}) -----------------

// TestFacadeHTTPIntegration_GS728TPPReadsAndUnsupportedStatsAndCertUpload
// proves box sensors are non-vacuous vs SeedGS728TPP(), that get_stats
// honestly raises (this model's web UI has NO per-port statistics page at
// all -- StatsPath is nil in its HTTPModelSpec), that SetVlanMembership
// ALSO honestly raises (no separate VLAN-membership POST page -- membership
// is read-only-derived from the PVID page's inline list), and that
// UploadCertificate reaches the GoAhead XML-API cert-upload flow (a
// GROUNDED write independent of any read-side gate).
func TestFacadeHTTPIntegration_GS728TPPReadsAndUnsupportedStatsAndCertUpload(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs728tpp")
	sw := httpFacadeFor(t, vsw, "gs728tpp")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	// gs728tpp's HTTPSensors seed (9 raw entries) is filtered by
	// webui.ParseGoAheadSensors' status-flag semantics exactly: fan1Status/
	// fan2Status="1" kept (healthy), fan3/4/5Status="5" SKIPPED
	// (goaheadAbsentStatus); mainPSStatus/redundantPSStatus="1" both kept;
	// tempSensorValue="0" fails the `temp > 0` guard (a captured 0 is not a
	// real reading) so NO temperature entry is emitted at all -- 2 fans + 2
	// power + 0 temperature = 4.
	sensors, err := sw.GetSensors(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetSensors() error = %v", err)
	}
	if len(sensors) != 4 {
		t.Fatalf("len(GetSensors()) = %d, want 4", len(sensors))
	}
	var foundFan1, foundMainPS bool
	for _, s := range sensors {
		if s.Kind == "temperature" {
			t.Errorf("GetSensors(): unexpected temperature entry %+v (tempSensorValue=0 must be excluded by the temp>0 guard)", s)
		}
		switch {
		case s.Name == "Fan1" && s.Kind == "fan" && s.Value == 1:
			foundFan1 = true
		case s.Name == "Main PS" && s.Kind == "power" && s.Value == 1:
			foundMainPS = true
		}
	}
	if !foundFan1 {
		t.Error("GetSensors(): no healthy (1.0) Fan1 fan-state reading")
	}
	if !foundMainPS {
		t.Error("GetSensors(): no healthy (1.0) Main PS power-state reading")
	}

	ports, err := sw.GetPorts(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPorts() error = %v", err)
	}
	if len(ports) != 28 {
		t.Errorf("len(GetPorts()) = %d, want 28", len(ports))
	}

	_, statsErr := sw.GetStats(ctx, overHTTP())
	if !errors.Is(statsErr, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetStats() error = %v, want wrapping ErrUnsupportedCapability (gs728tpp has no per-port stats page)", statsErr)
	}
	if !strings.Contains(statsErr.Error(), "http") {
		t.Errorf("GetStats() error = %q, want it to name the requested backend http", statsErr.Error())
	}

	writeErr := sw.SetVlanMembership(ctx, 5, 1, netgearswitch.VlanTagged, httpWrite(false))
	if !errors.Is(writeErr, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("SetVlanMembership() error = %v, want wrapping ErrUnsupportedCapability (gs728tpp has no VLAN-membership POST page)", writeErr)
	}

	// Cert upload: a GROUNDED, independent-of-reads_verified write flow
	// (D-HTTP-F §7.2/backend_http.go's UploadCertificate doc comment).
	// gs728tpp's GoAhead XML-API upload requires an actual parseable RSA
	// private key (certUploadXML -> rsaPKCS1Pair), unlike gsm7228ps's
	// multipart form below.
	certPEM := "-----BEGIN CERTIFICATE-----\nFAKECERTDATA\n-----END CERTIFICATE-----\n"
	if err := sw.UploadCertificate(ctx, certPEM, generateRSAKeyPEM(t), true); err != nil {
		t.Fatalf("UploadCertificate() error = %v, want nil", err)
	}
}

// --- gsm7228ps (S3300 dialect, backends {SNMP, HTTP, SSH, Telnet}) ---------
//
// gsm7228ps's HTTPModelSpec.ReadsVerified is TRUE at this pin (live
// HTTP<->SNMP cross-verified 2026-07-30, webui/endpoints.go's own doc
// comment) -- despite an OLDER/stale narrative elsewhere describing it as
// "UNVERIFIED-pending-capture cheetah". This test proves the ACTUAL current
// behavior: gsm7228ps's HTTP reads/writes are genuinely dispatchable, except
// GetSensors, which this dialect's own sysInfo page carries no live sensor
// table for (a real, measured device limitation, not a reads_verified
// gate).

// TestFacadeHTTPIntegration_GSM7228PSReadsNonVacuousSensorsUnsupportedAndCertUpload
// proves gsm7228ps's HTTP reads work (ReadsVerified=true), its GetSensors
// honestly raises (a real page-content gap, not the reads_verified gate),
// and UploadCertificate reaches the S3300 multipart cert-upload flow.
func TestFacadeHTTPIntegration_GSM7228PSReadsNonVacuousSensorsUnsupportedAndCertUpload(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7228ps")
	sw := httpFacadeFor(t, vsw, "gsm7228ps")

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	ports, err := sw.GetPorts(ctx, overHTTP())
	if err != nil {
		t.Fatalf("GetPorts() error = %v, want nil (gsm7228ps HTTP reads are ReadsVerified=true at this pin)", err)
	}
	if len(ports) != 52 {
		t.Errorf("len(GetPorts()) = %d, want 52", len(ports))
	}

	if _, err := sw.GetSensors(ctx, overHTTP()); !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Errorf("GetSensors() error = %v, want wrapping ErrUnsupportedCapability (S3300 sysInfo has no live sensor table -- a real page-content gap, not the reads_verified gate)", err)
	}

	certPEM := "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
	keyPEM := "-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----\n"
	if err := sw.UploadCertificate(ctx, certPEM, keyPEM, true); err != nil {
		t.Fatalf("UploadCertificate() error = %v, want nil (S3300 multipart upload doesn't parse the key -- any PEM-shaped string is accepted by the mock)", err)
	}
}

// --- reads_verified gate, exercised at the FACADE layer -------------------

// TestFacadeHTTPIntegration_ReadsVerifiedGateRefusesBeforeSessionUse proves
// the facade's HTTP dispatch honors the reads_verified gate end-to-end: with
// a real VirtualSwitch live and a correctly-configured password, temporarily
// flipping a model's shipped spec to ReadsVerified=false must still refuse
// with ErrUnsupportedCapability -- not merely at the webui.NewReader/
// buildHTTPReader unit level (already covered by backend_http_test.go), but
// through the FULL facade dispatch seam (readVia -> cannotServe), and
// without ever dialing the live HTTP face at all (proven by the fact this
// still passes even though sw's password/session ARE genuinely valid -- a
// gate bug that touched the session first would still happen to succeed
// against this real, correctly-configured switch, silently masking the
// defect; this test's whole point is that gate failure precedes ANY session
// use, so it must fail even when the session WOULD have worked).
func TestFacadeHTTPIntegration_ReadsVerifiedGateRefusesBeforeSessionUse(t *testing.T) {
	spec := webui.HTTPSpecs["gsm7228ps"]
	original := spec.ReadsVerified
	spec.ReadsVerified = false
	defer func() { spec.ReadsVerified = original }()

	vsw := startVirtualSwitch(t, "gsm7228ps")
	sw := httpFacadeFor(t, vsw, "gsm7228ps") // correctly-configured password + a live face

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	_, err := sw.GetPorts(ctx, overHTTP())
	if !errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Fatalf("GetPorts() on a ReadsVerified=false model error = %v, want wrapping ErrUnsupportedCapability", err)
	}
	if !strings.Contains(err.Error(), "UNVERIFIED-pending-capture") {
		t.Errorf("GetPorts() error = %q, want it to mention UNVERIFIED-pending-capture", err.Error())
	}
}

// --- auth failure: wrong HTTP password -> typed error ----------------------

// TestFacadeHTTPIntegration_WrongPasswordRaisesTypedError proves a
// misconfigured HTTP password fails login with an error wrapping
// model.ErrHTTPAuth (never silently treated as an UnsupportedCapability
// skip, and never masquerading as a parse/page error), mirroring
// facade_nsdp_integration_test.go's own wrong-password test shape.
func TestFacadeHTTPIntegration_WrongPasswordRaisesTypedError(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs305ep")
	sw := httpFacadeFor(t, vsw, "gs305ep", netgearswitch.WithHTTPPassword("wrong-password"))

	ctx, cancel := context.WithTimeout(context.Background(), facadeTestTimeout)
	defer cancel()

	_, err := sw.GetPorts(ctx, overHTTP())
	if err == nil {
		t.Fatal("GetPorts() with wrong HTTP password error = nil, want an error")
	}
	if !errors.Is(err, netgearswitch.ErrHTTPAuth) {
		t.Errorf("GetPorts() error = %v, want wrapping ErrHTTPAuth", err)
	}
	if errors.Is(err, netgearswitch.ErrUnsupportedCapability) {
		t.Error("GetPorts() with wrong password must NOT be treated as an UnsupportedCapability skip -- it must propagate immediately (D-FAC rule 5)")
	}
}

// --- helpers ----------------------------------------------------------
//
// containsInt is defined in facade_integration_test.go (same package);
// reused here as-is.

// generateRSAKeyPEM returns a freshly generated RSA private key as an
// unencrypted PKCS#8 PEM (the shape a real cert+key pair carries), mirroring
// webui/cert_test.go's own rsaKeyPEM helper (unexported there, so
// duplicated here for this external test package).
func generateRSAKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
