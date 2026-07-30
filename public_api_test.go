// public_api_test.go: root-package surface test, the Go analogue of
// tests/test_public_api.py's intent (the normative source; that repo is
// read-only from here) -- test_public_types_importable_from_top_level and
// test_facades_exported_from_top_level. This file lives in package
// netgearswitch_test (an EXTERNAL test package) and imports ONLY the root
// module, "context", "errors" and "testing" -- proving every exported
// read-side name documented so far (D-FAC's "Switch, dispatch, DetectModel,
// Snapshot", docs/superpowers/plans/2026-07-30-slice-03-dossier-facade.md
// §4.3) is reachable, usable, and correctly typed from a single top-level
// import, with no need to import the model or snmp subpackages directly.
//
// Every construction below is network-silent by construction (New/
// FromConfig do no I/O per D-FAC §2.2), and every dispatch call below is
// engineered to fail fast on the SNMP read-community credential gate
// (backend_snmp.go's requireSNMPCommunity) BEFORE any network attempt --
// so this file is deterministic and needs no live switch, fake client, or
// even the snmp package's Client interface.

package netgearswitch_test

import (
	"context"
	"errors"
	"testing"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
)

// acceptVlanMode/acceptIPMode/acceptBackend/acceptSwitchClass exist only to
// pin each enum-ish alias's TYPE (not just its constants' values) into this
// package-level surface, since a bare "var _ = netgearswitch.VlanTagged"
// would type-check the value without ever naming netgearswitch.VlanMode
// itself.
func acceptVlanMode(netgearswitch.VlanMode)       {}
func acceptIPMode(netgearswitch.IPMode)           {}
func acceptBackend(netgearswitch.Backend)         {}
func acceptSwitchClass(netgearswitch.SwitchClass) {}

// mustModel looks up a real registered model via the top-level GetModel,
// proving the registry lookup itself is part of the single-import surface.
func mustModel(t *testing.T, key string) *netgearswitch.SwitchModel {
	t.Helper()
	m, err := netgearswitch.GetModel(key)
	if err != nil {
		t.Fatalf("GetModel(%q) error = %v", key, err)
	}
	return m
}

func TestPublicAPI_ModelTypesReachableWithoutImportingModelPackage(t *testing.T) {
	m := mustModel(t, "gsm7252ps")
	if !m.HasMACTable() {
		t.Errorf("gsm7252ps.HasMACTable() = false, want true")
	}

	if len(netgearswitch.Models()) == 0 {
		t.Errorf("Models() = empty, want the full registry")
	}

	// Enum-ish constants re-exported from model must be usable by name,
	// with no "model." qualifier ever required by a caller of this package.
	if string(netgearswitch.PoEDetectDelivering) != "delivering" {
		t.Errorf("PoEDetectDelivering = %q, want \"delivering\"", netgearswitch.PoEDetectDelivering)
	}
	acceptVlanMode(netgearswitch.VlanTagged)
	acceptIPMode(netgearswitch.IPModeStatic)
	acceptBackend(netgearswitch.BackendSNMP)
	acceptSwitchClass(netgearswitch.ClassSmartManagedPro)

	// Device-data struct aliases must be constructible as plain literals.
	_ = netgearswitch.PortStatus{Port: 1}
	_ = netgearswitch.PoEStatus{}
	_ = netgearswitch.VLANInfo{}
	_ = netgearswitch.LLDPNeighbor{}
	_ = netgearswitch.MacEntry{}
	_ = netgearswitch.Sensor{}
	_ = netgearswitch.PortStats{}
	_ = netgearswitch.MgmtIPConfig{}
	_ = netgearswitch.DetectedModel{}
	_ = netgearswitch.Pvid{}
	_ = netgearswitch.SwitchData{}

	// Error sentinels must errors.Is-match without importing model.
	sentinels := []error{
		netgearswitch.ErrUnsupportedCapability,
		netgearswitch.ErrProtectedPort,
		netgearswitch.ErrKnownUnimplemented,
		netgearswitch.ErrCredential,
		netgearswitch.ErrConfig,
		netgearswitch.ErrUnknownModel,
		netgearswitch.ErrSNMP,
	}
	for _, s := range sentinels {
		if s == nil {
			t.Errorf("an exported error sentinel is nil")
		}
	}
}

func TestPublicAPI_SwitchConstructionIsNetworkSilent(t *testing.T) {
	m := mustModel(t, "gsm7252ps")

	sw, err := netgearswitch.New(m, "10.0.0.9",
		netgearswitch.WithSNMPCommunity("public"),
		netgearswitch.WithProtectedPorts(1, 2, 2), // duplicate deliberately: exercises the dedup path
		netgearswitch.WithNSDPInterface("eth0"),
		netgearswitch.WithHTTPPasswordResolver(func() (*string, error) { return nil, nil }),
		netgearswitch.WithSNMPWriteCommunityResolver(func() (*string, error) { return nil, nil }),
	)
	if err != nil {
		t.Fatalf("New() error = %v, want no I/O and no error at construction", err)
	}
	if sw == nil {
		t.Fatal("New() returned a nil *Switch with a nil error")
	}
	if err := sw.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil (nothing was ever opened)", err)
	}
}

func TestPublicAPI_FromConfigConstructsWithoutIO(t *testing.T) {
	m := mustModel(t, "gsm7252ps")
	community := "public"

	cfg := netgearswitch.SwitchConfig{
		Name:          "test-switch",
		Model:         m,
		Host:          "10.0.0.9",
		SNMPCommunity: &community,
	}

	sw, err := netgearswitch.FromConfig(cfg)
	if err != nil {
		t.Fatalf("FromConfig() error = %v, want no I/O and no error at construction", err)
	}
	if sw == nil {
		t.Fatal("FromConfig() returned a nil *Switch with a nil error")
	}
}

// TestPublicAPI_DetectModelReachableAndFailsFastOnCredentialGate proves
// DetectModel -- the pre-Switch-construction discovery entry point -- is
// exported and correctly wired to the same SNMP-community credential gate
// as every backend build, entirely from the top-level import: no client
// injected and no community configured must raise ErrCredential, never
// silently attempt a network round-trip.
func TestPublicAPI_DetectModelReachableAndFailsFastOnCredentialGate(t *testing.T) {
	_, err := netgearswitch.DetectModel(context.Background(), "10.0.0.9")
	if !errors.Is(err, netgearswitch.ErrCredential) {
		t.Fatalf("DetectModel() error = %v, want wrapping ErrCredential", err)
	}
}

// TestPublicAPI_ReadMethodsAndIdentifyAndSnapshotReachable exercises every
// exported Switch read method plus Identify and Snapshot by name, proving
// each compiles and dispatches from the top-level import alone. None of
// these ever reach the network: with no SNMP client injected and no
// community configured, the SNMP backend build itself fails the
// credential gate immediately, and since that error does NOT wrap
// ErrUnsupportedCapability, readVia's dispatch loop propagates it
// immediately rather than treating it as a per-backend skip (D-FAC §2.7
// rule 5) -- so every call below deterministically returns an
// ErrCredential-wrapping error with no live switch required.
func TestPublicAPI_ReadMethodsAndIdentifyAndSnapshotReachable(t *testing.T) {
	m := mustModel(t, "gsm7252ps")
	sw, err := netgearswitch.New(m, "10.0.0.9")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx := context.Background()

	assertCredentialError := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, netgearswitch.ErrCredential) {
			t.Errorf("%s error = %v, want wrapping ErrCredential", name, err)
		}
	}

	_, err = sw.GetPorts(ctx)
	assertCredentialError("GetPorts()", err)
	_, err = sw.GetStats(ctx)
	assertCredentialError("GetStats()", err)
	_, err = sw.GetVLANs(ctx)
	assertCredentialError("GetVLANs()", err)
	_, err = sw.GetPVIDs(ctx)
	assertCredentialError("GetPVIDs()", err)
	_, err = sw.GetLLDP(ctx)
	assertCredentialError("GetLLDP()", err)
	_, err = sw.GetMACs(ctx)
	assertCredentialError("GetMACs()", err)
	_, err = sw.GetPoE(ctx)
	assertCredentialError("GetPoE()", err)
	_, err = sw.GetSensors(ctx)
	assertCredentialError("GetSensors()", err)
	_, err = sw.GetMgmtIP(ctx)
	assertCredentialError("GetMgmtIP()", err)
	_, err = sw.Identify(ctx)
	assertCredentialError("Identify()", err)
	_, err = sw.Snapshot(ctx)
	assertCredentialError("Snapshot()", err)
}
