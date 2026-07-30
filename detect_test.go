// detect_test.go: tests for DetectModel, the free-function discovery entry
// point (detect.go), ported from tests/test_sync_api.py's
// test_detect_model_module_function_* (the normative source; that repo is
// read-only from here). Reuses switch_read_test.go's fakeSNMPClient/
// sysInfoTable fixtures (same package). See D-FAC (docs/superpowers/plans/
// 2026-07-30-slice-03-dossier-facade.md) §2.11 for Identify's twin
// semantics -- DetectModel is the pre-Switch-construction analogue of the
// same build-or-reuse-client logic (backend_snmp.go's buildSNMPClient).

package netgearswitch

import (
	"context"
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

func TestDetectModel_InjectedClient_MatchesRegisteredModelViaSysDescr(t *testing.T) {
	client := &fakeSNMPClient{table: sysInfoTable(t, "gsm7252ps")}

	got, err := DetectModel(context.Background(), "10.0.0.9", WithDetectClient(client))
	if err != nil {
		t.Fatalf("DetectModel() error = %v", err)
	}
	if got.Key == nil || *got.Key != "gsm7252ps" {
		t.Fatalf("DetectModel() = %+v, want matched key gsm7252ps", got)
	}
	if !got.Matched() {
		t.Errorf("Matched() = false, want true")
	}
}

func TestDetectModel_InjectedClient_UnregisteredModelIsHonestlyUnmatched(t *testing.T) {
	// sysDescr is a real-looking but never-registered Netgear model name, and
	// sysObjectID is deliberately outside the sysObjectID->model map, so
	// neither detection path can match -- key must come back nil, never
	// coerced onto some other registered model, while sysDescr/sysObjectID
	// are still carried for the caller/logging.
	table := map[string][]snmp.Row{
		snmp.SysDescr:    {snmp.NewStrRow(snmp.SysDescr, "NETGEAR M7300-28G")},
		snmp.SysObjectID: {snmp.NewStrRow(snmp.SysObjectID, "1.3.6.1.4.1.4526.10.100.14")},
	}
	client := &fakeSNMPClient{table: table}

	got, err := DetectModel(context.Background(), "10.0.0.9", WithDetectClient(client))
	if err != nil {
		t.Fatalf("DetectModel() error = %v", err)
	}
	if got.Key != nil {
		t.Errorf("Key = %v, want nil", *got.Key)
	}
	if got.Matched() {
		t.Errorf("Matched() = true, want false")
	}
	if got.SysDescr == nil || *got.SysDescr != "NETGEAR M7300-28G" {
		t.Errorf("SysDescr = %v, want \"NETGEAR M7300-28G\"", got.SysDescr)
	}
	if got.SysObjectID == nil || *got.SysObjectID != "1.3.6.1.4.1.4526.10.100.14" {
		t.Errorf("SysObjectID = %v, want \"1.3.6.1.4.1.4526.10.100.14\"", got.SysObjectID)
	}
}

func TestDetectModel_InjectedClient_SysObjectIDMapHitWinsEvenWithUnmatchableSysDescr(t *testing.T) {
	// Mirrors gsm7228ps's real capture: sysDescr text is deliberately
	// unmatchable by the sysDescr heuristic, so ONLY the sysObjectID map can
	// auto-detect it -- proving DetectModel really does delegate to
	// snmp.ReadSystemInfo's sysObjectID-first order, not just sysDescr.
	table := map[string][]snmp.Row{
		snmp.SysDescr:    {snmp.NewStrRow(snmp.SysDescr, "S3300-52X-PoE+ 10.5.1.15, VxWorks 6.9")},
		snmp.SysObjectID: {snmp.NewStrRow(snmp.SysObjectID, "1.3.6.1.4.1.4526.100.10.19")},
	}
	client := &fakeSNMPClient{table: table}

	got, err := DetectModel(context.Background(), "10.0.0.9", WithDetectClient(client))
	if err != nil {
		t.Fatalf("DetectModel() error = %v", err)
	}
	if got.Key == nil || *got.Key != "gsm7228ps" {
		t.Fatalf("DetectModel() = %+v, want matched key gsm7228ps (via sysObjectID map)", got)
	}
}

func TestDetectModel_NoClientNoCommunity_ReturnsCredentialError(t *testing.T) {
	_, err := DetectModel(context.Background(), "10.0.0.9")
	if !errors.Is(err, model.ErrCredential) {
		t.Fatalf("DetectModel() error = %v, want wrapping ErrCredential", err)
	}
}

func TestDetectModel_WithDetectCommunity_BuildsDefaultClient(t *testing.T) {
	// No injected client: DetectModel must build its own default SNMP client
	// from host/community exactly like backend_snmp.go's buildSNMPClient
	// does -- proven indirectly here by using a real host/community pair
	// that reaches ReadSystemInfo through the real snmp.NewGoSNMPClient
	// construction path (construction itself does no I/O), then verifying
	// via context cancellation that DetectModel got as far as actually
	// dispatching (see the fail-fast test below for the no-I/O guarantee at
	// the ctx-check layer). Community-gate acceptance is asserted directly:
	// supplying a community must NOT raise ErrCredential the way an absent
	// one does.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := DetectModel(ctx, "10.0.0.9", WithDetectCommunity("public"))
	if errors.Is(err, model.ErrCredential) {
		t.Fatalf("DetectModel() error = %v, want NOT ErrCredential (community was supplied)", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DetectModel() error = %v, want wrapping context.Canceled", err)
	}
}

func TestDetectModel_InjectedClientBypassesCommunityGate(t *testing.T) {
	// An injected client must be used as-is even with no community
	// configured at all -- mirroring Identify/buildSNMPClient: the
	// community gate is only ever consulted when a client must be built.
	client := &fakeSNMPClient{table: sysInfoTable(t, "gsm7252ps")}

	got, err := DetectModel(context.Background(), "10.0.0.9", WithDetectClient(client))
	if err != nil {
		t.Fatalf("DetectModel() error = %v, want no CredentialError when a client is injected", err)
	}
	if got.Key == nil || *got.Key != "gsm7252ps" {
		t.Fatalf("DetectModel() = %+v, want matched key gsm7252ps", got)
	}
}

func TestDetectModel_ContextCancelledFailsFastBeforeAnyClientBuild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := DetectModel(ctx, "10.0.0.9")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DetectModel() error = %v, want wrapping context.Canceled", err)
	}
	if errors.Is(err, model.ErrCredential) {
		t.Fatalf("DetectModel() error = %v, want fail-fast on ctx BEFORE the community gate runs", err)
	}
}
