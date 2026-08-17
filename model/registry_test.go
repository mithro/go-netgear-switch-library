package model_test

import (
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// wantModel is the expected shape of one registry entry, hand-verified
// against src/netgear_switch/registry.py (the normative source).
type wantModel struct {
	key               string
	displayName       string
	class             model.SwitchClass
	portCount         int
	poePortCount      int
	backends          []model.Backend
	vendorBase        string
	verified          bool
	hasMACTable       bool
	snmpCanCreateVLAN bool
}

// wantModelsInOrder mirrors the exact order and every field of Python's
// _MODELS table (registry.py lines 89-297). Do not reorder without
// re-checking the Python source: the Go registry order is a direct port.
var wantModelsInOrder = []wantModel{
	{
		key:               "m4300-24x",
		displayName:       "M4300-24X (XSM4324CS)",
		class:             model.ClassFullyManaged,
		portCount:         28,
		poePortCount:      0,
		backends:          []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendSSH, model.BackendTelnet},
		vendorBase:        "1.3.6.1.4.1.4526.10",
		verified:          true,
		hasMACTable:       true,
		snmpCanCreateVLAN: true,
	},
	{
		key:               "m4300-16x",
		displayName:       "M4300-16X (XSM4316)",
		class:             model.ClassFullyManaged,
		portCount:         16,
		poePortCount:      16,
		backends:          []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendSSH, model.BackendTelnet},
		vendorBase:        "1.3.6.1.4.1.4526.10",
		verified:          true,
		hasMACTable:       true,
		snmpCanCreateVLAN: true,
	},
	{
		key:               "gsm7252ps",
		displayName:       "GSM7252PS",
		class:             model.ClassFullyManaged,
		portCount:         52,
		poePortCount:      48,
		backends:          []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendSSH, model.BackendTelnet},
		vendorBase:        "1.3.6.1.4.1.4526.10",
		verified:          true,
		hasMACTable:       true,
		snmpCanCreateVLAN: true,
	},
	{
		key:               "gsm7228ps",
		displayName:       "GSM7228PS (S3300)",
		class:             model.ClassSmartManagedPro,
		portCount:         52,
		poePortCount:      48,
		backends:          []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendTelnet},
		vendorBase:        "1.3.6.1.4.1.4526.11",
		verified:          true,
		hasMACTable:       true,
		snmpCanCreateVLAN: true,
	},
	{
		key:               "gs110emx",
		displayName:       "GS110EMX",
		class:             model.ClassPlus,
		portCount:         10,
		poePortCount:      0,
		backends:          []model.Backend{model.BackendNSDP, model.BackendHTTP},
		vendorBase:        "",
		verified:          true,
		hasMACTable:       false,
		snmpCanCreateVLAN: true,
	},
	{
		key:               "gs305ep",
		displayName:       "GS305EP",
		class:             model.ClassPlus,
		portCount:         5,
		poePortCount:      4,
		backends:          []model.Backend{model.BackendNSDP, model.BackendHTTP},
		vendorBase:        "",
		verified:          true,
		hasMACTable:       false,
		snmpCanCreateVLAN: true,
	},
	{
		key:               "m7300",
		displayName:       "M7300-24XF",
		class:             model.ClassFullyManaged,
		portCount:         24,
		poePortCount:      0,
		backends:          []model.Backend{model.BackendSNMP},
		vendorBase:        "1.3.6.1.4.1.4526.10",
		verified:          false,
		hasMACTable:       true,
		snmpCanCreateVLAN: true,
	},
	{
		key:               "xs748t",
		displayName:       "XS748T",
		class:             model.ClassSmartManagedPro,
		portCount:         48,
		poePortCount:      0,
		backends:          []model.Backend{model.BackendSNMP},
		vendorBase:        "1.3.6.1.4.1.4526.11",
		verified:          false,
		hasMACTable:       true,
		snmpCanCreateVLAN: true,
	},
	{
		key:               "gs728tpp",
		displayName:       "GS728TPP",
		class:             model.ClassSmartManagedPro,
		portCount:         28,
		poePortCount:      24,
		backends:          []model.Backend{model.BackendSNMP, model.BackendHTTP},
		vendorBase:        "",
		verified:          true,
		hasMACTable:       true,
		snmpCanCreateVLAN: false,
	},
	{
		key:               "gs105pe",
		displayName:       "GS105PE",
		class:             model.ClassPlus,
		portCount:         5,
		poePortCount:      0,
		backends:          []model.Backend{model.BackendNSDP, model.BackendHTTP},
		vendorBase:        "",
		verified:          true,
		hasMACTable:       false,
		snmpCanCreateVLAN: true,
	},
}

func TestModelsCount(t *testing.T) {
	got := model.Models()
	if len(got) != 10 {
		t.Fatalf("len(Models()) = %d, want 10", len(got))
	}
}

func TestModelsOrderAndFields(t *testing.T) {
	got := model.Models()
	if len(got) != len(wantModelsInOrder) {
		t.Fatalf("len(Models()) = %d, want %d", len(got), len(wantModelsInOrder))
	}

	for i, want := range wantModelsInOrder {
		m := got[i]
		if m == nil {
			t.Fatalf("Models()[%d] = nil", i)
		}
		if m.Key != want.key {
			t.Errorf("Models()[%d].Key = %q, want %q (order must match Python's _MODELS)", i, m.Key, want.key)
		}
		if m.DisplayName != want.displayName {
			t.Errorf("%s: DisplayName = %q, want %q", want.key, m.DisplayName, want.displayName)
		}
		if m.Class != want.class {
			t.Errorf("%s: Class = %q, want %q", want.key, m.Class, want.class)
		}
		if m.PortCount != want.portCount {
			t.Errorf("%s: PortCount = %d, want %d", want.key, m.PortCount, want.portCount)
		}
		if m.PoEPortCount != want.poePortCount {
			t.Errorf("%s: PoEPortCount = %d, want %d", want.key, m.PoEPortCount, want.poePortCount)
		}
		if len(m.Backends) != len(want.backends) {
			t.Errorf("%s: Backends = %v, want %v", want.key, m.Backends, want.backends)
		} else {
			for j, b := range want.backends {
				if m.Backends[j] != b {
					t.Errorf("%s: Backends[%d] = %q, want %q", want.key, j, m.Backends[j], b)
				}
			}
		}
		if m.SNMPVendorBase != want.vendorBase {
			t.Errorf("%s: SNMPVendorBase = %q, want %q", want.key, m.SNMPVendorBase, want.vendorBase)
		}
		if m.Verified != want.verified {
			t.Errorf("%s: Verified = %v, want %v", want.key, m.Verified, want.verified)
		}
		if m.HasMACTable() != want.hasMACTable {
			t.Errorf("%s: HasMACTable() = %v, want %v", want.key, m.HasMACTable(), want.hasMACTable)
		}
		if m.SNMPCanCreateVLAN != want.snmpCanCreateVLAN {
			t.Errorf("%s: SNMPCanCreateVLAN = %v, want %v", want.key, m.SNMPCanCreateVLAN, want.snmpCanCreateVLAN)
		}
	}
}

func TestModelsEveryEntryHasBackendsAndPorts(t *testing.T) {
	for _, m := range model.Models() {
		if len(m.Backends) == 0 {
			t.Errorf("%s: Backends is empty, want non-empty", m.Key)
		}
		if m.PortCount <= 0 {
			t.Errorf("%s: PortCount = %d, want > 0", m.Key, m.PortCount)
		}
	}
}

func TestModelsKeysUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, m := range model.Models() {
		if seen[m.Key] {
			t.Errorf("duplicate key %q in Models()", m.Key)
		}
		seen[m.Key] = true
	}
}

func TestModelsReturnsFreshCopy(t *testing.T) {
	got1 := model.Models()
	if len(got1) == 0 {
		t.Fatal("Models() returned empty slice")
	}
	original := got1[0].DisplayName

	// Mutate the returned slice's element and slice header; a second call
	// to Models() must be unaffected -- Models() hands out a fresh copy,
	// not a view onto shared registry state.
	got1[0].DisplayName = "MUTATED"
	got1 = append(got1, nil)
	if len(got1) != 11 {
		t.Errorf("got1 len after append = %d, want 11", len(got1))
	}

	got2 := model.Models()
	if got2[0].DisplayName != original {
		t.Errorf("Models() call 2 DisplayName = %q, want %q (registry state was mutated)", got2[0].DisplayName, original)
	}
	if len(got2) != 10 {
		t.Errorf("Models() call 2 len = %d, want 10 (unaffected by append to a prior call's slice)", len(got2))
	}
}

func TestGetModelGS305EP(t *testing.T) {
	m, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("GetModel(gs305ep) error: %v", err)
	}
	if m.PoEPortCount != 4 {
		t.Errorf("PoEPortCount = %d, want 4", m.PoEPortCount)
	}
	if !m.HasBackend(model.BackendNSDP) || !m.HasBackend(model.BackendHTTP) {
		t.Errorf("Backends = %v, want nsdp+http", m.Backends)
	}
	if m.HasBackend(model.BackendSNMP) {
		t.Errorf("gs305ep unexpectedly HasBackend(snmp)")
	}
	if m.HasMACTable() {
		t.Error("HasMACTable() = true, want false (no SNMP backend)")
	}
}

func TestGetModelM4300_24X(t *testing.T) {
	m, err := model.GetModel("m4300-24x")
	if err != nil {
		t.Fatalf("GetModel(m4300-24x) error: %v", err)
	}
	if !m.HasMACTable() {
		t.Error("HasMACTable() = false, want true (has SNMP backend)")
	}
	if !m.Verified {
		t.Error("Verified = false, want true")
	}
}

func TestGetModelUnknown(t *testing.T) {
	_, err := model.GetModel("nope")
	if !errors.Is(err, model.ErrUnknownModel) {
		t.Errorf("errors.Is(err, ErrUnknownModel) = false, want true (err=%v)", err)
	}
}

// TestGetModelAliasS3300 verifies GetModel resolves the "s3300" alias to
// the canonical "gsm7228ps" entry, mirroring Python's
// MODEL_ALIASES = {"s3300": "gsm7228ps"} resolved by get_model().
func TestGetModelAliasS3300(t *testing.T) {
	alias, err := model.GetModel("s3300")
	if err != nil {
		t.Fatalf("GetModel(s3300) error: %v", err)
	}
	canonical, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("GetModel(gsm7228ps) error: %v", err)
	}
	if alias != canonical {
		t.Errorf("GetModel(s3300) = %p (%+v), want the same canonical entry as GetModel(gsm7228ps) = %p (%+v)", alias, alias, canonical, canonical)
	}
	if alias.Key != "gsm7228ps" {
		t.Errorf("GetModel(s3300).Key = %q, want %q", alias.Key, "gsm7228ps")
	}
}

// TestGetModelAliasCaseSensitive verifies alias resolution is an exact,
// case-sensitive match (Python's dict.get performs no normalisation), so
// an uppercase variant of a known alias is NOT resolved and is reported as
// unknown.
func TestGetModelAliasCaseSensitive(t *testing.T) {
	_, err := model.GetModel("S3300")
	if !errors.Is(err, model.ErrUnknownModel) {
		t.Errorf("GetModel(S3300): errors.Is(err, ErrUnknownModel) = false, want true (alias resolution must be case-sensitive; err=%v)", err)
	}
}

// TestModelsExcludesAliases verifies alias keys are NOT separate entries
// in Models() -- Python's MODEL_ALIASES is deliberately not added to
// MODELS, which stays a canonical one-key-per-model listing.
func TestModelsExcludesAliases(t *testing.T) {
	for _, m := range model.Models() {
		if m.Key == "s3300" {
			t.Errorf("Models() contains alias key %q as its own entry, want only canonical keys", m.Key)
		}
	}
	if len(model.Models()) != 10 {
		t.Errorf("len(Models()) = %d, want 10 (unchanged by alias support)", len(model.Models()))
	}
}

func TestGetModelUnverifiedFlags(t *testing.T) {
	// Spot-check the "honesty flag" models called out in registry.py: no
	// real-hardware capture exists for these, so verified must be false
	// even though they have full spec-derived data. gsm7228ps was in this
	// group until a real hardware capture on 2026-07-30 resolved its OID
	// family and confirmed all read ops -- it is now verified=true and is
	// deliberately NOT in this list (see TestGetModelGSM7228PSVerified).
	for _, key := range []string{"m7300", "xs748t"} {
		m, err := model.GetModel(key)
		if err != nil {
			t.Fatalf("GetModel(%s) error: %v", key, err)
		}
		if m.Verified {
			t.Errorf("%s: Verified = true, want false (unverified-pending-capture)", key)
		}
	}
}

// TestGetModelGSM7228PSVerified verifies gsm7228ps is Verified == true,
// matching registry.py's _model("gsm7228ps", ...) call (no verified=
// kwarg passed, so the SwitchModel dataclass default `verified: bool =
// True` applies) and its comment documenting a 2026-07-30 real-hardware
// capture that confirmed the 4526.11 (smart-managed-pro) vendor OID
// family and cross-verified all 9 read ops.
func TestGetModelGSM7228PSVerified(t *testing.T) {
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("GetModel(gsm7228ps) error: %v", err)
	}
	if !m.Verified {
		t.Error("gsm7228ps: Verified = false, want true (hardware-verified 2026-07-30)")
	}
}

// TestGSM7228PSHasNoSSH pins a real registry-data bug found while building
// the capabilities oracle: the pinned Python registry.py (commit a9e0ebc)
// registers gsm7228ps with {SNMP, HTTP, TELNET} -- explicitly NOT SSH -- with
// a live-verified comment that the real S3300-52X hardware runs no SSH
// listener at all (its own SNMP tcpConnTable shows only ports 80/443/60000;
// CLI is telnet-only on the non-standard port 60000). A Go registry that
// claims SSH here fabricates a capability the device does not have.
func TestGSM7228PSHasNoSSH(t *testing.T) {
	m, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("GetModel(gsm7228ps): %v", err)
	}
	if m.HasBackend(model.BackendSSH) {
		t.Error("gsm7228ps: HasBackend(BackendSSH) = true, want false (real S3300-52X has no SSH listener)")
	}
	if !m.HasBackend(model.BackendTelnet) {
		t.Error("gsm7228ps: HasBackend(BackendTelnet) = false, want true")
	}
	if !m.HasBackend(model.BackendSNMP) || !m.HasBackend(model.BackendHTTP) {
		t.Error("gsm7228ps: expected SNMP and HTTP backends unchanged")
	}
}
