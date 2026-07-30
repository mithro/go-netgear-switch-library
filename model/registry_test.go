package model_test

import (
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// wantModel is the expected shape of one registry entry, hand-verified
// against src/netgear_switch/registry.py (the normative source).
type wantModel struct {
	key          string
	displayName  string
	class        model.SwitchClass
	portCount    int
	poePortCount int
	backends     []model.Backend
	vendorBase   string
	verified     bool
	hasMACTable  bool
}

// wantModelsInOrder mirrors the exact order and every field of Python's
// _MODELS table (registry.py lines 89-297). Do not reorder without
// re-checking the Python source: the Go registry order is a direct port.
var wantModelsInOrder = []wantModel{
	{
		key:          "m4300-24x",
		displayName:  "M4300-24X (XSM4324CS)",
		class:        model.ClassFullyManaged,
		portCount:    28,
		poePortCount: 0,
		backends:     []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendSSH, model.BackendTelnet},
		vendorBase:   "1.3.6.1.4.1.4526.10",
		verified:     true,
		hasMACTable:  true,
	},
	{
		key:          "m4300-16x",
		displayName:  "M4300-16X (XSM4316)",
		class:        model.ClassFullyManaged,
		portCount:    16,
		poePortCount: 16,
		backends:     []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendSSH, model.BackendTelnet},
		vendorBase:   "1.3.6.1.4.1.4526.10",
		verified:     true,
		hasMACTable:  true,
	},
	{
		key:          "gsm7252ps",
		displayName:  "GSM7252PS",
		class:        model.ClassFullyManaged,
		portCount:    52,
		poePortCount: 48,
		backends:     []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendSSH, model.BackendTelnet},
		vendorBase:   "1.3.6.1.4.1.4526.10",
		verified:     true,
		hasMACTable:  true,
	},
	{
		key:          "gsm7228ps",
		displayName:  "GSM7228PS (S3300)",
		class:        model.ClassSmartManagedPro,
		portCount:    52,
		poePortCount: 48,
		backends:     []model.Backend{model.BackendSNMP, model.BackendHTTP, model.BackendSSH, model.BackendTelnet},
		vendorBase:   "1.3.6.1.4.1.4526.11",
		verified:     false,
		hasMACTable:  true,
	},
	{
		key:          "gs110emx",
		displayName:  "GS110EMX",
		class:        model.ClassPlus,
		portCount:    10,
		poePortCount: 0,
		backends:     []model.Backend{model.BackendNSDP, model.BackendHTTP},
		vendorBase:   "",
		verified:     true,
		hasMACTable:  false,
	},
	{
		key:          "gs305ep",
		displayName:  "GS305EP",
		class:        model.ClassPlus,
		portCount:    5,
		poePortCount: 4,
		backends:     []model.Backend{model.BackendNSDP, model.BackendHTTP},
		vendorBase:   "",
		verified:     true,
		hasMACTable:  false,
	},
	{
		key:          "m7300",
		displayName:  "M7300-24XF",
		class:        model.ClassFullyManaged,
		portCount:    24,
		poePortCount: 0,
		backends:     []model.Backend{model.BackendSNMP},
		vendorBase:   "1.3.6.1.4.1.4526.10",
		verified:     false,
		hasMACTable:  true,
	},
	{
		key:          "xs748t",
		displayName:  "XS748T",
		class:        model.ClassSmartManagedPro,
		portCount:    48,
		poePortCount: 0,
		backends:     []model.Backend{model.BackendSNMP},
		vendorBase:   "1.3.6.1.4.1.4526.11",
		verified:     false,
		hasMACTable:  true,
	},
	{
		key:          "gs728tpp",
		displayName:  "GS728TPP",
		class:        model.ClassSmartManagedPro,
		portCount:    28,
		poePortCount: 24,
		backends:     []model.Backend{model.BackendSNMP, model.BackendHTTP},
		vendorBase:   "",
		verified:     true,
		hasMACTable:  true,
	},
	{
		key:          "gs105pe",
		displayName:  "GS105PE",
		class:        model.ClassPlus,
		portCount:    5,
		poePortCount: 0,
		backends:     []model.Backend{model.BackendNSDP, model.BackendHTTP},
		vendorBase:   "",
		verified:     true,
		hasMACTable:  false,
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

func TestGetModelUnverifiedFlags(t *testing.T) {
	// Spot-check the "honesty flag" models called out in registry.py: no
	// real-hardware capture exists for these, so verified must be false
	// even though they have full spec-derived data.
	for _, key := range []string{"gsm7228ps", "m7300", "xs748t"} {
		m, err := model.GetModel(key)
		if err != nil {
			t.Fatalf("GetModel(%s) error: %v", key, err)
		}
		if m.Verified {
			t.Errorf("%s: Verified = true, want false (unverified-pending-capture)", key)
		}
	}
}
