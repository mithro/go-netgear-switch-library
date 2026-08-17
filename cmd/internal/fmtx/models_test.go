package fmtx

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// wantModelsText/wantModelsJSON were captured VERBATIM from a live run of
// the pinned Python source's cli/main.py `_cmd_models` handler body
// against its own registry.MODELS -- not hand-derived. This doubles as a
// registry-content cross-check: it only passes because this codebase's
// model.Models() registry (ported in an earlier slice) already agrees
// with Python's on every model/port-count/backend-set/verified flag.
const wantModelsText = `m4300-24x    M4300-24X (XSM4324CS)    http+snmp+ssh+telnet
m4300-16x    M4300-16X (XSM4316)      http+snmp+ssh+telnet
gsm7252ps    GSM7252PS                http+snmp+ssh+telnet
gsm7228ps    GSM7228PS (S3300)        http+snmp+telnet
gs110emx     GS110EMX                 http+nsdp
gs305ep      GS305EP                  http+nsdp
m7300        M7300-24XF               snmp  [UNVERIFIED]
xs748t       XS748T                   snmp  [UNVERIFIED]
gs728tpp     GS728TPP                 http+snmp
gs105pe      GS105PE                  http+nsdp`

const wantModelsJSON = `[
  {
    "key": "m4300-24x",
    "display_name": "M4300-24X (XSM4324CS)",
    "class": "fully_managed",
    "ports": 28,
    "backends": [
      "http",
      "snmp",
      "ssh",
      "telnet"
    ],
    "verified": true
  },
  {
    "key": "m4300-16x",
    "display_name": "M4300-16X (XSM4316)",
    "class": "fully_managed",
    "ports": 16,
    "backends": [
      "http",
      "snmp",
      "ssh",
      "telnet"
    ],
    "verified": true
  },
  {
    "key": "gsm7252ps",
    "display_name": "GSM7252PS",
    "class": "fully_managed",
    "ports": 52,
    "backends": [
      "http",
      "snmp",
      "ssh",
      "telnet"
    ],
    "verified": true
  },
  {
    "key": "gsm7228ps",
    "display_name": "GSM7228PS (S3300)",
    "class": "smart_managed_pro",
    "ports": 52,
    "backends": [
      "http",
      "snmp",
      "telnet"
    ],
    "verified": true
  },
  {
    "key": "gs110emx",
    "display_name": "GS110EMX",
    "class": "plus",
    "ports": 10,
    "backends": [
      "http",
      "nsdp"
    ],
    "verified": true
  },
  {
    "key": "gs305ep",
    "display_name": "GS305EP",
    "class": "plus",
    "ports": 5,
    "backends": [
      "http",
      "nsdp"
    ],
    "verified": true
  },
  {
    "key": "m7300",
    "display_name": "M7300-24XF",
    "class": "fully_managed",
    "ports": 24,
    "backends": [
      "snmp"
    ],
    "verified": false
  },
  {
    "key": "xs748t",
    "display_name": "XS748T",
    "class": "smart_managed_pro",
    "ports": 48,
    "backends": [
      "snmp"
    ],
    "verified": false
  },
  {
    "key": "gs728tpp",
    "display_name": "GS728TPP",
    "class": "smart_managed_pro",
    "ports": 28,
    "backends": [
      "http",
      "snmp"
    ],
    "verified": true
  },
  {
    "key": "gs105pe",
    "display_name": "GS105PE",
    "class": "plus",
    "ports": 5,
    "backends": [
      "http",
      "nsdp"
    ],
    "verified": true
  }
]`

func TestModelsTextMatchesPython(t *testing.T) {
	rows := ModelRows(model.Models())
	if got := ModelsText(rows); got != wantModelsText {
		t.Errorf("ModelsText(model.Models()) =\n%s\nwant\n%s", got, wantModelsText)
	}
}

func TestModelsJSONMatchesPython(t *testing.T) {
	rows := ModelRows(model.Models())
	got, err := ToJSON(rows)
	if err != nil {
		t.Fatalf("ToJSON() error = %v, want nil", err)
	}
	if got != wantModelsJSON {
		t.Errorf("ToJSON(ModelRows(model.Models())) =\n%s\nwant\n%s", got, wantModelsJSON)
	}
}

func TestModelRowsSortsBackends(t *testing.T) {
	m := &model.SwitchModel{
		Key:         "fake",
		DisplayName: "Fake",
		Class:       model.ClassFullyManaged,
		PortCount:   4,
		Backends:    []model.Backend{model.BackendTelnet, model.BackendSNMP, model.BackendHTTP},
		Verified:    true,
	}
	rows := ModelRows([]*model.SwitchModel{m})
	want := []string{"http", "snmp", "telnet"}
	got := rows[0].Backends
	if len(got) != len(want) {
		t.Fatalf("ModelRows backends = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ModelRows backends[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestModelsTextUnverifiedSuffix(t *testing.T) {
	rows := []ModelRow{
		{Key: "k1", DisplayName: "D1", Backends: []string{"snmp"}, Verified: true},
		{Key: "k2", DisplayName: "D2", Backends: []string{"snmp"}, Verified: false},
	}
	got := ModelsText(rows)
	want := "k1           D1                       snmp\n" +
		"k2           D2                       snmp  [UNVERIFIED]"
	if got != want {
		t.Errorf("ModelsText() =\n%q\nwant\n%q", got, want)
	}
}
