package capabilities

// support_cli_test.go: pins cliSupport against Python's _cli_support
// (capabilities.py:314-341) and the SCP cert gate
// (protocols/cli/commands.py's scp_cert_profile via fastpath.ScpProfile).

import (
	"testing"

	"github.com/mithro/go-netgear-switch-library/fastpath"
)

func TestCLISupportReadsWritesVerifiedToday(t *testing.T) {
	// Every CLI model's spec is ReadsVerified=WritesVerified=true today (see
	// fastpath/spec.go's newCliModelSpec calls) -- so cliSupport must report
	// SUPPORTED (subject to the other branches), never UNVERIFIED, for all 4.
	for _, key := range []string{"gsm7252ps", "m4300-24x", "m4300-16x", "gsm7228ps"} {
		m := mustModelSnmp(t, key)
		op, err := OperationByName("get_ports")
		if err != nil {
			t.Fatalf("OperationByName(get_ports): %v", err)
		}
		support, reason := cliSupport(m, op)
		if support != SupportSupported {
			t.Errorf("cliSupport(%s, get_ports) = %v (%s), want SupportSupported", key, support, reason)
		}
	}
}

func TestCLISupportSCPCertificateGateMatchesFastpath(t *testing.T) {
	// test_scp_certificate_gate's Go equivalent: the oracle's verdict for
	// upload_certificate_scp must equal whether fastpath.ScpProfile(m)
	// itself errors -- the oracle asks the facade's own gate, not a copy.
	for _, key := range []string{"gsm7252ps", "m4300-24x", "m4300-16x", "gsm7228ps"} {
		m := mustModelSnmp(t, key)
		_, profileErr := fastpath.ScpProfile(m)
		wantSupported := profileErr == nil

		op, err := OperationByName("upload_certificate_scp")
		if err != nil {
			t.Fatalf("OperationByName(upload_certificate_scp): %v", err)
		}
		support, _ := cliSupport(m, op)
		gotSupported := support == SupportSupported
		if gotSupported != wantSupported {
			t.Errorf("cliSupport(%s, upload_certificate_scp) supported = %v, want %v (ScpProfile err = %v)",
				key, gotSupported, wantSupported, profileErr)
		}
	}
}

func TestCLISupportPoEGate(t *testing.T) {
	// m4300-24x: CLI model with PoEPortCount == 0.
	m := mustModelSnmp(t, "m4300-24x")
	op, err := OperationByName("get_poe")
	if err != nil {
		t.Fatalf("OperationByName(get_poe): %v", err)
	}
	support, _ := cliSupport(m, op)
	if support != SupportUnsupported {
		t.Errorf("cliSupport(m4300-24x, get_poe) = %v, want SupportUnsupported", support)
	}
}

func TestCLISupportPoESupportedOnPSEModel(t *testing.T) {
	// gsm7252ps: CLI model that DOES have PSE ports.
	m := mustModelSnmp(t, "gsm7252ps")
	op, err := OperationByName("get_poe")
	if err != nil {
		t.Fatalf("OperationByName(get_poe): %v", err)
	}
	support, reason := cliSupport(m, op)
	if support != SupportSupported {
		t.Errorf("cliSupport(gsm7252ps, get_poe) = %v (%s), want SupportSupported", support, reason)
	}
}
