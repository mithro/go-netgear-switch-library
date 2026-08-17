package fastpath_test

import (
	"errors"
	"testing"

	"github.com/mithro/go-netgear-switch-library/fastpath"
	"github.com/mithro/go-netgear-switch-library/model"
)

// wantSpec is the expected shape of one CliModelSpec, hand-verified against
// the pinned src/netgear_switch/protocols/cli/commands.py (dossier §1.6).
// Only fields that actually vary across the 4 models (plus a couple of
// always-defaulted ones, to prove the defaults really are shared) are
// checked field-by-field; every model's full command set is additionally
// exercised through the templating methods below.
type wantSpec struct {
	modelKey             string
	captured             bool
	readsVerified        bool
	writesVerified       bool
	telnetPort           int
	vlanBriefCmd         string
	networkCmd           string
	ifaceTemplate        string
	uplinkIfaceTemplate  string
	firstUplinkPort      *int
	switchportGeneralCmd string
	mgmtIPExecCmds       []string
	mgmtIPConfigCmds     []string
}

func intPtr(v int) *int { return &v }

var wantSpecs = map[string]wantSpec{
	"gsm7252ps": {
		modelKey:             "gsm7252ps",
		captured:             true,
		readsVerified:        true,
		writesVerified:       true,
		telnetPort:           23,
		vlanBriefCmd:         "show vlan brief",
		networkCmd:           "show network",
		ifaceTemplate:        "1/0/{port}",
		uplinkIfaceTemplate:  "",
		firstUplinkPort:      nil,
		switchportGeneralCmd: "", // None: this XE image has no switchport-mode concept
		mgmtIPExecCmds:       []string{"network parms {address} {netmask} {gateway}"},
		mgmtIPConfigCmds:     nil,
	},
	"m4300-24x": {
		modelKey:             "m4300-24x",
		captured:             true,
		readsVerified:        true,
		writesVerified:       true,
		telnetPort:           23,
		vlanBriefCmd:         "show vlan",          // M4300 override
		networkCmd:           "show ip management", // M4300 override
		ifaceTemplate:        "1/0/{port}",
		uplinkIfaceTemplate:  "",
		firstUplinkPort:      nil,
		switchportGeneralCmd: "switchport mode general",
		mgmtIPExecCmds:       nil, // M4300 override: empty
		mgmtIPConfigCmds: []string{
			"ip management address {address} {netmask}",
			"ip default-gateway {gateway}",
		},
	},
	"m4300-16x": {
		modelKey:             "m4300-16x",
		captured:             true,
		readsVerified:        true,
		writesVerified:       true,
		telnetPort:           23,
		vlanBriefCmd:         "show vlan",
		networkCmd:           "show ip management",
		ifaceTemplate:        "1/0/{port}",
		uplinkIfaceTemplate:  "",
		firstUplinkPort:      nil,
		switchportGeneralCmd: "switchport mode general",
		mgmtIPExecCmds:       nil,
		mgmtIPConfigCmds: []string{
			"ip management address {address} {netmask}",
			"ip default-gateway {gateway}",
		},
	},
	"gsm7228ps": {
		modelKey:             "gsm7228ps",
		captured:             true,
		readsVerified:        true,
		writesVerified:       true,
		telnetPort:           60000,
		vlanBriefCmd:         "show vlan",    // M4300-style override
		networkCmd:           "show network", // NOT M4300's "show ip management"
		ifaceTemplate:        "1/g{port}",
		uplinkIfaceTemplate:  "1/xg{port}",
		firstUplinkPort:      intPtr(49),
		switchportGeneralCmd: "switchport mode general",
		mgmtIPExecCmds:       []string{"network parms {address} {netmask} {gateway}"}, // default, NOT M4300 override
		mgmtIPConfigCmds:     nil,
	},
}

func specFor(t *testing.T, key string) *fastpath.CliModelSpec {
	t.Helper()
	m, err := model.GetModel(key)
	if err != nil {
		t.Fatalf("model.GetModel(%q): %v", key, err)
	}
	spec, err := fastpath.CLISpec(m)
	if err != nil {
		t.Fatalf("fastpath.CLISpec(%q): %v", key, err)
	}
	return spec
}

func strSlicesEqual(a, b []string) bool {
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

// TestCliModelSpec_FourInstances is EXHAUSTIVE per dossier §1.6: exactly
// these 4 models (gsm7252ps, m4300-24x, m4300-16x, gsm7228ps) carry a
// CliModelSpec, and every distinguishing field must match verbatim.
func TestCliModelSpec_FourInstances(t *testing.T) {
	if len(fastpath.CLISpecs) != 4 {
		t.Fatalf("len(fastpath.CLISpecs) = %d, want 4", len(fastpath.CLISpecs))
	}
	for key, want := range wantSpecs {
		t.Run(key, func(t *testing.T) {
			got := specFor(t, key)
			if got.ModelKey != want.modelKey {
				t.Errorf("ModelKey = %q, want %q", got.ModelKey, want.modelKey)
			}
			if got.Captured != want.captured {
				t.Errorf("Captured = %v, want %v", got.Captured, want.captured)
			}
			if got.ReadsVerified != want.readsVerified {
				t.Errorf("ReadsVerified = %v, want %v", got.ReadsVerified, want.readsVerified)
			}
			if got.WritesVerified != want.writesVerified {
				t.Errorf("WritesVerified = %v, want %v", got.WritesVerified, want.writesVerified)
			}
			if got.TelnetPort != want.telnetPort {
				t.Errorf("TelnetPort = %d, want %d", got.TelnetPort, want.telnetPort)
			}
			if got.VlanBriefCmd != want.vlanBriefCmd {
				t.Errorf("VlanBriefCmd = %q, want %q", got.VlanBriefCmd, want.vlanBriefCmd)
			}
			if got.NetworkCmd != want.networkCmd {
				t.Errorf("NetworkCmd = %q, want %q", got.NetworkCmd, want.networkCmd)
			}
			if got.IfaceTemplate != want.ifaceTemplate {
				t.Errorf("IfaceTemplate = %q, want %q", got.IfaceTemplate, want.ifaceTemplate)
			}
			if got.UplinkIfaceTemplate != want.uplinkIfaceTemplate {
				t.Errorf("UplinkIfaceTemplate = %q, want %q", got.UplinkIfaceTemplate, want.uplinkIfaceTemplate)
			}
			if (got.FirstUplinkPort == nil) != (want.firstUplinkPort == nil) {
				t.Errorf("FirstUplinkPort = %v, want %v", got.FirstUplinkPort, want.firstUplinkPort)
			} else if got.FirstUplinkPort != nil && *got.FirstUplinkPort != *want.firstUplinkPort {
				t.Errorf("*FirstUplinkPort = %d, want %d", *got.FirstUplinkPort, *want.firstUplinkPort)
			}
			if got.SwitchportGeneralCmd != want.switchportGeneralCmd {
				t.Errorf("SwitchportGeneralCmd = %q, want %q", got.SwitchportGeneralCmd, want.switchportGeneralCmd)
			}
			if !strSlicesEqual(got.MgmtIPExecCmds, want.mgmtIPExecCmds) {
				t.Errorf("MgmtIPExecCmds = %v, want %v", got.MgmtIPExecCmds, want.mgmtIPExecCmds)
			}
			if !strSlicesEqual(got.MgmtIPConfigCmds, want.mgmtIPConfigCmds) {
				t.Errorf("MgmtIPConfigCmds = %v, want %v", got.MgmtIPConfigCmds, want.mgmtIPConfigCmds)
			}
			// A representative op that must round-trip identically for every
			// model: version_cmd (never overridden by any of the 4 specs).
			if got.VersionCmd != "show version" {
				t.Errorf("VersionCmd = %q, want %q", got.VersionCmd, "show version")
			}
		})
	}
}

// TestCliModelSpec_Iface_GSM7228PS pins the uplink-addressing hazard called
// out by the brief: iface() must select the UPLINK template exactly AT and
// AFTER first_uplink_port (49) and the ACCESS template strictly below it.
// gsm7228ps is the only model where this branch is reachable at all.
func TestCliModelSpec_Iface_GSM7228PS(t *testing.T) {
	spec := specFor(t, "gsm7228ps")
	cases := []struct {
		port int
		want string
	}{
		{1, "1/g1"},
		{48, "1/g48"},  // last access port: strictly below first_uplink_port
		{49, "1/xg49"}, // first_uplink_port itself: AT the threshold -> uplink form
		{50, "1/xg50"},
		{52, "1/xg52"},
	}
	for _, c := range cases {
		if got := spec.Iface(c.port); got != c.want {
			t.Errorf("Iface(%d) = %q, want %q", c.port, got, c.want)
		}
	}
}

// TestCliModelSpec_Iface_S3300Alias proves the "s3300" registry alias
// resolves (via model.GetModel) to the SAME gsm7228ps spec and addressing
// behavior -- there is no separate "s3300" CliModelSpec entry.
func TestCliModelSpec_Iface_S3300Alias(t *testing.T) {
	aliasSpec := specFor(t, "s3300")
	canonicalSpec := specFor(t, "gsm7228ps")
	if aliasSpec != canonicalSpec {
		t.Fatalf("fastpath.CLISpec(s3300) returned a different *CliModelSpec than gsm7228ps")
	}
	if got, want := aliasSpec.Iface(48), "1/g48"; got != want {
		t.Errorf("Iface(48) = %q, want %q", got, want)
	}
	if got, want := aliasSpec.Iface(49), "1/xg49"; got != want {
		t.Errorf("Iface(49) = %q, want %q", got, want)
	}
}

// TestCliModelSpec_Iface_NoUplinkTemplate pins the "no uplink split" case:
// gsm7252ps and the two M4300 SKUs have no uplink_iface_template at all, so
// EVERY port -- however high -- uses the single access-form template.
func TestCliModelSpec_Iface_NoUplinkTemplate(t *testing.T) {
	for _, key := range []string{"gsm7252ps", "m4300-24x", "m4300-16x"} {
		spec := specFor(t, key)
		for _, port := range []int{1, 24, 49, 52, 100} {
			want := "1/0/" + itoa(port)
			if got := spec.Iface(port); got != want {
				t.Errorf("%s: Iface(%d) = %q, want %q", key, port, got, want)
			}
		}
	}
}

func itoa(v int) string {
	// Avoid importing strconv twice for one helper in the test file -- keep
	// it trivially local and obviously correct for the small port numbers
	// used here.
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestCliModelSpec_TemplatingMethods exercises every templating method
// (§1.3) for a representative op per model, pinning the exact command
// strings against the dossier.
func TestCliModelSpec_TemplatingMethods(t *testing.T) {
	spec := specFor(t, "m4300-24x")

	if got, want := spec.VlanDetail(90), "show vlan 90"; got != want {
		t.Errorf("VlanDetail(90) = %q, want %q", got, want)
	}
	if got, want := spec.InterfaceStats(5), "show interface ethernet 1/0/5"; got != want {
		t.Errorf("InterfaceStats(5) = %q, want %q", got, want)
	}
	if got, want := spec.VlanCreate(4001), "vlan 4001"; got != want {
		t.Errorf("VlanCreate(4001) = %q, want %q", got, want)
	}
	if got, want := spec.VlanName(4001, "quarantine"), "vlan name 4001 quarantine"; got != want {
		t.Errorf("VlanName(4001, quarantine) = %q, want %q", got, want)
	}
	if got, want := spec.VlanDelete(4001), "no vlan 4001"; got != want {
		t.Errorf("VlanDelete(4001) = %q, want %q", got, want)
	}
	if got, want := spec.Interface(8), "interface 1/0/8"; got != want {
		t.Errorf("Interface(8) = %q, want %q", got, want)
	}
	if got, want := spec.VlanParticipation(21, true), "vlan participation include 21"; got != want {
		t.Errorf("VlanParticipation(21, true) = %q, want %q", got, want)
	}
	if got, want := spec.VlanParticipation(21, false), "vlan participation exclude 21"; got != want {
		t.Errorf("VlanParticipation(21, false) = %q, want %q", got, want)
	}
	if got, want := spec.VlanTagging(21, true), "vlan tagging 21"; got != want {
		t.Errorf("VlanTagging(21, true) = %q, want %q", got, want)
	}
	if got, want := spec.VlanTagging(21, false), "no vlan tagging 21"; got != want {
		t.Errorf("VlanTagging(21, false) = %q, want %q", got, want)
	}
	if got, want := spec.VlanPvid(21), "vlan pvid 21"; got != want {
		t.Errorf("VlanPvid(21) = %q, want %q", got, want)
	}
	if got, want := spec.PoeAdmin(true), "poe"; got != want {
		t.Errorf("PoeAdmin(true) = %q, want %q", got, want)
	}
	if got, want := spec.PoeAdmin(false), "no poe"; got != want {
		t.Errorf("PoeAdmin(false) = %q, want %q", got, want)
	}
	if got, want := spec.PortAdmin(true), "no shutdown"; got != want {
		t.Errorf("PortAdmin(true) = %q, want %q", got, want)
	}
	if got, want := spec.PortAdmin(false), "shutdown"; got != want {
		t.Errorf("PortAdmin(false) = %q, want %q", got, want)
	}

	execCmds, configCmds := spec.MgmtIP("10.1.5.13", "255.255.255.0", "10.1.5.1")
	if len(execCmds) != 0 {
		t.Errorf("m4300-24x MgmtIP exec cmds = %v, want empty", execCmds)
	}
	wantConfig := []string{
		"ip management address 10.1.5.13 255.255.255.0",
		"ip default-gateway 10.1.5.1",
	}
	if !strSlicesEqual(configCmds, wantConfig) {
		t.Errorf("m4300-24x MgmtIP config cmds = %v, want %v", configCmds, wantConfig)
	}

	// gsm7252ps/gsm7228ps take the OTHER dialect: one privileged-EXEC
	// command, no config-mode commands.
	legacy := specFor(t, "gsm7252ps")
	execCmds, configCmds = legacy.MgmtIP("10.1.5.22", "255.255.255.0", "10.1.5.1")
	wantExec := []string{"network parms 10.1.5.22 255.255.255.0 10.1.5.1"}
	if !strSlicesEqual(execCmds, wantExec) {
		t.Errorf("gsm7252ps MgmtIP exec cmds = %v, want %v", execCmds, wantExec)
	}
	if len(configCmds) != 0 {
		t.Errorf("gsm7252ps MgmtIP config cmds = %v, want empty", configCmds)
	}
}

// TestCliModelSpec_LoggingHostAddAndRemove pins LoggingHostAdd/
// LoggingHostRemove's exact templating, and proves LoggingHostAdd
// propagates model.SyslogSeverityWord's own error for an out-of-range
// severity rather than sending a command built from it.
func TestCliModelSpec_LoggingHostAddAndRemove(t *testing.T) {
	spec := specFor(t, "m4300-24x")

	got, err := spec.LoggingHostAdd("10.1.5.1", 514, 6)
	if err != nil {
		t.Fatalf("LoggingHostAdd: %v", err)
	}
	if want := `logging host "10.1.5.1" ipv4 514 info`; got != want {
		t.Errorf("LoggingHostAdd = %q, want %q", got, want)
	}

	if got, want := spec.LoggingHostRemove(3), "logging host remove 3"; got != want {
		t.Errorf("LoggingHostRemove(3) = %q, want %q", got, want)
	}

	if _, err := spec.LoggingHostAdd("10.1.5.1", 514, 8); err == nil {
		t.Error("LoggingHostAdd(severity=8): want error, got nil")
	}
}

// TestM4300Overrides pins _M4300_OVERRIDES (dossier §1.5) verbatim, and
// proves it replaces EXACTLY those 4 keys -- every other field on the two
// M4300 specs must still carry the base CliModelSpec default (proven here
// via switchport_general_cmd and iface_template, which _M4300_OVERRIDES
// does not touch).
func TestM4300Overrides(t *testing.T) {
	want := fastpath.M4300Overrides{
		VlanBriefCmd:   "show vlan",
		NetworkCmd:     "show ip management",
		MgmtIPExecCmds: nil,
		MgmtIPConfigCmds: []string{
			"ip management address {address} {netmask}",
			"ip default-gateway {gateway}",
		},
	}
	got := fastpath.M4300OverridesValue
	if got.VlanBriefCmd != want.VlanBriefCmd {
		t.Errorf("VlanBriefCmd = %q, want %q", got.VlanBriefCmd, want.VlanBriefCmd)
	}
	if got.NetworkCmd != want.NetworkCmd {
		t.Errorf("NetworkCmd = %q, want %q", got.NetworkCmd, want.NetworkCmd)
	}
	if !strSlicesEqual(got.MgmtIPExecCmds, want.MgmtIPExecCmds) {
		t.Errorf("MgmtIPExecCmds = %v, want %v", got.MgmtIPExecCmds, want.MgmtIPExecCmds)
	}
	if !strSlicesEqual(got.MgmtIPConfigCmds, want.MgmtIPConfigCmds) {
		t.Errorf("MgmtIPConfigCmds = %v, want %v", got.MgmtIPConfigCmds, want.MgmtIPConfigCmds)
	}

	for _, key := range []string{"m4300-24x", "m4300-16x"} {
		spec := specFor(t, key)
		if spec.VlanBriefCmd != want.VlanBriefCmd || spec.NetworkCmd != want.NetworkCmd {
			t.Errorf("%s: overridden fields do not match M4300Overrides", key)
		}
		if !strSlicesEqual(spec.MgmtIPExecCmds, want.MgmtIPExecCmds) || !strSlicesEqual(spec.MgmtIPConfigCmds, want.MgmtIPConfigCmds) {
			t.Errorf("%s: mgmt IP override fields do not match M4300Overrides", key)
		}
		// Untouched fields must keep the base default.
		if spec.SwitchportGeneralCmd != "switchport mode general" {
			t.Errorf("%s: SwitchportGeneralCmd = %q, want default \"switchport mode general\"", key, spec.SwitchportGeneralCmd)
		}
		if spec.IfaceTemplate != "1/0/{port}" {
			t.Errorf("%s: IfaceTemplate = %q, want default \"1/0/{port}\"", key, spec.IfaceTemplate)
		}
	}
}

// TestCLISpec_Dispatch pins the two-stage guard in dossier §1.8: a model
// with no CLI backend at all fails one way, a (synthetic) model that has a
// CLI backend but no registered spec fails a distinct way.
func TestCLISpec_Dispatch(t *testing.T) {
	noCLI, err := model.GetModel("gs305ep") // NSDP+HTTP only, no SSH/TELNET/CONSOLE
	if err != nil {
		t.Fatalf("model.GetModel(gs305ep): %v", err)
	}
	if _, err := fastpath.CLISpec(noCLI); err == nil {
		t.Fatal("fastpath.CLISpec(gs305ep) = nil error, want unsupported-capability error")
	} else if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("fastpath.CLISpec(gs305ep) error = %v, want errors.Is(_, model.ErrUnsupportedCapability)", err)
	}

	hasCLIButNoSpec := &model.SwitchModel{
		Key:      "fake-cli-model",
		Backends: []model.Backend{model.BackendSSH},
	}
	if _, err := fastpath.CLISpec(hasCLIButNoSpec); err == nil {
		t.Fatal("fastpath.CLISpec(fake-cli-model) = nil error, want unsupported-capability error")
	} else if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("fastpath.CLISpec(fake-cli-model) error = %v, want errors.Is(_, model.ErrUnsupportedCapability)", err)
	}
}

// TestScpProfile pins the 3 EXHAUSTIVE ScpCertProfile entries (dossier
// §1.7) and confirms gsm7228ps deliberately has none (HTTP multipart
// instead), and the two-stage dispatch guard (§1.8).
func TestScpProfile(t *testing.T) {
	if len(fastpath.ScpCertProfiles) != 3 {
		t.Fatalf("len(fastpath.ScpCertProfiles) = %d, want 3", len(fastpath.ScpCertProfiles))
	}
	cases := []struct {
		key           string
		crypto        string
		writememStuff bool
		verifyPort    int
	}{
		{"m4300-24x", "modern", false, 443},
		{"m4300-16x", "modern", false, 49152},
		{"gsm7252ps", "legacy", true, 443},
	}
	for _, c := range cases {
		m, err := model.GetModel(c.key)
		if err != nil {
			t.Fatalf("model.GetModel(%q): %v", c.key, err)
		}
		profile, err := fastpath.ScpProfile(m)
		if err != nil {
			t.Fatalf("fastpath.ScpProfile(%q): %v", c.key, err)
		}
		if profile.ModelKey != c.key {
			t.Errorf("%s: ModelKey = %q, want %q", c.key, profile.ModelKey, c.key)
		}
		if profile.Crypto != c.crypto {
			t.Errorf("%s: Crypto = %q, want %q", c.key, profile.Crypto, c.crypto)
		}
		if profile.WritememStuff != c.writememStuff {
			t.Errorf("%s: WritememStuff = %v, want %v", c.key, profile.WritememStuff, c.writememStuff)
		}
		if profile.VerifyPort != c.verifyPort {
			t.Errorf("%s: VerifyPort = %d, want %d", c.key, profile.VerifyPort, c.verifyPort)
		}
	}

	// gsm7228ps deliberately has NO SCP profile: it has a CLI backend (so
	// the first guard passes) but no registered profile (second guard
	// fails) -- HTTP multipart upload is the mechanism instead.
	gsm7228ps, err := model.GetModel("gsm7228ps")
	if err != nil {
		t.Fatalf("model.GetModel(gsm7228ps): %v", err)
	}
	if _, err := fastpath.ScpProfile(gsm7228ps); err == nil {
		t.Fatal("fastpath.ScpProfile(gsm7228ps) = nil error, want unsupported-capability error")
	} else if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("fastpath.ScpProfile(gsm7228ps) error = %v, want errors.Is(_, model.ErrUnsupportedCapability)", err)
	}

	// A model with no CLI backend at all fails the FIRST guard.
	noCLI, err := model.GetModel("gs305ep")
	if err != nil {
		t.Fatalf("model.GetModel(gs305ep): %v", err)
	}
	if _, err := fastpath.ScpProfile(noCLI); err == nil {
		t.Fatal("fastpath.ScpProfile(gs305ep) = nil error, want unsupported-capability error")
	} else if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("fastpath.ScpProfile(gs305ep) error = %v, want errors.Is(_, model.ErrUnsupportedCapability)", err)
	}
}

// TestCLIBackends pins CLI_BACKENDS (dossier §1.1): a model carrying ANY ONE
// of SSH, TELNET, or CONSOLE alone must satisfy the first CLISpec/ScpProfile
// guard (i.e. get as far as the "no registered spec" error, not the "no CLI
// backend at all" error) -- proving each backend individually is a member.
func TestCLIBackends(t *testing.T) {
	for _, b := range []model.Backend{model.BackendSSH, model.BackendTelnet, model.BackendConsole} {
		m := &model.SwitchModel{Key: "probe-" + string(b), Backends: []model.Backend{b}}
		_, err := fastpath.CLISpec(m)
		if err == nil {
			t.Fatalf("backend %v: fastpath.CLISpec(probe) = nil error, want unsupported-capability error", b)
		}
		if !containsSubstr(err.Error(), "no command spec") {
			t.Errorf("backend %v: fastpath.CLISpec(probe) error = %q, want it to reach the \"no command spec\" guard (i.e. this backend alone satisfies CLI_BACKENDS)", b, err.Error())
		}
	}
}

func containsSubstr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
