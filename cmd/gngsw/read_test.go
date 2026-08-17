package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// --- models: no switch touched at all -----------------------------------

func TestModels_Table(t *testing.T) {
	code, out, _ := runCLI([]string{"models"}, "", nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "gsm7252ps") {
		t.Errorf("stdout = %q, want it to contain \"gsm7252ps\"", out)
	}
}

func TestModels_JSON(t *testing.T) {
	code, out, _ := runCLI([]string{"--json", "models"}, "", nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out)
	}
	found := false
	for _, r := range rows {
		if r["key"] == "gsm7252ps" {
			found = true
		}
	}
	if !found {
		t.Errorf("no row with key=gsm7252ps in %v", rows)
	}
}

// --- real end-to-end: full flag parsing -> resolve.Resolve -> facade ----
// -> renderer, against a REAL virtual.VirtualSwitch over real loopback
// SNMP -- NO SwitchFactory bypass. Values asserted below are the SAME
// pinned literals facade_integration_test.go's own capstone test already
// verified at the facade layer (port1 "1/0/1", vlan90 "iot", ...): this
// proves gngsw's CLI plumbing reaches the same data through the real
// --host/--model/--community flags, not that the underlying protocol
// stack is correct (already proven elsewhere).

func TestE2E_PortsTable_RealSNMP(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	host := vsw.Host + ":" + strconv.Itoa(vsw.SnmpPort)

	code, out, errOut := runCLI([]string{"--host", host, "--model", "gsm7252ps", "--community", "public", "ports"}, "", nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "Port") {
		t.Errorf("stdout missing table header \"Port\": %q", out)
	}
	if !strings.Contains(out, "1/0/1") {
		t.Errorf("stdout missing port1 name \"1/0/1\": %q", out)
	}
}

func TestE2E_PortsJSON_FlagBeforeAndAfterSubcommand(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	host := vsw.Host + ":" + strconv.Itoa(vsw.SnmpPort)

	for _, argv := range [][]string{
		{"--json", "--host", host, "--model", "gsm7252ps", "--community", "public", "ports"},
		{"--host", host, "--model", "gsm7252ps", "--community", "public", "ports", "--json"},
	} {
		code, out, errOut := runCLI(argv, "", nil)
		if code != 0 {
			t.Fatalf("argv=%v: exit code = %d, want 0 (stderr=%q)", argv, code, errOut)
		}
		var ports []map[string]any
		if err := json.Unmarshal([]byte(out), &ports); err != nil {
			t.Fatalf("argv=%v: stdout is not valid JSON: %v\n%s", argv, err, out)
		}
		found := false
		for _, p := range ports {
			if p["name"] == "1/0/1" {
				found = true
			}
		}
		if !found {
			t.Errorf("argv=%v: no port with name=1/0/1 in %v", argv, ports)
		}
	}
}

func TestE2E_Vlans_RealSNMP(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	host := vsw.Host + ":" + strconv.Itoa(vsw.SnmpPort)

	code, out, _ := runCLI([]string{"--host", host, "--model", "gsm7252ps", "--community", "public", "vlans"}, "", nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "iot") {
		t.Errorf("stdout missing vlan90 name \"iot\": %q", out)
	}
}

func TestE2E_Show_RealSNMP(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	host := vsw.Host + ":" + strconv.Itoa(vsw.SnmpPort)

	code, out, _ := runCLI([]string{"--host", host, "--model", "gsm7252ps", "--community", "public", "show"}, "", nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "## VLANs") || !strings.Contains(out, "iot") {
		t.Errorf("stdout missing snapshot sections/data: %q", out)
	}
	if !strings.HasPrefix(out, "# gsm7252ps @ "+host) {
		t.Errorf("stdout header = %q, want prefix \"# gsm7252ps @ %s\"", out, host)
	}
}

func TestE2E_Identify_RealSNMP(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	host := vsw.Host + ":" + strconv.Itoa(vsw.SnmpPort)

	code, out, _ := runCLI([]string{"--host", host, "--model", "gsm7252ps", "--community", "public", "identify"}, "", nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "gsm7252ps") {
		t.Errorf("stdout missing detected key \"gsm7252ps\": %q", out)
	}
}

func TestE2E_PoeBare_RealSNMP(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	host := vsw.Host + ":" + strconv.Itoa(vsw.SnmpPort)

	code, out, _ := runCLI([]string{"--host", host, "--model", "gsm7252ps", "--community", "public", "poe"}, "", nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "Power(mW)") || !strings.Contains(out, "3500") {
		t.Errorf("stdout missing PoE table data: %q", out)
	}
}

// --- SwitchFactory-injected: remaining read commands, still against a --
// real virtual switch, proving each subcommand's facade-method + renderer
// wiring without re-proving the resolve.Resolve plumbing above already
// covers.

func TestReads_SwitchFactory(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")
	factory := snmpSwitchFactory(sw)

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{"stats", []string{"stats"}, "RxBytes"},
		{"pvids", []string{"pvids"}, "PVID"},
		{"lldp", []string{"lldp"}, "sw-cisco-shed"},
		{"macs", []string{"macs"}, "C8:00:84:89:71:70"},
		{"sensors", []string{"sensors"}, "Sensor"},
		{"hostname", []string{"hostname"}, ""},
		{"syslog", []string{"syslog"}, "enabled:"},
		{"ip", []string{"ip"}, "10.1.5.22"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runCLI(tc.argv, "", factory)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
			}
			if tc.want != "" && !strings.Contains(out, tc.want) {
				t.Errorf("stdout = %q, want it to contain %q", out, tc.want)
			}
		})
	}
}

// --- users/services: served only over CLI/HTTP, not SNMP (gsm7252ps's --
// default-preference backend) -- so this test injects an in-process CLI
// session (virtual.VirtualSwitch.CliSession, no real socket) and pins the
// dispatch to it via WithBackend, mirroring facade_cli_integration_test.go's
// own in-process pattern.

func TestReads_UsersServices_OverCLIBackend(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	factory := snmpSwitchFactory(cliBackedSwitch(t, vsw, "gsm7252ps"))

	for _, argv := range [][]string{{"users"}, {"services"}} {
		code, out, errOut := runCLI(argv, "", factory)
		if code != 0 {
			t.Fatalf("argv=%v: exit code = %d, want 0 (stderr=%q)", argv, code, errOut)
		}
		if out == "\n" || out == "" {
			t.Errorf("argv=%v: stdout is empty, want a rendered table", argv)
		}
	}
}

// --- nsdp-device: NSDP's port cannot be embedded in --host the way SNMP's
// can (see facade_nsdp_integration_test.go's own doc comment), so this
// injects an nsdp.Client pointed at the virtual switch's ephemeral
// NsdpPort directly -- the same seam that file's nsdpFacadeFor uses.

func TestRead_NSDPDevice_SwitchFactory(t *testing.T) {
	vsw := startVirtualSwitch(t, "gs110emx")
	sw := nsdpSwitch(t, vsw, "gs110emx")
	factory := snmpSwitchFactory(sw)

	code, out, errOut := runCLI([]string{"nsdp-device"}, "", factory)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "model:") {
		t.Errorf("stdout = %q, want it to contain \"model:\"", out)
	}
}

// --- --backend validation + poe usage errors -----------------------------

func TestBackendFlag_InvalidValue_ExitsUsage(t *testing.T) {
	code, out, errOut := runCLI([]string{"--backend", "bogus", "models"}, "", nil)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (stdout=%q stderr=%q)", code, out, errOut)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty (nothing should print before a usage error)", out)
	}
	if !strings.Contains(errOut, "backend") {
		t.Errorf("stderr = %q, want it to mention \"backend\"", errOut)
	}
}

func TestBackendFlag_CaseInsensitive(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	host := vsw.Host + ":" + strconv.Itoa(vsw.SnmpPort)

	code, _, errOut := runCLI([]string{"--host", host, "--model", "gsm7252ps", "--community", "public", "--backend", "SNMP", "ports"}, "", nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%q)", code, errOut)
	}
}

func TestPoe_PortWithoutAction_ExitsUsage(t *testing.T) {
	vsw := startVirtualSwitch(t, "gsm7252ps")
	sw := snmpSwitch(t, vsw, "gsm7252ps")

	code, out, errOut := runCLI([]string{"poe", "1"}, "", snmpSwitchFactory(sw))
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (stdout=%q stderr=%q)", code, out, errOut)
	}
	if !strings.Contains(errOut, "action") {
		t.Errorf("stderr = %q, want it to mention \"action\"", errOut)
	}
}

func TestPort_BadIntArg_ExitsUsage(t *testing.T) {
	code, _, errOut := runCLI([]string{"port", "abc", "up"}, "", nil)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr=%q)", code, errOut)
	}
}

func TestVlan_BareNoSubcommand_ExitsUsage(t *testing.T) {
	code, out, errOut := runCLI([]string{"vlan"}, "", nil)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (stdout=%q stderr=%q)", code, out, errOut)
	}
}

func TestBareInvocation_PrintsHelpToStderr_ExitsUsage(t *testing.T) {
	code, out, errOut := runCLI(nil, "", nil)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if out != "" {
		t.Errorf("stdout = %q, want empty", out)
	}
	if !strings.Contains(errOut, "gngsw") {
		t.Errorf("stderr = %q, want cobra help text mentioning \"gngsw\"", errOut)
	}
}
