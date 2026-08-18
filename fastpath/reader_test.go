package fastpath

// Tests for Reader (reader.go): the 10 FASTPATH CLI read ops, driven
// against a SCRIPTED fakeCliSession (an in-memory Session fake, not a real
// Transport/ShellDriver) that returns the byte-identical captured fixtures
// in testdata/cli/ as canned command outputs, mirroring the pinned
// python-netgear-switch-library @ b26eb1f
// cli_read.py tests' shape (a fake CliSession, not a live device).
//
// Per the task's methodology, expected parsed values are NEVER hand-
// derived here: every "want" is built by calling the SAME already-tested
// parse.go function (parse_entities{1,2}_test.go already ground-truth that
// function against the pinned Python reference) directly on the exact
// fixture text handed to the fake session -- these tests exist to verify
// Reader's WIRING (right command(s) issued, in the right order, addressed
// to the right session, fed to the right parser), not to re-verify parser
// correctness a second time.
//
// Where a real per-op fixture set doesn't cover every VLAN/port an N+1 op
// would query (only one gsm7252ps show-vlan-<id> capture exists, for
// example, not all 14 VLANs show_vlan_brief.txt lists), the same single
// real captured fixture is reused as the canned response for every such
// command -- still a byte-identical real transcript, never hand-crafted
// text -- because what these tests assert is the command SEQUENCE (every
// command Reader issues, in order, with the right per-port/per-VLAN
// addressing) and that each response is routed through the right parser
// call, not that 14 distinct real devices agree with each other.
import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// fakeCliSession is a scripted, in-memory Session (session.go's interface)
// fake: Run records every command issued (in order) and looks up its
// response via respond, a caller-supplied function so different tests can
// script anything from "one command, one fixture" to "route by command
// prefix" (needed for the N+1 ops' per-port/per-VLAN commands). RunSCPCopy/
// RunWriteMemory are unused by any read op and fail loudly if a test
// accidentally exercises them.
type fakeCliSession struct {
	mu       sync.Mutex
	commands []string
	respond  func(command string) (string, error)
}

func (f *fakeCliSession) Run(_ context.Context, command string) (string, error) {
	f.mu.Lock()
	f.commands = append(f.commands, command)
	f.mu.Unlock()
	if f.respond == nil {
		return "", nil
	}
	return f.respond(command)
}

func (f *fakeCliSession) RunSCPCopy(context.Context, string, string) (string, error) {
	return "", errors.New("fakeCliSession: RunSCPCopy unexpectedly called by a read op")
}

func (f *fakeCliSession) RunWriteMemory(context.Context, string, bool) (string, error) {
	return "", errors.New("fakeCliSession: RunWriteMemory unexpectedly called by a read op")
}

func (f *fakeCliSession) Close() error { return nil }

func (f *fakeCliSession) commandsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.commands))
	copy(out, f.commands)
	return out
}

// oneShotSession scripts a Session that responds with text for every
// command it receives, regardless of what the command is -- used by every
// single-round-trip op test below, where there is exactly one command to
// script.
func oneShotSession(text string) *fakeCliSession {
	return &fakeCliSession{respond: func(string) (string, error) { return text, nil }}
}

func mustGetModel(t *testing.T, key string) *model.SwitchModel {
	t.Helper()
	m, err := model.GetModel(key)
	if err != nil {
		t.Fatalf("model.GetModel(%q): %v", key, err)
	}
	return m
}

func mustNewReader(t *testing.T, session Session, m *model.SwitchModel) *Reader {
	t.Helper()
	r, err := NewReader(session, m)
	if err != nil {
		t.Fatalf("NewReader(%q): %v", m.Key, err)
	}
	return r
}

// ---------------------------------------------------------------------
// NewReader construction gate (dossier: "__init__ calls cli_spec(model)
// ... so constructing a CliReader for a model with no CLI backend or no
// spec raises UnsupportedCapabilityError IMMEDIATELY at construction").
// ---------------------------------------------------------------------

func TestReaderNewReaderUnsupportedModel(t *testing.T) {
	// gs110emx is a Plus-class model with no SSH/TELNET/CONSOLE backend at
	// all (dossier §1.6's "no 5th CLI model" list names it explicitly).
	m := mustGetModel(t, "gs110emx")
	session := &fakeCliSession{}
	_, err := NewReader(session, m)
	if err == nil {
		t.Fatal("NewReader(gs110emx): want error (no CLI backend), got nil")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("NewReader(gs110emx) error = %v, want wrapping model.ErrUnsupportedCapability", err)
	}
	if len(session.commandsSnapshot()) != 0 {
		t.Errorf("NewReader(gs110emx) issued commands before failing: %v", session.commandsSnapshot())
	}
}

// ---------------------------------------------------------------------
// GetPorts (dossier §3.1): one command, PortStatusCmd.
// ---------------------------------------------------------------------

func TestReaderGetPorts(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	text := readCLIFixture(t, "gsm7252ps_show_port_all.txt")
	session := oneShotSession(text)
	r := mustNewReader(t, session, m)

	got, err := r.GetPorts(context.Background())
	if err != nil {
		t.Fatalf("GetPorts: %v", err)
	}
	want := parsePortStatus(text)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetPorts() = %+v, want %+v", got, want)
	}
	wantCmds := []string{r.spec.PortStatusCmd}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

// ---------------------------------------------------------------------
// GetStats (dossier §3.2): N+1 round trips -- PortStatusCmd, then one
// InterfaceStats command per REAL port GetPorts reported (never
// model.PortCount).
// ---------------------------------------------------------------------

func TestReaderGetStats(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	portsText := readCLIFixture(t, "gsm7252ps_show_port_all.txt")
	ifaceText := readCLIFixture(t, "gsm7252ps_show_interface_ethernet_1_0_1.txt")
	session := &fakeCliSession{
		respond: func(command string) (string, error) {
			if strings.HasPrefix(command, "show interface ethernet") {
				return ifaceText, nil
			}
			return portsText, nil
		},
	}
	r := mustNewReader(t, session, m)

	got, err := r.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}

	ports := parsePortStatus(portsText)
	if len(ports) == 0 {
		t.Fatal("fixture parsed to zero ports -- test fixture broken")
	}
	wantCmds := []string{r.spec.PortStatusCmd}
	want := make([]model.PortStats, 0, len(ports))
	for _, p := range ports {
		wantCmds = append(wantCmds, r.spec.InterfaceStats(p.Port))
		want = append(want, parseInterfaceCounters(ifaceText, p.Port))
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetStats() = %+v, want %+v", got, want)
	}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

// TestReaderGetStatsGSM7228PSUplinkIface exercises the ONE per-model
// physical-interface-addressing hazard the dossier calls out (§1.3/§1.6):
// gsm7228ps addresses ports 1-48 as "1/gN" but ports >= 49 (its 10G
// uplinks) as "1/xgN" -- a naive port-only template would silently query
// the wrong interface for the uplinks. gsm7228ps_port_all.txt's real
// capture carries all 52 ports (1/g1..1/g48, 1/xg49..1/xg52), so this
// confirms GetStats's InterfaceStats(port) call routes every uplink port
// through the "1/xg{port}" template and every access port through
// "1/g{port}".
func TestReaderGetStatsGSM7228PSUplinkIface(t *testing.T) {
	m := mustGetModel(t, "gsm7228ps")
	portsText := readCLIFixture(t, "gsm7228ps_port_all.txt")
	// No gsm7228ps interface-counters capture exists in testdata/cli; reuse
	// the real gsm7252ps one as the canned per-port response -- this test's
	// point is the COMMAND a given port number produces, not that model's
	// own counter values (parseInterfaceCounters is a model-agnostic
	// labelled-scalar parser).
	ifaceText := readCLIFixture(t, "gsm7252ps_show_interface_ethernet_1_0_1.txt")
	session := &fakeCliSession{
		respond: func(command string) (string, error) {
			if strings.HasPrefix(command, "show interface ethernet") {
				return ifaceText, nil
			}
			return portsText, nil
		},
	}
	r := mustNewReader(t, session, m)

	if _, err := r.GetStats(context.Background()); err != nil {
		t.Fatalf("GetStats: %v", err)
	}

	cmds := session.commandsSnapshot()
	if len(cmds) < 2 {
		t.Fatalf("commands = %v, want at least PortStatusCmd + 1 interface command", cmds)
	}
	byPort := map[int]string{}
	for _, cmd := range cmds[1:] {
		for port := 1; port <= 52; port++ {
			if cmd == r.spec.InterfaceStats(port) {
				byPort[port] = cmd
			}
		}
	}
	if got, want := byPort[48], "show interface ethernet 1/g48"; got != want {
		t.Errorf("port 48 command = %q, want %q", got, want)
	}
	if got, want := byPort[49], "show interface ethernet 1/xg49"; got != want {
		t.Errorf("port 49 command = %q, want %q (first uplink port)", got, want)
	}
	if got, want := byPort[52], "show interface ethernet 1/xg52"; got != want {
		t.Errorf("port 52 command = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------
// GetVLANs (dossier §3.3): N+1 round trips -- VlanBriefCmd, then one
// VlanDetail(vid) command per VLAN listed there, with the brief's name
// OVERRIDING the detail page's own name.
// ---------------------------------------------------------------------

func TestReaderGetVLANs(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	briefText := readCLIFixture(t, "gsm7252ps_show_vlan_brief.txt")
	// Only one real per-VLAN detail capture exists for gsm7252ps (VLAN 90);
	// reused as the canned response for every "show vlan <id>" command --
	// see the file-level doc comment for why that's still a real fixture,
	// not hand-crafted text.
	detailText := readCLIFixture(t, "gsm7252ps_show_vlan_90.txt")
	session := &fakeCliSession{
		respond: func(command string) (string, error) {
			if command == "show vlan brief" {
				return briefText, nil
			}
			return detailText, nil
		},
	}
	r := mustNewReader(t, session, m)

	got, err := r.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs: %v", err)
	}

	brief := parseVLANBrief(briefText)
	if len(brief) == 0 {
		t.Fatal("fixture parsed to zero VLANs -- test fixture broken")
	}
	wantCmds := []string{"show vlan brief"}
	want := make([]model.VLANInfo, 0, len(brief))
	for _, row := range brief {
		wantCmds = append(wantCmds, r.spec.VlanDetail(row.vlan))
		name := row.name
		want = append(want, parseVLANDetail(detailText, &name))
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetVLANs() = %+v, want %+v", got, want)
	}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

// TestReaderGetVLANsM4300Rename confirms the M4300 command rename (dossier
// §1.5): "show vlan brief" -> "show vlan" -- M4300 FASTPATH rejects the
// gsm7252ps-style command outright, so a Reader that sent the wrong string
// here would issue a command the real device answers with "Invalid input".
func TestReaderGetVLANsM4300Rename(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	briefText := readCLIFixture(t, "m4300_24x_show_vlan.txt")
	detailText := readCLIFixture(t, "m4300_24x_show_vlan_5.txt")
	session := &fakeCliSession{
		respond: func(command string) (string, error) {
			if command == "show vlan" {
				return briefText, nil
			}
			return detailText, nil
		},
	}
	r := mustNewReader(t, session, m)
	if r.spec.VlanBriefCmd != "show vlan" {
		t.Fatalf("m4300-24x VlanBriefCmd = %q, want %q", r.spec.VlanBriefCmd, "show vlan")
	}

	got, err := r.GetVLANs(context.Background())
	if err != nil {
		t.Fatalf("GetVLANs: %v", err)
	}
	brief := parseVLANBrief(briefText)
	want := make([]model.VLANInfo, 0, len(brief))
	wantCmds := []string{"show vlan"}
	for _, row := range brief {
		wantCmds = append(wantCmds, r.spec.VlanDetail(row.vlan))
		name := row.name
		want = append(want, parseVLANDetail(detailText, &name))
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetVLANs() = %+v, want %+v", got, want)
	}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

// ---------------------------------------------------------------------
// GetPVIDs (dossier §3.4): one command, PvidCmd.
// ---------------------------------------------------------------------

func TestReaderGetPVIDs(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	text := readCLIFixture(t, "gsm7252ps_show_vlan_port_all.txt")
	session := oneShotSession(text)
	r := mustNewReader(t, session, m)

	got, err := r.GetPVIDs(context.Background())
	if err != nil {
		t.Fatalf("GetPVIDs: %v", err)
	}
	want := parsePVIDs(text)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetPVIDs() = %+v, want %+v", got, want)
	}
	wantCmds := []string{r.spec.PvidCmd}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

// ---------------------------------------------------------------------
// GetMACs (dossier §3.5): one command, MacTableCmd; gated on
// model.HasMACTable().
// ---------------------------------------------------------------------

func TestReaderGetMACs(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	text := readCLIFixture(t, "gsm7252ps_show_mac_addr_table.txt")
	session := oneShotSession(text)
	r := mustNewReader(t, session, m)

	got, err := r.GetMACs(context.Background())
	if err != nil {
		t.Fatalf("GetMACs: %v", err)
	}
	want := parseMacTable(text)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetMACs() = %+v, want %+v", got, want)
	}
	wantCmds := []string{r.spec.MacTableCmd}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

// TestReaderGetMACsGatedNoMACTable exercises the has_mac_table guard
// (dossier §3.5) with a synthetic CLI-backed-but-no-SNMP model -- no
// registered model triggers this today (every CLI model also carries SNMP),
// but the guard must fire honestly if one ever does, per the dossier's
// explicit instruction to port it faithfully.
func TestReaderGetMACsGatedNoMACTable(t *testing.T) {
	m := &model.SwitchModel{Key: "gsm7252ps", Backends: []model.Backend{model.BackendSSH}}
	session := &fakeCliSession{}
	r := mustNewReader(t, session, m)

	_, err := r.GetMACs(context.Background())
	if err == nil {
		t.Fatal("GetMACs: want error (no MAC table), got nil")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("GetMACs error = %v, want wrapping model.ErrUnsupportedCapability", err)
	}
	if cmds := session.commandsSnapshot(); len(cmds) != 0 {
		t.Errorf("GetMACs issued commands despite the gate: %v", cmds)
	}
}

// ---------------------------------------------------------------------
// GetLLDP (dossier §3.6): one command, LldpCmd.
// ---------------------------------------------------------------------

func TestReaderGetLLDP(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	text := readCLIFixture(t, "gsm7252ps_show_lldp_remote_device_all.txt")
	session := oneShotSession(text)
	r := mustNewReader(t, session, m)

	got, err := r.GetLLDP(context.Background())
	if err != nil {
		t.Fatalf("GetLLDP: %v", err)
	}
	want := parseLLDP(text)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetLLDP() = %+v, want %+v", got, want)
	}
	wantCmds := []string{r.spec.LldpCmd}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

// ---------------------------------------------------------------------
// GetPoE (dossier §3.7): one command, PoeCmd; gated on model.PoEPortCount
// == 0 (the one documented real device-limit gap among CLI reads).
// ---------------------------------------------------------------------

func TestReaderGetPoE(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	text := readCLIFixture(t, "gsm7252ps_show_poe_port_info_all.txt")
	session := oneShotSession(text)
	r := mustNewReader(t, session, m)

	got, err := r.GetPoE(context.Background())
	if err != nil {
		t.Fatalf("GetPoE: %v", err)
	}
	want := parsePoE(text)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetPoE() = %+v, want %+v", got, want)
	}
	wantCmds := []string{r.spec.PoeCmd}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

func TestReaderGetPoEGatedNoPSEPorts(t *testing.T) {
	// m4300-24x has zero PSE ports (dossier §1.6/§3.7's named "real gap vs
	// device limit" case) -- the guard must fire BEFORE ever sending PoeCmd.
	m := mustGetModel(t, "m4300-24x")
	if m.PoEPortCount != 0 {
		t.Fatalf("test assumption violated: m4300-24x.PoEPortCount = %d, want 0", m.PoEPortCount)
	}
	session := &fakeCliSession{}
	r := mustNewReader(t, session, m)

	_, err := r.GetPoE(context.Background())
	if err == nil {
		t.Fatal("GetPoE: want error (no PSE ports), got nil")
	}
	if !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Errorf("GetPoE error = %v, want wrapping model.ErrUnsupportedCapability", err)
	}
	if cmds := session.commandsSnapshot(); len(cmds) != 0 {
		t.Errorf("GetPoE issued commands despite the gate: %v", cmds)
	}
}

// ---------------------------------------------------------------------
// GetSensors (dossier §3.8): one command, EnvironmentCmd. No model gating.
// ---------------------------------------------------------------------

func TestReaderGetSensors(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	text := readCLIFixture(t, "gsm7252ps_show_environment.txt")
	session := oneShotSession(text)
	r := mustNewReader(t, session, m)

	got, err := r.GetSensors(context.Background())
	if err != nil {
		t.Fatalf("GetSensors: %v", err)
	}
	want := parseEnvironment(text)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetSensors() = %+v, want %+v", got, want)
	}
	wantCmds := []string{r.spec.EnvironmentCmd}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

// ---------------------------------------------------------------------
// GetMgmtIP (dossier §3.9): one command, NetworkCmd ("show network", or
// "show ip management" on M4300). No model gating.
// ---------------------------------------------------------------------

func TestReaderGetMgmtIP(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	text := readCLIFixture(t, "gsm7252ps_show_network.txt")
	session := oneShotSession(text)
	r := mustNewReader(t, session, m)

	got, err := r.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP: %v", err)
	}
	want := parseMgmtIP(text)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetMgmtIP() = %+v, want %+v", got, want)
	}
	wantCmds := []string{r.spec.NetworkCmd}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

// TestReaderGetMgmtIPM4300Rename confirms the M4300 command rename
// (dossier §1.5): "show network" -> "show ip management".
func TestReaderGetMgmtIPM4300Rename(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	text := readCLIFixture(t, "m4300_24x_show_ip_management.txt")
	session := oneShotSession(text)
	r := mustNewReader(t, session, m)
	if r.spec.NetworkCmd != "show ip management" {
		t.Fatalf("m4300-24x NetworkCmd = %q, want %q", r.spec.NetworkCmd, "show ip management")
	}

	got, err := r.GetMgmtIP(context.Background())
	if err != nil {
		t.Fatalf("GetMgmtIP: %v", err)
	}
	want := parseMgmtIP(text)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetMgmtIP() = %+v, want %+v", got, want)
	}
	wantCmds := []string{"show ip management"}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

// TestReaderGetHostname mirrors GetMgmtIP's shape: one command (HostsCmd,
// "show hosts"), routed through the already-tested parseHostname.
func TestReaderGetHostname(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	text := hostsFixture("sw-netgear-gsm7252ps-s1.welland.mithis.com")
	session := oneShotSession(text)
	r := mustNewReader(t, session, m)

	got, err := r.GetHostname(context.Background())
	if err != nil {
		t.Fatalf("GetHostname: %v", err)
	}
	want, err := parseHostname(text)
	if err != nil {
		t.Fatalf("test setup: parseHostname: %v", err)
	}
	if got != want {
		t.Errorf("GetHostname() = %q, want %q", got, want)
	}
	wantCmds := []string{r.spec.HostsCmd}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands (hostname) = %v, want %v", gotCmds, wantCmds)
	}
}

// TestReaderGetSyslog proves GetSyslog issues LoggingCmd then
// LoggingHostsCmd, in that order, and routes both responses through the
// already-tested parseSyslog.
func TestReaderGetSyslog(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	session := &fakeCliSession{respond: func(command string) (string, error) {
		switch command {
		case "show logging":
			return syslogLoggingText, nil
		case "show logging hosts":
			return syslogHostsText, nil
		}
		return "", nil
	}}
	r := mustNewReader(t, session, m)

	got, err := r.GetSyslog(context.Background())
	if err != nil {
		t.Fatalf("GetSyslog: %v", err)
	}
	want, err := parseSyslog(syslogLoggingText, syslogHostsText)
	if err != nil {
		t.Fatalf("test setup: parseSyslog: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetSyslog() = %+v, want %+v", got, want)
	}
	wantCmds := []string{r.spec.LoggingCmd, r.spec.LoggingHostsCmd}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands (syslog) = %v, want %v", gotCmds, wantCmds)
	}
}

// TestReaderGetSyslogPropagatesSessionErrorOnFirstCommand proves a session
// failure on LoggingCmd short-circuits GetSyslog before LoggingHostsCmd is
// ever issued.
func TestReaderGetSyslogPropagatesSessionErrorOnFirstCommand(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	wantErr := errors.New("boom")
	session := &fakeCliSession{respond: func(string) (string, error) { return "", wantErr }}
	r := mustNewReader(t, session, m)

	if _, err := r.GetSyslog(context.Background()); !errors.Is(err, wantErr) {
		t.Errorf("GetSyslog() error = %v, want wrapping %v", err, wantErr)
	}
	if gotCmds := session.commandsSnapshot(); len(gotCmds) != 1 {
		t.Errorf("commands = %v, want exactly 1 (LoggingHostsCmd must not be issued)", gotCmds)
	}
}

// TestReaderGetSyslogPropagatesSessionErrorOnSecondCommand proves a session
// failure on LoggingHostsCmd (after LoggingCmd succeeded) still propagates,
// rather than degrading to a partial answer.
func TestReaderGetSyslogPropagatesSessionErrorOnSecondCommand(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	wantErr := errors.New("boom")
	session := &fakeCliSession{respond: func(command string) (string, error) {
		if command == "show logging" {
			return syslogLoggingText, nil
		}
		return "", wantErr
	}}
	r := mustNewReader(t, session, m)

	if _, err := r.GetSyslog(context.Background()); !errors.Is(err, wantErr) {
		t.Errorf("GetSyslog() error = %v, want wrapping %v", err, wantErr)
	}
}

// ---------------------------------------------------------------------
// GetUsers/GetServices: no captured device-transcript FIXTURE FILE exists
// for either command at pin b26eb1f (see parse_users_services_test.go's
// package doc comment for the principle-5 citation), so these two reader
// tests use the SAME docstring-transcribed text that file's parser tests
// use, rather than readCLIFixture.
// ---------------------------------------------------------------------

func TestReaderGetUsers(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	text := "" +
		"User Name                 Access Mode\n" +
		"------------------------  ------------\n" +
		"admin                     Read/Write\n" +
		"guest                     Read Only\n"
	session := oneShotSession(text)
	r := mustNewReader(t, session, m)

	got, err := r.GetUsers(context.Background())
	if err != nil {
		t.Fatalf("GetUsers: %v", err)
	}
	want := parseUsers(text)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetUsers() = %+v, want %+v", got, want)
	}
	wantCmds := []string{r.spec.UsersCmd}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
	if r.spec.UsersCmd != "show users" {
		t.Errorf("UsersCmd = %q, want %q", r.spec.UsersCmd, "show users")
	}
}

// TestReaderGetServices exercises the three-command round trip (dossier-
// style routing, mirroring TestReaderGetStats's per-command fake), and
// confirms the exact command STRINGS -- in particular that the telnet
// command is "show telnetcon", never "show telnet" (which reports the
// switch as an outbound telnet client, not the inbound server).
func TestReaderGetServices(t *testing.T) {
	m := mustGetModel(t, "m4300-24x")
	httpText := "" +
		"HTTP Mode (Unsecure)........................... Enabled\n" +
		"HTTP Port...................................... 80\n" +
		"HTTP Mode (Secure)............................. Enabled\n" +
		"Secure Port..................................... 443\n"
	telnetText := "" +
		"Telnet Server Admin Mode....................... Enable\n" +
		"Telnet Server Port............................. 23\n"
	sshText := "" +
		"Administrative Mode: .......................... Enabled\n" +
		"SSH Port: ...................................... 22\n"
	session := &fakeCliSession{
		respond: func(command string) (string, error) {
			switch command {
			case "show ip http":
				return httpText, nil
			case "show telnetcon":
				return telnetText, nil
			case "show ip ssh":
				return sshText, nil
			default:
				return "", errors.New("unexpected command: " + command)
			}
		},
	}
	r := mustNewReader(t, session, m)

	got, err := r.GetServices(context.Background())
	if err != nil {
		t.Fatalf("GetServices: %v", err)
	}
	want := parseServices(httpText, telnetText, sshText)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetServices() = %+v, want %+v", got, want)
	}
	wantCmds := []string{"show ip http", "show telnetcon", "show ip ssh"}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
}

// TestReaderGetServicesPropagatesSessionError confirms a session failure on
// ANY of the three commands short-circuits GetServices rather than
// returning a partial/degraded result.
func TestReaderGetServicesPropagatesSessionError(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	wantErr := errors.New("boom")
	session := &fakeCliSession{respond: func(string) (string, error) { return "", wantErr }}
	r := mustNewReader(t, session, m)

	if _, err := r.GetServices(context.Background()); !errors.Is(err, wantErr) {
		t.Errorf("GetServices() error = %v, want wrapping %v", err, wantErr)
	}
}

// ---------------------------------------------------------------------
// Identify (dossier §3.10): one command, VersionCmd; searches the GLOBAL
// model registry, not just r.model.
// ---------------------------------------------------------------------

func TestReaderIdentify(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	text := readCLIFixture(t, "gsm7252ps_show_version.txt")
	session := oneShotSession(text)
	r := mustNewReader(t, session, m)

	got, err := r.Identify(context.Background())
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	want := parseVersion(text, model.Models())
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Identify() = %+v, want %+v", got, want)
	}
	wantCmds := []string{r.spec.VersionCmd}
	if gotCmds := session.commandsSnapshot(); !reflect.DeepEqual(gotCmds, wantCmds) {
		t.Errorf("commands = %v, want %v", gotCmds, wantCmds)
	}
	if got.Key == nil || *got.Key != "gsm7252ps" {
		t.Errorf("Identify() Key = %v, want \"gsm7252ps\"", strPtrOrNil(got.Key))
	}
}

// ---------------------------------------------------------------------
// Read op error propagation: a session.Run failure must surface as-is,
// never be swallowed.
// ---------------------------------------------------------------------

func TestReaderGetPortsPropagatesSessionError(t *testing.T) {
	m := mustGetModel(t, "gsm7252ps")
	wantErr := errors.New("boom")
	session := &fakeCliSession{respond: func(string) (string, error) { return "", wantErr }}
	r := mustNewReader(t, session, m)

	_, err := r.GetPorts(context.Background())
	if !errors.Is(err, wantErr) {
		t.Errorf("GetPorts error = %v, want wrapping %v", err, wantErr)
	}
}
