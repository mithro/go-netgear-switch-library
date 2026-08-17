package fastpath

// Tests for parseUsers/parseServices (parse.go). Unlike every other entity
// parser this package tests (parse_entities{1,2}_test.go), these two have
// NO captured device-transcript FIXTURE FILE on the Python side at pin
// b26eb1f -- no tests/fixtures/cli/*users*.txt or *_ip_http*.txt/
// *_telnetcon*.txt/*_ip_ssh*.txt exists, and neither op has a Python test
// file at all (tests/test_http_users.py and tests/test_http_services.py
// cover only the HTTP backend). The values exercised here instead come from
// TWO Python sources, both cited per-test below:
//
//   - parse_users'/parse_services' own inline docstring TRANSCRIPTS
//     (protocols/cli/parse.py:779-782, :714-733, pin b26eb1f) -- prose in a
//     doc comment, not a checked-in fixture.
//   - the live-verified value TABLES recorded in the two Python commit
//     messages that introduced these ops (4619e3c "feat(cli): read the
//     switch's local user accounts", 2c7ddff "feat(cli): read which
//     management services are enabled") -- also prose, not a fixture.
//
// Per this project's principle 5, this file is explicit that its "want"
// values are TRANSCRIBED FROM PYTHON'S DOCSTRING/COMMIT-MESSAGE PROSE, NOT
// FROM A CAPTURED DEVICE FIXTURE -- unlike parse_entities{1,2}_test.go's
// ground-truth-JSON-derived tables.

import (
	"reflect"
	"testing"

	"github.com/mithro/go-netgear-switch-library/model"
)

// ---------------------------------------------------------------------
// parseUsers
// ---------------------------------------------------------------------

// TestParseUsers_DocstringTranscript reproduces parse_users' own docstring
// example VERBATIM (protocols/cli/parse.py:779-782, pin b26eb1f): a single
// "admin" row under the real 3-line-wrapped header, ruler widths
// 24/12/11/14/10 -- the only measured column-width evidence for this
// command anywhere in the pinned source. The access_mode "Privilege-15" in
// this transcript uniquely identifies it as m4300-24x's row (gsm7252ps's
// own admin row reads "Read/Write" per commit 4619e3c, tested separately
// below), so PrivilegedAccess(...) must read Privilege-15 as true.
func TestParseUsers_DocstringTranscript(t *testing.T) {
	text := "" +
		"User        SNMPv3         SNMPv3        SNMPv3\n" +
		"User Name                 Access Mode   Access Mode  Authentication  Encryption\n" +
		"------------------------  ------------  -----------  --------------  ----------\n" +
		"admin                     Privilege-15  Read Only    MD5             None\n"

	got := parseUsers(text)
	want := []model.SwitchUser{
		{
			Name:             "admin",
			AccessMode:       "Privilege-15",
			Privileged:       model.Ptr(true),
			SNMPv3Access:     model.Ptr("Read Only"),
			SNMPv3Auth:       model.Ptr("MD5"),
			SNMPv3Encryption: model.Ptr("None"),
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseUsers(docstring transcript) = %+v, want %+v", got, want)
	}
}

// TestParseUsers_GSM7252PSAccessMode covers gsm7252ps's admin/guest
// access-mode WORDING, transcribed from Python commit 4619e3c's
// live-verified table ("gsm7252ps  admin Read/Write  guest Read Only") --
// NOT the docstring transcript (which is m4300-24x's row) and NOT a
// captured fixture. SNMPv3 columns are left blank: no SNMPv3 state for
// this switch's rows was recorded anywhere in the pinned source, and a
// blank cell must parse to nil, never a guessed value.
func TestParseUsers_GSM7252PSAccessMode(t *testing.T) {
	text := "" +
		"User        SNMPv3         SNMPv3        SNMPv3\n" +
		"User Name                 Access Mode   Access Mode  Authentication  Encryption\n" +
		"------------------------  ------------  -----------  --------------  ----------\n" +
		"admin                     Read/Write\n" +
		"guest                     Read Only\n"

	got := parseUsers(text)
	want := []model.SwitchUser{
		{Name: "admin", AccessMode: "Read/Write", Privileged: model.Ptr(true)},
		{Name: "guest", AccessMode: "Read Only", Privileged: model.Ptr(false)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseUsers(gsm7252ps access modes) = %+v, want %+v", got, want)
	}
}

// TestParseUsers_UnrecognisedAccessModeIsHonestNil covers an access-mode
// word this package's model.PrivilegedAccessModes/UnprivilegedAccessModes
// tables have not measured: Privileged must read nil (an honestly
// unrecognised level), never default to false.
func TestParseUsers_UnrecognisedAccessModeIsHonestNil(t *testing.T) {
	text := "" +
		"User Name                 Access Mode\n" +
		"------------------------  ------------\n" +
		"operator                  Some Future Level\n"

	got := parseUsers(text)
	if len(got) != 1 {
		t.Fatalf("parseUsers() returned %d users, want 1", len(got))
	}
	if got[0].Privileged != nil {
		t.Errorf("parseUsers()[0].Privileged = %v, want nil (unrecognised access mode)", *got[0].Privileged)
	}
}

// TestParseUsers_BlankFirstCellSkipped covers a row whose first cell is
// blank (a summary/footer line some firmware images print below the real
// table): it must be dropped, never fabricated into a nameless account.
func TestParseUsers_BlankFirstCellSkipped(t *testing.T) {
	text := "" +
		"User Name                 Access Mode\n" +
		"------------------------  ------------\n" +
		"admin                     Privilege-15\n" +
		"                          \n"

	got := parseUsers(text)
	if len(got) != 1 || got[0].Name != "admin" {
		t.Errorf("parseUsers() = %+v, want exactly one user named admin", got)
	}
}

// TestParseUsers_NoRulerReturnsEmpty covers text with no ruler line at all
// (e.g. "% Invalid input detected"): iterTableRows yields nothing, and
// parseUsers must return an empty result rather than panicking or
// fabricating a row.
func TestParseUsers_NoRulerReturnsEmpty(t *testing.T) {
	got := parseUsers("% Invalid input detected at '^' marker.\n")
	if len(got) != 0 {
		t.Errorf("parseUsers(no ruler) = %+v, want empty", got)
	}
}

// ---------------------------------------------------------------------
// parseServices
// ---------------------------------------------------------------------

// TestParseServices_DocstringTranscript reproduces parse_services' own
// docstring examples VERBATIM (protocols/cli/parse.py:714-733, pin
// b26eb1f): every field present, every service enabled. This is the
// "everything the command can print, printed" shape.
func TestParseServices_DocstringTranscript(t *testing.T) {
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

	got := parseServices(httpText, telnetText, sshText)
	want := []model.ServiceStatus{
		{Name: "http", Enabled: true, Port: model.Ptr(80)},
		{Name: "https", Enabled: true, Port: model.Ptr(443)},
		{Name: "telnet", Enabled: true, Port: model.Ptr(23)},
		{Name: "ssh", Enabled: true, Port: model.Ptr(22)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseServices(docstring transcript) = %+v, want %+v", got, want)
	}
}

// TestParseServices_GSM7252PSMeasuredShape reproduces the LIVE-VERIFIED
// gsm7252ps table from Python commit 2c7ddff ("feat(cli): read which
// management services are enabled"): "http=on:None  https=on:443
// telnet=off  ssh=on:None" -- confirming the absent-port lines (this
// switch's `show ip http`/`show ip ssh` print NO HTTP Port/SSH Port line
// at all) parse to nil, never defaulted to 80/22. Cross-checked against
// this package's own virtual fake seed (SeedGSM7252PS in
// virtual/seed.go), which was transcribed from the SAME commit.
func TestParseServices_GSM7252PSMeasuredShape(t *testing.T) {
	httpText := "" +
		"HTTP Mode (Unsecure)........................... Enabled\n" +
		"HTTP Mode (Secure)............................. Enabled\n" +
		"Secure Port..................................... 443\n"
	telnetText := "Telnet Server Admin Mode....................... Disable\n"
	sshText := "Administrative Mode: .......................... Enabled\n"

	got := parseServices(httpText, telnetText, sshText)
	want := []model.ServiceStatus{
		{Name: "http", Enabled: true, Port: nil},
		{Name: "https", Enabled: true, Port: model.Ptr(443)},
		{Name: "telnet", Enabled: false, Port: nil},
		{Name: "ssh", Enabled: true, Port: nil},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseServices(gsm7252ps measured shape) = %+v, want %+v", got, want)
	}
}

// TestParseServices_SSHLabelColonQuirk isolates the one documented FASTPATH
// quirk this parser exists to defuse: `show ip ssh` writes its labels WITH
// a trailing colon before the dotted leader, unlike every other FASTPATH
// scalar command. Without stripping it, the lookup misses and SSH reads as
// disabled on a switch whose own output says Enabled -- exactly what the
// first live Python run did (per parse_services' own doc comment).
func TestParseServices_SSHLabelColonQuirk(t *testing.T) {
	sshText := "Administrative Mode: .......................... Enabled\n"
	got := parseServices("", "", sshText)
	ssh := got[3]
	if ssh.Name != "ssh" || !ssh.Enabled {
		t.Errorf("parseServices(...)[ssh] = %+v, want enabled=true (colon-prefixed label must still match)", ssh)
	}
}

// TestParseServices_EmptyTextAllDisabledNoPorts covers every input command
// answering something this parser cannot read at all (e.g. an
// unprovisioned/unreachable command): every field must degrade to
// disabled/no-port, never panic.
func TestParseServices_EmptyTextAllDisabledNoPorts(t *testing.T) {
	got := parseServices("", "", "")
	for _, s := range got {
		if s.Enabled {
			t.Errorf("parseServices(\"\",\"\",\"\")[%s].Enabled = true, want false", s.Name)
		}
		if s.Port != nil {
			t.Errorf("parseServices(\"\",\"\",\"\")[%s].Port = %v, want nil", s.Name, *s.Port)
		}
	}
}
