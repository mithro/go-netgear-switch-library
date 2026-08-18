// Package fastpath drives NETGEAR's FASTPATH device CLI -- the interactive
// shell exposed over SSH, Telnet or a physical serial line on the
// fully-managed and Smart Managed Pro product lines -- as a backend for the
// root netgearswitch facade (model.BackendSSH / model.BackendTelnet /
// model.BackendConsole). It is the CLI-protocol analogue of package snmp's
// Reader/Writer and package webui's HTTPModelSpec.
//
// The package has three layers:
//
//   - Transport (ssh.go/telnet.go/serial.go): NewSSHTransport/
//     NewTelnetTransport/NewSerialTransport dial and authenticate a raw
//     interactive shell. Session and ShellDriver (session.go) turn that raw
//     shell into a line-oriented command/response API -- Run sends one
//     command and returns its output, RunSCPCopy and RunWriteMemory handle
//     the CLI's own multi-prompt SCP-copy and "write memory" confirmation
//     dialogs.
//   - CliModelSpec (spec.go), looked up per model via CLISpec, holds the
//     per-model command templates and verification flags every read/write
//     below consults -- which command string each operation sends, whether
//     this model's read/write surface has been cross-verified against real
//     hardware. ScpCertProfile/ScpProfile and DeployCertificateSCP
//     (spec.go/cert_scp.go) are the SCP-based certificate deployment path
//     UploadCertificateSCP uses.
//   - Reader (reader.go) and Writer (writer.go), constructed with
//     NewReader/NewWriter given a Session and a *model.SwitchModel, are
//     this backend's netgearswitch.BackendReader/BackendWriter
//     implementations: each read method runs a `show ...` command and
//     parses its table/labelled-scalar output (see the parsing primitives
//     below); each write method builds and sends a `configure`-mode
//     command sequence, applying the same protected-port guard and
//     verify-after-write pattern package snmp uses.
//
// The table/labelled-scalar parsing primitives every entity parser in this
// package builds on (labelledValues for "Label.......... value" dotted-
// leader lines, rulerSpans/iterTableRows for fixed-width "----"-ruled
// tables) live in parse.go; sliceCell there deliberately reproduces
// Python's out-of-range CLAMPING behaviour on a short data row, where Go's
// native slicing would panic.
//
// Ported field-for-field from the pinned python-netgear-switch-library @
// 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362 (src/netgear_switch/protocols/cli/
// commands.py and parse.py; the normative source, which is read-only from
// here). Any discrepancy between this package and that pin is a bug in this
// package, not a deliberate deviation, unless called out in a comment.
package fastpath
