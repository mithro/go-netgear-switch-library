// Package netgearswitch is a Go client library for reading and safely
// writing configuration on NETGEAR managed and "Plus" (smart-managed)
// switches. It is a field-for-field port of NETGEAR's
// python-netgear-switch-library, built with the goal of 100% feature
// parity: every read and write the Python reference supports has a Go
// equivalent here, ported from the same normative source and, wherever
// possible, cross-checked against the same real-hardware captures. Any
// discrepancy between this library and its pinned Python source is a bug,
// not a deliberate deviation, unless a comment says otherwise.
//
// This package (netgearswitch) is the facade callers use day to day: a
// model-driven Switch type with one method per read or write operation. Its
// sub-packages implement the four wire protocols and the supporting data
// model and are documented independently -- see model, snmp, nsdp, webui,
// fastpath, capabilities and virtual -- but most callers never need to
// import any of them directly, since alias.go re-exports the model types,
// enums and error sentinels callers most often need under this package's
// own name (netgearswitch.PortStatus, netgearswitch.ErrProtectedPort, and
// so on).
//
// # Backends
//
// A NETGEAR switch can be reached over up to four independent protocols,
// called backends in this library (model.Backend):
//
//   - SNMP (model.BackendSNMP) -- the richest and fastest backend on the
//     fully-managed and Smart Managed Pro product lines: standard MIB-II
//     plus a per-family NETGEAR vendor OID subtree. See package snmp.
//   - NSDP (model.BackendNSDP) -- NETGEAR's own Switch Discovery Protocol,
//     the only backend the unmanaged "Plus" line (GS110EMX, GS305EP,
//     GS105PE, ...) speaks besides its web UI. See package nsdp.
//   - HTTP (model.BackendHTTP) -- the switch's own web UI, scraped and
//     posted to directly; several distinct HTML/XML dialects exist across
//     models. See package webui.
//   - The FASTPATH device CLI, reachable over SSH (model.BackendSSH),
//     Telnet (model.BackendTelnet) or a physical serial line
//     (model.BackendConsole), driven as an interactive shell. See package
//     fastpath.
//
// No single model speaks all four: model.SwitchModel.Backends lists exactly
// which ones a given model supports (model.GetModel/Models -- re-exported
// here as GetModel/Models), and a model that lacks a backend entirely
// refuses any operation routed to it, naming the backend
// (model.ErrUnsupportedCapability). Before ever touching a switch, the
// capabilities package (re-exported here as For/ForKey/BackendsFor/Matrix)
// can answer "can model M do operation O over backend B, and why not?" from
// the registry data alone.
//
// # Getting started
//
// Construct a Switch with New, given an already-looked-up
// *model.SwitchModel and a host or "host:port" address, then call one of
// its read methods:
//
//	m, err := netgearswitch.GetModel("gsm7252ps")
//	sw, err := netgearswitch.New(m, "10.1.5.22", netgearswitch.WithSNMPCommunity("public"))
//	ports, err := sw.GetPorts(ctx)
//
// FromConfig builds a Switch from a SwitchConfig instead (e.g. one field of
// a parsed inventory file, see inventory.go), mapping its community/
// password/protected-port fields onto the same options New accepts.
// ResolveSecret and EnsureSecureFile support a SwitchConfig's secret
// fields, which may name a literal value, an "${ENV_VAR}" reference or a
// "!command args..." to run.
//
// The package-level Example, and ExampleSwitch_GetVLANs/ExampleSwitch_GetPoE/
// ExampleSwitch_Identify/ExampleSwitch_DeleteVlan/ExampleWithReadBackend
// below, are complete, runnable programs: each connects to an in-process
// virtual (fake) switch and prints real output verified by `go test`, so
// there is nothing to install to try them. See also ExampleFor/ExampleMatrix
// in package capabilities and ExampleNewVirtualSwitch in package virtual.
//
// # Backend selection
//
// Every read method takes a trailing ...ReadOption; every write method
// takes a Write value. Both carry an optional Backend override
// (WithReadBackend / Write.Backend) that pins ONE call to exactly that
// backend. Absent a per-call override, a Switch falls back to its own
// pinned default (WithBackend, set once at construction) and, absent that
// too, to the model's highest-preference backend: SNMP, then NSDP, then
// HTTP, then SSH -- Telnet and the serial console are never chosen
// automatically and must be named explicitly.
//
// Backend resolution is FAIL-FAST with NO silent fallback: exactly one
// backend is resolved for a given call, and if that backend cannot serve
// the requested operation (or the model does not have it at all), the call
// returns an error naming that backend and wrapping
// model.ErrUnsupportedCapability -- it is never silently retried against a
// different backend. This is deliberate: an earlier version of this
// library (and, historically, of the Python reference) would fall through
// to another backend on failure, which let a genuine capability gap on one
// backend hide behind a different backend quietly answering instead. A
// resolved backend is never switched mid-operation.
//
// # Writes and safety
//
// Every write method takes a Write value: Write.Force overrides that
// operation's own protected-port guard (WithProtectedPorts, set at
// construction) where one applies, and Write.Backend pins the call to one
// backend as described above. A disruptive write to a protected port
// without Force returns an error wrapping ErrProtectedPort naming the
// clashing port(s); DeleteVlan additionally checks its target VLAN's member
// ports against the protected set before dispatch, so every backend gets
// the same refusal even on a backend whose own writer has no such guard.
// SetMgmtIP's guard is unconditional (force=false always refuses, since a
// bad management-IP write can strand the switch), independent of protected
// ports.
//
// Most writers verify their own change by reading the affected state back
// immediately after writing it, returning a *WriteVerificationError
// (carrying the before/after values) if the device did not end up in the
// expected state.
//
// # Detection and identification
//
// DetectModel identifies a switch's actual model over SNMP before a Switch
// can even be constructed -- call it first, then GetModel(detected.Key) and
// New once detected.Key is non-nil. Switch.Identify does the same thing for
// an already-constructed Switch, but reports the DEVICE's real model,
// independent of (and ignoring) whichever model the Switch happens to have
// been constructed with -- useful to confirm a Switch's assumed identity
// before trusting it.
//
// # Testing with the virtual fake
//
// Package virtual implements an in-process, real-listener fake switch:
// NewVirtualSwitch binds real loopback SNMP/NSDP/HTTP/SSH/Telnet sockets
// (whichever the model supports) backed by seeded, deterministic in-memory
// state, so a Switch constructed with New/FromConfig and pointed at it
// exercises the exact same wire code a real switch would, with no hardware
// required. Every runnable example in this package and in capabilities/
// virtual is built on it; see package virtual's own documentation.
//
// # Companion CLIs
//
// This module also builds three command-line programs (cmd/):
//
//   - gngsw -- an interactive command-line client over this facade: read
//     and write a switch's configuration from a shell or a script.
//   - gngsw-mcp -- an MCP (Model Context Protocol) server exposing this
//     facade's read/write API as tools over stdio, for driving a switch
//     from an LLM agent.
//   - gngsw-virtual -- a standalone binary that runs the virtual package's
//     fake switches on real loopback sockets, so an external tool (a
//     cross-language conformance harness, or a human with snmpwalk/curl/
//     ssh) can talk to one without real hardware.
package netgearswitch
