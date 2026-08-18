// Package capabilities answers one question -- can model M do operation O
// over backend B, and why not? -- without touching a switch. It is a pure,
// stateless oracle: every verdict is derived from the SAME registry/spec
// objects the real dispatch path (the root package's dispatch.go,
// write_dispatch.go) reads -- model.SwitchModel fields,
// webui.HTTPModelSpec endpoint paths, fastpath.CliModelSpec verification
// flags, fastpath.ScpProfile -- never a parallel hand-written table, so
// this package can never quietly disagree with what dispatch actually
// does.
//
// # Operations and verdicts
//
// Operation is one facade operation (types.go's ReadOperations/
// WriteOperations, concatenated as Operations, 32 entries total); look one
// up by its Python-derived snake_case name (e.g. "get_ports") with
// OperationByName. For(m, backend, op) is the verdict for one (model,
// backend, operation) triple: a Capability carrying a Support value
// (SupportSupported, SupportNoBackend, SupportUnsupported or
// SupportUnverified) and, for anything other than SupportSupported, a
// human-readable Reason. ForKey is For's string-keyed convenience entry
// point (model key + operation name, for a caller that has not already
// resolved a *model.SwitchModel/Operation); BackendsFor lists a model's
// backends in the facade's own default-preference order; Matrix expands
// modelKeys x their backends x operations into every Capability at once,
// e.g. for a support-matrix report.
//
// # Per-backend derivation
//
// support.go's For dispatches to one of four per-backend derivations, one
// file each: support_snmp.go, support_nsdp.go, support_http.go and
// support_cli.go (SSH/Telnet/console share one CLI derivation). Each reads
// the SAME per-model spec data its real backend package (snmp, nsdp,
// webui, fastpath) already uses to decide whether it can serve an
// operation, so a change to what a backend can actually do can never drift
// silently out of sync with what this oracle reports.
//
// Ported field-for-field from src/netgear_switch/capabilities.py (pinned
// worktree go-port-pin-b26eb1f). Any discrepancy between this package and
// that pin is a bug in this package, not a deliberate deviation, unless
// called out in a comment.
package capabilities
