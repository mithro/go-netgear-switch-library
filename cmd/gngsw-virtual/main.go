// Command gngsw-virtual is a standalone binary that runs the Go virtual
// (fake) switch(es) on real loopback sockets, so an external tool -- a
// cross-language conformance harness, or a human poking at a mock with
// snmpwalk/curl/ssh -- can talk to them without real hardware. It
// reimplements Python's "ngsw serve" subcommand
// (src/netgear_switch/cli/main.py's _cmd_serve, the normative source for
// this binary's flag surface and validation behaviour) as its own binary,
// built on this repository's own virtual package (virtual.NewVirtualSwitch/
// Start/Stop) rather than re-implementing any fake-switch protocol logic
// here.
//
// Unlike Python's serve (a human-readable, multi-line-per-switch block --
// see server.py's _print_switch), this binary's announcement is Go's own
// contract (design doc §8.3): exactly one JSON line per successfully
// started switch, naming its model, host, every bound face's port, and the
// shared SNMP community / admin password -- so a cross-test harness can
// machine-parse where to connect without scraping prose. See serve.go's
// doc comment for the full contract and this package's exact deviations
// from Python's own flag semantics.
package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, stop))
}
