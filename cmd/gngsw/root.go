package main

import (
	"bytes"
	"fmt"
	"strings"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/safety"
	"github.com/spf13/cobra"
)

// validBackendNames is the set of --backend values gngsw accepts, keyed by
// the LOWERCASE wire value model.Backend itself uses (see
// backendFlag.Set's doc comment for why matching is case-INSENSITIVE at
// the flag layer despite that).
var validBackendNames = map[string]struct{}{
	string(netgearswitch.BackendSNMP):    {},
	string(netgearswitch.BackendNSDP):    {},
	string(netgearswitch.BackendHTTP):    {},
	string(netgearswitch.BackendSSH):     {},
	string(netgearswitch.BackendTelnet):  {},
	string(netgearswitch.BackendConsole): {},
}

// backendFlag is a pflag.Value implementing --backend's validation: cobra
// (unlike argparse's `choices=`) has no built-in "one of these strings"
// flag constraint, so this package supplies one explicitly, as the D1
// brief requires. Matching is case-INSENSITIVE (normalized to lowercase
// before being stored) -- a deliberate CLI-ergonomics improvement over
// main.py's own argparse `choices=[b.name.lower() for b in Backend]`
// (which is exact-case, so even Python's "SNMP" would be rejected): the
// underlying resolve.Params.Backend field itself still requires an exact
// lowercase match (resolve.go's backendNames), which the normalization
// here satisfies. A Set failure surfaces as a cobra flag-parsing error --
// i.e. BEFORE any subcommand's RunE runs -- which app.go's Run maps to
// safety.ExitUsage, a clean exit-2 usage error.
type backendFlag struct{ dest *string }

func (b backendFlag) String() string { return *b.dest }
func (b backendFlag) Type() string   { return "string" }
func (b backendFlag) Set(v string) error {
	lower := strings.ToLower(v)
	if _, ok := validBackendNames[lower]; !ok {
		return fmt.Errorf("invalid --backend %q: must be one of snmp, nsdp, http, ssh, telnet, console", v)
	}
	*b.dest = lower
	return nil
}

// newRootCmd builds gngsw's full command tree bound to cc, mirroring
// main.py's build_parser(): the root command plus every subcommand
// registered below. Every one of the 10 persistent (global) flags is
// registered EXACTLY ONCE, here, on root.PersistentFlags() -- cobra
// inherits a persistent flag into every descendant command automatically,
// flag position (before or after the subcommand name) is unrestricted,
// and cobra's own arg-scanning correctly separates flags from subcommand
// names regardless of order, so none of main.py's _global_parser/child_gp/
// suppress_defaults machinery (which exists purely to route around
// argparse's own subparser default-clobbering quirk) has any Go
// equivalent to port -- this is a case where the target platform's own
// design makes an entire source-side workaround simply not apply.
func newRootCmd(cc *cmdContext) *cobra.Command {
	root := &cobra.Command{
		Use:           "gngsw",
		Short:         "Query and control Netgear switches over the Switch facade.",
		SilenceUsage:  true,
		SilenceErrors: true,
		// A bare `gngsw` (no subcommand) mirrors main.py's own
		// `if args.func is None: parser.print_help(err); return EXIT_USAGE`:
		// print full help to STDERR (never stdout -- unlike an explicit
		// -h/--help, which cobra's own help flag machinery intercepts
		// before RunE ever runs, and which prints to root's configured
		// Out, i.e. stdout, matching argparse's own `-h` convention) and
		// report exit code 2.
		RunE: func(cmd *cobra.Command, _ []string) error {
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			_ = cmd.Help()
			_, _ = fmt.Fprint(cc.app.Stderr, buf.String()) // see cmdContext.fail's own doc comment on discarding this write's error.
			cc.code = safety.ExitUsage
			return nil
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&cc.flags.config, "config", "", "TOML inventory file")
	pf.StringVar(&cc.flags.switchName, "switch", "", "switch name from the inventory")
	pf.StringVar(&cc.flags.host, "host", "", "switch host (with --model)")
	pf.StringVar(&cc.flags.modelKey, "model", "", "model key (with --host)")
	pf.StringVar(&cc.flags.community, "community", "", "SNMP read community override")
	pf.StringVar(&cc.flags.writeCommunity, "write-community", "", "SNMP write community override")
	pf.StringVar(&cc.flags.nsdpInterface, "nsdp-interface", "", "network interface for NSDP (Plus switch) queries, e.g. eth0; overrides the inventory's nsdp.interface when both are set")
	pf.StringVar(&cc.flags.httpPassword, "http-password", "", "web-UI/NSDP admin password for a Plus switch (HTTP + NSDP v1 auth share this one secret); overrides the inventory's http.password when both are set")
	pf.Var(backendFlag{&cc.flags.backend}, "backend", "run the operation over EXACTLY this backend (snmp/nsdp/http/ssh/telnet/console) instead of the model's default; the operation fails if that backend cannot serve it -- it is never re-routed to another protocol")
	pf.BoolVar(&cc.flags.asJSON, "json", false, "emit machine-readable JSON output")
	pf.BoolVarP(&cc.flags.verbose, "verbose", "v", false, "print diagnostics on error")

	root.AddCommand(newModelsCmd(cc))
	for _, newCmd := range readCommands {
		root.AddCommand(newCmd(cc))
	}
	root.AddCommand(newPoeCmd(cc))
	root.AddCommand(newPortCmd(cc))
	root.AddCommand(newDescribeCmd(cc))
	root.AddCommand(newSpeedCmd(cc))
	root.AddCommand(newFlowControlCmd(cc))
	root.AddCommand(newCyclePoECmd(cc))
	root.AddCommand(newClearPoEFaultCmd(cc))
	root.AddCommand(newUploadCertificateCmd(cc))
	root.AddCommand(newUploadCertificateSCPCmd(cc))
	root.AddCommand(newPVIDCmd(cc))
	root.AddCommand(newVlanCmd(cc))
	root.AddCommand(newIPCmd(cc))
	root.AddCommand(newHostnameCmd(cc))
	root.AddCommand(newSyslogCmd(cc))
	root.AddCommand(newCaptureCmd(cc))

	return root
}
