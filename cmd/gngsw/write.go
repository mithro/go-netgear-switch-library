// write.go: gngsw's disruptive-write subcommands (and the four read/write
// hybrids -- poe/hostname/ip/syslog -- whose bare form reads and whose
// subcommand/arg form writes), mirroring main.py's corresponding _cmd_*
// handlers one-for-one, including their EXACT Description/Warning text
// (these strings appear verbatim in a write's "ok: <description>" success
// line, which -- per this package's stdout-byte-parity mandate -- goes to
// STDOUT, not just an interactive prompt).
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/fmtx"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/safety"
	"github.com/spf13/cobra"
)

// writeFlags holds the three flags every disruptive write subcommand
// shares, mirroring safety.py's add_write_args.
type writeFlags struct {
	dryRun bool
	yes    bool
	force  bool
}

// addWriteFlags registers --dry-run/-y,--yes/--force on cmd's OWN (local,
// non-persistent) flag set -- mirroring add_write_args(parser) being
// called only for write subcommands, never the read-only ones -- and
// returns the struct their values land in. Must be called at command
// CONSTRUCTION time (before cobra parses argv), with the returned pointer
// captured by the command's RunE closure.
func addWriteFlags(cmd *cobra.Command) *writeFlags {
	wf := &writeFlags{}
	cmd.Flags().BoolVar(&wf.dryRun, "dry-run", false, "print the operation that would be sent, then send nothing")
	cmd.Flags().BoolVarP(&wf.yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&wf.force, "force", false, "override protected_ports and other force-gates")
	return wf
}

// runWrite is the shared body every disruptive write subcommand's RunE
// delegates to: build the switch, run it through safety.DoWrite (dry-run /
// confirm / execute / report -- see that package's own doc comment), and
// record the resolved exit code -- mirroring main.py's
// `return safety.do_write(ctx, dry_run=..., assume_yes=..., host=...,
// description=..., action=..., warning=...)` shape exactly. Unlike
// runRead, DoWrite itself already prints "DRY-RUN: ...", the confirmation
// prompt, and "ok: ..."/"aborted: ..." to the right stream; this method's
// only remaining job on an error return is the SAME single "error: ..."
// report site cmdContext.libraryError uses everywhere else (mirroring
// main.py's do_write NEVER printing the exception itself -- that happens
// only in main()'s own except block).
func (cc *cmdContext) runWrite(wf *writeFlags, description, warning string, action func(ctx context.Context, sw *netgearswitch.Switch) error) error {
	sw, err := cc.getSwitch()
	if err != nil {
		return cc.libraryError(err)
	}
	defer func() { _ = sw.Close() }()

	code, err := safety.DoWrite(cc.streams(), safety.WriteRequest{
		DryRun:      wf.dryRun,
		AssumeYes:   wf.yes,
		Host:        sw.Host(),
		Description: description,
		Warning:     warning,
		Action:      func() error { return action(context.Background(), sw) },
	})
	cc.code = code
	if err != nil {
		if cc.flags.verbose {
			printVerboseChain(cc.app.Stderr, err)
		}
		_, _ = fmt.Fprintf(cc.app.Stderr, "error: %s\n", err) // see cmdContext.fail's own doc comment on discarding this write's error.
	}
	return nil
}

// parseIntArg parses a positional argument as a decimal integer, mirroring
// argparse's `type=int` -- a conversion failure becomes a usage-shaped
// error (%s-formatted straight into cc.usageError by every call site).
func parseIntArg(s, name string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: must be an integer", name, s)
	}
	return n, nil
}

// parseRate mirrors main.py's _parse_rate: "100" -> 100, "10G" -> 10000.
func parseRate(text string) (int, error) {
	token := strings.ToUpper(strings.TrimSpace(text))
	if strings.HasSuffix(token, "G") {
		n, err := strconv.Atoi(strings.TrimSuffix(token, "G"))
		if err != nil {
			return 0, err
		}
		return n * 1000, nil
	}
	return strconv.Atoi(token)
}

// vlanModes maps the vlan-set command's mode positional argument to
// netgearswitch.VlanMode, mirroring main.py's `VlanMode(args.mode)`.
var vlanModes = map[string]netgearswitch.VlanMode{
	"untagged": netgearswitch.VlanUntagged,
	"tagged":   netgearswitch.VlanTagged,
	"excluded": netgearswitch.VlanExcluded,
}

// readTextFile reads path and applies Python's Path.read_text() universal-
// newline translation ("\r\n"/"\r" -> "\n") so a cert/key/password file
// staged on a different platform still parses the same way Python's own
// upload-certificate handler would read it.
func readTextFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return universalNewlines(string(raw)), nil
}

// universalNewlines mirrors Python text-mode file reading's default
// newline translation.
func universalNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

// --- poe: bare read, or `poe PORT ACTION` write -----------------------

func newPoeCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "poe [port] [on|off|cycle|clear-fault]",
		Short: "show PoE status, or control a port's PoE",
		Args:  cobra.MaximumNArgs(2),
	}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		if len(args) == 0 {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) ([]netgearswitch.PoEStatus, error) {
				return sw.GetPoE(ctx)
			}, fmtx.PoeTable)
		}
		port, err := parseIntArg(args[0], "port")
		if err != nil {
			return cc.usageError("%s", err)
		}
		if len(args) == 1 {
			return cc.usageError("an action (on|off|cycle|clear-fault) is required with a port")
		}
		action := args[1]
		description := fmt.Sprintf("set PoE port %d -> %s", port, action)
		switch action {
		case "on":
			return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
				return sw.SetPoE(ctx, port, true, netgearswitch.Write{Force: wf.force})
			})
		case "off":
			return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
				return sw.SetPoE(ctx, port, false, netgearswitch.Write{Force: wf.force})
			})
		case "cycle":
			return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
				return sw.CyclePoE(ctx, port, netgearswitch.Write{Force: wf.force})
			})
		case "clear-fault":
			return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
				return sw.ClearPoEFault(ctx, port, netgearswitch.Write{Force: wf.force})
			})
		default:
			return cc.usageError("invalid action %q: must be one of on, off, cycle, clear-fault", action)
		}
	}
	return cmd
}

// --- port PORT up|down --------------------------------------------------

func newPortCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{Use: "port PORT up|down", Short: "bring a port up or down", Args: cobra.ExactArgs(2)}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		port, err := parseIntArg(args[0], "port")
		if err != nil {
			return cc.usageError("%s", err)
		}
		state := args[1]
		if state != "up" && state != "down" {
			return cc.usageError("invalid state %q: must be 'up' or 'down'", state)
		}
		enabled := state == "up"
		description := fmt.Sprintf("set port %d %s", port, state)
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.SetPortEnabled(ctx, port, enabled, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

// --- describe PORT DESCRIPTION -----------------------------------------

func newDescribeCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "describe PORT DESCRIPTION",
		Short: "set or clear a port's description (pass '' to clear)",
		Args:  cobra.ExactArgs(2),
	}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		port, err := parseIntArg(args[0], "port")
		if err != nil {
			return cc.usageError("%s", err)
		}
		text := args[1]
		description := fmt.Sprintf("clear the description on port %d", port)
		if text != "" {
			description = fmt.Sprintf("describe port %d as %s", port, pyRepr(text))
		}
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.SetPortDescription(ctx, port, text, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

// --- speed PORT RATE [--duplex full|half] -------------------------------

func newSpeedCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "speed PORT RATE",
		Short: "force a port's speed/duplex, or restore auto-negotiation",
		Args:  cobra.ExactArgs(2),
	}
	var duplex string
	cmd.Flags().StringVar(&duplex, "duplex", "full", "duplex for a forced rate (default: full; ignored for 'auto')")
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		port, err := parseIntArg(args[0], "port")
		if err != nil {
			return cc.usageError("%s", err)
		}
		if duplex != "full" && duplex != "half" {
			return cc.usageError("invalid --duplex %q: must be 'full' or 'half'", duplex)
		}
		rateArg := args[1]

		var speed netgearswitch.PortSpeed
		var description string
		if strings.ToLower(rateArg) == "auto" {
			speed = netgearswitch.AutoPortSpeed()
			description = fmt.Sprintf("set port %d to auto-negotiate", port)
		} else {
			rate, perr := parseRate(rateArg)
			if perr != nil {
				return cc.usageError("not a port rate: %s (try 'auto', '100' or '10G')", pyRepr(rateArg))
			}
			speed = netgearswitch.ForcedPortSpeed(rate, duplex == "full")
			description = fmt.Sprintf("force port %d to %d Mbit/s %s-duplex", port, rate, duplex)
		}
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.SetPortSpeed(ctx, port, speed, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

// --- flow-control PORT on|off -------------------------------------------

func newFlowControlCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flow-control PORT on|off",
		Short: "turn IEEE 802.3x flow control on or off for a port",
		Args:  cobra.ExactArgs(2),
	}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		port, err := parseIntArg(args[0], "port")
		if err != nil {
			return cc.usageError("%s", err)
		}
		state := args[1]
		if state != "on" && state != "off" {
			return cc.usageError("invalid state %q: must be 'on' or 'off'", state)
		}
		description := fmt.Sprintf("turn flow control %s for port %d", state, port)
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.SetFlowControl(ctx, port, state == "on", netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

// --- cycle-poe PORT / clear-poe-fault PORT ------------------------------

func newCyclePoECmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{Use: "cycle-poe PORT", Short: "power-cycle a port's PoE", Args: cobra.ExactArgs(1)}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		port, err := parseIntArg(args[0], "port")
		if err != nil {
			return cc.usageError("%s", err)
		}
		description := fmt.Sprintf("power-cycle PoE port %d", port)
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.CyclePoE(ctx, port, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

func newClearPoEFaultCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{Use: "clear-poe-fault PORT", Short: "clear a port's PoE fault state", Args: cobra.ExactArgs(1)}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		port, err := parseIntArg(args[0], "port")
		if err != nil {
			return cc.usageError("%s", err)
		}
		description := fmt.Sprintf("clear PoE fault on port %d", port)
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.ClearPoEFault(ctx, port, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

// --- upload-certificate / upload-certificate-scp ------------------------

func newUploadCertificateCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upload-certificate",
		Short: "upload an HTTPS SSL certificate + private key",
		Args:  cobra.NoArgs,
	}
	var certPath, keyPath string
	cmd.Flags().StringVar(&certPath, "cert", "", "PEM certificate file")
	cmd.Flags().StringVar(&keyPath, "key", "", "PEM private-key file")
	_ = cmd.MarkFlagRequired("cert")
	_ = cmd.MarkFlagRequired("key")
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		certPEM, err := readTextFile(certPath)
		if err != nil {
			return cc.fail(safety.ExitError, "%s", err)
		}
		keyPEM, err := readTextFile(keyPath)
		if err != nil {
			return cc.fail(safety.ExitError, "%s", err)
		}
		description := fmt.Sprintf("upload SSL certificate (%s) + key (%s)", certPath, keyPath)
		warning := "WARNING: uploading a certificate replaces the switch's running certificate and restarts its web server."
		return cc.runWrite(wf, description, warning, func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.UploadCertificate(ctx, certPEM, keyPEM, wf.force)
		})
	}
	return cmd
}

func newUploadCertificateSCPCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upload-certificate-scp",
		Short: "deploy an HTTPS SSL certificate over SCP (FASTPATH M4300/GSM7252PS)",
		Args:  cobra.NoArgs,
	}
	var scpSource, scpPasswordFile, remoteDir string
	var chain bool
	cmd.Flags().StringVar(&scpSource, "scp-source", "", "SCP source the switch pulls the staged PEM from")
	cmd.Flags().StringVar(&scpPasswordFile, "scp-password-file", "", "file holding the SCP source password")
	cmd.Flags().StringVar(&remoteDir, "remote-dir", "/var/lib/switchcert/staging", "directory on the SCP source holding the staged PEM(s)")
	cmd.Flags().BoolVar(&chain, "chain", false, "also copy the CA-chain PEM to nvram:sslpem-root")
	_ = cmd.MarkFlagRequired("scp-source")
	_ = cmd.MarkFlagRequired("scp-password-file")
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		raw, err := readTextFile(scpPasswordFile)
		if err != nil {
			return cc.fail(safety.ExitError, "%s", err)
		}
		scpPassword := strings.TrimSpace(raw)
		if scpPassword == "" {
			return cc.fail(safety.ExitError, "--scp-password-file is empty")
		}
		description := fmt.Sprintf("deploy SSL certificate over SCP from %s%s", scpSource, remoteDir)
		warning := "WARNING: this replaces the switch's running HTTPS certificate (disables + re-enables the secure web server); stage the PEM on the SCP source first."
		return cc.runWrite(wf, description, warning, func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.UploadCertificateSCP(ctx, scpSource, scpPassword, remoteDir, chain)
		})
	}
	return cmd
}

// --- pvid PORT VLAN ------------------------------------------------------

func newPVIDCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{Use: "pvid PORT VLAN", Short: "set a port's PVID", Args: cobra.ExactArgs(2)}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		port, err := parseIntArg(args[0], "port")
		if err != nil {
			return cc.usageError("%s", err)
		}
		vlan, err := parseIntArg(args[1], "vlan")
		if err != nil {
			return cc.usageError("%s", err)
		}
		description := fmt.Sprintf("set PVID port %d -> VLAN %d", port, vlan)
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.SetPVID(ctx, port, vlan, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

// --- vlan {set,create,delete} --------------------------------------------

func newVlanCmd(cc *cmdContext) *cobra.Command {
	vlan := &cobra.Command{
		Use:   "vlan",
		Short: "create/delete VLANs or set membership",
		// Unlike ip/hostname/syslog, `vlan` has no bare-read form: main.py
		// registers a REQUIRED vlan_cmd subparser and no _cmd_vlan handler
		// at all, so a bare `ngsw vlan` always exits 2 (argparse's own
		// "the following arguments are required: vlan_cmd" usage error).
		RunE: func(_ *cobra.Command, _ []string) error {
			return cc.usageError("vlan requires a subcommand: set, create, or delete")
		},
	}
	vlan.AddCommand(newVlanSetCmd(cc), newVlanCreateCmd(cc), newVlanDeleteCmd(cc))
	return vlan
}

func newVlanSetCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{Use: "set VLAN PORT MODE", Short: "set port VLAN membership", Args: cobra.ExactArgs(3)}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		vlan, err := parseIntArg(args[0], "vlan")
		if err != nil {
			return cc.usageError("%s", err)
		}
		port, err := parseIntArg(args[1], "port")
		if err != nil {
			return cc.usageError("%s", err)
		}
		mode := args[2]
		modeVal, ok := vlanModes[mode]
		if !ok {
			return cc.usageError("invalid mode %q: must be one of untagged, tagged, excluded", mode)
		}
		description := fmt.Sprintf("set VLAN %d port %d -> %s", vlan, port, mode)
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.SetVlanMembership(ctx, vlan, port, modeVal, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

func newVlanCreateCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{Use: "create VLAN NAME", Short: "create a VLAN", Args: cobra.ExactArgs(2)}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		vlan, err := parseIntArg(args[0], "vlan")
		if err != nil {
			return cc.usageError("%s", err)
		}
		name := args[1]
		description := fmt.Sprintf("create VLAN %d named %s", vlan, pyRepr(name))
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.CreateVlan(ctx, vlan, name, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

func newVlanDeleteCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{Use: "delete VLAN", Short: "delete a VLAN", Args: cobra.ExactArgs(1)}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		vlan, err := parseIntArg(args[0], "vlan")
		if err != nil {
			return cc.usageError("%s", err)
		}
		description := fmt.Sprintf("delete VLAN %d", vlan)
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.DeleteVlan(ctx, vlan, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

// --- ip: bare read, or `ip set ADDRESS NETMASK GATEWAY` -----------------

func newIPCmd(cc *cmdContext) *cobra.Command {
	ip := &cobra.Command{
		Use:   "ip",
		Short: "show or set the management IP",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) (netgearswitch.MgmtIPConfig, error) {
				return sw.GetMgmtIP(ctx)
			}, fmtx.MgmtIPText)
		},
	}
	ip.AddCommand(newIPSetCmd(cc))
	return ip
}

func newIPSetCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set ADDRESS NETMASK GATEWAY",
		Short: "set the management IP",
		Args:  cobra.ExactArgs(3),
	}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		address, netmask, gateway := args[0], args[1], args[2]
		description := fmt.Sprintf("set mgmt IP %s netmask %s gw %s", address, netmask, gateway)
		warning := "WARNING: a wrong management-IP change can strand the switch."
		return cc.runWrite(wf, description, warning, func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.SetMgmtIP(ctx, address, netmask, gateway, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

// --- hostname: bare read, or `hostname set NAME` -------------------------

func newHostnameCmd(cc *cmdContext) *cobra.Command {
	hostname := &cobra.Command{
		Use:   "hostname",
		Short: "show or set the switch's host name",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) (string, error) {
				return sw.GetHostname(ctx)
			}, fmtx.HostnameText)
		},
	}
	hostname.AddCommand(newHostnameSetCmd(cc))
	return hostname
}

func newHostnameSetCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{Use: "set NAME", Short: "set the switch's host name", Args: cobra.ExactArgs(1)}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		name := args[0]
		description := fmt.Sprintf("set hostname to %s", pyRepr(name))
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.SetHostname(ctx, name, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

// --- syslog: bare read, or `syslog {set,add,remove}` ---------------------

func newSyslogCmd(cc *cmdContext) *cobra.Command {
	syslog := &cobra.Command{
		Use:   "syslog",
		Short: "show remote-logging config, or turn it on/off",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) (netgearswitch.SyslogConfig, error) {
				return sw.GetSyslog(ctx)
			}, fmtx.SyslogText)
		},
	}
	syslog.AddCommand(newSyslogSetCmd(cc), newSyslogAddCmd(cc), newSyslogRemoveCmd(cc))
	return syslog
}

func newSyslogSetCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{Use: "set on|off", Short: "turn remote logging on or off", Args: cobra.ExactArgs(1)}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		state := args[0]
		if state != "on" && state != "off" {
			return cc.usageError("invalid state %q: must be 'on' or 'off'", state)
		}
		description := fmt.Sprintf("turn remote logging %s", state)
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.SetSyslogEnabled(ctx, state == "on", netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

func newSyslogAddCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{Use: "add ADDRESS", Short: "add a remote syslog collector", Args: cobra.ExactArgs(1)}
	var port, severity int
	cmd.Flags().IntVar(&port, "port", 514, "collector UDP port (default: 514)")
	cmd.Flags().IntVar(&severity, "severity", 6, "forward messages at or above this severity (0 emergency .. 7 debug; default: 6 info)")
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		address := args[0]
		if severity < 0 || severity > 7 {
			return cc.usageError("invalid --severity %d: must be 0-7", severity)
		}
		description := fmt.Sprintf("add syslog collector %s (port %d, severity %d)", address, port, severity)
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.AddSyslogCollector(ctx, address, port, severity, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}

func newSyslogRemoveCmd(cc *cmdContext) *cobra.Command {
	cmd := &cobra.Command{Use: "remove ADDRESS", Short: "remove a remote syslog collector", Args: cobra.ExactArgs(1)}
	wf := addWriteFlags(cmd)
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		address := args[0]
		description := fmt.Sprintf("remove syslog collector %s", address)
		return cc.runWrite(wf, description, "", func(ctx context.Context, sw *netgearswitch.Switch) error {
			return sw.RemoveSyslogCollector(ctx, address, netgearswitch.Write{Force: wf.force})
		})
	}
	return cmd
}
