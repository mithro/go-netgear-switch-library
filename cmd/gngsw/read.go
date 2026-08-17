// read.go: gngsw's pure-read subcommands (no positional/write flags at
// all), mirroring main.py's `read_cmd` registrations plus `_cmd_models`.
// Every handler below is the same three-step shape Python's own read
// handlers share (fmt.emit(ctx, get_switch().get_X(), fmt.x_table)): build
// the switch, call exactly one facade method, hand the result to
// fmtx.Emit alongside the matching table/JSON renderer.
package main

import (
	"context"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/fmtx"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/safety"
	"github.com/spf13/cobra"
)

// runRead is the shared body every pure-read subcommand's RunE delegates
// to: build the switch (cmdContext.getSwitch), call get, emit the result
// via fmtx.Emit (JSON or tableFn depending on --json), and record the
// resolved exit code -- mirroring main.py's
// `fmt.emit(ctx, get_switch().get_x(), fmt.x_table); return EXIT_OK` shape
// exactly, generic over every read method's own result type T.
func runRead[T any](cc *cmdContext, get func(ctx context.Context, sw *netgearswitch.Switch) (T, error), tableFn func(T) string) error {
	sw, err := cc.getSwitch()
	if err != nil {
		return cc.libraryError(err)
	}
	defer func() { _ = sw.Close() }()

	v, err := get(context.Background(), sw)
	if err != nil {
		return cc.libraryError(err)
	}
	if err := fmtx.Emit(cc.app.Stdout, v, cc.flags.asJSON, tableFn); err != nil {
		return cc.libraryError(err)
	}
	cc.code = safety.ExitOK
	return nil
}

// newModelsCmd is `gngsw models`, mirroring main.py's _cmd_models: this is
// the one "read" command that never touches a switch at all -- it lists
// the model registry.
func newModelsCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use:   "models",
		Short: "list the known switch models",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			rows := fmtx.ModelRows(netgearswitch.Models())
			if err := fmtx.Emit(cc.app.Stdout, rows, cc.flags.asJSON, fmtx.ModelsText); err != nil {
				return cc.libraryError(err)
			}
			cc.code = safety.ExitOK
			return nil
		},
	}
}

// readCommands lists every pure-read subcommand's constructor, mirroring
// main.py's build_parser() sequence of read_cmd(...) calls one-for-one
// (name, facade method, renderer, help text) -- registered from root.go's
// newRootCmd in this exact order.
var readCommands = []func(cc *cmdContext) *cobra.Command{
	newPortsCmd, newStatsCmd, newVlansCmd, newPvidsCmd, newLLDPCmd, newMacsCmd,
	newSensorsCmd, newUsersCmd, newServicesCmd, newShowCmd, newIdentifyCmd, newNSDPDeviceCmd,
}

func newPortsCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "ports", Short: "show port status", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) ([]netgearswitch.PortStatus, error) {
				return sw.GetPorts(ctx)
			}, fmtx.PortsTable)
		},
	}
}

func newStatsCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "stats", Short: "show port RX/TX counters", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) ([]netgearswitch.PortStats, error) {
				return sw.GetStats(ctx)
			}, fmtx.StatsTable)
		},
	}
}

func newVlansCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "vlans", Short: "show VLANs", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) ([]netgearswitch.VLANInfo, error) {
				return sw.GetVLANs(ctx)
			}, fmtx.VlansTable)
		},
	}
}

func newPvidsCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "pvids", Short: "show per-port PVIDs", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) ([]netgearswitch.Pvid, error) {
				return sw.GetPVIDs(ctx)
			}, fmtx.PvidsTable)
		},
	}
}

func newLLDPCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "lldp", Short: "show LLDP neighbours", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) ([]netgearswitch.LLDPNeighbor, error) {
				return sw.GetLLDP(ctx)
			}, fmtx.LldpTable)
		},
	}
}

func newMacsCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "macs", Short: "show the MAC/FDB table", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) ([]netgearswitch.MacEntry, error) {
				return sw.GetMACs(ctx)
			}, fmtx.MacsTable)
		},
	}
}

func newSensorsCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "sensors", Short: "show sensors", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) ([]netgearswitch.Sensor, error) {
				return sw.GetSensors(ctx)
			}, fmtx.SensorsTable)
		},
	}
}

func newUsersCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "users", Short: "show local login accounts", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) ([]netgearswitch.SwitchUser, error) {
				return sw.GetUsers(ctx)
			}, fmtx.UsersTable)
		},
	}
}

func newServicesCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "services", Short: "show which management services are enabled", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) ([]netgearswitch.ServiceStatus, error) {
				return sw.GetServices(ctx)
			}, fmtx.ServicesTable)
		},
	}
}

func newShowCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "show", Short: "show a full switch snapshot", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) (netgearswitch.SwitchData, error) {
				return sw.Snapshot(ctx)
			}, fmtx.SnapshotText)
		},
	}
}

func newIdentifyCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "identify", Short: "detect the switch's real model over SNMP", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) (netgearswitch.DetectedModel, error) {
				return sw.Identify(ctx)
			}, fmtx.DetectedModelText)
		},
	}
}

func newNSDPDeviceCmd(cc *cmdContext) *cobra.Command {
	return &cobra.Command{
		Use: "nsdp-device", Short: "show the raw NSDP device record (NSDP-capable models only)", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runRead(cc, func(ctx context.Context, sw *netgearswitch.Switch) (netgearswitch.NsdpDevice, error) {
				return sw.NSDPDevice(ctx)
			}, fmtx.NsdpDeviceText)
		},
	}
}
