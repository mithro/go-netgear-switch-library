package netgearswitch_test

// facade_cli_integration_test.go: the slice-07 CAPSTONE. Drives the real
// Switch facade's FASTPATH-CLI backend end-to-end against real
// virtual.VirtualSwitch SSH + telnet listeners over TCP loopback (Task 12),
// AND against the in-process CliFace (Task 11), proving the whole stack --
// facade dispatch -> backend_cli.go builder -> fastpath transport/session/
// reader/writer -> the byte-faithful fake -> shared VirtualSwitchState -- is
// wired correctly for every CLI model. This is the two-sided cross-check the
// unit tests (backend_cli_test.go's hand fakes) stand in for.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// The three models with a FASTPATH CLI backend reachable over SSH. gsm7228ps
// (S3300) is deliberately excluded here -- it is telnet-only on real hardware
// (see model/registry.go's gsm7228ps comment) -- and is exercised by
// TestCLICapstone_ReadsOverRealTelnet instead, which already uses it
// exclusively for the telnet path.
var cliCapstoneModels = []string{"gsm7252ps", "m4300-24x", "m4300-16x"}

const (
	cliCapstoneUser = "admin"
	cliCapstonePass = "password" // virtual.NewVirtualSwitch's default cli creds
)

func startCLICapstoneVSW(t *testing.T, modelKey string) *virtual.VirtualSwitch {
	t.Helper()
	vsw, err := virtual.NewVirtualSwitch(modelKey)
	if err != nil {
		t.Fatalf("NewVirtualSwitch(%q): %v", modelKey, err)
	}
	if err := vsw.Start(); err != nil {
		t.Fatalf("VirtualSwitch.Start(%q): %v", modelKey, err)
	}
	t.Cleanup(func() { _ = vsw.Stop() })
	m := mustCapstoneModel(t, modelKey)
	if m.HasBackend(model.BackendSSH) && vsw.SSHPort == 0 {
		t.Fatalf("model %q did not bind its SSH face", modelKey)
	}
	if vsw.TelnetPort == 0 {
		t.Fatalf("model %q did not bind its telnet face", modelKey)
	}
	return vsw
}

func mustCapstoneModel(t *testing.T, key string) *model.SwitchModel {
	t.Helper()
	m, err := model.GetModel(key)
	if err != nil {
		t.Fatalf("GetModel(%q): %v", key, err)
	}
	return m
}

func cliFacadeInProcess(t *testing.T, vsw *virtual.VirtualSwitch, m *model.SwitchModel, backend model.Backend) *netgearswitch.Switch {
	t.Helper()
	face, err := vsw.CliSession()
	if err != nil {
		t.Fatalf("CliSession: %v", err)
	}
	sw, err := netgearswitch.New(m, vsw.Host,
		netgearswitch.WithBackend(backend),
		netgearswitch.WithCLIClient(face))
	if err != nil {
		t.Fatalf("New (in-process): %v", err)
	}
	return sw
}

func cliFacadeOverSSH(t *testing.T, vsw *virtual.VirtualSwitch, m *model.SwitchModel) *netgearswitch.Switch {
	t.Helper()
	sw, err := netgearswitch.New(m, vsw.Host,
		netgearswitch.WithBackend(model.BackendSSH),
		netgearswitch.WithSSHPort(vsw.SSHPort),
		netgearswitch.WithCLIUsername(cliCapstoneUser),
		netgearswitch.WithCLIPassword(cliCapstonePass))
	if err != nil {
		t.Fatalf("New (ssh): %v", err)
	}
	t.Cleanup(func() { _ = sw.Close() })
	return sw
}

func cliFacadeOverTelnet(t *testing.T, vsw *virtual.VirtualSwitch, m *model.SwitchModel) *netgearswitch.Switch {
	t.Helper()
	sw, err := netgearswitch.New(m, vsw.Host,
		netgearswitch.WithBackend(model.BackendTelnet),
		netgearswitch.WithTelnetPort(vsw.TelnetPort),
		netgearswitch.WithCLIUsername(cliCapstoneUser),
		netgearswitch.WithCLIPassword(cliCapstonePass))
	if err != nil {
		t.Fatalf("New (telnet): %v", err)
	}
	t.Cleanup(func() { _ = sw.Close() })
	return sw
}

// TestCLICapstone_ReadsMatchInProcessOverRealSSH proves, for every CLI model,
// that reads served over a REAL SSH socket are byte-for-byte identical to the
// same reads over the in-process CliFace -- i.e. the SSH transport +
// ShellDriver framing + real listener add nothing and lose nothing versus the
// dispatcher both share. Equality to the CLI reference (not merely non-empty)
// is also the evidence the SSH backend served these, not SNMP: an SNMP read
// of the same state would differ (e.g. CLI GetPorts carries no description).
func TestCLICapstone_ReadsMatchInProcessOverRealSSH(t *testing.T) {
	ctx := context.Background()
	for _, mk := range cliCapstoneModels {
		t.Run(mk, func(t *testing.T) {
			vsw := startCLICapstoneVSW(t, mk)
			m := mustCapstoneModel(t, mk)
			ref := cliFacadeInProcess(t, vsw, m, model.BackendSSH)
			ssh := cliFacadeOverSSH(t, vsw, m)

			refPorts, err := ref.GetPorts(ctx)
			if err != nil {
				t.Fatalf("in-process GetPorts: %v", err)
			}
			sshPorts, err := ssh.GetPorts(ctx)
			if err != nil {
				t.Fatalf("ssh GetPorts: %v", err)
			}
			if len(sshPorts) == 0 {
				t.Fatalf("ssh GetPorts returned no ports")
			}
			if !reflect.DeepEqual(refPorts, sshPorts) {
				t.Fatalf("ssh GetPorts != in-process GetPorts\n in-proc=%+v\n ssh    =%+v", refPorts, sshPorts)
			}

			refVLANs, err := ref.GetVLANs(ctx)
			if err != nil {
				t.Fatalf("in-process GetVLANs: %v", err)
			}
			sshVLANs, err := ssh.GetVLANs(ctx)
			if err != nil {
				t.Fatalf("ssh GetVLANs: %v", err)
			}
			if !reflect.DeepEqual(refVLANs, sshVLANs) {
				t.Fatalf("ssh GetVLANs != in-process GetVLANs")
			}
		})
	}
}

// TestCLICapstone_ReadsOverRealTelnet proves the telnet transport + listener
// path serves reads identically to the in-process reference for a
// representative model.
func TestCLICapstone_ReadsOverRealTelnet(t *testing.T) {
	ctx := context.Background()
	vsw := startCLICapstoneVSW(t, "gsm7228ps") // the real S3300 is telnet-only hw
	m := mustCapstoneModel(t, "gsm7228ps")
	ref := cliFacadeInProcess(t, vsw, m, model.BackendTelnet)
	tel := cliFacadeOverTelnet(t, vsw, m)

	refPorts, err := ref.GetPorts(ctx)
	if err != nil {
		t.Fatalf("in-process GetPorts: %v", err)
	}
	telPorts, err := tel.GetPorts(ctx)
	if err != nil {
		t.Fatalf("telnet GetPorts: %v", err)
	}
	if !reflect.DeepEqual(refPorts, telPorts) {
		t.Fatalf("telnet GetPorts != in-process GetPorts")
	}
}

// TestCLICapstone_WriteOverSSHVisibleOverTelnet drives a write (CreateVlan +
// SetPVID) over a REAL SSH connection, then reads it back over a REAL TELNET
// connection to the SAME VirtualSwitch -- proving the write mutated the ONE
// shared VirtualSwitchState every face projects (a CLI write is visible over
// every protocol, exactly as on real hardware), end-to-end over two distinct
// live sockets.
func TestCLICapstone_WriteOverSSHVisibleOverTelnet(t *testing.T) {
	ctx := context.Background()
	vsw := startCLICapstoneVSW(t, "gsm7252ps")
	m := mustCapstoneModel(t, "gsm7252ps")
	ssh := cliFacadeOverSSH(t, vsw, m)
	tel := cliFacadeOverTelnet(t, vsw, m)

	const newVLAN = 4001
	const port = 1
	if err := ssh.CreateVlan(ctx, newVLAN, "cap", netgearswitch.Write{}); err != nil {
		t.Fatalf("ssh CreateVlan: %v", err)
	}
	if err := ssh.SetPVID(ctx, port, newVLAN, netgearswitch.Write{}); err != nil {
		t.Fatalf("ssh SetPVID: %v", err)
	}

	pvids, err := tel.GetPVIDs(ctx)
	if err != nil {
		t.Fatalf("telnet GetPVIDs: %v", err)
	}
	found := false
	for _, p := range pvids {
		if p.Port == port {
			found = true
			if p.Vlan != newVLAN {
				t.Fatalf("port %d PVID over telnet = %d, want %d (the SSH write is not visible)", port, p.Vlan, newVLAN)
			}
		}
	}
	if !found {
		t.Fatalf("port %d not present in telnet GetPVIDs after SSH write", port)
	}
}

// TestCLICapstone_DeviceLimitGateOverFacade proves the genuinely
// device-limited op (m4300-24x has no PSE hardware) refuses with
// ErrUnsupportedCapability THROUGH the facade over a real backend selection --
// a real hardware gate, not a faked success -- while a PoE-capable CLI model
// serves GetPoE normally.
func TestCLICapstone_DeviceLimitGateOverFacade(t *testing.T) {
	ctx := context.Background()

	// m4300-24x: no PoE -> ErrUnsupportedCapability (gated before any wire I/O).
	vswNoPoE := startCLICapstoneVSW(t, "m4300-24x")
	noPoE := cliFacadeOverSSH(t, vswNoPoE, mustCapstoneModel(t, "m4300-24x"))
	if _, err := noPoE.GetPoE(ctx); !errors.Is(err, model.ErrUnsupportedCapability) {
		t.Fatalf("m4300-24x GetPoE over facade: want ErrUnsupportedCapability, got %v", err)
	}

	// gsm7252ps: has PoE -> serves GetPoE.
	vswPoE := startCLICapstoneVSW(t, "gsm7252ps")
	poe := cliFacadeOverSSH(t, vswPoE, mustCapstoneModel(t, "gsm7252ps"))
	statuses, err := poe.GetPoE(ctx)
	if err != nil {
		t.Fatalf("gsm7252ps GetPoE over facade: %v", err)
	}
	if len(statuses) == 0 {
		t.Fatalf("gsm7252ps GetPoE returned no PoE statuses")
	}
}
