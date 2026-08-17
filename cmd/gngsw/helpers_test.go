package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/cmd/internal/resolve"
	"github.com/mithro/go-netgear-switch-library/nsdp"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// cliTestTimeout mirrors facade_integration_test.go's own facadeTestTimeout:
// generous for a loopback round trip under a resource-jailed `go test`, short
// enough that a genuine deadlock still fails the test.
const cliTestTimeout = 10 * time.Second

// startVirtualSwitch builds and starts a virtual.VirtualSwitch for modelKey,
// registering t.Cleanup to stop it -- the same helper shape
// facade_integration_test.go's own startVirtualSwitch uses (duplicated here:
// this is a different package, and Go test helpers aren't exported).
func startVirtualSwitch(t *testing.T, modelKey string) *virtual.VirtualSwitch {
	t.Helper()
	sw, err := virtual.NewVirtualSwitch(modelKey)
	if err != nil {
		t.Fatalf("virtual.NewVirtualSwitch(%q) error = %v", modelKey, err)
	}
	if err := sw.Start(); err != nil {
		t.Fatalf("VirtualSwitch.Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := sw.Stop(); err != nil {
			t.Errorf("VirtualSwitch.Stop() error = %v", err)
		}
	})
	return sw
}

// snmpSwitch builds a *netgearswitch.Switch bound to modelKey, talking to
// vsw's live SNMP face over "host:port" -- proving (indirectly, via every
// test that uses it) that gngsw's default resolve.Resolve path accepts a
// "host:port" --host value, exactly like facade_integration_test.go's own
// facadeFor. Configures BOTH the read community (WithSNMPCommunity) and the
// write community (WithSNMPWriteCommunityResolver) to "public" -- the
// virtual fake's single SNMP community string serves both (mirroring
// facade_write_integration_test.go's writableFacadeFor) -- so this one
// helper serves every read AND write test in this package without a
// separate "writable" variant.
func snmpSwitch(t *testing.T, vsw *virtual.VirtualSwitch, modelKey string, opts ...netgearswitch.SwitchOption) *netgearswitch.Switch {
	t.Helper()
	m, err := netgearswitch.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q) error = %v", modelKey, err)
	}
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	base := []netgearswitch.SwitchOption{
		netgearswitch.WithSNMPCommunity("public"),
		netgearswitch.WithSNMPWriteCommunityResolver(func() (*string, error) {
			c := "public"
			return &c, nil
		}),
	}
	sw, err := netgearswitch.New(m, host, append(base, opts...)...)
	if err != nil {
		t.Fatalf("New(%q) error = %v", modelKey, err)
	}
	return sw
}

// cliBackedSwitch builds a *netgearswitch.Switch bound to modelKey, with an
// in-process CLI session (virtual.VirtualSwitch.CliSession -- no real
// socket, see that method's own doc comment) injected and pinned as the
// default dispatch backend via WithBackend(BackendSSH) -- for ops SNMP
// refuses by name (SetPortSpeed, SetFlowControl, GetUsers, GetServices),
// mirroring facade_cli_integration_test.go's own in-process pattern.
func cliBackedSwitch(t *testing.T, vsw *virtual.VirtualSwitch, modelKey string) *netgearswitch.Switch {
	t.Helper()
	m, err := netgearswitch.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q) error = %v", modelKey, err)
	}
	session, err := vsw.CliSession()
	if err != nil {
		t.Fatalf("CliSession() error = %v", err)
	}
	sw, err := netgearswitch.New(m, vsw.Host,
		netgearswitch.WithCLIClient(session),
		netgearswitch.WithBackend(netgearswitch.BackendSSH),
	)
	if err != nil {
		t.Fatalf("New(%q) error = %v", modelKey, err)
	}
	return sw
}

// nsdpSwitch builds a *netgearswitch.Switch bound to modelKey, talking to
// vsw's live NSDP face over a real (non-default) UDP port via an injected
// nsdp.Client -- the NSDP analogue of snmpSwitch above, mirroring
// facade_nsdp_integration_test.go's own nsdpFacadeFor: package nsdp's own
// client separates host/port, so the facade's "host" string can't carry
// vsw's ephemeral NsdpPort the way SNMP's "host:port" convention does.
func nsdpSwitch(t *testing.T, vsw *virtual.VirtualSwitch, modelKey string) *netgearswitch.Switch {
	t.Helper()
	m, err := netgearswitch.GetModel(modelKey)
	if err != nil {
		t.Fatalf("GetModel(%q) error = %v", modelKey, err)
	}
	client, err := nsdp.NewUDPClient(vsw.Host,
		nsdp.WithServerPort(vsw.NsdpPort),
		nsdp.WithClientPort(0),
		nsdp.WithTimeout(cliTestTimeout),
	)
	if err != nil {
		t.Fatalf("nsdp.NewUDPClient() error = %v", err)
	}
	sw, err := netgearswitch.New(m, vsw.Host, netgearswitch.WithNSDPClient(client))
	if err != nil {
		t.Fatalf("New(%q) error = %v", modelKey, err)
	}
	return sw
}

// snmpSwitchFactory returns an App.SwitchFactory that always returns sw --
// the "resolve seam bypassed via switch_factory" pattern
// tests/cli/test_cli_integration.py documents and this package's app.go
// doc comment mirrors.
func snmpSwitchFactory(sw *netgearswitch.Switch) func(resolve.Params) (*netgearswitch.Switch, error) {
	return func(resolve.Params) (*netgearswitch.Switch, error) { return sw, nil }
}

// runCLI runs gngsw's full command tree against argv, with stdin fed from
// in (e.g. a confirmation reply), returning (exit code, stdout, stderr).
func runCLI(argv []string, in string, factory func(resolve.Params) (*netgearswitch.Switch, error)) (int, string, string) {
	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout:        &stdout,
		Stderr:        &stderr,
		Stdin:         strings.NewReader(in),
		SwitchFactory: factory,
	}
	code := Run(argv, app)
	return code, stdout.String(), stderr.String()
}
