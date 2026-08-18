// example_test.go holds this module's runnable godoc examples for the root
// netgearswitch facade. Every example below talks to an in-process
// virtual.VirtualSwitch (package virtual) rather than real hardware, so
// each one compiles, runs and is verified by `go test` with no switch to
// plug in -- against a real device the only difference is the host/
// community/password New is given. package netgearswitch_test (external)
// so these examples can import both this module's root package and
// virtual, exactly like this module's own integration tests
// (facade_integration_test.go et al.), whose connect-a-Switch-to-a-fake
// pattern these examples reuse.
package netgearswitch_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	netgearswitch "github.com/mithro/go-netgear-switch-library"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// exampleTimeout bounds every example's context, generous enough for a
// loopback round trip.
const exampleTimeout = 10 * time.Second

// startGSM7252PS starts an in-process virtual GSM7252PS switch (a
// fully-managed model reachable over SNMP) and returns a *netgearswitch.
// Switch talking to its SNMP face, plus a cleanup func the caller must run
// (typically via defer) to stop the fake. Shared by the several examples
// below that all want the same read-only SNMP-backed switch.
func startGSM7252PS() (*netgearswitch.Switch, func()) {
	vsw, err := virtual.NewVirtualSwitch("gsm7252ps")
	if err != nil {
		panic(err)
	}
	if err := vsw.Start(); err != nil {
		panic(err)
	}

	m, err := netgearswitch.GetModel("gsm7252ps")
	if err != nil {
		panic(err)
	}
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	sw, err := netgearswitch.New(m, host, netgearswitch.WithSNMPCommunity("public"))
	if err != nil {
		panic(err)
	}
	return sw, func() { _ = vsw.Stop() }
}

// Example connects to a switch and reads its per-port status -- the
// simplest possible use of this library.
func Example() {
	sw, stop := startGSM7252PS()
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), exampleTimeout)
	defer cancel()

	ports, err := sw.GetPorts(ctx)
	if err != nil {
		panic(err)
	}
	for _, p := range ports {
		if p.Port == 1 {
			fmt.Println("name:", *p.Name)
			fmt.Println("description:", *p.Description)
		}
	}
	// Output:
	// name: 1/0/1
	// description: eth0.rpi5-pmod
}

// ExampleSwitch_GetVLANs reads the static VLAN table and looks up one VLAN
// by ID.
func ExampleSwitch_GetVLANs() {
	sw, stop := startGSM7252PS()
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), exampleTimeout)
	defer cancel()

	vlans, err := sw.GetVLANs(ctx)
	if err != nil {
		panic(err)
	}
	for _, v := range vlans {
		if v.VlanID == 90 {
			fmt.Println("name:", *v.Name)
			fmt.Println("port 11 is a member:", slices.Contains(v.MemberPorts, 11))
			fmt.Println("port 10 is a member:", slices.Contains(v.MemberPorts, 10))
		}
	}
	// Output:
	// name: iot
	// port 11 is a member: true
	// port 10 is a member: false
}

// ExampleSwitch_GetPoE reads per-port Power-over-Ethernet status.
func ExampleSwitch_GetPoE() {
	sw, stop := startGSM7252PS()
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), exampleTimeout)
	defer cancel()

	statuses, err := sw.GetPoE(ctx)
	if err != nil {
		panic(err)
	}
	for _, s := range statuses {
		if s.Port == 1 {
			fmt.Println("delivering:", s.Delivering())
			fmt.Println("power (mW):", *s.PowerMw)
		}
	}
	// Output:
	// delivering: true
	// power (mW): 3500
}

// ExampleSwitch_Identify detects a switch's ACTUAL model over SNMP, which
// may differ from the model the Switch was constructed with -- useful to
// confirm a switch's identity before trusting it.
func ExampleSwitch_Identify() {
	vsw, err := virtual.NewVirtualSwitch("gsm7228ps")
	if err != nil {
		panic(err)
	}
	if err := vsw.Start(); err != nil {
		panic(err)
	}
	defer func() { _ = vsw.Stop() }()

	m, err := netgearswitch.GetModel("gsm7228ps")
	if err != nil {
		panic(err)
	}
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	sw, err := netgearswitch.New(m, host, netgearswitch.WithSNMPCommunity("public"))
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), exampleTimeout)
	defer cancel()

	detected, err := sw.Identify(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("key:", *detected.Key)
	// Output:
	// key: gsm7228ps
}

// ExampleSwitch_DeleteVlan shows Write.Force overriding the protected-port
// guard: deleting a VLAN whose members include a protected port is refused
// (wrapping netgearswitch.ErrProtectedPort) unless the caller passes
// Write{Force: true}.
func ExampleSwitch_DeleteVlan() {
	vsw, err := virtual.NewVirtualSwitch("gsm7252ps")
	if err != nil {
		panic(err)
	}
	if err := vsw.Start(); err != nil {
		panic(err)
	}
	defer func() { _ = vsw.Stop() }()

	m, err := netgearswitch.GetModel("gsm7252ps")
	if err != nil {
		panic(err)
	}
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort)
	const protectedPort = 11 // a seeded member of VLAN 90
	sw, err := netgearswitch.New(m, host,
		netgearswitch.WithSNMPCommunity("public"),
		netgearswitch.WithSNMPWriteCommunityResolver(func() (*string, error) {
			c := "public"
			return &c, nil
		}),
		netgearswitch.WithProtectedPorts(protectedPort),
	)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), exampleTimeout)
	defer cancel()

	const vlanID = 90
	err = sw.DeleteVlan(ctx, vlanID, netgearswitch.Write{Force: false})
	fmt.Println("refused without force:", errors.Is(err, netgearswitch.ErrProtectedPort))

	err = sw.DeleteVlan(ctx, vlanID, netgearswitch.Write{Force: true})
	fmt.Println("succeeds with force:", err == nil)
	// Output:
	// refused without force: true
	// succeeds with force: true
}

// ExampleWithReadBackend selects a specific backend for one read call,
// overriding the model's own default backend preference. gs305ep's default
// backend is NSDP (NSDP has no PoE tag at all), so reading it over HTTP
// requires naming the backend explicitly.
func ExampleWithReadBackend() {
	vsw, err := virtual.NewVirtualSwitch("gs305ep")
	if err != nil {
		panic(err)
	}
	if err := vsw.Start(); err != nil {
		panic(err)
	}
	defer func() { _ = vsw.Stop() }()

	m, err := netgearswitch.GetModel("gs305ep")
	if err != nil {
		panic(err)
	}
	host := fmt.Sprintf("%s:%d", vsw.Host, vsw.HTTPPort)
	sw, err := netgearswitch.New(m, host, netgearswitch.WithHTTPPassword("password"))
	if err != nil {
		panic(err)
	}
	defer func() { _ = sw.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), exampleTimeout)
	defer cancel()

	ports, err := sw.GetPorts(ctx, netgearswitch.WithReadBackend(netgearswitch.BackendHTTP))
	if err != nil {
		panic(err)
	}
	up := 0
	for _, p := range ports {
		if p.LinkUp {
			up++
		}
	}
	fmt.Println("ports:", len(ports))
	fmt.Println("up:", up)
	// Output:
	// ports: 5
	// up: 1
}
