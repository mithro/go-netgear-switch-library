// example_test.go holds this package's runnable godoc examples.
// package virtual_test (external) so these examples exercise the
// package's public API exactly as a caller would, and can import package
// snmp alongside it without an import cycle (package virtual itself
// imports snmp, not the other way around).
package virtual_test

import (
	"context"
	"fmt"
	"time"

	"github.com/mithro/go-netgear-switch-library/snmp"
	"github.com/mithro/go-netgear-switch-library/virtual"
)

// ExampleNewVirtualSwitch starts an in-process virtual GSM7252PS switch --
// no real hardware, no external process, just a goroutine and a loopback
// UDP socket -- and reads its identity with the snmp package directly, the
// same client code a caller would point at a real switch.
func ExampleNewVirtualSwitch() {
	vsw, err := virtual.NewVirtualSwitch("gsm7252ps")
	if err != nil {
		panic(err)
	}
	if err := vsw.Start(); err != nil {
		panic(err)
	}
	defer func() { _ = vsw.Stop() }()

	client := snmp.NewGoSNMPClient(fmt.Sprintf("%s:%d", vsw.Host, vsw.SnmpPort), "public")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info, err := snmp.ReadSystemInfo(ctx, client)
	if err != nil {
		panic(err)
	}
	fmt.Println("sysDescr:", *info.SysDescr)
	// Output:
	// sysDescr: NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6
}
