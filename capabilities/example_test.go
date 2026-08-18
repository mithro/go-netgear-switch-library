// example_test.go holds this package's runnable godoc examples.
// package capabilities_test (external) so these examples exercise the
// package's public API exactly as a caller would.
package capabilities_test

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/capabilities"
	"github.com/mithro/go-netgear-switch-library/model"
)

// ExampleFor asks whether a model can serve an operation over a backend it
// does not have at all: GS110EMX is an NSDP+HTTP-only "Plus" model, so
// asking about SNMP returns SupportNoBackend with a reason naming the
// backends it actually has.
func ExampleFor() {
	m, err := model.GetModel("gs110emx")
	if err != nil {
		panic(err)
	}
	op, err := capabilities.OperationByName("get_ports")
	if err != nil {
		panic(err)
	}

	c := capabilities.For(m, model.BackendSNMP, op)
	fmt.Println(c.Support)
	fmt.Println(c.Reason)
	// Output:
	// no-backend
	// model "gs110emx" has no snmp backend (it has: http, nsdp)
}

// ExampleMatrix expands one model's verdict for one operation across every
// backend it has. GS728TPP's SNMP agent cannot create a VLAN (every
// RowStatus creation mechanism its firmware offers answers
// inconsistentValue), so create_vlan is routed to its HTTP backend
// instead -- Matrix reports both verdicts at once.
func ExampleMatrix() {
	op, err := capabilities.OperationByName("create_vlan")
	if err != nil {
		panic(err)
	}

	caps, err := capabilities.Matrix([]string{"gs728tpp"}, []capabilities.Operation{op})
	if err != nil {
		panic(err)
	}
	for _, c := range caps {
		fmt.Printf("%s over %s: %s\n", c.Operation.Name, c.Backend, c.Support)
	}
	// Output:
	// create_vlan over snmp: unsupported
	// create_vlan over http: supported
}
