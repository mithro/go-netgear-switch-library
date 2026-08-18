// Package virtual implements an in-process, real-listener fake NETGEAR
// switch: seeded, deterministic in-memory device state plus real SNMP,
// NSDP, HTTP and SSH/Telnet listeners bound to loopback sockets, so a
// *netgearswitch.Switch (or any other client of packages snmp/nsdp/webui/
// fastpath) can talk to it exactly as it would to real hardware, with no
// hardware required. Every runnable Example function in this module's root
// package and in package capabilities is built on it, and it backs this
// module's own integration tests and its gngsw-virtual command.
//
// # Starting a fake switch
//
// NewVirtualSwitch(modelKey, ...Option) builds a VirtualSwitch for one
// registered model.SwitchModel, seeded via BuildState (which dispatches to
// that model's own SeedXxx function, e.g. SeedGSM7252PS, when one exists,
// or an empty-but-valid NewState otherwise). Start binds a real loopback
// listener for every protocol face the model's Backends declare --
// SnmpFace/NsdpFace/HTTPFace/SSHFace/TelnetFace, each backed by the SAME
// State -- and records the bound port on the VirtualSwitch's SnmpPort/
// NsdpPort/HTTPPort/SSHPort/TelnetPort fields (0 for any face the model
// does not have, or before Start). Stop tears every bound face down
// (idempotent; safe before Start or more than once). CliSession returns an
// in-process fastpath.Session talking to this switch's CLI face directly,
// with no socket at all -- useful where a real SSH/Telnet round trip is
// unnecessary. Option (WithCommunity, WithHost, WithHTTPPassword,
// WithCLIUsername, WithCLIPassword, WithPort, WithHTTPPort) overrides a
// VirtualSwitch's defaults at construction.
//
// EndpointProvider and GoFakeProvider are the conformance-harness seam:
// StartModel starts (or reuses) a VirtualSwitch for a model key and
// returns its Endpoints, for a test harness that wants "give me a live
// switch for this model" without caring about VirtualSwitch's own API.
//
// # Device state and protocol faces
//
// State (NewState/BuildState) holds everything a simulated switch "knows"
// about itself -- port link/admin/speed, counters, VLANs, PVIDs, PoE,
// sensors, the MAC/FDB table, LLDP neighbours, users/services, syslog and
// management IP -- as small mutable *Sim structs (PortSim, VlanSim,
// PoeSim, ...). It is shared, live, mutable state: a write accepted by one
// face is immediately visible to a read from any other face against the
// same VirtualSwitch, exactly as a real switch's own state is protocol-
// agnostic.
//
// MibView/NewMibView and OIDMap project State onto the flat numeric
// OID -> (type, value) view SnmpFace serves and writes into; the Render*
// functions (RenderXUI*, RenderGoAhead*, ...) render State back out as the
// HTML/XML pages HTTPFace serves, mirroring each of package webui's
// dialects; CliFace/NewCliFace implements the FASTPATH `show`/configure
// command surface NewSSHFace/NewTelnetFace's socket-level faces wrap.
//
// Ported field-for-field from src/netgear_switch/virtual/ (the normative
// source; that repo is read-only from here). Any discrepancy between this
// package and the pinned Python source is a bug in this package, not a
// deliberate deviation, unless called out in a comment.
package virtual
