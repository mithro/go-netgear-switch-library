package virtual

// Code in this file (SeedGSM7252PS, SeedGSM7228PS, SeedM4300_24X,
// SeedM4300_16X, SeedGS728TPP, SeedGS110EMX, SeedGS305EP, SeedGS105PE) is a
// byte-for-byte transcription of src/netgear_switch/virtual/seed.py's
// seed_gsm7252ps/seed_gsm7228ps/seed_m4300_24x/seed_m4300_16x/
// seed_gs728tpp/seed_gs110emx/seed_gs305ep/seed_gs105pe (the normative
// source; that repo is read-only from here -- pin b26eb1f). BuildState
// instead mirrors _build_state, which lives in server.py (not seed.py) as
// of pin b26eb1f: a small model-key -> seed-builder dict (_SEEDS) plus the
// one-line dispatch/fallback function itself (server.py:45-59) --
// BuildState's switch below is that dict-lookup-or-blank-state shape, just
// spelled as a Go switch. Any discrepancy between this file and the Python
// source is a bug here. See
// D-VIRT §4 for the SNMP-model seeds' dossier transcription (NOTE: §4.2's
// gsm7228ps text is documented STALE there -- this file transcribes
// gsm7228ps from the CURRENT, capture-based seed.py function, not the
// dossier's superseded illustrative text) and D-NSDP §7.3 for the three
// slice-05 Plus-model seeds (SeedGS110EMX/SeedGS305EP/SeedGS105PE).
//
// Every seed here is grounded in a real hardware capture committed under
// testdata/captures/ (gsm7252ps.json, gsm7228ps.json, m4300-24x.json,
// m4300-16x.json -- see that directory's README.md for provenance) EXCEPT
// gs728tpp: the Python seed_gs728tpp docstring cites a real live capture
// (10.2.5.10, 2026-07-29), but that capture was never committed to
// tests/fixtures/captures/ in the pinned Python repo (only its confirmed-live
// values, transcribed into seed.py itself, survive) -- so gs728tpp has no
// testdata/captures/gs728tpp.json here and is grounded only by direct
// structural pins against the transcribed seed.py values (see
// TestSeedGS728TPP* in seed_test.go), not the assertSeedMatchesCapture
// harness the other four seeds use. The three Plus-model seeds (gs110emx,
// gs305ep, gs105pe) likewise have no testdata/captures/*.json here: gs110emx
// and gs105pe are grounded in real HTTP-UI/live-NSDP captures cited only in
// the pinned Python seed.py's own docstrings (see each Seed function's doc
// comment for exactly which values are transcribed vs. illustrative), and
// gs305ep is HAND-INVENTED end to end (no capture of any kind exists for
// it) -- none of the three use the assertSeedMatchesCapture harness.

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
)

// withDefaultIfType backfills IfType == 6 (ethernetCsmacd, the physical-port
// default -- see PortSim.IfType's doc comment and NewPortSim) onto every
// port in ports whose IfType is still the Go zero value.
//
// Every seed function below builds its (very large) physical-port tables
// via bare struct literals for legibility/transcription fidelity, not
// NewPortSim, and sets IfType explicitly ONLY on each seed's genuinely
// non-physical rows (the CPU/LAG/VLAN-interface pseudo-ports, e.g. ifIndex
// 417/418 in SeedGSM7252PS) -- so every OTHER port literal's omitted
// IfType field is left at Go's zero value (0), not the physical default
// (6) NewPortSim itself would have applied. Left unfixed, every physical
// port in every seed answers ifType 0 on the wire, which
// snmp.physicalPorts (the reader's physical-vs-pseudo-interface filter)
// then excludes -- silently emptying GetPorts/GetStats for every single
// seeded model. This helper backfills exactly the default NewPortSim
// applies, mutating and returning ports for a single-expression call site
// at the end of each Seed function below.
func withDefaultIfType(ports map[int]*PortSim) map[int]*PortSim {
	for _, p := range ports {
		if p.IfType == 0 {
			p.IfType = 6
		}
	}
	return ports
}

// SeedGSM7252PS builds a GSM7252PS (52-port, 48-PoE) State transcribed field-for-field
// from the real hardware capture testdata/captures/gsm7252ps.json (SNMP,
// host 10.1.5.22) via the pinned Python seed_gsm7252ps: every port's
// admin/link/speed/ifAlias and counters, every PVID, all 14 VLANs' exact
// member/untagged ifIndex sets (including the per-VLAN lag 1..lag 64
// aggregation ifIndexes and the genuine hardware quirk that Untagged is
// NOT a subset of Member for several VLANs, e.g. VLAN 6), all 48 PoE
// ports, the SNMP-face box sensors (fan RPM + PSU watts, no temperature)
// and a separate HTTPSensors set the web sysInfo page reports instead
// (temperatures + fan/PSU health text), the management IP/base MAC,
// serial and firmware. Two of the capture's 65 non-physical ifIndexes
// (417 "CPU Interface", 418 "lag 1") are carried too so a renderer that
// forgets the web UI lists only physical ports is caught -- see
// assertSeedMatchesCapture in seed_test.go for the strict parity check
// this holds to (ports/PVIDs/VLANs/PoE/sensors/mgmt-IP).
//
// Genuinely ILLUSTRATIVE (regression traps the capture cannot express):
// the MAC/FDB entries and their non-identity bridge-port -> ifIndex join
// (BridgePorts[10]=110, deliberately not 10, proving get_macs must use
// the join and never the bare bridge-port number), the single LLDP
// neighbour, and Mgmt.Mode/Gateway (the real capture reports mode
// "unknown" and no gateway route; this mock needs a definite writable
// DHCP-mode OID to serve, so "static" + the subnet's router are
// structural stand-ins, never a claim about the real device).
func SeedGSM7252PS() *State {
	ports := map[int]*PortSim{
		1:   {Name: "1/0/1", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(45747246)), TxOctets: model.Ptr(uint64(912689098)), RxUcast: model.Ptr(uint64(217358)), TxUcast: model.Ptr(uint64(235430)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi5-pmod")},
		2:   {Name: "1/0/2", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(43729612)), TxOctets: model.Ptr(uint64(982042673)), RxUcast: model.Ptr(uint64(227304)), TxUcast: model.Ptr(uint64(287393)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi4-pmod")},
		3:   {Name: "1/0/3", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(309174274)), TxOctets: model.Ptr(uint64(2763396970)), RxUcast: model.Ptr(uint64(2703903)), TxUcast: model.Ptr(uint64(2832210)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.reterm2")},
		4:   {Name: "1/0/4", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(392406056)), TxOctets: model.Ptr(uint64(1208220179)), RxUcast: model.Ptr(uint64(455946)), TxUcast: model.Ptr(uint64(362560)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi3b-gwifi")},
		5:   {Name: "1/0/5", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(45296975)), TxOctets: model.Ptr(uint64(1784117938)), RxUcast: model.Ptr(uint64(252396)), TxUcast: model.Ptr(uint64(695269)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi4-usbdev")},
		6:   {Name: "1/0/6", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		7:   {Name: "1/0/7", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(45478982)), TxOctets: model.Ptr(uint64(1213479258)), RxUcast: model.Ptr(uint64(243846)), TxUcast: model.Ptr(uint64(319720)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpib-sdcard")},
		8:   {Name: "1/0/8", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		9:   {Name: "1/0/9", Admin: true, Link: true, Speed: 100, RxOctets: model.Ptr(uint64(43952641)), TxOctets: model.Ptr(uint64(2474560700)), RxUcast: model.Ptr(uint64(203437)), TxUcast: model.Ptr(uint64(525017)), RxErrors: model.Ptr(uint64(188)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpib-serial")},
		10:  {Name: "1/0/10", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		11:  {Name: "1/0/11", Admin: true, Link: true, Speed: 100, RxOctets: model.Ptr(uint64(191245854)), TxOctets: model.Ptr(uint64(2353135188)), RxUcast: model.Ptr(uint64(504340)), TxUcast: model.Ptr(uint64(779331)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.puck11")},
		12:  {Name: "1/0/12", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(242753298)), TxOctets: model.Ptr(uint64(2405690445)), RxUcast: model.Ptr(uint64(568614)), TxUcast: model.Ptr(uint64(871728)), RxErrors: model.Ptr(uint64(98)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.puck07")},
		13:  {Name: "1/0/13", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(54822647)), TxOctets: model.Ptr(uint64(1790957945)), RxUcast: model.Ptr(uint64(314512)), TxUcast: model.Ptr(uint64(686411)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi5-433mhz")},
		14:  {Name: "1/0/14", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(1371471567)), TxOctets: model.Ptr(uint64(2391786115)), RxUcast: model.Ptr(uint64(5452154)), TxUcast: model.Ptr(uint64(8842491)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi-birds-welland-back")},
		15:  {Name: "1/0/15", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		16:  {Name: "1/0/16", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(458026172)), TxOctets: model.Ptr(uint64(2161853643)), RxUcast: model.Ptr(uint64(4479341)), TxUcast: model.Ptr(uint64(7845883)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi-sdr-pluto")},
		17:  {Name: "1/0/17", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(48254266)), TxOctets: model.Ptr(uint64(1370034013)), RxUcast: model.Ptr(uint64(247191)), TxUcast: model.Ptr(uint64(559339)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi5-zigbee")},
		18:  {Name: "1/0/18", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(107301127)), TxOctets: model.Ptr(uint64(3428968332)), RxUcast: model.Ptr(uint64(662009)), TxUcast: model.Ptr(uint64(1912062)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi4-asus-aspeed2050-dev")},
		19:  {Name: "1/0/19", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		20:  {Name: "1/0/20", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(48094973)), TxOctets: model.Ptr(uint64(1600286182)), RxUcast: model.Ptr(uint64(261316)), TxUcast: model.Ptr(uint64(548326)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi4-hppdu-dev")},
		21:  {Name: "1/0/21", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		22:  {Name: "1/0/22", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(44983852)), TxOctets: model.Ptr(uint64(1761230194)), RxUcast: model.Ptr(uint64(274092)), TxUcast: model.Ptr(uint64(651683)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi4-precursor")},
		23:  {Name: "1/0/23", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		24:  {Name: "1/0/24", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(60929816)), TxOctets: model.Ptr(uint64(1662046751)), RxUcast: model.Ptr(uint64(292512)), TxUcast: model.Ptr(uint64(618541)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi4-gwifi")},
		25:  {Name: "1/0/25", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(860424)), TxOctets: model.Ptr(uint64(432228822)), RxUcast: model.Ptr(uint64(5367)), TxUcast: model.Ptr(uint64(11254)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		26:  {Name: "1/0/26", Admin: true, Link: true, Speed: 100, RxOctets: model.Ptr(uint64(42636836)), TxOctets: model.Ptr(uint64(1207912561)), RxUcast: model.Ptr(uint64(221448)), TxUcast: model.Ptr(uint64(441634)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpiz-3")},
		27:  {Name: "1/0/27", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(43106121)), TxOctets: model.Ptr(uint64(1783468534)), RxUcast: model.Ptr(uint64(249904)), TxUcast: model.Ptr(uint64(681000)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi4-esp")},
		28:  {Name: "1/0/28", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		29:  {Name: "1/0/29", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		30:  {Name: "1/0/30", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(46856497)), TxOctets: model.Ptr(uint64(1781675389)), RxUcast: model.Ptr(uint64(238217)), TxUcast: model.Ptr(uint64(691884)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi5-rfbridge")},
		31:  {Name: "1/0/31", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(34224983)), TxOctets: model.Ptr(uint64(1103571183)), RxUcast: model.Ptr(uint64(191771)), TxUcast: model.Ptr(uint64(227719)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.minnow-turbot-2")},
		32:  {Name: "1/0/32", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(36725195)), TxOctets: model.Ptr(uint64(1103043544)), RxUcast: model.Ptr(uint64(199490)), TxUcast: model.Ptr(uint64(236217)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.minnow-turbot-1")},
		33:  {Name: "1/0/33", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(41767749)), TxOctets: model.Ptr(uint64(1780610707)), RxUcast: model.Ptr(uint64(235994)), TxUcast: model.Ptr(uint64(676190)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi4-kindle")},
		34:  {Name: "1/0/34", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		35:  {Name: "1/0/35", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		36:  {Name: "1/0/36", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		37:  {Name: "1/0/37", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(61212753)), TxOctets: model.Ptr(uint64(1383861442)), RxUcast: model.Ptr(uint64(366925)), TxUcast: model.Ptr(uint64(650250)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi5-netv2")},
		38:  {Name: "1/0/38", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(44488789)), TxOctets: model.Ptr(uint64(1286245977)), RxUcast: model.Ptr(uint64(339689)), TxUcast: model.Ptr(uint64(516784)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi3-netv2")},
		39:  {Name: "1/0/39", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		40:  {Name: "1/0/40", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		41:  {Name: "1/0/41", Admin: true, Link: true, Speed: 100, RxOctets: model.Ptr(uint64(47611153)), TxOctets: model.Ptr(uint64(1597050827)), RxUcast: model.Ptr(uint64(285613)), TxUcast: model.Ptr(uint64(729735)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpiz-serial")},
		42:  {Name: "1/0/42", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(2121062532)), TxOctets: model.Ptr(uint64(3300194902)), RxUcast: model.Ptr(uint64(18659985)), TxUcast: model.Ptr(uint64(20148348)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi-sdr-rtlsdr-v3")},
		43:  {Name: "1/0/43", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("end0.hifive-unmatched-1")},
		44:  {Name: "1/0/44", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("end0.hifive-unmatched-2")},
		45:  {Name: "1/0/45", Admin: true, Link: true, Speed: 100, RxOctets: model.Ptr(uint64(895931591)), TxOctets: model.Ptr(uint64(720798804)), RxUcast: model.Ptr(uint64(1283153)), TxUcast: model.Ptr(uint64(515947)), RxErrors: model.Ptr(uint64(1)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("wired.fritz-box-7270-1")},
		46:  {Name: "1/0/46", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(215009366)), TxOctets: model.Ptr(uint64(3079995766)), RxUcast: model.Ptr(uint64(735039)), TxUcast: model.Ptr(uint64(1206637)), RxErrors: model.Ptr(uint64(111)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.puck12")},
		47:  {Name: "1/0/47", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(20987280)), TxOctets: model.Ptr(uint64(2708586643)), RxUcast: model.Ptr(uint64(114946)), TxUcast: model.Ptr(uint64(390277)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("p5.sw-poe-micro3")},
		48:  {Name: "1/0/48", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(88601206)), TxOctets: model.Ptr(uint64(3713706826)), RxUcast: model.Ptr(uint64(1025558)), TxUcast: model.Ptr(uint64(2517756)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("spare.ex-cisco")},
		49:  {Name: "1/0/49", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(28392074220)), TxOctets: model.Ptr(uint64(9325801127)), RxUcast: model.Ptr(uint64(77433287)), TxUcast: model.Ptr(uint64(62142947)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("1/0/2.sw-netgear-m4300-24x")},
		50:  {Name: "1/0/50", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(278014432)), TxOctets: model.Ptr(uint64(1694871324)), RxUcast: model.Ptr(uint64(2069292)), TxUcast: model.Ptr(uint64(2139039)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("1/0/49.sw-netgear-gsm7252ps-s2")},
		51:  {Name: "1/0/51", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(1075552286)), TxOctets: model.Ptr(uint64(2278779253)), RxUcast: model.Ptr(uint64(9235681)), TxUcast: model.Ptr(uint64(9547144)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("1/0/51.sw-netgear-gsm7252ps-s2")},
		52:  {Name: "1/0/52", Admin: true, Link: false, Speed: 10000, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		417: {Name: "CPU Interface:  0/5/1", Admin: true, Link: true, Speed: 0, IfType: 1},
		418: {Name: "lag 1", Admin: true, Link: true, Speed: 20000, IfType: 161, Description: model.Ptr("lag.sw-netgear-gsm7252ps-s2")},
	}

	vlans := map[int]*VlanSim{
		// Ports 50/51 are on this VLAN's static (configured) egress list but
		// are NOT current members -- live-captured on 10.1.5.22: `show vlan 1`
		// and vlanPortCfg_vlan1.html both list them "Current: Exclude /
		// Configured: Include", while dot1qVlanStaticEgressPorts and the VLAN
		// Membership page's hiddenMem grid DO carry them (see
		// VlanSim.ConfiguredOnly). Their Untagged bit stays set: that bitmap is
		// a separate axis the real switch keeps regardless of participation.
		1:   {Name: "default", Member: portSetFromSlice([]int{6, 8, 10, 15, 19, 21, 22, 26, 28, 29, 34, 35, 36, 39, 40, 49, 52, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481}), Untagged: portSetFromSlice([]int{3, 4, 6, 7, 8, 10, 14, 15, 16, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28, 29, 30, 31, 32, 34, 35, 36, 39, 40, 42, 49, 50, 51, 52, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481}), ConfiguredOnly: portSetFromSlice([]int{50, 51})},
		4:   {Name: "wifi", Member: portSetFromSlice([]int{11, 12, 46, 49, 50, 51}), Untagged: portSetFromSlice([]int{11, 12, 46})},
		5:   {Name: "net", Member: portSetFromSlice([]int{3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20, 21, 22, 24, 25, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 39, 40, 42, 46, 47, 48, 49, 50, 51, 52, 418, 419}), Untagged: portSetFromSlice([]int{9, 45, 47, 48, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481})},
		6:   {Name: "pwr", Member: portSetFromSlice([]int{46, 47, 49, 50, 51, 418, 419}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48, 52})},
		7:   {Name: "store", Member: portSetFromSlice([]int{}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481})},
		10:  {Name: "int", Member: portSetFromSlice([]int{9, 11, 12, 46, 47, 49, 50, 51, 418, 419}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 10, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48, 52})},
		20:  {Name: "roam", Member: portSetFromSlice([]int{9, 11, 12, 45, 46, 47, 49, 50, 51, 418, 419}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 10, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48, 52})},
		21:  {Name: "fpgas", Member: portSetFromSlice([]int{}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481})},
		41:  {Name: "sm", Member: portSetFromSlice([]int{46, 47, 49, 50, 51, 418, 419}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48, 52})},
		89:  {Name: "sdr", Member: portSetFromSlice([]int{}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481})},
		90:  {Name: "iot", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 7, 9, 11, 12, 13, 14, 16, 17, 18, 20, 22, 23, 24, 25, 26, 27, 30, 31, 32, 33, 37, 38, 41, 42, 43, 44, 46, 47, 49, 50, 51, 418, 419}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48, 52})},
		99:  {Name: "guest", Member: portSetFromSlice([]int{9, 11, 12, 46, 47, 49, 50, 51, 418, 419}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 10, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48, 52})},
		121: {Name: "t-fpgas", Member: portSetFromSlice([]int{46, 47, 49, 50, 51, 418, 419}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48, 52})},
		141: {Name: "t-sm", Member: portSetFromSlice([]int{46, 47, 49, 50, 51, 418, 419}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 48, 52})},
	}

	pvids := map[int]int{
		1: 90, 2: 90, 3: 90, 4: 90, 5: 90, 6: 1, 7: 90, 8: 1, 9: 90, 10: 1, 11: 4, 12: 4, 13: 90, 14: 90, 15: 1, 16: 90, 17: 90, 18: 90, 19: 1, 20: 90, 21: 1, 22: 90, 23: 90, 24: 90, 25: 90, 26: 90, 27: 90, 28: 1, 29: 1, 30: 90, 31: 90, 32: 90, 33: 90, 34: 1, 35: 1, 36: 1, 37: 90, 38: 90, 39: 1, 40: 1, 41: 90, 42: 90, 43: 90, 44: 90, 45: 20, 46: 4, 47: 5, 48: 5, 49: 1, 50: 1, 51: 1, 52: 1,
	}

	poe := map[int]*PoeSim{
		1:  {Admin: true, Detect: 3, PowerMw: 3500},
		2:  {Admin: true, Detect: 3, PowerMw: 2700},
		3:  {Admin: true, Detect: 3, PowerMw: 3500},
		4:  {Admin: true, Detect: 3, PowerMw: 9000},
		5:  {Admin: true, Detect: 3, PowerMw: 5800},
		6:  {Admin: true, Detect: 6, PowerMw: 0},
		7:  {Admin: true, Detect: 3, PowerMw: 3900},
		8:  {Admin: true, Detect: 3, PowerMw: 1500},
		9:  {Admin: true, Detect: 3, PowerMw: 3800},
		10: {Admin: true, Detect: 2, PowerMw: 0},
		11: {Admin: true, Detect: 3, PowerMw: 4100},
		12: {Admin: true, Detect: 3, PowerMw: 4700},
		13: {Admin: true, Detect: 3, PowerMw: 4600},
		14: {Admin: true, Detect: 3, PowerMw: 3800},
		15: {Admin: true, Detect: 2, PowerMw: 0},
		16: {Admin: true, Detect: 2, PowerMw: 0},
		17: {Admin: true, Detect: 3, PowerMw: 3400},
		18: {Admin: true, Detect: 3, PowerMw: 8500},
		19: {Admin: true, Detect: 2, PowerMw: 0},
		20: {Admin: true, Detect: 3, PowerMw: 6000},
		21: {Admin: true, Detect: 2, PowerMw: 0},
		22: {Admin: true, Detect: 3, PowerMw: 6000},
		23: {Admin: true, Detect: 2, PowerMw: 0},
		24: {Admin: true, Detect: 3, PowerMw: 7700},
		25: {Admin: true, Detect: 3, PowerMw: 3700},
		26: {Admin: true, Detect: 3, PowerMw: 1700},
		27: {Admin: true, Detect: 3, PowerMw: 7100},
		28: {Admin: true, Detect: 2, PowerMw: 0},
		29: {Admin: true, Detect: 2, PowerMw: 0},
		30: {Admin: true, Detect: 3, PowerMw: 4100},
		31: {Admin: true, Detect: 3, PowerMw: 3800},
		32: {Admin: true, Detect: 3, PowerMw: 3900},
		33: {Admin: true, Detect: 3, PowerMw: 5700},
		34: {Admin: true, Detect: 2, PowerMw: 0},
		35: {Admin: true, Detect: 2, PowerMw: 0},
		36: {Admin: true, Detect: 2, PowerMw: 0},
		37: {Admin: true, Detect: 3, PowerMw: 9400},
		38: {Admin: true, Detect: 3, PowerMw: 9900},
		39: {Admin: true, Detect: 2, PowerMw: 0},
		40: {Admin: true, Detect: 2, PowerMw: 0},
		41: {Admin: true, Detect: 3, PowerMw: 3200},
		42: {Admin: true, Detect: 3, PowerMw: 6900},
		43: {Admin: true, Detect: 2, PowerMw: 0},
		44: {Admin: true, Detect: 2, PowerMw: 0},
		45: {Admin: true, Detect: 2, PowerMw: 0},
		46: {Admin: true, Detect: 3, PowerMw: 4300},
		47: {Admin: true, Detect: 3, PowerMw: 1900},
		48: {Admin: true, Detect: 2, PowerMw: 0},
	}

	sensors := []SensorSim{
		{Kind: "fan", Instance: "0", Raw: "2850"},
		{Kind: "fan", Instance: "2", Raw: "2350"},
		{Kind: "power", Instance: "0", Raw: "49"},
		{Kind: "power", Instance: "1", Raw: "30"},
		{Kind: "power", Instance: "2", Raw: "32"},
		{Kind: "power", Instance: "3", Raw: "31"},
	}

	httpSensors := []SensorSim{
		{Kind: "temperature", Instance: "System", Raw: "29"},
		{Kind: "temperature", Instance: "CPU", Raw: "49"},
		{Kind: "temperature", Instance: "MAC", Raw: "N/A"},
		{Kind: "temperature", Instance: "MAC-A", Raw: "32"},
		{Kind: "temperature", Instance: "MAC-B", Raw: "31"},
		{Kind: "fan", Instance: "Fan1/PWR", Raw: "OK"},
		{Kind: "fan", Instance: "Fan2/CPU", Raw: "OK"},
		{Kind: "fan", Instance: "Fan3/SYS", Raw: "OK"},
		{Kind: "fan", Instance: "Fan4", Raw: "NA"},
		{Kind: "fan", Instance: "Fan5", Raw: "NA"},
		{Kind: "power", Instance: "RPS", Raw: "Operational"},
		{Kind: "power", Instance: "Power Module", Raw: "Operational"},
	}

	macs := []MacSim{
		{Vlan: 90, MacBytes: [6]byte{0xc8, 0x00, 0x84, 0x89, 0x71, 0x70}, BridgePort: 10},
		{Vlan: 1, MacBytes: [6]byte{0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e}, BridgePort: 11},
	}

	bridgePorts := map[int]int{
		10: 110, 11: 11,
	}

	lldp := []LldpSim{
		{TimeMark: 75, LocalPort: 49, RemIdx: 7, Chassis: string([]byte{0xc8, 0x00, 0x84, 0x89, 0x71, 0x70}), PortID: "1/xg51", PortDesc: "eth0", SysName: "sw-cisco-shed"},
	}

	mgmt := MgmtSim{Address: "10.1.5.22", Netmask: "255.255.255.0", Gateway: "10.1.5.1", Mode: "static"}

	s := NewState("gsm7252ps")

	s.Ports = withDefaultIfType(ports)

	s.Vlans = vlans

	s.Pvids = pvids

	s.Poe = poe

	s.Sensors = sensors

	s.HTTPSensors = httpSensors

	s.Macs = macs

	s.BridgePorts = bridgePorts

	s.Lldp = lldp

	s.Mgmt = mgmt

	// MEASURED 2026-08-03 on 10.1.5.22's own userManagement.html. The
	// wording is that PAGE's, not the CLI's -- the same switch's
	// `show users` calls admin "Read/Write" (see CLIAccessMode below).
	// Ported field-for-field from Python's seed_gsm7252ps (seed.py:1259).
	//
	// CLIAccessMode is PRINCIPLE-5 territory (see UserSim's own doc
	// comment): Python's own virtual fake has no `show users` CLI
	// renderer to port from at pin b26eb1f, so these two values are
	// transcribed from the live-verified table in Python commit 4619e3c
	// ("feat(cli): read the switch's local user accounts") rather than
	// from a Python fake seed or a captured fixture file.
	s.Users = []UserSim{
		{Name: "admin", HTTPAccessMode: "Super User", CLIAccessMode: "Read/Write"},
		{Name: "guest", HTTPAccessMode: "Read Only", CLIAccessMode: "Read Only"},
	}

	// MEASURED 2026-08-03 on 10.1.5.22, HTTP pages and `show ip http` /
	// `show ip ssh` / `show telnetcon` agreeing. Telnet really is OFF here,
	// independently confirmed by TCP 23 being refused. Neither this
	// switch's http nor its ssh page prints a port, so both are nil --
	// NOT defaulted to 80/22, which would be inventing a field. Ported
	// field-for-field from Python's seed_gsm7252ps (seed.py:1265).
	//
	// CLIPort is PRINCIPLE-5 territory the same way UserSim.CLIAccessMode
	// is above: transcribed from Python commit 2c7ddff's live-verified
	// table ("feat(cli): read which management services are enabled"),
	// "gsm7252ps  http=on:None  https=on:443  telnet=off  ssh=on:None" --
	// not from a Python fake seed or a captured fixture file.
	s.Services = map[string]ServiceSim{
		"http":   {Enabled: true},
		"https":  {Enabled: true, Port: model.Ptr(443), CLIPort: model.Ptr(443)},
		"ssh":    {Enabled: true},
		"telnet": {Enabled: false},
	}

	s.ModelName = "GSM7252PS"

	s.Serial = "2BW20A47000CC"

	s.Firmware = "10.0.0.53"

	s.Hostname = "sw-netgear-gsm7252ps-s1.welland.mithis.com"

	s.NsdpMac = [6]byte{0xe0, 0x91, 0xf5, 0x0c, 0xd6, 0xdb}

	s.SysDescr = "NETGEAR GSM7252PS Managed Switch, firmware 8.0.6.6"

	// REAL MEASURED value: live SNMP GET of sysObjectID against the actual
	// gsm7252ps @10.1.5.22 (firmware 10.0.0.53), captured 2026-08-20. This
	// replaces a previous unverified placeholder
	// ("1.3.6.1.4.1.4526.10.100.14", still carried unfixed by the Python
	// pin's seed_gsm7252ps -- see seed.py:1276-1281's own "UNVERIFIED
	// virtual/test placeholder ... no capture of the real value exists"
	// comment) now that a live capture exists. Not added to
	// snmp.SysObjectIDModels: that map is reserved for OIDs actually proven
	// to identify a model (see its own doc comment); this switch's
	// sysDescr already contains "GSM7252PS" and detects fine via
	// DetectModelFromSysDescr.
	s.SysObjectID = "1.3.6.1.4.1.4526.100.1.10"

	// Real fixed Q-BRIDGE PortList width, measured LIVE (read-only) on this
	// switch @10.1.5.22: dot1qVlanStaticEgressPorts is 79 bytes wide.
	s.VLANPortListWidth = model.Ptr(79)

	// MEASURED off the real VLAN-Membership capture (2026-07-30,
	// testdata/http/gsm7252ps_vlanPortCfg_vlan1.html): 116 hiddenMem slots
	// = 52 ports + 64 LAGs, LAG ifNames 0/3/N, the OLDER
	// toggleImageFirst/grey_[btu].gif grid, no trailing comma, no CSRFToken
	// and UNescaped ifName lists (the only one of the four like that).
	s.VlanMembershipPage = &VlanMembershipPageSim{Slots: 116, LagSlot: 3, Grid: "gif"}

	// MEASURED 2026-08-02 on 10.1.5.22: identical to the m4300 pair --
	// enabled, port 514, one collector 10.1.5.1 info(6) 514 Active. Ported
	// field-for-field from Python's seed_gsm7252ps (seed.py:1251).
	s.Syslog = SyslogSim{
		AdminMode:  1,
		LocalPort:  514,
		Collectors: []SyslogCollectorSim{{Host: "10.1.5.1", Port: 514, Severity: 6, Status: 1, Index: 1}},
	}

	return s
}

// SeedGSM7228PS builds a GSM7228PS / S3300-52X-PoE+ (52-port, 48-PoE Smart Managed
// Pro) State transcribed field-for-field from this model's OWN real
// hardware capture testdata/captures/gsm7228ps.json (SNMP host 10.1.5.11
// = sw-netgear-s3300-1, sysObjectID 1.3.6.1.4.1.4526.100.10.19, captured
// 2026-07-30) via the pinned Python seed_gsm7228ps: every physical
// port's name/admin/link/speed and counters, every PVID, all 5 VLANs
// with their exact member/untagged ifIndex sets (including the lag
// 1..lag 26 ifIndexes 314-339 VLAN 1 carries), all 48 PoE ports (2
// delivering, 1 fault, the rest searching), the box sensors (3 fan RPM +
// PSU watts + temperature), the management IP (10.1.5.11) and base MAC.
//
// IMPORTANT: this is the CURRENT, real-capture-based seed -- D-VIRT
// §4.2's text describes an OLDER, hand-invented illustrative seed that
// was superseded on the pinned Python branch; that dossier section is
// documented there as stale and does not apply here. This function
// transcribes seed.py as it exists on the pin, not the dossier.
//
// Genuinely ILLUSTRATIVE (regression traps the capture cannot express):
// Mgmt.Mode/Gateway (same static-DHCP-mode-OID reasoning as
// SeedGSM7252PS -- the real capture reports mode "unknown" and no
// gateway route). MAC/FDB and LLDP rows ARE transcribed from the
// capture but are inherently volatile point-in-time facts, so
// assertSeedMatchesCapture deliberately does not pin them (see its own
// doc comment).
func SeedGSM7228PS() *State {
	ports := map[int]*PortSim{
		1:  {Name: "1/g1", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		2:  {Name: "1/g2", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		3:  {Name: "1/g3", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		4:  {Name: "1/g4", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		5:  {Name: "1/g5", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		6:  {Name: "1/g6", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		7:  {Name: "1/g7", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		8:  {Name: "1/g8", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		9:  {Name: "1/g9", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		10: {Name: "1/g10", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		11: {Name: "1/g11", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		12: {Name: "1/g12", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		13: {Name: "1/g13", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		14: {Name: "1/g14", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		15: {Name: "1/g15", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		16: {Name: "1/g16", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		17: {Name: "1/g17", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		18: {Name: "1/g18", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		19: {Name: "1/g19", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		20: {Name: "1/g20", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		21: {Name: "1/g21", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		22: {Name: "1/g22", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		23: {Name: "1/g23", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		24: {Name: "1/g24", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		25: {Name: "1/g25", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		26: {Name: "1/g26", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		27: {Name: "1/g27", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		28: {Name: "1/g28", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		29: {Name: "1/g29", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		30: {Name: "1/g30", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		31: {Name: "1/g31", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		32: {Name: "1/g32", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		33: {Name: "1/g33", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		34: {Name: "1/g34", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		35: {Name: "1/g35", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		36: {Name: "1/g36", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		37: {Name: "1/g37", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		38: {Name: "1/g38", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("class0?")},
		39: {Name: "1/g39", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		40: {Name: "1/g40", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("class0?")},
		41: {Name: "1/g41", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth-local.tweed")},
		42: {Name: "1/g42", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("bmc.tweed")},
		43: {Name: "1/g43", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		44: {Name: "1/g44", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		45: {Name: "1/g45", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.hifive-unmatched-2")},
		46: {Name: "1/g46", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.hifive-unmatched-1")},
		47: {Name: "1/g47", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi-sdr-rtlsdr-v3")},
		48: {Name: "1/g48", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpiz-serial")},
		49: {Name: "1/xg49", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(492931)), TxOctets: model.Ptr(uint64(9048)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		50: {Name: "1/xg50", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("cisco-shed")},
		51: {Name: "1/xg51", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(5493036)), TxOctets: model.Ptr(uint64(5451371)), RxUcast: model.Ptr(uint64(49697)), TxUcast: model.Ptr(uint64(49690)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		52: {Name: "1/xg52", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxUcast: model.Ptr(uint64(0)), TxUcast: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
	}

	vlans := map[int]*VlanSim{
		1:    {Name: "Default", Member: portSetFromSlice([]int{49, 50, 51, 52, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339}), Untagged: portSetFromSlice([]int{49, 50, 51, 52, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339})},
		5:    {Name: "net", Member: portSetFromSlice([]int{41, 49, 50, 51, 52}), Untagged: portSetFromSlice([]int{41})},
		21:   {Name: "fpgas", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 42, 43, 44, 45, 46, 47}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 42, 43, 44, 45, 46, 47})},
		121:  {Name: "t-fpgas", Member: portSetFromSlice([]int{48, 49, 50, 51, 52}), Untagged: portSetFromSlice([]int{48})},
		4089: {Name: "Auto-Video", Member: portSetFromSlice([]int{}), Untagged: portSetFromSlice([]int{})},
	}

	pvids := map[int]int{
		1: 21, 2: 21, 3: 21, 4: 21, 5: 21, 6: 21, 7: 21, 8: 21, 9: 21, 10: 21, 11: 21, 12: 21, 13: 21, 14: 21, 15: 21, 16: 21, 17: 21, 18: 21, 19: 21, 20: 21, 21: 21, 22: 21, 23: 21, 24: 21, 25: 21, 26: 21, 27: 21, 28: 21, 29: 21, 30: 21, 31: 21, 32: 21, 33: 21, 34: 21, 35: 21, 36: 21, 37: 21, 38: 21, 39: 21, 40: 21, 41: 5, 42: 21, 43: 21, 44: 21, 45: 21, 46: 21, 47: 21, 48: 121, 49: 1, 50: 1, 51: 1, 52: 1,
	}

	poe := map[int]*PoeSim{
		1:  {Admin: true, Detect: 2, PowerMw: 0},
		2:  {Admin: true, Detect: 2, PowerMw: 0},
		3:  {Admin: true, Detect: 2, PowerMw: 0},
		4:  {Admin: true, Detect: 2, PowerMw: 0},
		5:  {Admin: true, Detect: 2, PowerMw: 0},
		6:  {Admin: true, Detect: 2, PowerMw: 0},
		7:  {Admin: true, Detect: 2, PowerMw: 0},
		8:  {Admin: true, Detect: 2, PowerMw: 0},
		9:  {Admin: true, Detect: 2, PowerMw: 0},
		10: {Admin: true, Detect: 2, PowerMw: 0},
		11: {Admin: true, Detect: 2, PowerMw: 0},
		12: {Admin: true, Detect: 2, PowerMw: 0},
		13: {Admin: true, Detect: 2, PowerMw: 0},
		14: {Admin: true, Detect: 2, PowerMw: 0},
		15: {Admin: true, Detect: 2, PowerMw: 0},
		16: {Admin: true, Detect: 2, PowerMw: 0},
		17: {Admin: true, Detect: 2, PowerMw: 0},
		18: {Admin: true, Detect: 2, PowerMw: 0},
		19: {Admin: true, Detect: 2, PowerMw: 0},
		20: {Admin: true, Detect: 2, PowerMw: 0},
		21: {Admin: true, Detect: 2, PowerMw: 0},
		22: {Admin: true, Detect: 2, PowerMw: 0},
		23: {Admin: true, Detect: 2, PowerMw: 0},
		24: {Admin: true, Detect: 2, PowerMw: 0},
		25: {Admin: true, Detect: 2, PowerMw: 0},
		26: {Admin: true, Detect: 2, PowerMw: 0},
		27: {Admin: true, Detect: 2, PowerMw: 0},
		28: {Admin: true, Detect: 2, PowerMw: 0},
		29: {Admin: true, Detect: 2, PowerMw: 0},
		30: {Admin: true, Detect: 2, PowerMw: 0},
		31: {Admin: true, Detect: 2, PowerMw: 0},
		32: {Admin: true, Detect: 2, PowerMw: 0},
		33: {Admin: true, Detect: 2, PowerMw: 0},
		34: {Admin: true, Detect: 2, PowerMw: 0},
		35: {Admin: true, Detect: 2, PowerMw: 0},
		36: {Admin: true, Detect: 2, PowerMw: 0},
		37: {Admin: true, Detect: 2, PowerMw: 0},
		38: {Admin: true, Detect: 2, PowerMw: 0},
		39: {Admin: true, Detect: 2, PowerMw: 0},
		40: {Admin: true, Detect: 2, PowerMw: 0},
		41: {Admin: true, Detect: 2, PowerMw: 0},
		42: {Admin: true, Detect: 2, PowerMw: 0},
		43: {Admin: true, Detect: 2, PowerMw: 0},
		44: {Admin: true, Detect: 3, PowerMw: 400},
		45: {Admin: true, Detect: 2, PowerMw: 0},
		46: {Admin: true, Detect: 4, PowerMw: 0},
		47: {Admin: true, Detect: 2, PowerMw: 0},
		48: {Admin: true, Detect: 3, PowerMw: 700},
	}

	sensors := []SensorSim{
		{Kind: "fan", Instance: "0", Raw: "4963"},
		{Kind: "fan", Instance: "1", Raw: "5212"},
		{Kind: "fan", Instance: "2", Raw: "5294"},
		{Kind: "power", Instance: "0", Raw: "38"},
		{Kind: "temperature", Instance: "1", Raw: "38"},
	}

	macs := []MacSim{
		{Vlan: 5, MacBytes: [6]byte{0x02, 0x00, 0x0a, 0x01, 0x05, 0x01}, BridgePort: 51},
		{Vlan: 121, MacBytes: [6]byte{0x02, 0x00, 0x0a, 0x01, 0x21, 0x01}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0x0c, 0xc4, 0x7a, 0x1b, 0xd9, 0xc7}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0x1c, 0x34, 0xda, 0x42, 0xe8, 0x8c}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0x1c, 0x34, 0xda, 0x42, 0xe8, 0x8d}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0x44, 0xa5, 0x6e, 0x60, 0xc5, 0xb6}, BridgePort: 51},
		{Vlan: 121, MacBytes: [6]byte{0x44, 0xa5, 0x6e, 0x60, 0xc5, 0xb6}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0x8c, 0x3b, 0xad, 0x69, 0x1c, 0x3b}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0x8c, 0x3b, 0xad, 0x6b, 0xbb, 0xe3}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0xac, 0x1f, 0x6b, 0xaa, 0x50, 0x53}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0xbc, 0xa5, 0x11, 0xb8, 0xec, 0xf1}, BridgePort: 51},
		{Vlan: 121, MacBytes: [6]byte{0xbc, 0xa5, 0x11, 0xb8, 0xec, 0xf1}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0xbc, 0xa5, 0x11, 0xb8, 0xed, 0x42}, BridgePort: 51},
		{Vlan: 121, MacBytes: [6]byte{0xbc, 0xa5, 0x11, 0xb8, 0xed, 0x42}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0xe0, 0x91, 0xf5, 0x0c, 0xd5, 0xc7}, BridgePort: 51},
		{Vlan: 1, MacBytes: [6]byte{0xe0, 0x91, 0xf5, 0x0c, 0xd5, 0xc9}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0xe0, 0x91, 0xf5, 0x0c, 0xd6, 0xdb}, BridgePort: 51},
		{Vlan: 5, MacBytes: [6]byte{0x08, 0xbd, 0x43, 0x6b, 0xb8, 0xd8}, BridgePort: 313},
	}

	lldp := []LldpSim{
		{TimeMark: 1, LocalPort: 49, RemIdx: 1, Chassis: string([]byte{0xe0, 0x91, 0xf5, 0x0c, 0xd6, 0xdb}), PortID: "1/0/48", PortDesc: "spare.ex-cisco", SysName: "sw-netgear-gsm7252ps-s1.welland.mithis.com"},
		{TimeMark: 2, LocalPort: 51, RemIdx: 2, Chassis: string([]byte{0xe0, 0x91, 0xf5, 0x0c, 0xd5, 0xc7}), PortID: "1/0/50", PortDesc: "1/0/50", SysName: "sw-netgear-gsm7252ps-s2.welland.mithis.com"},
	}

	mgmt := MgmtSim{Address: "10.1.5.11", Netmask: "255.255.255.0", Gateway: "10.1.5.1", Mode: "static"}

	s := NewState("gsm7228ps")

	s.Ports = withDefaultIfType(ports)

	s.Vlans = vlans

	s.Pvids = pvids

	s.Poe = poe

	s.Sensors = sensors

	s.Macs = macs

	s.Lldp = lldp

	s.Mgmt = mgmt

	s.ModelName = "GSM7228PS"

	s.Hostname = "sw-netgear-s3300-1"

	s.NsdpMac = [6]byte{0x08, 0xbd, 0x43, 0x6b, 0xb8, 0xd8}

	s.SysDescr = "S3300-52X-PoE+ ProSAFE 48-Port Gigabit Stackable Smart Switch with PoE+ and 4 10G uplinks"

	s.SysObjectID = "1.3.6.1.4.1.4526.100.10.19"

	// Real fixed Q-BRIDGE PortList width, measured LIVE (read-only) on this
	// switch @10.1.5.11: dot1qVlanStaticEgressPorts is 45 bytes wide -- a
	// third distinct width alongside the GSM7252PS's 79 and the M4300s'
	// 131, and still wider than its 52 physical ports need (LAG
	// pseudo-ports).
	s.VLANPortListWidth = model.Ptr(45)

	// MEASURED off the real VLAN-Membership capture (2026-07-30,
	// testdata/http/gsm7228ps_vlanPortCfg_vlan5.html): 78 hiddenMem slots
	// = 52 ports + 26 LAGs, LAG ifNames 0/3/N, the NEWER togImg/switch_*.png
	// grid, HTML-escaped ifName lists, no trailing comma and no CSRFToken.
	s.VlanMembershipPage = &VlanMembershipPageSim{Slots: 78, LagSlot: 3, Grid: "png", Escape: true}

	// MEASURED 2026-08-02 on 10.1.5.11: the vendor admin-mode column reads
	// 2 (disabled) and the host table is EMPTY -- this switch has no
	// collector configured, which is why GetSyslog returns none.
	//
	// DELIBERATELY KEPT even though the live switch has since moved on (a
	// re-read on 2026-08-03 over SNMP, HTTP and the CLI all returned
	// enabled + one collector). The switch's own buffered log dates the
	// change -- an operator reconfiguring a production device between two
	// reads, NOT the reader drifting from the hardware. This row is also
	// the fleet's only "logging configured nowhere" case, so re-seeding it
	// to match the others would delete the coverage that a genuinely empty
	// host table reads as empty. Ported field-for-field from Python's
	// seed_gsm7228ps (seed.py:1849) -- explicit even though it equals
	// SyslogSim's own NewState default, to keep this measurement pinned
	// rather than silently implicit.
	s.Syslog = SyslogSim{AdminMode: 2, LocalPort: 514}

	return s
}

// switchportSeedRow is one measured FASTPATH vendor switchport row: (mode,
// accessVlan, nativeVlan, allowedVlans, generalUntagged, generalTagged),
// mirroring Python seed.py's _SwitchportRow tuple type (seed.py:2162).
// Allowed == nil means "all 4093" (Python's _ALL_ALLOWED == None).
type switchportSeedRow struct {
	mode, access, native int
	allowed              []int
	generalUntagged      []int
	generalTagged        []int
}

// allVlansExcept returns [1..4093] minus the given exclusions, ascending --
// a small helper for the -24X seed table below, where two ports' allowed
// lists are "everything except two specific non-existent VLANs" rather than
// a hand-enumerated set.
func allVlansExcept(exclude ...int) []int {
	excl := portSetFromSlice(exclude)
	out := make([]int, 0, 4093)
	for v := 1; v <= 4093; v++ {
		if !excl[v] {
			out = append(out, v)
		}
	}
	return out
}

// switchportSeedM4300_24X is the FASTPATH vendor switchport configuration
// for the M4300-24X, READ OFF THE REAL SWITCH on 2026-07-30 (read-only walk
// of 1.3.6.1.4.1.4526.10.1.2.8.37.1 with community "public"; 1520 rows),
// mirroring Python seed.py's _M4300_24X_SWITCHPORT dict literal
// (seed.py:2163-2190) field-for-field, row for row, port for port.
//
// This is seeded, not computed, precisely so the mock is an INDEPENDENT
// source of truth: State derives Q-BRIDGE membership FROM these columns
// (see applySwitchport in state_switchport.go), so if that derivation rule
// is wrong the derived membership stops matching the captured membership
// SeedM4300_24X ships alongside (see seed_test.go's
// TestSwitchportSeedReproducesCapturedMembership, porting Python's
// test_seeded_switchport_columns_reproduce_the_captured_membership).
func switchportSeedM4300_24X() map[int]switchportSeedRow {
	rows := map[int]switchportSeedRow{
		// Ports 1/2 are the real uplink trunks; VLANs 3990 and 4007 happen
		// to be absent from their allowed lists on the live device (both
		// are non-existent VLANs, so neither affects membership -- kept
		// because it is what was read).
		1: {2, 1, 1, allVlansExcept(3990, 4007), []int{1}, nil},
		2: {2, 1, 1, allVlansExcept(3990, 4007), []int{1}, nil},
		3: {1, 5, 5, nil, []int{1}, nil},
		4: {1, 5, 5, nil, []int{1}, nil},
		// Port 5 is the most informative row on either switch: a trunk
		// whose ACCESS VLAN (90) differs from its NATIVE VLAN (5) --
		// proving membership follows col4 not col3 in trunk mode -- with a
		// genuinely sparse allowed list.
		5: {2, 90, 5, []int{1, 5, 6, 7, 10, 20, 41, 90, 99, 121, 141}, []int{1, 90}, nil},
		6: {1, 90, 5, nil, []int{1}, nil},
		7: {1, 1, 1, nil, []int{1}, nil},
		8: {1, 1, 1, nil, []int{1}, nil},
	}
	// 9-14: access on VLAN 5 with native 1 -- another proof col4 is ignored
	// in access mode -- and col7 reads 5 here while col7 reads 1 on 15-24,
	// which is why col7 cannot be a mirror of effective membership.
	for p := 9; p <= 14; p++ {
		rows[p] = switchportSeedRow{1, 5, 1, nil, []int{5}, nil}
	}
	for p := 15; p <= 24; p++ {
		rows[p] = switchportSeedRow{1, 10, 10, nil, []int{1}, nil}
	}
	return rows
}

// switchportSeedM4300_16X is the FASTPATH vendor switchport configuration
// for the M4300-16X, READ OFF THE REAL SWITCH on 2026-07-30 (1440 rows),
// mirroring Python seed.py's _M4300_16X_SWITCHPORT dict literal
// (seed.py:2191-2208) field-for-field, port for port.
//
// NOTE ports 11 and 12 read (2, 4, 4, all, {1}, {}) and
// (2, 5, 5, all-minus-5, {1,4}, {5,6,7,10,20,21,41,89,90,99,121,141}) on the
// live device TODAY -- someone re-homed them since the committed capture
// was taken (its membership has both untagged in VLAN 1). Seeded to the
// shape the CAPTURE implies, identical to their sibling trunks 9/10/13-16,
// so the mock stays internally coherent -- device config drift, NOT a
// mock/hardware behavioural difference (Python's own comment; the live
// values for both ports are exercised only by that pin's
// test_live_switchport_columns_derive_the_live_membership, which replays
// them directly against seed_m4300_16x() rather than via this table).
func switchportSeedM4300_16X() map[int]switchportSeedRow {
	rows := map[int]switchportSeedRow{}
	// 1-8 are GENERAL mode: membership comes from col7/col8, so despite an
	// access VLAN of 10/90 these ports are untagged in VLAN 1 -- exactly
	// what the committed capture shows.
	for p := 1; p <= 4; p++ {
		rows[p] = switchportSeedRow{3, 10, 10, nil, []int{1}, nil}
	}
	for p := 5; p <= 8; p++ {
		rows[p] = switchportSeedRow{3, 90, 90, nil, []int{1}, nil}
	}
	for p := 9; p <= 16; p++ {
		rows[p] = switchportSeedRow{2, 1, 1, nil, []int{1}, nil}
	}
	return rows
}

// applySwitchportSeed loads a measured switchport table into s, mirroring
// Python seed._apply_switchport_seed (seed.py:2211-2225).
func applySwitchportSeed(s *State, table map[int]switchportSeedRow) {
	for port, row := range table {
		s.SwitchportMode[port] = row.mode
		s.SwitchportAccessVlan[port] = row.access
		s.SwitchportNativeVlan[port] = row.native
		if row.allowed == nil {
			s.SwitchportAllowedVlans[port] = allVlansBitmap()
		} else {
			s.SwitchportAllowedVlans[port] = vlanBitmapBytes(portSetFromSlice(row.allowed))
		}
		s.SwitchportGeneralUntagged[port] = portSetFromSlice(row.generalUntagged)
		s.SwitchportGeneralTagged[port] = portSetFromSlice(row.generalTagged)
	}
}

// SeedM4300_24X builds a realistic M4300-24X (24-port, non-PoE Fully Managed) State
// transcribed field-for-field from testdata/captures/m4300-24x.json
// (SNMP host 10.1.5.13) via the pinned Python seed_m4300_24x: port
// name/admin/link/speed/description/counters, all 14 real VLANs with
// their full real member/untagged ifIndex sets (including the 128-wide
// LAG range 770-897 every VLAN's trunk carries), every PVID, the box
// sensors, and the base MAC. The real switch exposes 155 ifIndexes (24
// physical + a CPU interface + 128 LAG placeholders + 2 VLAN
// interfaces); only a representative slice of the non-physical ones is
// seeded (the one real in-use LAG plus one unused placeholder, the CPU
// interface, and both VLAN interfaces) rather than all 128
// mostly-identical unused LAGs -- the model's CAPABILITIES (port
// count/names/speeds, VLANs, PVIDs, sensors, mgmt-IP, and CRUCIALLY the
// absence of PoE, Poe stays the zero map) match the capture exactly.
//
// dot1dBaseBridgeAddress is VERIFIED to come back as ASCII colon-hex
// text on this exact model (see snmp.ParseBaseMac's macFromASCIIText),
// so Dot1dBaseMacASCII is true here specifically -- NOT on
// SeedM4300_16X, where no such quirk has been captured. MAC/FDB rows are
// a representative slice of the real (30-capped) captured table,
// identity-mapped bridge-port -> ifIndex (see SeedGSM7252PS for the
// non-identity-mapping case). LLDP neighbours mix MAC-shaped
// (raw-bytes) and plain-text port-id subtypes on purpose.
func SeedM4300_24X() *State {
	ports := map[int]*PortSim{
		1:   {Name: "1/0/1", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(14778916968081)), TxOctets: model.Ptr(uint64(11768639639224)), RxErrors: model.Ptr(uint64(5)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("trunk.sw-cisco-shed")},
		2:   {Name: "1/0/2", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(22592906553)), TxOctets: model.Ptr(uint64(72917119482)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("trunk.gsm7252ps-s1")},
		3:   {Name: "1/0/3", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(2762192715)), TxOctets: model.Ptr(uint64(3069701383)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("bmc.big-storage")},
		4:   {Name: "1/0/4", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("bmc.gpu")},
		5:   {Name: "1/0/5", Admin: true, Link: true, Speed: 100, RxOctets: model.Ptr(uint64(9928397370)), TxOctets: model.Ptr(uint64(103562789705)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("openmesh.wifi")},
		6:   {Name: "1/0/6", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(2936543951)), TxOctets: model.Ptr(uint64(6369912656)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("eth0.rpi4-ups")},
		7:   {Name: "1/0/7", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("empty")},
		8:   {Name: "1/0/8", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("empty")},
		9:   {Name: "1/0/9", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(241280077)), TxOctets: model.Ptr(uint64(1045875073)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("oob1.sw-bb-25g")},
		10:  {Name: "1/0/10", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(79644425)), TxOctets: model.Ptr(uint64(1532447568)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("oob2.sw-bb-25g")},
		11:  {Name: "1/0/11", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("oob1.sw-bb-100g")},
		12:  {Name: "1/0/12", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("oob2.sw-bb-100g")},
		13:  {Name: "1/0/13", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(4321)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("bmc1.nvmeof")},
		14:  {Name: "1/0/14", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(4385)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("bmc2.nvmeof")},
		15:  {Name: "1/0/15", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("empty")},
		16:  {Name: "1/0/16", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("empty")},
		17:  {Name: "1/0/17", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("10g1.gpu")},
		18:  {Name: "1/0/18", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("10g2.gpu")},
		19:  {Name: "1/0/19", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(10574049492450)), TxOctets: model.Ptr(uint64(7436979985884)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("10g1.big-storage")},
		20:  {Name: "1/0/20", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(906023695499)), TxOctets: model.Ptr(uint64(3169248684569)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("10g2.big-storage")},
		21:  {Name: "1/0/21", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(46742037001)), TxOctets: model.Ptr(uint64(214440657859)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("lag.sw-bb-25g")},
		22:  {Name: "1/0/22", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(62196040279)), TxOctets: model.Ptr(uint64(2295667872290)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("lag.sw-bb-25g")},
		23:  {Name: "1/0/23", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(53538213549)), TxOctets: model.Ptr(uint64(4490316365)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("lag.sw-bb-25g")},
		24:  {Name: "1/0/24", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(60910004579)), TxOctets: model.Ptr(uint64(1478343156644)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0)), Description: model.Ptr("lag.sw-bb-25g")},
		769: {Name: "CPU Interface:  0/15/1", Admin: true, Link: true, Speed: 0, IfType: 1},
		770: {Name: "lag 1", Admin: true, Link: true, Speed: 40000, IfType: 161, Description: model.Ptr("lag.sw-bb-25g")},
		771: {Name: "lag 2", Admin: true, Link: false, Speed: 0, IfType: 161},
		898: {Name: "vlan 1", Admin: true, Link: true, Speed: 10, IfType: 135},
		899: {Name: "vlan 5", Admin: true, Link: true, Speed: 10, IfType: 135},
	}

	vlans := map[int]*VlanSim{
		1:   {Name: "default", Member: portSetFromSlice([]int{1, 2, 5, 7, 8, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805, 806, 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817, 818, 819, 820, 821, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 832, 833, 834, 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 858, 859, 860, 861, 862, 863, 864, 865, 866, 867, 868, 869, 870, 871, 872, 873, 874, 875, 876, 877, 878, 879, 880, 881, 882, 883, 884, 885, 886, 887, 888, 889, 890, 891, 892, 893, 894, 895, 896, 897}), Untagged: portSetFromSlice([]int{1, 2, 7, 8, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805, 806, 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817, 818, 819, 820, 821, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 832, 833, 834, 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 858, 859, 860, 861, 862, 863, 864, 865, 866, 867, 868, 869, 870, 871, 872, 873, 874, 875, 876, 877, 878, 879, 880, 881, 882, 883, 884, 885, 886, 887, 888, 889, 890, 891, 892, 893, 894, 895, 896, 897})},
		4:   {Name: "wifi", Member: portSetFromSlice([]int{1, 2, 770}), Untagged: portSetFromSlice([]int{})},
		5:   {Name: "net", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 770}), Untagged: portSetFromSlice([]int{3, 4, 5, 9, 10, 11, 12, 13, 14})},
		6:   {Name: "pwr", Member: portSetFromSlice([]int{1, 2, 5, 770}), Untagged: portSetFromSlice([]int{})},
		7:   {Name: "store", Member: portSetFromSlice([]int{1, 2, 5, 770}), Untagged: portSetFromSlice([]int{})},
		10:  {Name: "int", Member: portSetFromSlice([]int{1, 2, 5, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 770}), Untagged: portSetFromSlice([]int{15, 16, 17, 18, 19, 20, 21, 22, 23, 24})},
		20:  {Name: "roam", Member: portSetFromSlice([]int{1, 2, 5, 770}), Untagged: portSetFromSlice([]int{})},
		21:  {Name: "fpgas", Member: portSetFromSlice([]int{1, 2, 770}), Untagged: portSetFromSlice([]int{})},
		41:  {Name: "sm", Member: portSetFromSlice([]int{1, 2, 5, 770}), Untagged: portSetFromSlice([]int{})},
		89:  {Name: "sdr", Member: portSetFromSlice([]int{1, 2, 770}), Untagged: portSetFromSlice([]int{})},
		90:  {Name: "iot", Member: portSetFromSlice([]int{1, 2, 5, 6, 770}), Untagged: portSetFromSlice([]int{6})},
		99:  {Name: "guest", Member: portSetFromSlice([]int{1, 2, 5, 770}), Untagged: portSetFromSlice([]int{})},
		121: {Name: "t-fpgas", Member: portSetFromSlice([]int{1, 2, 5, 770}), Untagged: portSetFromSlice([]int{})},
		141: {Name: "t-sm", Member: portSetFromSlice([]int{1, 2, 5, 770}), Untagged: portSetFromSlice([]int{})},
	}

	pvids := map[int]int{
		1: 1, 2: 1, 3: 5, 4: 5, 5: 5, 6: 90, 7: 1, 8: 1, 9: 5, 10: 5, 11: 5, 12: 5, 13: 5, 14: 5, 15: 10, 16: 10, 17: 10, 18: 10, 19: 10, 20: 10, 21: 10, 22: 10, 23: 10, 24: 10,
	}

	sensors := []SensorSim{
		{Kind: "fan", Instance: "0", Raw: "5160"},
		{Kind: "fan", Instance: "1", Raw: "4560"},
		{Kind: "power", Instance: "0", Raw: "49"},
		{Kind: "temperature", Instance: "1", Raw: "49"},
	}

	macs := []MacSim{
		{Vlan: 1, MacBytes: [6]byte{0x00, 0x0a, 0xfa, 0x24, 0x28, 0x20}, BridgePort: 1},
		{Vlan: 90, MacBytes: [6]byte{0x00, 0xe0, 0x4c, 0x68, 0x36, 0x95}, BridgePort: 1},
		{Vlan: 1, MacBytes: [6]byte{0x02, 0x00, 0x0a, 0x01, 0x00, 0x01}, BridgePort: 1},
	}

	lldp := []LldpSim{
		{TimeMark: 1, LocalPort: 1, RemIdx: 1, Chassis: string([]byte{0x88, 0xa2, 0x9e, 0x80, 0x87, 0x01}), PortID: string([]byte{0x88, 0xa2, 0x9e, 0x80, 0x87, 0x01}), PortDesc: "eth0", SysName: "rpi-sdr-kraken"},
		{TimeMark: 1, LocalPort: 2, RemIdx: 1, Chassis: string([]byte{0xe0, 0x91, 0xf5, 0x0c, 0xd6, 0xdb}), PortID: "1/0/49", PortDesc: "1/0/2.sw-netgear-m4300-24x", SysName: "sw-netgear-gsm7252ps-s1.welland.mithis.com"},
		{TimeMark: 1, LocalPort: 6, RemIdx: 1, Chassis: string([]byte{0xe4, 0x5f, 0x01, 0x8d, 0xf4, 0xfd}), PortID: string([]byte{0xe4, 0x5f, 0x01, 0x8d, 0xf4, 0xfd}), PortDesc: "eth0", SysName: "rpi4-ups"},
	}

	mgmt := MgmtSim{Address: "10.1.5.13", Netmask: "255.255.255.0", Gateway: "10.1.5.1", Mode: "static"}

	s := NewState("m4300-24x")

	s.Ports = withDefaultIfType(ports)

	s.Vlans = vlans

	s.Pvids = pvids

	s.Sensors = sensors

	s.Macs = macs

	s.Lldp = lldp

	s.Mgmt = mgmt

	// MEASURED 2026-08-03 on 10.1.5.13's own userManagement.html -- the
	// SAME two words the gsm7252ps page uses, even though this switch's
	// `show users` says "Privilege-15" where that one says "Read/Write"
	// (see CLIAccessMode below). The web UI is the consistent face; the
	// CLI is not. Ported field-for-field from Python's seed_m4300_24x
	// (seed.py:2466).
	//
	// CLIAccessMode is PRINCIPLE-5 territory -- see SeedGSM7252PS's
	// matching comment and UserSim's own doc comment for why (Python has
	// no CLI `show users` renderer to port from at pin b26eb1f). Values
	// transcribed from Python commit 4619e3c's live-verified table.
	//
	// admin's SNMPv3Access/SNMPv3Auth/SNMPv3Encryption ("Read
	// Only"/"MD5"/"None") are the ONE measured SNMPv3 row anywhere in the
	// pinned Python source -- parse_users' own docstring transcript
	// (protocols/cli/parse.py:779-782, pin b26eb1f) IS this switch's
	// admin row (its access_mode "Privilege-15" only matches m4300-24x,
	// never gsm7252ps's "Read/Write"). guest's SNMPv3 columns stay ""
	// (unmeasured) rather than guessed.
	s.Users = []UserSim{
		{
			Name: "admin", HTTPAccessMode: "Super User", CLIAccessMode: "Privilege-15",
			SNMPv3Access: "Read Only", SNMPv3Auth: "MD5", SNMPv3Encryption: "None",
		},
		{Name: "guest", HTTPAccessMode: "Read Only", CLIAccessMode: "Privilege-1"},
	}

	// MEASURED 2026-08-03 on 10.1.5.13, HTTP pages and CLI agreeing on
	// every state and every port the pages print. Unlike the gsm7252ps
	// this switch's http/https/ssh pages DO print their ports; its telnet
	// page still does not (the CLI reports 23, the page has no such
	// field), so telnet's HTTP Port stays nil here -- the mock must not
	// print what the device does not. Ported field-for-field from
	// Python's seed_m4300_24x (seed.py:2473).
	//
	// CLIPort is PRINCIPLE-5 territory -- see SeedGSM7252PS's matching
	// comment. Values transcribed from Python commit 2c7ddff's
	// live-verified table, "m4300-24x  http=on:80  https=on:443
	// telnet=on:23  ssh=on:22".
	s.Services = map[string]ServiceSim{
		"http":   {Enabled: true, Port: model.Ptr(80), CLIPort: model.Ptr(80)},
		"https":  {Enabled: true, Port: model.Ptr(443), CLIPort: model.Ptr(443)},
		"ssh":    {Enabled: true, Port: model.Ptr(22), CLIPort: model.Ptr(22)},
		"telnet": {Enabled: true, CLIPort: model.Ptr(23)},
	}

	s.NsdpMac = [6]byte{0x8c, 0x3b, 0xad, 0x6b, 0xbb, 0xe0}

	s.Dot1dBaseMacASCII = true

	// MEASURED via sysName/show hosts on the real 10.1.5.13, 2026-08-02 --
	// see snmp.SysName's own doc comment for why this is NOT the same value
	// as `show running-config`'s "manage-sw-netgear-..." prefix. Ported
	// field-for-field from Python's seed_m4300_24x (seed.py:2479).
	s.Hostname = "sw-netgear-m4300-24x"

	s.SysDescr = "NETGEAR M4300-24X (XSM4324CS) Managed Switch"

	// REAL MEASURED value: live SNMP GET of sysObjectID against the actual
	// m4300-24x @10.1.5.13 (firmware 12.0.13.8), captured 2026-08-20. This
	// replaces a previous unverified placeholder
	// ("1.3.6.1.4.1.4526.10.100.24", still carried unfixed by the Python
	// pin's seed_m4300_24x -- see seed.py:2518-2521's own "sysObjectID has
	// no known real value ... this is a placeholder" comment) now that a
	// live capture exists. Not added to snmp.SysObjectIDModels: that map is
	// reserved for OIDs actually proven to identify a model (see its own
	// doc comment); this switch's sysDescr already contains "M4300-24X"
	// and detects fine via DetectModelFromSysDescr.
	s.SysObjectID = "1.3.6.1.4.1.4526.100.1.34"

	// Real fixed Q-BRIDGE PortList width, measured LIVE (read-only) on the
	// M4300 @10.1.5.13: dot1qVlanStaticEgressPorts is 131 bytes wide.
	s.VLANPortListWidth = model.Ptr(131)

	// MEASURED off the real VLAN-Membership capture (2026-07-30,
	// testdata/http/m4300_vlanportcfg_vlan1.html): 152 hiddenMem slots = 24
	// ports + 128 LAGs, LAG ifNames 0/13/N, the togImg/switch_*.png grid,
	// HTML-escaped ifName lists, and this firmware's TRAILING comma on
	// hiddenMem/hiddenTagged. No CSRFToken on the 24X (the 16X has one).
	s.VlanMembershipPage = &VlanMembershipPageSim{Slots: 152, LagSlot: 13, Grid: "png", TrailingComma: true, Escape: true}

	// LIVE-PROVEN 2026-07-30 on 10.1.5.13: EVERY port on this switch is
	// "switchport mode access" or "trunk" (per its own show running-config),
	// and the M4300 image only accepts an explicit VLAN-membership apply on
	// a port in "general" mode. Applying anyway returns HTTP 200 with
	// err_flag=1 and err_msg="Unable to set VLAN membership for VLAN
	// ( 4004 )". The sibling M4300-16X (10.1.5.20) leaves ports 1-8 with no
	// switchport-mode line at all and the SAME apply succeeds there -- so
	// this is per-port configuration, not a per-model capability, and the
	// mock models it per-port too.
	s.VlanMembershipLockedPorts = portSetFromSlice([]int{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	})

	// MEASURED 2026-08-02 on 10.1.5.13: `show logging` reports "Syslog
	// Logging : enabled" and local port 514, and `show logging hosts` one
	// row 10.1.5.1 / info(6) / 514 / Active. Ported field-for-field from
	// Python's seed_m4300_24x (seed.py:2457).
	s.Syslog = SyslogSim{
		AdminMode:  1,
		LocalPort:  514,
		Collectors: []SyslogCollectorSim{{Host: "10.1.5.1", Port: 514, Severity: 6, Status: 1, Index: 1}},
	}

	// The real vendor switchport configuration behind the captured
	// membership above (READ OFF THE REAL SWITCH on 2026-07-30). Ported
	// field-for-field from Python's seed_m4300_24x's own trailing
	// `_apply_switchport_seed(state, _M4300_24X_SWITCHPORT)` call
	// (seed.py:2526) -- see switchportSeedM4300_24X's own doc comment.
	applySwitchportSeed(s, switchportSeedM4300_24X())

	return s
}

// SeedM4300_16X builds a realistic M4300-16X (16-port, all-16 PoE Fully Managed)
// State transcribed field-for-field from testdata/captures/m4300-16x.
// json via the pinned Python seed_m4300_16x: port name/admin/link/speed
// and counters, the same 14 VLANs as the 24X, every PVID, all 16 PoE
// ports (2 verified-live delivering: 11 at 5000mW, 12 at 2100mW), the
// box sensors, and the real base MAC.
//
// The real capture's mgmt_ip.address is None (no static IP was ever
// discovered over this OID chain on that device) -- honestly left
// unseeded (NewState's default blank 0.0.0.0/dhcp Mgmt) rather than
// inventing one; assertSeedMatchesCapture's mgmt check skips the
// address/netmask/gateway comparison in exactly this case (see its own
// doc comment), so get_mgmt_ip().BaseMac is still checked and still
// real. Dot1dBaseMacASCII is NOT set here: only the M4300-24X's
// ASCII-text quirk has been captured/verified -- this model uses the
// standard raw-6-bytes encoding.
func SeedM4300_16X() *State {
	ports := map[int]*PortSim{
		1:   {Name: "1/0/1", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		2:   {Name: "1/0/2", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		3:   {Name: "1/0/3", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		4:   {Name: "1/0/4", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		5:   {Name: "1/0/5", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		6:   {Name: "1/0/6", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		7:   {Name: "1/0/7", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		8:   {Name: "1/0/8", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		9:   {Name: "1/0/9", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		10:  {Name: "1/0/10", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		11:  {Name: "1/0/11", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(7813924)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		12:  {Name: "1/0/12", Admin: true, Link: true, Speed: 1000, RxOctets: model.Ptr(uint64(30388)), TxOctets: model.Ptr(uint64(7819868)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		13:  {Name: "1/0/13", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		14:  {Name: "1/0/14", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		15:  {Name: "1/0/15", Admin: true, Link: false, Speed: 0, RxOctets: model.Ptr(uint64(0)), TxOctets: model.Ptr(uint64(0)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		16:  {Name: "1/0/16", Admin: true, Link: true, Speed: 10000, RxOctets: model.Ptr(uint64(3347925876)), TxOctets: model.Ptr(uint64(7868391)), RxErrors: model.Ptr(uint64(0)), TxErrors: model.Ptr(uint64(0))},
		769: {Name: "CPU Interface:  0/15/1", Admin: true, Link: true, Speed: 0, IfType: 1},
		770: {Name: "lag 1", Admin: true, Link: false, Speed: 0, IfType: 161},
		898: {Name: "vlan 5", Admin: true, Link: true, Speed: 10, IfType: 135},
	}

	vlans := map[int]*VlanSim{
		1:   {Name: "default", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805, 806, 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817, 818, 819, 820, 821, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 832, 833, 834, 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 858, 859, 860, 861, 862, 863, 864, 865, 866, 867, 868, 869, 870, 871, 872, 873, 874, 875, 876, 877, 878, 879, 880, 881, 882, 883, 884, 885, 886, 887, 888, 889, 890, 891, 892, 893, 894, 895, 896, 897}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805, 806, 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817, 818, 819, 820, 821, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 832, 833, 834, 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 858, 859, 860, 861, 862, 863, 864, 865, 866, 867, 868, 869, 870, 871, 872, 873, 874, 875, 876, 877, 878, 879, 880, 881, 882, 883, 884, 885, 886, 887, 888, 889, 890, 891, 892, 893, 894, 895, 896, 897})},
		4:   {Name: "wifi", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		5:   {Name: "net", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		6:   {Name: "pwr", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		7:   {Name: "store", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		10:  {Name: "int", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		20:  {Name: "roam", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		21:  {Name: "fpgas", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		41:  {Name: "sm", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		89:  {Name: "sdr", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		90:  {Name: "iot", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		99:  {Name: "guest", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		121: {Name: "t-fpgas", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
		141: {Name: "t-sm", Member: portSetFromSlice([]int{9, 10, 11, 12, 13, 14, 15, 16}), Untagged: portSetFromSlice([]int{})},
	}

	pvids := map[int]int{
		1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1, 12: 1, 13: 1, 14: 1, 15: 1, 16: 1,
	}

	poe := map[int]*PoeSim{
		1:  {Admin: true, Detect: 2, PowerMw: 0},
		2:  {Admin: true, Detect: 2, PowerMw: 0},
		3:  {Admin: true, Detect: 2, PowerMw: 0},
		4:  {Admin: true, Detect: 2, PowerMw: 0},
		5:  {Admin: true, Detect: 2, PowerMw: 0},
		6:  {Admin: true, Detect: 2, PowerMw: 0},
		7:  {Admin: true, Detect: 2, PowerMw: 0},
		8:  {Admin: true, Detect: 2, PowerMw: 0},
		9:  {Admin: true, Detect: 2, PowerMw: 0},
		10: {Admin: true, Detect: 2, PowerMw: 0},
		11: {Admin: true, Detect: 3, PowerMw: 5000},
		12: {Admin: true, Detect: 3, PowerMw: 2100},
		13: {Admin: true, Detect: 2, PowerMw: 0},
		14: {Admin: true, Detect: 2, PowerMw: 0},
		15: {Admin: true, Detect: 2, PowerMw: 0},
		16: {Admin: true, Detect: 2, PowerMw: 0},
	}

	sensors := []SensorSim{
		{Kind: "fan", Instance: "0", Raw: "4200"},
		{Kind: "fan", Instance: "1", Raw: "4080"},
		{Kind: "power", Instance: "0", Raw: "40"},
		{Kind: "power", Instance: "1", Raw: "42"},
		{Kind: "temperature", Instance: "1", Raw: "42"},
	}

	macs := []MacSim{
		{Vlan: 1, MacBytes: [6]byte{0x80, 0xcc, 0x9c, 0x91, 0x4f, 0x8c}, BridgePort: 12},
		{Vlan: 90, MacBytes: [6]byte{0x00, 0x08, 0xa2, 0x09, 0xef, 0xed}, BridgePort: 16},
		{Vlan: 1, MacBytes: [6]byte{0x00, 0x0a, 0xfa, 0x24, 0x28, 0x1f}, BridgePort: 16},
	}

	lldp := []LldpSim{
		{TimeMark: 1, LocalPort: 12, RemIdx: 1, Chassis: string([]byte{0x80, 0xcc, 0x9c, 0x91, 0x4f, 0x8c}), PortID: "5", PortDesc: "Device Port 5", SysName: "sw-poe-micro2"},
		{TimeMark: 1, LocalPort: 16, RemIdx: 1, Chassis: string([]byte{0x00, 0x0a, 0xfa, 0x24, 0x28, 0x25}), PortID: string([]byte{0x00, 0x0a, 0xfa, 0x24, 0x28, 0x1f}), PortDesc: "eth8", SysName: "ten64.welland.mithis.com"},
	}

	mgmt := MgmtSim{Address: "0.0.0.0", Netmask: "0.0.0.0", Gateway: "0.0.0.0", Mode: "dhcp"}

	s := NewState("m4300-16x")

	s.Ports = withDefaultIfType(ports)

	s.Vlans = vlans

	s.Pvids = pvids

	s.Poe = poe

	s.Sensors = sensors

	s.Macs = macs

	s.Lldp = lldp

	s.Mgmt = mgmt

	s.NsdpMac = [6]byte{0x8c, 0x3b, 0xad, 0x69, 0x1c, 0x38}

	// MEASURED via sysName/show hosts on the real 10.1.5.20, 2026-08-02 --
	// see snmp.SysName's own doc comment: `show running-config` on this SKU
	// carries the DIFFERENT value "manage-sw-netgear-m4300-16x-poe-s2",
	// which is deliberately NOT what this library reads. Ported
	// field-for-field from Python's seed_m4300_16x (seed.py:2679).
	s.Hostname = "sw-netgear-m4300-16x-poe-s2"

	s.SysDescr = "NETGEAR M4300-16X (XSM4316) Managed Switch"

	s.SysObjectID = "1.3.6.1.4.1.4526.10.100.16"

	// Real fixed Q-BRIDGE PortList width, measured LIVE (read-only) on this
	// switch @10.1.5.20: dot1qVlanStaticEgressPorts is 131 bytes wide.
	s.VLANPortListWidth = model.Ptr(131)

	// MEASURED off the real VLAN-Membership capture (2026-07-30,
	// testdata/http/m4300_16x_vlanportcfg_vlan4.html): 144 hiddenMem slots
	// = 16 ports + 128 LAGs, LAG ifNames 0/13/N, togImg/switch_*.png grid,
	// escaped ifName lists, trailing comma -- AND the per-page CSRFToken
	// only this AV-era firmware carries (CSRF=true), which the form
	// builder must echo back.
	s.VlanMembershipPage = &VlanMembershipPageSim{
		Slots: 144, LagSlot: 13, Grid: "png", TrailingComma: true, CSRF: true, Escape: true,
	}
	// VlanMembershipLockedPorts stays empty (this SKU's ports 1-8 carry no
	// switchport-mode line -- see SeedM4300_24X's doc comment for the
	// live-proven per-port counter-example this pairs with).

	// s.Syslog stays at NewState's default (AdminMode 2/disabled, LocalPort
	// 514, no collectors): unlike SeedGSM7252PS/SeedM4300_24X/SeedGSM7228PS,
	// Python's seed_m4300_16x never sets syslog= at all -- this SKU's
	// remote-logging state was never separately measured, so this mock
	// honestly carries the dataclass default rather than inventing one.

	// The real vendor switchport configuration behind the captured
	// membership above (READ OFF THE REAL SWITCH on 2026-07-30). Ported
	// field-for-field from Python's seed_m4300_16x's own trailing
	// `_apply_switchport_seed(state, _M4300_16X_SWITCHPORT)` call
	// (seed.py:2712) -- see switchportSeedM4300_16X's own doc comment.
	applySwitchportSeed(s, switchportSeedM4300_16X())

	return s
}

// SeedGS728TPP builds a GS728TPP (28-port Smart Managed Pro, SNMP+HTTP) State
// transcribed field-for-field from the pinned Python seed_gs728tpp,
// whose own docstring cites REAL captures of the live switch 10.2.5.10
// (2026-07-29 SNMP walk, 2026-07-29 HTTP capture) -- but see this
// file's package doc comment: unlike the other four seeds, no
// testdata/captures/gs728tpp.json was ever committed to the Python
// repo at this pin, so this seed is grounded ONLY via the values
// already transcribed into seed.py itself (which this function copies
// verbatim) and via direct structural pins in seed_test.go
// (TestSeedGS728TPP*), not the assertSeedMatchesCapture harness.
//
// This model's SNMP agent implements ZERO Netgear vendor OIDs
// (model.SwitchModel.SNMPVendorBase == ""): Sensors stays empty (the
// SNMP face has no vendor box-sensor column to report), and the fan/PSU
// INVENTORY is instead exposed via the standard ENTITY-MIB
// EntityComponents (two PSUs, two fans -- entPhysicalIndex/Class/Name/
// Descr rows from the capture, inventory only, no live value). The HTTP
// sysInfo sensors (with live health status) live in HTTPSensors
// instead. Ports g1-g28 (7 up), the real 12 VLANs, real PVIDs, 24 PoE+
// ports (all Searching/0mW on this idle unit -- PowerMw stays nil over
// SNMP since this model has no vendor mW column either), a subset of
// the real dynamic FDB, 4 LLDP neighbours, and the static mgmt-IP.
// SysObjectID ("1.3.6.1.4.1.4526.100.4.27") is the REAL captured value:
// a bare identifier under 4526.100, NOT a vendor OID subtree this agent
// serves -- a walk of 1.3.6.1.4.1.4526 answers noSuchObject on this
// switch.
func SeedGS728TPP() *State {
	// ServesEtherlike: true on every physical port below -- this agent DOES
	// serve the EtherLike duplex/pause columns (unlike the GSM7252PS), and
	// every port reads flow control OFF (FlowControl zero value), MEASURED
	// 2026-08-03 across all 28 ports on both the SNMP and HTTP backends at
	// once. AutonegAdmin "2" on 25-28: the same capture's HTTP wcd page
	// (tests/fixtures/http/gs728tpp_ports.xml) shows the 24 copper ports
	// auto-negotiating (autoNegotiationAdminEnabled 1, PhysicalMode "Auto")
	// while the four SFP uplinks 25-28 are FORCED to 1000 full
	// (autoNegotiationAdminEnabled 2, SpeedAdmin/DuplexAdminMode at their
	// "1000"/"3" defaults) -- every port reports speedAdmin 1000 and
	// duplexAdminMode 3 regardless, so AutonegAdmin is the only thing
	// telling the two apart, exactly like the real capture.
	ports := map[int]*PortSim{
		1:  {Name: "g1", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		2:  {Name: "g2", Admin: true, Link: true, Speed: 1000, ServesEtherlike: true},
		3:  {Name: "g3", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		4:  {Name: "g4", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		5:  {Name: "g5", Admin: true, Link: true, Speed: 100, ServesEtherlike: true},
		6:  {Name: "g6", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		7:  {Name: "g7", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		8:  {Name: "g8", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		9:  {Name: "g9", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		10: {Name: "g10", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		11: {Name: "g11", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		12: {Name: "g12", Admin: true, Link: true, Speed: 100, ServesEtherlike: true},
		13: {Name: "g13", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		14: {Name: "g14", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		15: {Name: "g15", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		16: {Name: "g16", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		17: {Name: "g17", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		18: {Name: "g18", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		19: {Name: "g19", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		20: {Name: "g20", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		21: {Name: "g21", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		22: {Name: "g22", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true},
		23: {Name: "g23", Admin: true, Link: true, Speed: 100, ServesEtherlike: true},
		24: {Name: "g24", Admin: true, Link: true, Speed: 1000, ServesEtherlike: true},
		25: {Name: "g25", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true, AutonegAdmin: "2"},
		26: {Name: "g26", Admin: true, Link: true, Speed: 1000, ServesEtherlike: true, AutonegAdmin: "2"},
		27: {Name: "g27", Admin: true, Link: false, Speed: 1000, ServesEtherlike: true, AutonegAdmin: "2"},
		28: {Name: "g28", Admin: true, Link: true, Speed: 1000, ServesEtherlike: true, AutonegAdmin: "2"},
	}
	// The eight LAG pseudo-interfaces, MEASURED 2026-08-02 on the live switch:
	// ifName "po 1".."po 8" at ifIndex 1000-1007, ifType 161 (ieee8023adLag).
	// dot1dBasePortIfIndex is identity-mapped there, so those same numbers are
	// the Q-BRIDGE PortList bit positions. Seeded because they are what the
	// bitmaps actually contain: without them the mock cannot reproduce the
	// phantom "member port 1000" SNMP GetVLANs used to report (snmp.ParseVlans).
	for idx := 1000; idx <= 1007; idx++ {
		ports[idx] = &PortSim{Name: fmt.Sprintf("po %d", idx-999), Admin: true, Link: false, Speed: 0, IfType: 161}
	}

	// VLAN 1 is untagged on the access ports; every other VLAN is carried
	// tagged on the trunk set, except the untagged sets captured below.
	//
	// LAG membership is MEASURED (2026-08-02): VLAN 1's current-table bitmap
	// sets all eight LAG bits, while every configured VLAN's static bitmap
	// sets bit 1000 alone. VLAN 1 also has NO dot1qVlanStaticTable row on
	// this switch -- NoStaticRow=true -- which is precisely the VLAN a
	// static-table-only reader lost.
	vlans := map[int]*VlanSim{
		1: {Name: "", Member: portSetFromSlice([]int{2, 4, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 25, 27, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007}), Untagged: portSetFromSlice([]int{2, 4, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 25, 27, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007}), NoStaticRow: true},
		2: {Name: "Voice VLAN", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 1000}), Untagged: portSetFromSlice([]int{})},
		// Bit 1000 alone: the live static bitmap for VLAN 3 is all-zero
		// except that LAG bit, i.e. a VLAN whose ONLY member is a LAG.
		3:  {Name: "Auto Video VLAN", Member: portSetFromSlice([]int{1000}), Untagged: portSetFromSlice([]int{})},
		5:  {Name: "net", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 1000}), Untagged: portSetFromSlice([]int{3, 5, 12, 23})},
		6:  {Name: "pwr", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 1000}), Untagged: portSetFromSlice([]int{})},
		7:  {Name: "store", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 1000}), Untagged: portSetFromSlice([]int{})},
		10: {Name: "int", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 1000}), Untagged: portSetFromSlice([]int{1})},
		20: {Name: "roam", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 1000}), Untagged: portSetFromSlice([]int{})},
		31: {Name: "fpgas", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 1000}), Untagged: portSetFromSlice([]int{})},
		41: {Name: "sm", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 1000}), Untagged: portSetFromSlice([]int{})},
		90: {Name: "iot", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 1000}), Untagged: portSetFromSlice([]int{})},
		99: {Name: "guest", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 1000}), Untagged: portSetFromSlice([]int{})},
	}

	pvids := map[int]int{
		1: 10, 2: 1, 3: 5, 4: 1, 5: 5, 6: 1, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1, 12: 5, 13: 1, 14: 1, 15: 1, 16: 1, 17: 1, 18: 1, 19: 1, 20: 1, 21: 1, 22: 1, 23: 5, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1,
	}
	// The real dot1qPvid walk returns 36 rows, not 28: the eight LAGs carry a
	// PVID too (all 1, measured 2026-08-02). snmp.ParsePvids already filters
	// them out by ifType; seeding them keeps that filter honest work rather
	// than a no-op against a mock that never presents the case.
	for idx := 1000; idx <= 1007; idx++ {
		pvids[idx] = 1
	}

	poe := map[int]*PoeSim{
		1:  {Admin: true, Detect: 2, PowerMw: 0},
		2:  {Admin: true, Detect: 2, PowerMw: 0},
		3:  {Admin: true, Detect: 2, PowerMw: 0},
		4:  {Admin: true, Detect: 2, PowerMw: 0},
		5:  {Admin: true, Detect: 2, PowerMw: 0},
		6:  {Admin: true, Detect: 2, PowerMw: 0},
		7:  {Admin: true, Detect: 2, PowerMw: 0},
		8:  {Admin: true, Detect: 2, PowerMw: 0},
		9:  {Admin: true, Detect: 2, PowerMw: 0},
		10: {Admin: true, Detect: 2, PowerMw: 0},
		11: {Admin: true, Detect: 2, PowerMw: 0},
		12: {Admin: true, Detect: 2, PowerMw: 0},
		13: {Admin: true, Detect: 2, PowerMw: 0},
		14: {Admin: true, Detect: 2, PowerMw: 0},
		15: {Admin: true, Detect: 2, PowerMw: 0},
		16: {Admin: true, Detect: 2, PowerMw: 0},
		17: {Admin: true, Detect: 2, PowerMw: 0},
		18: {Admin: true, Detect: 2, PowerMw: 0},
		19: {Admin: true, Detect: 2, PowerMw: 0},
		20: {Admin: true, Detect: 2, PowerMw: 0},
		21: {Admin: true, Detect: 2, PowerMw: 0},
		22: {Admin: true, Detect: 2, PowerMw: 0},
		23: {Admin: true, Detect: 2, PowerMw: 0},
		24: {Admin: true, Detect: 2, PowerMw: 0},
	}

	httpSensors := []SensorSim{
		{Kind: "power", Instance: "mainPSStatus", Raw: "1"},
		{Kind: "power", Instance: "redundantPSStatus", Raw: "1"},
		{Kind: "fan", Instance: "fan1Status", Raw: "1"},
		{Kind: "fan", Instance: "fan2Status", Raw: "1"},
		{Kind: "fan", Instance: "fan3Status", Raw: "5"},
		{Kind: "fan", Instance: "fan4Status", Raw: "5"},
		{Kind: "fan", Instance: "fan5Status", Raw: "5"},
		{Kind: "temperature", Instance: "tempSensorValue", Raw: "0"},
		{Kind: "temperature", Instance: "tempSensorStatus", Raw: "2"},
	}

	entityComponents := []EntitySim{
		{Index: 67109185, PhysClass: 6, Name: "Main PowerSupply", Descr: "PowerSupply"},
		{Index: 67109186, PhysClass: 6, Name: "Redundant PowerSupply", Descr: "PowerSupply"},
		{Index: 67109249, PhysClass: 7, Name: "Fan1", Descr: "Fan"},
		{Index: 67109250, PhysClass: 7, Name: "Fan2", Descr: "Fan"},
	}

	macs := []MacSim{
		{Vlan: 1, MacBytes: [6]byte{0x00, 0x0a, 0xfa, 0x24, 0x28, 0xd8}, BridgePort: 24},
		{Vlan: 1, MacBytes: [6]byte{0x02, 0x00, 0x0a, 0x02, 0x00, 0x01}, BridgePort: 24},
		{Vlan: 1, MacBytes: [6]byte{0x02, 0x00, 0x0a, 0x02, 0x01, 0x01}, BridgePort: 24},
		{Vlan: 1, MacBytes: [6]byte{0x2c, 0xcf, 0x67, 0xbb, 0x49, 0xa1}, BridgePort: 2},
		{Vlan: 5, MacBytes: [6]byte{0x02, 0x00, 0x0a, 0x02, 0x00, 0x01}, BridgePort: 24},
		{Vlan: 5, MacBytes: [6]byte{0x02, 0x00, 0x0a, 0x02, 0x05, 0x01}, BridgePort: 24},
		{Vlan: 5, MacBytes: [6]byte{0xac, 0x86, 0x74, 0x07, 0x94, 0x98}, BridgePort: 12},
		{Vlan: 5, MacBytes: [6]byte{0xac, 0x86, 0x74, 0x07, 0x94, 0x9f}, BridgePort: 12},
		{Vlan: 5, MacBytes: [6]byte{0xac, 0x86, 0x74, 0x07, 0x95, 0x80}, BridgePort: 23},
		{Vlan: 5, MacBytes: [6]byte{0xac, 0x86, 0x74, 0x07, 0x95, 0x87}, BridgePort: 23},
		{Vlan: 5, MacBytes: [6]byte{0xac, 0x86, 0x74, 0x07, 0x95, 0x88}, BridgePort: 5},
		{Vlan: 5, MacBytes: [6]byte{0xac, 0x86, 0x74, 0x07, 0x95, 0x8f}, BridgePort: 5},
	}

	lldp := []LldpSim{
		{TimeMark: 0, LocalPort: 2, RemIdx: 1, Chassis: string([]byte{0x2c, 0xcf, 0x67, 0xbb, 0x49, 0xa1}), PortID: string([]byte{0x2c, 0xcf, 0x67, 0xbb, 0x49, 0xa1}), PortDesc: "eth0", SysName: "reterm1"},
		{TimeMark: 0, LocalPort: 24, RemIdx: 2, Chassis: string([]byte{0x00, 0x0a, 0xfa, 0x24, 0x28, 0xd1}), PortID: string([]byte{0x00, 0x0a, 0xfa, 0x24, 0x28, 0xd8}), PortDesc: "eth7", SysName: "ten64.monarto.mithis.com"},
		{TimeMark: 0, LocalPort: 26, RemIdx: 3, Chassis: string([]byte{0x00, 0x0a, 0xfa, 0x24, 0x28, 0xd1}), PortID: string([]byte{0x00, 0x0a, 0xfa, 0x24, 0x28, 0xd9}), PortDesc: "eth8", SysName: "ten64.monarto.mithis.com"},
		{TimeMark: 0, LocalPort: 28, RemIdx: 4, Chassis: string([]byte{0x00, 0x0a, 0xfa, 0x24, 0x28, 0xd1}), PortID: string([]byte{0x00, 0x0a, 0xfa, 0x24, 0x28, 0xda}), PortDesc: "eth9", SysName: "ten64.monarto.mithis.com"},
	}

	mgmt := MgmtSim{Address: "10.2.5.10", Netmask: "255.255.255.0", Gateway: "10.2.5.1", Mode: "static"}

	s := NewState("gs728tpp")

	s.Ports = withDefaultIfType(ports)

	s.Vlans = vlans

	s.Pvids = pvids

	s.Poe = poe

	s.HTTPSensors = httpSensors

	s.EntityComponents = entityComponents

	s.Macs = macs

	s.Lldp = lldp

	s.Mgmt = mgmt

	s.ModelName = "GS728TPP"

	s.Serial = "3AR476520016D"

	s.Firmware = "6.0.1.30"

	s.Hostname = "sw-netgear-gs728tpp"

	s.NsdpMac = [6]byte{0xb0, 0x39, 0x56, 0x77, 0x54, 0x29}

	s.SysDescr = "Netgear GS728TPP ProSafe Smart Managed Pro Switch"

	s.SysObjectID = "1.3.6.1.4.1.4526.100.4.27"

	// The device's REAL PortList width, measured off the wire 2026-08-02:
	// every dot1qVlanStatic/Current bitmap is 126 bytes (1008 bits), which
	// is what makes room for the LAG bits at 1000-1007. Seeded, never
	// derived -- a mock that recomputed it with the writer's own formula
	// could only ever agree with the writer (D-REC Topic B / principle 5).
	s.VLANPortListWidth = model.Ptr(126)

	return s
}

// SeedGS110EMX builds a GS110EMX (10-port Plus, NSDP+HTTP) State
// transcribed field-for-field from the pinned Python seed_gs110emx (D-NSDP
// §7.3), whose own docstring cites REAL captures of this exact model's own
// web UI (host 10.1.5.25: tests/fixtures/http/gs110emx_{sysinfo,
// port_settings,interface_stats,vlanmembership,pvid}.html at the Python
// pin): ports 6/8/9/10 up at 100M/1G/10G/10G with port 8 described
// "rumpus", the rest down; static 10.1.5.25/24 via 10.1.5.1; MAC
// bc:a5:11:b8:ec:f1. VLAN 1's membership (ports 1-8 untagged, 9-10 tagged)
// and every port's PVID (all 1) are likewise transcribed from that capture.
//
// STILL ILLUSTRATIVE (no capture exists, and this doc comment says so
// rather than implying otherwise): VLAN 90's member/untagged sets -- only
// VLAN 1's membership page was ever captured, and VLAN 90 is merely one of
// the 12 VLAN IDs the real Cf8021q capture lists -- and the
// QoS/mirroring/IGMP/broadcast/loop-detection tag values below, which are
// test fixtures chosen so a caller decoding this seed's NSDP tags has
// something non-vacuous on every one of them, NOT observed hardware
// values. No PoE (registry: PoEPortCount 0), no box sensors/MAC-FDB/LLDP
// (the Plus family exposes none of these over any face).
func SeedGS110EMX() *State {
	realSpeed := map[int]int{6: 100, 8: 1000, 9: 10000, 10: 10000}
	realOctets := map[int][2]uint64{
		6:  {0, 70_892_018_242},
		8:  {59_921_732_691, 78_637_274_870},
		9:  {2_963_140_428_936, 1_189_358_575_871},
		10: {1_195_417_274_187, 3_027_396_511_187},
	}
	ports := map[int]*PortSim{}
	for port := 1; port <= 10; port++ {
		sim := &PortSim{
			Name:  fmt.Sprintf("g%d", port),
			Admin: true,
			Link:  realSpeed[port] != 0,
			Speed: realSpeed[port],
			// Pin's PortSim.flow_control dataclass DEFAULT is True (pin
			// state.py:170), and seed_gs110emx (pin seed.py:1864-1962) never
			// overrides it -- so every port on the pin's seed is True,
			// matching the factory default 10.1.5.25/.26 (the unit this seed
			// transcribes) are still on. Go has no per-field struct-literal
			// default, so this is set explicitly per PortSim.FlowControl's
			// own doc comment.
			FlowControl: true,
		}
		if port == 8 {
			sim.Description = model.Ptr("rumpus")
		}
		octets := realOctets[port] // {0,0} zero value for every port not in real_octets
		sim.RxOctets = model.Ptr(octets[0])
		sim.TxOctets = model.Ptr(octets[1])
		sim.RxErrors = model.Ptr(uint64(0))
		ports[port] = sim
	}

	vlans := map[int]*VlanSim{
		1:  {Name: "", Member: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), Untagged: portSetFromSlice([]int{1, 2, 3, 4, 5, 6, 7, 8})},
		90: {Name: "", Member: portSetFromSlice([]int{1, 2, 10}), Untagged: portSetFromSlice([]int{1, 2})},
	}
	pvids := map[int]int{}
	for port := 1; port <= 10; port++ {
		pvids[port] = 1
	}

	mgmt := MgmtSim{Address: "10.1.5.25", Netmask: "255.255.255.0", Gateway: "10.1.5.1", Mode: "static"}

	s := NewState("gs110emx")

	s.Ports = withDefaultIfType(ports)

	s.Vlans = vlans

	s.Pvids = pvids

	s.Mgmt = mgmt

	s.ModelName = "GS110EMX"

	s.Serial = "53H60253A0032"

	s.Firmware = "1.0.1.4"

	s.Hostname = "sw-netgear-gs110emx1"

	s.NsdpMac = [6]byte{0xbc, 0xa5, 0x11, 0xb8, 0xec, 0xf1}
	// GS110EMX fw 1.0.2.8 requires NSDP v2 salted write auth (LIVE-MEASURED,
	// auth.py:11/36): AUTH_V2_ENCPASS reads 0x10, writes need the token-first
	// AUTH_V2_PASSWORD. The older Plus SKUs (gs305ep/gs105pe) stay v1.
	s.NsdpAuthV2 = true

	s.NsdpQosEngine = model.Ptr(1) // port-based

	s.NsdpPortMirroringDest = model.Ptr(10)

	s.NsdpPortMirroringSources = portSetFromSlice([]int{1, 2})

	s.NsdpIgmpSnoopingEnabled = model.Ptr(true)

	s.NsdpIgmpSnoopingVlan = model.Ptr(90)

	s.NsdpBroadcastFiltering = model.Ptr(true)

	s.NsdpLoopDetection = model.Ptr(true)

	return s
}

// SeedGS305EP builds an ILLUSTRATIVE GS305EP (5-port, PoE ports 1-4) State,
// transcribed field-for-field from the pinned Python seed_gs305ep (D-NSDP
// §7.3). HAND-INVENTED: no capture of any kind exists for gs305ep -- the
// port speeds, the 12800 mW PoE reading, VLAN 90 and the PVIDs are all
// structural test data, NOT observed values (same convention as
// SeedGSM7228PS, which says so explicitly). Only the shape is grounded:
// the Plus family genuinely has no MAC/FDB, no box sensors and no LLDP
// over its web UI.
//
// GENUINE GAP, ported deliberately, not filled in: the pinned Python
// constructor call passes no model_name/serial/firmware/hostname/nsdp_mac/
// nsdp_password/QoS/mirroring/IGMP/broadcast/loop-detection kwargs at all,
// so every one of those -- and Mgmt -- falls through to the
// VirtualSwitchState dataclass default (empty identity strings, the
// default NsdpMac/NsdpPassword, every NSDP-extra field nil/unseeded, Mgmt
// "0.0.0.0"/dhcp). This function therefore leaves every one of those
// fields at NewState's own matching defaults rather than inventing
// plausible-looking values gs305ep never actually had in the pinned
// reference -- doing so would silently diverge from a future Go<->Python
// cross-fake-equivalence test (roadmap slice 10). See D-NSDP
// §7.3/§10.6#7.
func SeedGS305EP() *State {
	ports := map[int]*PortSim{}
	for port := 1; port <= 5; port++ {
		speed := 0
		if port == 1 {
			speed = 1000
		}
		ports[port] = &PortSim{
			Name:  fmt.Sprintf("Port %d", port),
			Admin: port != 3,
			Link:  port == 1,
			Speed: speed,
			// Pin's seed_gs305ep (seed.py:2041-2072) never overrides
			// flow_control, so it falls through to PortSim's dataclass
			// default True (state.py:170) -- same as SeedGS110EMX's own
			// FlowControl: true, same citation.
			FlowControl: true,
		}
	}
	ports[1].RxOctets = model.Ptr(uint64(1_000_000))
	ports[1].TxOctets = model.Ptr(uint64(2_000_000))
	ports[1].RxErrors = model.Ptr(uint64(0))

	vlans := map[int]*VlanSim{
		1:  {Name: "default", Member: portSetFromSlice([]int{1, 2, 3, 4, 5}), Untagged: portSetFromSlice([]int{3, 4, 5})},
		90: {Name: "iot", Member: portSetFromSlice([]int{1, 2}), Untagged: portSetFromSlice([]int{1, 2})},
	}
	pvids := map[int]int{1: 90, 2: 90, 3: 1, 4: 1, 5: 1}
	poe := map[int]*PoeSim{
		1: {Admin: true, Detect: 3, PowerMw: 12_800},
		2: {Admin: true, Detect: 1, PowerMw: 0},
		3: {Admin: true, Detect: 1, PowerMw: 0},
		4: {Admin: false, Detect: 1, PowerMw: 0},
	}

	s := NewState("gs305ep")

	s.Ports = withDefaultIfType(ports)

	s.Vlans = vlans

	s.Pvids = pvids

	s.Poe = poe

	return s
}

// SeedGS105PE builds a GS105PE (5-port Plus, NSDP+HTTP) State transcribed
// field-for-field from the pinned Python seed_gs105pe (D-NSDP §7.3), whose
// own docstring cites a REAL live capture (host 10.1.5.30 / poe-micro3,
// 2026-07-21): ports 3 (100M) and 5 (1G) up, the rest down; VLANs 1/41/90
// with their real member/untagged sets; real PVIDs; DHCP mgmt-IP (address
// still the captured 10.1.5.30); and the QoS/mirroring/IGMP engine tags.
//
// Port mirroring is OFF on this unit (dest 0, no sources) -- the exact
// 3-byte PORT_MIRRORING TLV shape (dest byte + a narrow, model-sized source
// bitmap) that historically exposed a fixed-width parser bug in the pinned
// Python reference (see nsdp.ParsePortMirroring's own doc comment); kept
// here as a regression fixture for that same class of bug. No PoE
// (registry: PoEPortCount 0 -- "PoE pass-through" only, not PSE), no box
// sensors, no MAC/FDB over ANY interface (a confirmed firmware limitation),
// no LLDP.
func SeedGS105PE() *State {
	realSpeed := map[int]int{3: 100, 5: 1000}
	ports := map[int]*PortSim{}
	for port := 1; port <= 5; port++ {
		ports[port] = &PortSim{
			Name:  fmt.Sprintf("Port %d", port),
			Admin: true,
			Link:  port == 3 || port == 5,
			Speed: realSpeed[port],
			// Pin's seed_gs105pe (seed.py:2075-2127) never overrides
			// flow_control either, so this unit's captured PORT_STATUS
			// PROJECTION is the same True dataclass default (state.py:170)
			// as gs110emx/gs305ep -- not itself a per-unit measurement for
			// THIS switch, but the value the pin's fake actually emits.
			FlowControl: true,
		}
	}
	ports[3].TxOctets = model.Ptr(uint64(10_246_512))
	ports[5].RxOctets = model.Ptr(uint64(29_303_468))
	ports[5].TxOctets = model.Ptr(uint64(289_149))
	ports[5].RxErrors = model.Ptr(uint64(228_666))

	vlans := map[int]*VlanSim{
		1:  {Name: "", Member: portSetFromSlice([]int{5}), Untagged: portSetFromSlice([]int{5})},
		41: {Name: "", Member: portSetFromSlice([]int{1, 2, 4, 5}), Untagged: portSetFromSlice([]int{1, 2, 4})},
		90: {Name: "", Member: portSetFromSlice([]int{3, 5}), Untagged: portSetFromSlice([]int{3})},
	}
	pvids := map[int]int{1: 41, 2: 41, 3: 90, 4: 41, 5: 1}

	mgmt := MgmtSim{Address: "10.1.5.30", Netmask: "255.255.255.0", Gateway: "10.1.5.1", Mode: "dhcp"}

	s := NewState("gs105pe")

	s.Ports = withDefaultIfType(ports)

	s.Vlans = vlans

	s.Pvids = pvids

	s.Mgmt = mgmt

	s.ModelName = "GS105PE"

	s.Serial = "61W19753A00A8"

	s.Firmware = "V1.6.0.4"

	s.Hostname = "poe-micro3"

	s.NsdpMac = [6]byte{0x38, 0x94, 0xed, 0xb7, 0xcd, 0xe0}

	s.NsdpQosEngine = model.Ptr(2)

	// dest=0/no sources: mirroring OFF on this unit -- see doc comment above.
	s.NsdpPortMirroringDest = model.Ptr(0)

	s.NsdpIgmpSnoopingEnabled = model.Ptr(true)

	s.NsdpIgmpSnoopingVlan = model.Ptr(1)

	s.NsdpBroadcastFiltering = model.Ptr(false)

	s.NsdpLoopDetection = model.Ptr(false)

	return s
}

// BuildState returns a seeded State for modelKey when this slice has a
// hand-authored seed for it (the five SNMP-capable models: gsm7252ps,
// gsm7228ps, m4300-24x, m4300-16x, gs728tpp; plus, as of slice 05, the three
// NSDP/HTTP-only Plus models: gs110emx, gs305ep, gs105pe), or a
// blank-but-valid State (NewState's defaults) for every other registered
// model key.
//
// An unrecognized modelKey also gets a blank state: model-key validation is
// the caller's job (model.GetModel), mirroring the Python reference's
// _build_state, which likewise never validates the key itself.
func BuildState(modelKey string) *State {
	switch modelKey {
	case "gsm7252ps":
		return SeedGSM7252PS()
	case "gsm7228ps":
		return SeedGSM7228PS()
	case "m4300-24x":
		return SeedM4300_24X()
	case "m4300-16x":
		return SeedM4300_16X()
	case "gs728tpp":
		return SeedGS728TPP()
	case "gs110emx":
		return SeedGS110EMX()
	case "gs305ep":
		return SeedGS305EP()
	case "gs105pe":
		return SeedGS105PE()
	default:
		return NewState(modelKey)
	}
}
