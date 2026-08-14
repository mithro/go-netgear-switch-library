package capabilities

// support_http.go: the HTTP-backend derivation, ported field-for-field from
// src/netgear_switch/capabilities.py's _http_support and _http_path_for
// (pin go-port-pin-a9e0ebc, lines 243-311). Any discrepancy between this
// file and that pin is a bug in this file.
//
// httpSupport/httpPathFor take an already-resolved *webui.HTTPModelSpec
// rather than calling webui.HTTPSpec(m) themselves -- see this task's
// Interfaces note (Go has no monkeypatching, so the ReadsVerified gate is
// tested with a synthetic spec instead; For, in support.go, is the one place
// that calls the real webui.HTTPSpec).

import (
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/webui"
)

// httpSupport derives the HTTP-backend verdict for (m, op) given spec.
func httpSupport(m *model.SwitchModel, spec *webui.HTTPModelSpec, op Operation) (Support, string) {
	if !spec.ReadsVerified {
		// The facade gates BOTH reads and writes on ReadsVerified (see
		// backend_http.go's httpReadsSupported, reused for both directions):
		// output nobody has cross-verified against hardware is not
		// dispatched at all.
		return SupportUnverified, fmt.Sprintf("model %q HTTP reads are UNVERIFIED-pending-capture", m.Key)
	}
	if op.Name == "upload_certificate" {
		// These models CAN take a certificate -- just not over HTTP. The
		// real facade raises model.ErrKnownUnimplemented naming the real
		// mechanism (webui/cert.go's rejectKnownUnimplementedCertUpload)
		// rather than model.ErrUnsupportedCapability -- but the ORACLE folds
		// both into this single Support.UNSUPPORTED verdict, exactly
		// mirroring Python's collapse of UnsupportedCapabilityError and
		// NotImplementedError. Do not add a distinct Support value here.
		if mechanism, ok := webui.CertUploadKnownUnimplemented[m.Key]; ok {
			return SupportUnsupported, fmt.Sprintf(
				"this model takes a certificate by %s, not over the web UI -- use upload_certificate_scp",
				mechanism)
		}
	}
	path := httpPathFor(spec, op)
	if path == "" {
		return SupportUnsupported, fmt.Sprintf("model %q web UI has no page for %s (%s)", m.Key, op.Name, op.Summary)
	}
	return SupportSupported, ""
}

// httpPathFor is the endpoint op needs, or "" if this model's UI has no such
// page (Go's None sentinel, matching every other webui *ModelSpec string
// field). Mirrors http_read.py/http_write.py one line at a time; the three
// ops with composite conditions defer to webui's own exported helpers so
// there is exactly one definition of "this UI can answer that".
func httpPathFor(spec *webui.HTTPModelSpec, op Operation) string {
	switch op.Name {
	case "get_sensors":
		if webui.SupportsSensors(spec) {
			return spec.SysinfoPath
		}
		return ""
	case "get_mgmt_ip":
		return webui.MgmtIPPath(spec)
	case "set_mgmt_ip":
		// The XUI write needs the field map as well as the page.
		if spec.MgmtIPFields != nil {
			return spec.MgmtIPPath
		}
		return ""
	}
	simple := map[string]string{
		"get_ports":           spec.DashboardPath,
		"get_stats":           spec.StatsPath,
		"get_poe":             spec.PoEStatusPath,
		"get_pvids":           spec.PvidPath,
		"get_vlans":           spec.VlanConfigPath,
		"get_macs":            spec.MacTablePath,
		"get_lldp":            spec.LLDPPath,
		"set_poe":             spec.PoEConfigPath,
		"cycle_poe":           spec.PoEConfigPath,
		"clear_poe_fault":     spec.PoEConfigPath,
		"set_pvid":            spec.PvidPath,
		"set_vlan_membership": spec.VlanMembershipPath,
		"create_vlan":         spec.VlanConfigPath,
		"delete_vlan":         spec.VlanConfigPath,
		"set_port_enabled":    spec.PortConfigPath,
		"upload_certificate":  spec.CertUploadPath,
	}
	return simple[op.Name]
}
