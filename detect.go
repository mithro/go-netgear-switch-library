// detect.go: DetectModel, the free-function discovery entry point a caller
// uses BEFORE it can construct a Switch at all -- ported from
// src/netgear_switch/sync_api.py's module-level detect_model() (the
// normative source; that repo is read-only from here). Any discrepancy
// between this file and the pinned Python source is a bug in this file. See
// docs/superpowers/plans/2026-07-30-slice-03-dossier-facade.md (D-FAC) §2.11
// -- DetectModel is Identify's pre-construction twin: same
// build-default-or-reuse-injected-client shape, just without a *Switch to
// hang the community/client off of.

package netgearswitch

import (
	"context"

	"github.com/mithro/go-netgear-switch-library/model"
	"github.com/mithro/go-netgear-switch-library/snmp"
)

// detectConfig holds DetectModel's resolved options; unexported, mutated
// only via DetectOption functions applied in DetectModel.
type detectConfig struct {
	community *string
	client    snmp.Client
}

// DetectOption configures DetectModel at call time (functional-options
// pattern), mirroring Python's detect_model(host, *, community=None,
// client=None) keyword-only parameters.
type DetectOption func(*detectConfig)

// WithDetectCommunity sets the SNMP read community DetectModel's default
// client build uses. Ignored entirely if WithDetectClient also injects a
// client -- an injected client bypasses the community gate altogether,
// exactly like Identify/buildSNMPClient (D-FAC §2.11).
func WithDetectCommunity(s string) DetectOption {
	return func(c *detectConfig) { c.community = &s }
}

// WithDetectClient injects an already-built snmp.Client, used as-is instead
// of DetectModel building a default one from host/community. Primarily for
// tests (a fake/virtual client) or a caller reusing an already-open
// connection.
func WithDetectClient(c snmp.Client) DetectOption {
	return func(cfg *detectConfig) { cfg.client = c }
}

// DetectModel identifies a switch's model over SNMP, WITHOUT already
// knowing/hardcoding it -- the discovery entry point a caller uses BEFORE it
// can construct a Switch at all: call this first, then GetModel(detected.Key)
// + New(...) once detected.Key is non-nil. See model.DetectedModel /
// snmp.DetectModelFromSysDescr (via snmp.ReadSystemInfo) for exactly how (and
// why) an unmatched sysDescr honestly yields Key == nil rather than a guess.
//
// Builds the default GoSNMP client from host/community unless client is
// injected via WithDetectClient (tests, or an already-open connection) --
// mirroring Python's detect_model exactly, including its "community left
// unset raises CredentialError" default: DetectModel has no implicit
// fallback community value of its own (D-FAC §2.11/backend_snmp.go's
// requireSNMPCommunity is the single source of truth for that gate; this
// function reuses it verbatim via buildDetectClient below).
func DetectModel(ctx context.Context, host string, opts ...DetectOption) (model.DetectedModel, error) {
	if err := ctx.Err(); err != nil {
		return model.DetectedModel{}, err
	}

	var cfg detectConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	client := cfg.client
	if client == nil {
		community, err := requireSNMPCommunity(host, cfg.community)
		if err != nil {
			return model.DetectedModel{}, err
		}
		client = snmp.NewGoSNMPClient(host, community)
	}
	return snmp.ReadSystemInfo(ctx, client)
}
