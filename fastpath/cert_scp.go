// cert_scp.go: DeployCertificateSCP -- the FASTPATH SSL-certificate-over-
// SCP deploy, ported from the pinned python-netgear-switch-library @
// 7ebfe5d475411a7d88fd5cc68ff86ee3a4505362, src/netgear_switch/cli_write.py
// deploy_certificate_scp (module-level function, lines 106-141), dossier
// §4.10 (protocol dossier
// docs/superpowers/plans/2026-08-01-slice-07-dossier-cli-protocol.md). Any
// discrepancy between this file and the pin is a bug in this file, not a
// deliberate deviation, unless called out below.
//
// NOT a Writer method -- a standalone function over a raw Session, mirroring
// the pin's own shape exactly ("This is NOT a CliWriter method -- a
// standalone function taking a raw CliSession", dossier §4.10).
//
// DELIBERATE deviation from the pin's exact parameter list: Python's
// deploy_certificate_scp takes writemem_stuff as a caller-supplied bool --
// the CALLING code is expected to have already resolved
// ScpCertProfile.writemem_stuff for the target model (dossier §1.7/§4.10).
// This Go port instead takes the model directly and resolves ScpProfile(m)
// itself, for two reasons: (1) that IS where this slice's device-limit gate
// for gsm7228ps belongs -- "uses an HTTP multipart upload instead"
// (dossier §5.2, commands.py:365-366) -- a REAL mechanism difference, not a
// missing Go feature, and this package deliberately does not fake an SCP
// path for gsm7228ps; (2) Go has no equivalent upstream glue layer in this
// slice to resolve the profile first the way a future Python caller would.
package fastpath

import (
	"context"
	"fmt"

	"github.com/mithro/go-netgear-switch-library/model"
)

// The 4-or-5-step deploy_certificate_scp command vocabulary, mirroring
// Python's module-level constants (cli_write.py:106-111) EXACTLY.
const (
	scpServerDest     = "nvram:sslpem-server"
	scpRootDest       = "nvram:sslpem-root"
	scpServerSuffix   = "-server.pem"
	scpRootSuffix     = "-root.pem"
	scpWriteMemoryCmd = "write memory"
	scpHTTPSOffCmd    = "no ip http secure-server"
	scpHTTPSOnCmd     = "ip http secure-server"
)

// ScpSourceURL builds the scp:// source URL deploy_certificate_scp's copy
// commands address, mirroring Python scp_source_url (cli_write.py:127-128)
// EXACTLY -- including its central hazard: there is NO separating slash
// between scpSource and remoteDir (remoteDir is expected to already start
// with "/", an "ABSOLUTE staging path" per the pin's own docstring); only
// ONE slash is inserted, between remoteDir and filename. Reproducing this
// exact concatenation -- not "fixing" it with an extra slash -- is
// load-bearing: a Go port that added one would double a leading slash
// whenever a caller's remoteDir already starts with "/", diverging from
// the pin.
func ScpSourceURL(scpSource, remoteDir, filename string) string {
	return fmt.Sprintf("scp://%s%s/%s", scpSource, remoteDir, filename)
}

// scpCopyCmd builds one `copy scp://... <dest>` command, mirroring Python
// _copy_cmd (cli_write.py:130-131).
func scpCopyCmd(scpSource, remoteDir, filename, dest string) string {
	return fmt.Sprintf("copy %s %s", ScpSourceURL(scpSource, remoteDir, filename), dest)
}

// DeployCertificateSCP deploys an SSL server certificate (and optionally
// its CA chain) to m over an interactive `copy scp://...`, mirroring Python
// deploy_certificate_scp (cli_write.py:133-141, dossier §4.10) EXACTLY for
// the command sequence and session-method routing:
//
//  1. `no ip http secure-server` via session.Run -- NOT gated on empty
//     output the way every CliWriter write op is (session.go's `run`
//     helper is deliberately NOT used here): the pin calls session.run
//     directly, with no CliCommandError check at this one call site.
//  2. `copy scp://<scpSource><remoteDir>/<base>-server.pem
//     nvram:sslpem-server` via session.RunSCPCopy(cmd, scpPassword) --
//     interactive (TOFU/password/overwrite-confirm), success/failure
//     already detected by ShellDriver's own SCP sentinels (session.go).
//  3. IF chain: the same for `<base>-root.pem` -> `nvram:sslpem-root`.
//  4. `ip http secure-server` (re-enable; loads the new cert, no reboot),
//     via session.Run, same no-gate convention as step 1.
//  5. `write memory` via session.RunWriteMemory, with prestuff resolved
//     from m's ScpCertProfile.WritememStuff (spec.go) -- see the file doc
//     comment above for why this Go port resolves that itself.
//
// Gated FIRST, before any session I/O, by ScpProfile(m): a model with no
// CLI backend, OR a CLI model with no known copy-scp SSL-certificate
// deploy profile (today, ONLY gsm7228ps) returns an error wrapping
// model.ErrUnsupportedCapability, quoting the mechanism-difference
// justification (spec.go's ScpProfile).
//
// NOT gated by force at all (mirrors the pin: "no ProtectedPortError path
// in this function"). NOT independently verified after write -- the pin's
// own module docstring calls this "MOCK-TESTED end-to-end, but NOT
// live-verified"; success/failure detection is entirely RunSCPCopy's own
// job (dossier §6 point 7).
func DeployCertificateSCP(
	ctx context.Context, session Session, m *model.SwitchModel,
	scpSource, scpPassword, remoteDir, base string, chain bool,
) error {
	profile, err := ScpProfile(m)
	if err != nil {
		return err
	}
	if _, err := session.Run(ctx, scpHTTPSOffCmd); err != nil {
		return err
	}
	serverCmd := scpCopyCmd(scpSource, remoteDir, base+scpServerSuffix, scpServerDest)
	if _, err := session.RunSCPCopy(ctx, serverCmd, scpPassword); err != nil {
		return err
	}
	if chain {
		rootCmd := scpCopyCmd(scpSource, remoteDir, base+scpRootSuffix, scpRootDest)
		if _, err := session.RunSCPCopy(ctx, rootCmd, scpPassword); err != nil {
			return err
		}
	}
	if _, err := session.Run(ctx, scpHTTPSOnCmd); err != nil {
		return err
	}
	if _, err := session.RunWriteMemory(ctx, scpWriteMemoryCmd, profile.WritememStuff); err != nil {
		return err
	}
	return nil
}
