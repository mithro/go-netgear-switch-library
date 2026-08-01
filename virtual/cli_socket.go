package virtual

// cli_socket.go holds the byte-framing loop shared by the two REAL loopback
// CLI listeners (sshface.go, telnetface.go, Task 12) -- the part of "FASTPATH
// over a real socket" that has nothing to do with SSH or Telnet specifically:
// write a prompt, read one command line, echo it, dispatch it through a
// per-connection *CliFace (Task 11's in-process dispatcher -- shared
// VirtualSwitchState, independent mode stack), write any non-empty output,
// write the next prompt, repeat until the connection closes.
//
// This is [NEW DESIGN] (transport dossier §7.7): there is no Python fake to
// port from, since the Python virtual CLI face (cli.py) is in-process only
// and never served FASTPATH over a real socket. The one constraint this
// design must satisfy is the WIRE CONTRACT fastpath.ShellDriver (session.go)
// already assumes, since that is the real client this listener is proven
// against (dossier's own methodology: "start the SSH listener, connect with
// the REAL fastpath SSH client ... and round-trip a real read op"):
//
//   - readUntil accumulates raw bytes until promptRE (or, right after
//     "enable", passwordRE) matches the END of the accumulated buffer --
//     see cliPrompt's own doc comment for the exact prompt shape chosen to
//     satisfy promptRE.
//   - cleanOutput strips the FIRST line if it contains the command text
//     (a real terminal echoes what was typed) and every trailing
//     prompt-matching line -- so this loop must echo the command line back
//     before writing its output, exactly like a real interactive shell.
//
// Reused verbatim by both listeners (rather than each hand-rolling its own
// copy) precisely because SSH and Telnet differ only in how their bytes
// reach here (an authenticated ssh.Session channel vs a logged-in raw
// net.Conn) -- dossier §7.7's explicit recommendation: "the SAME in-process
// VirtualCliFace-equivalent Go code wrapped in a byte-framing layer".

import (
	"bufio"
	"context"
	"io"
	"strings"
)

// cliPrompt renders the FASTPATH prompt for face's CURRENT mode, mirroring
// the one live-captured real example -- `(manage-sw-netgear-s3300-1) >`,
// dossier §7.7/registry.py:202-203 -- for EXEC mode, and extending the same
// `(<model>) (<Mode>)#` shape session.go's own comment documents
// (`"(GSM7252PS) (Config)#"`) for every other mode. The exact mode-label
// text is [NEW DESIGN] (no capture exists for any of these), but the SHAPE
// is what fastpath.promptRE actually requires: a ")" immediately (optionally
// through one more "(...)" group) before a trailing #/>, which every branch
// below satisfies regardless of what came before it -- so a caller (real or
// fake) never needs to parse the mode label itself, only recognize that the
// buffer now ends in a prompt.
func cliPrompt(face *CliFace, modelKey string) string {
	switch face.Mode() {
	case cliModeConfig:
		return "(" + modelKey + ") (Config)#"
	case cliModeVlanDB:
		return "(" + modelKey + ") (Vlan)#"
	case cliModeInterface:
		if iface, ok := face.InterfaceName(); ok {
			return "(" + modelKey + ") (Interface " + iface + ")#"
		}
		return "(" + modelKey + ") (Interface)#"
	default: // "exec"
		return "(" + modelKey + ") >"
	}
}

// cliListenerLoop drives one already-authenticated CLI connection to
// completion: writes the initial EXEC prompt (Setup's first readUntil
// expects a banner/prompt before anything is sent), then repeatedly reads
// one command line from r, echoes it to w, dispatches it through face
// (Run -- the same accept/reject convention every write op relies on, since
// FASTPATH write commands are themselves driven through Session.Run, never
// a separate wire verb), writes any non-empty output, and writes the next
// mode-appropriate prompt -- until r hits EOF/an error or ctx is done. w and
// r are deliberately separate (rather than one io.ReadWriter) so a caller
// that already consumed a login handshake off the same underlying
// connection (telnetface.go) can hand in the SAME *bufio.Reader instance
// rather than risk dropping already-buffered bytes by wrapping a fresh one.
func cliListenerLoop(ctx context.Context, w io.Writer, r *bufio.Reader, face *CliFace, modelKey string) {
	write := func(s string) bool {
		_, err := io.WriteString(w, s)
		return err == nil
	}
	if !write(cliPrompt(face, modelKey)) {
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		raw, err := r.ReadString('\n')
		if raw == "" && err != nil {
			return // clean close or read error -- nothing more to serve
		}
		command := strings.TrimRight(raw, "\r\n")
		// Echo the command line back first -- a real terminal echoes typed
		// input, and ShellDriver's cleanOutput (session.go) strips exactly
		// this shape (a first line containing the command text) off the
		// front of every response.
		if !write(command + "\r\n") {
			return
		}
		output, runErr := face.Run(ctx, command)
		if runErr != nil {
			return // ctx cancelled, or face itself became unusable
		}
		if output != "" {
			if !write(strings.ReplaceAll(output, "\n", "\r\n") + "\r\n") {
				return
			}
		}
		if !write(cliPrompt(face, modelKey)) {
			return
		}
		if err != nil {
			// The line that just completed was also the last thing the
			// connection ever sent (a partial final write with no trailing
			// newline, immediately followed by close) -- handled it above,
			// nothing more to read.
			return
		}
	}
}
