//go:build linux

package nsdp

import "syscall"

// controlFunc returns a net.Dialer.Control callback applying dossier
// §5.3/§5.4's socket options: SO_REUSEADDR unconditionally (no suppression:
// a failure here propagates, mirroring Python's bare
// `sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)` with no
// try/except), and -- if iface is non-empty -- best-effort SO_BINDTODEVICE.
//
// SO_BINDTODEVICE needs CAP_NET_RAW/root, so its error is deliberately
// swallowed here (mirroring Python's `with contextlib.suppress(OSError)`)
// rather than surfaced: an unprivileged caller still attempts the query
// (succeeding on a directly-attached segment) rather than failing outright.
func controlFunc(iface string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var reuseErr error
		ctrlErr := c.Control(func(fd uintptr) {
			reuseErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if iface != "" {
				_ = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			}
		})
		if ctrlErr != nil {
			return ctrlErr
		}
		return reuseErr
	}
}
