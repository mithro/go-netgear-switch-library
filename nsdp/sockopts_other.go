//go:build !linux

package nsdp

import "syscall"

// controlFunc returns a net.Dialer.Control callback applying dossier §5.4's
// SO_REUSEADDR unconditionally. SO_BINDTODEVICE is explicitly Linux-only
// (dossier §5.3, and this file's build tag) so non-linux builds skip it
// entirely; iface is accepted only for signature parity with the linux
// variant (sockopts_linux.go) and is otherwise unused here.
func controlFunc(iface string) func(string, string, syscall.RawConn) error {
	_ = iface
	return func(_, _ string, c syscall.RawConn) error {
		var reuseErr error
		ctrlErr := c.Control(func(fd uintptr) {
			reuseErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
		if ctrlErr != nil {
			return ctrlErr
		}
		return reuseErr
	}
}
