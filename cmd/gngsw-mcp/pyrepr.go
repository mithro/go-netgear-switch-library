package main

import (
	"fmt"
	"strings"
	"unicode"
)

// pyRepr renders s the way Python's repr() renders a str, closely enough to
// match server.py's several f"...{value!r}" interpolations for realistic
// MCP tool input (a port-speed rate string, a VLAN mode string) -- these
// land verbatim in the pre-resolve structured-error results
// set_port_speed/set_vlan_membership return (see write.go), so this needs
// to be a faithful port, not a rough approximation. Duplicated from
// cmd/gngsw/pyrepr.go (a different `main` package, so it cannot be
// imported directly) -- byte-identical to that copy; see its own doc
// comment for the full behavioural contract (single- vs double-quote
// choice, backslash/control-character escaping).
func pyRepr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}

	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x80 && byte(r) == quote:
			b.WriteByte('\\')
			b.WriteByte(quote)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x100 && !unicode.IsPrint(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x10000 && !unicode.IsPrint(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		case !unicode.IsPrint(r):
			fmt.Fprintf(&b, `\U%08x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}
