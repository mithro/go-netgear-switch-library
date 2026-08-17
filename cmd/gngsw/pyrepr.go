package main

import (
	"fmt"
	"strings"
	"unicode"
)

// pyRepr renders s the way Python's repr() renders a str, closely enough to
// match main.py's several f"...{value!r}" interpolations byte-for-byte for
// realistic CLI input (port descriptions, VLAN names, host names -- plain
// human-typed text). These interpolations land in a write command's
// "ok: <description>" success line, which goes to STDOUT (fmtx/safety's
// Streams.Out), so this needs to be a faithful port, not a rough
// approximation: CPython's unicode_repr
//
//   - defaults to a single-quote-delimited string;
//   - switches to double quotes ONLY when s contains a single quote and no
//     double quote (so a string with both still gets single quotes, with
//     the single quote itself escaped);
//   - backslash-escapes a literal backslash, the chosen quote character,
//     '\n', '\r' and '\t';
//   - \xHH-escapes any other non-printable rune below 0x100, \uHHHH below
//     0x10000, and \UHHHHHHHH above that -- using Go's unicode.IsPrint as
//     the printability test, which is this codebase's closest stdlib
//     analogue of Python's unicodedata.isprintable(); the two disagree only
//     on a handful of obscure Unicode categories no switch config or CLI
//     operator is realistically going to type as a port description or
//     VLAN name.
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
