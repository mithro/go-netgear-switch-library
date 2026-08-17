package resolve

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// NewStdinPrompt returns a PromptFunc suitable for a real, interactive CLI
// invocation: it writes label to out (no trailing newline -- the label
// itself, e.g. "SNMP read community: ", is the whole prompt line) and
// reads one line from in, stripping the trailing newline only (leading/
// trailing whitespace trimming for the "blank reply means unresolved"
// rule is readCommunity's job, not this function's). An EOF with no bytes
// read (in is already exhausted, e.g. stdin closed/piped from /dev/null)
// is returned as an error, matching Python's builtin input() raising
// EOFError in the same situation; an EOF reached AFTER some bytes were
// read (the final line has no trailing newline) is NOT an error -- the
// partial line is returned as-is, matching Python's input() there too.
//
// Typical CLI wiring: resolve.WithPrompt(resolve.NewStdinPrompt(os.Stderr,
// bufio.NewReader(os.Stdin))) -- stderr, not stdout, so a prompt never
// pollutes JSON/table output a caller might be piping (mirrors safety.
// confirm's own out/err split).
func NewStdinPrompt(out io.Writer, in *bufio.Reader) PromptFunc {
	return func(label string) (string, error) {
		if _, err := fmt.Fprint(out, label); err != nil {
			return "", err
		}
		line, err := in.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && line != "" {
				return strings.TrimRight(line, "\n"), nil
			}
			return "", err
		}
		return strings.TrimRight(line, "\n"), nil
	}
}
