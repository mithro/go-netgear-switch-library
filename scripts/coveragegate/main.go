// Command coveragegate fails if statement coverage over the library packages
// in a Go cover profile is below -min percent.
//
// Coverage is computed directly from the profile file (mode: set/count/
// atomic), NOT from `go tool cover -func`: that tool's per-function
// percentages cannot be correctly averaged (an unweighted mean over
// functions of very different sizes), so this instead sums the profile's own
// per-block statement counts. For every profile line
//
//	file.go:startLine.startCol,endLine.endCol numStmt count
//
// numStmt is added to the running total, and to the covered total when
// count > 0; pct = covered / total * 100.
//
// Packages under scripts/ and cmd/ (path contains "/scripts/" or "/cmd/")
// are exempt from the total: they are internal tooling and CLI entry points
// covered by their own CLI-level tests rather than unit-test line coverage,
// and including them (often near-0%, since `go test ./...` runs them but
// exercises little of main()) would dilute the gate meant to police the
// library packages.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// exemptPath reports whether file is a scripts/ or cmd/ package path and so
// is excluded from the coverage total.
func exemptPath(file string) bool {
	return strings.Contains(file, "/scripts/") || strings.Contains(file, "/cmd/")
}

// parseProfile reads a Go cover profile (mode: line followed by
// "file:start,end numStmt count" lines) from r and returns the total and
// covered statement counts summed over every non-exempt file. It returns an
// error on any malformed data line.
func parseProfile(r io.Reader) (total, covered int64, err error) {
	scanner := bufio.NewScanner(r)
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			if strings.HasPrefix(line, "mode:") {
				continue
			}
		}
		// "file.go:startLine.startCol,endLine.endCol numStmt count"
		colon := strings.LastIndex(line, ":")
		if colon < 0 {
			return 0, 0, fmt.Errorf("coveragegate: malformed profile line: %q", line)
		}
		file := line[:colon]
		fields := strings.Fields(line[colon+1:])
		if len(fields) != 3 {
			return 0, 0, fmt.Errorf("coveragegate: malformed profile line: %q", line)
		}
		numStmt, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("coveragegate: malformed profile line: %q: %w", line, err)
		}
		count, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("coveragegate: malformed profile line: %q: %w", line, err)
		}
		if exemptPath(file) {
			continue
		}
		total += numStmt
		if count > 0 {
			covered += numStmt
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return total, covered, nil
}

func main() {
	profile := flag.String("profile", "coverage.out", "cover profile path")
	minPct := flag.Float64("min", 90, "minimum total coverage percent")
	flag.Parse()

	f, err := os.Open(*profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "coveragegate:", err)
		os.Exit(2)
	}
	defer func() { _ = f.Close() }()

	total, covered, err := parseProfile(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if total == 0 {
		fmt.Fprintln(os.Stderr, "coveragegate: no non-exempt statements found in profile")
		os.Exit(2)
	}

	pct := float64(covered) / float64(total) * 100
	if pct < *minPct {
		fmt.Fprintf(os.Stderr, "coverage %.1f%% below minimum %.1f%%\n", pct, *minPct)
		os.Exit(1)
	}
	fmt.Printf("coverage %.1f%% >= %.1f%%\n", pct, *minPct)
}
