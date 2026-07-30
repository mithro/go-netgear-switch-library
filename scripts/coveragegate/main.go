// Command coveragegate fails if total statement coverage in a Go cover
// profile is below -min percent. cmd/ packages are exempt per the spec
// (covered by CLI-level tests instead).
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	profile := flag.String("profile", "coverage.out", "cover profile path")
	min := flag.Float64("min", 90, "minimum total coverage percent")
	flag.Parse()
	out, err := exec.Command("go", "tool", "cover", "-func="+*profile).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "coveragegate:", err)
		os.Exit(2)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	last := lines[len(lines)-1] // "total: (statements) NN.N%"
	fields := strings.Fields(last)
	pct, err := strconv.ParseFloat(strings.TrimSuffix(fields[len(fields)-1], "%"), 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "coveragegate: cannot parse:", last)
		os.Exit(2)
	}
	if pct < *min {
		fmt.Fprintf(os.Stderr, "coverage %.1f%% below minimum %.1f%%\n", pct, *min)
		os.Exit(1)
	}
	fmt.Printf("coverage %.1f%% >= %.1f%%\n", pct, *min)
}
