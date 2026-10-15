// Command pqscan — a small, fast, chainable TLS/QUIC cipher-configuration
// and post-quantum readiness scanner.
//
// CLI surface is specified in docs/spec.md#8-cli-surface; the engines land
// via the PQ-01 register lanes.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// version carries the build's identity; pre-alpha until the release milestone.
const version = "0.0.1"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns the process exit code. The flag set is
// rebuilt per call so tests exercise the same path the process does
// (PQ-10; extraction of the -version / usage paths).
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pqscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print pqscan version and exit")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if *showVersion {
		fmt.Fprintf(stdout, "pqscan %s (pre-alpha; specification: docs/spec.md)\n", version)
		return 0
	}
	// engines land with the PQ-01 lanes; run() returns usage until then
	fmt.Fprintln(stderr, "pqscan: probe engines not implemented (M0 spike in progress; see the PQ-01 register)")
	return 64 // EX_USAGE
}
