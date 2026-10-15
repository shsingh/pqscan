// Command pqscan — a small, fast, chainable TLS/QUIC cipher-configuration
// and post-quantum readiness scanner.
//
// This file is the M0 substrate stub (PQ-04): it wires flag plumbing and
// prints the version. Probe engines land with PQ-05 (tlsx) and PQ-06
// (quicx); the CLI surface is specified in docs/spec.md#8-cli-surface.
package main

import (
	"io"
	"os"
)

// version carries the build's identity; pre-alpha until the release milestone.
const version = "0.0.1"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns the process exit code. PQ-10 watched
// RED: the tests land first; this stub always fails them until the
// extraction commit.
func run(args []string, stdout, stderr io.Writer) int {
	return -1
}
