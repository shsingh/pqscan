// Command pqscan — a small, fast, chainable TLS/QUIC cipher-configuration
// and post-quantum readiness scanner.
//
// This file is the M0 substrate stub (PQ-04): it wires flag plumbing and
// prints the version. Probe engines land with PQ-05 (tlsx) and PQ-06
// (quicx); the CLI surface is specified in docs/spec.md#8-cli-surface.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version carries the build's identity; pre-alpha until the release milestone.
const version = "0.0.1"

func main() {
	showVersion := flag.Bool("version", false, "print pqscan version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("pqscan %s (pre-alpha; specification: docs/spec.md)\n", version)
		os.Exit(0)
	}

	fmt.Fprintln(os.Stderr, "pqscan: probe engines not implemented (M0 spike in progress; see issue PQ-01 register)")
	os.Exit(64) // EX_USAGE — nothing to do yet
}
