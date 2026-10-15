// Command pqscan — a small, fast, chainable TLS/QUIC cipher-configuration
// and post-quantum readiness scanner.
//
// CLI surface is specified in docs/spec.md#8-cli-surface; -debug arms the
// diagnostics sink (USAGE.md DIAGNOSTICS): human stream to stderr, machine
// Report to -debug-out. Stdout stays results-only for pipes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/shsingh/pqscan/internal/diag"
)

// version carries the build's identity; pre-alpha until the release milestone.
const version = "0.0.1"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns the process exit code. The flag set is
// rebuilt per call so tests exercise the same path the process does
// (PQ-10). -debug arms the diagnostics sink (PQ-011).
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pqscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print pqscan version and exit")
	debug := fs.Bool("debug", false, "full diagnostics: human stream on stderr + machine report")
	debugOut := fs.String("debug-out", "", "write the machine-parsable diagnostics report (schema 1) to this JSON file")
	if err := fs.Parse(args); err != nil {
		return 64
	}

	if *showVersion {
		fmt.Fprintf(stdout, "pqscan %s (pre-alpha; specification: docs/spec.md)\n", version)
		return 0
	}

	// arm diagnostics under -debug; everything below emits
	if *debug {
		sink, err := diag.NewSink(stderr, 10000)
		if err == nil {
			sink.SetFlags(effectiveFlags(fs))
			diag.SetDefault(sink)
			defer drainDiagnostics(sink, *debugOut, stderr)
			diag.Emit(diag.Info, diag.DomConfig, "run", "", "diagnostics armed", nil,
				map[string]string{"version": version, "positional_args": strings.Join(fs.Args(), ",")})
		}
	}

	// engines land with the PQ-01 lanes; run() returns usage until then
	diag.Emit(diag.Warn, diag.DomEngine, "run", "", "probe engines not implemented; refusing to scan (M0 lanes in flight)", nil, nil)
	fmt.Fprintln(stderr, "pqscan: probe engines not implemented (M0 spike in progress; see the PQ-01 register)")
	return 64 // EX_USAGE
}

func effectiveFlags(fs *flag.FlagSet) map[string]string {
	m := map[string]string{}
	fs.Visit(func(f *flag.Flag) { m[f.Name] = f.Value.String() })
	return m
}

// drainDiagnostics prints the human block and writes the machine report
// (deferred so it runs on every exit path; streams to run()'s stderr).
func drainDiagnostics(sink *diag.Sink, outFile string, stderr io.Writer) {
	r, err := sink.Report()
	if err != nil {
		return
	}
	if h, err := diag.Humanize(r); err == nil {
		fmt.Fprint(stderr, h)
	}
	if outFile != "" {
		if data, err := json.MarshalIndent(r, "", "  "); err == nil {
			_ = os.WriteFile(outFile, data, 0o600) // diagnostics dump; failure is best-effort
		}
	}
	diag.SetDefault(nil)
}
