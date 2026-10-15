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
	"strconv"
	"strings"

	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/out"
)

// version carries the build's identity, stamped at build time by the
// release workflow via -ldflags "-X main.version=<tag>"; default is the
// source-tree revision (pre-alpha).
var version = "0.0.1"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns the process exit code. The flag set is
// rebuilt per call so tests exercise the same path the process does
// (PQ-10). -debug arms the diagnostics sink (PQ-011). -u / -l / --
// compose into one []grammar.Target list scanned by the multi-target
// pipeline (PQ-15; cidr specs refuse with the PQ-16 deferral).
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pqscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print pqscan version and exit")
	debug := fs.Bool("debug", false, "full diagnostics: human stream on stderr + machine report")
	debugOut := fs.String("debug-out", "", "write the machine-parsable diagnostics report (schema 1) to this JSON file")
	target := fs.String("u", "", "single target: host, host:port, or ip:port (composes with -l and --)")
	listFile := fs.String("l", "", "read newline-separated target specs from this file (composes with -u and --; deduped by host:port)")
	asJSONL := fs.Bool("jsonl", false, "emit one schema-1 JSON record per line")
	outFile := fs.String("o", "", "write results to file (default stdout)")
	quicOff := fs.Bool("quic-off", false, "skip the QUIC plane probe")
	resume := fs.Bool("resume", false, "resume an interrupted run from the WAL (<output basename>.wal next to -o)")
	if err := fs.Parse(args); err != nil {
		return 64
	}

	if *showVersion {
		fmt.Fprintf(stdout, "pqscan %s (pre-alpha; specification: docs/spec.md)\n", version)
		return 0
	}

	// -resume (PQ-16): the WAL replay is the RED half of the watched pair —
	// the flag exists, the replay logic lands GREEN.
	if *resume {
		diag.Emit(diag.Warn, diag.DomOutput, "run", "", "resume requested", nil, nil)
		fmt.Fprintln(stderr, "pqscan: -resume: WAL replay lands with the PQ-16 GREEN commit")
		return 64
	}

	// arm diagnostics under -debug; everything below emits
	if *debug || *debugOut != "" {
		sink, err := diag.NewSink(stderr, 10000)
		if err == nil {
			sink.SetFlags(effectiveFlags(fs))
			diag.SetDefault(sink)
			defer drainDiagnostics(sink, *debugOut, stderr)
			diag.Emit(diag.Info, diag.DomConfig, "run", "", "diagnostics armed", nil,
				map[string]string{"version": version, "positional_args": strings.Join(fs.Args(), ",")})
		}
	}

	targets, code := composeTargets(*target, *listFile, args, stderr)
	if code != 0 {
		return code
	}
	if len(targets) == 0 {
		diag.Emit(diag.Warn, diag.DomEngine, "run", "", "no targets; run refuses", nil, nil)
		fmt.Fprintln(stderr, "pqscan: no target specified (use -u, -l, or -- for stdin; probe engines per the PQ-01 register)")
		return 64 // EX_USAGE
	}

	recs, err := (&Engine{}).Run(targets, Options{QuicOff: *quicOff}, func(done, total int) {
		fmt.Fprintf(stderr, "pqscan: progress: %d/%d targets scanned\n", done, total)
	})
	if err != nil {
		diag.Emit(diag.Error, diag.DomEngine, "run", "", "pipeline failed", err, nil)
		fmt.Fprintln(stderr, "pqscan:", err)
		return 1
	}

	lines := make([]string, 0, len(recs))
	for _, rec := range recs {
		line, err := encodeRecord(rec, *asJSONL)
		if err != nil {
			diag.Emit(diag.Error, diag.DomOutput, "encode", rec.Target.Host, "record encode failed", err, nil)
			fmt.Fprintln(stderr, "pqscan:", err)
			return 1
		}
		lines = append(lines, line)
		diag.Emit(diag.Info, diag.DomOutput, "emit", rec.Target.Host, "record emitted", nil,
			map[string]string{"format": outFormat(*asJSONL)})
	}
	recTotal := strconv.Itoa(len(targets))
	if *outFile == "" {
		for _, line := range lines {
			fmt.Fprintln(stdout, line)
		}
		return 0
	}
	if err := writeResults(*outFile, lines); err != nil {
		diag.Emit(diag.Error, diag.DomOutput, "write", "", "results write failed", err,
			map[string]string{"file": *outFile, "records": recTotal})
		fmt.Fprintln(stderr, "pqscan:", err)
		return 1
	}
	return 0
}

func u32str(u uint32) string { return fmt.Sprint(u) }

// scanRecord is the schema-1 record (rc1 subset carried per target; the
// hand-rolled full encoder lands with PQ-16).
type scanRecord struct {
	Schema    int              `json:"schema"`
	Mode      string           `json:"mode"`
	Target    out.TargetRecord `json:"target"`
	Handshake handshakeRecord  `json:"handshake"`
	Quic      *quicRecord      `json:"quic,omitempty"`
	Error     string           `json:"error"`
}

type handshakeRecord struct {
	Negotiated uint32 `json:"negotiated"`
	GroupName  string `json:"group_name,omitempty"`
	GroupClass string `json:"group_class,omitempty"`
	Suite      string `json:"suite,omitempty"`
	Version    string `json:"version,omitempty"`
	ALPNNeg    string `json:"alpn_neg,omitempty"`
}

type quicRecord struct {
	Attempted  bool   `json:"attempted"`
	State      string `json:"state,omitempty"`
	Negotiated uint32 `json:"negotiated,omitempty"`
	GroupName  string `json:"group_name,omitempty"`
	GroupClass string `json:"group_class,omitempty"`
	UDPBlocked bool   `json:"udp_blocked,omitempty"`
}

func versionName(v uint16) string {
	switch v {
	case 0x0303:
		return "tls-1.2"
	case 0x0304:
		return "tls-1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func groupName(g uint32) string {
	switch g {
	case 4585:
		return "SecP256r1MLKEM512"
	case 4586:
		return "MLKEM512X25519"
	case 4587:
		return "SecP256r1MLKEM768"
	case 4588:
		return "X25519MLKEM768"
	case 4589:
		return "SecP384r1MLKEM1024"
	case 4590:
		return "curveSM2MLKEM768"
	case 29:
		return "x25519"
	case 23:
		return "secp256r1"
	case 24:
		return "secp384r1"
	case 25497:
		return "X25519Kyber768Draft00"
	default:
		return ""
	}
}

func outFormat(asJSONL bool) string {
	if asJSONL {
		return "jsonl"
	}
	return "text"
}

func encodeRecord(rec *scanRecord, asJSONL bool) (string, error) {
	if !asJSONL {
		h := rec.Handshake
		line := fmt.Sprintf("%s:%d group=%s class=%s suite=%s version=%s",
			orNoHost(rec.Target.Host), rec.Target.Port, orDash(h.GroupName), orDash(h.GroupClass), orDash(h.Suite), orDash(h.Version))
		if h.ALPNNeg != "" {
			line += " alpn=" + h.ALPNNeg
		}
		if rec.Quic != nil && rec.Quic.Negotiated > 0 {
			line += fmt.Sprintf(" quic_neg=%s quic_class=%s", orDash(rec.Quic.GroupName), orDash(rec.Quic.GroupClass))
		}
		if rec.Quic != nil && rec.Quic.UDPBlocked {
			line += " udp_blocked=true"
		}
		if rec.Error != "" {
			line += " error=" + rec.Error
		}
		return line, nil
	}
	b, err := json.Marshal(rec)
	return string(b), err
}

func writeResults(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	for _, line := range lines {
		if _, err := fmt.Fprintln(f, line); err != nil {
			return err
		}
	}
	return nil
}

func orNoHost(s string) string {
	if s == "" {
		return "(no host)"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
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
