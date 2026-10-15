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
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/grammar"
	"github.com/shsingh/pqscan/internal/out"
	"github.com/shsingh/pqscan/internal/wal"
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
// pipeline (PQ-15). The output selectors (-json/-jsonl/-csv/-urls/-text)
// choose the encoder (PQ-16); -resume replays the run journal beside -o
// and scans only the pending targets.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pqscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print pqscan version and exit")
	debug := fs.Bool("debug", false, "full diagnostics: human stream on stderr + machine report")
	debugOut := fs.String("debug-out", "", "write the machine-parsable diagnostics report (schema 1) to this JSON file")
	target := fs.String("u", "", "single target: host, host:port, or ip:port (composes with -l and --)")
	listFile := fs.String("l", "", "read newline-separated target specs from this file (composes with -u and --; deduped by host:port)")
	// Output format selectors (spec §5.7): the LAST selector on the
	// command line wins and text is the absent-flag default —
	// chooseFormat resolves it. The five spellings register as real flags
	// (the USAGE <-> source drift gate reads them back from the flag set).
	_ = fs.Bool("json", false, "emit one schema-1 JSON record per line (alias of -jsonl)")
	_ = fs.Bool("jsonl", false, "emit one schema-1 JSON record per line")
	_ = fs.Bool("csv", false, "emit CSV rows (header line first)")
	_ = fs.Bool("urls", false, "emit scheme://host:port lines, one per target")
	_ = fs.Bool("text", false, "one human line per target (default format)")
	outFile := fs.String("o", "", "write results to file (default stdout)")
	quicOff := fs.Bool("quic-off", false, "skip the QUIC plane probe")
	resume := fs.Bool("resume", false, "resume an interrupted run from the WAL (<output basename>.wal next to -o)")
	// Congestion wiring (PQ-23): the §7.3 control surfaces reach the
	// pipeline through two flags — the token-bucket launch pace and the
	// AIMD window ceiling. Both defaults stay the pre-PQ-23 engine: rate
	// 0 = uncapped, window 1 = the sequential dispatch.
	rate := fs.Float64("rate", 0, "probe launches per second through the token-bucket limiter (0 = uncapped: the pre-congestion pace)")
	threads := fs.Int("threads", 1, "AIMD window ceiling: max target probes in flight (default 1 = the sequential engine)")
	if err := fs.Parse(args); err != nil {
		return 64
	}

	if *showVersion {
		fmt.Fprintf(stdout, "pqscan %s (pre-alpha; specification: docs/spec.md)\n", version)
		return 0
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

	format := chooseFormat(args)

	targets, code := composeTargets(*target, *listFile, args, stderr)
	if code != 0 {
		return code
	}
	if len(targets) == 0 {
		diag.Emit(diag.Warn, diag.DomEngine, "run", "", "no targets; run refuses", nil, nil)
		fmt.Fprintln(stderr, "pqscan: no target specified (use -u, -l, or -- for stdin; probe engines per the PQ-01 register)")
		return 64 // EX_USAGE
	}

	// The run journal rides beside the output file (<basename>.wal, PQ-16):
	// a fresh run truncates it, -resume replays it and scans only the
	// pending targets. -resume without -o has no journal path to read.
	walPath := ""
	if *outFile != "" {
		walPath = walPathFor(*outFile)
		if walPath == *outFile {
			diag.Emit(diag.Warn, diag.DomOutput, "wal", "", "output path collides with the journal path", nil,
				map[string]string{"file": *outFile})
			fmt.Fprintf(stderr, "pqscan: -o %s: the run journal rides beside the output as <basename>.wal; choose a different output name\n", *outFile)
			return 64
		}
	}
	completed := map[string]out.Record{}
	var walState wal.State
	if *resume {
		if walPath == "" {
			diag.Emit(diag.Warn, diag.DomOutput, "resume", "", "resume without an output file", nil, nil)
			fmt.Fprintln(stderr, "pqscan: -resume requires -o (the WAL lives next to the output file: <basename>.wal)")
			return 64
		}
		state, err := wal.Replay(walPath)
		switch {
		case err == nil:
			walState = state
			for key, rec := range state.Completed {
				completed[key] = rec
			}
		case os.IsNotExist(err):
			fmt.Fprintf(stderr, "pqscan: -resume: no WAL at %s yet; scanning every target\n", walPath)
			diag.Emit(diag.Info, diag.DomOutput, "resume", "", "no WAL; scanning every target", nil,
				map[string]string{"wal": walPath})
		default:
			diag.Emit(diag.Error, diag.DomOutput, "resume", "", "WAL replay failed", err,
				map[string]string{"wal": walPath})
			fmt.Fprintln(stderr, "pqscan:", err)
			return 1
		}
	}

	// pending = the composed targets the journal does not already hold.
	pending := make([]grammar.Target, 0, len(targets))
	for _, t := range targets {
		key := targetKey(t.Host, t.Port)
		if _, done := completed[key]; done {
			continue
		}
		pending = append(pending, t)
	}
	if *resume {
		if len(pending) == 0 {
			fmt.Fprintf(stderr, "pqscan: resume: WAL %s: all %d targets already complete; 0 targets to scan\n", walPath, len(targets))
			diag.Emit(diag.Info, diag.DomOutput, "resume", "", "nothing pending", nil,
				map[string]string{"wal": walPath, "completed": strconv.Itoa(len(targets))})
		} else {
			fmt.Fprintf(stderr, "pqscan: resume: WAL %s: %d of %d targets already complete; scanning %d\n",
				walPath, len(targets)-len(pending), len(targets), len(pending))
			diag.Emit(diag.Info, diag.DomOutput, "resume", "", "resuming from the WAL", nil,
				map[string]string{"wal": walPath,
					"completed": strconv.Itoa(len(targets) - len(pending)),
					"pending":   strconv.Itoa(len(pending))})
		}
	}

	// The journal opens BEFORE anything scans: a crash keeps every
	// completed target (fsync-batched appends; encoders never wait on it).
	var j *wal.Writer
	if walPath != "" {
		var err error
		runID := wal.NewRunID()
		if *resume {
			j, err = wal.Reopen(walPath, runID, walState.MaxSeq)
		} else {
			j, err = wal.Create(walPath, runID)
		}
		if err != nil {
			diag.Emit(diag.Error, diag.DomOutput, "wal", "", "journal open failed", err,
				map[string]string{"wal": walPath})
			fmt.Fprintln(stderr, "pqscan:", err)
			return 1
		}
		defer func() { _ = j.Close() }()
	}

	recs := []*scanRecord{}
	if len(pending) > 0 {
		scanned, err := (&Engine{}).Run(pending, Options{
			QuicOff:   *quicOff,
			Rate:      *rate,
			MaxWindow: *threads,
			Record: func(rec *scanRecord) {
				if j == nil {
					return
				}
				if err := j.Append(rec); err != nil {
					diag.Emit(diag.Error, diag.DomOutput, "wal", rec.Target.Host, "journal append failed", err, nil)
					fmt.Fprintf(stderr, "pqscan: wal: append failed: %v\n", err)
				}
			},
		}, func(done, total int) {
			fmt.Fprintf(stderr, "pqscan: progress: %d/%d targets scanned\n", done, total)
		})
		if err != nil {
			diag.Emit(diag.Error, diag.DomEngine, "run", "", "pipeline failed", err, nil)
			fmt.Fprintln(stderr, "pqscan:", err)
			return 1
		}
		recs = scanned
	}

	// Final record stream in composed order: fresh records for the scanned
	// targets, WAL payloads for the skipped ones (the journal holds their
	// records — "skip already-completed" never drops a record).
	final := recs
	if len(pending) != len(targets) {
		final = make([]*scanRecord, 0, len(targets))
		byKey := make(map[string]*scanRecord, len(recs))
		for _, r := range recs {
			byKey[targetKey(r.Target.Host, int(r.Target.Port))] = r
		}
		for _, t := range targets {
			key := targetKey(t.Host, t.Port)
			if r, ok := byKey[key]; ok {
				final = append(final, r)
				continue
			}
			if rec, ok := completed[key]; ok {
				r := rec
				final = append(final, &r)
				continue
			}
			diag.Emit(diag.Error, diag.DomEngine, "run", t.Input, "record missing after resume", nil, nil)
			fmt.Fprintln(stderr, "pqscan: internal: no record for target", t.Input)
			return 1
		}
	}

	// Encode (default text) into the output stream; stdout stays
	// results-only, progress/notes stream to stderr.
	var sink io.Writer = stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			diag.Emit(diag.Error, diag.DomOutput, "write", "", "output open failed", err,
				map[string]string{"file": *outFile})
			fmt.Fprintln(stderr, "pqscan:", err)
			return 1
		}
		defer f.Close() //nolint:errcheck
		sink = f
	}
	enc := out.NewEncoder(sink, format)
	for _, rec := range final {
		if err := enc.Encode(rec); err != nil {
			diag.Emit(diag.Error, diag.DomOutput, "encode", rec.Target.Host, "record encode failed", err, nil)
			fmt.Fprintln(stderr, "pqscan:", err)
			return 1
		}
		diag.Emit(diag.Info, diag.DomOutput, "emit", rec.Target.Host, "record emitted", nil,
			map[string]string{"format": format.String()})
	}
	return 0
}

func u32str(u uint32) string { return fmt.Sprint(u) }

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

// chooseFormat resolves the -json/-jsonl/-csv/-urls/-text selectors from
// the RAW command line: the last selector present wins (Go's flag.Visit
// walks flags lexically, not in command order). Anything after the bare
// "--" marker is stdin input, not a selector; a bare or "=true" selector
// selects and an explicit "=false" does not; the default is text.
func chooseFormat(args []string) out.Format {
	chosen := out.FormatText
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			if name[i+1:] == "false" {
				continue
			}
			name = name[:i]
		}
		switch name {
		case "json", "jsonl":
			chosen = out.FormatJSONL
		case "csv":
			chosen = out.FormatCSV
		case "urls":
			chosen = out.FormatURLs
		case "text":
			chosen = out.FormatText
		}
	}
	return chosen
}

// targetKey is the identity of one endpoint across the composition, the
// journal and the resume state: host:port (canonical bracketing for IPv6).
func targetKey(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// walPathFor derives the journal path beside -o (<basename>.wal, same
// directory); a no-extension output keeps the same stem.
func walPathFor(outFile string) string {
	base := filepath.Base(outFile)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	if stem == "" {
		stem = base // "-o .wal" journals in place
	}
	return filepath.Join(filepath.Dir(outFile), stem+".wal")
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
