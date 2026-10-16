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
	"time"

	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/grammar"
	"github.com/shsingh/pqscan/internal/out"
	"github.com/shsingh/pqscan/internal/resolver"
	"github.com/shsingh/pqscan/internal/shard"
	"github.com/shsingh/pqscan/internal/wal"
)

// version carries the build's identity, stamped at build time by the
// release workflow via -ldflags "-X main.version=<tag>"; an unstamped
// source build prints the default revision. The diagnostics sink reads
// the same value (diag.SetBinaryVersion before it arms) so `-version`
// and the footer always agree.
var version = "0.0.1"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns the process exit code. The flag set is
// rebuilt per call so tests exercise the same path the process does
// (PQ-10). -debug arms the diagnostics sink (PQ-011). -u / -l / -- compose
// into one []grammar.Target list scanned by the multi-target pipeline
// (PQ-15): the PD-dialect adapter files -from-httpx/-from-naabu (PQ-35)
// join the same composition through internal/target — one grammar, one
// host:port dedupe, one record order. The output selectors
// (-json/-jsonl/-csv/-urls/-text)
// choose the encoder (PQ-16); -resume replays the run journal beside -o
// and scans only the pending targets.
func run(args []string, stdout, stderr io.Writer) int {
	// -h/-help is the help path (PQ-38): stdout, exit 0, decided from
	// the raw argv before the flag set parses (the scan stops at the
	// bare `--`, past which tokens are target data).
	if helpRequested(args) {
		printHelp(stdout)
		return 0
	}

	// One registration surface (flags.go): run() parses it, -help and
	// the completions render from it. The locals bind the same names
	// the body has always read.
	fs, vals := newFlagSet()
	wireFlagSetOutput(fs, stderr)
	showVersion, debug, debugOut := vals.ShowVersion, vals.Debug, vals.DebugOut
	target, listFile, httpxFile, naabuFile := vals.Target, vals.ListFile, vals.HTTPX, vals.Naabu
	shardSpec, outFile := vals.ShardSpec, vals.OutFile
	quicOff, quicAlways, resume := vals.QuicOff, vals.QuicAlways, vals.Resume
	rate, threads := vals.Rate, vals.Threads
	mode, deepPlan, ptr, sni, certsDir, explain := vals.Mode, vals.DeepPlan, vals.Ptr, vals.SNI, vals.CertsDir, vals.Explain
	if err := fs.Parse(args); err != nil {
		return 64
	}

	if *showVersion {
		fmt.Fprintf(stdout, "pqscan %s\n", version)
		return 0
	}

	// -completion (PQ-40): the meta emission, like -version — it wins
	// over the target composition; an unsupported shell is a usage
	// refusal naming the valid values.
	if comp := vals.Completion; comp != nil && *comp != "" {
		script, err := completionScript(*comp)
		if err != nil {
			diag.Emit(diag.Warn, diag.DomConfig, "run", "", "-completion refused", err,
				map[string]string{"shell": *comp})
			fmt.Fprintf(stderr, "pqscan: -completion: %v\n", err)
			return 64
		}
		fmt.Fprint(stdout, script)
		return 0
	}

	// arm diagnostics under -debug; everything below emits
	if *debug || *debugOut != "" {
		diag.SetBinaryVersion(version)
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

	// -explain is a text-presentation surface (PQ-38): under a machine
	// format it pollutes a schema-1/CSV/URL stream, so it is a
	// command-line mistake, refused before anything composes or scans.
	if *explain && format != out.FormatText {
		diag.Emit(diag.Warn, diag.DomOutput, "run", "", "-explain refused under a machine output format", nil,
			map[string]string{"format": format.String()})
		fmt.Fprintf(stderr, "pqscan: -explain applies to text output only (drop the -%s selector)\n", format.String())
		return 64
	}

	// Mode validation (PQ-20): bogus -mode/-deep values are usage-class
	// refusals before anything composes or scans (the offending value
	// named; exit 64).
	if !validMode(*mode) {
		diag.Emit(diag.Warn, diag.DomConfig, "run", "", "unknown -mode refused", nil,
			map[string]string{"mode": *mode})
		fmt.Fprintf(stderr, "pqscan: unknown -mode %q (want fast, deep, or pq)\n", *mode)
		return 64
	}
	if !validDeepPlan(*deepPlan) {
		diag.Emit(diag.Warn, diag.DomConfig, "run", "", "unknown -deep plan refused", nil,
			map[string]string{"deep": *deepPlan})
		fmt.Fprintf(stderr, "pqscan: unknown -deep plan %q (want standard or full)\n", *deepPlan)
		return 64
	}

	// Shard validation (PQ-24): the "i/n" grammar is a usage-class
	// refusal before anything composes (a bogus spec is a startup
	// mistake, like a bogus -mode).
	if *shardSpec != "" {
		if _, _, serr := shard.Spec(*shardSpec); serr != nil {
			diag.Emit(diag.Warn, diag.DomConfig, "run", "", "unknown -shard refused", serr,
				map[string]string{"shard": *shardSpec})
			fmt.Fprintf(stderr, "pqscan: -shard: %v\n", serr)
			return 64
		}
	}

	// Enrichment validation (PQ-26): unknown -sni strategies are
	// usage-class refusals — the pool would degrade silently (unknown
	// → auto), and the CLI refuses honestly instead.
	if !validSNIStrategy(*sni) {
		diag.Emit(diag.Warn, diag.DomConfig, "run", "", "unknown -sni refused", nil,
			map[string]string{"sni": *sni})
		fmt.Fprintf(stderr, "pqscan: unknown -sni %q (want auto, ptr-then-ip, or ip-only)\n", *sni)
		return 64
	}

	// The run's enrichment surfaces (PQ-26): the pool exists only under
	// -ptr (no flag → the pre-PQ-26 engine: no DNS touch, no fill); the
	// certs-dir exists before anything scans so every export succeeds.
	var ptrPool *resolver.Pool
	if *ptr {
		ptrPool = resolver.New(resolver.Options{
			Workers:     4,
			Timeout:     2 * time.Second,
			CacheSize:   1024,
			SNIStrategy: *sni,
		})
	}
	if *certsDir != "" {
		if err := os.MkdirAll(*certsDir, 0o755); err != nil {
			diag.Emit(diag.Error, diag.DomOutput, "certs-dir", "", "directory create failed", err,
				map[string]string{"dir": *certsDir})
			fmt.Fprintf(stderr, "pqscan: -certs-dir %s: %v\n", *certsDir, err)
			return 1
		}
	}

	targets, code := composeTargets(*target, *listFile, *httpxFile, *naabuFile, args, stderr)
	if code != 0 {
		return code
	}
	if len(targets) == 0 {
		diag.Emit(diag.Warn, diag.DomEngine, "run", "", "no targets; run refuses", nil, nil)
		fmt.Fprintln(stderr, "pqscan: no target specified (use -u TARGET, -l FILE, or -- for stdin; -h shows examples)")
		return 64 // EX_USAGE
	}

	// -shard i/n (PQ-24): the composed list FILTERS to the shard's
	// membership — deterministic FNV-1a over the target key, so a target
	// always lands in the same shard at a fixed total, and the n shards
	// over one list are a partition (disjoint + complete): a multi-box
	// pass covers the input with no target scanned twice. The box notes
	// its slice on stderr; an empty member set is a degenerate shard —
	// the honestly-empty run (nothing to scan, nothing invented).
	if *shardSpec != "" {
		shardIdx, shardTotal, _ := shard.Spec(*shardSpec) // validated above
		keys := make([]shard.TargetKey, 0, len(targets))
		for _, t := range targets {
			keys = append(keys, targetKey(t.Host, t.Port))
		}
		members := shard.Assign(keys, shardIdx, shardTotal)
		member := make(map[shard.TargetKey]bool, len(members))
		for _, k := range members {
			member[k] = true
		}
		shardTargets := make([]grammar.Target, 0, len(members))
		for i, t := range targets {
			if member[keys[i]] {
				shardTargets = append(shardTargets, t)
			}
		}
		fmt.Fprintf(stderr, "pqscan: shard %d/%d: %d of %d targets\n",
			shardIdx, shardTotal, len(shardTargets), len(targets))
		diag.Emit(diag.Info, diag.DomEngine, "shard", "", "targets filtered to the shard's membership", nil,
			map[string]string{"shard": fmt.Sprintf("%d/%d", shardIdx, shardTotal),
				"members": strconv.Itoa(len(shardTargets)), "composed": strconv.Itoa(len(targets))})
		targets = shardTargets
		if len(targets) == 0 {
			return 0
		}
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
			QuicOff:    *quicOff,
			QuicAlways: *quicAlways,
			Rate:       *rate,
			MaxWindow:  *threads,
			Mode:       *mode,
			DeepPlan:   *deepPlan,
			PtrPool:    ptrPool,
			CertsDir:   *certsDir,
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
	enc := out.NewEncoder(sink, format, explainOptions(*explain)...)
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

// validSNIStrategy reports whether s is a defined -sni strategy value
// (PQ-26: the resolver package's three; unknown values degrade to auto
// inside the pool, so the CLI refuses them honestly instead).
func validSNIStrategy(s string) bool {
	switch s {
	case resolver.StrategyAuto, resolver.StrategyPTRThenIP, resolver.StrategyIPOnly:
		return true
	default:
		return false
	}
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

// explainOptions renders the -explain flag into the encoder's option
// list (PQ-38). The option is honored when the explain renderer lands;
// until then the machine and text streams are identical either way.
func explainOptions(on bool) []out.EncoderOption {
	if on {
		return []out.EncoderOption{out.WithExplain()}
	}
	return nil
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
