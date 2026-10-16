package main

// flags.go is the CLI's single registration surface: newFlagSet builds
// the flag set run() parses AND the help/completion renderers read back
// — one flag table for every command-side rendering (PQ-38). The
// literal `fs.(Bool|String|Float64|Int)` call shapes stay: the
// CLI-surface drift gate greps them out of cmd/pqscan/*.go, and the
// help table's bidirectional pin (help_test) keeps this file's names
// and the rendered groups honest against the live flag set.

import (
	"flag"
	"io"
)

// flagVals carries the registered flags' value pointers, named as the
// run()-side locals so the body keeps reading *target, *rate, ... from
// the values run() binds locally.
type flagVals struct {
	ShowVersion *bool
	Debug       *bool
	DebugOut    *string
	Target      *string
	ListFile    *string
	HTTPX       *string
	Naabu       *string
	ShardSpec   *string
	JSON        *bool
	JSONL       *bool
	CSV         *bool
	URLs        *bool
	Text        *bool
	Explain     *bool
	OutFile     *string
	QuicOff     *bool
	QuicAlways  *bool
	Resume      *bool
	Rate        *float64
	Threads     *int
	Mode        *string
	DeepPlan    *string
	Ptr         *bool
	SNI         *string
	CertsDir    *string
	Completion  *string
}

// newFlagSet registers the whole implemented CLI surface in one place.
// The registration descs are the SINGLE source for both the -help
// rendering (help.go reads them straight off the flag set) and the
// completions (completion.go): the help table never duplicates text.
func newFlagSet() (*flag.FlagSet, flagVals) {
	fs := flag.NewFlagSet("pqscan", flag.ContinueOnError)
	v := flagVals{
		ShowVersion: fs.Bool("version", false, "print pqscan version and exit"),
		Debug:       fs.Bool("debug", false, "full diagnostics: human stream on stderr + machine report"),
		DebugOut:    fs.String("debug-out", "", "write the machine-parsable diagnostics report (schema 1) to this JSON file"),
		Target:      fs.String("u", "", "single target: host, host:port, or ip:port (composes with -l and --)"),
		ListFile:    fs.String("l", "", "read newline-separated target specs from this file (composes with -u and --; deduped by host:port)"),
		// PD-dialect input adapters (PQ-35/issue #80): the files' lines are
		// httpx/naabu output; internal/target strips the dialect decoration
		// and feeds the same grammar, so ONE composition — one dedupe —
		// serves every input source.
		HTTPX: fs.String("from-httpx", "", "read httpx-format input lines from this file (scheme://host:port with an optional URL path; composes with -u/-l/--; deduped by host:port)"),
		Naabu: fs.String("from-naabu", "", "read naabu-format input lines from this file (host:port lines, or a host line followed by bare-port lines; composes with -u/-l/--; deduped by host:port)"),
		// Multi-box partition (PQ-24/issue #47): -shard i/n names this box's
		// slice of the composed list — the deterministic fnv1a64(host:port)
		// % n == i-1 rule, so the n boxes' shards are disjoint and complete.
		ShardSpec: fs.String("shard", "", `scan only shard i of n (spec "i/n"; the composed targets filter to the shard's membership: a multi-box pass = disjoint, complete)`),
		// Output format selectors (spec §5.7): the LAST selector on the
		// command line wins and text is the absent-flag default —
		// chooseFormat resolves it. The five spellings register as real flags
		// (the USAGE <-> source drift gate reads them back from the flag set).
		JSON:    fs.Bool("json", false, "emit one schema-1 JSON record per line (alias of -jsonl)"),
		JSONL:   fs.Bool("jsonl", false, "emit one schema-1 JSON record per line"),
		CSV:     fs.Bool("csv", false, "emit CSV rows (header line first)"),
		URLs:    fs.Bool("urls", false, "emit scheme://host:port lines, one per target"),
		Text:    fs.Bool("text", false, "one human line per target (default format)"),
		Explain: fs.Bool("explain", false, "under each -text line, a plain-language reading of the record: the verdict in words, what the negotiated group/class means, the certificate and QUIC planes, an error-class hint when nothing negotiated (-text output only)"),
		OutFile: fs.String("o", "", "write results to file (default stdout)"),
		QuicOff: fs.Bool("quic-off", false, "skip the QUIC plane probe"),
		// PQ-25/-quic-always (issue #48, spec §5.3): the additive hint-gate
		// override — force the direct QUIC probe regardless of the alt-svc
		// hint; -quic-off keeps the highest precedence.
		QuicAlways: fs.Bool("quic-always", false, "run the direct QUIC probe regardless of Alt-Svc h3 hints (the hint gate's override)"),
		Resume:     fs.Bool("resume", false, "resume an interrupted run from the WAL (<output basename>.wal next to -o)"),
		// Congestion wiring (PQ-23): the §7.3 control surfaces reach the
		// pipeline through two flags — the token-bucket launch pace and the
		// AIMD window ceiling. Both defaults stay the pre-PQ-23 engine: rate
		// 0 = uncapped, window 1 = the sequential dispatch.
		Rate:    fs.Float64("rate", 0, "probe launches per second through the token-bucket limiter (0 = uncapped: the pre-congestion pace)"),
		Threads: fs.Int("threads", 1, "AIMD window ceiling: max target probes in flight (default 1 = the sequential engine)"),
		// Mode wiring (PQ-20/issue #43): -mode selects the per-target scan
		// mode and -deep the deep plan cap; the deep-mode record carries the
		// executed plan's deep block.
		Mode:     fs.String("mode", "fast", "scan mode: fast (default) | deep (the executed deep plan) | pq (the forced PQ ladder)"),
		DeepPlan: fs.String("deep", "standard", "deep-mode plan cap (-mode deep only): standard (default, <=24 probes/target) | full (the complete matrix)"),
		// Enrichment surfaces (PQ-26/issue #49): -ptr builds the run's
		// resolver pool (the system resolver, bounded: 4 workers, a 2s
		// budget, a 1024-entry LRU of positives) for IP targets' reverse
		// DNS; -sni selects the pool's strategy; -certs-dir names the PEM
		// export directory.
		Ptr:      fs.Bool("ptr", false, "PTR enrichment for IP targets: resolve reverse DNS pre-probe, SNI per -sni; the record carries ptr/sni_used"),
		SNI:      fs.String("sni", "auto", "SNI strategy for IP targets: auto (default) | ptr-then-ip | ip-only"),
		CertsDir: fs.String("certs-dir", "", "write each scanned host's end-entity certificate as PEM to <dir>/<host>.pem"),
		// PQ-40: the shell-completion emission (bash|zsh); the script
		// prints to stdout, the same surface table the help renders
		// generates it.
		Completion: fs.String("completion", "", "emit the shell completion script to stdout (bash | zsh); install one-liners ride the help and INSTALL.md"),
	}
	return fs, v
}

// wireFlagSetOutput points the flag set's parse-error stream at the
// caller's stderr (parse errors print the usage there; the help path
// prints to stdout through printHelp instead).
func wireFlagSetOutput(fs *flag.FlagSet, errW io.Writer) { fs.SetOutput(errW) }
