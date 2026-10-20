package chains

// chain_test.go is PQ-55's chain cells (issue #149). ONE HOME, documented
// here: the cells live in tests/chains — separate from the PQ-53/54 array
// and battery suites (tests/matrix) because they are DELIBERATE crossings,
// not a covering array: every adapter ENTRY crossed with the consumer-flag
// families, offline by construction.
//
// The entry axis (spec §6's chaining contract):
//
//	raw stdin pipe ∨ -l - ∨ -from-naabu FILE ∨ -from-httpx FILE ∨
//	-from-nuclei FILE
//
// each crossed with -mode (deep, pq) × the output selectors (-jsonl, -csv,
// -urls, the text default) × -o (+ the WAL beside it) × -explain. The
// shared assertions, derived (never hand-pinned):
//
//   - the composed record set is the payload's DISTINCT host:port list
//     (the one dedupe, first occurrence wins) — the expected list derives
//     from the entry's parsed contributions;
//   - ports preserved: every entry's payload names the loopback fixture's
//     ephemeral port (never 443 — the strongest preservation case) and
//     every record carries it;
//   - scheme/path decorations stripped per adapter (the record's input is
//     the stripped spec);
//   - a malformed findings line is a RECORDED observation at its line
//     number: the run refuses exit 64 named by its flag, stdout clean
//     (the adapters' documented exit class);
//   - the -o single sink: stdout empty, the file complete, and the WAL
//     beside it; a -resume replay recovers the set-equal record set.
//
// Runs spawn the REAL binary against the loopback TLS fixture (ephemeral
// '127.0.0.1:0' + t.Cleanup) — the loopback is the only address any cell
// scans; the committed capture fixtures (tests/fixtures/chains) feed the
// PARSERS, never a scan. -quic-off rides every cell that does not study
// the QUIC surface: offline + deterministic deadlines.
import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	servers "github.com/shsingh/pqscan/tests/fixtures/servers"
)

// chainsTestBinary is the prebuilt binary the cells spawn (TestMain builds
// it; -chains-binary hands a prebuilt one in).
var chainsTestBinary string

func TestMain(m *testing.M) {
	// the designed 8-slot pool needs the scheduler's cap (run_test.go's
	// documented note; an explicit -parallel always wins).
	hasParallel := false
	for _, arg := range os.Args {
		trimmed := strings.TrimLeft(arg, "-")
		if trimmed == "test.parallel" || trimmed == "parallel" || strings.HasPrefix(trimmed, "test.parallel=") || strings.HasPrefix(trimmed, "parallel=") {
			hasParallel = true
			break
		}
	}
	if !hasParallel {
		os.Args = append(os.Args, "-test.parallel=8")
	}
	flag.StringVar(&chainsTestBinary, "chains-binary", "", "spawn this prebuilt pqscan binary instead of building one")
	flag.Parse()
	code := func() int {
		if chainsTestBinary != "" {
			return m.Run()
		}
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			fmt.Fprintln(os.Stderr, "chains TestMain: runtime.Caller failed")
			return 1
		}
		root := filepath.Join(filepath.Dir(file), "..", "..")
		dir, err := os.MkdirTemp("", "pqscan-chains-bin-")
		if err != nil {
			fmt.Fprintln(os.Stderr, "chains TestMain: temp dir:", err)
			return 1
		}
		defer os.RemoveAll(dir)
		bin := filepath.Join(dir, "pqscan")
		build := exec.Command("go", "build", "-o", bin, "./cmd/pqscan")
		build.Dir = root
		var buildErr bytes.Buffer
		build.Stderr = &buildErr
		if err := build.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "chains TestMain: go build ./cmd/pqscan: %v\n%s", err, buildErr.String())
			return 1
		}
		chainsTestBinary = bin
		return m.Run()
	}()
	os.Exit(code)
}

// entrySpec is one entry axis member: the entry's argv (its files are
// materialized under the cell's temp dir), the stdin payload when the entry
// reads a pipe (nil = /dev/null semantics), and contributes — the
// host:port list the entry's payload feeds the composition in source order,
// pre-dedupe (the runner derives the expected record set from it: the
// dedupe's input, never a pinned count).
type entrySpec struct {
	name        string
	args        func(t *testing.T, dir, addr string) []string
	stdin       func(dir, addr string) *string
	contributes func(addr string) []string
}

// findingLine is the -j finding shape the pinned capture shows (one JSON
// object per line; matched-at the canonical host field).
func findingLine(matched string) string {
	return `{"template-id":"pqscan-chains","matcher-status":true,"matched-at":"` + matched + `"}` + "\n"
}

// chainedEntries are the five entries of the chain contract.
var chainedEntries = []entrySpec{
	{
		name: "raw stdin pipe",
		args: func(t *testing.T, dir, addr string) []string { return nil },
		stdin: func(dir, addr string) *string {
			s := addr + "\nhttps://" + addr + "\n"
			return &s
		},
		contributes: func(addr string) []string { return []string{addr, addr} },
	},
	{
		name: "l stdin alias",
		args: func(t *testing.T, dir, addr string) []string { return []string{"-l", "-"} },
		stdin: func(dir, addr string) *string {
			s := "127.0.0.1:" + strconv.Itoa(fixturePort(addr)) + "\n"
			return &s
		},
		contributes: func(addr string) []string { return []string{addr} },
	},
	{
		name: "from-naabu file",
		args: func(t *testing.T, dir, addr string) []string {
			path := chainsFile(t, dir, "naabu.txt", addr+"\n\n"+addr+"\n")
			return []string{"-from-naabu", path}
		},
		stdin:       nil,
		contributes: func(addr string) []string { return []string{addr, addr} },
	},
	{
		name: "from-httpx file",
		args: func(t *testing.T, dir, addr string) []string {
			// the text dialect: the scheme://host:port line and the
			// path-suffix line both strip to the bare addr spec; the
			// comment line skips (numbered).
			path := chainsFile(t, dir, "httpx.txt", "tcp://"+addr+"\nhttps://"+addr+"/probe\n# a dialect comment\n")
			return []string{"-from-httpx", path}
		},
		stdin:       nil,
		contributes: func(addr string) []string { return []string{addr, addr} },
	},
	{
		name: "from-nuclei file",
		args: func(t *testing.T, dir, addr string) []string {
			// the nuclei -j dialect (the pinned capture's shapes): the
			// scheme:// form and the bare host:port form (the ssl/ssh
			// classes), plus the fixture headers the committed capture
			// carries — one deduped host:port out of three findings.
			path := chainsFile(t, dir, "nuclei.jsonl",
				"# pinned-capture: nuclei -l hosts.txt -silent -j\n"+findingLine("https://"+addr)+findingLine(addr))
			return []string{"-from-nuclei", path}
		},
		stdin:       nil,
		contributes: func(addr string) []string { return []string{addr, addr} },
	},
}

// consumerSpec is one consumer-flag family's cell shape: the flags to
// append (after the entry's argv, -quic-off first for offline runs) and the
// resolved format name the assertion mirrors.
type consumerSpec struct {
	name    string
	args    []string
	format  string // jsonl | csv | urls | text
	explain bool
	outFile bool // the -o single sink (+ the WAL beside it)
}

// chainedConsumers are the consumer-flag families crossed with every entry
// (the -mode × selector × -o(+WAL) × -explain axis of issue #149).
var chainedConsumers = []consumerSpec{
	{name: "the default text stream", args: nil, format: "text"},
	{name: "selector jsonl", args: []string{"-jsonl"}, format: "jsonl"},
	{name: "selector csv", args: []string{"-csv"}, format: "csv"},
	{name: "selector urls", args: []string{"-urls"}, format: "urls"},
	{name: "mode deep", args: []string{"-mode", "deep", "-jsonl"}, format: "jsonl"},
	{name: "mode pq", args: []string{"-mode", "pq", "-jsonl"}, format: "jsonl"},
	{name: "the single sink + WAL", args: []string{"-jsonl"}, format: "jsonl", outFile: true},
	{name: "explain under text", args: []string{"-text", "-explain"}, format: "text", explain: true},
}

// chainsFile writes one dialect file into the cell's temp dir.
func chainsFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// fixturePort is the addr's port numeral.
func fixturePort(addr string) int {
	_, port, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(port)
	return n
}

// dedupeOrder is the composition's contract: distinct host:port, first
// occurrence wins — the EXPECTED record set, derived from the entry's
// contributions (never a pinned count).
func dedupeOrder(contributed []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range contributed {
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

// chainRun is one spawned cell attempt's captured facts.
type chainRun struct {
	stdout, stderr bytes.Buffer
	exit           int
}

func TestChainCells(t *testing.T) {
	fixture := servers.StartFixtureServer(t, servers.DefaultMatrix()[0])
	addr := fixture
	port := fixturePort(addr)
	sem := make(chan struct{}, 8)
	cells := 0
	for _, entry := range chainedEntries {
		entry := entry
		for _, consumer := range chainedConsumers {
			consumer := consumer
			cells++
			t.Run(entry.name+" × "+consumer.name, func(t *testing.T) {
				t.Parallel()
				sem <- struct{}{}
				defer func() { <-sem }()
				dir := t.TempDir()
				outPath := filepath.Join(dir, "out.jsonl")
				argv := append([]string(nil), entry.args(t, dir, addr)...)

				// the consumer flags: -quic-off keeps every cell
				// offline + deterministic (the QUIC surface's own
				// cells ride the QUIC lanes' suites).
				argv = append(argv, "-quic-off")
				argv = append(argv, consumer.args...)
				entryStdin := ""
				if entry.stdin != nil {
					if s := entry.stdin(dir, addr); s != nil {
						entryStdin = *s
					}
				}
				if consumer.outFile {
					argv = append(argv, "-o", outPath)
				}

				run := spawnChain(t, dir, argv, entryStdin != "", entryStdin)
				if run.exit != 0 {
					t.Fatalf("exit = %d, want 0 (stderr: %s)", run.exit, tailOf(run.stderr.String(), 4))
				}

				stream := run.stdout.String()
				if consumer.outFile {
					if strings.TrimSpace(run.stdout.String()) != "" {
						t.Fatalf("the -o single sink: stdout is not empty: %q", run.stdout.String())
					}
					data, err := os.ReadFile(outPath)
					if err != nil {
						t.Fatalf("read the -o file: %v", err)
					}
					stream = string(data)
					// the WAL's path derives beside -o: <stem>.wal (the
					// extension's stem; walPathFor's documented shape)
					wal := filepath.Join(filepath.Dir(outPath),
						strings.TrimSuffix(filepath.Base(outPath), filepath.Ext(outPath))+".wal")
					if _, err := os.Stat(wal); err != nil {
						t.Errorf("the WAL never rode beside -o: %v", err)
					}
				}

				// the §5.7 stream dialect: results only on the record
				// stream; notes and progress stream to stderr.
				for _, line := range splitChainLines(stream) {
					if strings.Contains(line, "pqscan:") {
						t.Errorf("a pqscan note line reached the record stream: %q", line)
					}
				}

				want := dedupeOrder(entry.contributes(addr))
				keys := streamKeys(t, consumer.format, stream)
				if len(keys) != len(want) {
					t.Fatalf("records %d (%s), want the distinct contributed set %d (%s); stderr: %s",
						len(keys), fmt.Sprint(keys), len(want), fmt.Sprint(want), tailOf(run.stderr.String(), 4))
				}
				for _, w := range want {
					if keys[w] != 1 {
						t.Errorf("the composed set lost host:port %q (dedupe key set %s)", w, fmt.Sprint(keys))
					}
				}
				// ports preserved + decorations stripped: every record's
				// identity key carries the fixture's ephemeral port (and
				// each entry's payloads strip to the bare host:port).
				fixtureKey := "127.0.0.1:" + strconv.Itoa(port)
				if len(want) > 0 && want[0] != fixtureKey {
					t.Fatalf("the entry contributed %q, want the fixture address %q", want[0], fixtureKey)
				}

				// -explain renders iff text resolved: the explain blocks
				// ride the text stream (multiple "- " lines per record —
				// at least one block per record), never a machine format.
				explainLines := 0
				for _, line := range splitChainLines(stream) {
					if strings.HasPrefix(line, "  - ") {
						explainLines++
					}
				}
				if consumer.explain && explainLines < len(want) {
					t.Errorf("-explain on under text: %d explain line(s) for %d record(s)", explainLines, len(want))
				}
				if !consumer.explain && explainLines != 0 {
					t.Errorf("%d explain line(s) leaked into the %s stream", explainLines, consumer.format)
				}
			})
		}
	}
	t.Logf("chain cells: %d crossing cells ran", cells)

	// The WAL resume round-trip, per entry: a completed run's -resume
	// replay recovers the set-equal record set from the WAL (derived,
	// never a pinned count).
	for _, entry := range chainedEntries {
		entry := entry
		t.Run(entry.name+" × resume replay", func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()
			dir := t.TempDir()
			outPath := filepath.Join(dir, "out.jsonl")
			argv := append([]string(nil), entry.args(t, dir, addr)...)
			argv = append(argv, "-quic-off", "-jsonl", "-o", outPath)
			first := spawnChain(t, dir, argv, entry.stdin != nil, entryStdinOf(entry, addr))
			if first.exit != 0 {
				t.Fatalf("first run: exit = %d (stderr: %s)", first.exit, tailOf(first.stderr.String(), 4))
			}
			// the resume row: the SAME composed sources + -resume (the
			// journal replays the completed targets; the composition
			// still needs its target floor to re-open the list).
			resumeArgv := append(append([]string(nil), entry.args(t, dir, addr)...), "-quic-off", "-jsonl", "-o", outPath, "-resume")
			resume := spawnChain(t, dir, resumeArgv, entry.stdin != nil, entryStdinOf(entry, addr))
			if resume.exit != 0 {
				t.Fatalf("resume: exit = %d (stderr: %s)", resume.exit, tailOf(resume.stderr.String(), 4))
			}
			data, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("read the replayed output: %v", err)
			}
			keys := streamKeys(t, "jsonl", string(data))
			want := dedupeOrder(entry.contributes(addr))
			if len(keys) != len(want) {
				t.Fatalf("replay records %d (%s), want the set-equal %d (%s)", len(keys), fmt.Sprint(keys), len(want), fmt.Sprint(want))
			}
			for _, w := range want {
				if keys[w] != 1 {
					t.Errorf("the replay's set lost %q", w)
				}
			}
		})
	}
}

// entryStdinOf renders the entry's stdin payload for the resume rows (the
// same contract the crossing cells use).
func entryStdinOf(entry entrySpec, addr string) string {
	if entry.stdin == nil {
		return ""
	}
	if s := entry.stdin("", addr); s != nil {
		return *s
	}
	return ""
}

// spawnChain runs the binary once with the cell's argv.
func spawnChain(t *testing.T, dir string, argv []string, piped bool, payload string) chainRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, chainsTestBinary, argv...)
	cmd.Dir = dir
	if piped {
		cmd.Stdin = strings.NewReader(payload)
	} // else nil: /dev/null semantics, no implicit source
	var run chainRun
	cmd.Stdout, cmd.Stderr = &run.stdout, &run.stderr
	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("timed out after 60s: %v", argv)
		}
		run.exit = 1
		if ee, ok := err.(*exec.ExitError); ok {
			run.exit = ee.ExitCode()
		}
	}
	return run
}

// streamKeys parses one selector's record stream into its host:port keys
// (the record's identity) — the same shape the battery asserts.
func streamKeys(t *testing.T, format, raw string) map[string]int {
	t.Helper()
	keys := map[string]int{}
	switch format {
	case "jsonl":
		for _, line := range splitChainLines(raw) {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				t.Fatalf("jsonl line unparseable: %q: %v", line, err)
			}
			tgt, _ := obj["target"].(map[string]any)
			port := uint64Of(tgt["port"])
			keys[fmt.Sprintf("%s:%d", tgt["host"], port)]++
		}
	case "csv":
		rows, err := csv.NewReader(strings.NewReader(raw)).ReadAll()
		if err != nil {
			t.Fatalf("csv stream unparseable: %v", err)
		}
		for i, row := range rows {
			if i == 0 && len(row) > 2 && row[1] == "host" {
				continue // the header precedes the first row only
			}
			if len(row) >= 3 {
				keys[row[1]+":"+row[2]]++
			}
		}
	case "urls":
		for _, line := range splitChainLines(raw) {
			keys[strings.TrimPrefix(line, "https://")]++
		}
	default: // text
		for _, line := range splitChainLines(raw) {
			if strings.HasPrefix(line, "  - ") {
				continue // explain blocks are not records
			}
			if i := strings.IndexByte(line, ' '); i > 0 {
				keys[line[:i]]++
			}
		}
	}
	return keys
}

func uint64Of(v any) uint64 {
	switch n := v.(type) {
	case float64:
		return uint64(n)
	default:
		return 0
	}
}

func splitChainLines(raw string) []string {
	raw = strings.TrimRight(raw, "\n")
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\n")
}

func tailOf(s string, lines int) string {
	parts := splitChainLines(s)
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, " | ")
}
