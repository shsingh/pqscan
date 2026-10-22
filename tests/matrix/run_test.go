package matrix

// run_test.go is the flag-matrix's executor (PQ-53): for every checked-in
// case in tests/matrix/cases.jsonl it spawns the REAL binary against the
// real loopback TLS fixture (tests/fixtures/servers — StartFixtureServer,
// ephemeral '127.0.0.1:0' + t.Cleanup always), captures stdout/stderr to a
// per-case buffer + files, and asserts the L0-adjacent invariants that ride
// the array runner from day one (the FULL L0 battery is PQ-54's lane):
//
//  1. the documented exit code — every array case is valid by construction
//     (the generator enforces the prereq/conflict classes), so the run is
//     the documented exit-0 class ("scan completed, empty or not", USAGE
//     EXIT STATUS); an exit-64 refusal in a case is a generation bug;
//  2. stdout carries the selector's records ONLY (one schema-1 JSON object
//     per line for the JSONL format, header+rows for CSV, scheme://host:port
//     lines for URLs, one record line per target for text) — and never any
//     progress line (progress/notes are stderr-side, the §5.7 dialect rule);
//  3. -explain renders iff (resolved text ∧ -explain on): the explain
//     blocks ride the text stream; under a machine format they never appear
//     (and the record's verdict tail pq=<label>(<score>) still rides);
//  4. no case ever invents a target: the runner binds the fixture's
//     addr:port as -u on EVERY case (targets ride the fixture plumbing,
//     recorded in the per-case run log), the $TARGET/@tmp placeholders
//     expand per case, and the record set matches the composed-then-
//     shard-filtered target count — 1 for every non-shard case, 0-or-1
//     behind the array's -shard spell, computed with the REAL
//     internal/shard assignment (never re-hashed here).
//
// Binary choice, documented: TestMain builds ONE dedicated binary
// (-matrix-binary overrides it for callers carrying a prebuilt one) and
// every case spawns it — 'go run' would recompile per case and blow the
// suite's wall-time budget. Cases run t.Parallel behind a bounded (8-slot)
// worker pool. The suite's budget is 60s; if exceeded, shrink the case
// count through the array, never the invariants.
//
// The fixture set: DefaultMatrix()'s t13-hybrid-mlkem row, bound ONCE per
// run (the array varies the FLAG dialect, not the server posture — the
// per-mode probe truth is PQ-54's lane).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/shard"
	servers "github.com/shsingh/pqscan/tests/fixtures/servers"
)

// binaryPath is the prebuilt binary the cases spawn (TestMain builds it;
// -matrix-binary hands a prebuilt one in instead).
var binaryPath string

func TestMain(m *testing.M) {
	// The suite's designed 8-slot parallel pool also needs the testing
	// SCHEDULER's cap at 8: t.Parallel resumes up to -parallel
	// (= GOMAXPROCS by default), and on a 4-core CI runner that quietly
	// halves the pool — the PQ-54 battery's budget caught it (the battery
	// ran 4-way for 186s where the pool intends ~90s). Raise the cap to
	// the pool when the operator did not set a parallelism themselves;
	// an explicit -parallel/-test.parallel always wins.
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
	flag.StringVar(&binaryPath, "matrix-binary", "", "spawn this prebuilt pqscan binary instead of building one")
	flag.Parse()
	code := func() int {
		if binaryPath != "" {
			return m.Run()
		}
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			fmt.Fprintln(os.Stderr, "matrix TestMain: runtime.Caller failed")
			return 1
		}
		root := filepath.Join(filepath.Dir(file), "..", "..")
		dir, err := os.MkdirTemp("", "pqscan-matrix-bin-")
		if err != nil {
			fmt.Fprintf(os.Stderr, "matrix TestMain: temp dir: %v", err)
			return 1
		}
		defer os.RemoveAll(dir)
		bin := filepath.Join(dir, "pqscan")
		build := exec.Command("go", "build", "-o", bin, "./cmd/pqscan")
		build.Dir = root
		var buildErr bytes.Buffer
		build.Stderr = &buildErr
		if err := build.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "matrix TestMain: go build ./cmd/pqscan: %v\n%s", err, buildErr.String())
			return 1
		}
		binaryPath = bin
		return m.Run()
	}()
	os.Exit(code)
}

// runnerPoolSize bounds the concurrent case subprocesses (the 8-worker
// pool) regardless of GOMAXPROCS.
const runnerPoolSize = 8

// caseTimeout caps one case's run. PQ-69 recalibration (measured 2026-10
// cycle): the -quic-always cases now carry the gate-on plan's QUIC
// rungs (the PQ-69 pair grows the gate-on ladder to 8 rungs in full
// mode), so a UDP-blocked case runs ~50s of clock-bound dial timeouts
// over the 8s probe budget; the 45s cap timed three cases out. 75s =
// the measured wall + headroom; a plan growth recalibrates this budget,
// never the result invariants it guards.
const caseTimeout = 75 * time.Second

// attempt is the per-case summary the report prints as the audit table.
type attempt struct {
	id      string
	records int
	wall    time.Duration
	format  string
}

// matrixAttempts + matrixRunStart carry the executor's results to the
// report: the parallel subtests pause before their bodies run, so the
// accounting belongs in a LATER serial test (t.Run calls in the parent
// return while the parallel children are still queued; a test function
// after TestFlagMatrixRun runs only after every child joined).
var (
	matrixAttempts   []attempt
	matrixAttemptsMu sync.Mutex
	matrixRunStart   time.Time
)

func TestFlagMatrixRun(t *testing.T) {
	root := matrixRoot(t)
	doc := loadDomains(t, root)
	cases := loadCases(t, root)
	params := arrayParams(doc)

	// The fixture plumbing: one loopback TLS row, the t13 hybrid, bound
	// once for the whole run; every case targets it (the runner's
	// unconditional -u, recorded in the per-case run log).
	addr := servers.StartFixtureServer(t, servers.DefaultMatrix()[0])
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("fixture addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("fixture port: %v", err)
	}
	// the array's shard spell, read out of the domain table (never
	// hand-pinned here): the 'slice' value's spelling "-shard 1/2"
	shardSpell := ""
	for _, p := range params {
		if p.ID == "shard" {
			for _, v := range p.Domain {
				if v != p.Default {
					shardSpell = p.Spell[v]
				}
			}
		}
	}
	if shardSpell == "" {
		t.Fatal("the domain table's shard parameter carries no non-default slice spelling")
	}

	sem := make(chan struct{}, runnerPoolSize)
	matrixRunStart = time.Now()
	attemptsMu := &matrixAttemptsMu

	for i := range cases {
		c := cases[i]
		t.Run(c.ID, func(t *testing.T) {
			t.Parallel()
			sem <- struct{}{}
			defer func() { <-sem }()
			caseStart := time.Now()

			// per-case workspace: every file the case touches is born and
			// dies inside it (t.TempDir cleans up after the case)
			dir := t.TempDir()
			stamp := func(name string) string { return filepath.Join(dir, name) }

			// the placeholder expansion: the target spec and the
			// materialized per-case files (list file: the fixture target
			// line; adapter files: their own dialect's line) — the shared
			// materializer (harness_test.go)
			argv := make([]string, 0, len(c.Args)+2)
			argv = append(argv, "-u", addr) // the runner's unconditional -u
			for _, tok := range c.Args {
				argv = append(argv, materializeToken(t, c.ID, dir, addr, tok))
			}
			stdin := strings.ReplaceAll(c.Stdin, "$TARGET", addr)

			ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, binaryPath, argv...)
			cmd.Dir = dir
			cmd.Stdin = strings.NewReader(stdin)
			var stdout, stderr bytes.Buffer
			stdoutCap, err := os.Create(stamp("stdout.txt"))
			if err != nil {
				t.Fatalf("stdout capture: %v", err)
			}
			stderrCap, err := os.Create(stamp("stderr.txt"))
			if err != nil {
				t.Fatalf("stderr capture: %v", err)
			}
			cmd.Stdout = io.MultiWriter(&stdout, stdoutCap)
			cmd.Stderr = io.MultiWriter(&stderr, stderrCap)

			runErr := cmd.Run()
			wall := time.Since(caseStart)
			exitCode := 0
			if runErr != nil {
				exitError, isExit := runErr.(*exec.ExitError)
				isTimeout := ctx.Err() == context.DeadlineExceeded
				if !isExit {
					t.Fatalf("case %s: run: %v", c.ID, runErr)
				}
				if isTimeout {
					t.Fatalf("case %s: timed out after %s", c.ID, caseTimeout)
				}
				if exitError.ExitCode() > 0 {
					// a refusal or a failure is not the documented exit for
					// a valid-by-construction row
					t.Fatalf("case %s: exit %d, want 0 (a valid row never refuses); stderr tail:\n%s",
						c.ID, exitError.ExitCode(), tail(stderr.String(), 6))
				}
				exitCode = exitError.ExitCode()
			}

			// the per-case run log: the argv (with the injected -u), the
			// stdin payload, the exit code and the wall — what actually ran
			logLine := fmt.Sprintf("case=%s argv=%q stdin=%q fixture=%s exit=%d wall=%s\n",
				c.ID, argv, stdin, addr, exitCode, wall.Truncate(time.Millisecond))
			if err := os.WriteFile(stamp("run.log"), []byte(logLine), 0o644); err != nil {
				t.Errorf("case %s: run log: %v", c.ID, err)
			}

			// invariant 1: the documented exit code
			if exitCode != 0 {
				t.Errorf("case %s: exit %d", c.ID, exitCode)
			}

			// the case's assignment + the resolved format
			assign := parseCaseArgs(t, c, params)
			resolved := mirrorFormat(c.Args)

			// invariant 4's guard: the runner's injection rode the case
			if len(argv) < 2 || argv[0] != "-u" || argv[1] != addr {
				t.Errorf("case %s: the runner's -u injection missing from argv %q", c.ID, argv)
			}

			// the composed-then-shard-filtered target count, computed with
			// the real shard package: the composition carries exactly the
			// fixture endpoint (every source line is the same host:port;
			// the composition dedupes by host:port)
			composed := []shard.TargetKey{net.JoinHostPort(host, portStr)}
			shardIndex, shardTotal := 1, 1
			if assign["shard"] == "slice" {
				fields := strings.Fields(shardSpell)
				if len(fields) != 2 || fields[0] != "-shard" {
					t.Fatalf("the shard spell in domains.json is not '-shard <i/n>': %q", shardSpell)
				}
				shardIndex, shardTotal, err = shard.Spec(fields[1])
				if err != nil {
					t.Fatalf("the array's shard spell %q: %v", fields[1], err)
				}
			}
			expected := len(shard.Assign(composed, shardIndex, shardTotal))

			streamRaw := stdout.String()
			if assign["o"] == "file" {
				data, readErr := os.ReadFile(stamp("out.txt"))
				switch {
				case readErr == nil:
					streamRaw = string(data)
					if strings.TrimSpace(stdout.String()) != "" {
						t.Errorf("case %s: -o set but stdout is not empty (the single-sink contract)", c.ID)
					}
				case os.IsNotExist(readErr) && expected == 0:
					// the honestly-empty run (the shard's membership excluded
					// the sole target): nothing scanned, the sink never
					// opened — the documented exit-0 empty run
					streamRaw = ""
				default:
					t.Fatalf("case %s: -o set: read the output file: %v", c.ID, readErr)
				}
			}

			// invariant 2: stdout = the selector's records only, never a
			// progress line (the §5.7 dialect rules)
			for _, line := range splitLines(stdout.String()) {
				if strings.Contains(line, "pqscan: progress:") {
					t.Errorf("case %s: progress line on stdout: %q", c.ID, first80(line))
				}
				if strings.HasPrefix(line, "pqscan:") {
					t.Errorf("case %s: a pqscan note line reached stdout: %q", c.ID, first80(line))
				}
			}

			// invariants 2-4: the records-only parse + explain-iff-text
			assertStream(t, c.ID, resolved, assign, host, port, expected, streamRaw)

			// the certs-dir's export: the flag's own documented effect (a
			// scanned host gets its PEM; the honestly-empty run exports none)
			if assign["certs-dir"] == "set" && expected > 0 {
				if _, statErr := os.Stat(stamp(filepath.Join("certs", "127.0.0.1.pem"))); statErr != nil {
					t.Errorf("case %s: -certs-dir set but 127.0.0.1.pem missing: %v", c.ID, statErr)
				}
			}

			attemptsMu.Lock()
			matrixAttempts = append(matrixAttempts, attempt{id: c.ID, records: expected, wall: wall, format: resolved})
			attemptsMu.Unlock()
		})
	}
}

// TestFlagMatrixReport prints the executor's audit table + the suite's
// wall-time accounting: it runs strictly after every parallel case of
// TestFlagMatrixRun joined (serial test order), so the numbers are real.
func TestFlagMatrixReport(t *testing.T) {
	matrixAttemptsMu.Lock()
	rows := matrixAttempts
	matrixAttempts = nil
	matrixAttemptsMu.Unlock()
	wall := time.Since(matrixRunStart)

	sort.Slice(rows, func(a, b int) bool { return rows[a].id < rows[b].id })
	for _, a := range rows {
		t.Logf("%s  fmt=%-5s exit=0 records=%d wall=%s", a.id, a.format, a.records, a.wall.Truncate(time.Millisecond))
	}
	if len(rows) == 0 {
		t.Fatal("the report's attempt table is empty: TestFlagMatrixRun collected no cases")
	}
	t.Logf("flag-matrix suite: %d cases over one loopback fixture, wall %.2fs (budget 60s)", len(rows), wall.Seconds())
	if wall > 60*time.Second {
		t.Errorf("suite wall %.2fs exceeded the 60s budget: shrink the case count through the array, never the invariants", wall.Seconds())
	}
}

// assertStream is invariant 2 + 3, the records-only contract: the parse
// shape per resolved format against the (shard-filtered) expected count,
// and the explain-iff-text rule in both directions. The stream is the -o
// file's bytes when -o set (the single sink), else stdout; the
// honestly-empty run's empty stream is asserted, nothing parsed.
func assertStream(t *testing.T, id, resolved string, assign map[string]string, host string, port int, expected int, streamRaw string) {
	t.Helper()
	raw := streamRaw
	if expected == 0 {
		if strings.TrimSpace(raw) != "" {
			t.Errorf("case %s: the honestly-empty run wrote %q, want an empty stream", id, first80(raw))
		}
		// zero records: no explain blocks in either direction, no parse
		return
	}
	lines := splitLines(raw)

	explainLines := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "  - ") {
			explainLines++
		}
	}
	resolvedText := resolved == "text"
	explainOn := assign["explain"] == "on"
	if explainOn && resolvedText {
		if explainLines < expected {
			t.Errorf("case %s: -explain on under text but %d explain line(s) for %d record(s)", id, explainLines, expected)
		}
	} else if explainLines != 0 {
		t.Errorf("case %s: %d explain line(s) in the %s stream (explain renders iff resolved text with -explain on)", id, explainLines, resolved)
	}

	switch resolved {
	case "jsonl":
		count := 0
		for _, line := range lines {
			if strings.HasPrefix(line, "  - ") {
				t.Errorf("case %s: explain text leaked into the JSONL stream: %q", id, first80(line))
				continue
			}
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				t.Errorf("case %s: JSONL line is not schema-valid JSON: %q (%v)", id, first80(line), err)
				continue
			}
			if v, ok := obj["schema"].(float64); !ok || v != 1 {
				t.Errorf("case %s: JSONL line without schema 1: %q", id, first80(line))
				continue
			}
			target, ok := obj["target"].(map[string]any)
			if !ok || target["host"] != host || uint64Of(target["port"]) != uint64(port) {
				t.Errorf("case %s: the JSONL record's target is not the fixture (%s:%d): %q", id, host, port, first80(line))
				continue
			}
			count++
		}
		if count != expected {
			t.Errorf("case %s: %d JSONL record(s) for %d expected target(s)", id, count, expected)
		}
	case "csv":
		reader := csv.NewReader(strings.NewReader(raw))
		reader.FieldsPerRecord = -1
		all, err := reader.ReadAll()
		if err != nil {
			t.Fatalf("case %s: CSV stream unreadable: %v", id, err)
		}
		if len(all) == 0 {
			t.Errorf("case %s: empty CSV stream", id)
			return
		}
		if len(all[0]) < 6 || all[0][0] != "target" || all[0][1] != "host" {
			t.Errorf("case %s: CSV header missing (first row %q)", id, strings.Join(all[0], ","))
			return
		}
		recs := all[1:]
		if len(recs) != expected {
			t.Errorf("case %s: %d CSV record row(s) for %d expected target(s)", id, len(recs), expected)
		}
		for _, row := range recs {
			if len(row) < 3 || row[1] != host || row[2] != strconv.Itoa(port) {
				t.Errorf("case %s: the CSV row's host/port columns are not the fixture: %q", id, strings.Join(row, ","))
			}
		}
	case "urls":
		want := "https://" + net.JoinHostPort(host, strconv.Itoa(port))
		count := 0
		for _, line := range lines {
			if line != want {
				t.Errorf("case %s: urls line is not the fixture endpoint: %q (want %q)", id, first80(line), want)
				continue
			}
			count++
		}
		if count != expected {
			t.Errorf("case %s: %d urls line(s) for %d expected target(s)", id, count, expected)
		}
	default: // the resolved text format
		recLines := 0
		for _, line := range lines {
			if strings.HasPrefix(line, "  - ") {
				continue // the -explain block rides under the record line
			}
			if !strings.HasPrefix(line, host+":"+strconv.Itoa(port)+" ") {
				t.Errorf("case %s: the text line does not open with the fixture target: %q", id, first80(line))
				continue
			}
			if !strings.Contains(line, " pq=") {
				t.Errorf("case %s: the text line lost the format-parity verdict tail: %q", id, first80(line))
			}
			recLines++
		}
		if recLines != expected {
			t.Errorf("case %s: %d text record line(s) for %d expected target(s) (explain blocks excluded)", id, recLines, expected)
		}
	}
}

func splitLines(raw string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if line := strings.TrimRight(sc.Text(), "\r"); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func first80(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

func tail(s string, lines int) string {
	parts := splitLines(s)
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}

func uint64Of(v any) uint64 {
	if n, ok := v.(float64); ok {
		return uint64(n)
	}
	return 0
}
