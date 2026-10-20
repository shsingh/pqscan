package matrix

// battery_test.go is PQ-54's whole-argv invariant battery (issue #148): the
// guarantee over the UNENUMERATED space. PQ-53's pairwise array (cases.jsonl)
// samples the space with a covering array; this battery samples it with a
// seeded RNG — valid whole-argv vectors drawn from the SHARED domain table
// (tests/matrix/domains.json: one truth for what is valid) — and runs the
// REAL binary against the real loopback fixture, asserting the invariants NO
// valid combination may violate:
//
//  1. the documented exit code — every sampled vector is valid by
//     construction (the sampler repairs the table's prereq/conflict classes),
//     so the run is the documented exit-0 class ("scan completed, empty or
//     not", USAGE.md EXIT STATUS);
//  2. stdout carries the selector's records ONLY: schema-1-valid on machine
//     formats — checked against the PUBLISHED schema contract
//     (docs/schema-v1.json, loaded from disk, never a hand-copy) — and
//     grammar-parsable on -text/-urls; STRICT: no line of stdout contains
//     "pqscan:" (progress/notes are stderr-side, the §5.7 dialect rule);
//  3. -explain renders iff text resolved (the §5.7 prereq; asserted in both
//     directions);
//  4. -o is the single sink (stdout empty beside it), writes every record
//     AND the WAL (<basename>.wal), and a `pqscan -resume` round-trip
//     recovers a SET-EQUAL record set — equality derived from the PARSED
//     sets, never a pinned count;
//  5. dedupe: one record per host:port across ALL source composition
//     (u ∨ l ∨ from-naabu ∨ from-httpx ∨ from-nuclei ∨ stdin ' -- ') — no
//     duplicate keys in any parsed stream;
//  6. multiple format selectors compose per the documented precedence
//     (last selector on the line wins, chooseFormat) without error; the
//     -json/-jsonl alias pair is CONFLICT-FREE (both-on normalizes to one
//     well-formed schema-1 stream, never an error class).
//
// Seed structure: two fixed seeds (batterySeeds) × batteryVectorsPerSeed
// vectors, a seeded-RNG sample of the constraint-repaired domain product;
// every seed's vector sequence is fully deterministic (fixed draw order).
// SEED ROTATION: PQ54_SEEDS="314159,271828" appends extra seeds, each run
// with the same per-seed count (that is the documented rotation knob; CI
// rotation sets it — the fixed seeds ALWAYS run).
//
// No runner: the battery composes raw argv itself in-process — the
// at-least-one-source prereq is re-enforced here against the FULL member
// list (u, l=file, l=stdin, from-naabu, from-httpx, '--' with the expanded
// stdin line), not by a standing injected -u. Failures emit the exact argv
// + stdin + a -debug/-debug-out diagnostic rerun's report path so a RED
// replays exactly.
//
// Reuse, not duplication: the built binary (TestMain's binaryPath), the
// fixture (servers.DefaultMatrix), the placeholder materializer
// (materializeToken), the constraint vocabulary (loadDomains/arrayParams),
// the format mirror (mirrorFormat) and the stream assertions (assertStream)
// are the run_test.go / harness_test.go helpers — the battery adds only the
// sampling, the round-trip and the published-schema validator.

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/shard"
	servers "github.com/shsingh/pqscan/tests/fixtures/servers"
)

// batterySeeds are the fixed, always-run seeds (the lane's landing date and
// a memorable constant); batteryVectorsPerSeed is the per-seed sample count
// (the e.g.-200-per-run shape of issue #148).
var batterySeeds = []int{20261020, 8675309}

const batteryVectorsPerSeed = 200

// batteryQuicAlwaysWeight deliberately thins the costliest valid posture:
// -quic-always is the hint gate's override, and against a TCP-only loopback
// fixture the direct QUIC probe rides its full deadline ladder (an ~8s
// scan; ~32s under -mode deep, whose planned QUIC rungs re-probe the same
// silent UDP port — the engine's deterministic deadline behavior, not
// flakiness). The battery samples the value thin but never skips it: at
// this weight every seed still renders dozens of quic-always vectors, and
// a seed-rotation run (PQ54_SEEDS) multiplies the coverage. The invariants
// hold over ANY sampled subset — pair coverage at full strength remains
// PQ-53's array's job (its cases carry quic-always rows against the same
// 60s wall budget).
const batteryQuicAlwaysWeight = 0.08

// batteryCaseTimeout caps ONE subprocess attempt. Held above the array
// runner's 45s: the heaviest deterministic vectors (the deep-plan's QUIC
// ladder against the TCP-only fixture) legitimately ride ~40s of engine
// deadlines — a cap is a flake guard, not a correctness bound.
const batteryCaseTimeout = 150 * time.Second

// batteryBudget caps the battery's added wall time (the CI test job runs
// `go test ./...`; the battery must stay a seconds-scale addition — the
// report test errors past the budget, never beyond). Calibrated against
// the CI-observed wall: on a 4-core runner the default -parallel cap had
// the battery running 4-way for 186.02s (caught by THIS guard before the
// PR went green); with the designed 8-slot pool enforced (TestMain's cap
// raise + the per-vector semaphore) the expected wall is ~90-120s, and the
// budget holds 2x headroom above it. Shrink batteryVectorsPerSeed only if
// still over — never weaken an invariant.
const batteryBudget = 180 * time.Second

// batterySeedSet returns the fixed seeds plus any PQ54_SEEDS=... extras
// (comma-separated integers; malformed entries fail the battery loudly —
// rotation must be explicit, never silently ignored).
func batterySeedSet(t *testing.T) []int {
	t.Helper()
	seeds := append([]int(nil), batterySeeds...)
	if raw := os.Getenv("PQ54_SEEDS"); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				t.Fatalf("PQ54_SEEDS: %q is not a comma-separated seed list: %v", raw, err)
			}
			seeds = append(seeds, n)
		}
	}
	sort.Ints(seeds)
	return seeds
}

// bVector is one sampled whole-argv vector: the effective assignment (every
// array param + u), the raw argv token list (pre-expansion, reused by the
// diagnostic rerun), the expanded argv + stdin payload, the resolved output
// format, and the derived expected record count (the REAL shard assignment
// over the composed set — never a hand-counted number).
//
// stdinPipe selects the spawn's stdin: true = a pipe carrying stdin
// (implicit piped stdin becomes a source when it holds specs, PQ-41), false
// (the default) = nil → /dev/null semantics (no implicit source — the
// source floor then rests on the argv members alone).
type bVector struct {
	id        string
	seed      int
	idx       int
	assign    map[string]string
	raw       []string
	argv      []string
	stdinPipe bool
	stdin     string
	expected  int
	resolved  string
	lastSel   string // the raw line's LAST selector token (the precedence decision)
	oFile     bool
	wall      time.Duration
	dir       string
	keys      map[string]int // run 1's parsed record set (host:port → 1)
}

// bSourceMembers is the source-member vocabulary the floor is enforced
// against (domains.json's at_least_one list, in its member order).
var bSourceMembers = []string{"u", "l", "from-naabu", "from-httpx", "from-nuclei", "--"}

// batterySourcePresent reports whether the assignment holds at least one
// source member (the table's source-floor prereq, re-enforced here because
// the battery runs WITHOUT the array runner's injected -u).
func batterySourcePresent(assign map[string]string) bool {
	return assign["u"] == "single" || assign["l"] != "unset" ||
		assign["from-naabu"] == "set" || assign["from-httpx"] == "set" ||
		assign["from-nuclei"] == "set" || assign["--"] == "present"
}

// batterySample draws one valid vector: every flag param independently
// biased toward its non-default values, a random 1-3 member source subset,
// then the table's prereq/conflict classes repaired toward validity
// (deterministic repair order; the draw ORDER is fixed so a seed replays
// identically everywhere).
func batterySample(params []mParam, rng *rand.Rand) map[string]string {
	assign := map[string]string{}
	for _, p := range params {
		if p.Kind == "meta" || p.Kind == "runner-injected" {
			continue // meta excluded (table contract); u rides the source draw
		}
		assign[p.ID] = p.Default
	}
	// flag draws, table order (text is emitted after every machine
	// selector — the ordering the explain prereq's resolution depends on)
	for _, p := range params {
		if p.Kind != "flag" || p.ID == "l" || p.ID == "from-naabu" || p.ID == "from-httpx" || p.ID == "from-nuclei" {
			continue // l/from-* are sources drawn separately
		}
		if rng.Float64() < batteryWeightFor(p.ID) {
			var nonDef []string
			for _, v := range p.Domain {
				if v != p.Default {
					nonDef = append(nonDef, v)
				}
			}
			assign[p.ID] = nonDef[rng.Intn(len(nonDef))]
		}
	}
	// the source draw: 1-3 distinct members over the FULL list; l picks
	// file or stdin; '--' joins once
	pick := rng.Intn(3) + 1
	pool := append([]string(nil), bSourceMembers...)
	for i := 0; i < pick; i++ {
		m := pool[rng.Intn(len(pool))]
		pool = removeStr(pool, m)
		switch m {
		case "u":
			assign["u"] = "single"
		case "l":
			if rng.Intn(2) == 0 {
				assign["l"] = "file"
			} else {
				assign["l"] = "stdin"
			}
		case "from-naabu":
			assign["from-naabu"] = "set"
		case "from-httpx":
			assign["from-httpx"] = "set"
		case "from-nuclei":
			assign["from-nuclei"] = "set"
		case "--":
			assign["--"] = "present"
		}
	}
	// conflict repair: quic-always ⊕ quic-off — the table holds the pair
	// out of every case; the battery drops quic-off deterministically
	if assign["quic-always"] == "on" && assign["quic-off"] == "on" {
		assign["quic-off"] = "off"
	}
	// deep-cap prereq: -deep full reads -mode deep; the repair coin flips
	// between promoting the mode and demoting the cap (both outcomes valid)
	if assign["deep"] == "full" && assign["mode"] != "deep" {
		if rng.Intn(2) == 0 {
			assign["mode"] = "deep"
		} else {
			assign["deep"] = "standard"
		}
	}
	// resume prereq: -resume without -o has no journal path — promote
	if assign["resume"] == "on" && assign["o"] != "file" {
		assign["o"] = "file"
	}
	// explain prereq: -explain renders iff text — force the selector on
	if assign["explain"] == "on" && assign["text"] != "on" {
		assign["text"] = "on"
	}
	// the source floor, re-enforced against the full member list
	if !batterySourcePresent(assign) {
		assign["u"] = "single"
	}
	return assign
}

func removeStr(xs []string, drop string) []string {
	out := xs[:0:0]
	for _, x := range xs {
		if x != drop {
			out = append(out, x)
		}
	}
	return out
}

// batteryWeightFor is the per-param non-default draw weight: 0.4 for
// everything except the deliberate thinning of the costliest posture
// (batteryQuicAlwaysWeight for -quic-always — see that const's contract).
func batteryWeightFor(param string) float64 {
	if param == "quic-always" {
		return batteryQuicAlwaysWeight
	}
	return 0.4
}

// batteryEmit renders the assignment into raw argv tokens (table order; -u
// leads when drawn, the '--' marker ends the line) and expands the
// domains.json placeholders into vec's dir. Also derives the expected
// record count from the REAL shard assignment.
func batteryEmit(t *testing.T, vec *bVector, params []mParam, addr string) {
	t.Helper()
	raw := []string(nil)
	if vec.assign["u"] == "single" {
		raw = append(raw, "-u", addr) // u first — the fixture plumbing's lead
	}
	for _, p := range params {
		if p.Kind != "flag" {
			continue
		}
		spelling, ok := p.Spell[vec.assign[p.ID]]
		if !ok || spelling == "absent" || spelling == "" {
			continue // the default spelling keeps the flag absent
		}
		raw = append(raw, strings.Fields(spelling)...)
	}
	if vec.assign["--"] == "present" {
		raw = append(raw, "--")
	}
	vec.raw = raw
	// the stdin payload: the expanded $TARGET spec line whenever any
	// stdin-class member joined (-l - or the bare marker)
	vec.stdin = ""
	if vec.assign["l"] == "stdin" || vec.assign["--"] == "present" {
		vec.stdin = addr + "\n"
	}
	vec.stdinPipe = vec.stdin != "" // a pipe only when specs ride it
	vec.argv = make([]string, 0, len(raw))
	for _, tok := range raw {
		vec.argv = append(vec.argv, materializeToken(t, vec.id, vec.dir, addr, tok))
	}
	// generator sanity: the resolved format must be text whenever explain
	// rides the line (the emission order guarantees it; assert the guard)
	vec.resolved = mirrorFormat(vec.raw)
	// the line's LAST selector (the chooseFormat decision token): scan
	// the raw tokens in reverse, stopping at the '--' marker; a non-
	// selector line resolves to text (the absent-selector default)
	vec.lastSel = ""
	for i := len(vec.raw) - 1; i >= 0; i-- {
		tok := vec.raw[i]
		if tok == "--" {
			break
		}
		if !strings.HasPrefix(tok, "-") {
			continue
		}
		switch strings.TrimLeft(tok, "-") {
		case "json", "jsonl", "csv", "urls", "text":
			vec.lastSel = strings.TrimLeft(tok, "-")
			i = -1
		}
	}
	if vec.assign["explain"] == "on" && vec.resolved != "text" {
		t.Fatalf("%s: generation bug: explain=on but the resolved format is %s (argv %q)",
			vec.id, vec.resolved, vec.argv)
	}
	composed := []shard.TargetKey{net.JoinHostPort(batteryFixHost, strconv.Itoa(batteryFixPort))}
	idx, total := 1, 1
	if vec.assign["shard"] == "slice" {
		spell := batteryParamSpell(t, params, "shard", "slice")
		fields := strings.Fields(spell)
		if len(fields) != 2 {
			t.Fatalf("%s: the shard spell in domains.json is not '-shard <i/n>': %q", vec.id, spell)
		}
		var err error
		idx, total, err = shard.Spec(fields[1])
		if err != nil {
			t.Fatalf("%s: the table's shard spell %q: %v", vec.id, fields[1], err)
		}
	}
	vec.expected = len(shard.Assign(composed, idx, total))
	vec.oFile = vec.assign["o"] == "file"
}

// batteryParamSpell fetches one parameter's value spelling straight from
// the table (never hand-pinned in the battery).
func batteryParamSpell(t *testing.T, params []mParam, id, value string) string {
	t.Helper()
	for _, p := range params {
		if p.ID == id {
			sp, ok := p.Spell[value]
			if !ok {
				t.Fatalf("domains.json: parameter %s carries no spell for %q", id, value)
			}
			return sp
		}
	}
	t.Fatalf("domains.json: parameter %s missing", id)
	return ""
}

// bAttempt is one vector's per-seed accounting row.
type bAttempt struct {
	seed    int
	idx     int
	wall    time.Duration
	records int
	format  string
}

var (
	batteryAttempts   []bAttempt
	batteryAttemptsMu sync.Mutex
	batteryRunStart   time.Time
	batteryFixAddr    string
	batteryFixHost    string
	batteryFixPort    int
	batterySchema     *bSchemaNode
)

// TestBatteryInvariants runs every seed's sample: seeded vectors spawn the
// real binary behind the same bounded pool the array runner uses, and each
// vector asserts the whole invariant set; any failure emits the exact argv
// + stdin + a -debug diagnostic rerun's report path.
func TestBatteryInvariants(t *testing.T) {
	root := matrixRoot(t)
	doc := loadDomains(t, root)
	params := arrayParams(doc)
	batterySchema = batteryLoadSchema(t, root)

	addr := servers.StartFixtureServer(t, servers.DefaultMatrix()[0])
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("fixture addr: %v", err)
	}
	batteryFixAddr = addr
	batteryFixHost = host
	batteryFixPort, err = strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("fixture port: %v", err)
	}

	batteryRunStart = time.Now()
	// the designed 8-slot pool, enforced by a semaphore inside each
	// parallel vector (the scheduler cap is raised to 8 in TestMain when
	// unset): one shared loopback fixture row — its accept loop is
	// concurrency-safe and the array runner has driven 8-way against it
	// since PQ-53
	sem := make(chan struct{}, runnerPoolSize)
	for _, seed := range batterySeedSet(t) {
		rng := rand.New(rand.NewSource(int64(seed)))
		for i := 0; i < batteryVectorsPerSeed; i++ {
			seed, i := seed, i
			// sample BEFORE spawning: the draw sequence is fully
			// deterministic per seed (fixed call order, no parallel races)
			assign := batterySample(params, rng)
			id := fmt.Sprintf("seed-%d-v%03d", seed, i)
			t.Run(id, func(t *testing.T) {
				t.Parallel()
				sem <- struct{}{}
				defer func() { <-sem }()
				vec := &bVector{id: id, seed: seed, idx: i, assign: assign, dir: t.TempDir()}
				batteryEmit(t, vec, params, addr)
				batteryAssertVector(t, vec)
				batteryAttemptsMu.Lock()
				batteryAttempts = append(batteryAttempts, bAttempt{
					seed: seed, idx: i, wall: vec.wall, records: vec.expected, format: vec.resolved,
				})
				batteryAttemptsMu.Unlock()
			})
		}
	}
}

// bRun is one subprocess attempt's captured facts.
type bRun struct {
	stdout, stderr string
	exit           int
	wall           time.Duration
}

// batterySpawn runs the binary once against the vector's plumbing.
func batterySpawn(t *testing.T, vec *bVector, argv []string) bRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), batteryCaseTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, argv...)
	cmd.Dir = vec.dir
	if vec.stdinPipe {
		cmd.Stdin = strings.NewReader(vec.stdin) // the piped stdin (the implicit-source dialect)
	} // else nil: a character-device stdin — /dev/null semantics
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()
	wall := time.Since(start)
	if err != nil {
		exitErr, isExit := err.(*exec.ExitError)
		if !isExit {
			t.Fatalf("%s: run: %v", vec.id, err)
		}
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("%s: timed out after %s", vec.id, batteryCaseTimeout)
		}
		return bRun{stdout: stdout.String(), stderr: stderr.String(), exit: exitErr.ExitCode(), wall: wall}
	}
	return bRun{stdout: stdout.String(), stderr: stderr.String(), exit: 0, wall: wall}
}

// batteryNoStdoutNotes is the STRICT stdout dialect rule (§5.7): no line of
// stdout may contain a "pqscan:" note — progress, shard notes and refusals
// stream to stderr; stdout is results-only. Returns the offending lines.
func batteryNoStdoutNotes(stdout string) []string {
	var bad []string
	for _, line := range splitLines(stdout) {
		if strings.Contains(line, "pqscan:") {
			bad = append(bad, first80(line))
		}
	}
	return bad
}

// batteryStreamKeys extracts the host:port identity key set from a parsed
// stream (the same parse families assertStream uses): one key per record,
// counts kept for the dedupe + set-equality assertions.
func batteryStreamKeys(t *testing.T, id, resolved, raw string) map[string]int {
	t.Helper()
	keys := map[string]int{}
	switch resolved {
	case "jsonl":
		for _, line := range splitLines(raw) {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				t.Fatalf("%s: jsonl line unparseable (assertStream should have caught it): %v", id, err)
			}
			target, _ := obj["target"].(map[string]any)
			keys[fmt.Sprintf("%s:%d", target["host"], uint64Of(target["port"]))]++
		}
	case "csv":
		rows := csvRows(raw)
		if len(rows) > 0 && len(rows[0]) >= 2 && rows[0][0] == "target" && rows[0][1] == "host" {
			rows = rows[1:] // the header precedes the first row only; never a record
		}
		for _, row := range rows {
			if len(row) >= 3 {
				keys[row[1]+":"+row[2]]++
			}
		}
	case "urls":
		for _, line := range splitLines(raw) {
			keys[strings.TrimPrefix(line, "https://")]++
		}
	default: // the resolved text format
		for _, line := range splitLines(raw) {
			if strings.HasPrefix(line, "  - ") {
				continue // -explain blocks are not records
			}
			if i := strings.IndexByte(line, ' '); i > 0 {
				keys[line[:i]]++
			}
		}
	}
	return keys
}

// csvRows parses a CSV stream into rows (the header excluded by the caller
// where the counts matter).
func csvRows(raw string) [][]string {
	reader := csv.NewReader(strings.NewReader(raw))
	reader.FieldsPerRecord = -1
	all, err := reader.ReadAll()
	if err != nil {
		return nil
	}
	return all
}

// batteryAssertVector runs the vector's whole invariant set; any failure
// triggers the diagnostic rerun and emits the exact argv + stdin + report
// path. Invariant failure messages name their spec anchor.
func batteryAssertVector(t *testing.T, vec *bVector) {
	t.Helper()
	var errs []string
	note := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	run1 := batterySpawn(t, vec, vec.argv)
	vec.wall = run1.wall

	// invariant 1: the documented exit code (valid vector ⇒ the exit-0 class)
	if run1.exit != 0 {
		note("exit %d, want 0 (the documented exit-0 class for a valid vector; anchor: USAGE.md#exit-status)",
			run1.exit)
	}
	// invariant 2 (strict): no pqscan note on stdout — the §5.7 dialect rule
	for _, bad := range batteryNoStdoutNotes(run1.stdout) {
		note("stdout carries a pqscan note line: %q (anchor: docs/spec.md#57-output-and-chainability)", bad)
	}

	// the stream is the -o file's bytes when -o set (the single sink),
	// else stdout
	stream := run1.stdout
	if vec.oFile {
		if strings.TrimSpace(run1.stdout) != "" {
			note("stdout not empty beside -o (the single-sink contract; anchor: docs/spec.md#57-output-and-chainability)")
		}
		out := filepath.Join(vec.dir, "out.txt")
		data, readErr := os.ReadFile(out)
		switch {
		case readErr == nil:
			stream = string(data)
		case os.IsNotExist(readErr) && vec.expected == 0:
			// the honestly-empty run: the shard excluded the sole target,
			// nothing was scanned, the sink never opened (exit 0)
			stream = ""
		default:
			t.Fatalf("%s: -o set, read the output file: %v", vec.id, readErr)
		}
	}

	// invariants 2+3: the records-only parse + explain-iff-text (the
	// runner's own assertions, reused)
	assertStream(t, vec.id, vec.resolved, vec.assign, batteryFixHost, batteryFixPort, vec.expected, stream)

	// invariant 2 (machine byte-contract): every jsonl record validates
	// against the PUBLISHED schema (docs/schema-v1.json), never a hand-copy
	if vec.resolved == "jsonl" {
		batteryValidateJSONL(t, vec.id+"\n  ", stream, note)
	}

	// invariant 5: one record per host:port — no duplicate keys in the
	// parsed set, and the set is exactly the fixture (no invented target)
	vec.keys = batteryStreamKeys(t, vec.id, vec.resolved, stream)
	for _, key := range batteryKeyList(vec.keys) {
		if vec.keys[key] != 1 {
			note("record key %s appears %d times (one record per host:port; anchor: docs/spec.md#51-targeting-and-discovery)", key, vec.keys[key])
		}
	}
	fixtureKey := net.JoinHostPort(batteryFixHost, strconv.Itoa(batteryFixPort))
	if vec.expected > 0 && len(vec.keys) != vec.expected {
		note("%d parsed record key(s) for %d expected target(s) (anchor: docs/spec.md#51-targeting-and-discovery)",
			len(vec.keys), vec.expected)
	}
	if vec.expected > 0 && vec.keys[fixtureKey] != 1 {
		note("the fixture endpoint %s is not exactly-once in the parsed set (no invented targets; anchor: docs/spec.md#51-targeting-and-discovery)", fixtureKey)
	}

	// invariant 6: multiple selectors compose per the documented
	// precedence (last selector on the line wins — chooseFormat) without
	// error, and the -json/-jsonl ALIAS PAIR is conflict-free: both-on
	// never refuses (invariant 1's exit-0 already rode the run) and, when
	// the pair is the line's LAST selection, normalizes to one JSONL
	// stream. When a LATER selector follows the pair, last-wins governs
	// and the pair is inert — asserting jsonl there would overwrite the
	// documented precedence, not the alias contract.
	if vec.assign["json"] == "on" && vec.assign["jsonl"] == "on" &&
		(vec.lastSel == "json" || vec.lastSel == "jsonl") && vec.resolved != "jsonl" {
		note("-json + -jsonl as the line's last selection resolved to %s, want jsonl (the alias pair normalizes to the JSONL stream; anchor: docs/spec.md#57-output-and-chainability)",
			vec.resolved)
	}

	// invariant 4: -o writes every record + the WAL, and -resume
	// round-trips a SET-EQUAL record set (equality from the parsed sets)
	if vec.oFile {
		wal := filepath.Join(vec.dir, "out.wal")
		if _, statErr := os.Stat(wal); statErr != nil && vec.expected > 0 {
			note("no WAL at %s after a %d-record run (the journal rides beside -o; anchor: docs/spec.md#51-targeting-and-discovery)",
				wal, vec.expected)
		}
		argv2 := append([]string(nil), vec.argv...)
		if vec.assign["resume"] != "on" {
			// -resume must PARSE: before a trailing '--' marker (after it
			// the token is target data and the flag never parses), else
			// appended
			if len(argv2) > 0 && argv2[len(argv2)-1] == "--" {
				argv2 = append(argv2[:len(argv2)-1:len(argv2)-1], "-resume", "--")
			} else {
				argv2 = append(argv2, "-resume")
			}
		}
		run2 := batterySpawn(t, vec, argv2)
		if run2.exit != 0 {
			note("resume round-trip exit %d, want 0 (the WAL round-trip is the documented exit-0 class; anchor: USAGE.md#exit-status)",
				run2.exit)
		}
		for _, bad := range batteryNoStdoutNotes(run2.stdout) {
			note("resume stdout carries a pqscan note line: %q (anchor: docs/spec.md#57-output-and-chainability)", bad)
		}
		stream2 := run2.stdout
		if strings.TrimSpace(run2.stdout) != "" {
			note("resume stdout not empty beside -o (the single-sink contract; anchor: docs/spec.md#57-output-and-chainability)")
		}
		data, readErr := os.ReadFile(filepath.Join(vec.dir, "out.txt"))
		switch {
		case readErr == nil:
			stream2 = string(data)
		case os.IsNotExist(readErr) && vec.expected == 0:
			stream2 = ""
		default:
			t.Fatalf("%s: resume round-trip: read the output file: %v", vec.id, readErr)
		}
		assertStream(t, vec.id+"-resume", vec.resolved, vec.assign, batteryFixHost, batteryFixPort, vec.expected, stream2)
		keys2 := batteryStreamKeys(t, vec.id+"-resume", vec.resolved, stream2)
		if !batterySetEqual(vec.keys, keys2) {
			note("resume round-trip record set differs: run1 {%s} vs resumed {%s} (SET-EQUAL record set, not a pinned count; anchor: docs/spec.md#51-targeting-and-discovery)",
				batteryKeyList(vec.keys), batteryKeyList(keys2))
		}
		if vec.resolved == "jsonl" && vec.expected > 0 {
			batteryValidateJSONL(t, vec.id+"-resume\n  ", stream2, note)
		}
	}

	if len(errs) == 0 {
		return
	}
	// the diagnostic rerun: the same vector with -debug/-debug-out arming
	// the diagnostics sink, in a fresh dir, so a RED replays exactly
	diagArgv, reportPath := batteryDiagnostic(t, vec)
	dr := batterySpawn(t, vec, diagArgv)
	t.Errorf("%s INVARIANT BATTERY RED (%d assertion(s)):\n  argv=%q\n  stdin=%q\n  exit(run1)=%d\n%s\n  diagnostic rerun: argv=%q exit=%d report=%s stderr_tail=%q",
		vec.id, len(errs), vec.argv, vec.stdin, run1.exit,
		strings.Join(mapSlice(errs, func(s string) string { return "  ✗ " + s }), "\n"),
		diagArgv, dr.exit, reportPath, first80(tail(dr.stderr, 3)))
}

// batteryDiagnostic builds the repro rerun: the vector's RAW tokens with
// -debug/-debug-out inserted before a trailing '--' (or appended),
// re-expanded in a fresh dir; returns the expanded argv and the report path.
func batteryDiagnostic(t *testing.T, vec *bVector) ([]string, string) {
	t.Helper()
	raw := append([]string(nil), vec.raw...)
	probe := []string{"-debug", "-debug-out", "@tmp/diag.json"}
	if len(raw) > 0 && raw[len(raw)-1] == "--" {
		raw = append(raw[:len(raw):len(raw)], probe...)
		raw = append(raw, "--")
	} else {
		raw = append(raw, probe...)
	}
	dir := t.TempDir()
	argv := make([]string, 0, len(raw))
	for _, tok := range raw {
		argv = append(argv, materializeToken(t, vec.id, dir, batteryFixAddr, tok))
	}
	return argv, filepath.Join(dir, "diag.json")
}

// batteryValidateJSONL validates every jsonl line of a stream against the
// published schema, reporting violations through the caller's collect-or.
func batteryValidateJSONL(t *testing.T, id string, stream string, note func(string, ...any)) {
	t.Helper()
	for li, line := range splitLines(stream) {
		var obj any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue // assertStream already reported the parse failure
		}
		if err := batteryValidate(batterySchema, obj); err != nil {
			note("%s jsonl record %d violates docs/schema-v1.json: %v (anchor: docs/spec.md#57-output-and-chainability)",
				id, li+1, err)
		}
	}
}

// batterySetEqual compares two parsed record sets (key → count); set
// equality is the round-trip contract, counts derived from the parses.
func batterySetEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, n := range a {
		if b[k] != n {
			return false
		}
	}
	return true
}

// batteryKeyList lists a parsed set's keys (sorted; the listing order of
// failure messages).
func batteryKeyList(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func mapSlice(xs []string, f func(string) string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, f(x))
	}
	return out
}

// batteryLoadSchema parses the published schema contract from disk — the
// battery checks machine rows against the file, never a hand-copy.
func batteryLoadSchema(t *testing.T, root string) *bSchemaNode {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "docs", "schema-v1.json"))
	if err != nil {
		t.Fatalf("read docs/schema-v1.json (the published schema contract): %v", err)
	}
	var schema bSchemaNode
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse docs/schema-v1.json: %v", err)
	}
	return &schema
}

// bSchemaNode is the schema subset docs/schema-v1.json uses (type, object
// properties+required, arrays, const) — the validator walks exactly that.
type bSchemaNode struct {
	Type       string                  `json:"type"`
	Required   []string                `json:"required"`
	Properties map[string]*bSchemaNode `json:"properties"`
	Items      *bSchemaNode            `json:"items"`
	Const      any                     `json:"const"`
}

// batteryValidate checks one decoded record against the published schema
// (the subset above). Errors name the violated path.
func batteryValidate(node *bSchemaNode, val any) error {
	if node == nil {
		return nil
	}
	if node.Const != nil {
		if !reflect.DeepEqual(val, node.Const) {
			return fmt.Errorf("const mismatch: got %#v, want %#v", val, node.Const)
		}
	}
	switch node.Type {
	case "object":
		obj, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("want object, got %s", reflect.TypeOf(val))
		}
		for _, req := range node.Required {
			if _, ok := obj[req]; !ok {
				return fmt.Errorf("missing required field %q", req)
			}
		}
		for key, sub := range node.Properties {
			if v, ok := obj[key]; ok {
				if err := batteryValidate(sub, v); err != nil {
					return fmt.Errorf("%s: %v", key, err)
				}
			}
		}
	case "string":
		if _, ok := val.(string); !ok {
			return fmt.Errorf("want string, got %s", reflect.TypeOf(val))
		}
	case "boolean":
		if _, ok := val.(bool); !ok {
			return fmt.Errorf("want boolean, got %s", reflect.TypeOf(val))
		}
	case "integer":
		n, ok := val.(float64)
		if !ok {
			return fmt.Errorf("want integer, got %s", reflect.TypeOf(val))
		}
		if math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) {
			return fmt.Errorf("want integer, got %v", n)
		}
	case "array":
		items, ok := val.([]any)
		if !ok {
			return fmt.Errorf("want array, got %s", reflect.TypeOf(val))
		}
		for i, it := range items {
			if err := batteryValidate(node.Items, it); err != nil {
				return fmt.Errorf("[%d]: %v", i, err)
			}
		}
	}
	return nil
}

// TestBatteryReport prints the battery's per-seed + total accounting after
// every vector joined (serial test order) and holds the wall-time budget.
func TestBatteryReport(t *testing.T) {
	batteryAttemptsMu.Lock()
	rows := batteryAttempts
	batteryAttempts = nil
	batteryAttemptsMu.Unlock()
	wall := time.Since(batteryRunStart)

	sort.Slice(rows, func(a, b int) bool {
		if rows[a].seed != rows[b].seed {
			return rows[a].seed < rows[b].seed
		}
		return rows[a].idx < rows[b].idx
	})
	perSeed := map[int]int{}
	var maxWall time.Duration
	for _, a := range rows {
		perSeed[a.seed]++
		if a.wall > maxWall {
			maxWall = a.wall
		}
	}
	seeds := make([]int, 0, len(perSeed))
	for s := range perSeed {
		seeds = append(seeds, s)
	}
	sort.Ints(seeds)
	for _, s := range seeds {
		t.Logf("seed=%d vectors=%d", s, perSeed[s])
	}
	if len(rows) == 0 {
		t.Fatal("the battery report's attempt table is empty: no vectors were collected")
	}
	recordsTotal := 0
	for _, a := range rows {
		recordsTotal += a.records
	}
	t.Logf("battery: %d vectors over %d seed(s) (%d fixture record(s) derived from the parsed sets), longest vector %s, wall %.2fs (budget %s)",
		len(rows), len(seeds), recordsTotal, maxWall.Truncate(time.Millisecond), wall.Seconds(), batteryBudget)
	if wall > batteryBudget {
		t.Errorf("battery wall %.2fs exceeded the %s budget: shrink batteryVectorsPerSeed, never the invariants", wall.Seconds(), batteryBudget)
	}
}
