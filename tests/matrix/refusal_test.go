package matrix

// refusal_test.go is PQ-54's invalid-class battery (issue #148): the
// DOCUMENTED exit-64 usage-class refusals as deliberate rows. Every row
// asserts only live-documented truth — the documented exit code, an EMPTY
// stdout (a refusal happens before any scan; stdout is results-only), and
// the documented stderr message class (substrings taken from the live
// binary's refusal lines, never invented text) — with the failure naming
// the anchor of the refusal's documentation.
//
// One deliberate NON-refusal row (deep-cap-outside-deep): `-deep full`
// outside `-mode deep` is NOT an exit-64 class in the live CLI — the value
// validation (`unknown -deep plan`) is the refusal; the cap PLACEMENT is
// the domain table's documented silent no-op ("an explicit -deep standard
// under a non-deep mode is a silent no-op in the binary"). The battery
// asserts that documented inert contract (exit 0, one well-formed record)
// rather than inventing a refusal — the live crosscheck of the shared
// table's normalization.

import (
	"net"
	"strconv"
	"strings"
	"testing"

	servers "github.com/shsingh/pqscan/tests/fixtures/servers"
)

// refusalRow is one documented invalid-class row.
type refusalRow struct {
	name      string
	argv      []string // raw argv; $ADDR expands to the fixture, $OUT to a temp file
	stdinPipe bool     // true = the child reads a PIPE carrying stdin; false = /dev/null semantics
	stdin     string   // the payload on the pipe (empty = the honest empty pipe)
	wantExit  int      // the DOCUMENTED exit code for the class (64, or 0 for the inert row)
	wantOut   bool     // stdout must be exactly empty (refusals write nothing)
	wantMsgs  []string // the documented stderr message class(es), each a literal substring of the live refusal line
	anchor    string   // where the refusal is documented (named in any failure)
	note      string   // the class's one-line contract
}

// refusalRows is the deliberate invalid-class battery.
var refusalRows = []refusalRow{
	{
		name:     "explain-refused-under-json",
		argv:     []string{"-json", "-explain", "-u", "$ADDR"},
		wantExit: 64, wantOut: true,
		wantMsgs: []string{"-explain applies to text output only"},
		anchor:   "docs/spec.md#57-output-and-chainability",
		note:     "-explain is a text-presentation surface; refused under a machine format",
	},
	{
		name:     "explain-refused-under-csv",
		argv:     []string{"-csv", "-explain", "-u", "$ADDR"},
		wantExit: 64, wantOut: true,
		wantMsgs: []string{"-explain applies to text output only"},
		anchor:   "docs/spec.md#57-output-and-chainability",
		note:     "the same refusal class over the CSV selector",
	},
	{
		name:     "sni-strict-sni-refused",
		argv:     []string{"-sni", "strict-sni", "-u", "$ADDR"},
		wantExit: 64, wantOut: true,
		wantMsgs: []string{`unknown -sni "strict-sni"`, "want auto | ptr-then-ip | ip-only"},
		anchor:   "docs/spec.md#51-targeting-and-discovery",
		note:     "the spec's authored-ahead strict-sni token is outside the live valid domain; the CLI refuses it naming the value",
	},
	{
		name:     "source-floor-refusal",
		argv:     []string{"-json"},
		wantExit: 64, wantOut: true,
		wantMsgs: []string{"no target specified"},
		anchor:   "docs/spec.md#51-targeting-and-discovery",
		note:     "the source floor: no u/l/from-*/-- member on the line names the documented refusal (/dev/null stdin — no implicit source)",
	},
	{
		name:      "implicit-empty-pipe-refusal",
		argv:      []string{"-json"},
		stdinPipe: true,
		stdin:     "",
		wantExit:  64, wantOut: true,
		wantMsgs: []string{"piped stdin held no target specs"},
		anchor:   "docs/spec.md#57-output-and-chainability",
		note:     "the PQ-41 implicit piped-stdin dialect: an EMPTY pipe refuses with its own honest line (a distinct documented class from the argv source floor)",
	},
	{
		name:     "marker-empty-stdin-refusal",
		argv:     []string{"-json", "--"},
		stdin:    "",
		wantExit: 64, wantOut: true,
		wantMsgs: []string{"no target specified"},
		anchor:   "docs/spec.md#51-targeting-and-discovery",
		note:     "the '--' marker with an empty stdin: nothing arrived, nothing scanned, the refusal names the floor",
	},
	{
		name:     "list-flag-empty-stdin-refusal",
		argv:     []string{"-l", "-"},
		stdin:    "",
		wantExit: 64, wantOut: true,
		wantMsgs: []string{"no target specified"},
		anchor:   "docs/spec.md#51-targeting-and-discovery",
		note:     "an empty pipe through '-l -' (the stdin-file alias) still refuses with the honest line",
	},
	{
		name:     "resume-requires-o-refusal",
		argv:     []string{"-u", "$ADDR", "-resume"},
		wantExit: 64, wantOut: true,
		wantMsgs: []string{"-resume requires -o"},
		anchor:   "docs/spec.md#51-targeting-and-discovery",
		note:     "the table's resume prereq: no -o means no journal path to read",
	},
	{
		name: "deep-cap-outside-deep-is-inert",
		argv: []string{"-deep", "full", "-mode", "fast", "-u", "$ADDR"},
		// the documented non-refusal: the cap PLACEMENT outside -mode deep
		// is a silent no-op in the live CLI (domains.json normalization);
		// the run is the documented exit-0 class with one well-formed record
		wantExit: 0,
		wantMsgs: nil,
		anchor:   "docs/spec.md#74-deep-mode-scheduling-the-probe-plan-dag",
		note:     "-deep full ∖ -mode deep is the domain table's documented silent no-op — NOT an exit-64 class; the CLI refuses the -deep VALUE only",
	},
	{
		name:     "deep-value-refused",
		argv:     []string{"-deep", "ultra", "-u", "$ADDR"},
		wantExit: 64, wantOut: true,
		wantMsgs: []string{`unknown -deep plan "ultra"`, "want standard | full"},
		anchor:   "USAGE.md#exit-status",
		note:     "the -deep VALUE class is the documented usage refusal (unknown -mode/-deep/-sni)",
	},
	{
		name:     "mode-value-refused",
		argv:     []string{"-mode", "bogus", "-u", "$ADDR"},
		wantExit: 64, wantOut: true,
		wantMsgs: []string{`unknown -mode "bogus"`, "want fast | deep | pq"},
		anchor:   "docs/spec.md#52-modes",
		note:     "the -mode VALUE class: the documented usage refusal naming the value",
	},
	{
		name:     "unknown-flag-refusal",
		argv:     []string{"-u", "$ADDR", "-bogus"},
		wantExit: 64, wantOut: true,
		wantMsgs: []string{"flag provided but not defined: -bogus"},
		anchor:   "USAGE.md#exit-status",
		note:     "a flag parse error is a usage-class refusal before anything composes",
	},
	{
		name:     "missing-arg-refusal",
		argv:     []string{"-u", "$ADDR", "-l"},
		wantExit: 64, wantOut: true,
		wantMsgs: []string{"flag needs an argument: -l"},
		anchor:   "USAGE.md#exit-status",
		note:     "a value flag missing its operand at end-of-line is a usage-class refusal",
	},
	{
		name:     "httpx-adapter-eats-next-flag",
		argv:     []string{"-u", "$ADDR", "-from-httpx", "-json"},
		wantExit: 64, wantOut: true,
		// the documented diagnostic names the eaten operand ("-json" became
		// the adapter's filename operand) + the open failure
		wantMsgs: []string{"-from-httpx -json", "no such file or directory"},
		anchor:   "docs/spec.md#6-chaining-reference-implementations",
		note:     "the file-taking adapters take FILES only: without its file operand the adapter eats the next flag, and the diagnostic names what it tried to open",
	},
	{
		name:     "naabu-adapter-eats-next-flag",
		argv:     []string{"-u", "$ADDR", "-from-naabu", "-text"},
		wantExit: 64, wantOut: true,
		wantMsgs: []string{"-from-naabu -text", "no such file or directory"},
		anchor:   "docs/spec.md#6-chaining-reference-implementations",
		note:     "the same documented class over the naabu adapter",
	},
}

// TestBatteryRefusals runs every deliberate invalid-class row against the
// real binary and asserts the documented exit + empty stdout + message
// class. The deep-cap inert row additionally asserts its one well-formed
// record (the domain table's documented no-op contract).
func TestBatteryRefusals(t *testing.T) {
	addr := servers.StartFixtureServer(t, servers.DefaultMatrix()[0])
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("fixture addr: %v", err)
	}
	fixturePort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("fixture port: %v", err)
	}

	for i := range refusalRows {
		row := &refusalRows[i]
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			argv := make([]string, 0, len(row.argv)+2)
			for _, tok := range row.argv {
				switch tok {
				case "$ADDR":
					tok = addr
				case "$OUT":
					tok = dir + "/out.txt"
				}
				argv = append(argv, tok)
			}
			run := batterySpawn(t, &bVector{id: row.name, dir: dir, stdinPipe: row.stdinPipe, stdin: row.stdin}, argv)

			if run.exit != row.wantExit {
				t.Errorf("%s: exit %d, want %d (the DOCUMENTED exit for this class; anchor: %s) — %s\n  argv=%q\n  stderr tail: %q",
					row.name, run.exit, row.wantExit, row.anchor, row.note, argv, tail(run.stderr, 3))
			}
			if row.wantOut && strings.TrimSpace(run.stdout) != "" {
				t.Errorf("%s: stdout is not empty on a refusal (stdout is results-only; anchor: %s): %q",
					row.name, row.anchor, first80(run.stdout))
			}
			for _, want := range row.wantMsgs {
				if !strings.Contains(run.stderr, want) {
					t.Errorf("%s: stderr misses the documented message class %q (anchor: %s) — %s\n  stderr tail: %q",
						row.name, want, row.anchor, row.note, tail(run.stderr, 3))
				}
			}
			// the inert deep-cap row's shape: the run is the exit-0 class
			// with ONE well-formed record — the documented silent no-op
			if row.name == "deep-cap-outside-deep-is-inert" {
				assertStream(t, row.name, mirrorFormat(argv), map[string]string{}, host, fixturePort, 1, run.stdout)
				keys := batteryStreamKeys(t, row.name, mirrorFormat(argv), run.stdout)
				if len(keys) != 1 {
					t.Errorf("%s: %d parsed record key(s), want exactly the fixture's one (the documented inert no-op still scans; anchor: %s): %v",
						row.name, len(keys), row.anchor, keys)
				}
			}
			// every row's repro line: the exact argv rides even on pass —
			// a later RED elsewhere names the shape without re-deriving it
			t.Logf("%s: argv=%q exit=%d (%s)", row.name, argv, run.exit, row.note)
		})
	}
}
