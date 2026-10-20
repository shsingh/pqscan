package chains

// fixtures_test.go (PQ-55, issue #149): the committed pinnd-capture
// fixtures crosschecked against their adapters — the parses agree with an
// INDEPENDENT derivation from the same bytes (never a pinned count), and
// the documented refusal classes (exit 64, the flag named, the line
// number named, stdout clean) are deliberate rows over the real bytes.
import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/shsingh/pqscan/internal/target"
)

// chainsFixtureRoot resolves the repo root from this source file (tests/
// chains/*_test.go → two dirs up) and hands out tests/fixtures/chains
// paths, independent of the working directory.
func chainsFixture(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", ".."))
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	path := filepath.Join(root, "tests", "fixtures", "chains", name)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture %s: %v", path, err)
	}
	return path
}

// derivedNucleiSpecs independently derives the host:port list the fixture's
// findings lines contribute (json-parse matched-at/url, strip the scheme
// and any path suffix manually — the shared decoration rule's contract,
// lines not skipped — so no adapter code is trusted in the derivation):
// the crosscheck the fixture-agreement asserts against.
func derivedNucleiSpecs(t *testing.T, raw string) []string {
	t.Helper()
	var out []string
	for no, line := range strings.Split(strings.TrimRight(raw, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		var finding struct {
			MatchedAt string `json:"matched-at"`
			URL       string `json:"url"`
		}
		if err := json.Unmarshal([]byte(trimmed), &finding); err != nil {
			t.Fatalf("the committed capture's line %d is not JSON (the pin must stay parseable): %v", no+1, err)
		}
		spec := finding.MatchedAt
		if spec == "" {
			spec = finding.URL
		}
		if spec == "" {
			t.Fatalf("the committed capture's line %d carries no matched-at/url", no+1)
		}
		out = append(out, spec)
	}
	return out
}

// TestPinnedNucleiFixtureParse: the committed nuclei -j capture parses
// through FromNuclei EXACTLY as an independent derivation of its own bytes
// says (order and count included), and the distinct host:port set is the
// capture's two-port truth (scanme.sh:443 + scanme.sh:22 — the 28 findings
// dedupe through the composition, never in the adapter).
func TestPinnedNucleiFixtureParse(t *testing.T) {
	raw := readFixture(t, chainsFixture(t, "nuclei-findings.jsonl"))
	got, err := target.FromNuclei(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("FromNuclei over the committed capture: %v", err)
	}
	var want []string
	distinct := map[string]int{}
	for _, spec := range derivedNucleiSpecs(t, raw) {
		stripped := stripForCheck(spec)
		want = append(want, stripped)
		distinct[hostPortOf(stripped)]++
	}
	if len(got) != len(want) {
		t.Fatalf("targets = %d, want the independently derived %d", len(got), len(want))
	}
	for i, g := range got {
		if g.Input != want[i] {
			t.Errorf("target %d = %q, want the derived spec %q", i, g.Input, want[i])
		}
	}
	if len(distinct) != 2 {
		t.Fatalf("the capture's distinct host:port set = %d members (%s), want 2 (scanme.sh:443 + scanme.sh:22)", len(distinct), fmt.Sprint(distinct))
	}
	if _, ok := distinct["scanme.sh:443"]; !ok {
		t.Errorf("the capture's ssl-class port 443 is missing from the parse")
	}
	if _, ok := distinct["scanme.sh:22"]; !ok {
		t.Errorf("the capture's ssh-class port 22 is missing from the parse (ports preserved)")
	}
}

// TestPinnedNaabuFixtureParse: the naabu capture's two identical host:port
// lines parse through the adapter; the composition dedupes upstream.
func TestPinnedNaabuFixtureParse(t *testing.T) {
	raw := readFixture(t, chainsFixture(t, "naabu-text.txt"))
	got, err := target.FromNaabu(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("FromNaabu over the committed capture: %v", err)
	}
	var want []string
	for _, line := range strings.Split(strings.TrimRight(raw, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		want = append(want, trimmed)
	}
	if len(got) != len(want) {
		t.Fatalf("targets = %d, want the file's own %d spec lines", len(got), len(want))
	}
	for i, g := range got {
		if g.Input != want[i] {
			t.Errorf("target %d = %q, want %q", i, g.Input, want[i])
		}
	}
}

// TestPinnedHttpxTextFixtureParse: the httpx text capture's single
// scheme:// line strips to the https default (443).
func TestPinnedHttpxTextFixtureParse(t *testing.T) {
	raw := readFixture(t, chainsFixture(t, "httpx-text.txt"))
	got, err := target.FromHTTPX(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("FromHTTPX over the committed capture: %v", err)
	}
	if len(got) != 1 || got[0].Input != "scanme.sh" || got[0].Port != 443 || got[0].Host != "scanme.sh" || got[0].Class != "host" {
		t.Fatalf("the text-dialect capture parses to %s, want exactly {scanme.sh:443}", targetsOfString(got))
	}
}

// TestPinnedHttpxCsvRefusal: the committed csv capture (a 50-column table,
// NOT url,status) is not the text-dialect adapter's row shape: the parse
// refuses with the data row's line number, no partial list escapes.
func TestPinnedHttpxCsvRefusal(t *testing.T) {
	path := chainsFixture(t, "httpx-csv.csv")
	raw := readFixture(t, path)
	got, err := target.FromHTTPX(strings.NewReader(raw))
	if err == nil {
		t.Fatalf("FromHTTPX over the csv capture unexpectedly parsed %d target(s): %s", len(got), targetsOfString(got))
	}
	if got != nil {
		t.Fatalf("the refusal must abort the stream (no partial list): got %d targets", len(got))
	}
	// the data row is the fixture's last physical line (the csv rows are
	// the only non-comment lines) — the refusal names it.
	dataRow := len(strings.Split(strings.TrimRight(raw, "\n"), "\n"))
	if !strings.Contains(err.Error(), fmt.Sprintf("line %d", dataRow)) {
		t.Errorf("the refusal must name the data row (line %d): %v", dataRow, err)
	}
	if !strings.Contains(err.Error(), "invalid port") {
		t.Errorf("the refusal's own class text: %v (the grammar's port refusal over the table's columns)", err)
	}
}

// stripForCheck applies the shared decoration rule to a matched-at/url
// value, independently of the adapters (the test's own strip).
func stripForCheck(spec string) string {
	if i := strings.Index(spec, "://"); i >= 0 {
		spec = spec[i+3:]
	}
	if j := strings.Index(spec, "/"); j >= 0 {
		spec = spec[:j]
	}
	return spec
}

// hostPortOf normalizes a stripped spec to host:port (the bare host keeps
// the https default — the derivation's own default).
func hostPortOf(spec string) string {
	if strings.Contains(spec, ":") {
		return spec
	}
	return spec + ":443"
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func targetsOfString(ts interface{}) string {
	return fmt.Sprint(ts)
}

// TestChainRefusalCells: the chain contract's documented refusal classes as
// deliberate rows over the REAL fixtures (exit 64, stdout clean, the flag
// and the offending line named — the adapters' one recorded-observation
// convention).
func TestChainRefusalCells(t *testing.T) {
	rows := []struct {
		name     string
		argv     []string
		fileSpec string // "$FILE"'s content ("" = no file token in argv)
		piped    bool
		stdin    string
		wantExit int
		wantMsgs []string
	}{
		{
			name:     "the nuclei adapter without its file arg eats the next flag",
			argv:     []string{"-from-nuclei", "-jsonl", "-u", "203.0.113.9"},
			wantExit: 64,
			wantMsgs: []string{"-from-nuclei -jsonl", "no such file or directory"},
		},
		{
			name:     "a malformed findings line is a recorded, line-numbered observation",
			argv:     []string{"-from-nuclei", "$FILE"},
			fileSpec: findingLine("https://scanme.sh:443") + "scanme.sh:443 (not json)\n",
			wantExit: 64,
			wantMsgs: []string{"-from-nuclei", "line 2", "not a nuclei findings JSONL object"},
		},
		{
			name:     "a findings object with no matched-at and no url refuses too",
			argv:     []string{"-from-nuclei", "$FILE"},
			fileSpec: `{"template-id":"pqscan-chains","matcher-status":false}` + "\n",
			wantExit: 64,
			wantMsgs: []string{"line 1", "neither matched-at nor url"},
		},
		{
			name:     "the committed csv capture refuses through the text adapter",
			argv:     []string{"-from-httpx", chainsFixture(t, "httpx-csv.csv")},
			wantExit: 64,
			wantMsgs: []string{"-from-httpx", "invalid port"},
		},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			argv := make([]string, len(row.argv))
			for i, a := range row.argv {
				if a == "$FILE" {
					a = chainsFile(t, dir, "refusal-fixture.txt", row.fileSpec)
				}
				argv[i] = a
			}
			run := spawnChain(t, dir, argv, row.piped, row.stdin)
			if run.exit != row.wantExit {
				t.Fatalf("exit = %d, want %d (stderr: %s)", run.exit, row.wantExit, tailOf(run.stderr.String(), 4))
			}
			if strings.TrimSpace(run.stdout.String()) != "" {
				t.Fatalf("a refusal writes nothing to the record stream: %q", run.stdout.String())
			}
			for _, msg := range row.wantMsgs {
				if !strings.Contains(run.stderr.String(), msg) {
					t.Fatalf("the refusal must carry %q; stderr: %s", msg, run.stderr.String())
				}
			}
			if run.exit == 64 {
				t.Logf("refusal class %q: exit 64, stdout clean, %v named ✓", row.name, row.wantMsgs)
			}
		})
	}
}
