package main

// Nuclei-adapter flag wiring tests (PQ-55, issue #149, watched RED): the
// -from-nuclei findings file enters the ONE composition the -u/-l/-- specs
// and the other adapter files share — internal/target's FromNuclei feeds
// grammar.Parse (matched-at, url fallback, scheme/path stripped), the
// composition dedupes by host:port (first occurrence wins), and the record
// order is the source order (specs first, then the adapter files in flag
// order: -from-httpx, -from-naabu, -from-nuclei). Refusal paths are the
// composition's usage class (exit 64): an unreadable or unparseable findings
// file refuses the run named by its flag with the offending line's number,
// and no partial list ever scans.
import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestNucleiFlagRegistration: the -from-nuclei input flag registers via the
// fs.String shape the usage-drift gate reads back — both dash spellings --
// and each parse lands on the adapter's own usage refusal (exit 64, the
// unreadable file named by the flag), never the flag-provided-but-not-defined
// artifact.
func TestNucleiFlagRegistration(t *testing.T) {
	rows := []struct {
		name string
		args []string
	}{
		{"from-nuclei registers", []string{"-from-nuclei", "/nonexistent/pqscan/nuclei.jsonl"}},
		{"--from-nuclei registers", []string{"--from-nuclei", "/nonexistent/pqscan/nuclei.jsonl"}},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(row.args, &out, &errOut)
			if code != 64 {
				t.Fatalf("exit = %d, want 64 (stderr: %s)", code, errOut.String())
			}
			if strings.Contains(errOut.String(), "flag provided but not defined") {
				t.Fatalf("the flag -from-nuclei did not register: %q", errOut.String())
			}
			if !strings.Contains(errOut.String(), "-from-nuclei") {
				t.Fatalf("the refusal should name its flag -from-nuclei: %q", errOut.String())
			}
		})
	}
}

// TestNucleiComposition: the -from-nuclei findings file composes with -u and
// the other spec sources under the ONE dedupe (host:port, first occurrence
// wins) in source order.
func TestNucleiComposition(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	classicAddr := startClassicFixture(t)
	secondHybridAddr := startHybridFixture(t)
	thirdHybridAddr := startHybridFixture(t)
	_, classicPort, _ := strings.Cut(classicAddr, ":")
	_, secondHybridPort, _ := strings.Cut(secondHybridAddr, ":")
	_, thirdHybridPort, _ := strings.Cut(thirdHybridAddr, ":")
	// The findings shapes are the pinned capture's (nuclei -j: one JSON
	// finding per line, matched-at the canonical host field).
	finding := func(matched string) string {
		return `{"template-id":"pqscan-chain","matcher-status":true,"matched-at":"` + matched + `"}` + "\n"
	}

	rows := []struct {
		name       string
		args       []string
		nuclei     string // the -from-nuclei fixture file's finding lines; "" = flag absent
		wantCode   int
		wantStderr string // a refusal must carry this; "" = none required
		wantOrder  []string
	}{
		{
			name: "a findings file composes with -u, deduped by host:port",
			args: []string{"-u", hybridAddr},
			// all three shapes (scheme://host:port and the bare
			// host:port, twice) strip to the -u spec: one record.
			nuclei:    finding("https://"+hybridAddr) + finding(hybridAddr) + finding("https://"+hybridAddr),
			wantCode:  0,
			wantOrder: []string{hybridAddr},
		},
		{
			name:      "standalone findings dedupe in order; the ssh class keeps its port",
			args:      []string{},
			nuclei:    finding("https://127.0.0.1:"+classicPort) + finding("127.0.0.1:"+classicPort) + finding("127.0.0.1:"+secondHybridPort),
			wantCode:  0,
			wantOrder: []string{classicAddr, "127.0.0.1:" + secondHybridPort},
		},
		{
			name: "the url field is the fallback when matched-at is empty",
			args: []string{},
			nuclei: `{"template-id":"pqscan-chain","matcher-status":true,"matched-at":"","url":"https://` +
				hybridAddr + `"}` + "\n",
			wantCode:  0,
			wantOrder: []string{hybridAddr},
		},
		{
			name:       "a non-JSON line refuses named by its flag, at its line number (exit 64)",
			args:       []string{},
			nuclei:     finding("https://"+hybridAddr) + "scanme.sh:443\n",
			wantCode:   64,
			wantStderr: "line 2",
		},
		{
			name:       "a comments-only file holds no targets: the source-floor refusal",
			args:       []string{},
			nuclei:     "# pinned-capture: nuclei -l hosts.txt -silent -j\n\n",
			wantCode:   64,
			wantStderr: "no target specified",
		},
	}

	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			args := append([]string(nil), row.args...)
			args = append(args, "-quic-off", "-jsonl")
			outFile := ""
			if row.nuclei != "" {
				path := writeSpecFile(t, "nuclei-fixture.jsonl", row.nuclei)
				args = append(args, "-from-nuclei", path)
			}
			if row.wantOrder != nil {
				outFile = filepath.Join(t.TempDir(), "nuclei.jsonl")
				args = append(args, "-o", outFile)
			}

			var out, errOut bytes.Buffer
			code := run(args, &out, &errOut)
			if code != row.wantCode {
				t.Fatalf("exit = %d, want %d (stderr: %s)", code, row.wantCode, errOut.String())
			}
			if row.wantStderr != "" && !strings.Contains(errOut.String(), row.wantStderr) {
				t.Fatalf("stderr missing %q: %s", row.wantStderr, errOut.String())
			}
			if row.wantStderr == "line 2" && !strings.Contains(errOut.String(), "-from-nuclei") {
				t.Fatalf("the parse refusal should name its flag -from-nuclei: %s", errOut.String())
			}
			if outFile == "" {
				if out.Len() != 0 {
					t.Fatalf("stdout polluted on a refusal (results belong to -o): %q", out.String())
				}
				return
			}
			recs := readJSONLRecords(t, outFile)
			if len(recs) != len(row.wantOrder) {
				t.Fatalf("records = %d, want %d (stderr: %s)", len(recs), len(row.wantOrder), errOut.String())
			}
			for i, want := range row.wantOrder {
				if recs[i]["target"].(map[string]any)["input"] != want {
					t.Fatalf("record %d input = %v, want %q", i, recs[i]["target"].(map[string]any)["input"], want)
				}
			}
		})
	}

	// The full source-order row: one record each for -u, -from-httpx,
	// -from-naabu, -from-nuclei, in that composed order (the adapters'
	// files in flag order; the nuclei file joins last).
	t.Run("the adapter files compose in flag order (the record order contract)", func(t *testing.T) {
		outFile := filepath.Join(t.TempDir(), "order.jsonl")
		httpxPath := writeSpecFile(t, "httpx-fixture.txt", "tcp://"+classicAddr+"\n")
		naabuPath := writeSpecFile(t, "naabu-fixture.txt", "127.0.0.1:"+secondHybridPort+"\n")
		nucleiPath := writeSpecFile(t, "nuclei-order-fixture.jsonl", finding("https://127.0.0.1:"+thirdHybridPort))
		args := []string{
			"-u", hybridAddr, "-quic-off", "-jsonl", "-o", outFile,
			"-from-httpx", httpxPath, "-from-naabu", naabuPath, "-from-nuclei", nucleiPath,
		}
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 0 {
			t.Fatalf("exit = %d (stderr: %s)", code, errOut.String())
		}
		want := []string{hybridAddr, classicAddr, secondHybridAddr, thirdHybridAddr}
		recs := readJSONLRecords(t, outFile)
		if len(recs) != len(want) {
			t.Fatalf("records = %d, want %d (stderr: %s)", len(recs), len(want), errOut.String())
		}
		for i, w := range want {
			if recs[i]["target"].(map[string]any)["input"] != w {
				t.Fatalf("record %d input = %v, want %q (source order, first-occurrence dedupe)",
					i, recs[i]["target"].(map[string]any)["input"], w)
			}
		}
	})
}
