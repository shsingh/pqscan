package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/grammar"
	"github.com/shsingh/pqscan/internal/out"
	fixtures "github.com/shsingh/pqscan/tests/fixtures/servers"
)

func startHybridFixture(t *testing.T) string {
	t.Helper()
	return fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-hybrid-mlkem",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})
}

func startClassicFixture(t *testing.T) string {
	t.Helper()
	return fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-classic-x25519-only",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})
}

// closedLoopbackPort returns a deterministic unreachable host:port: an
// address that listened a moment ago and is closed now (loopback RST — no
// network, no resolver, no long dial timeout).
func closedLoopbackPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

func mustParse(t *testing.T, specs []string) []grammar.Target {
	t.Helper()
	var ts []grammar.Target
	for _, spec := range specs {
		parsed, err := grammar.Parse(spec)
		if err != nil {
			t.Fatalf("grammar.Parse(%q): %v", spec, err)
		}
		ts = append(ts, parsed...)
	}
	return ts
}

// wantRec is one expected record. class pins handshake.group_class (""
// for an error record, whose handshake must be zero); wantError pins a
// probe-failure record (error, zero handshake, no verdict blocks);
// wantScanError pins the rubric's zero-PQ-signal scan-error record (the
// error path carries the rubric's error text, the verdict block is
// present with the scan-error label). Every record is pinned to schema
// 1 / fast mode.
type wantRec struct {
	class         string
	wantError     bool
	wantScanError bool
}

// TestPipelineMultiTarget: Engine.Run scans the composed targets in order,
// fast mode — one schema-1 record per reachable target, an error record for
// the unreachable one, progress reported every N targets plus a final
// report, CIDR refused until PQ-16 (issue #38 / PQ-15, watched RED).
func TestPipelineMultiTarget(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	classicAddr := startClassicFixture(t)
	deadAddr := closedLoopbackPort(t)

	rows := []struct {
		name         string
		specs        []string
		every        int
		probeTimeout time.Duration
		wantErr      string // Engine.Run error substring; "" = success
		wantRecs     []wantRec
		wantProgress [][2]int
	}{
		{
			name:         "reachable targets scan in order",
			specs:        []string{hybridAddr, classicAddr},
			every:        0, // default: 50-target cadence
			probeTimeout: 2 * time.Second,
			wantRecs:     []wantRec{{class: "pq_hybrid"}, {class: "classic", wantScanError: true}},
			wantProgress: [][2]int{{2, 2}}, // final report only
		},
		{
			name:         "dead target between reachable ones yields error records in order",
			specs:        []string{hybridAddr, deadAddr, classicAddr},
			every:        0,
			probeTimeout: 500 * time.Millisecond,
			wantRecs:     []wantRec{{class: "pq_hybrid"}, {class: "", wantError: true}, {class: "classic", wantScanError: true}},
			wantProgress: [][2]int{{3, 3}},
		},
		{
			name:         "progress reports every N targets then final",
			specs:        []string{hybridAddr, classicAddr, deadAddr},
			every:        2,
			probeTimeout: 500 * time.Millisecond,
			wantRecs:     []wantRec{{class: "pq_hybrid"}, {class: "classic", wantScanError: true}, {class: "", wantError: true}},
			wantProgress: [][2]int{{2, 3}, {3, 3}},
		},
		{
			name:     "empty target list is a caller error",
			specs:    nil,
			wantErr:  "no targets",
			wantRecs: nil,
		},
		{
			name:    "cidr targets are refused until PQ-16",
			specs:   []string{"192.0.2.0/24"},
			wantErr: "cidr expansion lands with PQ-16",
		},
	}

	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			engine := &Engine{ProgressEvery: row.every}
			opts := Options{QuicOff: true, ProbeTimeout: row.probeTimeout}

			var calls [][2]int
			recs, err := engine.Run(mustParse(t, row.specs), opts, func(done, total int) {
				calls = append(calls, [2]int{done, total})
			})

			if row.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), row.wantErr) {
					t.Fatalf("Run error = %v, want substring %q", err, row.wantErr)
				}
				if recs != nil {
					t.Fatalf("records on refusual path = %v, want nil", recs)
				}
				return
			}
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(recs) != len(row.wantRecs) {
				t.Fatalf("records = %d, want %d", len(recs), len(row.wantRecs))
			}
			for i, rec := range recs {
				if rec.Schema != 1 || rec.Mode != "fast" {
					t.Fatalf("record %d: schema=%d mode=%s, want schema 1 fast", i, rec.Schema, rec.Mode)
				}
				if rec.Target.Input != row.specs[i] {
					t.Fatalf("record %d: input = %q, want %q (order)", i, rec.Target.Input, row.specs[i])
				}
				want := row.wantRecs[i]
				switch {
				case want.wantError:
					if rec.Error == "" {
						t.Fatalf("record %d (%s): error empty, want non-empty", i, rec.Target.Input)
					}
					if rec.Handshake.Negotiated != 0 {
						t.Fatalf("record %d (%s): negotiated = %d on an error record, want zero",
							i, rec.Target.Input, rec.Handshake.Negotiated)
					}
					// A failed probe presents no verdict blocks: the
					// record's error path carries it (score 0 lives in
					// the zero value, never an invented rubric).
					if rec.Pq != nil || rec.Cert != nil {
						t.Fatalf("record %d (%s): probe failure carries verdict blocks (pq=%v cert=%v), want nil",
							i, rec.Target.Input, rec.Pq, rec.Cert)
					}
				case want.wantScanError:
					if rec.Error == "" || !strings.Contains(rec.Error, "zero PQ signal") {
						t.Fatalf("record %d (%s): error = %q, want the rubric scan-error text", i, rec.Target.Input, rec.Error)
					}
					if rec.Pq == nil {
						t.Fatalf("record %d (%s): pq block missing on a scanned target", i, rec.Target.Input)
					}
					if rec.Pq.Label != "scan-error" || rec.Pq.Score != 0 {
						t.Fatalf("record %d (%s): pq = {%d %q}, want the scan-error verdict shape",
							i, rec.Target.Input, rec.Pq.Score, rec.Pq.Label)
					}
					if rec.Handshake.GroupClass != want.class {
						t.Fatalf("record %d (%s): group_class = %q, want %q",
							i, rec.Target.Input, rec.Handshake.GroupClass, want.class)
					}
				default:
					if rec.Error != "" {
						t.Fatalf("record %d (%s): unexpected error %q", i, rec.Target.Input, rec.Error)
					}
					if rec.Pq == nil {
						t.Fatalf("record %d (%s): pq block missing on a scanned target", i, rec.Target.Input)
					}
					if rec.Handshake.GroupClass != want.class {
						t.Fatalf("record %d (%s): group_class = %q, want %q",
							i, rec.Target.Input, rec.Handshake.GroupClass, want.class)
					}
				}
			}
			if row.wantProgress != nil {
				if len(calls) != len(row.wantProgress) {
					t.Fatalf("progress calls = %v, want %v", calls, row.wantProgress)
				}
				for j, want := range row.wantProgress {
					if calls[j] != want {
						t.Fatalf("progress call %d = %v, want %v", j, calls[j], want)
					}
				}
			}
		})
	}
}

// TestPipelineVerdictWireIn (PQ-19/PQ-21, watched RED): the pipeline maps
// the observed handshake + certificate facts onto classify's ScoreInput
// and fills the record's cert/pq blocks from the REAL rubric — the same
// DefaultRubric the verdict table pins, no rubric stub. The fixture
// server's leaf is a self-signed ECDSA P-256 certificate (the
// tlsx surface test's same ground truth): classical, so cert_pq_sig
// never fires here and the cert block carries the classical names —
// presence of the block (it was analyzed), not a PQ claim.
func TestPipelineVerdictWireIn(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	classicAddr := startClassicFixture(t)
	deadAddr := closedLoopbackPort(t)

	rows := []struct {
		name     string
		addr     string
		timeout  time.Duration
		wantPq   *out.PqRecord
		wantCert *out.CertRecord
	}{
		{
			name:    "hybrid fixture: negotiated_pq_hybrid(+40) = 40 pq-partial, classical leaf analyzed",
			addr:    hybridAddr,
			timeout: 2 * time.Second,
			wantPq:  &out.PqRecord{Score: 40, Label: "pq-partial", HNDL: false, Summary: "negotiated_pq_hybrid(+40)"},
			wantCert: &out.CertRecord{
				SigAlg: "ecdsa-with-SHA256", SigPQ: false,
				KeyAlg: "ECDSA", KeyPQ: false, Dual: false,
			},
		},
		{
			name:    "classic fixture: weak_classical_preferred(-5) floors to 0 = scan-error, summary carried",
			addr:    classicAddr,
			timeout: 2 * time.Second,
			wantPq:  &out.PqRecord{Score: 0, Label: "scan-error", HNDL: false, Summary: "weak_classical_preferred(-5)"},
			wantCert: &out.CertRecord{
				SigAlg: "ecdsa-with-SHA256", SigPQ: false,
				KeyAlg: "ECDSA", KeyPQ: false, Dual: false,
			},
		},
	}

	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			recs, err := (&Engine{}).Run(mustParse(t, []string{row.addr}),
				Options{QuicOff: true, ProbeTimeout: row.timeout}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(recs) != 1 {
				t.Fatalf("records = %d, want 1", len(recs))
			}
			rec := recs[0]

			if !reflect.DeepEqual(rec.Pq, row.wantPq) {
				t.Fatalf("pq block = %+v, want %+v", rec.Pq, row.wantPq)
			}
			if !reflect.DeepEqual(rec.Cert, row.wantCert) {
				t.Fatalf("cert block = %+v, want %+v", rec.Cert, row.wantCert)
			}
		})
	}

	// The failed probe is the record's error path, not a verdict: no
	// cert/pq block (score 0 stays the zero value — the rubric never
	// ran), the error field carries the failure.
	recs, err := (&Engine{}).Run(mustParse(t, []string{deadAddr}),
		Options{QuicOff: true, ProbeTimeout: 500 * time.Millisecond}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rec := recs[0]
	if rec.Error == "" {
		t.Fatal("failed probe: record error empty, want the error path")
	}
	if rec.Handshake.Negotiated != 0 {
		t.Fatalf("failed probe: negotiated = %d, want zero", rec.Handshake.Negotiated)
	}
	if rec.Pq != nil || rec.Cert != nil {
		t.Fatalf("failed probe: pq/cert blocks invented (%v/%v), want nil", rec.Pq, rec.Cert)
	}
}

// TestNoTargets: with none of -u / -l / -- present (or none yielding specs)
// the run refuses with EX_USAGE (64) — guidance on stderr, clean stdout,
// and never a flag-parsing artifact (issue #38 / PQ-15, watched RED: the
// -l rows fail while the flag is undefined).
func TestNoTargets(t *testing.T) {
	rows := []struct {
		name string
		args []string
	}{
		{name: "no flags at all", args: []string{}},
		{name: "-l with an empty file", args: []string{"-l", writeSpecFile(t, "empty.txt", "\n\n  \n")}},
		{name: "-l with a missing file", args: []string{"-l", filepath.Join(t.TempDir(), "missing.txt")}},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(row.args, &out, &errOut)
			if code != 64 {
				t.Fatalf("exit = %d, want 64 (EX_USAGE; stderr: %s)", code, errOut.String())
			}
			if errOut.Len() == 0 {
				t.Fatal("no usage guidance on stderr")
			}
			if out.Len() != 0 {
				t.Fatalf("stdout polluted on usage path: %q", out.String())
			}
			if bytes.Contains(errOut.Bytes(), []byte("flag provided but not defined")) {
				t.Fatalf("flag-parsing artifact surfaced instead of the usage refusal: %q", errOut.String())
			}
		})
	}
}

// writeSpecFile writes one -l input file and returns its path.
func writeSpecFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// setStdin swaps the stdin seam for the test's reader (restored on cleanup).
func setStdin(t *testing.T, r string) {
	t.Helper()
	stdin = strings.NewReader(r)
	t.Cleanup(func() { stdin = os.Stdin })
}

func readJSONLRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("jsonl: %v", err)
	}
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("record json invalid (%q): %v", line, err)
		}
		recs = append(recs, rec)
	}
	return recs
}

// TestFlagComposition: -u, -l and the -- stdin marker compose into one
// []grammar.Target list via internal/grammar Parse — scanned in order with
// duplicates removed by host:port (first occurrence wins); cidr specs are
// refused with the PQ-16 message and exit 64 (watched RED: the flags are
// undefined until the GREEN commit).
func TestFlagComposition(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	classicAddr := startClassicFixture(t)
	secondHybridAddr := startHybridFixture(t)

	rows := []struct {
		name        string
		args        []string
		stdinSpecs  string // read via the -- marker; "" = no stdin content needed
		listContent string // written to the row's -l file; "" = no -l in args
		wantCode    int
		wantOrder   []string // jsonl record Target.Input order; nil = no -o record check
	}{
		{
			name:        "all three sources compose, deduped by host:port in order",
			args:        []string{"-u", hybridAddr, "-l", "", "-jsonl", "-quic-off", "--"},
			listContent: classicAddr + "\n\n" + hybridAddr + "\n",
			stdinSpecs:  secondHybridAddr + "\n" + classicAddr + "\n",
			wantCode:    0,
			// dedupe: -u hybrid; -l classic, hybrid(dup); stdin second-hybrid, classic(dup)
			wantOrder: []string{hybridAddr, classicAddr, secondHybridAddr},
		},
		{
			name:        "cidr in the target list refuses before scanning (exit 64)",
			args:        []string{"-l", "", "-quic-off"},
			listContent: "192.0.2.0/24\n" + hybridAddr + "\n",
			wantCode:    64,
		},
	}

	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			args := row.args
			if row.listContent != "" {
				idx := -1
				for i, a := range args {
					if a == "-l" {
						idx = i
						break
					}
				}
				if idx < 0 || idx+1 >= len(args) {
					t.Fatalf("row %q carries listContent but no -l placeholder", row.name)
				}
				path := writeSpecFile(t, "targets-"+strings.ReplaceAll(row.name, " ", "-")+".txt", row.listContent)
				args = append(append(args[:idx+1:idx+1], path), args[idx+2:]...)
			}
			outFile := ""
			if row.wantOrder != nil {
				outFile = filepath.Join(t.TempDir(), "composed.jsonl")
				// -o must sit BEFORE the -- marker: Go's flag parser stops
				// at --, so an -o after it is a positional, not a flag.
				pos := -1
				for i, a := range args {
					if a == "--" {
						pos = i
						break
					}
				}
				oFlag := []string{"-o", outFile}
				if pos >= 0 {
					args = append(append(args[:pos:pos], oFlag...), args[pos:]...)
				} else {
					args = append(args, oFlag...)
				}
			}
			setStdin(t, row.stdinSpecs)

			var out, errOut bytes.Buffer
			code := run(args, &out, &errOut)
			if code != row.wantCode {
				t.Fatalf("exit = %d, want %d (stderr: %s)", code, row.wantCode, errOut.String())
			}
			if code == 64 && !bytes.Contains(errOut.Bytes(), []byte("cidr expansion lands with PQ-16")) {
				t.Fatalf("stderr missing the cidr deferral message: %q", errOut.String())
			}
			if out.Len() != 0 {
				t.Fatalf("stdout polluted (results belong to -o, refusal is stderr-only): %q", out.String())
			}

			if row.wantOrder != nil {
				recs := readJSONLRecords(t, outFile)
				if len(recs) != len(row.wantOrder) {
					t.Fatalf("records = %d, want %d", len(recs), len(row.wantOrder))
				}
				for i, want := range row.wantOrder {
					if recs[i]["target"].(map[string]any)["input"] != want {
						t.Fatalf("record %d input = %v, want %q (source order, first-occurrence dedupe)",
							i, recs[i]["target"].(map[string]any)["input"], want)
					}
					if recs[i]["schema"].(float64) != 1 {
						t.Fatalf("record %d schema missing", i)
					}
				}
			}
		})
	}
}
