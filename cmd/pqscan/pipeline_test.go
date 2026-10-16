package main

import (
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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

// closedPortSeen is the package's record of every loopback port the
// closed-loop helper has already returned in this process: the kernel may
// hand the SAME port back immediately after its release (observed on CI's
// Linux runner — the ephemeral allocator walks back over freed ports
// under load, two of a 12-target synthetic list collapsed into one
// host:port and the composition's host:port dedupe dropped the duplicate,
// breaking the count-pinned shard battery). The dedupe rule is the
// composition's contract — the helper guarantees distinct addresses
// instead of every caller guarding.
var closedPortMu sync.Mutex
var closedPortSeen = map[string]bool{}

// closedLoopbackPort returns a deterministic unreachable host:port: an
// address that listened a moment ago and is closed now (loopback RST — no
// network, no resolver, no long dial timeout). A repeat pick is retried
// (the allocator walks forward; the retry lands within a few iterations).
func closedLoopbackPort(t *testing.T) string {
	t.Helper()
	closedPortMu.Lock()
	defer closedPortMu.Unlock()
	for i := 0; i < 64; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		if !closedPortSeen[addr] {
			closedPortSeen[addr] = true
			return addr
		}
	}
	t.Fatal("the kernel kept handing back already-used closed loopback ports")
	return ""
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
// verdict block is present with the scan-error label and score 0; the
// record's error is EMPTY — PQ-43: the state lives in the pq block and
// the rubric's error stays the classifier's internal path). Every record
// is pinned to schema 1 / fast mode.
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
					if rec.Error != "" {
						t.Fatalf("record %d (%s): error = %q, want empty (PQ-43: the verdict block is the scan-error state's only honest home)",
							i, rec.Target.Input, rec.Error)
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
	// The no-input-source refusal is asserted, not the ambient stdin
	// state: pin the class non-piped so the rows never consult whatever
	// stream the test process inherits (PQ-41's implicit-pipe seam).
	setStdinPipe(t, false)
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

// --- PQ-23 congestion wiring (issue #46, watched RED) ----------------------

// startStalledFixture returns the address of the deliberate timeout
// target: a listener that accepts and then goes silent (never reads,
// never writes). The probe connects, the TLS handshake waits for a
// ServerHello that never comes, and its probe deadline expires — net's
// "i/o timeout", the throttle signal class the wiring halves the window
// on. (Unlike the negotiation fixtures the hold here is the point; this
// helper lives in cmd because it exercises pacing, not negotiation.)
func startStalledFixture(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	conns := make([]net.Conn, 0, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // the cleanup closed the listener
			}
			conns = append(conns, conn) // held: silent to the client
		}
	}()
	return ln.Addr().String()
}

// TestRateLimiterEnforced (PQ-23, watched RED): -rate paces probe
// LAUNCHES through the token-bucket limiter (burst 1: the pace is the
// launch cadence) — three targets at 5 rps pay floor(2 launches)/5 rps =
// 2/5 s between the first and the last launch.
//
// The clock statement the pair must carry honestly: the pipeline's clock
// is the REAL system clock. The congestion core takes an injectable
// Clock, but no seam carries one into cmd/pqscan's production path (the
// engine builds the limiter with congestion.NewLimiter, the package's
// system-clock constructor), so this test asserts the real timing
// window 2/rps with a 50 ms epsilon for timer/scheduling slop — timers
// never fire early, so the lower bound is sound; the limiter's pacing
// math itself is already sim-clock-proven in internal/congestion. The
// run is the real CLI path (run()): the flags must reach the engine's
// Options end to end.
func TestRateLimiterEnforced(t *testing.T) {
	rows := []struct {
		name    string
		rate    string // the -rate value; "" = the flag absent (default 0)
		wantMin time.Duration
		wantMax time.Duration
	}{
		{
			name:    "-rate 5 paces three launches (floor 2/5 s minus 50 ms)",
			rate:    "5",
			wantMin: 350 * time.Millisecond,
		},
		{
			name:    "default rate 0 stays uncapped",
			rate:    "",
			wantMax: 200 * time.Millisecond,
		},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			// Three distinct loopback targets on closed ports: instant
			// refusals, so the only pacing between launches is the
			// limiter's (the refusals are records, the run still exits 0).
			ports := make([]string, 3)
			for i := range ports {
				ports[i] = closedLoopbackPort(t)
			}
			list := writeSpecFile(t, "rate-targets.txt", strings.Join(ports, "\n")+"\n")
			output := filepath.Join(t.TempDir(), "rate.jsonl")
			args := []string{"-l", list, "-jsonl", "-o", output}
			if row.rate != "" {
				args = append([]string{"-rate", row.rate}, args...)
			}

			start := time.Now()
			var out, errOut bytes.Buffer
			code := run(args, &out, &errOut)
			elapsed := time.Since(start)
			if code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
			}
			recs := readJSONLRecords(t, output)
			if len(recs) != len(ports) {
				t.Fatalf("records = %d, want %d (stderr: %s)", len(recs), len(ports), errOut.String())
			}
			for i, rec := range recs {
				if rec["target"].(map[string]any)["input"] != ports[i] {
					t.Fatalf("record %d input = %v, want %q (composed order)",
						i, rec["target"].(map[string]any)["input"], ports[i])
				}
				if e, _ := rec["error"].(string); !strings.Contains(e, "connection refused") {
					t.Fatalf("record %d error = %q, want the loopback refusal", i, e)
				}
			}
			if row.wantMin > 0 && elapsed < row.wantMin {
				t.Fatalf("elapsed = %s (< %s): -rate %s does not pace the launches",
					elapsed, row.wantMin, row.rate)
			}
			if row.wantMax > 0 && elapsed > row.wantMax {
				t.Fatalf("elapsed = %s (> %s): the uncapped default paces anyway",
					elapsed, row.wantMax)
			}
		})
	}
}

// TestBreakerOpens (PQ-23, watched RED): three consecutive per-host probe
// failures open the host's breaker; every target behind the open breaker
// leaves as a schema-1 error record with the "breaker open" reason, in the
// same shape as any failed-probe record, WITHOUT a dial. The proof the
// dial was skipped lives in the record's own error text: the ports below
// are CLOSED — a dial would surface the OS refusal ("connection refused"),
// never "breaker open". The breaker is in-memory per run.
func TestBreakerOpens(t *testing.T) {
	rows := []struct {
		name        string
		targetN     int
		wantBreaker bool // records past the threshold = "breaker open"
	}{
		{
			name:        "below the threshold every target still dials",
			targetN:     2,
			wantBreaker: false,
		},
		{
			name:        "the opening refusal itself dialed (3rd failure)",
			targetN:     3,
			wantBreaker: false,
		},
		{
			name:        "past the threshold later targets skip the dial",
			targetN:     5,
			wantBreaker: true,
		},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			ports := make([]string, row.targetN)
			for i := range ports {
				ports[i] = closedLoopbackPort(t)
			}
			recs, err := (&Engine{}).Run(mustParse(t, ports),
				Options{QuicOff: true, ProbeTimeout: 500 * time.Millisecond}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(recs) != len(ports) {
				t.Fatalf("records = %d, want %d", len(recs), len(ports))
			}
			for i, rec := range recs {
				if rec.Target.Input != ports[i] {
					t.Fatalf("record %d input = %q, want %q (composed order)",
						i, rec.Target.Input, ports[i])
				}
				if i < breakerThreshold {
					if rec.Error == "" || !strings.Contains(rec.Error, "connection refused") {
						t.Fatalf("record %d error = %q, want the loopback refusal (a dial happened)",
							i, rec.Error)
					}
					continue
				}
				if rec.Pq != nil || rec.Cert != nil {
					t.Fatalf("record %d: error record carries verdict blocks (pq=%v cert=%v), want nil",
						i, rec.Pq, rec.Cert)
				}
				if row.wantBreaker {
					if rec.Error != "breaker open" {
						t.Fatalf("record %d error = %q, want %q (no dial: the OS refusal would name connection refused)",
							i, rec.Error, "breaker open")
					}
					continue
				}
				if !strings.Contains(rec.Error, "connection refused") {
					t.Fatalf("record %d error = %q, want the refusal (the breaker must not open below the threshold)",
						i, rec.Error)
				}
			}
		})
	}
}

// TestAIMDHalving (PQ-23, watched RED): ONE shared AIMD backs the
// dispatch — successes grow the window additively toward the -threads
// ceiling, a timed-out probe halves it (the record pins the probe
// timeout as the throttle signal). Four healthy fixtures ramp the window
// onto its ceiling; the fifth target is the stalled fixture, whose probe
// deadline expires and whose completion must come back with the window
// halved (4 x 0.5 = 2).
//
// The assertion is the exposed window (read off the engine after Run
// returns — the same-package field; the pacing alternative is timing
// noise here). The GREEN dispatch gates launches on the window, so the
// stalled target is dispatched only after the healthy four complete:
// the halve is the last signal processed and the final window is
// deterministic. The real-clock pacing cost of the ramp belongs to
// TestRateLimiterEnforced's window; this test pins the window STATE.
func TestAIMDHalving(t *testing.T) {
	fast := []string{
		startHybridFixture(t), startHybridFixture(t),
		startHybridFixture(t), startHybridFixture(t),
	}
	stalled := startStalledFixture(t)

	engine := &Engine{}
	recs, err := engine.Run(mustParse(t, append(fast, stalled)),
		Options{QuicOff: true, ProbeTimeout: 500 * time.Millisecond, MaxWindow: 4}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(recs) != len(fast)+1 {
		t.Fatalf("records = %d, want %d", len(recs), len(fast)+1)
	}
	for i := range fast {
		if recs[i].Target.Input != fast[i] {
			t.Fatalf("record %d input = %q, want %q (composed order)", i, recs[i].Target.Input, fast[i])
		}
		if recs[i].Error != "" {
			t.Fatalf("record %d error = %q, want none", i, recs[i].Error)
		}
	}
	last := recs[len(recs)-1]
	if last.Target.Input != stalled {
		t.Fatalf("record 5 input = %q, want %q (composed order)", last.Target.Input, stalled)
	}
	if last.Error == "" || (!strings.Contains(last.Error, "i/o timeout") &&
		!strings.Contains(last.Error, "deadline")) {
		t.Fatalf("record 5 error = %q, want the probe's deadline expiry (net's i/o timeout / the tls-with-dialer context deadline class)", last.Error)
	}
	if last.Handshake.Negotiated != 0 {
		t.Fatalf("record 5 negotiated = %d, want zero on a timed-out record", last.Handshake.Negotiated)
	}
	if engine.aimd == nil {
		t.Fatal("the run's AIMD window is missing off the engine")
	}
	if got := engine.aimd.Window(); got != 2 {
		t.Fatalf("window after 4 successes + 1 timeout = %d, want 2 (capped 4, halved by the timeout)", got)
	}
}

// TestRateThreadsFlagRegistration: the two congestion flags register via
// the fs.Float64/fs.Int shape the usage-drift gate reads back; a parse of
// both lands on the no-targets refusal (exit 64), never the
// flag-provided-but-not-defined artifact (issue #46 / PQ-23).
func TestRateThreadsFlagRegistration(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-rate", "5", "-threads", "4"}, &out, &errOut)
	if code != 64 {
		t.Fatalf("exit = %d, want 64 (no targets; stderr: %s)", code, errOut.String())
	}
	if bytes.Contains(errOut.Bytes(), []byte("flag provided but not defined")) {
		t.Fatalf("the congestion flags did not register: %q", errOut.String())
	}
}

// TestPipelineScanErrorRecordCarriesEmptyError (PQ-43, watched RED): the
// rubric's zero-PQ-signal refusal is the classifier's internal path and
// never the record's user-facing error. A verdict-carrying record — the
// profile handshake SUCCEEDED (a classical group negotiated, the pq
// block scored 0 / scan-error) — leaves record.error empty: the state's
// only honest home is the pq block (label/score/summary), rendered as
// pq=scan-error(0) on the text line. jsonl/csv agree (the schema-1 error
// key/cell is present and empty: "the probe failed" — the probe did
// not). Probe-failure records keep their verbatim failure text (the
// unchanged error = probe-failure contract, pinned by TestPipelineMultiTarget
// and the error.* goldens); the pq block MUST stay the scan-error shape.
func TestPipelineScanErrorRecordCarriesEmptyError(t *testing.T) {
	classicAddr := startClassicFixture(t)
	recs, err := (&Engine{}).Run(mustParse(t, []string{classicAddr}),
		Options{QuicOff: true, ProbeTimeout: 2 * time.Second}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Handshake.Negotiated == 0 || rec.Handshake.GroupClass != "classic" {
		t.Fatalf("handshake = %d/%q, want a negotiated classical group (the scan succeeded)",
			rec.Handshake.Negotiated, rec.Handshake.GroupClass)
	}
	if rec.Pq == nil {
		t.Fatal("pq block missing on a scanned target")
	}
	if rec.Pq.Label != "scan-error" || rec.Pq.Score != 0 {
		t.Fatalf("pq = {%d %q}, want the scan-error verdict shape (score 0)",
			rec.Pq.Score, rec.Pq.Label)
	}
	if rec.Error != "" {
		t.Fatalf("error = %q, want empty (PQ-43: a verdict-carrying record's state lives in the pq block, not the record's error field)",
			rec.Error)
	}

	// jsonl: the schema-1 error key stays present (the schema keeps its
	// meaning) and empty.
	var jbuf bytes.Buffer
	if err := out.NewEncoder(&jbuf, out.FormatJSONL).Encode(rec); err != nil {
		t.Fatalf("encode jsonl: %v", err)
	}
	var line map[string]any
	if err := json.Unmarshal(jbuf.Bytes(), &line); err != nil {
		t.Fatalf("decode jsonl: %v", err)
	}
	if got, ok := line["error"]; !ok || got != "" {
		t.Fatalf("jsonl error = %v (present=%v), want present and empty", got, ok)
	}

	// csv: the error cell empties.
	var cbuf bytes.Buffer
	if err := out.NewEncoder(&cbuf, out.FormatCSV).Encode(rec); err != nil {
		t.Fatalf("encode csv: %v", err)
	}
	rows, rerr := csv.NewReader(&cbuf).ReadAll()
	if rerr != nil {
		t.Fatalf("read csv: %v", rerr)
	}
	if len(rows) != 2 {
		t.Fatalf("csv rows = %d, want 2 (header + record)", len(rows))
	}
	col := -1
	for c, name := range rows[0] {
		if name == "error" {
			col = c
			break
		}
	}
	if col < 0 {
		t.Fatalf("csv header %v carries no error column", rows[0])
	}
	if got := rows[1][col]; got != "" {
		t.Fatalf("csv error cell = %q, want empty", got)
	}
}

// --- PQ-41 input-grammar parity (issue #117, watched RED) -------------------

// TestListFileStdinAlias: -l - is the explicit stdin-file alias (PQ-41;
// the nmap -iL - / nuclei -l - convention) — the composition reads the
// stdin seam as the list, never the filesystem. "-" is not a file name:
// the rc1 shape refused at the grammar with `open -: no such file or
// directory` (exit 64). The alias composes with -- under the stdin
// class's expand-exactly-once rule (the companion marker adds nothing),
// and every line still arrives by the one grammar, deduped by host:port.
func TestListFileStdinAlias(t *testing.T) {
	hybridAddr := startHybridFixture(t)

	t.Run("the alias reads stdin as the list file", func(t *testing.T) {
		setStdin(t, hybridAddr+"\n")
		output := filepath.Join(t.TempDir(), "alias.jsonl")
		var out, errOut bytes.Buffer
		code := run([]string{"-l", "-", "-jsonl", "-o", output, "-quic-off"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		if out.Len() != 0 {
			t.Fatalf("stdout polluted (results belong to -o): %q", out.String())
		}
		recs := readJSONLRecords(t, output)
		if len(recs) != 1 {
			t.Fatalf("records = %d, want 1", len(recs))
		}
		target := recs[0]["target"].(map[string]any)
		if target["input"] != hybridAddr {
			t.Fatalf("input = %v, want %q (the alias feeds the one grammar)", target["input"], hybridAddr)
		}
	})

	t.Run("the alias composes with --, stdin expands once", func(t *testing.T) {
		setStdin(t, hybridAddr+"\n")
		output := filepath.Join(t.TempDir(), "alias-marker.jsonl")
		var out, errOut bytes.Buffer
		code := run([]string{"-l", "-", "-o", output, "-jsonl", "-quic-off", "--"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		recs := readJSONLRecords(t, output)
		if len(recs) != 1 {
			t.Fatalf("records = %d, want 1 (-l - and -- name the same stdin; the class expands exactly once)", len(recs))
		}
	})
}

// --- PQ-41 implicit piped stdin (issue #117, watched RED) -------------------

// setStdinPipe pins the piped-stdin class the implicit-input detector
// reports (restored on cleanup): the seam decouples the run's input
// decision from whatever stdin the test process inherited.
func setStdinPipe(t *testing.T, piped bool) {
	t.Helper()
	prev := stdinIsPipe
	stdinIsPipe = func() bool { return piped }
	t.Cleanup(func() { stdinIsPipe = prev })
}

// TestImplicitPipedStdin: with a pipe on stdin and NO target source given
// (-u/-l/--/adapters all absent) the pipe IS the target source (PQ-41;
// issue #117) — the httpx/naabu handoff convention, `pd-tool | scanner`.
// The rc1 shape refuses with "no target specified" on the same command.
// An interactive terminal (a character device) never triggers the implicit
// read, an explicit source wins over the pipe, and a piped-but-EMPTY
// stdin still refuses exit 64 — honestly: nothing arrived, nothing
// scanned. A piped-open never-terminating stdin blocks by contract (the
// documented automation hazard).
func TestImplicitPipedStdin(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	classicAddr := startClassicFixture(t)

	t.Run("a piped stdin with no other source scans", func(t *testing.T) {
		setStdinPipe(t, true)
		setStdin(t, hybridAddr+"\n")
		output := filepath.Join(t.TempDir(), "implicit.jsonl")
		var out, errOut bytes.Buffer
		code := run([]string{"-jsonl", "-o", output, "-quic-off"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		if out.Len() != 0 {
			t.Fatalf("stdout polluted (results belong to -o): %q", out.String())
		}
		recs := readJSONLRecords(t, output)
		if len(recs) != 1 {
			t.Fatalf("records = %d, want 1", len(recs))
		}
		if input := recs[0]["target"].(map[string]any)["input"]; input != hybridAddr {
			t.Fatalf("input = %v, want %q", input, hybridAddr)
		}
	})

	t.Run("an empty pipe refuses honestly at exit 64", func(t *testing.T) {
		setStdinPipe(t, true)
		setStdin(t, "")
		var out, errOut bytes.Buffer
		code := run([]string{}, &out, &errOut)
		if code != 64 {
			t.Fatalf("exit = %d, want 64 (nothing arrived; the run must refuse)", code)
		}
		if !strings.Contains(errOut.String(), "piped stdin") {
			t.Fatalf("refusal does not name the empty pipe: %q", errOut.String())
		}
		if out.Len() != 0 {
			t.Fatalf("stdout polluted on the refusal path: %q", out.String())
		}
	})

	t.Run("an explicit -u beats the pipe", func(t *testing.T) {
		setStdinPipe(t, true)
		setStdin(t, classicAddr+"\n")
		output := filepath.Join(t.TempDir(), "explicit.jsonl")
		var out, errOut bytes.Buffer
		code := run([]string{"-u", hybridAddr, "-jsonl", "-o", output, "-quic-off"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		recs := readJSONLRecords(t, output)
		if len(recs) != 1 {
			t.Fatalf("records = %d, want 1 (the piped spec must not compose beside -u)", len(recs))
		}
		if input := recs[0]["target"].(map[string]any)["input"]; input != hybridAddr {
			t.Fatalf("input = %v, want %q (-u is the explicit source)", input, hybridAddr)
		}
	})

	t.Run("a non-pipe stdin never reads implicitly", func(t *testing.T) {
		setStdinPipe(t, false)
		setStdin(t, hybridAddr+"\n")
		var out, errOut bytes.Buffer
		code := run([]string{}, &out, &errOut)
		if code != 64 {
			t.Fatalf("exit = %d, want 64 (a terminal/char-device stdin is never an implicit source)", code)
		}
		if out.Len() != 0 {
			t.Fatalf("stdout polluted on the refusal path: %q", out.String())
		}
	})

	t.Run("an adapter file is a source; the pipe stays unread", func(t *testing.T) {
		setStdinPipe(t, true)
		setStdin(t, hybridAddr+"\n")
		output := filepath.Join(t.TempDir(), "adapter.jsonl")
		var out, errOut bytes.Buffer
		code := run([]string{"-from-httpx", writeSpecFile(t, "hx.txt", "https://"+classicAddr+"\n"),
			"-jsonl", "-o", output, "-quic-off"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		recs := readJSONLRecords(t, output)
		if len(recs) != 1 {
			t.Fatalf("records = %d, want 1 (the adapter is the source; the pipe must not join)", len(recs))
		}
		if input := recs[0]["target"].(map[string]any)["input"]; input != classicAddr {
			t.Fatalf("input = %v, want %q (the adapter dialed, not the piped stdin)", input, classicAddr)
		}
	})
}

// --- PQ-41 scheme:// on the spec path (issue #117, watched RED) -------------

// TestSchemeSpecs: -u/-l/-- lines accept scheme://host[:port] — the
// USAGE -u row's promise implemented on the spec path with the same
// internal/target strip the adapters apply (PQ-41; issue #117). A URL
// path suffix stays refused with the adapter named; CIDR specs keep
// their exactly-as-shaped grammar semantics (the composition refuses the
// class untouched); the record's input is the stripped host[:port] spec
// the same way an adapter line composes.
func TestSchemeSpecs(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	classicAddr := startClassicFixture(t)

	t.Run("-u accepts scheme://host:port", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "scheme.jsonl")
		var out, errOut bytes.Buffer
		code := run([]string{"-u", "https://" + hybridAddr, "-jsonl", "-o", output, "-quic-off"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		if out.Len() != 0 {
			t.Fatalf("stdout polluted (results belong to -o): %q", out.String())
		}
		recs := readJSONLRecords(t, output)
		if len(recs) != 1 {
			t.Fatalf("records = %d, want 1", len(recs))
		}
		if input := recs[0]["target"].(map[string]any)["input"]; input != hybridAddr {
			t.Fatalf("input = %v, want %q (the stripped spec composes, adapter-style)", input, hybridAddr)
		}
	})

	t.Run("piped scheme lines scan through the stdin marker", func(t *testing.T) {
		setStdin(t, "https://"+classicAddr+"\n")
		output := filepath.Join(t.TempDir(), "scheme-marker.jsonl")
		var out, errOut bytes.Buffer
		code := run([]string{"-o", output, "-jsonl", "-quic-off", "--"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		recs := readJSONLRecords(t, output)
		if len(recs) != 1 {
			t.Fatalf("records = %d, want 1", len(recs))
		}
		if input := recs[0]["target"].(map[string]any)["input"]; input != classicAddr {
			t.Fatalf("input = %v, want %q", input, classicAddr)
		}
	})

	t.Run("-l lines accept the scheme", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "scheme-list.jsonl")
		var out, errOut bytes.Buffer
		code := run([]string{"-l", writeSpecFile(t, "schemes.txt", "https://"+classicAddr+"\n"),
			"-jsonl", "-o", output, "-quic-off"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		recs := readJSONLRecords(t, output)
		if len(recs) != 1 {
			t.Fatalf("records = %d, want 1", len(recs))
		}
		if input := recs[0]["target"].(map[string]any)["input"]; input != classicAddr {
			t.Fatalf("input = %v, want %q", input, classicAddr)
		}
	})

	t.Run("a URL path suffix on -u stays refused, the adapter named", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := run([]string{"-u", "https://" + hybridAddr + "/api"}, &out, &errOut)
		if code != 64 {
			t.Fatalf("exit = %d, want 64 (a URL path is not spec-path grammar)", code)
		}
		if !strings.Contains(errOut.String(), "-from-httpx") {
			t.Fatalf("refusal does not name the adapter: %q", errOut.String())
		}
		if out.Len() != 0 {
			t.Fatalf("stdout polluted on the refusal path: %q", out.String())
		}
	})

	t.Run("a piped URL path refuses naming the adapter", func(t *testing.T) {
		setStdin(t, "https://"+classicAddr+"/api\n")
		output := filepath.Join(t.TempDir(), "scheme-path.jsonl")
		var out, errOut bytes.Buffer
		code := run([]string{"-o", output, "-quic-off", "--"}, &out, &errOut)
		if code != 64 {
			t.Fatalf("exit = %d, want 64 (a URL path is not spec-path grammar)", code)
		}
		if !strings.Contains(errOut.String(), "-from-httpx") {
			t.Fatalf("refusal does not name the adapter: %q", errOut.String())
		}
		if out.Len() != 0 {
			t.Fatalf("stdout polluted on the refusal path: %q", out.String())
		}
	})

	t.Run("CIDR specs are untouched by the scheme strip", func(t *testing.T) {
		setStdin(t, "192.0.2.0/24\n")
		var out, errOut bytes.Buffer
		code := run([]string{"-o", filepath.Join(t.TempDir(), "cidr.jsonl"), "-quic-off", "--"}, &out, &errOut)
		if code != 64 {
			t.Fatalf("exit = %d, want 64 (the CIDR class refuses until expansion ships)", code)
		}
		if !bytes.Contains(errOut.Bytes(), []byte("cidr expansion lands with PQ-16")) {
			t.Fatalf("stderr missing the cidr deferral message: %q", errOut.String())
		}
		if out.Len() != 0 {
			t.Fatalf("stdout polluted on the refusal path: %q", out.String())
		}
	})
}
