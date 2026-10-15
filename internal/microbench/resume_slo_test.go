// Resume SLO (PQ-24, spec §7.8): a SIGKILL-resume cycle re-scans only the
// pending targets and the wall time of the resumed pass stays inside the
// recorded budget — 50 loopback targets, the standard W (the fast-path
// pipeline's own in-order scan, no override), TCP plane only (-quic-off:
// the fixture farm is a TLS negotiation oracle; a QUIC probe against
// fixture-less UDP ports would measure timeout behavior, not resume).
// Offline CI never touches this: the gate reads the ENVIRONMENT for
// PQSCAN_PERF (offline runs show the SKIP line), and the CI perf suite
// (.github/workflows/perf.yml) runs it under PQSCAN_PERF=1.
//
// The resumed pass is the real binary (./cmd/pqscan -l … -o … -resume):
// phase 1 scans the list, the journal fills (spec §7.6: one JSON line per
// scanned target), the process is SIGKILLed mid-run, phase 2 replays that
// journal and scans only what is missing. The observation surface is the
// journal's run_id partition: entries appended under the resumed run's id
// are exactly the re-scans the contract allows.
//
// Watched-RED history (the pair's RED = the SLO assertion vs a
// deliberately-pessimal seed): the RED run seeded the replayed journal
// with MANGLED completion keys — the compat/keying regression class (a
// journal from a schema whose target keys moved replays as "nothing
// complete" and the resumed pass re-scans everything) — so the SLO
// assertion failed before the true seed was wired in. The verbatim runs
// are the issue #47 audit record (ADR-0002 §3).
package microbench

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/out"
	"github.com/shsingh/pqscan/internal/wal"
)

// perfSuiteEnv is the CI-perf-suite gate. The helper reads the
// ENVIRONMENT, never a constant's name.
const perfSuiteEnv = "PQSCAN_PERF"

// The recorded SLO: 50 loopback targets, the standard W, the resumed pass
// inside 6s of wall. The per-handshake fixture delay is what makes both
// SLO terms measurable: a killed run reaches the kill window while real
// pending targets remain, and a re-scan-everything pass is distinguishable
// from a pending-only pass.
const (
	resumeSLOTargets       = 50
	resumeSLOKillAt        = 25              // journal entries before the SIGKILL lands
	resumeSLOBudget        = 6 * time.Second // the SLO budget (the scaled fixture for "10M WAL < 60s")
	resumeSLOStartDeadline = 30 * time.Second
	fixtureHandshakeDelay  = 100 * time.Millisecond
)

// pessimalSeed is the watched-RED switch: the deliberately-pessimal
// journal seed (mangled completion keys → the resumed pass re-scans
// everything) vs the true resume contract (the killed run's real journal
// replays). The RED state (true) is the pair's first commit with its
// failing run in the commit body; the GREEN commit seeds the true
// contract, so the value stays false — flipping it back to true IS the
// SLO drill (the SLO assertion must fail: it caught the class before).
const pessimalSeed = false

// TestResumeSLO: the SIGKILL-resume cycle re-scans only the pending
// targets and the resumed pass stays inside the wall budget (spec §7.8,
// PQ-24).
func TestResumeSLO(t *testing.T) {
	if os.Getenv(perfSuiteEnv) == "" {
		t.Skip("PQSCAN_PERF not set; resume SLO probe skipped")
	}

	bin := buildNativePQScan(t)
	farm := startResumeSLOFarm(t, resumeSLOTargets)
	// The list order is the pipeline's scan order (the Engine scans
	// in-order): the journal fills from the head of the list and the kill
	// leaves the tail pending.
	var specs strings.Builder
	for _, addr := range farm.addrs {
		specs.WriteString(addr + "\n")
	}
	listFile := filepath.Join(t.TempDir(), "resume-slo-targets.txt")
	if err := os.WriteFile(listFile, []byte(specs.String()), 0o600); err != nil {
		t.Fatalf("target list: %v", err)
	}

	dir := t.TempDir()
	outFile := filepath.Join(dir, "results.jsonl")
	walPath := filepath.Join(dir, "results.wal")

	// ---- Phase 1: the killed run. Every journaled record survives
	// SIGKILL (os.File writes land in the kernel immediately; the fsync
	// batching is for power loss, not kills) — a torn tail is at most
	// one line, and the replay tolerates it as malformed.
	run1Start := time.Now()
	var out1, errOut1 bytes.Buffer
	cmd1 := exec.Command(bin, "-l", listFile, "-o", outFile, "-jsonl", "-quic-off")
	cmd1.Stdout, cmd1.Stderr = &out1, &errOut1
	if err := cmd1.Start(); err != nil {
		t.Fatalf("run 1 start: %v", err)
	}
	killedAt := waitJournalEntries(t, walPath, resumeSLOKillAt, resumeSLOStartDeadline)
	if err := cmd1.Process.Signal(os.Kill); err != nil {
		t.Fatalf("SIGKILL run 1: %v", err)
	}
	if err := cmd1.Wait(); err == nil {
		t.Fatalf("run 1 exited cleanly after %d journal entries; the kill never landed in the scan window", killedAt)
	} else if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("run 1 wait: %v (want a killed-signal exit)", err)
	}
	t.Logf("SIGKILL landed at %d valid journal entries (run 1 wall %.2fs)", killedAt, time.Since(run1Start).Seconds())

	preEntries, preMalformed := parseWALJournal(t, walPath)
	if len(preEntries)+preMalformed < resumeSLOKillAt {
		t.Fatalf("journal before resume = %d valid + %d malformed, want >= %d", len(preEntries), preMalformed, resumeSLOKillAt)
	}
	preRunIDs := map[string]bool{}
	preMaxSeq := uint64(0)
	for _, e := range preEntries {
		preRunIDs[e.RunID] = true
		if e.Seq > preMaxSeq {
			preMaxSeq = e.Seq
		}
	}
	seedResumeWAL(t, walPath, preEntries)

	// pending = the composed target set minus what the pre-resume journal
	// completed — the same host:port keying the engine filters on.
	completed := map[string]bool{}
	for _, e := range preEntries {
		completed[walKey(e.Record.Target.Host, e.Record.Target.Port)] = true
	}
	addrByKey := map[string]string{}
	for _, addr := range farm.addrs {
		host, port, _ := strings.Cut(addr, ":")
		p, err := strconv.Atoi(port)
		if err != nil {
			t.Fatalf("fixture port %q: %v", port, err)
		}
		addrByKey[walKey(host, uint16(p))] = addr
	}
	pending := map[string]bool{}
	for key := range addrByKey {
		if !completed[key] {
			pending[key] = true
		}
	}
	if len(pending) == 0 {
		t.Fatalf("the kill left zero pending targets (all %d journaled inside one poll); re-run", resumeSLOTargets)
	}

	// ---- Phase 2: the resumed pass — the real -resume run.
	var out2, errOut2 bytes.Buffer
	cmd2 := exec.Command(bin, "-l", listFile, "-o", outFile, "-jsonl", "-resume", "-quic-off")
	cmd2.Stdout, cmd2.Stderr = &out2, &errOut2
	resumeStart := time.Now()
	if err := cmd2.Run(); err != nil {
		t.Fatalf("resumed pass: %v (stderr: %s)", err, errOut2.String())
	}
	elapsed := time.Since(resumeStart)
	t.Logf("resumed pass wall: %.2fs for %d pending of %d targets (SLO budget %.0fs)",
		elapsed.Seconds(), len(pending), resumeSLOTargets, resumeSLOBudget.Seconds())

	// The engine's own resume accounting, on the same journal, must match
	// the test-side contract arithmetic.
	wantSummary := fmt.Sprintf("scanning %d", len(pending))
	if !strings.Contains(errOut2.String(), wantSummary) {
		t.Fatalf("resume stderr missing %q (the resumed pass's accounting); stderr:\n%s", wantSummary, errOut2.String())
	}

	postEntries, postMalformed := parseWALJournal(t, walPath)
	if postMalformed < preMalformed {
		t.Fatalf("journal lost malformed-line accounting across resume: pre %d, post %d", preMalformed, postMalformed)
	}

	// The re-scans = entries appended under a run id the pre-resume
	// journal never carried, for a real run candidate.
	reScannedSet := map[string]bool{}
	for _, e := range postEntries {
		if preRunIDs[e.RunID] {
			continue
		}
		key := walKey(e.Record.Target.Host, e.Record.Target.Port)
		if addrByKey[key] != "" {
			reScannedSet[key] = true
		}
	}

	// Fresh appends are contract-visible only beyond the pre-resume
	// watermark (the sequence continues from the replayed one).
	for _, e := range postEntries {
		if preRunIDs[e.RunID] {
			continue // the replayed entries legitimately carry the old watermark
		}
		if e.Seq <= preMaxSeq {
			t.Fatalf("journal sequence not monotone across resume: seq %d <= pre-resume watermark %d", e.Seq, preMaxSeq)
		}
	}

	// SLO term 1 (the watched-RED assertion): the resumed pass re-scans
	// ONLY the pending targets — nothing completed-by-the-crash is
	// rescanned and nothing pending is left behind.
	var extra, missing []string
	for key := range reScannedSet {
		if !pending[key] {
			extra = append(extra, key)
		}
	}
	for key := range pending {
		if !reScannedSet[key] {
			missing = append(missing, key)
		}
	}
	if len(extra) != 0 || len(missing) != 0 {
		t.Fatalf("resumed pass re-scan set != pending set: %d complete-but-re-scanned, %d pending-not-re-scanned (fresh entries %d, pending %d)\nextra: %v\nmissing: %v",
			len(extra), len(missing), len(reScannedSet), len(pending),
			addrsOf(extra, addrByKey)[:min(len(extra), 3)], addrsOf(missing, addrByKey)[:min(len(missing), 3)])
	}

	// The completed targets were not journaled again: every pre-resume
	// entry survives the replay (append-only across resume, semantically
	// by run_id+seq — not by byte luck).
	byRunSeq := map[string]wal.Entry{}
	for _, e := range postEntries {
		byRunSeq[e.RunID+"/"+strconv.FormatUint(e.Seq, 10)] = e
	}
	for _, e := range preEntries {
		keep, ok := byRunSeq[e.RunID+"/"+strconv.FormatUint(e.Seq, 10)]
		if !ok {
			t.Fatalf("append-only violated: pre-resume entry %s seq %d absent after resume", e.RunID, e.Seq)
		}
		if got := walKey(keep.Record.Target.Host, keep.Record.Target.Port); got != walKey(e.Record.Target.Host, e.Record.Target.Port) || keep.Ts != e.Ts {
			t.Fatalf("pre-resume entry %s seq %d mutated: %s@%s vs %s@%s",
				e.RunID, e.Seq, got, keep.Ts, walKey(e.Record.Target.Host, e.Record.Target.Port), e.Ts)
		}
	}

	// The resumed output holds ALL targets (the completed replay out of
	// the journal, the pending from the scan): the contract's visible half.
	outJSONL, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("resumed output read: %v", err)
	}
	outLines := strings.Split(strings.TrimSuffix(string(outJSONL), "\n"), "\n")
	if len(outLines) == 1 && outLines[0] == "" {
		outLines = nil
	}
	if len(outLines) != resumeSLOTargets {
		t.Fatalf("resumed output carries %d records, want %d (replayed + scanned)", len(outLines), resumeSLOTargets)
	}

	// SLO term 2: the resumed pass's wall time inside the budget.
	if elapsed > resumeSLOBudget {
		t.Fatalf("resume SLO: resumed pass wall %.2fs > %.0fs budget (%d pending of %d targets)",
			elapsed.Seconds(), resumeSLOBudget.Seconds(), len(pending), resumeSLOTargets)
	}

	totalHandshakes := int64(0)
	for _, c := range farm.handshakes {
		totalHandshakes += c.Load()
	}
	t.Logf("fixture farm: %d loopback TLS servers (the standard hybrid row), %d handshakes served across both passes",
		len(farm.addrs), totalHandshakes)
}

// TestResumeSLOWALPartition: the journal partition the SLO reads is
// correct offline — valid-entry parse, malformed-tail tolerance, run-id
// partition — a pure stdlib check over a synthetic journal (no env gate,
// no network).
func TestResumeSLOWALPartition(t *testing.T) {
	entry := func(runID string, seq uint64, host string, port uint16) wal.Entry {
		stamp := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC).Add(time.Duration(seq) * time.Second).Format(time.RFC3339Nano)
		return wal.Entry{
			RunID: runID,
			Seq:   seq,
			Ts:    stamp,
			Record: out.Record{
				Schema: out.SchemaVersion,
				Mode:   "fast",
				Target: out.TargetRecord{Input: fmt.Sprintf("%s:%d", host, port), Host: host, Port: port},
			},
		}
	}
	l1, err := json.Marshal(entry("seed-run", 1, "127.0.0.1", 40001))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	l2, err := json.Marshal(entry("seed-run", 2, "127.0.0.1", 40002))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	l3, err := json.Marshal(entry("resume-run", 3, "127.0.0.1", 40003))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "part.wal")
	journal := string(l1) + "\n" + string(l2) + "\n" + "{torn" + "\n" + string(l3) + "\n"
	if err := os.WriteFile(path, []byte(journal), 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}

	entries, malformed := parseWALJournal(t, path)
	if len(entries) != 3 || malformed != 1 {
		t.Fatalf("journal parse = %d valid + %d malformed, want 3 valid + 1 malformed", len(entries), malformed)
	}
	preRunIDs := map[string]bool{"seed-run": true}
	var reScanned []string
	for _, e := range entries {
		if preRunIDs[e.RunID] {
			continue
		}
		reScanned = append(reScanned, walKey(e.Record.Target.Host, e.Record.Target.Port))
	}
	if len(reScanned) != 1 || reScanned[0] != "127.0.0.1:40003" {
		t.Fatalf("run-id partition = %v, want exactly [127.0.0.1:40003]", reScanned)
	}
	if entries[0].Ts == "" {
		t.Fatalf("entry stamp lost in parse: %+v", entries[0])
	}
}

// ---- SLO helpers (test-local; the farm is per-test, never shared). ----

// walKey is the journal's completion key (host:port, canonical bracketing
// for IPv6) — the exact key the engine's resume filter reads.
func walKey(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// addrsOf maps wal keys back to the fixture addrs for readable failures.
func addrsOf(keys []string, addrByKey map[string]string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, addrByKey[k])
	}
	return out
}

// tryParseWALJournal reads a journal into (valid entries, malformed
// count) — the replay's tolerance, test-side: a torn tail (the killed
// run's last write) is one malformed line at most.
func tryParseWALJournal(path string) ([]wal.Entry, int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil // the run has not journaled anything yet
		}
		return nil, 0, err
	}
	var entries []wal.Entry
	malformed := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e wal.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			malformed++
			continue
		}
		entries = append(entries, e)
	}
	return entries, malformed, nil
}

func parseWALJournal(t *testing.T, path string) ([]wal.Entry, int) {
	t.Helper()
	entries, malformed, err := tryParseWALJournal(path)
	if err != nil {
		t.Fatalf("journal read %s: %v", path, err)
	}
	if malformed > 0 {
		t.Logf("journal %s: %d malformed line(s) skipped (a torn tail is at most the killed run's last write)", path, malformed)
	}
	return entries, malformed
}

// waitJournalEntries polls until the killed run's journal holds n valid
// entries, then returns the count — the SIGKILL window.
func waitJournalEntries(t *testing.T, walPath string, n int, deadline time.Duration) int {
	t.Helper()
	deadlineTS := time.Now().Add(deadline)
	var (
		count     int
		malformed int
	)
	for {
		entries, malformedNow, err := tryParseWALJournal(walPath)
		if err != nil {
			t.Fatalf("journal poll %s: %v", walPath, err)
		}
		count, malformed = len(entries), malformedNow
		if count >= n {
			return count
		}
		if time.Now().After(deadlineTS) {
			t.Fatalf("journal %s never reached %d entries within %s (last read: %d valid + %d malformed)",
				walPath, n, deadline, count, malformed)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// seedResumeWAL decides the journal the resumed run replays. Pessimal
// seed (the RED state): replace the killed run's journal with mangled
// completion keys — the compat/keying regression class, where the replay
// matches no candidate and the resumed pass re-scans everything. True
// contract (GREEN): the killed run's real journal is exactly what the
// resume replays.
func seedResumeWAL(t *testing.T, walPath string, pre []wal.Entry) {
	t.Helper()
	if !pessimalSeed {
		return
	}
	if err := os.Remove(walPath); err != nil {
		t.Fatalf("pessimal seed: replace journal: %v", err)
	}
	w, err := wal.Create(walPath, "pessimal-seed")
	if err != nil {
		t.Fatalf("pessimal seed journal: %v", err)
	}
	for i, e := range pre {
		mangled := out.Record{
			Schema: out.SchemaVersion,
			Mode:   "fast",
			Target: out.TargetRecord{
				Input: fmt.Sprintf("pessimal-%d.invalid:%d", i, e.Record.Target.Port),
				Host:  fmt.Sprintf("pessimal-%d.invalid", i),
				Port:  e.Record.Target.Port,
			},
		}
		if err := w.Append(&mangled); err != nil {
			t.Fatalf("pessimal seed append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("pessimal seed close: %v", err)
	}
	t.Logf("pessimal seed: journal replaced with %d mangled-key entries (replay matches no candidate)", len(pre))
}

// buildNativePQScan builds ./cmd/pqscan natively for the resumed pass —
// the size-gate helper's release build is a different target (GOOS pin);
// this one is the local-machine probe binary, in $TMPDIR only.
func buildNativePQScan(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "pqscan.native")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/pqscan")
	cmd.Dir = pqscanModuleRoot(t)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build ./cmd/pqscan: %v\n%s", err, combined)
	}
	return bin
}

// resumeSLOFarm is n loopback TLS servers serving the standard hybrid
// fixture row (t13-hybrid-mlkem) with a per-handshake delay and a served-
// handshake counter (logging evidence: kills cancel in-flight probes, so
// the contract observation is the journal, not raw connection counts).
type resumeSLOFarm struct {
	addrs      []string
	handshakes []*atomic.Int64
}

func startResumeSLOFarm(t *testing.T, n int) *resumeSLOFarm {
	t.Helper()
	cert := resumeSLOCertificate(t)
	cfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
	farm := &resumeSLOFarm{handshakes: make([]*atomic.Int64, n)}
	for i := 0; i < n; i++ {
		ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("listen %d: %v", i, err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		counter := &atomic.Int64{}
		farm.handshakes[i] = counter
		go func(ln *net.TCPListener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return // closed by the test cleanup
				}
				go func(conn net.Conn) {
					_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
					time.Sleep(fixtureHandshakeDelay)
					counter.Add(1)
					_ = tls.Server(conn, cfg).Handshake()
				}(conn)
			}
		}(ln)
		farm.addrs = append(farm.addrs, ln.Addr().String())
	}
	return farm
}

// resumeSLOCertificate is the farm's shared fixture certificate (same
// posture as the matrix fixture: pqscan.fixture, IP SANs for loopback).
func resumeSLOCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(20261015),
		Subject:               pkix.Name{CommonName: "pqscan.fixture"},
		DNSNames:              []string{"pqscan.fixture"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert gen: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
