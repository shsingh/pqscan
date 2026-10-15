package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shsingh/pqscan/internal/grammar"
)

// walLine mirrors one journal entry for the test-side parses.
type walLine struct {
	RunID  string `json:"run_id"`
	Seq    uint64 `json:"seq"`
	Ts     string `json:"ts"`
	Record struct {
		Schema int    `json:"schema"`
		Mode   string `json:"mode"`
		Target struct {
			Input string `json:"input"`
			Host  string `json:"host"`
			Port  uint16 `json:"port"`
		} `json:"target"`
	} `json:"record"`
}

func walHost(t *testing.T, addr string) string {
	t.Helper()
	parsed, err := grammar.Parse(addr)
	if err != nil {
		t.Fatalf("grammar.Parse(%q): %v", addr, err)
	}
	return parsed[0].Host
}

// TestResumeRun (PQ-16, watched RED): a WAL pre-populated with 1 of 2
// targets + -resume scans ONLY the pending target; the final output holds
// ALL records (the completed one replays out of the WAL, stamp and all),
// the journal gains exactly one new line under the new run id, and the
// sequence stays monotone.
func TestResumeRun(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	classicAddr := startClassicFixture(t)
	hybridHost := walHost(t, hybridAddr)
	classicHost := walHost(t, classicAddr)

	dir := t.TempDir()
	outFile := filepath.Join(dir, "results.jsonl")
	walPath := filepath.Join(dir, "results.wal")

	// 1. Seed run: one complete, non-resume target run — its journal lands
	// next to the output file.
	var out1, errOut1 bytes.Buffer
	code := run([]string{"-u", hybridAddr, "-o", outFile, "-quic-off"}, &out1, &errOut1)
	if code != 0 {
		t.Fatalf("seed exit = %d (stderr: %s)", code, errOut1.String())
	}
	if out1.Len() != 0 {
		t.Fatalf("stdout polluted (results belong to -o): %q", out1.String())
	}
	walB, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("wal after seed run: %v", err)
	}
	seedLines := strings.Split(strings.TrimSuffix(string(walB), "\n"), "\n")
	if len(seedLines) != 1 {
		t.Fatalf("seed wal lines = %d, want 1", len(seedLines))
	}
	var seed walLine
	if err := json.Unmarshal([]byte(seedLines[0]), &seed); err != nil {
		t.Fatalf("seed wal line invalid (%q): %v", seedLines[0], err)
	}
	if seed.Record.Target.Host != hybridHost || seed.Seq != 1 || seed.RunID == "" || seed.Ts == "" {
		t.Fatalf("seed wal entry = %+v (want host %s seq 1 run id + stamp)", seed, hybridHost)
	}

	// 2. Resume run: both targets composed; the hybrid one is already
	// complete. Only the classic one may be scanned; the output carries
	// both records (CSV so the replayed stamp is visible in the cells).
	listFile := writeSpecFile(t, "resume-two.txt", hybridAddr+"\n"+classicAddr+"\n")
	var out2, errOut2 bytes.Buffer
	code = run([]string{"-l", listFile, "-o", outFile, "-csv", "-resume", "-quic-off"}, &out2, &errOut2)
	if code != 0 {
		t.Fatalf("resume exit = %d (stderr: %s)", code, errOut2.String())
	}
	if out2.Len() != 0 {
		t.Fatalf("stdout polluted on the resume run: %q", out2.String())
	}
	for _, want := range []string{"pqscan: resume: WAL ", "1 of 2 targets already complete", "scanning 1"} {
		if !strings.Contains(errOut2.String(), want) {
			t.Fatalf("resume summary missing %q; stderr:\n%s", want, errOut2.String())
		}
	}

	outB, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("resumed output: %v", err)
	}
	rows := strings.Split(strings.TrimSuffix(string(outB), "\n"), "\n")
	if len(rows) != 3 {
		t.Fatalf("resumed output rows = %d, want 3 (header + 2 records):\n%s", len(rows), outB)
	}
	if rows[0] != "target,host,port,ptr,sni,negotiated,group_name,group_class,suite,version,alpn,quic_state,quic_group,udp_blocked,error,ts" {
		t.Fatalf("csv header wrong: %s", rows[0])
	}
	fields1 := strings.Split(rows[1], ",")
	if fields1[0] != hybridAddr || fields1[1] != hybridHost || strings.Join(fields1[5:8], ",") != "4588,X25519MLKEM768,pq_hybrid" {
		t.Fatalf("replayed row 1 = %v, want the hybrid record (input %s, host %s) from the WAL", fields1, hybridAddr, hybridHost)
	}
	if fields1[15] != seed.Ts {
		t.Fatalf("row 1 ts = %q, want the wal stamp %q (the record must come from the journal, not a rescan)", fields1[15], seed.Ts)
	}
	fields2 := strings.Split(rows[2], ",")
	if fields2[0] != classicAddr || fields2[1] != classicHost {
		t.Fatalf("row 2 = %v, want the pending target scanned (input %s, host %s)", fields2, classicAddr, classicHost)
	}
	if fields2[15] == "" || fields2[15] == seed.Ts {
		t.Fatalf("row 2 ts = %q, want a fresh scan stamp", fields2[15])
	}

	// 3. Journal after resume: exactly 2 lines — the seed entry byte-for-
	// byte unchanged, one new entry with the new run id and seq 2.
	walB2, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("wal after resume: %v", err)
	}
	resumeLines := strings.Split(strings.TrimSuffix(string(walB2), "\n"), "\n")
	if len(resumeLines) != 2 {
		t.Fatalf("wal lines after resume = %d, want 2 (the completed target must NOT be re-journaled):\n%s", len(resumeLines), walB2)
	}
	if resumeLines[0] != seedLines[0] {
		t.Fatalf("first journal entry changed (append-only violated)\n got: %s\nwant: %s", resumeLines[0], seedLines[0])
	}
	var fresh walLine
	if err := json.Unmarshal([]byte(resumeLines[1]), &fresh); err != nil {
		t.Fatalf("resumed wal line invalid (%q): %v", resumeLines[1], err)
	}
	if fresh.RunID == seed.RunID {
		t.Fatalf("resumed entry carries the seed run id %q; want the new run's id", fresh.RunID)
	}
	if fresh.Seq != 2 || fresh.Record.Target.Host != classicHost {
		t.Fatalf("resumed entry = %+v, want seq 2 for %s", fresh, classicHost)
	}
}

// TestResumeRequiresOutputFile: -resume without -o refuses (EX_USAGE) —
// the journal path derives from the output file.
func TestResumeRequiresOutputFile(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	var out, errOut bytes.Buffer
	code := run([]string{"-u", hybridAddr, "-resume", "-quic-off"}, &out, &errOut)
	if code != 64 {
		t.Fatalf("exit = %d, want 64 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "-resume requires -o") {
		t.Fatalf("stderr missing the -requires--o message: %q", errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout polluted: %q", out.String())
	}
}

// TestResumeMissingWALFullScan: -resume with no journal yet scans
// everything and says so (a first resume over a fresh state is a run,
// not an error).
func TestResumeMissingWALFullScan(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	dir := t.TempDir()
	outFile := filepath.Join(dir, "fresh.jsonl")
	var out, errOut bytes.Buffer
	code := run([]string{"-u", hybridAddr, "-o", outFile, "-jsonl", "-resume", "-quic-off"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "no WAL") {
		t.Fatalf("stderr missing the missing-WAL notice: %q", errOut.String())
	}
	recs := readJSONLRecords(t, outFile)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	// the run journaled its record: a resumed follow-up would skip nothing
	if _, err := os.Stat(filepath.Join(dir, "fresh.wal")); err != nil {
		t.Fatalf("journal missing after the run: %v", err)
	}
}

// TestResumeNothingPending: a resume whose WAL already holds every
// composed target scans nothing, replays all records, and leaves the
// journal untouched.
func TestResumeNothingPending(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	dir := t.TempDir()
	outFile := filepath.Join(dir, "done.jsonl")
	walPath := filepath.Join(dir, "done.wal")

	var out1, errOut1 bytes.Buffer
	if code := run([]string{"-u", hybridAddr, "-o", outFile, "-quic-off"}, &out1, &errOut1); code != 0 {
		t.Fatalf("seed exit = %d (stderr: %s)", code, errOut1.String())
	}
	seedB, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("seed wal: %v", err)
	}

	var out2, errOut2 bytes.Buffer
	listFile := writeSpecFile(t, "one.txt", hybridAddr+"\n")
	code := run([]string{"-l", listFile, "-o", outFile, "-csv", "-resume", "-quic-off"}, &out2, &errOut2)
	if code != 0 {
		t.Fatalf("resume exit = %d (stderr: %s)", code, errOut2.String())
	}
	if !strings.Contains(errOut2.String(), "0 targets to scan") {
		t.Fatalf("stderr missing the nothing-pending notice: %q", errOut2.String())
	}
	outB, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("resumed output: %v", err)
	}
	rows := strings.Split(strings.TrimSuffix(string(outB), "\n"), "\n")
	if len(rows) != 2 {
		t.Fatalf("output rows = %d, want 2 (header + the replayed record):\n%s", len(rows), outB)
	}
	walB2, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("wal after no-op resume: %v", err)
	}
	if string(walB2) != string(seedB) {
		t.Fatalf("journal changed on a nothing-pending resume:\n got: %s\nwant: %s", walB2, seedB)
	}
}
