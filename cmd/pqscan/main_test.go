package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto/tls"

	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/tlsx"
	fixtures "github.com/shsingh/pqscan/tests/fixtures/servers"
)

// TestRunVersion pins the -version path exactly (PQ-38 scrub): the stamp
// and nothing else — no status words, no developer-document references,
// stdout only. The release stamps `<tag>` via -ldflags; a source build
// prints the default revision.
func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-version"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if got := out.String(); got != "pqscan 0.0.1\n" {
		t.Fatalf("version output = %q, want exactly %q", got, "pqscan 0.0.1\n")
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr polluted on -version: %q", errOut.String())
	}
	for _, bad := range []string{"pre-alpha", "spec", "docs/"} {
		if bytes.Contains(out.Bytes(), []byte(bad)) {
			t.Fatalf("version output carries the internal reference %q: %q", bad, out.String())
		}
	}
}

// TestRunUsage pins the no-argument path: usage guidance on stderr with
// the EX_USAGE exit code (64) — and no internal reference: an issue id
// ("PQ-01"), the word "register", a spec/doc path — none of those mean
// anything to an operator (PQ-38).
func TestRunUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{}, &out, &errOut)
	if code != 64 {
		t.Fatalf("exit = %d, want 64 (EX_USAGE)", code)
	}
	if errOut.Len() == 0 {
		t.Fatal("no usage guidance on stderr")
	}
	if out.String() != "" {
		t.Fatalf("stdout polluted on usage path: %q", out.String())
	}
	for _, bad := range []string{"PQ-", "register", "spec", "docs/"} {
		if bytes.Contains(errOut.Bytes(), []byte(bad)) {
			t.Fatalf("usage guidance carries the internal reference %q: %q", bad, errOut.String())
		}
	}
	for _, want := range []string{"-u", "-l", "--", "-h"} {
		if !bytes.Contains(errOut.Bytes(), []byte(want)) {
			t.Fatalf("usage guidance missing %q: %q", want, errOut.String())
		}
	}
}

// TestRunVersionWiredIntoDiagnostics (PQ-38): the diagnostics footer and
// the machine Report must carry the SAME identity `-version` prints —
// one version symbol, wired from the stamped `version` var, not a
// hard-coded internal default.
func TestRunVersionWiredIntoDiagnostics(t *testing.T) {
	defer func(v string) { version = v }(version)
	version = "v-test-stamp"

	dump := t.TempDir() + "/diag.json"
	var out, errOut bytes.Buffer
	code := run([]string{"-debug", "-debug-out", dump}, &out, &errOut)
	if code != 64 {
		t.Fatalf("exit = %d, want 64 (no targets)", code)
	}
	for _, want := range []string{"v-test-stamp", "pqscan diagnostics"} {
		if !bytes.Contains(errOut.Bytes(), []byte(want)) {
			t.Fatalf("diagnostics footer missing %q:\n%s", want, errOut.String())
		}
	}
	if bytes.Contains(errOut.Bytes(), []byte("0.0.1")) {
		t.Fatalf("diagnostics footer still carries the hard-coded default:\n%s", errOut.String())
	}
	raw, err := os.ReadFile(dump)
	if err != nil {
		t.Fatalf("read debug-out: %v", err)
	}
	var report struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.Version != "v-test-stamp" {
		t.Fatalf("report version = %q, want the stamped identity %q", report.Version, "v-test-stamp")
	}
}

// TestDebugFlagDiagnostics: -debug turns on the human diagnostics stream
// (stderr) and a machine Report via -debug-out — even when nothing is
// scanned, the run's own decisions are on record (issue comments and bug
// reports attach this; PQ-011).
func TestDebugFlagDiagnostics(t *testing.T) {
	dump := t.TempDir() + "/diag.json"
	var out, errOut bytes.Buffer
	code := run([]string{"-debug", "-debug-out", dump}, &out, &errOut)
	if code != 64 {
		t.Fatalf("exit = %d, want 64 (no targets)", code)
	}
	if !bytes.Contains(errOut.Bytes(), []byte("pqscan diagnostics")) {
		t.Fatalf("stderr missing the diagnostics block:\n%s", errOut.String())
	}
	b, err := os.ReadFile(dump)
	if err != nil {
		t.Fatalf("debug-out file: %v", err)
	}
	var rep map[string]any
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("report json invalid: %v", err)
	}
	if rep["schema"].(float64) != 1 {
		t.Fatal("diag report schema missing")
	}
	events := rep["events"].([]any)
	if len(events) < 1 {
		t.Fatal("no events recorded for a CLI-only run")
	}
}

// TestDebugKeepsStdoutClean: the diagnostics stream must NEVER contaminate
// the stdout results stream (chainability rule).
func TestDebugKeepsStdoutClean(t *testing.T) {
	var out, errOut bytes.Buffer
	_ = run([]string{"-debug"}, &out, &errOut)
	if out.Len() != 0 {
		t.Fatalf("debug leaked to stdout: %q", out.String())
	}
}

// tlsx engine instrumentation: the ladder's decisions are diagnostics.
func TestLadderEmitsDiagnostics(t *testing.T) {
	sink, _ := diag.NewSink(nil, 0)
	diag.SetDefault(sink)
	defer diag.SetDefault(nil)

	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-hybrid-mlkem",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})
	_ = tlsx.GroupLadder(addr, "pqscan.fixture", []uint32{4588}, 5*time.Second)

	r, err := sink.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	found := 0
	for _, e := range r.Events {
		if e.Domain == diag.DomTLS && e.Op == "ladder" {
			if e.Fields["negotiated"] == "4588" {
				found++
			}
		}
	}
	if found == 0 {
		t.Fatalf("no tls/ladder diagnostics with negotiated=4588; events:\n%s", mustHuman(t, r))
	}
}

func mustHuman(t *testing.T, r *diag.Report) string {
	t.Helper()
	h, err := diag.Humanize(r)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestRunSingleTargetFastScan: -u target runs the fast-mode probe end to
// end and emits the schema-1 record (rc1's live single-target contract;
// the multi-target grammar lands with PQ-15). The QUIC plane probes only
// hostname targets; the fixture provides a loopback host:port.
func TestRunSingleTargetFastScan(t *testing.T) {
	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-hybrid-mlkem",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		ALPN:             []string{"h2", "http/1.1"},
	})
	outFile := filepath.Join(t.TempDir(), "out.jsonl")

	var out, errOut bytes.Buffer
	code := run([]string{"-u", addr, "-jsonl", "-o", outFile, "-quic-off"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("jsonl: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(b[:len(b)-1], &rec); err != nil {
		t.Fatalf("record json invalid: %v", err)
	}
	if rec["schema"].(float64) != 1 {
		t.Fatal("record schema missing")
	}
	hs, _ := rec["handshake"].(map[string]any)
	if hs["negotiated"].(float64) != 4588 {
		t.Fatalf("handshake.negotiated = %v, want 4588", hs["negotiated"])
	}
	if hs["group_class"] != "pq_hybrid" {
		t.Fatalf("handshake.group_class = %v, want pq_hybrid", hs["group_class"])
	}
	if hs["alpn_neg"] != "h2" {
		t.Fatalf("handshake.alpn_neg = %v, want h2", hs["alpn_neg"])
	}
}

// TestRunSingleTargetText pins the default text one-liner (human output;
// the jsonl line is the machine form).
func TestRunSingleTargetText(t *testing.T) {
	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-hybrid-mlkem",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})
	var out, errOut bytes.Buffer
	code := run([]string{"-u", addr, "-quic-off"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("pq_hybrid")) || !bytes.Contains(out.Bytes(), []byte("X25519MLKEM768")) {
		t.Fatalf("text line missing the negotiated class/group: %q", out.String())
	}
}
