package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"crypto/tls"

	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/tlsx"
	fixtures "github.com/shsingh/pqscan/tests/fixtures/servers"
)

// TestRunVersion pins the -version path (PQ-10 coverage audit; watched
// RED lands with these tests before run() is implemented).
func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-version"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !bytes.Contains(out.Bytes(), []byte("pqscan 0.0.1")) {
		t.Fatalf("version output missing %q; got %q", "pqscan 0.0.1", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr polluted on -version: %q", errOut.String())
	}
}

// TestRunUsage pins the no-argument path: usage guidance on stderr with
// the EX_USAGE exit code (64) — the engine-stub contract until M1.
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
