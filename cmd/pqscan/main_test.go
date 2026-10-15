package main

import (
	"bytes"
	"testing"
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
