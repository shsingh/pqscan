package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRunDeepModeTextParity (PQ-46): -mode deep's text line carries
// the executed plan's counts and the certificate layer — the same
// story `-jsonl` would tell, on the line a human reads.
func TestRunDeepModeTextParity(t *testing.T) {
	addr := startHybridFixture(t)
	var out, errOut bytes.Buffer
	code := run([]string{"-u", addr, "-mode", "deep", "-deep", "standard"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	got := out.String()
	for _, want := range []string{
		" deep=standard:",
		"p/", "ok/", "rej",
		" cert=ecdsa-with-SHA256/ECDSA",
		" pq=pq-partial(40)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("deep-mode text line missing %q; got:\n%s", want, got)
		}
	}
}

// TestRunFastModeCertOnLine (PQ-46): the certificate layer renders on
// every mode's text line — the pq-mode / fast-mode delta vs -jsonl
// was exactly this missing block.
func TestRunFastModeCertOnLine(t *testing.T) {
	addr := startHybridFixture(t)
	var out, errOut bytes.Buffer
	if code := run([]string{"-u", addr, "-mode", "pq"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(out.String(), " cert=ecdsa-with-SHA256/ECDSA") {
		t.Fatalf("pq-mode text line lost the certificate tail:\n%s", out.String())
	}
}
