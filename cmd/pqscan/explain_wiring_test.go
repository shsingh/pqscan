package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRunExplainRefusedUnderMachineFormats (PQ-38): -explain is a text
// presentation surface; under a machine format it is a command-line
// mistake (the machine streams stay pristine), refused before anything
// composes or scans. The selector order does not matter.
func TestRunExplainRefusedUnderMachineFormats(t *testing.T) {
	rows := [][]string{
		{"-u", "example.com", "-json", "-explain"},
		{"-u", "example.com", "-jsonl", "-explain"},
		{"-u", "example.com", "-csv", "-explain"},
		{"-u", "example.com", "-urls", "-explain"},
		{"-u", "example.com", "-explain", "-csv"},
	}
	for _, args := range rows {
		var out, errOut bytes.Buffer
		code := run(args, &out, &errOut)
		if code != 64 {
			t.Fatalf("args %v: exit = %d, want 64 (the refusal)", args, code)
		}
		if !strings.Contains(errOut.String(), "text output only") {
			t.Fatalf("args %v: refusal does not name the -text-only contract: %q", args, errOut.String())
		}
		if out.Len() != 0 {
			t.Fatalf("args %v: stdout polluted: %q", args, out.String())
		}
	}
}

// TestRunExplainAddsTheBlock (PQ-38): with -explain the default text run
// carries the plain-language block under each target line — the verdict
// in words first, then the per-layer readings.
func TestRunExplainAddsTheBlock(t *testing.T) {
	addr := startHybridFixture(t)
	var out, errOut bytes.Buffer
	code := run([]string{"-u", addr, "-explain"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	got := out.String()
	for _, want := range []string{
		"  - rating: pq-partial 40/100",
		"  - key exchange: X25519MLKEM768 (pq_hybrid)",
		"  - certificate: classical identity",
		"  - quic: ",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("explained output missing %q; got:\n%s", want, got)
		}
	}
}

// TestRunExplainStaysTransparentWithout (PQ-38): without -explain the
// default run is the shipped rc1 text line and nothing else — no block,
// no interpretation markers; the encoder-level pins own the byte shape.
func TestRunExplainStaysTransparentWithout(t *testing.T) {
	addr := startHybridFixture(t)
	var out, errOut bytes.Buffer
	code := run([]string{"-u", addr}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Fatalf("one target = one output line; got %d lines:\n%s", n, out.String())
	}
	if strings.Contains(out.String(), "  - ") {
		t.Fatalf("block leaked without -explain:\n%s", out.String())
	}
}
