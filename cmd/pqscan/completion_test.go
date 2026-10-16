package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// The completion pair's watched RED (ADR-0002) — PQ-40: the stub is
// inert (the emission lands in the GREEN half), so every pin fails on
// the missing script.
func TestRunCompletionBash(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-completion", "bash"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, want 0 (the emission; stderr: %s)", code, errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, "complete -F") {
		t.Fatalf("bash completion does not register a completion function:\n%s", got)
	}
	// every implemented flag is completable
	fs, _ := newFlagSet()
	fs.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(got, "-"+f.Name) {
			t.Fatalf("bash completion missing -%s", f.Name)
		}
	})
	// the choice values complete
	if !strings.Contains(got, "fast deep pq") {
		t.Fatalf("bash completion missing the -mode values:\n%s", got)
	}
}

// TestRunCompletionZsh pins the zsh shape and the install line.
func TestRunCompletionZsh(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-completion", "zsh"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, "#compdef pqscan") {
		t.Fatalf("zsh completion missing the #compdef header:\n%s", got)
	}
	for _, want := range []string{"-mode", "fast deep pq", "-l", "auto ptr-then-ip ip-only"} {
		if !strings.Contains(got, want) {
			t.Fatalf("zsh completion missing %q:\n%s", want, got)
		}
	}
}

// TestRunCompletionDeterministic: two runs, one byte stream.
func TestRunCompletionDeterministic(t *testing.T) {
	for _, shell := range []string{"bash", "zsh"} {
		var a, b bytes.Buffer
		if code := run([]string{"-completion", shell}, &a, &b); code != 0 {
			t.Fatalf("%s: exit = %d", shell, code)
		}
		var c bytes.Buffer
		var errOut bytes.Buffer
		if code := run([]string{"-completion", shell}, &c, &errOut); code != 0 {
			t.Fatalf("%s: rerun exit = %d", shell, code)
		}
		if a.String() != c.String() {
			t.Fatalf("%s: the completion script is not deterministic", shell)
		}
	}
}

// TestRunCompletionUnknownShell: an unsupported shell is a usage
// refusal naming the valid values.
func TestRunCompletionUnknownShell(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-completion", "fish"}, &out, &errOut)
	if code != 64 {
		t.Fatalf("exit = %d, want 64", code)
	}
	if !strings.Contains(errOut.String(), "bash or zsh") {
		t.Fatalf("refusal does not name the valid shells: %q", errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout polluted: %q", out.String())
	}
}

// TestRunCompletionWinsOverScan: the emission is a meta path like
// -version — it wins over the target composition (-completion zsh
// -json emits the script and exits 0 without scanning).
func TestRunCompletionWinsOverScan(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-completion", "zsh", "-json"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "#compdef pqscan") {
		t.Fatalf("the -json selector overrode the completion emission")
	}
}
