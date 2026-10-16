package main

// surface_test.go is the surface-contract audit (PQ-45): ONE visible
// test that re-checks the whole human-facing CLI surface on every code
// change — so checking the CLI never requires cutting a binary.
//
//	go test ./cmd/pqscan/ -run TestCLISurfaceContract -v
//
// renders, under -v: the per-flag coverage table (help group +
// man-page row + completion reach), the full rendered -h, a live
// fixture scan with -explain (the complete human surface a recipe
// promises), both completion script headers, and the repo gates'
// verdicts. CI's test workflow runs it alongside everything else.
//
// The layers it audits already ship their own focused tests
// (TestRunHelp, the completion pins, the drift gate); this file has
// exactly one job: make the WHOLE surface's truth visible and assert
// the cross-cutting contract in one place. It deliberately does NOT
// duplicate the input-grammar battery — PQ-41's stream tests own that
// grammar, and a second copy would go stale the day the real tests
// change.

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// repoRoot resolves the clone root from the test's package directory
// (go test runs each package from its own dir): cmd/pqscan is two
// levels below.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join(".", "..", ".."))
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	for _, marker := range []string{"USAGE.md", "scripts"} {
		if _, err := os.Stat(filepath.Join(root, marker)); err != nil {
			t.Fatalf("%s is not the pqscan repo root (missing %s): %v", root, marker, err)
		}
	}
	return root
}

// usageManRows parses the USAGE.md OPTIONS rows with the same line
// grammar the drift gate's awk uses: the block starts at a line whose
// leading-trimmed text is OPTIONS and ends at the first column-0
// [A-Z#] header; a row's tokens are its FIRST field plus the
// comma-list continuation, "--" maps to the stdin synthetic.
func usageManRows(t *testing.T, root string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "USAGE.md"))
	if err != nil {
		t.Fatalf("read USAGE.md: %v", err)
	}
	rows := map[string]bool{}
	inOptions := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !inOptions {
			if trimmed == "OPTIONS" {
				inOptions = true
			}
			continue
		}
		if line != "" && line[0] >= 'A' && (line[0] <= 'Z' || line[0] == '#') {
			break // the column-0 section header ends the OPTIONS block
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if !strings.HasPrefix(fields[0], "-") {
			continue // continuation/prose lines are not rows
		}
		if strings.HasPrefix(line, "--") || fields[0] == "--" {
			rows["stdin"] = true // the synthetic token for the stdin marker
			continue
		}
		j := 0
		for ; j < len(fields); j++ {
			tok := strings.TrimSuffix(fields[j], ",")
			if !strings.HasPrefix(tok, "-") {
				break
			}
			rows[tok] = true
			if !strings.HasSuffix(fields[j], ",") {
				break // the comma-list continues only while tokens end with ,
			}
		}
	}
	return rows
}

// plannedManRows is the doc-ahead allowlist (scripts/usage-planned-flags.txt),
// normalized dash-less like the gate reads it.
func plannedManRows(t *testing.T, root string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "usage-planned-flags.txt"))
	if err != nil {
		t.Fatalf("read planned-flags allowlist: %v", err)
	}
	rows := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rows[strings.TrimPrefix(strings.TrimSuffix(trimmed, ","), "-")] = true
	}
	return rows
}

// helpGroupFor resolves a flag's rendered group (name, position).
func helpGroupFor(name string) (string, int) {
	for _, grp := range helpGroups {
		for i, n := range grp.flags {
			if n == name {
				return grp.name, i
			}
		}
	}
	return "", -1
}

// runGate shells one repo gate script and returns its combined output
// with the exit status as a verdict string.
func runGate(t *testing.T, root, script string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", filepath.Join(root, "scripts", script), root)
	cmd.Dir = root
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %s: %v", script, err)
	}
	return strings.TrimRight(buf.String(), "\n"), rc
}

func TestCLISurfaceContract(t *testing.T) {
	root := repoRoot(t)
	fs, _ := newFlagSet()
	usageRows := usageManRows(t, root)
	planned := plannedManRows(t, root)

	// ---- 1. every implemented flag: help + man page + completion reach.
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	sort.Strings(names)
	t.Logf("── implemented flags: %d ──", len(names))
	for _, name := range names {
		f := fs.Lookup(name)
		if f.Usage == "" {
			t.Errorf("-%-14s registered WITHOUT a description (the help would render nothing)", name)
			continue
		}
		grp, pos := helpGroupFor(name)
		if pos < 0 {
			t.Errorf("-%-14s registered but in NO help group", name)
			continue
		}
		if !usageRows["-"+name] {
			t.Errorf("-%-14s in help group %q but MISSING its USAGE.md OPTIONS row", name, grp)
			continue
		}
		t.Logf("-%-14s group=%-24s man=OK (%2d of group)", name, grp, pos+1)
	}
	// the reverse direction: man rows outside src+planned are the
	// unauthorized drift the gate names — assert the same union here so
	// the report shows the offending rows verbatim.
	for row := range usageRows {
		if row == "stdin" {
			continue // the synthetic stdin token (the -- marker)
		}
		dashless := strings.TrimPrefix(row, "-")
		if _, err := fsLookup(fs, dashless); err != nil {
			if !planned[dashless] {
				t.Errorf("USAGE.md row %s is neither a registered flag nor on the planned allowlist", row)
			}
		}
	}

	// ---- 2. -h renders the full practitioner help.
	var help, helpErr bytes.Buffer
	if code := run([]string{"-h"}, &help, &helpErr); code != 0 {
		t.Fatalf("-h exit = %d, want 0", code)
	}
	if helpErr.Len() != 0 {
		t.Fatalf("-h wrote to stderr: %q", helpErr.String())
	}
	for _, want := range []string{"EXAMPLES", "READING THE OUTPUT", "EXIT STATUS", "post-quantum"} {
		if !bytes.Contains(help.Bytes(), []byte(want)) {
			t.Fatalf("-h missing the %q section", want)
		}
	}
	for _, bad := range []string{"spec.md", "docs/", "PQ-0", "pre-alpha", "register"} {
		if bytes.Contains(help.Bytes(), []byte(bad)) {
			t.Fatalf("-h carries the internal reference %q", bad)
		}
	}
	t.Logf("── -h: sections OK, %d lines rendered ──", strings.Count(help.String(), "\n"))
	t.Logf("rendered -h ↓\n%s", strings.ReplaceAll(strings.TrimRight(help.String(), "\n"), "\n", "\n    | "))

	// ---- 3. -version: the stamp and nothing else.
	var vOut, vErr bytes.Buffer
	if code := run([]string{"-version"}, &vOut, &vErr); code != 0 || vOut.String() != fmt.Sprintf("pqscan %s\n", version) || vErr.Len() != 0 {
		t.Fatalf("-version malformed: rc=%d out=%q err=%q", code, vOut.String(), vErr.String())
	}
	t.Logf("── -version: %q ──", strings.TrimRight(vOut.String(), "\n"))

	// ---- 4. the completions: every flag completable, deterministic.
	for _, shell := range []string{"bash", "zsh"} {
		var a, b, cErr bytes.Buffer
		if code := run([]string{"-completion", shell}, &a, &cErr); code != 0 || cErr.Len() != 0 {
			t.Fatalf("-completion %s: rc=%d err=%q", shell, code, cErr.String())
		}
		if code := run([]string{"-completion", shell}, &b, &cErr); code != 0 || a.String() != b.String() {
			t.Fatalf("-completion %s: not deterministic", shell)
		}
		for _, name := range names {
			if !bytes.Contains(a.Bytes(), []byte("-"+name)) {
				t.Fatalf("-completion %s missing -%s", shell, name)
			}
		}
		head := strings.SplitN(a.String(), "\n", 2)[0]
		t.Logf("── -completion %-4s: header %q, %d flags complete, deterministic ──", shell, head, len(names))
	}
	var fishOut, fishErr bytes.Buffer
	if code := run([]string{"-completion", "fish"}, &fishOut, &fishErr); code != 64 || !bytes.Contains(fishErr.Bytes(), []byte("bash or zsh")) {
		t.Fatalf("-completion fish: rc=%d err=%q, want the 64 refusal naming bash or zsh", code, fishErr.String())
	}
	t.Logf("── -completion fish: refused exit 64 naming bash or zsh ──")

	// ---- 5. the usage-class exit-code table (pre-composition, fast).
	rows := []struct {
		args []string
		code int
	}{
		{nil, 64},
		{[]string{"-u", "example.com", "-mode", "bogus"}, 64},
		{[]string{"-u", "example.com", "-deep", "bogus"}, 64},
		{[]string{"-u", "example.com", "-sni", "bogus"}, 64},
		{[]string{"-u", "example.com", "-shard", "9/1"}, 64},
		{[]string{"-u", "example.com", "-explain", "-json"}, 64},
		{[]string{"-shar" /* unknown flag */}, 64},
		{[]string{"-h"}, 0},
		{[]string{"-version"}, 0},
		{[]string{"-completion", "zsh"}, 0},
	}
	t.Logf("── usage-class exit codes ──")
	for _, row := range rows {
		var o, e bytes.Buffer
		code := run(row.args, &o, &e)
		if code != row.code {
			t.Errorf("exit(%-v) = %d, want %d (stderr: %q)", row.args, code, row.code, e.String())
			continue
		}
		if code == 64 && e.Len() == 0 {
			t.Errorf("exit(%-v) = 64 with EMPTY stderr (a refusal must say why)", row.args)
			continue
		}
		t.Logf("exit(%-24v) = %-3d ✓", row.args, code)
	}

	// ---- 6. one live scan: the complete human surface, verbatim.
	addr := startHybridFixture(t)
	var scanOut, scanErr bytes.Buffer
	if code := run([]string{"-u", addr, "-explain"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("hybrid scan: rc=%d (stderr: %s)", code, scanErr.String())
	}
	for _, want := range []string{
		" pq=pq-partial(40)",
		"  - verdict: pq-partial 40/100",
		"  - key exchange: X25519MLKEM768 (pq_hybrid)",
		"  - certificate: classical identity",
		"  - quic: ",
	} {
		if !bytes.Contains(scanOut.Bytes(), []byte(want)) {
			t.Errorf("the live scan lost %q", want)
		}
	}
	t.Logf("live -explain scan ↓\n%s", indentBlock(scanOut.String()))

	// ---- 7. the repo gates, verdicts visible.
	for _, script := range []string{"check_usage_drift.sh", "check_schema_sync.sh"} {
		out, rc := runGate(t, root, script)
		t.Logf("── gate %-28s rc=%d: %s", script, rc, strings.ReplaceAll(out, "\n", " | "))
		if rc != 0 {
			t.Errorf("gate %s failed: %s", script, out)
		}
	}
}

// fsLookup is the flag-set lookup shaped for the map-driven row check.
func fsLookup(fs *flag.FlagSet, name string) (*flag.Flag, error) {
	f := fs.Lookup(name)
	if f == nil {
		return nil, fmt.Errorf("not registered")
	}
	return f, nil
}

// indentBlock prefixes every line for a legible test log block.
func indentBlock(s string) string {
	return strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n    | ")
}
