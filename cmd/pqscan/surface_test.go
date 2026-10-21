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
	"regexp"
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

// docRefRe is the zero-reference census inventory (PQ-57): the token
// classes no user-facing string carries — docs/ paths, repo doc file
// names (.md), section-symbol anchors, issue/register references (#N,
// PQ-N), status words, and the PRD itself. TestCLISurfaceContract's
// zero-reference section renders every user-facing face live and greps
// it against this one inventory; a string that re-introduces a
// reference goes red there in CI.
var docRefRe = regexp.MustCompile(`\.md|docs/|§|PQ-?[0-9]|#[0-9]|PRD|\bplanned\b|\bdeferred\b|\blands\b|\blanded\b|\bunimplemented\b|\bpre-alpha\b|\bregister\b`)

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
	// The exit-64 refusal streams are collected here for the
	// zero-reference scan (section 10): a refusal must say why — and
	// carry no doc references while saying it.
	var refArgs [][]string
	var refErrs [][]byte
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
		if code == 64 {
			refArgs = append(refArgs, row.args)
			refErrs = append(refErrs, append([]byte(nil), e.Bytes()...))
		}
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
	if testing.Verbose() {
		t.Logf("live -explain scan ↓\n%s", indentBlock(scanOut.String()))
	}

	// ---- 6b. deep mode: the executed plan's counts ride the line (the
	// format-parity contract, PQ-46 — the story must not depend on the
	// output format).
	var deepOut, deepErr bytes.Buffer
	if code := run([]string{"-u", addr, "-mode", "deep", "-deep", "standard", "-explain"}, &deepOut, &deepErr); code != 0 {
		t.Fatalf("deep scan: rc=%d (stderr: %s)", code, deepErr.String())
	}
	if !strings.Contains(deepOut.String(), " deep=standard:") || !strings.Contains(deepOut.String(), "ok/") || !strings.Contains(deepOut.String(), "rej") {
		t.Errorf("the deep-mode text line lost the executed plan's counts:\n%s", deepOut.String())
	}
	if !strings.Contains(deepOut.String(), " cert=") {
		t.Errorf("the deep-mode text line lost the certificate layer:\n%s", deepOut.String())
	}
	// PQ-50 (issue #134): with -explain the deep block carries the deep
	// reading — the executed plan in words after the verdict lines.
	if !strings.Contains(deepOut.String(), "  - deep: the executed standard plan ran ") ||
		!strings.Contains(deepOut.String(), "the per-probe detail lives in the jsonl findings") {
		t.Errorf("the deep-mode -explain block lost the PQ-50 deep reading line:\n%s", deepOut.String())
	}
	if testing.Verbose() {
		t.Logf("live deep-mode scan ↓\n%s", indentBlock(deepOut.String()))
	}

	// ---- 6c. pq mode: the forced PQ ladder's reading rides -explain
	// (PQ-50, issue #134): the mode's counts tail on the text line, then
	// the ladder line in operator words — the accepted rows named, the
	// refusals framed as the expected default.
	var pqOut, pqErr bytes.Buffer
	if code := run([]string{"-u", addr, "-mode", "pq", "-explain"}, &pqOut, &pqErr); code != 0 {
		t.Fatalf("pq scan: rc=%d (stderr: %s)", code, pqErr.String())
	}
	if !strings.Contains(pqOut.String(), " deep=pq:") {
		t.Errorf("the pq-mode text line lost the ladder's counts tail:\n%s", pqOut.String())
	}
	if !strings.Contains(pqOut.String(), "  - deep: the forced PQ ladder made ") ||
		!strings.Contains(pqOut.String(), "each forced PQ-only group came back refused unless the server truly speaks it") {
		t.Errorf("the pq-mode -explain block lost the PQ-50 ladder reading line:\n%s", pqOut.String())
	}
	if testing.Verbose() {
		t.Logf("live pq-mode scan ↓\n%s", indentBlock(pqOut.String()))
	}

	// ---- 7. the repo gates, verdicts visible.
	for _, script := range []string{"check_usage_drift.sh", "check_schema_sync.sh"} {
		out, rc := runGate(t, root, script)
		t.Logf("── gate %-28s rc=%d: %s", script, rc, strings.ReplaceAll(out, "\n", " | "))
		if rc != 0 {
			t.Errorf("gate %s failed: %s", script, out)
		}
	}

	// ---- 8. the doubled dash spellings (PQ-48): one assertion row per
	// family — the family's lead flag surfaces with BOTH dash forms in
	// both completion generators, and the help renders the equivalence
	// note (--word spells the same as -word everywhere; both parse).
	t.Logf("── doubled dash spellings, one assertion row per family ──")
	for _, shell := range []string{"bash", "zsh"} {
		var cOut, cErr bytes.Buffer
		if code := run([]string{"-completion", shell}, &cOut, &cErr); code != 0 {
			t.Fatalf("-completion %s: rc=%d (stderr: %q)", shell, code, cErr.String())
		}
		script := cOut.String()
		for _, grp := range helpGroups {
			lead := ""
			for _, n := range grp.flags {
				if n != "--" { // the synthetic stdin row leads no family
					lead = n
					break
				}
			}
			if lead == "" {
				continue
			}
			missing := []string{}
			for _, form := range []string{"-" + lead, "--" + lead} {
				if !strings.Contains(script, form) {
					missing = append(missing, form)
					t.Errorf("-completion %s misses %s (the %q family's lead flag must surface with both dash spellings)", shell, form, grp.name)
				}
			}
			if len(missing) == 0 {
				t.Logf("-%-12s family=%-24s both dash forms complete in %s ✓", lead, grp.name, shell)
			}
		}
	}
	if !strings.Contains(help.String(), "--word spells the same as -word") {
		t.Errorf("-h misses the doubled-dash equivalence note: the doubled spellings parse, the help must say so")
	}
	t.Logf("── -h carries the --word ≡ -word equivalence note ──")

	// ---- 9. the -from-nuclei import surface (PQ-55, issue #149): the
	// findings adapter rides the same contract every input flag ships —
	// registered on the single surface with a both-dash parse, a
	// TARGETS AND INPUT help group, a filesystem-path completion entry,
	// its man-page IMPLEMENTED row, and planned-list exit.
	t.Logf("── the -from-nuclei import surface ──")
	if f := fs.Lookup("from-nuclei"); f == nil {
		t.Errorf("-from-nuclei does not register on the single flag surface")
	} else {
		if f.DefValue != "" {
			t.Errorf("-from-nuclei's default is %q, want the empty file default", f.DefValue)
		}
		grp, pos := helpGroupFor("from-nuclei")
		if grp != "TARGETS AND INPUT" || pos < 0 {
			t.Errorf("-from-nuclei help group = %q (pos %d), want TARGETS AND INPUT", grp, pos)
		} else {
			t.Logf("-from-nuclei group=%s (row %d of the group), man=%v", grp, pos+1, usageRows["-from-nuclei"])
		}
	}
	for _, spell := range []string{"-from-nuclei", "--from-nuclei"} {
		var o, e bytes.Buffer
		absent := filepath.Join(t.TempDir(), "absent-findings.jsonl")
		if code := run([]string{spell, absent}, &o, &e); code != 64 {
			t.Errorf("%s <absent file>: exit = %d, want 64 (the adapter's usage refusal)", spell, code)
		} else if strings.Contains(e.String(), "flag provided but not defined") || !strings.Contains(e.String(), "-from-nuclei") {
			t.Errorf("%s <absent file>: stderr %q — want the adapter refusal naming -from-nuclei", spell, e.String())
		} else {
			t.Logf("%s refusal ✓ (both dash spellings parse to the same usage class)", spell)
		}
	}
	if !usageRows["-from-nuclei"] {
		t.Errorf("-from-nuclei has no USAGE.md OPTIONS row (the standing duty: usage = src)")
	}
	if planned["from-nuclei"] {
		t.Errorf("-from-nuclei still rides the planned allowlist: an implemented flag leaves the list in the same change")
	}
	inFileFlags := false
	for _, n := range flagFiles {
		if n == "from-nuclei" {
			inFileFlags = true
		}
	}
	if !inFileFlags {
		t.Errorf("from-nuclei is not in flagFiles: the completions would not offer filesystem paths for its file argument")
	} else {
		t.Logf("-from-nuclei file-completion entry ✓; man row ✓; planned-list exit ✓")
	}

	// ---- 10. the zero-reference policy (PQ-57): every face the CLI can
	// put in front of an operator greps clean of doc-reference tokens.
	// The tool speaks its own language — documentation lives in the
	// repository, never in the binary's output: no docs/ paths, no repo
	// doc file names, no section-symbol anchors, no issue or register
	// references, no status words. Every face is rendered live and
	// scanned by line against the one census inventory (docRefRe). The
	// -h, -version, -explain and refusal faces come off the renders and
	// the fixture scans above; the completions are re-rendered here; one
	// extra fixture scan runs under -debug so the diagnostics human
	// stream and the report footer stand in the scan too.
	t.Logf("── zero-reference policy (PQ-57): every user-facing face × the census inventory ──")
	var dbgOut, dbgErr bytes.Buffer
	if code := run([]string{"-u", addr, "-debug", "-explain"}, &dbgOut, &dbgErr); code != 0 {
		t.Fatalf("the zero-reference scan run: rc=%d (stderr: %s)", code, dbgErr.String())
	}
	zeroFaces := []struct {
		face string
		data []byte
	}{
		{"-h render", help.Bytes()},
		{"-version", vOut.Bytes()},
		{"-explain scan (fast)", scanOut.Bytes()},
		{"-explain scan (deep)", deepOut.Bytes()},
		{"-explain scan (pq ladder)", pqOut.Bytes()},
		{"-debug stderr (human stream + report footer)", dbgErr.Bytes()},
		{"-debug stdout (the scan's own output under -debug)", dbgOut.Bytes()},
	}
	for _, shell := range []string{"bash", "zsh"} {
		var c, ce bytes.Buffer
		if code := run([]string{"-completion", shell}, &c, &ce); code != 0 || ce.Len() != 0 {
			t.Fatalf("-completion %s re-render (the zero-reference pass): rc=%d err=%q", shell, code, ce.String())
		}
		zeroFaces = append(zeroFaces, struct {
			face string
			data []byte
		}{"-completion " + shell + " script", c.Bytes()})
	}
	if len(refErrs) == 0 {
		t.Fatalf("zero-reference pass: no refusal streams were collected (section 5 feeds them)")
	}
	for i, e := range refErrs {
		zeroFaces = append(zeroFaces, struct {
			face string
			data []byte
		}{fmt.Sprintf("exit-64 refusal #%d (%v)", i+1, refArgs[i]), e})
	}
	clean := 0
	for _, face := range zeroFaces {
		lines := strings.Split(string(face.data), "\n")
		hits := 0
		for _, line := range lines {
			if hit := docRefRe.FindString(line); hit != "" {
				hits++
				t.Errorf("the %s surface carries a doc reference %q: %q", face.face, hit, strings.TrimSpace(line))
			}
		}
		if hits == 0 {
			clean++
			t.Logf("zero-reference %-56s ✓ (%d lines)", face.face, len(lines))
		}
	}
	t.Logf("zero-reference policy: %d/%d faces × the census inventory, clean",
		clean, len(zeroFaces))
	t.Logf("zero-reference policy: no docs/ paths, no repo doc file names, no section anchors, no issue or register references, no status words")

	// ---- 11. the ASD-STE100 census: every face stands in the writing
	// standard. The faces render live above (the -h render, the exit-64
	// refusal streams, the fast/deep/pq -explain blocks, the completion
	// scripts). The census scans each face whitespace-normalized — a
	// line wrap never hides a word — against the banned classes below:
	// the future tense, the first/second person, the metaphor nouns
	// (the fixed words are the PQ offer set and the readiness rating,
	// never "ladder" or "verdict"), and the comma/semicolon-joined
	// compound sentences the census can see. A re-introduced class goes
	// red here in CI. The -v output adds the sentence-length report for
	// the prose faces: the sentences over 20 words, report only (the
	// pattern greps are the gate; the counts-tail grammar is a record
	// contract, so the report reads its length and the greps stay the
	// failing check).
	t.Logf("── ASD-STE100 banned-class census ──")
	steFaces := []struct {
		face string
		data []byte
	}{
		{"-h render", help.Bytes()},
		{"-explain block (fast)", scanOut.Bytes()},
		{"-explain block (deep)", deepOut.Bytes()},
		{"-explain block (pq offer set)", pqOut.Bytes()},
	}
	for _, shell := range []string{"bash", "zsh"} {
		var c, ce bytes.Buffer
		if code := run([]string{"-completion", shell}, &c, &ce); code != 0 || ce.Len() != 0 {
			t.Fatalf("-completion %s (census render): rc=%d err=%q", shell, code, ce.String())
		}
		steFaces = append(steFaces, struct {
			face string
			data []byte
		}{"-completion " + shell + " script", c.Bytes()})
	}
	if len(refErrs) == 0 {
		t.Fatalf("STE census: no refusal streams (section 5 feeds them)")
	}
	for i, e := range refErrs {
		steFaces = append(steFaces, struct {
			face string
			data []byte
		}{fmt.Sprintf("refusal stream #%d (%v)", i+1, refArgs[i]), e})
	}
	steHits := 0
	for _, face := range steFaces {
		plain := strings.Join(strings.Fields(string(face.data)), " ")
		for _, row := range steBanned {
			for _, loc := range row.re.FindAllStringIndex(plain, -1) {
				steHits++
				t.Errorf("face %s carries the banned class %q near %q",
					face.face, row.class, steWindow(plain, loc[0], loc[1]))
			}
		}
		if testing.Verbose() {
			long := 0
			for _, s := range steSentences(plain) {
				if n := len(strings.Fields(s)); n > 20 {
					long++
					t.Logf("face %s, %2d words: %s", face.face, n, s)
				}
			}
			t.Logf("census %s: %d sentences, %d over 20 words", face.face, len(steSentences(plain)), long)
		}
	}
	if steHits == 0 {
		t.Logf("STE census: %d faces × %d banned classes, zero", len(steFaces), len(steBanned))
	}
}

// steBanned is the census inventory (as of the STE100 lane): the string
// classes no user-facing face carries. One row per class; the grep runs
// on whitespace-normalized text so a wrapped line never hides a word.
var steBanned = []struct {
	class string
	re    *regexp.Regexp
}{
	{"future tense", regexp.MustCompile(`(?i)\b(will|would)\b`)},
	{"first/second person", regexp.MustCompile(`\b(you|your|yours|we|us|our|ours|me|my|mine)\b|\bI\b`)},
	{"metaphor nouns", regexp.MustCompile(`(?i)\b(verdict|ladder|estate|neighbour|trap)\b`)},
	{"joined compound", regexp.MustCompile(`[,;]\s*(and|but|or|so)\b`)},
}

// steWindow cuts a readable context window around a census hit.
func steWindow(s string, start, end int) string {
	lo, hi := start-40, end+40
	if lo < 0 {
		lo = 0
	}
	if hi > len(s) {
		hi = len(s)
	}
	return "…" + s[lo:hi] + "…"
}

// steSentences splits normalized prose into sentence candidates: the
// spans up to a sentence-period (a report aid; the greps are the gate).
func steSentences(s string) []string {
	var out []string
	cur := ""
	for _, w := range strings.Fields(s) {
		cur += w + " "
		if strings.HasSuffix(w, ".") || strings.HasSuffix(w, "!") || strings.HasSuffix(w, "?") {
			if strings.TrimSuffix(cur, " ") != "" {
				out = append(out, strings.TrimSuffix(cur, " "))
			}
			cur = ""
		}
	}
	if strings.TrimSpace(cur) != "" {
		out = append(out, strings.TrimSpace(cur))
	}
	return out
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
