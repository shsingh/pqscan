package main

// doubledash_test.go is the PQ-48 pair-of-pins: the doubled dash spellings
// (--word) parse and surface everywhere their single-dash twin (-word)
// does. Go's flag package already reads one and two dashes alike, so the
// parse-parity pins below were TRUE before this lane — the issue is that
// nothing said so. The battery pins both halves of that contract:
//
//   - value parity for EVERY registered flag (newFlagSet().VisitAll) across
//     the dash-count boundary: the exact fs.Parse call run() performs on the
//     single registration surface binds the -word and --word arguments to
//     the same rendered values with the same parse outcome (a parse failure
//     is run()'s exit-64 face — the same shape, the same 64).
//   - run()-level parity for every flag family whose surface behavior is
//     observable offline: the meta paths (-h/--h, -version/--version,
//     -completion/--completion), the output selectors (the raw-arg
//     chooseFormat pre-scan: last selector wins across dash counts,
//     "-csv --jsonl" selects jsonl), the refusal paths (--mode bogus,
//     --explain --jsonl), and the input grammar (--l - reads stdin like
//     -l -; the adapter files; the spec paths). Silent-value flags
//     (rate, threads, debug, ...) are value-pinned at the parse boundary
//     and behavior-pinned through run() exactly where an offline
//     observation exists; the live-scan families stay owned by the
//     fixture tests.
//
// The parse-level layer is deliberately the same newFlagSet() + fs.Parse
// run() executes (main.go run() — "One registration surface"): pinning it
// pins the real boundary, not a second copy of it.

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// doubledDashProbes carries a non-default probe value per value-taking
// flag, so the parity pins bind something observable (a bare -mode parse
// would leave the default and render equal to an unparsed run).
var doubledDashProbes = map[string]string{
	"u":          "10.0.0.0/24",
	"l":          "-",
	"from-httpx": "hx.txt",
	"from-naabu": "nb.txt",
	"shard":      "1/2",
	"o":          "out.txt",
	"completion": "zsh",
	"debug-out":  "diag.json",
	"mode":       "pq",
	"deep":       "full",
	"sni":        "ip-only",
	"certs-dir":  "certs",
	"rate":       "5",
	"threads":    "50",
}

// parseForDash parses one dash form through the registration surface run()
// uses and returns every flag's rendered value plus whether the parse
// succeeded (failure = run()'s exit-64 face; the parse-error stream goes to
// a sink, never the test process's stderr).
func parseForDash(args []string) (vals map[string]string, ok bool) {
	fs, _ := newFlagSet()
	var sink bytes.Buffer
	fs.SetOutput(&sink)
	err := fs.Parse(args)
	vals = map[string]string{}
	fs.VisitAll(func(f *flag.Flag) { vals[f.Name] = f.Value.String() })
	return vals, err == nil
}

// TestEveryFlagParsesBothDashForms: for every registered flag, run()'s
// parser binds -<name> and --<name> (same argument value) to the same
// rendered value, with the same parse success/failure — the flag package's
// dash equivalence, verified and PINNED on live registrations.
func TestEveryFlagParsesBothDashForms(t *testing.T) {
	fs, _ := newFlagSet()
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	if len(names) == 0 {
		t.Fatal("no registered flags found: the parity battery has nothing to pin")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			// booleans take the bare spelling; everything else takes the
			// probe value (default "probe" keeps new registrations pinned
			// the day they appear).
			var args1, args2 []string
			if bf, isBool := fs.Lookup(name).Value.(interface{ IsBoolFlag() bool }); isBool && bf.IsBoolFlag() {
				args1 = []string{"-" + name}
				args2 = []string{"--" + name}
			} else {
				probe := doubledDashProbes[name]
				if probe == "" {
					probe = "probe"
				}
				args1 = []string{"-" + name, probe}
				args2 = []string{"--" + name, probe}
			}
			vals1, ok1 := parseForDash(args1)
			vals2, ok2 := parseForDash(args2)
			if ok1 != ok2 {
				t.Errorf("-%s vs --%s: parse success = %v vs %v (the exit-64 face diverges across the dash boundary)", name, name, ok1, ok2)
			}
			if len(vals1) != len(vals2) {
				t.Fatalf("-%s vs --%s: %d vs %d flags bound", name, name, len(vals1), len(vals2))
			}
			for n, v1 := range vals1 {
				if v2, bound := vals2[n]; !bound || v1 != v2 {
					t.Errorf("flag -%s binds %q on its single-dash spelling but %q on its doubled spelling", n, v1, v2)
				}
			}
			// the probe must have landed (the parity above is meaningful
			// only for arguments that actually bound)
			parsed := vals1[name]
			if len(args1) == 2 && parsed != args1[len(args1)-1] {
				t.Errorf("-%s %v did not bind the probe (bound %q); the parity pin would pass on defaults", name, args1[len(args1)-1], parsed)
			}
		})
	}
}

// runDashPair runs one parity row both ways and reports the deltas: the
// two spellings must exit alike with byte-identical output surfaces.
func runDashPair(t *testing.T, row string, single, doubled []string) (codeS, codeD int, outS, outD, errS, errD bytes.Buffer) {
	t.Helper()
	codeS = run(single, &outS, &errS)
	codeD = run(doubled, &outD, &errD)
	if codeS != codeD {
		t.Errorf("%s: exit(-form) = %d, exit(--form) = %d (stderrs: %q | %q)", row, codeS, codeD, errS.String(), errD.String())
	}
	if outS.String() != outD.String() {
		t.Errorf("%s: stdout differs across the dash boundary:\n%s\n----\n%s", row, outS.String(), outD.String())
	}
	if errS.String() != errD.String() {
		t.Errorf("%s: stderr differs across the dash boundary:\n%q\n----\n%q", row, errS.String(), errD.String())
	}
	if codeS == 64 && strings.TrimSpace(errS.String()) == "" {
		t.Errorf("%s: usage refusal with EMPTY stderr (a refusal must say why)", row)
	}
	return
}

// TestDoubledDashRunParity: the run()-level parity rows for every flag
// family whose surface behavior is observable offline — meta paths, output
// selectors, refusal paths, input grammar (see the file head).
func TestDoubledDashRunParity(t *testing.T) {
	t.Run("meta: help covers both spellings, byte-identical", func(t *testing.T) {
		var reference bytes.Buffer
		run([]string{"-h"}, &reference, new(bytes.Buffer))
		for _, spell := range [][]string{{"--h"}, {"-help"}, {"--help"}, {"-h=true"}, {"--h=true"}} {
			var out, errOut bytes.Buffer
			if code := run(spell, &out, &errOut); code != 0 {
				t.Errorf("%v: exit = %d, want 0 (the help path; stderr: %q)", spell, code, errOut.String())
				continue
			}
			if out.String() != reference.String() {
				t.Errorf("%v: help renders differently than -h", spell)
			}
		}
	})

	t.Run("meta: -help=false is not help (the =-branch stays honest)", func(t *testing.T) {
		runDashPair(t, "-help=false", []string{"-help=false"}, []string{"--help=false"})
	})

	t.Run("meta: version stamp over both spellings", func(t *testing.T) {
		var outS, outD, errS, errD bytes.Buffer
		codeS := run([]string{"-version"}, &outS, &errS)
		codeD := run([]string{"--version"}, &outD, &errD)
		if codeS != 0 || codeD != 0 || outS.String() != outD.String() {
			t.Errorf("version parity: rc %d/%d, stdout %q vs %q", codeS, codeD, outS.String(), outD.String())
		}
		if !strings.HasPrefix(outS.String(), "pqscan ") {
			t.Errorf("-version is not the stamp: %q", outS.String())
		}
	})

	t.Run("meta: completion emission and its refusal", func(t *testing.T) {
		for _, shell := range []string{"bash", "zsh"} {
			runDashPair(t, "completion "+shell,
				[]string{"-completion", shell}, []string{"--completion", shell})
		}
		// the fish refusal: the 64 usage class naming the valid shells,
		// identical across the dash boundary
		codeS, codeD, _, _, errS, _ := runDashPair(t, "completion fish",
			[]string{"-completion", "fish"}, []string{"--completion", "fish"})
		if codeS != 64 || codeD != 64 || !strings.Contains(errS.String(), "bash or zsh") {
			t.Errorf("completion fish: the refusal is not the 64 usage class naming bash or zsh (%d/%d, %q)", codeS, codeD, errS.String())
		}
	})

	t.Run("selectors: the raw-arg pre-scan reads both dash forms", func(t *testing.T) {
		// the -explain refusal names the chosen format: a deterministic
		// offline observation of chooseFormat's normalization
		for _, sel := range []string{"jsonl", "csv", "urls"} {
			runDashPair(t, "selector -"+sel,
				[]string{"-explain", "-" + sel}, []string{"-explain", "--" + sel})
		}
		// last selector wins, across the dash-count boundary both ways
		for _, row := range []struct {
			args []string
			want string
		}{
			{[]string{"-csv", "--jsonl"}, "jsonl"},
			{[]string{"--csv", "-jsonl"}, "jsonl"},
			{[]string{"-jsonl", "--csv"}, "csv"},
			{[]string{"--jsonl", "-csv"}, "csv"},
			{[]string{"--urls", "-csv"}, "csv"},
		} {
			var out, errOut bytes.Buffer
			if code := run(append([]string{"-explain"}, row.args...), &out, &errOut); code != 64 {
				t.Errorf("%v: exit = %d, want 64", row.args, code)
				continue
			}
			if want := "(drop the -" + row.want + " selector)"; !strings.Contains(errOut.String(), want) {
				t.Errorf("selectors %v chose wrong: stderr %q, want %q", row.args, errOut.String(), want)
			}
		}
		// the =-branch stays intact on both spellings: =true selects,
		// =false does not
		var out, errOut bytes.Buffer
		if code := run([]string{"-explain", "--csv=true"}, &out, &errOut); code != 64 || !strings.Contains(errOut.String(), "(drop the -csv selector)") {
			t.Errorf("--csv=true: rc=%d stderr=%q (the =-true branch should select csv)", code, errOut.String())
		}
		if code := run([]string{"-explain", "--json=false"}, &out, &errOut); code != 64 {
			t.Errorf("--json=false: rc=%d (the =-false branch must not select; only the no-targets refusal may follow)", code)
		}
		runDashPair(t, "text through both spellings",
			[]string{"-explain", "-text"}, []string{"-explain", "--text"})
	})

	t.Run("refusals: the flagged-value paths read the doubled dashes", func(t *testing.T) {
		runDashPair(t, "mode", []string{"-u", "example.com", "-mode", "bogus"}, []string{"-u", "example.com", "--mode", "bogus"})
		runDashPair(t, "deep", []string{"-u", "example.com", "-deep", "bogus"}, []string{"-u", "example.com", "--deep", "bogus"})
		runDashPair(t, "sni", []string{"-u", "example.com", "-sni", "bogus"}, []string{"-u", "example.com", "--sni", "bogus"})
		runDashPair(t, "shard", []string{"-u", "example.com", "-shard", "9/1"}, []string{"-u", "example.com", "--shard", "9/1"})
		runDashPair(t, "explain under machine output",
			[]string{"-explain", "-jsonl"}, []string{"-explain", "--jsonl"})
		// the refusal must name the parsed value — the value truly
		// traveled through run() on the doubled spelling
		var out, errOut bytes.Buffer
		if code := run([]string{"-u", "example.com", "--mode", "bogus"}, &out, &errOut); code != 64 || !strings.Contains(errOut.String(), `"bogus"`) {
			t.Errorf("--mode bogus: rc=%d stderr=%q (the refusal must carry the parsed value)", code, errOut.String())
		}
	})

	t.Run("input grammar: the doubled spellings feed the composition", func(t *testing.T) {
		// the target spec: the cidr refusal is the deterministic offline
		// observation that the parsed -u value reached the grammar
		runDashPair(t, "target spec",
			[]string{"-u", "10.0.0.0/24"}, []string{"--u", "10.0.0.0/24"})
		// the list file: the missing-file refusal names the parsed path
		absent := filepath.Join(t.TempDir(), "absent.txt")
		runDashPair(t, "list file",
			[]string{"-l", absent}, []string{"--l", absent})
		// the stdin alias: --l - reads the stdin seam exactly like -l -
		// (the cidr line refuses AFTER the read; an unread stdin would
		// refuse with the no-targets line instead)
		for _, spell := range [][]string{{"-l", "-"}, {"--l", "-"}} {
			setStdin(t, "10.0.0.0/24\n")
			var out, errOut bytes.Buffer
			if code := run(spell, &out, &errOut); code != 64 || !strings.Contains(errOut.String(), "cidr") {
				t.Errorf("%v on piped stdin: rc=%d stderr=%q (the alias must read stdin — the post-read cidr refusal proves it)", spell, code, errOut.String())
			}
		}
		// the adapters: the missing-file refusal proves run() dispatched
		// the adapter on the doubled spelling with the parsed path
		runDashPair(t, "from-httpx",
			[]string{"-from-httpx", absent}, []string{"--from-httpx", absent})
		runDashPair(t, "from-naabu",
			[]string{"-from-naabu", absent}, []string{"--from-naabu", absent})
	})

	t.Run("silent values: the offline-observable behavior rows", func(t *testing.T) {
		// numeric parse failures are the usage class on both spellings
		runDashPair(t, "rate malformed", []string{"-rate", "soon"}, []string{"--rate", "soon"})
		runDashPair(t, "threads malformed", []string{"-threads", "soon"}, []string{"--threads", "soon"})
		// -resume without -o: the refusal on either spelling
		runDashPair(t, "resume without -o", []string{"-resume"}, []string{"--resume"})
		// the journal-path collision refusal (-o .wal) on both spellings
		runDashPair(t, "o collision", []string{"-o", ".wal"}, []string{"--o", ".wal"})
		// -certs-dir: the directory is created before the no-targets
		// refusal — the doubled spelling must leave the same file-system
		// effect, not merely the same exit code
		dirS := filepath.Join(t.TempDir(), "certs-s")
		dirD := filepath.Join(t.TempDir(), "certs-d")
		var outS, errS, outD, errD bytes.Buffer
		codeS := run([]string{"-certs-dir", dirS}, &outS, &errS)
		codeD := run([]string{"--certs-dir", dirD}, &outD, &errD)
		if codeS != 64 || codeD != 64 {
			t.Errorf("certs-dir rows: rc %d/%d, want 64/64", codeS, codeD)
		}
		if _, statS := os.Stat(dirS); statS != nil {
			t.Errorf("-certs-dir %s: directory not created (%v)", dirS, statS)
		}
		if _, statD := os.Stat(dirD); statD != nil {
			t.Errorf("--certs-dir %s: directory not created (%v)", dirD, statD)
		}
	})
}

// TestCompletionsListBothSpellings: both completion generators offer the
// doubled dash twin for every registered flag (PQ-48) — an operator's
// "--m<TAB>" completes, on bash and zsh alike.
func TestCompletionsListBothSpellings(t *testing.T) {
	fs, _ := newFlagSet()
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	for _, shell := range []string{"bash", "zsh"} {
		var out, errOut bytes.Buffer
		if code := run([]string{"-completion", shell}, &out, &errOut); code != 0 {
			t.Fatalf("-completion %s: rc=%d (stderr: %q)", shell, code, errOut.String())
		}
		script := out.String()
		for _, name := range names {
			for _, form := range []string{"-" + name, "--" + name} {
				if !strings.Contains(script, form) {
					t.Errorf("-completion %s misses the flag spelling %s", shell, form)
				}
			}
		}
	}
}

// TestHelpDocumentsTheEquivalence: the -h help carries the PQ-48
// equivalence note, prominently (near the top, before the flag rows) —
// "--word spells the same as -word everywhere".
func TestHelpDocumentsTheEquivalence(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-h"}, &out, &errOut); code != 0 {
		t.Fatalf("-h: rc=%d (stderr: %q)", code, errOut.String())
	}
	help := out.String()
	note := "--word spells the same as -word"
	if !strings.Contains(help, note) {
		t.Errorf("-h misses the doubled-dash equivalence note %q — the doubled dashes already parse, the help must say so", note)
	}
	flagsAt := strings.Index(help, "FLAGS, BY ROLE")
	noteAt := strings.Index(help, note)
	if flagsAt >= 0 && noteAt >= 0 && noteAt > flagsAt {
		t.Errorf("the equivalence note rides below the flag rows (%d vs %d): it must sit near the top, before the surface rows", noteAt, flagsAt)
	}
}
