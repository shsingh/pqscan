package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// The help pair's watched RED (ADR-0002): these pins fail against the
// rc1 help (the Go flag dump). The contract: every implemented flag is
// listed under a group, the stdin grammar and the examples and the
// real exit codes and the output glossary are present, and the help
// carries no developer-document references.
func TestRunHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-h"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (-h is the help path)", code)
	}
	got := out.String()
	// the sections an operator reads
	for _, want := range []string{
		"EXAMPLES",
		"READING THE OUTPUT",
		"EXIT STATUS",
		"post-quantum",
		"pq-ready",
		"pq-missing",
		"harvest", // the HNDL plain-language
		"--",      // the stdin grammar
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("-h help missing %q", want)
		}
	}
	// every implemented flag listed (the whole implemented surface)
	fs, _ := newFlagSet()
	fs.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(got, "-"+f.Name) {
			t.Fatalf("-h help missing the implemented flag -%s", f.Name)
		}
	})
	// help is stdout-only, and carries no internal references
	if errOut.Len() != 0 {
		t.Fatalf("-h wrote to stderr: %q", errOut.String())
	}
	for _, bad := range []string{"spec.md", "docs/", "PQ-", "pre-alpha", "register"} {
		if strings.Contains(got, bad) {
			t.Fatalf("-h help carries the internal reference %q", bad)
		}
	}
}

// TestRunHelpSpellingsAndPlacement: the help path covers every spelling
// (-help, --h, --help, =true forms) and stays option-side: past the
// bare -- marker the tokens are target data, never an option (the same
// semantics as the output selectors).
func TestRunHelpSpellingsAndPlacement(t *testing.T) {
	for _, spell := range [][]string{{"-help"}, {"--h"}, {"--help"}, {"-help=true"}, {"-json", "--help"}} {
		var out, errOut bytes.Buffer
		if code := run(spell, &out, &errOut); code != 0 {
			t.Fatalf("%v: exit = %d, want 0", spell, code)
		}
		if !strings.Contains(out.String(), "EXAMPLES") {
			t.Fatalf("%v: not the rich help", spell)
		}
	}
	// past -- : target data. The run refuses for lack of targets and
	// never prints the help.
	var out, errOut bytes.Buffer
	if code := run([]string{"--", "-h"}, &out, &errOut); code == 0 {
		t.Fatalf("-h past -- was consumed as an option; want the data treatment")
	}
	if strings.Contains(out.String(), "EXAMPLES") {
		t.Fatalf("-h past -- printed the help:\n%s", out.String())
	}
}

// TestHelpTableMatchesFlags is the bidirectional pin (PQ-38): every
// registered flag belongs to exactly one render group, every group row
// resolves to a registered flag (or the synthetic -- row), and the
// value-taking flags carry token forms. A registration without a
// group, or a group row without a flag, is drift the drift gate cannot
// see (it reads only the registration shapes).
func TestHelpTableMatchesFlags(t *testing.T) {
	fs, _ := newFlagSet()
	covered := map[string]bool{}
	for _, grp := range helpGroups {
		if grp.name == "" {
			t.Fatalf("group with no name: %+v", grp)
		}
		for _, name := range grp.flags {
			if name == "--" {
				continue // the synthetic stdin row
			}
			f := fs.Lookup(name)
			if f == nil {
				t.Fatalf("group %q lists -%s, which no build registers", grp.name, name)
			}
			if f.Usage == "" {
				t.Fatalf("flag -%s registered without a description: the help has nothing to render", name)
			}
			if seen := covered[name]; seen {
				t.Fatalf("flag -%s listed in more than one group", name)
			}
			covered[name] = true
		}
	}
	fs.VisitAll(func(f *flag.Flag) {
		if !covered[f.Name] {
			t.Fatalf("registered flag -%s is in no render group: the help would omit it", f.Name)
		}
	})
}
