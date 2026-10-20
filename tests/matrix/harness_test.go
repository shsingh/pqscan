package matrix

// harness_test.go is the matrix suite's shared plumbing: the module-root
// locator, the domains.json + cases.jsonl loaders, the live-registration
// reader (the SAME grep basis the usage-drift gate uses), the constraint
// vocabulary's evaluation, and the chooseFormat mirror the runner needs.
// Everything here is offline: files and strings, never the network.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// mParam is one domains.json parameter entry.
type mParam struct {
	ID      string            `json:"id"`
	Kind    string            `json:"kind"` // flag | meta | runner-injected | argv-marker
	Shape   string            `json:"shape"`
	Domain  []string          `json:"domain"`
	Default string            `json:"default"`
	Spell   map[string]string `json:"spell"`
	Anchor  string            `json:"anchor"`
	Note    string            `json:"note"`
}

// mPair is one (parameter, value) reference from a constraint entry.
type mPair struct {
	Param string `json:"param"`
	Value string `json:"value"`
}

// mConstraint is one constraint-class entry (the ledger's vocabulary:
// prereq B-requires-A edges and conflict sets; alias / meta-exclusion are
// documented classification, not enforcement edges).
type mConstraint struct {
	Class      string  `json:"class"`
	Given      []mPair `json:"given"`
	Require    []mPair `json:"require"`
	Members    []mPair `json:"members"`
	AtLeastOne []mPair `json:"at_least_one"`
	Anchor     string  `json:"anchor"`
	Note       string  `json:"note"`
}

// mDomains is the domain table's parse (schema field + the array's inputs).
type mDomains struct {
	Schema      string        `json:"schema"`
	Strength    int           `json:"strength"`
	Parameters  []mParam      `json:"parameters"`
	Constraints []mConstraint `json:"constraints"`
}

// mCase is one case.jsonl row.
type mCase struct {
	ID    string   `json:"id"`
	Args  []string `json:"args"`
	Stdin string   `json:"stdin"`
	Note  string   `json:"note"`
}

func fatalf(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Fatalf(format, args...)
}

// matrixRoot is the repository root, derived from this source file's
// location (tests/matrix/*_test.go → three dirs up), so the suite is
// location-independent for both local runs and CI.
func matrixRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		fatalf(t, "matrixRoot: runtime.Caller failed")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", ".."))
	if err != nil {
		fatalf(t, "matrixRoot: %v", err)
	}
	if st, err := os.Stat(filepath.Join(root, "cmd", "pqscan")); err != nil || !st.IsDir() {
		fatalf(t, "matrixRoot: %s is not the repo root (cmd/pqscan missing)", root)
	}
	return root
}

// loadDomains parses tests/matrix/domains.json.
func loadDomains(t *testing.T, root string) mDomains {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "tests", "matrix", "domains.json"))
	if err != nil {
		fatalf(t, "read domains.json: %v", err)
	}
	var doc mDomains
	if err := json.Unmarshal(raw, &doc); err != nil {
		fatalf(t, "parse domains.json: %v", err)
	}
	if doc.Schema != "pqscan.matrix.domains/1" {
		fatalf(t, "domains.json schema is %q, want pqscan.matrix.domains/1", doc.Schema)
	}
	return doc
}

// loadCases parses tests/matrix/cases.jsonl in file order.
func loadCases(t *testing.T, root string) []mCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "tests", "matrix", "cases.jsonl"))
	if err != nil {
		fatalf(t, "read cases.jsonl: %v", err)
	}
	var cases []mCase
	for ln, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var c mCase
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			fatalf(t, "cases.jsonl line %d: %v", ln+1, err)
		}
		cases = append(cases, c)
	}
	return cases
}

// liveRegistrations is the usage-drift gate's grep re-implemented: the
// fs.(Bool|String|Float64|Int)( shapes over cmd/pqscan/*.go (non-test), in
// (file, line) order. It is a TEST-side static check — no subprocess.
func liveRegistrations(t *testing.T, root string) (names []string, shapeOf map[string]string) {
	t.Helper()
	dir := filepath.Join(root, "cmd", "pqscan")
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		fatalf(t, "glob cmd/pqscan: %v", err)
	}
	sort.Strings(matches)
	type found struct {
		name, shape string
		order       int
	}
	var all []found
	for fi, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			fatalf(t, "read %s: %v", path, err)
		}
		re := regexp.MustCompile(`fs\.(Bool|String|Float64|Int)\("([^"]+)"`)
		for ln, line := range strings.Split(string(data), "\n") {
			if m := re.FindStringSubmatch(line); m != nil {
				all = append(all, found{name: m[2], shape: m[1], order: fi*1000000 + ln})
			}
		}
	}
	sort.SliceStable(all, func(a, b int) bool { return all[a].order < all[b].order })
	shapeOf = map[string]string{}
	seen := map[string]bool{}
	for _, f := range all {
		if seen[f.name] {
			continue
		}
		seen[f.name] = true
		shapeOf[f.name] = f.shape
		names = append(names, f.name)
	}
	return names, shapeOf
}

// spellEntry is one spelling the tokenizer can consume from case args.
type spellEntry struct {
	tokens []string
	param  string
	value  string
}

// spellTable inverts every value spelling into tokens, longest first (the
// tokenizer consumes the longest match; the table is sorted deterministically).
func spellTable(params []mParam) []spellEntry {
	var entries []spellEntry
	for _, p := range params {
		if p.Kind == "meta" || p.Kind == "runner-injected" {
			continue
		}
		for _, v := range p.Domain {
			spelling, ok := p.Spell[v]
			if !ok || spelling == "absent" || spelling == "" {
				continue
			}
			entries = append(entries, spellEntry{tokens: strings.Fields(spelling), param: p.ID, value: v})
		}
	}
	sort.SliceStable(entries, func(a, b int) bool {
		if len(entries[a].tokens) != len(entries[b].tokens) {
			return len(entries[a].tokens) > len(entries[b].tokens)
		}
		return entries[a].param+":"+entries[a].value < entries[b].param+":"+entries[b].value
	})
	return entries
}

// parseCaseArgs spells a case's static args back into the (param, value)
// assignment the generator emitted, with every unset parameter at its
// default. Unknown tokens are a failure: every argv token must come from
// the domain table (the gate never lets a foreign token into the array).
func parseCaseArgs(t *testing.T, c mCase, params []mParam) map[string]string {
	t.Helper()
	entries := spellTable(params)
	assign := map[string]string{}
	for _, p := range params {
		if p.Kind != "meta" && p.Kind != "runner-injected" {
			assign[p.ID] = p.Default
		}
	}
	args := c.Args
	for i := 0; i < len(args); {
		matched := false
		for _, e := range entries {
			if len(e.tokens) > len(args)-i {
				continue
			}
			ok := true
			for j, tok := range e.tokens {
				if args[i+j] != tok {
					ok = false
					break
				}
			}
			if ok {
				assign[e.param] = e.value
				i += len(e.tokens)
				matched = true
				break
			}
		}
		if !matched {
			fatalf(t, "case %s: arg %q matches no spelling in domains.json", c.ID, args[i])
		}
	}
	return assign
}

// violated checks one full EFFECTIVE assignment (the case's static parse
// plus the runner's standing u=single) against the table's enforcement
// classes. The source floor reads the effective source set: the runner's
// -u injection makes every case satisfy it — recorded in the run log; the
// coverage gate validates the floor on the same effective set the runner
// builds.
func violated(c mCase, assign map[string]string, doc mDomains) []string {
	var out []string
	onCell := func(pr mPair) bool { return assign[pr.Param] == pr.Value }
	for _, con := range doc.Constraints {
		switch con.Class {
		case "prereq":
			if len(con.AtLeastOne) > 0 {
				any := false
				for _, m := range con.AtLeastOne {
					if onCell(m) {
						any = true
						break
					}
				}
				if !any {
					out = append(out, fmt.Sprintf("%s: the source floor holds no member", c.ID))
				}
				continue
			}
			allGiven := true
			for _, g := range con.Given {
				if !onCell(g) {
					allGiven = false
					break
				}
			}
			if !allGiven {
				continue
			}
			for _, r := range con.Require {
				if !onCell(r) {
					out = append(out, fmt.Sprintf("%s: prereq violated: given %s=%s requires %s=%s",
						c.ID, con.Given[0].Param, con.Given[0].Value, r.Param, r.Value))
				}
			}
		case "conflict":
			n := 0
			for _, m := range con.Members {
				if onCell(m) {
					n++
				}
			}
			if n >= 2 {
				var parts []string
				for _, m := range con.Members {
					parts = append(parts, m.Param+"="+m.Value)
				}
				out = append(out, fmt.Sprintf("%s: conflict held: %s", c.ID, strings.Join(parts, " ⊕ ")))
			}
		}
	}
	return out
}

// materializeToken expands one placeholder token from domains.json's
// placeholder_semantics into its per-case materialized form: $TARGET → the
// fixture's addr:port, @tmp files → real files in dir (the list/adapter
// payloads written, the certs dir created, out/diag paths stamped). label
// names the calling case in error messages. Shared by the array runner
// (run_test.go) and the PQ-54 battery (both run REAL binary vectors against
// the same fixture plumbing).
func materializeToken(t *testing.T, label, dir, addr, tok string) string {
	t.Helper()
	stamp := func(name string) string { return filepath.Join(dir, name) }
	switch tok {
	case "$TARGET":
		return addr
	case "@tmp/diag.json", "@tmp/out.txt":
		return stamp(strings.TrimPrefix(tok, "@tmp/"))
	case "@tmp/certs":
		d := stamp("certs")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("%s: certs dir: %v", label, err)
		}
		return d
	case "@tmp/targets-l.txt":
		p := stamp("targets-l.txt")
		if err := os.WriteFile(p, []byte(addr+"\n"), 0o644); err != nil {
			t.Fatalf("%s: list file: %v", label, err)
		}
		return p
	case "@tmp/targets-httpx.txt":
		p := stamp("targets-httpx.txt")
		if err := os.WriteFile(p, []byte("tcp://"+addr+"\n"), 0o644); err != nil {
			t.Fatalf("%s: httpx file: %v", label, err)
		}
		return p
	case "@tmp/targets-naabu.txt":
		p := stamp("targets-naabu.txt")
		if err := os.WriteFile(p, []byte(addr+"\n"), 0o644); err != nil {
			t.Fatalf("%s: naabu file: %v", label, err)
		}
		return p
	case "@tmp/targets-nuclei.txt":
		// The nuclei -j finding dialect (the pinned capture's observed
		// shape): one JSON finding per line, matched-at the canonical
		// host field (the parser's url fallback covers the empty
		// matched-at; the materialized line never needs it).
		p := stamp("targets-nuclei.txt")
		finding := `{"template-id":"pqscan-matrix","matcher-status":true,"matched-at":"https://` + addr + `"}` + "\n"
		if err := os.WriteFile(p, []byte(finding), 0o644); err != nil {
			t.Fatalf("%s: nuclei finding file: %v", label, err)
		}
		return p
	}
	if strings.HasPrefix(tok, "@tmp/") {
		t.Fatalf("%s: unknown materialized-file token: %q", label, tok)
	}
	return tok
}

// pair is one unordered (paramA, paramB) pair of values from two different
// parameters (t=2).
type pair struct {
	p1, v1, p2, v2 string
}

// validPairs enumerates the constraint-filtered t=2 pair pool: every
// (value, value) cross of two distinct parameters, minus the pairs whose
// two cells together violate a prereq or a conflict. The array's coverage
// contract is exactly this pool (the relaxation rule matches the
// generator's: a require on an out-of-pair parameter is the full row's
// repair, not the pair's rejection).
func validPairs(doc mDomains, arrayParams []mParam) []pair {
	arrayParam := map[string]bool{}
	for _, p := range arrayParams {
		arrayParam[p.ID] = true
	}
	onOne := func(a map[string]string, pr mPair) bool { return a[pr.Param] == pr.Value }
	pairInvalid := func(a map[string]string) bool {
		for _, con := range doc.Constraints {
			switch con.Class {
			case "prereq":
				if len(con.AtLeastOne) > 0 {
					continue // a row-level class, never a pair filter
				}
				allGiven := true
				for _, g := range con.Given {
					if !onOne(a, g) {
						allGiven = false
						break
					}
				}
				if !allGiven {
					continue
				}
				for _, r := range con.Require {
					if _, in := a[r.Param]; in && !onOne(a, r) {
						return true
					}
				}
			case "conflict":
				n := 0
				for _, m := range con.Members {
					if onOne(a, m) {
						n++
					}
				}
				if n == len(con.Members) && len(con.Members) >= 2 {
					return true
				}
			}
		}
		return false
	}
	var out []pair
	for i := 0; i < len(arrayParams); i++ {
		for j := i + 1; j < len(arrayParams); j++ {
			p1, p2 := arrayParams[i].ID, arrayParams[j].ID
			for _, v1 := range arrayParams[i].Domain {
				for _, v2 := range arrayParams[j].Domain {
					if pairInvalid(map[string]string{p1: v1, p2: v2}) {
						continue
					}
					out = append(out, pair{p1: p1, v1: v1, p2: p2, v2: v2})
				}
			}
		}
	}
	return out
}

// pairKey sorts the pair pool (the listing order of failures).
func pairKey(pr pair) string {
	if pr.p1 < pr.p2 || (pr.p1 == pr.p2 && pr.v1 < pr.v2) {
		return pr.p1 + "=" + pr.v1 + " × " + pr.p2 + "=" + pr.v2
	}
	return pr.p2 + "=" + pr.v2 + " × " + pr.p1 + "=" + pr.v1
}

// arrayParams returns the table's array-plane parameters in table order:
// the plain flags plus the argv marker; meta entries and the
// runner-injected -u ride no case.
func arrayParams(doc mDomains) []mParam {
	var out []mParam
	for _, p := range doc.Parameters {
		if p.Kind == "flag" || p.Kind == "argv-marker" {
			out = append(out, p)
		}
	}
	return out
}

// mirrorFormat is cmd/pqscan's chooseFormat (main.go) reimplemented for the
// runner: the last output selector on the raw command line wins, the scan
// stops at the bare '--', an explicit "=false" does not select, and the
// default is text. This is the one piece of CLI logic the runner mirrors
// (package main is not importable); a surface change that moves selector
// semantics without moving this mirror goes red right here.
func mirrorFormat(args []string) string {
	chosen := "text"
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			if name[i+1:] == "false" {
				continue
			}
			name = name[:i]
		}
		switch name {
		case "json", "jsonl":
			chosen = "jsonl"
		case "csv":
			chosen = "csv"
		case "urls":
			chosen = "urls"
		case "text":
			chosen = "text"
		}
	}
	return chosen
}
