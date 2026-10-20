package matrix

// coverage_test.go is the flag-matrix's self-verifying gate (PQ-53). It is
// static and offline: it reloads the SAME inputs the generator reads — the
// live registrations (the usage-drift gate's grep basis), the domain +
// constraint table (tests/matrix/domains.json) and the checked-in array
// (tests/matrix/cases.jsonl) — and re-derives the array's contract:
//
//   - completeness, both directions: every registered flag carries a
//     domain entry; every non-marker domain entry names a registered flag;
//     the shapes agree;
//   - every case's tokens spell values out of the table (no foreign
//     tokens), and every case is valid under the table's constraint
//     classes on the effective source set;
//   - the recomputed t=2 pair pool (constraint-filtered) is fully covered
//     by the array's cases — FAILS listing any uncovered pair, so a
//     surface change without regeneration in the same PR goes red here.
//
// The generator keeps its own copy of the same rule (scripts/
// gen_flag_matrix.go); the duplication is the point — the gate re-derives
// rather than trusting the generator's output, and the CI job's
// regenerate-and-cmp step pins the generator to the checked-in bytes.

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestFlagMatrixDomains(t *testing.T) {
	root := matrixRoot(t)
	doc := loadDomains(t, root)
	names, shapeOf := liveRegistrations(t, root)
	registered := make(map[string]bool, len(names))
	for _, n := range names {
		registered[n] = true
	}
	byID := map[string]mParam{}
	for i := range doc.Parameters {
		p := &doc.Parameters[i]
		if _, dup := byID[p.ID]; dup {
			t.Errorf("domain table carries parameter %q twice", p.ID)
			continue
		}
		byID[p.ID] = *p
		switch p.Kind {
		case "flag", "meta", "runner-injected", "argv-marker":
		default:
			t.Errorf("parameter %q: unknown kind %q", p.ID, p.Kind)
		}
		if p.Kind == "argv-marker" {
			if registered[p.ID] {
				t.Errorf("argv-marker %q is also a registered flag; the marker is a raw-argv token, not an fs flag", p.ID)
			}
			continue
		}
		if !registered[p.ID] {
			t.Errorf("domain entry %q names no registered flag (check the fs.(...) registrations in cmd/pqscan)", p.ID)
		}
		if p.Kind == "meta" || p.Kind == "runner-injected" {
			continue // no spellings contract: meta paths and -u ride no case
		}
		if len(p.Domain) == 0 {
			t.Errorf("parameter %q: empty domain", p.ID)
			continue
		}
		defIn := false
		for _, v := range p.Domain {
			if spell, ok := p.Spell[v]; ok && v != p.Default && spell == "absent" {
				t.Errorf("parameter %q: only the default may spell \"absent\" (value %q)", p.ID, v)
			}
			if v == p.Default {
				defIn = true
				if spell, ok := p.Spell[v]; ok && spell != "absent" {
					t.Errorf("parameter %q: the default %q must spell \"absent\", got %q", p.ID, v, spell)
				}
			} else if _, ok := p.Spell[v]; !ok {
				t.Errorf("parameter %q: value %q has no spelling and is not the default", p.ID, v)
			}
		}
		if !defIn {
			t.Errorf("parameter %q: default %q missing from its domain", p.ID, p.Default)
		}
	}
	for _, name := range names {
		p, ok := byID[name]
		if !ok {
			t.Errorf("registered flag %q has no domain entry (fix domains.json in the same change)", name)
			continue
		}
		if got, want := shapeOf[name], p.Shape; got != want {
			t.Errorf("flag %q: domain table shape %q, live registration %q", name, got, want)
		}
	}
	for i := range doc.Parameters {
		p := &doc.Parameters[i]
		if p.Anchor == "" {
			t.Errorf("parameter %q: no spec anchor", p.ID)
		}
		if strings.Contains(p.Anchor, ".pdf") {
			t.Errorf("parameter %q: anchor must be a GitHub heading anchor, never a '.pdf' path", p.ID)
		}
	}
	// constraint hygiene: every referenced (param, value) resolves in the
	// table; alias and meta-exclusion entries document (never enforce).
	var marker, injected int
	for i := range doc.Parameters {
		p := &doc.Parameters[i]
		if p.Kind == "argv-marker" {
			marker++
		}
		if p.Kind == "runner-injected" {
			injected++
		}
	}
	if marker != 1 {
		t.Errorf("want exactly one argv-marker entry (the '--' stdin marker), got %d", marker)
	}
	if injected != 1 {
		t.Errorf("want exactly one runner-injected entry (-u), got %d", injected)
	}
	resolve := func(table map[string]mParam, m mPair) error {
		p, ok := table[m.Param]
		if !ok {
			return fmt.Errorf("constraint names unknown parameter %q", m.Param)
		}
		for _, v := range p.Domain {
			if v == m.Value {
				return nil
			}
		}
		return fmt.Errorf("constraint names unknown value %q for %q", m.Value, m.Param)
	}
	for _, con := range doc.Constraints {
		switch con.Class {
		case "prereq":
			if len(con.AtLeastOne) > 0 {
				for _, m := range con.AtLeastOne {
					if err := resolve(byID, m); err != nil {
						t.Errorf("source floor: %v", err)
					}
				}
				continue
			}
			if len(con.Given) != 1 || len(con.Require) != 1 {
				t.Errorf("a prereq must carry exactly one given and one require pair (B requires A)")
				continue
			}
			for _, m := range append(append([]mPair{}, con.Given...), con.Require...) {
				if err := resolve(byID, m); err != nil {
					t.Errorf("prereq: %v", err)
				}
			}
		case "conflict":
			if len(con.Members) < 2 {
				t.Errorf("a conflict needs at least two members")
				continue
			}
			for _, m := range con.Members {
				if err := resolve(byID, m); err != nil {
					t.Errorf("conflict: %v", err)
				}
			}
		case "alias", "meta-exclusion":
			for _, m := range con.Members {
				if err := resolve(byID, m); err != nil {
					t.Errorf("%s: %v", con.Class, err)
				}
			}
		default:
			t.Errorf("constraint class %q is not part of the table's vocabulary", con.Class)
		}
	}
}

func TestFlagMatrixCoverage(t *testing.T) {
	root := matrixRoot(t)
	doc := loadDomains(t, root)
	cases := loadCases(t, root)
	params := arrayParams(doc)
	if len(cases) == 0 {
		t.Fatal("cases.jsonl is empty: run go run scripts/gen_flag_matrix.go -write")
	}

	// the effective source set: the runner's -u injection is a standing
	// member on every case (recorded in the per-case run log)
	effective := func(assign map[string]string) map[string]string {
		eff := map[string]string{"u": "single"}
		for k, v := range assign {
			eff[k] = v
		}
		return eff
	}

	pool := validPairs(doc, params)
	if len(pool) == 0 {
		t.Fatal("the recomputed pair pool is empty: the domain table is broken")
	}
	uncovered := map[pair]bool{}
	for _, pr := range pool {
		uncovered[pr] = true
	}

	idRe := regexp.MustCompile(`^M\d{4}$`)
	seen := map[string]bool{}
	for _, c := range cases {
		if !idRe.MatchString(c.ID) {
			t.Errorf("case id %q is not the M#### form", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("case id %q appears twice", c.ID)
		}
		seen[c.ID] = true
		if strings.TrimSpace(c.Note) == "" {
			t.Errorf("case %s: empty note", c.ID)
		}
		assign := parseCaseArgs(t, c, params)
		eff := effective(assign)
		for _, why := range violated(c, eff, doc) {
			t.Errorf("%s", why)
		}
		for _, pr := range pool {
			if eff[pr.p1] == pr.v1 && eff[pr.p2] == pr.v2 {
				delete(uncovered, pr)
			}
		}
	}

	if len(uncovered) > 0 {
		var keys []string
		for pr := range uncovered {
			keys = append(keys, pairKey(pr))
		}
		// sorted listing: the gate's output is a regeneration runbook
		for i := 1; i < len(keys); i++ {
			for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
				keys[j], keys[j-1] = keys[j-1], keys[j]
			}
		}
		const capList = 20
		shown := keys
		if len(shown) > capList {
			shown = shown[:capList]
		}
		t.Fatalf("flag-matrix coverage gate: %d pair(s) uncovered — the array is stale (regenerate in the same change: go run scripts/gen_flag_matrix.go -write):\n\t%s",
			len(uncovered), strings.Join(shown, "\n\t"))
	}
}
