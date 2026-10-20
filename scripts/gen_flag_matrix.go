//go:build matrixgen

// PQ-53: the flag-matrix generator. It reads the LIVE registration surface
// (cmd/pqscan/*.go, the same fs.(Bool|String|Float64|Int)( grep basis the
// usage-drift gate uses) plus the hand-authored domain + constraint table
// (tests/matrix/domains.json) and emits the deterministic pairwise covering
// array to stdout (or rewrites tests/matrix/cases.jsonl under -write):
//
//	go run scripts/gen_flag_matrix.go            # array bytes on stdout
//	go run scripts/gen_flag_matrix.go -write     # rewrite the checked-in array
//
// Deterministic always: fixed seed, sorted traversal, the seed+fill+repair
// greedy — two runs on the same tree are byte-identical (the flag-matrix CI
// job regenerates and cmp-s the checked-in array exactly to prove it).
//
// The generator FAILS (exit 2) when the table and the surface drift apart:
// a registered flag with no domain entry, or a domain entry that names no
// registered flag — completeness both directions. It never invents values:
// the emitted rows carry only flag tokens from the table's spellings plus
// the runner placeholders ($TARGET, @tmp/...) — literal targets ride the
// fixture plumbing (the runner binds -u per case), never the static array.
//
// Constraint model (tests/matrix/domains.json, the ledger's vocabulary):
//
//   - prereq (B requires A): explain=on → text=on; deep=full → mode=deep;
//     resume=on → o=file; and the source floor (≥1 of u/l/from-naabu/
//     from-httpx/'--'), satisfied per row through the runner's unconditional
//     -u injection.
//   - conflict (mutually exclusive members): quic-always=on ⊕ quic-off=on.
//
// -json/-jsonl stay CONFLICT-free (the alias pair; both resolve to the
// JSONL encoder). version/completion are meta-excluded (pinned already by
// the surface contract) and -u is the runner's injected source.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// lcgSeed starts the deterministic tie-break stream (the bytes of "PQSMPQSM"):
// a fixed constant, so every traversal choice lands the same way twice.
const lcgSeed uint64 = 0x5051534D5051534D

type drifter struct{ s uint64 }

func (d *drifter) next() uint64 {
	d.s ^= d.s << 13
	d.s ^= d.s >> 7
	d.s ^= d.s << 17
	return d.s
}

func (d *drifter) pickIndex(n int) int { return int(d.next() % uint64(n)) }

type pairSpec struct {
	Param string `json:"param"`
	Value string `json:"value"`
}

type paramSpec struct {
	ID      string            `json:"id"`
	Kind    string            `json:"kind"` // flag | meta | runner-injected | argv-marker
	Shape   string            `json:"shape"`
	Domain  []string          `json:"domain"`
	Default string            `json:"default"`
	Spell   map[string]string `json:"spell"`
	Anchor  string            `json:"anchor"`
	Note    string            `json:"note"`
}

type constraintSpec struct {
	Class      string     `json:"class"` // prereq | conflict | alias | meta-exclusion
	Given      []pairSpec `json:"given"`
	Require    []pairSpec `json:"require"`
	Members    []pairSpec `json:"members"`
	AtLeastOne []pairSpec `json:"at_least_one"`
	Anchor     string     `json:"anchor"`
	Note       string     `json:"note"`
}

type domainsDoc struct {
	Schema      string            `json:"schema"`
	Strength    int               `json:"strength"`
	Parameters  []paramSpec       `json:"parameters"`
	Constraints []constraintSpec  `json:"constraints"`
	SpellWords  map[string]string `json:"placeholder_semantics"`
	Normal      []string          `json:"normalization"`
}

type caseLine struct {
	ID    string   `json:"id"`
	Args  []string `json:"args"`
	Stdin string   `json:"stdin"`
	Note  string   `json:"note"`
}

// registration is one fs.(Bool|String|Float64|Int)("name", ...) shape as
// the drift gate greps it.
type registration struct {
	Name  string
	Shape string
}

func locateRoot(flagRoot string) (string, error) {
	dir, err := filepath.Abs(flagRoot)
	if err != nil {
		return "", err
	}
	for i := 0; i < 8; i++ {
		if st, serr := os.Stat(filepath.Join(dir, "cmd", "pqscan")); serr == nil && st.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("repo root with cmd/pqscan not found at or above %s", flagRoot)
}

// liveRegistrations mirrors the usage-drift gate's grep exactly: the literal
// fs.(Bool|String|Float64|Int)("name", shapes over cmd/pqscan/*.go, in
// (file, line) order — the flags.go registration order.
func liveRegistrations(root string) ([]registration, error) {
	matches, err := filepath.Glob(filepath.Join(root, "cmd", "pqscan", "*.go"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	re := regexp.MustCompile(`fs\.(Bool|String|Float64|Int)\("([^"]+)"`)
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
			return nil, err
		}
		for ln, line := range strings.Split(string(data), "\n") {
			if m := re.FindStringSubmatch(line); m != nil {
				all = append(all, found{name: m[2], shape: m[1], order: fi*100000 + ln})
			}
		}
	}
	sort.SliceStable(all, func(a, b int) bool { return all[a].order < all[b].order })
	var regs []registration
	seen := map[string]bool{}
	for _, f := range all {
		if seen[f.name] {
			continue
		}
		seen[f.name] = true
		regs = append(regs, registration{Name: f.name, Shape: f.shape})
	}
	return regs, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen_flag_matrix: "+format+"\n", args...)
	os.Exit(2)
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

// noUnset is the value index of "not fixed by this combo" in combo probes.
const unsetCell = -1

// cell is one (parameter index, value index) position in the array plane.
type cell struct{ p, v int }

// rowRec is one completed row: its full assignment plus the count of
// never-before-covered pairs it added to the array.
type rowRec struct {
	vals  []int
	fresh int
}

// prereqEdge is one resolved B-requires-A edge (cells, not spellings).
type prereqEdge struct {
	given   []cell
	require []cell
}

func kindRank(kind string) int {
	switch kind {
	case "flag":
		return 0
	case "argv-marker":
		return 1
	}
	return 2
}

func countKinds(arr []paramSpec, kind string) int {
	n := 0
	for _, p := range arr {
		if p.Kind == kind {
			n++
		}
	}
	return n
}

func hasCell(c []cell, p, v int) bool {
	for _, cc := range c {
		if cc.p == p && cc.v == v {
			return true
		}
	}
	return false
}

func cellLess(a, b []cell) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i].p != b[i].p {
			return a[i].p < b[i].p
		}
		if a[i].v != b[i].v {
			return a[i].v < b[i].v
		}
	}
	return len(a) < len(b)
}

// conflictLocked reports whether the probe holds every member of a conflict
// class at once.
func conflictLocked(vals []int, conflicts [][]cell) bool {
	for _, conf := range conflicts {
		all := true
		for _, m := range conf {
			if vals[m.p] != m.v {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// gainOf counts the uncovered combos the probe's row fully covers: the
// greedy's density signal.
func gainOf(vals []int, validCombos [][]cell, uncovered []bool) int {
	g := 0
	for i, c := range validCombos {
		if !uncovered[i] {
			continue
		}
		all := true
		for _, cc := range c {
			if vals[cc.p] != cc.v {
				all = false
				break
			}
		}
		if all {
			g++
		}
	}
	return g
}

func spellArgv(row []int, arrParams []paramSpec) []string {
	args := make([]string, 0, len(row))
	for i, v := range row {
		spelling := arrParams[i].Spell[arrParams[i].Domain[v]]
		if spelling == "absent" || spelling == "" {
			continue
		}
		args = append(args, strings.Fields(spelling)...)
	}
	return args
}

func stdinPayload(row []int, arrParams []paramSpec) string {
	payload := ""
	for i := range row {
		id := arrParams[i].ID
		val := arrParams[i].Domain[row[i]]
		if (id == "--" && val == "present") || (id == "l" && val == "stdin") {
			payload = "$TARGET\n"
		}
	}
	return payload
}

// rowNote is the case's deterministic one-line why: what the row added to
// the array and which parameters vary from their defaults.
func rowNote(idx int, row rowRec, arrParams []paramSpec) string {
	if idx == 0 {
		return "seed row: the all-default run (the zero-configuration scan; -u carries the only target)"
	}
	var varies []string
	for i, v := range row.vals {
		p := arrParams[i]
		if v != indexOf(p.Domain, p.Default) {
			varies = append(varies, p.ID+"="+p.Domain[v])
		}
	}
	return fmt.Sprintf("covers %d new pairs; varies %s", row.fresh, strings.Join(varies, " "))
}

func main() {
	rootFlag := flag.String("root", ".", "repository root (walks up when cmd/pqscan is not here)")
	strengthFlag := flag.Int("strength", 0, "covering strength t (0 = the domain table's strength field)")
	writeFlag := flag.Bool("write", false, "rewrite tests/matrix/cases.jsonl instead of printing the array")
	flag.Parse()

	root, err := locateRoot(*rootFlag)
	if err != nil {
		fatal("%v", err)
	}

	regs, err := liveRegistrations(root)
	if err != nil {
		fatal("read registrations: %v", err)
	}

	var doc domainsDoc
	raw, err := os.ReadFile(filepath.Join(root, "tests", "matrix", "domains.json"))
	if err != nil {
		fatal("read domains.json: %v", err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fatal("parse domains.json: %v", err)
	}
	if doc.Schema != "pqscan.matrix.domains/1" {
		fatal("domains.json schema is %q, want pqscan.matrix.domains/1", doc.Schema)
	}
	t := doc.Strength
	if *strengthFlag != 0 {
		t = *strengthFlag
	}
	if t < 2 {
		fatal("covering strength t=%d refuses: the shipped CI core is t=2 (pairwise); pass -strength 3 for the opt-in deep array", t)
	}

	// Completeness, both directions.
	byName := map[string]*paramSpec{}
	for i := range doc.Parameters {
		p := &doc.Parameters[i]
		switch p.Kind {
		case "flag", "meta", "runner-injected", "argv-marker":
		default:
			fatal("parameter %q: unknown kind %q", p.ID, p.Kind)
		}
		if _, dup := byName[p.ID]; dup {
			fatal("domain table carries parameter %q twice", p.ID)
		}
		byName[p.ID] = p
		if p.Kind == "meta" || p.Kind == "runner-injected" {
			continue // meta paths and the runner's -u ride no case and emit no tokens
		}
		if indexOf(p.Domain, p.Default) < 0 {
			fatal("parameter %q: default %q missing from its domain", p.ID, p.Default)
		}
		for _, v := range p.Domain {
			spell, ok := p.Spell[v]
			if !ok && v != p.Default {
				fatal("parameter %q: value %q has no spelling and is not the default", p.ID, v)
			}
			if ok && v == p.Default && spell != "absent" {
				fatal("parameter %q: the default value %q must spell \"absent\"", p.ID, v)
			}
			if ok && spell == "absent" && v != p.Default {
				fatal("parameter %q: only the default may spell \"absent\" (value %q)", p.ID, v)
			}
		}
	}
	var missing []string
	for _, r := range regs {
		p, ok := byName[r.Name]
		if !ok {
			missing = append(missing, r.Name)
			continue
		}
		if p.Shape != r.Shape {
			fatal("flag %q: domain table shape %s, live registration %s", r.Name, p.Shape, r.Shape)
		}
	}
	if len(missing) > 0 {
		fatal("registered flags with no domain entry (fix domains.json in the same change): %s", strings.Join(missing, ", "))
	}
	var unknown []string
	for _, p := range doc.Parameters {
		if p.Kind == "argv-marker" {
			continue // the '--' token is documented, not an fs flag (the drift gate's synthetic 'stdin' row)
		}
		live := false
		for _, r := range regs {
			if r.Name == p.ID {
				live = true
				break
			}
		}
		if !live {
			unknown = append(unknown, p.ID)
		}
	}
	if len(unknown) > 0 {
		fatal("domain entries naming no registered flag: %s", strings.Join(unknown, ", "))
	}

	// The array plane: the plain flags + the argv marker. The
	// runner-injected flag (-u) stays out of the static array by contract;
	// the meta entries ride no case.
	var arrParams []paramSpec
	var injected paramSpec
	for i := range doc.Parameters {
		switch doc.Parameters[i].Kind {
		case "flag", "argv-marker":
			arrParams = append(arrParams, doc.Parameters[i])
		case "runner-injected":
			injected = doc.Parameters[i]
		}
	}
	// Array order = registration order (grep order among the flags), with
	// the argv marker riding last: the emitter never places flag tokens
	// behind the raw-argv terminator.
	sort.SliceStable(arrParams, func(a, b int) bool {
		ka, kb := kindRank(arrParams[a].Kind), kindRank(arrParams[b].Kind)
		if ka != kb {
			return ka < kb
		}
		if ka == 1 {
			return false // one marker only
		}
		ia, ib := -1, -1
		for i, r := range regs {
			if r.Name == arrParams[a].ID {
				ia = i
			}
			if r.Name == arrParams[b].ID {
				ib = i
			}
		}
		return ia < ib
	})

	n := len(arrParams)
	pi := func(id string) int {
		for i, p := range arrParams {
			if p.ID == id {
				return i
			}
		}
		return -1
	}
	resolve := func(pr pairSpec) cell {
		p := pi(pr.Param)
		if p < 0 {
			fatal("constraint names unknown parameter %q", pr.Param)
		}
		v := indexOf(arrParams[p].Domain, pr.Value)
		if v < 0 {
			fatal("constraint names unknown value %q for %q", pr.Value, pr.Param)
		}
		return cell{p, v}
	}

	// Resolved enforcement edges.
	var prereqs []prereqEdge
	var conflicts [][]cell
	var floor []cell // source-floor members; virtual members (the runner's -u) drop out here
	hasVirtualFloor := false
	for _, c := range doc.Constraints {
		switch c.Class {
		case "prereq":
			if len(c.AtLeastOne) > 0 {
				for _, m := range c.AtLeastOne {
					if p := pi(m.Param); p >= 0 {
						floor = append(floor, resolve(m))
					} else if m.Param == injected.ID {
						hasVirtualFloor = true // present on every case by construction
					} else {
						fatal("the source floor names neither an array parameter nor the runner-injected flag: %q", m.Param)
					}
				}
				continue
			}
			if len(c.Given) != 1 || len(c.Require) != 1 {
				fatal("a prereq must carry exactly one given and one require pair (B requires A)")
			}
			g := resolve(c.Given[0])
			r := resolve(c.Require[0])
			if g.p == r.p {
				fatal("a prereq's given and require name the same parameter")
			}
			prereqs = append(prereqs, prereqEdge{given: []cell{g}, require: []cell{r}})
		case "conflict":
			if len(c.Members) < 2 {
				fatal("conflict %+v carries fewer than two members", c.Members)
			}
			cells := make([]cell, 0, len(c.Members))
			for _, m := range c.Members {
				cells = append(cells, resolve(m))
			}
			conflicts = append(conflicts, cells)
		case "alias", "meta-exclusion":
			// documented classification, not an enforcement edge
		default:
			fatal("constraint class %q is unenforced in this generator", c.Class)
		}
	}

	defVals := make([]int, n)
	for i, p := range arrParams {
		defVals[i] = indexOf(p.Domain, p.Default)
	}

	// comboInvalid is the pairwise relaxation: a t-combo is invalid only
	// when a prereq's given side sits fully inside it while its require
	// param is also inside on another value (a require on an out-of-combo
	// parameter — an unset cell — is the full row's repair, not the combo's
	// rejection), or a conflict's members all sit inside. The source floor
	// is a row-level class: the effective source set carries the runner's
	// -u injection (recorded in the per-case run log), so the floor holds
	// for every row by construction — asserted, not assumed.
	//
	// Combo probes mark un-fixed parameters with value index -1 (distinct
	// from every default), so "inside the combo" is a real test, not a
	// default-value shadow.
	onCell := func(vals []int, c cell) bool { return vals[c.p] == c.v }
	comboInvalid := func(vals []int) bool {
		for _, pr := range prereqs {
			allGiven := true
			for _, g := range pr.given {
				if !onCell(vals, g) {
					allGiven = false
					break
				}
			}
			if !allGiven {
				continue
			}
			for _, r := range pr.require {
				if vals[r.p] == unsetCell {
					continue
				}
				if vals[r.p] != r.v {
					return true
				}
			}
		}
		return conflictLocked(vals, conflicts)
	}
	rowInvalid := func(vals []int) bool {
		if comboInvalid(vals) {
			return true
		}
		for _, c := range floor {
			if onCell(vals, c) {
				return false
			}
		}
		return !hasVirtualFloor // the runner's -u ride-along satisfies the floor
	}

	// Valid t-combos (sorted traversal). Combo probes leave non-combo
	// parameters at unsetCell — distinct from every default value.
	var validCombos [][]cell
	var walkCombos func(remaining []int, acc []cell)
	walkCombos = func(remaining []int, acc []cell) {
		if len(acc) == t {
			vals := make([]int, n)
			for i := range vals {
				vals[i] = unsetCell
			}
			for _, c := range acc {
				vals[c.p] = c.v
			}
			if !comboInvalid(vals) {
				validCombos = append(validCombos, append([]cell(nil), acc...))
			}
			return
		}
		for i := 0; i < len(remaining); i++ {
			p := remaining[i]
			for v := range arrParams[p].Domain {
				next := append(append([]cell(nil), acc...), cell{p, v})
				walkCombos(remaining[i+1:], next)
			}
		}
	}
	alls := make([]int, n)
	for i := range alls {
		alls[i] = i
	}
	walkCombos(alls, nil)
	sort.SliceStable(validCombos, func(a, b int) bool { return cellLess(validCombos[a], validCombos[b]) })

	fullCartesian := 1
	for _, p := range arrParams {
		fullCartesian *= len(p.Domain)
	}
	pairsFiltered := len(validCombos)

	// The all-defaults seed row: the zero-configuration scan (-u only).
	seed := append([]int(nil), defVals...)
	if rowInvalid(seed) {
		fatal("the all-defaults row is invalid under the table's constraints")
	}

	uncovered := make([]bool, pairsFiltered)
	for i := range uncovered {
		uncovered[i] = true
	}
	uncoveredCount := pairsFiltered
	rows := make([]rowRec, 0, 64)
	markCovered := func(vals []int) int {
		got := 0
		for i, c := range validCombos {
			if !uncovered[i] {
				continue
			}
			all := true
			for _, cc := range c {
				if vals[cc.p] != cc.v {
					all = false
					break
				}
			}
			if all {
				uncovered[i] = false
				uncoveredCount--
				got++
			}
		}
		return got
	}
	rows = append(rows, rowRec{vals: seed, fresh: markCovered(seed)})

	rng := drifter{s: lcgSeed}
	for uncoveredCount > 0 && len(rows) <= 8*pairsFiltered+8 {
		// degrees over the uncovered pool
		deg := make([][]int, n)
		for i := range deg {
			deg[i] = make([]int, len(arrParams[i].Domain))
		}
		for i, c := range validCombos {
			if !uncovered[i] {
				continue
			}
			for _, cc := range c {
				deg[cc.p][cc.v]++
			}
		}
		cur := 0
		for _, byV := range deg {
			for _, d := range byV {
				if d > cur {
					cur = d
				}
			}
		}
		if cur < 1 {
			fatal("greedy stuck: no uncovered combo is reachable (degrees exhausted)")
		}
		var cands []cell
		for p := 0; p < n; p++ {
			for v := 0; v < len(arrParams[p].Domain); v++ {
				if deg[p][v] == cur {
					cands = append(cands, cell{p, v})
				}
			}
		}
		chosen := cands[rng.pickIndex(len(cands))]

		// the first uncovered combo carrying the chosen cell, forced whole
		var forced []cell
		for i, c := range validCombos {
			if !uncovered[i] {
				continue
			}
			if hasCell(c, chosen.p, chosen.v) {
				forced = c
				break
			}
		}
		if forced == nil {
			fatal("greedy stuck: no uncovered combo carries the chosen cell")
		}

		// fill: the forced cells pinned, everything else default, then the
		// rest by covering gain — never accepting a value that locks a
		// conflict in or would make a prereq's repair collide with a forced
		// cell
		row := append([]int(nil), defVals...)
		forcedSet := map[int]bool{}
		for _, fc := range forced {
			row[fc.p] = fc.v
			forcedSet[fc.p] = true
		}
		for p := 0; p < n; p++ {
			if _, isForced := forcedSet[p]; isForced {
				continue
			}
			bestGain := -1
			pick := defVals[p]
			var vals []int
			for v := 0; v < len(arrParams[p].Domain); v++ {
				probe := append([]int(nil), row...)
				probe[p] = v
				if conflictLocked(probe, conflicts) {
					continue
				}
				blocked := false
				for _, pr := range prereqs {
					allGiven := true
					for _, g := range pr.given {
						if !onCell(probe, g) {
							allGiven = false
							break
						}
					}
					if !allGiven {
						continue
					}
					for _, r := range pr.require {
						if probe[r.p] != r.v && forcedSet[r.p] {
							blocked = true
						}
					}
				}
				if blocked {
					continue
				}
				g := gainOf(probe, validCombos, uncovered)
				if g > bestGain {
					bestGain = g
					vals = vals[:0]
					vals = append(vals, v)
					continue
				}
				if g == bestGain {
					vals = append(vals, v)
				}
			}
			if len(vals) > 0 {
				pick = vals[rng.pickIndex(len(vals))]
			}
			row[p] = pick
		}

		// repair: prereqs add their require side (the fill's filters keep
		// forced cells untouchable; repair only adds)
		for pass := 0; pass < 4; pass++ {
			changed := false
			for _, pr := range prereqs {
				allGiven := true
				for _, g := range pr.given {
					if !onCell(row, g) {
						allGiven = false
						break
					}
				}
				if !allGiven {
					continue
				}
				for _, r := range pr.require {
					if !onCell(row, r) {
						row[r.p] = r.v
						changed = true
					}
				}
			}
			if !changed {
				break
			}
		}
		if rowInvalid(row) {
			fatal("the completed row is invalid under the table's constraints")
		}
		for _, fc := range forced {
			if row[fc.p] != fc.v {
				fatal("repair disturbed the forced cell of the row under construction")
			}
		}
		got := markCovered(row)
		rows = append(rows, rowRec{vals: row, fresh: got})
	}
	if uncoveredCount != 0 {
		fatal("greedy finished with %d uncovered combos", uncoveredCount)
	}

	// Emit: args in array (registration) order, the marker last; the runner
	// expands the $TARGET placeholder in argv and in the stdin payload.
	var sb strings.Builder
	for idx, row := range rows {
		line := caseLine{
			ID:    fmt.Sprintf("M%04d", idx+1),
			Args:  spellArgv(row.vals, arrParams),
			Stdin: stdinPayload(row.vals, arrParams),
			Note:  rowNote(idx, row, arrParams),
		}
		b, err := json.Marshal(line)
		if err != nil {
			fatal("marshal case %d: %v", idx+1, err)
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	array := sb.String()

	fmt.Fprintf(os.Stderr, "flag-matrix: params=%d (%d flags + the '--' argv marker; -u runner-injected; version/completion meta-excluded) t=%d full-cartesian=%d constraint-filtered-combos=%d rows=%d coverage=%d/%d\n",
		n, countKinds(arrParams, "flag"), t, fullCartesian, pairsFiltered, len(rows), pairsFiltered-uncoveredCount, pairsFiltered)

	if *writeFlag {
		if err := os.WriteFile(filepath.Join(root, "tests", "matrix", "cases.jsonl"), []byte(array), 0o644); err != nil {
			fatal("write cases.jsonl: %v", err)
		}
		return
	}
	fmt.Print(array)
}
