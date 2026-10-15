// deep.go — PQ-20's deep-mode executor wiring (issue #43): the -mode
// dispatch. FAST mode is the shipped single-handshake probe (unchanged);
// PQ mode runs the forced PQ ladder (tlsx.GroupLadder over the standards-
// track PQ hybrids 4585–4590 + the obsolete-Kyber drafts) and lands the
// ladder's observations in the record's handshake + pq blocks; DEEP mode
// consumes internal/deepplan's plan: the profile handshake runs FIRST and
// feeds deepplan.Observed (spec §7.4 phase 1 gates phase 2), then the
// executor dispatches every probe by kind and lands the executed plan in
// the record's deep block.
package main

import (
	"github.com/shsingh/pqscan/internal/grammar"
)

// The mode labels (-mode) and the deep plan selector (-deep) as the
// commands surface them; the record's mode field carries the same token.
const (
	modeFast = "fast"
	modeDeep = "deep"
	modePQ   = "pq"

	deepStandard = "standard"
	deepFull     = "full"
)

// validMode reports whether m is a defined -mode value.
func validMode(m string) bool {
	switch m {
	case modeFast, modeDeep, modePQ:
		return true
	default:
		return false
	}
}

// validDeepPlan reports whether d is a defined -deep plan value.
func validDeepPlan(d string) bool {
	switch d {
	case deepStandard, deepFull:
		return true
	default:
		return false
	}
}

// scanTargetDeep is the PQ-20 RED STUB: it returns the fast shape under
// the deep mode label; the executor wiring (the deepplan.Build consumption
// with the profile handshake's facts prune, the offer-one dispatch by
// probe kind and the record's deep block) lands in the GREEN commit.
func scanTargetDeep(t grammar.Target, opts Options) (*scanRecord, bool, bool) {
	rec, failing, timedOut := scanTargetFast(t, opts)
	rec.Mode = modeDeep
	return rec, failing, timedOut
}

// scanTargetPQ is the PQ-20 RED STUB: it returns the fast shape under the
// pq mode label; the forced PQ ladder (4585–4590 + the drafts) and the
// ladder-observation wire-in (handshake block + pq verdict) land in the
// GREEN commit.
func scanTargetPQ(t grammar.Target, opts Options) (*scanRecord, bool, bool) {
	rec, failing, timedOut := scanTargetFast(t, opts)
	rec.Mode = modePQ
	return rec, failing, timedOut
}
