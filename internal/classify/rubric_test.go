package classify

import (
	"strings"
	"testing"
)

// rubricCell is one cell of the verdict table (PQ-19): an input plus the
// fully derived Verdict the rubric must produce. The table pins score
// accumulation, label banding, HNDL, the scan-error contract (score 0
// always carries an error) and the exact summary line, end to end.
type rubricCell struct {
	name            string
	in              ScoreInput
	wantScore       int
	wantLabel       string
	wantHNDL        bool
	wantErr         bool
	wantErrContains string
	wantSummary     string
}

func TestVerdictTable(t *testing.T) {
	cells := []rubricCell{
		{
			name:        "negotiated pq_hybrid, clean ladder: 40 = pq-partial",
			in:          ScoreInput{NegotiatedClass: "pq_hybrid", OfferedPQ: true},
			wantScore:   40,
			wantLabel:   "pq-partial",
			wantHNDL:    false,
			wantSummary: "negotiated_pq_hybrid(+40)",
		},
		{
			name:        "negotiated pq_hybrid + dual_cert wired: 60 = pq-ready-hybrid",
			in:          ScoreInput{NegotiatedClass: "pq_hybrid", OfferedPQ: true, DualCert: true},
			wantScore:   60,
			wantLabel:   "pq-ready-hybrid",
			wantHNDL:    false,
			wantSummary: "negotiated_pq_hybrid(+40); dual_cert(+20)",
		},
		{
			name:        "negotiated pq_hybrid + cert_pq_sig + dual_cert: 85 = pq-ready",
			in:          ScoreInput{NegotiatedClass: "pq_hybrid", OfferedPQ: true, CertPQ: true, DualCert: true},
			wantScore:   85,
			wantLabel:   "pq-ready",
			wantHNDL:    false,
			wantSummary: "negotiated_pq_hybrid(+40); cert_pq_sig(+25); dual_cert(+20)",
		},
		{
			name:        "negotiated pq_hybrid + cert_pq_sig: 65 = pq-ready-hybrid",
			in:          ScoreInput{NegotiatedClass: "pq_hybrid", OfferedPQ: true, CertPQ: true},
			wantScore:   65,
			wantLabel:   "pq-ready-hybrid",
			wantHNDL:    false,
			wantSummary: "negotiated_pq_hybrid(+40); cert_pq_sig(+25)",
		},
		{
			name:        "negotiated pure pq: 30 = pq-missing below the 40 band",
			in:          ScoreInput{NegotiatedClass: "pq", OfferedPQ: true},
			wantScore:   30,
			wantLabel:   "pq-missing",
			wantHNDL:    false,
			wantSummary: "negotiated_pq(+30)",
		},
		{
			name:        "negotiated pq_hybrid with draft acceptance: 25 = pq-missing, HNDL true",
			in:          ScoreInput{NegotiatedClass: "pq_hybrid", OfferedPQ: true, AcceptsDraft: true},
			wantScore:   25,
			wantLabel:   "pq-missing",
			wantHNDL:    true,
			wantSummary: "negotiated_pq_hybrid(+40); obsolete_draft_negotiated(-15)",
		},
		{
			name:            "classic-only, no PQ offer: zero PQ signal = scan-error (informational row)",
			in:              ScoreInput{NegotiatedClass: "classic"},
			wantScore:       0,
			wantLabel:       "scan-error",
			wantHNDL:        false,
			wantErr:         true,
			wantErrContains: "zero PQ signal",
			wantSummary:     "no_pq_offer(0)",
		},
		{
			name:            "classic-only with PQ offered (unaccepted): offers are informational, zero = scan-error",
			in:              ScoreInput{NegotiatedClass: "classic", OfferedPQ: true},
			wantScore:       0,
			wantLabel:       "scan-error",
			wantHNDL:        false,
			wantErr:         true,
			wantErrContains: "zero PQ signal",
			wantSummary:     "scan-error",
		},
		{
			name:            "classical group accepted over offered pq_hybrid: -5 penalty floors to scan-error",
			in:              ScoreInput{NegotiatedClass: "classic", OfferedPQ: true, ClassicalPreferred: true},
			wantScore:       0,
			wantLabel:       "scan-error",
			wantHNDL:        false,
			wantErr:         true,
			wantErrContains: "zero PQ signal",
			wantSummary:     "weak_classical_preferred(-5)",
		},
		{
			name:            "draft 25497 (obsolete Kyber) negotiated: penalty floors to scan-error, HNDL true",
			in:              ScoreInput{NegotiatedClass: "draft", OfferedPQ: true, AcceptsDraft: true},
			wantScore:       0,
			wantLabel:       "scan-error",
			wantHNDL:        true,
			wantErr:         true,
			wantErrContains: "zero PQ signal",
			wantSummary:     "obsolete_draft_negotiated(-15)",
		},
		{
			name:            "unknown negotiated class (valid rubric token): zero PQ signal = scan-error",
			in:              ScoreInput{NegotiatedClass: "unknown"},
			wantScore:       0,
			wantLabel:       "scan-error",
			wantHNDL:        false,
			wantErr:         true,
			wantErrContains: "zero PQ signal",
			wantSummary:     "no_pq_offer(0)",
		},
		{
			name:            "empty negotiated class: unrecognised, no rules evaluated",
			in:              ScoreInput{},
			wantScore:       0,
			wantLabel:       "scan-error",
			wantHNDL:        false,
			wantErr:         true,
			wantErrContains: "unrecognised negotiated class",
			wantSummary:     "scan-error",
		},
	}
	for _, tc := range cells {
		t.Run(tc.name, func(t *testing.T) {
			v, err := DefaultRubric().Score(tc.in)
			if v.Score != tc.wantScore {
				t.Errorf("Score = %d, want %d", v.Score, tc.wantScore)
			}
			if v.Label != tc.wantLabel {
				t.Errorf("Label = %q, want %q", v.Label, tc.wantLabel)
			}
			if v.HNDL != tc.wantHNDL {
				t.Errorf("HNDL = %v, want %v", v.HNDL, tc.wantHNDL)
			}
			if v.Summary != tc.wantSummary {
				t.Errorf("Summary = %q, want %q", v.Summary, tc.wantSummary)
			}
			if tc.wantErr && err == nil {
				t.Errorf("Score() err = nil, want non-nil containing %q", tc.wantErrContains)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Score() err = %v, want nil", err)
			}
			if tc.wantErrContains != "" && err != nil && !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Errorf("Score() err = %q, want it to contain %q", err.Error(), tc.wantErrContains)
			}
		})
	}
}

// TestDefaultRubricShape pins the default rule table exactly: the spec
// §5.6-ordered weights, and cert_pq_sig present in the slice even though
// the certificate analysis it needs only arrives with PQ-21 (Score treats
// its absence as zero points, never an error).
func TestDefaultRubricShape(t *testing.T) {
	want := []RubricRule{
		{Name: "negotiated_pq_hybrid", Weight: 40, Class: "pq_hybrid"},
		{Name: "negotiated_pq", Weight: 30, Class: "pq"},
		{Name: "cert_pq_sig", Weight: 25, Class: "pq"},
		{Name: "obsolete_draft_negotiated", Weight: -15, Class: "draft"},
		{Name: "no_pq_offer", Weight: 0, Class: "classic"},
		{Name: "weak_classical_preferred", Weight: -5, Class: "classic"},
		{Name: "dual_cert", Weight: 20, Class: "pq"},
	}
	got := DefaultRubric().Rules
	if len(got) != len(want) {
		t.Fatalf("DefaultRubric rules len = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("DefaultRubric rule[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

// TestHNDLDraft25497 pins the grammar: draft group 25497 is
// X25519Kyber768Draft00 — the obsolete-Kyber compatibility oracle (spec §5.6
// hndl_risk; register PQ-19 "HNDL pin for 25497"). The taxonomy classifies
// it as a pre-standards hybrid; a server that accepted it is HNDL-exposed
// (harvest-now-decrypt-later), so the verdict must set HNDL true and land
// the obsolete_draft_negotiated penalty.
func TestHNDLDraft25497(t *testing.T) {
	c, ok := GroupClass(25497)
	if !ok || c != ClassPQHybridD {
		t.Fatalf("taxonomy pin: GroupClass(25497) = (%q, %v), want (pq_hybrid_draft, true)", c, ok)
	}
	v, err := DefaultRubric().Score(ScoreInput{NegotiatedClass: "draft", OfferedPQ: true, AcceptsDraft: true})
	if err == nil {
		t.Fatalf("Score(draft 25497) err = nil, want the zero-PQ-signal scan-error")
	}
	if !v.HNDL {
		t.Errorf("HNDL = false, want true: draft 25497 (X25519Kyber768Draft00) is obsolete-Kyber, HNDL-exposed")
	}
	if v.Score != 0 || v.Label != "scan-error" {
		t.Errorf("verdict = (%d, %q), want (0, scan-error): the -15 penalty floors the score at 0", v.Score, v.Label)
	}
	want := "obsolete_draft_negotiated(-15)"
	if !strings.Contains(v.Summary, want) {
		t.Errorf("Summary = %q, want it to contain %q", v.Summary, want)
	}
}

// TestHNDLIffAcceptsDraft pins the iff: the flag must stay false for a PQ
// verdict with no draft acceptance — HNDL tracks AcceptsDraft alone.
func TestHNDLIffAcceptsDraft(t *testing.T) {
	v, err := DefaultRubric().Score(ScoreInput{NegotiatedClass: "pq_hybrid", OfferedPQ: true})
	if err != nil {
		t.Fatalf("Score() err = %v, want nil", err)
	}
	if v.HNDL {
		t.Errorf("HNDL = true with AcceptsDraft=false, want false (iff)")
	}
}

// TestVerdictBandBoundaries pins the label ladder exactly at each boundary
// via a synthetic single-rule rubric: pq-ready >= 80, pq-ready-hybrid >= 60,
// pq-partial >= 40, pq-missing >= 1.
func TestVerdictBandBoundaries(t *testing.T) {
	cells := []struct {
		weight    int
		wantLabel string
	}{
		{1, "pq-missing"}, {39, "pq-missing"},
		{40, "pq-partial"}, {59, "pq-partial"},
		{60, "pq-ready-hybrid"}, {79, "pq-ready-hybrid"},
		{80, "pq-ready"}, {100, "pq-ready"},
	}
	for _, tc := range cells {
		r := &Rubric{Rules: []RubricRule{{Name: "negotiated_pq_hybrid", Weight: tc.weight, Class: "pq_hybrid"}}}
		v, err := r.Score(ScoreInput{NegotiatedClass: "pq_hybrid", OfferedPQ: true})
		if err != nil {
			t.Fatalf("weight %d: Score() err = %v, want nil", tc.weight, err)
		}
		if v.Score != tc.weight {
			t.Errorf("weight %d: Score = %d, want %d", tc.weight, v.Score, tc.weight)
		}
		if v.Label != tc.wantLabel {
			t.Errorf("weight %d: Label = %q, want %q", tc.weight, v.Label, tc.wantLabel)
		}
	}
}

// TestScoreClamp pins the 0-100 clamp at both ends via synthetic rubrics:
// a weight overshooting the band still reports 100, and stacked penalties
// floor at 0 (scan-error) rather than going negative.
func TestScoreClamp(t *testing.T) {
	hi := &Rubric{Rules: []RubricRule{{Name: "negotiated_pq_hybrid", Weight: 120, Class: "pq_hybrid"}}}
	v, err := hi.Score(ScoreInput{NegotiatedClass: "pq_hybrid", OfferedPQ: true})
	if err != nil || v.Score != 100 || v.Label != "pq-ready" {
		t.Errorf("upper clamp: got (%d, %q, %v), want (100, pq-ready, nil)", v.Score, v.Label, err)
	}
	lo := &Rubric{Rules: []RubricRule{
		{Name: "obsolete_draft_negotiated", Weight: -50, Class: "draft"},
		{Name: "weak_classical_preferred", Weight: -30, Class: "classic"},
	}}
	v, err = lo.Score(ScoreInput{NegotiatedClass: "classic", OfferedPQ: true, AcceptsDraft: true, ClassicalPreferred: true})
	if err == nil {
		t.Errorf("lower clamp: err = nil, want non-nil (score floored at 0 = scan-error)")
	}
	if v.Score != 0 {
		t.Errorf("lower clamp: Score = %d, want 0 (not -80)", v.Score)
	}
}
