// Package classify holds the IANA-derived taxonomy: supported groups,
// signature schemes and certificate OID classes (spec §5.6, Appendix A).
//
// rubric.go is the readiness rubric and verdict calculator (spec §5.6,
// PQ-19): weights are fixed in code and printable — DefaultRubric is the
// rule table. cert_pq_sig and dual_cert ride in the table ahead of PQ-21;
// Score treats an absent certificate analysis as zero points, never an
// error. The record wire-in (PQ-19b) maps ladder observations onto
// ScoreInput and lands the PQS-record field.
package classify

import (
	"fmt"
	"strings"
)

// Rubric class tokens (spec §5.6 taxonomy, rubric-side compact form).
const (
	rubricClassPQ       = "pq"
	rubricClassPQHybrid = "pq_hybrid"
	rubricClassClassic  = "classic"
	rubricClassDraft    = "draft"
	rubricClassUnknown  = "unknown"
)

// Verdict label bands (0-100 clamped, spec §5.6 readiness verdicts).
const (
	labelPQReady       = "pq-ready"
	labelPQReadyHybrid = "pq-ready-hybrid"
	labelPQPartial     = "pq-partial"
	labelPQMissing     = "pq-missing"
	labelScanError     = "scan-error"
)

// RubricRule is one weighted line of the readiness rubric.
type RubricRule struct {
	Name   string // rule id, as printed by the rubric summary
	Weight int    // points, negative = penalty
	Class  string // the class the points ride on: pq / pq_hybrid / classic / draft / unknown
}

// Rubric is a scored rule table.
type Rubric struct {
	Rules []RubricRule
}

// DefaultRubric returns the printable rule table in spec order: negotiated
// PQ hybrid (40), negotiated pure PQ (30), negotiated PQ certificate (25 --
// in the table so the shape is fixed, scored only when PQ-21 feeds the cert
// analysis), obsolete-draft penalty (-15), informational no-PQ-offer row
// (0), weak-classical-preferred penalty (-5) and dual certificate (20 --
// likewise pending PQ-21).
func DefaultRubric() *Rubric {
	return &Rubric{Rules: []RubricRule{
		{Name: "negotiated_pq_hybrid", Weight: 40, Class: rubricClassPQHybrid},
		{Name: "negotiated_pq", Weight: 30, Class: rubricClassPQ},
		{Name: "cert_pq_sig", Weight: 25, Class: rubricClassPQ},                   // PQ-21 feeds; 0 until a PQ cert signal is analysable
		{Name: "obsolete_draft_negotiated", Weight: -15, Class: rubricClassDraft}, // HNDL signal: draft groups in use (e.g. 25497 X25519Kyber768Draft00)
		{Name: "no_pq_offer", Weight: 0, Class: rubricClassClassic},               // informational: why a classic-only target scored nothing
		{Name: "weak_classical_preferred", Weight: -5, Class: rubricClassClassic}, // classical group accepted over an offered pq_hybrid (ladder result)
		{Name: "dual_cert", Weight: 20, Class: rubricClassPQ},                     // PQ-21 feeds; 0 until a dual cert is observed
	}}
}

// ScoreInput carries one target's ladder-derived PQ observations. The
// negotiated class uses the rubric-side compact tokens (pq, pq_hybrid,
// classic, draft, unknown); an empty or unrecognised token is a scan error,
// not a zero read. OfferedPQ is the PQ-capability-observable-in-offers
// signal -- informational under this rubric (no points, never fatal).
// CertPQ/DualCert stay false on every caller until PQ-21 lands the
// certificate analysis; their absence scores 0 and raises no error.
type ScoreInput struct {
	NegotiatedClass    string
	OfferedPQ          bool
	AcceptsDraft       bool
	ClassicalPreferred bool
	CertPQ             bool
	DualCert           bool
}

// Verdict is the rubric's readiness output for one target.
type Verdict struct {
	Score   int    // 0-100 clamped
	Label   string // pq-ready / pq-ready-hybrid / pq-partial / pq-missing / scan-error
	HNDL    bool   // true iff AcceptsDraft: obsolete-draft groups in use = harvest-now-decrypt-later exposure
	Summary string // the fired rules in table order, e.g. "negotiated_pq_hybrid(+40); obsolete_draft_negotiated(-15)"
}

// Score evaluates the readiness rubric against one observation set.
//
// Verdict bands (0-100 clamped): pq-ready >= 80, pq-ready-hybrid >= 60,
// pq-partial >= 40, pq-missing >= 1, and score 0 = scan-error, which always
// returns a non-nil error: a scan with zero PQ signal is an error state for
// the caller to surface in the record, not a passing readiness verdict. The
// error text distinguishes an unrecognised negotiated class from a
// well-formed-but-zero observation set.
//
// HNDL is true iff AcceptsDraft -- a server accepting an obsolete-draft PQ
// group (draft 25497 X25519Kyber768Draft00, the obsolete-Kyber compat
// oracle) is HNDL-exposed, because the classical half of the handshake
// remains decryptable to a future CRQC (spec §5.6 hndl_risk).
func (r *Rubric) Score(in ScoreInput) (Verdict, error) {
	if !validRubricClass(in.NegotiatedClass) {
		v := Verdict{Score: 0, Label: labelScanError, Summary: labelScanError}
		return v, fmt.Errorf("rubric: unrecognised negotiated class %q", in.NegotiatedClass)
	}
	v := Verdict{HNDL: in.AcceptsDraft}
	var parts []string
	for _, rule := range r.Rules {
		if rubricFires(rule.Name, in) {
			v.Score += rule.Weight
			parts = append(parts, fmt.Sprintf("%s(%+d)", rule.Name, rule.Weight))
		}
	}
	v.Score = clampScore(v.Score)
	v.Label = verdictLabel(v.Score)
	v.Summary = strings.Join(parts, "; ")
	if v.Score == 0 {
		if v.Summary == "" {
			v.Summary = labelScanError
		}
		return v, fmt.Errorf("rubric: zero PQ signal (score 0) — verdict %s", labelScanError)
	}
	return v, nil
}

// validRubricClass reports whether s is a recognised negotiated-class token.
func validRubricClass(s string) bool {
	switch s {
	case rubricClassPQ, rubricClassPQHybrid, rubricClassClassic, rubricClassDraft, rubricClassUnknown:
		return true
	default:
		return false
	}
}

// rubricFires reports whether a named rule contributes its weight for this
// observation set. The name → input mapping is the rubric's contract:
// negotiated_pq_hybrid/negotiated_pq key on the negotiated class,
// cert_pq_sig and dual_cert key on the PQ-21 cert inputs (absent = never
// fired), obsolete_draft_negotiated and weak_classical_preferred key on the
// ladder-derived acceptance facts, and no_pq_offer is the informational
// marker that fires only when no PQ capability was offered at all.
func rubricFires(name string, in ScoreInput) bool {
	switch name {
	case "negotiated_pq_hybrid":
		return in.NegotiatedClass == rubricClassPQHybrid
	case "negotiated_pq":
		return in.NegotiatedClass == rubricClassPQ
	case "cert_pq_sig":
		return in.CertPQ
	case "obsolete_draft_negotiated":
		return in.AcceptsDraft
	case "no_pq_offer":
		return !in.OfferedPQ
	case "weak_classical_preferred":
		return in.ClassicalPreferred
	case "dual_cert":
		return in.DualCert
	default:
		return false // unknown rule names stay inert: the table is curated
	}
}

// clampScore limits a raw rubric total to the 0-100 verdict range.
func clampScore(s int) int {
	if s < 0 {
		return 0
	}
	if s > 100 {
		return 100
	}
	return s
}

// verdictLabel maps a clamped score onto the verdict bands.
func verdictLabel(score int) string {
	switch {
	case score >= 80:
		return labelPQReady
	case score >= 60:
		return labelPQReadyHybrid
	case score >= 40:
		return labelPQPartial
	case score >= 1:
		return labelPQMissing
	default:
		return labelScanError
	}
}
