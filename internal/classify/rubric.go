// Package classify holds the IANA-derived taxonomy: supported groups,
// signature schemes and certificate OID classes (spec §5.6, Appendix A).
//
// rubric.go is the readiness rubric and verdict calculator (spec §5.6,
// PQ-19): weights fixed in code and printable — DefaultRubric is the rule
// table. cert_pq_sig and dual_cert ride in the table ahead of PQ-21; Score
// treats an absent certificate analysis as zero points, never an error.
// The record wire-in (PQ-19b) maps ladder observations onto ScoreInput and
// lands the PQS-record field.
package classify

import "errors"

// RubricRule is one weighted line of the readiness rubric.
type RubricRule struct {
	Name   string
	Weight int    // points, negative = penalty
	Class  string // the class the points ride on: pq / pq_hybrid / classic / draft / unknown
}

// Rubric is a scored rule table.
type Rubric struct {
	Rules []RubricRule
}

// ScoreInput carries one target's ladder-derived PQ observations.
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
	Score   int
	Label   string
	HNDL    bool
	Summary string
}

// DefaultRubric returns the printable rule table (spec §5.6 order).
func DefaultRubric() *Rubric { return &Rubric{} }

// Score evaluates the readiness rubric against one observation set.
func (r *Rubric) Score(in ScoreInput) (Verdict, error) {
	return Verdict{}, errRubricNotImplemented
}

// errRubricNotImplemented marks the watched-RED stub (ADR-0002): the PQ-19
// GREEN commit replaces it with the scoring engines; types stay intact so
// the RED run fails on assertions, never on compilation.
var errRubricNotImplemented = errors.New("classify rubric scoring: not implemented (watched-RED stub, PQ-19)")
