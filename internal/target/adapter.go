// Package target — PQ-35 watched-RED stub: the adapter signatures only,
// bodies return errNotImplemented so the contract table runs and fails on
// assertions, not compile errors (ADR-0002). The GREEN commit replaces
// these bodies with the real dialect feeders and retires the PQ-04 stub's
// Input struct (dead; grammar.Target already carries it).

package target

import (
	"errors"
	"io"

	"github.com/shsingh/pqscan/internal/grammar"
)

// errNotImplemented is the RED-stub sentinel: the contract table must fail
// against this error while the package still compiles (a compile-fail RED
// is not a watched RED).
var errNotImplemented = errors.New("target adapters (PQ-35): not implemented (watched-RED stub)")

// FromHTTPX is the PQ-35 RED stub (httpx text-mode lines -> grammar
// targets; the body lands with the GREEN commit).
func FromHTTPX(r io.Reader) ([]grammar.Target, error) {
	return nil, errNotImplemented
}

// FromNaabu is the PQ-35 RED stub (naabu text lines -> grammar targets;
// the body lands with the GREEN commit).
func FromNaabu(r io.Reader) ([]grammar.Target, error) {
	return nil, errNotImplemented
}

// FromLines is the PQ-35 RED stub (raw -l/-- spec lines -> grammar
// targets; the body lands with the GREEN commit).
func FromLines(r io.Reader) ([]grammar.Target, error) {
	return nil, errNotImplemented
}
