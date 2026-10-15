// Package shard implements the deterministic core behind pqscan's -shard
// flag (PQ-24): the "i/n" spec grammar and the hash-based assignment of
// scan targets to shards.
//
// Watched-RED stub (ADR-0002): the API surface below compiles, the full
// test file (shard_test.go, landed in this same pair) fails against it,
// and the GREEN pair replaces the bodies with the real implementation.
// Contracts the tests pin: the i/n spec grammar, per-key FNV-1a
// assignment, the shards-1..n partition property, the +/-1 balance
// report and fixed-(key,total) stability.
package shard

import "errors"

// errNotImplemented is the watched-RED stub marker (ADR-0002). Every
// stub body below is replaced in the GREEN pair.
var errNotImplemented = errors.New("shard: not implemented (watched-RED stub)")

// TargetKey identifies a scan target: "host:port".
type TargetKey = string

// Spec parses an "i/n" shard spec (1-based: i counts shards from 1) and
// returns the shard Index and Total. RED stub: fails for every input.
func Spec(spec string) (Index, Total int, err error) {
	return 0, 0, errNotImplemented
}

// Assign returns the keys belonging to shard index of total (1-based
// index, from Spec). RED stub: assigns nothing.
func Assign(keys []TargetKey, index, total int) []TargetKey {
	return nil
}

// fnv1a64 is the 64-bit FNV-1a hash over the raw key bytes. RED stub:
// returns zero.
func fnv1a64(s string) uint64 {
	return 0
}
