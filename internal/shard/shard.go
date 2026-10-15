// Package shard implements the deterministic core behind pqscan's -shard
// flag (PQ-24): the "i/n" spec grammar and the hash-based assignment of
// scan targets to shards.
//
// A scan target is identified by its TargetKey, the "host:port" string the
// rest of the scanner keys its work on. Spec parses the CLI-side "i/n"
// grammar; Assign computes one shard's member set from the full key list.
// The two compose: a box launched with -shard i/n scans Assign(keys, i, n)
// with i and n the parsed Index and Total.
//
// Assignment is hash-based per key: shard(k) = fnv1a64(k) % total + 1. It
// depends only on the (key, total) pair, so the same key always lands in
// the same shard — across runs, across machines, and regardless of which
// other keys the list carries. The shards 1..total over any key set are a
// partition (disjoint + complete). Sharding is STABLE ONLY FOR A FIXED
// total: a different box count re-buckets every key, so resume and re-run
// flows must keep the total the original run used.
package shard

import (
	"fmt"
	"strconv"
	"strings"
)

// TargetKey identifies a scan target: "host:port".
type TargetKey = string

// Spec parses an "i/n" shard specification (1-based: i counts shards from
// 1) and returns the shard Index and Total.
//
// One "i/n" integer pair is accepted; surrounding whitespace is tolerated
// around the whole spec and around each part ("  2 / 8  " parses as 2 of
// 8). Rejected per the PQ-24 grammar:
//
//   - anything but a single i/n pair (missing divider, empty or extra
//     parts): want "i/n"
//   - non-integer parts
//   - n < 1
//   - i < 1 (negative, or "0/n": an empty shard)
//   - i == n ("n/n") and i > n: the PQ-24 grammar accepts only 1 <= i < n
func Spec(spec string) (Index, Total int, err error) {
	raw := spec
	s := strings.TrimSpace(spec)
	if strings.Count(s, "/") != 1 {
		return 0, 0, fmt.Errorf("shard: invalid spec %q: want \"i/n\"", raw)
	}
	parts := strings.SplitN(s, "/", 2)
	idxPart, totPart := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if idxPart == "" || totPart == "" {
		return 0, 0, fmt.Errorf("shard: invalid spec %q: want \"i/n\"", raw)
	}
	idx, err := strconv.Atoi(idxPart)
	if err != nil {
		return 0, 0, fmt.Errorf("shard: invalid spec %q: %q is not an integer", raw, idxPart)
	}
	tot, err := strconv.Atoi(totPart)
	if err != nil {
		return 0, 0, fmt.Errorf("shard: invalid spec %q: %q is not an integer", raw, totPart)
	}
	if tot < 1 {
		return 0, 0, fmt.Errorf("shard: invalid spec %q: shard total must be at least 1 (got %d)", raw, tot)
	}
	switch {
	case idx < 0:
		return 0, 0, fmt.Errorf("shard: invalid spec %q: shard index %d must be at least 1 (negative)", raw, idx)
	case idx == 0:
		return 0, 0, fmt.Errorf("shard: invalid spec %q: 0/n assigns no targets; the shard index must be at least 1", raw)
	case idx == tot:
		return 0, 0, fmt.Errorf("shard: invalid spec %q: n/n rejected per PQ-24 grammar; valid shard specs satisfy 1 <= i < n", raw)
	case idx > tot:
		return 0, 0, fmt.Errorf("shard: invalid spec %q: shard index %d > total %d", raw, idx, tot)
	}
	return idx, tot, nil
}

// Assign returns the keys belonging to shard index of total, preserving
// the caller's key order. index is 1-based (matching Spec; it is the value
// the -shard wiring will pass through): a key k belongs to shard i exactly
// when fnv1a64(k) % total == i-1.
//
// The rule depends only on the (key, total) pair, so the same key lands in
// the same shard on every run and every machine — as long as total stays
// fixed (see the package comment: stability is per total, and a different
// box count re-buckets every key). An out-of-range index or a total < 1 is
// a caller bug and panics.
func Assign(keys []TargetKey, index, total int) []TargetKey {
	if total < 1 {
		panic(fmt.Sprintf("shard: total %d must be at least 1", total))
	}
	if index < 1 || index > total {
		panic(fmt.Sprintf("shard: index %d out of range [1, %d]", index, total))
	}
	members := make([]TargetKey, 0)
	want := uint64(index - 1)
	for _, k := range keys {
		if fnv1a64(k)%uint64(total) == want {
			members = append(members, k)
		}
	}
	return members
}

// fnv1a64 is the 64-bit FNV-1a hash over the raw key bytes (offset
// 0xcbf29ce484222325, prime 0x100000001b3) — the only mixing step in the
// shard rule (see Assign). TestAssignFnv1a64Golden anchors it against an
// independent reference implementation.
func fnv1a64(s string) uint64 {
	const (
		offset64 = 0xcbf29ce484222325
		prime64  = 0x100000001b3
	)
	h := uint64(offset64)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}
