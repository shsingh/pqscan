// Package target parses the input grammar (hosts, ip[:port], scheme-URIs,
// CIDR) with dedupe/shard/resume semantics (spec §5.1, §5.7).
//
// Substrate stub (PQ-04) — the grammar parser lands with M1's fast mode.
package target

// Input carries one parsed target from any accepted grammar form.
type Input struct {
	Host string
	IP   string
	Port uint16 // 0 = caller default (443)
}
