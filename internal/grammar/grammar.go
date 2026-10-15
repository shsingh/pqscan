// Package grammar parses pqscan target specs into Targets (spec §5.1): bare
// hosts (port 443 default), host:port, IPv4/IPv6 literals, bracketed IPv6
// "[addr]:port", CIDR v4/v6 and the "--" stdin marker. Scheme-prefixed specs
// are rejected: pqscan speaks host/port targets only.
//
// The grammar layer parses one spec per call; CIDR expansion to per-address
// probes, dedupe and shard belong to the run pipeline that consumes it.
package grammar

import "errors"

// Target is one parsed target: Class is "host", "ip", "cidr" or "stdin";
// Prefix is the CIDR prefix length (0 otherwise); Port is the probe port
// (0 only for the stdin marker, which carries no port).
type Target struct {
	Input  string // the spec this Target was parsed from (whitespace-trimmed)
	Host   string // host, address literal or network address (empty for stdin)
	Port   int    // scan port; 443 unless the spec carries its own
	Class  string // host | ip | cidr | stdin
	Prefix int    // CIDR prefix length; 0 for every other class
}

// Parse turns one target spec into its Targets — exactly one, except CIDR
// input, which maps to one Target per network (Parse never explodes a CIDR
// into per-address targets; the run pipeline does that).
//
// Watched-RED stub (ADR-0002): Target's shape is fixed so the grammar table
// compiles and fails on assertions; the parser lands in the GREEN commit.
func Parse(spec string) ([]Target, error) {
	return nil, errors.New("not implemented: grammar.Parse (watched-RED stub)")
}
