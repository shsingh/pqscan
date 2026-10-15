// Package grammar parses pqscan target specs into Targets (spec §5.1): bare
// hosts (port 443 default), host:port, IPv4/IPv6 literals, bracketed IPv6
// "[addr]:port", CIDR v4/v6 and the "--" stdin marker. Scheme-prefixed specs
// are rejected: pqscan speaks host/port targets only.
//
// The grammar layer parses one spec per call; CIDR expansion to per-address
// probes, dedupe and shard belong to the run pipeline that consumes it.
package grammar

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

// defaultPort is the probe port for every spec that does not carry its own.
const defaultPort = 443

// Class values recorded on every Target.
const (
	classHost  = "host"
	classIP    = "ip"
	classCIDR  = "cidr"
	classStdin = "stdin"
)

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
// Accepted forms: bare hosts (port 443), host:port, IPv4 and IPv6 literals
// with or without port, bracketed IPv6 "[addr]:port" (the only form that
// attaches a port to IPv6 — an unbracketed string that parses as an address
// is one, however colon-y it looks), CIDR v4/v6, and the "--" stdin marker.
// The returned Input mirrors the trimmed spec; Host is the canonical form of
// an address literal.
//
// Rejected: empty or whitespace-only specs, bare ports, ports outside
// 1-65535, malformed CIDRs and any URL-scheme prefix (the error names the
// scheme and states that pqscan speaks host/port targets only).
func Parse(spec string) ([]Target, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return nil, errors.New("target spec is empty (or only whitespace)")
	}
	if strings.IndexFunc(s, unicode.IsSpace) >= 0 {
		return nil, fmt.Errorf("target spec %q contains whitespace", s)
	}
	if i := strings.Index(s, "://"); i >= 0 {
		return nil, fmt.Errorf("scheme %q in target spec %q: pqscan speaks host/port targets only (no URL scheme prefixes)", s[:i], s)
	}
	if s == "--" {
		return []Target{{Input: s, Class: classStdin}}, nil
	}
	if strings.Contains(s, "/") {
		return parseCIDR(s)
	}
	if strings.HasPrefix(s, "[") {
		return parseBracketed(s)
	}
	// A bare literal that netip accepts — v4 or v6, however colon-y — is
	// an address; ports attach to IPv6 literals only in brackets.
	if addr, err := netip.ParseAddr(s); err == nil {
		return []Target{{Input: s, Host: addr.String(), Port: defaultPort, Class: classIP}}, nil
	}
	if strings.Contains(s, ":") {
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			return nil, fmt.Errorf("invalid target spec %q: %v (attaching a port to an IPv6 literal requires brackets: \"[<addr>]:<port>\")", s, err)
		}
		if host == "" {
			return nil, fmt.Errorf("bare port in target spec %q: missing host before \":\"", s)
		}
		p, err := parsePort(port, s)
		if err != nil {
			return nil, err
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			return []Target{{Input: s, Host: addr.String(), Port: p, Class: classIP}}, nil
		}
		return []Target{{Input: s, Host: host, Port: p, Class: classHost}}, nil
	}
	if isAllDigits(s) {
		return nil, fmt.Errorf("bare port %q in target spec: give a host, e.g. \"example.com:%s\"", s, s)
	}
	return []Target{{Input: s, Host: s, Port: defaultPort, Class: classHost}}, nil
}

// parseCIDR handles the CIDR forms of both families ("10.0.0.0/24",
// "2001:db8::/32"), masking host bits so the Target always names the
// network itself.
func parseCIDR(s string) ([]Target, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR in target spec %q", s)
	}
	return []Target{{
		Input:  s,
		Host:   prefix.Masked().Addr().String(),
		Port:   defaultPort,
		Class:  classCIDR,
		Prefix: prefix.Bits(),
	}}, nil
}

// parseBracketed handles "[addr]:port" (SplitHostPort splits the bracketed
// form) and bracketed literals without a port, which the bare ParseAddr
// path never sees: it errors there and this function owns it.
func parseBracketed(s string) ([]Target, error) {
	if host, port, err := net.SplitHostPort(s); err == nil {
		if host == "" {
			return nil, fmt.Errorf("bare port in target spec %q: missing host before \":\"", s)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv6 literal %q in target spec %q", host, s)
		}
		p, err := parsePort(port, s)
		if err != nil {
			return nil, err
		}
		return []Target{{Input: s, Host: addr.String(), Port: p, Class: classIP}}, nil
	}
	// SplitHostPort wants a port after the brackets; "[addr]" with none
	// still parses — anything left is a bracket mistake.
	if !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("unbalanced brackets in target spec %q", s)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	addr, err := netip.ParseAddr(inner)
	if err != nil {
		return nil, fmt.Errorf("invalid IPv6 literal in target spec %q", s)
	}
	return []Target{{Input: s, Host: addr.String(), Port: defaultPort, Class: classIP}}, nil
}

// parsePort validates a ":"-carried port: non-empty, digits only, 1-65535.
func parsePort(port, spec string) (int, error) {
	if port == "" {
		return 0, fmt.Errorf("target spec %q: missing port after \":\"", spec)
	}
	if !isAllDigits(port) {
		return 0, fmt.Errorf("invalid port %q in target spec %q", port, spec)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q out of range in target spec %q (valid ports are 1-65535)", port, spec)
	}
	return n, nil
}

// isAllDigits reports whether s is non-empty and digits only.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
