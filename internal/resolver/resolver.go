// Package resolver provides the PQ-26 PTR/SNI lookup pool for pqscan: a
// bounded reverse-DNS worker pool, an LRU result cache and the SNI host-name
// strategies the scanner applies to IP targets (spec §5.1 targeting table,
// §7.2 pipeline shape, §8 CLI surface -sni knob).
//
// Every DNS touch is INJECTED: Options.LookupAddr supplies the lookup — the
// production pool wires the system resolver, tests wire a fake table — so
// the package performs zero DNS of its own.
//
// Stub (watched RED, ADR-0002): signatures and constants are final; the
// engines land with the GREEN commit of the pair.
package resolver

import (
	"context"
	"net/netip"
	"time"
)

// SNI strategies for IP targets (spec §5.1; selectable via Options.SNIStrategy).
const (
	// StrategyAuto is the fast-mode default: the PTR hostname first, else the
	// IP literal.
	StrategyAuto = "auto"
	// StrategyPTRThenIP prefers the PTR-derived hostname and falls back to the
	// IP literal when the PTR is missing or not domain-shaped.
	StrategyPTRThenIP = "ptr-then-ip"
	// StrategyIPOnly always answers with the raw IP literal.
	StrategyIPOnly = "ip-only"
)

// defaultWorkers is the worker cap for Options.Workers <=0 (the pool must
// never be unbounded by omission).
const defaultWorkers = 4

// Options configures a resolver Pool.
type Options struct {
	// Workers bounds the number of concurrent injected lookups; <=0 selects
	// the package default (defaultWorkers).
	Workers int
	// Timeout bounds each injected lookup; <=0 keeps only the caller's
	// context deadline.
	Timeout time.Duration
	// CacheSize is the LRU capacity; <=0 disables caching.
	CacheSize int
	// SNIStrategy selects the SNI rule: StrategyAuto (default),
	// StrategyPTRThenIP or StrategyIPOnly. Unrecognized values fall back to
	// StrategyAuto.
	SNIStrategy string
	// LookupAddr is the INJECTED DNS dependency (net.Resolver.LookupAddr
	// signature: the reverse names for the literal "addr"). The zero value
	// wires the real system resolver; tests inject a fake table so nothing
	// touches DNS.
	LookupAddr func(ctx context.Context, addr string) ([]string, error)
}

// Stats is a snapshot of the pool's counters (approximate under concurrency:
// fields are read independently).
type Stats struct {
	// Lookups counts ResolvePTR calls received.
	Lookups int64
	// Hits counts answers served from the LRU cache.
	Hits int64
	// Misses counts answers that required an injected lookup.
	Misses int64
	// Malformed counts injected lookups whose PTR names all failed
	// domain-shape validation (a subset of Misses; never cached).
	Malformed int64
	// Evictions counts LRU entries evicted to stay inside CacheSize.
	Evictions int64
}

// Pool is a bounded reverse-DNS lookup pool with an LRU result cache and the
// SNI strategies for IP targets. Safe for concurrent use.
type Pool struct {
	opts     Options
	strategy string
}

// New builds a Pool from opts: Workers <=0 becomes the package default,
// CacheSize <=0 disables the cache, an empty or unknown SNIStrategy becomes
// StrategyAuto (degraded-but-alive: the scanner never refuses to start over
// an unrecognized option), and a nil LookupAddr wires the real system
// resolver.
func New(opts Options) *Pool {
	return &Pool{opts: opts, strategy: StrategyAuto}
}

// ResolvePTR resolves reverse DNS for addr through the bounded worker pool
// and reports the first domain-shaped PTR name (one trailing root dot
// stripped) as (name, true). It is (\"\", false) when the lookup errors,
// hits the Timeout budget, or yields no domain-shaped name — a malformed
// answer is a recorded miss and is never cached.
func (p *Pool) ResolvePTR(ctx context.Context, addr netip.Addr) (string, bool) {
	return "", false // stub: engines land with the GREEN commit (ADR-0002)
}

// SNIFromPTR applies the pool's SNI strategy to an IP target and returns the
// SNI candidate plus the strategy that won:
//
//   - ptr-then-ip: the PTR hostname when it is domain-shaped, else the IP
//     literal; the winner stays "ptr-then-ip" when its own fallback fires.
//   - ip-only: always the raw IP literal (unbracketed, exactly as the TLS
//     ClientHello server_name data takes it for the spec's ip-only knob).
//   - auto: the fast-mode default — the PTR first, else the IP literal — and
//     it reports the rule that actually won.
//
// ptr is validated with the same shape rules ResolvePTR applies; an invalid
// target address yields ("", "").
func (p *Pool) SNIFromPTR(ptr string, addr netip.Addr) (string, string) {
	return "", "" // stub: engines land with the GREEN commit (ADR-0002)
}

// Stats returns a snapshot of the pool counters.
func (p *Pool) Stats() Stats {
	return Stats{} // stub: engines land with the GREEN commit (ADR-0002)
}
