// Package resolver provides the PQ-26 PTR/SNI lookup pool for pqscan: a
// bounded reverse-DNS worker pool, an LRU result cache and the SNI host-name
// strategies the scanner applies to IP targets (spec §5.1 targeting table,
// §7.2 pipeline shape, §8 CLI surface -sni knob).
//
// Every DNS touch is INJECTED: Options.LookupAddr supplies the lookup — the
// production pool wires the system resolver (net.DefaultResolver), tests
// wire a fake table — so the package performs zero DNS of its own.
package resolver

import (
	"container/list"
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
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

type counters struct {
	lookups, hits, misses, malformed, evictions atomic.Int64
}

type lruEntry struct {
	key  netip.Addr
	name string
}

// Pool is a bounded reverse-DNS lookup pool with an LRU result cache and the
// SNI strategies for IP targets. Safe for concurrent use.
type Pool struct {
	opts     Options
	strategy string
	slots    chan struct{}
	timeout  time.Duration
	lookup   func(ctx context.Context, addr string) ([]string, error)

	stats counters

	mu    sync.Mutex
	cache map[netip.Addr]*list.Element
	order *list.List
}

// New builds a Pool from opts: Workers <=0 becomes the package default,
// CacheSize <=0 disables the cache, an empty or unknown SNIStrategy becomes
// StrategyAuto (degraded-but-alive: the scanner never refuses to start over
// an unrecognized option), and a nil LookupAddr wires the real system
// resolver (net.DefaultResolver.LookupAddr).
func New(opts Options) *Pool {
	workers := opts.Workers
	if workers <= 0 {
		workers = defaultWorkers
	}
	p := &Pool{
		opts:     opts,
		strategy: normalizeStrategy(opts.SNIStrategy),
		slots:    make(chan struct{}, workers),
		timeout:  opts.Timeout,
		lookup:   opts.LookupAddr,
		order:    list.New(),
	}
	if p.lookup == nil {
		p.lookup = net.DefaultResolver.LookupAddr
	}
	if opts.CacheSize > 0 {
		p.cache = make(map[netip.Addr]*list.Element, opts.CacheSize)
	}
	return p
}

func normalizeStrategy(s string) string {
	switch s {
	case StrategyPTRThenIP, StrategyIPOnly:
		return s
	default:
		return StrategyAuto
	}
}

// ResolvePTR resolves reverse DNS for addr through the bounded worker pool
// and reports the first domain-shaped PTR name (one trailing root dot
// stripped) as (name, true). It is ("", false) when the lookup errors, hits
// the Timeout budget, or yields no domain-shaped name — a malformed answer
// is a recorded miss and is never cached.
//
// The cache holds positives only: misses, timeouts, errors and malformed
// answers are re-resolved on the next call. A worker slot is acquired only
// for an actual injected lookup; saturated callers wait (honouring ctx)
// instead of fanning out unbounded.
func (p *Pool) ResolvePTR(ctx context.Context, addr netip.Addr) (string, bool) {
	if !addr.IsValid() {
		return "", false
	}
	p.stats.lookups.Add(1)
	if name, ok := p.cacheGet(addr); ok {
		p.stats.hits.Add(1)
		return name, true
	}
	p.stats.misses.Add(1)
	if p.slots != nil {
		select {
		case p.slots <- struct{}{}:
			defer func() { <-p.slots }()
		case <-ctx.Done():
			return "", false
		}
	}
	lctx, cancel := context.WithCancel(ctx)
	if p.timeout > 0 {
		lctx, cancel = context.WithTimeout(ctx, p.timeout)
	}
	defer cancel()
	names, err := p.lookup(lctx, addr.String())
	if err != nil || len(names) == 0 {
		return "", false
	}
	name, ok := pickPTR(names)
	if !ok {
		p.stats.malformed.Add(1)
		return "", false
	}
	p.cachePut(addr, name)
	return name, true
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
	if !addr.IsValid() {
		return "", ""
	}
	ip := addr.String()
	if p.strategy == StrategyIPOnly {
		return ip, StrategyIPOnly
	}
	if name, ok := normalizePTR(ptr); ok {
		return name, StrategyPTRThenIP
	}
	if p.strategy == StrategyAuto {
		return ip, StrategyIPOnly
	}
	return ip, StrategyPTRThenIP
}

// Stats returns a snapshot of the pool counters.
func (p *Pool) Stats() Stats {
	return Stats{
		Lookups:   p.stats.lookups.Load(),
		Hits:      p.stats.hits.Load(),
		Misses:    p.stats.misses.Load(),
		Malformed: p.stats.malformed.Load(),
		Evictions: p.stats.evictions.Load(),
	}
}

// pickPTR returns the first domain-shaped name in a PTR answer, normalized
// (one trailing root dot stripped); names that fail shape validation are
// skipped rather than promoted.
func pickPTR(names []string) (string, bool) {
	for _, n := range names {
		if name, ok := normalizePTR(n); ok {
			return name, true
		}
	}
	return "", false
}

// normalizePTR validates a PTR claim as a TLS-usable DNS name and strips one
// trailing root dot (PTR answers conventionally carry the FQDN dot).
func normalizePTR(ptr string) (string, bool) {
	name := strings.TrimSuffix(ptr, ".")
	if !isDomainName(name) {
		return "", false
	}
	return name, true
}

// isDomainName reports whether name is a host name usable as an SNI
// candidate: letters/digits/hyphen labels of 1–63 bytes, no empty label, no
// leading/trailing label hyphen, at most 253 bytes overall (RFC 1035 §2.3.1
// preference, RFC 1123 host-name form; unlabelled wildcard '*' excluded).
func isDomainName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (p *Pool) cacheGet(addr netip.Addr) (string, bool) {
	if p.cache == nil {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	el, ok := p.cache[addr]
	if !ok {
		return "", false
	}
	p.order.MoveToFront(el)
	return el.Value.(*lruEntry).name, true
}

func (p *Pool) cachePut(addr netip.Addr, name string) {
	if p.cache == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if el, ok := p.cache[addr]; ok {
		el.Value.(*lruEntry).name = name
		p.order.MoveToFront(el)
		return
	}
	el := p.order.PushFront(&lruEntry{key: addr, name: name})
	p.cache[addr] = el
	if p.order.Len() > p.opts.CacheSize {
		if victim := p.order.Remove(p.order.Back()); victim != nil {
			delete(p.cache, victim.(*lruEntry).key)
			p.stats.evictions.Add(1)
		}
	}
}
