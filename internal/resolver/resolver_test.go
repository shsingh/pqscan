package resolver

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDNS is the INJECTED lookup dependency: a fixed answer table plus call
// accounting. It never performs real DNS — the resolver package only ever
// sees this func's return values.
type fakeDNS struct {
	mu     sync.Mutex
	calls  map[string]int
	table  map[string][]string
	err    error
	blockc <-chan struct{} // non-nil: every call blocks until closed or ctx done
	gate   func()          // instrument on entry (concurrency observation)
}

func (d *fakeDNS) lookup(ctx context.Context, addr string) ([]string, error) {
	d.mu.Lock()
	if d.calls == nil {
		d.calls = map[string]int{}
	}
	d.calls[addr]++
	d.mu.Unlock()
	if d.gate != nil {
		d.gate()
	}
	if d.blockc != nil {
		select {
		case <-d.blockc:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if d.err != nil {
		return nil, d.err
	}
	return d.table[addr], nil
}

func (d *fakeDNS) count(addr string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls[addr]
}

func (d *fakeDNS) total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, c := range d.calls {
		n += c
	}
	return n
}

var (
	addrA = netip.MustParseAddr("198.51.100.10")
	addrB = netip.MustParseAddr("198.51.100.11")
	addrC = netip.MustParseAddr("198.51.100.12")
)

// TestResolvePTR_CacheHitMissEviction walks a CacheSize=2 LRU through miss,
// hit, eviction and re-miss; every step must be served by the injected table
// exactly when the cache could not answer.
func TestResolvePTR_CacheHitMissEviction(t *testing.T) {
	dns := &fakeDNS{table: map[string][]string{
		addrA.String(): {"a.example.com"},
		addrB.String(): {"b.example.com"},
		addrC.String(): {"c.example.com"},
	}}
	p := New(Options{Workers: 1, CacheSize: 2, LookupAddr: dns.lookup})

	type step struct {
		addr   netip.Addr
		want   string
		wantOK bool
	}
	for i, s := range []step{
		{addr: addrA, want: "a.example.com", wantOK: true}, // miss
		{addr: addrA, want: "a.example.com", wantOK: true}, // hit
		{addr: addrB, want: "b.example.com", wantOK: true}, // miss (LRU: B,A)
		{addr: addrC, want: "c.example.com", wantOK: true}, // miss, evicts A
		{addr: addrA, want: "a.example.com", wantOK: true}, // miss again (evicted), evicts B
		{addr: addrB, want: "b.example.com", wantOK: true}, // miss again (evicted), evicts C
	} {
		got, ok := p.ResolvePTR(context.Background(), s.addr)
		if got != s.want || ok != s.wantOK {
			t.Errorf("step %d ResolvePTR(%s): got (%q, %v), want (%q, %v)", i, s.addr, got, ok, s.want, s.wantOK)
		}
	}
	wantCalls := map[string]int{addrA.String(): 2, addrB.String(): 2, addrC.String(): 1}
	for a, n := range wantCalls {
		if got := dns.count(a); got != n {
			t.Errorf("injected lookups for %s: got %d, want %d (repeats must be served from the cache until evicted)", a, got, n)
		}
	}
	want := Stats{Lookups: 6, Hits: 1, Misses: 5, Evictions: 3}
	if st := p.Stats(); st != want {
		t.Errorf("Stats: got %+v, want %+v", st, want)
	}
}

// runWorkerCap saturates a pool at `workers` (0 = the package default) with
// `targets` blocked injected lookups: the fake blocks every call until the
// gate opens, so the configured cap is observable as the max number of
// concurrent entries. The cap must be exactly `want` — no less (pool must
// saturate) and no more (bounded).
func runWorkerCap(t *testing.T, workers, targets int) {
	t.Helper()
	table := map[string][]string{}
	addrs := make([]netip.Addr, targets)
	for i := range addrs {
		addrs[i] = netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", 20+i))
		table[addrs[i].String()] = []string{fmt.Sprintf("w%d.example.com", i)}
	}
	gate := make(chan struct{})
	dns := &fakeDNS{table: table, blockc: gate}
	var (
		mu   sync.Mutex
		cur  int
		maxc int
	)
	dns.gate = func() {
		mu.Lock()
		cur++
		if cur > maxc {
			maxc = cur
		}
		mu.Unlock()
	}
	want := workers
	if want <= 0 {
		want = defaultWorkers
	}
	p := New(Options{Workers: workers, LookupAddr: dns.lookup})

	var wg sync.WaitGroup
	for _, a := range addrs {
		wg.Add(1)
		go func(a netip.Addr) {
			defer wg.Done()
			name, ok := p.ResolvePTR(context.Background(), a)
			if !ok {
				t.Errorf("ResolvePTR(%s): !ok — every blocked lookup must finish when the gate opens", a)
				return
			}
			if name != table[a.String()][0] {
				t.Errorf("ResolvePTR(%s): got %q, want %q", a, name, table[a.String()][0])
			}
		}(a)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		saturated := maxc >= want
		mu.Unlock()
		if saturated {
			break
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	observed := maxc
	mu.Unlock()
	if observed != want {
		t.Fatalf("max concurrent injected lookups: got %d, want exactly %d — worker cap not enforced", observed, want)
	}
	close(gate)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("workers did not drain after the gate opened")
	}
	if n := dns.total(); n != targets {
		t.Errorf("injected lookups: got %d, want %d — caching is disabled here", n, targets)
	}
}

func TestResolvePTR_WorkerCap(t *testing.T) {
	runWorkerCap(t, 2, 5)
}

// TestResolvePTR_DefaultWorkers pins the Options.Workers<=0 fallback so the
// "bounded" in the package contract is never accidental.
func TestResolvePTR_DefaultWorkers(t *testing.T) {
	runWorkerCap(t, 0, 7)
}

func TestResolvePTR_LookupTimeout(t *testing.T) {
	hang := make(chan struct{}) // never closed: only the ctx budget can unblock
	dns := &fakeDNS{
		table:  map[string][]string{addrA.String(): {"a.example.com"}},
		blockc: hang,
	}
	p := New(Options{Workers: 1, Timeout: 25 * time.Millisecond, LookupAddr: dns.lookup})
	got, ok := p.ResolvePTR(context.Background(), addrA)
	if got != "" || ok {
		t.Errorf(`ResolvePTR under a 25ms budget vs an uncooperative resolver: got (%q, %v), want ("", false)`, got, ok)
	}
	if n := dns.count(addrA.String()); n != 1 {
		t.Errorf("injected lookups: got %d, want 1 (the budget must not trigger retry storms)", n)
	}
	if st := p.Stats(); st.Misses != 1 || st.Hits != 0 || st.Malformed != 0 {
		t.Errorf("Stats: got %+v, want a single recorded miss", st)
	}
}

// TestResolvePTR_MalformedPTR: names that fail domain-shape validation are
// skipped (the first valid name wins); a malformed-only answer is a recorded
// miss AND is never cached — a repeat re-runs the injected lookup.
func TestResolvePTR_MalformedPTR(t *testing.T) {
	target := netip.MustParseAddr("198.51.100.30")
	cases := []struct {
		name          string
		ptrs          []string
		want          string
		wantOK        bool
		wantMalformed int64
	}{
		{"plain", []string{"host.example.com"}, "host.example.com", true, 0},
		{"trailing dot stripped", []string{"host.example.com."}, "host.example.com", true, 0},
		{"skips malformed, takes valid", []string{"bad_host.example.com", "good.example.com"}, "good.example.com", true, 0},
		{"valid before malformed", []string{"good.example.com", "bad_host.example.com"}, "good.example.com", true, 0},
		{"empty name", []string{""}, "", false, 1},
		{"underscore label", []string{"bad_host.example.com"}, "", false, 1},
		{"leading hyphen label", []string{"-bad.example.com"}, "", false, 1},
		{"trailing hyphen label", []string{"bad-.example.com"}, "", false, 1},
		{"empty label", []string{"bad..example.com"}, "", false, 1},
		{"space in label", []string{"bad example.com"}, "", false, 1},
		{"label too long", []string{strings.Repeat("a", 64)}, "", false, 1},
		{"name too long", []string{strings.Repeat("a.", 127) + "y"}, "", false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dns := &fakeDNS{table: map[string][]string{target.String(): tc.ptrs}}
			p := New(Options{Workers: 1, LookupAddr: dns.lookup})
			got, ok := p.ResolvePTR(context.Background(), target)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("ResolvePTR: got (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
			if st := p.Stats(); st.Misses != 1 || st.Malformed != tc.wantMalformed {
				t.Errorf("Stats: misses=%d malformed=%d, want misses=1 malformed=%d", st.Misses, st.Malformed, tc.wantMalformed)
			}
			if n := dns.count(target.String()); n != 1 {
				t.Fatalf("first attempt must hit the injected table exactly once: got %d", n)
			}
			if tc.wantOK {
				if _, ok := p.ResolvePTR(context.Background(), target); !ok {
					t.Error("cached positive must return ok on repeat")
				}
				if n := dns.count(target.String()); n != 1 {
					t.Errorf("positive result must be cached (no re-lookup): got %d injected lookups", n)
				}
			} else {
				if _, ok := p.ResolvePTR(context.Background(), target); ok {
					t.Error("misses are never cached; a repeat must not surface a cached positive")
				}
				if n := dns.count(target.String()); n != 2 {
					t.Errorf("misses are never cached: second attempt must re-lookup; got %d injected lookups", n)
				}
			}
		})
	}
}

// TestSNIFromPTR_StrategyMatrix — the spec's SNI decision matrix for IP
// targets: ptr-then-ip prefers a domain-shaped PTR and keeps its name when
// its fallback fires; ip-only always answers with the raw IP literal; auto
// is the fast-mode default (PTR first, else IP) reporting the rule that won;
// unknown strategies clamp to auto; an invalid address yields no candidate.
// Performed with no resolver configured at all: the choice is pure data.
func TestSNIFromPTR_StrategyMatrix(t *testing.T) {
	v4 := netip.MustParseAddr("198.51.100.7")
	v6 := netip.MustParseAddr("2001:db8::1")
	cases := []struct {
		strategy string
		ptr      string
		addr     netip.Addr
		wantSNI  string
		wantWon  string
	}{
		{"", "", v4, v4.String(), "ip-only"},
		{"", "host.example.com", v4, "host.example.com", "ptr-then-ip"},
		{"auto", "host.example.com", v4, "host.example.com", "ptr-then-ip"},
		{"auto", "host.example.com.", v4, "host.example.com", "ptr-then-ip"},
		{"auto", "bad_host.example.com", v4, v4.String(), "ip-only"},
		{"auto", "", v4, v4.String(), "ip-only"},
		{"auto", "", v6, v6.String(), "ip-only"},
		{"auto", "host.example.com", netip.Addr{}, "", ""},
		{"ptr-then-ip", "host.example.com", v4, "host.example.com", "ptr-then-ip"},
		{"ptr-then-ip", "bad_host.example.com", v4, v4.String(), "ptr-then-ip"},
		{"ptr-then-ip", "", v4, v4.String(), "ptr-then-ip"},
		{"ip-only", "host.example.com", v4, v4.String(), "ip-only"},
		{"ip-only", "", v4, v4.String(), "ip-only"},
		{"nonsense", "host.example.com", v4, "host.example.com", "ptr-then-ip"},
	}
	for _, tc := range cases {
		t.Run(tc.strategy+"|"+tc.ptr, func(t *testing.T) {
			p := New(Options{SNIStrategy: tc.strategy})
			sni, won := p.SNIFromPTR(tc.ptr, tc.addr)
			if sni != tc.wantSNI || won != tc.wantWon {
				t.Errorf("SNIFromPTR(%q, %s) under %q: got (%q, %q), want (%q, %q)", tc.ptr, tc.addr, tc.strategy, sni, won, tc.wantSNI, tc.wantWon)
			}
		})
	}
}

// TestResolvePTR_InjectedLookupOnly proves the fake table is the ONLY
// resolver: answers must come from it, hits must not re-call it, and an
// address outside the table must fail without any further resolution.
func TestResolvePTR_InjectedLookupOnly(t *testing.T) {
	dns := &fakeDNS{table: map[string][]string{addrB.String(): {"b.example.com"}}}
	p := New(Options{Workers: 1, CacheSize: 4, LookupAddr: dns.lookup})
	got, ok := p.ResolvePTR(context.Background(), addrB)
	if !ok || got != "b.example.com" {
		t.Fatalf("ResolvePTR(%s): got (%q, %v), want (b.example.com, true) — the injected table is the only resolver", addrB, got, ok)
	}
	if n := dns.count(addrB.String()); n != 1 {
		t.Fatalf("injected lookups: got %d, want 1", n)
	}
	if _, ok := p.ResolvePTR(context.Background(), addrB); !ok {
		t.Fatal("cached answer must return ok")
	}
	if n := dns.count(addrB.String()); n != 1 {
		t.Errorf("cache hit must not re-lookup: got %d injected lookups", n)
	}
	if _, ok := p.ResolvePTR(context.Background(), addrC); ok {
		t.Errorf("an address outside the injected table must not resolve")
	}
	if st := p.Stats(); st.Misses != 2 || st.Hits != 1 {
		t.Errorf("Stats: got %+v, want misses=2 hits=1", st)
	}
}

func TestResolvePTR_LookupError(t *testing.T) {
	dns := &fakeDNS{err: context.DeadlineExceeded}
	p := New(Options{Workers: 1, LookupAddr: dns.lookup})
	if _, ok := p.ResolvePTR(context.Background(), addrB); ok {
		t.Error("a lookup error must not resolve")
	}
	if _, ok := p.ResolvePTR(context.Background(), addrB); ok {
		t.Error("a failed lookup must not be cached")
	}
	if n := dns.count(addrB.String()); n != 2 {
		t.Errorf("injected lookups: got %d, want 2 — errors are never cached", n)
	}
}

func TestResolvePTR_InvalidAddr(t *testing.T) {
	dns := &fakeDNS{}
	p := New(Options{Workers: 1, LookupAddr: dns.lookup})
	if _, ok := p.ResolvePTR(context.Background(), netip.Addr{}); ok {
		t.Error("an invalid address must not resolve")
	}
	if n := dns.total(); n != 0 {
		t.Errorf("an invalid address must not reach the injected lookup: got %d calls", n)
	}
}

func TestNew_ClampsAndDefaults(t *testing.T) {
	p := New(Options{})
	if p == nil {
		t.Fatal("nil pool")
	}
	if st := p.Stats(); st != (Stats{}) {
		t.Errorf("fresh pool: got %+v, want zero Stats", st)
	}
	// Unknown/empty strategy clamps to auto — no resolver call at all: the
	// SNI choice is pure data.
	p2 := New(Options{Workers: 0, CacheSize: -5, SNIStrategy: "wat"})
	sni, won := p2.SNIFromPTR("", netip.MustParseAddr("198.51.100.7"))
	if sni != "198.51.100.7" || won != StrategyIPOnly {
		t.Errorf("unknown strategy must clamp to auto: got (%q, %q), want (198.51.100.7, ip-only)", sni, won)
	}
}
