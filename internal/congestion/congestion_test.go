package congestion

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- simulated clock -------------------------------------------------------
//
// The tests drive time entirely by hand: no test ever calls time.Sleep. The
// only wall-clock waits below are bounded safety nets on fence receives
// (select with a timeout); they never gate a correct run — their sole job is
// to turn a would-be deadlock into a clean failure.

// simClock is a Clock the test advances by hand. After registers a timer that
// fires (buffered) the moment Advance reaches its target, so a blocked
// Acquire can be released deterministically.
type simClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*simTimer
	waits  []time.Duration // every duration ever passed to After
	gated  chan struct{}   // one token per After registration: park fence
}

type simTimer struct {
	at    time.Time
	ch    chan time.Time
	fired bool
}

func newSimClock() *simClock {
	return &simClock{
		now:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		gated: make(chan struct{}, 1),
	}
}

func (c *simClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *simClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waits = append(c.waits, d)
	t := &simTimer{at: c.now.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		t.at = c.now
	}
	c.timers = append(c.timers, t)
	select {
	case c.gated <- struct{}{}:
	default:
	}
	return t.ch
}

// Advance moves the clock and fires every timer whose target is now reached.
func (c *simClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, t := range c.timers {
		if !t.fired && !t.at.After(c.now) {
			t.fired = true
			select {
			case t.ch <- c.now:
			default:
			}
		}
	}
}

// waitsSoFar copies every duration the limiter has passed to After so far.
func (c *simClock) waitsSoFar() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.waits)
}

// --- limiter ---------------------------------------------------------------

type limiterStep struct {
	advance time.Duration // advance the clock before the step
	want    bool          // TryAcquire expectation
}

var limiterCases = []struct {
	name  string
	rps   float64
	burst int
	steps []limiterStep
}{
	{
		name:  "burst grants, then elapsed time refills (rps 2, burst 2)",
		rps:   2,
		burst: 2,
		steps: []limiterStep{
			{want: true},
			{want: true},
			{want: false},
			{want: false},
			{advance: 250 * time.Millisecond, want: false}, // 0.5 token: fractional stays locked
			{advance: 250 * time.Millisecond, want: true},  // 0.5 + 0.5 = 1.0
			{want: false},
		},
	},
	{
		name:  "idle refill caps at the burst (rps 10, burst 2)",
		rps:   10,
		burst: 2,
		steps: []limiterStep{
			{want: true},
			{want: true},
			{advance: 3 * time.Second, want: true}, // 30 tokens accrued, capped at 2
			{want: true},
			{want: false},
		},
	},
	{
		name:  "fractional balance carries over (rps 1, burst 1)",
		rps:   1,
		burst: 1,
		steps: []limiterStep{
			{want: true},
			{advance: 400 * time.Millisecond, want: false}, // balance 0.4 held, not spent
			{advance: 600 * time.Millisecond, want: true},  // 0.4 + 0.6 = 1.0
			{want: false},
		},
	},
}

func TestLimiterTryAcquireRefill(t *testing.T) {
	for _, tc := range limiterCases {
		t.Run(tc.name, func(t *testing.T) {
			c := newSimClock()
			lim := NewLimiterWithClock(tc.rps, tc.burst, c)
			for i, st := range tc.steps {
				if st.advance > 0 {
					c.Advance(st.advance)
				}
				if got := lim.TryAcquire(); got != st.want {
					t.Fatalf("step %d (advance %v): TryAcquire = %v, want %v", i, st.advance, got, st.want)
				}
			}
		})
	}
}

// TestLimiterAcquireReturnsWhenTokenAvailable: a full bucket hands a token to
// Acquire without blocking.
func TestLimiterAcquireReturnsWhenTokenAvailable(t *testing.T) {
	lim := NewLimiter(1000, 1)
	if err := lim.Acquire(context.Background()); err != nil {
		t.Fatalf("Acquire = %v, want nil (bucket starts full)", err)
	}
}

// TestLimiterTryAcquireIsAtomic: exactly burst grants under contention.
func TestLimiterTryAcquireIsAtomic(t *testing.T) {
	lim := NewLimiter(1000, 20)
	const contenders = 100
	var granted atomic.Int64
	var wg sync.WaitGroup
	wg.Add(contenders)
	for range contenders {
		go func() {
			defer wg.Done()
			if lim.TryAcquire() {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()
	if g := granted.Load(); g != int64(20) {
		t.Errorf("concurrent TryAcquire granted %d, want exactly the burst of 20", g)
	}
}

// TestLimiterAcquireBlocksUntilToken: an exhausted limiter parks Acquire on
// the clock for exactly the refill instant; advancing the clock releases it.
func TestLimiterAcquireBlocksUntilToken(t *testing.T) {
	c := newSimClock()
	lim := NewLimiterWithClock(2, 2, c)
	for range 2 {
		lim.TryAcquire() // drain the burst; results asserted by the refill table
	}
	res := make(chan error, 1)
	go func() { res <- lim.Acquire(context.Background()) }()

	select {
	case <-c.gated:
		// parked on the clock: the only way a token can arrive
	case err := <-res:
		t.Fatalf("Acquire returned %v with no tokens available", err)
	case <-time.After(3 * time.Second):
		t.Fatal("Acquire neither parked on the clock nor returned")
	}
	if waits := c.waitsSoFar(); len(waits) != 1 || waits[0] != 500*time.Millisecond {
		t.Fatalf("Acquire waited %v, want [500ms]", waits)
	}
	c.Advance(500 * time.Millisecond)
	select {
	case err := <-res:
		if err != nil {
			t.Fatalf("Acquire = %v, want nil after refill", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Acquire did not return after the clock advanced")
	}
	if lim.TryAcquire() {
		t.Error("TryAcquire after the blocked Acquire returned = true, want false (the refilled token was consumed)")
	}
}

// TestLimiterAcquireRespectsContextCancel: a parked Acquire returns ctx.Err()
// when the context ends, without consuming a token the refill never earned.
func TestLimiterAcquireRespectsContextCancel(t *testing.T) {
	c := newSimClock()
	lim := NewLimiterWithClock(2, 2, c)
	for range 2 {
		lim.TryAcquire()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := make(chan error, 1)
	go func() { res <- lim.Acquire(ctx) }()

	select {
	case <-c.gated:
	case err := <-res:
		t.Fatalf("Acquire returned %v with no tokens available", err)
	case <-time.After(3 * time.Second):
		t.Fatal("Acquire neither parked on the clock nor returned")
	}
	cancel()
	select {
	case err := <-res:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Acquire = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Acquire did not return after the context was cancelled")
	}
}

// --- AIMD ------------------------------------------------------------------

type aimdStep struct {
	op   string // "success", "timeout", "throttle"
	want int    // expected Window() immediately after
}

var aimdCases = []struct {
	name  string
	max   int
	steps []aimdStep
}{
	{
		name: "additive increase caps at max",
		max:  3,
		steps: []aimdStep{
			{"success", 2},
			{"success", 3},
			{"success", 3},
			{"success", 3},
		},
	},
	{
		name: "multiplicative decrease floors at one",
		max:  4,
		steps: []aimdStep{
			{"timeout", 1},
			{"timeout", 1},
			{"success", 2},
		},
	},
	{
		name: "throttle signals behave like timeouts (odd halving)",
		max:  8,
		steps: []aimdStep{
			{"success", 2},
			{"success", 3},
			{"success", 4},
			{"success", 5},
			{"throttle", 2}, // floor(5 * 0.5)
			{"success", 3},
		},
	},
}

func TestAIMD(t *testing.T) {
	for _, tc := range aimdCases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAIMD(tc.max)
			for i, st := range tc.steps {
				switch st.op {
				case "success":
					a.OnSuccess()
				case "timeout":
					a.OnTimeout()
				case "throttle":
					a.OnThrottle()
				default:
					t.Fatalf("unknown op %q", st.op)
				}
				if got := a.Window(); got != st.want {
					t.Fatalf("step %d (%s): Window = %d, want %d", i, st.op, got, st.want)
				}
			}
		})
	}
}

// TestAIMDLadderTrace pins the exact window sequence: starting from one,
// 5 successes then 1 timeout then 2 successes walk the window through
// 1 → 2 → 3 → 4 → 5 → 6, halved to 3, back up to 4 → 5.
func TestAIMDLadderTrace(t *testing.T) {
	a := NewAIMD(10)
	var got []int
	for range 5 {
		a.OnSuccess()
		got = append(got, a.Window())
	}
	a.OnTimeout()
	got = append(got, a.Window())
	for range 2 {
		a.OnSuccess()
		got = append(got, a.Window())
	}
	want := []int{2, 3, 4, 5, 6, 3, 4, 5}
	if !slices.Equal(got, want) {
		t.Errorf("ladder trace: got %v, want %v", got, want)
	}
	if final := a.Window(); final != 5 {
		t.Errorf("Window after ladder = %d, want 5", final)
	}
}

// --- breaker ---------------------------------------------------------------

type breakerStep struct {
	advance time.Duration // advance the clock before the step
	do      string        // "allow" (host), "allow-other", "fail" (host), "ok" (host)
	want    bool          // expected Allow result, for allow steps
}

var breakerCases = []struct {
	name      string
	threshold int
	cooldown  time.Duration
	host      string // "" → "api.example"
	steps     []breakerStep
}{
	{
		name:      "closed opens at the threshold, half-opens after cooldown, closes on probe success",
		threshold: 2,
		cooldown:  30 * time.Second,
		steps: []breakerStep{
			{do: "allow", want: true},  // closed
			{do: "fail"},               // 1 consecutive failure
			{do: "allow", want: true},  // still closed below the threshold
			{do: "fail"},               // 2 consecutive: OPEN
			{do: "allow", want: false}, // open
			{do: "allow", want: false},
			{advance: 15 * time.Second, do: "allow", want: false}, // cooldown not elapsed
			{advance: 15 * time.Second, do: "allow", want: true},  // half-open: single probe allowance
			{do: "allow", want: false},                            // allowance consumed, outcome pending
			{advance: 5 * time.Second, do: "allow", want: false},  // time alone never re-opens
			{do: "ok"}, // probe succeeded: CLOSED, count reset
			{do: "allow", want: true},
		},
	},
	{
		name:      "probe failure re-opens for a fresh cooldown",
		threshold: 1,
		cooldown:  10 * time.Second,
		steps: []breakerStep{
			{do: "fail"}, // threshold reached: OPEN
			{do: "allow", want: false},
			{advance: 10 * time.Second, do: "allow", want: true}, // half-open probe
			{do: "allow", want: false},                           // single allowance
			{do: "fail"},                                         // probe failed: re-OPEN at now
			{do: "allow", want: false},
			{advance: 3 * time.Second, do: "allow", want: false}, // fresh cooldown ticking
			{advance: 7 * time.Second, do: "allow", want: true},  // probe again
			{do: "ok"}, // CLOSED
			{do: "allow", want: true},
		},
	},
	{
		name:      "success resets the consecutive-failure count",
		threshold: 3,
		cooldown:  10 * time.Second,
		steps: []breakerStep{
			{do: "fail"},
			{do: "fail"},
			{do: "allow", want: true}, // 2 < 3, still closed
			{do: "ok"},                // count reset
			{do: "fail"},
			{do: "fail"},
			{do: "allow", want: true}, // would have opened without the reset
		},
	},
	{
		name:      "hosts are isolated",
		threshold: 1,
		cooldown:  10 * time.Second,
		host:      "a.example",
		steps: []breakerStep{
			{do: "fail"}, // a: OPEN
			{do: "allow", want: false},
			{do: "allow-other", want: true},                      // b unaffected
			{advance: 10 * time.Second, do: "allow", want: true}, // a half-open probe
			{do: "allow-other", want: true},
		},
	},
}

func TestBreakerStateMachine(t *testing.T) {
	for _, tc := range breakerCases {
		t.Run(tc.name, func(t *testing.T) {
			host := tc.host
			if host == "" {
				host = "api.example"
			}
			other := host + "-other"
			c := newSimClock()
			b := NewBreakerWithClock(tc.threshold, tc.cooldown, c)
			for i, st := range tc.steps {
				if st.advance > 0 {
					c.Advance(st.advance)
				}
				switch st.do {
				case "allow":
					if got := b.Allow(host); got != st.want {
						t.Errorf("step %d (+%v): Allow(%q) = %v, want %v", i, st.advance, host, got, st.want)
					}
				case "allow-other":
					if got := b.Allow(other); got != st.want {
						t.Errorf("step %d (+%v): Allow(%q) = %v, want %v", i, st.advance, other, got, st.want)
					}
				case "fail":
					b.RecordFailure(host)
				case "ok":
					b.RecordSuccess(host)
				default:
					t.Fatalf("unknown step op %q", st.do)
				}
			}
		})
	}
}

// --- constructor guards ----------------------------------------------------

// TestConstructorsRejectInvalidBudgets pins the documented panics for
// impossible budgets.
func TestConstructorsRejectInvalidBudgets(t *testing.T) {
	cases := []struct {
		name string
		mk   func()
	}{
		{"limiter rejects zero rps", func() { NewLimiter(0, 1) }},
		{"limiter rejects negative rps", func() { NewLimiter(-1, 1) }},
		{"limiter rejects zero burst", func() { NewLimiter(100, 0) }},
		{"aimd rejects zero max", func() { NewAIMD(0) }},
		{"breaker rejects zero threshold", func() { NewBreaker(0, time.Second) }},
		{"breaker rejects negative cooldown", func() { NewBreaker(1, -time.Second) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: expected a panic for an invalid budget", tc.name)
				}
			}()
			tc.mk()
		})
	}
}
