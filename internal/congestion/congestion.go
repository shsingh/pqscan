// Package congestion provides the pure control surfaces the pqscan engine
// consumes for its probe budgets (PQ-23, docs/spec.md §7.3): a token-bucket
// rate limiter, an AIMD concurrency window, and a per-host circuit breaker.
//
// The package performs no I/O and never reads the wall clock directly — all
// time flows through an injectable Clock, so every control loop is testable
// on a simulated clock with no time.Sleep anywhere. Nothing here logs or
// emits; the engine wires diag and reporting around these primitives.
package congestion

import (
	"context"
	"sync"
	"time"
)

// Clock is the only notion of time the package consumes. Production code uses
// the implicit system clock; tests inject implementations they can advance.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// After returns a channel that receives a time.Time once Now has
	// advanced by at least d, relative to the Now at call time.
	After(d time.Duration) <-chan time.Time
}

// systemClock is the production Clock.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) After(d time.Duration) <-chan time.Time {
	return time.NewTimer(d).C
}

// --- AIMD ------------------------------------------------------------------

const (
	// aimdAddStep is the additive-increase increment applied per success.
	aimdAddStep = 1
	// aimdMulDown is the multiplicative-decrease factor applied per timeout
	// or throttle signal (the classic ×0.5 backoff).
	aimdMulDown = 0.5
	// aimdMinWindow is the floor the AIMD window never drops below.
	aimdMinWindow = 1
)

// AIMD is an additive-increase / multiplicative-decrease window over a
// concurrency budget: the engine's in-flight count W follows Window(). The
// window starts at one; each success raises it by aimdAddStep (up to max) and
// each timeout or throttle signal multiplies it by aimdMulDown (floored at
// aimdMinWindow).
type AIMD struct {
	mu     sync.Mutex
	max    int
	window int
}

// NewAIMD creates an AIMD window over the given maximum; max must be >= 1.
func NewAIMD(max int) *AIMD {
	if max < aimdMinWindow {
		panic("congestion: aimd max must be >= 1")
	}
	return &AIMD{max: max, window: aimdMinWindow}
}

// OnSuccess records one successful completion: additive increase.
func (a *AIMD) OnSuccess() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if w := a.window + aimdAddStep; w < a.max {
		a.window = w
	} else {
		a.window = a.max
	}
}

// OnTimeout records a timed-out request: multiplicative decrease.
func (a *AIMD) OnTimeout() { a.decrease() }

// OnThrottle records a throttle signal (back-pressure): it is handled exactly
// like a timeout.
func (a *AIMD) OnThrottle() { a.decrease() }

// Window returns the current window: the number of requests the engine may
// keep in flight.
func (a *AIMD) Window() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.window
}

// decrease multiplies the window by aimdMulDown, floored at aimdMinWindow.
func (a *AIMD) decrease() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if w := int(float64(a.window) * aimdMulDown); w > aimdMinWindow {
		a.window = w
	} else {
		a.window = aimdMinWindow
	}
}

// --- limiter ---------------------------------------------------------------

// Limiter is a token-bucket rate limiter: tokens refill continuously at rps
// per second, the bucket holds at most burst tokens, and it starts full.
type Limiter struct {
	mu     sync.Mutex
	rps    float64
	burst  float64
	tokens float64
	last   time.Time // simulation point the tokens were last refilled to
	clock  Clock
}

// NewLimiter returns a limiter with a full bucket. rps must be > 0 and burst
// must be >= 1.
func NewLimiter(rps float64, burst int) *Limiter {
	return NewLimiterWithClock(rps, burst, systemClock{})
}

// NewLimiterWithClock is NewLimiter with an injectable clock for tests.
func NewLimiterWithClock(rps float64, burst int, c Clock) *Limiter {
	if rps <= 0 {
		panic("congestion: limiter rps must be > 0")
	}
	if burst < 1 {
		panic("congestion: limiter burst must be >= 1")
	}
	return &Limiter{
		rps:    rps,
		burst:  float64(burst),
		tokens: float64(burst),
		last:   c.Now(),
		clock:  c,
	}
}

// TryAcquire takes one token if one is available and reports whether it
// succeeded; it never blocks.
func (l *Limiter) TryAcquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.grantLocked()
}

// Acquire takes one token, blocking until a token is available or ctx is
// done. It is nil on success, or ctx.Err() when the context finished first;
// no token is consumed in the error case.
func (l *Limiter) Acquire(ctx context.Context) error {
	for {
		l.mu.Lock()
		if l.grantLocked() {
			l.mu.Unlock()
			return nil
		}
		ch := l.clock.After(l.delayLocked())
		l.mu.Unlock()
		select {
		case <-ch: // a refill instant has passed; retry from the top
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// grantLocked refills and consumes one token; the caller holds mu.
func (l *Limiter) grantLocked() bool {
	l.refillLocked()
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// refillLocked accrues tokens for the elapsed time, capped at the burst; the
// caller holds mu.
func (l *Limiter) refillLocked() {
	now := l.clock.Now()
	if !now.After(l.last) {
		return
	}
	l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rps)
	l.last = now
}

// delayLocked is the wait until the next token; the caller holds mu and the
// bucket is empty.
func (l *Limiter) delayLocked() time.Duration {
	wait := time.Duration((1 - l.tokens) / l.rps * float64(time.Second))
	if wait < time.Millisecond {
		// Rounding must never busy-spin the acquire loop.
		wait = time.Millisecond
	}
	return wait
}

// --- breaker ---------------------------------------------------------------

// Breaker is a per-host circuit breaker: after failThreshold consecutive
// failures a host OPENS — Allow returns false — for cooldown; after the
// cooldown it HALF-OPENS with a single probe allowance, whose success closes
// the host again and whose failure re-opens it for a fresh cooldown.
type Breaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	clock     Clock
	hosts     map[string]*hostState
}

// hostState is one host's position in the closed → open → half-open machine.
type hostState struct {
	fails    int       // consecutive failures while closed
	open     bool      // OPEN: Allow is false until the cooldown elapses
	openedAt time.Time // when the host opened
	probed   bool      // the half-open allowance is consumed, outcome pending
}

// NewBreaker returns a breaker over the given consecutive-failure threshold
// and open-state cooldown; threshold must be >= 1 and cooldown >= 0.
func NewBreaker(failThreshold int, cooldown time.Duration) *Breaker {
	return NewBreakerWithClock(failThreshold, cooldown, systemClock{})
}

// NewBreakerWithClock is NewBreaker with an injectable clock for tests.
func NewBreakerWithClock(failThreshold int, cooldown time.Duration, c Clock) *Breaker {
	if failThreshold < 1 {
		panic("congestion: breaker threshold must be >= 1")
	}
	if cooldown < 0 {
		panic("congestion: breaker cooldown must be >= 0")
	}
	return &Breaker{
		threshold: failThreshold,
		cooldown:  cooldown,
		clock:     c,
		hosts:     map[string]*hostState{},
	}
}

// Allow reports whether a request to host may be sent, advancing the
// closed → open → half-open machine as of the clock's current time.
func (b *Breaker) Allow(host string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.hostLocked(host)
	if !s.open {
		return true // CLOSED
	}
	if b.clock.Now().Sub(s.openedAt) < b.cooldown {
		return false // OPEN, cooling down
	}
	if s.probed {
		return false // HALF-OPEN: the single allowance is already out
	}
	s.probed = true // HALF-OPEN: grant exactly one probe
	return true
}

// RecordSuccess records a successful request to host: the host closes and its
// consecutive-failure count resets. Healthy hosts drop out of the map.
func (b *Breaker) RecordSuccess(host string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.hosts, host)
}

// RecordFailure records a failed request to host: while closed, one more
// consecutive failure; reaching the threshold — or failing the half-open
// probe — opens the host for a fresh cooldown.
func (b *Breaker) RecordFailure(host string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.hostLocked(host)
	s.fails++
	if s.probed || (!s.open && s.fails >= b.threshold) {
		s.open = true
		s.openedAt = b.clock.Now()
		s.probed = false
	}
}

// hostLocked returns (creating) the state row for host; the caller holds mu.
func (b *Breaker) hostLocked(host string) *hostState {
	s, ok := b.hosts[host]
	if !ok {
		s = &hostState{}
		b.hosts[host] = s
	}
	return s
}
