// Package congestion provides the pure control surfaces the pqscan engine
// consumes for its probe budgets (PQ-23, docs/spec.md §7.3): a token-bucket
// rate limiter, an AIMD concurrency window, and a per-host circuit breaker.
//
// The package performs no I/O and never reads the wall clock directly — all
// time flows through an injectable Clock, so every control loop is testable
// on a simulated clock with no time.Sleep anywhere. Nothing here logs or
// emits; the engine wires diag and reporting around these primitives.
//
// This file is the watched-RED stub (ADR-0002): the types and API surface are
// final so the tests compile, but every body is not implemented yet and the
// tests fail on their assertions, not on compile errors.
package congestion

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrNotImplemented marks the watched-RED stub state; the GREEN commit
// removes it.
var ErrNotImplemented = errors.New("congestion: not implemented")

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
func NewLimiter(rps float64, burst int) *Limiter { return &Limiter{} }

// NewLimiterWithClock is NewLimiter with an injectable clock for tests.
func NewLimiterWithClock(rps float64, burst int, c Clock) *Limiter { return &Limiter{} }

// TryAcquire takes one token if one is available and reports whether it
// succeeded; it never blocks.
func (l *Limiter) TryAcquire() bool { return false }

// Acquire takes one token, blocking until a token is available or ctx is
// done. It is nil on success, or ctx.Err() when the context finished first;
// no token is consumed in the error case.
func (l *Limiter) Acquire(ctx context.Context) error { return ErrNotImplemented }

// AIMD is an additive-increase / multiplicative-decrease window over a
// concurrency budget: the engine's in-flight count W follows Window(). The
// window starts at one; each success raises it by the additive step (up to
// max) and each timeout or throttle signal multiplies it by 0.5, floored at
// one.
type AIMD struct {
	mu     sync.Mutex
	max    int
	window int
}

// NewAIMD creates an AIMD window over the given maximum; max must be >= 1.
func NewAIMD(max int) *AIMD { return &AIMD{} }

// OnSuccess records one successful completion: additive increase.
func (a *AIMD) OnSuccess() {}

// OnTimeout records a timed-out request: multiplicative decrease.
func (a *AIMD) OnTimeout() {}

// OnThrottle records a throttle signal (back-pressure): it is handled exactly
// like a timeout.
func (a *AIMD) OnThrottle() {}

// Window returns the current window: the number of requests the engine may
// keep in flight.
func (a *AIMD) Window() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.window
}

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
	return &Breaker{hosts: map[string]*hostState{}}
}

// NewBreakerWithClock is NewBreaker with an injectable clock for tests.
func NewBreakerWithClock(failThreshold int, cooldown time.Duration, c Clock) *Breaker {
	return &Breaker{hosts: map[string]*hostState{}}
}

// Allow reports whether a request to host may be sent, advancing the
// closed → open → half-open machine as of the clock's current time.
func (b *Breaker) Allow(host string) bool { return false }

// RecordSuccess records a successful request to host: the host closes and
// its consecutive-failure count resets.
func (b *Breaker) RecordSuccess(host string) {}

// RecordFailure records a failed request to host: while closed, one more
// consecutive failure; reaching the threshold — or failing the half-open
// probe — opens the host for a fresh cooldown.
func (b *Breaker) RecordFailure(host string) {}
