// Package discovery hosts the h3-discovery plane (spec §5.1, §5.3, §9;
// PQ-25): the Alt-Svc hint collected by an HTTP/1.1-over-TLS GET on the
// target, and the direct QUIC v1 handshake that is the truth — "Alt-Svc
// used as a hint only", and a hint-vs-direct mismatch is a finding, not
// an error.
//
// The HTTP half deliberately lives here and NOT in tlsx: the alt-svc hint
// needs an HTTP request, and the TLS plane stays HTTP-free. The direct
// half reuses quicx's QUIC probe path (ALPN pinned to h3 there).
package discovery

import (
	"context"
	"errors"
	"time"
)

// Hints carries one h3-discovery observation (PQ-25).
//
// AltSvcH3 is the hint half: an alt-svc response header directive assigns
// the h3 protocol (RFC 7838). H3Direct is the truth half: a successful
// QUIC v1 handshake with h3 negotiated (spec §5.3 — direct probe is
// truth, Alt-Svc used as a hint only). AltSvcValue keeps the raw alt-svc
// value when the h3 token was found, for the classifier's mismatch
// findings; it stays empty when no h3 token was seen.
type Hints struct {
	AltSvcH3    bool   // HTTP hint: alt-svc carries an h3= directive
	H3Direct    bool   // QUIC truth: direct handshake negotiated h3
	AltSvcValue string // raw alt-svc header value, kept when an h3 token was found
}

// Options bounds the discovery probes. Zero (or negative) Timeout falls
// back to defaultTimeout.
type Options struct {
	Timeout time.Duration
}

var (
	errNotImplemented = errors.New("discovery engine: not implemented (watched-RED stub)")
	errHostRequired   = errors.New("discovery: host required")
)

// defaultTimeout bounds each half when Options.Timeout is unset.
const defaultTimeout = 5 * time.Second

// Discover runs the h3-discovery contract against host:port (PQ-25):
//
//   - hint half: TLS with ALPN http/1.1 (no proxy), a single HTTP/1.1
//     GET / on the target, and the response's alt-svc header parsed
//     loosely — any h3= directive token marks the hint and the raw value
//     is kept;
//   - direct half: the existing quicx QUIC v1 handshake (ALPN h3) — a
//     negotiated h3 session is the truth (H3Direct).
//
// Target refusals and silence are results, not errors: a TCP port that
// refuses or a server that never speaks TLS yields zero-valued hints with
// a nil error. Discover returns an error only for caller aborts (context
// cancellation / deadline) and contract misuse (empty host).
func Discover(ctx context.Context, host string, port uint16, opts Options) (*Hints, error) {
	_ = ctx
	_ = host
	_ = port
	_ = opts
	return nil, errNotImplemented
}

// parseAltSvc reads one alt-svc header value against the RFC 7838
// directive grammar loosely: comma-separated directives, each an
// optional-parameter list where an "ident=" assignment whose identifier
// is h3 (case-insensitive) marks the hint. The RAW value is carried out
// whenever the h3 token was found (classifier input); otherwise the
// second return is empty. "clear" (RFC 7838 §6.1) rescinds the cache and
// carries no hint.
func parseAltSvc(raw string) (bool, string) {
	_ = raw
	return false, ""
}
