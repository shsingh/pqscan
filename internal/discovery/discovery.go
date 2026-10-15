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
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/quicx"
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

var errHostRequired = errors.New("discovery: host required")

// defaultTimeout bounds each half when Options.Timeout is unset.
const defaultTimeout = 5 * time.Second

// alpnHTTP11 is the ALPN id of HTTP/1.1 (RFC 7301 registry).
const alpnHTTP11 = "http/1.1"

// altSvcH3ID is the alt-svc protocol id asserted by RFC 9114 h3. Draft
// variants (h3-29 and friends) negotiate draft QUIC, not h3, so they are
// other protocols here: exactly the h3 token marks the hint.
const altSvcH3ID = "h3"

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
// refuses, a server that never speaks TLS, or one that negotiates a
// non-HTTP/1.1 protocol yields zero-valued hints with a nil error.
// Discover returns an error only for caller aborts (context
// cancellation / deadline) and contract misuse (empty host).
func Discover(ctx context.Context, host string, port uint16, opts Options) (*Hints, error) {
	if host == "" {
		return nil, errHostRequired
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	hints := &Hints{}

	// Hint half first, then the direct half (sequential keeps the probe
	// budget deterministic: worst case is one opts.Timeout per half).
	hint, kept, err := probeAltSvc(ctx, host, port, opts.Timeout)
	if err != nil {
		return nil, err // caller abort, not a target result
	}
	hints.AltSvcH3, hints.AltSvcValue = hint, kept

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if qr, qerr := quicx.ProbeQUIC(target, host, nil, opts.Timeout); qerr == nil {
		// The QUIC v1 handshake is the truth (spec §5.3). A quicx probe
		// error is only a transport-level defect — refusals and silence
		// reach here as classified results, never errors — so the truth
		// falls back to unknown (= false) and the defect is recorded.
		hints.H3Direct = qr.State == "negotiated" && qr.ALPN == altSvcH3ID
	} else {
		diag.Emit(diag.Warn, diag.DomQuic, "h3-discovery", target, "QUIC probe errored", qerr, nil)
	}

	diag.Emit(diag.Info, diag.DomQuic, "h3-discovery", target, "h3 discovery recorded", nil, map[string]string{
		"alt_svc_h3": strconv.FormatBool(hints.AltSvcH3),
		"h3_direct":  strconv.FormatBool(hints.H3Direct),
		"alt_svc":    hints.AltSvcValue,
	})
	return hints, nil
}

// probeAltSvc runs the hint half: one HTTP/1.1 GET / over TLS with ALPN
// http/1.1 (no proxy), reading the response's alt-svc headers. It returns
// (h3, raw alt-svc value, err); err is non-nil only for caller aborts —
// every transport-level answer (refused, TLS alert, non-HTTP/1.1 choice,
// malformed response) is a result carrying an empty hint.
func probeAltSvc(ctx context.Context, host string, port uint16, timeout time.Duration) (bool, string, error) {
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, "", ctxErr
		}
		return false, "", nil // refusal / unreachable: a result, not an error
	}
	defer func() { _ = conn.Close() }()

	tlsCfg := &tls.Config{
		ServerName:         host,
		NextProtos:         []string{alpnHTTP11},
		InsecureSkipVerify: true, // the hint is the assertion; cert analytics is a separate probe
	}
	tc := tls.Client(conn, tlsCfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, "", ctxErr
		}
		return false, "", nil // TLS rejection: a result, not an error
	}
	if alpn := tc.ConnectionState().NegotiatedProtocol; alpn != alpnHTTP11 {
		diag.Emit(diag.Info, diag.DomQuic, "h3-discovery", target, "no http/1.1 ALPN; alt-svc unreadable", nil,
			map[string]string{"alpn": alpn})
		return false, "", nil
	}
	_ = conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	// One handcrafted HTTP/1.1 request (no proxy, no pipeline). A refused
	// write after a completed handshake is a result, not an error.
	_, _ = tc.Write([]byte("GET / HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: pqscan\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"))

	resp, err := http.ReadResponse(bufio.NewReader(tc), &http.Request{Method: http.MethodGet})
	if err != nil {
		return false, "", nil // mid-response close: a result, not an error
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	h3, kept := parseAltSvc(strings.Join(resp.Header.Values("Alt-Svc"), ", "))
	return h3, kept, nil
}

// parseAltSvc reads one alt-svc header value against the RFC 7838
// directive grammar loosely: comma-separated directives, each an
// optional-parameter list where an "ident=" assignment whose identifier
// is h3 (case-insensitive) marks the hint. The RAW value is carried out
// whenever the h3 token was found (classifier input); otherwise the
// second return is empty. "clear" (RFC 7838 §6.1) rescinds the cache and
// carries no hint.
func parseAltSvc(raw string) (bool, string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false, ""
	}
	if strings.EqualFold(trimmed, "clear") {
		return false, ""
	}
	for _, dir := range strings.Split(raw, ",") {
		token, _, found := strings.Cut(strings.TrimSpace(dir), "=")
		if !found {
			continue // no "=" — not an alt-svc assignment
		}
		if strings.EqualFold(strings.TrimSpace(token), altSvcH3ID) {
			return true, raw // hint found: the raw value is kept for the classifier
		}
	}
	return false, ""
}
