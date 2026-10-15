// Package quicx hosts the UDP handshake plane on quic-go: TLS 1.3 inside
// QUIC v1 (h3) with the same key-exchange group control as the TCP plane
// (spec §5.7, §7.5; PQ-06).
package quicx

import "errors"

// H3ALPN is the ALPN id the QUIC plane pins for its handshakes (RFC 9114
// h3 — the QUIC-plane truth's protocol token).
const H3ALPN = "h3"

// QuicResult carries one QUIC handshake observation (spec §5.7). Group
// semantics match the TCP plane; classes come from the shared taxonomy.
type QuicResult struct {
	Group       uint32 // negotiated key-exchange group (4588 = X25519MLKEM768)
	GroupClass  string // classify taxonomy class of the negotiated group
	Version     uint32 // QUIC transport version (1 = v1)
	ALPN        string // asserted "h3"
	UDPBlocked  bool   // server silent / policy-filtered (recorded as a result)
	State       string // negotiated | refused | blocked | error
	DialMs      float64
	HandshakeMs float64

	// Err is the raw dial/handshake failure text for the classified
	// (non-negotiated) states (PQ-25): the wiring's honest-refusal
	// classifier re-reads it to separate the client stack's own
	// construction refusals from transport outcomes — a local failure
	// is never recorded as a server verdict.
	Err string
}

// H3Negotiated reports whether the session negotiated h3 (PQ-25, spec
// §5.3: the direct QUIC handshake is the TRUTH, Alt-Svc the hint only).
// The lane wiring reads exactly this off the probe's result.
func (r *QuicResult) H3Negotiated() bool {
	return r.State == "negotiated" && r.ALPN == H3ALPN
}

// CostStats = per-connection cost of one QUIC session (feeds the 10k
// in-flight budget validation, spec §7.5).
type CostStats struct {
	Sessions    int
	HeapDeltaKB float64 // per-session heap delta, KB
	Goroutines  int     // per-session goroutine delta
	AvgTotalMs  float64
}

var errNotImplemented = errors.New("quicx engine: not implemented (watched-RED stub)")

// quicIntegrationEnv gates live-network probes (ADR-0002 evidence runs; never set in CI).
const quicIntegrationEnv = "PQSCAN_INTEGRATION"

// errNotImplementedShortRun guards MeasureCost's degenerate input.
var errNotImplementedShortRun = errors.New("quicx: sessions must be >= 1")
