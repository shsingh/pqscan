package quicx

import (
	"time"
)

// probe_h3exchange.go — the functional HTTP/3 verification surface
// (PQ-69, issue #181): VerifyH3Exchange dials QUIC v1 (ALPN h3), waits
// for the server's SETTINGS frame on the control stream, then completes
// ONE HTTP/3 GET / through the pinned quic-go v0.63 http3 stack. The
// finding separates "ALPN h3 negotiated" from "an HTTP/3 exchange
// completed": a server that answers the handshake but carries no
// functional h3 layer records its own finding class at the executor.

// H3ExchangeResult carries one functional HTTP/3 exchange observation
// (PQ-69). The state vocabulary matches QuicResult's (the one dial-class
// word list): negotiated | refused | blocked | error for the QUIC
// dial/handshake phase.
type H3ExchangeResult struct {
	State      string // negotiated | refused | blocked | error
	ALPN       string // the negotiated ALPN ("h3" expected)
	UDPBlocked bool   // server silent / policy-filtered (recorded as a result)

	// Settings reports the server's HTTP/3 SETTINGS frame (the control
	// stream's mandatory first frame, RFC 9114 §4.2). Status carries
	// the ONE HTTP/3 GET /'s response status (0 = no completed
	// exchange). ExchangeErr is the h3 layer's failure text: the
	// server's own answers verbatim, the probe's class words for a
	// silent layer.
	Settings    bool
	Status      int
	ExchangeErr string

	DialMs     float64
	ExchangeMs float64

	// Err is the raw dial/handshake failure text for the classified
	// (non-negotiated) states — the wiring's honest-refusal classifier
	// re-reads it (the same contract as QuicResult.Err).
	Err string
}

// The h3 layer's probe-shaped class words (the probe states them; the
// remote's answers ride ExchangeErr verbatim).
const (
	h3NoSettings  = "the server sent no HTTP/3 SETTINGS frame"
	h3ALPNNeverH3 = "the negotiated ALPN is not h3"
)

// VerifyH3Exchange runs the functional HTTP/3 probe (PQ-69, issue
// #181).
//
// Watched-RED stub (PQ-69, the second pair): the real exchange through
// the pinned quic-go http3 stack lands with the GREEN half; the tests
// COMPILE against this stub and fail on their assertions (ADR-0002).
func VerifyH3Exchange(addr, host string, timeout time.Duration) (*H3ExchangeResult, error) {
	return nil, errNotImplemented
}
