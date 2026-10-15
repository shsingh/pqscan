// Package microbench measures the engine's throughput claims so the M0
// report's SLO cells are measured facts (spec §7.1 latency model, §7.8
// SLOs; PQ-07).
package microbench

import (
	"net"
	"time"
)

// Decomposition breaks one handshake's wall time into the model's terms
// (spec §7.1): connect (1 RTT + kernel) and handshake (TLS flight; the
// server compute lives inside it).
type Decomposition struct {
	ConnectMs   float64
	HandshakeMs float64
	TotalMs     float64 // connect + handshake
}

// Results aggregates one measured run.
type Results struct {
	Targets        string
	Attempted      int
	Negotiated     int
	Decompositions []Decomposition
	ElapsedTotalS  float64
}

// MeasureHost — RED stub; lands with the PQ-07 GREEN commit.
func MeasureHost(addr, host string, n int, timeout time.Duration) (*Results, error) {
	var _ = net.Dial
	return nil, errMicrobenchStub
}

var errMicrobenchStub = stubError("microbench: not implemented (watched-RED stub)")

type stubError string

func (e stubError) Error() string { return string(e) }
