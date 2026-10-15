package quicx

import "time"

// ProbeQUIC — RED stub; engine lands in the PQ-06 GREEN commit.
func ProbeQUIC(addr, host string, groups []uint32, timeout time.Duration) (*QuicResult, error) {
	return nil, errNotImplemented
}

// MeasureCost — RED stub; engine lands in the PQ-06 GREEN commit.
func MeasureCost(addr, host string, sessions int, timeout time.Duration) (*CostStats, error) {
	return nil, errNotImplemented
}
