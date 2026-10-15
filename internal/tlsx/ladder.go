package tlsx

import (
	"time"
)

// ProbeResult is one row of the capability matrix (spec §5.4, §5.7).
type ProbeResult struct {
	Offered        uint32 `json:"offered_group"`
	Shared         bool   `json:"shared"`
	Path           string `json:"path"`
	State          string `json:"state"`
	Negotiated     uint32 `json:"negotiated_group"`
	RequestedGroup uint32 `json:"requested_group"`
	Suite          string `json:"suite"`
	Version        uint16 `json:"version"`
	AlertDesc      uint8  `json:"alert"`
	Error          string `json:"error"`
}

// ProbeNegotiated — stub; the engine follows in the PQ-05 commit.
func ProbeNegotiated(addr, host string, groups []uint32, timeout time.Duration) (*ProbeResult, error) {
	var _ = addr
	var _ = host
	return nil, errNotImplemented
}

// GroupLadder — stub; the engine follows in the PQ-05 commit.
func GroupLadder(addr, host string, groups []uint32, timeout time.Duration) []ProbeResult {
	var _ = timeout
	var _ = addr
	var _ = host
	return make([]ProbeResult, 0, len(groups))
}
