package tlsx

import (
	"errors"
	"net"
)

// HelloObservation classifies one raw first-flight response (spec §5.4).
// Implemented in the PQ-05 engine commit; the watched-RED commit carries
// the failing tests against these stubs.
type HelloObservation struct {
	State          string
	Version        uint16
	RequestedGroup uint32
	AlertDesc      uint8
	FarVersion     uint16
}

const (
	StateHRR   = "hrr"
	StateSH    = "sh"
	StateAlert = "alert"
	StateRead  = "read-error"
)

var errNotImplemented = errors.New("tlsx engine: not implemented (watched-RED stub)")

// SendHelloProbe — stub; the engine follows in the PQ-05 commit.
func SendHelloProbe(addr, host string, groups []uint32, shareGroup uint32) (*HelloObservation, error) {
	var _ = net.DialTimeout
	return nil, errNotImplemented
}

// SendHelloProbeRaw — stub; the engine follows in the PQ-05 commit.
func SendHelloProbeRaw(conn net.Conn, host string, groups []uint32, shareGroup uint32) (*HelloObservation, error) {
	return nil, errNotImplemented
}
