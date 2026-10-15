// Package quicx hosts the UDP handshake plane on quic-go (spec §5.7, §7.5).
//
// Substrate stub (PQ-04). The QUIC v1 capability probe, negotiated-group
// readback and udp_blocked classification land with PQ-06.
package quicx

// QuicResult carries one QUIC handshake observation. Group semantics match
// the TCP plane (classify taxonomy).
type QuicResult struct {
	Group       uint32
	GroupClassI string // classify.Class name for the negotiated group
	Version     uint32 // QUIC version (0x00000001 = v1)
	ALPN        string // asserted "h3"
	UDPBlocked  bool   // outbound UDP/443 appears policy-blocked
}
