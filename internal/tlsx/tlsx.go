// Package tlsx hosts the TCP handshake plane: crypto/tls as the negotiation
// core, uTLS as the hello-construction escape hatch (spec §5.4).
//
// Substrate stub (PQ-04): shared result types only. The capability-matrix
// probes (forced groups, suites, HRR observation, CurveID readback) land
// with PQ-05.
package tlsx

// HandshakeResult carries everything observed in one handshake. Field names
// mirror the JSONL schema (spec §5.7, schema: 1).
type HandshakeResult struct {
	Group     uint32   // negotiated key-exchange group (4588 = X25519MLKEM768)
	GroupID   string   // IANA name of the negotiated group
	Suite     string   // negotiated cipher suite name
	Version   uint16   // TLS version negotiated (0x0303 / 0x0304)
	SigScheme string   // negotiated signature scheme
	ALPN      []string // ALPN protocols offered/received
}
