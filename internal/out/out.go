// Package out hosts the encoders (jsonl/csv/text/urls) and the schema-1
// record shape (spec §5.7): the writers are hand-rolled per format (no
// reflection, no encoding/json on the encode hot path) and every encoder
// takes the caller's stream — results never touch a hardwired stdout.
package out

// SchemaVersion is the JSONL schema generation (spec §5.7). Field semantics
// lock per generation; changes to existing fields are breaking and bump it.
const SchemaVersion = 1

// Record is the schema-1 record carried per target (spec §5.7): the
// hand-rolled encoders write it without reflection. The JSONL line pins the
// shipped rc-1 field set byte-exact (the golden tests in tests/goldens);
// the full §5.7 shape (ts, http/cert/pq/offered blocks) lands with its own
// features — Ts rides the CSV line and the journal meanwhile.
type Record struct {
	Schema    int             `json:"schema"`
	Mode      string          `json:"mode"`
	Target    TargetRecord    `json:"target"`
	Handshake HandshakeRecord `json:"handshake"`
	Quic      *QuicRecord     `json:"quic,omitempty"`
	Error     string          `json:"error"`

	// Ts is the record's wall-clock stamp (RFC 3339 UTC, set by the scan
	// pipeline). JSON-ignored: the schema-1 JSONL line stays byte-pinned
	// while CSV and the WAL entry carry it explicitly.
	Ts string `json:"-"`
}

// TargetRecord identifies what was scanned and with which SNI strategy.
type TargetRecord struct {
	Input   string `json:"input"`
	Host    string `json:"host"`
	IP      string `json:"ip"`
	Port    uint16 `json:"port"`
	Ptr     string `json:"ptr"`
	SNIUsed string `json:"sni_used"`
}

// HandshakeRecord is the negotiated TCP/TLS handshake block.
type HandshakeRecord struct {
	Negotiated uint32 `json:"negotiated"`
	GroupName  string `json:"group_name,omitempty"`
	GroupClass string `json:"group_class,omitempty"`
	Suite      string `json:"suite,omitempty"`
	Version    string `json:"version,omitempty"`
	ALPNNeg    string `json:"alpn_neg,omitempty"`
}

// QuicRecord is the QUIC plane block; nil when the probe never ran.
type QuicRecord struct {
	Attempted  bool   `json:"attempted"`
	State      string `json:"state,omitempty"`
	Negotiated uint32 `json:"negotiated,omitempty"`
	GroupName  string `json:"group_name,omitempty"`
	GroupClass string `json:"group_class,omitempty"`
	UDPBlocked bool   `json:"udp_blocked,omitempty"`
}
