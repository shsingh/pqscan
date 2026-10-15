// Package out hosts the encoders (jsonl/csv/text/urls) and the schema-1
// record shape (spec §5.7): the writers are hand-rolled per format (no
// reflection, no encoding/json on the encode hot path) and every encoder
// takes the caller's stream — results never touch a hardwired stdout.
package out

// SchemaVersion is the JSONL schema generation (spec §5.7). Field semantics
// lock per generation; changes to existing fields are breaking and bump it.
const SchemaVersion = 1

// Record is the schema-1 record carried per target (spec §5.7): the
// hand-rolled encoders write it without reflection. The JSONL line pins
// the shipped field set byte-exact (the golden tests in tests/goldens):
// schema, mode, target, handshake, quic, cert, pq, error — with the
// optional blocks zero/absent per the omitempty corners; Ts rides the
// CSV line and the journal meanwhile.
type Record struct {
	Schema    int             `json:"schema"`
	Mode      string          `json:"mode"`
	Target    TargetRecord    `json:"target"`
	Handshake HandshakeRecord `json:"handshake"`
	// Quic is the QUIC plane block; nil when the probe never ran.
	//
	// Cert (PQ-21) and Pq (PQ-19) are the certificate-analytics and
	// readiness-verdict blocks, spec §5.7's record layout: handshake,
	// quic, cert, pq, error — cert leads pq (the analyzed facts, then
	// the verdict computed on them). Both nil on a record whose probe
	// failed before their step: the Error field is that record's
	// verdict path.
	//
	// Deep (PQ-20) is the deep-mode executor block (-mode deep only):
	// the executed plan's counts + findings. Nil on fast/pq records and
	// on deep records whose profile handshake failed (phase 1 gates
	// phase 2); the CSV projection carries no deep columns — the
	// findings vector lives in the JSONL line alone.
	Quic  *QuicRecord `json:"quic,omitempty"`
	Cert  *CertRecord `json:"cert,omitempty"`
	Pq    *PqRecord   `json:"pq,omitempty"`
	Deep  *DeepRecord `json:"deep,omitempty"`
	Error string      `json:"error"`

	// Ts is the record's wall-clock stamp (RFC 3339 UTC, set by the scan
	// pipeline). JSON-ignored: the schema-1 JSONL line stays byte-pinned
	// while CSV and the WAL entry carry it explicitly.
	Ts string `json:"-"`
}

// CertRecord is the PQ-21 leaf-certificate analytics block: the leaf's
// signature and key algorithms (names per certinfo's owned OID table,
// "unknown-…" notes carried verbatim), their PQ flags, and the delivered
// chain's dual-cert signal. Nil when no certificate was analyzed (failed
// probe, raw path, unanalyzable chain — the tlsx zero policy: no invented
// rows). A present block encodes every inner field unconditionally, also
// the false flags and the classical names: presence = the leaf was
// analyzed, so the booleans are facts, not omissions.
type CertRecord struct {
	SigAlg string `json:"sig_alg"`
	SigPQ  bool   `json:"sig_pq"`
	KeyAlg string `json:"key_alg"`
	KeyPQ  bool   `json:"key_pq"`
	Dual   bool   `json:"dual"`
}

// PqRecord is the PQ-19 readiness-verdict block: the rubric's Score
// output over the ladder-derived observations — the 0-100 clamped score,
// the verdict label, the HNDL flag (obsolete-draft groups in use =
// harvest-now-decrypt-later exposure), and the fired rules as the
// printable summary. Nil only for records whose probe failed before a
// verdict: the rubric's scan-error behavior surfaces there as the
// record's error path (score 0 stays the zero value; a failed probe
// never presents an invented verdict block). A verdict block that DID
// run encodes scan-error too — score 0, label scan-error, the fired
// rows' summary.
type PqRecord struct {
	Score   int    `json:"score"`
	Label   string `json:"label"`
	HNDL    bool   `json:"hndl"`
	Summary string `json:"summary"`
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

// H3Discovery is the h3-discovery block (PQ-25, spec §5.3): the QUIC
// lane's two halves as observed — AltSvcH3 the hint (an alt-svc h3=
// directive on the fast pass's HTTP probe), H3Direct the direct QUIC
// truth. Presence is the fact: the block appears wherever the lane
// evaluated the hint (the probe-run, mismatch and skipped-no-hint
// states); it stays nil on -quic-off records, where the discovery never
// ran. JSONL-only fields — the CSV/text projections carry no new
// columns.
type H3Discovery struct {
	AltSvcH3 bool `json:"alt_svc_h3"`
	H3Direct bool `json:"h3_direct"`
}

// QuicRecord is the QUIC plane block; nil when the probe never ran.
//
// PQ-25 (spec §5.3) lands the discovery facts ADDITIVELY: Discovered
// carries the hint/truth halves, Mismatch marks the hint-vs-truth
// disagreement (its finding state token rides State:
// "mismatch: hint=yes truth=no" / reverse — a finding, not an error:
// the run's exit code never moves on it); State may also carry the
// honest information token "skipped: no alt-svc h3 hint" when the hint
// gate itself decided the lane. CSV/text unchanged.
type QuicRecord struct {
	Attempted  bool   `json:"attempted"`
	State      string `json:"state,omitempty"`
	Negotiated uint32 `json:"negotiated,omitempty"`
	GroupName  string `json:"group_name,omitempty"`
	GroupClass string `json:"group_class,omitempty"`
	UDPBlocked bool   `json:"udp_blocked,omitempty"`
	// Discovered is the hint/truth discovery block (nil = the lane
	// never evaluated the hint, e.g. -quic-off).
	Discovered *H3Discovery `json:"discovered,omitempty"`
	// Mismatch marks the hint/truth disagreement class (true only on
	// the mismatch states; an omitempty field — absent = consistent).
	Mismatch bool `json:"mismatch,omitempty"`
}

// DeepFinding is one executed deep-mode probe's verdict (spec §7.4, PQ-20):
// the plan's probe id, the observation's verdict class, and the observed
// detail verbatim. Result vocabulary (the report contract, spec §8 --mode):
// accepted | rejected | refused | error — a rejection is the SERVER's
// decision on the offer (it saw a well-formed offer and refused, alert
// class); refused covers both a dial-class refusal and a probe the
// scanning engine itself cannot offer (the not-offerable class: the detail
// says which, honestly); error is any other probe-path failure.
type DeepFinding struct {
	Probe  string `json:"probe"`
	Result string `json:"result"`
	Detail string `json:"detail"`
}

// DeepRecord is the deep-mode executor block (PQ-20): the executed plan's
// summary and the per-probe findings, one per attempted probe (the plan
// order). Mode is the executed -deep plan (standard | full). Attempted,
// OK and Rejected count the executed probes (Attempted = the executed
// count; OK the accepted; Rejected the server-rejected — refusals and
// errors ride Findings only). Nil for every record that did not execute a
// deep plan (-mode fast/pq, and the deep runs that short-circuited on a
// failed profile handshake — spec §7.4 phase 1 gates phase 2).
type DeepRecord struct {
	Mode      string        `json:"mode"`
	Attempted int           `json:"attempted"`
	OK        int           `json:"ok"`
	Rejected  int           `json:"rejected"`
	Findings  []DeepFinding `json:"findings"`
}
