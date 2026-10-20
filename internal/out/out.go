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
// schema, mode, target, handshake, quic, cert, pq, error — every record
// CLASS (success and error alike) carries the schema-required blocks
// (PQ-60's uniform contract: on error records the blocks ride
// zero-populated, the never-ran halves); Ts rides the CSV line and the
// journal meanwhile.
type Record struct {
	Schema    int             `json:"schema"`
	Mode      string          `json:"mode"`
	Target    TargetRecord    `json:"target"`
	Handshake HandshakeRecord `json:"handshake"`
	// Quic is the QUIC plane block. The engine populates it on every
	// record (the zero halves where the plane never ran — PQ-60's
	// uniform contract; the -quic-off plane since PQ-54), so a nil
	// block exists only in hand-built or legacy-journal records.
	//
	// Cert (PQ-21) and Pq (PQ-19) are the certificate-analytics and
	// readiness-verdict blocks, spec §5.7's record layout: handshake,
	// quic, cert, pq, error — cert leads pq (the analyzed facts, then
	// the verdict computed on them). The engine likewise never leaves
	// them nil: a probe that never reached their step rides the
	// zero-populated blocks (empty names, score 0, empty label — no
	// invented verdict) and the Error field is that record's failure
	// path (PQ-60: the uniform contract, issue #157).
	//
	//	Deep (PQ-20) is the deep-mode executor block (-mode deep):
	//	the executed plan's counts + findings. Nil on fast records
	//	and on deep records whose profile handshake failed (phase 1
	//	gates phase 2); the CSV projection carries no deep columns —
	//	the findings vector lives in the JSONL line alone.
	//	PQ-47 (issue #129): the SAME block carries the -mode pq
	//	ladder — the forced PQ lane's per-probe observations with
	//	Mode "pq" mirroring the deep executor's shape; the -text
	//	counts tail (deep=pq:<N>p/<N>ok/<N>rej) rides it unchanged.
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
// chain's dual-cert signal. Nil outside the engine's record path only
// (hand-built and legacy-journal records): on error records the block
// rides ZERO-POPULATED (PQ-60's uniform contract — empty names, false
// flags: nothing was analyzed, nothing is claimed), and a present block
// encodes every inner field unconditionally, also the false flags and
// the classical names: presence = the leaf was analyzed, so the
// booleans are facts, not omissions.
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
// printable summary. Outside the engine's record path (hand-built and
// legacy-journal records) the block may be nil; on error records the
// ENGINE populates the ZERO half (PQ-60's uniform contract — score 0,
// empty label, no invented verdict: the rubric never ran, and a failed
// probe never reaches it; the rubric's scan-error behavior surfaces as
// the record's error path). A verdict block that DID run encodes
// scan-error too — score 0, label scan-error, the fired rows' summary.
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

// HandshakeRecord is the negotiated TCP/TLS handshake block. The
// schema-required strings carry NO omitempty (PQ-54: the writer emits the
// required keys unconditionally — an unknown value is the empty string,
// never a missing key), so encoding/json and the hand-rolled writer agree.
type HandshakeRecord struct {
	Negotiated uint32 `json:"negotiated"`
	GroupName  string `json:"group_name"`
	GroupClass string `json:"group_class"`
	Suite      string `json:"suite"`
	Version    string `json:"version"`
	ALPNNeg    string `json:"alpn_neg"`
}

// H3Discovery is the h3-discovery block (PQ-25, spec §5.3): the QUIC
// lane's two halves as observed — AltSvcH3 the hint (an alt-svc h3=
// directive on the fast pass's HTTP probe), H3Direct the direct QUIC
// truth. The block rides every quic block the engine builds, its zero
// halves where the discovery never ran (the -quic-off plane — PQ-54's
// populate-the-zeros cure; the error paths likewise, PQ-60's uniform
// contract). JSONL-only fields — the CSV/text projections carry no new
// columns.
type H3Discovery struct {
	AltSvcH3 bool `json:"alt_svc_h3"`
	H3Direct bool `json:"h3_direct"`
}

// QuicRecord is the QUIC plane block. The engine populates it on every
// record it builds: the error paths ride the zero halves like the
// -quic-off plane (PQ-60's uniform contract, issue #157); a nil block is
// a hand-built or legacy-journal record only.
//
// PQ-25 (spec §5.3) lands the discovery facts ADDITIVELY: Discovered
// carries the hint/truth halves, Mismatch marks the hint-vs-truth
// disagreement (its finding state token rides State:
// "mismatch: hint=yes truth=no" / reverse — a finding, not an error:
// the run's exit code never moves on it); State may also carry the
// honest information token "skipped: no alt-svc h3 hint" when the hint
// gate itself decided the lane. CSV/text unchanged.
//
// PQ-54: the schema-required fields (state, negotiated, group_name,
// group_class, discovered) carry NO omitempty — the writer emits them
// unconditionally once the block is present (zeros and empty strings,
// never missing keys), and encoding/json agrees.
type QuicRecord struct {
	Attempted  bool   `json:"attempted"`
	State      string `json:"state"`
	Negotiated uint32 `json:"negotiated"`
	GroupName  string `json:"group_name"`
	GroupClass string `json:"group_class"`
	UDPBlocked bool   `json:"udp_blocked,omitempty"`
	// Discovered is the hint/truth discovery block; the engine populates
	// the zero halves wherever the plane never ran (PQ-54: the schema
	// requires the block on every record that carries a quic block).
	Discovered *H3Discovery `json:"discovered"`
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
// order). Mode is the executed -deep plan (standard | full), or "pq" —
// PQ-47 (issue #129) fills the SAME block with the -mode pq forced
// ladder's per-probe observations (the lattice mirrors the deep shape;
// the findings ride the lane's row vocabulary verbatim). Attempted,
// OK and Rejected count the executed probes (Attempted = the executed
// count; OK the accepted; Rejected the server-rejected — refusals and
// errors ride Findings only). Nil for every record that did not execute
// a deep plan or the forced PQ ladder (-mode fast, and the deep runs
// that short-circuited on a failed profile handshake — spec §7.4 phase 1
// gates phase 2).
type DeepRecord struct {
	Mode      string        `json:"mode"`
	Attempted int           `json:"attempted"`
	OK        int           `json:"ok"`
	Rejected  int           `json:"rejected"`
	Findings  []DeepFinding `json:"findings"`
}
