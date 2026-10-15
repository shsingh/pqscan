package tlsx

import (
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/shsingh/pqscan/internal/certinfo"
	"github.com/shsingh/pqscan/internal/diag"
)

// defaultProtos = the browser-grade ALPN offer (negotiated result is
// recorded; no application data is exchanged).
var defaultProtos = []string{"h2", "http/1.1"}

// strconvUint keeps diagnostics fields string-typed.
func strconvUint(u uint32) string { return strconv.FormatUint(uint64(u), 10) }

// ProbeResult is one row of the capability matrix: what was offered, what
// the server answered, and the observed negotiation (spec §5.4; JSONL
// mapping mirrors the schema in spec §5.7).
type ProbeResult struct {
	Offered        uint32 `json:"offered_group"`
	Shared         bool   `json:"shared"`
	Path           string `json:"path"`             // "stdlib" | "raw"
	State          string `json:"state"`            // negotiated | hrr | alert | read-error | error
	Negotiated     uint32 `json:"negotiated_group"` // stdlib path: 0 = unknown
	RequestedGroup uint32 `json:"requested_group"`  // raw path: HRR target
	Suite          string `json:"suite"`
	Version        uint16 `json:"version"`
	ALPN           string `json:"alpn_neg"` // negotiated ALPN protocol
	AlertDesc      uint8  `json:"alert"`
	Error          string `json:"error"`

	// PQ-21 certificate analytics, computed from the peer chain delivered
	// by the same handshake that fills ConnectionState (stdlib path only;
	// a raw-path row or an unanalyzable chain leaves the zero values:
	// CertificatePQ=false, CertificateSigAlg=""). CertificatePQ is true
	// when the leaf's signature or key algorithm carries a PQ component
	// (pure PQ or composite hybrid per certinfo's owned OID table);
	// CertificateSigAlg carries the leaf's signature-algorithm name, with
	// an "unknown-signature-algorithm(<oid>)" note for OIDs outside the
	// table.
	CertificatePQ     bool   `json:"cert_pq"`
	CertificateSigAlg string `json:"cert_sig_alg"`

	// PQ-19/PQ-21 record wire-in: the FULL certinfo.Info from the same
	// handshake that fills the row — the record's cert block (sig/key
	// names + flags, the chain's DualCert) and the pipeline's rubric
	// DualCert input both come off this. Nil when the chain is missing,
	// a raw path, or unanalyzable (the zero policy: no invented rows);
	// the CertificatePQ/CertificateSigAlg pair above is the #82 sig
	// surface and stays untouched in shape.
	CertificateInfo *certinfo.Info `json:"cert_info,omitempty"`

	// PQ-26 (issue #49): the end-entity certificate's RAW DER bytes as
	// the same handshake delivered them — the -certs-dir PEM export's
	// input. Empty for a raw path or a chain the handshake never
	// carried; json:"-" (the record's cert block is the ANALYSIS, the
	// raw bytes ride only to the exporter).
	LeafRaw []byte `json:"-"`
}

// StdlibGroup reports whether ONE codepoint takes the stdlib share path
// (the Go stack can construct a real key share for it, 1.26+ toolchain
// floor) versus the raw share-less oracle path. This is the SINGLE
// routing table: GroupLadder dispatches on it, and the QUIC plane's
// wiring reuses it (PQ-25) — the UDP plane offers NO raw path, so a
// non-stdlib codepoint there is not-offerable (an honest refused finding,
// never a dial).
func StdlibGroup(g uint32) bool {
	switch g {
	case 4585, 4586, 4590, 25497, 25498:
		return false
	}
	return g <= 65535
}

// stdlibGroups are the codepoints the Go stack can construct a real share
// for (1.26+/toolchain floor; anything else is offered share-less via the
// raw path — the oracle probes).
func stdlibGroups(groups []uint32) bool {
	for _, g := range groups {
		if !StdlibGroup(g) {
			return false
		}
	}
	return true
}

// ProbeNegotiated forces `groups` via crypto/tls and reports the observed
// negotiation end to end (real key shares, real HRR handling). addr is
// host:port; host carries the SNI.
func ProbeNegotiated(addr, host string, groups []uint32, timeout time.Duration) (*ProbeResult, error) {
	res := &ProbeResult{Shared: true, Path: "stdlib"}
	if len(groups) > 0 {
		res.Offered = groups[0]
	}
	var curvePrefs []tls.CurveID
	if len(groups) > 0 {
		curvePrefs = make([]tls.CurveID, 0, len(groups))
		for _, g := range groups {
			curvePrefs = append(curvePrefs, tls.CurveID(g))
		}
	}
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,       // negotiation is the assertion; cert analytics is a separate probe
		CurvePreferences:   curvePrefs, // nil = browser-grade defaults (MLKEM hybrid preferred)
		NextProtos:         defaultProtos,
		MinVersion:         tls.VersionTLS12,
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		res.State = "error"
		res.Error = err.Error()
		return res, nil // rejection is a result, not a failure of the ladder
	}
	defer conn.Close() //nolint:errcheck

	cs := conn.ConnectionState()
	res.State = "negotiated"
	res.Negotiated = uint32(cs.CurveID)
	res.Version = cs.Version
	res.ALPN = cs.NegotiatedProtocol
	if id := cs.CipherSuite; id != 0 {
		res.Suite = tls.CipherSuiteName(cs.CipherSuite)
	}
	// PQ-21: the peer chain arrives with the same ConnectionState that
	// fills the negotiated row — classify it in this same call, no extra
	// probe. Fields stay zero for an unanalyzable chain (no invented data).
	// PQ-26: the raw end-entity DER rides the same block (json:"-" on the
	// field) for the -certs-dir exporter.
	if len(cs.PeerCertificates) > 0 {
		res.LeafRaw = cs.PeerCertificates[0].Raw
		if ci, cerr := certinfo.Analyze(cs.PeerCertificates); cerr == nil {
			res.CertificateInfo = ci
			res.CertificatePQ = ci.SigAlgPQ || ci.KeyAlgPQ
			res.CertificateSigAlg = ci.SigAlgName
		}
	}
	return res, nil
}

// GroupLadder runs the forced-group ladder against one host (spec §5.2 `pq`
// mode core, §7.4): standards-track groups through the stdlib path (real
// shares), everything else — the obsolete-Kyber oracle and exotic hybrids —
// share-less through the raw first-flight path, observing HRR/alerts and
// recording the server's demanded group where it asks for one.
func GroupLadder(addr, host string, groups []uint32, timeout time.Duration) []ProbeResult {
	out := make([]ProbeResult, 0, len(groups))
	for _, g := range groups {
		if stdlibGroups([]uint32{g}) {
			r, err := ProbeNegotiated(addr, host, []uint32{g}, timeout)
			if err != nil {
				diag.Emit(diag.Error, diag.DomTLS, "ladder", addr, "stdlib probe errored", err,
					map[string]string{"offered_group": strconvUint(g)})
				out = append(out, ProbeResult{Offered: g, Path: "stdlib", State: "error", Error: err.Error()})
				continue
			}
			diag.Emit(diag.Info, diag.DomTLS, "ladder", addr, "forced-group probe", nil,
				map[string]string{"offered_group": strconvUint(g), "shared": "true", "state": r.State,
					"negotiated": strconvUint(r.Negotiated), "suite": r.Suite})
			out = append(out, *r)
			continue
		}
		obs, err := SendHelloProbe(addr, host, []uint32{g}, 0)
		if err != nil {
			diag.Emit(diag.Error, diag.DomTLS, "ladder", addr, "raw oracle probe errored", err,
				map[string]string{"offered_group": strconvUint(g), "shared": "false"})
			out = append(out, ProbeResult{Offered: g, Shared: false, Path: "raw", State: "error", Error: err.Error()})
			continue
		}
		level := diag.Info
		if obs.State == StateAlert {
			level = diag.Warn
		}
		diag.Emit(level, diag.DomTLS, "ladder", addr, "raw oracle probe", nil,
			map[string]string{"offered_group": strconvUint(g), "shared": "false", "state": obs.State,
				"requested_group": strconvUint(obs.RequestedGroup), "alert": strconvUint(uint32(obs.AlertDesc))})
		out = append(out, ProbeResult{
			Offered:        g,
			Shared:         false,
			Path:           "raw",
			State:          obs.State,
			RequestedGroup: obs.RequestedGroup,
			Version:        obs.Version,
			AlertDesc:      obs.AlertDesc,
		})
	}
	return out
}
