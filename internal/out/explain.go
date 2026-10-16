package out

import (
	"strconv"
	"strings"
)

// Explain turns a record's fields into the plain-language reading a
// netsec/netops operator needs at the terminal (PQ-39): the verdict in
// words, what the negotiated group/class means, the certificate and
// the QUIC planes, and an error-class hint when nothing negotiated.
// The renderer is pure (explainBlock) so the prose is testable against
// every record class; the Encoder only decides whether the block rides
// the line. Machine formats (jsonl/csv/urls) never carry the block —
// the CLI refuses -explain there before anything scans.
//
// Rejections stay observations: an unreachable endpoint is "no cipher
// verdict is possible", never tool failure; a draft group is stated as
// the readiness risk it actually is (HNDL), and the fix is named
// (rotate the certificate, strip the drafts) because that is what the
// operator acts on. Prose rides ONLY fields the record actually holds —
// nothing is inferred past what the scan observed.

// EncoderOption adjusts the encoder at construction (variadic; the
// 2-argument NewEncoder call sites stay intact).
type EncoderOption func(*Encoder)

// WithExplain appends the -explain block under every -text line.
func WithExplain() EncoderOption {
	return func(e *Encoder) { e.explain = true }
}

// explainBlock renders one record's reading as full lines (the caller
// newline-terminates each). Line order: verdict, HNDL warning, key
// exchange, certificate, QUIC; the error line replaces the verdict
// lines on a record whose probe failed before one existed.
func explainBlock(r *Record) []string {
	lines := []string{}
	if p := r.Pq; p != nil {
		lines = append(lines, verdictLine(p))
		if p.HNDL {
			lines = append(lines, hndlLine)
		}
	}
	if r.Handshake.Negotiated > 0 {
		lines = append(lines, keyExchangeLine(r.Handshake.GroupName, r.Handshake.GroupClass))
	}
	if c := r.Cert; c != nil {
		lines = append(lines, certificateLine(c))
	}
	if q := r.Quic; q != nil {
		lines = append(lines, quicLine(q))
	}
	if r.Pq == nil && r.Error != "" {
		lines = append(lines, errorLine(r.Error))
	}
	return lines
}

// verdictLine reads the rubric verdict in words, per band. The band
// meanings follow the default rubric's actual composition: every PQ
// signal the rubric can see fired for ready (the negotiated hybrid is
// 40 alone; >=80 needs the certificate layer too), one certificate
// signal for ready-hybrid, and a zero-signal scan is an error state,
// never a passing verdict.
func verdictLine(p *PqRecord) string {
	var meaning string
	switch p.Label {
	case "pq-ready":
		meaning = "Post-quantum on the negotiated key exchange AND the certificate layer."
	case "pq-ready-hybrid":
		meaning = "The post-quantum hybrid protects the session; the certificate layer carries a PQ signal."
	case "pq-partial":
		meaning = "The negotiated key exchange is post-quantum; the certificate layer is classical — see the lines below."
	case "pq-missing":
		meaning = "Some PQ signal observed, but no PQ negotiation the verdict could stand on."
	case "scan-error":
		meaning = "Zero usable PQ signal — scored as an error state, not a passing verdict."
	}
	line := "  - verdict: " + p.Label + " " + strconv.Itoa(p.Score) + "/100"
	if meaning != "" {
		line += ". " + meaning
	}
	return line
}

// hndlLine is the standing warning for an endpoint that accepts the
// obsolete draft PQ groups: post-quantum in appearance, not in fact.
const hndlLine = "  - hndl: HARVEST-NOW-DECRYPT-LATER exposure — the endpoint accepts an obsolete draft PQ group (a pre-ML-KEM algorithm); those handshakes' classical halves stay decryptable to a future quantum computer: strip the draft groups from the server configuration."

// keyExchangeLine reads the negotiated group and its class. The hybrid
// partner is derived from the group name (ML-KEM-<N> + the classical
// curve); unrecognised names carry the class without a fabricated
// partner.
func keyExchangeLine(group, class string) string {
	switch class {
	case "pq_hybrid":
		return "  - key exchange: " + orDash(group) + " (pq_hybrid) — post-quantum hybrid: " + hybridParts(group) + ". Session traffic is protected from later decryption by a quantum computer; the harvest-now-decrypt-later risk does not apply while this group negotiates."
	case "pq":
		return "  - key exchange: " + orDash(group) + " (pq) — post-quantum key exchange: the negotiation itself is quantum-safe."
	case "classic":
		return "  - key exchange: " + orDash(group) + " (classic) — classical: a future quantum computer breaks it, so traffic captured today can be decrypted later (harvest now, decrypt later)."
	case "draft":
		return "  - key exchange: " + orDash(group) + " (draft) — obsolete post-quantum draft (pre-final Kyber): readiness in appearance only, not the standard ML-KEM."
	default:
		return "  - key exchange: " + orDash(group) + " (unknown) — an unrecognised group class; -debug carries the raw negotiation."
	}
}

// hybridParts renders an ML-KEM hybrid group's two halves from the
// name: the ML-KEM parameter set and the classical curve; a name that
// does not parse falls back to itself (no invented halves).
func hybridParts(group string) string {
	mlkem := ""
	for _, set := range []struct {
		token string
		name  string
	}{
		{"MLKEM512", "ML-KEM-512"},
		{"MLKEM768", "ML-KEM-768"},
		{"MLKEM1024", "ML-KEM-1024"},
	} {
		if i := strings.Index(group, set.token); i >= 0 {
			mlkem = set.name
			group = group[:i] + group[i+len(set.token):]
			break
		}
	}
	if mlkem == "" {
		return group
	}
	switch group {
	case "SecP256r1":
		group = "P-256"
	case "SecP384r1":
		group = "P-384"
	case "curveSM2":
		group = "SM2"
	}
	return mlkem + " + " + group
}

// certificateLine reads the leaf's PQ state; "classical" names the
// rotation that closes the gap, because that is the action the
// operator takes next.
func certificateLine(c *CertRecord) string {
	switch {
	case c.SigPQ && c.KeyPQ:
		return "  - certificate: post-quantum identity (" + c.KeyAlg + " key, " + c.SigAlg + " signature) — the identity layer keeps pace with the session."
	case c.SigPQ && !c.KeyPQ:
		return "  - certificate: PQ signature (" + c.SigAlg + ") over a classical key (" + c.KeyAlg + ")."
	case !c.SigPQ && c.KeyPQ:
		return "  - certificate: PQ key (" + c.KeyAlg + ") signed " + c.SigAlg + " (classical)."
	default:
		return "  - certificate: classical identity (" + c.KeyAlg + " key, " + c.SigAlg + " signature). Rotating to a PQ-signed (or dual) certificate at the next renewal closes the readiness gap."
	}
}

// quicLine reads the UDP plane: the negotiated verdict, the blocked
// path, the hint/truth mismatch (a finding, not an error), or the
// plane's refusal.
func quicLine(q *QuicRecord) string {
	if q.UDPBlocked {
		return "  - quic: UDP probes are blocked on this path (egress filter, firewall, or no responsive h3 endpoint) — the QUIC plane is unobservable; not a cipher verdict."
	}
	if q.Negotiated > 0 {
		line := "  - quic: " + orDash(q.GroupName) + " (" + orDash(q.GroupClass) + ") on the UDP plane"
		switch q.GroupClass {
		case "pq_hybrid", "pq":
			return line + " — the same post-quantum verdict applies to h3 traffic."
		case "classic":
			return line + " — classical there too: a PQ negotiation on TCP does not protect the QUIC plane."
		case "draft":
			return line + " — the same obsolete draft on the UDP plane."
		default:
			return line + "."
		}
	}
	if d := q.Discovered; d != nil && q.Mismatch {
		switch {
		case d.AltSvcH3 && !d.H3Direct:
			return "  - quic: Alt-Svc advertises h3, but the direct probe could not negotiate it — the mismatch is a finding, not an error; treat the QUIC plane as promised-but-unverified."
		case !d.AltSvcH3 && d.H3Direct:
			return "  - quic: h3 negotiates on the wire although Alt-Svc never advertised it — the hint is stale or the advertisement is path-dependent."
		}
	}
	if q.Attempted {
		return "  - quic: attempted, no QUIC negotiation on the UDP plane."
	}
	return "  - quic: the lane never ran on this record."
}

// errorLine carries the verbatim error plus one class hint — refused /
// stalled / TLS-layer / fallback. The wording keeps the contract: no
// handshake = no cipher verdict; nothing here reads as tool failure.
func errorLine(err string) string {
	switch {
	case strings.Contains(err, "refused"):
		return "  - error: " + err + " — no handshake was reached: the endpoint is unreachable on this port (closed or filtered); no cipher verdict is possible."
	case strings.Contains(err, "i/o timeout") || strings.Contains(err, "timeout") || strings.Contains(err, "deadline exceeded"):
		return "  - error: " + err + " — the endpoint stalled past the probe budget (a stalled accept and a filtered path look the same); no cipher verdict possible."
	case strings.Contains(err, "tls:") || strings.Contains(err, "x509:"):
		return "  - error: " + err + " — the handshake failed at the TLS/certificate layer (the offer was rejected or the chain failed analysis); no negotiated parameters to score."
	default:
		return "  - error: " + err + " — no handshake completed; no cipher verdict."
	}
}
