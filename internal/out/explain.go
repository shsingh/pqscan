package out

import (
	"strconv"
	"strings"

	"github.com/shsingh/pqscan/internal/classify"
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
// newline-terminates each). Line order: verdict, HNDL warning, the deep
// reading (PQ-50: the executed plan in words, when the record executes a
// deep plan), key exchange, certificate, QUIC; the error line carries any
// error the
// record actually holds — it replaces the verdict lines when the probe
// failed before one existed (pq == nil) and rides under them on a
// verdict-carrying record with a leftover error string (PQ-43
// belt-and-braces: the renderer accounts for the record's fields, and
// the engine never feeds the rubric's error onto a graded record, so
// that case is defence in depth).
func explainBlock(r *Record) []string {
	lines := []string{}
	if p := r.Pq; p != nil {
		lines = append(lines, verdictLine(p))
		if p.HNDL {
			lines = append(lines, hndlLine)
		}
	}
	if d := r.Deep; d != nil {
		lines = append(lines, deepLine(d, r))
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
	if r.Error != "" {
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

// The deep block's finding result vocabulary — the record's own contract
// (DeepFinding, spec §8): accepted | rejected | refused | error. The
// renderer counts the record's fields and invents nothing past them.
const (
	deepResultAccepted = "accepted"
	deepResultRejected = "rejected"
	deepResultRefused  = "refused"
	deepResultError    = "error"
)

// deepTally is one probe-id family's roll-up: the findings counted, the
// ones the server accepted.
type deepTally struct {
	acc, tot int
}

// deepFamilies is the plan's probe-id vocabulary in plan order (spec
// §7.4's phase-2 kinds): the roll-up groups the findings by the ids'
// common prefix and reports each family's yield acc/tot. A finding
// outside the table (a future kind) rolls up under "other" so the
// reading's counts stay complete.
var deepFamilies = []struct {
	prefix string
	name   string
}{
	{"version/", "version floor"},
	{"group/", "group ladder"},
	{"quic/", "quic rungs"},
	{"suite/", "suite matrix"},
	{"sigalg/", "sigalg ladder"},
	{"cert/", "certificate probe"},
	{"resumption/", "resumption vectors"},
	{"hrr/", "hrr probe"},
}

// deepLine reads the executed deep plan in words (PQ-50, issue #134): the
// counts the record actually carries (attempted, accepted, server-
// rejected; the refused/not-offerable and errored tails counted from the
// findings vector), the offer-one matrix's yield rolled up by probe-id
// family, and the accepted rows NAMED — the naming is the actionable
// part: a PQ group accepted where the profile handshake negotiated
// classical is the estate-wide "their stack speaks PQ when forced" fact,
// and a draft-group acceptance IS the harvest-now-decrypt-later exposure
// spelled out. Refusals stay the expected default of a forced-offer
// matrix (observations, not tool failure) and the per-probe detail lives
// in the jsonl findings — the line invents nothing past the fields.
// Group classes ride internal/classify (the IANA-derived taxonomy's
// single home; the registry rule forbids inlining codepoints into
// prose).
func deepLine(d *DeepRecord, r *Record) string {
	refused, errored := 0, 0
	tallies := map[string]*deepTally{}
	var accepted []DeepFinding
	for i := range d.Findings {
		f := &d.Findings[i]
		prefix := "other"
		for _, fam := range deepFamilies {
			if strings.HasPrefix(f.Probe, fam.prefix) {
				prefix = fam.prefix
				break
			}
		}
		t := tallies[prefix]
		if t == nil {
			t = &deepTally{}
			tallies[prefix] = t
		}
		t.tot++
		if f.Result == deepResultAccepted {
			t.acc++
			accepted = append(accepted, *f)
		}
		switch f.Result {
		case deepResultRefused:
			refused++
		case deepResultError:
			errored++
		}
	}

	var b strings.Builder
	b.WriteString("  - deep: the executed " + d.Mode + " plan ran " + strconv.Itoa(d.Attempted) + " probes: ")
	if d.OK == 0 {
		b.WriteString("no offer was accepted")
	} else {
		b.WriteString(strconv.Itoa(d.OK) + " accepted")
	}
	b.WriteString(", " + strconv.Itoa(d.Rejected) + " refused with the server's reasons")
	if len(d.Findings) > 0 {
		b.WriteString(", " + strconv.Itoa(refused) + " not-offerable")
		if errored > 0 {
			b.WriteString(", " + strconv.Itoa(errored) + " errored on the probe path")
		}
		b.WriteString("; the offered-one matrix read: ")
		first := true
		for _, fam := range deepFamilies {
			t := tallies[fam.prefix]
			if t == nil {
				continue
			}
			if !first {
				b.WriteString(", ")
			}
			first = false
			b.WriteString(fam.name + " " + strconv.Itoa(t.acc) + "/" + strconv.Itoa(t.tot))
		}
		if t := tallies["other"]; t != nil {
			if !first {
				b.WriteString(", ")
			}
			b.WriteString("other " + strconv.Itoa(t.acc) + "/" + strconv.Itoa(t.tot))
		}
		b.WriteString("; ")
		if d.OK == 0 {
			b.WriteString("the profile handshake above carries the negotiation")
		} else {
			b.WriteString("accepted: ")
			for i := range accepted {
				if i > 0 {
					b.WriteString("; ")
				}
				b.WriteString(accepted[i].Probe)
				if note := deepRowNote(accepted[i].Probe, r.Handshake.GroupClass); note != "" {
					b.WriteString(" (" + note + ")")
				}
			}
		}
	}
	b.WriteString(" — the per-probe detail lives in the jsonl findings.")
	return b.String()
}

// deepRowNote names the notable shapes among the accepted rows: a PQ
// group accepted where the profile handshake negotiated classical (the
// fact the forced offer exists to answer for the estate), and a
// draft-group acceptance — the harvest-now-decrypt-later exposure, here
// spelled out because the hndl line rides the pq verdict's flag and a
// deep finding's draft acceptance is this line's data. The class lookup
// is classify's — the sanctioned taxonomy home; unknown codepoints name
// nothing.
func deepRowNote(id, handshakeClass string) string {
	if !strings.HasPrefix(id, "group/") {
		return ""
	}
	cp, err := strconv.ParseUint(strings.TrimPrefix(id, "group/"), 10, 32)
	if err != nil {
		return ""
	}
	cls, known := classify.GroupClass(uint32(cp))
	if !known {
		return ""
	}
	switch cls {
	case classify.ClassPQHybridD:
		return "an obsolete draft group accepted — the harvest-now-decrypt-later exposure: strip the draft groups from the server configuration"
	case classify.ClassPQHybrid, classify.ClassPQ, classify.ClassHybridSM:
		if handshakeClass == "classic" {
			return "a PQ group accepted where the profile handshake negotiated classical"
		}
	}
	return ""
}

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
