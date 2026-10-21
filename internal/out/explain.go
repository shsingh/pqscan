package out

import (
	"strconv"
	"strings"

	"github.com/shsingh/pqscan/internal/classify"
)

// Explain turns a record's fields into the plain-language reading a
// netsec/netops operator needs at the terminal (PQ-39): the rating in
// words, what the negotiated group/class means, the certificate and
// the QUIC planes, and an error-class hint when nothing negotiated.
// The renderer is pure (explainBlock) so the prose is testable against
// every record class; the Encoder only decides whether the block rides
// the line. Machine formats (jsonl/csv/urls) never carry the block —
// the CLI refuses -explain there before anything scans.
//
// Rejections stay observations: an unreachable endpoint is "no cipher
// rating is possible", never tool failure; a draft group is stated as
// the readiness risk it actually is (HNDL), and the fix is named
// (rotate the certificate, strip the drafts) because that is what the
// operator acts on. Prose rides ONLY fields the record actually holds —
// nothing is inferred past what the scan observed. The prose reads in
// ASD-STE100 (issue #173's lanes): one thought per sentence, the active
// voice in the present tense, the fixed technical names verbatim.

// EncoderOption adjusts the encoder at construction (variadic; the
// 2-argument NewEncoder call sites stay intact).
type EncoderOption func(*Encoder)

// WithExplain appends the -explain block under every -text line.
func WithExplain() EncoderOption {
	return func(e *Encoder) { e.explain = true }
}

// explainBlock renders one record's reading as full lines (the caller
// newline-terminates each). Line order: rating, HNDL warning, the deep
// reading (PQ-50: the executed plan in words, when the record executes a
// deep plan), key exchange, certificate, QUIC; the error line carries any
// error the
// record actually holds — it replaces the rating lines when the probe
// failed before one existed (pq == nil) and rides under them on a
// rating-carrying record with a leftover error string (PQ-43
// belt-and-braces: the renderer accounts for the record's fields, and
// the engine never feeds the rubric's error onto a graded record, so
// that case is defence in depth).
func explainBlock(r *Record) []string {
	lines := []string{}
	// The zero-populated blocks (PQ-60's uniform record contract: the
	// schema-required blocks stand zero-populated on error records) yield
	// NO prose: an empty label means the rubric never ran and unnamed
	// algorithms mean no leaf was analyzed — reading either would invent
	// a claim past what the scan observed. The quic block's zero halves
	// render their own honest line ("the lane never ran").
	if p := r.Pq; p != nil && p.Label != "" {
		lines = append(lines, ratingLine(p))
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
	if c := r.Cert; c != nil && (c.SigAlg != "" || c.KeyAlg != "") {
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

// ratingLine reads the rubric rating in words, per band. The band
// meanings follow the default rubric's actual composition: every PQ
// signal the rubric can see fired for ready (the negotiated hybrid is
// 40 alone; >=80 needs the certificate layer too), one certificate
// signal for ready-hybrid, and a zero-signal scan is an error state,
// never a passing rating.
func ratingLine(p *PqRecord) string {
	var meaning string
	switch p.Label {
	case "pq-ready":
		meaning = "The negotiated key exchange and the certificate layer are both post-quantum."
	case "pq-ready-hybrid":
		meaning = "The post-quantum hybrid protects the session. The certificate layer carries a PQ signal."
	case "pq-partial":
		meaning = "The negotiated key exchange is post-quantum. The certificate layer is classical. The lines below carry the detail."
	case "pq-missing":
		meaning = "A PQ signal is on the record. No PQ negotiation feeds the rating."
	case "scan-error":
		meaning = "Zero usable PQ signal. The rubric records an error state, not a rating."
	}
	line := "  - rating: " + p.Label + " " + strconv.Itoa(p.Score) + "/100"
	if meaning != "" {
		line += ". " + meaning
	}
	return line
}

// hndlLine is the standing warning for an endpoint that accepts the
// obsolete draft PQ groups: post-quantum in appearance, not in fact.
const hndlLine = "  - hndl: HARVEST-NOW-DECRYPT-LATER exposure. The endpoint accepts an obsolete draft PQ group (a pre-ML-KEM algorithm). Those handshakes stay decryptable to a future quantum computer. Remove the draft groups from the server configuration."

// The deep block's finding result vocabulary — the record's own contract
// (DeepFinding, spec §8): accepted | rejected | refused | error. The
// renderer counts the record's fields and invents nothing past them.
const (
	deepResultAccepted = "accepted"
	deepResultRejected = "rejected"
	deepResultRefused  = "refused"
	deepResultError    = "error"

	// deepModePQ is the pq ladder's mode token in the deep block (PQ-47):
	// the block mirrors the deep executor's shape with the lane's token,
	// and the ladder reading (PQ-50) keys on it.
	deepModePQ = "pq"
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
// reading's counts stay complete. The family names are the reading's
// prose (ste100: "offer set" for the forced-offer families).
var deepFamilies = []struct {
	prefix string
	name   string
}{
	{"version/", "version floor"},
	{"group/", "group offer set"},
	{"quic/", "quic offer set"},
	{"suite/", "suite matrix"},
	{"sigalg/", "sigalg offer set"},
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
// prose). The pq ladder (Deep.Mode == "pq", PQ-47's block) reads
// differently — its forced-ladder prose is pqLadderLine.
func deepLine(d *DeepRecord, r *Record) string {
	if d.Mode == deepModePQ {
		return pqLadderLine(d, r)
	}
	refused, errored, tallies, accepted := deepFindingsTally(d)

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

// deepFindingsTally walks a deep block's findings vector once — the
// shared roll-up behind both readings of the block (the deep plan's and
// the pq ladder's): each probe-id family's acc/tot in family order, the
// not-offerable (refused) and errored counts, and the accepted rows in
// vector order.
func deepFindingsTally(d *DeepRecord) (refused, errored int, tallies map[string]*deepTally, accepted []DeepFinding) {
	tallies = map[string]*deepTally{}
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
	return refused, errored, tallies, accepted
}

// pqLadderLine reads the forced PQ ladder in words (PQ-50, issue #134;
// the Deep.Mode == "pq" block PQ-47 lands): the forced-offer counts, the
// ACCEPTED rows named — the actionable part; a draft-group acceptance IS
// the harvest-now-decrypt-later exposure, spelled by the deep reading's
// row-note discipline — and the refusals framed as the expected default:
// each forced PQ-only group refused unless the server supports that
// group. The per-probe pointer is the deep reading's. No second
// roll-up mechanism: the findings tally and the row notes are the deep
// reading's helpers.
func pqLadderLine(d *DeepRecord, r *Record) string {
	refused, errored, _, accepted := deepFindingsTally(d)

	var b strings.Builder
	b.WriteString("  - deep: the forced PQ offer set sent " + strconv.Itoa(d.Attempted) + " offers: ")
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
	}
	if len(accepted) > 0 {
		b.WriteString("; accepted: ")
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
	b.WriteString("; each forced PQ-only group refused unless the server supports that group")
	b.WriteString(" — the per-probe detail lives in the jsonl findings.")
	return b.String()
}

// deepRowNote names the notable shapes among the accepted rows: a PQ
// group accepted where the profile handshake negotiated classical (the
// fact the forced offer exists to answer for the estate), and a
// draft-group acceptance — the harvest-now-decrypt-later exposure, here
// spelled out because the hndl line rides the pq rating's flag and a
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
		return "  - key exchange: " + orDash(group) + " (pq_hybrid) — post-quantum hybrid: " + hybridParts(group) + ". This group protects the session traffic. The harvest-now-decrypt-later risk does not apply while this group negotiates."
	case "pq":
		return "  - key exchange: " + orDash(group) + " (pq) — post-quantum key exchange: the negotiation itself is quantum-safe."
	case "classic":
		return "  - key exchange: " + orDash(group) + " (classic) — classical. A quantum computer breaks this exchange over time. The captured traffic carries the harvest-now-decrypt-later exposure."
	case "draft":
		return "  - key exchange: " + orDash(group) + " (draft) — an obsolete pre-final PQ draft (pre-ML-KEM Kyber). This class is not the standard ML-KEM. It gives no real PQ readiness."
	default:
		return "  - key exchange: " + orDash(group) + " (unknown) — an unrecognised group class. -debug carries the raw negotiation."
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
// renewal that closes the gap, because that is the action the
// operator takes next.
func certificateLine(c *CertRecord) string {
	switch {
	case c.SigPQ && c.KeyPQ:
		return "  - certificate: post-quantum identity (" + c.KeyAlg + " key, " + c.SigAlg + " signature). The identity layer is post-quantum, too."
	case c.SigPQ && !c.KeyPQ:
		return "  - certificate: PQ signature (" + c.SigAlg + ") over a classical key (" + c.KeyAlg + ")."
	case !c.SigPQ && c.KeyPQ:
		return "  - certificate: PQ key (" + c.KeyAlg + ") signed " + c.SigAlg + " (classical)."
	default:
		return "  - certificate: classical identity (" + c.KeyAlg + " key, " + c.SigAlg + " signature). Use a PQ-signed or dual certificate at the next renewal."
	}
}

// quicLine reads the UDP plane: the negotiated rating, the blocked
// path, the hint/truth mismatch (a finding, not an error), or the
// plane's refusal.
func quicLine(q *QuicRecord) string {
	if q.UDPBlocked {
		return "  - quic: the path blocks the UDP probes (a filter | a firewall | no responsive h3 endpoint). The QUIC plane gives no rating."
	}
	if q.Negotiated > 0 {
		line := "  - quic: " + orDash(q.GroupName) + " (" + orDash(q.GroupClass) + ") on the UDP plane"
		switch q.GroupClass {
		case "pq_hybrid", "pq":
			return line + " — the same post-quantum rating applies to h3 traffic."
		case "classic":
			return line + " — classical there, too: a PQ negotiation on TCP does not protect the QUIC plane."
		case "draft":
			return line + " — the same obsolete draft on the UDP plane."
		default:
			return line + "."
		}
	}
	if d := q.Discovered; d != nil && q.Mismatch {
		switch {
		case d.AltSvcH3 && !d.H3Direct:
			return "  - quic: Alt-Svc advertises h3. The direct probe could not negotiate h3. The mismatch is a finding, not an error. The QUIC plane is unverified."
		case !d.AltSvcH3 && d.H3Direct:
			return "  - quic: h3 negotiates on the wire. Alt-Svc never advertised h3. The hint is stale (or the advertisement is path-dependent)."
		}
	}
	if q.Attempted {
		return "  - quic: attempted, no QUIC negotiation on the UDP plane."
	}
	return "  - quic: the lane never ran on this record."
}

// errorLine carries the verbatim error plus one class hint — refused /
// stalled / TLS-layer / fallback. The wording keeps the contract: no
// handshake = no cipher rating; nothing here reads as tool failure.
func errorLine(err string) string {
	switch {
	case strings.Contains(err, "refused"):
		return "  - error: " + err + " — the probe reached no handshake. The endpoint is unreachable on this port (closed or filtered). No rating is possible."
	case strings.Contains(err, "i/o timeout") || strings.Contains(err, "timeout") || strings.Contains(err, "deadline exceeded"):
		return "  - error: " + err + " — the probe budget expired (a stalled endpoint and a filtered path give this line). No rating is possible."
	case strings.Contains(err, "tls:") || strings.Contains(err, "x509:"):
		return "  - error: " + err + " — the handshake failed at the TLS/certificate layer (a rejected offer or a failed chain analysis). No negotiated parameters remain for the rating."
	default:
		return "  - error: " + err + " — no handshake completed. No cipher rating."
	}
}
