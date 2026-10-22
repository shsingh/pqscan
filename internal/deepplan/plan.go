// Package deepplan builds per-target deep-mode probe plans (spec §7.4,
// PQ-20): the pure offer-one spec the executor hands to the handshake
// plane. A plan is data, never execution: Build turns a target + mode +
// the FAST-mode record's facts (Observed) into a deterministic probe list.
//
// Modes:
//   - standard: the exhaustive candidate matrix with the profile
//     handshake's facts pruned (a suite already negotiating is skipped —
//     spec §7.4 phase 2) and the remainder cut to the default budget (24
//     probes) along the documented prune priority (pruneStandard): the
//     negotiated suite's adjacency goes first; the forced-group ladder
//     and the PQ sigalgs survive longest — the PQ ladder runs even on
//     classic servers (spec §7.4).
//   - full: the COMPLETE offer-one matrix, unpruned — every stdlib
//     suite × supported-version pair the handshake plane can construct,
//     the registry's forced-group blocks (4585–4590, 25–29), the
//     signature-scheme ladder (classic + ML-DSA), and the feature
//     probes: resumption + 0-RTT + HRR. Observed facts never prune it.
//
// The offer-one principle (spec §7.4): each suite probe is its OWN
// handshake — offer exactly one suite, observe whether the server
// accepts it. The plan is the pure spec of those handshakes; the
// executor wiring (its own PQ-20 pair) maps payloads onto engine calls.
// The full matrix auto-tracks the linked toolchain's stdlib suite list
// (crypto/tls CipherSuites + InsecureCipherSuites) — duplicate suite
// tables are never minted here; the suite-count bound is asserted by
// test (FullMatrixBound) and the standard-prune table is structural only.
package deepplan

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
)

// Probe kinds (the deep-mode phase-2 vocabulary, spec §7.4).
const (
	KindVersion    = "version"
	KindSuite      = "suite"
	KindGroup      = "group"
	KindSigalg     = "sigalg"
	KindCert       = "cert"
	KindResumption = "resumption"
	KindHRR        = "hrr"
	// KindQuic is the deep-QUIC rung kind (PQ-25, PQ-69; spec §5.3, §7.4):
	// the whole QUIC offer set plans under this ONE kind, so the census
	// counts the set as one class. The group rungs carry a uint32 payload
	// (one per rung, dispatched by the executor onto quicx's forced-group
	// probe); the two non-group rungs (PQ-69) carry the string payloads
	// below — never a group codepoint, so factPrune's QuicNegotiated
	// prune (a uint32 match) can never drop them. The UDP plane offers
	// NO raw share-less path, so a group rung the stdlib cannot
	// construct a share for lands as an honest refused finding (the
	// #101 discipline), never a dial and never a fabricated verdict.
	KindQuic = "quic"
)

// The deep-QUIC rungs' non-group payloads (PQ-69, issue #181). The
// payloads are the fixed string tokens below the group space; the plan
// never invents a codepoint for them.
const (
	// QuicRungV2 is the RFC 9369 transport-version rung's payload: the
	// rung dials QUIC v2 only, ALPN h3, and lands the negotiated
	// version as the finding.
	QuicRungV2 = "v2"
	// QuicRungH3Exchange is the functional HTTP/3 rung's payload: the
	// rung reads the server's SETTINGS frame and completes ONE HTTP/3
	// GET through the pinned quic-go h3 stack.
	QuicRungH3Exchange = "h3-exchange"
)

// Plan modes (the -deep plan semantics; unknown modes are errors).
const (
	ModeStandard = "standard"
	ModeFull     = "full"
)

// Budgets and bounds (spec §7.4).
const (
	StandardBudget  = 24  // default deep plan cap per target
	FullMatrixBound = 130 // full-matrix hard bound asserted by tests
)

// Resumption vector labels (the Payload of a KindResumption probe).
const (
	ResTicket12 = "ticket-tls12" // TLS 1.2 session-ticket resumption
	ResPSK13    = "psk-tls13"    // TLS 1.3 PSK resumption
	Res0RTT13   = "0rtt-tls13"   // TLS 1.3 0-RTT early-data acceptance
)

// probeVersions is the version floor/acceptance enumeration: the core
// TLS 1.0–1.3 versions, forced one per handshake (SSLv3 stays in the
// opt-in legacy module, spec §5.2).
var probeVersions = []uint16{0x0301, 0x0302, 0x0303, 0x0304}

// probeGroups is the forced-group ladder of the deep full matrix: the
// registry's PQ hybrid blocks 4585–4590 (RFC 10024 + the ECDHE-MLKEM
// and SM2 hybrid drafts) then the classic standards-track block 25–29
// (secp521r1, the brainpools, x25519 — forced-offer probes for the
// groups a target may accept but never default-negotiate). The PQ
// ladder runs even on classic servers: "does their stack accept 4588
// when forced" is the actionable estate-wide fact (spec §7.4).
var probeGroups = []uint32{4585, 4586, 4587, 4588, 4589, 4590, 25, 26, 27, 28, 29}

// probeSigalgs is the signature-scheme ladder: the four classic schemes
// the handshake plane constructs shares for, then the three ML-DSA
// schemes (spec §5.6: mldsa44/65/87 = 0x0904–0x0906). Composite ML-DSA
// schemes ride later: no IANA-final codepoints exist, and the plan never
// invents a codepoint.
var probeSigalgs = []uint16{0x0403, 0x0804, 0x0805, 0x0806, 0x0904, 0x0905, 0x0906}

// sigalgNames is the ladder's printable vocabulary (probe names and
// diag lines); unknown schemes fall back to their raw codepoint.
var sigalgNames = map[uint16]string{
	0x0403: "ecdsa_secp256r1_sha256",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha4096",
	0x0904: "mldsa44",
	0x0905: "mldsa65",
	0x0906: "mldsa87",
}

// mldsaSchemes is the PQ sigalg set the prune classes never cut.
var mldsaSchemes = map[uint16]bool{0x0904: true, 0x0905: true, 0x0906: true}

// Observed carries the FAST-mode record's facts (spec §7.4 phase 1: one
// handshake whose result prunes phase 2). Zero values mean unknown; a
// nil *Observed means no facts at all (e.g. the fast handshake failed —
// the plan then keeps the version-floor enumeration and drops the
// classic sigalgs instead).
type Observed struct {
	NegotiatedGroup uint32 // negotiated key-exchange group code (0 = unknown)
	NegotiatedSuite string // negotiated cipher suite name ("" = unknown)
	Version         uint16 // negotiated TLS version code (0 = unknown)
	HasCert         bool   // the fast handshake already fetched the certificate

	// QuicAttempted is the QUIC lane's gate (PQ-25, spec §5.3): the
	// profile's hint-gated direct QUIC probe ran (the hint asserted h3
	// or -quic-always forced it). The deep-QUIC rungs plan only then —
	// the same gate the fast lane used; -quic-off and an unhinted
	// target leave the plan QUIC-free. The gate rides Observed because
	// it is the fast record's OWN fact, not a mode property.
	QuicAttempted bool
	// QuicNegotiated is the group the QUIC plane's direct probe already
	// negotiated (0 = none/unknown): its rung never re-probes (spec
	// §7.4 phase 1 — the group the profile handshake answered is never
	// re-run, on either plane). The prune matches uint32 payloads only:
	// the PQ-69 string rungs (quic/v2, quic/h3-exchange) plan unpruned
	// in every fact shape.
	QuicNegotiated uint32
}

// SuiteOffer is the concrete spec of a suite probe: one suite offered on
// one forced protocol version (the offer-one unit of the matrix —
// acceptance at one version implies nothing at another).
type SuiteOffer struct {
	Name    string // IANA cipher suite name as the stdlib reports it
	Version uint16 // the forced protocol version for this offer
}

// quicGroups is the deep-QUIC ladder's block rungs (PQ-25, spec §5.3):
// the registry's 4585–4590 hybrid block — the QUIC plane shares the TCP
// lane's forced-group grammar (RFC 10024 verified per rung on its own
// transport). The negotiated-group rung rides Observed, not this table.
// The plan never invents a codepoint.
var quicGroups = []uint32{4585, 4586, 4587, 4588, 4589, 4590}

// Probe is one scheduled handshake assertion in the plan.
type Probe struct {
	Name string // stable, greppable probe id (e.g. "group/4588")
	Kind string // version | suite | group | sigalg | cert | resumption | hrr
	// Payload is the kind's concrete spec: a version code (uint16), a
	// SuiteOffer, a group code (uint32), a signature scheme code (uint16),
	// a resumption vector label (string), or nil (cert, hrr).
	Payload any
}

// Plan is one target's deep-mode probe plan (the executor's input).
type Plan struct {
	Target string
	Mode   string // standard | full
	Probes []Probe
	// EstimatedHandshakes equals len(Probes): every probe in the plan is
	// one handshake (offer-one / observe-accept); nothing in the plan is
	// free, so the two move together by construction.
	EstimatedHandshakes int
}

// Build returns one target's deep-mode probe plan.
//
// standard: the exhaustive candidate matrix with the profile facts
// pruned, then the prune classes applied down to the default budget —
// the plan's probe list never exceeds 24. full: the unpruned complete
// matrix. Unknown modes (anything but "standard" | "full") and an empty
// target are errors.
func Build(target string, mode string, observed *Observed) (*Plan, error) {
	if target == "" {
		return nil, fmt.Errorf("deepplan: empty target")
	}
	obs := Observed{}
	if observed != nil {
		obs = *observed
	}
	candidate := candidateMatrix(obs)
	switch mode {
	case ModeStandard:
		pruned, err := pruneStandard(candidate, obs, StandardBudget)
		if err != nil {
			return nil, err
		}
		return &Plan{Target: target, Mode: mode, Probes: pruned, EstimatedHandshakes: len(pruned)}, nil
	case ModeFull:
		return &Plan{Target: target, Mode: mode, Probes: candidate, EstimatedHandshakes: len(candidate)}, nil
	default:
		return nil, fmt.Errorf("deepplan: unknown mode %q (want %q or %q)", mode, ModeStandard, ModeFull)
	}
}

// candidateMatrix is the exhaustive offer-one list both modes start
// from, in phase-2 execution order (spec §7.4): the version
// enumeration, then the forced-group ladder, the QUIC-plane rungs
// (PQ-25: gated on the observed QuicAttempted fact), the suite ×
// version matrix, the signature-scheme ladder, and the feature probes
// (cert, resumption incl. 0-RTT, hrr).
func candidateMatrix(obs Observed) []Probe {
	probes := make([]Probe, 0, 80)
	for _, v := range probeVersions {
		probes = append(probes, Probe{Name: "version/" + versionName(v), Kind: KindVersion, Payload: v})
	}
	for _, g := range probeGroups {
		probes = append(probes, Probe{
			Name:    "group/" + strconv.FormatUint(uint64(g), 10),
			Kind:    KindGroup,
			Payload: g,
		})
	}
	probes = append(probes, quicProbes(obs)...)
	for _, cs := range stdlibSuites() {
		for _, v := range cs.SupportedVersions {
			if v < tls.VersionTLS10 || v > tls.VersionTLS13 {
				continue
			}
			probes = append(probes, Probe{
				Name:    fmt.Sprintf("suite/%s@%s", cs.Name, versionName(v)),
				Kind:    KindSuite,
				Payload: SuiteOffer{Name: cs.Name, Version: v},
			})
		}
	}
	for _, s := range probeSigalgs {
		probes = append(probes, Probe{Name: "sigalg/" + sigalgName(s), Kind: KindSigalg, Payload: s})
	}
	probes = append(probes, Probe{Name: "cert/chain", Kind: KindCert})
	for _, label := range []string{ResTicket12, ResPSK13, Res0RTT13} {
		probes = append(probes, Probe{Name: "resumption/" + label, Kind: KindResumption, Payload: label})
	}
	probes = append(probes, Probe{Name: "hrr/x25519-shareless", Kind: KindHRR})
	return probes
}

// quicProbes is the deep-QUIC ladder (PQ-25, issue #48; PQ-69, issue
// #181): the group rungs over the QUIC plane — the negotiated-group
// anchor rung first (the TCP profile's negotiated group, verified on its
// own transport; named "quic/negotiated-<g>"), then the registry's
// 4585–4590 block rungs in IANA order ("quic/<g>"), the negotiated
// payload deduped away, then the two non-group rungs of the PQ-69 census
// ("quic/v2": the RFC 9369 transport-version rung; "quic/h3-exchange":
// the functional HTTP/3 rung). The rungs plan ONLY when the observed
// QuicAttempted fact says the profile's hint-gated QUIC lane ran;
// -quic-off and unhinted targets plan none. The executor maps each rung
// onto quicx's probes and lands the non-stdlib group rungs as honest
// refused findings (the UDP plane has no share-less raw path — the #101
// discipline, spec §5.3's v1 deferral).
func quicProbes(obs Observed) []Probe {
	if !obs.QuicAttempted {
		return nil
	}
	var rungs []uint32
	if obs.NegotiatedGroup != 0 {
		rungs = append(rungs, obs.NegotiatedGroup) // the anchor rides first
	}
	for _, g := range quicGroups {
		if g != obs.NegotiatedGroup {
			rungs = append(rungs, g)
		}
	}
	probes := make([]Probe, 0, len(rungs)+2)
	for _, g := range rungs {
		name := "quic/" + strconv.FormatUint(uint64(g), 10)
		if g == obs.NegotiatedGroup {
			name = "quic/negotiated-" + strconv.FormatUint(uint64(g), 10)
		}
		probes = append(probes, Probe{Name: name, Kind: KindQuic, Payload: g})
	}
	// The PQ-69 rungs ride after the block, in fixed order (the plan is
	// data; the executor dispatches by the payload's type switch).
	probes = append(probes,
		Probe{Name: "quic/v2", Kind: KindQuic, Payload: QuicRungV2},
		Probe{Name: "quic/h3-exchange", Kind: KindQuic, Payload: QuicRungH3Exchange},
	)
	return probes
}

// stdlibSuites is the complete suite vocabulary the handshake plane can
// construct: the secure list AND the insecure one (RC4/3DES/CBC
// acceptance is exactly the fact a cipher scanner records — the
// InsecureCipherSuites half is mandatory, not optional).
func stdlibSuites() []*tls.CipherSuite {
	return append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
}

// pruneStandard fact-prunes the candidate list for obs and cuts the
// remainder to the budget along the documented priority order. The
// priority (first cut first, whole classes; the budget is an upper
// bound):
//
//  1. negotiated-suite-adjacent suites first — suite probes on the
//     observed version in the negotiated suite's (kex, auth) family:
//     the profile handshake already sampled that neighbourhood, and
//     per spec §7.4 "a suite already negotiating" is the most redundant
//     probe land;
//  2. the remaining suite probes on the observed version;
//  3. all remaining suite probes — the offer-one matrix is the bulk of
//     any deep pass and its information rides behind the structural
//     ladders;
//  4. version probes for versions other than the observed one (with no
//     observed version this class is skipped: the floor facts stay);
//  5. the classic sigalg probes (the ML-DSA ladder always stays — the
//     PQ ladder runs even on classic servers, spec §7.4);
//  6. the basic resumption vectors (ticket, psk — 0-RTT stays, it is
//     the headline-era fact).
//
// Never pruned: the forced-group ladder, the ML-DSA sigalgs, the cert
// probe, the 0-RTT and hrr probes. A candidate that still exceeds the
// budget after every class is a programming error in the static matrix —
// the guard reports it rather than silently dropping the PQ core.
func pruneStandard(in []Probe, observed Observed, budget int) ([]Probe, error) {
	probes := factPrune(in, observed)
	for _, cut := range []func([]Probe, Observed) []Probe{
		cutAdjacentSuites,
		cutSuitesOnObservedVersion,
		cutAllSuites,
		cutForeignVersions,
		cutClassicSigalgs,
		cutBasicResumption,
	} {
		if len(probes) <= budget {
			break
		}
		probes = cut(probes, observed)
	}
	if len(probes) > budget {
		return nil, fmt.Errorf(
			"deepplan: standard candidate exceeds budget %d even after the documented prune classes: %d remain (the group ladder, the QUIC-plane rungs, mldsa sigalgs, 0-RTT, hrr and cert probes must not be silently cut)",
			budget, len(probes))
	}
	return probes, nil
}

// factPrune removes the probes the FAST-mode record already answered
// (spec §7.4 phase 1): the negotiated (suite, version) pair, the
// negotiated group, the negotiated version, and the cert probe when the
// fast handshake fetched the certificate. Prunes are physical — no
// placeholder rows.
func factPrune(in []Probe, obs Observed) []Probe {
	probes := make([]Probe, 0, len(in))
	for _, p := range in {
		if obs.NegotiatedSuite != "" && obs.Version != 0 && p.Kind == KindSuite {
			if o, ok := p.Payload.(SuiteOffer); ok && o.Name == obs.NegotiatedSuite && o.Version == obs.Version {
				continue // the profile handshake negotiated exactly this pair
			}
		}
		if obs.NegotiatedGroup != 0 && p.Kind == KindGroup {
			if g, ok := p.Payload.(uint32); ok && g == obs.NegotiatedGroup {
				continue
			}
		}
		if obs.Version != 0 && p.Kind == KindVersion {
			if v, ok := p.Payload.(uint16); ok && v == obs.Version {
				continue
			}
		}
		if obs.HasCert && p.Kind == KindCert {
			continue
		}
		if obs.QuicNegotiated != 0 && p.Kind == KindQuic {
			// The QUIC plane already answered this rung in the
			// profile's own probe (spec §7.4 phase 1 — the group the
			// profile handshake answered is never re-run, on either
			// plane). The match is uint32-typed: the PQ-69 string
			// rungs (quic/v2, quic/h3-exchange) never collide with a
			// group codepoint and never prune.
			if g, ok := p.Payload.(uint32); ok && g == obs.QuicNegotiated {
				continue
			}
		}
		probes = append(probes, p)
	}
	return probes
}

// cutAdjacentSuites applies priority class 1: suites on the observed
// version in the negotiated suite's family.
func cutAdjacentSuites(probes []Probe, obs Observed) []Probe {
	if obs.NegotiatedSuite == "" || obs.Version == 0 {
		return probes // no adjacency anchor
	}
	family := suiteFamily(obs.NegotiatedSuite)
	return filter(probes, func(p Probe) bool {
		o, ok := p.Payload.(SuiteOffer)
		return !(ok && o.Version == obs.Version && suiteFamily(o.Name) == family)
	})
}

// cutSuitesOnObservedVersion applies priority class 2.
func cutSuitesOnObservedVersion(probes []Probe, obs Observed) []Probe {
	if obs.Version == 0 {
		return probes // no version anchor: nothing is on "the observed version"
	}
	return filter(probes, func(p Probe) bool {
		o, ok := p.Payload.(SuiteOffer)
		return !(ok && o.Version == obs.Version)
	})
}

// cutAllSuites applies priority class 3 (the offer-one bulk).
func cutAllSuites(probes []Probe, obs Observed) []Probe {
	return filter(probes, func(p Probe) bool { return p.Kind != KindSuite })
}

// cutForeignVersions applies priority class 4; unobserved versions keep
// the whole floor enumeration.
func cutForeignVersions(probes []Probe, obs Observed) []Probe {
	if obs.Version == 0 {
		return probes
	}
	return filter(probes, func(p Probe) bool {
		v, ok := p.Payload.(uint16)
		return !(ok && p.Kind == KindVersion && v != obs.Version)
	})
}

// cutClassicSigalgs applies priority class 5 (the ML-DSA ladder stays).
func cutClassicSigalgs(probes []Probe, obs Observed) []Probe {
	return filter(probes, func(p Probe) bool {
		if p.Kind != KindSigalg {
			return true
		}
		s, ok := p.Payload.(uint16)
		return ok && mldsaSchemes[s]
	})
}

// cutBasicResumption applies priority class 6 (0-RTT stays).
func cutBasicResumption(probes []Probe, obs Observed) []Probe {
	basic := map[string]bool{ResTicket12: true, ResPSK13: true}
	return filter(probes, func(p Probe) bool {
		if p.Kind != KindResumption {
			return true
		}
		s, ok := p.Payload.(string)
		return ok && !basic[s]
	})
}

// filter rebuilds the probe list keeping the entries the keep predicate
// admits.
func filter(in []Probe, keep func(Probe) bool) []Probe {
	out := make([]Probe, 0, len(in))
	for _, p := range in {
		if keep(p) {
			out = append(out, p)
		}
	}
	return out
}

// suiteFamily groups a suite name by its (kex, auth) shape from the
// IANA name prefixes; TLS 1.3 names carry no kex/auth segments and fall
// in "other".
func suiteFamily(name string) string {
	switch {
	case strings.HasPrefix(name, "TLS_ECDHE_RSA_"):
		return "ecdhe-rsa"
	case strings.HasPrefix(name, "TLS_ECDHE_ECDSA_"):
		return "ecdhe-ecdsa"
	case strings.HasPrefix(name, "TLS_RSA_"):
		return "rsa-kex"
	default:
		return "other"
	}
}

// versionName prints a TLS version code in the plan's probe names.
func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("%04x", v)
	}
}

// sigalgName prints a signature scheme code in the plan's probe names.
func sigalgName(s uint16) string {
	if n, ok := sigalgNames[s]; ok {
		return n
	}
	return fmt.Sprintf("0x%04x", s)
}
