// Package deepplan builds per-target deep-mode probe plans (spec §7.4,
// PQ-20): the pure offer-one spec the executor hands to the handshake
// plane. A plan is data, never execution: Build turns a target + mode +
// the FAST-mode record's facts (Observed) into a deterministic probe list.
//
// Modes:
//   - standard: the exhaustive candidate matrix with the profile
//     handshake's facts pruned (a suite already negotiating is skipped —
//     spec §7.4 phase 2) and the remainder cut to the default budget (24
//     probes) along the documented prune priority: the negotiated
//     suite's adjacency goes first; the forced-group ladder and the PQ
//     sigalgs survive longest — the PQ ladder runs even on classic
//     servers (spec §7.4).
//   - full: the COMPLETE offer-one matrix, unpruned — every stdlib
//     suite × supported-version pair the handshake plane can construct,
//     the registry's forced-group blocks (4585–4590, 25–29), the
//     signature-scheme ladder (classic + ML-DSA), and the feature
//     probes: resumption + 0-RTT + HRR.
//
// The offer-one principle (spec §7.4): each suite probe is its OWN
// handshake — offer exactly one suite, observe whether the server
// accepts it. The plan is the pure spec of those handshakes; the
// executor wiring (its own PQ-20 pair) maps payloads onto engine calls.
//
// RED stub (ADR-0002): the type surface the tests compile against;
// Build and pruneStandard return errNotImplemented until GREEN.
package deepplan

import "errors"

// Probe kinds (the deep-mode phase-2 vocabulary, spec §7.4).
const (
	KindVersion    = "version"
	KindSuite      = "suite"
	KindGroup      = "group"
	KindSigalg     = "sigalg"
	KindCert       = "cert"
	KindResumption = "resumption"
	KindHRR        = "hrr"
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

// Observed carries the FAST-mode record's facts (spec §7.4 phase 1: one
// handshake whose result prunes phase 2). Zero values mean unknown; a
// nil *Observed means no facts at all.
type Observed struct {
	NegotiatedGroup uint32 // negotiated key-exchange group code (0 = unknown)
	NegotiatedSuite string // negotiated cipher suite name ("" = unknown)
	Version         uint16 // negotiated TLS version code (0 = unknown)
	HasCert         bool   // the fast handshake already fetched the certificate
}

// SuiteOffer is the concrete spec of a suite probe: one suite offered on
// one forced protocol version (the offer-one unit of the matrix).
type SuiteOffer struct {
	Name    string // IANA cipher suite name as the stdlib reports it
	Version uint16 // the forced protocol version for this offer
}

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

// errNotImplemented is the RED stub's sentinel (ADR-0002): the tests
// compile against this surface and fail on assertions, not compilation.
var errNotImplemented = errors.New("deepplan: not implemented")

// Build returns one target's deep-mode probe plan.
func Build(target string, mode string, observed *Observed) (*Plan, error) {
	return nil, errNotImplemented
}

// pruneStandard fact-prunes the candidate list for obs and cuts the
// remainder to the budget along the documented priority order.
func pruneStandard(probes []Probe, observed Observed, budget int) ([]Probe, error) {
	return probes, errNotImplemented
}
