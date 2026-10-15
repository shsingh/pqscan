// Package probe builds and executes per-target probe plans (spec §7.4).
//
// Substrate stub (PQ-04): the plan/type vocabulary only. The plan builder
// (profile handshake -> pruned phase-2 DAG) and the deadline ladder land
// in M1/M2 slices.
package probe

// Mode selects the probe family (spec §5.2).
type Mode string

const (
	ModeFast Mode = "fast" // one engineered handshake
	ModeDeep Mode = "deep" // gnutls-debug-style exhaustive plan
	ModePQ   Mode = "pq"   // forced PQ-group ladder + readiness verdict
)

// Probe is one scheduled handshake assertion (offer-one / observe-accept).
type Probe struct {
	Kind      string // "suite" | "group" | "sigalg" | "version" | "feature"
	Candidate string // the offered code point (suite/group/sigalg name)
}
