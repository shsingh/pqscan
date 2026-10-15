// Package classify holds the IANA-derived taxonomy: supported groups,
// signature schemes and certificate OID classes (spec §5.6, Appendix A).
//
// Substrate stub (PQ-04): the classification constants plus the initial
// hand-maintained group table with snapshot provenance. The regeneration
// pipeline (registry CSV -> generated table, snapshot date committed)
// lands with PQ-08's IANA-regen work; this table must never drift into
// hand-edits after that point (AGENTS.md, registry rule).
package classify

// Class is the per-observation PQC taxonomy (spec §5.6).
type Class string

const (
	ClassPQ        Class = "pq_pure"         // modern PQ primitive alone
	ClassPQHybrid  Class = "pq_hybrid"       // PQ + classical combiner, standards track
	ClassPQHybridD Class = "pq_hybrid_draft" // pre-standards hybrid (compatibility oracle)
	ClassHybridSM  Class = "hybrid_sm"       // SM-family hybrids (4590)
	ClassClassic   Class = "classic"         // X25519, P-256/P-384, RSA, FFDHE
	ClassObsolete  Class = "obsolete"        // RSA kex, RC4 era, non-compliant
)

// groupClass maps IANA supported-group codepoints to classes.
// Snapshot provenance: IANA TLS Supported Groups registry as observed
// 2026-10-15 while drafting the spec (see RFC 10024 for 4587–4589).
var groupClass = map[uint32]Class{
	4585:  ClassPQHybrid,  // SecP256r1MLKEM512
	4586:  ClassPQHybrid,  // MLKEM512X25519
	4587:  ClassPQHybrid,  // SecP256r1MLKEM768
	4588:  ClassPQHybrid,  // X25519MLKEM768
	4589:  ClassPQHybrid,  // SecP384r1MLKEM1024
	4590:  ClassHybridSM,  // curveSM2MLKEM768
	25497: ClassPQHybridD, // X25519Kyber768Draft00 (obsolete — compat oracle)
	25498: ClassPQHybridD, // SecP256r1Kyber768Draft00 (same)
	29:    ClassClassic,   // x25519
	23:    ClassClassic,   // secp256r1
	24:    ClassClassic,   // secp384r1
	1024:  ClassObsolete,  // RSA kex family marker (1024-bit era)
}

// GroupClass returns the taxonomy class for a supported-group codepoint.
// Unknown codepoints classify as ClassClassic with the caller responsible
// for surfacing "unknown" where the CLI prints it; engines never invent a
// PQ verdict for an unrecognised group.
func GroupClass(id uint32) (Class, bool) {
	c, ok := groupClass[id]
	return c, ok
}
