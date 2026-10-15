// Package certinfo classifies X.509 certificate chains by their algorithm
// OIDs — the PQ-21 certificate PQ-analytics core. For a delivered peer chain
// it reports the leaf's subject/issuer/validity, the leaf's signature and key
// algorithms classified against an OWNED algorithm table (dotted-string OIDs,
// names, classes), the set of PQ-oid-bearing algorithms present across the
// chain, and whether the chain mixes signature eras (dual-cert signal).
//
// The algorithm table is owned here as a testable const + slice table.
// Unknown OIDs are recorded (never crashed on): they are classified
// classical=false,false — i.e. not claimed PQ and not claimed classical —
// with the name carrying an "unknown-…" note so downstream code can
// distinguish "known classical" from "saw an OID we do not know".
package certinfo

import (
	"crypto/x509"
	"errors"
	"time"
)

// Algorithm classes in the owned OID table.
const (
	ClassClassical = iota // RSA / ECDSA / Ed25519 / DSA families
	ClassPQ               // pure PQ: ML-DSA, SLH-DSA (FN-DSA entries land when IANA assigns OIDs)
	ClassHybrid           // composite PQ/T hybrids (composite ML-DSA, IANA PKIX arc)
)

// oidEntry is one row of the owned OID table.
type oidEntry struct {
	OID   string // dotted string, exactly as NIST/IANA registered
	Name  string // human name reported in the Name fields
	Class int    // ClassClassical | ClassPQ | ClassHybrid
}

// oidTable is the PQ-21 owned algorithm table under test. Watched-RED stub:
// intentionally EMPTY so the table/analysis tests fail on missing rows, not
// on compile errors (ADR-0002). The GREEN commit fills the rows.
var oidTable = []oidEntry{}

// Info is the analytics row for one parsed certificate chain.
type Info struct {
	Subject    string
	Issuer     string
	SigAlg     string
	SigAlgPQ   bool
	SigAlgName string
	KeyAlg     string
	KeyAlgPQ   bool
	DualCert   bool
	PQOIDs     []string
	NotBefore  time.Time
	NotAfter   time.Time
}

// Analyze classifies the leaf and walks the delivered chain. PQ-21
// watched-RED stub: returns not-implemented until the GREEN commit.
func Analyze(chain []*x509.Certificate) (*Info, error) {
	return nil, errors.New("certinfo: not implemented (PQ-21 watched-RED stub)")
}
