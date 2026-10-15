package certinfo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fixture building (all in-code; spec §10.1 fixture-first).
//
// RSA/ECDSA chains are genuinely key-signed via x509.CreateCertificate.
//
// PQ/hybrid/unknown algorithm shapes are hand-built OID cases as the issue
// prescribes, because x509 cannot sign with those algorithms and the
// toolchain floor (go.mod go1.26) predates crypto/mldsa (a go1.27 API —
// generating real ML-DSA certs was verified locally on go1.27.2, but is out
// of reach at the repo floor; that verification is pinned in mldsa_test.go,
// a //go:build go1.27 file). The OID cases are REAL certificate DER
// re-encoded with the relevant AlgorithmIdentifier OIDs swapped, honestly
// recorded below:
//
//   - both signature OIDs (TBS + outer) swapped: x509.ParseCertificate
//     ACCEPTS signature OIDs it does not know (unknown enumeration) —
//     verified on the toolchain in use;
//   - SPKI OID swapped to an ML-DSA OID: ParseCertificate REJECTS the
//     wrong-length key body ("ML-DSA key encoded with illegal parameters")
//     — verified — so key-side OID cases are consumed by Analyze as
//     raw-DER certificates (&x509.Certificate{Raw: der}), which is the
//     production contract input too (Analyze reads cert.Raw only).
//
// Analyze classifies by OIDs read from the DER, so every shape below
// exercises the same OID-table path a real ML-DSA/composite cert hits.
// ---------------------------------------------------------------------------

// algID mirrors a X.509 AlgorithmIdentifier.
type algID struct {
	Alg    asn1.ObjectIdentifier
	Params asn1.RawValue `asn1:"optional,tag:params"`
}

// spkiT mirrors SubjectPublicKeyInfo.
type spkiT struct {
	Alg algID
	Key asn1.BitString
}

// tbsT mirrors TBSCertificate (the fields needed to re-encode).
type tbsT struct {
	Raw      asn1.RawContent
	Version  int `asn1:"optional,tag:0,default:0,explicit"`
	Serial   *big.Int
	Sig      algID
	Issuer   asn1.RawValue
	Validity asn1.RawValue
	Subject  asn1.RawValue
	SPKI     spkiT
}

// certT mirrors the outer Certificate.
type certT struct {
	TBS  tbsT
	SigA algID
	SigV asn1.BitString
}

// mustCert creates + parses one certificate; signer is the ISSUER's key.
func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("create %s: %v", tmpl.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %v", tmpl.Subject.CommonName, err)
	}
	return cert
}

func caTmpl(cn string, serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
}

func leafTmpl(cn string, serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
}

// dottedOID converts a dotted string to an ASN.1 ObjectIdentifier.
func dottedOID(s string) (asn1.ObjectIdentifier, error) {
	chunks := strings.Split(s, ".")
	out := make(asn1.ObjectIdentifier, 0, len(chunks))
	for _, c := range chunks {
		n, err := strconv.Atoi(c)
		if err != nil || n < 0 {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// relabelCert re-encodes real certificate DER with the signature
// AlgorithmIdentifier OIDs (both slots) and/or the SPKI algorithm OID
// swapped to the given dotted strings ("" = keep). When wantParse is true
// the re-encoded DER must still pass x509.ParseCertificate (the verified
// honest behavior for signature-side swaps); when false, ParseCertificate
// is expected to reject it (ML-DSA SPKI on a wrong-length body — the
// verified honest finding) and the fixture is delivered as a raw-DER
// certificate, a production contract input for Analyze.
func relabelCert(t *testing.T, cert *x509.Certificate, sigOID, spKIOID string, wantParse bool) *x509.Certificate {
	t.Helper()
	var c certT
	if _, err := asn1.Unmarshal(cert.Raw, &c); err != nil {
		t.Fatalf("tbs unmarshal: %v", err)
	}
	if sigOID != "" {
		oid, err := dottedOID(sigOID)
		if err != nil {
			t.Fatalf("bad signature oid %q: %v", sigOID, err)
		}
		c.TBS.Raw = nil // otherwise RawContent overrides the edited fields
		c.TBS.Sig.Alg = oid
		c.SigA.Alg = oid
	}
	if spKIOID != "" {
		oid, err := dottedOID(spKIOID)
		if err != nil {
			t.Fatalf("bad SPKI oid %q: %v", spKIOID, err)
		}
		c.TBS.Raw = nil
		c.TBS.SPKI.Alg.Alg = oid
	}
	der, err := asn1.Marshal(c)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	out, err := x509.ParseCertificate(der)
	if err != nil {
		if wantParse {
			t.Fatalf("parse relabeled cert: %v", err)
		}
		t.Logf("honest finding: relabeled DER rejected by ParseCertificate (%v); fixture delivered as raw-DER certificate", err)
		return &x509.Certificate{Raw: der}
	}
	if !wantParse {
		t.Fatalf("re-labeled DER parsed though the fixture wanted the raw-DER path")
	}
	return out
}

// buildClassicalChain: RSA leaf <- ECDSA intermediate <- RSA root.
// FULLY REAL (no relabeled OIDs): the leaf sig is ECDSA-SHA256 (EC issuer
// key), intermediate and root are sha256WithRSAEncryption. This is also the
// base for the hand-built OID cases below (real DER -> target OIDs).
func buildClassicalChain(t *testing.T) []*x509.Certificate {
	t.Helper()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	rsaRoot := mustCert(t, caTmpl("pqscan-rsa-root", 1), caTmpl("pqscan-rsa-root", 1), &rsaPriv.PublicKey, rsaPriv)
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec key: %v", err)
	}
	ecInter := mustCert(t, caTmpl("pqscan-ec-inter", 2), rsaRoot, &ecPriv.PublicKey, rsaPriv)
	rsaLeafPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa leaf key: %v", err)
	}
	leaf := mustCert(t, leafTmpl("pqscan-classical-leaf", 3), ecInter, &rsaLeafPriv.PublicKey, ecPriv)
	return []*x509.Certificate{leaf, ecInter, rsaRoot}
}

// buildAllPQChain: both members carry the same pure ML-DSA OID as
// signature AND key OID (RFC 9881: one OID per parameter set, used for key
// and signature) — the PQOIDs dedup case. Key-side relabels ride the
// raw-DER contract (see the honest findings note above).
func buildAllPQChain(t *testing.T) []*x509.Certificate {
	t.Helper()
	chain := buildClassicalChain(t)
	leaf := relabelCert(t, chain[0], "2.16.840.1.101.3.4.3.19", "2.16.840.1.101.3.4.3.19", false)
	root := relabelCert(t, chain[2], "2.16.840.1.101.3.4.3.19", "2.16.840.1.101.3.4.3.19", false)
	return []*x509.Certificate{leaf, root}
}

// tableEntry scans the owned table directly (no unexported analyzer helper
// under test needed for the table pins).
func tableEntry(oid string) (oidEntry, bool) {
	for _, e := range oidTable {
		if e.OID == oid {
			return e, true
		}
	}
	return oidEntry{}, false
}

// TestOIDTableWellFormed pins the OWNED table: unique parseable dotted
// OIDs, names, valid classes — plus the family anchors, written as string
// literals so a typo in an implementation const cannot validate itself.
func TestOIDTableWellFormed(t *testing.T) {
	if len(oidTable) == 0 {
		t.Fatalf("oidTable is empty: the owned PQ-21 table must carry rows")
	}
	seen := map[string]bool{}
	for _, e := range oidTable {
		if seen[e.OID] {
			t.Fatalf("duplicate table row for OID %s", e.OID)
		}
		seen[e.OID] = true
		if e.Name == "" {
			t.Fatalf("table row %s carries no name", e.OID)
		}
		switch e.Class {
		case ClassClassical, ClassPQ, ClassHybrid:
			// valid
		default:
			t.Fatalf("table row %s carries invalid class %d", e.OID, e.Class)
		}
		oid, err := dottedOID(e.OID)
		if err != nil {
			t.Fatalf("table row OID %q is not parseable: %v", e.OID, err)
		}
		if got := oid.String(); got != e.OID {
			t.Fatalf("table row OID %q does not round-trip through ASN.1 (%q)", e.OID, got)
		}
		if len(oid) < 2 {
			t.Fatalf("table row OID %q must have at least two arcs", e.OID)
		}
	}

	// family anchors — pure PQ (RFC 9881 FIPS-204 ML-DSA / RFC 9909 FIPS-205
	// SLH-DSA): the same OID identifies key and signature per parameter set
	for oid, name := range map[string]string{
		"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
		"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
		"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
		"2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
		"2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
		"2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
	} {
		e, ok := tableEntry(oid)
		if !ok {
			t.Fatalf("pure PQ anchor OID %s (%s) missing from table", oid, name)
		}
		if e.Class != ClassPQ {
			t.Fatalf("anchor %s classified %d, want ClassPQ", oid, e.Class)
		}
		if e.Name != name {
			t.Fatalf("anchor %s named %q, want %q", oid, e.Name, name)
		}
	}

	// HashSLH-DSA (RFC 9909 pre-hash variant) stays in the PQ family
	if e, ok := tableEntry("2.16.840.1.101.3.4.3.35"); !ok || e.Class != ClassPQ {
		t.Fatalf("HashSLH-DSA OID 2.16.840.1.101.3.4.3.35: ok=%v class=%d, want present+ClassPQ", ok, e.Class)
	}

	// composite hybrid anchors (IANA PKIX alg arc 1.3.6.1.5.5.7.6,
	// draft-ietf-lamps-pq-composite-sigs-13/-14): the whole verified span
	// 37..53 of the COMPSIG-MLDSA set
	for n := 37; n <= 53; n++ {
		oid := "1.3.6.1.5.5.7.6." + strconv.Itoa(n)
		e, ok := tableEntry(oid)
		if !ok {
			t.Fatalf("composite anchor OID %s missing from table", oid)
		}
		if e.Class != ClassHybrid {
			t.Fatalf("composite anchor %s classified %d, want ClassHybrid", oid, e.Class)
		}
	}
	e41, ok := tableEntry("1.3.6.1.5.5.7.6.41")
	if !ok || e41.Name != "MLDSA65-RSA3072-PSS-SHA512" {
		t.Fatalf("composite 1.3.6.1.5.5.7.6.41: name=%q ok=%v, want MLDSA65-RSA3072-PSS-SHA512", e41.Name, ok)
	}

	// classical anchors
	for oid, name := range map[string]string{
		"1.2.840.113549.1.1.1":  "RSA",
		"1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
		"1.2.840.113549.1.1.10": "RSASSA-PSS",
		"1.2.840.10045.2.1":     "ECDSA",
		"1.2.840.10045.4.3.2":   "ecdsa-with-SHA256",
		"1.3.101.112":           "Ed25519",
		"1.2.840.10040.4.1":     "DSA",
	} {
		e, ok := tableEntry(oid)
		if !ok {
			t.Fatalf("classical anchor OID %s (%s) missing from table", oid, name)
		}
		if e.Class != ClassClassical {
			t.Fatalf("anchor %s classified %d, want ClassClassical", oid, e.Class)
		}
		if e.Name != name {
			t.Fatalf("anchor %s named %q, want %q", oid, e.Name, name)
		}
	}

	// FN-DSA/Falcon has no assigned X.509 OID as of this table (IETF draft
	// stage, lamps-wg/fn-dsa-certificates): the table must not carry an
	// invented one — this pin guards the absence.
	if _, ok := tableEntry("1.3.6.1.4.1.58216"); ok {
		t.Fatalf("invented non-registry OID must not be in the table")
	}
}

// TestAnalyzeClassicalRSALeaf pins the analytics for the fully-real
// RSA/ECDSA chain: leaf RSA key, ECDSA-SHA256 signature, nothing PQ,
// dual-cert false, leaf times surfaced.
func TestAnalyzeClassicalRSALeaf(t *testing.T) {
	chain := buildClassicalChain(t)
	info, err := Analyze(chain)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if info.Subject != "CN=pqscan-classical-leaf" {
		t.Fatalf("Subject = %q, want the leaf's CN only", info.Subject)
	}
	if info.Issuer != "CN=pqscan-ec-inter" {
		t.Fatalf("Issuer = %q, want the direct issuer's CN", info.Issuer)
	}
	if info.SigAlg != "1.2.840.10045.4.3.2" {
		t.Fatalf("SigAlg = %q, want the ecdsa-with-SHA256 dotted OID", info.SigAlg)
	}
	if info.SigAlgName != "ecdsa-with-SHA256" {
		t.Fatalf("SigAlgName = %q, want ecdsa-with-SHA256", info.SigAlgName)
	}
	if info.SigAlgPQ {
		t.Fatalf("SigAlgPQ = true, want false for a classical chain")
	}
	if info.KeyAlg != "RSA" {
		t.Fatalf("KeyAlg = %q, want RSA (the leaf's key alg, not the signer's)", info.KeyAlg)
	}
	if info.KeyAlgPQ {
		t.Fatalf("KeyAlgPQ = true, want false for a classical chain")
	}
	if info.DualCert {
		t.Fatalf("DualCert = true, want false: all-signatures-classical chain")
	}
	if len(info.PQOIDs) != 0 {
		t.Fatalf("PQOIDs = %v, want none", info.PQOIDs)
	}
	if !info.NotBefore.After(time.Now().Add(-2*time.Hour)) || !info.NotAfter.After(time.Now()) {
		t.Fatalf("NotBefore/NotAfter not surfaced from the leaf: %v / %v", info.NotBefore, info.NotAfter)
	}
}

// TestAnalyzeLeafSubjectWins pins that chain[0] is the analytics leaf
// (subject/issuer read from the first member, not the root).
func TestAnalyzeLeafSubjectWins(t *testing.T) {
	chain := buildClassicalChain(t)
	info, err := Analyze(chain)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if info.Subject != "CN=pqscan-classical-leaf" && info.Subject == info.Issuer {
		t.Fatalf("Subject = %q Issuer = %q: the delivered leaf must win", info.Subject, info.Issuer)
	}
	if info.Subject != "CN=pqscan-classical-leaf" {
		t.Fatalf("Subject = %q, want the delivered leaf's CN", info.Subject)
	}
}

// TestAnalyzePQSigLeafWithClassicalIssuers pins the hand-built ML-DSA OID
// case (the issue's issue-case "leaf PQ-sig + issuer classical = still
// dual"): the leaf's signature OID re-labeled to ML-DSA-65 over a fully
// real classical chain. Expectations: leaf sig classified PQ by OID with
// the table name, leaf RSA key classified classical, dual-cert TRUE, PQ
// OID recorded.
func TestAnalyzePQSigLeafWithClassicalIssuers(t *testing.T) {
	chain := buildClassicalChain(t)
	leaf := relabelCert(t, chain[0], "2.16.840.1.101.3.4.3.18", "", true)
	chained := []*x509.Certificate{leaf, chain[1], chain[2]}
	info, err := Analyze(chained)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if info.SigAlg != "2.16.840.1.101.3.4.3.18" {
		t.Fatalf("SigAlg = %q, want the ML-DSA-65 dotted OID", info.SigAlg)
	}
	if info.SigAlgName != "ML-DSA-65" {
		t.Fatalf("SigAlgName = %q, want ML-DSA-65", info.SigAlgName)
	}
	if !info.SigAlgPQ {
		t.Fatalf("SigAlgPQ = false, want true for the ML-DSA-65 signature OID")
	}
	if info.KeyAlg != "RSA" || info.KeyAlgPQ {
		t.Fatalf("KeyAlg = %q KeyAlgPQ = %v, want RSA/false (leaf key is RSA)", info.KeyAlg, info.KeyAlgPQ)
	}
	if !info.DualCert {
		t.Fatalf("DualCert = false, want true: leaf PQ-sig with classical-signed issuers")
	}
	found := false
	for _, oid := range info.PQOIDs {
		if oid == "2.16.840.1.101.3.4.3.18" {
			found = true
		}
	}
	if !found {
		t.Fatalf("PQOIDs %v does not contain the ML-DSA-65 OID", info.PQOIDs)
	}
}

// TestAnalyzeClassicalLeafOverPQIssuers pins the mirrored dual case: a
// classical leaf signature with PQ-OID members above it (the estate
// framing's "PQ signature anywhere").
func TestAnalyzeClassicalLeafOverPQIssuers(t *testing.T) {
	chain := buildClassicalChain(t)
	inter := relabelCert(t, chain[1], "2.16.840.1.101.3.4.3.18", "", true)
	root := relabelCert(t, chain[2], "2.16.840.1.101.3.4.3.18", "", true)
	chained := []*x509.Certificate{chain[0], inter, root}
	info, err := Analyze(chained)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if info.SigAlgPQ {
		t.Fatalf("SigAlgPQ = true, want false (leaf sig is classical)")
	}
	if !info.DualCert {
		t.Fatalf("DualCert = false, want true: classical leaf with PQ-signed members above")
	}
	if len(info.PQOIDs) != 1 || info.PQOIDs[0] != "2.16.840.1.101.3.4.3.18" {
		t.Fatalf("PQOIDs = %v, want exactly the ML-DSA-65 OID once (dedup)", info.PQOIDs)
	}
}

// TestAnalyzeAllPQChain pins the pure-PQ hand-built chain: signature AND
// key OIDs re-labeled to ML-DSA-87 on both members (key-side relabels ride
// the raw-DER contract per the honest ParseCertificate finding). PQOIDs
// must dedup to exactly one row; the dual rule must stay false.
func TestAnalyzeAllPQChain(t *testing.T) {
	chain := buildAllPQChain(t)
	info, err := Analyze(chain)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !info.SigAlgPQ || !info.KeyAlgPQ {
		t.Fatalf("SigAlgPQ = %v KeyAlgPQ = %v, want true/true", info.SigAlgPQ, info.KeyAlgPQ)
	}
	if info.KeyAlg != "ML-DSA-87" {
		t.Fatalf("KeyAlg = %q, want ML-DSA-87", info.KeyAlg)
	}
	if info.DualCert {
		t.Fatalf("DualCert = true, want false: no classical signature anywhere in a pure PQ chain")
	}
	if len(info.PQOIDs) != 1 || info.PQOIDs[0] != "2.16.840.1.101.3.4.3.19" {
		t.Fatalf("PQOIDs = %v, want exactly [2.16.840.1.101.3.4.3.19] (dedup)", info.PQOIDs)
	}
}

// TestAnalyzePQKeyUnderClassicalSig pins the issuer-key shape: a
// classical-signed member carrying an ML-DSA SPKI (the transitional
// key-deployment case) must surface its PQ key in PQOIDs while the leaf's
// KeyAlg stays the LEAF's own RSA — the issuer's key must not leak.
func TestAnalyzePQKeyUnderClassicalSig(t *testing.T) {
	chain := buildClassicalChain(t)
	leaf := relabelCert(t, chain[0], "2.16.840.1.101.3.4.3.18", "", true)
	inter := relabelCert(t, chain[1], "", "2.16.840.1.101.3.4.3.18", false)
	info, err := Analyze([]*x509.Certificate{leaf, inter, chain[2]})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if info.KeyAlg != "RSA" {
		t.Fatalf("KeyAlg = %q, want the LEAF's RSA (issuer's ML-DSA key must not leak)", info.KeyAlg)
	}
	if info.KeyAlgPQ {
		t.Fatalf("KeyAlgPQ = true, want false: the leaf's own key is RSA")
	}
	if !info.DualCert {
		t.Fatalf("DualCert = false, want true: leaf PQ-sig with classical-signed members")
	}
	if len(info.PQOIDs) != 1 || info.PQOIDs[0] != "2.16.840.1.101.3.4.3.18" {
		t.Fatalf("PQOIDs = %v, want exactly [2.16.840.1.101.3.4.3.18] (leaf sig + issuer key dedup)", info.PQOIDs)
	}
}

// TestAnalyzeCompositeHybrid pins the composite row: x509 cannot sign with
// the composite algorithm, so the fixture is real RSA DER re-labeled to the
// IANA composite OID; the table must classify it hybrid (PQ signal) and the
// dual rule must see the classical-signed members behind it.
func TestAnalyzeCompositeHybrid(t *testing.T) {
	chain := buildClassicalChain(t)
	leaf := relabelCert(t, chain[0], "1.3.6.1.5.5.7.6.41", "", true)
	chained := []*x509.Certificate{leaf, chain[1], chain[2]}
	info, err := Analyze(chained)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if info.SigAlg != "1.3.6.1.5.5.7.6.41" {
		t.Fatalf("SigAlg = %q, want the composite MLDSA65-RSA3072-PSS-SHA512 OID", info.SigAlg)
	}
	if info.SigAlgName != "MLDSA65-RSA3072-PSS-SHA512" {
		t.Fatalf("SigAlgName = %q, want the composite name", info.SigAlgName)
	}
	if !info.SigAlgPQ {
		t.Fatalf("SigAlgPQ = false, want true: a composite hybrid carries a PQ component")
	}
	if !info.DualCert {
		t.Fatalf("DualCert = false, want true: hybrid leaf above classical-signed members")
	}
	found := false
	for _, oid := range info.PQOIDs {
		if oid == "1.3.6.1.5.5.7.6.41" {
			found = true
		}
	}
	if !found {
		t.Fatalf("PQOIDs %v does not contain the composite OID", info.PQOIDs)
	}

	// single-member composite chain: no classical-signature member, so the
	// dual-cert rule stays false for the chain view (the intra-cert hybrid
	// component is not a chain member)
	solo, err := Analyze([]*x509.Certificate{leaf})
	if err != nil {
		t.Fatalf("analyze solo composite: %v", err)
	}
	if solo.DualCert {
		t.Fatalf("solo composite DualCert = true, want false for the chain-view rule")
	}
}

// TestAnalyzeUnknownOIDNeverCrashes pins the unknown contract: unknown
// signature OIDs are recorded verbatim, never claimed PQ, never claimed
// classical, and the name carries the unknown note — no crash, no panic.
func TestAnalyzeUnknownOIDNeverCrashes(t *testing.T) {
	chain := buildClassicalChain(t)
	leaf := relabelCert(t, chain[0], "1.3.6.1.4.1.99999.1.2", "", true)
	info, err := Analyze([]*x509.Certificate{leaf, chain[1], chain[2]})
	if err != nil {
		t.Fatalf("analyze must not fail on unknown OIDs: %v", err)
	}
	if info.SigAlg != "1.3.6.1.4.1.99999.1.2" {
		t.Fatalf("SigAlg = %q, want the unknown OID verbatim", info.SigAlg)
	}
	if info.SigAlgPQ {
		t.Fatalf("SigAlgPQ = true, want false for an unknown OID")
	}
	if !strings.HasPrefix(info.SigAlgName, "unknown") || !strings.Contains(info.SigAlgName, "1.3.6.1.4.1.99999.1.2") {
		t.Fatalf("SigAlgName = %q, want an unknown note carrying the OID", info.SigAlgName)
	}
	if info.DualCert {
		t.Fatalf("DualCert = true, want false: unknown OIDs contribute to neither side")
	}
	if len(info.PQOIDs) != 0 {
		t.Fatalf("PQOIDs = %v, want none for an unknown chain", info.PQOIDs)
	}
}

// TestAnalyzeEmptyChain pins the graceful non-crash on empty input.
func TestAnalyzeEmptyChain(t *testing.T) {
	info, err := Analyze(nil)
	if err == nil {
		t.Fatalf("Analyze(nil) must error, got info %+v", info)
	}
	if info != nil {
		t.Fatalf("Analyze(nil) must return a nil info on error, got %+v", info)
	}
}
