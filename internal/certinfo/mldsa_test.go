//go:build go1.27

package certinfo

// Toolchain-floor record for PQ-21 (honest, tagged): crypto/mldsa is a
// go1.27 API — the repo floor (go.mod go1.26.0) cannot generate or express
// real in-process ML-DSA key material, so the main fixture set exercises
// the OID-table path via hand-built (DER-re-labeled) OID cases. This file
// compiles only on go1.27+ toolchains and pins the SAME classification
// against GENUINELY ML-DSA-SIGNED certificates produced through
// x509.CreateCertificate + crypto/mldsa, so the OID-shape fixtures above
// are anchored to real-world cert encodings wherever the toolchain allows.
// CI (go1.26.x) excludes this file; the offline suite never depends on it.

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func mustCertGo127(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}

// TestAnalyzeRealMLDSACertChain generates a genuine ML-DSA-signed
// certificate chain in-process (needs go1.27+) and pins the analytics.
func TestAnalyzeRealMLDSACertChain(t *testing.T) {
	mld, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("mldsa key gen: %v", err)
	}
	caTmpl := func(cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(21),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}
	root := mustCertGo127(t, caTmpl("pqscan-mldsa65-real-root"), caTmpl("pqscan-mldsa65-real-root"), mld.Public(), mld)
	rsaLeafPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa leaf key: %v", err)
	}
	// ML-DSA-signed leaf over an RSA leaf key: signature AND issuer key are
	// real ML-DSA-65 (RFC 9881); the leaf's own SPKI is classical RSA.
	leaf := mustCertGo127(t, &x509.Certificate{
		SerialNumber: big.NewInt(22),
		Subject:      pkix.Name{CommonName: "pqscan-mldsa65-real-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, root, &rsaLeafPriv.PublicKey, mld)
	if leaf.SignatureAlgorithm != x509.MLDSA65 || root.SignatureAlgorithm != x509.MLDSA65 {
		t.Fatalf("sanity: generated certs not ML-DSA-65 (leaf=%v root=%v)", leaf.SignatureAlgorithm, root.SignatureAlgorithm)
	}

	info, err := Analyze([]*x509.Certificate{leaf, root})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if info.SigAlg != "2.16.840.1.101.3.4.3.18" || info.SigAlgName != "ML-DSA-65" {
		t.Fatalf("SigAlg = %q/%q, want the RFC 9881 ML-DSA-65 OID + name", info.SigAlg, info.SigAlgName)
	}
	if !info.SigAlgPQ {
		t.Fatalf("SigAlgPQ = false, want true for the genuinely signed ML-DSA-65 leaf")
	}
	if info.KeyAlg != "RSA" || info.KeyAlgPQ {
		t.Fatalf("KeyAlg = %q/%v, want RSA/false", info.KeyAlg, info.KeyAlgPQ)
	}
	// leaf sig=PQ(.18), leaf key=RSA; root sig=PQ(.18), root key=PQ(.18)
	// → all signatures PQ → dual must stay FALSE (no classical member).
	if info.DualCert {
		t.Fatalf("DualCert = true, want false (all signatures PQ)")
	}
	if len(info.PQOIDs) != 1 || info.PQOIDs[0] != "2.16.840.1.101.3.4.3.18" {
		t.Fatalf("PQOIDs = %v, want exactly the ML-DSA-65 OID once (key+sig dedup)", info.PQOIDs)
	}

	// ML-DSA-44-pinned anchor through the same generation path: a leaf whose
	// own key is ML-DSA-44 signed by the ML-DSA-65 root — two PQ parameter
	// sets must surface as two PQ OIDs, both names from the table.
	mld44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa44 key gen: %v", err)
	}
	leaf44 := mustCertGo127(t, &x509.Certificate{
		SerialNumber: big.NewInt(23),
		Subject:      pkix.Name{CommonName: "pqscan-mldsa44-real-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, root, mld44.Public(), mld44)
	info44, err := Analyze([]*x509.Certificate{leaf44, root})
	if err != nil {
		t.Fatalf("analyze 44: %v", err)
	}
	if info44.SigAlg != "2.16.840.1.101.3.4.3.17" || info44.SigAlgName != "ML-DSA-44" {
		t.Fatalf("SigAlg = %q/%q, want the ML-DSA-44 anchor", info44.SigAlg, info44.SigAlgName)
	}
	if !info44.KeyAlgPQ || info44.KeyAlg != "ML-DSA-44" {
		t.Fatalf("KeyAlg = %q/%v, want ML-DSA-44/PQ", info44.KeyAlg, info44.KeyAlgPQ)
	}
}
