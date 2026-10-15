// Package certinfo classifies X.509 certificate chains by their algorithm
// OIDs — the PQ-21 certificate PQ-analytics core. For a delivered peer chain
// it reports the leaf's subject/issuer/validity, the leaf's signature and key
// algorithms classified against an OWNED algorithm table (dotted-string OIDs,
// names, classes), the set of PQ-bearing algorithm OIDs present across the
// chain, and whether the chain mixes signature eras (the dual-cert signal).
//
// The algorithm table is owned here as a testable const + slice table.
// Unknown OIDs are recorded (never crashed on): they are classified
// classical=false,false — i.e. not claimed PQ and not claimed classical —
// with the name carrying an "unknown-…" note so downstream code can
// distinguish "known classical" from "saw an OID we do not know".
//
// Classification is OID-driven from the certificate DER on purpose: the
// stdlib enumeration cannot represent composite (or otherwise toolchain-
// unregistered) algorithms, while the DER OIDs exist for every certificate
// a peer delivers. A table row can name an algorithm the local toolchain
// cannot parse key bodies for; the classification still reports it.
package certinfo

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Algorithm classes in the owned OID table.
const (
	ClassClassical = iota // RSA / ECDSA / Ed25519 / DSA families (RFC 5280/5480/3279/8410)
	ClassPQ               // pure PQ: ML-DSA (RFC 9881), SLH-DSA + HashSLH-DSA (RFC 9909); FN-DSA rows land when IANA assigns
	ClassHybrid           // composite PQ/T hybrids (the COMPSIG-MLDSA set, IANA PKIX alg arc)
)

// The owned OID table's identifiers, written as dotted strings exactly as
// NIST CSOR / IANA registered them. The pure PQ OIDs (RFC 9881 §2, RFC 9909
// §3) use the same OID per parameter set for BOTH the public key and the
// signature.
const (
	oidMLDSA44 = "2.16.840.1.101.3.4.3.17"
	oidMLDSA65 = "2.16.840.1.101.3.4.3.18"
	oidMLDSA87 = "2.16.840.1.101.3.4.3.19"

	oidSLHDSASha2_128s = "2.16.840.1.101.3.4.3.20"
	oidSLHDSASha2_128f = "2.16.840.1.101.3.4.3.21"
	oidSLHDSASha2_192s = "2.16.840.1.101.3.4.3.22"
	oidSLHDSASha2_192f = "2.16.840.1.101.3.4.3.23"
	oidSLHDSASha2_256s = "2.16.840.1.101.3.4.3.24"
	oidSLHDSASha2_256f = "2.16.840.1.101.3.4.3.25"
	oidSLHDSAShake128s = "2.16.840.1.101.3.4.3.26"
	oidSLHDSAShake128f = "2.16.840.1.101.3.4.3.27"
	oidSLHDSAShake192s = "2.16.840.1.101.3.4.3.28"
	oidSLHDSAShake192f = "2.16.840.1.101.3.4.3.29"
	oidSLHDSAShake256s = "2.16.840.1.101.3.4.3.30"
	oidSLHDSAShake256f = "2.16.840.1.101.3.4.3.31"

	oidHashSLHDSASha2_128s = "2.16.840.1.101.3.4.3.35"
	oidHashSLHDSASha2_128f = "2.16.840.1.101.3.4.3.36"
	oidHashSLHDSASha2_192s = "2.16.840.1.101.3.4.3.37"
	oidHashSLHDSASha2_192f = "2.16.840.1.101.3.4.3.38"
	oidHashSLHDSASha2_256s = "2.16.840.1.101.3.4.3.39"
	oidHashSLHDSASha2_256f = "2.16.840.1.101.3.4.3.40"
	oidHashSLHDSAShake128s = "2.16.840.1.101.3.4.3.41"
	oidHashSLHDSAShake128f = "2.16.840.1.101.3.4.3.42"
	oidHashSLHDSAShake192s = "2.16.840.1.101.3.4.3.43"
	oidHashSLHDSAShake192f = "2.16.840.1.101.3.4.3.44"
	oidHashSLHDSAShake256s = "2.16.840.1.101.3.4.3.45"
	oidHashSLHDSAShake256f = "2.16.840.1.101.3.4.3.46"

	oidCompMLDSA44_RSA2048_PSS    = "1.3.6.1.5.5.7.6.37"
	oidCompMLDSA44_RSA2048_PKCS15 = "1.3.6.1.5.5.7.6.38"
	oidCompMLDSA44_Ed25519        = "1.3.6.1.5.5.7.6.39"
	oidCompMLDSA44_ECDSA_P256     = "1.3.6.1.5.5.7.6.40"
	oidCompMLDSA65_RSA3072_PSS    = "1.3.6.1.5.5.7.6.41"
	oidCompMLDSA65_RSA3072_PKCS15 = "1.3.6.1.5.5.7.6.42"
	oidCompMLDSA65_RSA4096_PSS    = "1.3.6.1.5.5.7.6.43"
	oidCompMLDSA65_RSA4096_PKCS15 = "1.3.6.1.5.5.7.6.44"
	oidCompMLDSA65_ECDSA_P256     = "1.3.6.1.5.5.7.6.45"
	oidCompMLDSA65_ECDSA_P384     = "1.3.6.1.5.5.7.6.46"
	oidCompMLDSA65_ECDSA_BP256    = "1.3.6.1.5.5.7.6.47"
	oidCompMLDSA65_Ed25519        = "1.3.6.1.5.5.7.6.48"
	oidCompMLDSA87_ECDSA_P384     = "1.3.6.1.5.5.7.6.49"
	oidCompMLDSA87_ECDSA_BP384    = "1.3.6.1.5.5.7.6.50"
	oidCompMLDSA87_Ed448          = "1.3.6.1.5.5.7.6.51"
	oidCompMLDSA87_RSA3072_PSS    = "1.3.6.1.5.5.7.6.52"
	oidCompMLDSA87_RSA4096_PSS    = "1.3.6.1.5.5.7.6.53"

	oidRSAEncryption   = "1.2.840.113549.1.1.1"
	oidMD5WithRSA      = "1.2.840.113549.1.1.4"
	oidSHA1WithRSA     = "1.2.840.113549.1.1.5"
	oidSHA256WithRSA   = "1.2.840.113549.1.1.11"
	oidSHA384WithRSA   = "1.2.840.113549.1.1.12"
	oidSHA512WithRSA   = "1.2.840.113549.1.1.13"
	oidRSASSAPSS       = "1.2.840.113549.1.1.10"
	oidECPublicKey     = "1.2.840.10045.2.1"
	oidECDSAWithSHA1   = "1.2.840.10045.4.1"
	oidECDSAWithSHA224 = "1.2.840.10045.4.3.1"
	oidECDSAWithSHA256 = "1.2.840.10045.4.3.2"
	oidECDSAWithSHA384 = "1.2.840.10045.4.3.3"
	oidECDSAWithSHA512 = "1.2.840.10045.4.3.4"
	oidEd25519         = "1.3.101.112"
	oidEd448           = "1.3.101.113"
	oidDSAKey          = "1.2.840.10040.4.1"
	oidDSAWithSHA1     = "1.2.840.10040.4.3"
	oidDSAWithSHA256   = "2.16.840.1.101.3.4.3.2"
)

// oidEntry is one row of the owned OID table.
type oidEntry struct {
	OID   string // dotted string, exactly as NIST/IANA registered
	Name  string // human name reported in the Name fields
	Class int    // ClassClassical | ClassPQ | ClassHybrid
}

// oidTable is the PQ-21 owned algorithm table. Composite names drop the
// IANA label's "COMPSIG-" prefix (common to every row of that set). FN-DSA
// (Falcon) has NO assigned X.509 OID as of this table (IETF draft stage,
// lamps-wg/fn-dsa-certificates) — no invented OID is carried here; add its
// rows when IANA assigns. Composite-KEM SPKI hybrids (composite ML-KEM key
// types) are intentionally out of scope: this table classifies
// signature-bearing certificates; the KEM/key-scan lanes own KEM coverage.
var oidTable = []oidEntry{
	// ML-DSA (RFC 9881; FIPS-204) — key and signature use the same OID
	{oidMLDSA44, "ML-DSA-44", ClassPQ},
	{oidMLDSA65, "ML-DSA-65", ClassPQ},
	{oidMLDSA87, "ML-DSA-87", ClassPQ},
	// SLH-DSA (RFC 9909; FIPS-205) — same OID for key and signature
	{oidSLHDSASha2_128s, "SLH-DSA-SHA2-128s", ClassPQ},
	{oidSLHDSASha2_128f, "SLH-DSA-SHA2-128f", ClassPQ},
	{oidSLHDSASha2_192s, "SLH-DSA-SHA2-192s", ClassPQ},
	{oidSLHDSASha2_192f, "SLH-DSA-SHA2-192f", ClassPQ},
	{oidSLHDSASha2_256s, "SLH-DSA-SHA2-256s", ClassPQ},
	{oidSLHDSASha2_256f, "SLH-DSA-SHA2-256f", ClassPQ},
	{oidSLHDSAShake128s, "SLH-DSA-SHAKE-128s", ClassPQ},
	{oidSLHDSAShake128f, "SLH-DSA-SHAKE-128f", ClassPQ},
	{oidSLHDSAShake192s, "SLH-DSA-SHAKE-192s", ClassPQ},
	{oidSLHDSAShake192f, "SLH-DSA-SHAKE-192f", ClassPQ},
	{oidSLHDSAShake256s, "SLH-DSA-SHAKE-256s", ClassPQ},
	{oidSLHDSAShake256f, "SLH-DSA-SHAKE-256f", ClassPQ},
	// HashSLH-DSA (RFC 9909 pre-hash variants)
	{oidHashSLHDSASha2_128s, "HashSLH-DSA-SHA2-128s-with-SHA256", ClassPQ},
	{oidHashSLHDSASha2_128f, "HashSLH-DSA-SHA2-128f-with-SHA256", ClassPQ},
	{oidHashSLHDSASha2_192s, "HashSLH-DSA-SHA2-192s-with-SHA512", ClassPQ},
	{oidHashSLHDSASha2_192f, "HashSLH-DSA-SHA2-192f-with-SHA512", ClassPQ},
	{oidHashSLHDSASha2_256s, "HashSLH-DSA-SHA2-256s-with-SHA512", ClassPQ},
	{oidHashSLHDSASha2_256f, "HashSLH-DSA-SHA2-256f-with-SHA512", ClassPQ},
	{oidHashSLHDSAShake128s, "HashSLH-DSA-SHAKE-128s-with-SHAKE128", ClassPQ},
	{oidHashSLHDSAShake128f, "HashSLH-DSA-SHAKE-128f-with-SHAKE128", ClassPQ},
	{oidHashSLHDSAShake192s, "HashSLH-DSA-SHAKE-192s-with-SHAKE256", ClassPQ},
	{oidHashSLHDSAShake192f, "HashSLH-DSA-SHAKE-192f-with-SHAKE256", ClassPQ},
	{oidHashSLHDSAShake256s, "HashSLH-DSA-SHAKE-256s-with-SHAKE256", ClassPQ},
	{oidHashSLHDSAShake256f, "HashSLH-DSA-SHAKE-256f-with-SHAKE256", ClassPQ},
	// Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs-13/-14; IANA
	// PKIX SMI alg arc 1.3.6.1.5.5.7.6 decimals 37-53, verified span)
	{oidCompMLDSA44_RSA2048_PSS, "MLDSA44-RSA2048-PSS-SHA256", ClassHybrid},
	{oidCompMLDSA44_RSA2048_PKCS15, "MLDSA44-RSA2048-PKCS15-SHA256", ClassHybrid},
	{oidCompMLDSA44_Ed25519, "MLDSA44-Ed25519-SHA512", ClassHybrid},
	{oidCompMLDSA44_ECDSA_P256, "MLDSA44-ECDSA-P256-SHA256", ClassHybrid},
	{oidCompMLDSA65_RSA3072_PSS, "MLDSA65-RSA3072-PSS-SHA512", ClassHybrid},
	{oidCompMLDSA65_RSA3072_PKCS15, "MLDSA65-RSA3072-PKCS15-SHA512", ClassHybrid},
	{oidCompMLDSA65_RSA4096_PSS, "MLDSA65-RSA4096-PSS-SHA512", ClassHybrid},
	{oidCompMLDSA65_RSA4096_PKCS15, "MLDSA65-RSA4096-PKCS15-SHA512", ClassHybrid},
	{oidCompMLDSA65_ECDSA_P256, "MLDSA65-ECDSA-P256-SHA512", ClassHybrid},
	{oidCompMLDSA65_ECDSA_P384, "MLDSA65-ECDSA-P384-SHA512", ClassHybrid},
	{oidCompMLDSA65_ECDSA_BP256, "MLDSA65-ECDSA-BP256-SHA512", ClassHybrid},
	{oidCompMLDSA65_Ed25519, "MLDSA65-Ed25519-SHA512", ClassHybrid},
	{oidCompMLDSA87_ECDSA_P384, "MLDSA87-ECDSA-P384-SHA512", ClassHybrid},
	{oidCompMLDSA87_ECDSA_BP384, "MLDSA87-ECDSA-BP384-SHA512", ClassHybrid},
	{oidCompMLDSA87_Ed448, "MLDSA87-Ed448-SHAKE256", ClassHybrid},
	{oidCompMLDSA87_RSA3072_PSS, "MLDSA87-RSA3072-PSS-SHA512", ClassHybrid},
	{oidCompMLDSA87_RSA4096_PSS, "MLDSA87-RSA4096-PSS-SHA512", ClassHybrid},
	// classical — RSA family
	{oidRSAEncryption, "RSA", ClassClassical},
	{oidMD5WithRSA, "md5WithRSAEncryption", ClassClassical},
	{oidSHA1WithRSA, "sha1WithRSAEncryption", ClassClassical},
	{oidSHA256WithRSA, "sha256WithRSAEncryption", ClassClassical},
	{oidSHA384WithRSA, "sha384WithRSAEncryption", ClassClassical},
	{oidSHA512WithRSA, "sha512WithRSAEncryption", ClassClassical},
	{oidRSASSAPSS, "RSASSA-PSS", ClassClassical},
	// classical — ECDSA / EdDSA / DSA families
	{oidECPublicKey, "ECDSA", ClassClassical},
	{oidECDSAWithSHA1, "ecdsa-with-SHA1", ClassClassical},
	{oidECDSAWithSHA224, "ecdsa-with-SHA224", ClassClassical},
	{oidECDSAWithSHA256, "ecdsa-with-SHA256", ClassClassical},
	{oidECDSAWithSHA384, "ecdsa-with-SHA384", ClassClassical},
	{oidECDSAWithSHA512, "ecdsa-with-SHA512", ClassClassical},
	{oidEd25519, "Ed25519", ClassClassical},
	{oidEd448, "Ed448", ClassClassical},
	{oidDSAKey, "DSA", ClassClassical},
	{oidDSAWithSHA1, "dsaWithSHA1", ClassClassical},
	{oidDSAWithSHA256, "dsaWithSHA256", ClassClassical},
}

// Info is the analytics row for one parsed certificate chain.
//
// Bool semantics: SigAlgPQ/KeyAlgPQ are true for both ClassPQ and
// ClassHybrid (a hybrid carries a PQ component; for estate analytics a PQ
// signature is present either way). A known-classical algorithm is
// false/false with a recognizable table name. An UNKNOWN OID is false/false
// WITH a name note — the name fields carry the "unknown-…" prefix so
// "known classical" stays distinguishable from "unclassified".
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

// algID mirrors a X.509 AlgorithmIdentifier (RFC 5280 §4.1).
type algID struct {
	Alg    asn1.ObjectIdentifier
	Params asn1.RawValue `asn1:"optional,tag:params"`
}

// spkiT mirrors SubjectPublicKeyInfo.
type spkiT struct {
	Algorithm algID
	PublicKey asn1.BitString
}

// tbsT mirrors TBSCertificate (the fields the classifier reads).
type tbsT struct {
	Raw          asn1.RawContent
	Version      int `asn1:"optional,tag:0,default:0,explicit"`
	SerialNumber *big.Int
	Signature    algID
	Issuer       asn1.RawValue
	Validity     asn1.RawValue
	Subject      asn1.RawValue
	SubjectPKI   spkiT
}

// certT mirrors the outer Certificate.
type certT struct {
	TBSCertificate     tbsT
	SignatureAlgorithm algID
	SignatureValue     asn1.BitString
}

// certAlgs extracts the outer signature-algorithm OID and the SPKI
// algorithm OID from the certificate's DER. Production callers hand over
// parsed certificates (ConnectionState().PeerCertificates), which always
// carry Raw; raw-DER struct literals (the hand-built OID-case fixture path)
// work equally.
func certAlgs(cert *x509.Certificate) (sigOID, keyOID string, err error) {
	if len(cert.Raw) == 0 {
		return "", "", errors.New("certinfo: certificate has no DER (Raw) to classify")
	}
	var c certT
	if _, err := asn1.Unmarshal(cert.Raw, &c); err != nil {
		return "", "", fmt.Errorf("certinfo: cannot parse certificate DER: %w", err)
	}
	// RFC 5280 requires the two signature identifiers to match; record the
	// outer one, falling back to the inner if the outer is absent.
	if len(c.SignatureAlgorithm.Alg) > 0 {
		sigOID = c.SignatureAlgorithm.Alg.String()
	} else if len(c.TBSCertificate.Signature.Alg) > 0 {
		sigOID = c.TBSCertificate.Signature.Alg.String()
	} else {
		return "", "", errors.New("certinfo: certificate carries no signature algorithm OID")
	}
	if len(c.TBSCertificate.SubjectPKI.Algorithm.Alg) == 0 {
		return "", "", errors.New("certinfo: certificate carries no subject public key algorithm OID")
	}
	keyOID = c.TBSCertificate.SubjectPKI.Algorithm.Alg.String()
	return sigOID, keyOID, nil
}

// classifyOID scans the owned table.
func classifyOID(oid string) (class int, name string, known bool) {
	for _, e := range oidTable {
		if e.OID == oid {
			return e.Class, e.Name, true
		}
	}
	return -1, "", false
}

func unknownSigName(oid string) string { return "unknown-signature-algorithm(" + oid + ")" }
func unknownKeyName(oid string) string { return "unknown-key-algorithm(" + oid + ")" }

// Analyze classifies the LEAF (chain[0]) and walks the delivered chain.
//
// DualCert — the exact rule (issue #44's framing, spec M2 "estate"): the
// delivered chain mixes signature eras. DualCert is true if and only if
// (a) at least one member's SIGNATURE classifies classical AND (b) at
// least one member's signature classifies PQ or hybrid. Concretely: a
// classical-signed leaf under PQ-signed issuers is dual; a PQ-signed leaf
// over classical-signed issuers is STILL dual (the estate framing: the
// relying path still carries a classically-validated link). An all-
// classical chain fails (b); an all-PQ chain fails (a); both are not dual.
// A composite member counts as the PQ side only — its internal classical
// half is not a separate chain member (intra-cert duality is a property of
// the COMPSIG certificate itself). Key material does NOT create the dual
// signal: a PQ key under a classical signature is the transitional
// key-deployment case, recorded via KeyAlgPQ/PQOIDs; the eras-mixing
// signal is signature-driven. The rule is per DELIVERED chain: a sender
// that truncates the peer chain changes what this row reports.
//
// Unknown OIDs never crash and never claim a class: they are recorded
// verbatim with an "unknown-…" name note (see Info). Only structural
// failures (empty chain, unreadable DER) return an error.
func Analyze(chain []*x509.Certificate) (*Info, error) {
	if len(chain) == 0 {
		return nil, errors.New("certinfo: empty certificate chain")
	}
	leaf := chain[0]
	sigOID, keyOID, err := certAlgs(leaf)
	if err != nil {
		return nil, err
	}
	sigClass, sigName, sigKnown := classifyOID(sigOID)
	keyClass, keyName, keyKnown := classifyOID(keyOID)
	if !sigKnown {
		sigName = unknownSigName(sigOID)
	}
	if !keyKnown {
		keyName = unknownKeyName(keyOID)
	}
	info := &Info{
		Subject:    leaf.Subject.String(),
		Issuer:     leaf.Issuer.String(),
		SigAlg:     sigOID,
		SigAlgPQ:   sigClass == ClassPQ || sigClass == ClassHybrid,
		SigAlgName: sigName,
		KeyAlg:     keyName,
		KeyAlgPQ:   keyClass == ClassPQ || keyClass == ClassHybrid,
		NotBefore:  leaf.NotBefore,
		NotAfter:   leaf.NotAfter,
	}

	// Walk every member: collect PQ-bearing OIDs (dedup, leaf-first order)
	// and the two dual-rule sides (signature-driven only).
	pqSeen := map[string]bool{}
	classicalSig, pqSig := false, false
	for _, cert := range chain {
		mSig, mKey, mErr := certAlgs(cert)
		if mErr != nil {
			continue // an unparseable member contributes nothing — never crash
		}
		c, _, known := classifyOID(mSig)
		if known {
			switch c {
			case ClassPQ, ClassHybrid:
				pqSig = true
				if !pqSeen[mSig] {
					pqSeen[mSig] = true
					info.PQOIDs = append(info.PQOIDs, mSig)
				}
			case ClassClassical:
				classicalSig = true
			}
		}
		c, _, known = classifyOID(mKey)
		if known && (c == ClassPQ || c == ClassHybrid) && !pqSeen[mKey] {
			pqSeen[mKey] = true
			info.PQOIDs = append(info.PQOIDs, mKey)
		}
	}
	info.DualCert = classicalSig && pqSig
	return info, nil
}
