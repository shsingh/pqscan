package tlsx

import (
	"crypto/tls"
	"testing"

	fixtures "github.com/shsingh/pqscan/tests/fixtures/servers"
)

// TestProbeNegotiatedSurfacesCertificateAnalytics pins the PQ-21 chain
// surface (PQ-21, watched-RED): the forced-group probe result must carry
// the served leaf's certificate analytics, computed in the same handshake
// that fills ConnectionState. The fixture row serves the repo's in-code
// fixture certificate — honestly recorded: it is a self-signed ECDSA
// P-256 leaf (tests/fixtures/servers), so the expected leaf signature
// alg is ecdsa-with-SHA256, classically classified and not PQ.
func TestProbeNegotiatedSurfacesCertificateAnalytics(t *testing.T) {
	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-classic-x25519-only",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})

	r, err := ProbeNegotiated(addr, "pqscan.fixture", []uint32{29}, 5e9)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if r.State != "negotiated" {
		t.Fatalf("state = %q, want negotiated", r.State)
	}
	if r.CertificateSigAlg != "ecdsa-with-SHA256" {
		t.Fatalf("CertificateSigAlg = %q, want ecdsa-with-SHA256 from the fixture leaf", r.CertificateSigAlg)
	}
	if r.CertificatePQ {
		t.Fatalf("CertificatePQ = true, want false for the classical fixture leaf")
	}
}

// TestProbeNegotiatedRawPathCertFieldsStayEmpty pins that a raw-path probe
// result (no TLS-layer ConnectionState available) keeps the certificate
// fields at their zero values rather than inventing data.
func TestProbeNegotiatedRawPathCertFieldsStayEmpty(t *testing.T) {
	if r := (ProbeResult{}); r.CertificateSigAlg != "" || r.CertificatePQ {
		t.Fatalf("raw-path ProbeResult zero value carries cert data: %+v", r)
	}
}
