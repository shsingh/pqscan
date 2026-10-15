package quicx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shsingh/pqscan/internal/diag"
)

// quicFixture spins a local QUIC v1 listener (ALPN h3, self-signed cert,
// pinned group preferences) — the offline ground truth the probe engine
// is verified against (spec §10.1).
func quicFixture(t *testing.T, curvePrefs []tls.CurveID) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(20261016),
		Subject:               pkix.Name{CommonName: "pqscan.fixture"},
		DNSNames:              []string{"pqscan.fixture"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		CurvePreferences: curvePrefs,
		NextProtos:       []string{"h3"},
		MinVersion:       tls.VersionTLS13,
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, &quic.Config{HandshakeIdleTimeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			sess, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				stream, err := sess.AcceptStream(ctx)
				if err == nil {
					_ = stream.Close()
				}
			}()
		}
	}()

	return ln.Addr().String()
}

// TestQuicNegotiatesHybrid: group control on the QUIC plane — a client
// forced to X25519MLKEM768 negotiates 4588 inside QUIC v1 (watched RED:
// the test runs and fails against the engine stub).
func TestQuicNegotiatesHybrid(t *testing.T) {
	addr := quicFixture(t, []tls.CurveID{tls.X25519MLKEM768, tls.X25519})

	r, err := ProbeQUIC(addr, "pqscan.fixture", []uint32{4588}, 3*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err) // RED: stub returns not-implemented
	}
	if r.State != "negotiated" {
		t.Fatalf("state = %q, want negotiated", r.State)
	}
	if r.Group != 4588 {
		t.Fatalf("negotiated group = %d, want 4588", r.Group)
	}
	if r.GroupClass != "pq_hybrid" {
		t.Fatalf("group class = %q, want pq_hybrid", r.GroupClass)
	}
	if r.Version != 1 {
		t.Fatalf("quic version = %d, want 1", r.Version)
	}
	if r.ALPN != "h3" {
		t.Fatalf("alpn = %q, want h3", r.ALPN)
	}
}

// TestQuicUDPRefusedClassifies: no listener on the port ⇒ the engine
// records a refused/blocked classification as a RESULT (never a crash).
func TestQuicUDPRefusedClassifies(t *testing.T) {
	r, err := ProbeQUIC("127.0.0.1:1", "pqscan.fixture", []uint32{29}, 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err) // RED: stub
	}
	if r.State == "negotiated" {
		t.Fatal("negotiated against a dead port; classification broken")
	}
}

// integrationOnly gates live-network truth (never in CI).
func integrationOnly(t *testing.T) {
	t.Helper()
	if quicIntegration() == "" {
		t.Skip("PQSCAN_INTEGRATION not set; live-network probe skipped")
	}
}

func quicIntegration() string { return quicIntegrationEnv }

// TestIntegrationQuicCloudflareHybrid: forced 4588 inside QUIC v1 against
// a hybrid edge — the UDP-plane ground truth (spec §10.1).
func TestIntegrationQuicCloudflareHybrid(t *testing.T) {
	integrationOnly(t)

	r, err := ProbeQUIC("cloudflare.com:443", "cloudflare.com", []uint32{4588}, 8*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	t.Logf("cloudflare quic 4588-forced: %+v", r)
	if r.State != "negotiated" {
		t.Fatalf("state = %q blocked=%v; want negotiated", r.State, r.UDPBlocked)
	}
	if r.Group != 4588 {
		t.Fatalf("negotiated group = %d, want 4588", r.Group)
	}
}

// TestQuicEmitsDiagnostics: the QUIC probe emits the same decision events
// the TCP ladder does — the debug record covers both planes (PQ-13, the
// PQ-11 acceptance leftover).
func TestQuicEmitsDiagnostics(t *testing.T) {
	sink, _ := diag.NewSink(nil, 0)
	diag.SetDefault(sink)
	defer diag.SetDefault(nil)

	addr := quicFixture(t, []tls.CurveID{tls.X25519MLKEM768, tls.X25519})
	if _, err := ProbeQUIC(addr, "pqscan.fixture", []uint32{4588}, 3*time.Second); err != nil {
		t.Fatalf("probe: %v", err)
	}
	rep, err := sink.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	found := false
	for _, e := range rep.Events {
		if e.Domain == diag.DomQuic && e.Fields["negotiated"] == "4588" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no quic diagnostics carrying negotiated=4588; events=%d", rep.Summary.Events)
	}
}
