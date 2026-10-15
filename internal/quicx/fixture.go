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
)

// FixtureH3 spins a local QUIC v1 listener (ALPN h3, self-signed cert,
// pinned group preferences) — the offline ground truth the probe engines
// are verified against (spec §10.1). Exported so sibling packages' test
// fixtures reuse the same listener (discovery's h3-direct half, PQ-25)
// instead of duplicating cert + accept plumbing.
//
// The listener binds the ephemeral :0 (UDP): it is safe ALONE — no
// process, test or fixture collides a listener on it. A lane that pairs
// BOTH transports on one port number (the QUIC lane dials the target's
// port on TCP for the hint and UDP for the direct probe) must NOT assume
// a fresh UDP number's TCP side is free: `go test ./...` runs package
// binaries concurrently and the port space is machine-wide across
// processes. discovery.FixtureH3AndHint is the coupled contract: both
// halves bind and are HELD, the pair retried while a number is held in
// either namespace.
func FixtureH3(t *testing.T, curvePrefs []tls.CurveID) string {
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
