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
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// FixtureH3 spins a local QUIC v1 listener (ALPN h3, self-signed cert,
// pinned group preferences) that also CARRIES the h3 plane: the http3
// server reads its SETTINGS frames and answers one HTTP/3 request (the
// PQ-69 functional-h3 ground truth; spec §10.1). Exported so sibling
// packages' test fixtures reuse the same listener (discovery's h3-direct
// half, PQ-25) instead of duplicating cert + accept plumbing.
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
//
// PQ-69: the pre-69 fixture accepted one stream and closed it — it
// carried no h3 layer, so it cannot verify a completed HTTP/3 exchange.
// fixtureQUICNoH3 keeps that raw shape as its own class fixture.
func FixtureH3(t *testing.T, curvePrefs []tls.CurveID) string {
	t.Helper()
	return fixtureH3Serving(t, []quic.Version{quic.Version1}, curvePrefs)
}

// FixtureH3V2 spins a local QUIC v2 listener (RFC 9369: the QUIC
// transport version pinned to v2 ONLY, ALPN h3, self-signed cert) that
// carries the h3 plane like FixtureH3 does (PQ-69, spec §10.1). A
// version negotiation from a v1-only offer answers with quic-go's
// version-negotiation error — the fixture carries the v2-only host
// shape. Exported so sibling packages' tests reuse it; the listener
// binds the ephemeral :0 (UDP) exactly like FixtureH3.
func FixtureH3V2(t *testing.T, curvePrefs []tls.CurveID) string {
	t.Helper()
	return fixtureH3Serving(t, []quic.Version{quic.Version2}, curvePrefs)
}

// fixtureH3Serving is the shared h3-plane build (PQ-69): one self-signed
// P-256 identity, one UDP bind on :0 held by t.Cleanup, one http3.Server
// pinned to the caller's transport versions. Every h3 fixture in this
// package rides this plumbing — no fixture re-implements the cert or the
// serve loop.
func fixtureH3Serving(t *testing.T, versions []quic.Version, curvePrefs []tls.CurveID) string {
	t.Helper()

	key, der := fixtureCert(t)
	tlsCfg := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		CurvePreferences: curvePrefs,
		NextProtos:       []string{"h3"},
		MinVersion:       tls.VersionTLS13,
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	srv := &http3.Server{
		TLSConfig: tlsCfg,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 3 * time.Second,
			MaxIdleTimeout:       3 * time.Second,
			Versions:             versions,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("pqscan-fixture"))
		}),
	}
	go func() { _ = srv.Serve(udp) }() // Serve returns http.ErrServerClosed on Close
	t.Cleanup(func() {
		_ = srv.Close()
		_ = udp.Close()
	})
	return udp.LocalAddr().String()
}

// fixtureCert is the shared self-signed P-256 identity of the QUIC
// fixtures (the one cert plumbing; no fixture mints its own).
func fixtureCert(t *testing.T) (*ecdsa.PrivateKey, []byte) {
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
	return key, der
}

// fixtureQUICRaw spins a raw QUIC listener with NO h3 layer (PQ-69):
// quic-go serves the transport handshake; the accept loop closes the
// first stream it accepts. A client that opens the HTTP/3 control
// stream then finds no SETTINGS frame and no exchange — the fixture
// behind the broken-h3-path finding class. Exported so sibling
// packages' tests reuse the listener (the executor's mapping tests).
func fixtureQUICRaw(t *testing.T, versions []quic.Version, nextProtos []string) string {
	t.Helper()
	key, der := fixtureCert(t)

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   nextProtos,
		MinVersion:   tls.VersionTLS13,
	}
	qcfg := &quic.Config{
		HandshakeIdleTimeout: 3 * time.Second,
		MaxIdleTimeout:       3 * time.Second,
		Versions:             versions,
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	ln, err := quic.Listen(udp, tlsCfg, qcfg)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
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
	t.Cleanup(func() { _ = ln.Close() })
	return udp.LocalAddr().String()
}

// FixtureQUICNoH3 is the raw v1 listener with the h3 ALPN but no h3
// layer — the broken-h3-path class fixture AND the v1-only transport
// ground truth (PQ-69): the negotiation answers; the exchange never
// completes.
func FixtureQUICNoH3(t *testing.T) string {
	t.Helper()
	return fixtureQUICRaw(t, []quic.Version{quic.Version1}, []string{"h3"})
}

// FixtureQUICStrangerALPN is the v1 listener whose ALPN vocabulary
// excludes h3 — the ALPN-mismatch class fixture (PQ-69): the TLS
// negotiation answers a non-overlap alert (the server's decision,
// verbatim at the executor's rejected row).
func FixtureQUICStrangerALPN(t *testing.T) string {
	t.Helper()
	return fixtureQUICRaw(t, []quic.Version{quic.Version1}, []string{"hq-29"})
}
