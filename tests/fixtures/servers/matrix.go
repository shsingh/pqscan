// Package fixtures hosts the locally served TLS configuration matrix — the
// ground truth the probe engine is verified against offline (spec §10.1:
// fixture matrix; PQ-04 acceptance: a local fixture TLS server that runs
// under go test and serves a known suite/group matrix).
package fixtures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// ServerConfig pins one row of the fixture matrix. Each row is a complete,
// known TLS posture the scanners can be verified against locally.
type ServerConfig struct {
	Name             string
	MinVersion       uint16
	MaxVersion       uint16
	CurvePreferences []tls.CurveID
	CipherSuites     []uint16
	ALPN             []string
}

// DefaultMatrix returns the initial fixture rows (spec §10.1). Extend with
// a row + its expectation test, never by loosening an existing one.
func DefaultMatrix() []ServerConfig {
	return []ServerConfig{
		{
			Name:             "t13-hybrid-mlkem",
			MinVersion:       tls.VersionTLS13,
			MaxVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		},
		{
			Name:             "t13-classic-x25519-only",
			MinVersion:       tls.VersionTLS13,
			MaxVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519},
		},
		{
			Name:             "t13-hrr-required",
			MinVersion:       tls.VersionTLS13,
			MaxVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, // client offering only P-256 must HRR
		},
		{
			Name:             "t12-rsa-ecdsa-suites",
			MinVersion:       tls.VersionTLS12,
			MaxVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.X25519},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			},
			ALPN: []string{"h2", "http/1.1"},
		},
	}
}

// StartFixtureServer serves one matrix row on loopback for the test's
// lifetime; the returned address is host:port.
func StartFixtureServer(t *testing.T, cfg ServerConfig) string {
	t.Helper()

	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen resolve: %v", err)
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	tlsCfg := &tls.Config{
		Certificates:     []tls.Certificate{fixtureCert(t)},
		CurvePreferences: cfg.CurvePreferences,
		CipherSuites:     cfg.CipherSuites,
		NextProtos:       cfg.ALPN,
		MinVersion:       cfg.MinVersion,
		MaxVersion:       cfg.MaxVersion,
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // closed by cleanup
			}
			go func() {
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				sc := tls.Server(conn, tlsCfg)
				// run the handshake now — the fixture is a negotiation
				// oracle, not an application endpoint
				_ = sc.Handshake()
			}()
		}
	}()

	return ln.Addr().String()
}

func fixtureCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(20261015),
		Subject:               pkix.Name{CommonName: "pqscan.fixture"},
		DNSNames:              []string{"pqscan.fixture"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert gen: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
