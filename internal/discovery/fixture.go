package discovery

// fixture.go hosts the exported test fixture the sibling packages' wiring
// tests reuse (the quicx.FixtureH3 precedent, PQ-25): a TLS TCP listener
// speaking http/1.1 ALPN that answers the first request with the caller's
// crafted bytes — the alt-svc hint half's offline oracle. UDP and TCP
// port namespaces are independent, so the caller can share one port
// number across this fixture and a QUIC listener (the h3-discovery tests'
// two-halves shape).

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// fixtureCert is the fixture's self-signed server cert (same shape as the
// quicx fixture's).
func fixtureCert(t *testing.T) tls.Certificate {
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// FixtureHintHTTP binds a TLS TCP listener on 127.0.0.1:port whose accept
// loop handshakes (fixture hygiene: a never-handshaken server side
// presents as a client deadline, not an obvious fixture bug), reads the
// request, and answers with the crafted response bytes. Callers own the
// response body — the hint vocabulary (an alt-svc h3= directive, an
// alt-svc header without h3, no alt-svc at all) is the test's choice.
func FixtureHintHTTP(t *testing.T, port int, resp []byte) {
	t.Helper()
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{fixtureCert(t)},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("tcp listen %d: %v", port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := tls.Server(conn, tlsCfg)
				defer func() { _ = tc.Close() }()
				if err := tc.Handshake(); err != nil {
					return
				}
				if _, lerr := http.ReadRequest(bufio.NewReader(tc)); lerr != nil {
					return
				}
				_, _ = tc.Write(resp)
			}()
		}
	}()
}

// FreeTCPPort grabs an ephemeral port and releases it — a port number
// nothing is bound to (the hint half must refuse).
func FreeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// PortOf extracts the port from a fixture addr ("127.0.0.1:P").
func PortOf(t *testing.T, addr string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("fixture addr %q: %v", addr, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("fixture port %q: %v", port, err)
	}
	return p
}
