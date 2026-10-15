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

	"github.com/shsingh/pqscan/internal/quicx"
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

// FixtureHintHTTP binds a TLS TCP listener on 127.0.0.1:port and answers
// the request with the crafted response bytes; port 0 = the ephemeral
// pick. The BIND (not a grab-and-release) holds the number for the test's
// whole lifetime — the returned value is the bound port. Callers own the
// response body — the hint vocabulary (an alt-svc h3= directive, an
// alt-svc header without h3, no alt-svc at all) is the test's choice.
func FixtureHintHTTP(t *testing.T, port int, resp []byte) int {
	t.Helper()
	ln, err := listenHintHTTP(t, port, resp)
	if err != nil {
		t.Fatalf("tcp listen %d: %v", port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// listenHintHTTP is the non-fatal bind the coupled pair's retry loop
// drives: it hands the listener back for the caller to serve, or the bind
// error (the number's TCP side is held elsewhere — on a concurrent `go
// test ./...` the package binaries share one machine-wide port space).
func listenHintHTTP(t *testing.T, port int, resp []byte) (net.Listener, error) {
	t.Helper()
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{fixtureCert(t)},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
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
	return ln, nil
}

// FixtureH3AndHint spins the QUIC lane's coupled offline fixture: BOTH
// halves of ONE loopback port number — the UDP QUIC h3 listener (the
// quicx fixture) and the TCP TLS/h1 listener answering resp — because the
// lane DIALS the target's host:port on both transports. The pair binds
// FIRST and stays bound for the test's whole lifetime, and the PAIR is
// retried as a unit: `go test ./...` runs package test binaries
// concurrently and the port space is machine-wide across processes, so a
// number is only safe once BOTH transports hold it (the single-process
// same-port trick flaked on CI: a concurrent process held the fresh UDP
// fixture's number on TCP, and the second half's bind died with
// "address already in use"; no fixed ports anywhere — every listener
// binds :0 or the held pair).
func FixtureH3AndHint(t *testing.T, resp []byte) string {
	t.Helper()
	var lastErr error
	for i := 0; i < 16; i++ {
		addr := quicx.FixtureH3(t, nil)
		port := PortOf(t, addr)
		if ln, err := listenHintHTTP(t, port, resp); err == nil {
			t.Cleanup(func() { _ = ln.Close() })
			return addr // both halves bound and held: the number is safe
		} else {
			lastErr = err // the TCP twin is held elsewhere; retry the pair
		}
	}
	t.Fatalf("no free two-transport loopback port in 16 pair attempts: %v", lastErr)
	return ""
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
