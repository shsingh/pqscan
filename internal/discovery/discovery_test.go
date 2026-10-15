package discovery

// The h3-discovery contract (PQ-25): the hint half against an in-process
// TLS fixture that answers GET / with crafted HTTP/1.1 response bytes (a
// header is text — no real h3 listener is needed for the hint), the
// direct half against the shared quicx h3 fixture (UDP and TCP ports are
// independent namespaces, so both halves can share one port). The live
// cloudflare proof is env-gated per ADR-0002: it never runs offline, and
// the offline suite proves the gate by skipping it.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/quicx"
)

// Crafted HTTP/1.1 response bytes for the hint-half fixture.
const (
	respH3Hint     = "HTTP/1.1 200 OK\r\nServer: pqscan-fixture\r\nAlt-Svc: h3=\":8443\"; ma=86400\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	respNoAltSvc   = "HTTP/1.1 200 OK\r\nServer: pqscan-fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	respH2OnlyHint = "HTTP/1.1 200 OK\r\nServer: pqscan-fixture\r\nAlt-Svc: h2=\":443\"; ma=86400\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
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

// tlsHTTPFixture binds the TLS TCP listener on port and answers the
// request with the crafted response bytes. The accept loop MUST
// handshake (fixture hygiene): a never-handshaken server side presents
// as a client deadline, not an obvious fixture bug. The request is read
// and discarded before the write so a clean close never RSTs the
// response mid-flight.
func tlsHTTPFixture(t *testing.T, port int, resp []byte) {
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

// freeTCPPort grabs an ephemeral port and releases it — a port number
// nothing is bound to (both halves must refuse).
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// portOf extracts the port from a fixture addr ("127.0.0.1:P").
func portOf(t *testing.T, addr string) int {
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

// TestParseAltSvc: the loose directive grammar (RFC 7838) — any h3=
// assignment token marks the hint and the raw value is kept; other
// protocol ids (h2, h3-29-era drafts), clear, and malformed rows do not.
func TestParseAltSvc(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantH3  bool
		wantRaw string
	}{
		{"quoted authority", `h3=":8443"`, true, `h3=":8443"`},
		{"with parameters", `h3=":8443"; ma=86400`, true, `h3=":8443"; ma=86400`},
		{"named authority", `h3="alt.example:443"`, true, `h3="alt.example:443"`},
		{"case-insensitive token", `H3=":443"`, true, `H3=":443"`},
		{"h2 then h3", `h2=":443", h3=":8443"`, true, `h2=":443", h3=":8443"`},
		{"h2 only", `h2=":443"`, false, ""},
		{"draft token is not h3", `h3-29=":8443"`, false, ""},
		{"clear rescinds", `clear`, false, ""},
		{"clear padded", `clear `, false, ""},
		{"empty", "", false, ""},
		{"no assignment is malformed", `h3; ma=86400`, false, ""},
		{"whitespace tolerated", `  h3=":443"  `, true, `  h3=":443"  `},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h3, kept := parseAltSvc(tc.raw)
			if h3 != tc.wantH3 {
				t.Fatalf("parseAltSvc(%q) h3 = %v, want %v", tc.raw, h3, tc.wantH3)
			}
			if kept != tc.wantRaw {
				t.Fatalf("parseAltSvc(%q) raw = %q, want %q", tc.raw, kept, tc.wantRaw)
			}
		})
	}
}

// TestDiscoverFixtures: the full Discover contract against the offline
// fixtures (one port, two transports). Refusals and silence are results,
// not errors; caller aborts and contract misuse are the only errors.
func TestDiscoverFixtures(t *testing.T) {
	type buildResult struct {
		host string
		port uint16
	}
	cases := []struct {
		name      string
		timeout   time.Duration // 0 exercises the Options default fallback
		build     func(t *testing.T) buildResult
		want      Hints
		wantAbort error // sentinel via errors.Is; nil = result path (no error)
	}{
		{
			name:    "alt-svc hint and direct h3 agree",
			timeout: 5 * time.Second,
			build: func(t *testing.T) buildResult {
				addr := quicx.FixtureH3(t, nil) // binds UDP 127.0.0.1:P
				port := portOf(t, addr)
				tlsHTTPFixture(t, port, []byte(respH3Hint)) // TCP on the same P
				return buildResult{"127.0.0.1", uint16(port)}
			},
			want: Hints{AltSvcH3: true, H3Direct: true, AltSvcValue: `h3=":8443"; ma=86400`},
		},
		{
			name: "no alt-svc header = no hint",
			build: func(t *testing.T) buildResult {
				port := freeTCPPort(t)
				tlsHTTPFixture(t, port, []byte(respNoAltSvc))
				return buildResult{"127.0.0.1", uint16(port)}
			},
			want: Hints{},
		},
		{
			name: "alt-svc without h3 token = no hint",
			build: func(t *testing.T) buildResult {
				port := freeTCPPort(t)
				tlsHTTPFixture(t, port, []byte(respH2OnlyHint))
				return buildResult{"127.0.0.1", uint16(port)}
			},
			want: Hints{},
		},
		{
			name: "direct h3 without TLS (quic-only target)",
			build: func(t *testing.T) buildResult {
				addr := quicx.FixtureH3(t, nil)
				return buildResult{"127.0.0.1", uint16(portOf(t, addr))}
			},
			want: Hints{H3Direct: true},
		},
		{
			name:    "transport refused is a result, not an error",
			timeout: 700 * time.Millisecond,
			build: func(t *testing.T) buildResult {
				return buildResult{"127.0.0.1", uint16(freeTCPPort(t))}
			},
			want: Hints{},
		},
		{
			name: "cancelled context aborts",
			build: func(t *testing.T) buildResult {
				return buildResult{"127.0.0.1", uint16(freeTCPPort(t))}
			},
			wantAbort: context.Canceled,
		},
		{
			name:      "empty host is contract misuse",
			build:     func(t *testing.T) buildResult { return buildResult{} },
			wantAbort: errHostRequired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := tc.build(t)
			ctx := context.Background()
			var cancel context.CancelFunc
			if tc.wantAbort != nil {
				ctx, cancel = context.WithCancel(ctx)
				cancel() // pre-cancelled: Discover must still return promptly
			}
			hints, err := Discover(ctx, tr.host, tr.port, Options{Timeout: tc.timeout})
			if !errors.Is(err, tc.wantAbort) {
				t.Fatalf("Discover err = %v, want %v", err, tc.wantAbort)
			}
			if tc.wantAbort != nil {
				if hints != nil {
					t.Fatalf("hints = %+v, want nil on abort", hints)
				}
				return
			}
			if hints == nil {
				t.Fatal("hints = nil on a result path, want zero-valued or populated Hints")
			}
			if *hints != tc.want {
				t.Fatalf("hints = %+v, want %+v", *hints, tc.want)
			}
		})
	}
}

// TestDiscoverEmitsDiagnostics: discovery emits the same decision events
// the planes do (the diag record covers the discovery surface too).
func TestDiscoverEmitsDiagnostics(t *testing.T) {
	sink, err := diag.NewSink(nil, 0)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	diag.SetDefault(sink)
	defer diag.SetDefault(nil)

	addr := quicx.FixtureH3(t, nil)
	port := portOf(t, addr)
	tlsHTTPFixture(t, port, []byte(respH3Hint))
	if _, err := Discover(context.Background(), "127.0.0.1", uint16(port), Options{Timeout: 5 * time.Second}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	rep, err := sink.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	found := false
	for _, e := range rep.Events {
		if e.Domain == diag.DomQuic && e.Op == "h3-discovery" &&
			e.Fields["alt_svc_h3"] == "true" && e.Fields["h3_direct"] == "true" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no h3-discovery diagnostics with alt_svc_h3/h3_direct=true; events=%d", rep.Summary.Events)
	}
}

const integrationEnv = "PQSCAN_INTEGRATION"

// integrationOnly gates live-network truth (never in CI): the gate reads
// the ENVIRONMENT, not the const name (the const merely names the var).
// The offline suite proves the gate by showing the SKIP lines.
func integrationOnly(t *testing.T) {
	t.Helper()
	if os.Getenv(integrationEnv) == "" {
		t.Skip("PQSCAN_INTEGRATION not set; live-network probe skipped")
	}
}

// TestIntegrationDiscoverCloudflare: the real-world proof — hint and
// truth agree on a hybrid edge: cloudflare.com serves alt-svc h3 on the
// HTTP/1.1 response and negotiates h3 over the direct QUIC handshake
// (spec §5.1, §5.3). Env-gated per ADR-0002; no invented transcripts.
func TestIntegrationDiscoverCloudflare(t *testing.T) {
	integrationOnly(t)

	hints, err := Discover(context.Background(), "cloudflare.com", 443, Options{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	t.Logf("cloudflare discovery: %+v", hints)
	if !hints.AltSvcH3 {
		t.Fatalf("alt-svc hint = %v (value %q); cloudflare serves the h3 hint", hints.AltSvcH3, hints.AltSvcValue)
	}
	if !hints.H3Direct {
		t.Fatal("direct h3 = false; want a negotiated QUIC h3 session")
	}
	if hints.AltSvcValue == "" {
		t.Fatal("raw alt-svc value not kept with the hint")
	}
}
