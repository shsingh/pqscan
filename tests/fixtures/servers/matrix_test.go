package fixtures

import (
	"crypto/tls"
	"testing"
)

// TestHybridMLKEMNegotiated pins the 4588 observation end to end on the
// local fixture: a client forced to X25519MLKEM768 negotiates it (spec
// Appendix A; PQ-05 grounds its forced-group ladder on this oracle).
func TestHybridMLKEMNegotiated(t *testing.T) {
	addr := StartFixtureServer(t, ServerConfig{
		Name:             "t13-hybrid-mlkem",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // fixture self-signed; the negotiation is the assertion
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial fixture: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	got := uint32(conn.ConnectionState().CurveID)
	if got != 4588 {
		t.Fatalf("negotiated group = %d, want 4588 (X25519MLKEM768)", got)
	}
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatalf("negotiated version = %#x, want TLS 1.3", conn.ConnectionState().Version)
	}
}

// TestHRRRetargetsToServerPreference exercises the hello-retry path: the
// server accepts only the hybrid group, the client offers only P-256; the
// handshake must complete with the server's preference after HRR (the
// tlsx engine's HRR observation in PQ-05 builds directly on this).
func TestHRRRetargetsToServerPreference(t *testing.T) {
	addr := StartFixtureServer(t, ServerConfig{
		Name:             "t13-hrr-required",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	})

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		// client supports both groups but sends its key_share for the
		// first preference only — crypto/tls shares P-256's key; the
		// server (hybrid-only) must hello-retry before completing. The
		// post-HRR result is asserted below.
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519MLKEM768},
		MaxVersion:       tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial fixture: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	if got := uint32(conn.ConnectionState().CurveID); got != 4588 {
		t.Fatalf("post-HRR negotiated group = %d, want 4588", got)
	}
}

// TestSuitesForcedOnTLS12 pins offer-one/observe-accept on the 1.2 plane:
// a client offering exactly one suite negotiates exactly that suite.
func TestSuitesForcedOnTLS12(t *testing.T) {
	addr := StartFixtureServer(t, ServerConfig{
		Name:             "t12-rsa-ecdsa-suites",
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305},
		ALPN:             []string{"h2", "http/1.1"},
	})

	want := uint16(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CurvePreferences:   []tls.CurveID{tls.X25519},
		CipherSuites:       []uint16{want},
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		t.Fatalf("dial fixture: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	cs := conn.ConnectionState()
	if uint16(cs.CipherSuite) != want {
		t.Fatalf("negotiated suite = %#x, want %#x", cs.CipherSuite, want)
	}
	if proto := cs.NegotiatedProtocol; proto != "h2" {
		t.Fatalf("negotiated ALPN = %q, want h2", proto)
	}
}

// TestClassicX25519 pins the classic control row: offering only X25519
// against an X25519-only fixture asserts the baseline before any PQ ladder.
func TestClassicX25519(t *testing.T) {
	addr := StartFixtureServer(t, ServerConfig{
		Name:             "t13-classic-x25519-only",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		CurvePreferences:   []tls.CurveID{tls.X25519},
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial fixture: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	if got := uint32(conn.ConnectionState().CurveID); got != 29 {
		t.Fatalf("negotiated group = %d, want 29 (x25519)", got)
	}
}
