package tlsx

import (
	"crypto/tls"
	"testing"

	fixtures "github.com/shsingh/pqscan/tests/fixtures/servers"
)

// TestRawProbeDetectsHRR pins the on-the-wire HRR observation against the
// fixture matrix: the client shares only x25519; the hybrid-only fixture
// must hello-retry, and the probe must extract the server's demanded
// group (4588) from the retry's key_share extension.
func TestRawProbeDetectsHRR(t *testing.T) {
	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-hrr-required",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	})

	// offer both groups but share only x25519: the hybrid-only server
	// cannot use the offered share and must hello-retry to demand its
	// preferred (4588) group — the exact HRR condition the tlsx engine
	// observes on real hosts.
	obs, err := SendHelloProbe(addr, "pqscan.fixture", []uint32{4588, 29}, 29)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if obs.State != StateHRR {
		t.Fatalf("state = %q, want hrr (obs: %+v)", obs.State, obs)
	}
	if obs.RequestedGroup != 4588 {
		t.Fatalf("requested group = %d, want 4588", obs.RequestedGroup)
	}
}

// TestRawProbeSeesPlainServerHello pins the no-HRR path: the share
// matches the server preference and the first flight is an ordinary
// ServerHello.
func TestRawProbeSeesPlainServerHello(t *testing.T) {
	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-classic-x25519-only",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})

	obs, err := SendHelloProbe(addr, "pqscan.fixture", []uint32{29}, 29)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if obs.State != StateSH {
		t.Fatalf("state = %q, want sh", obs.State)
	}
	if obs.RequestedGroup != 0 {
		t.Fatalf("no HRR expected; requested group = %d", obs.RequestedGroup)
	}
}

// TestRawProbeEmptyShareOffer pins the share-less oracle offer: the
// fixture (needs a share it cannot elicit) answers with an alert — a
// recorded observation, not a crash.
func TestRawProbeEmptyShareOffer(t *testing.T) {
	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-classic-x25519-only",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	})

	obs, err := SendHelloProbe(addr, "pqscan.fixture", []uint32{25497}, 0)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	switch obs.State {
	case StateAlert, StateHRR, StateSH:
		// any of these is a legitimate server answer to a Kyber-draft
		// offer; the ladder records it as-is
	default:
		t.Fatalf("state = %q; expected alert/hrr/sh from a real stack", obs.State)
	}
}

// TestLadderNegotiatesBothPaths pins the ladder composition on the
// fixture matrix: the standards-track hybrid via the stdlib path
// (negotiated 4588) and the oracle via the raw path.
func TestLadderNegotiatesBothPaths(t *testing.T) {
	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-hybrid-mlkem",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})

	results := GroupLadder(addr, "pqscan.fixture", []uint32{4588, 29}, 5e9)
	if len(results) != 2 {
		t.Fatalf("ladder produced %d results, want 2", len(results))
	}
	hybrid := results[0]
	if hybrid.State != "negotiated" || hybrid.Negotiated != 4588 {
		t.Fatalf("hybrid step = %+v; want negotiated 4588", hybrid)
	}
	if hybrid.Suite != "TLS_AES_128_GCM_SHA256" && hybrid.Suite != "TLS_AES_256_GCM_SHA384" && hybrid.Suite != "TLS_CHACHA20_POLY1305_SHA256" {
		t.Fatalf("hybrid suite = %q; want a TLS 1.3 suite", hybrid.Suite)
	}
	classic := results[1]
	if classic.State != "negotiated" || classic.Negotiated != 29 {
		t.Fatalf("classic step = %+v; want negotiated 29", classic)
	}
}
