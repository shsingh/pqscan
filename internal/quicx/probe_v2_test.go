package quicx

// probe_v2_test.go — the RFC 9369 transport-version probe's behaviour
// pair (PQ-69, issue #181, ADR-0002): the v2 offer negotiates on a
// v2-pinned listener; a v1-only listener's version-negotiation answer
// rides the result verbatim; the dial classes stay results (never
// errors); the finding detail's version tokens carry both versions.

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

// TestQuicV2NegotiatesH3: the v2 offer, ALPN h3 — a v2-pinned listener
// answers the connection on QUIC v2 with the negotiated group riding it.
func TestQuicV2NegotiatesH3(t *testing.T) {
	addr := FixtureH3V2(t, []tls.CurveID{tls.X25519MLKEM768, tls.X25519})

	r, err := ProbeQUICV2(addr, "pqscan.fixture", 3*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if r.State != "negotiated" {
		t.Fatalf("state = %q, want negotiated", r.State)
	}
	if r.Version != 0x6b3343cf { // RFC 9369's QUIC v2 transport-version code
		t.Fatalf("quic version = %#x, want 0x6b3343cf", r.Version)
	}
	if r.Group != 4588 {
		t.Fatalf("negotiated group = %d, want 4588", r.Group)
	}
	if r.GroupClass != "pq_hybrid" {
		t.Fatalf("group class = %q, want pq_hybrid", r.GroupClass)
	}
	if r.ALPN != H3ALPN {
		t.Fatalf("alpn = %q, want h3", r.ALPN)
	}
}

// TestQuicV2VersionNegotiationMissIsTheServerAnswer: a v1-only listener
// answers the v2-only offer with a version-negotiation error — the
// server's capability answer, carried verbatim on the result (the
// executor maps it a rejected row; the exact words stay the server's).
func TestQuicV2VersionNegotiationMissIsTheServerAnswer(t *testing.T) {
	addr := FixtureQUICNoH3(t) // a v1-only transport listener

	r, err := ProbeQUICV2(addr, "pqscan.fixture", 3*time.Second)
	if err != nil {
		t.Fatalf("probe: %v — rejections are results", err)
	}
	if r.State == "negotiated" {
		t.Fatalf("the v1-only listener negotiated the v2-only offer: %+v", r)
	}
	if want := "no compatible QUIC version found (we support [v2], server offered"; !strings.Contains(r.Err, want) {
		t.Fatalf("err = %q, want the version-negotiation miss shape %q", r.Err, want)
	}
}

// TestQuicV2RefusedClassifies: a dead port's v2 dial records its class
// as a result (never an error return).
func TestQuicV2RefusedClassifies(t *testing.T) {
	r, err := ProbeQUICV2("127.0.0.1:1", "pqscan.fixture", 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if r.State == "negotiated" {
		t.Fatal("negotiated against a dead port; classification broken")
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
