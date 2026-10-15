package quicx

import (
	"crypto/tls"
	"os"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/diag"
)

// quicFixture is the in-package shim over the shared fixture (FixtureH3,
// exported so sibling packages' tests reuse the same offline ground truth).
func quicFixture(t *testing.T, curvePrefs []tls.CurveID) string {
	t.Helper()
	return FixtureH3(t, curvePrefs)
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

// integrationOnly gates live-network truth (never in CI): the gate reads
// the ENVIRONMENT, not the const name — the const merely names the var
// (PQ-13: this helper previously returned the const itself, so the gate
// was always open and quic integration probes ran live in offline runs;
// regression-proven by the offline suite skipping them).
func integrationOnly(t *testing.T) {
	t.Helper()
	if os.Getenv(quicIntegrationEnv) == "" {
		t.Skip("PQSCAN_INTEGRATION not set; live-network probe skipped")
	}
}

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
