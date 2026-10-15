package tlsx

import (
	"os"
	"testing"
	"time"
)

// Live-network ground truth for the capability matrix. Skipped unless
// PQSCAN_INTEGRATION=1: CI stays offline; a maintainer runs these before
// the M0 gate closes (spec §10.1).
func integrationOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("PQSCAN_INTEGRATION") == "" {
		t.Skip("PQSCAN_INTEGRATION not set; live-network probe skipped")
	}
}

// TestIntegrationCloudflareHybrid: a known hybrid-negotiating endpoint —
// forced 4588 must negotiate 4588 through the stdlib path.
func TestIntegrationCloudflareHybrid(t *testing.T) {
	integrationOnly(t)

	r, err := ProbeNegotiated("cloudflare.com:443", "cloudflare.com", []uint32{4588}, 8*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	t.Logf("cloudflare 4588-forced: %+v", r)
	if r.State != "negotiated" {
		t.Fatalf("state = %q (%s); want negotiated", r.State, r.Error)
	}
	if r.Negotiated != 4588 {
		t.Fatalf("negotiated group = %d, want 4588", r.Negotiated)
	}
}

// TestIntegrationKyberDraftOracle: the obsolete-Kyber draft group offered
// share-less to a modern endpoint — every outcome (hrr / alert / sh) is a
// recorded fact; this test pins the ORACLE CONTRACT (no crash, one
// observation) rather than a specific server behaviour.
func TestIntegrationKyberDraftOracle(t *testing.T) {
	integrationOnly(t)

	obs, err := SendHelloProbe("cloudflare.com:443", "cloudflare.com", []uint32{25497}, 0)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	t.Logf("kyber-draft oracle observation: %+v", obs)
	switch obs.State {
	case StateHRR, StateAlert, StateSH:
		t.Logf("oracle contract satisfied: state=%s requested=%d alert=%d", obs.State, obs.RequestedGroup, obs.AlertDesc)
	default:
		t.Fatalf("unexpected oracle state %q", obs.State)
	}
}
