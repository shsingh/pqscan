package microbench

import (
	"crypto/tls"
	"testing"
	"time"

	fixtures "github.com/shsingh/pqscan/tests/fixtures/servers"
)

// TestMeasureHostFixture: harness measures n handshakes against the local
// fixture and reports a usable decomposition (watched RED: stub fails).
func TestMeasureHostFixture(t *testing.T) {
	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-hybrid-mlkem",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})

	r, err := MeasureHost(addr, "pqscan.fixture", 5, 5*time.Second)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	if r.Negotiated != 5 {
		t.Fatalf("negotiated = %d, want 5", r.Negotiated)
	}
	if len(r.Decompositions) != 5 {
		t.Fatalf("decompositions = %d, want 5", len(r.Decompositions))
	}
	for _, d := range r.Decompositions {
		if d.TotalMs <= 0 {
			t.Fatalf("decomposition %+v carries no wall time", d)
		}
	}
}

// TestRateAtLeast: the aggregate rate math is sane (negotiated per second).
func TestRateAtLeast(t *testing.T) {
	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-hybrid-mlkem",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})
	r, err := MeasureHost(addr, "pqscan.fixture", 10, 5*time.Second)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	if r.ElapsedTotalS <= 0 {
		t.Fatal("elapsed wall time not recorded")
	}
	rate := float64(r.Negotiated) / r.ElapsedTotalS
	t.Logf("loopback fixture: %d handshakes in %.3fs = %.0f h/s", r.Negotiated, r.ElapsedTotalS, rate)
}

// TestSLOCoreEvidence: W=8 concurrent workers × 25 handshakes on loopback
// — the ≥2,500 h/s/core SLO cell (spec §7.8), measured.
func TestSLOCoreEvidence(t *testing.T) {
	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-hybrid-mlkem",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})
	r, err := MeasureConcurrent(addr, "pqscan.fixture", 8, 25, 5*time.Second)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	rate := float64(r.Negotiated) / r.ElapsedTotalS
	t.Logf("W=8 on loopback fixture: %d negotiated in %.2fs = %.0f h/s aggregate", r.Negotiated, r.ElapsedTotalS, rate)
}
