package quicx

import (
	"testing"
	"time"
)

// TestCostMeasurement: per-session QUIC cost on the loopback fixture —
// the 10k budget inputs (spec §7.5); run under integration flag for the
// PR evidence.
func TestCostMeasurement(t *testing.T) {
	integrationOnly(t)
	addr := "google.com:443"
	stats, err := MeasureCost(addr, "cloudflare.com", 15, 8*time.Second)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	t.Logf("quic per-conn cost (n=%d): avg_handshake_ms=%.1f goroutine_delta=%d heap_kb=%.0f", stats.Sessions, stats.AvgTotalMs, stats.Goroutines, stats.HeapDeltaKB)
}
