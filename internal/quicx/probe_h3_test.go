package quicx

// probe_h3_test.go — the functional HTTP/3 exchange's behaviour pair
// (PQ-69, issue #181, ADR-0002): the probe reads the server's SETTINGS
// frame and completes ONE HTTP/3 GET against the serving fixture; a
// listener without an h3 layer rides its own class; the server's ALPN
// answer and the dial classes ride verbatim/the class words.

import (
	"strings"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/diag"
)

// TestH3ExchangeCompletes: the serving fixture answers the exchange —
// SETTINGS read, one GET / completed with its status, the ALPN named.
func TestH3ExchangeCompletes(t *testing.T) {
	addr := FixtureH3(t, nil)

	r, err := VerifyH3Exchange(addr, "pqscan.fixture", 3*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if r.State != "negotiated" {
		t.Fatalf("state = %q, want negotiated", r.State)
	}
	if r.ALPN != H3ALPN {
		t.Fatalf("alpn = %q, want h3", r.ALPN)
	}
	if !r.Settings {
		t.Fatal("the serving fixture never sent its SETTINGS frame")
	}
	if r.Status != 200 {
		t.Fatalf("status = %d, want 200 (the completed GET)", r.Status)
	}
	if r.ExchangeErr != "" {
		t.Fatalf("exchange error on a completed run: %q", r.ExchangeErr)
	}
	if r.Err != "" {
		t.Fatalf("dial error on a completed run: %q", r.Err)
	}
}

// TestH3ExchangeNoSettingsIsItsOwnClass: a listener that negotiates h3
// but carries no h3 layer answers no SETTINGS frame and no exchange —
// the broken-h3-path class (state negotiated, no status, the class
// words on ExchangeErr).
func TestH3ExchangeNoSettingsIsItsOwnClass(t *testing.T) {
	addr := FixtureQUICNoH3(t)

	r, err := VerifyH3Exchange(addr, "pqscan.fixture", 2*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if r.State != "negotiated" {
		t.Fatalf("state = %q, want negotiated (the QUIC handshake answered)", r.State)
	}
	if r.Settings {
		t.Fatal("a layer-less listener sent SETTINGS; the class is broken")
	}
	if r.Status != 0 {
		t.Fatalf("status = %d, want 0 (no completed exchange)", r.Status)
	}
	if want := h3NoSettings; r.ExchangeErr != want {
		t.Fatalf("exchange error = %q, want %q", r.ExchangeErr, want)
	}
}

// TestH3ExchangeStrangerALPNIsTheServerAnswer: a listener whose ALPN
// vocabulary excludes h3 answers the offer with its alert — the remote's
// decision, carried verbatim (the executor maps it a rejected row).
func TestH3ExchangeStrangerALPNIsTheServerAnswer(t *testing.T) {
	addr := FixtureQUICStrangerALPN(t)

	r, err := VerifyH3Exchange(addr, "pqscan.fixture", 3*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if r.State == "negotiated" {
		t.Fatalf("the stranger-ALPN listener negotiated the h3 offer: %+v", r)
	}
	if want := "no application protocol"; !strings.Contains(r.Err, want) {
		t.Fatalf("err = %q, want the ALPN non-overlap alert's words", r.Err)
	}
}

// TestH3ExchangeRefusedClassifies: a dead port's h3 dial records its
// class as a result, never an error.
func TestH3ExchangeRefusedClassifies(t *testing.T) {
	r, err := VerifyH3Exchange("127.0.0.1:1", "pqscan.fixture", 2*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if r.State == "negotiated" {
		t.Fatal("negotiated against a dead port; classification broken")
	}
}

// TestH3ExchangeEmitsDiagnostics: the exchange rides the DomQuic
// decision record (the debug surface covers the rung's planes).
func TestH3ExchangeEmitsDiagnostics(t *testing.T) {
	sink, _ := diag.NewSink(nil, 0)
	diag.SetDefault(sink)
	defer diag.SetDefault(nil)

	addr := FixtureH3(t, nil)
	if _, err := VerifyH3Exchange(addr, "pqscan.fixture", 3*time.Second); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	rep, err := sink.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	found := false
	for _, e := range rep.Events {
		if e.Domain == diag.DomQuic && e.Op == "h3-exchange" && e.Fields["status"] == "200" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no h3-exchange diagnostics row carrying status=200; events=%d", rep.Summary.Events)
	}
}
