// PTR/SNI/certs-dir wiring tests (PQ-26, issue #49, watched RED): -ptr
// wires the resolver Pool into the pipeline PRE-PROBE — IP targets
// resolve reverse DNS through the pool (injected here, so nothing
// touches real DNS) and the record's ptr + sni_used fill from the
// strategy's candidate per SNIFromPTR; hostname targets never consult
// -certs-dir exports the handshake's end-entity certificate as PEM
// (<dir>/<host>.pem); unknown -sni values are usage-class refusals.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/resolver"
)

// poolFor builds the pool the run's -ptr wiring uses: system resolver
// swapped for a fake table (the resolver package's own injection seam —
// the wiring must not reach real DNS here).
func poolFor(t *testing.T, strategy string, table map[string][]string) *resolver.Pool {
	t.Helper()
	return resolver.New(resolver.Options{
		Workers:     1,
		Timeout:     2 * time.Second,
		CacheSize:   16,
		SNIStrategy: strategy,
		LookupAddr: func(ctx context.Context, addr string) ([]string, error) {
			return table[addr], nil
		},
	})
}

// TestIPTargetSNIWiring (engine level, injected pool): an IP target's
// record carries the pool's answer — ptr the resolved reverse name ("" on
// a miss), sni_used the strategy's candidate; the probe dials with that
// candidate, so the handshake block's facts come back on an SNI the
// strategy picked.
func TestIPTargetSNIWiring(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	const ptrName = "lab.example.com" // the pool strips the root dot
	rows := []struct {
		name        string
		strategy    string
		table       map[string][]string
		wantPtr     string
		wantSNIUsed string
	}{
		{
			name:     "auto with a resolving ptr: the ptr-derived name is the SNI candidate",
			strategy: resolver.StrategyAuto,
			table:    map[string][]string{"127.0.0.1": {"lab.example.com."}},
			wantPtr:  ptrName,
			// the candidate actually used (auto reports the ptr-then-ip
			// rule's win; the record carries the NAME)
			wantSNIUsed: ptrName,
		},
		{
			name:        "auto without a ptr: the fallback candidate is the literal",
			strategy:    resolver.StrategyAuto,
			table:       nil,
			wantPtr:     "",
			wantSNIUsed: "127.0.0.1",
		},
		{
			name:        "ptr-then-ip without a ptr: same fallback candidate",
			strategy:    resolver.StrategyPTRThenIP,
			table:       nil,
			wantPtr:     "",
			wantSNIUsed: "127.0.0.1",
		},
		{
			name:     "ip-only ignores the ptr (enrichment still records it)",
			strategy: resolver.StrategyIPOnly,
			table:    map[string][]string{"127.0.0.1": {"lab.example.com."}},
			wantPtr:  ptrName,
			// ip-only's candidate is always the literal
			wantSNIUsed: "127.0.0.1",
		},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			pool := poolFor(t, row.strategy, row.table)
			recs, err := (&Engine{}).Run(mustParse(t, []string{hybridAddr}),
				Options{QuicOff: true, ProbeTimeout: 2 * time.Second, PtrPool: pool}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(recs) != 1 {
				t.Fatalf("records = %d, want 1", len(recs))
			}
			rec := recs[0]
			if rec.Target.Ptr != row.wantPtr {
				t.Fatalf("record ptr = %q, want %q", rec.Target.Ptr, row.wantPtr)
			}
			if rec.Target.SNIUsed != row.wantSNIUsed {
				t.Fatalf("record sni_used = %q, want %q", rec.Target.SNIUsed, row.wantSNIUsed)
			}
			if rec.Error != "" {
				t.Fatalf("the probe should have dialed with the strategy's SNI: %q", rec.Error)
			}
			if rec.Handshake.Negotiated == 0 {
				t.Fatalf("the handshake never negotiated (the probe ignored the wiring)")
			}
		})
	}
}

// TestHostTargetSkipsPTR: a hostname target's SNI is the host — the pool
// (and the record's ptr/sni_used) must stay untouched for it.
func TestHostTargetSkipsPTR(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	_, port, _ := strings.Cut(hybridAddr, ":")
	spec := "local.host.example:" + port
	table := map[string][]string{"127.0.0.1": {"lab.example.com."}}
	pool := poolFor(t, resolver.StrategyAuto, table)
	recs, err := (&Engine{}).Run(mustParse(t, []string{spec}),
		Options{QuicOff: true, ProbeTimeout: 2 * time.Second, PtrPool: pool}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	if recs[0].Target.Ptr != "" || recs[0].Target.SNIUsed != "" {
		t.Fatalf("hostname target enriched (ptr=%q sni_used=%q): the pool must serve IP targets only",
			recs[0].Target.Ptr, recs[0].Target.SNIUsed)
	}
	if stats := pool.Stats(); stats.Lookups != 0 {
		t.Fatalf("the pool saw %d lookups for a hostname-only run, want 0", stats.Lookups)
	}
}

// TestSNIStrategyValidation: a bogus -sni is a usage-class refusal
// naming the offending value, before anything composes or scans.
func TestSNIStrategyValidation(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-u", "127.0.0.1:443", "-ptr", "-sni", "bogus"}, &out, &errOut)
	if code != 64 {
		t.Fatalf("exit = %d, want 64 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "unknown -sni") || !strings.Contains(errOut.String(), "bogus") {
		t.Fatalf("the refusal should name the unknown strategy: %q", errOut.String())
	}
}

// TestPQ26FlagRegistration: the three flags register via the fs shapes
// the usage-drift gate reads; a parse lands on the no-targets refusal,
// never the flag-provided-but-not-defined artifact.
func TestPQ26FlagRegistration(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-ptr", "-sni", "auto", "-certs-dir", t.TempDir()}, &out, &errOut)
	if code != 64 {
		t.Fatalf("exit = %d, want 64 (no targets; stderr: %s)", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "flag provided but not defined") {
		t.Fatalf("the PQ-26 flags did not register: %q", errOut.String())
	}
}

// TestCertsDirExport (run level): -certs-dir writes the scanned host's
// end-entity certificate as PEM (<dir>/<host>.pem); a parseable
// CERTIFICATE block, and nothing written for a target whose probe never
// reached a handshake.
func TestCertsDirExport(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	deadAddr := closedLoopbackPort(t)
	dir := t.TempDir()

	var out, errOut bytes.Buffer
	code := run([]string{"-u", hybridAddr, "-quic-off", "-certs-dir", dir,
		"-jsonl", "-o", filepath.Join(t.TempDir(), "certs.jsonl")}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut.String())
	}
	pemBytes, err := os.ReadFile(filepath.Join(dir, "127.0.0.1.pem"))
	if err != nil {
		t.Fatalf("the scanned host's PEM is missing: %v (stderr: %s)", err, errOut.String())
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("the export is not a CERTIFICATE PEM block (%d bytes)", len(pemBytes))
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("the exported DER does not parse: %v", err)
	}

	// a failed probe exports nothing (no invented data)
	deadDir := t.TempDir()
	errOut.Reset()
	code = run([]string{"-u", deadAddr, "-quic-off", "-certs-dir", deadDir}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d for the dead-target run (stderr: %s)", code, errOut.String())
	}
	entries, _ := os.ReadDir(deadDir)
	if len(entries) != 0 {
		t.Fatalf("a failed probe wrote %d PEMs, want none", len(entries))
	}
}
