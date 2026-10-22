// QUIC lane wiring tests (PQ-25, issue #48, watched RED): the fast pass's
// alt-svc h3 hint DECIDES the direct QUIC probe — hint present → attempt,
// absent → the honest "skipped: no alt-svc h3 hint" informational state
// (never an error; the exit code never moves on it); -quic-always forces
// the direct probe regardless of the hint; -quic-off skips the plane at
// the highest precedence; a hint/truth disagreement is a FINDING (the
// record's mismatch state + flag + the diagnostics finding row); deep
// mode plans the QUIC group rungs exactly when the lane ran. Offline
// ground truth: quicx's h3 fixture + discovery's alt-svc fixture on one
// loopback port (the discovery tests' two-halves trick).
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/discovery"
	"github.com/shsingh/pqscan/internal/out"
	"github.com/shsingh/pqscan/internal/quicx"
	"github.com/shsingh/pqscan/internal/tlsx"
)

// The crafted HTTP/1.1 responses the hint-half fixture answers with.
const (
	quicRespH3Hint = "HTTP/1.1 200 OK\r\nServer: pqscan-fixture\r\nAlt-Svc: h3=\":8443\"; ma=86400\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	quicRespPlain  = "HTTP/1.1 200 OK\r\nServer: pqscan-fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)

// startHintedQUICFixture spins the coupled lane fixture (the discovery
// package's FixtureH3AndHint): BOTH halves of one loopback port bound and
// held, retried as a pair under concurrent package binaries. resp carries
// the crafted HTTP/1.1 answer — the h3-hint or the plain (no-alt-svc)
// response.
func startHintedQUICFixture(t *testing.T, resp string) string {
	t.Helper()
	return discovery.FixtureH3AndHint(t, []byte(resp))
}

// quicRecordOf decodes the first record's quic block.
func quicRecordOf(t *testing.T, rec *scanRecord) *out.QuicRecord {
	t.Helper()
	if rec.Quic == nil {
		t.Fatal("the record carries no quic block — the lane never wrote its state")
	}
	return rec.Quic
}

// TestQUICHintGateMatrix (engine level): the gate matrix — hint yes/no ×
// always/off — against the loopback fixtures. Every row asserts the
// record's quic block shape the run's exit code never moves on.
func TestQUICHintGateMatrix(t *testing.T) {
	hintedQUIC := startHintedQUICFixture(t, quicRespH3Hint)
	hintlessQUIC := startHintedQUICFixture(t, quicRespPlain) // TCP speaks, no UDP hint half... both bound; no hint

	rows := []struct {
		name        string
		addr        string
		always, off bool
		check       func(t *testing.T, q *out.QuicRecord)
	}{
		{
			name: "hint present: the direct probe runs and the halves agree",
			addr: hintedQUIC,
			check: func(t *testing.T, q *out.QuicRecord) {
				if !q.Attempted {
					t.Fatal("hint present: the direct probe did not attempt")
				}
				if q.State != "negotiated" {
					t.Fatalf("state = %q, want negotiated (the fixture speaks h3)", q.State)
				}
				if q.Discovered == nil || !q.Discovered.AltSvcH3 || !q.Discovered.H3Direct {
					t.Fatalf("discovered = %+v, want {alt_svc_h3:true h3_direct:true}", q.Discovered)
				}
				if q.Mismatch {
					t.Fatal("consistent halves must never set the mismatch flag")
				}
				if q.Negotiated == 0 {
					t.Fatalf("negotiated group = 0 (block %+v)", q)
				}
			},
		},
		{
			name: "hint present but -quic-off: the plane never runs",
			addr: hintedQUIC,
			off:  true,
			check: func(t *testing.T, q *out.QuicRecord) {
				if q.Attempted {
					t.Fatal("-quic-off must keep the highest precedence")
				}
				if q.State != "" {
					t.Fatalf("state = %q, want empty (the shipped -quic-off shape)", q.State)
				}
				// PQ-54 (issue #148): the record contract never omits a
				// required key — the plane's skipped fact rides the zero
				// discovery halves instead of a nil block
				if q.Discovered == nil || q.Discovered.AltSvcH3 || q.Discovered.H3Direct {
					t.Fatalf("discovered = %+v, want both halves false under -quic-off (the discovery never ran)", q.Discovered)
				}
			},
		},
		{
			name: "hint absent: the honest informational skip",
			addr: hintlessQUIC,
			check: func(t *testing.T, q *out.QuicRecord) {
				if q.Attempted {
					t.Fatalf("hint absent: the probe ran anyway (state %q)", q.State)
				}
				if q.State != discovery.SkipStateNoHint {
					t.Fatalf("state = %q, want %q (the honest skip token)", q.State, discovery.SkipStateNoHint)
				}
				if q.Discovered == nil || q.Discovered.AltSvcH3 || q.Discovered.H3Direct {
					t.Fatalf("discovered = %+v, want both halves false (hint absent, no probe ran)", q.Discovered)
				}
				if q.Mismatch {
					t.Fatal("an unprobed skip is information, not a mismatch")
				}
			},
		},
		{
			name:   "hint absent but -quic-always: the direct truth answers",
			addr:   hintlessQUIC,
			always: true,
			check: func(t *testing.T, q *out.QuicRecord) {
				if !q.Attempted {
					t.Fatal("-quic-always forced the probe, the record never attempted it")
				}
				if q.Discovered == nil || q.Discovered.AltSvcH3 || !q.Discovered.H3Direct {
					t.Fatalf("discovered = %+v, want alt_svc_h3:false h3_direct:true (the unhinted truth)", q.Discovered)
				}
				// The hint said no and the truth said yes: the mismatch
				// finding rides its own test; this row pins only that
				// the probe RAN.
			},
		},
		{
			name:   "hint absent, -quic-always AND -quic-off: off wins",
			addr:   hintlessQUIC,
			always: true,
			off:    true,
			check: func(t *testing.T, q *out.QuicRecord) {
				// PQ-54 (issue #148): -quic-off still encodes its
				// schema-required discovered block — the zero halves
				if q.Attempted {
					t.Fatal("-quic-off must keep the highest precedence")
				}
				if q.Discovered == nil || q.Discovered.AltSvcH3 || q.Discovered.H3Direct {
					t.Fatalf("quic-off lost to -quic-always or dropped its discovery block (state %q, discovered %+v)", q.State, q.Discovered)
				}
			},
		},
		{
			name: "IP target joins the same gate: hint present, probe runs",
			addr: hintedQUIC,
			check: func(t *testing.T, q *out.QuicRecord) {
				if !q.Attempted || q.State != "negotiated" {
					t.Fatalf("IP target with the hint: state %q attempted %v", q.State, q.Attempted)
				}
			},
		},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			opts := Options{QuicOff: row.off, QuicAlways: row.always, ProbeTimeout: time.Second}
			recs, err := (&Engine{}).Run(mustParse(t, []string{row.addr}), opts, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(recs) != 1 {
				t.Fatalf("records = %d, want 1", len(recs))
			}
			rec := recs[0]
			if rec.Error != "" {
				t.Fatalf("the profile dial failed, the lane never gated: %q", rec.Error)
			}
			row.check(t, quicRecordOf(t, rec))
		})
	}
}

// TestQUICMismatchIsAFinding (the RED core): a hint/truth disagreement is
// recorded as the mismatch state + flag — NEVER an error. Both
// directions: the hint that answers h3 while the direct QUIC plane stays
// silent, and the h3 that speaks with no hint ever sent (-quic-always).
func TestQUICMismatchIsAFinding(t *testing.T) {
	t.Run("hint=yes truth=no: the hint lied", func(t *testing.T) {
		// TCP speaks the h3 hint; the UDP plane answers nothing.
		port := discovery.FixtureHintHTTP(t, 0, []byte(quicRespH3Hint)) // binds and holds its own number
		rec, err := singleScan(t, "127.0.0.1:"+fmt.Sprint(port), Options{ProbeTimeout: 500 * time.Millisecond})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		q := quicRecordOf(t, rec)
		if q.State != "mismatch: hint=yes truth=no" {
			t.Fatalf("state = %q, want the hint-lied mismatch token (block %+v)", q.State, q)
		}
		if !q.Mismatch {
			t.Fatal("the mismatch flag did not ride the finding")
		}
		if q.Discovered == nil || !q.Discovered.AltSvcH3 || q.Discovered.H3Direct {
			t.Fatalf("discovered = %+v, want the hint asserted and the truth absent", q.Discovered)
		}
		if rec.Error != "" {
			t.Fatalf("the mismatch is a finding, not an error: %q", rec.Error)
		}
	})
	t.Run("hint=no truth=yes: h3 speaks unhinted", func(t *testing.T) {
		// The TCP plane speaks TLS+h1 but sends no alt-svc; the UDP
		// plane answers the forced probe. (A TCP-refusing endpoint never
		// reaches the lane at all: the profile's own error record.)
		addr := startHintedQUICFixture(t, quicRespPlain)
		rec, err := singleScan(t, addr, Options{QuicAlways: true, ProbeTimeout: time.Second})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		q := quicRecordOf(t, rec)
		if q.State != "mismatch: hint=no truth=yes" {
			t.Fatalf("state = %q, want the unhinted-h3 mismatch token (block %+v)", q.State, q)
		}
		if !q.Mismatch {
			t.Fatal("the mismatch flag did not ride the finding")
		}
		if q.Discovered == nil || q.Discovered.AltSvcH3 || !q.Discovered.H3Direct {
			t.Fatalf("discovered = %+v, want the truth without the hint", q.Discovered)
		}
		if q.Negotiated == 0 {
			t.Fatalf("the truth half's negotiated group vanished (block %+v)", q)
		}
	})
	t.Run("exit code unaffected by either mismatch direction (run level)", func(t *testing.T) {
		port := discovery.FixtureHintHTTP(t, 0, []byte(quicRespH3Hint)) // binds and holds its own number
		var stdout, stderr bytes.Buffer
		code := run([]string{"-u", "127.0.0.1:" + fmt.Sprint(port), "-jsonl",
			"-o", filepath.Join(t.TempDir(), "quic.jsonl")}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 — a mismatch finding is not an error (stderr: %s)", code, stderr.String())
		}
	})
}

// TestQUICMismatchEmitsDiagnosticRow: the finding row also lands in the
// diagnostics record (the -debug surface) with the hint/truth fields.
func TestQUICMismatchEmitsDiagnosticRow(t *testing.T) {
	sink, err := diag.NewSink(nil, 0)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	diag.SetDefault(sink)
	defer diag.SetDefault(nil)

	port := discovery.FixtureHintHTTP(t, 0, []byte(quicRespH3Hint)) // binds and holds its own number
	if _, err := singleScan(t, "127.0.0.1:"+fmt.Sprint(port), Options{ProbeTimeout: 500 * time.Millisecond}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	rep, err := sink.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	found := false
	for _, e := range rep.Events {
		if e.Domain == diag.DomQuic && strings.Contains(e.Op, "mismatch") &&
			e.Fields["hint"] == "yes" && e.Fields["truth"] == "no" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no h3-mismatch diagnostics row; events=%d", rep.Summary.Events)
	}
}

// TestQuicAlwaysFlagRegistration: the additive flag registers via the fs
// shape the usage-drift gate reads and reaches the pipeline (the record's
// blocked gate opens on the forced path).
func TestQuicAlwaysFlagRegistration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	addr := startHintedQUICFixture(t, quicRespPlain) // no hint: the flag is the only way the probe runs
	dir := t.TempDir()
	code := run([]string{"-u", addr, "-quic-always", "-jsonl",
		"-o", filepath.Join(dir, "always.jsonl")}, &stdout, &stderr)
	if code != 0 {
		if strings.Contains(stderr.String(), "flag provided but not defined") {
			t.Fatalf("-quic-always did not register: %q", stderr.String())
		}
		t.Fatalf("exit = %d (stderr: %s)", code, stderr.String())
	}
	data, err := os.ReadFile(filepath.Join(dir, "always.jsonl"))
	if err != nil {
		t.Fatalf("read back: %v (stderr: %s)", err, stderr.String())
	}
	var rec out.Record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("jsonl: %v", err)
	}
	if rec.Quic == nil || !rec.Quic.Attempted {
		t.Fatalf("the forced probe never attempted (quic=%+v)", rec.Quic)
	}
	line := string(data)
	if !strings.Contains(line, `"discovered":{"alt_svc_h3":false,"h3_direct":true}`) {
		t.Fatalf("the quic block carries no discovered halves: %s", line)
	}
	// The unhinted truth answering = the mismatch finding's state.
	if rec.Quic.State != "mismatch: hint=no truth=yes" || !rec.Quic.Mismatch {
		t.Fatalf("quic state = %q mismatch = %v, want the unhinted-h3 mismatch", rec.Quic.State, rec.Quic.Mismatch)
	}
}

// TestDeepQUICEnumerationRows (issue #48, #181): deep mode plans the
// QUIC group rungs exactly when the lane ran, and PQ-69's two non-group
// rungs close the ladder. The rung facts: the negotiated-4588 rung
// fact-pruned (the profile's QUIC probe already answered 4588), the
// stdlib-shareable rungs probed against the h3 fixture, the exotic rungs
// honest refused rows (the UDP plane's no-raw-path deferral), the v2
// rung's accepted row on the multi-version listener, the h3-exchange
// rung's row — and the record's quic block still carries the profile
// shape.
func TestDeepQUICEnumerationRows(t *testing.T) {
	addr := startHintedQUICFixture(t, quicRespH3Hint)
	recs, err := (&Engine{}).Run(mustParse(t, []string{addr}),
		Options{Mode: modeDeep, ProbeTimeout: 2 * time.Second}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rec := recs[0]
	if rec.Error != "" {
		t.Fatalf("the fixture round tripped, the deep run errored anyway: %q", rec.Error)
	}
	q := quicRecordOf(t, rec)
	if q.Discovered == nil || !q.Discovered.AltSvcH3 || !q.Discovered.H3Direct {
		t.Fatalf("the profile's quic block lost the discovery halves: %+v", q.Discovered)
	}
	if rec.Deep == nil {
		t.Fatal("the deep block stayed nil")
	}
	var quicRows []out.DeepFinding
	for _, f := range rec.Deep.Findings {
		if strings.HasPrefix(f.Probe, "quic/") {
			quicRows = append(quicRows, f)
		}
	}
	if len(quicRows) != 7 {
		t.Fatalf("quic rungs = %d (%v: %+v), want 7 (the 4588 rung is the QuicNegotiated-fact-pruned one; PQ-69's v2 + h3-exchange rungs close the ladder)",
			len(quicRows), rungNamesOf(quicRows), quicRows)
	}
	for _, name := range []string{"quic/4585", "quic/4586", "quic/4587", "quic/4589", "quic/4590", "quic/v2", "quic/h3-exchange"} {
		found := false
		for _, f := range quicRows {
			if f.Probe == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("quic rung %s missing from the deep findings (%s)", name, rungNamesOf(quicRows))
		}
	}

	// The stdlib-shareable rungs probed for real: the fixture accepts
	// the hybrid shares.
	for _, f := range quicRows {
		if f.Probe == "quic/4587" || f.Probe == "quic/4589" {
			if f.Result != tlsx.SuiteAccepted {
				t.Fatalf("%s: result = %q (%s), want accepted (the fixture constructs the share)", f.Probe, f.Result, f.Detail)
			}
			continue
		}
		if f.Probe == "quic/v2" || f.Probe == "quic/h3-exchange" {
			continue // the PQ-69 rungs' shapes pin in their own tests
		}
		if f.Result != tlsx.SuiteRefused {
			t.Fatalf("%s: result = %q (%s), want the honest not-offerable refusal (the UDP plane has no share-less path)", f.Probe, f.Result, f.Detail)
		}
		if !strings.HasPrefix(f.Detail, "not-offerable on quic:") {
			t.Fatalf("%s: refused detail = %q, want the not-offerable-on-quic grammar", f.Probe, f.Detail)
		}
	}
	if rec.Deep.Attempted != 24 {
		t.Fatalf("deep attempted = %d, want 24 (the structural landing with the 7 quic rungs)", rec.Deep.Attempted)
	}
}

// TestDeepQuicV2RungRows (PQ-69, issue #181): the RFC 9369 rung's
// dispatch. The v2 offer negotiates on the v2-pinned listener (the
// quic-v2 detail tail); a v1-only listener's version-negotiation answer
// rides a REJECTED row (the server's answer verbatim — the server names
// its capability, never an error row); a dead dial stays a result.
func TestDeepQuicV2RungRows(t *testing.T) {
	t.Run("accepted on the v2-pinned listener", func(t *testing.T) {
		addr := quicx.FixtureH3V2(t, nil)
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("fixture addr: %v", err)
		}
		f := deepQuicV2Finding("quic/v2", addr, host, 2*time.Second)
		if f.Result != tlsx.SuiteAccepted {
			t.Fatalf("result = %q (%s), want the v2 negotiation's accepted row", f.Result, f.Detail)
		}
		if !strings.HasSuffix(f.Detail, "quic-v2)") {
			t.Fatalf("detail = %q, want the quic-v2 tail", f.Detail)
		}
		if !strings.Contains(f.Detail, "negotiated X25519MLKEM768") {
			t.Fatalf("detail = %q, want the negotiated group in today's finding shape", f.Detail)
		}
	})
	t.Run("version-negotiation miss maps the server's answer a rejected row", func(t *testing.T) {
		addr := quicx.FixtureQUICNoH3(t) // a v1-only transport listener
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("fixture addr: %v", err)
		}
		f := deepQuicV2Finding("quic/v2", addr, host, 2*time.Second)
		if f.Result != tlsx.SuiteRejected {
			t.Fatalf("result = %q (%s), want the server's version-negotiation answer as a rejected row", f.Result, f.Detail)
		}
		if !strings.Contains(f.Detail, "no compatible QUIC version found") {
			t.Fatalf("detail = %q, want the server's answer verbatim", f.Detail)
		}
	})
	t.Run("a dead dial stays a result", func(t *testing.T) {
		f := deepQuicV2Finding("quic/v2", "127.0.0.1:1", "pqscan.fixture", 500*time.Millisecond)
		if f.Result == tlsx.SuiteError {
			t.Fatalf("result = %q (%s), want a dial-class result row (refused/blocked)", f.Result, f.Detail)
		}
		if f.Result != tlsx.SuiteRefused {
			t.Fatalf("result = %q (%s), want the dead dial's refused row", f.Result, f.Detail)
		}
	})
}

// rungNamesOf renders the probe names of a findings slice.
func rungNamesOf(fs []out.DeepFinding) string {
	names := make([]string, 0, len(fs))
	for _, f := range fs {
		names = append(names, f.Probe)
	}
	return strings.Join(names, ",")
}

// singleScan is the wiring tests' engine convenience: one target, one
// record.
func singleScan(t *testing.T, addr string, opts Options) (*scanRecord, error) {
	t.Helper()
	if opts.MaxWindow < 1 {
		opts.MaxWindow = 1
	}
	recs, err := (&Engine{}).Run(mustParse(t, []string{addr}), opts, nil)
	if err != nil {
		return nil, err
	}
	if len(recs) != 1 {
		return nil, fmt.Errorf("records = %d, want 1", len(recs))
	}
	return recs[0], nil
}

// TestQUICGateGrammarTargetsNeverBlocks: the -jsonl row's quic block
// stays schema-1 additive (the skipped state rides in, the CSV/text
// projections carry no new columns).
func TestQUICGateGrammarTargetsNeverBlocks(t *testing.T) {
	addr := startHintedQUICFixture(t, quicRespPlain)
	var stdout, stderr bytes.Buffer
	outFile := filepath.Join(t.TempDir(), "skip.jsonl")
	if code := run([]string{"-u", addr, "-jsonl", "-o", outFile}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr.String())
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	line := string(data)
	if !strings.Contains(line, `"attempted":false,"state":"skipped: no alt-svc h3 hint"`) {
		t.Fatalf("the skipped state is missing from the jsonl row: %s", line)
	}
	if !strings.Contains(line, `"discovered":{"alt_svc_h3":false,"h3_direct":false}`) {
		t.Fatalf("the skipped row carries no discovered halves: %s", line)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Fatalf("stat: %v", err)
	}
}

// TestDeepQUICRemoteRejectionIsARow: a shareable rung the SERVER
// refuses (an x25519-only listener cannot honor a forced 4589 share)
// answers with a remote crypto alert — the finding is REJECTED (the
// server's decision, the alert verbatim), not an error (a probe-path
// failure would misrecord a real handshake verdict), and never refused
// (the plane could offer the rung; the server said no).
func TestDeepQUICRemoteRejectionIsARow(t *testing.T) {
	addr := quicx.FixtureH3(t, []tls.CurveID{tls.X25519})
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("fixture addr: %v", err)
	}
	f := deepQuicFinding("quic/4589-rejected", addr, host, 4589, 2*time.Second)
	if f.Result != tlsx.SuiteRejected {
		t.Fatalf("result = %q (%s), want the server's rejected verdict (detail %q)", f.Result, f.Detail, f.Detail)
	}
	if !strings.Contains(f.Detail, "remote") {
		t.Fatalf("detail = %q, want the remote side of the alert verbatim", f.Detail)
	}
}

// TestDeepQuicH3RungRow (PQ-69, issue #181): the functional HTTP/3
// rung's dispatch. A completed exchange rides the accepted row (the
// status named); a listener with no h3 layer rides its own rejected row
// (the class words verbatim); a stranger-ALPN listener's rejection and
// a dead dial stay their own classes.
func TestDeepQuicH3RungRow(t *testing.T) {
	t.Run("accepted: the exchange completed", func(t *testing.T) {
		addr := quicx.FixtureH3(t, nil)
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("fixture addr: %v", err)
		}
		f := deepH3ExchangeFinding("quic/h3-exchange", addr, host, 2*time.Second)
		if f.Result != tlsx.SuiteAccepted {
			t.Fatalf("result = %q (%s), want the completed-exchange accepted row", f.Result, f.Detail)
		}
		if want := "h3 exchange completed: status 200 (GET /, alpn h3, quic-v1)"; f.Detail != want {
			t.Fatalf("detail = %q, want %q", f.Detail, want)
		}
	})
	t.Run("no exchange: the listener's own class", func(t *testing.T) {
		addr := quicx.FixtureQUICNoH3(t) // negotiates h3, carries no h3 layer
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("fixture addr: %v", err)
		}
		f := deepH3ExchangeFinding("quic/h3-exchange", addr, host, 2*time.Second)
		if f.Result != tlsx.SuiteRejected {
			t.Fatalf("result = %q (%s), want the broken-h3-path rejected row", f.Result, f.Detail)
		}
		if want := "the server sent no HTTP/3 SETTINGS frame"; f.Detail != want {
			t.Fatalf("detail = %q, want the class words %q", f.Detail, want)
		}
	})
	t.Run("rejected: the server's ALPN answer verbatim", func(t *testing.T) {
		addr := quicx.FixtureQUICStrangerALPN(t)
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("fixture addr: %v", err)
		}
		f := deepH3ExchangeFinding("quic/h3-exchange", addr, host, 2*time.Second)
		if f.Result != tlsx.SuiteRejected {
			t.Fatalf("result = %q (%s), want the server's ALPN answer as a rejected row", f.Result, f.Detail)
		}
		if !strings.Contains(f.Detail, "no application protocol") || !strings.Contains(f.Detail, "(remote)") {
			t.Fatalf("detail = %q, want the server's alert verbatim", f.Detail)
		}
	})
	t.Run("a dead dial stays a result", func(t *testing.T) {
		f := deepH3ExchangeFinding("quic/h3-exchange", "127.0.0.1:1", "pqscan.fixture", 500*time.Millisecond)
		if f.Result != tlsx.SuiteRefused {
			t.Fatalf("result = %q (%s), want the dead dial's refused row", f.Result, f.Detail)
		}
	})
}
