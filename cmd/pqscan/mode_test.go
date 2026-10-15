package main

// mode_test.go — PQ-20's deep-mode EXECUTOR wiring tests (issue #43;
// watched RED: the dispatch stubs return the fast shape, so every
// assertion below fails on the stub until the GREEN commit wires the
// executor). The fixture servers are negotiation oracles (spec §10.1).

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"

	"net"
	"strings"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/deepplan"
	"github.com/shsingh/pqscan/internal/out"
	fixtures "github.com/shsingh/pqscan/tests/fixtures/servers"
)

// startReorderedFixture serves TLS 1.3 with the server preference order
// [SecP384r1MLKEM1024, x25519]: the profile handshake (the browser-grade
// default offer, which carries 4588 but not 4589) negotiates classic
// x25519, while the ladder forces 4589 and the fixture accepts it — the
// pq-mode handshake block is the LADDER's observation (4589), and the
// verdict's weak_classical_preferred fires (the profile negotiated
// classic while the forced PQ offer was accepted).
func startReorderedFixture(t *testing.T) string {
	t.Helper()
	return fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name:             "t13-pq-reordered",
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveID(4589), tls.X25519},
	})
}

// draftHRROracle is the share-less HRR oracle fixture: it reads one TLS
// record and answers with a static HelloRetryRequest demanding the
// obsolete Kyber draft 25497. No modern client can share-match the
// demanded group, so a real negotiation on this endpoint never lands —
// the draft preference itself is the observation (the HNDL-positive
// row: the pq ladder's raw draft probe HRRs to 25497).
func startDraftHRROracle(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				hdr := make([]byte, 5)
				if _, err := readFullBytes(c, hdr); err != nil {
					return
				}
				body := make([]byte, int(binary.BigEndian.Uint16(hdr[3:5])))
				_, _ = readFullBytes(c, body) // the ClientHello; content unused
				_, _ = c.Write(draftHRRRecord())
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func readFullBytes(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// draftHRRRecord builds one TLS 1.3 record carrying a ServerHello with
// the HRR magic random and a key_share extension selecting 25497 — the
// exact shape readFirstFlight's hrrRequestedGroup parses.
func draftHRRRecord() []byte {
	random := [32]byte{
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02,
		0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
	}
	payload := []byte{}
	payload = append(payload, 0x03, 0x03)                  // legacy_version
	payload = append(payload, random[:]...)                // random (the HRR magic)
	payload = append(payload, 0x00)                        // session_id: empty
	payload = append(payload, 0x13, 0x01)                  // cipher suite
	payload = append(payload, 0x00)                        // compression
	payload = append(payload, 0x00, 0x06)                  // extensions total
	payload = append(payload, 0x00, 0x33)                  // key_share
	payload = append(payload, 0x00, 0x02)                  // ext length
	payload = append(payload, byte(25497>>8), byte(25497&0xFF)) // selected group

	hs := []byte{0x02}
	hs = append(hs, byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)))
	hs = append(hs, payload...)

	rec := []byte{0x16, 0x03, 0x03}
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))
	return append(rec, hs...)
}

// testDeepRun scans one target in deep mode against the given engine
// options and returns the record.
func testDeepRun(t *testing.T, addr string, opts Options) *scanRecord {
	t.Helper()
	recs, err := (&Engine{}).Run(mustParse(t, []string{addr}), opts, nil)
	if err != nil {
		t.Fatalf("Engine.Run: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	return recs[0]
}

// findingsBy returns the deep finding for a probe id (nil = absent).
func findingsBy(rec *scanRecord, id string) *out.DeepFinding {
	if rec.Deep == nil {
		return nil
	}
	for _, f := range rec.Deep.Findings {
		if f.Probe == id {
			f := f
			return &f
		}
	}
	return nil
}

// TestDeepModeStandardExecutesPlan: -mode deep (the default standard
// plan) on the hybrid fixture — the profile handshake runs first and its
// facts prune the plan; the executed plan lands in the record's deep
// block with per-row verdicts. The fixture's facts (negotiated 4588 on
// TLS 1.3 + a fetched certificate) prune the negotiated version/group/
// suite/cert probes, the suite class is cut entirely (the standard
// budget's suite tiers), and the executed plan is exactly the budget-pinned
// 24: 3 version + 10 group + 7 sigalg + 3 resumption + 1 hrr.
func TestDeepModeStandardExecutesPlan(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	rec := testDeepRun(t, hybridAddr, Options{Mode: modeDeep, ProbeTimeout: 2 * time.Second})
	if rec.Mode != "deep" {
		t.Fatalf("rec.Mode = %q, want deep", rec.Mode)
	}
	if rec.Deep == nil {
		t.Fatalf("the deep block is absent on the deep-mode record — the executor did not land (rec=%+v)", rec)
	}
	if rec.Deep.Mode != "standard" {
		t.Fatalf("deep.Mode = %q, want standard (the default plan)", rec.Deep.Mode)
	}

	// The facts prune (spec §7.4 phase 1): the deep plan built on the
	// profile handshake's facts (4588 / the negotiated 1.3 suite / TLS
	// 1.3 / the delivered chain) — every anchored probe is ABSENT.
	if got := findingsBy(rec, "group/4588"); got != nil {
		t.Fatalf("group/4588 executed despite being the profile handshake's negotiated group: %+v", got)
	}
	if got := findingsBy(rec, "version/1.3"); got != nil {
		t.Fatalf("version/1.3 executed despite being the profile handshake's negotiated version: %+v", got)
	}
	if got := findingsBy(rec, "cert/chain"); got != nil {
		t.Fatalf("cert/chain executed despite the profile handshake's delivered chain: %+v", got)
	}
	for _, f := range rec.Deep.Findings {
		if strings.HasPrefix(f.Probe, "suite/") {
			t.Fatalf("a suite row ran in the standard plan (the budget cuts the suite class): %+v", f)
		}
	}

	// The budget-pinned composition: 24 attempted in plan order.
	if rec.Deep.Attempted != 24 {
		t.Fatalf("attempted = %d, want 24 (3 version + 10 group + 7 sigalg + 3 resumption + 1 hrr)", rec.Deep.Attempted)
	}
	if len(rec.Deep.Findings) != rec.Deep.Attempted {
		t.Fatalf("findings = %d, want the attempted count %d", len(rec.Deep.Findings), rec.Deep.Attempted)
	}

	// Verdicts per row class: the hybrid fixture speaks TLS 1.3 with prefs
	// [4588, 29] — every non-negotiated version/group probe is REJECTED
	// (the server's alerts are results); x25519 is accepted on the real
	// share; the sigalg and resumption rows are the honest refusals.
	if rec.Deep.OK != 2 || rec.Deep.Rejected != 12 {
		t.Fatalf("deep counts ok=%d rejected=%d, want 2 (group/29, hrr) / 12 (3 versions + 9 groups)", rec.Deep.OK, rec.Deep.Rejected)
	}
	v10 := findingsBy(rec, "version/1.0")
	if v10 == nil || v10.Result != "rejected" || v10.Detail == "" {
		t.Fatalf("version/1.0: %+v, want a rejected row with the server's reason", v10)
	}
	if got := findingsBy(rec, "group/29"); got == nil || got.Result != "accepted" {
		t.Fatalf("group/29: %+v, want accepted (the fixture serves x25519)", got)
	}
	if got := findingsBy(rec, "group/4587"); got == nil || got.Result != "rejected" {
		t.Fatalf("group/4587: %+v, want rejected (the fixture does not offer it)", got)
	}
	if got := findingsBy(rec, "group/25497"); got == nil || got.Result != "rejected" {
		t.Fatalf("group/25497: %+v, want rejected (the standards-only fixture)", got)
	}
	for _, id := range []string{"sigalg/rsa_pss_rsae_sha256", "sigalg/mldsa44", "sigalg/mldsa65", "sigalg/mldsa87"} {
		got := findingsBy(rec, id)
		if got == nil || got.Result != "refused" || got.Detail != "not-offerable: the raw ClientHello path pins its signature_algorithms list (custom-list offers are a planned surface)" {
			t.Fatalf("%s: %+v, want the honest not-offerable refusal", id, got)
		}
	}
	for _, id := range []string{"resumption/ticket-tls12", "resumption/psk-tls13", "resumption/0rtt-tls13"} {
		got := findingsBy(rec, id)
		if got == nil || got.Result != "refused" || got.Detail != "not-offerable: no resumption surface is instrumented in the tlsx plane (planned)" {
			t.Fatalf("%s: %+v, want the honest not-offerable refusal", id, got)
		}
	}
	if got := findingsBy(rec, "hrr/x25519-shareless"); got == nil || got.Result != "accepted" || !strings.Contains(got.Detail, "29") {
		t.Fatalf("hrr/x25519-shareless: %+v, want an accepted HRR demanding 29", got)
	}
	// The deep block never invents a second QUIC plane or clears the
	// profile facts: the handshake/cert blocks stay the profile's.
	if rec.Handshake.Negotiated != 4588 {
		t.Fatalf("handshake.Negotiated = %d, want 4588 (the profile handshake's facts stay)", rec.Handshake.Negotiated)
	}
}

// TestDeepModeFullPlanExecution: -deep full runs the complete matrix —
// no fact prune (spec §7.4: Observed never prunes full), so the profile
// handshake's own suite@1.3 pair re-runs (as the fixed-set caveat rows)
// and the negotiated GROUP re-runs as an explicit offer-one probe.
func TestDeepModeFullPlanExecution(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	rec := testDeepRun(t, hybridAddr, Options{Mode: modeDeep, DeepPlan: deepFull, ProbeTimeout: 2 * time.Second})
	if rec.Mode != "deep" {
		t.Fatalf("rec.Mode = %q, want deep", rec.Mode)
	}
	if rec.Deep == nil || rec.Deep.Mode != "full" {
		t.Fatalf("deep.Mode = %+v, want full", rec.Deep)
	}
	// Full executes the plan verbatim (no fact prune), bound-checked.
	plan, err := deepplan.Build(rec.Target.Input, deepplan.ModeFull, &deepplan.Observed{
		NegotiatedGroup: 4588, NegotiatedSuite: "TLS_AES_128_GCM_SHA256",
		Version: tls.VersionTLS13, HasCert: true,
	})
	if err != nil {
		t.Fatalf("Build(full): %v", err)
	}
	if rec.Deep.Attempted != len(plan.Probes) {
		t.Fatalf("attempted = %d, want the full plan's %d probes", rec.Deep.Attempted, len(plan.Probes))
	}
	if rec.Deep.Attempted > deepplan.FullMatrixBound {
		t.Fatalf("attempted = %d exceeds the full-matrix bound %d", rec.Deep.Attempted, deepplan.FullMatrixBound)
	}
	// The negotiated group re-runs and is accepted offer-one.
	if got := findingsBy(rec, "group/4588"); got == nil || got.Result != "accepted" {
		t.Fatalf("group/4588 in full: %+v, want accepted (full never fact-prunes)", got)
	}
	// The 1.3 suite rows: the fixed-set caveat (crypto/tls cannot
	// restrict the 1.3 suite list — spec §7.4's matrix note) with the
	// profile handshake's negotiated suite in the detail.
	got := findingsBy(rec, "suite/TLS_AES_128_GCM_SHA256@1.3")
	if got == nil || got.Result != "refused" || !strings.Contains(got.Detail, "fixed 1.3 suite set") {
		t.Fatalf("suite/TLS_AES_128_GCM_SHA256@1.3: %+v, want the fixed-set refusal", got)
	}
	// A 1.2 suite row against the TLS-1.3-only fixture: genuinely rejected.
	if got := findingsBy(rec, "suite/TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256@1.2"); got == nil || got.Result != "rejected" {
		t.Fatalf("suite @1.2: %+v, want rejected", got)
	}
	// Cert + hrr both accepted in full.
	if got := findingsBy(rec, "cert/chain"); got == nil || got.Result != "accepted" {
		t.Fatalf("cert/chain: %+v, want accepted (the profile chain)", got)
	}
}

func TestDeepModeProfileFailureShortCircuits(t *testing.T) {
	deadAddr := closedLoopbackPort(t)
	rec := testDeepRun(t, deadAddr, Options{Mode: modeDeep, ProbeTimeout: 500 * time.Millisecond})
	if rec.Deep != nil {
		t.Fatalf("the deep block ran on a failed profile handshake (phase 1 gates phase 2): %+v", rec.Deep)
	}
	if rec.Error == "" {
		t.Fatalf("the failed profile handshake's error is empty")
	}
	if rec.Mode != "deep" {
		t.Fatalf("rec.Mode = %q, want deep", rec.Mode)
	}
}

// TestPQModeLadderWireIn: -mode pq runs the forced PQ ladder
// (4585–4590 + the obsolete drafts) and lands the ladder's observations
// in the record: the handshake block = the ladder's first accepted group
// (the reordered fixture pins the ladder-vs-profile distinction), and
// the pq verdict scores the ladder's facts.
func TestPQModeLadderWireIn(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	reorderedAddr := startReorderedFixture(t)
	classicAddr := startClassicFixture(t)
	rows := []struct {
		name  string
		addr  string
		group uint32
		gname string
		gcls  string
		score int
		label string
		hndl  bool
	}{
		{
			name: "hybrid fixture: the ladder keeps the negotiated hybrid",
			addr: hybridAddr, group: 4588, gname: "X25519MLKEM768", gcls: "pq_hybrid",
			score: 40, label: "pq-partial", hndl: false,
		},
		{
			name: "reordered fixture: the block is the ladder's accepted 4589, not the profile's x25519",
			addr: reorderedAddr, group: 4589, gname: "SecP384r1MLKEM1024", gcls: "pq_hybrid",
			score: 35, label: "pq-missing", hndl: false,
		},
		{
			name: "classic fixture: no PQ group accepted, the block falls back to the profile facts",
			addr: classicAddr, group: 29, gname: "x25519", gcls: "classic",
			score: 0, label: "scan-error", hndl: false,
		},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			rec := testDeepRun(t, row.addr, Options{Mode: modePQ, ProbeTimeout: 2 * time.Second})
			if rec.Mode != "pq" {
				t.Fatalf("rec.Mode = %q, want pq", rec.Mode)
			}
			if rec.Handshake.Negotiated != row.group || rec.Handshake.GroupName != row.gname || rec.Handshake.GroupClass != row.gcls {
				t.Fatalf("handshake block %d/%s/%s, want the ladder's observation %d/%s/%s",
					rec.Handshake.Negotiated, rec.Handshake.GroupName, rec.Handshake.GroupClass, row.group, row.gname, row.gcls)
			}
			if rec.Pq == nil {
				t.Fatalf("the pq verdict is absent")
			}
			if rec.Pq.Score != row.score || rec.Pq.Label != row.label {
				t.Fatalf("pq verdict %d/%s, want %d/%s", rec.Pq.Score, rec.Pq.Label, row.score, row.label)
			}
			if rec.Pq.HNDL != row.hndl {
				t.Fatalf("HNDL = %v, want %v", rec.Pq.HNDL, row.hndl)
			}
		})
	}
}

// TestPQModeHNDLOnDraftAcceptance: the pq ladder's raw draft probes
// observe the draft-preference oracle's HRR to 25497 — HNDL fires even
// though no handshake ever completes on the endpoint.
func TestPQModeHNDLOnDraftAcceptance(t *testing.T) {
	oracleAddr := startDraftHRROracle(t)
	rec := testDeepRun(t, oracleAddr, Options{Mode: modePQ, ProbeTimeout: 2 * time.Second})
	if rec.Mode != "pq" {
		t.Fatalf("rec.Mode = %q, want pq", rec.Mode)
	}
	if rec.Error == "" {
		t.Fatalf("the profile handshake cannot complete on the draft-only oracle; its error must ride the record's error path")
	}
	if rec.Pq == nil {
		t.Fatalf("the pq verdict is absent")
	}
	if !rec.Pq.HNDL {
		t.Fatalf("HNDL false — the ladder's HRR to 25497 must surface the HNDL exposure (verdict=%+v)", rec.Pq)
	}
	if rec.Pq.Score != 0 || rec.Pq.Label != "scan-error" {
		t.Fatalf("verdict = %d/%s, want 0/scan-error on the draft-only oracle", rec.Pq.Score, rec.Pq.Label)
	}
	if !strings.Contains(rec.Pq.Summary, "obsolete_draft_negotiated(-15)") {
		t.Fatalf("summary %q missing the fired draft rule", rec.Pq.Summary)
	}
}

// TestModeFlagValidation: -mode and -deep validate before anything
// scans (exit 64, usage class, the offending value named).
func TestModeFlagValidation(t *testing.T) {
	var outBuf, errOut strings.Builder
	code := run([]string{"-mode", "bogus"}, &outBuf, &errOut)
	if code != 64 {
		t.Fatalf("exit = %d, want 64", code)
	}
	if !strings.Contains(errOut.String(), "unknown -mode") || !strings.Contains(errOut.String(), "bogus") {
		t.Fatalf("stderr should name the unknown mode (exit path before any scan): %q", errOut.String())
	}

	errOut.Reset()
	code = run([]string{"-mode", "deep", "-deep", "bogus"}, &outBuf, &errOut)
	if code != 64 {
		t.Fatalf("exit = %d, want 64", code)
	}
	if !strings.Contains(errOut.String(), "unknown -deep") {
		t.Fatalf("stderr should name the unknown deep plan: %q", errOut.String())
	}
}

// TestModeFlagRegistration: the PQ-20 flags register via the fs.String
// shape the usage-drift gate reads; a parse lands on the no-targets
// refusal (64), never the flags-not-defined artifact.
func TestModeFlagRegistration(t *testing.T) {
	var outBuf bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"-mode", "deep", "-deep", "full"}, &outBuf, &errOut)
	if code != 64 {
		t.Fatalf("exit = %d, want 64 (no targets; stderr: %s)", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "flag provided but not defined") {
		t.Fatalf("the mode flags did not register: %s", errOut.String())
	}
}

// TestDeepRecordJSONLLanding: the deep-mode JSONL line carries the deep
// block (the byte contract pinned by the goldens); the fast-mode line
// (the same encoder) carries none.
func TestDeepRecordJSONLLanding(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	dir := t.TempDir()
	path := dir + "/deep.jsonl"
	var outBuf bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"-u", hybridAddr, "-mode", "deep", "-deep", "standard", "-quic-off", "-jsonl", "-o", path}, &outBuf, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, stderr: %s", code, errOut.String())
	}
	recs := readJSONLRecords(t, path)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	deep, ok := recs[0]["deep"].(map[string]any)
	if !ok {
		t.Fatalf("the jsonl record carries no deep block: %v", recs[0])
	}
	if deep["mode"] != "standard" {
		t.Fatalf("deep.mode = %v", deep["mode"])
	}
	if n, _ := deep["attempted"].(float64); int(n) != 24 {
		t.Fatalf("deep.attempted = %v, want 24", deep["attempted"])
	}
	findings, ok := deep["findings"].([]any)
	if !ok || len(findings) != 24 {
		t.Fatalf("deep.findings = %T/%v, want 24 rows", deep["findings"], deep["findings"])
	}
	first, _ := findings[0].(map[string]any)
	if first["probe"] == nil || first["result"] == nil || first["detail"] == nil {
		t.Fatalf("finding row missing pinned keys: %v", first)
	}
}
