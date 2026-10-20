// PQ-22: differential parity engine tests. Both reference-tool transcripts
// are canned (embedded): the gnutls-cli-debug sample mirrors the tool's
// check-verdict table format ("%58s..." + " yes/no") as printed by
// gnutls 3.8.9's tls_tests[], the summary shapes, and — for sslyze — a
// schema-conformant slice of the released JSON output schema
// (nabla-c0d3/sslyze json_output_schema.json). The real-tool E2E runs are
// the second pair's lane; this suite keeps the pure engine honest offline.
package differential

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/shsingh/pqscan/internal/classify"
	"github.com/shsingh/pqscan/internal/registry"
)

// gnutlsSample: real gnutls-cli-debug transcript shape (check-verdict
// table + priority-summary lines + the verbose connection-info line).
const gnutlsSample = `GnuTLS debug client 3.8.9
Checking localhost:4433
         whether the server accepts default record size (512 bytes)... yes
                                   for SSL 3.0 (RFC6101) support... no
                                   for TLS 1.0 (RFC2246) support... yes
                                   for TLS 1.1 (RFC4346) support... yes
                                   for TLS 1.2 (RFC5246) support... yes
                                   for TLS 1.3 (RFC8446) support... yes
                                   for known TLS or SSL protocols support... yes
                                   for curve SECP256r1 (RFC4492)... yes
                                   for curve SECP384r1 (RFC4492)... yes
                                   for curve X25519 (RFC8422)... yes
                                   for curve SECP521r1 (RFC4492)... no
                                   for AES-GCM cipher (RFC5288) support... yes
Protocols: TLS1.3, TLS1.2
Ciphersuites: TLS1.3-AES128-GCM-SHA256, TLS1.3-AES256-GCM-SHA384
- Version: TLS1.3. Output record version: TLS1.2. Input record version: TLS1.2.
`

// sslyzeSample: schema-conformant sslyze JSON root (server_scan_results →
// scan_result: tls_1_2/tls_1_3_cipher_suites, elliptic_curves,
// certificate_info). TLS 1.2 unsupported; TLS 1.3 with two accepted
// suites; OpenSSL group spellings as sslyze surfaces them; one rejected
// curve; RSA-2048 leaf signed with sha256WithRSAEncryption.
const sslyzeSample = `{
    "server_scan_results": [
        {
            "uuid": "3b23ecf3-2874-4a5e-94f9-5d0cfa7f0012",
            "server_location": {"hostname": "fixture.local", "ip_address": "127.0.0.1", "port": 443, "network_route": "", "tls_probing_failed": false},
            "connectivity_status": "COMPLETED",
            "connectivity_error_trace": null,
            "connectivity_result": {"server_name_indication": "fixture.local", "highest_tls_version_supported_by_sslyze": "TLSv1_3", "tls_versions_supported_by_sslyze": ["TLSv1_2", "TLSv1_3"], "ecdsa_cert_accepted_by_default_client": true, "supports_ecdh_key_exchange": true},
            "scan_status": "COMPLETED",
            "scan_result": {
                "certificate_info": {
                    "status": "COMPLETED",
                    "error_reason": null,
                    "error_trace": null,
                    "result": {
                        "hostname_used_for_server_name_indication": "fixture.local",
                        "certificate_deployments": [{
                            "leaf_certificate_subject_matches_hostname": true,
                            "certificate_chain": [{
                                "certificate": {
                                    "signature_hash_algorithm": "sha256",
                                    "signature_algorithm_oid": {"name": "sha256WithRSAEncryption", "dotted_string": "1.2.840.113549.1.1.11"},
                                    "public_key": {"algorithm": "RSAPublicKey", "key_size": 2048, "rsa_e": 65537, "rsa_n": 123, "ec_curve_name": null, "ec_x": null, "ec_y": null}
                                },
                                "chain_position": 0
                            }]
                        }]
                    }
                },
                "ssl_2_0_cipher_suites": {"status": "COMPLETED", "error_reason": null, "error_trace": null, "result": {"tls_version_used": null, "is_tls_version_supported": false, "accepted_cipher_suites": [], "rejected_cipher_suites": []}},
                "tls_1_0_cipher_suites": {"status": "COMPLETED", "error_reason": null, "error_trace": null, "result": {"tls_version_used": null, "is_tls_version_supported": false, "accepted_cipher_suites": [], "rejected_cipher_suites": []}},
                "tls_1_2_cipher_suites": {"status": "COMPLETED", "error_reason": null, "error_trace": null, "result": {"tls_version_used": null, "is_tls_version_supported": false, "accepted_cipher_suites": [], "rejected_cipher_suites": []}},
                "tls_1_3_cipher_suites": {
                    "status": "COMPLETED",
                    "error_reason": null,
                    "error_trace": null,
                    "result": {
                        "tls_version_used": "TLSv1_3",
                        "is_tls_version_supported": true,
                        "accepted_cipher_suites": [
                            {"cipher_suite": {"name": "TLS_AES_128_GCM_SHA256", "is_anonymous": false, "key_size": 128, "openssl_name": "TLS_AES_128_GCM_SHA256"}, "ephemeral_key": null},
                            {"cipher_suite": {"name": "TLS_AES_256_GCM_SHA384", "is_anonymous": false, "key_size": 256, "openssl_name": "TLS_AES_256_GCM_SHA384"}, "ephemeral_key": null}
                        ],
                        "rejected_cipher_suites": []
                    }
                },
                "elliptic_curves": {
                    "status": "COMPLETED",
                    "error_reason": null,
                    "error_trace": null,
                    "result": {
                        "supports_ecdh_key_exchange": true,
                        "supported_curves": [
                            {"name": "X25519", "openssl_nid": 1034},
                            {"name": "prime256v1", "openssl_nid": 415},
                            {"name": "X25519MLKEM768", "openssl_nid": 1108}
                        ],
                        "rejected_curves": [
                            {"name": "secp384r1", "openssl_nid": 715}
                        ]
                    }
                }
            }
        }
    ],
    "invalid_server_strings": [],
    "sslyze_version": "6.1.0",
    "sslyze_url": "https://github.com/nabla-c0d3/sslyze"
}`

func TestParseGnutlsCLIExtractsProtocolGroupAndSuiteVerdicts(t *testing.T) {
	got, err := ParseGnutlsCLI(gnutlsSample)
	if err != nil {
		t.Fatalf("ParseGnutlsCLI(gnutlsSample) unexpected error: %v", err)
	}
	want := []Obs{
		{"gnutls-cli-debug", CheckProtocol, "TLS1.3"},
		{"gnutls-cli-debug", GroupCheck("SECP256r1"), "secp256r1"},
		{"gnutls-cli-debug", GroupCheck("SECP384r1"), "secp384r1"},
		{"gnutls-cli-debug", GroupCheck("X25519"), "x25519"},
		{"gnutls-cli-debug", GroupCheck("SECP521r1"), "not accepted"},
		{"gnutls-cli-debug", CheckSuite, "TLS_AES_128_GCM_SHA256"},
		{"gnutls-cli-debug", CheckSuite, "TLS_AES_256_GCM_SHA384"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d obs, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("obs[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

func TestParseGnutlsCLIRejectsUnrecognisedOutput(t *testing.T) {
	for _, bad := range []string{"", "hello world", "GET / HTTP/1.0 404"} {
		if obs, err := ParseGnutlsCLI(bad); err == nil {
			t.Errorf("ParseGnutlsCLI(%q) = %+v, want an error (no recognizable gnutls shape)", bad, obs)
		}
	}
}

func TestParseSSLyzeExtractsProtocolSuitesGroupsAndCert(t *testing.T) {
	got, err := ParseSSLyze(sslyzeSample)
	if err != nil {
		t.Fatalf("ParseSSLyze(sslyzeSample) unexpected error: %v", err)
	}
	want := []Obs{
		{"sslyze", CheckProtocol, "TLS1.3"},
		{"sslyze", GroupCheck("X25519"), "x25519"},
		{"sslyze", GroupCheck("prime256v1"), "secp256r1"},
		{"sslyze", GroupCheck("X25519MLKEM768"), "X25519MLKEM768"},
		{"sslyze", GroupCheck("secp384r1"), "not accepted"},
		{"sslyze", CheckSuite, "TLS_AES_128_GCM_SHA256"},
		{"sslyze", CheckSuite, "TLS_AES_256_GCM_SHA384"},
		{"sslyze", CheckCertificate, "sig=sha256WithRSAEncryption; key=RSAPublicKey(2048)"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d obs, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("obs[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

func TestParseSSLyzeRejectsUnrecognisedShapes(t *testing.T) {
	for _, bad := range []string{"", "not json", `{"unexpected": true}`, `{"server_scan_results": 3}`} {
		if obs, err := ParseSSLyze(bad); err == nil {
			t.Errorf("ParseSSLyze(%q) = %+v, want an error", bad, obs)
		}
	}
}

func TestParityProtocolAgrees(t *testing.T) {
	pqscan := []Obs{{Tool: "pqscan", Check: CheckProtocol, Detail: "TLS1.3"}}
	refs := []Obs{{Tool: "sslyze", Check: CheckProtocol, Detail: "TLS1.3"}}
	rows := Parity(pqscan, refs)
	wantRow := Comparison{Check: CheckProtocol, Agree: true, PQObs: "TLS1.3"}
	if len(rows) != 1 || rows[0] != wantRow {
		t.Fatalf("Parity protocol agree = %+v, want %+v", rows, wantRow)
	}
}

func TestParityProtocolDisagrees(t *testing.T) {
	pqscan := []Obs{{Tool: "pqscan", Check: CheckProtocol, Detail: "TLS1.3"}}
	refs := []Obs{{Tool: "gnutls-cli-debug", Check: CheckProtocol, Detail: "TLS1.2"}}
	rows := Parity(pqscan, refs)
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	row := rows[0]
	if row.Agree {
		t.Errorf("row = %+v, want disagree", row)
	}
	if row.PQObs != "TLS1.3" {
		t.Errorf("PQObs = %q, want TLS1.3", row.PQObs)
	}
	wantDiff := "pqscan: TLS1.3 vs gnutls-cli-debug: TLS1.2"
	if row.Diff != wantDiff {
		t.Errorf("Diff = %q, want %q", row.Diff, wantDiff)
	}
}

func TestParitySuiteAgreesThroughNormalization(t *testing.T) {
	// pqscan negotiated the RFC name; gnutls listed the same suite in its
	// own spelling (TLS1.3-AES128-GCM-SHA256) via "Ciphersuites:".
	pqscan := []Obs{{Tool: "pqscan", Check: CheckSuite, Detail: "TLS_AES_128_GCM_SHA256"}}
	refs := []Obs{{Tool: "gnutls-cli-debug", Check: CheckSuite, Detail: "TLS1.3-AES128-GCM-SHA256"}}
	rows := Parity(pqscan, refs)
	if len(rows) != 1 || !rows[0].Agree {
		t.Fatalf("suite row = %+v, want agree", rows)
	}
	if rows[0].PQObs != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("PQObs = %q", rows[0].PQObs)
	}
}

func TestParitySuiteDisagreesWhenNotNamedByReference(t *testing.T) {
	pqscan := []Obs{{Tool: "pqscan", Check: CheckSuite, Detail: "TLS_CHACHA20_POLY1305_SHA256"}}
	refs := []Obs{
		{Tool: "gnutls-cli-debug", Check: CheckSuite, Detail: "TLS_AES_128_GCM_SHA256"},
		{Tool: "gnutls-cli-debug", Check: CheckSuite, Detail: "TLS_AES_256_GCM_SHA384"},
	}
	rows := Parity(pqscan, refs)
	if len(rows) != 1 || rows[0].Agree {
		t.Fatalf("suite row = %+v, want disagree", rows)
	}
	wantSub := "TLS_CHACHA20_POLY1305_SHA256 not among gnutls-cli-debug:"
	if !strings.Contains(rows[0].Diff, wantSub) {
		t.Errorf("Diff = %q, want it to contain %q", rows[0].Diff, wantSub)
	}
}

func TestParityGroupClassAgrees(t *testing.T) {
	pqscan := []Obs{{Tool: "pqscan", Check: GroupCheck("x25519"), Detail: "x25519"}}
	refs := []Obs{{Tool: "gnutls-cli-debug", Check: GroupCheck("X25519"), Detail: "x25519"}}
	rows := Parity(pqscan, refs)
	if len(rows) != 1 || !rows[0].Agree {
		t.Fatalf("group row = %+v, want agree", rows)
	}
	// The pqscan side carries the derived class in its rendering.
	if !strings.Contains(rows[0].PQObs, "x25519 (classic)") {
		t.Errorf("PQObs = %q, want it to carry the derived class", rows[0].PQObs)
	}
}

func TestParityPQClassMismatchFlagged(t *testing.T) {
	// The gate's target: pqscan's executor claims the server negotiated
	// X25519MLKEM768 on a row the reference observed as x25519 — the two
	// classifications disagree and the row must be flagged.
	pqscan := []Obs{{Tool: "pqscan", Check: GroupCheck("x25519"), Detail: "X25519MLKEM768"}}
	refs := []Obs{{Tool: "sslyze", Check: GroupCheck("X25519"), Detail: "x25519"}}
	rows := Parity(pqscan, refs)
	if len(rows) != 1 || rows[0].Agree {
		t.Fatalf("group row = %+v, want flagged", rows)
	}
	row := rows[0]
	if row.PQObs != "X25519MLKEM768 (pq_hybrid)" {
		t.Errorf("PQObs = %q, want %q", row.PQObs, "X25519MLKEM768 (pq_hybrid)")
	}
	wantDiff := "pqscan: X25519MLKEM768 (pq_hybrid) vs sslyze: x25519 (classic)"
	if row.Diff != wantDiff {
		t.Errorf("Diff = %q, want %q", row.Diff, wantDiff)
	}
}

func TestParityDraftHybridAgreesWithReference(t *testing.T) {
	// Both sides observed the same draft-hybrid group: same class bucket.
	pqscan := []Obs{{Tool: "pqscan", Check: GroupCheck("X25519Kyber768Draft00"), Detail: "X25519Kyber768Draft00"}}
	refs := []Obs{{Tool: "sslyze", Check: GroupCheck("X25519Kyber768Draft00"), Detail: "X25519Kyber768Draft00"}}
	rows := Parity(pqscan, refs)
	if len(rows) != 1 || !rows[0].Agree {
		t.Fatalf("group row = %+v, want agree", rows)
	}
}

func TestParityPQOnlyGroupIsPqscanOnlyProbe(t *testing.T) {
	// gnutls-cli-debug cannot construct PQ groups: no reference row for
	// X25519MLKEM768. Not a divergence — the pqscan-only probe is recorded
	// in the note.
	pqscan := []Obs{{Tool: "pqscan", Check: GroupCheck("X25519MLKEM768"), Detail: "X25519MLKEM768"}}
	refs := []Obs{{Tool: "gnutls-cli-debug", Check: CheckProtocol, Detail: "TLS1.3"}}
	rows := Parity(pqscan, refs)
	row := findRow(t, rows, GroupCheck("X25519MLKEM768"))
	if !row.Agree {
		t.Fatalf("row = %+v, want agree (the pqscan-only probe note)", row)
	}
	for _, sub := range []string{"no reference observation", "pqscan-only"} {
		if !strings.Contains(row.Note, sub) {
			t.Errorf("Note = %q, want it to contain %q", row.Note, sub)
		}
	}
}

func TestParityUnknownToolShapeNonAgreement(t *testing.T) {
	// A reference group observation whose textual detail resolves to
	// nothing (unparseable semantics) must yield NonAgreement with a Note
	// — never a crash and never a false agreement.
	pqscan := []Obs{{Tool: "pqscan", Check: GroupCheck("x25519"), Detail: "x25519"}}
	refs := []Obs{
		{Tool: "gnutls-cli-debug", Check: GroupCheck("x25519"), Detail: "x25519"},
		{Tool: "gnutls-cli-debug", Check: "group weirdCurve", Detail: "weirdCurve"},
	}
	rows := Parity(pqscan, refs)
	row := findRow(t, rows, "group weirdCurve")
	if row.Agree {
		t.Fatalf("row = %+v, want NonAgreement", row)
	}
	if !strings.Contains(row.Note, "reference semantic unknown") {
		t.Errorf("Note = %q, want it to mark the unknown shape", row.Note)
	}
	// The resolved row beside it still agrees.
	classicRow := findRow(t, rows, GroupCheck("x25519"))
	if !classicRow.Agree {
		t.Errorf("row = %+v, want agree", classicRow)
	}
}

func TestParityUnknownCheckKeyNonAgreement(t *testing.T) {
	pqscan := []Obs{{Tool: "pqscan", Check: CheckProtocol, Detail: "TLS1.3"}}
	refs := []Obs{
		{Tool: "sslyze", Check: CheckProtocol, Detail: "TLS1.3"},
		{Tool: "sslyze", Check: "kex", Detail: "ECDHE_RSA"},
	}
	rows := Parity(pqscan, refs)
	row := findRow(t, rows, "kex")
	if row.Agree {
		t.Fatalf("row = %+v, want NonAgreement", row)
	}
	if !strings.Contains(row.Note, "no parity rule") {
		t.Errorf("Note = %q, want it to name the rule-less check", row.Note)
	}
}

func TestParityGroupRejectedSymmetry(t *testing.T) {
	// sslyze rejected secp384r1; pqscan never observed it. Both sides
	// effectively reject/omit: agreement, not a divergence.
	pqscan := []Obs{{Tool: "pqscan", Check: CheckProtocol, Detail: "TLS1.3"}}
	refs := []Obs{{Tool: "sslyze", Check: GroupCheck("secp384r1"), Detail: "not accepted"}}
	rows := Parity(pqscan, refs)
	row := findRow(t, rows, GroupCheck("secp384r1"))
	if !row.Agree {
		t.Fatalf("row = %+v, want agree (both sides reject/omit)", row)
	}
	if !strings.Contains(row.Note, "reject") {
		t.Errorf("Note = %q, want it to record the both-reject symmetry", row.Note)
	}
	// The contradiction case: pqscan claims the group was accepted while
	// the reference explicitly observed a rejection → flagged.
	pqscanAccept := append(append([]Obs{}, pqscan...),
		Obs{Tool: "pqscan", Check: GroupCheck("x25519"), Detail: "x25519"})
	refsReject := []Obs{{Tool: "gnutls-cli-debug", Check: GroupCheck("x25519"), Detail: "not accepted"}}
	rows = Parity(pqscanAccept, refsReject)
	row = findRow(t, rows, GroupCheck("x25519"))
	if row.Agree {
		t.Fatalf("row = %+v, want flagged (acceptance contradiction)", row)
	}
}

func TestParityRowsAreSortedAndComplete(t *testing.T) {
	pqscan := []Obs{
		{Tool: "pqscan", Check: CheckProtocol, Detail: "TLS1.3"},
		{Tool: "pqscan", Check: CheckSuite, Detail: "TLS_AES_128_GCM_SHA256"},
		{Tool: "pqscan", Check: GroupCheck("x25519"), Detail: "x25519"},
	}
	refObs, err := ParseSSLyze(sslyzeSample)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rows := Parity(pqscan, refObs)
	// sslyzeSample additionally carries: secp256r1 (accepted, no pqscan
	// obs → coverage gap), X25519MLKEM768 (no pqscan obs) and
	// secp384r1 (rejected) plus the rule-less certificate row.
	prev := ""
	for i, row := range rows {
		if row.Check < prev {
			t.Errorf("rows[%d].Check = %q after %q: not sorted", i, row.Check, prev)
		}
		prev = row.Check
	}
	if _, ok := findRowOK(rows, GroupCheck("secp256r1")); !ok {
		t.Errorf("missing coverage-gap row for group secp256r1 in %+v", rows)
	}
	gap := findRow(t, rows, GroupCheck("secp256r1"))
	if gap.Agree || !strings.Contains(gap.Note, "no pqscan observation") {
		t.Errorf("gap row = %+v, want NonAgreement with a coverage-gap note", gap)
	}
	if row := findRow(t, rows, CheckCertificate); row.Agree || !strings.Contains(row.Note, "no parity rule") {
		t.Errorf("certificate row = %+v, want rule-less NonAgreement", row)
	}
	if rows[0].Check != CheckCertificate {
		t.Errorf("first row Check = %q, want %q (sorted", rows[0].Check, CheckCertificate)
	}
}

func TestScanInjectsRunnerAndParses(t *testing.T) {
	canned := map[string]string{
		ToolGnutlsCLIDebug: gnutlsSample,
		ToolSSLyze:         sslyzeSample,
	}
	runner := &cannedRunner{canned: canned}
	ctx := context.Background()
	obs, err := Scan(ctx, ToolSSLyze, runner, "fixture.local:443")
	if err != nil {
		t.Fatalf("Scan(sslyze) unexpected error: %v", err)
	}
	if len(obs) == 0 || obs[0].Tool != ToolSSLyze {
		t.Fatalf("Scan(sslyze) = %+v, want parsed sslyze observations", obs)
	}
	obs, err = Scan(ctx, ToolGnutlsCLIDebug, runner, "localhost:4433")
	if err != nil {
		t.Fatalf("Scan(gnutls-cli-debug) unexpected error: %v", err)
	}
	if len(obs) == 0 || obs[0].Tool != ToolGnutlsCLIDebug {
		t.Fatalf("Scan(gnutls-cli-debug) = %+v, want parsed gnutls observations", obs)
	}
	if _, err := Scan(ctx, "openssl-s-client", runner, "localhost:4433"); err == nil {
		t.Errorf("Scan(unknown tool) = no error, want unknown-reference-tool error")
	}
	if _, err := Scan(ctx, ToolSSLyze, nil, "fixture.local:443"); err == nil {
		t.Errorf("Scan(nil runner) = no error, want an error")
	}
	if _, err := Scan(ctx, ToolSSLyze, &cannedRunner{err: errors.New("exec failed")}, "fixture.local"); err == nil {
		t.Errorf("Scan(errored runner) = no error, want the runner error propagated")
	}
	if _, err := Scan(ctx, ToolSSLyze, &cannedRunner{canned: map[string]string{ToolSSLyze: ""}}, "fixture.local"); err == nil {
		t.Errorf("Scan(empty output) = no error, want empty-transcript error")
	}
}

// TestGroupCheckCanonicalizes pins the row-key contract: alias spellings
// collapse to the canonical IANA name (single join key for both sides),
// unknown names keep their raw token (lower-cased) and surface as unknown.
func TestGroupCheckCanonicalizes(t *testing.T) {
	cases := map[string]string{
		"X25519":                "group x25519",
		"x25519":                "group x25519",
		"prime256v1":            "group secp256r1",
		"P-256":                 "group secp256r1",
		"SECP384r1":             "group secp384r1",
		"X25519MLKEM768":        "group X25519MLKEM768",
		"X25519Kyber768Draft00": "group X25519Kyber768Draft00",
		"brainpoolP256r1":       "group brainpoolp256r1",
	}
	for in, want := range cases {
		if got := GroupCheck(in); got != want {
			t.Errorf("GroupCheck(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNameIndexCrossChecksRegistrySnapshot proves the comparison name
// index reuses (never duplicates) the committed IANA snapshot: every
// indexed codepoint exists in tests/fixtures/iana/tls-parameters-8.csv and
// every indexed name matches the snapshot's Description name token
// (registry entries carry a trailing " (OBSOLETE)" marker; that suffix is
// stripped here). Classes stay single-sourced in classify.GroupClass.
func TestNameIndexCrossChecksRegistrySnapshot(t *testing.T) {
	f, openErr := os.Open("../../tests/fixtures/iana/tls-parameters-8.csv")
	if openErr != nil {
		t.Fatalf("registry snapshot fixture: %v", openErr)
	}
	defer f.Close()
	entries, loadErr := registry.Load(f)
	if loadErr != nil {
		t.Fatalf("registry.Load: %v", loadErr)
	}
	checks := map[string]uint32{
		"x25519":                   29,
		"secp256r1":                23,
		"secp384r1":                24,
		"secp521r1":                25,
		"MLKEM512":                 512,
		"MLKEM768":                 513,
		"MLKEM1024":                514,
		"SecP256r1MLKEM512":        4585,
		"MLKEM512X25519":           4586,
		"SecP256r1MLKEM768":        4587,
		"X25519MLKEM768":           4588,
		"SecP384r1MLKEM1024":       4589,
		"curveSM2MLKEM768":         4590,
		"X25519Kyber768Draft00":    25497,
		"SecP256r1Kyber768Draft00": 25498,
	}
	for name, cp := range checks {
		e, ok := entries[cp]
		if !ok {
			t.Errorf("codepoint %d for %q missing from registry snapshot", cp, name)
			continue
		}
		snapshotName := strings.TrimSpace(strings.TrimSuffix(e.Name, " (OBSOLETE)"))
		if snapshotName != name {
			t.Errorf("registry snapshot name for %d = %q, index pins %q", cp, snapshotName, name)
		}
		// The parity buckets derive from classify — pinned here for the
		// rows they feed. Codepoints classify does not pin (25, pure
		// ML-KEM 512/513/514) stay unknown: parity surfaces unknown
		// semantics as NonAgreement with a Note, never as an invented
		// verdict.
		class, known := classify.GroupClass(cp)
		switch cp {
		case 29, 23, 24:
			if !known || class != classify.ClassClassic {
				t.Errorf("classify.GroupClass(%d) = (%q, %v), want classic", cp, class, known)
			}
		case 25, 512, 513, 514:
			if known {
				t.Errorf("classify.GroupClass(%d) = (%q, true); taxonomy does not pin this codepoint and parity must never invent", cp, class)
			}
		case 4585, 4586, 4587, 4588, 4589:
			if !known || class != classify.ClassPQHybrid {
				t.Errorf("classify.GroupClass(%d) = (%q, %v), want pq_hybrid", cp, class, known)
			}
		case 4590:
			if !known || class != classify.ClassHybridSM {
				t.Errorf("classify.GroupClass(%d) = (%q, %v), want hybrid_sm", cp, class, known)
			}
		case 25497, 25498:
			if !known || class != classify.ClassPQHybridD {
				t.Errorf("classify.GroupClass(%d) = (%q, %v), want pq_hybrid_draft", cp, class, known)
			}
		default:
			t.Errorf("unpinned cross-check codepoint %d: extend the parity bucket pins", cp)
		}
	}
}

func findRow(t *testing.T, rows []Comparison, check string) Comparison {
	t.Helper()
	row, ok := findRowOK(rows, check)
	if !ok {
		t.Fatalf("missing row for check %q in %+v", check, rows)
	}
	return row
}

func findRowOK(rows []Comparison, check string) (Comparison, bool) {
	for _, r := range rows {
		if r.Check == check {
			return r, true
		}
	}
	return Comparison{}, false
}

// cannedRunner is the injected runner feeding canned tool outputs
// (offline; nothing shells out in CI).
type cannedRunner struct {
	canned map[string]string
	err    error
}

func (r *cannedRunner) Run(ctx context.Context, tool string, args ...string) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	out, ok := r.canned[tool]
	if !ok {
		return "", errors.New("no canned output for tool")
	}
	return out, nil
}
