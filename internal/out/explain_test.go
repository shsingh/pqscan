package out

import (
	"bytes"
	"strings"
	"testing"
)

// The -explain prose (PQ-38): the plain-language reading a netsec/netops
// operator needs at the terminal. The blocks below are byte-pinned per
// record class — hybrid negotiated (the google.com shape), classical-only,
// obsolete draft with HNDL, and a failed probe.
func TestExplainBlockGolden(t *testing.T) {
	hybrid := Record{
		Target:    TargetRecord{Input: "google.com", Host: "google.com", Port: 443},
		Handshake: HandshakeRecord{Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid", Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3", ALPNNeg: "h2"},
		Quic:      &QuicRecord{Attempted: true, State: "negotiated", Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid"},
		Cert:      &CertRecord{SigAlg: "sha256WithRSAEncryption", KeyAlg: "ECDSA"},
		Pq:        &PqRecord{Score: 40, Label: "pq-partial", Summary: "negotiated_pq_hybrid(+40)"},
	}

	t.Run("negotiated pq hybrid", func(t *testing.T) {
		want := strings.Join([]string{
			"  - rating: pq-partial 40/100. The negotiated key exchange is post-quantum. The certificate layer is classical. The lines below carry the detail.",
			"  - key exchange: X25519MLKEM768 (pq_hybrid) — post-quantum hybrid: ML-KEM-768 + X25519. This group protects the session traffic. The harvest-now-decrypt-later risk does not apply while this group negotiates.",
			"  - certificate: classical identity (ECDSA key, sha256WithRSAEncryption signature). Use a PQ-signed or dual certificate at the next renewal.",
			"  - quic: X25519MLKEM768 (pq_hybrid) on the UDP plane — the same post-quantum rating applies to h3 traffic.",
		}, "\n")
		if got := strings.Join(explainBlock(&hybrid), "\n"); got != want {
			t.Fatalf("explain block:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})

	t.Run("classical only", func(t *testing.T) {
		classic := Record{
			Target:    TargetRecord{Host: "192.0.2.10", Port: 443},
			Handshake: HandshakeRecord{Negotiated: 29, GroupName: "x25519", GroupClass: "classic", Suite: "TLS_AES_256_GCM_SHA384", Version: "tls-1.3"},
			Cert:      &CertRecord{SigAlg: "sha256WithRSAEncryption", KeyAlg: "RSAPublicKey"},
			Pq:        &PqRecord{Score: 0, Label: "scan-error", Summary: "scan-error"},
		}
		want := strings.Join([]string{
			"  - rating: scan-error 0/100. Zero usable PQ signal. The rubric records an error state, not a rating.",
			"  - key exchange: x25519 (classic) — classical. A quantum computer breaks this exchange over time. The captured traffic carries the harvest-now-decrypt-later exposure.",
			"  - certificate: classical identity (RSAPublicKey key, sha256WithRSAEncryption signature). Use a PQ-signed or dual certificate at the next renewal.",
		}, "\n")
		if got := strings.Join(explainBlock(&classic), "\n"); got != want {
			t.Fatalf("explain block:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})

	t.Run("obsolete draft + HNDL", func(t *testing.T) {
		draft := Record{
			Target:    TargetRecord{Host: "203.0.113.7", Port: 443},
			Handshake: HandshakeRecord{Negotiated: 25497, GroupName: "X25519Kyber768Draft00", GroupClass: "draft", Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3"},
			Quic:      &QuicRecord{Attempted: true, State: "negotiated", Negotiated: 29, GroupName: "x25519", GroupClass: "classic"},
			Pq:        &PqRecord{Score: 0, Label: "scan-error", HNDL: true, Summary: "obsolete_draft_negotiated(-15)"},
		}
		want := strings.Join([]string{
			"  - rating: scan-error 0/100. Zero usable PQ signal. The rubric records an error state, not a rating.",
			"  - hndl: HARVEST-NOW-DECRYPT-LATER exposure. The endpoint accepts an obsolete draft PQ group (a pre-ML-KEM algorithm). Those handshakes stay decryptable to a future quantum computer. Remove the draft groups from the server configuration.",
			"  - key exchange: X25519Kyber768Draft00 (draft) — an obsolete pre-final PQ draft (pre-ML-KEM Kyber). This class is not the standard ML-KEM. It gives no real PQ readiness.",
			"  - quic: x25519 (classic) on the UDP plane — classical there, too: a PQ negotiation on TCP does not protect the QUIC plane.",
		}, "\n")
		if got := strings.Join(explainBlock(&draft), "\n"); got != want {
			t.Fatalf("explain block:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})

	t.Run("failed probe", func(t *testing.T) {
		refused := Record{
			Target: TargetRecord{Host: "203.0.113.10", Port: 8443},
			Error:  "connect: connection refused",
		}
		want := strings.Join([]string{
			"  - error: connect: connection refused — the probe reached no handshake. The endpoint is unreachable on this port (closed or filtered). No rating is possible.",
		}, "\n")
		if got := strings.Join(explainBlock(&refused), "\n"); got != want {
			t.Fatalf("explain block:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})
}

// --- PQ-50 deep reading (issue #134, watched RED) ---------------------------

// TestExplainDeepReading pins the deep reading line (PQ-50, issue #134):
// when the record executes a deep plan (Deep != nil) the block adds ONE
// line in operator words after the verdict lines — the executed plan's
// counts, the offer-one matrix's yield rolled up by probe-id family, and
// the accepted rows NAMED (the actionable part: a PQ group accepted where
// the profile handshake negotiated classical; a draft-group acceptance IS
// the HNDL exposure spelled out). Refusals are the expected default of a
// forced-offer matrix; the per-probe detail points at the jsonl findings.
// The records are pure construction — no scan runs. The no-block records
// above stay byte-identical: the line rides only when a deep block exists.
func TestExplainDeepReading(t *testing.T) {
	t.Run("deep reading: the executed plan in words, accepted rows named", func(t *testing.T) {
		mixed := Record{
			Target:    TargetRecord{Host: "198.51.100.20", Port: 443},
			Handshake: HandshakeRecord{Negotiated: 29, GroupName: "x25519", GroupClass: "classic", Suite: "TLS_AES_256_GCM_SHA384", Version: "tls-1.3"},
			Pq:        &PqRecord{Score: 0, Label: "scan-error", Summary: "scan-error"},
			Deep: &DeepRecord{Mode: "standard", Attempted: 8, OK: 2, Rejected: 3, Findings: []DeepFinding{
				{Probe: "version/1.0", Result: "rejected", Detail: "alert protocol_version"},
				{Probe: "group/4588", Result: "accepted", Detail: "negotiated X25519MLKEM768, suite TLS_AES_128_GCM_SHA256, tls-1.3"},
				{Probe: "group/29", Result: "rejected", Detail: "remote error: tls: illegal_parameter"},
				{Probe: "suite/TLS_RSA_WITH_AES_128_CBC_SHA@1.2", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "sigalg/mldsa65", Result: "refused", Detail: "not-offerable: the raw ClientHello path pins its signature_algorithms list (custom-list offers are not offered)"},
				{Probe: "cert/chain", Result: "accepted", Detail: "the profile handshake delivered the certificate chain (analyzed in the record's cert block)"},
				{Probe: "resumption/psk-tls13", Result: "refused", Detail: "not-offerable: no resumption surface is instrumented in the tlsx plane"},
				{Probe: "hrr/x25519-shareless", Result: "error", Detail: "read-error: the server closed without a TLS answer"},
			}},
		}
		want := strings.Join([]string{
			"  - rating: scan-error 0/100. Zero usable PQ signal. The rubric records an error state, not a rating.",
			"  - deep: the executed standard plan ran 8 probes: 2 accepted, 3 refused with the server's reasons, 2 not-offerable, 1 errored on the probe path; the offered-one matrix read: version floor 0/1, group offer set 1/2, suite matrix 0/1, sigalg offer set 0/1, certificate probe 1/1, resumption vectors 0/1, hrr probe 0/1; accepted: group/4588 (a PQ group accepted where the profile handshake negotiated classical); cert/chain — the per-probe detail lives in the jsonl findings.",
			"  - key exchange: x25519 (classic) — classical. A quantum computer breaks this exchange over time. The captured traffic carries the harvest-now-decrypt-later exposure.",
		}, "\n")
		if got := strings.Join(explainBlock(&mixed), "\n"); got != want {
			t.Fatalf("deep reading block:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})

	t.Run("deep reading: nothing accepted reads the roll-up, the handshake carries the verdict", func(t *testing.T) {
		all := Record{
			Target:    TargetRecord{Host: "198.51.100.21", Port: 443},
			Handshake: HandshakeRecord{Negotiated: 29, GroupName: "x25519", GroupClass: "classic", Suite: "TLS_AES_256_GCM_SHA384", Version: "tls-1.3"},
			Pq:        &PqRecord{Score: 0, Label: "scan-error", Summary: "scan-error"},
			Deep: &DeepRecord{Mode: "full", Attempted: 14, OK: 0, Rejected: 14, Findings: []DeepFinding{
				{Probe: "version/1.0", Result: "rejected", Detail: "alert protocol_version"},
				{Probe: "version/1.1", Result: "rejected", Detail: "alert protocol_version"},
				{Probe: "version/1.2", Result: "rejected", Detail: "alert protocol_version"},
				{Probe: "group/4585", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "group/4586", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "group/4587", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "group/4588", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "group/4589", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "group/4590", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "group/25", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "group/26", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "group/27", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "group/28", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "group/29", Result: "rejected", Detail: "remote error: tls: illegal_parameter"},
			}},
		}
		want := strings.Join([]string{
			"  - rating: scan-error 0/100. Zero usable PQ signal. The rubric records an error state, not a rating.",
			"  - deep: the executed full plan ran 14 probes: no offer was accepted, 14 refused with the server's reasons, 0 not-offerable; the offered-one matrix read: version floor 0/3, group offer set 0/11; the profile handshake above carries the negotiation — the per-probe detail lives in the jsonl findings.",
			"  - key exchange: x25519 (classic) — classical. A quantum computer breaks this exchange over time. The captured traffic carries the harvest-now-decrypt-later exposure.",
		}, "\n")
		if got := strings.Join(explainBlock(&all), "\n"); got != want {
			t.Fatalf("nothing-accepted deep reading:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})

	t.Run("deep reading: a draft-group acceptance spells the HNDL exposure", func(t *testing.T) {
		draft := Record{
			Target:    TargetRecord{Host: "198.51.100.22", Port: 443},
			Handshake: HandshakeRecord{Negotiated: 29, GroupName: "x25519", GroupClass: "classic", Suite: "TLS_AES_256_GCM_SHA384", Version: "tls-1.3"},
			Pq:        &PqRecord{Score: 0, Label: "scan-error", Summary: "scan-error"},
			Deep: &DeepRecord{Mode: "standard", Attempted: 5, OK: 1, Rejected: 3, Findings: []DeepFinding{
				{Probe: "group/25497", Result: "accepted", Detail: "hrr: the server requested group X25519Kyber768Draft00 (25497)"},
				{Probe: "group/4588", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "group/29", Result: "rejected", Detail: "remote error: tls: illegal_parameter"},
				{Probe: "suite/TLS_RSA_WITH_AES_256_GCM_SHA384@1.2", Result: "rejected", Detail: "alert handshake_failure"},
				{Probe: "resumption/psk-tls13", Result: "refused", Detail: "not-offerable: no resumption surface is instrumented in the tlsx plane"},
			}},
		}
		want := strings.Join([]string{
			"  - rating: scan-error 0/100. Zero usable PQ signal. The rubric records an error state, not a rating.",
			"  - deep: the executed standard plan ran 5 probes: 1 accepted, 3 refused with the server's reasons, 1 not-offerable; the offered-one matrix read: group offer set 1/3, suite matrix 0/1, resumption vectors 0/1; accepted: group/25497 (an obsolete draft group accepted — the harvest-now-decrypt-later exposure: strip the draft groups from the server configuration) — the per-probe detail lives in the jsonl findings.",
			"  - key exchange: x25519 (classic) — classical. A quantum computer breaks this exchange over time. The captured traffic carries the harvest-now-decrypt-later exposure.",
		}, "\n")
		if got := strings.Join(explainBlock(&draft), "\n"); got != want {
			t.Fatalf("draft-acceptance deep reading:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})

	t.Run("deep reading: an empty findings vector degrades to the field counts", func(t *testing.T) {
		bare := Record{
			Target: TargetRecord{Host: "198.51.100.23", Port: 443},
			Pq:     &PqRecord{Score: 0, Label: "scan-error", Summary: "scan-error"},
			Deep:   &DeepRecord{Mode: "standard", Attempted: 24, OK: 2, Rejected: 3},
		}
		want := strings.Join([]string{
			"  - rating: scan-error 0/100. Zero usable PQ signal. The rubric records an error state, not a rating.",
			"  - deep: the executed standard plan ran 24 probes: 2 accepted, 3 refused with the server's reasons — the per-probe detail lives in the jsonl findings.",
		}, "\n")
		if got := strings.Join(explainBlock(&bare), "\n"); got != want {
			t.Fatalf("degenerate deep reading:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})
}

// TestExplainOtherErrorClasses pins the error-prose mapping for the error
// classes beyond a plain refusal: a stalled accept (the deadline text),
// a TLS-layer rejection, and the fallback.
func TestExplainOtherErrorClasses(t *testing.T) {
	rows := []struct {
		err     string
		content string
	}{
		{"dial tcp 192.0.2.1:443: i/o timeout", "stalled"},
		{"context deadline exceeded", "stalled"},
		{"tls: handshake failure", "TLS/certificate layer"},
		{"x509: certificate signed by unknown authority", "TLS/certificate layer"},
		{"something novel", "No cipher rating"},
	}
	for _, row := range rows {
		rec := &Record{Target: TargetRecord{Host: "203.0.113.10", Port: 443}, Error: row.err}
		got := strings.Join(explainBlock(rec), "\n")
		if !strings.Contains(got, row.content) {
			t.Fatalf("error %q: block missing %q; got\n%s", row.err, row.content, got)
		}
		if !strings.Contains(got, "  - error: "+row.err+" ") {
			t.Fatalf("error %q: block does not carry the verbatim error; got\n%s", row.err, got)
		}
	}
}

// TestExplainStaysOffMachineFormats is exercised at the CLI layer (the
// refusal happens before anything scans); here, the encoder-level
// contract: with WithExplain the text line carries the verdict tail and
// the block rides under it, while jsonl/csv/urls stay byte-identical
// whether or not the option was set.
func TestExplainStaysOffMachineFormats(t *testing.T) {
	rec := Record{
		Target:    TargetRecord{Host: "example.com", Port: 443},
		Handshake: HandshakeRecord{Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid", Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3"},
		Pq:        &PqRecord{Score: 40, Label: "pq-partial"},
	}
	for _, f := range []Format{FormatJSONL, FormatCSV, FormatURLs} {
		var plain, opted bytes.Buffer
		if err := NewEncoder(&plain, f).Encode(&rec); err != nil {
			t.Fatalf("encode %v: %v", f, err)
		}
		if err := NewEncoder(&opted, f, WithExplain()).Encode(&rec); err != nil {
			t.Fatalf("encode %v explained: %v", f, err)
		}
		if plain.String() != opted.String() {
			t.Fatalf("format %v changed under -explain:\nplain: %q\nopted: %q", f, plain.String(), opted.String())
		}
	}
}

// --- PQ-43 belt-and-braces (issue #119, watched RED) ------------------------

// TestExplainErrorLineRidesAVerdictRecord: the block's error line renders
// whenever the record actually carries an error, not only under
// pq == nil. The post-PQ-43 engine never puts the rubric's error on a
// verdict-carrying record (the state lives in the pq block), so this is
// defence in depth: a leftover error string on a graded record must
// still reach the terminal verbatim, beside the verdict lines (issue
// #119's design: the renderer accounts for the case).
func TestExplainErrorLineRidesAVerdictRecord(t *testing.T) {
	rec := &Record{
		Target:    TargetRecord{Host: "link.shain.io", Port: 443},
		Handshake: HandshakeRecord{Negotiated: 29, GroupName: "x25519", GroupClass: "classic", Suite: "TLS_AES_256_GCM_SHA384", Version: "tls-1.3"},
		Pq:        &PqRecord{Score: 0, Label: "scan-error", Summary: "scan-error"},
		Error:     "rubric: zero PQ signal (score 0) — verdict scan-error",
	}
	got := strings.Join(explainBlock(rec), "\n")
	for _, want := range []string{
		"  - rating: scan-error 0/100",
		"  - error: rubric: zero PQ signal (score 0) — verdict scan-error",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("verdict-carrying record with a leftover error: block missing %q; got\n%s", want, got)
		}
	}
}

// --- PQ-50 ladder reading (issue #134, the PQ-47 follow-up, watched RED) -----

// TestExplainPQLadderReading pins the pq ladder line (PQ-50, issue #134):
// when the record's deep block is the forced PQ ladder (Deep.Mode == "pq",
// PQ-47) the block adds ONE line in operator words — the ladder's
// forced-offer counts, the ACCEPTED rows named (the actionable part: a
// draft-group acceptance IS the harvest-now-decrypt-later exposure,
// spelled by the deep reading's row-note discipline), and the refusals
// framed as the expected default: each forced PQ-only group came back
// refused unless the server truly speaks it. The pointer to the jsonl
// findings is the deep reading's. The no-ladder records above stay
// byte-identical: the wording rides only the pq mode token.
func TestExplainPQLadderReading(t *testing.T) {
	t.Run("ladder reading: one accepted PQ group, the refusals are the expected default", func(t *testing.T) {
		ladder := Record{
			Target:    TargetRecord{Host: "198.51.100.30", Port: 443},
			Handshake: HandshakeRecord{Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid", Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3"},
			Cert:      &CertRecord{SigAlg: "ecdsa-with-SHA256", KeyAlg: "ECDSA"},
			Pq:        &PqRecord{Score: 40, Label: "pq-partial", Summary: "negotiated_pq_hybrid(+40)"},
			Deep: &DeepRecord{Mode: "pq", Attempted: 8, OK: 1, Rejected: 7, Findings: []DeepFinding{
				{Probe: "group/4585", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4586", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4587", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4588", Result: "accepted", Detail: "negotiated X25519MLKEM768, suite TLS_AES_128_GCM_SHA256, tls-1.3"},
				{Probe: "group/4589", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4590", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/25497", Result: "rejected", Detail: "alert 122"},
				{Probe: "group/25498", Result: "rejected", Detail: "alert 122"},
			}},
		}
		want := strings.Join([]string{
			"  - rating: pq-partial 40/100. The negotiated key exchange is post-quantum. The certificate layer is classical. The lines below carry the detail.",
			"  - deep: the forced PQ offer set sent 8 offers: 1 accepted, 7 refused with the server's reasons, 0 not-offerable; accepted: group/4588; each forced PQ-only group refused unless the server supports that group — the per-probe detail lives in the jsonl findings.",
			"  - key exchange: X25519MLKEM768 (pq_hybrid) — post-quantum hybrid: ML-KEM-768 + X25519. This group protects the session traffic. The harvest-now-decrypt-later risk does not apply while this group negotiates.",
			"  - certificate: classical identity (ECDSA key, ecdsa-with-SHA256 signature). Use a PQ-signed or dual certificate at the next renewal.",
		}, "\n")
		if got := strings.Join(explainBlock(&ladder), "\n"); got != want {
			t.Fatalf("ladder reading block:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})

	t.Run("ladder reading: a draft-group acceptance spells the HNDL exposure", func(t *testing.T) {
		draft := Record{
			Target:    TargetRecord{Host: "198.51.100.31", Port: 443},
			Handshake: HandshakeRecord{Negotiated: 29, GroupName: "x25519", GroupClass: "classic", Suite: "TLS_AES_256_GCM_SHA384", Version: "tls-1.3"},
			Pq:        &PqRecord{Score: 0, Label: "scan-error", HNDL: true, Summary: "obsolete_draft_negotiated(-15); weak_classical_preferred(-5)"},
			Deep: &DeepRecord{Mode: "pq", Attempted: 8, OK: 1, Rejected: 7, Findings: []DeepFinding{
				{Probe: "group/4585", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4586", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4587", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4588", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4589", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4590", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/25497", Result: "accepted", Detail: "hrr: the server requested group X25519Kyber768Draft00 (25497)"},
				{Probe: "group/25498", Result: "rejected", Detail: "alert 122"},
			}},
		}
		want := strings.Join([]string{
			"  - rating: scan-error 0/100. Zero usable PQ signal. The rubric records an error state, not a rating.",
			"  - hndl: HARVEST-NOW-DECRYPT-LATER exposure. The endpoint accepts an obsolete draft PQ group (a pre-ML-KEM algorithm). Those handshakes stay decryptable to a future quantum computer. Remove the draft groups from the server configuration.",
			"  - deep: the forced PQ offer set sent 8 offers: 1 accepted, 7 refused with the server's reasons, 0 not-offerable; accepted: group/25497 (an obsolete draft group accepted — the harvest-now-decrypt-later exposure: strip the draft groups from the server configuration); each forced PQ-only group refused unless the server supports that group — the per-probe detail lives in the jsonl findings.",
			"  - key exchange: x25519 (classic) — classical. A quantum computer breaks this exchange over time. The captured traffic carries the harvest-now-decrypt-later exposure.",
		}, "\n")
		if got := strings.Join(explainBlock(&draft), "\n"); got != want {
			t.Fatalf("draft-acceptance ladder reading:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})

	t.Run("ladder reading: nothing accepted reads the refusals as the default", func(t *testing.T) {
		none := Record{
			Target:    TargetRecord{Host: "198.51.100.32", Port: 443},
			Handshake: HandshakeRecord{Negotiated: 29, GroupName: "x25519", GroupClass: "classic", Suite: "TLS_AES_256_GCM_SHA384", Version: "tls-1.3"},
			Pq:        &PqRecord{Score: 0, Label: "scan-error", Summary: "weak_classical_preferred(-5)"},
			Deep: &DeepRecord{Mode: "pq", Attempted: 8, OK: 0, Rejected: 8, Findings: []DeepFinding{
				{Probe: "group/4585", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4586", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4587", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4588", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4589", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4590", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/25497", Result: "rejected", Detail: "alert 122"},
				{Probe: "group/25498", Result: "rejected", Detail: "alert 122"},
			}},
		}
		want := strings.Join([]string{
			"  - rating: scan-error 0/100. Zero usable PQ signal. The rubric records an error state, not a rating.",
			"  - deep: the forced PQ offer set sent 8 offers: no offer was accepted, 8 refused with the server's reasons, 0 not-offerable; each forced PQ-only group refused unless the server supports that group — the per-probe detail lives in the jsonl findings.",
			"  - key exchange: x25519 (classic) — classical. A quantum computer breaks this exchange over time. The captured traffic carries the harvest-now-decrypt-later exposure.",
		}, "\n")
		if got := strings.Join(explainBlock(&none), "\n"); got != want {
			t.Fatalf("nothing-accepted ladder reading:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})

	t.Run("ladder reading: an errored probe tail keeps the counts complete", func(t *testing.T) {
		errored := Record{
			Target:    TargetRecord{Host: "198.51.100.33", Port: 443},
			Handshake: HandshakeRecord{Negotiated: 29, GroupName: "x25519", GroupClass: "classic", Suite: "TLS_AES_256_GCM_SHA384", Version: "tls-1.3"},
			Pq:        &PqRecord{Score: 0, Label: "scan-error", Summary: "weak_classical_preferred(-5)"},
			Deep: &DeepRecord{Mode: "pq", Attempted: 8, OK: 0, Rejected: 6, Findings: []DeepFinding{
				{Probe: "group/4585", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4586", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4587", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4588", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4589", Result: "rejected", Detail: "remote error: tls: handshake_failure"},
				{Probe: "group/4590", Result: "error", Detail: "read-error: the server closed without a TLS answer"},
				{Probe: "group/25497", Result: "rejected", Detail: "alert 122"},
				{Probe: "group/25498", Result: "rejected", Detail: "alert 122"},
			}},
		}
		want := strings.Join([]string{
			"  - rating: scan-error 0/100. Zero usable PQ signal. The rubric records an error state, not a rating.",
			"  - deep: the forced PQ offer set sent 8 offers: no offer was accepted, 6 refused with the server's reasons, 0 not-offerable, 1 errored on the probe path; each forced PQ-only group refused unless the server supports that group — the per-probe detail lives in the jsonl findings.",
			"  - key exchange: x25519 (classic) — classical. A quantum computer breaks this exchange over time. The captured traffic carries the harvest-now-decrypt-later exposure.",
		}, "\n")
		if got := strings.Join(explainBlock(&errored), "\n"); got != want {
			t.Fatalf("errored-tail ladder reading:\n(got)\n%s\n(want)\n%s", got, want)
		}
	})
}
