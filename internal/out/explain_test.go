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
			"  - verdict: pq-partial 40/100. The negotiated key exchange is post-quantum; the certificate layer is classical — see the lines below.",
			"  - key exchange: X25519MLKEM768 (pq_hybrid) — post-quantum hybrid: ML-KEM-768 + X25519. Session traffic is protected from later decryption by a quantum computer; the harvest-now-decrypt-later risk does not apply while this group negotiates.",
			"  - certificate: classical identity (ECDSA key, sha256WithRSAEncryption signature). Rotating to a PQ-signed (or dual) certificate at the next renewal closes the readiness gap.",
			"  - quic: X25519MLKEM768 (pq_hybrid) on the UDP plane — the same post-quantum verdict applies to h3 traffic.",
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
			"  - verdict: scan-error 0/100. Zero usable PQ signal — scored as an error state, not a passing verdict.",
			"  - key exchange: x25519 (classic) — classical: a future quantum computer breaks it, so traffic captured today can be decrypted later (harvest now, decrypt later).",
			"  - certificate: classical identity (RSAPublicKey key, sha256WithRSAEncryption signature). Rotating to a PQ-signed (or dual) certificate at the next renewal closes the readiness gap.",
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
			"  - verdict: scan-error 0/100. Zero usable PQ signal — scored as an error state, not a passing verdict.",
			"  - hndl: HARVEST-NOW-DECRYPT-LATER exposure — the endpoint accepts an obsolete draft PQ group (a pre-ML-KEM algorithm); those handshakes' classical halves stay decryptable to a future quantum computer: strip the draft groups from the server configuration.",
			"  - key exchange: X25519Kyber768Draft00 (draft) — obsolete post-quantum draft (pre-final Kyber): readiness in appearance only, not the standard ML-KEM.",
			"  - quic: x25519 (classic) on the UDP plane — classical there too: a PQ negotiation on TCP does not protect the QUIC plane.",
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
			"  - error: connect: connection refused — no handshake was reached: the endpoint is unreachable on this port (closed or filtered); no cipher verdict is possible.",
		}, "\n")
		if got := strings.Join(explainBlock(&refused), "\n"); got != want {
			t.Fatalf("explain block:\n(got)\n%s\n(want)\n%s", got, want)
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
		{"something novel", "no cipher verdict"},
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
		"  - verdict: scan-error 0/100",
		"  - error: rubric: zero PQ signal (score 0) — verdict scan-error",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("verdict-carrying record with a leftover error: block missing %q; got\n%s", want, got)
		}
	}
}
