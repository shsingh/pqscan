// Package goldens pins the encoder output byte-exact: the golden files in
// this directory are hand-crafted against the shipped rc-1 encode surface
// (the text one-liner and the json.Marshal record shape) and committed
// BEFORE the hand-rolled encoders land (PQ-16 watched RED, ADR-0002). The
// encoders must reproduce these bytes, not derive them.
package goldens

import (
	"bytes"
	"os"
	"testing"

	"github.com/shsingh/pqscan/internal/out"
)

// goldenRecord is the known record the record.* goldens encode: a fully
// populated handshake, QUIC, cert and pq blocks (every optional field
// present, a negotiated PQ hybrid) and fixed scan stamps.
//
// The cert/pq block values are a coherent rubric row for this record's
// negotiated PQ hybrid — negotiated_pq_hybrid(+40) + cert_pq_sig(+25)
// (composite-signed leaf) + dual_cert(+20) (classical-signed issuer) = 85
// → pq-ready — and the leaf analytics carried by certinfo's owned OID
// table (hybrid signature, classical ECDSA key, classical issuer ⇒
// dual). The golden pins the BYTE contract (key order incl. the new
// blocks; every inner field unconditionally encoded, false flags too),
// not a live scan; the wire-in's rubric consistency is pinned in
// cmd/pqscan's fixture tests.
func goldenRecord() *out.Record {
	return &out.Record{
		Schema: out.SchemaVersion,
		Mode:   "fast",
		Target: out.TargetRecord{
			Input:   "example.com",
			Host:    "example.com",
			IP:      "203.0.113.10",
			Port:    443,
			Ptr:     "example.com.",
			SNIUsed: "example.com",
		},
		Handshake: out.HandshakeRecord{
			Negotiated: 4588,
			GroupName:  "X25519MLKEM768",
			GroupClass: "pq_hybrid",
			Suite:      "TLS_AES_128_GCM_SHA256",
			Version:    "tls-1.3",
			ALPNNeg:    "h2",
		},
		Quic: &out.QuicRecord{
			Attempted:  true,
			State:      "handshaked",
			Negotiated: 4588,
			GroupName:  "X25519MLKEM768",
			GroupClass: "pq_hybrid",
		},
		Cert: &out.CertRecord{
			SigAlg: "MLDSA65-ECDSA-P256-SHA512",
			SigPQ:  true,
			KeyAlg: "ECDSA",
			KeyPQ:  false,
			Dual:   true,
		},
		Pq: &out.PqRecord{
			Score:   85,
			Label:   "pq-ready",
			HNDL:    false,
			Summary: "negotiated_pq_hybrid(+40); cert_pq_sig(+25); dual_cert(+20)",
		},
		Ts: "2026-10-15T09:30:12Z",
	}
}

// errorRecord is the unreachable-endpoint record: zero handshake, no QUIC
// block, an error containing a comma (CSV quoting) — the error.* goldens.
func errorRecord() *out.Record {
	return &out.Record{
		Schema: out.SchemaVersion,
		Mode:   "fast",
		Target: out.TargetRecord{
			Input:   "203.0.113.10:8443",
			Host:    "203.0.113.10",
			Port:    8443,
			SNIUsed: "",
		},
		Error: "connect: no route to host, retry 2",
		Ts:    "2026-10-15T09:30:13Z",
	}
}

// TestEncoderGoldens: for each format the encoder emits the exact hand-
// crafted bytes for the known record (and the error record where its
// zero/omitted shape matters).
func TestEncoderGoldens(t *testing.T) {
	rows := []struct {
		name   string
		file   string
		format out.Format
		rec    *out.Record
	}{
		{name: "jsonl", file: "record.jsonl", format: out.FormatJSONL, rec: goldenRecord()},
		{name: "json alias", file: "record.json", format: out.FormatJSONL, rec: goldenRecord()},
		{name: "csv", file: "record.csv", format: out.FormatCSV, rec: goldenRecord()},
		{name: "urls", file: "record.urls", format: out.FormatURLs, rec: goldenRecord()},
		{name: "text", file: "record.text", format: out.FormatText, rec: goldenRecord()},

		{name: "jsonl error record", file: "error.jsonl", format: out.FormatJSONL, rec: errorRecord()},
		{name: "csv error record", file: "error.csv", format: out.FormatCSV, rec: errorRecord()},
		{name: "text error record", file: "error.text", format: out.FormatText, rec: errorRecord()},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := out.NewEncoder(&buf, row.format).Encode(row.rec); err != nil {
				t.Fatalf("encode: %v", err)
			}
			want, err := os.ReadFile(row.file)
			if err != nil {
				t.Fatalf("golden %s: %v", row.file, err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Fatalf("bytes differ from %s\n got: %q\nwant: %q", row.file, buf.Bytes(), want)
			}
		})
	}
}

// TestJSONAliasIsJSONL: -json and -jsonl are the same byte stream (the
// record.json and record.jsonl goldens are byte-identical by construction).
func TestJSONAliasIsJSONL(t *testing.T) {
	a, err := os.ReadFile("record.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("record.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("record.json and record.jsonl differ (%d vs %d bytes)", len(a), len(b))
	}
}
