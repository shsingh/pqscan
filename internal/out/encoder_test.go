package out

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// jsonRec is the stdlib-marshal reference shape: encoding/json over the
// same tagged record (this is what the rc-1 cmd encoder emitted before the
// hand-rolled writers; Ts is JSON-ignored so it never perturbs the line).
func jsonRec(r *Record) ([]byte, error) { return json.Marshal(r) }

// TestJSONLMatchesStdlibMarshal: the hand-rolled jsonl line is byte-
// identical to encoding/json over the same record for a battery of shapes —
// every omitempty corner and the escape classes (HTML bytes, quotes,
// backslashes, control chars, U+2028/2029, invalid UTF-8). The stdlib runs
// here TEST-SIDE ONLY; production encoding never touches it.
func TestJSONLMatchesStdlibMarshal(t *testing.T) {
	base := Record{
		Schema: 1, Mode: "fast",
		Target: TargetRecord{Input: "example.com:443", Host: "example.com", Port: 443, SNIUsed: "example.com"},
		Handshake: HandshakeRecord{
			Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid",
			Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3", ALPNNeg: "h2",
		},
		// PQ-54: a quic block always carries the discovery block (the
		// engine populates the zero halves where the plane never ran) —
		// the equality rows cover reachable record shapes only
		Quic: &QuicRecord{Attempted: true, State: "handshaked", Negotiated: 4588,
			GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid", UDPBlocked: true,
			Discovered: &H3Discovery{}},
	}
	rows := []struct {
		name string
		mut  func(*Record)
	}{
		{"full record", func(r *Record) {}},
		{"zero handshake, nil quic", func(r *Record) { r.Handshake = HandshakeRecord{}; r.Quic = nil }},
		{"quic attempted, no state", func(r *Record) { r.Quic = &QuicRecord{Attempted: true, Discovered: &H3Discovery{}} }},
		{"quic udp-blocked", func(r *Record) {
			r.Quic.Negotiated = 0
			r.Quic.GroupName = ""
			r.Quic.GroupClass = ""
			r.Quic.State = "blocked"
			r.Quic.UDPBlocked = true
		}},
		{"quic discovered block, consistent halves", func(r *Record) {
			r.Quic.Discovered = &H3Discovery{AltSvcH3: true, H3Direct: true}
		}},
		{"quic mismatch: hint lies", func(r *Record) {
			r.Quic = &QuicRecord{
				Attempted: true, State: "mismatch: hint=yes truth=no", Mismatch: true,
				Discovered: &H3Discovery{AltSvcH3: true, H3Direct: false},
			}
		}},
		{"quic skipped-no-hint state", func(r *Record) {
			r.Quic = &QuicRecord{
				Attempted: false, State: "skipped: no alt-svc h3 hint",
				Discovered: &H3Discovery{AltSvcH3: false, H3Direct: false},
			}
		}},
		{"quic -quic-off record: the plane's zero discovery halves (PQ-54: the engine populates them; the writer never omits a required key)", func(r *Record) {
			r.Quic = &QuicRecord{Attempted: false, Discovered: &H3Discovery{}}
		}},
		{"pq + cert blocks", func(r *Record) {
			r.Cert = &CertRecord{SigAlg: "MLDSA65-ECDSA-P256-SHA512", SigPQ: true, KeyAlg: "ECDSA", KeyPQ: false, Dual: true}
			r.Pq = &PqRecord{Score: 85, Label: "pq-ready", HNDL: false,
				Summary: "negotiated_pq_hybrid(+40); cert_pq_sig(+25); dual_cert(+20)"}
		}},
		{"zero pq block, classical cert block", func(r *Record) {
			r.Pq = &PqRecord{} // score 0 / empty label: no omitempty inside a present block
			r.Cert = &CertRecord{SigAlg: "ecdsa-with-SHA256", KeyAlg: "ECDSA"}
		}},
		{"html bytes in error", func(r *Record) { r.Error = "alert <ssl3> & \"bad\\path\"\nsecond line	tab" }},
		{"unicode separators in host", func(r *Record) { r.Target.Host = "h\u2028o\u2029st"; r.Target.Input = "2028\u2028 20\u2029 29" }},
		{"invalid utf-8 in error", func(r *Record) { r.Error = "dial \xff tcp: refused" }},
		{"empty everything", func(r *Record) { *r = Record{Schema: 1} }},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			rec := base
			row.mut(&rec)

			var buf bytes.Buffer
			enc := NewEncoder(&buf, FormatJSONL)
			if err := enc.Encode(&rec); err != nil {
				t.Fatalf("encode: %v", err)
			}
			got := strings.TrimSuffix(buf.String(), "\n")
			if row.name == "invalid utf-8 in error" {
				// Toolchain-sensitive in encoding/json itself: go1.26
				// emits the ESCAPE TEXT \ufffd (6 bytes), go1.27 the raw
				// replacement rune (3 bytes) — surfaced by CI on this PR
				// (go.mod pins 1.26, local runs 1.27). The writer's own
				// choice is pinned below, NOT against a moving stdlib:
				// one replacement rune per bad byte (RFC 8259: JSON text
				// is exchanged as UTF-8; the line stays valid UTF-8).
				if !(strings.Contains(got, "\ufffd") && utf8.ValidString(got)) {
					t.Fatalf("hand-rolled invalid-utf-8 behavior drifted (want one U+FFFD rune, output still valid UTF-8): %s", got)
				}
				return
			}
			want, err := jsonRec(&rec)
			if err != nil {
				t.Fatalf("stdlib marshal: %v", err)
			}
			if got != string(want) {
				t.Fatalf("hand-rolled line differs from encoding/json\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// TestJSONLReplacesInvalidUTF8: every bad byte becomes one U+FFFD and the
// line stays valid UTF-8 on any toolchain (the CI-vs-local stdlib drift
// never reaches the wire).
func TestJSONLReplacesInvalidUTF8(t *testing.T) {
	rec := &Record{
		Schema: 1, Mode: "fast",
		Target: TargetRecord{Input: "\xff\xfe bad \x80", Host: "bad", Port: 443},
		Error:  "dial \xff tcp: refused",
	}
	var buf bytes.Buffer
	if err := NewEncoder(&buf, FormatJSONL).Encode(rec); err != nil {
		t.Fatalf("encode: %v", err)
	}
	got := buf.String()
	if !utf8.ValidString(got) {
		t.Fatalf("line with invalid utf-8 leaves the encoder still invalid: %q", got)
	}
	if strings.Contains(got, "\\ufffd") {
		t.Fatalf("escape-text \\ufffd leaked into the line (want the raw rune): %q", got)
	}
	var recOut map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSuffix(got, "\n")), &recOut); err != nil {
		t.Fatalf("line is not parseable json: %v", err)
	}
}

func TestFormatNames(t *testing.T) {
	rows := map[Format]string{
		FormatText: "text", FormatJSONL: "jsonl", FormatCSV: "csv", FormatURLs: "urls",
	}
	for f, want := range rows {
		if f.String() != want {
			t.Fatalf("Format(%d).String() = %q, want %q", int(f), f.String(), want)
		}
	}
}

func TestCSVHeaderOnceAndCells(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf, FormatCSV)
	recs := []*Record{
		{ // the same known record the tests/goldens files encode
			Schema: 1, Mode: "fast",
			Target: TargetRecord{Input: "example.com", Host: "example.com", IP: "203.0.113.10",
				Port: 443, Ptr: "example.com.", SNIUsed: "example.com"},
			Handshake: HandshakeRecord{Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid",
				Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3", ALPNNeg: "h2"},
			Quic: &QuicRecord{Attempted: true, State: "handshaked", Negotiated: 4588,
				GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid"},
			Ts: "2026-10-15T09:30:12Z",
		},
		{ // second record: no second header; quoted + empty cells
			Schema: 1, Mode: "fast",
			Target: TargetRecord{Input: "203.0.113.10:8443", Host: "203.0.113.10", Port: 8443},
			Error:  "connect: no route to host, retry 2",
			Ts:     "2026-10-15T09:30:13Z",
		},
	}
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3 (header + 2 rows)", len(lines))
	}
	if lines[0] != "target,host,port,ptr,sni,negotiated,group_name,group_class,suite,version,alpn,quic_state,quic_group,udp_blocked,cert_sig_alg,cert_sig_pq,cert_key_alg,cert_key_pq,cert_dual,pq_score,pq_label,pq_hndl,pq_summary,error,ts" {
		t.Fatalf("bad header: %s", lines[0])
	}
	// Both rows carry nil cert/pq blocks: the nine cells between the QUIC
	// block and error stay empty (the populated-block row is pinned by the
	// tests/goldens record.csv).
	if lines[1] != "example.com,example.com,443,example.com.,example.com,4588,X25519MLKEM768,pq_hybrid,TLS_AES_128_GCM_SHA256,tls-1.3,h2,handshaked,X25519MLKEM768,false,,,,,,,,,,,2026-10-15T09:30:12Z" {
		t.Fatalf("row 1: %s", lines[1])
	}
	if lines[2] != "203.0.113.10:8443,203.0.113.10,8443,,,,,,,,,,,,,,,,,,,,,\"connect: no route to host, retry 2\",2026-10-15T09:30:13Z" {
		t.Fatalf("row 2 (quoting + empty cells): %s", lines[2])
	}
}

func TestURLLines(t *testing.T) {
	rows := []struct {
		rec  Record
		want string
	}{
		{Record{Target: TargetRecord{Input: "example.com", Host: "example.com", Port: 443}}, "https://example.com:443"},
		{Record{Target: TargetRecord{Input: "[2001:db8::1]:8443", Host: "2001:db8::1", Port: 8443}}, "https://[2001:db8::1]:8443"},
	}
	for _, row := range rows {
		var buf bytes.Buffer
		if err := NewEncoder(&buf, FormatURLs).Encode(&row.rec); err != nil {
			t.Fatalf("encode: %v", err)
		}
		if buf.String() != row.want+"\n" {
			t.Fatalf("urls line = %q, want %q", buf.String(), row.want+"\n")
		}
	}
}

// TestTextLineShape pins the default one-liner beyond the goldens: the
// orDash/orNoHost fallbacks and every optional tail (alpn, quic pair,
// udp_blocked, error) reproduce the shipped encode surface.
func TestTextLineShape(t *testing.T) {
	rows := []struct {
		rec  Record
		want string
	}{
		{
			Record{Target: TargetRecord{Host: "example.com", Port: 443},
				Handshake: HandshakeRecord{GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid",
					Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3", ALPNNeg: "h2"},
				Quic: &QuicRecord{Attempted: true, Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid", UDPBlocked: true}},
			"example.com:443 group=X25519MLKEM768 class=pq_hybrid suite=TLS_AES_128_GCM_SHA256 version=tls-1.3 alpn=h2 quic_neg=X25519MLKEM768 quic_class=pq_hybrid udp_blocked=true",
		},
		{ // empty host and empty handshake fields carry the dash fallbacks
			Record{Target: TargetRecord{Port: 443}},
			"(no host):443 group=- class=- suite=- version=-",
		},
		{
			Record{Target: TargetRecord{Host: "203.0.113.10", Port: 8443}, Error: "connect: refused"},
			"203.0.113.10:8443 group=- class=- suite=- version=- error=connect: refused",
		},
		{
			// PQ-38: the verdict rides the line as pq=<label>(<score>)
			// — suffix-appended, every pre-existing field byte-identical.
			Record{Target: TargetRecord{Host: "example.com", Port: 443},
				Handshake: HandshakeRecord{Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid",
					Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3"},
				Pq: &PqRecord{Score: 40, Label: "pq-partial"}},
			"example.com:443 group=X25519MLKEM768 class=pq_hybrid suite=TLS_AES_128_GCM_SHA256 version=tls-1.3 pq=pq-partial(40)",
		},
		{ // the verdict tail sits between the quic block and error
			Record{Target: TargetRecord{Host: "example.com", Port: 443},
				Handshake: HandshakeRecord{Negotiated: 29, GroupName: "x25519", GroupClass: "classic", Suite: "TLS_AES_256_GCM_SHA384", Version: "tls-1.3"},
				Quic:      &QuicRecord{Attempted: true, UDPBlocked: true},
				Pq:        &PqRecord{Score: 0, Label: "scan-error"},
				Error:     "connect: no route to host"},
			"example.com:443 group=x25519 class=classic suite=TLS_AES_256_GCM_SHA384 version=tls-1.3 udp_blocked=true pq=scan-error(0) error=connect: no route to host",
		},
		{
			// PQ-46: the executed plan rides the line as a counts summary
			// (deep=<plan>:<N>p/<N>ok/<N>rej); the findings vector stays
			// jsonl-only.
			Record{Target: TargetRecord{Host: "example.com", Port: 443},
				Handshake: HandshakeRecord{Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid", Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3"},
				Pq:        &PqRecord{Score: 40, Label: "pq-partial"},
				Deep:      &DeepRecord{Mode: "standard", Attempted: 22, OK: 2, Rejected: 8}},
			"example.com:443 group=X25519MLKEM768 class=pq_hybrid suite=TLS_AES_128_GCM_SHA256 version=tls-1.3 deep=standard:22p/2ok/8rej pq=pq-partial(40)",
		},
		{
			// the certificate layer is on the line in every mode; the PQ
			// and dual facts speak only when true.
			Record{Target: TargetRecord{Host: "example.com", Port: 443},
				Handshake: HandshakeRecord{Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid", Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3"},
				Cert:      &CertRecord{SigAlg: "sha256WithRSAEncryption", KeyAlg: "ECDSA"},
				Pq:        &PqRecord{Score: 40, Label: "pq-partial"}},
			"example.com:443 group=X25519MLKEM768 class=pq_hybrid suite=TLS_AES_128_GCM_SHA256 version=tls-1.3 cert=sha256WithRSAEncryption/ECDSA pq=pq-partial(40)",
		},
		{
			Record{Target: TargetRecord{Host: "example.com", Port: 443},
				Handshake: HandshakeRecord{Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid", Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3"},
				Cert:      &CertRecord{SigAlg: "MLDSA65", SigPQ: true, KeyAlg: "MLDSA65", KeyPQ: true},
				Pq:        &PqRecord{Score: 85, Label: "pq-ready"}},
			"example.com:443 group=X25519MLKEM768 class=pq_hybrid suite=TLS_AES_128_GCM_SHA256 version=tls-1.3 cert=MLDSA65/MLDSA65 +pq-sig +pq-key pq=pq-ready(85)",
		},
		{
			Record{Target: TargetRecord{Host: "example.com", Port: 443},
				Handshake: HandshakeRecord{Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid", Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3"},
				Cert:      &CertRecord{SigAlg: "sha256WithRSAEncryption", KeyAlg: "ECDSA", Dual: true},
				Pq:        &PqRecord{Score: 60, Label: "pq-ready-hybrid"}},
			"example.com:443 group=X25519MLKEM768 class=pq_hybrid suite=TLS_AES_128_GCM_SHA256 version=tls-1.3 cert=sha256WithRSAEncryption/ECDSA +dual pq=pq-ready-hybrid(60)",
		},
		{
			// the enrichment facts ride too (ptr/sni; -ptr runs), and the
			// full field order: quic → deep → cert → ptr → sni → pq → error.
			Record{Target: TargetRecord{Host: "example.com", Port: 443, Ptr: "example.com.", SNIUsed: "ptr-then-ip"},
				Handshake: HandshakeRecord{Negotiated: 4588, GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid", Suite: "TLS_AES_128_GCM_SHA256", Version: "tls-1.3"},
				Quic:      &QuicRecord{Attempted: true, UDPBlocked: true},
				Deep:      &DeepRecord{Mode: "standard", Attempted: 24, OK: 3, Rejected: 21},
				Cert:      &CertRecord{SigAlg: "sha256WithRSAEncryption", KeyAlg: "ECDSA"},
				Pq:        &PqRecord{Score: 40, Label: "pq-partial"}},
			"example.com:443 group=X25519MLKEM768 class=pq_hybrid suite=TLS_AES_128_GCM_SHA256 version=tls-1.3 udp_blocked=true deep=standard:24p/3ok/21rej cert=sha256WithRSAEncryption/ECDSA ptr=example.com. sni=ptr-then-ip pq=pq-partial(40)",
		},
	}
	for _, row := range rows {
		var buf bytes.Buffer
		if err := NewEncoder(&buf, FormatText).Encode(&row.rec); err != nil {
			t.Fatalf("encode: %v", err)
		}
		if buf.String() != row.want+"\n" {
			t.Fatalf("text line =\n got: %q\nwant: %q", buf.String(), row.want+"\n")
		}
	}
}
