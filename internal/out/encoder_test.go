package out

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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
		Quic: &QuicRecord{Attempted: true, State: "handshaked", Negotiated: 4588,
			GroupName: "X25519MLKEM768", GroupClass: "pq_hybrid", UDPBlocked: true},
	}
	rows := []struct {
		name string
		mut  func(*Record)
	}{
		{"full record", func(r *Record) {}},
		{"zero handshake, nil quic", func(r *Record) { r.Handshake = HandshakeRecord{}; r.Quic = nil }},
		{"quic attempted, no state", func(r *Record) { r.Quic = &QuicRecord{Attempted: true} }},
		{"quic udp-blocked", func(r *Record) {
			r.Quic.Negotiated = 0
			r.Quic.GroupName = ""
			r.Quic.GroupClass = ""
			r.Quic.State = "blocked"
			r.Quic.UDPBlocked = true
		}},
		{"html bytes in error", func(r *Record) { r.Error = "alert <ssl3> & \"bad\\path\"\nsecond line\ttab" }},
		{"unicode separators in host", func(r *Record) { r.Target.Host = "h o st"; r.Target.Input = "2028 20 29" }},
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
			want, err := jsonRec(&rec)
			if err != nil {
				t.Fatalf("stdlib marshal: %v", err)
			}
			got := strings.TrimSuffix(buf.String(), "\n")
			if got != string(want) {
				t.Fatalf("hand-rolled line differs from encoding/json\n got: %s\nwant: %s", got, want)
			}
		})
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
	if lines[0] != "target,host,port,ptr,sni,negotiated,group_name,group_class,suite,version,alpn,quic_state,quic_group,udp_blocked,error,ts" {
		t.Fatalf("bad header: %s", lines[0])
	}
	if lines[1] != "example.com,example.com,443,example.com.,example.com,4588,X25519MLKEM768,pq_hybrid,TLS_AES_128_GCM_SHA256,tls-1.3,h2,handshaked,X25519MLKEM768,false,,2026-10-15T09:30:12Z" {
		t.Fatalf("row 1: %s", lines[1])
	}
	if lines[2] != "203.0.113.10:8443,203.0.113.10,8443,,,,,,,,,,,,\"connect: no route to host, retry 2\",2026-10-15T09:30:13Z" {
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
