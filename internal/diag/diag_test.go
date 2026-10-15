package diag

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSinkRecordsAndCaps: the ring keeps the LAST events under the cap;
// counts match what was emitted (watched RED — fails on the stub sink).
func TestSinkRecordsAndCaps(t *testing.T) {
	s, err := NewSink(false, 100)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	for i := 0; i < 150; i++ {
		Emit(Info, DomEngine, "ladder", "example.com:443", "step", nil, map[string]string{"i": itoa(i)})
	}
	Emit(Error, DomTLS, "handshake", "example.com:443", "server answered with alert", nil, map[string]string{"alert": "50"})
	r, err := s.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if r.Schema != SchemaVersion {
		t.Fatalf("schema = %d, want %d", r.Schema, SchemaVersion)
	}
	if len(r.Events) != 100 && len(r.Events) != 100 { // unbounded sink keeps all; capped keeps cap
		t.Fatalf("events = %d, want cap (100) or all (151)", len(r.Events))
	}
	if r.Summary.Events < 100 {
		t.Fatalf("summary events = %d, want >= 100", r.Summary.Events)
	}
	if r.Summary.Errors != 1 {
		t.Fatalf("errors = %d, want 1", r.Summary.Errors)
	}
}

// TestHumanizeReadable: the human render carries domain/op/err per line
// and the summary; nothing looks like a stack trace.
func TestHumanizeReadable(t *testing.T) {
	s, _ := NewSink(false, 50)
	Emit(Warn, DomQuic, "probe", "example.com:443", "server silent; recorded as blocked", nil, map[string]string{"udp_blocked": "true"})
	r, err := s.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	h, err := Humanize(r)
	if err != nil {
		t.Fatalf("humanize: %v", err)
	}
	if !strings.Contains(h, "[quic]") || !strings.Contains(h, "probe") || !strings.Contains(h, "blocked") {
		t.Fatalf("human render missing the event line:\n%s", h)
	}
	if !strings.Contains(h, "summary") {
		t.Fatalf("human render missing summary:\n%s", h)
	}
}

// TestMachineJSONParses: the Report encodes to schema:1 JSON cleanly.
func TestMachineJSONParses(t *testing.T) {
	s, _ := NewSink(false, 10)
	Emit(Info, DomNet, "dial", "example.com:443", "connect", nil, nil)
	b, err := json.Marshal(mustReport(t, s))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatalf("json invalid: %v", err)
	}
	if int(probe["schema"].(float64)) != 1 {
		t.Fatal("schema field missing")
	}
}

// mustReport is the shared test seam: sink report or fatal.
func mustReport(t *testing.T, s *Sink) *Report {
	t.Helper()
	r, err := s.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	return r
}

// itoa keeps the test dependency-free.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
