package wal

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/out"
)

func walRecord(host string) *out.Record {
	return &out.Record{
		Schema: out.SchemaVersion,
		Mode:   "fast",
		Target: out.TargetRecord{Input: host, Host: host, Port: 443},
		Ts:     "2026-10-15T09:30:12Z",
	}
}

func readWALLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// TestCreateAppendSeqRunID: one line per append, monotone seq from 1, the
// writer's run id on every entry, the record + stamp round-trip — and the
// first line byte-exact for a known record (the journal's pinned shape).
func TestCreateAppendSeqRunID(t *testing.T) {
	path := t.TempDir() + "/run.wal"
	w, err := Create(path, "0123456789abcdef")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	hosts := []string{"a.example", "b.example", "c.example"}
	for _, h := range hosts {
		rec := walRecord(h)
		if err := w.Append(rec); err != nil {
			t.Fatalf("append %s: %v", h, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := readWALLines(t, path)
	if len(lines) != len(hosts) {
		t.Fatalf("wal lines = %d, want %d", len(lines), len(hosts))
	}
	wantLine := `{"run_id":"0123456789abcdef","seq":1,"ts":"2026-10-15T09:30:12Z","record":{"schema":1,"mode":"fast","target":{"input":"a.example","host":"a.example","ip":"","port":443,"ptr":"","sni_used":""},"handshake":{"negotiated":0,"group_name":"","group_class":"","suite":"","version":"","alpn_neg":""},"error":""}}`
	if lines[0] != wantLine {
		t.Fatalf("journal entry shape\n got: %s\nwant: %s", lines[0], wantLine)
	}
}

// TestReplayRoundTrip: a replay of a written journal restores the
// completed records exactly (fields and stamps).
func TestReplayRoundTrip(t *testing.T) {
	path := t.TempDir() + "/run.wal"
	w, err := Create(path, "aaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, h := range []string{"a.example", "b.example"} {
		if err := w.Append(walRecord(h)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	state, err := Replay(path)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(state.Completed) != 2 {
		t.Fatalf("completed = %d, want 2 (%v)", len(state.Completed), state.Completed)
	}
	for _, h := range []string{"a.example", "b.example"} {
		rec, ok := state.Completed[h+":443"]
		if !ok {
			t.Fatalf("completed missing %s: %v", h+":443", state.Completed)
		}
		if rec.Target.Host != h || rec.Target.Port != 443 || rec.Schema != 1 || rec.Mode != "fast" {
			t.Fatalf("replayed record for %s: %+v", h, rec)
		}
		if rec.Ts != "2026-10-15T09:30:12Z" {
			t.Fatalf("replayed stamp for %s = %q, want the journal stamp", h, rec.Ts)
		}
	}
	if state.MaxSeq != 2 {
		t.Fatalf("max seq = %d, want 2", state.MaxSeq)
	}
	if state.Lines != 2 || state.Malformed != 0 {
		t.Fatalf("lines = %d malformed = %d, want 2/0", state.Lines, state.Malformed)
	}
}

// TestReplayPartialTail: a crash leaves a truncated tail (and tests a
// malformed line too) — every complete line replays, the damage is
// counted, and the resume state never contains the broken entry.
func TestReplayPartialTail(t *testing.T) {
	path := t.TempDir() + "/partial.wal"
	full := make([]string, 0, 3)
	full = append(full,
		`{"run_id":"1111111111111111","seq":1,"ts":"2026-10-15T09:30:11Z","record":{"schema":1,"mode":"fast","target":{"input":"a.example","host":"a.example","ip":"","port":443,"ptr":"","sni_used":""},"handshake":{"negotiated":0},"error":""}}`,
		`{"run_id":"1111111111111111","seq":2,"ts":"2026-10-15T09:30:12Z","record":{"schema":1,"mode":"fast","target":{"input":"b.example","host":"b.example","ip":"","port":443,"ptr":"","sni_used":""},"handshake":{"negotiated":4588,"group_class":"pq_hybrid"},"error":""}}`,
		"this is not json",
		`{"run_id":"1111111111111111","seq":3,"ts":"2026-10-15T09:30:1`, // crash-truncated tail
	)
	if err := os.WriteFile(path, []byte(strings.Join(full, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	state, err := Replay(path)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(state.Completed) != 2 {
		t.Fatalf("completed = %d, want 2 (%v)", len(state.Completed), state.Completed)
	}
	if rec := state.Completed["b.example:443"]; rec.Handshake.GroupClass != "pq_hybrid" || rec.Handshake.Negotiated != 4588 {
		t.Fatalf("replayed b.example record lost its handshake: %+v", rec)
	}
	if state.MaxSeq != 2 {
		t.Fatalf("max seq = %d, want 2", state.MaxSeq)
	}
	if state.Malformed != 2 {
		t.Fatalf("malformed = %d, want 2 (bad line + truncated tail)", state.Malformed)
	}
}

// TestReopenContinuesSeq: the resumed append continues the journal's
// sequence and carries its own run id (resume replay + append).
func TestReopenContinuesSeq(t *testing.T) {
	path := t.TempDir() + "/continued.wal"
	w, err := Create(path, "1111111111111111")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := w.Append(walRecord("a.example")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Append(walRecord("b.example")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	state, err := Replay(path)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	w2, err := Reopen(path, "2222222222222222", state.MaxSeq)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := w2.Append(walRecord("c.example")); err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := readWALLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("wal lines = %d, want 3", len(lines))
	}
	if !strings.Contains(lines[2], `"run_id":"2222222222222222"`) || !strings.Contains(lines[2], `"seq":3`) {
		t.Fatalf("reopened entry carries neither the new run id nor seq 3: %s", lines[2])
	}
}

// TestCreateTruncates: a fresh (non-resume) journal start rewrites the
// previous journal — a new run does not inherit the old entries.
func TestCreateTruncates(t *testing.T) {
	path := t.TempDir() + "/fresh.wal"
	w, err := Create(path, "1111111111111111")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := w.Append(walRecord("a.example")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	w2, err := Create(path, "2222222222222222")
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	state, err := Replay(path)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(state.Completed) != 0 || state.MaxSeq != 0 || state.Lines != 0 {
		t.Fatalf("truncated journal state = %+v, want empty", state)
	}
}

// TestNewRunIDShape: 16 lowercase hex chars, unique across calls.
func TestNewRunIDShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		id := NewRunID()
		if len(id) != 16 {
			t.Fatalf("run id %q has length %d, want 16", id, len(id))
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("run id %q is not hex: %v", id, err)
		}
		if seen[id] {
			t.Fatalf("run id %q repeated", id)
		}
		seen[id] = true
	}
}

// TestAppendStampsUntstampedRecord: an entry's stamp falls back to the
// wall clock when the record carries none (RFC 3339 UTC).
func TestAppendStampsUntstampedRecord(t *testing.T) {
	path := t.TempDir() + "/stamp.wal"
	w, err := Create(path, "3333333333333333")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	rec := walRecord("a.example")
	rec.Ts = ""
	if err := w.Append(rec); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	state, err := Replay(path)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	got := state.Completed["a.example:443"]
	if _, err := time.Parse(time.RFC3339, got.Ts); err != nil {
		t.Fatalf("fallback stamp %q is not RFC 3339: %v", got.Ts, err)
	}
}

// TestReplayMissingFile: reading a journal that does not exist is the
// caller's signal to do a full scan (surfaced as the underlying error).
func TestReplayMissingFile(t *testing.T) {
	_, err := Replay(t.TempDir() + "/absent.wal")
	if err == nil {
		t.Fatal("replay of a missing file: error is nil, want the os error")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("replay error = %v, want a not-exist error", err)
	}
}
