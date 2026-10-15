// Package wal implements the append-only run journal (<output>.wal, spec
// §7.6): one JSON line per scanned target, a monotone per-run seq, and a
// run id — enough to replay an interrupted run without re-scanning the
// completed targets ("<output>.wal" rides beside the -o file; -resume
// reads it back into the run pipeline).
//
// The entry shape is {"run_id","seq","ts","record"}: the run id of the
// appender, the monotone per-writer sequence, the wall-clock stamp, and
// the schema-1 record body (internal/out.AppendRecordJSON). Writes are
// hand-rolled (no reflection, no encoding/json on the append path;
// fsync-batched). Replay is a cold path run once per resume and parses
// with encoding/json — correctness first where it costs nothing.
package wal

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/shsingh/pqscan/internal/out"
)

// fsyncBatch batches the journal's fsyncs (spec §7.6: write-batched every
// 1,000 records; encoders never wait on disk). Close always syncs.
const fsyncBatch = 1000

// Entry is one journal line: the run that appended it, its monotone seq,
// the wall-clock stamp, and the schema-1 record.
type Entry struct {
	RunID  string     `json:"run_id"`
	Seq    uint64     `json:"seq"`
	Ts     string     `json:"ts"`
	Record out.Record `json:"record"`
}

// State is a replayed journal: the completed targets (host:port → last
// record, in seq order; an error record is as completed as a handshake —
// the result was recorded), the sequence watermark, and the counts.
// Malformed counts the skipped lines (decode failures and a crash-
// truncated tail — at most the killed run's LAST write is lost).
type State struct {
	Completed map[string]out.Record
	MaxSeq    uint64
	Lines     int
	Malformed int
}

// Writer appends entries to one journal file. Not safe for concurrent
// use: the pipeline's record callback feeds it from its own goroutine.
type Writer struct {
	path      string
	f         *os.File
	runID     string
	seq       uint64
	sinceSync int
}

// Create starts a fresh journal, truncating any existing one: a run that
// is not resuming does not inherit the old journal.
func Create(path, runID string) (*Writer, error) {
	return openWriter(path, runID, 0, os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
}

// Reopen continues an existing journal after a resume: appends only
// (O_APPEND — the prior entries stay byte-for-byte), the sequence
// continues from the replayed watermark, and the new entries carry the
// resuming run's id.
func Reopen(path, runID string, seqBase uint64) (*Writer, error) {
	return openWriter(path, runID, seqBase, os.O_CREATE|os.O_WRONLY|os.O_APPEND)
}

func openWriter(path, runID string, seq uint64, flag int) (*Writer, error) {
	f, err := os.OpenFile(path, flag, 0o600)
	if err != nil {
		return nil, err
	}
	return &Writer{path: path, f: f, runID: runID, seq: seq}, nil
}

// Append journals one record: the sequence increments per append (and
// stays monotone across Reopen), and the entry stamp comes from the
// record — or the wall clock when it carries none.
func (w *Writer) Append(r *out.Record) error {
	w.seq++
	ts := r.Ts
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	dst := make([]byte, 0, 512)
	dst = append(dst, `{"run_id":`...)
	dst = out.AppendJSONString(dst, w.runID)
	dst = append(dst, `,"seq":`...)
	dst = strconv.AppendUint(dst, w.seq, 10)
	dst = append(dst, `,"ts":`...)
	dst = out.AppendJSONString(dst, ts)
	dst = append(dst, `,"record":`...)
	dst = out.AppendRecordJSON(dst, r)
	dst = append(dst, '}', '\n')
	if _, err := w.f.Write(dst); err != nil {
		w.seq-- // the entry never landed; the next append owns this seq
		return err
	}
	w.sinceSync++
	if w.sinceSync >= fsyncBatch {
		return w.Sync()
	}
	return nil
}

// Sync flushes the batch to disk (the batched fsync of spec §7.6).
func (w *Writer) Sync() error {
	w.sinceSync = 0
	return w.f.Sync()
}

// Close syncs then closes the journal — the last batch is never lost.
func (w *Writer) Close() error {
	err := w.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// NewRunID returns a fresh run id: 16 hex chars from crypto/rand (a time-
// hex fallback only if the CSPRNG itself errors — the journal still gets
// a fresh, distinguishable run id).
func NewRunID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// Replay reads a journal into resume state: completed targets keyed by
// host:port (the last record wins, in seq order), the sequence watermark,
// and the malformed-line count. A missing file surfaces the os error so
// the caller can choose a full scan; truncated/malformed lines are data
// loss of the killed run's last write at most — every complete entry
// replays.
func Replay(path string) (State, error) {
	f, err := os.Open(path)
	if err != nil {
		return State{}, err
	}
	defer f.Close() //nolint:errcheck

	state := State{Completed: make(map[string]out.Record)}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			state.Malformed++
			continue
		}
		state.Lines++
		key := net.JoinHostPort(e.Record.Target.Host, strconv.Itoa(int(e.Record.Target.Port)))
		e.Record.Ts = e.Ts // the replay restores the journal's stamp
		state.Completed[key] = e.Record
		if e.Seq > state.MaxSeq {
			state.MaxSeq = e.Seq
		}
	}
	if err := sc.Err(); err != nil {
		return state, err
	}
	return state, nil
}
