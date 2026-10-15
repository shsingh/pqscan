// Package wal implements the append-only run journal (<output>.wal, spec
// §7.6): one JSON line per scanned target, a monotone per-run seq, and a
// run id — enough to replay an interrupted run without re-scanning the
// completed targets.
//
// Writes are hand-rolled (no reflection, no encoding/json on the append
// path; fsync-batched). Replay is a cold path run once per resume and
// parses with encoding/json — correctness first where it costs nothing.
package wal

import (
	"errors"
	"os"

	"github.com/shsingh/pqscan/internal/out"
)

// WALSchema is the journal line generation; entry-shape changes bump it.
const WALSchema = 1

// Entry is one journal line: the run that appended it, its monotone seq,
// the wall-clock stamp, and the schema-1 record.
type Entry struct {
	RunID  string     `json:"run_id"`
	Seq    uint64     `json:"seq"`
	Ts     string     `json:"ts"`
	Record out.Record `json:"record"`
}

// State is a replayed journal: the completed targets (host:port → last
// record, in seq order) and how far the sequence ran. Malformed counts the
// skipped lines (decode failures and a crash-truncated tail).
type State struct {
	Completed map[string]out.Record
	MaxSeq    uint64
	Lines     int
	Malformed int
}

// Writer appends entries to one journal file. Not safe for concurrent use.
type Writer struct {
	path      string
	f         *os.File
	runID     string
	seq       uint64
	sinceSync int
}

// Create starts a fresh journal, truncating any existing one (a run that
// is not resuming does not inherit the old journal).
func Create(path, runID string) (*Writer, error) {
	return nil, errNotImplemented
}

// Reopen continues an existing journal after a resume: appends only, the
// sequence continues from the replayed watermark.
func Reopen(path, runID string, seqBase uint64) (*Writer, error) {
	return nil, errNotImplemented
}

// Append journals one record: seq increments per append, the stamp comes
// from the record (or the wall clock when it carries none).
func (w *Writer) Append(r *out.Record) error {
	return errNotImplemented
}

// Close flushes and syncs the journal (always syncs at close).
func (w *Writer) Close() error {
	return errNotImplemented
}

// NewRunID returns a fresh run id (16 hex chars, crypto/rand).
func NewRunID() string {
	return ""
}

// Replay reads a journal into resume state: completed targets keyed by
// host:port (last record wins), max seq, and the malformed-line count (a
// crash-truncated tail is data loss of the killed run's LAST write at
// most — every complete line replays).
func Replay(path string) (State, error) {
	return State{}, errNotImplemented
}

var errNotImplemented = errors.New("not implemented: WAL lands with the PQ-16 GREEN commit")
