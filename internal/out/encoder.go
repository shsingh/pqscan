package out

import (
	"errors"
	"io"
)

// Format selects the record encoder for a run (spec §5.7 dialect rules:
// one JSON object per line in -jsonl, csv for spreadsheets, urls for the
// chainable endpoint list, and single-line text as the default).
type Format int

const (
	// FormatText is the default: one human line per target.
	FormatText Format = iota
	// FormatJSONL writes one schema-1 JSON record per line (-json/-jsonl).
	FormatJSONL
	// FormatCSV writes the header line once, then one row per record.
	FormatCSV
	// FormatURLs writes one scheme://host:port line per record.
	FormatURLs
)

// String returns the flag-level format name (diagnostics, progress).
func (f Format) String() string {
	switch f {
	case FormatJSONL:
		return "jsonl"
	case FormatCSV:
		return "csv"
	case FormatURLs:
		return "urls"
	default:
		return "text"
	}
}

// Encoder writes records in one format to an injected stream. Not safe
// for concurrent use: the streaming stage feeds it from its own goroutine.
type Encoder struct {
	w      io.Writer
	format Format
	header bool // csv header emitted

	buf []byte
}

// NewEncoder wires a format into a destination stream (stdout or the -o
// file — the caller owns the stream, the encoder only writes lines).
func NewEncoder(w io.Writer, f Format) *Encoder {
	return &Encoder{w: w, format: f}
}

// Encode writes one record line to the stream (CSV: the header line goes
// out ahead of the first row). One line per call; newline included.
func (e *Encoder) Encode(r *Record) error {
	return errNotImplemented
}

var errNotImplemented = errors.New("not implemented: hand-rolled encoders land with the PQ-16 GREEN commit")
