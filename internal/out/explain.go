package out

// Explain turns a record's fields into the plain-language reading a
// netsec/netops operator needs at the terminal: PQ-38. The renderer is
// pure (explainBlock) so the prose is testable against every record
// class; the Encoder only decides whether the block rides the line.
// Machine formats (jsonl/csv/urls) never carry the block — the CLI
// refuses -explain there before anything scans.

// EncoderOption adjusts the encoder at construction (variadic; the
// 2-argument NewEncoder call sites stay intact).
type EncoderOption func(*Encoder)

// WithExplain appends the -explain block under every -text line.
func WithExplain() EncoderOption {
	return func(e *Encoder) { e.explain = true }
}

// explainBlock renders one record's reading as full lines (newline
// terminated, no trailing blank line). Stub for PQ-38's watched RED:
// returns nothing yet.
func explainBlock(r *Record) []string {
	return nil
}
