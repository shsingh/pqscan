// Package out hosts the encoders (jsonl/csv/text/urls) and the append-only
// WAL that keeps encoders off the hot path (spec §7.2, §7.6).
//
// Substrate stub (PQ-04): schema constant and encoder contract only.
package out

// SchemaVersion is the JSONL schema generation (spec §5.7). Field semantics
// lock per generation; changes to existing fields are breaking and bump it.
const SchemaVersion = 1

// Record is the JSONL record shape. The hand-rolled encoder writes it
// without reflection; see the schema example in the spec.
type Record struct {
	Schema int    `json:"schema"`
	Mode   string `json:"mode"`
	Target TargetRecord
	Error  string `json:"error"`
}

// TargetRecord identifies what was scanned and with which SNI strategy.
type TargetRecord struct {
	Input   string `json:"input"`
	Host    string `json:"host"`
	IP      string `json:"ip"`
	Port    uint16 `json:"port"`
	Ptr     string `json:"ptr"`
	SNIUsed string `json:"sni_used"`
}
