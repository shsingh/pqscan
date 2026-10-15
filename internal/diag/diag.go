// Package diag is pqscan's diagnostics sink: every engine decision point
// (dial, hello, handshake, refusal, classification, resolution, encoding)
// can emit an Event; with -debug the run collects a complete, machine-
// parsable Report (schema: 1) and a human-readable stream on stderr —
// the stdout stream stays clean for pipes.
package diag

import (
	"errors"
	"sync"
	"time"
)

// SchemaVersion of the diagnostics Report (breaking changes bump it).
const SchemaVersion = 1

// Event levels and domains (closed sets; adding one is a schema-aware change).
const (
	Debug = "debug"
	Info  = "info"
	Warn  = "warn"
	Error = "error"
)

// Domain buckets the event source (engine | tls | quic | dns | target |
// output | config | net).
const (
	DomEngine = "engine"
	DomTLS    = "tls"
	DomQuic   = "quic"
	DomDNS    = "dns"
	DomTarget = "target"
	DomOutput = "output"
	DomConfig = "config"
	DomNet    = "net"
)

// Event is one diagnostic observation.
type Event struct {
	Ts     time.Time         `json:"ts"`
	Level  string            `json:"level"`
	Domain string            `json:"domain"`
	Op     string            `json:"op"`
	Target string            `json:"target,omitempty"`
	Msg    string            `json:"msg,omitempty"`
	Err    string            `json:"err,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
}

// Report is the complete machine-parsable diagnostics record.
type Report struct {
	Schema    int               `json:"schema"`
	Version   string            `json:"version"`
	GoVersion string            `json:"go_version"`
	Platform  string            `json:"platform"`
	Started   time.Time         `json:"started_at"`
	Ended     time.Time         `json:"ended_at"`
	Flags     map[string]string `json:"flags,omitempty"`
	Summary   struct {
		Events   int `json:"events"`
		Errors   int `json:"errors"`
		Warnings int `json:"warnings"`
	} `json:"summary"`
	Events []Event `json:"events"`
}

var errNotImplemented = errors.New("diag: not implemented (watched-RED stub)")

// Sink collects events (ring-capped, thread-safe) and can stream a human
// rendering as they arrive. The zero value emits nothing.
type Sink struct {
	mu    sync.Mutex
	limit int
	human bool
}

// NewSink creates the run's sink. limit <= 0 means unbounded.
func NewSink(human bool, limit int) (*Sink, error) {
	return nil, errNotImplemented
}

// Emit records one event on the package sink (no-op when -debug unset).
func Emit(level, domain, op, target, msg string, err error, fields map[string]string) {}

// Report — not implemented at RED.
func (s *Sink) Report() (*Report, error) {
	return nil, errNotImplemented
}

// Humanize — not implemented at RED.
func Humanize(r *Report) (string, error) {
	return "", errNotImplemented
}
