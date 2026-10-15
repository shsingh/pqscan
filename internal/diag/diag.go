// Package diag is pqscan's diagnostics sink: every engine decision point
// (dial, hello, handshake, refusal, classification, resolution, encoding)
// can emit an Event; with -debug the run collects a complete, machine-
// parsable Report (schema: 1) and a human-readable stream on stderr —
// the stdout stream stays clean for pipes.
package diag

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// SchemaVersion of the diagnostics Report (breaking changes bump it).
const SchemaVersion = 1

// Event levels.
const (
	Debug = "debug"
	Info  = "info"
	Warn  = "warn"
	Error = "error"
)

// Domain buckets the event source.
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

// Sink collects events (ring-capped, thread-safe, human-streaming optional).
type Sink struct {
	mu      sync.Mutex
	limit   int // 0 = unbounded
	human   bool
	flags   map[string]string
	started time.Time
	ended   time.Time
	events  []Event
}

// defaultSink is the package sink engines write to; nil until the CLI
// arms it with -debug (Emit stays a near-free no-op until then).
var defaultSink *Sink

// SetDefault arms the package sink (run() calls it under -debug).
func SetDefault(s *Sink) {
	defaultSink = s
}

// Default returns the armed sink or nil.
func Default() *Sink { return defaultSink }

// NewSink creates the run's sink; human=true streams events live to
// stderr. limit <= 0 means unbounded.
func NewSink(human bool, limit int) (*Sink, error) {
	return &Sink{limit: limit, human: human, started: time.Now()}, nil
}

// SetFlags records the effective configuration on the sink (appears in
// every Report).
func (s *Sink) SetFlags(f map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flags = f
}

// Emit records one event on the package sink (no-op when -debug unset).
func Emit(level, domain, op, target, msg string, err error, fields map[string]string) {
	s := Default()
	if s == nil {
		return
	}
	ev := Event{
		Ts: time.Now(), Level: level, Domain: domain, Op: op, Target: target,
		Msg: msg, Fields: fields,
	}
	if err != nil {
		ev.Err = err.Error()
	}
	s.mu.Lock()
	if s.limit > 0 && len(s.events) >= s.limit {
		s.events = s.events[1:]
	}
	s.events = append(s.events, ev)
	human := s.human
	s.mu.Unlock()

	if human {
		fmt.Fprintf(os.Stderr, "  %s [%s][%s] %s %s: %s%s %s\n",
			ev.Ts.Format("15:04:05.000"), ev.Level, ev.Domain, ev.Op, ev.Target,
			ev.Msg, errSuffix(ev.Err), fieldsSuffix(ev.Fields))
	}
}

// Report builds the machine record; the call timestamps ended_at.
func (s *Sink) Report() (*Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ended = time.Now()
	return &Report{
		Schema:    SchemaVersion,
		Version:   binaryVersion(),
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		Started:   s.started,
		Ended:     s.ended,
		Flags:     s.flags,
		Events:    append([]Event(nil), s.events...),
		Summary:   summarize(s.events),
	}, nil
}

// Humanize renders the whole report as the run's readable diagnostics
// block — the same shape users paste into issues.
func Humanize(r *Report) (string, error) {
	b := &strings.Builder{}
	fmt.Fprintf(b, "── pqscan diagnostics ── schema %d ── %s (%s, %s)\n", r.Schema, r.Version, r.GoVersion, r.Platform)
	fmt.Fprintf(b, "run: %s → %s\n", r.Started.Format(time.RFC3339Nano), r.Ended.Format(time.RFC3339Nano))
	if keys := sortedKeys(r.Flags); len(keys) > 0 {
		pairs := make([]string, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, k+"="+r.Flags[k])
		}
		fmt.Fprintf(b, "flags: %s\n", strings.Join(pairs, " "))
	}
	fmt.Fprintf(b, "events (%d):\n", r.Summary.Events)
	for _, e := range r.Events {
		fmt.Fprintf(b, "  %s [%s][%s] %s %s: %s%s %s\n",
			e.Ts.Format("15:04:05.000"), e.Level, e.Domain, e.Op, e.Target,
			e.Msg, errSuffix(e.Err), fieldsSuffix(e.Fields))
	}
	fmt.Fprintf(b, "summary: %d events (%d errors, %d warnings)\n", r.Summary.Events, r.Summary.Errors, r.Summary.Warnings)
	return b.String(), nil
}

func summarize(events []Event) (out struct {
	Events   int `json:"events"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
}) {
	out.Events = len(events)
	for _, e := range events {
		switch e.Level {
		case Error:
			out.Errors++
		case Warn:
			out.Warnings++
		}
	}
	return out
}

func errSuffix(err string) string {
	if err == "" {
		return ""
	}
	return " (" + err + ")"
}

func fieldsSuffix(f map[string]string) string {
	keys := sortedKeys(f)
	if len(keys) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+f[k])
	}
	return " " + strings.Join(pairs, " ")
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// binaryVersion is injected by ldflags -X diag.mainVersion at build time.
var binaryVersion = func() string { return mainVersion }
