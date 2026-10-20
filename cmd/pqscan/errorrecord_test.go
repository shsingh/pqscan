package main

// errorrecord_test.go is PQ-60's battery-shaped check on the ERROR-class
// record contract (issue #157). The invariant battery (tests/matrix) cannot
// reach the error class — its loopback fixture always completes the
// handshake — so the dead-target fixture drives the same published-schema
// check here: the REAL pipeline + the REAL encoder against closed loopback
// ports, every jsonl line validated against the PUBLISHED docs/schema-v1.json
// (loaded from disk, never a hand-copy). The mirror validator is an
// unavoidable duplicate, not a divergence: _test.go files of another package
// are not importable, and the load-bearing discipline (schema from disk,
// violations named by their JSON path) rides along verbatim.
//
// ADR-0002 watched RED: this test pins the defect first. Error-class records
// (the handshake never completes) omit the quic/cert/pq blocks
// docs/schema-v1.json requires at top level — the engine leaves the blocks
// nil on the error paths and the writer emits them only when present, so a
// consumer's jq over an error-heavy stream sees a different record shape per
// class. The cure on #157 (choice A, the uniform contract) populates the
// zero halves engine-side; the zero-populated blocks carry no invented
// observation (the rubric never ran, no leaf was analyzed, the QUIC plane
// made no attempt), and the schema-required blocks stand on every record.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// pq60SchemaNode is the schema subset docs/schema-v1.json uses (type, object
// properties+required, arrays, const) — the subset the battery also walks.
type pq60SchemaNode struct {
	Type       string                     `json:"type"`
	Required   []string                   `json:"required"`
	Properties map[string]*pq60SchemaNode `json:"properties"`
	Items      *pq60SchemaNode            `json:"items"`
	Const      any                        `json:"const"`
}

// pq60LoadSchema parses the published schema contract from disk, walking up
// from the package dir to the repo root (the test's cwd is cmd/pqscan).
func pq60LoadSchema(t *testing.T) *pq60SchemaNode {
	t.Helper()
	var path string
	for dir, err := os.Getwd(); err == nil; dir = filepath.Dir(dir) {
		cand := filepath.Join(dir, "docs", "schema-v1.json")
		if _, statErr := os.Stat(cand); statErr == nil {
			path = cand
			break
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	if path == "" {
		t.Fatal("docs/schema-v1.json not found from the test's cwd (the published contract must load from disk)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s (the published schema contract): %v", path, err)
	}
	var schema pq60SchemaNode
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return &schema
}

// pq60Validate checks one decoded record against the published schema
// (the subset above); errors name the violated path.
func pq60Validate(node *pq60SchemaNode, val any) error {
	if node == nil {
		return nil
	}
	if node.Const != nil {
		if !reflect.DeepEqual(val, node.Const) {
			return fmt.Errorf("const mismatch: got %#v, want %#v", val, node.Const)
		}
	}
	switch node.Type {
	case "object":
		obj, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("want object, got %s", reflect.TypeOf(val))
		}
		for _, req := range node.Required {
			if _, ok := obj[req]; !ok {
				return fmt.Errorf("missing required field %q", req)
			}
		}
		for key, sub := range node.Properties {
			if v, ok := obj[key]; ok {
				if err := pq60Validate(sub, v); err != nil {
					return fmt.Errorf("%s: %v", key, err)
				}
			}
		}
	case "string":
		if _, ok := val.(string); !ok {
			return fmt.Errorf("want string, got %s", reflect.TypeOf(val))
		}
	case "boolean":
		if _, ok := val.(bool); !ok {
			return fmt.Errorf("want boolean, got %s", reflect.TypeOf(val))
		}
	case "integer":
		n, ok := val.(float64)
		if !ok {
			return fmt.Errorf("want integer, got %s", reflect.TypeOf(val))
		}
		if n != float64(int64(n)) {
			return fmt.Errorf("want integer, got %v", n)
		}
	case "array":
		items, ok := val.([]any)
		if !ok {
			return fmt.Errorf("want array, got %s", reflect.TypeOf(val))
		}
		for i, it := range items {
			if err := pq60Validate(node.Items, it); err != nil {
				return fmt.Errorf("[%d]: %v", i, err)
			}
		}
	}
	return nil
}

// pq60ParseJSONL parses a jsonl stream into one decoded record per line
// (the count derives from the parse, never a pinned number).
func pq60ParseJSONL(t *testing.T, stream string) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(stream, "\n"), "\n")
	if stream == "" {
		lines = nil
	}
	recs := make([]map[string]any, 0, len(lines))
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("jsonl line %d unparseable: %v\nline: %s", i+1, err, line)
		}
		recs = append(recs, obj)
	}
	return recs
}

// pq60AssertErrorZeroContract asserts the zero-populated contract on one
// ERROR-class record's decoded blocks: the schema-required quic/cert/pq
// blocks are present and carry NO invented observation — the QUIC plane
// made no attempt, no leaf was analyzed, the rubric never produced a
// verdict — while the Error field alone carries the failure class.
func pq60AssertErrorZeroContract(t *testing.T, rec map[string]any) {
	t.Helper()
	if errText, _ := rec["error"].(string); errText == "" {
		t.Fatalf("record carries no error string — not an error-class record: %v", rec)
	}
	if hs, _ := rec["handshake"].(map[string]any); hs != nil {
		if n, _ := hs["negotiated"].(float64); n != 0 {
			t.Fatalf("error record negotiated = %v, want zero (the handshake never completed)", n)
		}
	}
	quic, ok := rec["quic"].(map[string]any)
	if !ok {
		t.Fatalf("error record omits the quic block entirely — the schema-required block must be present, zero-populated (missing key)")
		return
	}
	if attempted, _ := quic["attempted"].(bool); attempted {
		t.Fatal("error record quic.attempted = true, want false (the QUIC plane never ran)")
	}
	if state, _ := quic["state"].(string); state != "" {
		t.Fatalf("error record quic.state = %q, want the empty string (no QUIC observation exists)", state)
	}
	cert, ok := rec["cert"].(map[string]any)
	if !ok {
		t.Fatal("error record omits the cert block entirely — the schema-required block must be present, zero-populated (missing key)")
	}
	if alg, _ := cert["sig_alg"].(string); alg != "" {
		t.Fatalf("error record cert.sig_alg = %q, want the empty string (no leaf was analyzed)", alg)
	}
	if alg, _ := cert["key_alg"].(string); alg != "" {
		t.Fatalf("error record cert.key_alg = %q, want the empty string (no leaf was analyzed)", alg)
	}
	pq, ok := rec["pq"].(map[string]any)
	if !ok {
		t.Fatal("error record omits the pq block entirely — the schema-required block must be present, zero-populated (missing key)")
	}
	if score, _ := pq["score"].(float64); score != 0 {
		t.Fatalf("error record pq.score = %v, want 0 (the rubric never ran)", score)
	}
	if label, _ := pq["label"].(string); label != "" {
		t.Fatalf("error record pq.label = %q, want the empty string (the rubric never ran — no invented verdict)", label)
	}
}

// pq60RunJSONL drives one real run and returns the parsed jsonl record set
// off stdout (the encode path's own bytes; stderr reports on failure).
func pq60RunJSONL(t *testing.T, args []string) (recs []map[string]any, raw string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (an unreachable endpoint is a record, not a process failure; stderr: %s)",
			code, stderr.String())
	}
	for _, line := range strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n") {
		if strings.Contains(line, "pqscan:") {
			t.Fatalf("stdout carries a pqscan note line: %q (the dialect rule: stdout is results-only)", line)
		}
	}
	raw = stdout.String()
	return pq60ParseJSONL(t, raw), raw
}

// TestErrorRecordSchemaContract (PQ-60, issue #157, watched RED): every
// error-class record the engine emits — the dialed-and-refused target and
// the breaker-skipped target alike — validates against the PUBLISHED
// schema (docs/schema-v1.json, loaded from disk) with the required blocks
// present and zero-populated.
func TestErrorRecordSchemaContract(t *testing.T) {
	schema := pq60LoadSchema(t)

	t.Run("the refused target's record validates against the published schema", func(t *testing.T) {
		deadAddr := closedLoopbackPort(t)
		recs, raw := pq60RunJSONL(t, []string{"-u", deadAddr, "-jsonl"})
		if n := len(recs); n != 1 {
			t.Fatalf("parsed %d jsonl record(s), want 1 (the composed target's sole record)\nstream: %s", n, raw)
		}
		if err := pq60Validate(schema, recs[0]); err != nil {
			t.Fatalf("the error-class record violates the published docs/schema-v1.json: %v\nline: %s", err, strings.TrimSpace(raw))
		}
		pq60AssertErrorZeroContract(t, recs[0])
	})

	t.Run("the breaker-open record validates against the published schema", func(t *testing.T) {
		// Five closed ports share one host: the per-host breaker opens at
		// breakerThreshold consecutive failures; the later targets leave as
		// "breaker open" records without a dial. Every record in the stream
		// (both the refusal class and the breaker class) must satisfy the
		// same contract; the class counts derive from the parsed stream.
		ports := make([]string, breakerThreshold+2)
		for i := range ports {
			ports[i] = closedLoopbackPort(t)
		}
		list := writeSpecFile(t, "errorrecord-targets.txt", strings.Join(ports, "\n")+"\n")
		recs, raw := pq60RunJSONL(t, []string{"-l", list, "-jsonl"})
		if n := len(recs); n != len(ports) {
			t.Fatalf("parsed %d jsonl record(s), want %d (one per composed target; every composed target yields a record)\nstream: %s", n, len(ports), raw)
		}
		breakerOpens, refusals := 0, 0
		for i, rec := range recs {
			if err := pq60Validate(schema, rec); err != nil {
				t.Fatalf("error-class record %d violates the published docs/schema-v1.json: %v\nline: %s", i+1, err, strings.TrimSpace(raw))
			}
			pq60AssertErrorZeroContract(t, rec)
			errText, _ := rec["error"].(string)
			switch {
			case strings.Contains(errText, "breaker open"):
				breakerOpens++
			case strings.Contains(errText, "connection refused"):
				refusals++
			default:
				t.Fatalf("record %d error = %q, want the refusal or the breaker skip (the stream's classes)", i+1, errText)
			}
		}
		// the classes derive from the contract, not a pinned count: the
		// first breakerThreshold targets dial (the refusals), the rest
		// ride the open breaker
		if got, want := refusals, breakerThreshold; got != want {
			t.Fatalf("refusal-class records = %d, want %d (every pre-threshold target dials)", got, want)
		}
		if got, want := breakerOpens, len(ports)-breakerThreshold; got != want {
			t.Fatalf("breaker-class records = %d, want %d (every past-threshold target skips the dial)", got, want)
		}
	})
}
