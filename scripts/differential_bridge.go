// PQ-22 second pair: the real-tool differential harness's bridge wire.
//
// scripts/differential_bridge.go reads the three captured tool outputs
// (pqscan's schema-1 JSONL, the gnutls-cli-debug transcript, sslyze's
// --json_out document), parses them through the parity engine's own
// parsers (internal/differential.ParseGnutlsCLI / ParseSSLyze) plus the
// record mapping below, reduces them through differential.Parity and
// prints the comparison rows. Exit codes:
//
//	0 — parity holds: no row carries a concrete divergence;
//	1 — a PQ-relevant disagreement: at least one row's Diff is non-empty
//	    (a concrete contradiction between pqscan and a reference tool);
//	2 — the inputs themselves could not be read or parsed (missing
//	    fixture, empty transcript, unrecognizable shape — never a crash).
//
// Note-only rows (reference-side coverage gaps, the pqscan-only probe
// exception, rule-less checks) are printed and never affect the exit
// code: parity is about concrete contradictions, not about the
// reference tools being narrower on some probes than the pqscan side.
//
// Offline CI feeds it the canned fixtures (tests/fixtures/differential/)
// through the differential-parity job; the live harness
// (scripts/differential_run.sh, DIFFERENTIAL_LIVE=1) feeds it real runs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/shsingh/pqscan/internal/differential"
)

// recordVersion maps pqscan's schema-1 handshake.version spellings
// ("tls-1.3") to the canonical tokens the parity rows use ("TLS1.3");
// the engine's version normalizer is package-internal, so the mapping
// lives here at the wire level (script-level fixes stay preferred; the
// engine only grows when a live cross-validated run demands it).
var recordVersion = map[string]string{
	"ssl-3.0": "SSL3.0",
	"tls-1.0": "TLS1.0",
	"tls-1.1": "TLS1.1",
	"tls-1.2": "TLS1.2",
	"tls-1.3": "TLS1.3",
}

func main() {
	pqscanPath := flag.String("pqscan", "", "pqscan schema-1 JSONL (one or more records)")
	gnutlsPath := flag.String("gnutls", "", "gnutls-cli-debug transcript")
	sslyzePath := flag.String("sslyze", "", "sslyze --json_out document")
	flag.Parse()
	if *pqscanPath == "" || *gnutlsPath == "" || *sslyzePath == "" {
		fmt.Fprintln(os.Stderr, "differential_bridge: all three inputs are required: -pqscan <jsonl> -gnutls <transcript> -sslyze <json>")
		os.Exit(2)
	}

	pqObs, err := pqscanObservations(*pqscanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "differential_bridge: -pqscan %s: %v\n", *pqscanPath, err)
		os.Exit(2)
	}
	gnutlsRaw, gnutlsObs, err := readParsed(*gnutlsPath, "gnutls-cli-debug transcript", differential.ParseGnutlsCLI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "differential_bridge: -gnutls %s: %v\n", *gnutlsPath, err)
		os.Exit(2)
	}
	sslyzeRaw, sslyzeObs, err := readParsed(*sslyzePath, "sslyze JSON document", differential.ParseSSLyze)
	if err != nil {
		fmt.Fprintf(os.Stderr, "differential_bridge: -sslyze %s: %v\n", *sslyzePath, err)
		os.Exit(2)
	}

	rows := differential.Parity(pqObs, append(gnutlsObs, sslyzeObs...))
	report(os.Stdout, rows, *pqscanPath, *gnutlsPath, *sslyzePath, gnutlsRaw, sslyzeRaw)
	if diverged(rows) > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

// pqscanObservations parses the schema-1 JSONL into the pqscan-side
// observations (the wire the parity engine's doc comment reserves for
// this pair): per record's handshake block — the top observed protocol
// version, the negotiated suite (RFC/IANA spelling) and the negotiated
// group row (keyed via differential.GroupCheck so both sides join on the
// same row). A record with no handshake evidence (failed probe, error
// record) contributes nothing; its absence then surfaces as note rows.
func pqscanObservations(path string) ([]differential.Obs, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("missing or unreadable input (%w)", err)
	}
	var obs []differential.Obs
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			Handshake struct {
				GroupName string `json:"group_name"`
				Suite     string `json:"suite"`
				Version   string `json:"version"`
			} `json:"handshake"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("unparseable pqscan JSONL record: %w", err)
		}
		if rec.Handshake.GroupName == "" && rec.Handshake.Suite == "" && rec.Handshake.Version == "" {
			continue // a failed probe record: its absence surfaces as note rows
		}
		if v, ok := recordVersion[strings.TrimSpace(strings.ToLower(rec.Handshake.Version))]; ok {
			obs = append(obs, differential.Obs{Tool: "pqscan", Check: differential.CheckProtocol, Detail: v})
		}
		if rec.Handshake.Suite != "" {
			obs = append(obs, differential.Obs{Tool: "pqscan", Check: differential.CheckSuite, Detail: rec.Handshake.Suite})
		}
		if rec.Handshake.GroupName != "" {
			obs = append(obs, differential.Obs{Tool: "pqscan",
				Check:  differential.GroupCheck(rec.Handshake.GroupName),
				Detail: rec.Handshake.GroupName})
		}
	}
	if len(obs) == 0 {
		return nil, fmt.Errorf("no handshake evidence in the pqscan JSONL records (empty file, or every probe failed)")
	}
	return obs, nil
}

// readParsed reads one reference-tool output and parses it; the raw text
// rides along for the report's provenance lines.
func readParsed(path, what string, parse func(string) ([]differential.Obs, error)) (string, []differential.Obs, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("%s: missing or unreadable input (%w)", what, err)
	}
	obs, err := parse(string(raw))
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", what, err)
	}
	return string(raw), obs, nil
}

// gnutlsSelfReport picks the version banner off a transcript's first
// non-empty line ("GnuTLS debug client 3.8.13").
func gnutlsSelfReport(raw string) string {
	for _, ln := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(ln)
		if line != "" {
			return line
		}
	}
	return ""
}

// sslyzeSelfReport picks sslyze's reported version ("sslyze_version") off
// the JSON root.
func sslyzeSelfReport(raw string) (string, error) {
	var meta struct {
		SslyzeVersion string `json:"sslyze_version"`
	}
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return "", fmt.Errorf("unparseable sslyze JSON root: %w", err)
	}
	if meta.SslyzeVersion == "" {
		return "(no sslyze_version)", nil
	}
	return meta.SslyzeVersion, nil
}

// diverged counts the rows that carry a concrete divergence (the
// PQ-relevant disagreement set for the exit-code contract).
func diverged(rows []differential.Comparison) int {
	n := 0
	for _, r := range rows {
		if r.Diff != "" {
			n++
		}
	}
	return n
}

// report prints the comparison rows and the summary footer; rows arrive
// in the engine's deterministic (sorted by check) order.
func report(w *os.File, rows []differential.Comparison, pqscanPath, gnutlsPath, sslyzePath, gnutlsRaw, sslyzeRaw string) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "== PQ-22 differential parity — the gate keeping pqscan honest vs the references ==")
	fmt.Fprintf(tw, "inputs: -pqscan %s\n", pqscanPath)
	fmt.Fprintf(tw, "        -gnutls %s (%q)\n", gnutlsPath, gnutlsSelfReport(gnutlsRaw))
	sslyzeVer, err := sslyzeSelfReport(sslyzeRaw)
	if err != nil {
		sslyzeVer = "(unparseable)"
	}
	fmt.Fprintf(tw, "        -sslyze %s (sslyze %s)\n", sslyzePath, sslyzeVer)
	fmt.Fprintln(tw, "check\tpqscan observation\tagreement\tdivergence / note")
	for _, r := range rows {
		pq := r.PQObs
		if pq == "" {
			pq = "-"
		}
		verdict := "note"
		if r.Diff != "" {
			verdict = "DIVERGE"
		} else if r.Agree {
			verdict = "AGREE"
		}
		detail := r.Diff
		if detail == "" {
			detail = r.Note
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Check, pq, verdict, detail)
	}
	fmt.Fprintf(tw, "parity: %d rows — %d agree, %d diverge, %d noted; exit code %d\n",
		len(rows), agreed(rows), diverged(rows), noted(rows), exitCode(rows))
	tw.Flush()
}

// agreed counts the agreeing rows; noted counts the note-only remainder.
func agreed(rows []differential.Comparison) int {
	n := 0
	for _, r := range rows {
		if r.Diff == "" && r.Agree {
			n++
		}
	}
	return n
}

func noted(rows []differential.Comparison) int {
	return len(rows) - agreed(rows) - diverged(rows)
}

func exitCode(rows []differential.Comparison) int {
	if diverged(rows) > 0 {
		return 1
	}
	return 0
}
