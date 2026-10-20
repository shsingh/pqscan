// Adapter flag wiring tests (PQ-35, issue #80, watched RED): the
// -from-httpx / -from-naabu files enter the ONE composition the
// -u/-l/-- specs share — internal/target's PD-dialect adapters feed
// grammar.Parse, the composition dedupes by host:port (first occurrence
// wins), and the record order is the source order (specs first, then the
// adapter files in flag order). Refusal paths are the composition's
// usage class (exit 64): an unreadable or unparseable adapter file
// refuses the run named by its flag, and no partial list ever scans.
package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestAdapterFlagRegistration: the PD-dialect input flags register via
// the fs.String shape the usage-drift gate reads back; each flag's parse
// lands on the adapter's own usage refusal (exit 64, the unreadable file
// named by the flag) — never the flag-provided-but-not-defined artifact.
func TestAdapterFlagRegistration(t *testing.T) {
	rows := []struct {
		name string
		args []string
		flag string
	}{
		{"from-httpx registers", []string{"-from-httpx", "/nonexistent/pqscan/httpx.txt"}, "-from-httpx"},
		{"from-naabu registers", []string{"-from-naabu", "/nonexistent/pqscan/naabu.txt"}, "-from-naabu"},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(row.args, &out, &errOut)
			if code != 64 {
				t.Fatalf("exit = %d, want 64 (stderr: %s)", code, errOut.String())
			}
			if strings.Contains(errOut.String(), "flag provided but not defined") {
				t.Fatalf("the adapter flag %s did not register: %q", row.flag, errOut.String())
			}
			if !strings.Contains(errOut.String(), row.flag) {
				t.Fatalf("the refusal should name its flag %s: %q", row.flag, errOut.String())
			}
		})
	}
}

// TestAdapterComposition: -from-httpx and -from-naabu fixture files
// compose with -u and the other spec sources under the ONE dedupe
// (host:port, first occurrence wins) in source order.
func TestAdapterComposition(t *testing.T) {
	hybridAddr := startHybridFixture(t)
	classicAddr := startClassicFixture(t)
	secondHybridAddr := startHybridFixture(t)
	// The naabu ports-block shape renders per the tool: a host line, then
	// bare-decimal port lines beneath it.
	naabuBlock := func(addr string) string {
		_, port, _ := strings.Cut(addr, ":")
		return "127.0.0.1\n    " + port + "\n"
	}
	_, classicPort, _ := strings.Cut(classicAddr, ":")

	rows := []struct {
		name       string
		args       []string
		httpx      string // the -from-httpx fixture file's lines; "" = flag absent
		naabu      string // the -from-naabu fixture file's lines; "" = flag absent
		wantCode   int
		wantStderr string // a refusal must carry this; "" = none required
		wantOrder  []string
	}{
		{
			name: "both adapter files compose with -u, deduped by host:port in order",
			args: []string{"-u", hybridAddr},
			// httpx decoration (scheme + path suffix) strips to the
			// host:port spec; the -u line dedupes against its stripped
			// form, classic arrives once, the naabu ports block appends
			// the second hybrid.
			httpx:     "https://" + classicAddr + "/admin\nhttps://" + hybridAddr + "\n",
			naabu:     naabuBlock(secondHybridAddr),
			wantCode:  0,
			wantOrder: []string{hybridAddr, classicAddr, secondHybridAddr},
		},
		{
			name:      "naabu's two shapes: the host:port line and the bare-host ports block",
			args:      []string{},
			naabu:     "# the lab sweep\n\n127.0.0.1:" + classicPort + "\n" + naabuBlock(hybridAddr),
			wantCode:  0,
			wantOrder: []string{classicAddr, hybridAddr},
		},
		{
			name:       "a naabu port outside a ports block refuses the run (exit 64)",
			args:       []string{},
			naabu:      "8443\n",
			wantCode:   64,
			wantStderr: "outside a ports block",
		},
		{
			name:       "an out-of-range naabu port refuses with the line number (exit 64)",
			args:       []string{},
			naabu:      "127.0.0.1\n    99999\n",
			wantCode:   64,
			wantStderr: "line 2",
		},
		{
			name:       "a naabu cidr line takes the composition's PQ-16 refusal (exit 64)",
			args:       []string{},
			naabu:      "192.0.2.0/24\n",
			wantCode:   64,
			wantStderr: "cidr expansion is not supported",
		},
		{
			name:       "an httpx line whose stripped spec is a bare port refuses (exit 64)",
			args:       []string{},
			httpx:      "https://:443/admin\n",
			wantCode:   64,
			wantStderr: "-from-httpx",
		},
	}

	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			args := append([]string(nil), row.args...)
			args = append(args, "-quic-off", "-jsonl")
			outFile := ""
			if row.wantOrder != nil {
				outFile = filepath.Join(t.TempDir(), "adapters.jsonl")
				args = append(args, "-o", outFile)
			}
			if row.httpx != "" {
				path := writeSpecFile(t, "httpx-fixture.txt", row.httpx)
				args = append(args, "-from-httpx", path)
			}
			if row.naabu != "" {
				path := writeSpecFile(t, "naabu-fixture.txt", row.naabu)
				args = append(args, "-from-naabu", path)
			}

			var out, errOut bytes.Buffer
			code := run(args, &out, &errOut)
			if code != row.wantCode {
				t.Fatalf("exit = %d, want %d (stderr: %s)", code, row.wantCode, errOut.String())
			}
			if row.wantStderr != "" && !strings.Contains(errOut.String(), row.wantStderr) {
				t.Fatalf("stderr missing %q: %s", row.wantStderr, errOut.String())
			}
			if outFile == "" {
				if out.Len() != 0 {
					t.Fatalf("stdout polluted on a refusal (results belong to -o): %q", out.String())
				}
				return
			}
			recs := readJSONLRecords(t, outFile)
			if len(recs) != len(row.wantOrder) {
				t.Fatalf("records = %d, want %d (stderr: %s)", len(recs), len(row.wantOrder), errOut.String())
			}
			for i, want := range row.wantOrder {
				if recs[i]["target"].(map[string]any)["input"] != want {
					t.Fatalf("record %d input = %v, want %q (source order, first-occurrence dedupe)",
						i, recs[i]["target"].(map[string]any)["input"], want)
				}
			}
		})
	}
}
