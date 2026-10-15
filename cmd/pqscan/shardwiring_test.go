// Shard flag wiring tests (PQ-24, issue #47, watched RED): -shard i/n
// parses the shard "i/n" grammar (internal/shard's Spec) and,
// POST-composition, filters the composed targets to the shard's
// membership (internal/shard's Assign: fnv1a64(host:port) % n == i-1).
// The partition property the wiring consumes: shards 1..n over the same
// composed list are disjoint and, unioned, complete — a multi-box pass
// covers the input with no target scanned twice. The run notes the
// membership on stderr ("shard i/n: N of M targets").
package main

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestShardSpecValidation: the shard value is the "i/n" grammar — a
// bogus value is a usage-class refusal (exit 64) that names the
// problem, before anything composes or scans; the flag itself
// registers (never "flag provided but not defined").
func TestShardSpecValidation(t *testing.T) {
	rows := []struct {
		spec   string
		stderr string
	}{
		{"bogus", `want "i/n"`},
		{"0/2", "shard index must be at least 1"},
		{"3/2", "shard index 3 > total 2"},
		{"1/0", "total must be at least 1"},
	}
	for _, row := range rows {
		row := row
		t.Run("spec "+row.spec, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run([]string{"-u", "127.0.0.1:443", "-shard", row.spec}, &out, &errOut)
			if code != 64 {
				t.Fatalf("exit = %d, want 64 (stderr: %s)", code, errOut.String())
			}
			if strings.Contains(errOut.String(), "flag provided but not defined") {
				t.Fatalf("the -shard flag did not register: %q", errOut.String())
			}
			if !strings.Contains(errOut.String(), row.stderr) {
				t.Fatalf("the refusal should carry the shard-grammar error: %q", errOut.String())
			}
		})
	}
}

// TestShardPartitionDisjointCovering (the dispatch's 2-shard test on a
// synthetic list): shard 1 + shard 2 = the union = the complete list,
// disjointly. The membership note on stderr must carry the recorded
// count and the composed total.
func TestShardPartitionDisjointCovering(t *testing.T) {
	// 12 synthetic targets, all closed loopback ports: instant refusals —
	// every record comes back (an error record), the run exits 0, and
	// nothing touches the network.
	ports := make([]string, 12)
	for i := range ports {
		ports[i] = closedLoopbackPort(t)
	}

	shardScan := func(t *testing.T, spec string) []string {
		t.Helper()
		list := writeSpecFile(t, "shard-targets.txt", strings.Join(ports, "\n")+"\n")
		output := filepath.Join(t.TempDir(), "shard.jsonl")
		var out, errOut bytes.Buffer
		code := run([]string{"-l", list, "-shard", spec, "-jsonl", "-o", output}, &out, &errOut)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		recs := readJSONLRecords(t, output)
		inputs := make([]string, 0, len(recs))
		for _, rec := range recs {
			inputs = append(inputs, rec["target"].(map[string]any)["input"].(string))
		}
		// the membership note counts exactly what the shard scanned
		note := "shard " + spec + ": " + strconv.Itoa(len(inputs)) + " of 12 targets"
		if !strings.Contains(errOut.String(), note) {
			t.Fatalf("stderr note %q missing: %q", note, errOut.String())
		}
		// the shard's slice stays in composed order (a subsequence of
		// the composed list)
		positions := make([]int, 0, len(inputs))
		for _, input := range inputs {
			seen := false
			for i, p := range ports {
				if p == input {
					positions = append(positions, i)
					seen = true
					break
				}
			}
			if !seen {
				t.Fatalf("shard %s scanned %q, not a member of the composed list", spec, input)
			}
		}
		for i := 1; i < len(positions); i++ {
			if positions[i] <= positions[i-1] {
				t.Fatalf("shard %s's records left composed order: %v", spec, positions)
			}
		}
		return inputs
	}

	shard1 := shardScan(t, "1/2")
	shard2 := shardScan(t, "2/2")

	// disjoint: no target scanned twice across the pair
	mem1 := make(map[string]bool, len(shard1))
	for _, input := range shard1 {
		mem1[input] = true
	}
	for _, input := range shard2 {
		if mem1[input] {
			t.Fatalf("%q scanned by both 1/2 and 2/2 (the shards must be disjoint)", input)
		}
	}

	// complete: shard1 + shard2 = the union = the composed list
	union := make(map[string]bool, len(shard1)+len(shard2))
	for _, input := range append(shard1, shard2...) {
		union[input] = true
	}
	if len(union) != len(ports) {
		t.Fatalf("shard union covers %d targets, want %d (the shards must be complete)", len(union), len(ports))
	}
	for _, p := range ports {
		if !union[p] {
			t.Fatalf("target %q is in no shard (the shards must be complete)", p)
		}
	}
}
