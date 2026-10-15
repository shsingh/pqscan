package badssl

import (
	"encoding/json"
	"os"
	"testing"
)

// TestExpectationsSchema validates the badssl fixture rows (data-only in
// CI; the network pass reads the same file under PQSCAN_INTEGRATION=1).
type expectations struct {
	Snapshot string `json:"snapshot"`
	Rows     []struct {
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Expect struct {
			Verdict    string `json:"verdict"`
			CertState  string `json:"cert_state"`
			SuiteClass string `json:"suite_class"`
			VersionMax string `json:"version_max"`
			Reachable  *bool  `json:"reachable"`
		} `json:"expect"`
	} `json:"rows"`
}

func TestExpectationsSchema(t *testing.T) {
	f, err := os.Open("expectations.json")
	if err != nil {
		t.Fatalf("open expectations: %v", err)
	}
	defer f.Close() //nolint:errcheck

	var want expectations
	if err := json.NewDecoder(f).Decode(&want); err != nil {
		t.Fatalf("parse expectations: %v", err)
	}
	if len(want.Rows) < 5 {
		t.Fatalf("expected a real fixture matrix, got %d rows", len(want.Rows))
	}
	if want.Snapshot == "" {
		t.Fatal("rows carry snapshot provenance (AGENTS.md registry rule)")
	}
	for _, r := range want.Rows {
		if r.Host == "" || r.Port == 0 {
			t.Errorf("row %q: host/port required", r.Host)
		}
	}
}
