package microbench

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// PQ-32: the shipped binary is an SLO surface, not a side effect (docs/spec.md
// §6 performance contract). TestSizeSLO builds ./cmd/pqscan with the exact
// release flags (-trimpath -ldflags "-s -w", CGO_ENABLED=0) cross-compiled to
// the SLO reference target (linux/amd64) and asserts the measured byte size
// against the gate. Build output goes to $TMPDIR only — never the repo tree.
//
// Watched-RED history: this lane's RED run asserted a deliberately wrong
// pre-BinaryOptim bound (< 1,000,000) so the gate was seen failing against the
// 6.5 MB measured baseline before it was corrected here. Evidence: issue #62.
//
// SLO: linux/amd64 release build < 8,000,000 bytes (8 MB); 7 MB for
// darwin/arm64. Levers and measured sizes: docs/size-ledger.md.
const sizeSLOBytes = 8_000_000

// buildReleaseBinary is the size-gate helper: release-flags build of
// ./cmd/pqscan for linux/amd64, byte size stat, and the measured number
// written to the test log so CI logs carry it.
func buildReleaseBinary(t *testing.T) int64 {
	t.Helper()

	out := filepath.Join(t.TempDir(), "pqscan")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", out, "./cmd/pqscan")
	cmd.Dir = pqscanModuleRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("release build ./cmd/pqscan: %v\n%s", err, combined)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat built binary: %v", err)
	}
	t.Logf("linux/amd64 release build (-trimpath -ldflags \"-s -w\", CGO_ENABLED=0): %d bytes (%.2f MB)",
		fi.Size(), float64(fi.Size())/1e6)
	return fi.Size()
}

// TestSizeSLO: the linux/amd64 release binary stays under the byte gate.
func TestSizeSLO(t *testing.T) {
	size := buildReleaseBinary(t)
	if size >= sizeSLOBytes {
		t.Fatalf("size gate: linux/amd64 release build = %d bytes, want < %d (8 MB SLO)", size, sizeSLOBytes)
	}
}

// pqscanModuleRoot walks up from the test package dir to the repo root
// (go.mod) so the helper can invoke go build on ./cmd/pqscan.
func pqscanModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if fi, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && !fi.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found walking up from %s", dir)
		}
		dir = parent
	}
}
