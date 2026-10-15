package registry

import (
	"strings"
	"testing"

	"github.com/shsingh/pqscan/internal/classify"
)

// TestRegistryClassifyBridge pins the seam between the IANA registry
// snapshot and the hand-snapshot taxonomy table: for the PQ-18 anchor
// codepoints, the registry NAME (IANA Description) and the classify
// GROUP CLASS must keep telling the same story — standards-track
// X25519MLKEM768 is a PQ hybrid, x25519 is classical, and the pre-
// standards Kyber draft stays the compat-oracle hybrid_draft. A regen
// that changed a codepoint's name or its class (or deleted one side of
// the pair) breaks this table. 25497 matches by prefix: IANA annotates
// "(OBSOLETE)" into the Description; classify carries the class.
func TestRegistryClassifyBridge(t *testing.T) {
	m := loadSnapshot(t)

	cases := []struct {
		value     uint32
		wantName  string
		nameExact bool
		wantClass classify.Class
	}{
		{4588, "X25519MLKEM768", true, classify.ClassPQHybrid},
		{29, "x25519", true, classify.ClassClassic},
		{25497, "X25519Kyber768Draft00", false, classify.ClassPQHybridD},
	}
	for _, c := range cases {
		entry, ok := Lookup(m, c.value)
		if !ok {
			t.Fatalf("Lookup(%d) missing from the registry snapshot", c.value)
		}
		if entry.Value != c.value {
			t.Errorf("Lookup(%d).Value = %d, want %d", c.value, entry.Value, c.value)
		}
		nameLinesUp := false
		if c.nameExact {
			nameLinesUp = entry.Name == c.wantName
		} else {
			nameLinesUp = strings.HasPrefix(entry.Name, c.wantName)
		}
		if !nameLinesUp {
			t.Errorf("registry name %q for %d does not line up with %q", entry.Name, c.value, c.wantName)
		}
		got, known := classify.GroupClass(c.value)
		if !known {
			t.Errorf("classify.GroupClass(%d) unknown — classify snapshot drifted from the registry", c.value)
			continue
		}
		if got != c.wantClass {
			t.Errorf("classify.GroupClass(%d) = %q, want %q (registry name %q says %q semantics)", c.value, got, c.wantClass, entry.Name, c.wantClass)
		}
	}
}
