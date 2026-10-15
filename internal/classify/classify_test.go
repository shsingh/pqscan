package classify

import "testing"

// TestGroupClassTable pins the taxonomy snapshot: standards-track hybrids,
// the obsolete-Kyber compat oracle, and classics (spec Appendix A; the
// table regenerates from the IANA registry in PQ-08 and must never drift
// into hand-edits after that).
func TestGroupClassTable(t *testing.T) {
	cases := []struct {
		id    uint32
		want  Class
		known bool
	}{
		{4585, ClassPQHybrid, true},
		{4588, ClassPQHybrid, true},
		{4589, ClassPQHybrid, true},
		{4590, ClassHybridSM, true},
		{25497, ClassPQHybridD, true},
		{29, ClassClassic, true},
		{24, ClassClassic, true},
		{99999, "", false}, // unknown codepoint: never a PQ verdict
	}
	for _, c := range cases {
		got, ok := GroupClass(c.id)
		if ok != c.known {
			t.Errorf("GroupClass(%d) known=%v, want %v", c.id, ok, c.known)
		}
		if ok && got != c.want {
			t.Errorf("GroupClass(%d) = %q, want %q", c.id, got, c.want)
		}
	}
}
