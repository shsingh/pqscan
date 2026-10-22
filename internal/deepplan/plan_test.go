package deepplan

// plan_test.go — the PQ-20 plan-generator behaviour pair (ADR-0002).
// Table-driven battery over the mode matrix, the fact-prune outcomes,
// the prune priority order, the full-matrix composition (cross-checked
// against the stdlib suite list and the committed IANA registry
// snapshot), and the estimated==len invariant.

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/shsingh/pqscan/internal/registry"
)

// payloadKey is the probe-identity key: kind + concrete payload. The
// offer-one matrix is a SET — no two probes share it.
func payloadKey(p Probe) string {
	switch v := p.Payload.(type) {
	case uint16:
		return fmt.Sprintf("%s:v%04x", p.Kind, v)
	case uint32:
		return fmt.Sprintf("%s:g%d", p.Kind, v)
	case SuiteOffer:
		return fmt.Sprintf("%s:%s@%04x", p.Kind, v.Name, v.Version)
	case string:
		return fmt.Sprintf("%s:%s", p.Kind, v)
	case nil:
		return fmt.Sprintf("%s:nil", p.Kind)
	default:
		return fmt.Sprintf("%s:<other>", p.Kind)
	}
}

// kindCounts folds a probe list into kind → count.
func kindCounts(probes []Probe) map[string]int {
	out := map[string]int{}
	for _, p := range probes {
		out[p.Kind]++
	}
	return out
}

// suitePayloads returns the SuiteOffer payloads of all suite probes.
func suitePayloads(probes []Probe) map[SuiteOffer]bool {
	out := map[SuiteOffer]bool{}
	for _, p := range probes {
		if p.Kind == KindSuite {
			out[p.Payload.(SuiteOffer)] = true
		}
	}
	return out
}

// probeWithPayload reports whether the plan carries a kind probe with an
// equal payload.
func probeWithPayload(probes []Probe, kind string, payload any) bool {
	for _, p := range probes {
		if p.Kind == kind && p.Payload == payload {
			return true
		}
	}
	return false
}

func TestBuildValidatesMode(t *testing.T) {
	for _, mode := range []string{"", "fast", "FAST", "Standard", "full-matrix", "deep", "pq"} {
		plan, err := Build("example.com:443", mode, nil)
		if err == nil {
			t.Fatalf("mode %q: want unknown-mode error, got nil", mode)
		}
		if !strings.Contains(err.Error(), "unknown mode") {
			t.Fatalf("mode %q: error %v does not name the unknown mode", mode, err)
		}
		if plan != nil {
			t.Fatalf("mode %q: want nil plan with error", mode)
		}
	}
}

func TestBuildRejectsEmptyTarget(t *testing.T) {
	for _, mode := range []string{ModeStandard, ModeFull} {
		plan, err := Build("", mode, nil)
		if err == nil {
			t.Fatalf("mode %q: want empty-target error, got nil", mode)
		}
		if !strings.Contains(err.Error(), "empty target") {
			t.Fatalf("mode %q: error %v does not name the empty target", mode, err)
		}
		if plan != nil {
			t.Fatalf("mode %q: want nil plan with error", mode)
		}
	}
}

func TestBuildFullMatrixComposition(t *testing.T) {
	const target = "example.com:443"
	plan, err := Build(target, ModeFull, nil)
	if err != nil {
		t.Fatalf("Build(full): %v", err)
	}
	if plan.Target != target {
		t.Fatalf("Target = %q, want %q", plan.Target, target)
	}
	if plan.Mode != ModeFull {
		t.Fatalf("Mode = %q, want %q", plan.Mode, ModeFull)
	}
	if plan.EstimatedHandshakes != len(plan.Probes) {
		t.Fatalf("EstimatedHandshakes = %d, want len(Probes) = %d (estimated==len invariant)",
			plan.EstimatedHandshakes, len(plan.Probes))
	}
	if len(plan.Probes) > FullMatrixBound {
		t.Fatalf("full matrix = %d probes, exceeds the %d bound", len(plan.Probes), FullMatrixBound)
	}
	if len(plan.Probes) < 70 {
		t.Fatalf("full matrix = %d probes — implausibly thin for the complete matrix", len(plan.Probes))
	}

	// Version probes: exactly the four core versions (spec: TLS 1.0-1.3 core).
	for _, v := range []uint16{0x0301, 0x0302, 0x0303, 0x0304} {
		if !probeWithPayload(plan.Probes, KindVersion, v) {
			t.Fatalf("full matrix missing version probe %04x", v)
		}
	}

	// Group probes: exactly the registry blocks (4585-4590 + 25-29).
	wantGroups := map[uint32]bool{}
	for g := uint32(4585); g <= 4590; g++ {
		wantGroups[g] = true
	}
	for g := uint32(25); g <= 29; g++ {
		wantGroups[g] = true
	}
	gotGroups := map[uint32]bool{}
	for _, p := range plan.Probes {
		if p.Kind == KindGroup {
			gotGroups[p.Payload.(uint32)] = true
		}
	}
	if !reflect.DeepEqual(gotGroups, wantGroups) {
		t.Fatalf("group ladder = %v, want the registry sets %v", gotGroups, wantGroups)
	}

	// Sigalg probes: the four classic schemes the handshake plane owns
	// plus the three ML-DSA schemes (spec §5.6: mldsa44/65/87 = 0x0904-0x0906).
	wantSigs := map[uint16]bool{0x0403: true, 0x0804: true, 0x0805: true, 0x0806: true,
		0x0904: true, 0x0905: true, 0x0906: true}
	gotSigs := map[uint16]bool{}
	for _, p := range plan.Probes {
		if p.Kind == KindSigalg {
			gotSigs[p.Payload.(uint16)] = true
		}
	}
	if !reflect.DeepEqual(gotSigs, wantSigs) {
		t.Fatalf("sigalg ladder = %v, want %v", gotSigs, wantSigs)
	}

	// Cert probe: exactly one (the cert chain fetch for the analytics lane).
	if n := kindCounts(plan.Probes)[KindCert]; n != 1 {
		t.Fatalf("cert probes = %d, want 1", n)
	}

	// Feature probes: resumption vectors + exactly one HRR probe.
	wantRes := map[string]bool{ResTicket12: true, ResPSK13: true, Res0RTT13: true}
	gotRes := map[string]bool{}
	for _, p := range plan.Probes {
		if p.Kind == KindResumption {
			gotRes[p.Payload.(string)] = true
		}
	}
	if !reflect.DeepEqual(gotRes, wantRes) {
		t.Fatalf("resumption vectors = %v, want %v", gotRes, wantRes)
	}
	if n := kindCounts(plan.Probes)[KindHRR]; n != 1 {
		t.Fatalf("hrr probes = %d, want 1", n)
	}

	// Uniqueness: the offer-one matrix is a set — each probe is its own
	// handshake, so no two probes share (kind, payload).
	seen := map[string]string{}
	for _, p := range plan.Probes {
		if p.Name == "" {
			t.Fatalf("probe with empty name (kind %s)", p.Kind)
		}
		key := payloadKey(p)
		if prev, dup := seen[key]; dup {
			t.Fatalf("duplicate probe %s (name %q already used by %q)", key, p.Name, prev)
		}
		seen[key] = p.Name
	}
	if len(seen) != len(plan.Probes) {
		t.Fatalf("probe identity keys = %d, plan size = %d — duplicates present", len(seen), len(plan.Probes))
	}
}

// TestBuildFullCoversStdlibSuitePairs cross-checks the suite matrix
// against the living stdlib list the handshake plane constructs from:
// exactly the (suite, supported version) pairs within TLS 1.0-1.3, from
// both the secure and the insecure stdlib suites (a cipher scanner MUST
// probe the insecure ones — RC4/3DES/CBC acceptance is exactly the fact
// it exists to record).
func TestBuildFullCoversStdlibSuitePairs(t *testing.T) {
	plan, err := Build("example.com:443", ModeFull, nil)
	if err != nil {
		t.Fatalf("Build(full): %v", err)
	}
	want := map[SuiteOffer]bool{}
	for _, cs := range tls.CipherSuites() {
		for _, v := range cs.SupportedVersions {
			if v >= tls.VersionTLS10 && v <= tls.VersionTLS13 {
				want[SuiteOffer{Name: cs.Name, Version: v}] = true
			}
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		for _, v := range cs.SupportedVersions {
			if v >= tls.VersionTLS10 && v <= tls.VersionTLS13 {
				want[SuiteOffer{Name: cs.Name, Version: v}] = true
			}
		}
	}
	got := suitePayloads(plan.Probes)
	if !reflect.DeepEqual(got, want) {
		missing, extra := 0, 0
		for w := range want {
			if !got[w] {
				if missing == 0 {
					t.Logf("first missing: %s@0x%04x", w.Name, w.Version)
				}
				missing++
			}
		}
		for g := range got {
			if !want[g] {
				if extra == 0 {
					t.Logf("first extra: %s@0x%04x", g.Name, g.Version)
				}
				extra++
			}
		}
		t.Fatalf("suite matrix off the stdlib product: %d missing, %d extra (want %d pairs)", missing, extra, len(want))
	}
	if n := kindCounts(plan.Probes)[KindSuite]; n != len(want) {
		t.Fatalf("suite probes = %d, want the full stdlib product %d", n, len(want))
	}
}

// TestBuildFullGroupsAreRegistryReal loads the committed IANA snapshot
// and asserts every group probe names a registry row: the plan never
// invents a codepoint (AGENTS.md registry rule).
func TestBuildFullGroupsAreRegistryReal(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "tests", "fixtures", "iana", "tls-parameters-8.csv"))
	if err != nil {
		t.Fatalf("registry snapshot: %v", err)
	}
	defer f.Close() //nolint:errcheck
	entries, err := registry.Load(f)
	if err != nil {
		t.Fatalf("registry load: %v", err)
	}
	plan, err := Build("example.com:443", ModeFull, nil)
	if err != nil {
		t.Fatalf("Build(full): %v", err)
	}
	for _, p := range plan.Probes {
		if p.Kind != KindGroup {
			continue
		}
		g := p.Payload.(uint32)
		entry, ok := registry.Lookup(entries, g)
		if !ok {
			t.Fatalf("plan probes unregistered group %d", g)
		}
		if entry.Name == "" {
			t.Fatalf("probe group %d: registry row carries no name", g)
		}
	}
}

// TestBuildStandardPruneTable is the core table: for each observed-fact
// fixture the standard plan lands at an exact, deterministic composition.
// The counts below depend only on the structural ladder (4 versions, 11
// groups, 7 sigalgs, 1 cert, 3 resumption vectors, 1 hrr) — the suite
// matrix is cut whole by the prune priority in every case, so the table
// is stable across toolchains that reshape the stdlib suite list.
func TestBuildStandardPruneTable(t *testing.T) {
	cases := []struct {
		name     string
		observed *Observed
		wantKind map[string]int // kind → exact probe count
		wantLen  int
	}{
		{
			name:     "no facts: version floor kept, classic sigalgs cut",
			observed: nil,
			wantKind: map[string]int{"version": 4, "suite": 0, "group": 11, "sigalg": 3, "cert": 1, "resumption": 3, "hrr": 1},
			wantLen:  23,
		},
		{
			name:     "zero Observed behaves as no facts",
			observed: &Observed{},
			wantKind: map[string]int{"version": 4, "suite": 0, "group": 11, "sigalg": 3, "cert": 1, "resumption": 3, "hrr": 1},
			wantLen:  23,
		},
		{
			name:     "TLS 1.2 facts: negotiated suite+group+version pruned",
			observed: &Observed{Version: 0x0303, NegotiatedSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", NegotiatedGroup: 29},
			wantKind: map[string]int{"version": 0, "suite": 0, "group": 10, "sigalg": 7, "cert": 1, "resumption": 3, "hrr": 1},
			wantLen:  22,
		},
		{
			name:     "TLS 1.3 PQ facts + cert: cert probe pruned",
			observed: &Observed{Version: 0x0304, NegotiatedSuite: "TLS_AES_128_GCM_SHA256", NegotiatedGroup: 4588, HasCert: true},
			wantKind: map[string]int{"version": 3, "suite": 0, "group": 10, "sigalg": 7, "cert": 0, "resumption": 3, "hrr": 1},
			wantLen:  24,
		},
		{
			name:     "classic RSA facts + cert: group ladder intact",
			observed: &Observed{Version: 0x0303, NegotiatedSuite: "TLS_RSA_WITH_AES_128_CBC_SHA", HasCert: true},
			wantKind: map[string]int{"version": 0, "suite": 0, "group": 11, "sigalg": 7, "cert": 0, "resumption": 3, "hrr": 1},
			wantLen:  22,
		},
		{
			name:     "group fact only: classic sigalgs cut, mldsa kept",
			observed: &Observed{NegotiatedGroup: 4588},
			wantKind: map[string]int{"version": 4, "suite": 0, "group": 10, "sigalg": 3, "cert": 1, "resumption": 3, "hrr": 1},
			wantLen:  22,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := Build("example.com:443", ModeStandard, tc.observed)
			if err != nil {
				t.Fatalf("Build(standard): %v", err)
			}
			if plan.Mode != ModeStandard {
				t.Fatalf("Mode = %q, want %q", plan.Mode, ModeStandard)
			}
			if len(plan.Probes) != tc.wantLen {
				t.Fatalf("standard plan = %d probes, want %d (kinds %v)", len(plan.Probes), tc.wantLen, kindCounts(plan.Probes))
			}
			if plan.EstimatedHandshakes != len(plan.Probes) {
				t.Fatalf("EstimatedHandshakes = %d, want len(Probes) = %d", plan.EstimatedHandshakes, len(plan.Probes))
			}
			if len(plan.Probes) > StandardBudget {
				t.Fatalf("standard plan = %d probes, exceeds the %d default budget", len(plan.Probes), StandardBudget)
			}
			gotKind := kindCounts(plan.Probes)
			for kind, want := range tc.wantKind {
				if gotKind[kind] != want {
					t.Fatalf("kind %s = %d probes, want %d (kinds %v)", kind, gotKind[kind], want, gotKind)
				}
			}
			if observed := tc.observed; observed != nil {
				// Fact-pruned probes are gone from Probes entirely (no
				// kind=pruned markers — the prune is physical).
				if observed.NegotiatedSuite != "" && observed.Version != 0 {
					if probeWithPayload(plan.Probes, KindSuite, SuiteOffer{Name: observed.NegotiatedSuite, Version: observed.Version}) {
						t.Fatalf("negotiated suite %s@%04x still probed", observed.NegotiatedSuite, observed.Version)
					}
				}
				if observed.NegotiatedGroup != 0 {
					if probeWithPayload(plan.Probes, KindGroup, observed.NegotiatedGroup) {
						t.Fatalf("negotiated group %d still probed", observed.NegotiatedGroup)
					}
				}
				if observed.Version != 0 {
					if probeWithPayload(plan.Probes, KindVersion, observed.Version) {
						t.Fatalf("observed version %04x still probed", observed.Version)
					}
				}
				if observed.HasCert {
					for _, p := range plan.Probes {
						if p.Kind == KindCert {
							t.Fatalf("cert fetched by the fast handshake: cert probe still planned")
						}
					}
				}
			}
			// The PQ ladder runs even on classic servers (spec §7.4): the
			// ML-DSA sigalgs and the hrr/cert-class probes are never pruned.
			if !probeWithPayload(plan.Probes, KindSigalg, uint16(0x0904)) {
				t.Fatalf("mldsa44 probe pruned from the standard plan")
			}
			if !probeWithPayload(plan.Probes, KindHRR, nil) {
				t.Fatalf("hrr probe pruned from the standard plan")
			}
		})
	}
}

// TestBuildStandardDeterministic: two builds from the same inputs are
// equal, probe for probe (the executor consumes stable plans).
func TestBuildStandardDeterministic(t *testing.T) {
	obs := &Observed{Version: 0x0303, NegotiatedSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", NegotiatedGroup: 4588}
	a, err := Build("example.com:443", ModeStandard, obs)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	b, err := Build("example.com:443", ModeStandard, obs)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("plans differ between identical builds:\nfirst: %+v\nsecond: %+v", a, b)
	}
}

// TestBuildStandardNoSuiteProbes: the suite matrix is the offer-one
// bulk; under the default budget the prune priority cuts it whole in
// every documented case, so standard plans carry the structural ladder
// and the suite matrix is a full-mode surface.
func TestBuildStandardNoSuiteProbes(t *testing.T) {
	plan, err := Build("example.com:443", ModeStandard, nil)
	if err != nil {
		t.Fatalf("Build(standard): %v", err)
	}
	if n := kindCounts(plan.Probes)[KindSuite]; n != 0 {
		t.Fatalf("standard plan carries %d suite probes, want 0 under the default budget", n)
	}
}

// TestPrunePriorityOrder pins the documented cut order
// (negotiated-suite-adjacent first) on a synthetic candidate list where
// each class is separately observable. Budgets hit class boundaries:
// each successful step cuts exactly the next class and stops.
func TestPrunePriorityOrder(t *testing.T) {
	adj := func(n string) Probe {
		return Probe{Name: "s/" + n, Kind: KindSuite, Payload: SuiteOffer{Name: n, Version: 0x0303}}
	}
	other122 := func(n string) Probe {
		return Probe{Name: "s/" + n, Kind: KindSuite, Payload: SuiteOffer{Name: n, Version: 0x0303}}
	}
	other10 := func(n string) Probe {
		return Probe{Name: "s/" + n, Kind: KindSuite, Payload: SuiteOffer{Name: n, Version: 0x0301}}
	}

	candidate := []Probe{
		// tier 1: the negotiated suite's adjacency (same version, same family)
		adj("TLS_ECDHE_RSA_WITH_ONE"), adj("TLS_ECDHE_RSA_WITH_TWO"), adj("TLS_ECDHE_RSA_WITH_THREE"),
		adj("TLS_ECDHE_RSA_WITH_FOUR"), adj("TLS_ECDHE_RSA_WITH_FIVE"),
		// tier 2: the negotiated version's remaining suites (other family)
		other122("TLS_ECDHE_ECDSA_WITH_ONE"), other122("TLS_ECDHE_ECDSA_WITH_TWO"),
		other122("TLS_ECDHE_ECDSA_WITH_THREE"), other122("TLS_ECDHE_ECDSA_WITH_FOUR"),
		// tier 3: other versions' suites
		other10("TLS_RSA_WITH_ONE"), other10("TLS_RSA_WITH_TWO"), other10("TLS_RSA_WITH_THREE"),
		other10("TLS_RSA_WITH_FOUR"), other10("TLS_RSA_WITH_FIVE"), other10("TLS_RSA_WITH_SIX"),
		// tier 4: version probes for versions other than the observed one
		{Name: "version/1.0", Kind: KindVersion, Payload: uint16(0x0301)},
		{Name: "version/1.1", Kind: KindVersion, Payload: uint16(0x0302)},
		// tier 5: classic sigalgs (the mldsa one stays)
		{Name: "sigalg/ecdsa", Kind: KindSigalg, Payload: uint16(0x0403)},
		{Name: "sigalg/rsa-pss", Kind: KindSigalg, Payload: uint16(0x0804)},
		{Name: "sigalg/mldsa44", Kind: KindSigalg, Payload: uint16(0x0904)},
		// tier 6: the basic resumption vectors (0-RTT stays)
		{Name: "resumption/ticket", Kind: KindResumption, Payload: ResTicket12},
		{Name: "resumption/psk", Kind: KindResumption, Payload: ResPSK13},
		{Name: "resumption/0rtt", Kind: KindResumption, Payload: Res0RTT13},
		// never pruned
		{Name: "cert/chain", Kind: KindCert},
		{Name: "group/g1", Kind: KindGroup, Payload: uint32(4588)},
		{Name: "group/g2", Kind: KindGroup, Payload: uint32(4589)},
		{Name: "hrr/shareless", Kind: KindHRR},
	}
	const candidateLen = 27
	if len(candidate) != candidateLen {
		t.Fatalf("synthetic candidate = %d, want %d — fix the ladder table", len(candidate), candidateLen)
	}
	// No fact hits this list: the observed suite/group are non-members.
	obs := Observed{Version: 0x0303, NegotiatedSuite: "TLS_ECDHE_RSA_WITH_N", NegotiatedGroup: 9999}

	cases := []struct {
		name     string
		budget   int
		wantErr  bool
		wantKind map[string]int
		wantKept []string // payload keys that must survive
		wantGone []string // payload keys that must be pruned
	}{
		{
			name:     "budget holds: no cut",
			budget:   candidateLen,
			wantKind: map[string]int{"suite": 15, "version": 2, "sigalg": 3, "resumption": 3, "cert": 1, "group": 2, "hrr": 1},
			wantGone: []string{},
		},
		{
			name:     "budget 22: tier 1 only — the adjacency is pruned first",
			budget:   22,
			wantKind: map[string]int{"suite": 10, "version": 2, "sigalg": 3, "resumption": 3, "cert": 1, "group": 2, "hrr": 1},
			wantGone: []string{"suite:TLS_ECDHE_RSA_WITH_ONE@0303", "suite:TLS_ECDHE_RSA_WITH_FIVE@0303"},
			wantKept: []string{"suite:TLS_ECDHE_ECDSA_WITH_ONE@0303", "suite:TLS_RSA_WITH_ONE@0301"},
		},
		{
			name:     "budget 18: tier 2 — remaining same-version suites",
			budget:   18,
			wantKind: map[string]int{"suite": 6, "version": 2, "sigalg": 3, "resumption": 3, "cert": 1, "group": 2, "hrr": 1},
			wantKept: []string{"suite:TLS_RSA_WITH_ONE@0301"},
		},
		{
			name:     "budget 12: tier 3 — other-version suites, versions kept",
			budget:   12,
			wantKind: map[string]int{"suite": 0, "version": 2, "sigalg": 3, "resumption": 3, "cert": 1, "group": 2, "hrr": 1},
			wantKept: []string{"version:v0301", "version:v0302"},
		},
		{
			name:     "budget 10: tier 4 — foreign version probes",
			budget:   10,
			wantKind: map[string]int{"suite": 0, "version": 0, "sigalg": 3, "resumption": 3, "cert": 1, "group": 2, "hrr": 1},
			wantGone: []string{"version:v0301", "version:v0302"},
			wantKept: []string{"sigalg:v0403"},
		},
		{
			name:     "budget 8: tier 5 — classic sigalgs (mldsa stays)",
			budget:   8,
			wantKind: map[string]int{"suite": 0, "version": 0, "sigalg": 1, "resumption": 3, "cert": 1, "group": 2, "hrr": 1},
			wantGone: []string{"sigalg:v0403", "sigalg:v0804"},
			wantKept: []string{"sigalg:v0904"},
		},
		{
			name:     "budget 6: tier 6 — ticket and psk cut, 0-RTT stays",
			budget:   6,
			wantKind: map[string]int{"suite": 0, "version": 0, "sigalg": 1, "resumption": 1, "cert": 1, "group": 2, "hrr": 1},
			wantGone: []string{"resumption:ticket-tls12", "resumption:psk-tls13"},
			wantKept: []string{"resumption:0rtt-tls13", "hrr:nil", "cert:nil", "group:g4588"},
		},
		{
			name:    "budget 4: unprunable PQ core — the guard errors, no silent loss",
			budget:  4,
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pruned, err := pruneStandard(candidate, obs, tc.budget)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("budget %d: want guard error, got %d probes", tc.budget, len(pruned))
				}
				if !strings.Contains(err.Error(), "exceeds budget") {
					t.Fatalf("budget %d: guard error %v does not name the budget", tc.budget, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("budget %d: %v", tc.budget, err)
			}
			if len(pruned) != tc.budget {
				t.Fatalf("budget %d: %d probes remain", tc.budget, len(pruned))
			}
			gotKind := kindCounts(pruned)
			for kind, want := range tc.wantKind {
				if gotKind[kind] != want {
					t.Fatalf("budget %d: kind %s = %d, want %d (kinds %v)", tc.budget, kind, gotKind[kind], want, gotKind)
				}
			}
			for _, key := range tc.wantGone {
				for _, p := range pruned {
					if payloadKey(p) == key {
						t.Fatalf("budget %d: probe %s survived, want it pruned", tc.budget, key)
					}
				}
			}
			for _, key := range tc.wantKept {
				found := false
				for _, p := range pruned {
					if payloadKey(p) == key {
						found = true
					}
				}
				if !found {
					t.Fatalf("budget %d: probe %s pruned, want it kept", tc.budget, key)
				}
			}
		})
	}
}

// TestBuildFullUnaffectedByFacts: full mode IS the complete matrix, always
// — observed facts never prune it.
func TestBuildFullUnaffectedByFacts(t *testing.T) {
	facts := &Observed{Version: 0x0304, NegotiatedSuite: "TLS_AES_128_GCM_SHA256", NegotiatedGroup: 4588, HasCert: true}
	withFacts, err := Build("example.com:443", ModeFull, facts)
	if err != nil {
		t.Fatalf("Build(full with facts): %v", err)
	}
	plain, err := Build("example.com:443", ModeFull, nil)
	if err != nil {
		t.Fatalf("Build(full plain): %v", err)
	}
	if !reflect.DeepEqual(plain, withFacts) {
		t.Fatalf("full mode must ignore observed facts: plans differ (%d vs %d probes)",
			len(plain.Probes), len(withFacts.Probes))
	}
	for _, p := range withFacts.Probes {
		if p.Kind == KindCert {
			return // cert probe present — complete matrix confirmed
		}
	}
	t.Fatalf("full mode lost the cert probe")
}

// TestBuildEstimatedInvariant: EstimatedHandshakes == len(Probes) holds in
// every built plan (the executor's cost contract).
func TestBuildEstimatedInvariant(t *testing.T) {
	facts := &Observed{Version: 0x0303, NegotiatedSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", NegotiatedGroup: 4588, HasCert: true}
	for _, mode := range []string{ModeStandard, ModeFull} {
		for _, obs := range []*Observed{nil, facts} {
			plan, err := Build("example.com:443", mode, obs)
			if err != nil {
				t.Fatalf("Build(%s): %v", mode, err)
			}
			if plan.EstimatedHandshakes != len(plan.Probes) {
				t.Fatalf("mode %s: EstimatedHandshakes = %d, want len(Probes) = %d",
					mode, plan.EstimatedHandshakes, len(plan.Probes))
			}
		}
	}
}

// TestPlanProbeNamesAreUniqueAndStable: names are the grep/audit surface
// (diag lines, executor logs) — unique inside each plan and stable across
// builds.
func TestPlanProbeNamesAreUniqueAndStable(t *testing.T) {
	for _, mode := range []string{ModeStandard, ModeFull} {
		plan, err := Build("example.com:443", mode, nil)
		if err != nil {
			t.Fatalf("Build(%s): %v", mode, err)
		}
		names := map[string]bool{}
		var got []string
		for _, p := range plan.Probes {
			if names[p.Name] {
				t.Fatalf("mode %s: duplicate probe name %q", mode, p.Name)
			}
			names[p.Name] = true
			got = append(got, p.Name)
		}
		plan2, err := Build("example.com:443", mode, nil)
		if err != nil {
			t.Fatalf("Build(%s) again: %v", mode, err)
		}
		var got2 []string
		for _, p := range plan2.Probes {
			got2 = append(got2, p.Name)
		}
		if !reflect.DeepEqual(got, got2) {
			t.Fatalf("mode %s: probe names not stable across builds", mode)
		}
	}
}

// TestBuildQuicRungGate (PQ-25, issue #48; PQ-69, issue #181 — the
// deep-QUIC enumeration counts): the QUIC-plane rungs ride the lane's
// own gate. A plan whose observed fact says the profile's QUIC lane ran
// carries the rungs in BOTH modes (full = the complete matrix, standard
// = the fact-pruned structural landing); the gate's false side (-quic-off,
// an unhinted target) leaves every plan QUIC-free. PQ-69's two non-group
// rungs (quic/v2, quic/h3-exchange) ride AFTER the block rungs in both
// gate-on shapes; the full mode ignores the facts' pruning (the
// QuicNegotiated rung stays planned there); the standard mode drops
// exactly that answered rung.
func TestBuildQuicRungGate(t *testing.T) {
	const target = "example.com:443"

	// countQuicRungs returns the plan's quic-kind probes.
	countQuicRungs := func(probes []Probe) int { return kindCounts(probes)[KindQuic] }

	// 1) The gate is the only presence switch: both modes stay QUIC-free
	//    when the lane's profile probe never ran.
	plainFull, err := Build(target, ModeFull, nil)
	if err != nil {
		t.Fatalf("Build(full): %v", err)
	}
	if n := countQuicRungs(plainFull.Probes); n != 0 {
		t.Fatalf("full plan on a lane-gate-zero target carries %d quic rungs, want 0", n)
	}
	plainStd, err := Build(target, ModeStandard, nil)
	if err != nil {
		t.Fatalf("Build(standard): %v", err)
	}
	if n := countQuicRungs(plainStd.Probes); n != 0 {
		t.Fatalf("standard plan on a lane-gate-zero target carries %d quic rungs, want 0", n)
	}

	// 2) The full matrix with the lane's gate on: the negotiated-anchor
	//    rung (named quic/negotiated-<g>) precedes the 4585–4590 block
	//    in IANA order, and PQ-69's two rungs close the ladder (the v2
	//    transport-version rung, then the functional h3-exchange rung);
	//    the QuicNegotiated fact never prunes the full matrix (observed
	//    facts never reach it).
	fullFacts := Observed{
		Version: 0x0304, NegotiatedSuite: "TLS_AES_128_GCM_SHA256", NegotiatedGroup: 4588,
		HasCert: true, QuicAttempted: true, QuicNegotiated: 4588,
	}
	fullGated, err := Build(target, ModeFull, &fullFacts)
	if err != nil {
		t.Fatalf("Build(full gated): %v", err)
	}
	fullPlainGate := Observed{QuicAttempted: true, QuicNegotiated: 0}
	fullGateOnly, err := Build(target, ModeFull, &fullPlainGate)
	if err != nil {
		t.Fatalf("Build(full gate-only): %v", err)
	}
	// (the gate-only fixture has no NegotiatedGroup anchor: the 4588 rung
	// keeps the plain name and IANA order.)
	type wantRung struct {
		name    string
		payload any
	}
	wantFull := []wantRung{
		{"quic/negotiated-4588", uint32(4588)},
		{"quic/4585", uint32(4585)}, {"quic/4586", uint32(4586)}, {"quic/4587", uint32(4587)},
		{"quic/4589", uint32(4589)}, {"quic/4590", uint32(4590)},
		{"quic/v2", QuicRungV2},
		{"quic/h3-exchange", QuicRungH3Exchange},
	}
	wantGateOnly := []wantRung{
		{"quic/4585", uint32(4585)}, {"quic/4586", uint32(4586)}, {"quic/4587", uint32(4587)},
		{"quic/4588", uint32(4588)}, {"quic/4589", uint32(4589)}, {"quic/4590", uint32(4590)},
		{"quic/v2", QuicRungV2},
		{"quic/h3-exchange", QuicRungH3Exchange},
	}
	checkRungs := func(t *testing.T, plan *Plan, want []wantRung, label string) {
		t.Helper()
		var got []Probe
		for _, p := range plan.Probes {
			if p.Kind == KindQuic {
				got = append(got, p)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%s: quic rungs = %d (%s), want %d", label, len(got), rungNames(got), len(want))
		}
		for i, w := range want {
			if got[i].Name != w.name {
				t.Fatalf("%s: rung %d name = %q, want %q (names %s)", label, i, got[i].Name, w.name, rungNames(got))
			}
			if got[i].Payload != w.payload {
				t.Fatalf("%s: rung %d payload = %v, want %v", label, i, got[i].Payload, w.payload)
			}
		}
	}
	checkRungs(t, fullGated, wantFull, "full gated (negotiated anchor named)")
	checkRungs(t, fullGateOnly, wantGateOnly, "full gate-only (plain IANA order)")

	// 3) The standard plan with the gate on: the structural landing is
	//    STABLE (the suite matrix cuts whole) and the QUIC rungs are
	//    never pruned — only the QuicNegotiated fact drops its own rung.
	//    Fixture = the happy cloudflare shape (negotiated 4588 on both
	//    planes; the suite@1.3, group/4588, version/1.3 and cert probes
	//    all fact-pruned): the plan lands at 24 probes = group 10 +
	//    quic 7 (the 5 unanswered block rungs + the PQ-69 pair) +
	//    sigalg 3 (the mldsa row) + resumption 3 + hrr 1 — exactly the
	//    default budget.
	stdFacts := fullFacts
	stdPlan, err := Build(target, ModeStandard, &stdFacts)
	if err != nil {
		t.Fatalf("Build(standard gated): %v", err)
	}
	if len(stdPlan.Probes) != 24 {
		t.Fatalf("standard gated plan = %d probes (%v), want 24 (kinds %v)",
			len(stdPlan.Probes), rungNames(stdPlan.Probes), kindCounts(stdPlan.Probes))
	}
	if got := kindCounts(stdPlan.Probes); got[KindQuic] != 7 || got[KindGroup] != 10 ||
		got[KindSigalg] != 3 || got[KindResumption] != 3 || got[KindHRR] != 1 || got[KindVersion] != 0 {
		t.Fatalf("standard gated plan kinds = %v, want quic 7 / group 10 / sigalg 3 / resumption 3 / hrr 1 / version 0", got)
	}
	for _, name := range []string{"quic/negotiated-4588", "quic/4588"} {
		for _, p := range stdPlan.Probes {
			if p.Name == name {
				t.Fatalf("standard gated plan still carries %s — the QUIC plane answered 4588 (QuicNegotiated fact); spec §7.4 phase 1", name)
			}
		}
	}
	for name, g := range map[string]uint32{
		"quic/4585": 4585, "quic/4586": 4586, "quic/4587": 4587, "quic/4589": 4589, "quic/4590": 4590,
	} {
		if !probeWithPayload(stdPlan.Probes, KindQuic, g) {
			t.Fatalf("standard gated plan lost %s — the deep-QUIC rungs are never pruned", name)
		}
	}

	// 4) The negotiated anchor rides OUTSIDE the block: a TCP plane that
	//    negotiated x25519 (29) plans quic/negotiated-29 first and the
	//    whole 4585–4590 set plus PQ-69's pair after — 9 rungs, and the
	//    standard plan still lands INSIDE the 24 budget (the extra two
	//    rungs cut through the documented prune classes: the foreign
	//    versions, the classic sigalgs, the basic resumption vectors).
	x25519Facts := Observed{
		Version: 0x0304, NegotiatedSuite: "TLS_AES_128_GCM_SHA256", NegotiatedGroup: 29,
		HasCert: true, QuicAttempted: true, QuicNegotiated: 0,
	}
	stdX, err := Build(target, ModeStandard, &x25519Facts)
	if err != nil {
		t.Fatalf("Build(standard x25519 anchor): %v", err)
	}
	if len(stdX.Probes) != 24 {
		t.Fatalf("standard x25519-anchor plan = %d probes, want the exact 24 budget (kinds %v)", len(stdX.Probes), kindCounts(stdX.Probes))
	}
	if got := kindCounts(stdX.Probes); got[KindQuic] != 9 {
		t.Fatalf("standard x25519-anchor quic rungs = %d, want 9 (negotiated-29 + the block + the PQ-69 pair) (kinds %v)", got[KindQuic], got)
	}
	var xRungs []Probe
	for _, p := range stdX.Probes {
		if p.Kind == KindQuic {
			xRungs = append(xRungs, p)
		}
	}
	if xRungs[0].Name != "quic/negotiated-29" {
		t.Fatalf("first quic rung = %q, want quic/negotiated-29 (the anchor rides first)", xRungs[0].Name)
	}
	if xRungs[len(xRungs)-2].Name != "quic/v2" || xRungs[len(xRungs)-1].Name != "quic/h3-exchange" {
		t.Fatalf("the PQ-69 rungs must close the QUIC ladder, got %s", rungNames(xRungs))
	}

	// 5) Uniqueness over the gated full plan (the offer-one set: no two
	//    quic rungs share a payload).
	seen := map[string]string{}
	for _, p := range fullGated.Probes {
		key := payloadKey(p)
		if prev, dup := seen[key]; dup {
			t.Fatalf("duplicate probe %s (%q already used by %q)", key, p.Name, prev)
		}
		seen[key] = p.Name
	}
}

// TestBuildQuicStringRungsNeverPrune (PQ-69, issue #181): the two
// non-group rungs' payloads are strings; factPrune's QuicNegotiated
// prune matches uint32 group payloads only, so the rungs survive every
// fact shape in both modes — the QUIC offer set stays one countable
// class (one KindQuic) and the census never loses the version rung.
func TestBuildQuicStringRungsNeverPrune(t *testing.T) {
	const target = "example.com:443"
	facts := []Observed{
		{Version: 0x0304, NegotiatedSuite: "TLS_AES_128_GCM_SHA256", NegotiatedGroup: 4588,
			HasCert: true, QuicAttempted: true, QuicNegotiated: 4588},
		{Version: 0x0303, NegotiatedSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", NegotiatedGroup: 29,
			HasCert: true, QuicAttempted: true, QuicNegotiated: 30},
		{Version: 0x0304, NegotiatedSuite: "TLS_AES_128_GCM_SHA256", NegotiatedGroup: 0,
			HasCert: true, QuicAttempted: true, QuicNegotiated: 4590},
	}
	for i, obs := range facts {
		for _, mode := range []string{ModeStandard, ModeFull} {
			plan, err := Build(target, mode, &obs)
			if err != nil {
				t.Fatalf("facts %d, %s: %v", i, mode, err)
			}
			if !probeWithPayload(plan.Probes, KindQuic, QuicRungV2) {
				t.Fatalf("facts %d, %s: the quic/v2 rung pruned (the string payload may never match the uint32 prune)", i, mode)
			}
			if !probeWithPayload(plan.Probes, KindQuic, QuicRungH3Exchange) {
				t.Fatalf("facts %d, %s: the quic/h3-exchange rung pruned (the string payload may never match the uint32 prune)", i, mode)
			}
			if n := kindCounts(plan.Probes)[KindQuic]; n < 2 {
				t.Fatalf("facts %d, %s: quic rungs = %d, the PQ-69 pair alone needs 2", i, mode, n)
			}
			// The payload types: the two rungs are string-typed, never
			// a group codepoint.
			for _, p := range plan.Probes {
				if p.Name == "quic/v2" || p.Name == "quic/h3-exchange" {
					if _, ok := p.Payload.(string); !ok {
						t.Fatalf("rung %s payload %v (%T), want a string token", p.Name, p.Payload, p.Payload)
					}
				}
			}
		}
	}
}

// rungNames renders a quic-rung list for failure messages.
func rungNames(probes []Probe) string {
	names := make([]string, 0, len(probes))
	for _, p := range probes {
		names = append(names, p.Name)
	}
	return strings.Join(names, ",")
}
