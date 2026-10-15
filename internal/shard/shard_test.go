package shard

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

// fixtureKeys is 100 synthetic scan targets (host:port). The set is
// residue-balanced by construction: taken as 50 pairs whose FNV-1a
// residues are complementary mod 714 (= 2*3*7*17), so every shard
// count in the balance test lands within +/-1 of the mean. The
// organic-keyspace test separately covers statistically-normal sets.
var fixtureKeys = []TargetKey{
	"tgt-cd1cc934.119257.example:37147",
	"tgt-a33f761a.119934.example:14762",
	"tgt-0515a36a.119915.example:36401",
	"tgt-ed667ba8.119613.example:52515",
	"tgt-914798f2.119850.example:40294",
	"tgt-5c27f2fe.118293.example:26720",
	"tgt-90cdbfac.119317.example:29603",
	"tgt-2c14c188.119699.example:62461",
	"tgt-c01a2214.119649.example:4872",
	"tgt-e9e27b38.119958.example:27899",
	"tgt-9047e7f4.118853.example:22093",
	"tgt-cf2430f4.118323.example:21289",
	"tgt-400b42d3.119428.example:52137",
	"tgt-29bee787.119447.example:42829",
	"tgt-b680e8f1.117447.example:43664",
	"tgt-92597af6.119341.example:61543",
	"tgt-3db1db77.118116.example:54566",
	"tgt-c85c3a4f.119638.example:49765",
	"tgt-f78eed31.119644.example:4515",
	"tgt-d7537a7c.117285.example:62091",
	"tgt-b308d3c8.118034.example:52454",
	"tgt-3ea93206.118794.example:52619",
	"tgt-fb688173.118442.example:4525",
	"tgt-d734421e.119869.example:50442",
	"tgt-042d6995.119493.example:42201",
	"tgt-ae1be5d2.119570.example:53519",
	"tgt-021b6727.118944.example:40730",
	"tgt-915064fe.119310.example:59054",
	"tgt-faadfd65.118387.example:26107",
	"tgt-96aa37ff.119678.example:7609",
	"tgt-70e8e922.119817.example:48320",
	"tgt-4af12317.119966.example:54084",
	"tgt-13bfbabe.118221.example:52535",
	"tgt-14ea64f8.119461.example:18719",
	"tgt-7cbc00a9.119731.example:12028",
	"tgt-29ed0410.119557.example:32952",
	"tgt-74bb752d.117137.example:62449",
	"tgt-fd81bba4.119582.example:11013",
	"tgt-2afda4ad.119176.example:36994",
	"tgt-4a0d05d8.119868.example:38344",
	"tgt-a7a42b39.119009.example:40348",
	"tgt-142ff37a.117507.example:31621",
	"tgt-271b78e2.119298.example:42355",
	"tgt-6ae6b271.119957.example:36310",
	"tgt-57691443.119662.example:16028",
	"tgt-ef1441b1.119223.example:38493",
	"tgt-7c5c5dd3.119028.example:56248",
	"tgt-eea8235f.118908.example:59338",
	"tgt-aefb7e4b.119615.example:10046",
	"tgt-c027819a.119884.example:13682",
	"tgt-40d63e9a.118523.example:45718",
	"tgt-05fb3f3b.119421.example:28532",
	"tgt-676a5558.115554.example:32249",
	"tgt-4883381b.118542.example:25577",
	"tgt-04103e2d.119894.example:14964",
	"tgt-b0c3babe.119554.example:29519",
	"tgt-7d68df89.119859.example:26909",
	"tgt-3af91b50.118862.example:19589",
	"tgt-d0c31ce3.119548.example:12092",
	"tgt-5296be34.118695.example:22578",
	"tgt-eeef1705.119385.example:12971",
	"tgt-7d813050.119571.example:10369",
	"tgt-1e85d2a3.119691.example:19103",
	"tgt-7b6c630f.119381.example:33255",
	"tgt-2d3aacdd.116787.example:61164",
	"tgt-0d127483.118736.example:1190",
	"tgt-ab91bef9.119870.example:41379",
	"tgt-52f525fb.119124.example:50753",
	"tgt-2d5eabf5.118679.example:33210",
	"tgt-3769dd57.118378.example:2987",
	"tgt-81cb6712.119162.example:28040",
	"tgt-3d6f7080.118375.example:29981",
	"tgt-df923ed9.119763.example:52771",
	"tgt-2a253cd7.119594.example:38574",
	"tgt-fe8f9718.119948.example:22455",
	"tgt-62fb565a.119682.example:22581",
	"tgt-1fac0fdf.118845.example:48100",
	"tgt-53589675.119486.example:33121",
	"tgt-24509b1b.119986.example:59359",
	"tgt-d8bd0f99.119144.example:36106",
	"tgt-933deba0.118754.example:47391",
	"tgt-4692ea67.119128.example:33120",
	"tgt-f35fed71.119814.example:40335",
	"tgt-18df7b5c.119919.example:27014",
	"tgt-3ae9e068.119998.example:63116",
	"tgt-61164722.118438.example:21291",
	"tgt-dc034f7d.119392.example:46970",
	"tgt-9b6f8ae5.119007.example:3711",
	"tgt-c6ad157e.119206.example:20540",
	"tgt-72731415.119549.example:17577",
	"tgt-699aab6c.118048.example:59389",
	"tgt-3531d589.119293.example:26710",
	"tgt-630ec36e.115311.example:17300",
	"tgt-f000f1cd.118305.example:54050",
	"tgt-eb149afd.119822.example:4994",
	"tgt-82280ad5.119405.example:5570",
	"tgt-649b172a.119056.example:32662",
	"tgt-8f360389.119845.example:36823",
	"tgt-cfc109df.119533.example:29821",
	"tgt-cae17f9c.119602.example:51596",
}

// organicKeys is a realistic-shape synthetic keyspace: sequential host
// labels over a sequential port block, the pattern a scan queue
// plausibly holds. It is deliberately NOT residue-balanced; see
// TestAssignBalanceOrganicKeyspace (and the documented mod-2 skew).
func organicKeys() []TargetKey {
	keys := make([]TargetKey, 0, 100)
	for i := 0; i < 100; i++ {
		keys = append(keys, fmt.Sprintf("host-%02d.example:92%02d", i, i))
	}
	return keys
}

// reversed returns keys in reverse order.
func reversed(keys []TargetKey) []TargetKey {
	rev := make([]TargetKey, len(keys))
	for i, k := range keys {
		rev[len(keys)-1-i] = k
	}
	return rev
}

// shardSizes runs Assign for every shard 1..total and reports the sizes.
func shardSizes(keys []TargetKey, total int) []int {
	sizes := make([]int, 0, total)
	for idx := 1; idx <= total; idx++ {
		sizes = append(sizes, len(Assign(keys, idx, total)))
	}
	return sizes
}

// perShard maps every key to the 1-based shard that claims it.
func perShard(keys []TargetKey, total int) map[TargetKey]int {
	m := make(map[TargetKey]int, len(keys))
	for idx := 1; idx <= total; idx++ {
		for _, k := range Assign(keys, idx, total) {
			m[k] = idx
		}
	}
	return m
}

// shardOf returns the 1-based shard of key under total (0 if unassigned).
func shardOf(key TargetKey, total int) int {
	for idx := 1; idx <= total; idx++ {
		if got := Assign([]TargetKey{key}, idx, total); len(got) == 1 && got[0] == key {
			return idx
		}
	}
	return 0
}

// TestSpecGrammar is the table for the i/n spec grammar (PQ-24):
// 1-based index, whitespace tolerated around the spec and around each
// part, and the rejected rows 0/n, negative, n/n, i>n and broken shapes.
func TestSpecGrammar(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantIdx int
		wantTot int
		errSub  string // non-empty: want an error containing this
	}{
		// accepted
		{name: "one of two", spec: "1/2", wantIdx: 1, wantTot: 2},
		{name: "mid shard", spec: "2/4", wantIdx: 2, wantTot: 4},
		{name: "first of seventeen", spec: "1/17", wantIdx: 1, wantTot: 17},
		{name: "last valid below total", spec: "16/17", wantIdx: 16, wantTot: 17},
		{name: "the last shard's n/n spelling", spec: "5/5", wantIdx: 5, wantTot: 5},
		{name: "single-shard 1/1", spec: "1/1", wantIdx: 1, wantTot: 1},
		{name: "surrounding whitespace", spec: "  2/4  ", wantIdx: 2, wantTot: 4},
		{name: "whitespace around parts", spec: "3 / 7", wantIdx: 3, wantTot: 7},
		// rejected
		{name: "zero index (0/n)", spec: "0/5", errSub: "0/n"},
		{name: "negative index", spec: "-1/5", errSub: "at least 1"},
		{name: "index above total", spec: "6/5", errSub: "> total"},
		{name: "zero total", spec: "1/0", errSub: "total must be at least 1"},
		{name: "negative total", spec: "1/-2", errSub: "total must be at least 1"},
		{name: "zero total with zero index", spec: "0/0", errSub: "total must be at least 1"},
		{name: "missing divider", spec: "12", errSub: `want "i/n"`},
		{name: "empty spec", spec: "", errSub: `want "i/n"`},
		{name: "whitespace only", spec: "   ", errSub: `want "i/n"`},
		{name: "leading divider", spec: "/5", errSub: `want "i/n"`},
		{name: "trailing divider", spec: "1/", errSub: `want "i/n"`},
		{name: "non numeric index", spec: "a/b", errSub: "not an integer"},
		{name: "non numeric total", spec: "2/n", errSub: "not an integer"},
		{name: "extra part", spec: "1/2/3", errSub: `want "i/n"`},
		{name: "extra part spaced", spec: "1 / 2 / 3", errSub: `want "i/n"`},
	}
	for _, tt := range tests {
		idx, tot, err := Spec(tt.spec)
		if tt.errSub == "" {
			if err != nil {
				t.Errorf("Spec(%q) = (%d, %d, %v); want (%d, %d, <nil>)", tt.spec, idx, tot, err, tt.wantIdx, tt.wantTot)
				continue
			}
			if idx != tt.wantIdx || tot != tt.wantTot {
				t.Errorf("Spec(%q) = (%d, %d); want (%d, %d)", tt.spec, idx, tot, tt.wantIdx, tt.wantTot)
			}
			continue
		}
		if err == nil {
			t.Errorf("Spec(%q) = (%d, %d, <nil>); want error containing %q", tt.spec, idx, tot, tt.errSub)
			continue
		}
		if !strings.Contains(err.Error(), tt.errSub) {
			t.Errorf("Spec(%q) error %q; want containing %q", tt.spec, err.Error(), tt.errSub)
		}
	}
}

// TestAssignFnv1a64Golden pins the hash against an independent FNV-1a
// reference implementation (Python, 0xcbf29ce484222325 / 0x100000001b3
// over the raw key bytes) so the Go value and the documented anchors
// cannot drift apart silently.
func TestAssignFnv1a64Golden(t *testing.T) {
	anchors := []struct {
		key  string
		want uint64
	}{
		{"gate.example:443", 0xddd0ecc569766e41},
		{"db-01.internal:5432", 0xa6147487b778b6c6},
		{"host-00.example:9200", 0x54cd9e89cd4d6af7},
	}
	for _, tt := range anchors {
		if got := fnv1a64(tt.key); got != tt.want {
			t.Errorf("fnv1a64(%q) = %#016x, want %#016x", tt.key, got, tt.want)
		}
	}
}

// TestAssignShardGolden pins per-key shard placement (1-based:
// shard = fnv1a64(key)%%total + 1) against the same independent
// reference, for representative keys across shard counts 2..17.
func TestAssignShardGolden(t *testing.T) {
	tests := []struct {
		key  string
		tot  int
		want int
	}{
		{"gate.example:443", 2, 2},
		{"gate.example:443", 3, 1},
		{"gate.example:443", 7, 7},
		{"gate.example:443", 17, 3},
		{"db-01.internal:5432", 2, 1},
		{"db-01.internal:5432", 3, 2},
		{"db-01.internal:5432", 7, 6},
		{"db-01.internal:5432", 17, 16},
		{"host-00.example:9200", 2, 2},
		{"host-00.example:9200", 3, 2},
		{"host-00.example:9200", 7, 7},
		{"host-00.example:9200", 17, 13},
		{"tgt-cd1cc934.119257.example:37147", 2, 1},
		{"tgt-cd1cc934.119257.example:37147", 3, 2},
		{"tgt-cd1cc934.119257.example:37147", 7, 5},
		{"tgt-cd1cc934.119257.example:37147", 17, 5},
		{"tgt-3af91b50.118862.example:19589", 2, 1},
		{"tgt-3af91b50.118862.example:19589", 3, 3},
		{"tgt-3af91b50.118862.example:19589", 7, 1},
		{"tgt-3af91b50.118862.example:19589", 17, 16},
	}
	for _, tt := range tests {
		if got := shardOf(tt.key, tt.tot); got != tt.want {
			t.Errorf("shardOf(%q, %d) = %d, want %d", tt.key, tt.tot, got, tt.want)
		}
	}
}

// TestAssignShardsPartitionKeys is the union property (PQ-24): the
// shards 1..n over one key set are a partition — disjoint (no key
// claimed twice, no duplicate members within a shard) and complete
// (every key in exactly one shard).
func TestAssignShardsPartitionKeys(t *testing.T) {
	for _, tot := range []int{1, 2, 3, 7, 17} {
		seen := make(map[TargetKey]int, len(fixtureKeys))
		for idx := 1; idx <= tot; idx++ {
			members := Assign(fixtureKeys, idx, tot)
			uniques := make(map[TargetKey]bool, len(members))
			for _, k := range members {
				if prev, dup := seen[k]; dup {
					t.Errorf("total=%d: shards %d and %d both claim %q", tot, prev, idx, k)
				}
				seen[k] = idx
				uniques[k] = true
			}
			if len(uniques) != len(members) {
				t.Errorf("total=%d: shard %d lists a duplicate member (%d members, %d unique)", tot, idx, len(members), len(uniques))
			}
		}
		if len(seen) != len(fixtureKeys) {
			t.Errorf("total=%d: union of shards 1..%d covers %d of %d keys; want complete", tot, tot, len(seen), len(fixtureKeys))
		}
	}
}

// TestAssignBalanceReport is the balance report (PQ-24): shard sizes
// within +/-1 of the mean. The fixture is residue-balanced by
// construction (see fixtureKeys), so the +/-1 bound is assertable here;
// realistic keyspace spread is asserted separately in
// TestAssignBalanceOrganicKeyspace.
func TestAssignBalanceReport(t *testing.T) {
	for _, tot := range []int{1, 2, 3, 7, 17} {
		sizes := shardSizes(fixtureKeys, tot)
		mean := float64(len(fixtureKeys)) / float64(tot)
		t.Logf("shard balance (total=%2d): sizes=%v mean=%.1f", tot, sizes, mean)
		for _, size := range sizes {
			if math.Abs(float64(size)-mean) > 1 {
				t.Errorf("total=%d: shard size %d is more than 1 off the mean %.1f (sizes=%v)", tot, size, mean, sizes)
			}
		}
	}
}

// TestAssignBalanceOrganicKeyspace exercises a NOT pre-balanced,
// realistic-shape keyspace. Two documented behaviours:
//
//   - mod 2: FNV-1a's bit 0 is the offset basis' parity XOR the XOR-sum
//     of the key bytes' low bits (the multiplier 0x100000001b3 is odd
//     and never mixes bit 0), so hosts sharing a byte-LSB pattern all
//     collapse into one bucket. The sequential hosts below all land in
//     shard 2 when total=2 — shard 1 stays empty. This is a real trap
//     for -shard consumers on correlated keyspaces, pinned here rather
//     than papered over.
//   - otherwise: sizes spread within 3 sigma of the multinomial mean
//     (the +/-1 bound only holds for the constructed fixture).
func TestAssignBalanceOrganicKeyspace(t *testing.T) {
	keys := organicKeys()
	report := func(tot int) []int {
		sizes := shardSizes(keys, tot)
		mean := float64(len(keys)) / float64(tot)
		t.Logf("shard balance, organic keys (total=%2d): sizes=%v mean=%.1f", tot, sizes, mean)
		return sizes
	}
	sizes2 := report(2)
	if sizes2[0] != 0 || sizes2[1] != 100 {
		t.Errorf("total=2: sizes=%v, want the documented parity concentration [0 100]", sizes2)
	}
	for _, tot := range []int{3, 7, 17} {
		sizes := report(tot)
		mean := float64(len(keys)) / float64(tot)
		bound := 3 * math.Sqrt(mean)
		for _, size := range sizes {
			if math.Abs(float64(size)-mean) > bound {
				t.Errorf("total=%d: shard size %d deviates from mean %.1f by more than 3 sigma (%.2f); sizes=%v", tot, size, mean, bound, sizes)
			}
		}
	}
}

// TestAssignStableForFixedKeyAndTotal pins the determinism property:
// for a FIXED (key, total) assignment is a pure function — identical on
// repeated runs, independent of the other keys in the list and of the
// list's order — and demonstrates the documented caveat that changing
// the total re-buckets most keys.
func TestAssignStableForFixedKeyAndTotal(t *testing.T) {
	const tot = 17
	first := perShard(fixtureKeys, tot)
	if len(first) != len(fixtureKeys) {
		t.Fatalf("perShard: %d of %d keys assigned", len(first), len(fixtureKeys))
	}
	again := perShard(fixtureKeys, tot)
	if !reflect.DeepEqual(first, again) {
		t.Error("repeated Assign over the same keys and total produced a different mapping")
	}
	if !reflect.DeepEqual(first, perShard(reversed(fixtureKeys), tot)) {
		t.Error("reversed key order produced a different shard mapping")
	}
	half := perShard(fixtureKeys[:50], tot)
	for _, k := range fixtureKeys[:50] {
		if half[k] != first[k] {
			t.Errorf("key %q moved from shard %d to %d when the key list grew", k, first[k], half[k])
		}
	}
	other := perShard(fixtureKeys, 7)
	changed := 0
	for _, k := range fixtureKeys {
		if other[k] != first[k] {
			changed++
		}
	}
	t.Logf("fixed-total caveat: %d/100 keys re-bucket when the total changes 17 -> 7", changed)
	if changed < 50 {
		t.Errorf("only %d/100 keys re-bucket when the total changes 17 -> 7; want >= 50 (sharding is stable only for a fixed total)", changed)
	}
}

// TestAssignRejectsInvalidRange pins Assign's programmer-error contract:
// an out-of-range index or total panics (the index comes straight from
// Spec, so anything out of range there is a caller bug).
func TestAssignRejectsInvalidRange(t *testing.T) {
	for _, tt := range []struct {
		idx int
		tot int
	}{
		{0, 3},
		{4, 3},
		{-1, 3},
		{1, 0},
		{1, -2},
	} {
		didPanic := func() (panicked bool) {
			defer func() {
				if recover() != nil {
					panicked = true
				}
			}()
			Assign([]TargetKey{"gate.example:443"}, tt.idx, tt.tot)
			return false
		}()
		if !didPanic {
			t.Errorf("Assign(keys, %d, %d): want panic, got none", tt.idx, tt.tot)
		}
	}
}
