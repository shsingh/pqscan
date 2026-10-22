# Binary size ledger (PQ-32)

The shipped binary is an SLO surface, not a side effect (performance contract:
[`docs/spec.md#7-the-hard-part-async-architecture-and-throughput-first-class`](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#7-the-hard-part-async-architecture-and-throughput-first-class);
evidence discipline: [`docs/adr/0002-watched-red-merge-gate.md`](https://github.com/shsingh/pqscan/blob/main/docs/adr/0002-watched-red-merge-gate.md)).
Every size claim below is a measured number; every tool verdict carries the
verbatim output. Issue: [#62](https://github.com/shsingh/pqscan/issues/62).

## Size SLO

| target | SLO | enforced by |
|---|---|---|
| linux/amd64 | < 10,000,000 bytes (10 MB) — the gate | `TestSizeSLO` in `internal/microbench/sizegate_test.go` + the `size-gate` CI job (`.github/workflows/build.yml`) |
| darwin/arm64 | < 10,000,000 bytes (10 MB) | measured and reported; CI enforces linux/amd64 (the SLO reference target). The reference-target amendment (2026-10-22, PQ-70) binds 10 MB on both planes; the rc3-era readings below stay as recorded |

## Measured sizes

Baseline measured 2026-10-15, toolchain go1.27.2, release flags
`-s -w -trimpath`, `CGO_ENABLED=0`:

| target | build | size |
|---|---|---|
| linux/amd64 | release flags | 6.5 MB (6,840,480 B) |
| darwin/arm64 | release flags | 6.1 MB (6,445,938 B) |

Both rows were re-verified byte-for-byte in the PQ-32 watched-RED→GREEN pair
(same toolchain, same machine class as the baseline measurement): the RED run
logged `6840480 bytes (6.84 MB)` and failed against the deliberately wrong
pre-BinaryOptim bound, the corrected gate passed at 6,840,480 < 8,000,000
(verbatim runs on issue #62 and the PQ-32 PR). Headroom at baseline:
1,159,520 bytes (~14.5%) below the linux/amd64 SLO.

Sizes are toolchain-dependent. The CI `size-gate` job builds linux/amd64 with
the go.mod-pinned toolchain (`go-version-file`, GOTOOLCHAIN=local):
go1.26.0 measures **6,230,178 bytes** (the rc1-era tree — `size OK: 6230178 <
8000000` — check
run [38706131466](https://github.com/shsingh/pqscan/actions/runs/38706131466)),
while the go1.27.2 baseline row above measures 6,840,480 bytes. Both sit under
the 8 MB SLO; the gate binds the toolchain in CI (go-version-file), so the CI
number is the enforcement number. The t.Logf helper carries the test-run
number too, and the dedicated job's log lines carry the CI number — the
2026.01-rc3 prep's read is below.

### The 2026.01-rc3 release-prep measurement (2026-10-20, the to-be-cut tree)

Measured live on the rc3 release-prep tree (`8d87da5` + this PR's docs, no
engine or package changes) at release flags `-s -w -trimpath`,
`CGO_ENABLED=0`, host toolchain go1.27.2 (`go test ./internal/microbench/
-run TestSizeSLO -v` plus fresh manual builds of `./cmd/pqscan`):

| target | build | size |
|---|---|---|
| linux/amd64 | release flags | 7,643,296 B (7.64 MB) |
| darwin/arm64 | release flags | 7,220,402 B (7.22 MB) |

The tree has grown since the 2026-10-15 baseline row (the matrix, adapter and
error-contract lanes added packages, zero handshake-plane changes):
linux/amd64 is 802,816 bytes heavier, darwin/arm64 is 774,464 bytes heavier.
Headroom at this tree: linux/amd64 keeps 356,704 bytes (~4.5%) under the
8,000,000-byte SLO.

The CI enforcement number moved with the tree: the same go1.26.0
`size-gate` build binds at **7,131,298 bytes** (`7131298 bytes (7.13
MB)` — run
[39406285869](https://github.com/shsingh/pqscan/actions/runs/39406285869),
job 118572894846, 2026-10-20 — the dedicated run's log; the shared
`TestSizeSLO` in the perf suite's own run read the identical byte count),
868,702 bytes (~10.9%) under the SLO. CI stays the enforcement number.

The darwin/arm64 SLO row above is a measured-and-reported reference, not a
CI-enforced gate — and at this tree the reference is exceeded: 7,220,402
bytes is 220,402 bytes above the 7,000,000-byte reference target. Recorded
here as the honest reading; a size-lever pass for the reference target is a
separate filed lane, not a silently relaxed row.

## The PQ-63 size-lever evaluation (2026-10-20, the rc3-era tree)

The lever lane measured whether the release-flag recipe still has headroom to
give on darwin/arm64 or whether the 7,000,000-byte reference needs a reviewed
amendment. Read fresh: issue [#167](https://github.com/shsingh/pqscan/issues/167).
The tree under measurement is the rc3 cut's tree (`61d1287` — the rc3 tree plus
the docs-only zero-reference sweep, no package or build-recipe changes),
toolchain go1.27.2, `CGO_ENABLED=0`, every row a fresh `go build -o` of
`./cmd/pqscan` measured on the same host.

The recipe state first: the strip lever is ALREADY everywhere the release
recipe builds — `.goreleaser.yaml` (`flags: -trimpath`, `ldflags: -s -w -X
main.version={{ .Version }}`), the `size-gate` job (`CGO_ENABLED=0 GOOS=linux
GOARCH=amd64 go build -trimpath -ldflags "-s -w"`), `attest.yml`
(`-trimpath -ldflags="-s -w -X main.version=..."`), and the `TestSizeSLO`
helper. The bake-off below therefore measures the lever's VALUE, not a missing
application.

darwin/arm64 bake-off:

| build | flags | bytes |
|---|---|---|
| unstripped reference | none | 10,751,938 |
| trimpath only | `-trimpath` | 10,702,354 |
| strip only | `-ldflags "-s -w"` | 7,253,426 |
| release flags (the recipe) | `-trimpath -ldflags "-s -w"` | 7,220,402 |
| release flags + dead-DWARF compile pass | + `-gcflags=all=-dwarf=false` | 7,220,402 (+0) |
| release flags + the release version stamp | + `-ldflags "-X main.version=<stamp>"` | 7,220,402 (+0) |
| release flags + buildid override | + `-ldflags "-B 0x00"` | 7,220,402 (+0) |

linux/amd64, the CI-equivalent build (the exact command shape the `size-gate`
job runs):

| build | flags | bytes |
|---|---|---|
| unstripped reference | none | 11,346,104 |
| release flags, host toolchain go1.27.2 | `-trimpath -ldflags "-s -w"` | 7,643,296 |
| release flags, GOTOOLCHAIN=go1.26.0 (the CI-pinned toolchain) | release flags | 7,131,298 |

The go1.26.0 local build reproduces the CI enforcement number byte-for-byte
(`7131298 < 8000000` — run
[39406285869](https://github.com/shsingh/pqscan/actions/runs/39406285869)):
the lane's CI-equivalent row and the CI gate now agree on every byte, not just
"under the SLO".

Verdict:

- The lever is worth 3,531,536 bytes on darwin/arm64 (10,751,938 → 7,220,402,
  −32.8%) and 3,702,808 bytes on linux/amd64 (11,346,104 → 7,643,296) — and it
  is already applied: its delta is consumed in every recorded row, not pending.
- The residual knobs measure +0: `-gcflags=all=-dwarf=false` (the linker's `-w`
  already drops the DWARF), the `-X` stamp and the buildid override
  (byte-identical outputs). No flag-level lever remains that honestly reaches
  7,000,000: the measured-best darwin/arm64 build IS the recipe's build,
  7,220,402 bytes.
- What the growth is: the stripped release binary's section anatomy (`size -m`)
  is `__text` 3,051,348, `__gopclntab` 2,632,652, `__go_type` 734,744,
  `__rodata` 222,137, `__noptrdata` 256,705, `__data` 55,794 — machine mass,
  not repo text. Symbol-attributed text on the same tree: the largest repo
  packages are `internal/out` 29,296, `internal/tlsx` 13,008, `internal/deepplan`
  12,544 (the record/finding encode and the adapter/plan surfaces the issue
  names); all repo packages sum ≈ 92 KB; quic-go ≈ 374 KB. The +774,464-byte
  growth rides the wider reachable surface the new lanes register (more
  dep/stdlib surface and its metadata for the adapter, finding and
  error-contract work), and carries a toolchain share on the SAME tree and
  flags of +511,998 bytes (go1.27.2 vs go1.26.0 on linux/amd64: 7,643,296 vs
  7,131,298).
- The honest path to the 7,000,000 reference therefore runs through (a) the
  `-tags lite` QUIC-plane drop (lever 2 — its own paired lane; the saving is
  measured there, not asserted here), or (b) a REVIEWED reference-target
  amendment. Neither is applied here: this lane does not relax the gate. The
  amendment question goes to review in the PQ-63 PR with the measured-best
  above; the darwin/arm64 SLO row keeps binding 7,000,000 until that review.

## Levers — priority order

1. **`-s -w -trimpath` with `CGO_ENABLED=0` — IN PLACE.** Applied to the
   release build, to `TestSizeSLO`, and to the CI `size-gate` job. The
   zero-risk lever: strips symbol/DWARF tables (`-s -w`) and build-path noise
   (`-trimpath`) with no runtime cost; the baseline numbers above carry it.
   The PQ-63 evaluation measured the lever's value on the rc3-era tree:
   3,531,536 bytes on darwin/arm64 and 3,702,808 bytes on linux/amd64 (the
   unstripped-vs-release deltas); the residual flags measure +0.
2. **`-tags lite` no-QUIC build — PLANNED (lands with its own pair later).**
   A TLS-only build tag that drops the QUIC plane (`internal/quicx`) for
   scanners that never probe QUIC. Estimated savings will be measured in that
   lane — not asserted here, because no lite build exists yet in this tree.
3. **UPX — REJECTED up front.** Packing the release binary trips AV/EDR
   false-positive heuristics — in the PD-ecosystem context a scanner binary
   must not present like packed malware — and it invalidates the
   uncompressed-artifact assumption the SLSA attestation chain relies on
   ([`docs/adr/0003-slsa-provenance-attestations.md`](https://github.com/shsingh/pqscan/blob/main/docs/adr/0003-slsa-provenance-attestations.md)).
   Verdict: pqscan is never shipped UPX-packed.
4. **tinygo — EVALUATED.** Non-starter for the full binary; verdict below.

## tinygo verdict — non-starter (2026-10-15, output verbatim)

tinygo 0.43.0 (darwin/arm64 binary release, unpacked into the workspace
scratch dir — the repo tree was not touched), host toolchain go1.27.2:

```text
tinygo version 0.43.0 darwin/arm64 (using go version go1.27.2 and LLVM version 22.1.4)
```

Build attempt from the repo root (binary output directed to the scratch dir):

```text
$ tinygo build -o "<scratch-dir>/pqscan-tinygo" ./cmd/pqscan
exit status 1 — no binary produced

# github.com/quic-go/quic-go/internal/protocol
../../go/pkg/mod/github.com/quic-go/quic-go@v0.63.0/internal/protocol/encryption_level.go:37:53: undefined: tls.QUICEncryptionLevel
../../go/pkg/mod/github.com/quic-go/quic-go@v0.63.0/internal/protocol/encryption_level.go:40:14: undefined: tls.QUICEncryptionLevelInitial
../../go/pkg/mod/github.com/quic-go/quic-go@v0.63.0/internal/protocol/encryption_level.go:42:14: undefined: tls.QUICEncryptionLevelHandshake
../../go/pkg/mod/github.com/quic-go/quic-go@v0.63.0/internal/protocol/encryption_level.go:44:14: undefined: tls.QUICEncryptionLevelApplication
../../go/pkg/mod/github.com/quic-go/quic-go@v0.63.0/internal/protocol/encryption_level.go:46:14: undefined: tls.QUICEncryptionLevelEarly
../../go/pkg/mod/github.com/quic-go/quic-go@v0.63.0/internal/protocol/encryption_level.go:52:35: undefined: tls.QUICEncryptionLevel
../../go/pkg/mod/github.com/quic-go/quic-go@v0.63.0/internal/protocol/encryption_level.go:54:11: undefined: tls.QUICEncryptionLevelInitial
../../go/pkg/mod/github.com/quic-go/quic-go@v0.63.0/internal/protocol/encryption_level.go:56:11: undefined: tls.QUICEncryptionLevelHandshake
../../go/pkg/mod/github.com/quic-go/quic-go@v0.63.0/internal/protocol/encryption_level.go:58:11: undefined: tls.QUICEncryptionLevelApplication
../../go/pkg/mod/github.com/quic-go/quic-go@v0.63.0/internal/protocol/encryption_level.go:60:11: undefined: tls.QUICEncryptionLevelEarly
```

Interpretation: tinygo's build of the standard library carries a `crypto/tls`
without the QUIC surface (`tls.QUICEncryptionLevel…` is undefined), so
`github.com/quic-go/quic-go@v0.63.0` cannot compile under tinygo — the
dependency chain that gives pqscan its QUIC plane is what tinygo cannot host,
exactly the class the issue predicted. tinygo is a non-starter for the full
binary; the `-tags lite` path is the size lever that does not sacrifice the
TLS plane.

## Gate wiring

- **Test:** `TestSizeSLO` (`internal/microbench/sizegate_test.go`) builds
  `./cmd/pqscan` with the release flags for linux/amd64 into a temp dir,
  stats the bytes, asserts < 10,000,000, and logs the measured bytes into the
  CI test log (watched-RED pair on record: RED asserted < 1,000,000 against
  the 6.5 MB baseline; GREEN asserted the real SLO). The bound reads
  10,000,000 since the PQ-70 amendment.
- **CI job:** `.github/workflows/build.yml` `size-gate` — checkout → setup-go
  → `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s
  -w" -o pqscan ./cmd/pqscan` → `stat -c %s` + awk asserting < 10000000.

## The reference-target amendment (2026-10-22, PQ-70)

The operator reviews and approves the amendment in issue
[#183](https://github.com/shsingh/pqscan/issues/183). Both planes bind
10,000,000 bytes (10 MB) from this change: the enforced linux/amd64 bound and
the measured-and-reported darwin/arm64 reference move together. One bound, one
reading, both planes.

The re-measure runs LIVE on the pre-PR tree (`origin/main`, `9dda379`), with
the recipe build (`go build -trimpath -ldflags "-s -w"`, `CGO_ENABLED=0`) and
the host toolchain go1.27.2:

| target | build | size |
|---|---|---|
| linux/amd64 | release flags | 7,643,296 B (7.64 MB) |
| darwin/arm64 | release flags | 7,220,402 B (7.22 MB) |

Both rows measure byte-identical to the rc3 release-prep rows above: the tree
carries zero engine growth since the rc3 cut (the merged lanes changed
documents, strings and CI, and the build recipe stays fixed). The measured
rows above stay as live-derived truth; nothing here restates a measured cell.

Headroom at the amended bound:

| target | headroom | share |
|---|---|---|
| linux/amd64 | 2,356,704 B | 23.6% of the bound |
| darwin/arm64 | 2,779,598 B | 27.8% of the bound |

Why the amendment lands now:

- The QUIC census lane (PQ-69) adds the quic-go http3 exchange surface to the
  binary. The 8 MB gate left 356,704 bytes (~4.5%) of headroom on the measured
  tree. The http3 surface exceeds that margin.
- The darwin/arm64 reference (7,000,000) was already exceeded on the same
  tree (the 220,402-byte reading the PQ-63 evaluation recorded). The reviewed
  amendment is the honest close for that lane (the PQ-63 verdict's option
  (b)); option (a), the `-tags lite` lever, stays planned in the levers list
  above.
- The bound stays a reviewed contract item: the gate keeps one binding
  constant, the CI job keeps its matching assert, and the amendment rides
  this ledger with its measured rows.

The verdict's decision record: issue [#167](https://github.com/shsingh/pqscan/issues/167)
named the paths; issue [#183](https://github.com/shsingh/pqscan/issues/183)
carries the review and the operator's approval.
