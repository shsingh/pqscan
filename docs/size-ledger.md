# Binary size ledger (PQ-32)

The shipped binary is an SLO surface, not a side effect (performance contract:
[`docs/spec.md#7-the-hard-part-async-architecture-and-throughput-first-class`](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#7-the-hard-part-async-architecture-and-throughput-first-class);
evidence discipline: [`docs/adr/0002-watched-red-merge-gate.md`](https://github.com/shsingh/pqscan/blob/main/docs/adr/0002-watched-red-merge-gate.md)).
Every size claim below is a measured number; every tool verdict carries the
verbatim output. Issue: [#62](https://github.com/shsingh/pqscan/issues/62).

## Size SLO

| target | SLO | enforced by |
|---|---|---|
| linux/amd64 | < 8,000,000 bytes (8 MB) — the gate | `TestSizeSLO` in `internal/microbench/sizegate_test.go` + the `size-gate` CI job (`.github/workflows/build.yml`) |
| darwin/arm64 | < 7,000,000 bytes (7 MB) | measured and reported; CI enforces linux/amd64 (the SLO reference target) |

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

## Levers — priority order

1. **`-s -w -trimpath` with `CGO_ENABLED=0` — IN PLACE.** Applied to the
   release build, to `TestSizeSLO`, and to the CI `size-gate` job. The
   zero-risk lever: strips symbol/DWARF tables (`-s -w`) and build-path noise
   (`-trimpath`) with no runtime cost; the baseline numbers above carry it.
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
  stats the bytes, asserts < 8,000,000, and logs the measured bytes into the
  CI test log (watched-RED pair on record: RED asserted < 1,000,000 against
  the 6.5 MB baseline; GREEN asserted the real SLO).
- **CI job:** `.github/workflows/build.yml` `size-gate` — checkout → setup-go
  → `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s
  -w" -o pqscan ./cmd/pqscan` → `stat -c %s` + awk asserting < 8000000.
