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
