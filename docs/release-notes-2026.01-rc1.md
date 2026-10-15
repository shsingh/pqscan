# pqscan 2026.01-rc1 — TLS/QUIC cipher-configuration and PQC readiness scanner

pqscan is a small, fast, chainable TLS/QUIC cipher-configuration and
post-quantum readiness scanner shipped as a single static binary (the
PD-ecosystem contract in
[`docs/spec.md#5-feature-set`](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#5-feature-set)).
2026.01-rc1 is the first release candidate: it packages the engine state
that closed the [M0 gate](https://github.com/shsingh/pqscan/blob/main/docs/m0-report.md)
together with the tooling needed to verify it. Artifacts are verifiable
*before* they are run — that is the governance contract of this tool.

## What is included

- **Both-plane engine proven live.** Forced-group probing negotiates the
  PQC hybrid group `X25519MLKEM768` (4588) on both transport planes:
  on the TCP plane (`internal/tlsx`) — TLS 1.3, `TLS_AES_128_GCM_SHA256`
  (version 772) — and inside QUIC v1 with ALPN `h3`
  (`internal/quicx`). Measured against a live hybrid edge, evidence
  verbatim on [issue #8](https://github.com/shsingh/pqscan/issues/8)
  (TCP) and [issue #9](https://github.com/shsingh/pqscan/issues/9)
  (QUIC). Rejections are results, not errors: UDP failures are
  classified (`refused` / `blocked`) and recorded; on-the-wire HRR
  observation (RFC 8446 §4.1.3) extracts the group a server demands,
  including the obsolete Kyber draft 25497 still honoured by some
  edges — the finding that seeds the compat-oracle ladder.
- **`-debug` / `-debug-out` diagnostics.** Every engine decision point
  (ladder step, QUIC handshake, refusal classification) emits a
  diagnostics event: a human stream on stderr under `-debug`, and a
  schema-1 machine report via `-debug-out diag.json`
  ([USAGE.md](https://github.com/shsingh/pqscan/blob/main/USAGE.md),
  [issue #29](https://github.com/shsingh/pqscan/issues/29)).
- **Single-target fast mode.** The fast path the run pipeline will
  drive at M1 is engine-proven end to end on the loopback fixture:
  **2,952 handshakes/s at W=8** (re-run 3,026) against the
  ≥ 2,500 target
  ([issue #10](https://github.com/shsingh/pqscan/issues/10)).
- **Measured benchmarks.** The latency decomposition holds on live
  hosts: connect ≈ 1 RTT (18.94 ms), handshake 23.44 ms, total ≈
  2 RTT + server compute (42.4 ms, cloudflare seq×20); QUIC per-conn
  cost 22.5 ms avg handshake, goroutine delta 3, heap 665 KB. Full SLO
  cells in [docs/m0-report.md](https://github.com/shsingh/pqscan/blob/main/docs/m0-report.md).
- **SLSA provenance on every artifact.** Every binary in this release
  is built in Actions and attested in the same job that produces it
  (`actions/attest-build-provenance`, no post-hoc wrapping):
  Sigstore-signed SLSA build provenance bound to the repository/OID
  issuer
  ([ADR-0003: SLSA provenance via GitHub Artifact Attestations](https://github.com/shsingh/pqscan/blob/main/docs/adr/0003-slsa-provenance-attestations.md)).

## Verify before running

Every artifact carries SLSA build provenance; verify it — the digests
must match the artifacts for this repository. With the `gh` CLI:

```
gh attestation verify <artifact> -R shsingh/pqscan
```

A verified run exits `0` with a verified/attested summary line for the
artifact's digest. The per-run bundle is also uploaded as an artifact
(`*.intoto.jsonl`) and ships as a release asset for offline checks.

Each release also carries `CHECKSUMS-sha256.txt` (sha256 over every
binary). From the directory holding the artifacts:

```
sha256sum --check CHECKSUMS-sha256.txt
```

## Limitations

2026.01-rc1 is an engine-gate release candidate, not the full M1/M2
surface:

- **Multi-target grammar and run pipeline** land with M1: target
  grammar and the run pipeline
  ([#38](https://github.com/shsingh/pqscan/issues/38)), output encoders
  and the WAL ([#39](https://github.com/shsingh/pqscan/issues/39)).
  Until then the rc1 binary's scan surface is intentionally minimal —
  the live-proven engines are demonstrated through the M0 gate runs
  (#8, #9, #10) and the diagnostics path is fully functional.
- **Deep- and pq-mode ladders** land with M2: the deep-mode plan
  executor (offer-one matrix, pruned DAG)
  ([#43](https://github.com/shsingh/pqscan/issues/43)), PQC readiness
  scoring ([#42](https://github.com/shsingh/pqscan/issues/42)), IANA
  regen tables ([#41](https://github.com/shsingh/pqscan/issues/41)) and
  the surrounding analytics — the full range is tracked under issues
  [#38](https://github.com/shsingh/pqscan/issues/38)–[#45](https://github.com/shsingh/pqscan/issues/45).
- **M0 deferred SLO cells** — aggregate sustained under load, p95
  per-target, RSS at 50k in-flight and deep-mode rate are measured at
  their owning milestones (M3/M4) and are listed explicitly in
  [docs/m0-report.md](https://github.com/shsingh/pqscan/blob/main/docs/m0-report.md)
  so no cell is silently skipped.
