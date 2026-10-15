# pqscan 2026.01-rc1 — TLS/QUIC cipher-configuration and PQC readiness scanner

`2026.01-rc1` is the milestone-completion candidate: every register leaf
([PQ-02](https://github.com/shsingh/pqscan/issues/5) through
[PQ-37](https://github.com/shsingh/pqscan/issues/109)) has landed via
reviewed, GPG-signed watched-RED pairs — grammar, pipeline, encoders/WAL/
resume, the usage-drift gate, the IANA registry, the readiness rubric
(+ the live verdict), certificate PQ analytics, congestion control
(limiter/AIMD/breakers with `-rate`/`-threads`), the deep-mode plan and
executor, the h3 discovery, the resolver pool and the PD-dialect input
adapters. Artifacts are verifiable *before* they run
([ADR-0003](docs/adr/0003-slsa-provenance-attestations.md)); the release
gate ([PQ-34](https://github.com/shsingh/pqscan/pull/75)) re-verifies the
signed tag, the repo's version sync, the site render and FRESH
performance numbers as part of every publish.

## Verify

```bash
sha256sum -c <(grep <artifact> CHECKSUMS-sha256.txt)
gh attestation verify <artifact> -R shsingh/pqscan
```

`2026.01-rc1` content:

- **goreleaser consolidation** ([PQ-27](https://github.com/shsingh/pqscan/issues/50)):
  the release matrix is now five targets — linux/amd64+arm64,
  darwin/amd64+arm64, windows/amd64 — built by
  [goreleaser](https://github.com/goreleaser/goreleaser) (v2) from
  `.goreleaser.yaml`, with `CHECKSUMS-sha256.txt` over the bare
  `pqscan-<os>-<arch>` asset names and a deterministic
  `GORELEASER_CURRENT_TAG` version stamp.
- **Pre-built windows/amd64 binary** (the
  [PQ-29](https://github.com/shsingh/pqscan/issues/52) install-story
  promise kept): `pqscan-windows-amd64.exe`, attested like the rest.
- **Release gate as publish pre-flight**: the publish job runs
  `scripts/check_release_consistency.sh <tag>` before creating the release
  (the runner has no release key, so the tag signature is verified at the
  cut machine and recorded here in
  [PQ-27](https://github.com/shsingh/pqscan/issues/50)).
- **Sample scan dataset committed**: `docs/sample-scan.jsonl` — one live
  fast-mode record against `google.com` (the reference
  [PQ-36](https://github.com/shsingh/pqscan/issues/108) target),
  captured by this cut's build.
