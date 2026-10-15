# pqscan 2026.01-rc1 — TLS/QUIC cipher-configuration and PQC readiness scanner

`2026.01-rc1` is the milestone-completion candidate: every register leaf
([PQ-15](https://github.com/shsingh/pqscan/issues/4) through
[PQ-26](https://github.com/shsingh/pqscan/issues/4)) has landed via
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

`2026.01-rc1` content: TBD-AT-CUT (the final feature list stamps from the merged register at cut time — the file must exist in the tagged tree BEFORE the tag per the publish contract).
