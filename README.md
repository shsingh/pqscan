# pqscan

[![License: MIT](https://img.shields.io/badge/licence-MIT-blue)](https://github.com/shsingh/pqscan/blob/main/LICENSE) [![pqscan site](https://img.shields.io/website?down_message=offline&up_message=live&url=https%3A%2F%2Fshsingh.github.io%2Fpqscan%2F&label=site)](https://shsingh.github.io/pqscan/) [![GitHub commit activity](https://img.shields.io/github/commit-activity/m/shsingh/pqscan)](https://github.com/shsingh/pqscan/graphs/commit-activity) [![Libraries.io dependency status for GitHub repo](https://img.shields.io/librariesio/github/shsingh/pqscan)](https://libraries.io/github/shsingh/pqscan) [![GitHub Release](https://img.shields.io/github/v/release/shsingh/pqscan?include_prereleases)](https://github.com/shsingh/pqscan/releases)

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/shsingh/pqscan/main.svg)](https://results.pre-commit.ci/latest/github/shsingh/pqscan/main)

A small, fast, chainable TLS / QUIC cipher-configuration and post-quantum
readiness scanner. One static binary. The tool reads the negotiated cipher
configuration of remote endpoints. The fields: protocol versions, cipher
suites, key-exchange groups, signature algorithms, certificate properties.
A fixed rubric rates every observation on the post-quantum readiness scale.
The record carries the rating as `pq=<label>(<score>)`. The tool reads the
import toolset's forms and writes them out: stdin → stdout, streaming
JSONL, the chain `subfinder` → `httpx` → `naabu` → `nuclei`.

**Status:** the `2026.01-rc3` release-candidate cut is live and attested.
The specification ([`docs/spec.md`](docs/spec.md)) is in force.

## What it does

- **fast mode** — one engineered handshake per target (a browser-grade
  hello; the hybrid ML-KEM key share preferred). The record: the negotiated
  parameters, the certificate chain, ALPN, the session features.
- **deep mode** — one probe plan per target; every suite, version, group
  and signature algorithm probes one per handshake (offer-one /
  observe-accept). The checks: HRR detection, resumption, 0-RTT.
- **pq mode** — the forced PQ-group offer set (the registered PQ
  codepoints). The classifier reads the PQ signatures and the
  certificates. Every target takes one readiness rating; the HNDL risk
  flag rides on a draft acceptance.
- **the two planes** — TCP (crypto/tls + uTLS) and QUIC (quic-go) on
  UDP/443. HTTP/1.1 and h2 negotiate by ALPN. h3 runs through the direct
  QUIC handshake.
- **chainable** — the inputs: hosts, `host:port`/`ip:port`,
  `scheme://host[:port]` spec lines (the scheme strips), the piped stdin,
  the subfinder/httpx/naabu/masscan output forms. The outputs: JSONL, CSV,
  text, URLs.

## Measured performance

Rows tagged *historical* carry the capture of their evidence run; google.com
is the live reference target for re-measurement.

Measured baselines (spec
[`§7.8`](docs/spec.md#7-the-hard-part-async-architecture-and-throughput-first-class)):
the SLO suite re-runs on every perf-suite merge; this table carries the
current numbers. The linked evidence comments carry the verbatim run
transcripts.

| Metric | Target | Measured | Run |
|---|---|---|---|
| fast-mode handshakes/s (aggregate, W=8, loopback fixture) | ≥ 2,500/s/core | 2,952 (re-run 3,026) | `go test ./internal/microbench/ -run SLO -v` — [evidence #10](https://github.com/shsingh/pqscan/issues/10) |
| external control decomposition (cloudflare.com:443, forced hybrid) | — | connect 18.9 ms / handshake 23.4 ms / total 42.4 ms | `go run ./cmd/bench -target cloudflare.com:443 -host cloudflare.com -n 20 -mode seq` — [evidence #10](https://github.com/shsingh/pqscan/issues/10) |
| external control decomposition (google.com:443, the reference live target) | — | connect 20.7 ms / handshake 140.3 ms / total 161.0 ms | `go run ./cmd/bench -target google.com:443 -host google.com -n 20 -mode seq` |
| QUIC plane ground truth (live, cloudflare.com) | — | 4588 `X25519MLKEM768` negotiated inside QUIC v1 (ALPN `h3`) at 27.6 ms/handshake | `PQSCAN_INTEGRATION=1 go test ./internal/quicx/ -run Integration -v` — [evidence #9](https://github.com/shsingh/pqscan/issues/9) |
| obsolete-Kyber compat oracle (live) | — | share-less offer of group 25497 answered by an HRR demanding the draft group | `PQSCAN_INTEGRATION=1 go test ./internal/tlsx/ -run Integration -v` — [evidence #8](https://github.com/shsingh/pqscan/issues/8) |

## Quick examples

```bash
# subfinder gives the target names; pqscan scans them
subfinder -d example.com -silent | pqscan -mode fast -jsonl -o assets.jsonl

# naabu gives the live ports; the cipher pass reads them
naabu -l domains.txt -p 443,8443,993 -silent | pqscan -mode fast -jsonl

# deep: the offer-one matrix on one asset (versions, suites, groups, HRR)
pqscan -u google.com -mode deep -deep full -jsonl

# the weekly PQ job over the target list; jq reports every below-ready target
pqscan -l targets.txt -jsonl \
  | jq -r 'select(.pq.score < 60) | [.target.host,.pq.label,(.pq.hndl|tostring)] | @tsv'
```

A defect report needs the diagnostics. Re-run the same arguments with
`-debug -debug-out diag.json` and
[open an issue](https://github.com/shsingh/pqscan/issues/new?template=bug_report.yml) —
the templates require the diagnostics attached.

## Specification and roadmap

The canonical specification is
[`docs/spec.md`](docs/spec.md). Every issue links the sections it
implements through the heading anchors.

| Section | Anchor |
|---|---|
| Problem statement | [`docs/spec.md#1-problem-statement`](docs/spec.md#1-problem-statement) |
| Goals and non-goals | [`docs/spec.md#2-goals-and-non-goals`](docs/spec.md#2-goals-and-non-goals) |
| Related work | [`docs/spec.md#3-related-work--honest-survey`](docs/spec.md#3-related-work--honest-survey) |
| Language decision | [`docs/spec.md#4-language-decision-go-or-rust`](docs/spec.md#4-language-decision-go-or-rust) |
| Feature set | [`docs/spec.md#5-feature-set`](docs/spec.md#5-feature-set) |
| Chaining recipes | [`docs/spec.md#6-chaining-reference-implementations`](docs/spec.md#6-chaining-reference-implementations) |
| Async architecture and throughput | [`docs/spec.md#7-the-hard-part-async-architecture-and-throughput-first-class`](docs/spec.md#7-the-hard-part-async-architecture-and-throughput-first-class) |
| CLI surface | [`docs/spec.md#8-cli-surface`](docs/spec.md#8-cli-surface) |
| Milestones | [`docs/spec.md#9-milestones`](docs/spec.md#9-milestones) |
| Test and verification | [`docs/spec.md#10-test-and-verification-strategy`](docs/spec.md#10-test-and-verification-strategy) |
| PQC codepoints (registry snapshot) | [`docs/spec.md#appendix-a-pqc-codepoint-reference-snapshot`](docs/spec.md#appendix-a-pqc-codepoint-reference-snapshot) |

The milestone list is historical. The record lives in the repository's
milestones and the closed issues. The releases and the live CLI surface
carry the current state.

## Contributing

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — the working agreement (Conventional Commits, signed commits, one logical change per PR).
- [`AGENTS.md`](AGENTS.md) — the single source of truth for contributors and coding agents.
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting
  ([private advisory](https://github.com/shsingh/pqscan/security/advisories/new)).
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

**Engineering standard — watched RED ([ADR-0002](docs/adr/0002-watched-red-merge-gate.md)):** every behavioural change goes in as a RED→GREEN pair. The failing test exists and runs first. The PR records the RED output verbatim. See [CONTRIBUTING.md](CONTRIBUTING.md) for the hypothesis-first procedure.

Scan only the systems the operator owns or holds authorisation to test. The
tool's etiquette defaults (the rate caps, the per-subnet concurrency, the
circuit breakers) are published defaults and security-relevant.

## Licence

[MIT](LICENSE).
