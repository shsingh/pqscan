# pqscan: guide for contributors and coding agents

This file is the single source of truth for humans and coding agents
(GitHub Copilot, Claude, Cursor, Hermes, etc.) working on pqscan.
Tool-specific files (`CLAUDE.md`) only point here. When this file and a
tool-specific file disagree, this file wins.

Read the [Testing](#testing), [Pull requests](#pull-requests) and
[Security](#security) sections before changing anything. The rest is a map
of the codebase.

The product specification is
[`docs/spec.md`](https://github.com/shsingh/pqscan/blob/main/docs/spec.md)
in this repository — the normative prose for modes, budgets, scoring and
milestones. Every issue that drives work links the specification sections it
implements using GitHub heading anchors (never bare section numbers, never
`.pdf` references, never `/pulls/N` links for issues).

## Project overview

pqscan is a small, fast, chainable TLS/QUIC cipher-configuration scanner
with a post-quantum readiness view: one static binary that enumerates
protocols, cipher suites, key-exchange groups, signature algorithms and
certificate properties for a target estate, classifies every observation
`pq | pq_hybrid | classic | obsolete`, and pipes naturally with
subfinder → httpx → naabu → nuclei. Two handshake planes: TCP
(crypto/tls + uTLS) and QUIC (quic-go) on UDP/443.

The delivery unit is a leaf-sized slice: one milestone acceptance row or
issue task, tests in the same change, merge via pull request.

## Running pqscan (operator and agent runbook)

This section is for humans AND agents that need to execute the tool — read it,
run it, verify it, no other context required.

- **Build locally** (toolchain floor Go 1.25):

```bash
go build -o pqscan ./cmd/pqscan && ./pqscan -version
```

- **Execute a scan** (engines land per the [register](https://github.com/shsingh/pqscan/issues/4);
  `run()` refuses with exit 64 until a plane is live):

```bash
./pqscan -u example.com                          # fast mode, text out
subfinder -d example.com -silent | ./pqscan -mode fast -jsonl -o assets.jsonl
naabu -l domains.txt -p 443,8443,993 -silent | ./pqscan -from-naabu -mode fast -jsonl
./pqscan -l estate.txt -mode pq -jsonl           # PQ ladder + readiness verdicts
./pqscan -cidr 198.51.100.0/24 -ptr -sni ptr-then-ip -mode fast -jsonl
```

- **Read the output**: streaming JSONL, one record per target —
  `.target` (host/ip/ptr/sni_used), `.handshake` (version, group +
  `group_class`, suite, sig scheme, ALPN), `.cert` (key/sig alg classes,
  PQ flag), `.pq` (`score`, `verdict` A+…D, `flags` incl. `hndl_risk`,
  `reasons[]`), `.error`. Non-negotiated states (`hrr`, `alert`,
  `skipped`, `error`) are recorded facts with reasons. The full schema
  example is in [`docs/spec.md` §5.7](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#5-feature-set);
  recipes live on the [site](https://shsingh.github.io/pqscan/) and in
  [`docs/spec.md#6-chaining-reference-implementations`](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#6-chaining-reference-implementations).
- **Verify before trusting a binary**: every artifact from CI carries SLSA
  provenance ([ADR-0003](docs/adr/0003-slsa-provenance-attestations.md)) —
  `gh attestation verify <artifact> -R shsingh/pqscan` (unsigned or
  unprovable → do not run).
- **Prove the tool itself**:

```bash
go test ./...                            # offline: fixture matrix + unit pairs
PQSCAN_INTEGRATION=1 go test ./internal/tlsx/ -run Integration -v
                                         # live-network truth, never in CI
```

- **Etiquette invariants** (security-relevant, ADR-relevant): only scan
  systems you own or are authorised to test; the rate caps, per-subnet
  ceilings and breaker thresholds are published defaults — never bypass
  them in scripts.

## Repository structure

| Path | Purpose |
| --- | --- |
| `cmd/pqscan/` | main, flag plumbing, config |
| `internal/tlsx/` | TCP engine: crypto/tls + uTLS client, hello templates |
| `internal/quicx/` | QUIC engine (quic-go) |
| `internal/probe/` | probe plans, executors, deadline ladder |
| `internal/classify/` | IANA-derived tables, taxonomy, scoring |
| `internal/resolver/` | DNS pool, PTR enrichment, caches |
| `internal/target/` | input grammar, dedupe, shard, resume set |
| `internal/out/` | encoders (jsonl/csv/text/urls), WAL |
| `internal/legacy/` | optional legacy module (heartbleed/ccs/robot/sslv3) |
| `docs/spec.md` | product specification (canonical) |
| `tests/fixtures/` | server configs, badssl expectations, registry snapshots |

## The registry rule (single home for volatile data)

IANA-derived tables — supported groups, signature schemes, certificate OIDs —
are versioned data under `internal/classify/` with a snapshot date and a
documented regeneration command beside the artifact. They are **never
hand-edited**: codepoint drift is fixed by regenerating, not by surveying.
The obsolete Kyber draft codepoints are deliberately kept as compatibility
oracles (spec, Appendix A). A review rejects any change that inlines
codepoints into engines or prose.

## Testing

**Test before feature.** Every change ships with the check that proves it in
the same pull request; nothing merges ahead of the check that would catch its
regression.

- **Fixture invariants** (badssl.com suite/version/certificate-hostile
  endpoints, locally served TLS configuration matrix) live as expectation
  rows under `tests/fixtures/`; a probe change without its fixture row is a
  review-blocking smell.
- **Differential correctness**: results on the fixture matrix are
  cross-checked against gnutls-cli-debug and sslyze; a divergence either
  becomes a documented, reasoned exception in the fixture file or is a bug.
- **PQC ground truth**: known hybrid-group-negotiating endpoints pin the
  classifier; the obsolete-Kyber oracle pins compat handling.
- **Decision procedure.** 1. Probe invariant → a fixture row. 2. Behaviour →
  a Go test in the owning package. 3. Neither → a one-line comment explaining
  why it could not be either.
- **No invented transcripts.** Any README/PR/issue claim about behaviour
  cites a real run verbatim (or links the CI run); a claim without a
  traceable run is marked PENDING with its owning issue — never approximated.

## Signing

**Everything is GPG-signed, always** — commits and tags
(`git config commit.gpgsign true`; releases are signed tags). The
`protect-default` ruleset enforces `required_signatures`; an unsigned or
badly-attributed commit blocks the pull request. The signing key and the
commit email must agree with a GitHub-verified identity or verification fails
with `bad_email` and the PR cannot merge.

This repository signs with the OWASP identity: OpenPGP key fingerprint
`9CB1781DC2BB28D37A0155DCAAF8226F3F4C1712`, email `shain.singh@owasp.org`.

Default branch: **`main`**.

## Architecture Decision Records

Structural changes carry an ADR in the same PR. Most slices are leaf-sized —
the issue plus the linked spec sections are the design record, no ADR needed —
write one only when the change **introduces a new persistent artifact** (the
JSONL schema shape, the probe-plan format, a ruleset, a registry snapshot
layout) **or removes/changes one**. Records live in `docs/adr/`, numbered
sequentially, one decision per file; accepted records are immutable and are
superseded, never rewritten.

## Pull requests

Follow [`CONTRIBUTING.md`](CONTRIBUTING.md) and treat the PR checklist as a
contract, not decoration.

### Before opening

- Work happens on a leaf branch cut from current `origin/main` — branch
  names follow `<type>/<short-description>` kebab-case
  (e.g. `feat/group-ladder`, `docs/spec-scoring`).
- **One logical change per PR.** No drive-by refactors, formatting or
  dependency bumps.
- All commits GPG-signed with a GitHub-verified identity (see [Signing](#signing)).
- Run what CI runs locally before opening: `gofmt -l .`, `go vet ./...`,
  `go test ./...`, `pre-commit run --all-files`.

### Title and description

- Title follows Conventional Commits; roadmap slices carry the task id in
  the subject — `type(scope): PQ-XXn — summary` (e.g. `feat(classify):
  PQ-04 — hybrid-group ladder + verdicts`). A CI title gate checks the form.
  Issue titles are a separate surface: `PQ-XXn — summary` in the title.
- Body: **what** changed, **why** (issue), **how verified** (test output,
  fixture/differential evidence). Spec sections the change implements are
  hyperlinked (`docs/spec.md#<heading-anchor>`); reviewers should not have
  to read the diff to know something changed.
- The maintainer personally reviews and merges every PR. Do not enable
  auto-merge on the maintainer's behalf.

### Commits

- Small, self-contained, conventional-commit subjects; no stray scratch
  files; probe files and temporary scripts are deleted before commit, not
  gitignored.

## Labels

| Label | Meaning |
| --- | --- |
| `PQ-XXn — <summary>` (issue titles carry it in the title, PR titles in the conventional subject) | issue/PR identity |
| `area:probe` / `area:quic` / `area:classify` / `area:resolver` / `area:target` / `area:out` / `area:legacy` / `area:cli` / `area:docs` / `area:ci` / `area:release` | component |
| `type:task` | a leaf-sized roadmap slice — the only `type:*` label today |
| `target:m0` … `target:m5`, `target:backlog` | milestone |
| `s:xs` / `s:s` / `s:m` / `s:l` | effort |
| `bug`, `documentation`, `ci` | maintenance |

Board status (`Todo` / `In Progress` / `Done`) is a project-field, not a
label: labels never encode progress. Never invent new `area:*`/`type:*`
names — growing the catalog is a deliberate change, not agent improvisation.

## Security

### Vulnerabilities

**Never open a public issue or PR describing an exploitable bug.** Report
through the GitHub security advisory link
([new advisory](https://github.com/shsingh/pqscan/security/advisories/new));
see [`SECURITY.md`](SECURITY.md).

### Policy-relevant invariants

- **Etiquette defaults are security-relevant.** Rate caps, per-subnet
  concurrency, breaker thresholds and the deadline ladder are the tool's
  published safety posture; a change that silently loosens them is
  review-blocking and needs its own ADR.
- **Registry integrity.** IANA-derived files are supply-chain artifacts:
  their regeneration command, snapshot date and provenance are part of the
  file; drift between the registry snapshot and the engines that consume it
  is a security bug, not a docs fix.
- **No personal-infrastructure references.** This is a public repository:
  issues, PR bodies, commit messages and code carry no local paths, private
  tooling, or environment specifics — abstract wording only.
- Secrets never enter the tree; secret scanning and push protection stay
  enabled in repository settings.

### Code style and conventions

- Go 1.25+; stdlib-first, zero-dependency posture: a new dependency needs
  justification in the PR body (uTLS and quic-go are the sanctioned exceptions).
- One concern per package file; no `interface{}` escape hatches in engine code.
- Generated artifacts (`internal/classify/` tables, `flake`-less lockfiles if
  any) are committed; regeneration commands are documented next to the artifact.
- The JSONL output schema is versioned (`schema: 1`); changes to existing
  fields are breaking and require a schema bump plus a migration note.
