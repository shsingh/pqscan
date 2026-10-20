# Contributing

Contributions are welcome. This document defines the working agreement: how
changes are proposed, reviewed, and merged, and what the continuous-integration
gates enforce.

## Ground rules

1. **Never commit to `main`.** All work happens on a branch, one change per
   branch, merged via pull request. Branch names follow
   `<type>/<short-description>` kebab-case — e.g. `feat/group-ladder`,
   `fix/resolver-ewma`, `docs/spec-scoring`.
2. **Conventional Commits.** Every commit subject follows the
   [specification](https://www.conventionalcommits.org/en/v1.0.0):
   `type(scope): subject`.
   - Types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`,
     `chore`, `perf`, `revert`.
   - `scope` is a component: `probe` (probe plans, deadline ladder),
     `quic` (QUIC plane), `classify` (registry tables, taxonomy, scoring),
     `resolver` (DNS/PTR), `target` (grammar, dedupe, shard), `out`
     (encoders, WAL), `legacy` (optional legacy module), `cli`, `docs`,
     `ci`, `release`.
   - Subject: imperative, lowercase, no trailing period. Body (optional):
     what changed and why; wrap at 72 columns.
   - PR titles follow the same form; roadmap slices carry the task id in
     the subject — `type(scope): PQ-XXn — subject`. Squash merges use the
     PR title as the commit subject, so the PR title is the commit record.
     A CI gate checks the form on every PR; bot/dependency PRs (renovate,
     pre-commit.ci autoupdate) keep their canonical titles.
3. **Sign everything.** Commits must be GPG- or SSH-signed
   (`git config commit.gpgsign true`); releases are signed tags — unsigned
   commits and unsigned tags are not merged/published. This repository signs
   with the OWASP identity: OpenPGP key `9CB1781DC2BB28D37A0155DCAAF8226F3F4C1712`,
   email `shain.singh@owasp.org`. The `protect-default` ruleset enforces
   `required_signatures`. Verify with `git log --show-signature` /
   `git tag -v`.
4. **One logical change per PR.** Small, reviewable diffs merge faster.
5. **Pre-commit runs locally.** Install the hooks once per clone —
   `pre-commit install && pre-commit install --hook-type pre-push` — then
   every `git commit` and `git push` runs the same hook set CI runs
   (bypass with `--no-verify` for the rare legitimate exception).

## Security-sensitive changes

Anything touching probe etiquette defaults, the classifier registry tables,
or the output schema warrants extra care (see [SECURITY.md](SECURITY.md) for
the full posture):

- **Vulnerabilities are not issues.** Follow [SECURITY.md](SECURITY.md) —
  never open a public issue for an unreported vulnerability.
- **Etiquette defaults** (rate caps, per-subnet concurrency, breaker
  thresholds, deadline ladder) are the published safety posture: a change
  that loosens them implicitly is rejected in review and needs its own ADR.
- **Registry integrity:** IANA-derived files are regenerated from the
  registry, never hand-edited; a review rejects inline codepoints in engines
  or prose.
- **Output schema:** field removals or semantic changes are breaking — a
  schema bump plus a migration note is required.

## The acceptance suite

```
gofmt -l . && go vet ./...          # formatting + static analysis
go test ./...                       # the fixture matrix + unit suite
pre-commit run --all-files          # the hook set CI runs
```

The repo is stdlib-first: new dependencies require justification in the PR
body. The hook set (trailing whitespace, YAML/JSON validity, large-file
guards, `detect-private-key`, shellcheck on shell scripts) runs on every PR.

## CI on every pull request

| Check | What it does |
|---|---|
| `PR title — Conventional Commits + PQ id` | PR title checked against the Conventional Commits form |
| Dependency Review | flags vulnerable or licence-incompatible dependency changes |
| `required_signatures` | ruleset-enforced: unsigned commits block the PR |

Required status checks grow as CI surfaces land (build/test legs arrive with
the first Go tree — M0).

## Commits and pull requests

- Push the branch and open a PR against `main`; describe the what and the why.
- The PR body links the `PQ-XXn` issue the change implements and the
  `docs/spec.md` sections it exercises (GitHub heading anchors).
- The maintainer personally reviews and merges every PR; do not enable
  auto-merge on the maintainer's behalf.
- Releases are signed tags; the release ladder is defined with the release
  milestone in [`docs/spec.md`](docs/spec.md).

## Reporting bugs

Open a [GitHub issue](https://github.com/shsingh/pqscan/issues/new) with the
version or commit, the mode and probe surface hit, host OS, and the relevant
output excerpt. Security issues never go here — [SECURITY.md](SECURITY.md)
instead.

### The matrix-cell duty: fix a bug, add the cell

Every bug fix and every feature touching a flag combination lands its
reproducing combination as a new matrix cell in the same PR — an array case, a
battery vector class, a refusal row or a chain cell — with its row in
[tests/matrix/LEDGER.md](tests/matrix/LEDGER.md) (origin, landing date, the
invariant it pins) and its checkbox in
[issue #150](https://github.com/shsingh/pqscan/issues/150)'s body registry, an
unticked box being the standing drift signal the next build must clear. Bug
reports name the cell through the required Matrix cell field of the bug report
template; `new` there means the fixer derives the row and lands the cell.

## Licence

The project is licensed under **MIT** — see [LICENSE](LICENSE). Contributions
are made under MIT: by submitting a pull request the work is licensed under
the project's MIT terms.

## Engineering standard: hypothesis-first, check-first

Every feature, fix and refactor follows **hypothesis → failing test →
minimal implementation → refactor**:

1. State the hypothesis in the issue: expected behaviour, assumed mechanism,
   falsifying observation.
2. Commit the failing test first on the feature branch; paste the RED run's
   failure line into the PR.
3. Implement the minimum that passes; then the suite; then refactor with
   tests green.
4. Edge/error paths (timeouts, malformed targets, failure modes) are covered
   before close.

Where unit tests cannot reach (live-network behaviour), the issue's
acceptance criterion is the test: record the expected-vs-observed run before
the change, re-run after.

**Harness before capability.** The check that gates a behaviour ships in the
same PR as the behaviour; nothing merges ahead of the check that would catch
its regression, and a new gate's negative case is proven in CI, not asserted
in prose.

Exceptions require the maintainer's explicit go-ahead in the issue before
work starts.
