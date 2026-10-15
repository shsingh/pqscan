# 0002 — Watched RED: test-first as the merge gate

Status: accepted

## Context

The project's stated engineering standard (AGENTS.md testing section,
CONTRIBUTING.md hypothesis-first section) commits to test-before-feature and
harness-before-capability, but the standard lived as convention — nothing
bound the ORDER of test and implementation in the commit history. M0 gave
two live demonstrations of the cost: the fixture server whose accept loop
never executed its handshake ([#13](https://github.com/shsingh/pqscan/pull/13))
and the raw probe's malformed server_name list length
([#16](https://github.com/shsingh/pqscan/pull/16)) were caught by tests that
were written *with* their implementations, after the code existed. Both
defects were exactly detectable by the very first test run; earlier
existence of the tests is what the standard should have delivered.

Decision context also cites the specification's verification strategy
([`docs/spec.md#10-test-and-verification-strategy`](../../blob/main/docs/spec.md#10-test-and-verification-strategy))
and the coverage audit recorded in
[PQ-10](https://github.com/shsingh/pqscan/issues/18) (gaps: the `cmd/pqscan`
version/usage path and the ClientHello wire-format roundtrip were shipped or
proposed without their pairs; the audit tracks their closure).

## Decision

Every behavioural change lands as a **watched RED→GREEN commit pair**:

1. The failing test(s) exist and RUN before the implementation — the RED
   commit carries the failing run's output in its commit body.
2. The implementation commit turns the suite green; its body carries the
   green run.
3. The PR body repeats both outputs verbatim (no invented transcripts;
   `AGENTS.md`), and — where the change implements an issue — the same
   evidence posts as a timeline **comment on the implementing issue**;
   the issue is the audit record, the PR is the change record. Because
   this repository squash-merges, the PR body + the issue comment are the
   durable evidence surfaces.
4. Non-behavioural changes (docs, pure data additions, dependency bumps)
   carry no pair but must not reduce tested behaviour.
5. PR review treats a behaviour change without its pair as a
   review-blocking smell.

## Consequences

- Engine lanes structure their commits test-first from now on; the
  capability-matrix leaf ([PQ-05](https://github.com/shsingh/pqscan/issues/8),
  PR #16) was force-pushed into a RED→GREEN pair as the first enforcement
  demonstration.
- The coverage audit's gaps close under this gate
  ([PQ-10](https://github.com/shsingh/pqscan/issues/18)); no M0 gate closure
  (PQ-08) happens with open audit gaps.
- CI keeps re-proving GREEN independently of local runs; the RED evidence
  is unverifiable-at-distance (honesty is on the author), which is why the
  output verbatim convention exists.
- Documentation-only PRs gain speed in exchange: their diff needs no
  run evidence.
