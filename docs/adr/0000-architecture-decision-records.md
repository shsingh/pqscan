# pqscan — Architecture Decision Records

This directory holds the project's Architecture Decision Records (ADRs):
short, numbered documents recording a *structural* decision — what was
decided, why, and what it supersedes.

## Index

| Number | Title | Status |
| --- | --- | --- |
| [0000](0000-architecture-decision-records.md) | Architecture decision records (this process) | accepted |
| [0001](0001-adopt-go-over-rust.md) | Adopt Go over Rust for the pqscan engines | accepted |
| [0002](0002-watched-red-merge-gate.md) | Watched RED: test-first as the merge gate | accepted |

## When an ADR is required

Most changes are leaf-sized slices whose design record is the roadmap
issue's spec references (`PQ-XXn`); they do **not** need an ADR. Write one
only when the change **introduces a new persistent artifact** or **removes
or changes one** — the JSONL schema shape, the probe-plan format, the
registry-snapshot layout, a ruleset, the wire grammar of any output mode, or
the engine/runtime substrate. Dependency bumps, documentation and CI tweaks
never need an ADR.

Rules (full text in
[`0000`](0000-architecture-decision-records.md)): accepted ADRs are
immutable and get superseded, never rewritten; never invent discussion,
deciders or quotes — cite permalinks or say "No substantive technical
discussion recorded"; every ADR lands in the same PR as the change it
records.

## Discipline

- **Accepted ADRs are immutable.** A change that contradicts an accepted
  ADR supersedes it with a new one; never rewrite the accepted record.
- **No invented evidence.** Cite issue/commit/spec-section permalinks, or
  state "No substantive technical discussion recorded".
- **One decision per file**, `docs/adr/NNNN-short-slug.md`, numbered
  sequentially; numbers are never recycled.
- The index above gains one row per ADR at merge time.
