# 0001 — Adopt Go over Rust for the pqscan engines

Status: accepted

## Context

The engine substrate must drive two handshake planes — TCP (crypto/tls plus
hello-level control) and QUIC (TLS 1.3 inside QUIC) — while enforcing the
product's identity decisions: PD-dialect chainability (spec
[`§6`](../../blob/main/docs/spec.md#6-chaining-reference-implementations))
and the throughput/concurrency SLOs (spec
[`§7`](../../blob/main/docs/spec.md#7-the-hard-part-async-architecture-and-throughput-first-class)).

The full analysis is the language-decision section of the canonical
specification ([`docs/spec.md#4-language-decision-go-or-rust`](../../blob/main/docs/spec.md#4-language-decision-go-or-rust),
recorded in the specification review,
[issue #1](https://github.com/shsingh/pqscan/issues/1)). The forces:

- Go's crypto/tls ships ML-KEM by default since Go 1.24 and exposes the
  negotiated result (`ConnectionState.CurveID`) from 1.25 — negotiated
  hybrid-group observation without C bindings.
- uTLS provides ClientHello-level construction (custom `supported_groups`,
  explicit `key_share`, browser presets) — the probe mechanism for the
  forced-group ladder and the obsolete-Kyber compatibility oracle.
- quic-go wraps crypto/tls, so the same group-control story applies to the
  QUIC plane with no second crypto stack.
- The scanner's binding constraint is socket parallelism and latency, not
  per-connection CPU (spec §7.1); the throughput model is
  budget-driven and language-independent.
- The output/CLI dialect and release pipeline (streaming JSONL, exit codes,
  goreleaser) are idiomatic Go.
- Rust's strengths are recorded honestly: the rustls provider API is the
  cleanest custom-KEM injection surface, GC-free tail latency, smaller
  binaries. Its costs here: restricted legacy-suite coverage (TLS 1.0/1.2
  enumeration awkward; SSLv3-era probing would need vendored OpenSSL
  bindings either way), tokio cancellation complexity across thousands of
  short-lived probe handshakes, and slower iteration.

No substantive technical discussion recorded beyond the specification
review; the decision analysis lives in the spec section cited above.

## Decision

Adopt Go as the implementation language: crypto/tls as the negotiation
core, uTLS as the hello-construction escape hatch, quic-go for the UDP
plane. Toolchain floor Go 1.25 (negotiated-group readback). Dependency
posture stays stdlib-first; uTLS and quic-go are the sanctioned exceptions.

## Consequences

- Easier: probe iteration, cross-compiled static releases, CI without
  cross-language build glue, MLKEM defaults inherited and pinned in CI, the
  PD-dialect conventions the spec requires.
- Harder: garbage-collected memory at extreme in-flight counts — bounded by
  the budgets and allocation discipline in spec §7.7 and measured, not
  assumed (PQ-07); exotic-group construction for non-stdlib groups routes
  through uTLS hello construction rather than a crypto-provider API.
- Deferred: nothing on the language; the SSLv3-era legacy module needs the
  optional sidecar in either language (spec, legacy module scope).

**Re-validation clause.** This decision carries an explicit re-score gate:
M0's measurement report (PQ-08) either re-affirms acceptance with measured
numbers against the spec §7.8 SLOs, or the kill-switch fires — a
superseding ADR proposes the switch with the measured deficit as evidence.
Switching languages is a decision, not a vibe.
