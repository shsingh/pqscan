# M0 measurement and decision gate — report

**Status: gate closing.** This report is the M0 milestone's acceptance
record ([`docs/spec.md#9-milestones`](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#9-milestones)):
every engine claim below is a measured run, evidence verbatim on the
linked issues (run output verbatim per ADR-0002 — no invented transcripts).

## 1. Capability matrix — both planes

### TCP plane (`internal/tlsx`)

| Probe | Result | Evidence |
|---|---|---|
| Forced 4588 `X25519MLKEM768` | negotiated against live hybrid edge (`TLS_AES_128_GCM_SHA256`, TLS 1.3, version 772) | run on [issue #8](https://github.com/shsingh/pqscan/issues/8) |
| HRR observation | on-the-wire detection via the RFC 8446 §4.1.3 magic random; demanded-group extraction from the retry's key_share (fixture: 4588) | fixture test, #8 |
| Kyber-draft oracle 25497 | share-less offer answered by the edge with an **HRR demanding 25497** — the obsolete draft remains accepted live | integration run, #8 |
| Suite forcing (offer-one/observe-accept) | exact-suite negotiation incl. ALPN pinned | fixture matrix, #8 |

### QUIC plane (`internal/quicx`)

| Probe | Result | Evidence |
|---|---|---|
| Forced 4588 inside QUIC v1 | negotiated, ALPN `h3`, DialMs 27.636 / 39.901 across two runs, `UDPBlocked: false` | [issue #9](https://github.com/shsingh/pqscan/issues/9) |
| UDP failures classified as results | `refused` / `blocked` (+`udp_blocked`) recorded, never crashes | #9 |
| Per-connection cost (n=15, live) | avg handshake 22.5 ms; goroutine delta 3; heap snapshot 665 KB | #9 |

## 2. SLO cells (spec §7.8) — measured at M0

| Cell | Target | Measured | Run |
|---|---|---|---|
| fast-mode handshakes/s/core | ≥ 2,500 | **2,952** (re-run 3,026) at W=8 on the loopback fixture | `go test ./internal/microbench/ -run SLO -v` ([#10](https://github.com/shsingh/pqscan/issues/10)) |
| Latency decomposition shape | connect ≈ 1 RTT; total ≈ 2 RTT + server compute | external control matches the model: connect 18.94 ms / handshake 23.44 ms / total 42.4 ms (cloudflare, seq×20) | `go run ./cmd/bench -target cloudflare.com:443` |
| QUIC per-conn cost | budget inputs for the 10k in-flight ceiling | 22.5 ms avg handshake; goroutine delta 3; heap 665 KB | `MeasureCost`, #9 |
| Aggregate sustained under load; p95 per-target; RSS at 50k in-flight; deep-mode rate | spec cells | **deferred to their owning milestones** (M3/M4) — not M0 scope; listed so no cell is silently skipped | register |

## 3. Language decision — re-validation outcome

Verdict: **ADR-0001 re-affirmed** ([`docs/adr/0001-adopt-go-over-rust.md`](https://github.com/shsingh/pqscan/blob/main/docs/adr/0001-adopt-go-over-rust.md)).

- The throughput SLO is met on the Go stack with the model evidenced
  (T ≈ W/L decomposition matches measurements on live and loopback hosts).
- Both planes negotiate PQC groups without C bindings or stack forks;
  the uTLS/raw-hello construction covers the non-stdlib oracle groups.
- The kill-switch clauses (measured deficit; missing capability) did not
  fire. The record's re-validation clause is satisfied by this report;
  the ADR index marks 0001 re-affirmed at the M0 gate.

## 4. Gate criteria checklist

- [x] Forced-group handshake negotiates 4588 against a live hybrid endpoint; fixture row pins the observation
- [x] HRR observed and recorded (on-wire detector + demanded-group extraction)
- [x] QUIC handshake reports the negotiated group on the UDP plane
- [x] Microbench ≥ 2,500 handshakes/s/core (2,952 / 3,026 measured) with memory/goroutine footprints recorded
- [x] Language decision re-scored with numbers (re-affirmed; kill-switch un-fired)

Watched-RED pair history for every engine commit: #16, #20, #25, #26,
#30, #34 (each with verbatim RED/GREEN runs in the PR + issue comments).
Diagnostics: `-debug`/`-debug-out` shipped (PQ-11); both planes emit
decision events.

## 5. What M1 inherits

- Target grammar + the run pipeline (PQ-01 register) with the proven
  engines underneath; the encoders/WAL lane; the flag↔man-page drift check.
- The measured cost numbers feed the budget-tuning defaults at startup.
- The obsolete-Kyber finding (edge still honouring 25497) gives the `pq`
  mode its first survey target: the compat-oracle ladder is live.
